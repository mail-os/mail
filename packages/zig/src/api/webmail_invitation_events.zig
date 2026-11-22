//! Apply organizer revisions to an attendee's private Calendar copy.
const std = @import("std");
const calendar = @import("webmail_calendar_events.zig");
const invites = @import("webmail_calendar_invite.zig");
const dav = @import("../storage/caldav_store.zig");
const ical = @import("../protocol/icalendar.zig");
const clock = @import("../protocol/icalendar_time.zig");
const recurrence = @import("../protocol/icalendar_busy.zig");
const Allocator = std.mem.Allocator;
const AppliedRevision = invites.AppliedRevision;

fn revisionOrder(left: invites.Revision, right: invites.Revision) std.math.Order {
    const sequence = std.math.order(left.sequence, right.sequence);
    if (sequence != .eq) return sequence;
    const stamp = std.math.order(left.dtstamp, right.dtstamp);
    if (stamp != .eq) return stamp;
    return std.math.order(@intFromBool(left.method == .cancel), @intFromBool(right.method == .cancel));
}

fn covers(change: invites.Revision, instance: ?invites.WallTime, key: [64]u8, future: bool) bool {
    if (std.mem.eql(u8, &change.component, &key)) return change.this_and_future or !future;
    const anchor = change.occurrence orelse return change.method == .cancel;
    if (!change.this_and_future) return false;
    const occurrence = instance orelse return false;
    return occurrence.all_day == anchor.all_day and occurrence.wall >= anchor.wall and
        std.mem.eql(u8, occurrence.zone orelse "", anchor.zone orelse "");
}

const Slot = struct {
    event: ical.Component,
    anchor: ?ical.Property,
    occurrence: ?invites.WallTime,
    key: [64]u8,
    future: bool,
    version: ?invites.Revision = null,

    fn read(a: Allocator, invite: invites.Invitation, event: ical.Component) !Slot {
        var properties = ical.Properties.init(event);
        const anchor = while (try properties.next(a)) |property| {
            if (property.named("RECURRENCE-ID")) break property;
        } else null;
        const occurrence = if (anchor) |field| invites.WallTime.read(field) orelse return error.InvalidCalendar else null;
        return .{
            .event = event,
            .anchor = anchor,
            .occurrence = occurrence,
            .key = try invite.keyForOccurrence(a, occurrence),
            .future = if (anchor) |field| std.ascii.eqlIgnoreCase(field.param("RANGE") orelse "", "THISANDFUTURE") else false,
        };
    }

    fn matches(self: Slot, revision: invites.Revision) bool {
        return self.future == revision.this_and_future and std.mem.eql(u8, &self.key, &revision.component);
    }
};

fn digest(component: ical.Component) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(component.bytes, &result, .{});
    return result;
}

fn savedSlots(a: Allocator, invite: invites.Invitation, original: []const ical.Component, previous: []const AppliedRevision) !std.ArrayList(Slot) {
    var slots: std.ArrayList(Slot) = .empty;
    var generated: std.AutoHashMapUnmanaged([32]u8, void) = .empty;
    var physical: std.AutoHashMapUnmanaged(struct { [64]u8, bool }, AppliedRevision) = .empty;
    for (previous) |item| {
        var key = item.revision.component;
        if (item.projection) |projection| {
            for (projection.generated) |fingerprint| try generated.put(a, fingerprint, {});
            if (projection.omitted_event) |body| {
                var slot = try Slot.read(a, invite, .{ .name = "VEVENT", .bytes = body });
                slot.version = item.revision;
                try slots.append(a, slot);
                continue;
            }
            key = try invite.keyForOccurrence(a, projection.physical_anchor orelse return error.InvalidCalendar);
        }
        try physical.put(a, .{ key, item.revision.this_and_future }, item);
    }
    var project: ?recurrence.RangeProjection = null;
    for (original) |event| {
        if (!std.ascii.eqlIgnoreCase(event.name, "VEVENT")) continue;
        var slot = try Slot.read(a, invite, event);
        if (physical.get(.{ slot.key, slot.future })) |item| {
            if (item.projection) |projection| {
                if (project == null) {
                    const master = try masterEvent(a, original);
                    project = try recurrence.RangeProjection.init(a, master, original);
                }
                const canonical = try project.?.move(a, event, .{ .field = projection.original_anchor }, true);
                slot = try Slot.read(a, invite, canonical);
            }
            slot.version = item.revision;
        } else if (generated.count() != 0 and generated.contains(digest(event))) continue;
        try slots.append(a, slot);
    }
    return slots;
}

fn masterEvent(a: Allocator, components: []const ical.Component) !ical.Component {
    for (components) |component| {
        if (!std.ascii.eqlIgnoreCase(component.name, "VEVENT")) continue;
        if (try ical.componentText(a, component, "RECURRENCE-ID") == null) return component;
    }
    return error.NoPrimaryEvent;
}

const organizer_fields = [_][]const u8{
    "DTSTART", "DTEND",       "DURATION", "RECURRENCE-ID", "RRULE", "RDATE", "EXDATE",
    "SUMMARY", "DESCRIPTION", "LOCATION", "TRANSP",
};
const controlled_fields = organizer_fields ++ [_][]const u8{
    "UID", "SEQUENCE", "DTSTAMP", "ORGANIZER", "ATTENDEE", "STATUS", "CLASS",
};

fn allowed(property: ical.Property, fields: []const []const u8) bool {
    for (fields) |field| if (property.named(field)) return true;
    return false;
}

fn organizerProperty(output: *ical.Export, property: ical.Property, name: []const u8) !void {
    const a = output.allocator;
    var line: std.ArrayList(u8) = .empty;
    try line.appendSlice(a, name);
    if (allowed(property, &.{ "DTSTART", "DTEND", "RECURRENCE-ID", "RDATE", "EXDATE" })) {
        if (property.param("VALUE")) |value| {
            if (!std.ascii.eqlIgnoreCase(value, "DATE") and !std.ascii.eqlIgnoreCase(value, "DATE-TIME") and
                !(property.named("RDATE") and std.ascii.eqlIgnoreCase(value, "PERIOD"))) return error.InvalidCalendar;
            try line.print(a, ";VALUE={s}", .{value});
        }
        if (property.param("TZID")) |value| {
            if (std.mem.indexOfAny(u8, value, "\"\r\n\x00") != null) return error.InvalidCalendar;
            try line.print(a, ";TZID=\"{s}\"", .{value});
        }
        if (std.ascii.eqlIgnoreCase(name, "RECURRENCE-ID")) {
            if (property.param("RANGE")) |value| {
                if (!std.ascii.eqlIgnoreCase(value, "THISANDFUTURE")) return error.InvalidCalendar;
                try line.appendSlice(a, ";RANGE=THISANDFUTURE");
            }
        }
    }
    try line.print(a, ":{s}", .{property.value});
    try output.foldedLine(&output.events, line.items);
}

fn writeChange(output: *ical.Export, invite: invites.Invitation, attendee: []const u8, existing: ?ical.Component) !void {
    const a = output.allocator;
    const cancel = invite.preview.method == .cancel;
    const master_cancel = cancel and invite.recurrence == null;
    const source = if (master_cancel) existing orelse return error.InvitationEventRequired else invite.component;
    try output.events.appendSlice(a, "BEGIN:VEVENT\r\n");
    try output.foldedLine(&output.events, try std.fmt.allocPrint(a, "ORGANIZER:{s}", .{try invites.addressUri(a, invite.preview.organizer)}));
    try output.foldedLine(&output.events, try std.fmt.allocPrint(a, "ATTENDEE:{s}", .{try invites.addressUri(a, attendee)}));
    try output.events.appendSlice(a, if (cancel) "STATUS:CANCELLED\r\n" else "STATUS:CONFIRMED\r\n");
    try output.events.appendSlice(a, "CLASS:PRIVATE\r\n");
    var incoming = ical.Properties.init(invite.component);
    while (try incoming.next(a)) |property| {
        if (allowed(property, &.{ "UID", "SEQUENCE", "DTSTAMP" })) try organizerProperty(output, property, property.name);
    }
    if (cancel and !master_cancel) {
        const anchor = invite.recurrence.?;
        try organizerProperty(output, anchor, "RECURRENCE-ID");
        try organizerProperty(output, anchor, "DTSTART");
    } else {
        var fields = ical.Properties.init(source);
        while (try fields.next(a)) |field| {
            if (allowed(field, &organizer_fields)) try organizerProperty(output, field, field.name);
        }
    }
    if (existing) |old| {
        var properties = ical.Properties.init(old);
        while (try properties.next(a)) |property| {
            if (allowed(property, &controlled_fields)) continue;
            const params = if (property.params.len > 0) ";" else "";
            try output.foldedLine(&output.events, try std.fmt.allocPrint(a, "{s}{s}{s}:{s}", .{ property.name, params, property.params, property.value }));
        }
        if (!cancel) for (try ical.childComponents(a, old)) |child| {
            if (std.ascii.eqlIgnoreCase(child.name, "VALARM")) try output.addComponent(&output.events, a, child);
        };
    }
    try output.events.appendSlice(a, "END:VEVENT\r\n");
}

fn findZone(a: Allocator, components: []const ical.Component, tzid: []const u8) !?ical.Component {
    var found: ?ical.Component = null;
    for (components) |item| {
        if (!std.ascii.eqlIgnoreCase(item.name, "VTIMEZONE")) continue;
        const id = (try ical.componentText(a, item, "TZID")) orelse continue;
        if (!std.mem.eql(u8, id, tzid)) continue;
        if (found != null) return error.ConflictingTimezone;
        found = item;
    }
    return found;
}

fn appendTimezones(output: *ical.Export, incoming: []const ical.Component, stored: []const ical.Component) !void {
    const a = output.allocator;
    // Walk the projected VEVENTs, including retained overrides, to include just
    // the zones the resulting CalDAV resource actually uses.
    const body = try std.mem.concat(a, u8, &.{ "BEGIN:VCALENDAR\r\n", output.events.items, "END:VCALENDAR\r\n" });
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    for (try ical.components(a, body)) |item| {
        var properties = ical.Properties.init(item);
        while (try properties.next(a)) |property| {
            const name = property.param("TZID") orelse continue;
            if ((try seen.getOrPut(a, name)).found_existing) continue;
            const proposed = try findZone(a, incoming, name);
            const existing = try findZone(a, stored, name);
            if (proposed != null and existing != null) {
                var prior: ical.Export = .{ .allocator = a };
                var candidate: ical.Export = .{ .allocator = a };
                try ical.addSchedulingTimezone(&prior, existing.?);
                try ical.addSchedulingTimezone(&candidate, proposed.?);
                // A zone definition also applies to occurrences retained
                // from the saved event, including the recurrence anchor.
                if (!std.mem.eql(u8, prior.headers.items, candidate.headers.items)) return error.ConflictingTimezone;
            }
            const zone = proposed orelse existing orelse ical.Component{
                .name = "VTIMEZONE",
                .bytes = clock.bundledTimezone(name) orelse return error.UnsupportedTimezone,
            };
            _ = try clock.Zone.parse(a, zone);
            try ical.addSchedulingTimezone(output, zone);
        }
    }
}

fn projectRanges(output: *ical.Export, slots: []const Slot, versions: []AppliedRevision) !void {
    const a = output.allocator;
    var master: ?ical.Component = null;
    var has_ranges = false;
    var has_exact = false;
    for (slots) |slot| {
        if (slot.anchor == null) master = slot.event;
        has_ranges = has_ranges or slot.future;
        has_exact = has_exact or (slot.anchor != null and !slot.future);
    }
    if (!has_ranges or !has_exact) return;
    // Read the same validated zone definitions that will be exported.
    const zone_document = try std.mem.concat(a, u8, &.{ output.headers.items, "END:VCALENDAR\r\n" });
    var projection = try recurrence.RangeProjection.init(a, master orelse return error.NoPrimaryEvent, try ical.components(a, zone_document));
    var occupied: std.ArrayList(i64) = .empty;
    var exact: std.AutoHashMapUnmanaged(i64, [64]u8) = .empty;
    var ranged: std.AutoHashMapUnmanaged(i64, [64]u8) = .empty;
    const keys = try a.alloc(?i64, slots.len);
    for (slots, keys) |slot, *key| {
        key.* = null;
        if (slot.anchor) |field| {
            const stamp = try projection.stamp(a, field);
            key.* = stamp;
            try occupied.append(a, stamp);
            const index = if (slot.future) &ranged else &exact;
            const entry = try index.getOrPut(a, stamp);
            if (entry.found_existing) return error.InvalidCalendar;
            entry.value_ptr.* = slot.key;
        }
    }
    var range_keys = ranged.keyIterator();
    while (range_keys.next()) |anchor| {
        if (exact.contains(anchor.*)) break;
    } else return;
    const exclusive_end = (clock.Date{ .year = 10000, .month = 1, .day = 1, .seconds = 0, .kind = .utc }).epoch();
    var budget = recurrence.expansion_budget;
    output.events.clearRetainingCapacity();
    for (slots, keys) |slot, key| {
        const individual = if (slot.future) exact.get(key.?) else null;
        if (individual == null) {
            try output.addComponent(&output.events, a, slot.event);
            continue;
        }
        if (!std.mem.eql(u8, &slot.key, &individual.?)) return error.InvitationScopeConflict;
        const applied = slot.version orelse return error.InvitationScopeConflict;
        const entry = for (versions) |*item| {
            if (item.revision.sameVersion(applied)) break item;
        } else return error.InvalidCalendar;
        var upper = exclusive_end;
        var anchors = ranged.keyIterator();
        while (anchors.next()) |anchor| {
            if (anchor.* > key.?) upper = @min(upper, anchor.*);
        }
        const inherits_period = applied.method != .cancel and
            try ical.componentText(a, slot.event, "DTEND") == null and try ical.componentText(a, slot.event, "DURATION") == null;
        var state: AppliedRevision.Projection = .{ .component = applied.component, .original_anchor = slot.anchor.? };
        var generated: std.ArrayList([32]u8) = .empty;
        var after = key.?;
        while (try projection.next(a, after, upper, occupied.items, &budget)) |next| {
            if (inherits_period and next.period != null) {
                // A detached range's duration governs every later instance.
                // Give an RDATE period its own exception when it would
                // otherwise impose its custom length on the rest of the range.
                const occurrence = try projection.move(a, slot.event, next, false);
                try output.addComponent(&output.events, a, occurrence);
                try generated.append(a, digest(occurrence));
                after = try projection.stamp(a, next.field);
                continue;
            }
            const range = try projection.move(a, slot.event, next, true);
            try output.addComponent(&output.events, a, range);
            state.physical_anchor = invites.WallTime.read(next.field) orelse return error.InvalidCalendar;
            break;
        } else {
            state.omitted_event = slot.event.bytes;
        }
        state.generated = generated.items;
        entry.projection = state;
    }
}

/// Prepare and validate outside the storage locks. The caller commits this
/// document against the same event ETag and current mail revision.
pub fn prepare(a: Allocator, invite: invites.Invitation, attendee: []const u8, revision: invites.Revision, source: dav.MessageReference, saved: ?dav.CalDavStore.InvitationSnapshot) !?dav.CalDavStore.EventData {
    if (saved == null and (revision.method == .cancel or revision.occurrence != null)) return error.InvitationEventRequired;
    const original = if (saved) |entry| try ical.components(a, entry.detail.ics_data) else &.{};
    const previous = if (saved) |entry| try AppliedRevision.read(a, entry.revisions, entry.projections) else &.{};
    var versions: std.ArrayList(AppliedRevision) = .empty;
    for (previous) |record| {
        const item = record.revision;
        const order = revisionOrder(item, revision);
        if (covers(item, revision.occurrence, revision.component, revision.this_and_future) and order == .gt) return error.CalendarInvitationStale;
        if (item.sameVersion(revision)) return null;
        if (!covers(revision, item.occurrence, item.component, item.this_and_future) or order == .gt)
            try versions.append(a, .{ .revision = item });
    }
    try versions.append(a, .{ .revision = revision });

    var output: ical.Export = .{ .allocator = a };
    try output.headers.appendSlice(a, "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Mail//Calendar Invitation//EN\r\n");
    var slots = try savedSlots(a, invite, original, previous);
    var existing: ?ical.Component = null;
    var kept: usize = 0;
    for (slots.items) |slot| {
        if (slot.matches(revision)) {
            if (existing != null) return error.InvalidCalendar;
            existing = slot.event;
            continue;
        }
        if (covers(revision, slot.occurrence, slot.key, slot.future)) {
            if (slot.version) |item_revision| {
                if (revisionOrder(item_revision, revision) != .gt) continue;
            } else if (revision.method == .cancel and revision.occurrence == null) continue;
        }
        slots.items[kept] = slot;
        kept += 1;
        try output.addComponent(&output.events, a, slot.event);
    }
    slots.items.len = kept;
    const changed_start = output.events.items.len;
    try writeChange(&output, invite, attendee, existing);
    const changed = try a.dupe(u8, output.events.items[changed_start..]);
    var updated = try Slot.read(a, invite, .{ .name = "VEVENT", .bytes = changed });
    updated.version = revision;
    try slots.append(a, updated);
    try appendTimezones(&output, invite.components, original);
    try projectRanges(&output, slots.items, versions.items);

    const body = try output.finish();
    var data = try calendar.prepareDocument(a, body, invite.preview.uid);
    data.uid = if (saved) |entry| entry.detail.event.uid else try ical.resourceUid(a, invite.preview.uid);
    data.source_message = source;
    data.invitation_key = revision.series;
    const revisions = try a.alloc(invites.Revision, versions.items.len);
    var projections: std.ArrayList(AppliedRevision.Projection) = .empty;
    for (versions.items, revisions) |item, *stored| {
        stored.* = item.revision;
        if (item.projection) |projection| try projections.append(a, projection);
    }
    data.invitation_revisions = try std.json.Stringify.valueAlloc(a, revisions, .{});
    if (projections.items.len > 0)
        data.invitation_projections = try std.json.Stringify.valueAlloc(a, projections.items, .{});
    return data;
}
