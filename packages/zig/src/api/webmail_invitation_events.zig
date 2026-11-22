//! Apply organizer revisions to an attendee's private Calendar copy.
const std = @import("std");
const calendar = @import("webmail_calendar_events.zig");
const invites = @import("webmail_calendar_invite.zig");
const dav = @import("../storage/caldav_store.zig");
const ical = @import("../protocol/icalendar.zig");
const clock = @import("../protocol/icalendar_time.zig");
const Allocator = std.mem.Allocator;

fn revisionOrder(left: invites.Revision, right: invites.Revision) std.math.Order {
    const sequence = std.math.order(left.sequence, right.sequence);
    if (sequence != .eq) return sequence;
    const stamp = std.math.order(left.dtstamp, right.dtstamp);
    if (stamp != .eq) return stamp;
    return std.math.order(@intFromBool(left.method == .cancel), @intFromBool(right.method == .cancel));
}

fn covers(change: invites.Revision, instance: ?invites.WallTime, key: [64]u8) bool {
    if (std.mem.eql(u8, &change.component, &key)) return true;
    const anchor = change.occurrence orelse return change.method == .cancel;
    if (!change.this_and_future) return false;
    const occurrence = instance orelse return false;
    return occurrence.all_day == anchor.all_day and occurrence.wall >= anchor.wall and
        std.mem.eql(u8, occurrence.zone orelse "", anchor.zone orelse "");
}

fn revisionFor(items: []const invites.Revision, key: [64]u8) ?invites.Revision {
    for (items) |item| if (std.mem.eql(u8, &item.component, &key)) return item;
    return null;
}

fn occurrenceTime(a: Allocator, item: ical.Component) !?invites.WallTime {
    var properties = ical.Properties.init(item);
    while (try properties.next(a)) |property| {
        if (property.named("RECURRENCE-ID")) return invites.WallTime.read(property) orelse error.InvalidCalendar;
    }
    return null;
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
            try line.print(a, ";VALUE:{s}", .{value});
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

/// Prepare and validate outside the storage locks. The caller commits this
/// document against the same event ETag and current mail revision.
pub fn prepare(a: Allocator, invite: invites.Invitation, attendee: []const u8, revision: invites.Revision, source: dav.MessageReference, saved: ?dav.CalDavStore.InvitationSnapshot) !?dav.CalDavStore.EventData {
    if (saved == null and (revision.method == .cancel or revision.occurrence != null)) return error.InvitationEventRequired;
    const original = if (saved) |entry| try ical.components(a, entry.detail.ics_data) else &.{};
    const previous = if (saved) |entry| try std.json.parseFromSliceLeaky([]const invites.Revision, a, entry.revisions, .{}) else &.{};
    var versions: std.ArrayList(invites.Revision) = .empty;
    for (previous) |item| {
        const same = std.mem.eql(u8, &item.component, &revision.component);
        const order = revisionOrder(item, revision);
        if (covers(item, revision.occurrence, revision.component) and order == .gt) return error.CalendarInvitationStale;
        if (item.sameVersion(revision)) return null;
        if (same and item.this_and_future and !revision.this_and_future) return error.InvitationScopeConflict;
        if (!covers(revision, item.occurrence, item.component) or order == .gt) try versions.append(a, item);
    }
    try versions.append(a, revision);

    var output: ical.Export = .{ .allocator = a };
    try output.headers.appendSlice(a, "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Mail//Calendar Invitation//EN\r\n");
    var existing: ?ical.Component = null;
    for (original) |item| {
        if (!std.ascii.eqlIgnoreCase(item.name, "VEVENT")) continue;
        const occurrence = try occurrenceTime(a, item);
        const key = try invite.keyForOccurrence(a, occurrence);
        if (std.mem.eql(u8, &key, &revision.component)) {
            if (existing != null) return error.InvalidCalendar;
            existing = item;
            continue;
        }
        if (covers(revision, occurrence, key)) {
            if (revisionFor(previous, key)) |item_revision| {
                if (revisionOrder(item_revision, revision) != .gt) continue;
            } else if (revision.method == .cancel and revision.occurrence == null) continue;
        }
        try output.addComponent(&output.events, a, item);
    }
    try writeChange(&output, invite, attendee, existing);
    try appendTimezones(&output, invite.components, original);

    const body = try output.finish();
    var data = try calendar.prepareDocument(a, body, invite.preview.uid);
    data.uid = if (saved) |entry| entry.detail.event.uid else try ical.resourceUid(a, invite.preview.uid);
    data.source_message = source;
    data.invitation_key = revision.series;
    data.invitation_revisions = try std.json.Stringify.valueAlloc(a, versions.items, .{});
    return data;
}
