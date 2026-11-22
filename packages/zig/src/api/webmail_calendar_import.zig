const std = @import("std");
const ical = @import("../protocol/icalendar.zig");
const clock = @import("../protocol/icalendar_time.zig");
const dav = @import("../storage/caldav_store.zig");
const Allocator = std.mem.Allocator;

const max_events = 1000;
const max_prepared_bytes = 16 * 1024 * 1024;

pub fn calendarName(a: Allocator, input: []const u8) ![]const u8 {
    const name = std.mem.trim(u8, input, " \t\r\n");
    if (name.len == 0 or name.len > 100 or !std.unicode.utf8ValidateSlice(name) or hasControl(name) or
        std.mem.indexOfAny(u8, name, "/\\") != null or std.mem.eql(u8, name, ".") or std.mem.indexOf(u8, name, "..") != null)
        return error.InvalidCalendarName;
    var encoded: std.ArrayList(u8) = .empty;
    for (name) |byte| {
        if (std.ascii.isAlphanumeric(byte) or std.mem.indexOfScalar(u8, "-._~", byte) != null) {
            try encoded.append(a, byte);
        } else {
            try encoded.append(a, '%');
            try encoded.appendSlice(a, &std.fmt.bytesToHex([_]u8{byte}, .upper));
        }
    }
    return encoded.items;
}

pub const Entry = struct {
    number: usize,
    uid: ?[]const u8 = null,
    summary: []const u8 = "Untitled event",
    event: ?dav.CalDavStore.EventData = null,
    issue: ?[]const u8 = null,
};

const Event = struct {
    component: ical.Component,
    uid: ?[]const u8 = null,
    recurrence_id: ?ical.Property = null,
    start: ?ical.Property = null,
    end: ?ical.Property = null,
    duration: ?[]const u8 = null,
    summary: []const u8 = "Untitled event",
    description: ?[]const u8 = null,
    location: ?[]const u8 = null,
    organizer: ?[]const u8 = null,
    rule: ?[]const u8 = null,
    status: dav.Event.EventStatus = .confirmed,

    fn read(a: Allocator, component: ical.Component) !Event {
        var result = Event{ .component = component };
        var props = ical.Properties.init(component);
        while (try props.next(a)) |prop| {
            if (prop.named("UID")) {
                result.uid = if (result.uid == null) try ical.unescapeText(a, prop.value) else "";
            } else if (prop.named("RECURRENCE-ID")) {
                result.recurrence_id = prop;
            } else if (prop.named("DTSTART")) {
                result.start = prop;
            } else if (prop.named("DTEND")) {
                result.end = prop;
            } else if (prop.named("DURATION")) {
                result.duration = prop.value;
            } else if (prop.named("SUMMARY") and prop.value.len > 0) {
                result.summary = try ical.unescapeText(a, prop.value);
            } else if (prop.named("DESCRIPTION")) {
                result.description = try ical.unescapeText(a, prop.value);
            } else if (prop.named("LOCATION")) {
                result.location = try ical.unescapeText(a, prop.value);
            } else if (prop.named("ORGANIZER")) {
                result.organizer = if (std.ascii.startsWithIgnoreCase(prop.value, "mailto:")) prop.value[7..] else prop.value;
            } else if (prop.named("RRULE")) {
                result.rule = prop.value;
            } else if (prop.named("STATUS")) {
                if (std.ascii.eqlIgnoreCase(prop.value, "CANCELLED")) result.status = .cancelled;
                if (std.ascii.eqlIgnoreCase(prop.value, "TENTATIVE")) result.status = .tentative;
            }
        }
        return result;
    }
};

const Zone = struct {
    component: ical.Component,
    definition: ?clock.Zone,
};

const Group = struct {
    entry: Entry,
    events: std.ArrayList(Event) = .empty,
};

pub fn prepare(a: Allocator, input: []const u8) ![]Entry {
    const components = try ical.components(a, input);
    var groups: std.ArrayList(Group) = .empty;
    var by_uid: std.StringHashMapUnmanaged(usize) = .empty;
    var zones: std.StringHashMapUnmanaged(Zone) = .empty;
    var number: usize = 0;
    for (components) |component| {
        if (std.ascii.eqlIgnoreCase(component.name, "VTIMEZONE")) {
            try registerZone(a, &zones, component);
            continue;
        }
        number += 1;
        if (number > max_events) return error.TooManyEvents;
        if (!std.ascii.eqlIgnoreCase(component.name, "VEVENT")) {
            try groups.append(a, .{ .entry = .{ .number = number, .summary = component.name, .issue = "Only calendar events can be imported." } });
            continue;
        }
        const event = try Event.read(a, component);
        const uid = event.uid orelse "";
        if (uid.len == 0 or uid.len > 1024 or hasControl(uid)) {
            try groups.append(a, .{ .entry = .{ .number = number, .summary = event.summary, .issue = "The event needs a valid UID." } });
            continue;
        }
        const item = try by_uid.getOrPut(a, uid);
        if (!item.found_existing) {
            item.value_ptr.* = groups.items.len;
            try groups.append(a, .{ .entry = .{ .number = number, .summary = event.summary, .uid = uid } });
        }
        try groups.items[item.value_ptr.*].events.append(a, event);
    }
    if (groups.items.len == 0) return error.NoEvents;

    var entries: std.ArrayList(Entry) = .empty;
    var prepared_bytes: usize = 0;
    for (groups.items) |*group| {
        if (group.entry.issue == null) {
            const event: ?dav.CalDavStore.EventData = prepareGroup(a, group, &zones, prepared_bytes) catch |err| rejected: {
                group.entry.issue = switch (err) {
                    error.MissingStart => "The event needs a valid start date.",
                    error.InvalidEnd => "The event has an invalid end date or duration.",
                    error.UnsupportedTimezone => "A time zone referenced by this event is missing or unsupported.",
                    error.DuplicateInstance => "The file contains conflicting definitions for this event or occurrence.",
                    error.EventTooLarge => "The event and its time zones exceed the calendar size limit.",
                    else => return err,
                };
                break :rejected null;
            };
            group.entry.event = event;
            if (event) |item| prepared_bytes += item.ics_data.?.len;
        }
        try entries.append(a, group.entry);
    }
    return entries.items;
}

fn registerZone(a: Allocator, zones: *std.StringHashMapUnmanaged(Zone), component: ical.Component) !void {
    const tzid = try ical.componentText(a, component, "TZID") orelse return;
    const item = try zones.getOrPut(a, tzid);
    if (item.found_existing) {
        if (!std.mem.eql(u8, item.value_ptr.component.bytes, component.bytes)) item.value_ptr.definition = null;
    } else {
        item.value_ptr.* = .{
            .component = component,
            .definition = clock.Zone.parse(a, component) catch |err| switch (err) {
                error.UnsupportedTimezone, error.InvalidCalendar => null,
                else => return err,
            },
        };
    }
}

/// Index the primary event of a DAV resource with the same time interpretation
/// as webmail import. The caller still retains the original resource bytes.
pub fn indexDavEvent(a: Allocator, body: []const u8) !?dav.CalDavStore.EventData {
    const items = ical.components(a, body) catch |err| switch (err) {
        error.InvalidCalendar => return null,
        else => return err,
    };
    var zones: std.StringHashMapUnmanaged(Zone) = .empty;
    var master: ?Event = null;
    var first: ?Event = null;
    for (items) |item| {
        if (std.ascii.eqlIgnoreCase(item.name, "VTIMEZONE")) try registerZone(a, &zones, item);
        if (!std.ascii.eqlIgnoreCase(item.name, "VEVENT")) continue;
        const event = try Event.read(a, item);
        if (first == null) first = event;
        if (event.recurrence_id == null) {
            if (master != null) return null;
            master = event;
        }
    }
    const event = master orelse first orelse return null;
    const times = eventTimes(event, &zones) catch |err| switch (err) {
        error.MissingStart, error.InvalidEnd, error.UnsupportedTimezone => return null,
    };
    return eventData(event, times, null, body);
}

fn hasControl(value: []const u8) bool {
    for (value) |byte| if (byte < 32 or byte == 127) return true;
    return false;
}

fn prepareGroup(a: Allocator, group: *Group, zones: *const std.StringHashMapUnmanaged(Zone), prepared_bytes: usize) !dav.CalDavStore.EventData {
    var instances: std.StringHashMapUnmanaged(ical.Component) = .empty;
    var events: std.ArrayList(ical.Component) = .empty;
    var used_zones: std.StringHashMapUnmanaged(void) = .empty;
    const Instance = struct { event: Event, times: EventTimes };
    var master: ?Instance = null;
    var first: ?Instance = null;
    for (group.events.items) |event| {
        const key = if (event.recurrence_id) |recurrence| recurrence.value else "";
        if (event.recurrence_id != null and clock.Date.parse(key) == null) return error.DuplicateInstance;
        const item = try instances.getOrPut(a, key);
        if (item.found_existing) {
            if (!std.mem.eql(u8, item.value_ptr.bytes, event.component.bytes)) return error.DuplicateInstance;
            continue;
        }
        item.value_ptr.* = event.component;
        const instance = Instance{ .event = event, .times = try eventTimes(event, zones) };
        if (event.recurrence_id == null) master = instance;
        if (first == null) first = instance;
        try events.append(a, event.component);
        var props = ical.Properties.init(event.component);
        while (try props.next(a)) |prop| {
            const tzid = prop.param("TZID") orelse continue;
            if (zones.contains(tzid)) {
                try used_zones.put(a, tzid, {});
            } else if (std.ascii.eqlIgnoreCase(tzid, "UTC")) {
                continue;
            } else if (clock.Date.parse(prop.value)) |date| {
                // Accept older Google exports that decorate DATE values with a TZID.
                if (date.kind != .date) return error.UnsupportedTimezone;
            } else {
                return error.UnsupportedTimezone;
            }
        }
    }
    const instance = master orelse first orelse return error.MissingStart;
    const event = instance.event;
    group.entry.summary = event.summary;

    var document: std.ArrayList(u8) = .empty;
    try document.appendSlice(a, "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Mail//Calendar Import//EN\r\n");
    var ordered_zones = zones.iterator();
    while (ordered_zones.next()) |zone| {
        if (!used_zones.contains(zone.key_ptr.*)) continue;
        if (zone.value_ptr.definition == null) return error.UnsupportedTimezone;
        try appendComponent(a, &document, zone.value_ptr.component, prepared_bytes);
    }
    for (events.items) |component| try appendComponent(a, &document, component, prepared_bytes);
    try document.appendSlice(a, "END:VCALENDAR\r\n");

    return eventData(event, instance.times, try ical.resourceUid(a, group.entry.uid.?), document.items);
}

fn eventData(event: Event, times: EventTimes, uid: ?[]const u8, body: []const u8) dav.CalDavStore.EventData {
    return .{
        .uid = uid,
        .summary = event.summary,
        .description = event.description,
        .location = event.location,
        .dtstart = times.start,
        .dtend = times.end,
        .all_day = times.all_day,
        .rrule = event.rule,
        .organizer = event.organizer,
        .status = event.status,
        .ics_data = body,
    };
}

const EventTimes = struct { start: i64, end: ?i64, all_day: bool };

fn eventTimes(event: Event, zones: *const std.StringHashMapUnmanaged(Zone)) !EventTimes {
    const start = event.start orelse (if (event.status == .cancelled) event.recurrence_id else null) orelse return error.MissingStart;
    const date = clock.Date.parse(start.value) orelse return error.MissingStart;
    const start_at = try timestamp(date, start.param("TZID"), zones);
    var end_at: ?i64 = null;
    if (event.end) |end| {
        const finish = clock.Date.parse(end.value) orelse return error.InvalidEnd;
        if ((date.kind == .date) != (finish.kind == .date) or event.duration != null) return error.InvalidEnd;
        end_at = try timestamp(finish, end.param("TZID"), zones);
    } else if (event.duration) |value| {
        var interval = clock.duration(value) orelse return error.InvalidEnd;
        if (date.kind == .date) {
            // Legacy exports may express a whole all-day interval in seconds.
            if (@mod(interval.seconds, 86400) != 0) return error.InvalidEnd;
            interval.days += @divFloor(interval.seconds, 86400);
            interval.seconds = 0;
        }
        // Days and weeks are wall-clock time across daylight-saving transitions.
        const local_end = clock.Date.fromEpoch(date.epoch() + interval.days * 86400, date.kind);
        if (local_end.year > 9999) return error.InvalidEnd;
        end_at = try timestamp(local_end, start.param("TZID"), zones) + interval.seconds;
    }
    if (end_at) |end| if (end <= start_at) return error.InvalidEnd;
    return .{ .start = start_at, .end = end_at, .all_day = date.kind == .date };
}

fn appendComponent(a: Allocator, document: *std.ArrayList(u8), component: ical.Component, prepared_bytes: usize) !void {
    const limit = @min(1024 * 1024, max_prepared_bytes - prepared_bytes);
    if (document.items.len + component.bytes.len + 32 > limit) return error.EventTooLarge;
    try document.appendSlice(a, component.bytes);
    if (!std.mem.endsWith(u8, component.bytes, "\n")) try document.appendSlice(a, "\r\n");
}

fn timestamp(date: clock.Date, tzid: ?[]const u8, zones: *const std.StringHashMapUnmanaged(Zone)) !i64 {
    const name = tzid orelse return date.epoch();
    if (date.kind != .local or std.ascii.eqlIgnoreCase(name, "UTC")) return date.epoch();
    const zone = zones.get(name) orelse return error.UnsupportedTimezone;
    const rules = zone.definition orelse return error.UnsupportedTimezone;
    return date.epoch() - rules.offsetAt(date);
}
