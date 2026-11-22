const std = @import("std");
const icalendar = @import("../protocol/icalendar.zig");
const calendar_import = @import("webmail_calendar_import.zig");
const dav = @import("../storage/caldav_store.zig");
const io_compat = @import("../core/io_compat.zig");
const time_compat = @import("../core/time_compat.zig");
const Allocator = std.mem.Allocator;

pub const Create = struct {
    calendarId: u64,
    summary: []const u8,
    description: ?[]const u8 = null,
    location: ?[]const u8 = null,
    time: icalendar.EventTiming,
};

pub const Edit = icalendar.EventEdit;

/// Replace a single existing calendar resource, preserving its logical UID
/// and its DAV path. Every exception must belong to the same master.
pub fn prepareReplacement(a: Allocator, stored: dav.CalendarEventDetail, body: []const u8) !dav.CalDavStore.EventData {
    var uid: ?[]const u8 = null;
    for (try icalendar.components(a, stored.ics_data)) |item| {
        if (!std.ascii.eqlIgnoreCase(item.name, "VEVENT")) continue;
        if (try icalendar.componentText(a, item, "RECURRENCE-ID") != null) continue;
        uid = try icalendar.componentText(a, item, "UID");
        break;
    }
    const expected = uid orelse return error.InvalidCalendar;
    return prepareDocument(a, body, expected);
}

pub fn prepareDocument(a: Allocator, body: []const u8, expected_uid: ?[]const u8) !dav.CalDavStore.EventData {
    if (!std.unicode.utf8ValidateSlice(body)) return error.InvalidCalendar;

    var count: usize = 0;
    var master = false;
    var uid = expected_uid;
    var keys: std.StringHashMapUnmanaged(void) = .empty;
    defer keys.deinit(a);
    for (try icalendar.components(a, body)) |item| {
        if (std.ascii.eqlIgnoreCase(item.name, "VTIMEZONE")) continue;
        if (!std.ascii.eqlIgnoreCase(item.name, "VEVENT")) return error.InvalidCalendar;
        count += 1;
        if (count > 1000) return error.EventTooLarge;
        const supplied = try icalendar.componentText(a, item, "UID") orelse return error.InvalidCalendar;
        if (supplied.len == 0 or supplied.len > 1024) return error.InvalidCalendar;
        for (supplied) |byte| if (byte < 32 or byte == 127) return error.InvalidCalendar;
        if (uid) |expected| {
            if (!std.mem.eql(u8, expected, supplied)) return error.InvalidCalendar;
        } else uid = supplied;
        if (try icalendar.componentText(a, item, "RECURRENCE-ID")) |key| {
            const slot = try keys.getOrPut(a, key);
            if (slot.found_existing) return error.InvalidCalendar;
        } else {
            if (master) return error.InvalidCalendar;
            master = true;
        }
    }
    if (!master) return error.InvalidCalendar;
    var event = (try calendar_import.indexDavEvent(a, body)) orelse return error.InvalidCalendar;
    if (expected_uid == null) {
        try validateFields(.{
            .summary = event.summary,
            .description = event.description,
            .location = event.location,
            .time = .{ .start = event.dtstart, .end = event.dtend, .allDay = event.all_day },
        });
        event.uid = try icalendar.resourceUid(a, uid orelse return error.InvalidCalendar);
    }
    return event;
}

pub fn prepareCreate(a: Allocator, input: Create) !dav.CalDavStore.EventData {
    try validateFields(.{ .summary = input.summary, .description = input.description, .location = input.location, .time = input.time });
    var entropy: [16]u8 = undefined;
    io_compat.randomBytes(&entropy);
    const uid = try a.dupe(u8, &std.fmt.bytesToHex(entropy, .lower));
    var data = dav.CalDavStore.EventData{
        .uid = uid,
        .summary = input.summary,
        .description = nonempty(input.description),
        .location = nonempty(input.location),
        .dtstart = input.time.start,
        .dtend = input.time.end,
        .all_day = input.time.allDay,
    };
    data.ics_data = try eventDocument(a, data, time_compat.timestamp());
    return data;
}

pub fn prepareEdit(a: Allocator, stored: dav.CalendarEventDetail, edit: Edit) !dav.CalDavStore.EventData {
    try validateFields(edit);
    if (edit.summary == null and edit.description == null and edit.location == null and edit.time == null) return error.EmptyEventEdit;
    const previous = stored.event;
    var data = dav.CalDavStore.EventData{
        .uid = previous.uid,
        .summary = previous.summary,
        .description = stored.description,
        .location = previous.location,
        .dtstart = previous.start,
        .dtend = previous.end,
        .all_day = previous.all_day,
        .rrule = previous.recurrence_rule,
        .organizer = stored.organizer,
        .status = previous.status,
    };
    const raw = if (stored.ics_data.len == 0) try eventDocument(a, data, stored.modified_at) else stored.ics_data;
    data.ics_data = try icalendar.editPrimaryEvent(a, raw, edit);
    if (edit.summary) |value| data.summary = value;
    if (edit.description) |value| data.description = nonempty(value);
    if (edit.location) |value| data.location = nonempty(value);
    if (edit.time) |time| {
        data.dtstart = time.start;
        data.dtend = time.end;
        data.all_day = time.allDay;
    }
    return data;
}

fn validateFields(edit: Edit) !void {
    if (edit.summary) |value| {
        if (std.mem.trim(u8, value, " \t\r\n").len == 0) return error.InvalidEventTitle;
        try validateText(value, 512);
    }
    if (edit.description) |value| try validateText(value, 64 * 1024);
    if (edit.location) |value| try validateText(value, 1024);
    if (edit.time) |time| {
        try validateInstant(time.start, time.allDay);
        if (time.end) |end| {
            try validateInstant(end, time.allDay);
            if (end <= time.start) return error.InvalidEventTime;
        }
    }
}

fn validateText(text: []const u8, limit: usize) !void {
    if (text.len > limit or !std.unicode.utf8ValidateSlice(text)) return error.InvalidEventText;
    for (text) |byte| {
        if ((byte < 32 and byte != '\t' and byte != '\r' and byte != '\n') or byte == 127) return error.InvalidEventText;
    }
}

fn validateInstant(timestamp: i64, all_day: bool) !void {
    if (timestamp < -62135596800 or timestamp >= 253402300800 or (all_day and @mod(timestamp, 86400) != 0)) return error.InvalidEventTime;
}

fn nonempty(value: ?[]const u8) ?[]const u8 {
    if (value) |text| {
        if (text.len > 0) return text;
    }
    return null;
}

fn eventDocument(a: Allocator, data: dav.CalDavStore.EventData, stamp: i64) ![]const u8 {
    var document = try icalendar.Export.init(a, "Calendar");
    try document.addEvent(.{
        .uid = data.uid.?,
        .modified_at = stamp,
        .summary = data.summary,
        .description = data.description,
        .location = data.location,
        .organizer = data.organizer,
        .start = data.dtstart,
        .end = data.dtend,
        .all_day = data.all_day,
        .recurrence = data.rrule,
        .status = switch (data.status) {
            .tentative => "TENTATIVE",
            .confirmed => "CONFIRMED",
            .cancelled => "CANCELLED",
        },
    });
    return document.finish();
}
