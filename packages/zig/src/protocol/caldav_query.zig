//! VEVENT time-range filters for calendar-query reports.
const std = @import("std");
const xml = @import("ews/xml.zig");
const ical = @import("icalendar.zig");
const clock = @import("icalendar_time.zig");
const recurrence = @import("icalendar_busy.zig");
const Allocator = std.mem.Allocator;

pub const Query = struct {
    window: ?recurrence.Window = null,
    timezone: ?clock.Zone = null,
};

pub fn parse(a: Allocator, body: []const u8) !Query {
    var xml_doc = xml.Iterator{ .input = body };
    const root = (try xml_doc.next()) orelse return error.InvalidFilter;
    if (!std.mem.eql(u8, root.name, "calendar-query") or try xml_doc.next() != null) return error.InvalidFilter;
    var query: Query = .{};
    if (try root.child("filter")) |filter| try findTimeRange(filter, &query.window);
    if (query.window != null) {
        if (try root.child("timezone")) |zone| query.timezone = try parseTimezone(a, zone.content);
    }
    return query;
}

fn findTimeRange(element: xml.Element, result: *?recurrence.Window) error{ InvalidFilter, InvalidXml, UnsupportedFilter }!void {
    var children = element.children();
    while (try children.next()) |child| {
        if (!std.mem.eql(u8, child.name, "time-range")) {
            try findTimeRange(child, result);
            continue;
        }
        if (result.* != null) return error.InvalidFilter;
        const component = element.attribute("name") orelse "";
        if (!std.mem.eql(u8, element.name, "comp-filter") or !std.ascii.eqlIgnoreCase(component, "VEVENT"))
            return error.UnsupportedFilter;
        if (std.mem.trim(u8, child.content, " \t\r\n").len != 0) return error.InvalidFilter;
        const begin = child.attribute("start");
        const end = child.attribute("end");
        if (begin == null and end == null) return error.InvalidFilter;
        const window = recurrence.Window{
            .start = if (begin) |value| try utc(value) else -62135596800, // 0001-01-01
            .end = if (end) |value| try utc(value) else 253402300800, // after 9999-12-31
        };
        if (window.start >= window.end) return error.InvalidFilter;
        result.* = window;
    }
}

fn utc(value: []const u8) !i64 {
    const date = clock.Date.parse(value) orelse return error.InvalidFilter;
    if (date.kind != .utc) return error.InvalidFilter;
    return date.epoch();
}

fn parseTimezone(a: Allocator, content: []const u8) !clock.Zone {
    const text = std.mem.trim(u8, content, " \t\r\n");
    const calendar = if (std.mem.startsWith(u8, text, "<![CDATA[") and std.mem.endsWith(u8, text, "]]>"))
        std.mem.trim(u8, text[9 .. text.len - 3], " \t\r\n")
    else
        try xml.unescapeText(a, text);
    const components = ical.components(a, calendar) catch |err| switch (err) {
        error.InvalidCalendar => return error.InvalidQueryTimezone,
        else => return err,
    };
    if (components.len != 1 or !std.ascii.eqlIgnoreCase(components[0].name, "VTIMEZONE"))
        return error.InvalidQueryTimezone;
    return clock.Zone.parse(a, components[0]) catch |err| switch (err) {
        error.InvalidCalendar, error.UnsupportedTimezone => error.InvalidQueryTimezone,
        else => return err,
    };
}
