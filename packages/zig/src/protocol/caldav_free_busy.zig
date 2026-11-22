//! CalDAV free-busy-query request and VFREEBUSY response.
const std = @import("std");
const xml = @import("ews/xml.zig");
const busy = @import("icalendar_busy.zig");
const Date = @import("icalendar_time.zig").Date;
const io_compat = @import("../core/io_compat.zig");

const namespace = "urn:ietf:params:xml:ns:caldav";

pub fn parse(body: []const u8) !busy.Window {
    var document = xml.Iterator{ .input = body };
    const root = (try document.next()) orelse return error.InvalidReport;
    if (!matches(root, null, "free-busy-query") or try document.next() != null) return error.InvalidReport;
    var children = root.children();
    const range = (try children.next()) orelse return error.InvalidReport;
    if (!matches(range, root, "time-range") or try children.next() != null or
        std.mem.trim(u8, range.content, " \t\r\n").len != 0) return error.InvalidReport;
    const start = Date.parse(range.attribute("start") orelse "") orelse return error.InvalidReport;
    const end = Date.parse(range.attribute("end") orelse "") orelse return error.InvalidReport;
    if (start.kind != .utc or end.kind != .utc) return error.InvalidReport;
    return .{ .start = start.epoch(), .end = end.epoch() };
}

fn matches(element: xml.Element, parent: ?xml.Element, name: []const u8) bool {
    if (!std.mem.eql(u8, element.name, name)) return false;
    var buf: [128]u8 = undefined;
    const key = if (std.mem.indexOfScalar(u8, element.qualified_name, ':')) |colon|
        std.fmt.bufPrint(&buf, "xmlns:{s}", .{element.qualified_name[0..colon]}) catch return false
    else
        "xmlns";
    const uri = element.attribute(key) orelse if (parent) |root| root.attribute(key) orelse return false else return false;
    return std.mem.eql(u8, uri, namespace);
}

pub fn render(a: std.mem.Allocator, window: busy.Window, periods: []const busy.Period, now: i64) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var random: [16]u8 = undefined;
    io_compat.randomBytes(&random);
    var start: [16]u8 = undefined;
    var end: [16]u8 = undefined;
    var stamp: [16]u8 = undefined;
    try out.print(a, "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Mail//CalDAV//EN\r\n" ++
        "BEGIN:VFREEBUSY\r\nUID:{s}@mail\r\nDTSTAMP:{s}\r\nDTSTART:{s}\r\nDTEND:{s}\r\n", .{
        std.fmt.bytesToHex(random, .lower), try utc(&stamp, now), try utc(&start, window.start), try utc(&end, window.end),
    });
    for (periods) |period| {
        try out.print(a, "FREEBUSY;FBTYPE={s}:{s}/{s}\r\n", .{ period.kind.label(), try utc(&start, period.start), try utc(&end, period.end) });
    }
    try out.appendSlice(a, "END:VFREEBUSY\r\nEND:VCALENDAR\r\n");
    return out.items;
}

fn utc(buf: *[16]u8, epoch: i64) ![]const u8 {
    const date = Date.fromEpoch(epoch, .utc);
    if (date.year < 1 or date.year > 9999) return error.InvalidRange;
    const year: u16 = @intCast(date.year);
    const seconds: u32 = @intCast(date.seconds);
    return std.fmt.bufPrint(buf, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
        year, date.month, date.day, seconds / 3600, seconds / 60 % 60, seconds % 60,
    });
}
