//! iCalendar component parsing and portable calendar serialization (RFC 5545).
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Component = struct {
    name: []const u8,
    bytes: []const u8,
};

const ContentLine = struct {
    start: usize,
    text: []const u8,
};

const Lines = struct {
    source: []const u8,
    offset: usize = 0,

    fn physical(self: *const Lines) []const u8 {
        const rest = self.source[self.offset..];
        return rest[0 .. std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len];
    }

    fn take(self: *Lines) []const u8 {
        const line = self.physical();
        self.offset = @min(self.source.len, self.offset + line.len + 1);
        return std.mem.trimEnd(u8, line, "\r");
    }

    fn next(self: *Lines, a: Allocator) !?ContentLine {
        if (self.offset == self.source.len) return null;
        const start = self.offset;
        const first = self.take();
        if (std.mem.indexOfScalar(u8, first, '\r') != null) return error.InvalidCalendar;
        if (first.len > 0 and (first[0] == ' ' or first[0] == '\t')) return error.InvalidCalendar;
        var unfolded: std.ArrayList(u8) = .empty;
        while (self.offset < self.source.len) {
            const following = self.physical();
            if (following.len == 0 or (following[0] != ' ' and following[0] != '\t')) break;
            if (unfolded.items.len == 0) try unfolded.appendSlice(a, first);
            const continuation = self.take()[1..];
            if (std.mem.indexOfScalar(u8, continuation, '\r') != null) return error.InvalidCalendar;
            try unfolded.appendSlice(a, continuation);
        }
        return .{ .start = start, .text = if (unfolded.items.len > 0) unfolded.items else first };
    }
};

pub const Property = struct {
    name: []const u8,
    params: []const u8,
    value: []const u8,

    pub fn parse(line: []const u8) ?Property {
        var quoted = false;
        var params: ?usize = null;
        for (line, 0..) |byte, index| {
            if (byte == '"') quoted = !quoted;
            if (quoted) continue;
            if (byte == ';' and params == null) params = index;
            if (byte != ':') continue;
            const split = params orelse index;
            if (split == 0) return null;
            return .{
                .name = line[0..split],
                .params = if (params != null) line[split + 1 .. index] else "",
                .value = line[index + 1 ..],
            };
        }
        return null;
    }

    pub fn named(self: Property, name: []const u8) bool {
        return std.ascii.eqlIgnoreCase(self.name, name);
    }

    pub fn param(self: Property, name: []const u8) ?[]const u8 {
        var rest = self.params;
        while (rest.len > 0) {
            var quoted = false;
            var end: usize = rest.len;
            for (rest, 0..) |byte, index| {
                if (byte == '"') quoted = !quoted;
                if (!quoted and byte == ';') {
                    end = index;
                    break;
                }
            }
            const pair = rest[0..end];
            rest = if (end == rest.len) "" else rest[end + 1 ..];
            const equals = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
            if (std.ascii.eqlIgnoreCase(pair[0..equals], name)) return std.mem.trim(u8, pair[equals + 1 ..], "\"");
        }
        return null;
    }
};

/// The arena owns the component list and unfolded property values. Component
/// bodies borrow the original input so nested alarms, overrides, and unknown
/// provider properties survive serialization.
pub fn components(a: Allocator, input: []const u8) ![]const Component {
    const source = if (std.mem.startsWith(u8, input, "\xef\xbb\xbf")) input[3..] else input;
    if (!std.unicode.utf8ValidateSlice(source) or std.mem.indexOfScalar(u8, source, 0) != null) return error.InvalidCalendar;
    return childComponents(a, .{ .name = "VCALENDAR", .bytes = source });
}

pub fn childComponents(a: Allocator, component: Component) ![]const Component {
    const source = component.bytes;
    var lines = Lines{ .source = source };
    const opening = try lines.next(a) orelse return error.InvalidCalendar;
    const first = Property.parse(opening.text) orelse return error.InvalidCalendar;
    if (!first.named("BEGIN") or !std.ascii.eqlIgnoreCase(first.value, component.name)) return error.InvalidCalendar;
    var stack: [16][]const u8 = undefined;
    stack[0] = component.name;
    var depth: usize = 1;
    var component_start: usize = 0;
    var result: std.ArrayList(Component) = .empty;
    while (try lines.next(a)) |line| {
        if (line.text.len == 0) continue;
        const prop = Property.parse(line.text) orelse return error.InvalidCalendar;
        if (prop.named("BEGIN")) {
            if (depth == stack.len or prop.value.len == 0) return error.InvalidCalendar;
            if (depth == 1) component_start = line.start;
            stack[depth] = prop.value;
            depth += 1;
        } else if (prop.named("END")) {
            depth -= 1;
            if (!std.ascii.eqlIgnoreCase(prop.value, stack[depth])) return error.InvalidCalendar;
            if (depth == 0) {
                if (std.mem.trim(u8, source[lines.offset..], " \t\r\n").len != 0) return error.InvalidCalendar;
                return result.items;
            }
            if (depth == 1) try result.append(a, .{ .name = stack[1], .bytes = source[component_start..lines.offset] });
        }
    }
    return error.InvalidCalendar;
}

pub const Properties = struct {
    lines: Lines,
    depth: usize = 0,

    pub fn init(component: Component) Properties {
        return .{ .lines = .{ .source = component.bytes } };
    }

    /// Properties of this component, excluding any nested subcomponents.
    pub fn next(self: *Properties, a: Allocator) !?Property {
        while (try self.lines.next(a)) |line| {
            const prop = Property.parse(line.text) orelse continue;
            if (prop.named("BEGIN")) {
                self.depth += 1;
            } else if (prop.named("END")) {
                self.depth -= 1;
            } else if (self.depth == 1) {
                return prop;
            }
        }
        return null;
    }
};

pub fn unescapeText(a: Allocator, value: []const u8) ![]const u8 {
    if (std.mem.indexOfScalar(u8, value, '\\') == null) return value;
    var result: std.ArrayList(u8) = .empty;
    var index: usize = 0;
    while (index < value.len) : (index += 1) {
        const byte = value[index];
        if (byte == '\\' and index + 1 < value.len) {
            const escaped = value[index + 1];
            switch (escaped) {
                'n', 'N' => try result.append(a, '\n'),
                '\\', ';', ',' => try result.append(a, escaped),
                else => {
                    try result.append(a, byte);
                    continue;
                },
            }
            index += 1;
        } else try result.append(a, byte);
    }
    return result.items;
}

pub fn componentText(a: Allocator, component: Component, name: []const u8) !?[]const u8 {
    var props = Properties.init(component);
    while (try props.next(a)) |prop| if (prop.named(name)) return try unescapeText(a, prop.value);
    return null;
}

pub fn resourceUid(a: Allocator, uid: []const u8) ![]const u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(uid, &digest, .{});
    return a.dupe(u8, &std.fmt.bytesToHex(digest, .lower));
}

pub const EventTiming = struct { start: i64, end: ?i64 = null, allDay: bool = false };

/// Detect recurrence properties directly on a VEVENT. Time zone observances
/// and alarms have their own rules and do not make an event recurring.
pub fn hasRecurrence(body: []const u8) bool {
    var lines = Lines{ .source = body };
    var depth: usize = 0;
    var event_depth: ?usize = null;
    while (lines.offset < body.len) {
        const line = lines.take();
        if (line.len == 0 or line[0] == ' ' or line[0] == '\t') continue;
        const start = line[0 .. std.mem.indexOfAny(u8, line, ":;") orelse continue];
        if (std.ascii.eqlIgnoreCase(start, "BEGIN")) {
            depth += 1;
            if (std.ascii.eqlIgnoreCase(line, "BEGIN:VEVENT")) event_depth = depth;
        } else if (std.ascii.eqlIgnoreCase(start, "END")) {
            if (event_depth == depth) event_depth = null;
            depth -|= 1;
        } else if (event_depth == depth) {
            for ([_][]const u8{ "RRULE", "RDATE", "EXDATE", "RECURRENCE-ID" }) |property|
                if (std.ascii.eqlIgnoreCase(start, property)) return true;
        }
    }
    return false;
}

pub const EventEdit = struct {
    summary: ?[]const u8 = null,
    description: ?[]const u8 = null,
    location: ?[]const u8 = null,
    time: ?EventTiming = null,
};

/// Change selected properties on the primary event. The other content lines,
/// including recurrence exceptions, alarms and timezone definitions, keep
/// their original bytes and folding.
pub fn editPrimaryEvent(a: Allocator, body: []const u8, edit: EventEdit) ![]const u8 {
    const items = try components(a, body);
    var primary: ?Component = null;
    var event_count: usize = 0;
    for (items) |item| {
        if (!std.ascii.eqlIgnoreCase(item.name, "VEVENT")) continue;
        event_count += 1;
        if (try componentText(a, item, "RECURRENCE-ID") != null) continue;
        if (primary != null) return error.NoPrimaryEvent;
        primary = item;
    }
    const event = primary orelse return error.NoPrimaryEvent;
    if (edit.time != null and event_count != 1) return error.RecurringTimeEdit;
    const start = @intFromPtr(event.bytes.ptr) - @intFromPtr(body.ptr);
    var output = Export{ .allocator = a };
    try output.append(&output.events, body[0..start]);

    var lines = Lines{ .source = event.bytes };
    var depth: usize = 0;
    while (try lines.next(a)) |line| {
        if (Property.parse(line.text)) |prop| {
            if (prop.named("BEGIN")) {
                depth += 1;
            } else if (prop.named("END")) {
                if (depth == 1) try appendEventChanges(&output, edit);
                depth -= 1;
            } else if (depth == 1) {
                if ((edit.summary != null and prop.named("SUMMARY")) or
                    (edit.description != null and prop.named("DESCRIPTION")) or
                    (edit.location != null and prop.named("LOCATION"))) continue;
                if (edit.time != null) {
                    if (prop.named("RRULE") or prop.named("RDATE") or prop.named("EXDATE")) return error.RecurringTimeEdit;
                    if (prop.named("DTSTART") or prop.named("DTEND") or prop.named("DURATION")) continue;
                }
            }
        }
        try output.append(&output.events, event.bytes[line.start..lines.offset]);
    }
    try output.append(&output.events, body[start + event.bytes.len ..]);
    return output.events.items;
}

fn appendEventChanges(output: *Export, edit: EventEdit) !void {
    if (edit.summary) |value| try output.textProperty(&output.events, "SUMMARY", value);
    if (edit.description) |value| {
        if (value.len > 0) try output.textProperty(&output.events, "DESCRIPTION", value);
    }
    if (edit.location) |value| {
        if (value.len > 0) try output.textProperty(&output.events, "LOCATION", value);
    }
    if (edit.time) |time| {
        try output.dateProperty("DTSTART", time.start, time.allDay);
        if (time.end) |end| try output.dateProperty("DTEND", end, time.allDay);
    }
}

pub const max_export_bytes = 16 * 1024 * 1024;

pub const SchedulingReply = struct {
    uid: []const u8,
    stamp: i64,
    sequence: u32,
    organizer_uri: []const u8,
    attendee_uri: []const u8,
    participation: []const u8,
    occurrence_line: ?[]const u8 = null,
    timezone: ?Component = null,
};

pub fn schedulingReply(a: Allocator, reply: SchedulingReply) ![]const u8 {
    var output: Export = .{ .allocator = a };
    try output.headers.appendSlice(a, "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Mail//Calendar RSVP//EN\r\nMETHOD:REPLY\r\n");
    if (reply.timezone) |zone| try addSchedulingTimezone(&output, zone);
    try output.events.appendSlice(a, "BEGIN:VEVENT\r\n");
    try output.textProperty(&output.events, "UID", reply.uid);
    try output.dateProperty("DTSTAMP", reply.stamp, false);
    try output.events.print(a, "SEQUENCE:{d}\r\n", .{reply.sequence});
    try output.foldedLine(&output.events, try std.fmt.allocPrint(a, "ORGANIZER:{s}", .{reply.organizer_uri}));
    try output.foldedLine(&output.events, try std.fmt.allocPrint(a, "ATTENDEE;PARTSTAT={s}:{s}", .{ reply.participation, reply.attendee_uri }));
    if (reply.occurrence_line) |line| try output.foldedLine(&output.events, line);
    try output.events.appendSlice(a, "END:VEVENT\r\n");
    return output.finish();
}

pub fn addSchedulingTimezone(output: *Export, zone: Component) !void {
    const a = output.allocator;
    const id = (try componentText(a, zone, "TZID")) orelse return error.InvalidCalendar;
    try output.headers.appendSlice(a, "BEGIN:VTIMEZONE\r\n");
    try output.textProperty(&output.headers, "TZID", id);
    // Scheduling consumers need the time rules, without organizer URLs
    // or extension components.
    for (try childComponents(a, zone)) |child| {
        const kind: []const u8 = if (std.ascii.eqlIgnoreCase(child.name, "STANDARD"))
            "STANDARD"
        else if (std.ascii.eqlIgnoreCase(child.name, "DAYLIGHT"))
            "DAYLIGHT"
        else
            continue;
        try output.headers.print(a, "BEGIN:{s}\r\n", .{kind});
        var properties = Properties.init(child);
        const fields = [_][]const u8{ "DTSTART", "TZOFFSETFROM", "TZOFFSETTO", "RRULE", "RDATE" };
        var seen: [fields.len]bool = @splat(false);
        while (try properties.next(a)) |property| {
            for (fields, 0..) |name, index| {
                if (!property.named(name)) continue;
                if (seen[index] and !property.named("RDATE")) return error.InvalidCalendar;
                seen[index] = true;
                try output.foldedLine(&output.headers, try std.fmt.allocPrint(a, "{s}:{s}", .{ name, property.value }));
                break;
            }
        }
        try output.headers.print(a, "END:{s}\r\n", .{kind});
    }
    try output.headers.appendSlice(a, "END:VTIMEZONE\r\n");
}

pub const Export = struct {
    allocator: Allocator,
    zones: std.StringHashMapUnmanaged([]const u8) = .empty,
    headers: std.ArrayList(u8) = .empty,
    events: std.ArrayList(u8) = .empty,

    pub fn init(a: Allocator, name: []const u8) !Export {
        var result = Export{ .allocator = a };
        try result.append(&result.headers, "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Mail//Calendar Export//EN\r\nCALSCALE:GREGORIAN\r\n");
        try result.textProperty(&result.headers, "X-WR-CALNAME", name);
        return result;
    }

    pub fn addDocument(self: *Export, data: []const u8) !void {
        var scratch = std.heap.ArenaAllocator.init(self.allocator);
        defer scratch.deinit();
        const a = scratch.allocator();
        for (try components(a, data)) |component| {
            if (!std.ascii.eqlIgnoreCase(component.name, "VTIMEZONE")) {
                try self.addComponent(&self.events, a, component);
                continue;
            }
            var props = Properties.init(component);
            const tzid = while (try props.next(a)) |prop| {
                if (prop.named("TZID") and prop.value.len > 0) break prop.value;
            } else return error.InvalidCalendar;
            const zone = try self.zones.getOrPut(self.allocator, tzid);
            if (zone.found_existing) {
                if (!try equalContent(a, zone.value_ptr.*, component.bytes)) return error.ConflictingTimezone;
            } else {
                zone.key_ptr.* = try self.allocator.dupe(u8, tzid);
                zone.value_ptr.* = try self.allocator.dupe(u8, component.bytes);
                try self.addComponent(&self.headers, a, component);
            }
        }
    }

    fn equalContent(a: Allocator, lhs: []const u8, rhs: []const u8) !bool {
        if (std.mem.eql(u8, lhs, rhs)) return true;
        var left = Lines{ .source = lhs };
        var right = Lines{ .source = rhs };
        while (try left.next(a)) |line| {
            const other = try right.next(a) orelse return false;
            if (!std.mem.eql(u8, line.text, other.text)) return false;
        }
        return try right.next(a) == null;
    }

    pub fn addComponent(self: *Export, target: *std.ArrayList(u8), a: Allocator, component: Component) !void {
        var lines = Lines{ .source = component.bytes };
        while (try lines.next(a)) |line| {
            if (line.text.len > 0) try self.foldedLine(target, line.text);
        }
    }

    pub const Event = struct {
        uid: []const u8,
        modified_at: i64,
        summary: []const u8,
        description: ?[]const u8,
        location: ?[]const u8,
        organizer: ?[]const u8,
        start: i64,
        end: ?i64,
        all_day: bool,
        recurrence: ?[]const u8,
        recurrence_id: ?i64 = null,
        status: []const u8,
    };

    /// Serialize older events created by integrations that only stored fields.
    pub fn addEvent(self: *Export, event: Event) !void {
        try self.append(&self.events, "BEGIN:VEVENT\r\n");
        try self.textProperty(&self.events, "UID", event.uid);
        try self.dateProperty("DTSTAMP", event.modified_at, false);
        try self.dateProperty("DTSTART", event.start, event.all_day);
        if (event.end) |end| try self.dateProperty("DTEND", end, event.all_day);
        if (event.recurrence_id) |id| try self.dateProperty("RECURRENCE-ID", id, event.all_day);
        try self.textProperty(&self.events, "SUMMARY", event.summary);
        if (event.description) |value| try self.textProperty(&self.events, "DESCRIPTION", value);
        if (event.location) |value| try self.textProperty(&self.events, "LOCATION", value);
        if (event.organizer) |value| {
            if (std.mem.indexOfAny(u8, value, "\r\n") == null) {
                const address = try std.fmt.allocPrint(self.allocator, "ORGANIZER:mailto:{s}", .{value});
                try self.foldedLine(&self.events, address);
            }
        }
        if (event.recurrence) |value| {
            if (std.mem.indexOfAny(u8, value, "\r\n") == null) {
                const recurrence = try std.fmt.allocPrint(self.allocator, "RRULE:{s}", .{value});
                try self.foldedLine(&self.events, recurrence);
            }
        }
        try self.append(&self.events, "STATUS:");
        try self.append(&self.events, event.status);
        try self.append(&self.events, "\r\nEND:VEVENT\r\n");
    }

    pub fn finish(self: *Export) ![]const u8 {
        try self.append(&self.events, "END:VCALENDAR\r\n");
        try self.headers.appendSlice(self.allocator, self.events.items);
        return self.headers.items;
    }

    fn dateProperty(self: *Export, property: []const u8, timestamp: i64, all_day: bool) !void {
        if (timestamp < -62135596800 or timestamp >= 253402300800) return error.InvalidCalendar;
        const days = @divFloor(timestamp, 86400) + 719468;
        const era = @divFloor(days, 146097);
        const era_day = days - era * 146097;
        const era_year = @divFloor(era_day - @divFloor(era_day, 1460) + @divFloor(era_day, 36524) - @divFloor(era_day, 146096), 365);
        const year_day = era_day - (365 * era_year + @divFloor(era_year, 4) - @divFloor(era_year, 100));
        const march_month = @divFloor(5 * year_day + 2, 153);
        const month = march_month + @as(i64, if (march_month < 10) 3 else -9);
        const month_day = year_day - @divFloor(153 * march_month + 2, 5) + 1;
        const year: u16 = @intCast(era_year + era * 400 + @intFromBool(month <= 2));
        const month_number: u8 = @intCast(month);
        const day_number: u8 = @intCast(month_day);
        const day_seconds: u32 = @intCast(@mod(timestamp, 86400));
        var buf: [64]u8 = undefined;
        const value = if (all_day)
            try std.fmt.bufPrint(&buf, "{s};VALUE=DATE:{d:0>4}{d:0>2}{d:0>2}", .{ property, year, month_number, day_number })
        else
            try std.fmt.bufPrint(&buf, "{s}:{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
                property, year, month_number, day_number, day_seconds / 3600, day_seconds / 60 % 60, day_seconds % 60,
            });
        try self.foldedLine(&self.events, value);
    }

    fn textProperty(self: *Export, target: *std.ArrayList(u8), property: []const u8, value: []const u8) !void {
        var line: std.ArrayList(u8) = .empty;
        try line.print(self.allocator, "{s}:", .{property});
        for (value) |byte| switch (byte) {
            '\\', ';', ',' => try line.appendSlice(self.allocator, &.{ '\\', byte }),
            '\r' => {},
            '\n' => try line.appendSlice(self.allocator, "\\n"),
            else => try line.append(self.allocator, byte),
        };
        try self.foldedLine(target, line.items);
    }

    pub fn foldedLine(self: *Export, target: *std.ArrayList(u8), line: []const u8) !void {
        var remaining = line;
        var width: usize = 75;
        while (remaining.len > width) {
            var end = width;
            // Keep UTF-8 code points intact in each physical content line.
            while (end > 0 and remaining[end] & 0xc0 == 0x80) end -= 1;
            if (end == 0) return error.InvalidCalendar;
            try self.append(target, remaining[0..end]);
            try self.append(target, "\r\n ");
            remaining = remaining[end..];
            width = 74;
        }
        try self.append(target, remaining);
        try self.append(target, "\r\n");
    }

    fn append(self: *Export, target: *std.ArrayList(u8), bytes: []const u8) !void {
        if (self.headers.items.len + self.events.items.len + bytes.len > max_export_bytes) return error.CalendarExportTooLarge;
        try target.appendSlice(self.allocator, bytes);
    }
};
