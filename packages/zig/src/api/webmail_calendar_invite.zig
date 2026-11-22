//! VEVENT scheduling messages carried by email (RFC 5546 and RFC 6047).
const std = @import("std");
const submission = @import("../message/submission.zig");
const ical = @import("../protocol/icalendar.zig");
const clock = @import("../protocol/icalendar_time.zig");

const Allocator = std.mem.Allocator;
pub const max_part_bytes = 128 * 1024;
pub const max_parts = 8;
pub const max_previews = 32;

pub const Method = enum {
    request,
    cancel,

    fn parse(value: []const u8) ?Method {
        if (equal(value, "REQUEST")) return .request;
        if (equal(value, "CANCEL")) return .cancel;
        return null;
    }
};

pub const Part = struct { method: Method, body: []const u8 };

pub const WallTime = struct {
    wall: i64,
    zone: ?[]const u8,
    all_day: bool,

    pub fn read(property: ical.Property) ?WallTime {
        const date = clock.Date.parse(property.value) orelse return null;
        const zone = property.param("TZID");
        if (zone) |name| {
            if (date.kind != .local or !singleLine(name, 128)) return null;
        }
        if (property.param("VALUE")) |kind| {
            if (!equal(kind, if (date.kind == .date) "DATE" else "DATE-TIME")) return null;
        }
        return .{ .wall = date.epoch(), .zone = if (date.kind == .utc) "UTC" else zone, .all_day = date.kind == .date };
    }
};

pub const Preview = struct {
    method: Method,
    uid: []const u8,
    organizer: []const u8,
    organizer_verified: bool,
    for_mailbox: bool,
    sequence: u32,
    dtstamp: i64,
    occurrence: ?WallTime,
    this_and_future: bool,
    summary: ?[]const u8,
    location: ?[]const u8,
    start: ?WallTime,
    end: ?WallTime,
};

pub const Revision = struct {
    component: [64]u8,
    series: [64]u8,
    method: Method,
    sequence: u32,
    dtstamp: i64,
    occurrence: ?WallTime,
    this_and_future: bool,

    pub fn sameVersion(self: Revision, other: Revision) bool {
        return self.sequence == other.sequence and self.dtstamp == other.dtstamp and
            self.method == other.method and self.this_and_future == other.this_and_future and
            std.mem.eql(u8, &self.component, &other.component);
    }
};

pub const Response = enum {
    accepted,
    tentative,
    declined,

    fn partstat(self: Response) []const u8 {
        return switch (self) {
            .accepted => "ACCEPTED",
            .tentative => "TENTATIVE",
            .declined => "DECLINED",
        };
    }
};

pub const Invitation = struct {
    preview: Preview,
    components: []const ical.Component,
    component: ical.Component,
    recurrence: ?ical.Property,

    pub fn canReply(self: Invitation, attendee: []const u8) bool {
        return self.preview.method == .request and !self.preview.this_and_future and self.canTrack(attendee);
    }

    pub fn canTrack(self: Invitation, attendee: []const u8) bool {
        return self.preview.organizer_verified and self.preview.for_mailbox and
            submission.validMailbox(attendee) and !equal(attendee, self.preview.organizer);
    }

    pub fn revision(self: Invitation, a: Allocator) !Revision {
        const series = try self.keyForOccurrence(a, null);
        return .{
            .component = if (self.preview.occurrence) |occurrence| try self.keyForOccurrence(a, occurrence) else series,
            .series = series,
            .method = self.preview.method,
            .sequence = self.preview.sequence,
            .dtstamp = self.preview.dtstamp,
            .occurrence = self.preview.occurrence,
            .this_and_future = self.preview.this_and_future,
        };
    }

    pub fn key(self: Invitation, a: Allocator) ![64]u8 {
        return self.keyForOccurrence(a, self.preview.occurrence);
    }

    pub fn keyForOccurrence(self: Invitation, a: Allocator, occurrence: ?WallTime) ![64]u8 {
        const material = try std.json.Stringify.valueAlloc(a, .{
            .organizer = try std.ascii.allocLowerString(a, self.preview.organizer),
            .uid = self.preview.uid,
            .occurrence = occurrence,
        }, .{});
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(material, &digest, .{});
        return std.fmt.bytesToHex(digest, .lower);
    }

    pub fn reply(self: Invitation, a: Allocator, attendee: []const u8, response: Response, now: i64) ![]const u8 {
        if (!self.canReply(attendee)) return error.CalendarReplyUnavailable;
        var occurrence_line: ?[]const u8 = null;
        var zone: ?ical.Component = null;
        if (self.recurrence) |property| {
            const occurrence = self.preview.occurrence.?;
            if (property.param("TZID")) |name| {
                if (std.mem.indexOfScalar(u8, name, '"') != null) return error.CalendarReplyTimezone;
                for (self.components) |component| {
                    if (!equal(component.name, "VTIMEZONE")) continue;
                    const id = (try ical.componentText(a, component, "TZID")) orelse continue;
                    if (!std.mem.eql(u8, name, id)) continue;
                    if (zone != null) return error.CalendarReplyTimezone;
                    zone = component;
                }
                if (zone == null) {
                    if (clock.bundledTimezone(name)) |body| zone = .{ .name = "VTIMEZONE", .bytes = body };
                }
                if (zone) |definition| {
                    _ = clock.Zone.parse(a, definition) catch |err| switch (err) {
                        error.OutOfMemory => return err,
                        else => return error.CalendarReplyTimezone,
                    };
                    occurrence_line = try std.fmt.allocPrint(a, "RECURRENCE-ID;TZID=\"{s}\":{s}", .{ name, property.value });
                } else if (equal(name, "UTC")) {
                    occurrence_line = try std.fmt.allocPrint(a, "RECURRENCE-ID:{s}Z", .{property.value});
                } else return error.CalendarReplyTimezone;
            } else {
                occurrence_line = try std.fmt.allocPrint(a, "RECURRENCE-ID{s}:{s}", .{ if (occurrence.all_day) ";VALUE=DATE" else "", property.value });
            }
        }
        return ical.schedulingReply(a, .{
            .uid = self.preview.uid,
            .stamp = now,
            .sequence = self.preview.sequence,
            .organizer_uri = try addressUri(a, self.preview.organizer),
            .attendee_uri = try addressUri(a, attendee),
            .participation = response.partstat(),
            .occurrence_line = occurrence_line,
            .timezone = zone,
        }) catch |err| switch (err) {
            error.InvalidCalendar => error.CalendarReplyTimezone,
            else => return err,
        };
    }
};

pub fn addressUri(a: Allocator, address: []const u8) ![]const u8 {
    var encoded: std.ArrayList(u8) = .empty;
    try encoded.appendSlice(a, "mailto:");
    for (address) |byte| {
        if (std.ascii.isAlphanumeric(byte) or std.mem.indexOfScalar(u8, "-._~+@", byte) != null) {
            try encoded.append(a, byte);
        } else {
            try encoded.append(a, '%');
            try encoded.appendSlice(a, &std.fmt.bytesToHex([_]u8{byte}, .upper));
        }
    }
    return encoded.items;
}

fn equal(left: []const u8, right: []const u8) bool {
    return std.ascii.eqlIgnoreCase(left, right);
}

/// Read an exact MIME method parameter. A quoted filename or an unrelated
/// parameter containing the string "method" cannot supply a scheduling method.
pub fn mimeMethod(content_type: []const u8) ?Method {
    const separator = std.mem.indexOfScalar(u8, content_type, ';') orelse return null;
    if (!equal(std.mem.trim(u8, content_type[0..separator], " \t"), "text/calendar")) return null;
    var rest = content_type[separator + 1 ..];
    var found: ?Method = null;
    while (std.mem.trim(u8, rest, " \t").len != 0) {
        var quoted = false;
        var escaped = false;
        const end = for (rest, 0..) |byte, i| {
            if (escaped) {
                escaped = false;
            } else if (quoted and byte == '\\') {
                escaped = true;
            } else if (byte == '"') {
                quoted = !quoted;
            } else if (!quoted and byte == ';') {
                break i;
            }
        } else rest.len;
        if (quoted) return null;
        const param = rest[0..end];
        rest = rest[@min(end + 1, rest.len)..];
        const equals = std.mem.indexOfScalar(u8, param, '=') orelse return null;
        if (!equal(std.mem.trim(u8, param[0..equals], " \t"), "method")) continue;
        if (found != null) return null;
        var value = std.mem.trim(u8, param[equals + 1 ..], " \t");
        if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') value = value[1 .. value.len - 1];
        found = Method.parse(value) orelse return null;
    }
    return found;
}

pub fn invitations(a: Allocator, parts: []const Part, mailbox: []const u8, verified_author: []const u8) ![]const Invitation {
    var result: std.ArrayList(Invitation) = .empty;
    for (parts) |part| {
        const source = if (std.mem.startsWith(u8, part.body, "\xef\xbb\xbf")) part.body[3..] else part.body;
        const components = ical.components(a, source) catch |err| switch (err) {
            error.InvalidCalendar => continue,
            else => return err,
        };
        var properties = ical.Properties.init(.{ .name = "VCALENDAR", .bytes = source });
        var method: ?Method = null;
        while (try properties.next(a)) |property| {
            if (!property.named("METHOD")) continue;
            if (method != null or Method.parse(property.value) != part.method) {
                method = null;
                break;
            }
            method = part.method;
        }
        if (method == null) continue;
        for (components) |component| {
            if (result.items.len == max_previews) return result.items;
            if (!equal(component.name, "VEVENT")) continue;
            const event = readEvent(a, components, component, part.method, mailbox, verified_author) catch |err| switch (err) {
                error.InvalidInvitation => continue,
                else => return err,
            };
            try result.append(a, event);
        }
    }
    return result.items;
}

fn one(slot: *?ical.Property, value: ical.Property) !void {
    if (slot.* != null) return error.InvalidInvitation;
    slot.* = value;
}

/// Earlier Outbox rows retained the generated REPLY and stored the
/// organizer's original sequence and stamp separately in the decision.
pub fn queuedReplyRevision(a: Allocator, body: []const u8, attendee: []const u8, organizer: []const u8, key_value: []const u8, sequence: u32, original_stamp: i64) !Revision {
    const components = try ical.components(a, body);
    const method = (try ical.componentText(a, .{ .name = "VCALENDAR", .bytes = body }, "METHOD")) orelse return error.InvalidInvitation;
    if (!equal(method, "REPLY")) return error.InvalidInvitation;
    var event: ?ical.Component = null;
    for (components) |component| {
        if (!equal(component.name, "VEVENT")) continue;
        if (event != null) return error.InvalidInvitation;
        event = component;
    }
    var reply = try readEvent(a, components, event orelse return error.InvalidInvitation, null, attendee, organizer);
    if (!reply.canReply(attendee) or reply.preview.sequence != sequence) return error.InvalidInvitation;
    reply.preview.dtstamp = original_stamp;
    const revision = try reply.revision(a);
    if (!std.mem.eql(u8, &revision.component, key_value)) return error.InvalidInvitation;
    return revision;
}

fn readEvent(a: Allocator, components: []const ical.Component, component: ical.Component, method: ?Method, mailbox: []const u8, verified_author: []const u8) !Invitation {
    var props = ical.Properties.init(component);
    var uid: ?ical.Property = null;
    var organizer: ?ical.Property = null;
    var sequence: ?ical.Property = null;
    var dtstamp: ?ical.Property = null;
    var recurrence: ?ical.Property = null;
    var start: ?ical.Property = null;
    var end: ?ical.Property = null;
    var summary: ?ical.Property = null;
    var location: ?ical.Property = null;
    var for_mailbox = false;
    while (try props.next(a)) |prop| {
        if (prop.named("UID")) {
            try one(&uid, prop);
        } else if (prop.named("ORGANIZER")) {
            try one(&organizer, prop);
        } else if (prop.named("SEQUENCE")) {
            try one(&sequence, prop);
        } else if (prop.named("DTSTAMP")) {
            try one(&dtstamp, prop);
        } else if (prop.named("RECURRENCE-ID")) {
            try one(&recurrence, prop);
        } else if (prop.named("DTSTART")) {
            try one(&start, prop);
        } else if (prop.named("DTEND")) {
            try one(&end, prop);
        } else if (prop.named("SUMMARY")) {
            try one(&summary, prop);
        } else if (prop.named("LOCATION")) {
            try one(&location, prop);
        } else if (prop.named("ATTENDEE")) {
            if (try mailto(a, prop.value)) |address| for_mailbox = for_mailbox or equal(address, mailbox);
        }
    }
    const identity = try ical.unescapeText(a, (uid orelse return error.InvalidInvitation).value);
    if (!singleLine(identity, 1024)) return error.InvalidInvitation;
    const organizer_address = (try mailto(a, (organizer orelse return error.InvalidInvitation).value)) orelse return error.InvalidInvitation;
    const revision = if (sequence) |value| blk: {
        for (value.value) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidInvitation;
        break :blk std.fmt.parseInt(u31, value.value, 10) catch return error.InvalidInvitation;
    } else 0;
    const timestamp = clock.Date.parse((dtstamp orelse return error.InvalidInvitation).value) orelse return error.InvalidInvitation;
    if (timestamp.kind != .utc) return error.InvalidInvitation;
    const begins = if (start) |prop| WallTime.read(prop) orelse return error.InvalidInvitation else null;
    if (method == .request and begins == null) return error.InvalidInvitation;
    const finish = if (end) |prop| WallTime.read(prop) orelse return error.InvalidInvitation else null;
    if (finish) |stop| {
        if (begins) |begin| {
            const same_zone = std.mem.eql(u8, stop.zone orelse "", begin.zone orelse "");
            if (stop.all_day != begin.all_day or (same_zone and stop.wall <= begin.wall)) return error.InvalidInvitation;
        }
    }
    return .{ .components = components, .component = component, .recurrence = recurrence, .preview = .{
        .method = method orelse .request,
        .uid = identity,
        .organizer = organizer_address,
        .organizer_verified = equal(verified_author, organizer_address),
        .for_mailbox = for_mailbox,
        .sequence = revision,
        .dtstamp = timestamp.epoch(),
        .occurrence = if (recurrence) |prop| WallTime.read(prop) orelse return error.InvalidInvitation else null,
        .this_and_future = if (recurrence) |prop| equal(prop.param("RANGE") orelse "", "THISANDFUTURE") else false,
        .summary = try displayText(a, summary, 512),
        .location = try displayText(a, location, 1024),
        .start = begins,
        .end = finish,
    } };
}

fn singleLine(value: []const u8, limit: usize) bool {
    if (value.len == 0 or value.len > limit) return false;
    for (value) |byte| if (byte < 32 or byte == 127) return false;
    return true;
}

fn displayText(a: Allocator, property: ?ical.Property, limit: usize) !?[]const u8 {
    const value = try ical.unescapeText(a, (property orelse return null).value);
    return if (value.len != 0 and value.len <= limit) value else null;
}

fn mailto(a: Allocator, value: []const u8) !?[]const u8 {
    if (!std.ascii.startsWithIgnoreCase(value, "mailto:")) return null;
    const address = value[7..];
    if (address.len > 3 * 254 or std.mem.indexOfAny(u8, address, "?#") != null) return null;
    const decoded = if (std.mem.indexOfScalar(u8, address, '%') != null)
        std.Uri.percentDecodeBackwards(try a.alloc(u8, address.len), address)
    else
        address;
    return if (decoded.len <= 254 and std.unicode.utf8ValidateSlice(decoded) and submission.validMailbox(decoded)) decoded else null;
}
