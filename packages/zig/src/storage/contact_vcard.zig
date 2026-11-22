//! Read the editable fields of a vCard and rewrite only those properties.
//! Phone numbers, photos, and client extensions stay on their original card.
const std = @import("std");

const Allocator = std.mem.Allocator;
pub const Kind = enum { contact, group };

pub const Fields = struct {
    kind: Kind = .contact,
    name: []const u8 = "",
    note: []const u8 = "",
    uid: []const u8 = "",
    emails: []const []const u8 = &.{},
    members: []const []const u8 = &.{},
};

pub const Property = struct { name: []const u8, value: []const u8 };

pub fn property(line: []const u8) ?Property {
    var quoted = false;
    for (line, 0..) |byte, i| {
        if (byte == '"') quoted = !quoted;
        if (byte != ':' or quoted) continue;
        const raw_name = line[0 .. std.mem.indexOfScalar(u8, line[0..i], ';') orelse i];
        const name = if (std.mem.lastIndexOfScalar(u8, raw_name, '.')) |dot| raw_name[dot + 1 ..] else raw_name;
        return .{ .name = name, .value = line[i + 1 ..] };
    }
    return null;
}

pub fn unfold(a: Allocator, raw: []const u8) ![]const u8 {
    var it = std.mem.splitScalar(u8, raw, '\n');
    var result: std.ArrayList(u8) = .empty;
    while (it.next()) |physical| {
        const line = std.mem.trimEnd(u8, physical, "\r");
        if (line.len == 0) continue;
        if (result.items.len > 0) {
            if (line[0] == ' ' or line[0] == '\t') {
                try result.appendSlice(a, line[1..]);
                continue;
            }
            try result.append(a, '\n');
        }
        try result.appendSlice(a, line);
    }
    return result.toOwnedSlice(a);
}

pub fn decode(a: Allocator, value: []const u8) ![]const u8 {
    if (std.mem.indexOfScalar(u8, value, '\\') == null) return value;
    var text: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < value.len) : (i += 1) {
        if (value[i] == '\\' and i + 1 < value.len) switch (value[i + 1]) {
            'n', 'N' => {
                try text.append(a, '\n');
                i += 1;
                continue;
            },
            '\\', ',', ';' => {
                try text.append(a, value[i + 1]);
                i += 1;
                continue;
            },
            else => {},
        };
        try text.append(a, value[i]);
    }
    return text.toOwnedSlice(a);
}

pub fn read(a: Allocator, raw: []const u8) !Fields {
    var result: Fields = .{};
    var emails: std.ArrayList([]const u8) = .empty;
    var members: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, try unfold(a, raw), '\n');
    while (it.next()) |line| {
        const field = property(line) orelse continue;
        if (is(field, "FN")) result.name = try decode(a, field.value) else if (is(field, "NOTE")) {
            result.note = try decode(a, field.value);
        } else if (is(field, "UID")) {
            result.uid = field.value;
        } else if (is(field, "KIND") or is(field, "X-ADDRESSBOOKSERVER-KIND")) {
            if (std.ascii.eqlIgnoreCase(field.value, "group")) result.kind = .group;
        } else if (is(field, "EMAIL")) {
            try emails.append(a, try decode(a, field.value));
        } else if (isMember(field)) {
            try members.append(a, field.value);
        }
    }
    result.emails = try emails.toOwnedSlice(a);
    result.members = try members.toOwnedSlice(a);
    return result;
}

fn is(field: Property, name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(field.name, name);
}

fn isMember(field: Property) bool {
    return is(field, "MEMBER") or is(field, "X-ADDRESSBOOKSERVER-MEMBER");
}

fn appendFolded(a: Allocator, buf: *std.ArrayList(u8), line: []const u8) !void {
    var width: usize = 75;
    var rest = line;
    while (rest.len > width) {
        var cut = width;
        while (cut > 0 and rest[cut] & 0xc0 == 0x80) cut -= 1;
        if (cut == 0) cut = width;
        try buf.appendSlice(a, rest[0..cut]);
        try buf.appendSlice(a, "\r\n ");
        rest = rest[cut..];
        width = 74;
    }
    try buf.appendSlice(a, rest);
    try buf.appendSlice(a, "\r\n");
}

pub fn appendText(a: Allocator, buf: *std.ArrayList(u8), name: []const u8, text: []const u8) !void {
    var line: std.ArrayList(u8) = .empty;
    defer line.deinit(a);
    try line.appendSlice(a, name);
    try line.append(a, ':');
    for (text, 0..) |byte, i| switch (byte) {
        '\r' => if (i + 1 == text.len or text[i + 1] != '\n') try line.appendSlice(a, "\\n"),
        '\n' => try line.appendSlice(a, "\\n"),
        '\\', ',', ';' => try line.appendSlice(a, &.{ '\\', byte }),
        else => try line.append(a, byte),
    };
    try appendFolded(a, buf, line.items);
}

pub fn apply(a: Allocator, raw: []const u8, id: []const u8, updated: Fields) ![]const u8 {
    var output: std.ArrayList(u8) = .empty;
    var existing_emails: std.StringHashMap([]const u8) = .init(a);
    defer existing_emails.deinit();
    var it = std.mem.splitScalar(u8, try unfold(a, raw), '\n');
    var version: []const u8 = "4.0";
    var uid: []const u8 = "";
    var legacy_group = false;
    var has_kind = false;
    while (it.next()) |line| {
        const field = property(line) orelse continue;
        if (is(field, "VERSION")) version = field.value;
        if (is(field, "UID") and field.value.len > 0) uid = field.value;
        if (is(field, "KIND") or is(field, "X-ADDRESSBOOKSERVER-KIND")) has_kind = true;
        if (is(field, "X-ADDRESSBOOKSERVER-KIND") or is(field, "X-ADDRESSBOOKSERVER-MEMBER")) legacy_group = true;
        if (is(field, "EMAIL") and updated.kind == .contact) try existing_emails.put(try decode(a, field.value), line);
    }
    if (uid.len == 0) uid = if (std.mem.eql(u8, version, "4.0") and isUuid(id))
        try std.fmt.allocPrint(a, "urn:uuid:{s}", .{id})
    else
        id;
    try output.appendSlice(a, "BEGIN:VCARD\r\n");
    try appendFolded(a, &output, try std.fmt.allocPrint(a, "VERSION:{s}", .{version}));
    try appendFolded(a, &output, try std.fmt.allocPrint(a, "UID:{s}", .{uid}));
    try appendText(a, &output, "FN", updated.name);
    if (updated.note.len > 0) try appendText(a, &output, "NOTE", updated.note);
    if (updated.kind == .group and !has_kind) try output.appendSlice(a, "KIND:group\r\n");
    it.index = 0;
    while (it.next()) |line| {
        const field = property(line) orelse continue;
        if (is(field, "BEGIN") or is(field, "END") or is(field, "VERSION") or is(field, "UID") or is(field, "FN") or is(field, "NOTE")) continue;
        if (updated.kind == .contact and is(field, "EMAIL")) continue;
        if (updated.kind == .group and isMember(field)) continue;
        try appendFolded(a, &output, line);
    }
    for (updated.emails) |email| {
        if (existing_emails.get(email)) |line| try appendFolded(a, &output, line) else try appendText(a, &output, "EMAIL", email);
    }
    const member_key = if (legacy_group) "X-ADDRESSBOOKSERVER-MEMBER" else "MEMBER";
    for (updated.members) |member| try appendFolded(a, &output, try std.fmt.allocPrint(a, "{s}:{s}", .{ member_key, member }));
    try output.appendSlice(a, "END:VCARD\r\n");
    return output.toOwnedSlice(a);
}

pub fn uuid(a: Allocator, random: *[16]u8) ![]const u8 {
    random[6] = (random[6] & 0x0f) | 0x40;
    random[8] = (random[8] & 0x3f) | 0x80;
    const hex = std.fmt.bytesToHex(random.*, .lower);
    return std.fmt.allocPrint(a, "{s}-{s}-{s}-{s}-{s}", .{ hex[0..8], hex[8..12], hex[12..16], hex[16..20], hex[20..32] });
}

pub fn cardIdentifier(value: []const u8) []const u8 {
    return if (std.ascii.startsWithIgnoreCase(value, "urn:uuid:")) value[9..] else value;
}

pub fn isUuid(value: []const u8) bool {
    if (value.len != 36) return false;
    for (value, 0..) |byte, index| {
        if (index == 8 or index == 13 or index == 18 or index == 23) {
            if (byte != '-') return false;
        } else if (!std.ascii.isHex(byte)) return false;
    }
    return true;
}
