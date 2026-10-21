//! Extract one unambiguous author for authenticated SMTP submission.
//! Inbound messages and forwarding keep their existing author semantics.
const std = @import("std");

pub fn validMailbox(value: []const u8) bool {
    const at = std.mem.indexOfScalar(u8, value, '@') orelse return false;
    if (at == 0 or at + 1 == value.len) return false;
    for (value, 0..) |byte, index| {
        if (byte <= 32 or byte == 127 or std.mem.indexOfScalar(u8, "<>\"\\,():;", byte) != null) return false;
        if (byte == '@' and index != at) return false;
    }
    return true;
}

fn mailbox(value: []const u8) ![]const u8 {
    const trimmed = std.mem.trim(u8, value, " \t\r");
    if (std.mem.indexOfScalar(u8, trimmed, '<')) |open| {
        const close = std.mem.indexOfScalarPos(u8, trimmed, open + 1, '>') orelse return error.InvalidFrom;
        if (std.mem.trim(u8, trimmed[close + 1 ..], " \t").len != 0) return error.InvalidFrom;
        const display = std.mem.trim(u8, trimmed[0..open], " \t");
        // Quotes in a display name do not delimit additional mailboxes.
        var quoted = false;
        var escaped = false;
        for (display) |byte| {
            if (escaped) {
                escaped = false;
                continue;
            }
            if (quoted and byte == '\\') {
                escaped = true;
                continue;
            }
            if (byte == '"') {
                quoted = !quoted;
                continue;
            }
            if (!quoted and std.mem.indexOfScalar(u8, ",:;<>@()", byte) != null) return error.InvalidFrom;
        }
        if (quoted or escaped) return error.InvalidFrom;
        const address = std.mem.trim(u8, trimmed[open + 1 .. close], " \t");
        if (!validMailbox(address)) return error.InvalidFrom;
        return address;
    }
    if (!validMailbox(trimmed)) return error.InvalidFrom;
    return trimmed;
}

/// Caller owns a returned author. Null means there was no From header.
pub fn author(allocator: std.mem.Allocator, message: []const u8) !?[]u8 {
    var value: std.ArrayList(u8) = .empty;
    defer value.deinit(allocator);
    var found = false;
    var collecting = false;
    var lines = std.mem.splitScalar(u8, message, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) break;
        if (line[0] == ' ' or line[0] == '\t') {
            if (collecting) {
                try value.append(allocator, ' ');
                try value.appendSlice(allocator, std.mem.trim(u8, line, " \t"));
            }
            continue;
        }
        collecting = false;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidFrom;
        if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " \t"), "from")) continue;
        if (found) return error.InvalidFrom;
        found = true;
        collecting = true;
        try value.appendSlice(allocator, line[colon + 1 ..]);
    }
    if (!found) return null;
    return try allocator.dupe(u8, try mailbox(value.items));
}

test "security: submission From has one unambiguous author" {
    const a = std.testing.allocator;
    for ([_][]const u8{ "From: user@example.com\r\n\r\nbody", "From: \"Doe, Jane\" <user@example.com>\n\nbody", "From:\r\n user@example.com\r\n\r\n" }) |message| {
        const address = (try author(a, message)).?;
        defer a.free(address);
        try std.testing.expectEqualStrings("user@example.com", address);
    }
    for ([_][]const u8{ "From: a@example.com\nFrom: b@example.com\n\n", "From: a@example.com, b@example.com\n\n", "From: victim@example.com, Alice <user@example.com>\n\n", "From: a@example.com\rBcc: b@example.com\n\n" }) |bad|
        try std.testing.expectError(error.InvalidFrom, author(a, bad));
}
