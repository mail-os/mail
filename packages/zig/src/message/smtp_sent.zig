//! Bind a client-filed Sent copy to the bytes the same account submitted.
const std = @import("std");
const headers = @import("submission.zig");
const thread_ids = @import("thread_ids.zig");

pub const Evidence = struct {
    wire_id: []const u8,
    parent: []const u8,
    digest: [64]u8,
};

/// SMTP DATA supplies LF while IMAP literals typically retain CRLF. The
/// transport line ending is the only difference allowed in the fingerprint.
pub fn fingerprint(raw: []const u8) [64]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var start: usize = 0;
    while (std.mem.indexOfPos(u8, raw, start, "\r\n")) |cr| {
        hash.update(raw[start..cr]);
        start = cr + 1;
    }
    hash.update(raw[start..]);
    var result: [32]u8 = undefined;
    hash.final(&result);
    return std.fmt.bytesToHex(result, .lower);
}

pub fn headerLength(raw: []const u8) ?usize {
    var start: usize = 0;
    while (std.mem.indexOfScalarPos(u8, raw, start, '\n')) |end| {
        if (end == start or (end == start + 1 and raw[start] == '\r')) return end + 1;
        start = end + 1;
    }
    return null;
}

pub fn inspect(a: std.mem.Allocator, raw: []const u8, user: []const u8, envelope: ?[]const []const u8) !?Evidence {
    if (std.mem.indexOfScalar(u8, raw, 0) != null) return null;
    const header = raw[0 .. headerLength(raw) orelse return null];
    const author = (headers.author(a, header) catch return null) orelse return null;
    if (!std.ascii.eqlIgnoreCase(author, user)) return null;
    const ids = try thread_ids.parse(a, header);
    if (ids.automatic or ids.message_id_fields != 1 or ids.message_ids != 1 or ids.reply_fields > 1) return null;
    const own = ids.own orelse return null;
    const parent = (if (ids.reply_fields == 1) ids.direct_reply_parent else ids.reply_parent) orelse return null;
    if (std.mem.eql(u8, own, parent)) return null;

    var lines = std.mem.splitScalar(u8, header, '\n');
    while (lines.next()) |line| {
        if (std.ascii.startsWithIgnoreCase(line, "Resent-")) return null;
    }
    const mail = headers.prepareClientMime(a, header, user) catch return null;
    if (mail.has_bcc or mail.recipients.len == 0) return null;
    if (envelope) |recipients| {
        for (recipients) |address| if (!hasAddress(mail.recipients, address)) return null;
        for (mail.recipients) |address| if (!hasAddress(recipients, address)) return null;
    }
    return .{ .wire_id = own, .parent = parent, .digest = fingerprint(raw) };
}

fn hasAddress(addresses: []const []const u8, wanted: []const u8) bool {
    for (addresses) |address| if (std.ascii.eqlIgnoreCase(address, wanted)) return true;
    return false;
}

test "SMTP and Sent evidence agrees across line endings and binds the full message" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const user = "owner@example.test";
    const peer = "peer@example.test";
    const head = "From: owner@example.test\nTo: peer@example.test\nMessage-ID: <reply@example.test>\nIn-Reply-To: <parent@example.test>\n";
    const raw = head ++ "\nReply\n";
    const copy = "From: owner@example.test\r\nTo: peer@example.test\r\nMessage-ID: <reply@example.test>\r\nIn-Reply-To: <parent@example.test>\r\n\r\nReply\r\n";
    const sent = (try inspect(a, raw, user, &.{peer})).?;
    try std.testing.expectEqual(sent.digest, (try inspect(a, copy, user, null)).?.digest);
    try std.testing.expect(!std.mem.eql(u8, &sent.digest, &(try inspect(a, head ++ "\nEdited\n", user, null)).?.digest));
    try std.testing.expect((try inspect(a, raw, user, &.{ peer, "hidden@example.test" })) == null);
    try std.testing.expect((try inspect(a, head ++ "Bcc:\n\nReply\n", user, null)) == null);
    try std.testing.expect((try inspect(a, head ++ " \nMessage-ID: <duplicate@example.test>\n\nReply\n", user, null)) == null);
    try std.testing.expect((try inspect(a, head ++ "In-Reply-To: <elsewhere@example.test>\n\nReply\n", user, null)) == null);
    try std.testing.expect((try inspect(a, raw, peer, null)) == null);
}
