const std = @import("std");

/// Room for an account name in a log line.
pub const Buffer = [128]u8;

/// An account name as a client sent it, made fit for a log line: control bytes
/// (a CRLF would forge a second entry) become '?', and an oversize name is cut.
///
/// Failed logins used to log only the peer address. When a deploy replaced
/// three mailbox passwords, a Mail.app with several accounts failed five times
/// an hour for a day, and nothing on the server said which account it was.
pub fn account(buf: *Buffer, name: []const u8) []const u8 {
    const len = @min(name.len, buf.len);
    for (name[0..len], 0..) |c, i| {
        buf[i] = if (c < 0x20 or c == 0x7f) '?' else c;
    }
    return buf[0..len];
}

test "an ordinary address is logged as sent" {
    var buf: Buffer = undefined;
    try std.testing.expectEqualStrings("chris@stacksjs.com", account(&buf, "chris@stacksjs.com"));
}

test "control bytes cannot forge a log entry" {
    var buf: Buffer = undefined;
    try std.testing.expectEqualStrings("a??info: forged\x3f", account(&buf, "a\r\ninfo: forged\x00"));
}

test "an oversize name is cut to the buffer" {
    var buf: Buffer = undefined;
    const long: [300]u8 = @splat('x');
    try std.testing.expectEqual(@as(usize, buf.len), account(&buf, &long).len);
}
