const std = @import("std");
const time_compat = @import("../core/time_compat.zig");

/// Process-wide counter so concurrently generated bounces get distinct MIME
/// boundaries even within the same second.
var boundary_seq: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

/// Bounce message generator (RFC 3464 - DSN)
///
/// NOTE: not yet wired into the delivery path — permanently failed queue
/// messages are currently dropped without a DSN (see queue.markForRetry).
pub const BounceGenerator = struct {
    allocator: std.mem.Allocator,
    our_hostname: []const u8,

    pub fn init(allocator: std.mem.Allocator, our_hostname: []const u8) !BounceGenerator {
        return .{
            .allocator = allocator,
            .our_hostname = try allocator.dupe(u8, our_hostname),
        };
    }

    pub fn deinit(self: *BounceGenerator) void {
        self.allocator.free(self.our_hostname);
    }

    /// Generate a bounce message for a failed delivery
    pub fn generateBounce(
        self: *BounceGenerator,
        original_from: []const u8,
        original_to: []const u8,
        error_message: []const u8,
        original_message: ?[]const u8,
    ) ![]const u8 {
        const timestamp = time_compat.timestamp();
        const date_str = try time_compat.formatRfc5322Date(self.allocator, timestamp);
        defer self.allocator.free(date_str);

        // Unique per-message boundary: a fixed boundary corrupts the MIME
        // structure whenever the quoted original message contains it.
        var boundary_buf: [64]u8 = undefined;
        const seq = boundary_seq.fetchAdd(1, .monotonic);
        const boundary = try std.fmt.bufPrint(&boundary_buf, "=_Bounce_{d}_{d}", .{ timestamp, seq });

        var bounce: std.ArrayList(u8) = .empty;
        defer bounce.deinit(self.allocator);

        try self.appendf(&bounce, "From: Mail Delivery System <mailer-daemon@{s}>\r\n", .{self.our_hostname});
        try self.appendf(&bounce, "To: {s}\r\n", .{original_from});
        try bounce.appendSlice(self.allocator, "Subject: Mail delivery failed: returning message to sender\r\n");
        try self.appendf(&bounce, "Date: {s}\r\n", .{date_str});
        try bounce.appendSlice(self.allocator, "Auto-Submitted: auto-replied\r\n");
        try bounce.appendSlice(self.allocator, "MIME-Version: 1.0\r\n");
        try self.appendf(&bounce, "Content-Type: multipart/report; report-type=delivery-status; boundary=\"{s}\"\r\n", .{boundary});
        try bounce.appendSlice(self.allocator, "\r\n");

        // Human-readable part
        try self.appendf(&bounce, "--{s}\r\n", .{boundary});
        try bounce.appendSlice(self.allocator, "Content-Type: text/plain; charset=utf-8\r\n\r\n");
        try self.appendf(&bounce, "This is the mail system at host {s}.\r\n\r\n", .{self.our_hostname});
        try bounce.appendSlice(self.allocator, "I'm sorry to have to inform you that your message could not\r\n");
        try bounce.appendSlice(self.allocator, "be delivered to one or more recipients.\r\n\r\n");
        try self.appendf(&bounce, "Failed recipient: {s}\r\n", .{original_to});
        try self.appendf(&bounce, "Error: {s}\r\n\r\n", .{error_message});
        try bounce.appendSlice(self.allocator, "The mail system will not retry delivery.\r\n\r\n");

        // Machine-readable delivery status
        try self.appendf(&bounce, "--{s}\r\n", .{boundary});
        try bounce.appendSlice(self.allocator, "Content-Type: message/delivery-status\r\n\r\n");
        try self.appendf(&bounce, "Reporting-MTA: dns; {s}\r\n\r\n", .{self.our_hostname});
        try self.appendf(&bounce, "Final-Recipient: rfc822; {s}\r\n", .{original_to});
        try bounce.appendSlice(self.allocator, "Action: failed\r\n");
        try bounce.appendSlice(self.allocator, "Status: 5.0.0\r\n");
        try self.appendf(&bounce, "Diagnostic-Code: smtp; {s}\r\n\r\n", .{error_message});

        // Original message headers (if available)
        if (original_message) |msg| {
            try self.appendf(&bounce, "--{s}\r\n", .{boundary});
            try bounce.appendSlice(self.allocator, "Content-Type: message/rfc822\r\n\r\n");

            // Include first 1000 bytes of original message
            const preview_len = @min(1000, msg.len);
            try bounce.appendSlice(self.allocator, msg[0..preview_len]);
            if (msg.len > 1000) {
                try bounce.appendSlice(self.allocator, "\r\n[... message truncated ...]\r\n");
            }
            try bounce.appendSlice(self.allocator, "\r\n");
        }

        try self.appendf(&bounce, "--{s}--\r\n", .{boundary});

        return try bounce.toOwnedSlice(self.allocator);
    }

    fn appendf(self: *BounceGenerator, list: *std.ArrayList(u8), comptime fmt: []const u8, args: anytype) !void {
        const s = try std.fmt.allocPrint(self.allocator, fmt, args);
        defer self.allocator.free(s);
        try list.appendSlice(self.allocator, s);
    }
};

/// Bounce reasons
pub const BounceReason = enum {
    user_unknown,
    mailbox_full,
    message_too_large,
    relay_denied,
    connection_timeout,
    general_failure,

    pub fn toString(self: BounceReason) []const u8 {
        return switch (self) {
            .user_unknown => "550 User unknown",
            .mailbox_full => "552 Mailbox full",
            .message_too_large => "552 Message size exceeds limit",
            .relay_denied => "550 Relay access denied",
            .connection_timeout => "421 Connection timeout",
            .general_failure => "554 Transaction failed",
        };
    }

    pub fn statusCode(self: BounceReason) []const u8 {
        return switch (self) {
            .user_unknown => "5.1.1",
            .mailbox_full => "5.2.2",
            .message_too_large => "5.3.4",
            .relay_denied => "5.7.1",
            .connection_timeout => "4.4.2",
            .general_failure => "5.0.0",
        };
    }
};

test "generate bounce message" {
    const testing = std.testing;
    var gen = try BounceGenerator.init(testing.allocator, "mail.example.com");
    defer gen.deinit();

    const bounce = try gen.generateBounce(
        "sender@example.com",
        "recipient@example.com",
        "User unknown",
        "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nBody",
    );
    defer testing.allocator.free(bounce);

    // Verify bounce contains expected parts
    try testing.expect(std.mem.indexOf(u8, bounce, "mailer-daemon@mail.example.com") != null);
    try testing.expect(std.mem.indexOf(u8, bounce, "sender@example.com") != null);
    try testing.expect(std.mem.indexOf(u8, bounce, "User unknown") != null);
    try testing.expect(std.mem.indexOf(u8, bounce, "multipart/report") != null);
    // No hardcoded date or fixed boundary
    try testing.expect(std.mem.indexOf(u8, bounce, "1 Jan 2024") == null);
    try testing.expect(std.mem.indexOf(u8, bounce, "=_Bounce_123") == null);
}

test "bounce reasons" {
    const testing = std.testing;

    try testing.expectEqualStrings("550 User unknown", BounceReason.user_unknown.toString());
    try testing.expectEqualStrings("5.1.1", BounceReason.user_unknown.statusCode());
}

test "bounce date uses shared RFC 5322 formatter" {
    const testing = std.testing;
    // 2026-06-10 12:34:56 UTC
    const date = try time_compat.formatRfc5322Date(testing.allocator, 1781094896);
    defer testing.allocator.free(date);
    try testing.expectEqualStrings("Wed, 10 Jun 2026 12:34:56 +0000", date);
}
