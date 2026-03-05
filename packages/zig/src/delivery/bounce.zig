const std = @import("std");
const time_compat = @import("../core/time_compat.zig");

/// Bounce message generator (RFC 3464 - DSN)
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
        const date_str = try self.formatDate(timestamp);
        defer self.allocator.free(date_str);

        var bounce = std.ArrayList(u8).init(self.allocator);
        defer bounce.deinit();

        const writer = bounce.writer();

        // Headers
        try writer.print("From: Mail Delivery System <mailer-daemon@{s}>\r\n", .{self.our_hostname});
        try writer.print("To: {s}\r\n", .{original_from});
        try writer.print("Subject: Mail delivery failed: returning message to sender\r\n", .{});
        try writer.print("Date: {s}\r\n", .{date_str});
        try writer.print("Auto-Submitted: auto-replied\r\n", .{});
        try writer.print("MIME-Version: 1.0\r\n", .{});
        try writer.print("Content-Type: multipart/report; report-type=delivery-status; boundary=\"----=_Bounce_123\"\r\n", .{});
        try writer.print("\r\n", .{});

        // Human-readable part
        try writer.print("------=_Bounce_123\r\n", .{});
        try writer.print("Content-Type: text/plain; charset=utf-8\r\n", .{});
        try writer.print("\r\n", .{});
        try writer.print("This is the mail system at host {s}.\r\n\r\n", .{self.our_hostname});
        try writer.print("I'm sorry to have to inform you that your message could not\r\n", .{});
        try writer.print("be delivered to one or more recipients.\r\n\r\n", .{});
        try writer.print("Failed recipient: {s}\r\n", .{original_to});
        try writer.print("Error: {s}\r\n\r\n", .{error_message});
        try writer.print("The mail system will not retry delivery.\r\n\r\n", .{});

        // Machine-readable delivery status
        try writer.print("------=_Bounce_123\r\n", .{});
        try writer.print("Content-Type: message/delivery-status\r\n", .{});
        try writer.print("\r\n", .{});
        try writer.print("Reporting-MTA: dns; {s}\r\n", .{self.our_hostname});
        try writer.print("\r\n", .{});
        try writer.print("Final-Recipient: rfc822; {s}\r\n", .{original_to});
        try writer.print("Action: failed\r\n", .{});
        try writer.print("Status: 5.0.0\r\n", .{});
        try writer.print("Diagnostic-Code: smtp; {s}\r\n", .{error_message});
        try writer.print("\r\n", .{});

        // Original message headers (if available)
        if (original_message) |msg| {
            try writer.print("------=_Bounce_123\r\n", .{});
            try writer.print("Content-Type: message/rfc822\r\n", .{});
            try writer.print("\r\n", .{});

            // Include first 1000 bytes of original message
            const preview_len = @min(1000, msg.len);
            try writer.print("{s}", .{msg[0..preview_len]});
            if (msg.len > 1000) {
                try writer.print("\r\n[... message truncated ...]\r\n", .{});
            }
            try writer.print("\r\n", .{});
        }

        try writer.print("------=_Bounce_123--\r\n", .{});

        return try bounce.toOwnedSlice();
    }

    fn formatDate(self: *BounceGenerator, timestamp: i64) ![]const u8 {
        _ = timestamp;
        // Simplified date format - in production, use proper RFC 5322 date formatting
        return try std.fmt.allocPrint(self.allocator, "Mon, 1 Jan 2024 00:00:00 +0000", .{});
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
}

test "bounce reasons" {
    const testing = std.testing;

    try testing.expectEqualStrings("550 User unknown", BounceReason.user_unknown.toString());
    try testing.expectEqualStrings("5.1.1", BounceReason.user_unknown.statusCode());
}
