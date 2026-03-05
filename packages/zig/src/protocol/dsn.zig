const std = @import("std");
const time_compat = @import("../core/time_compat.zig");

/// DSN (Delivery Status Notification) extension (RFC 3461)
/// Allows senders to request notification of delivery status
pub const DSNHandler = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) DSNHandler {
        return .{
            .allocator = allocator,
        };
    }

    /// Parse MAIL FROM DSN parameters
    /// Format: MAIL FROM:<address> RET=FULL|HDRS ENVID=<envelope-id>
    pub fn parseMailParams(self: *DSNHandler, params: []const u8) !DSNMailParams {
        var result = DSNMailParams{
            .ret = .headers_only,
            .envid = null,
        };

        var parts = std.mem.splitScalar(u8, params, ' ');
        while (parts.next()) |part| {
            if (std.mem.startsWith(u8, part, "RET=")) {
                const ret_value = part[4..];
                if (std.mem.eql(u8, ret_value, "FULL")) {
                    result.ret = .full_message;
                } else if (std.mem.eql(u8, ret_value, "HDRS")) {
                    result.ret = .headers_only;
                }
            } else if (std.mem.startsWith(u8, part, "ENVID=")) {
                const envid = part[6..];
                result.envid = try self.allocator.dupe(u8, envid);
            }
        }

        return result;
    }

    /// Parse RCPT TO DSN parameters
    /// Format: RCPT TO:<address> NOTIFY=NEVER|SUCCESS|FAILURE|DELAY ORCPT=<original-recipient>
    pub fn parseRcptParams(self: *DSNHandler, params: []const u8) !DSNRcptParams {
        var result = DSNRcptParams{
            .notify = .{},
            .orcpt = null,
        };

        var parts = std.mem.splitScalar(u8, params, ' ');
        while (parts.next()) |part| {
            if (std.mem.startsWith(u8, part, "NOTIFY=")) {
                const notify_value = part[7..];
                result.notify = try self.parseNotifyValue(notify_value);
            } else if (std.mem.startsWith(u8, part, "ORCPT=")) {
                const orcpt = part[6..];
                result.orcpt = try self.allocator.dupe(u8, orcpt);
            }
        }

        return result;
    }

    fn parseNotifyValue(self: *DSNHandler, value: []const u8) !DSNNotify {
        _ = self;

        var notify = DSNNotify{};

        if (std.mem.eql(u8, value, "NEVER")) {
            notify.never = true;
            return notify;
        }

        var conditions = std.mem.splitScalar(u8, value, ',');
        while (conditions.next()) |condition| {
            if (std.mem.eql(u8, condition, "SUCCESS")) {
                notify.success = true;
            } else if (std.mem.eql(u8, condition, "FAILURE")) {
                notify.failure = true;
            } else if (std.mem.eql(u8, condition, "DELAY")) {
                notify.delay = true;
            }
        }

        return notify;
    }

    /// Generate DSN success notification
    pub fn generateSuccessDSN(
        self: *DSNHandler,
        params: DSNMailParams,
        recipient: []const u8,
        original_message: ?[]const u8,
    ) ![]const u8 {
        var dsn = std.ArrayList(u8).init(self.allocator);
        defer dsn.deinit();

        const now = time_compat.timestamp();

        // Headers
        try dsn.appendSlice("Content-Type: multipart/report; report-type=delivery-status; boundary=\"DSN_BOUNDARY\"\r\n");
        try std.fmt.format(dsn.writer(), "Date: {d}\r\n", .{now});
        try std.fmt.format(dsn.writer(), "To: {s}\r\n", .{recipient});
        try dsn.appendSlice("Subject: Delivery Status Notification (Success)\r\n");
        try dsn.appendSlice("Auto-Submitted: auto-replied\r\n");
        try dsn.appendSlice("\r\n");

        // Human-readable part
        try dsn.appendSlice("--DSN_BOUNDARY\r\n");
        try dsn.appendSlice("Content-Type: text/plain; charset=UTF-8\r\n");
        try dsn.appendSlice("\r\n");
        try dsn.appendSlice("This is a delivery status notification.\r\n\r\n");
        try std.fmt.format(dsn.writer(), "Your message was successfully delivered to {s}.\r\n", .{recipient});
        try dsn.appendSlice("\r\n");

        // Machine-readable DSN part
        try dsn.appendSlice("--DSN_BOUNDARY\r\n");
        try dsn.appendSlice("Content-Type: message/delivery-status\r\n");
        try dsn.appendSlice("\r\n");

        // Per-Message DSN fields
        try dsn.appendSlice("Reporting-MTA: dns; mail\r\n");
        if (params.envid) |envid| {
            try std.fmt.format(dsn.writer(), "Original-Envelope-Id: {s}\r\n", .{envid});
        }
        try dsn.appendSlice("\r\n");

        // Per-Recipient DSN fields
        try std.fmt.format(dsn.writer(), "Final-Recipient: rfc822; {s}\r\n", .{recipient});
        try dsn.appendSlice("Action: delivered\r\n");
        try dsn.appendSlice("Status: 2.0.0\r\n");
        try dsn.appendSlice("\r\n");

        // Original message (full or headers only)
        if (original_message) |msg| {
            try dsn.appendSlice("--DSN_BOUNDARY\r\n");
            try dsn.appendSlice("Content-Type: message/rfc822\r\n");
            try dsn.appendSlice("\r\n");

            if (params.ret == .headers_only) {
                // Extract and include only headers
                const headers = try self.extractHeaders(msg);
                defer self.allocator.free(headers);
                try dsn.appendSlice(headers);
            } else {
                // Include full message
                try dsn.appendSlice(msg);
            }
            try dsn.appendSlice("\r\n");
        }

        try dsn.appendSlice("--DSN_BOUNDARY--\r\n");

        return try dsn.toOwnedSlice();
    }

    /// Generate DSN failure notification
    pub fn generateFailureDSN(
        self: *DSNHandler,
        params: DSNMailParams,
        recipient: []const u8,
        error_message: []const u8,
        original_message: ?[]const u8,
    ) ![]const u8 {
        var dsn = std.ArrayList(u8).init(self.allocator);
        defer dsn.deinit();

        const now = time_compat.timestamp();

        // Headers
        try dsn.appendSlice("Content-Type: multipart/report; report-type=delivery-status; boundary=\"DSN_BOUNDARY\"\r\n");
        try std.fmt.format(dsn.writer(), "Date: {d}\r\n", .{now});
        try std.fmt.format(dsn.writer(), "To: {s}\r\n", .{recipient});
        try dsn.appendSlice("Subject: Delivery Status Notification (Failure)\r\n");
        try dsn.appendSlice("Auto-Submitted: auto-replied\r\n");
        try dsn.appendSlice("\r\n");

        // Human-readable part
        try dsn.appendSlice("--DSN_BOUNDARY\r\n");
        try dsn.appendSlice("Content-Type: text/plain; charset=UTF-8\r\n");
        try dsn.appendSlice("\r\n");
        try dsn.appendSlice("This is a delivery status notification.\r\n\r\n");
        try std.fmt.format(dsn.writer(), "Delivery to {s} failed.\r\n\r\n", .{recipient});
        try std.fmt.format(dsn.writer(), "Error: {s}\r\n", .{error_message});
        try dsn.appendSlice("\r\n");

        // Machine-readable DSN part
        try dsn.appendSlice("--DSN_BOUNDARY\r\n");
        try dsn.appendSlice("Content-Type: message/delivery-status\r\n");
        try dsn.appendSlice("\r\n");

        // Per-Message DSN fields
        try dsn.appendSlice("Reporting-MTA: dns; mail\r\n");
        if (params.envid) |envid| {
            try std.fmt.format(dsn.writer(), "Original-Envelope-Id: {s}\r\n", .{envid});
        }
        try dsn.appendSlice("\r\n");

        // Per-Recipient DSN fields
        try std.fmt.format(dsn.writer(), "Final-Recipient: rfc822; {s}\r\n", .{recipient});
        try dsn.appendSlice("Action: failed\r\n");
        try dsn.appendSlice("Status: 5.0.0\r\n");
        try std.fmt.format(dsn.writer(), "Diagnostic-Code: smtp; {s}\r\n", .{error_message});
        try dsn.appendSlice("\r\n");

        // Original message
        if (original_message) |msg| {
            try dsn.appendSlice("--DSN_BOUNDARY\r\n");
            try dsn.appendSlice("Content-Type: message/rfc822\r\n");
            try dsn.appendSlice("\r\n");

            if (params.ret == .headers_only) {
                const headers = try self.extractHeaders(msg);
                defer self.allocator.free(headers);
                try dsn.appendSlice(headers);
            } else {
                try dsn.appendSlice(msg);
            }
            try dsn.appendSlice("\r\n");
        }

        try dsn.appendSlice("--DSN_BOUNDARY--\r\n");

        return try dsn.toOwnedSlice();
    }

    /// Generate DSN delay notification
    pub fn generateDelayDSN(
        self: *DSNHandler,
        params: DSNMailParams,
        recipient: []const u8,
        delay_reason: []const u8,
    ) ![]const u8 {
        var dsn = std.ArrayList(u8).init(self.allocator);
        defer dsn.deinit();

        const now = time_compat.timestamp();

        try dsn.appendSlice("Content-Type: multipart/report; report-type=delivery-status; boundary=\"DSN_BOUNDARY\"\r\n");
        try std.fmt.format(dsn.writer(), "Date: {d}\r\n", .{now});
        try std.fmt.format(dsn.writer(), "To: {s}\r\n", .{recipient});
        try dsn.appendSlice("Subject: Delivery Status Notification (Delay)\r\n");
        try dsn.appendSlice("Auto-Submitted: auto-replied\r\n");
        try dsn.appendSlice("\r\n");

        try dsn.appendSlice("--DSN_BOUNDARY\r\n");
        try dsn.appendSlice("Content-Type: text/plain; charset=UTF-8\r\n");
        try dsn.appendSlice("\r\n");
        try dsn.appendSlice("This is a delivery status notification.\r\n\r\n");
        try std.fmt.format(dsn.writer(), "Delivery to {s} has been delayed.\r\n\r\n", .{recipient});
        try std.fmt.format(dsn.writer(), "Reason: {s}\r\n", .{delay_reason});
        try dsn.appendSlice("\r\n");

        try dsn.appendSlice("--DSN_BOUNDARY\r\n");
        try dsn.appendSlice("Content-Type: message/delivery-status\r\n");
        try dsn.appendSlice("\r\n");

        try dsn.appendSlice("Reporting-MTA: dns; mail\r\n");
        if (params.envid) |envid| {
            try std.fmt.format(dsn.writer(), "Original-Envelope-Id: {s}\r\n", .{envid});
        }
        try dsn.appendSlice("\r\n");

        try std.fmt.format(dsn.writer(), "Final-Recipient: rfc822; {s}\r\n", .{recipient});
        try dsn.appendSlice("Action: delayed\r\n");
        try dsn.appendSlice("Status: 4.0.0\r\n");
        try std.fmt.format(dsn.writer(), "Diagnostic-Code: smtp; {s}\r\n", .{delay_reason});
        try dsn.appendSlice("\r\n");

        try dsn.appendSlice("--DSN_BOUNDARY--\r\n");

        return try dsn.toOwnedSlice();
    }

    fn extractHeaders(self: *DSNHandler, message: []const u8) ![]const u8 {
        // Find the end of headers (blank line)
        if (std.mem.indexOf(u8, message, "\r\n\r\n")) |pos| {
            return try self.allocator.dupe(u8, message[0 .. pos + 2]);
        } else if (std.mem.indexOf(u8, message, "\n\n")) |pos| {
            return try self.allocator.dupe(u8, message[0 .. pos + 1]);
        }

        // No body separator found, return entire message
        return try self.allocator.dupe(u8, message);
    }

    pub fn freeParams(self: *DSNHandler, params: *DSNMailParams) void {
        if (params.envid) |envid| {
            self.allocator.free(envid);
        }
    }

    pub fn freeRcptParams(self: *DSNHandler, params: *DSNRcptParams) void {
        if (params.orcpt) |orcpt| {
            self.allocator.free(orcpt);
        }
    }
};

pub const DSNMailParams = struct {
    ret: DSNReturnType,
    envid: ?[]const u8, // Envelope ID for tracking
};

pub const DSNReturnType = enum {
    full_message,
    headers_only,
};

pub const DSNRcptParams = struct {
    notify: DSNNotify,
    orcpt: ?[]const u8, // Original recipient
};

pub const DSNNotify = struct {
    never: bool = false,
    success: bool = false,
    failure: bool = false,
    delay: bool = false,

    pub fn shouldNotify(self: *const DSNNotify, event: DSNEvent) bool {
        if (self.never) return false;

        return switch (event) {
            .success => self.success,
            .failure => self.failure,
            .delay => self.delay,
        };
    }
};

pub const DSNEvent = enum {
    success,
    failure,
    delay,
};

test "parse MAIL FROM DSN params" {
    const testing = std.testing;
    var handler = DSNHandler.init(testing.allocator);

    const params_str = "RET=FULL ENVID=abc123";
    var params = try handler.parseMailParams(params_str);
    defer handler.freeParams(&params);

    try testing.expectEqual(DSNReturnType.full_message, params.ret);
    try testing.expect(params.envid != null);
    try testing.expectEqualStrings("abc123", params.envid.?);
}

test "parse RCPT TO DSN params" {
    const testing = std.testing;
    var handler = DSNHandler.init(testing.allocator);

    const params_str = "NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;original@example.com";
    var params = try handler.parseRcptParams(params_str);
    defer handler.freeRcptParams(&params);

    try testing.expect(params.notify.success);
    try testing.expect(params.notify.failure);
    try testing.expect(!params.notify.delay);
    try testing.expect(params.orcpt != null);
}

test "DSN notify conditions" {
    const testing = std.testing;

    var notify = DSNNotify{
        .success = true,
        .failure = true,
        .delay = false,
    };

    try testing.expect(notify.shouldNotify(.success));
    try testing.expect(notify.shouldNotify(.failure));
    try testing.expect(!notify.shouldNotify(.delay));

    var never_notify = DSNNotify{ .never = true };
    try testing.expect(!never_notify.shouldNotify(.success));
    try testing.expect(!never_notify.shouldNotify(.failure));
}

test "generate success DSN" {
    const testing = std.testing;
    var handler = DSNHandler.init(testing.allocator);

    var params = DSNMailParams{
        .ret = .headers_only,
        .envid = try testing.allocator.dupe(u8, "test-123"),
    };
    defer testing.allocator.free(params.envid.?);

    const dsn = try handler.generateSuccessDSN(params, "recipient@example.com", null);
    defer testing.allocator.free(dsn);

    try testing.expect(std.mem.indexOf(u8, dsn, "Action: delivered") != null);
    try testing.expect(std.mem.indexOf(u8, dsn, "Status: 2.0.0") != null);
    try testing.expect(std.mem.indexOf(u8, dsn, "test-123") != null);
}

test "generate failure DSN" {
    const testing = std.testing;
    var handler = DSNHandler.init(testing.allocator);

    var params = DSNMailParams{
        .ret = .headers_only,
        .envid = null,
    };

    const dsn = try handler.generateFailureDSN(params, "recipient@example.com", "Mailbox full", null);
    defer testing.allocator.free(dsn);

    try testing.expect(std.mem.indexOf(u8, dsn, "Action: failed") != null);
    try testing.expect(std.mem.indexOf(u8, dsn, "Status: 5.0.0") != null);
    try testing.expect(std.mem.indexOf(u8, dsn, "Mailbox full") != null);
}
