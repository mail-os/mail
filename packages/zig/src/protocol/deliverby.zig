const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");

/// DELIVERBY extension (RFC 2852)
/// Allows clients to request delivery within a specified time period
/// Provides notification if delivery cannot be completed in time
///
/// MAIL FROM parameters:
///   BY=<time>;[R|N|T]
///
/// Examples:
///   MAIL FROM:<sender@example.com> BY=3600;R
///   - Deliver within 1 hour (3600 seconds)
///   - R = Return notification if deadline missed
///   - N = Never return notification
///   - T = Trace (return notification with trace info)
///
/// Response codes:
///   250 OK
///   455 Server unable to accommodate parameters
///   501 Syntax error in parameters
pub const DeliverByHandler = struct {
    allocator: std.mem.Allocator,
    max_delivery_time: i64, // Maximum time we can commit to (seconds)
    min_delivery_time: i64, // Minimum time we require (seconds)

    pub fn init(allocator: std.mem.Allocator, max_delivery_time: i64, min_delivery_time: i64) DeliverByHandler {
        return .{
            .allocator = allocator,
            .max_delivery_time = max_delivery_time,
            .min_delivery_time = min_delivery_time,
        };
    }

    /// Parse DELIVERBY parameter from MAIL FROM
    pub fn parseParameter(self: *DeliverByHandler, params: []const u8) !DeliverByParams {
        _ = self;

        var result = DeliverByParams{
            .deadline_seconds = 0,
            .notify_mode = .return_notification,
        };

        // Find BY= parameter
        var parts = std.mem.splitScalar(u8, params, ' ');
        while (parts.next()) |part| {
            if (std.mem.startsWith(u8, part, "BY=")) {
                const by_value = part[3..];

                // Parse: <time>;[R|N|T]
                if (std.mem.indexOf(u8, by_value, ";")) |semicolon| {
                    const time_str = by_value[0..semicolon];
                    const mode_str = by_value[semicolon + 1 ..];

                    // Parse deadline
                    result.deadline_seconds = try std.fmt.parseInt(i64, time_str, 10);

                    // Parse notify mode
                    if (mode_str.len > 0) {
                        result.notify_mode = switch (mode_str[0]) {
                            'R', 'r' => .return_notification,
                            'N', 'n' => .never_notify,
                            'T', 't' => .trace_notification,
                            else => return error.InvalidNotifyMode,
                        };
                    }
                } else {
                    // No mode specified, just time
                    result.deadline_seconds = try std.fmt.parseInt(i64, by_value, 10);
                }

                return result;
            }
        }

        return error.NoDeliverByParameter;
    }

    /// Validate that we can meet the requested deadline
    pub fn validateDeadline(self: *DeliverByHandler, params: DeliverByParams) !ValidationResult {
        // Check if deadline is too short
        if (params.deadline_seconds < self.min_delivery_time) {
            return ValidationResult{
                .acceptable = false,
                .reason = .deadline_too_short,
                .recommended_deadline = self.min_delivery_time,
            };
        }

        // Check if deadline exceeds our maximum
        if (params.deadline_seconds > self.max_delivery_time) {
            return ValidationResult{
                .acceptable = false,
                .reason = .deadline_too_long,
                .recommended_deadline = self.max_delivery_time,
            };
        }

        return ValidationResult{
            .acceptable = true,
            .reason = .none,
            .recommended_deadline = params.deadline_seconds,
        };
    }

    /// Calculate delivery deadline timestamp
    pub fn calculateDeadline(self: *DeliverByHandler, params: DeliverByParams) i64 {
        _ = self;
        const now = time_compat.timestamp();
        return now + params.deadline_seconds;
    }

    /// Check if delivery deadline has been exceeded
    pub fn isDeadlineExceeded(self: *DeliverByHandler, deadline: i64) bool {
        _ = self;
        const now = time_compat.timestamp();
        return now > deadline;
    }

    /// Generate delivery status notification for missed deadline
    pub fn generateDeadlineNotification(
        self: *DeliverByHandler,
        original_sender: []const u8,
        original_recipient: []const u8,
        deadline_seconds: i64,
        notify_mode: NotifyMode,
    ) ![]const u8 {
        if (notify_mode == .never_notify) {
            return error.NotificationNotRequested;
        }

        var notification = std.ArrayList(u8).init(self.allocator);
        defer notification.deinit(self.allocator);

        // Generate RFC 3464 compliant DSN
        try std.fmt.format(
            notification.writer(self.allocator),
            \\From: Mail Delivery Subsystem <mailer-daemon@localhost>
            \\To: {s}
            \\Subject: Delivery Status Notification (Failure - Deadline Exceeded)
            \\Content-Type: multipart/report; report-type=delivery-status; boundary="----=_Part_0"
            \\
            \\------=_Part_0
            \\Content-Type: text/plain; charset=utf-8
            \\
            \\This is an automatically generated Delivery Status Notification.
            \\
            \\Your message could not be delivered to the following recipient(s) within the requested time:
            \\
            \\  {s}
            \\
            \\Requested delivery time: {d} seconds
            \\Reason: Delivery deadline exceeded
            \\
            \\------=_Part_0
            \\Content-Type: message/delivery-status
            \\
            \\Reporting-MTA: dns; localhost
            \\Arrival-Date:
            \\
            \\Final-Recipient: rfc822; {s}
            \\Action: failed
            \\Status: 4.4.7
            \\Diagnostic-Code: smtp; Delivery time expired
            \\
            \\------=_Part_0--
            \\
        ,
            .{ original_sender, original_recipient, deadline_seconds, original_recipient },
        );

        return try notification.toOwnedSlice(self.allocator);
    }

    /// Get EHLO capability string
    pub fn getCapability(self: *DeliverByHandler) ![]const u8 {
        return try std.fmt.allocPrint(
            self.allocator,
            "DELIVERBY {d}",
            .{self.max_delivery_time},
        );
    }
};

/// DELIVERBY parameters from MAIL FROM
pub const DeliverByParams = struct {
    deadline_seconds: i64, // Delivery deadline in seconds
    notify_mode: NotifyMode,

    pub fn toString(self: DeliverByParams, allocator: std.mem.Allocator) ![]const u8 {
        return try std.fmt.allocPrint(
            allocator,
            "BY={d};{s}",
            .{ self.deadline_seconds, self.notify_mode.toChar() },
        );
    }
};

/// Notification mode for missed deadlines
pub const NotifyMode = enum {
    return_notification, // R - Return notification if deadline missed
    never_notify, // N - Never return notification
    trace_notification, // T - Return with trace information

    pub fn toChar(self: NotifyMode) []const u8 {
        return switch (self) {
            .return_notification => "R",
            .never_notify => "N",
            .trace_notification => "T",
        };
    }

    pub fn fromChar(c: u8) !NotifyMode {
        return switch (c) {
            'R', 'r' => .return_notification,
            'N', 'n' => .never_notify,
            'T', 't' => .trace_notification,
            else => error.InvalidNotifyMode,
        };
    }
};

/// Validation result for deadline
pub const ValidationResult = struct {
    acceptable: bool,
    reason: ValidationReason,
    recommended_deadline: i64,
};

pub const ValidationReason = enum {
    none,
    deadline_too_short,
    deadline_too_long,
    server_overloaded,

    pub fn toString(self: ValidationReason) []const u8 {
        return switch (self) {
            .none => "OK",
            .deadline_too_short => "Deadline too short for delivery",
            .deadline_too_long => "Deadline exceeds maximum",
            .server_overloaded => "Server cannot accept timed delivery",
        };
    }
};

/// Message with delivery deadline
pub const TimedMessage = struct {
    message_id: []const u8,
    deadline: i64, // Unix timestamp
    notify_mode: NotifyMode,
    sender: []const u8,
    recipient: []const u8,

    pub fn deinit(self: *TimedMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.message_id);
        allocator.free(self.sender);
        allocator.free(self.recipient);
    }

    pub fn isExpired(self: *const TimedMessage) bool {
        const now = time_compat.timestamp();
        return now > self.deadline;
    }

    pub fn timeRemaining(self: *const TimedMessage) i64 {
        const now = time_compat.timestamp();
        const remaining = self.deadline - now;
        return if (remaining > 0) remaining else 0;
    }
};

/// Priority queue for timed messages
pub const TimedMessageQueue = struct {
    allocator: std.mem.Allocator,
    messages: std.ArrayList(TimedMessage),
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator) TimedMessageQueue {
        return .{
            .allocator = allocator,
            .messages = std.ArrayList(TimedMessage).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *TimedMessageQueue) void {
        for (self.messages.items) |*msg| {
            msg.deinit(self.allocator);
        }
        self.messages.deinit(self.allocator);
    }

    /// Add message to queue (sorted by deadline)
    pub fn push(self: *TimedMessageQueue, message: TimedMessage) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.messages.append(self.allocator, message);

        // Sort by deadline (earliest first)
        std.mem.sort(TimedMessage, self.messages.items, {}, compareDeadlines);
    }

    /// Get next message to deliver
    pub fn pop(self: *TimedMessageQueue) ?TimedMessage {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.messages.items.len == 0) return null;
        return self.messages.orderedRemove(0);
    }

    /// Peek at next message without removing
    pub fn peek(self: *TimedMessageQueue) ?*const TimedMessage {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.messages.items.len == 0) return null;
        return &self.messages.items[0];
    }

    /// Get count of messages
    pub fn count(self: *TimedMessageQueue) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.messages.items.len;
    }

    fn compareDeadlines(_: void, a: TimedMessage, b: TimedMessage) bool {
        return a.deadline < b.deadline;
    }
};

test "parse DELIVERBY parameter" {
    const testing = std.testing;

    var handler = DeliverByHandler.init(testing.allocator, 86400, 60);

    const params = try handler.parseParameter("BY=3600;R");
    try testing.expectEqual(@as(i64, 3600), params.deadline_seconds);
    try testing.expectEqual(NotifyMode.return_notification, params.notify_mode);
}

test "parse DELIVERBY with different modes" {
    const testing = std.testing;

    var handler = DeliverByHandler.init(testing.allocator, 86400, 60);

    const params_n = try handler.parseParameter("BY=7200;N");
    try testing.expectEqual(NotifyMode.never_notify, params_n.notify_mode);

    const params_t = try handler.parseParameter("BY=1800;T");
    try testing.expectEqual(NotifyMode.trace_notification, params_t.notify_mode);
}

test "validate deadline" {
    const testing = std.testing;

    var handler = DeliverByHandler.init(testing.allocator, 86400, 60);

    // Valid deadline
    const valid_params = DeliverByParams{ .deadline_seconds = 3600, .notify_mode = .return_notification };
    const valid_result = try handler.validateDeadline(valid_params);
    try testing.expect(valid_result.acceptable);

    // Too short
    const short_params = DeliverByParams{ .deadline_seconds = 30, .notify_mode = .return_notification };
    const short_result = try handler.validateDeadline(short_params);
    try testing.expect(!short_result.acceptable);
    try testing.expectEqual(ValidationReason.deadline_too_short, short_result.reason);

    // Too long
    const long_params = DeliverByParams{ .deadline_seconds = 100000, .notify_mode = .return_notification };
    const long_result = try handler.validateDeadline(long_params);
    try testing.expect(!long_result.acceptable);
    try testing.expectEqual(ValidationReason.deadline_too_long, long_result.reason);
}

test "calculate deadline" {
    const testing = std.testing;

    var handler = DeliverByHandler.init(testing.allocator, 86400, 60);

    const params = DeliverByParams{ .deadline_seconds = 3600, .notify_mode = .return_notification };
    const deadline = handler.calculateDeadline(params);

    const now = time_compat.timestamp();
    try testing.expect(deadline > now);
    try testing.expect(deadline <= now + 3600 + 1); // Allow 1 second for execution
}

test "notify mode enum" {
    const testing = std.testing;

    try testing.expectEqualStrings("R", NotifyMode.return_notification.toChar());
    try testing.expectEqualStrings("N", NotifyMode.never_notify.toChar());
    try testing.expectEqualStrings("T", NotifyMode.trace_notification.toChar());

    const mode = try NotifyMode.fromChar('R');
    try testing.expectEqual(NotifyMode.return_notification, mode);
}

test "timed message expiration" {
    const testing = std.testing;

    const now = time_compat.timestamp();
    var message = TimedMessage{
        .message_id = try testing.allocator.dupe(u8, "msg-123"),
        .deadline = now - 100, // Expired 100 seconds ago
        .notify_mode = .return_notification,
        .sender = try testing.allocator.dupe(u8, "sender@example.com"),
        .recipient = try testing.allocator.dupe(u8, "recipient@example.com"),
    };
    defer message.deinit(testing.allocator);

    try testing.expect(message.isExpired());
    try testing.expectEqual(@as(i64, 0), message.timeRemaining());
}

test "timed message queue" {
    const testing = std.testing;

    var queue = TimedMessageQueue.init(testing.allocator);
    defer queue.deinit();

    const now = time_compat.timestamp();

    // Add messages with different deadlines
    const msg1 = TimedMessage{
        .message_id = try testing.allocator.dupe(u8, "msg-1"),
        .deadline = now + 3600,
        .notify_mode = .return_notification,
        .sender = try testing.allocator.dupe(u8, "sender1@example.com"),
        .recipient = try testing.allocator.dupe(u8, "recipient1@example.com"),
    };

    const msg2 = TimedMessage{
        .message_id = try testing.allocator.dupe(u8, "msg-2"),
        .deadline = now + 1800, // Earlier deadline
        .notify_mode = .return_notification,
        .sender = try testing.allocator.dupe(u8, "sender2@example.com"),
        .recipient = try testing.allocator.dupe(u8, "recipient2@example.com"),
    };

    try queue.push(msg1);
    try queue.push(msg2);

    try testing.expectEqual(@as(usize, 2), queue.count());

    // Should get msg2 first (earlier deadline)
    const next = queue.pop();
    try testing.expect(next != null);
    if (next) |msg| {
        var msg_copy = msg;
        defer msg_copy.deinit(testing.allocator);
        try testing.expectEqualStrings("msg-2", msg.message_id);
    }
}

test "get capability" {
    const testing = std.testing;

    var handler = DeliverByHandler.init(testing.allocator, 86400, 60);

    const capability = try handler.getCapability();
    defer testing.allocator.free(capability);

    try testing.expectEqualStrings("DELIVERBY 86400", capability);
}

test "params to string" {
    const testing = std.testing;

    const params = DeliverByParams{
        .deadline_seconds = 3600,
        .notify_mode = .return_notification,
    };

    const str = try params.toString(testing.allocator);
    defer testing.allocator.free(str);

    try testing.expectEqualStrings("BY=3600;R", str);
}
