const std = @import("std");

// =============================================================================
// Email Scheduling System
// =============================================================================
//
// ## Overview
// Allows users to schedule emails to be sent at a specific future time.
// Supports one-time sends, recurring emails, and timezone handling.
//
// ## Features
// - Schedule for specific date/time
// - Recurring schedules (daily, weekly, monthly)
// - Cancel/reschedule pending emails
// - Timezone support
// - Queue management
//
// =============================================================================

/// Scheduling errors
pub const ScheduleError = error{
    ScheduleNotFound,
    InvalidTime,
    PastTime,
    AlreadySent,
    QueueFull,
    OutOfMemory,
};

/// Schedule status
pub const ScheduleStatus = enum {
    /// Scheduled and waiting
    pending,
    /// Currently being sent
    sending,
    /// Successfully sent
    sent,
    /// Cancelled by user
    cancelled,
    /// Failed to send
    failed,
    /// Rescheduled to new time
    rescheduled,

    pub fn toString(self: ScheduleStatus) []const u8 {
        return switch (self) {
            .pending => "Pending",
            .sending => "Sending",
            .sent => "Sent",
            .cancelled => "Cancelled",
            .failed => "Failed",
            .rescheduled => "Rescheduled",
        };
    }
};

/// Recurrence pattern
pub const RecurrencePattern = enum {
    /// One-time send
    none,
    /// Every day
    daily,
    /// Every week
    weekly,
    /// Every two weeks
    biweekly,
    /// Every month
    monthly,
    /// Custom interval (in seconds)
    custom,

    pub fn toString(self: RecurrencePattern) []const u8 {
        return switch (self) {
            .none => "One-time",
            .daily => "Daily",
            .weekly => "Weekly",
            .biweekly => "Bi-weekly",
            .monthly => "Monthly",
            .custom => "Custom",
        };
    }

    /// Get interval in seconds
    pub fn getInterval(self: RecurrencePattern) ?i64 {
        return switch (self) {
            .none => null,
            .daily => 24 * 60 * 60,
            .weekly => 7 * 24 * 60 * 60,
            .biweekly => 14 * 24 * 60 * 60,
            .monthly => 30 * 24 * 60 * 60, // Approximate
            .custom => null,
        };
    }
};

/// Scheduled email
pub const ScheduledEmail = struct {
    /// Unique schedule ID
    id: []const u8,
    /// Recipients (comma-separated)
    recipients: []const u8,
    /// CC recipients
    cc: ?[]const u8,
    /// BCC recipients
    bcc: ?[]const u8,
    /// Email subject
    subject: []const u8,
    /// Email body (text)
    body_text: []const u8,
    /// Email body (HTML)
    body_html: ?[]const u8,
    /// Attachment IDs
    attachment_ids: ?[]const u8,
    /// Scheduled send time (Unix timestamp)
    send_at: i64,
    /// Recurrence pattern
    recurrence: RecurrencePattern,
    /// Custom interval for recurrence (seconds)
    custom_interval: ?i64,
    /// Number of times to repeat (null = infinite)
    repeat_count: ?u32,
    /// Current repeat iteration
    current_iteration: u32,
    /// Timezone offset (seconds from UTC)
    timezone_offset: i32,
    /// Current status
    status: ScheduleStatus,
    /// When schedule was created
    created_at: i64,
    /// When last modified
    updated_at: i64,
    /// When actually sent (if sent)
    sent_at: ?i64,
    /// Error message if failed
    error_message: ?[]const u8,

    pub fn toJson(self: *const ScheduledEmail, allocator: std.mem.Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        errdefer buffer.deinit();
        const writer = buffer.writer();

        try writer.writeAll("{");
        try writer.print("\"id\":\"{s}\",", .{self.id});
        try writer.print("\"recipients\":\"{s}\",", .{self.recipients});
        try writer.print("\"subject\":\"{s}\",", .{escapeJson(self.subject)});
        try writer.print("\"send_at\":{d},", .{self.send_at});
        try writer.print("\"recurrence\":\"{s}\",", .{self.recurrence.toString()});
        try writer.print("\"status\":\"{s}\",", .{self.status.toString()});
        try writer.print("\"created_at\":{d},", .{self.created_at});

        if (self.sent_at) |t| {
            try writer.print("\"sent_at\":{d},", .{t});
        } else {
            try writer.writeAll("\"sent_at\":null,");
        }

        // Time until send
        const now = std.time.timestamp();
        const time_until = self.send_at - now;
        try writer.print("\"time_until_send\":{d}", .{if (time_until > 0) time_until else 0});

        try writer.writeAll("}");
        return buffer.toOwnedSlice();
    }

    /// Check if it's time to send
    pub fn isReadyToSend(self: *const ScheduledEmail) bool {
        if (self.status != .pending) return false;
        return std.time.timestamp() >= self.send_at;
    }

    /// Get next send time for recurring emails
    pub fn getNextSendTime(self: *const ScheduledEmail) ?i64 {
        if (self.recurrence == .none) return null;

        // Check repeat limit
        if (self.repeat_count) |count| {
            if (self.current_iteration >= count) return null;
        }

        const interval = if (self.recurrence == .custom)
            self.custom_interval orelse return null
        else
            self.recurrence.getInterval() orelse return null;

        return self.send_at + interval;
    }
};

/// Email scheduler
pub const EmailScheduler = struct {
    allocator: std.mem.Allocator,
    schedules: std.StringHashMap(ScheduledEmail),
    config: SchedulerConfig,

    pub const SchedulerConfig = struct {
        /// Maximum scheduled emails
        max_schedules: usize = 100,
        /// Check interval for due emails (seconds)
        check_interval: u32 = 60,
        /// Maximum future schedule time (seconds)
        max_future_time: i64 = 365 * 24 * 60 * 60, // 1 year
    };

    pub fn init(allocator: std.mem.Allocator, config: SchedulerConfig) EmailScheduler {
        return .{
            .allocator = allocator,
            .schedules = std.StringHashMap(ScheduledEmail).init(allocator),
            .config = config,
        };
    }

    pub fn deinit(self: *EmailScheduler) void {
        var it = self.schedules.iterator();
        while (it.next()) |entry| {
            self.freeSchedule(entry.key_ptr.*, entry.value_ptr.*);
        }
        self.schedules.deinit();
    }

    fn freeSchedule(self: *EmailScheduler, key: []const u8, sched: ScheduledEmail) void {
        self.allocator.free(key);
        self.allocator.free(sched.id);
        self.allocator.free(sched.recipients);
        if (sched.cc) |c| self.allocator.free(c);
        if (sched.bcc) |b| self.allocator.free(b);
        self.allocator.free(sched.subject);
        self.allocator.free(sched.body_text);
        if (sched.body_html) |h| self.allocator.free(h);
        if (sched.attachment_ids) |a| self.allocator.free(a);
        if (sched.error_message) |e| self.allocator.free(e);
    }

    /// Schedule an email
    pub fn schedule(
        self: *EmailScheduler,
        recipients: []const u8,
        subject: []const u8,
        body_text: []const u8,
        send_at: i64,
        options: ScheduleOptions,
    ) ![]const u8 {
        if (self.schedules.count() >= self.config.max_schedules) {
            return ScheduleError.QueueFull;
        }

        const now = std.time.timestamp();
        if (send_at <= now) {
            return ScheduleError.PastTime;
        }

        if (send_at - now > self.config.max_future_time) {
            return ScheduleError.InvalidTime;
        }

        var rand_bytes: [8]u8 = undefined;
        std.c.arc4random_buf(&rand_bytes, rand_bytes.len);

        const id = try std.fmt.allocPrint(self.allocator, "sched_{x}_{x}", .{
            @as(u64, @intCast(now)),
            std.mem.readInt(u64, &rand_bytes, .big),
        });
        errdefer self.allocator.free(id);

        const sched = ScheduledEmail{
            .id = id,
            .recipients = try self.allocator.dupe(u8, recipients),
            .cc = if (options.cc) |c| try self.allocator.dupe(u8, c) else null,
            .bcc = if (options.bcc) |b| try self.allocator.dupe(u8, b) else null,
            .subject = try self.allocator.dupe(u8, subject),
            .body_text = try self.allocator.dupe(u8, body_text),
            .body_html = if (options.body_html) |h| try self.allocator.dupe(u8, h) else null,
            .attachment_ids = if (options.attachment_ids) |a| try self.allocator.dupe(u8, a) else null,
            .send_at = send_at,
            .recurrence = options.recurrence,
            .custom_interval = options.custom_interval,
            .repeat_count = options.repeat_count,
            .current_iteration = 0,
            .timezone_offset = options.timezone_offset,
            .status = .pending,
            .created_at = now,
            .updated_at = now,
            .sent_at = null,
            .error_message = null,
        };

        const key = try self.allocator.dupe(u8, id);
        try self.schedules.put(key, sched);

        return id;
    }

    pub const ScheduleOptions = struct {
        cc: ?[]const u8 = null,
        bcc: ?[]const u8 = null,
        body_html: ?[]const u8 = null,
        attachment_ids: ?[]const u8 = null,
        recurrence: RecurrencePattern = .none,
        custom_interval: ?i64 = null,
        repeat_count: ?u32 = null,
        timezone_offset: i32 = 0,
    };

    /// Get scheduled email by ID
    pub fn get(self: *const EmailScheduler, id: []const u8) ?*const ScheduledEmail {
        return self.schedules.getPtr(id);
    }

    /// Cancel a scheduled email
    pub fn cancel(self: *EmailScheduler, id: []const u8) !void {
        if (self.schedules.getPtr(id)) |sched| {
            if (sched.status == .sent) return ScheduleError.AlreadySent;
            sched.status = .cancelled;
            sched.updated_at = std.time.timestamp();
        } else {
            return ScheduleError.ScheduleNotFound;
        }
    }

    /// Reschedule to a new time
    pub fn reschedule(self: *EmailScheduler, id: []const u8, new_send_at: i64) !void {
        const now = std.time.timestamp();
        if (new_send_at <= now) return ScheduleError.PastTime;

        if (self.schedules.getPtr(id)) |sched| {
            if (sched.status == .sent) return ScheduleError.AlreadySent;
            sched.send_at = new_send_at;
            sched.status = .pending;
            sched.updated_at = now;
        } else {
            return ScheduleError.ScheduleNotFound;
        }
    }

    /// Get all emails due for sending
    pub fn getDueEmails(self: *const EmailScheduler, allocator: std.mem.Allocator) ![]const ScheduledEmail {
        var count: usize = 0;
        var it = self.schedules.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.isReadyToSend()) {
                count += 1;
            }
        }

        var result = try allocator.alloc(ScheduledEmail, count);
        var i: usize = 0;

        it = self.schedules.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.isReadyToSend()) {
                result[i] = entry.value_ptr.*;
                i += 1;
            }
        }

        return result;
    }

    /// Mark as sent
    pub fn markSent(self: *EmailScheduler, id: []const u8) !void {
        if (self.schedules.getPtr(id)) |sched| {
            const now = std.time.timestamp();
            sched.status = .sent;
            sched.sent_at = now;
            sched.updated_at = now;

            // Handle recurrence
            if (sched.getNextSendTime()) |next_time| {
                sched.send_at = next_time;
                sched.status = .pending;
                sched.current_iteration += 1;
                sched.sent_at = null;
            }
        } else {
            return ScheduleError.ScheduleNotFound;
        }
    }

    /// Mark as failed
    pub fn markFailed(self: *EmailScheduler, id: []const u8, error_msg: []const u8) !void {
        if (self.schedules.getPtr(id)) |sched| {
            sched.status = .failed;
            sched.updated_at = std.time.timestamp();
            if (sched.error_message) |old| self.allocator.free(old);
            sched.error_message = try self.allocator.dupe(u8, error_msg);
        } else {
            return ScheduleError.ScheduleNotFound;
        }
    }

    /// Get all pending schedules
    pub fn getPending(self: *const EmailScheduler, allocator: std.mem.Allocator) ![]const ScheduledEmail {
        var count: usize = 0;
        var it = self.schedules.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.status == .pending) {
                count += 1;
            }
        }

        var result = try allocator.alloc(ScheduledEmail, count);
        var i: usize = 0;

        it = self.schedules.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.status == .pending) {
                result[i] = entry.value_ptr.*;
                i += 1;
            }
        }

        // Sort by send_at
        std.mem.sort(ScheduledEmail, result, {}, struct {
            fn lessThan(_: void, a: ScheduledEmail, b: ScheduledEmail) bool {
                return a.send_at < b.send_at;
            }
        }.lessThan);

        return result;
    }

    /// Get all schedules
    pub fn getAll(self: *const EmailScheduler, allocator: std.mem.Allocator) ![]const ScheduledEmail {
        var result = try allocator.alloc(ScheduledEmail, self.schedules.count());
        var i: usize = 0;

        var it = self.schedules.iterator();
        while (it.next()) |entry| {
            result[i] = entry.value_ptr.*;
            i += 1;
        }

        return result;
    }

    /// Delete a schedule
    pub fn delete(self: *EmailScheduler, id: []const u8) !void {
        if (self.schedules.fetchRemove(id)) |entry| {
            self.freeSchedule(entry.key, entry.value);
        } else {
            return ScheduleError.ScheduleNotFound;
        }
    }

    /// Get statistics
    pub fn getStats(self: *const EmailScheduler) SchedulerStats {
        var pending: usize = 0;
        var sent: usize = 0;
        var failed: usize = 0;
        var recurring: usize = 0;

        var it = self.schedules.iterator();
        while (it.next()) |entry| {
            switch (entry.value_ptr.status) {
                .pending => pending += 1,
                .sent => sent += 1,
                .failed => failed += 1,
                else => {},
            }
            if (entry.value_ptr.recurrence != .none) {
                recurring += 1;
            }
        }

        return .{
            .total = self.schedules.count(),
            .pending = pending,
            .sent = sent,
            .failed = failed,
            .recurring = recurring,
        };
    }
};

/// Scheduler statistics
pub const SchedulerStats = struct {
    total: usize,
    pending: usize,
    sent: usize,
    failed: usize,
    recurring: usize,
};

/// Format timestamp for display
pub fn formatSendTime(timestamp: i64, allocator: std.mem.Allocator) ![]u8 {
    const epoch_seconds = @as(u64, @intCast(timestamp));
    const days_since_epoch = epoch_seconds / 86400;
    const seconds_today = epoch_seconds % 86400;
    const hours = seconds_today / 3600;
    const minutes = (seconds_today % 3600) / 60;

    // Simple date calculation
    var year: u32 = 1970;
    var remaining_days = days_since_epoch;

    while (true) {
        const days_in_year: u64 = if (isLeapYear(year)) 366 else 365;
        if (remaining_days < days_in_year) break;
        remaining_days -= days_in_year;
        year += 1;
    }

    const months = [_]u32{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    var month: u32 = 1;
    for (months, 0..) |days, i| {
        var d = days;
        if (i == 1 and isLeapYear(year)) d = 29;
        if (remaining_days < d) break;
        remaining_days -= d;
        month += 1;
    }

    const day = @as(u32, @intCast(remaining_days)) + 1;

    return std.fmt.allocPrint(allocator, "{d}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}", .{
        year,
        month,
        day,
        @as(u32, @intCast(hours)),
        @as(u32, @intCast(minutes)),
    });
}

fn isLeapYear(year: u32) bool {
    return (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0);
}

fn escapeJson(s: []const u8) []const u8 {
    return s;
}

// =============================================================================
// Tests
// =============================================================================

test "EmailScheduler schedule and get" {
    const allocator = std.testing.allocator;

    var scheduler = EmailScheduler.init(allocator, .{});
    defer scheduler.deinit();

    const future = std.time.timestamp() + 3600; // 1 hour from now
    const id = try scheduler.schedule(
        "test@example.com",
        "Test Subject",
        "Test body",
        future,
        .{},
    );

    const sched = scheduler.get(id);
    try std.testing.expect(sched != null);
    try std.testing.expectEqual(ScheduleStatus.pending, sched.?.status);
}

test "EmailScheduler cancel" {
    const allocator = std.testing.allocator;

    var scheduler = EmailScheduler.init(allocator, .{});
    defer scheduler.deinit();

    const future = std.time.timestamp() + 3600;
    const id = try scheduler.schedule("test@example.com", "Test", "Body", future, .{});

    try scheduler.cancel(id);

    const sched = scheduler.get(id);
    try std.testing.expectEqual(ScheduleStatus.cancelled, sched.?.status);
}

test "EmailScheduler past time rejected" {
    const allocator = std.testing.allocator;

    var scheduler = EmailScheduler.init(allocator, .{});
    defer scheduler.deinit();

    const past = std.time.timestamp() - 3600;
    const result = scheduler.schedule("test@example.com", "Test", "Body", past, .{});
    try std.testing.expectError(ScheduleError.PastTime, result);
}

test "RecurrencePattern intervals" {
    try std.testing.expectEqual(@as(?i64, 24 * 60 * 60), RecurrencePattern.daily.getInterval());
    try std.testing.expectEqual(@as(?i64, 7 * 24 * 60 * 60), RecurrencePattern.weekly.getInterval());
    try std.testing.expectEqual(@as(?i64, null), RecurrencePattern.none.getInterval());
}
