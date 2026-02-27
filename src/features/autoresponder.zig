const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");

/// Auto-responder rule for vacation/out-of-office messages
pub const AutoResponderRule = struct {
    allocator: std.mem.Allocator,
    email: []const u8,
    subject: []const u8,
    message: []const u8,
    enabled: bool,
    start_date: ?i64, // Unix timestamp
    end_date: ?i64, // Unix timestamp
    response_limit: ?usize, // Max responses per sender (to prevent loops)
    sent_responses: std.StringHashMap(ResponseRecord),

    pub fn init(
        allocator: std.mem.Allocator,
        email: []const u8,
        subject: []const u8,
        message: []const u8,
    ) !AutoResponderRule {
        return .{
            .allocator = allocator,
            .email = try allocator.dupe(u8, email),
            .subject = try allocator.dupe(u8, subject),
            .message = try allocator.dupe(u8, message),
            .enabled = false,
            .start_date = null,
            .end_date = null,
            .response_limit = 1, // Default: one response per sender
            .sent_responses = std.StringHashMap(ResponseRecord).init(allocator),
        };
    }

    pub fn deinit(self: *AutoResponderRule) void {
        self.allocator.free(self.email);
        self.allocator.free(self.subject);
        self.allocator.free(self.message);

        var it = self.sent_responses.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.sent_responses.deinit();
    }

    /// Enable the auto-responder
    pub fn enable(self: *AutoResponderRule) void {
        self.enabled = true;
    }

    /// Disable the auto-responder
    pub fn disable(self: *AutoResponderRule) void {
        self.enabled = false;
    }

    /// Set date range for the auto-responder
    pub fn setDateRange(self: *AutoResponderRule, start: i64, end: i64) void {
        self.start_date = start;
        self.end_date = end;
    }

    /// Check if the auto-responder should be triggered
    pub fn shouldRespond(self: *AutoResponderRule, from_email: []const u8, to_email: []const u8) !bool {
        if (!self.enabled) return false;

        // Check if the recipient matches this rule
        if (!std.mem.eql(u8, to_email, self.email)) return false;

        // Check date range
        const now = time_compat.timestamp();
        if (self.start_date) |start| {
            if (now < start) return false;
        }
        if (self.end_date) |end| {
            if (now > end) return false;
        }

        // Check response limit
        if (self.response_limit) |limit| {
            const gop = try self.sent_responses.getOrPut(try self.allocator.dupe(u8, from_email));
            if (!gop.found_existing) {
                gop.value_ptr.* = ResponseRecord{
                    .count = 0,
                    .last_sent = 0,
                };
            }

            if (gop.value_ptr.count >= limit) {
                return false;
            }
        }

        return true;
    }

    /// Record that a response was sent
    pub fn recordResponse(self: *AutoResponderRule, from_email: []const u8) !void {
        const gop = try self.sent_responses.getOrPut(try self.allocator.dupe(u8, from_email));
        if (!gop.found_existing) {
            gop.value_ptr.* = ResponseRecord{
                .count = 0,
                .last_sent = 0,
            };
        }

        gop.value_ptr.count += 1;
        gop.value_ptr.last_sent = time_compat.timestamp();
    }

    /// Generate auto-response message
    pub fn generateResponse(self: *AutoResponderRule, from_email: []const u8) ![]const u8 {
        var response = std.ArrayList(u8).init(self.allocator);
        defer response.deinit();

        // Email headers
        try std.fmt.format(response.writer(), "From: {s}\r\n", .{self.email});
        try std.fmt.format(response.writer(), "To: {s}\r\n", .{from_email});
        try std.fmt.format(response.writer(), "Subject: {s}\r\n", .{self.subject});
        try response.appendSlice("Auto-Submitted: auto-replied\r\n"); // RFC 3834
        try response.appendSlice("Precedence: bulk\r\n");
        try response.appendSlice("Content-Type: text/plain; charset=UTF-8\r\n");
        try response.appendSlice("\r\n");

        // Message body
        try response.appendSlice(self.message);

        return try response.toOwnedSlice();
    }

    /// Reset response counters (useful for testing or manual reset)
    pub fn resetCounters(self: *AutoResponderRule) void {
        var it = self.sent_responses.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.sent_responses.clearRetainingCapacity();
    }
};

pub const ResponseRecord = struct {
    count: usize,
    last_sent: i64,
};

/// Auto-responder manager
pub const AutoResponderManager = struct {
    allocator: std.mem.Allocator,
    rules: std.ArrayList(*AutoResponderRule),
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator) AutoResponderManager {
        return .{
            .allocator = allocator,
            .rules = std.ArrayList(*AutoResponderRule).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *AutoResponderManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.rules.items) |rule| {
            rule.deinit();
            self.allocator.destroy(rule);
        }
        self.rules.deinit();
    }

    /// Add an auto-responder rule
    pub fn addRule(self: *AutoResponderManager, rule: *AutoResponderRule) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.rules.append(rule);
    }

    /// Remove an auto-responder rule by email
    pub fn removeRule(self: *AutoResponderManager, email: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.rules.items, 0..) |rule, i| {
            if (std.mem.eql(u8, rule.email, email)) {
                _ = self.rules.swapRemove(i);
                rule.deinit();
                self.allocator.destroy(rule);
                return;
            }
        }

        return error.RuleNotFound;
    }

    /// Process an incoming message and generate auto-responses if needed
    pub fn processMessage(
        self: *AutoResponderManager,
        from_email: []const u8,
        to_email: []const u8,
    ) !?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Skip auto-responses for certain sender patterns (to prevent loops)
        if (self.shouldSkipSender(from_email)) {
            return null;
        }

        // Find matching rule
        for (self.rules.items) |rule| {
            if (try rule.shouldRespond(from_email, to_email)) {
                const response = try rule.generateResponse(from_email);
                try rule.recordResponse(from_email);
                return response;
            }
        }

        return null;
    }

    /// Check if sender should be skipped (to prevent auto-response loops)
    fn shouldSkipSender(self: *AutoResponderManager, email: []const u8) bool {
        _ = self;

        // Skip common automated senders
        const skip_patterns = [_][]const u8{
            "noreply@",
            "no-reply@",
            "mailer-daemon@",
            "postmaster@",
            "bounce@",
            "automated@",
        };

        const lower_email = std.ascii.allocLowerString(self.allocator, email) catch return false;
        defer self.allocator.free(lower_email);

        for (skip_patterns) |pattern| {
            if (std.mem.indexOf(u8, lower_email, pattern)) |_| {
                return true;
            }
        }

        return false;
    }

    /// Get all rules
    pub fn getRules(self: *AutoResponderManager) []*AutoResponderRule {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.rules.items;
    }
};

test "auto-responder rule creation" {
    const testing = std.testing;

    var rule = try AutoResponderRule.init(
        testing.allocator,
        "user@example.com",
        "Out of Office",
        "I'm currently out of office and will return on Monday.",
    );
    defer rule.deinit();

    try testing.expectEqualStrings("user@example.com", rule.email);
    try testing.expect(!rule.enabled);
}

test "auto-responder enable/disable" {
    const testing = std.testing;

    var rule = try AutoResponderRule.init(
        testing.allocator,
        "user@example.com",
        "Out of Office",
        "I'm currently out of office.",
    );
    defer rule.deinit();

    rule.enable();
    try testing.expect(rule.enabled);

    rule.disable();
    try testing.expect(!rule.enabled);
}

test "auto-responder should respond" {
    const testing = std.testing;

    var rule = try AutoResponderRule.init(
        testing.allocator,
        "user@example.com",
        "Out of Office",
        "I'm currently out of office.",
    );
    defer rule.deinit();

    // Disabled rule should not respond
    try testing.expect(!try rule.shouldRespond("sender@example.com", "user@example.com"));

    // Enabled rule should respond
    rule.enable();
    try testing.expect(try rule.shouldRespond("sender@example.com", "user@example.com"));

    // Different recipient should not trigger response
    try testing.expect(!try rule.shouldRespond("sender@example.com", "other@example.com"));
}

test "auto-responder response limit" {
    const testing = std.testing;

    var rule = try AutoResponderRule.init(
        testing.allocator,
        "user@example.com",
        "Out of Office",
        "I'm currently out of office.",
    );
    defer rule.deinit();

    rule.enable();
    rule.response_limit = 2;

    // First two responses should be allowed
    try testing.expect(try rule.shouldRespond("sender@example.com", "user@example.com"));
    try rule.recordResponse("sender@example.com");

    try testing.expect(try rule.shouldRespond("sender@example.com", "user@example.com"));
    try rule.recordResponse("sender@example.com");

    // Third response should be blocked
    try testing.expect(!try rule.shouldRespond("sender@example.com", "user@example.com"));
}

test "auto-responder date range" {
    const testing = std.testing;

    var rule = try AutoResponderRule.init(
        testing.allocator,
        "user@example.com",
        "Out of Office",
        "I'm currently out of office.",
    );
    defer rule.deinit();

    rule.enable();

    // Set date range in the past
    const past_start = time_compat.timestamp() - 86400 * 7; // 7 days ago
    const past_end = time_compat.timestamp() - 86400; // 1 day ago
    rule.setDateRange(past_start, past_end);

    // Should not respond (date range is in the past)
    try testing.expect(!try rule.shouldRespond("sender@example.com", "user@example.com"));
}

test "auto-responder generate response" {
    const testing = std.testing;

    var rule = try AutoResponderRule.init(
        testing.allocator,
        "user@example.com",
        "Out of Office",
        "I'm currently out of office.",
    );
    defer rule.deinit();

    const response = try rule.generateResponse("sender@example.com");
    defer testing.allocator.free(response);

    try testing.expect(std.mem.indexOf(u8, response, "From: user@example.com") != null);
    try testing.expect(std.mem.indexOf(u8, response, "To: sender@example.com") != null);
    try testing.expect(std.mem.indexOf(u8, response, "Subject: Out of Office") != null);
    try testing.expect(std.mem.indexOf(u8, response, "Auto-Submitted: auto-replied") != null);
    try testing.expect(std.mem.indexOf(u8, response, "I'm currently out of office.") != null);
}

test "auto-responder manager" {
    const testing = std.testing;

    var manager = AutoResponderManager.init(testing.allocator);
    defer manager.deinit();

    var rule = try testing.allocator.create(AutoResponderRule);
    rule.* = try AutoResponderRule.init(
        testing.allocator,
        "user@example.com",
        "Out of Office",
        "I'm currently out of office.",
    );
    rule.enable();

    try manager.addRule(rule);

    const response = try manager.processMessage("sender@example.com", "user@example.com");
    if (response) |r| {
        defer testing.allocator.free(r);
        try testing.expect(std.mem.indexOf(u8, r, "Out of Office") != null);
    }
}

test "auto-responder skip automated senders" {
    const testing = std.testing;

    var manager = AutoResponderManager.init(testing.allocator);
    defer manager.deinit();

    // These senders should be skipped
    try testing.expect(manager.shouldSkipSender("noreply@example.com"));
    try testing.expect(manager.shouldSkipSender("no-reply@example.com"));
    try testing.expect(manager.shouldSkipSender("mailer-daemon@example.com"));
    try testing.expect(manager.shouldSkipSender("postmaster@example.com"));
    try testing.expect(manager.shouldSkipSender("bounce@example.com"));

    // Regular senders should not be skipped
    try testing.expect(!manager.shouldSkipSender("user@example.com"));
}
