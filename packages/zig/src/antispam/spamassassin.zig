const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");

/// SpamAssassin spam filtering integration
/// Scans email messages for spam using SpamAssassin daemon (spamd)
pub const SpamAssassinScanner = struct {
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    timeout_ms: u32,
    enabled: bool,
    stats: ScanStats,
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator, host: []const u8, port: u16, timeout_ms: u32) !SpamAssassinScanner {
        return .{
            .allocator = allocator,
            .host = try allocator.dupe(u8, host),
            .port = port,
            .timeout_ms = timeout_ms,
            .enabled = true,
            .stats = ScanStats{},
            .mutex = .{},
        };
    }

    pub fn deinit(self: *SpamAssassinScanner) void {
        self.allocator.free(self.host);
    }

    /// Scan a message for spam
    pub fn scanMessage(self: *SpamAssassinScanner, message: []const u8) !ScanResult {
        if (!self.enabled) {
            return ScanResult{
                .is_spam = false,
                .score = 0.0,
                .threshold = 0.0,
                .symbols = null,
                .scan_time_ms = 0,
            };
        }

        const start = std.time.milliTimestamp();

        // Connect to spamd
        const address = try std.net.Address.parseIp(self.host, self.port);
        const stream = try std.net.tcpConnectToAddress(address);
        defer stream.close();

        // Send SYMBOLS SPAMC/1.5 request
        var request = std.ArrayList(u8).init(self.allocator);
        defer request.deinit(self.allocator);

        try std.fmt.format(request.writer(self.allocator), "SYMBOLS SPAMC/1.5\r\nContent-length: {d}\r\n\r\n", .{message.len});
        try request.appendSlice(self.allocator, message);

        try stream.writeAll(request.items);

        // Read response
        var response_buf: [8192]u8 = undefined;
        const bytes_read = try stream.read(&response_buf);
        const response = response_buf[0..bytes_read];

        const scan_time = std.time.milliTimestamp() - start;

        // Update statistics
        self.mutex.lock();
        defer self.mutex.unlock();
        self.stats.total_scans += 1;

        // Parse response
        return try self.parseResponse(response, scan_time);
    }

    /// Check a message (faster, less detailed than scanMessage)
    pub fn checkMessage(self: *SpamAssassinScanner, message: []const u8) !ScanResult {
        if (!self.enabled) {
            return ScanResult{
                .is_spam = false,
                .score = 0.0,
                .threshold = 0.0,
                .symbols = null,
                .scan_time_ms = 0,
            };
        }

        const start = std.time.milliTimestamp();

        // Connect to spamd
        const address = try std.net.Address.parseIp(self.host, self.port);
        const stream = try std.net.tcpConnectToAddress(address);
        defer stream.close();

        // Send CHECK request (faster, only returns spam/ham)
        var request = std.ArrayList(u8).init(self.allocator);
        defer request.deinit(self.allocator);

        try std.fmt.format(request.writer(self.allocator), "CHECK SPAMC/1.5\r\nContent-length: {d}\r\n\r\n", .{message.len});
        try request.appendSlice(self.allocator, message);

        try stream.writeAll(request.items);

        // Read response
        var response_buf: [4096]u8 = undefined;
        const bytes_read = try stream.read(&response_buf);
        const response = response_buf[0..bytes_read];

        const scan_time = std.time.milliTimestamp() - start;

        // Update statistics
        self.mutex.lock();
        defer self.mutex.unlock();
        self.stats.total_scans += 1;

        return try self.parseResponse(response, scan_time);
    }

    /// Report a message as spam (train Bayes filter)
    pub fn reportSpam(self: *SpamAssassinScanner, message: []const u8) !void {
        if (!self.enabled) return;

        const address = try std.net.Address.parseIp(self.host, self.port);
        const stream = try std.net.tcpConnectToAddress(address);
        defer stream.close();

        var request = std.ArrayList(u8).init(self.allocator);
        defer request.deinit(self.allocator);

        try std.fmt.format(request.writer(self.allocator), "TELL SPAMC/1.5\r\nMessage-class: spam\r\nSet: local\r\nContent-length: {d}\r\n\r\n", .{message.len});
        try request.appendSlice(self.allocator, message);

        try stream.writeAll(request.items);

        // Read response (just to confirm)
        var response_buf: [256]u8 = undefined;
        _ = try stream.read(&response_buf);
    }

    /// Report a message as ham (train Bayes filter)
    pub fn reportHam(self: *SpamAssassinScanner, message: []const u8) !void {
        if (!self.enabled) return;

        const address = try std.net.Address.parseIp(self.host, self.port);
        const stream = try std.net.tcpConnectToAddress(address);
        defer stream.close();

        var request = std.ArrayList(u8).init(self.allocator);
        defer request.deinit(self.allocator);

        try std.fmt.format(request.writer(self.allocator), "TELL SPAMC/1.5\r\nMessage-class: ham\r\nSet: local\r\nContent-length: {d}\r\n\r\n", .{message.len});
        try request.appendSlice(self.allocator, message);

        try stream.writeAll(request.items);

        var response_buf: [256]u8 = undefined;
        _ = try stream.read(&response_buf);
    }

    /// Ping spamd to check if it's alive
    pub fn ping(self: *SpamAssassinScanner) !bool {
        const address = try std.net.Address.parseIp(self.host, self.port);
        const stream = std.net.tcpConnectToAddress(address) catch return false;
        defer stream.close();

        try stream.writeAll("PING SPAMC/1.5\r\n\r\n");

        var response_buf: [256]u8 = undefined;
        const bytes_read = try stream.read(&response_buf);
        const response = response_buf[0..bytes_read];

        return std.mem.indexOf(u8, response, "PONG") != null;
    }

    /// Parse SpamAssassin response
    fn parseResponse(self: *SpamAssassinScanner, response: []const u8, scan_time: i64) !ScanResult {
        var result = ScanResult{
            .is_spam = false,
            .score = 0.0,
            .threshold = 5.0,
            .symbols = null,
            .scan_time_ms = scan_time,
        };

        // Parse response headers
        var lines = std.mem.splitScalar(u8, response, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \r\n\t");
            if (trimmed.len == 0) break; // End of headers

            // Look for Spam: header
            if (std.mem.startsWith(u8, trimmed, "Spam:")) {
                if (std.mem.indexOf(u8, trimmed, "True")) |_| {
                    result.is_spam = true;
                    self.stats.spam_messages += 1;
                } else {
                    self.stats.ham_messages += 1;
                }

                // Extract score (format: "Spam: True ; score / threshold")
                if (std.mem.indexOf(u8, trimmed, ";")) |semicolon| {
                    const score_part = trimmed[semicolon + 1 ..];
                    if (std.mem.indexOf(u8, score_part, "/")) |slash| {
                        const score_str = std.mem.trim(u8, score_part[0..slash], " \t");
                        const threshold_str = std.mem.trim(u8, score_part[slash + 1 ..], " \t");

                        result.score = std.fmt.parseFloat(f64, score_str) catch 0.0;
                        result.threshold = std.fmt.parseFloat(f64, threshold_str) catch 5.0;
                    }
                }
            }

            // Extract symbols/rules that matched
            if (std.mem.indexOf(u8, trimmed, ":")) |colon| {
                const header_name = trimmed[0..colon];
                if (std.mem.eql(u8, header_name, "Symbols")) {
                    const symbols_str = std.mem.trim(u8, trimmed[colon + 1 ..], " \t");
                    result.symbols = try self.allocator.dupe(u8, symbols_str);
                }
            }
        }

        return result;
    }

    /// Get scanning statistics
    pub fn getStats(self: *SpamAssassinScanner) ScanStats {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.stats;
    }

    /// Reset statistics
    pub fn resetStats(self: *SpamAssassinScanner) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.stats = ScanStats{};
    }

    /// Enable/disable scanning
    pub fn setEnabled(self: *SpamAssassinScanner, enabled: bool) void {
        self.enabled = enabled;
    }
};

pub const ScanResult = struct {
    is_spam: bool,
    score: f64,
    threshold: f64,
    symbols: ?[]const u8, // Comma-separated list of rules that matched
    scan_time_ms: i64,

    pub fn deinit(self: *ScanResult, allocator: std.mem.Allocator) void {
        if (self.symbols) |symbols| {
            allocator.free(symbols);
        }
    }
};

pub const ScanStats = struct {
    total_scans: usize = 0,
    spam_messages: usize = 0,
    ham_messages: usize = 0,
    errors: usize = 0,
};

/// Action to take when spam is detected
pub const SpamAction = enum {
    reject, // Reject the message
    quarantine, // Move to spam folder
    tag, // Add X-Spam headers and deliver
    discard, // Silently discard
    rewrite_subject, // Add [SPAM] to subject

    pub fn toString(self: SpamAction) []const u8 {
        return switch (self) {
            .reject => "reject",
            .quarantine => "quarantine",
            .tag => "tag",
            .discard => "discard",
            .rewrite_subject => "rewrite_subject",
        };
    }
};

/// Spam scanning policy
pub const SpamPolicy = struct {
    scan_enabled: bool = true,
    scan_threshold: f64 = 5.0, // Score above this is spam
    action_on_spam: SpamAction = .tag,
    action_on_error: SpamAction = .tag, // What to do if scanning fails
    quarantine_path: ?[]const u8 = null,
    tag_header_name: []const u8 = "X-Spam-Status",
    subject_prefix: []const u8 = "[SPAM] ",
    auto_learn: bool = true, // Automatically train Bayes filter
    required_score: f64 = 5.0, // SpamAssassin required_score setting

    pub fn shouldScan(self: *const SpamPolicy) bool {
        return self.scan_enabled;
    }

    pub fn isSpam(self: *const SpamPolicy, score: f64) bool {
        return score >= self.scan_threshold;
    }
};

/// SpamAssassin configuration for different user tiers
pub const SpamPolicyPreset = enum {
    strict, // Low threshold, aggressive filtering
    standard, // Normal threshold
    permissive, // High threshold, fewer false positives

    pub fn toPolicy(self: SpamPolicyPreset) SpamPolicy {
        return switch (self) {
            .strict => SpamPolicy{
                .scan_threshold = 3.0,
                .required_score = 3.0,
                .action_on_spam = .quarantine,
            },
            .standard => SpamPolicy{
                .scan_threshold = 5.0,
                .required_score = 5.0,
                .action_on_spam = .tag,
            },
            .permissive => SpamPolicy{
                .scan_threshold = 8.0,
                .required_score = 8.0,
                .action_on_spam = .rewrite_subject,
            },
        };
    }
};

test "SpamAssassin scanner initialization" {
    const testing = std.testing;

    var scanner = try SpamAssassinScanner.init(testing.allocator, "localhost", 783, 5000);
    defer scanner.deinit();

    try testing.expectEqualStrings("localhost", scanner.host);
    try testing.expectEqual(@as(u16, 783), scanner.port);
    try testing.expect(scanner.enabled);
}

test "scan result struct" {
    const testing = std.testing;

    var result = ScanResult{
        .is_spam = true,
        .score = 7.5,
        .threshold = 5.0,
        .symbols = try testing.allocator.dupe(u8, "BAYES_99,URIBL_BLACK"),
        .scan_time_ms = 42,
    };
    defer result.deinit(testing.allocator);

    try testing.expect(result.is_spam);
    try testing.expectEqual(@as(f64, 7.5), result.score);
    try testing.expectEqualStrings("BAYES_99,URIBL_BLACK", result.symbols.?);
}

test "spam policy" {
    const testing = std.testing;

    const policy = SpamPolicy{};

    try testing.expect(policy.shouldScan());
    try testing.expect(policy.isSpam(6.0));
    try testing.expect(!policy.isSpam(4.0));
}

test "spam action enum" {
    const testing = std.testing;

    try testing.expectEqualStrings("reject", SpamAction.reject.toString());
    try testing.expectEqualStrings("quarantine", SpamAction.quarantine.toString());
    try testing.expectEqualStrings("tag", SpamAction.tag.toString());
    try testing.expectEqualStrings("rewrite_subject", SpamAction.rewrite_subject.toString());
}

test "spam policy presets" {
    const testing = std.testing;

    const strict = SpamPolicyPreset.strict.toPolicy();
    try testing.expectEqual(@as(f64, 3.0), strict.scan_threshold);
    try testing.expectEqual(SpamAction.quarantine, strict.action_on_spam);

    const standard = SpamPolicyPreset.standard.toPolicy();
    try testing.expectEqual(@as(f64, 5.0), standard.scan_threshold);

    const permissive = SpamPolicyPreset.permissive.toPolicy();
    try testing.expectEqual(@as(f64, 8.0), permissive.scan_threshold);
}

test "scanner statistics" {
    const testing = std.testing;

    var scanner = try SpamAssassinScanner.init(testing.allocator, "localhost", 783, 5000);
    defer scanner.deinit();

    const stats = scanner.getStats();
    try testing.expectEqual(@as(usize, 0), stats.total_scans);
    try testing.expectEqual(@as(usize, 0), stats.spam_messages);
    try testing.expectEqual(@as(usize, 0), stats.ham_messages);
}

test "enable/disable scanner" {
    const testing = std.testing;

    var scanner = try SpamAssassinScanner.init(testing.allocator, "localhost", 783, 5000);
    defer scanner.deinit();

    try testing.expect(scanner.enabled);

    scanner.setEnabled(false);
    try testing.expect(!scanner.enabled);

    scanner.setEnabled(true);
    try testing.expect(scanner.enabled);
}
