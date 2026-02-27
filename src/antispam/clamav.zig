const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");

/// ClamAV virus scanning integration
/// Scans email messages and attachments for viruses using ClamAV daemon
pub const ClamAVScanner = struct {
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    timeout_ms: u32,
    enabled: bool,
    stats: ScanStats,
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator, host: []const u8, port: u16, timeout_ms: u32) !ClamAVScanner {
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

    pub fn deinit(self: *ClamAVScanner) void {
        self.allocator.free(self.host);
    }

    /// Scan a message for viruses
    pub fn scanMessage(self: *ClamAVScanner, message: []const u8) !ScanResult {
        if (!self.enabled) {
            return ScanResult{
                .clean = true,
                .virus_name = null,
                .scan_time_ms = 0,
            };
        }

        const start = std.time.milliTimestamp();

        // Connect to ClamAV daemon
        const address = try std.net.Address.parseIp(self.host, self.port);
        const stream = try std.net.tcpConnectToAddress(address);
        defer stream.close();

        // Send INSTREAM command to clamd
        try stream.writeAll("zINSTREAM\x00");

        // Send message in chunks with size prefix
        const chunk_size = 2048;
        var offset: usize = 0;

        while (offset < message.len) {
            const remaining = message.len - offset;
            const to_send = @min(remaining, chunk_size);

            // Send chunk size (network byte order)
            var size_buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &size_buf, @intCast(to_send), .big);
            try stream.writeAll(&size_buf);

            // Send chunk data
            try stream.writeAll(message[offset .. offset + to_send]);

            offset += to_send;
        }

        // Send zero-length chunk to signal end
        var zero_buf: [4]u8 = [_]u8{ 0, 0, 0, 0 };
        try stream.writeAll(&zero_buf);

        // Read response
        var response_buf: [1024]u8 = undefined;
        const bytes_read = try stream.read(&response_buf);
        const response = response_buf[0..bytes_read];

        const scan_time = std.time.milliTimestamp() - start;

        // Update statistics
        self.mutex.lock();
        defer self.mutex.unlock();
        self.stats.total_scans += 1;

        // Parse response
        if (std.mem.indexOf(u8, response, "OK")) |_| {
            self.stats.clean_messages += 1;
            return ScanResult{
                .clean = true,
                .virus_name = null,
                .scan_time_ms = scan_time,
            };
        } else if (std.mem.indexOf(u8, response, "FOUND")) |_| {
            self.stats.infected_messages += 1;

            // Extract virus name
            const virus_name = try self.extractVirusName(response);

            return ScanResult{
                .clean = false,
                .virus_name = virus_name,
                .scan_time_ms = scan_time,
            };
        } else {
            self.stats.errors += 1;
            return error.ScanFailed;
        }
    }

    /// Scan a file for viruses
    pub fn scanFile(self: *ClamAVScanner, file_path: []const u8) !ScanResult {
        if (!self.enabled) {
            return ScanResult{
                .clean = true,
                .virus_name = null,
                .scan_time_ms = 0,
            };
        }

        // Connect to ClamAV daemon
        const address = try std.net.Address.parseIp(self.host, self.port);
        const stream = try std.net.tcpConnectToAddress(address);
        defer stream.close();

        // Send SCAN command with file path
        var command = std.ArrayList(u8).init(self.allocator);
        defer command.deinit();

        try command.appendSlice("zSCAN ");
        try command.appendSlice(file_path);
        try command.append('\x00');

        try stream.writeAll(command.items);

        // Read response
        var response_buf: [1024]u8 = undefined;
        const bytes_read = try stream.read(&response_buf);
        const response = response_buf[0..bytes_read];

        // Parse response
        if (std.mem.indexOf(u8, response, "OK")) |_| {
            return ScanResult{
                .clean = true,
                .virus_name = null,
                .scan_time_ms = 0,
            };
        } else if (std.mem.indexOf(u8, response, "FOUND")) |_| {
            const virus_name = try self.extractVirusName(response);
            return ScanResult{
                .clean = false,
                .virus_name = virus_name,
                .scan_time_ms = 0,
            };
        } else {
            return error.ScanFailed;
        }
    }

    /// Ping ClamAV daemon to check if it's alive
    pub fn ping(self: *ClamAVScanner) !bool {
        const address = try std.net.Address.parseIp(self.host, self.port);
        const stream = std.net.tcpConnectToAddress(address) catch return false;
        defer stream.close();

        try stream.writeAll("zPING\x00");

        var response_buf: [32]u8 = undefined;
        const bytes_read = try stream.read(&response_buf);
        const response = response_buf[0..bytes_read];

        return std.mem.indexOf(u8, response, "PONG") != null;
    }

    /// Get ClamAV version
    pub fn getVersion(self: *ClamAVScanner) ![]const u8 {
        const address = try std.net.Address.parseIp(self.host, self.port);
        const stream = try std.net.tcpConnectToAddress(address);
        defer stream.close();

        try stream.writeAll("zVERSION\x00");

        var response_buf: [256]u8 = undefined;
        const bytes_read = try stream.read(&response_buf);
        const response = response_buf[0..bytes_read];

        // Remove trailing null byte if present
        const end = if (bytes_read > 0 and response[bytes_read - 1] == 0)
            bytes_read - 1
        else
            bytes_read;

        return try self.allocator.dupe(u8, response[0..end]);
    }

    /// Reload virus database
    pub fn reload(self: *ClamAVScanner) !void {
        const address = try std.net.Address.parseIp(self.host, self.port);
        const stream = try std.net.tcpConnectToAddress(address);
        defer stream.close();

        try stream.writeAll("zRELOAD\x00");

        var response_buf: [32]u8 = undefined;
        const bytes_read = try stream.read(&response_buf);
        const response = response_buf[0..bytes_read];

        if (std.mem.indexOf(u8, response, "RELOADING") == null) {
            return error.ReloadFailed;
        }
    }

    /// Extract virus name from ClamAV response
    fn extractVirusName(self: *ClamAVScanner, response: []const u8) ![]const u8 {
        // Response format: "stream: Virus.Name FOUND"
        if (std.mem.indexOf(u8, response, ":")) |colon_pos| {
            const after_colon = response[colon_pos + 1 ..];
            const trimmed = std.mem.trim(u8, after_colon, " \t\r\n");

            if (std.mem.indexOf(u8, trimmed, " FOUND")) |found_pos| {
                return try self.allocator.dupe(u8, trimmed[0..found_pos]);
            }
        }

        return try self.allocator.dupe(u8, "Unknown");
    }

    /// Get scanning statistics
    pub fn getStats(self: *ClamAVScanner) ScanStats {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.stats;
    }

    /// Reset statistics
    pub fn resetStats(self: *ClamAVScanner) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.stats = ScanStats{};
    }

    /// Enable/disable scanning
    pub fn setEnabled(self: *ClamAVScanner, enabled: bool) void {
        self.enabled = enabled;
    }
};

pub const ScanResult = struct {
    clean: bool,
    virus_name: ?[]const u8,
    scan_time_ms: i64,

    pub fn deinit(self: *ScanResult, allocator: std.mem.Allocator) void {
        if (self.virus_name) |name| {
            allocator.free(name);
        }
    }
};

pub const ScanStats = struct {
    total_scans: usize = 0,
    clean_messages: usize = 0,
    infected_messages: usize = 0,
    errors: usize = 0,
};

/// Action to take when a virus is detected
pub const VirusAction = enum {
    reject, // Reject the message
    quarantine, // Move to quarantine folder
    tag, // Add header and deliver
    discard, // Silently discard

    pub fn toString(self: VirusAction) []const u8 {
        return switch (self) {
            .reject => "reject",
            .quarantine => "quarantine",
            .tag => "tag",
            .discard => "discard",
        };
    }
};

/// Virus scanning policy
pub const ScanPolicy = struct {
    scan_enabled: bool = true,
    scan_attachments_only: bool = false, // Only scan attachments, not entire message
    max_scan_size: usize = 25 * 1024 * 1024, // 25 MB max
    action_on_virus: VirusAction = .reject,
    action_on_error: VirusAction = .tag, // What to do if scanning fails
    quarantine_path: ?[]const u8 = null,
    tag_header_name: []const u8 = "X-Virus-Scanned",
    tag_header_value: []const u8 = "ClamAV",

    pub fn shouldScan(self: *ScanPolicy, message_size: usize) bool {
        if (!self.scan_enabled) return false;
        if (message_size > self.max_scan_size) return false;
        return true;
    }
};

test "ClamAV scanner initialization" {
    const testing = std.testing;

    var scanner = try ClamAVScanner.init(testing.allocator, "localhost", 3310, 5000);
    defer scanner.deinit();

    try testing.expectEqualStrings("localhost", scanner.host);
    try testing.expectEqual(@as(u16, 3310), scanner.port);
    try testing.expect(scanner.enabled);
}

test "scan result struct" {
    const testing = std.testing;

    var result = ScanResult{
        .clean = false,
        .virus_name = try testing.allocator.dupe(u8, "EICAR-Test-Signature"),
        .scan_time_ms = 42,
    };
    defer result.deinit(testing.allocator);

    try testing.expect(!result.clean);
    try testing.expectEqualStrings("EICAR-Test-Signature", result.virus_name.?);
}

test "scan policy" {
    const testing = std.testing;

    var policy = ScanPolicy{};

    // Should scan small messages
    try testing.expect(policy.shouldScan(1024));

    // Should not scan oversized messages
    try testing.expect(!policy.shouldScan(30 * 1024 * 1024));

    // Disabled policy
    policy.scan_enabled = false;
    try testing.expect(!policy.shouldScan(1024));
}

test "virus action enum" {
    const testing = std.testing;

    try testing.expectEqualStrings("reject", VirusAction.reject.toString());
    try testing.expectEqualStrings("quarantine", VirusAction.quarantine.toString());
    try testing.expectEqualStrings("tag", VirusAction.tag.toString());
}

test "scanner statistics" {
    const testing = std.testing;

    var scanner = try ClamAVScanner.init(testing.allocator, "localhost", 3310, 5000);
    defer scanner.deinit();

    const stats = scanner.getStats();
    try testing.expectEqual(@as(usize, 0), stats.total_scans);
    try testing.expectEqual(@as(usize, 0), stats.clean_messages);
}

test "enable/disable scanner" {
    const testing = std.testing;

    var scanner = try ClamAVScanner.init(testing.allocator, "localhost", 3310, 5000);
    defer scanner.deinit();

    try testing.expect(scanner.enabled);

    scanner.setEnabled(false);
    try testing.expect(!scanner.enabled);

    scanner.setEnabled(true);
    try testing.expect(scanner.enabled);
}
