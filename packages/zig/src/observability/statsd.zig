const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const posix = std.posix;

/// StatsD client for metrics reporting
/// Sends metrics to a StatsD server via UDP
/// Note: Networking disabled in Zig 0.16 migration - needs update
pub const StatsDClient = struct {
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    prefix: ?[]const u8, // Optional metric prefix (e.g., "smtp.")
    socket_fd: ?posix.socket_t,
    enabled: bool,
    mutex: mutex_compat.Mutex,

    pub fn init(
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
        prefix: ?[]const u8,
    ) !StatsDClient {
        return .{
            .allocator = allocator,
            .host = try allocator.dupe(u8, host),
            .port = port,
            .prefix = if (prefix) |p| try allocator.dupe(u8, p) else null,
            .socket_fd = null,
            .enabled = true,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *StatsDClient) void {
        self.allocator.free(self.host);
        if (self.prefix) |p| {
            self.allocator.free(p);
        }
        if (self.socket_fd) |fd| {
            _ = std.c.close(fd);
        }
    }

    /// Connect to StatsD server
    pub fn connect(self: *StatsDClient) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.socket_fd != null) return; // Already connected

        // Create UDP socket
        const fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        self.socket_fd = fd;
    }

    /// Send a counter metric
    /// Format: metric:value|c[|@sample_rate]
    pub fn counter(self: *StatsDClient, name: []const u8, value: i64, sample_rate: ?f64) !void {
        if (!self.enabled) return;

        const metric = try self.formatMetric(name, value, "c", sample_rate);
        defer self.allocator.free(metric);

        try self.send(metric);
    }

    /// Increment a counter by 1
    pub fn increment(self: *StatsDClient, name: []const u8) !void {
        try self.counter(name, 1, null);
    }

    /// Decrement a counter by 1
    pub fn decrement(self: *StatsDClient, name: []const u8) !void {
        try self.counter(name, -1, null);
    }

    /// Send a gauge metric
    /// Format: metric:value|g
    pub fn gauge(self: *StatsDClient, name: []const u8, value: i64) !void {
        if (!self.enabled) return;

        const metric = try self.formatMetric(name, value, "g", null);
        defer self.allocator.free(metric);

        try self.send(metric);
    }

    /// Send a timing metric (in milliseconds)
    /// Format: metric:value|ms[|@sample_rate]
    pub fn timing(self: *StatsDClient, name: []const u8, value: i64, sample_rate: ?f64) !void {
        if (!self.enabled) return;

        const metric = try self.formatMetric(name, value, "ms", sample_rate);
        defer self.allocator.free(metric);

        try self.send(metric);
    }

    /// Send a histogram/distribution metric
    /// Format: metric:value|h[|@sample_rate]
    pub fn histogram(self: *StatsDClient, name: []const u8, value: i64, sample_rate: ?f64) !void {
        if (!self.enabled) return;

        const metric = try self.formatMetric(name, value, "h", sample_rate);
        defer self.allocator.free(metric);

        try self.send(metric);
    }

    /// Send a set metric (unique occurrences)
    /// Format: metric:value|s
    pub fn set(self: *StatsDClient, name: []const u8, value: []const u8) !void {
        if (!self.enabled) return;

        const full_name = if (self.prefix) |p|
            try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ p, name })
        else
            try self.allocator.dupe(u8, name);
        defer self.allocator.free(full_name);

        const metric = try std.fmt.allocPrint(
            self.allocator,
            "{s}:{s}|s",
            .{ full_name, value },
        );
        defer self.allocator.free(metric);

        try self.send(metric);
    }

    /// Time a function execution
    pub fn timed(self: *StatsDClient, name: []const u8, comptime func: anytype) !@TypeOf(func()).ReturnType {
        const start = std.time.milliTimestamp();
        const result = try func();
        const duration = std.time.milliTimestamp() - start;

        try self.timing(name, duration, null);

        return result;
    }

    /// Format a metric string
    fn formatMetric(
        self: *StatsDClient,
        name: []const u8,
        value: i64,
        metric_type: []const u8,
        sample_rate: ?f64,
    ) ![]const u8 {
        const full_name = if (self.prefix) |p|
            try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ p, name })
        else
            try self.allocator.dupe(u8, name);
        defer self.allocator.free(full_name);

        if (sample_rate) |rate| {
            return try std.fmt.allocPrint(
                self.allocator,
                "{s}:{d}|{s}|@{d:.2}",
                .{ full_name, value, metric_type, rate },
            );
        } else {
            return try std.fmt.allocPrint(
                self.allocator,
                "{s}:{d}|{s}",
                .{ full_name, value, metric_type },
            );
        }
    }

    /// Send metric via UDP
    fn send(self: *StatsDClient, metric: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Use UDP for StatsD (connectionless)
        const address = try std.net.Address.parseIp(self.host, self.port);
        const sock = try std.posix.socket(
            address.any.family,
            std.posix.SOCK.DGRAM,
            std.posix.IPPROTO.UDP,
        );
        defer _ = std.c.close(sock);

        _ = try std.posix.sendto(
            sock,
            metric,
            0,
            &address.any,
            address.getOsSockLen(),
        );
    }

    /// Batch send multiple metrics
    pub fn sendBatch(self: *StatsDClient, metrics: []const []const u8) !void {
        if (!self.enabled) return;

        self.mutex.lock();
        defer self.mutex.unlock();

        var batch = std.ArrayList(u8).init(self.allocator);
        defer batch.deinit();

        for (metrics, 0..) |metric, i| {
            try batch.appendSlice(metric);
            if (i < metrics.len - 1) {
                try batch.append('\n');
            }
        }

        const address = try std.net.Address.parseIp(self.host, self.port);
        const sock = try std.posix.socket(
            address.any.family,
            std.posix.SOCK.DGRAM,
            std.posix.IPPROTO.UDP,
        );
        defer _ = std.c.close(sock);

        _ = try std.posix.sendto(
            sock,
            batch.items,
            0,
            &address.any,
            address.getOsSockLen(),
        );
    }

    /// Enable/disable metrics collection
    pub fn setEnabled(self: *StatsDClient, enabled: bool) void {
        self.enabled = enabled;
    }
};

/// StatsD metrics aggregator for common SMTP metrics
pub const SMTPMetrics = struct {
    client: *StatsDClient,

    pub fn init(client: *StatsDClient) SMTPMetrics {
        return .{ .client = client };
    }

    pub fn recordConnection(self: *SMTPMetrics) !void {
        try self.client.increment("connections.total");
    }

    pub fn recordAuthSuccess(self: *SMTPMetrics) !void {
        try self.client.increment("auth.success");
    }

    pub fn recordAuthFailure(self: *SMTPMetrics) !void {
        try self.client.increment("auth.failure");
    }

    pub fn recordMessageReceived(self: *SMTPMetrics, size: usize) !void {
        try self.client.increment("messages.received");
        try self.client.histogram("messages.size", @intCast(size), null);
    }

    pub fn recordMessageSent(self: *SMTPMetrics) !void {
        try self.client.increment("messages.sent");
    }

    pub fn recordBounce(self: *SMTPMetrics) !void {
        try self.client.increment("messages.bounced");
    }

    pub fn recordRateLimit(self: *SMTPMetrics) !void {
        try self.client.increment("ratelimit.hits");
    }

    pub fn recordDNSBLBlock(self: *SMTPMetrics) !void {
        try self.client.increment("spam.dnsbl_blocks");
    }

    pub fn recordGreylistDelay(self: *SMTPMetrics) !void {
        try self.client.increment("spam.greylist_delays");
    }

    pub fn recordCommandDuration(self: *SMTPMetrics, command: []const u8, duration_ms: i64) !void {
        const metric_name = try std.fmt.allocPrint(
            self.client.allocator,
            "commands.{s}.duration",
            .{command},
        );
        defer self.client.allocator.free(metric_name);

        try self.client.timing(metric_name, duration_ms, null);
    }

    pub fn recordQueueDepth(self: *SMTPMetrics, depth: usize) !void {
        try self.client.gauge("queue.depth", @intCast(depth));
    }

    pub fn recordActiveConnections(self: *SMTPMetrics, count: usize) !void {
        try self.client.gauge("connections.active", @intCast(count));
    }
};

test "StatsD metric formatting" {
    const testing = std.testing;

    var client = try StatsDClient.init(testing.allocator, "127.0.0.1", 8125, "smtp.");
    defer client.deinit();

    const metric1 = try client.formatMetric("connections", 1, "c", null);
    defer testing.allocator.free(metric1);
    try testing.expectEqualStrings("smtp.connections:1|c", metric1);

    const metric2 = try client.formatMetric("messages", 100, "ms", 0.5);
    defer testing.allocator.free(metric2);
    try testing.expect(std.mem.indexOf(u8, metric2, "smtp.messages:100|ms|@0.50") != null);
}

test "StatsD client initialization" {
    const testing = std.testing;

    var client = try StatsDClient.init(testing.allocator, "localhost", 8125, null);
    defer client.deinit();

    try testing.expectEqualStrings("localhost", client.host);
    try testing.expectEqual(@as(u16, 8125), client.port);
    try testing.expect(client.prefix == null);
    try testing.expect(client.enabled);
}

test "StatsD enable/disable" {
    const testing = std.testing;

    var client = try StatsDClient.init(testing.allocator, "127.0.0.1", 8125, null);
    defer client.deinit();

    try testing.expect(client.enabled);

    client.setEnabled(false);
    try testing.expect(!client.enabled);

    client.setEnabled(true);
    try testing.expect(client.enabled);
}

test "SMTP metrics helper" {
    const testing = std.testing;

    var client = try StatsDClient.init(testing.allocator, "127.0.0.1", 8125, "test.");
    defer client.deinit();

    var metrics = SMTPMetrics.init(&client);

    // These would send to StatsD in production, but we're just testing the API
    client.setEnabled(false); // Disable actual sending for tests

    try metrics.recordConnection();
    try metrics.recordAuthSuccess();
    try metrics.recordMessageReceived(1024);
    try metrics.recordQueueDepth(10);
}
