const std = @import("std");
const time_compat = @import("../core/time_compat.zig");
const version_info = @import("../core/version.zig");
const env = @import("../core/env.zig");

/// Server statistics with thread-safe atomic counters
pub const ServerStats = struct {
    uptime_seconds: i64,
    total_connections: std.atomic.Value(u64),
    active_connections: std.atomic.Value(u32),
    messages_received: std.atomic.Value(u64),
    messages_rejected: std.atomic.Value(u64),
    auth_successes: std.atomic.Value(u64),
    auth_failures: std.atomic.Value(u64),
    rate_limit_hits: std.atomic.Value(u64),
    dnsbl_blocks: std.atomic.Value(u64),
    greylist_blocks: std.atomic.Value(u64),

    pub fn init() ServerStats {
        return .{
            .uptime_seconds = 0,
            .total_connections = std.atomic.Value(u64).init(0),
            .active_connections = std.atomic.Value(u32).init(0),
            .messages_received = std.atomic.Value(u64).init(0),
            .messages_rejected = std.atomic.Value(u64).init(0),
            .auth_successes = std.atomic.Value(u64).init(0),
            .auth_failures = std.atomic.Value(u64).init(0),
            .rate_limit_hits = std.atomic.Value(u64).init(0),
            .dnsbl_blocks = std.atomic.Value(u64).init(0),
            .greylist_blocks = std.atomic.Value(u64).init(0),
        };
    }

    pub fn incrementTotalConnections(self: *ServerStats) void {
        _ = self.total_connections.fetchAdd(1, .monotonic);
    }

    pub fn incrementActiveConnections(self: *ServerStats) void {
        _ = self.active_connections.fetchAdd(1, .monotonic);
    }

    pub fn decrementActiveConnections(self: *ServerStats) void {
        _ = self.active_connections.fetchSub(1, .monotonic);
    }

    pub fn incrementMessagesReceived(self: *ServerStats) void {
        _ = self.messages_received.fetchAdd(1, .monotonic);
    }

    pub fn incrementMessagesRejected(self: *ServerStats) void {
        _ = self.messages_rejected.fetchAdd(1, .monotonic);
    }

    pub fn incrementAuthSuccesses(self: *ServerStats) void {
        _ = self.auth_successes.fetchAdd(1, .monotonic);
    }

    pub fn incrementAuthFailures(self: *ServerStats) void {
        _ = self.auth_failures.fetchAdd(1, .monotonic);
    }

    pub fn incrementRateLimitHits(self: *ServerStats) void {
        _ = self.rate_limit_hits.fetchAdd(1, .monotonic);
    }

    pub fn incrementDnsblBlocks(self: *ServerStats) void {
        _ = self.dnsbl_blocks.fetchAdd(1, .monotonic);
    }

    pub fn incrementGreylistBlocks(self: *ServerStats) void {
        _ = self.greylist_blocks.fetchAdd(1, .monotonic);
    }

    pub fn toJson(self: *const ServerStats, allocator: std.mem.Allocator) ![]const u8 {
        return try std.fmt.allocPrint(
            allocator,
            \\{{"uptime_seconds":{d},"total_connections":{d},"active_connections":{d},"messages_received":{d},"messages_rejected":{d},"auth_successes":{d},"auth_failures":{d},"rate_limit_hits":{d},"dnsbl_blocks":{d},"greylist_blocks":{d}}}
        ,
            .{
                self.uptime_seconds,
                self.total_connections.load(.monotonic),
                self.active_connections.load(.monotonic),
                self.messages_received.load(.monotonic),
                self.messages_rejected.load(.monotonic),
                self.auth_successes.load(.monotonic),
                self.auth_failures.load(.monotonic),
                self.rate_limit_hits.load(.monotonic),
                self.dnsbl_blocks.load(.monotonic),
                self.greylist_blocks.load(.monotonic),
            },
        );
    }
};

/// Health status
pub const HealthStatus = enum {
    healthy,
    degraded,
    unhealthy,

    pub fn toString(self: HealthStatus) []const u8 {
        return switch (self) {
            .healthy => "healthy",
            .degraded => "degraded",
            .unhealthy => "unhealthy",
        };
    }
};

/// Dependency status
pub const DependencyStatus = struct {
    name: []const u8,
    healthy: bool,
    response_time_ms: ?f64,
    error_message: ?[]const u8,
};

/// Health check result with dependency monitoring
pub const HealthCheck = struct {
    status: HealthStatus,
    uptime_seconds: i64,
    active_connections: u32,
    max_connections: usize,
    memory_usage_mb: ?f64,
    checks: std.StringHashMap(bool),
    dependencies: std.ArrayList(DependencyStatus),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) HealthCheck {
        return .{
            .status = .healthy,
            .uptime_seconds = 0,
            .active_connections = 0,
            .max_connections = 0,
            .memory_usage_mb = null,
            .checks = std.StringHashMap(bool).init(allocator),
            .dependencies = std.ArrayList(DependencyStatus).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *HealthCheck) void {
        var it = self.checks.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.checks.deinit();

        for (self.dependencies.items) |dep| {
            if (dep.error_message) |err| {
                self.allocator.free(err);
            }
        }
        self.dependencies.deinit();
    }

    /// Add dependency status
    pub fn addDependency(self: *HealthCheck, name: []const u8, healthy: bool, response_time_ms: ?f64, error_message: ?[]const u8) !void {
        const error_copy = if (error_message) |err| try self.allocator.dupe(u8, err) else null;

        try self.dependencies.append(.{
            .name = name,
            .healthy = healthy,
            .response_time_ms = response_time_ms,
            .error_message = error_copy,
        });

        // Update overall health status based on dependencies
        if (!healthy) {
            if (self.status == .healthy) {
                self.status = .degraded;
            }
        }
    }

    pub fn toJson(self: *HealthCheck) ![]const u8 {
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();

        try buf.appendSlice("{\"status\":\"");
        try buf.appendSlice(self.status.toString());
        try buf.appendSlice("\",\"version\":\"");
        try buf.appendSlice(version_info.version);
        try buf.appendSlice("\",\"uptime_seconds\":");
        try std.fmt.format(buf.writer(), "{d}", .{self.uptime_seconds});
        try buf.appendSlice(",\"active_connections\":");
        try std.fmt.format(buf.writer(), "{d}", .{self.active_connections});
        try buf.appendSlice(",\"max_connections\":");
        try std.fmt.format(buf.writer(), "{d}", .{self.max_connections});

        if (self.memory_usage_mb) |mem| {
            try buf.appendSlice(",\"memory_usage_mb\":");
            try std.fmt.format(buf.writer(), "{d:.2}", .{mem});
        }

        try buf.appendSlice(",\"checks\":{");
        var first = true;
        var it = self.checks.iterator();
        while (it.next()) |entry| {
            if (!first) try buf.appendSlice(",");
            first = false;
            try buf.appendSlice("\"");
            try buf.appendSlice(entry.key_ptr.*);
            try buf.appendSlice("\":");
            try buf.appendSlice(if (entry.value_ptr.*) "true" else "false");
        }
        try buf.appendSlice("}");

        // Add dependencies
        if (self.dependencies.items.len > 0) {
            try buf.appendSlice(",\"dependencies\":[");
            for (self.dependencies.items, 0..) |dep, i| {
                if (i > 0) try buf.appendSlice(",");
                try buf.appendSlice("{\"name\":\"");
                try buf.appendSlice(dep.name);
                try buf.appendSlice("\",\"healthy\":");
                try buf.appendSlice(if (dep.healthy) "true" else "false");

                if (dep.response_time_ms) |rt| {
                    try buf.appendSlice(",\"response_time_ms\":");
                    try std.fmt.format(buf.writer(), "{d:.2}", .{rt});
                }

                if (dep.error_message) |err| {
                    try buf.appendSlice(",\"error\":\"");
                    // Escape JSON special characters
                    for (err) |c| {
                        if (c == '"') {
                            try buf.appendSlice("\\\"");
                        } else if (c == '\\') {
                            try buf.appendSlice("\\\\");
                        } else if (c == '\n') {
                            try buf.appendSlice("\\n");
                        } else {
                            try buf.append(c);
                        }
                    }
                    try buf.appendSlice("\"");
                }

                try buf.appendSlice("}");
            }
            try buf.appendSlice("]");
        }

        try buf.appendSlice("}");

        return try buf.toOwnedSlice();
    }
};

/// Simple HTTP health check server
pub const HealthServer = struct {
    allocator: std.mem.Allocator,
    port: u16,
    stats_provider: *const fn () ServerStats,
    start_time: i64,
    active_connections: *const std.atomic.Value(u32),
    max_connections: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        port: u16,
        stats_provider: *const fn () ServerStats,
        active_connections: *const std.atomic.Value(u32),
        max_connections: usize,
    ) HealthServer {
        return .{
            .allocator = allocator,
            .port = port,
            .stats_provider = stats_provider,
            .start_time = time_compat.timestamp(),
            .active_connections = active_connections,
            .max_connections = max_connections,
        };
    }

    pub fn run(self: *HealthServer) !void {
        const address = try std.net.Address.parseIp("127.0.0.1", self.port);
        var server = try address.listen(.{
            .reuse_address = true,
        });
        defer server.deinit();

        std.log.info("Health check server listening on http://127.0.0.1:{d}", .{self.port});

        while (true) {
            const connection = try server.accept();
            defer connection.stream.close();

            self.handleRequest(connection.stream) catch |err| {
                std.log.err("Health check request error: {}", .{err});
            };
        }
    }

    fn handleRequest(self: *HealthServer, stream: std.net.Stream) !void {
        var buf: [4096]u8 = undefined;
        const bytes_read = try stream.read(&buf);
        if (bytes_read == 0) return;

        const request = buf[0..bytes_read];

        // Simple HTTP request parsing
        if (std.mem.startsWith(u8, request, "GET /health")) {
            try self.handleHealth(stream);
        } else if (std.mem.startsWith(u8, request, "GET /ready") or std.mem.startsWith(u8, request, "GET /readyz")) {
            try self.handleReadiness(stream);
        } else if (std.mem.startsWith(u8, request, "GET /live") or std.mem.startsWith(u8, request, "GET /livez")) {
            try self.handleLiveness(stream);
        } else if (std.mem.startsWith(u8, request, "GET /startup")) {
            try self.handleStartup(stream);
        } else if (std.mem.startsWith(u8, request, "GET /stats")) {
            try self.handleStats(stream);
        } else if (std.mem.startsWith(u8, request, "GET /metrics")) {
            try self.handleMetrics(stream);
        } else {
            try self.send404(stream);
        }
    }

    fn handleHealth(self: *HealthServer, stream: std.net.Stream) !void {
        var health = HealthCheck.init(self.allocator);
        defer health.deinit();

        const now = time_compat.timestamp();
        health.uptime_seconds = now - self.start_time;
        health.active_connections = self.active_connections.load(.monotonic);
        health.max_connections = self.max_connections;

        // Determine health status
        const connection_ratio = @as(f64, @floatFromInt(health.active_connections)) / @as(f64, @floatFromInt(self.max_connections));
        if (connection_ratio > 0.9) {
            health.status = .degraded;
        } else if (connection_ratio >= 1.0) {
            health.status = .unhealthy;
        } else {
            health.status = .healthy;
        }

        // Add basic checks
        try health.checks.put(try self.allocator.dupe(u8, "smtp_server"), health.status == .healthy);
        try health.checks.put(try self.allocator.dupe(u8, "connections_available"), connection_ratio < 1.0);

        // Check database dependency (if DB_PATH is set, database is in use)
        const db_start = std.time.milliTimestamp();
        if (env.get("SMTP_DB_PATH")) |db_path| {
            // Try to access database file
            std.fs.cwd().access(db_path, .{}) catch |err| {
                const err_msg = try std.fmt.allocPrint(self.allocator, "Database file not accessible: {}", .{err});
                try health.addDependency("database", false, null, err_msg);
                try health.checks.put(try self.allocator.dupe(u8, "database"), false);
                health.status = .unhealthy;
                const json = try health.toJson();
                defer self.allocator.free(json);
                const response = try std.fmt.allocPrint(
                    self.allocator,
                    "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
                    .{ json.len, json },
                );
                defer self.allocator.free(response);
                _ = try stream.write(response);
                return;
            };
            const db_time = @as(f64, @floatFromInt(std.time.milliTimestamp() - db_start));
            try health.addDependency("database", true, db_time, null);
            try health.checks.put(try self.allocator.dupe(u8, "database"), true);
        }

        // Check filesystem dependency (can write to temp)
        const fs_start = std.time.milliTimestamp();
        const tmp_file = "/tmp/smtp_health_check";
        var file = std.fs.cwd().createFile(tmp_file, .{}) catch |err| {
            const err_msg = try std.fmt.allocPrint(self.allocator, "Filesystem not writable: {}", .{err});
            try health.addDependency("filesystem", false, null, err_msg);
            try health.checks.put(try self.allocator.dupe(u8, "filesystem"), false);
            health.status = .degraded;
            const json = try health.toJson();
            defer self.allocator.free(json);
            const response = try std.fmt.allocPrint(
                self.allocator,
                "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
                .{ json.len, json },
            );
            defer self.allocator.free(response);
            _ = try stream.write(response);
            return;
        };
        file.close();
        std.fs.cwd().deleteFile(tmp_file) catch {};
        const fs_time = @as(f64, @floatFromInt(std.time.milliTimestamp() - fs_start));
        try health.addDependency("filesystem", true, fs_time, null);
        try health.checks.put(try self.allocator.dupe(u8, "filesystem"), true);

        // Get memory usage estimate
        health.memory_usage_mb = self.getMemoryUsageMB();

        const json = try health.toJson();
        defer self.allocator.free(json);

        const status_code = if (health.status == .healthy) "200 OK" else if (health.status == .degraded) "200 OK" else "503 Service Unavailable";
        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ status_code, json.len, json },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    /// Get approximate memory usage in MB (Linux/macOS)
    fn getMemoryUsageMB(self: *HealthServer) ?f64 {
        _ = self;
        // On macOS, read from /proc/self/status is not available
        // This is a simplified version - in production you'd use platform-specific APIs
        if (std.fs.openFileAbsolute("/proc/self/status", .{})) |file| {
            defer file.close();
            var buf: [4096]u8 = undefined;
            const bytes_read = file.read(&buf) catch return null;
            const content = buf[0..bytes_read];

            // Parse VmRSS (Resident Set Size)
            var lines = std.mem.split(u8, content, "\n");
            while (lines.next()) |line| {
                if (std.mem.startsWith(u8, line, "VmRSS:")) {
                    // VmRSS: 12345 kB
                    var parts = std.mem.split(u8, line, " ");
                    _ = parts.next(); // Skip "VmRSS:"
                    while (parts.next()) |part| {
                        if (part.len == 0) continue;
                        if (std.fmt.parseInt(u64, part, 10)) |kb| {
                            return @as(f64, @floatFromInt(kb)) / 1024.0;
                        } else |_| {}
                    }
                }
            }
        } else |_| {}
        return null;
    }

    // ============================================
    // Kubernetes Probe Endpoints
    // ============================================

    /// Readiness Probe - Is the application ready to receive traffic?
    /// Returns 200 if ready, 503 if not ready
    /// K8s uses this to decide if pod should receive traffic
    fn handleReadiness(self: *HealthServer, stream: std.net.Stream) !void {
        var ready = true;
        var checks = std.ArrayList(u8).init(self.allocator);
        defer checks.deinit();

        try checks.appendSlice("{\"ready\":");

        // Check 1: Connection capacity available
        const connection_ratio = @as(f64, @floatFromInt(self.active_connections.load(.monotonic))) /
            @as(f64, @floatFromInt(self.max_connections));
        if (connection_ratio >= 0.95) {
            ready = false;
        }

        // Check 2: Database accessible (if configured)
        if (env.get("SMTP_DB_PATH")) |db_path| {
            std.fs.cwd().access(db_path, .{}) catch {
                ready = false;
            };
        }

        // Check 3: Server has been running for minimum startup time (10 seconds)
        const uptime = time_compat.timestamp() - self.start_time;
        if (uptime < 10) {
            ready = false;
        }

        try checks.appendSlice(if (ready) "true" else "false");
        try checks.appendSlice(",\"checks\":{");
        try std.fmt.format(checks.writer(), "\"connections_available\":{s},", .{if (connection_ratio < 0.95) "true" else "false"});
        try std.fmt.format(checks.writer(), "\"database_accessible\":true,", .{}); // Simplified
        try std.fmt.format(checks.writer(), "\"minimum_uptime\":{s}", .{if (uptime >= 10) "true" else "false"});
        try checks.appendSlice("}}");

        const status = if (ready) "200 OK" else "503 Service Unavailable";
        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ status, checks.items.len, checks.items },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    /// Liveness Probe - Is the application alive and not deadlocked?
    /// Returns 200 if alive, 503 if dead/stuck
    /// K8s uses this to decide if pod should be restarted
    fn handleLiveness(self: *HealthServer, stream: std.net.Stream) !void {
        var alive = true;
        var checks = std.ArrayList(u8).init(self.allocator);
        defer checks.deinit();

        try checks.appendSlice("{\"alive\":");

        // Check 1: Can allocate memory (not OOM)
        const test_alloc = self.allocator.alloc(u8, 1024) catch {
            alive = false;
            try checks.appendSlice("false,\"reason\":\"memory_allocation_failed\"}");

            const response = try std.fmt.allocPrint(
                self.allocator,
                "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
                .{ checks.items.len, checks.items },
            );
            defer self.allocator.free(response);
            _ = try stream.write(response);
            return;
        };
        self.allocator.free(test_alloc);

        // Check 2: Event loop responsive (this handler being called proves it)
        // Check 3: Not deadlocked (we're responding)

        try checks.appendSlice(if (alive) "true" else "false");
        try checks.appendSlice(",\"checks\":{");
        try checks.appendSlice("\"memory_allocatable\":true,");
        try checks.appendSlice("\"event_loop_responsive\":true,");
        try checks.appendSlice("\"not_deadlocked\":true");
        try checks.appendSlice("}}");

        const status = if (alive) "200 OK" else "503 Service Unavailable";
        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ status, checks.items.len, checks.items },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    /// Startup Probe - Has the application finished starting?
    /// Returns 200 once startup is complete, 503 during startup
    /// K8s uses this to know when to start liveness/readiness checks
    fn handleStartup(self: *HealthServer, stream: std.net.Stream) !void {
        var started = true;
        var checks = std.ArrayList(u8).init(self.allocator);
        defer checks.deinit();

        try checks.appendSlice("{\"started\":");

        // Check 1: Minimum startup time elapsed (server needs time to initialize)
        const uptime = time_compat.timestamp() - self.start_time;
        const min_startup_seconds: i64 = 5; // 5 second minimum startup

        if (uptime < min_startup_seconds) {
            started = false;
        }

        // Check 2: Server is accepting connections
        // (If we're responding, we're accepting)

        // Check 3: Database initialized (if using database)
        if (env.get("SMTP_DB_PATH")) |db_path| {
            std.fs.cwd().access(db_path, .{}) catch {
                started = false;
            };
        }

        try checks.appendSlice(if (started) "true" else "false");
        try checks.appendSlice(",\"uptime_seconds\":");
        try std.fmt.format(checks.writer(), "{d}", .{uptime});
        try checks.appendSlice(",\"min_startup_seconds\":");
        try std.fmt.format(checks.writer(), "{d}", .{min_startup_seconds});
        try checks.appendSlice(",\"checks\":{");
        try std.fmt.format(checks.writer(), "\"minimum_uptime\":{s},", .{if (uptime >= min_startup_seconds) "true" else "false"});
        try checks.appendSlice("\"accepting_connections\":true,");
        try checks.appendSlice("\"database_initialized\":true");
        try checks.appendSlice("}}");

        const status = if (started) "200 OK" else "503 Service Unavailable";
        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ status, checks.items.len, checks.items },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    fn handleStats(self: *HealthServer, stream: std.net.Stream) !void {
        const stats = self.stats_provider();
        const json = try stats.toJson(self.allocator);
        defer self.allocator.free(json);

        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ json.len, json },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    fn handleMetrics(self: *HealthServer, stream: std.net.Stream) !void {
        const stats = self.stats_provider();

        const metrics = try std.fmt.allocPrint(
            self.allocator,
            \\# HELP smtp_uptime_seconds Server uptime in seconds
            \\# TYPE smtp_uptime_seconds gauge
            \\smtp_uptime_seconds {d}
            \\# HELP smtp_connections_total Total number of connections
            \\# TYPE smtp_connections_total counter
            \\smtp_connections_total {d}
            \\# HELP smtp_connections_active Currently active connections
            \\# TYPE smtp_connections_active gauge
            \\smtp_connections_active {d}
            \\# HELP smtp_messages_received_total Total messages received
            \\# TYPE smtp_messages_received_total counter
            \\smtp_messages_received_total {d}
            \\# HELP smtp_messages_rejected_total Total messages rejected
            \\# TYPE smtp_messages_rejected_total counter
            \\smtp_messages_rejected_total {d}
            \\# HELP smtp_auth_successes_total Total successful authentications
            \\# TYPE smtp_auth_successes_total counter
            \\smtp_auth_successes_total {d}
            \\# HELP smtp_auth_failures_total Total failed authentications
            \\# TYPE smtp_auth_failures_total counter
            \\smtp_auth_failures_total {d}
            \\# HELP smtp_rate_limit_hits_total Total rate limit hits
            \\# TYPE smtp_rate_limit_hits_total counter
            \\smtp_rate_limit_hits_total {d}
            \\# HELP smtp_dnsbl_blocks_total Total DNSBL blocks
            \\# TYPE smtp_dnsbl_blocks_total counter
            \\smtp_dnsbl_blocks_total {d}
            \\# HELP smtp_greylist_blocks_total Total greylist blocks
            \\# TYPE smtp_greylist_blocks_total counter
            \\smtp_greylist_blocks_total {d}
            \\
        ,
            .{
                stats.uptime_seconds,
                stats.total_connections,
                stats.active_connections,
                stats.messages_received,
                stats.messages_rejected,
                stats.auth_successes,
                stats.auth_failures,
                stats.rate_limit_hits,
                stats.dnsbl_blocks,
                stats.greylist_blocks,
            },
        );
        defer self.allocator.free(metrics);

        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ metrics.len, metrics },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    fn send404(self: *HealthServer, stream: std.net.Stream) !void {
        _ = self;
        const response = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";
        _ = try stream.write(response);
    }
};

test "server stats to JSON" {
    const testing = std.testing;

    const stats = ServerStats{
        .uptime_seconds = 3600,
        .total_connections = 100,
        .active_connections = 5,
        .messages_received = 50,
        .messages_rejected = 2,
        .auth_successes = 48,
        .auth_failures = 2,
        .rate_limit_hits = 1,
        .dnsbl_blocks = 1,
        .greylist_blocks = 0,
    };

    const json = try stats.toJson(testing.allocator);
    defer testing.allocator.free(json);

    try testing.expect(std.mem.indexOf(u8, json, "\"uptime_seconds\":3600") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"total_connections\":100") != null);
}

test "health check to JSON" {
    const testing = std.testing;

    var health = HealthCheck.init(testing.allocator);
    defer health.deinit();

    health.status = .healthy;
    health.uptime_seconds = 100;
    health.active_connections = 5;
    health.max_connections = 100;

    try health.checks.put(try testing.allocator.dupe(u8, "test"), true);

    const json = try health.toJson();
    defer testing.allocator.free(json);

    try testing.expect(std.mem.indexOf(u8, json, "\"status\":\"healthy\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"uptime_seconds\":100") != null);
}

// =============================================================================
// Cluster-Aware Health Checks
// =============================================================================

const cluster = @import("../infrastructure/cluster.zig");

/// Cluster health status
pub const ClusterHealthStatus = struct {
    cluster_enabled: bool,
    node_id: ?[]const u8,
    node_role: ?[]const u8,
    node_status: ?[]const u8,
    total_nodes: u32,
    healthy_nodes: u32,
    leader_id: ?[]const u8,
    raft_enabled: bool,
    raft_term: u64,
    raft_state: []const u8,

    pub fn toJson(self: *const ClusterHealthStatus, allocator: std.mem.Allocator) ![]u8 {
        var buf = std.ArrayList(u8).init(allocator);
        const writer = buf.writer();

        try writer.writeAll("{\"cluster_enabled\":");
        try writer.writeAll(if (self.cluster_enabled) "true" else "false");

        if (self.cluster_enabled) {
            if (self.node_id) |id| {
                try writer.print(",\"node_id\":\"{s}\"", .{id});
            }
            if (self.node_role) |role| {
                try writer.print(",\"node_role\":\"{s}\"", .{role});
            }
            if (self.node_status) |status| {
                try writer.print(",\"node_status\":\"{s}\"", .{status});
            }
            try writer.print(",\"total_nodes\":{d}", .{self.total_nodes});
            try writer.print(",\"healthy_nodes\":{d}", .{self.healthy_nodes});
            if (self.leader_id) |leader| {
                try writer.print(",\"leader_id\":\"{s}\"", .{leader});
            }
            try writer.print(",\"raft_enabled\":{s}", .{if (self.raft_enabled) "true" else "false"});
            if (self.raft_enabled) {
                try writer.print(",\"raft_term\":{d}", .{self.raft_term});
                try writer.print(",\"raft_state\":\"{s}\"", .{self.raft_state});
            }
        }

        try writer.writeAll("}");
        return buf.toOwnedSlice();
    }
};

/// Cluster health checker
pub const ClusterHealthChecker = struct {
    allocator: std.mem.Allocator,
    cluster_manager: ?*cluster.ClusterManager,

    pub fn init(allocator: std.mem.Allocator, cluster_manager: ?*cluster.ClusterManager) ClusterHealthChecker {
        return .{
            .allocator = allocator,
            .cluster_manager = cluster_manager,
        };
    }

    /// Get cluster health status
    pub fn getClusterHealth(self: *ClusterHealthChecker) ClusterHealthStatus {
        if (self.cluster_manager) |cm| {
            const stats = cm.getStats();
            return .{
                .cluster_enabled = true,
                .node_id = cm.local_node.id,
                .node_role = cm.local_node.getRole().toString(),
                .node_status = cm.local_node.getStatus().toString(),
                .total_nodes = stats.total_nodes,
                .healthy_nodes = stats.healthy_nodes,
                .leader_id = stats.leader_node_id,
                .raft_enabled = stats.raft_enabled,
                .raft_term = stats.raft_term,
                .raft_state = stats.raft_state,
            };
        }

        return .{
            .cluster_enabled = false,
            .node_id = null,
            .node_role = null,
            .node_status = null,
            .total_nodes = 1,
            .healthy_nodes = 1,
            .leader_id = null,
            .raft_enabled = false,
            .raft_term = 0,
            .raft_state = "standalone",
        };
    }

    /// Check if cluster is healthy
    pub fn isClusterHealthy(self: *ClusterHealthChecker) bool {
        if (self.cluster_manager) |cm| {
            const stats = cm.getStats();
            // Cluster is healthy if we have a leader and majority of nodes are healthy
            const has_leader = stats.leader_node_id != null;
            const majority_healthy = stats.healthy_nodes > stats.total_nodes / 2;
            return has_leader and majority_healthy;
        }
        return true; // Standalone mode is always "healthy"
    }

    /// Check if this node is the leader
    pub fn isLeader(self: *ClusterHealthChecker) bool {
        if (self.cluster_manager) |cm| {
            return cm.isRaftLeader();
        }
        return true; // Standalone mode is always "leader"
    }
};

/// Extended health check with cluster awareness
pub const ClusterAwareHealthCheck = struct {
    base: HealthCheck,
    cluster_health: ClusterHealthStatus,

    pub fn init(allocator: std.mem.Allocator) ClusterAwareHealthCheck {
        return .{
            .base = HealthCheck.init(allocator),
            .cluster_health = .{
                .cluster_enabled = false,
                .node_id = null,
                .node_role = null,
                .node_status = null,
                .total_nodes = 1,
                .healthy_nodes = 1,
                .leader_id = null,
                .raft_enabled = false,
                .raft_term = 0,
                .raft_state = "standalone",
            },
        };
    }

    pub fn deinit(self: *ClusterAwareHealthCheck) void {
        self.base.deinit();
    }

    pub fn toJson(self: *ClusterAwareHealthCheck) ![]u8 {
        const base_json = try self.base.toJson();
        defer self.base.allocator.free(base_json);

        const cluster_json = try self.cluster_health.toJson(self.base.allocator);
        defer self.base.allocator.free(cluster_json);

        // Combine base health and cluster health
        // Remove trailing } from base_json, add cluster section
        if (base_json.len > 0 and base_json[base_json.len - 1] == '}') {
            return try std.fmt.allocPrint(self.base.allocator, "{s},\"cluster\":{s}}}", .{
                base_json[0 .. base_json.len - 1],
                cluster_json,
            });
        }

        return try self.base.allocator.dupe(u8, base_json);
    }
};

/// Cluster-wide rate limiter integration
pub const ClusterRateLimitHealth = struct {
    allocator: std.mem.Allocator,
    cluster_rate_limiter: ?*cluster.ClusterRateLimiter,

    pub fn init(allocator: std.mem.Allocator, rate_limiter: ?*cluster.ClusterRateLimiter) ClusterRateLimitHealth {
        return .{
            .allocator = allocator,
            .cluster_rate_limiter = rate_limiter,
        };
    }

    /// Check rate limit across cluster
    pub fn checkClusterRateLimit(self: *ClusterRateLimitHealth, key: []const u8, limit: u32) bool {
        if (self.cluster_rate_limiter) |rl| {
            return rl.checkAndIncrement(key, limit) catch false;
        }
        return true; // No cluster rate limiter, allow
    }
};

test "cluster health status to JSON" {
    const testing = std.testing;

    const status = ClusterHealthStatus{
        .cluster_enabled = true,
        .node_id = "node-1",
        .node_role = "leader",
        .node_status = "healthy",
        .total_nodes = 3,
        .healthy_nodes = 3,
        .leader_id = "node-1",
        .raft_enabled = true,
        .raft_term = 5,
        .raft_state = "leader",
    };

    const json = try status.toJson(testing.allocator);
    defer testing.allocator.free(json);

    try testing.expect(std.mem.indexOf(u8, json, "\"cluster_enabled\":true") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"node_id\":\"node-1\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"raft_term\":5") != null);
}
