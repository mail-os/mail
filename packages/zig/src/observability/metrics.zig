const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const statsd = @import("statsd.zig");

/// Enhanced Application Metrics for SMTP Server
/// Tracks comprehensive statistics including:
/// - Message processing (sent, received, bounced, deferred)
/// - Spam/virus detection rates
/// - Authentication statistics
/// - Connection metrics
/// - Queue metrics
/// - Performance timing
///
/// ## Usage
/// ```zig
/// var metrics = try SmtpMetrics.init(allocator, "localhost", 8125, "smtp");
/// defer metrics.deinit();
///
/// metrics.recordMessageReceived("user@example.com", 1024);
/// metrics.recordSpamDetected(.spamassassin, 7.5);
/// metrics.recordAuthAttempt(.plain, true);
/// ```
/// Spam detection engine types
pub const SpamEngine = enum {
    spamassassin,
    rspamd,
    dnsbl,
    dkim,
    dmarc,
    spf,
    custom,

    pub fn toString(self: SpamEngine) []const u8 {
        return switch (self) {
            .spamassassin => "spamassassin",
            .rspamd => "rspamd",
            .dnsbl => "dnsbl",
            .dkim => "dkim",
            .dmarc => "dmarc",
            .spf => "spf",
            .custom => "custom",
        };
    }
};

/// Authentication mechanism types
pub const AuthMechanism = enum {
    plain,
    login,
    cram_md5,
    oauth2,
    external,
    api_key,

    pub fn toString(self: AuthMechanism) []const u8 {
        return switch (self) {
            .plain => "plain",
            .login => "login",
            .cram_md5 => "cram_md5",
            .oauth2 => "oauth2",
            .external => "external",
            .api_key => "api_key",
        };
    }
};

/// Message delivery status
pub const DeliveryStatus = enum {
    delivered,
    bounced,
    deferred,
    rejected,
    quarantined,

    pub fn toString(self: DeliveryStatus) []const u8 {
        return switch (self) {
            .delivered => "delivered",
            .bounced => "bounced",
            .deferred => "deferred",
            .rejected => "rejected",
            .quarantined => "quarantined",
        };
    }
};

/// Bounce type classification
pub const BounceType = enum {
    hard, // Permanent failure (invalid address)
    soft, // Temporary failure (mailbox full, server down)
    block, // Blocked by recipient
    technical, // Technical issue (DNS, network)
    policy, // Policy rejection (DMARC, etc.)

    pub fn toString(self: BounceType) []const u8 {
        return switch (self) {
            .hard => "hard",
            .soft => "soft",
            .block => "block",
            .technical => "technical",
            .policy => "policy",
        };
    }
};

/// Connection type
pub const ConnectionType = enum {
    smtp, // Port 25
    submission, // Port 587
    smtps, // Port 465
    internal, // Internal relay

    pub fn toString(self: ConnectionType) []const u8 {
        return switch (self) {
            .smtp => "smtp",
            .submission => "submission",
            .smtps => "smtps",
            .internal => "internal",
        };
    }
};

/// Comprehensive SMTP Metrics collector
pub const SmtpMetrics = struct {
    allocator: std.mem.Allocator,
    client: ?*statsd.StatsDClient,
    enabled: bool,
    mutex: mutex_compat.Mutex,

    // In-memory counters for local aggregation
    counters: MetricCounters,
    gauges: MetricGauges,
    histograms: MetricHistograms,

    pub fn init(
        allocator: std.mem.Allocator,
        statsd_host: ?[]const u8,
        statsd_port: u16,
        prefix: []const u8,
    ) !SmtpMetrics {
        var client: ?*statsd.StatsDClient = null;

        if (statsd_host) |host| {
            const c = try allocator.create(statsd.StatsDClient);
            c.* = try statsd.StatsDClient.init(allocator, host, statsd_port, prefix);
            client = c;
        }

        return .{
            .allocator = allocator,
            .client = client,
            .enabled = true,
            .mutex = .{},
            .counters = MetricCounters{},
            .gauges = MetricGauges{},
            .histograms = MetricHistograms.init(),
        };
    }

    pub fn deinit(self: *SmtpMetrics) void {
        if (self.client) |c| {
            c.deinit();
            self.allocator.destroy(c);
        }
    }

    // ===== Message Metrics =====

    /// Record a message received
    pub fn recordMessageReceived(self: *SmtpMetrics, domain: []const u8, size_bytes: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.messages_received += 1;
        self.counters.bytes_received += size_bytes;

        if (self.client) |c| {
            c.increment("messages.received") catch {};
            c.counter("bytes.received", @intCast(size_bytes), null) catch {};
            // Per-domain metric
            var metric_name_buf: [128]u8 = undefined;
            const metric_name = std.fmt.bufPrint(&metric_name_buf, "messages.received.{s}", .{domain}) catch return;
            c.increment(metric_name) catch {};
        }
    }

    /// Record a message sent/delivered
    pub fn recordMessageSent(self: *SmtpMetrics, domain: []const u8, size_bytes: usize, delivery_time_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.messages_sent += 1;
        self.counters.bytes_sent += size_bytes;
        self.histograms.addDeliveryTime(delivery_time_ms);

        if (self.client) |c| {
            c.increment("messages.sent") catch {};
            c.counter("bytes.sent", @intCast(size_bytes), null) catch {};
            c.timing("delivery.time", @intCast(delivery_time_ms), null) catch {};
            _ = domain;
        }
    }

    /// Record a message bounce
    pub fn recordBounce(self: *SmtpMetrics, bounce_type: BounceType, domain: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.messages_bounced += 1;
        switch (bounce_type) {
            .hard => self.counters.bounces_hard += 1,
            .soft => self.counters.bounces_soft += 1,
            else => {},
        }

        if (self.client) |c| {
            c.increment("messages.bounced") catch {};
            var bounce_metric_buf: [128]u8 = undefined;
            const bounce_metric = std.fmt.bufPrint(&bounce_metric_buf, "bounces.{s}", .{bounce_type.toString()}) catch return;
            c.increment(bounce_metric) catch {};
            _ = domain;
        }
    }

    /// Record a deferred message
    pub fn recordDeferred(self: *SmtpMetrics, reason: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.messages_deferred += 1;

        if (self.client) |c| {
            c.increment("messages.deferred") catch {};
            _ = reason;
        }
    }

    // ===== Spam/Virus Metrics =====

    /// Record spam detection
    pub fn recordSpamDetected(self: *SmtpMetrics, engine: SpamEngine, score: f64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.spam_detected += 1;
        self.histograms.addSpamScore(score);

        if (self.client) |c| {
            c.increment("spam.detected") catch {};
            var engine_metric_buf: [128]u8 = undefined;
            const engine_metric = std.fmt.bufPrint(&engine_metric_buf, "spam.detected.{s}", .{engine.toString()}) catch return;
            c.increment(engine_metric) catch {};
            c.histogram("spam.score", @intFromFloat(score * 100), null) catch {};
        }
    }

    /// Record virus detection
    pub fn recordVirusDetected(self: *SmtpMetrics, virus_name: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.viruses_detected += 1;

        if (self.client) |c| {
            c.increment("virus.detected") catch {};
            _ = virus_name;
        }
    }

    /// Record message scanned (clean)
    pub fn recordMessageScanned(self: *SmtpMetrics, scan_time_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.messages_scanned += 1;
        self.histograms.addScanTime(scan_time_ms);

        if (self.client) |c| {
            c.increment("messages.scanned") catch {};
            c.timing("scan.time", @intCast(scan_time_ms), null) catch {};
        }
    }

    // ===== Authentication Metrics =====

    /// Record authentication attempt
    pub fn recordAuthAttempt(self: *SmtpMetrics, mechanism: AuthMechanism, success: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.auth_attempts += 1;
        if (success) {
            self.counters.auth_successes += 1;
        } else {
            self.counters.auth_failures += 1;
        }

        if (self.client) |c| {
            c.increment("auth.attempts") catch {};
            if (success) {
                c.increment("auth.success") catch {};
            } else {
                c.increment("auth.failure") catch {};
            }
            var mech_metric_buf: [128]u8 = undefined;
            const mech_metric = std.fmt.bufPrint(
                &mech_metric_buf,
                "auth.{s}.{s}",
                .{ mechanism.toString(), if (success) "success" else "failure" },
            ) catch return;
            c.increment(mech_metric) catch {};
        }
    }

    /// Record rate limit hit
    pub fn recordRateLimitHit(self: *SmtpMetrics, limit_type: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.rate_limits_hit += 1;

        if (self.client) |c| {
            c.increment("ratelimit.hit") catch {};
            var metric_buf: [128]u8 = undefined;
            const metric = std.fmt.bufPrint(&metric_buf, "ratelimit.{s}", .{limit_type}) catch return;
            c.increment(metric) catch {};
        }
    }

    // ===== Connection Metrics =====

    /// Record new connection
    pub fn recordConnection(self: *SmtpMetrics, conn_type: ConnectionType, tls_enabled: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.connections_total += 1;
        self.gauges.connections_active += 1;
        if (tls_enabled) {
            self.counters.connections_tls += 1;
        }

        if (self.client) |c| {
            c.increment("connections.total") catch {};
            c.gauge("connections.active", @intCast(self.gauges.connections_active)) catch {};
            var type_metric_buf: [128]u8 = undefined;
            const type_metric = std.fmt.bufPrint(&type_metric_buf, "connections.{s}", .{conn_type.toString()}) catch return;
            c.increment(type_metric) catch {};
            if (tls_enabled) {
                c.increment("connections.tls") catch {};
            }
        }
    }

    /// Record connection closed
    pub fn recordConnectionClosed(self: *SmtpMetrics, duration_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.gauges.connections_active > 0) {
            self.gauges.connections_active -= 1;
        }
        self.histograms.addConnectionDuration(duration_ms);

        if (self.client) |c| {
            c.gauge("connections.active", @intCast(self.gauges.connections_active)) catch {};
            c.timing("connection.duration", @intCast(duration_ms), null) catch {};
        }
    }

    // ===== Queue Metrics =====

    /// Update queue size
    pub fn updateQueueSize(self: *SmtpMetrics, queue_name: []const u8, size: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.gauges.queue_size = size;

        if (self.client) |c| {
            c.gauge("queue.size", @intCast(size)) catch {};
            var metric_buf: [128]u8 = undefined;
            const metric = std.fmt.bufPrint(&metric_buf, "queue.{s}.size", .{queue_name}) catch return;
            c.gauge(metric, @intCast(size)) catch {};
        }
    }

    /// Record queue processing time
    pub fn recordQueueProcessTime(self: *SmtpMetrics, time_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.histograms.addQueueTime(time_ms);

        if (self.client) |c| {
            c.timing("queue.process_time", @intCast(time_ms), null) catch {};
        }
    }

    // ===== DKIM/DMARC/SPF Metrics =====

    /// Record DKIM verification result
    pub fn recordDkimResult(self: *SmtpMetrics, passed: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.dkim_checks += 1;
        if (passed) {
            self.counters.dkim_passed += 1;
        }

        if (self.client) |c| {
            c.increment("dkim.checked") catch {};
            if (passed) {
                c.increment("dkim.passed") catch {};
            } else {
                c.increment("dkim.failed") catch {};
            }
        }
    }

    /// Record DMARC verification result
    pub fn recordDmarcResult(self: *SmtpMetrics, policy: []const u8, passed: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.dmarc_checks += 1;
        if (passed) {
            self.counters.dmarc_passed += 1;
        }

        if (self.client) |c| {
            c.increment("dmarc.checked") catch {};
            _ = policy;
            if (passed) {
                c.increment("dmarc.passed") catch {};
            } else {
                c.increment("dmarc.failed") catch {};
            }
        }
    }

    /// Record SPF verification result
    pub fn recordSpfResult(self: *SmtpMetrics, result: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters.spf_checks += 1;

        if (self.client) |c| {
            c.increment("spf.checked") catch {};
            var metric_buf: [128]u8 = undefined;
            const metric = std.fmt.bufPrint(&metric_buf, "spf.{s}", .{result}) catch return;
            c.increment(metric) catch {};
        }
    }

    // ===== Statistics =====

    /// Get current metrics snapshot
    pub fn getSnapshot(self: *SmtpMetrics) MetricsSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();

        return MetricsSnapshot{
            .counters = self.counters,
            .gauges = self.gauges,
            .spam_rate = self.calculateSpamRate(),
            .bounce_rate = self.calculateBounceRate(),
            .auth_success_rate = self.calculateAuthSuccessRate(),
            .tls_rate = self.calculateTlsRate(),
            .dkim_pass_rate = self.calculateDkimPassRate(),
            .dmarc_pass_rate = self.calculateDmarcPassRate(),
        };
    }

    /// Reset all counters
    pub fn reset(self: *SmtpMetrics) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.counters = MetricCounters{};
        self.gauges = MetricGauges{};
        self.histograms = MetricHistograms.init();
    }

    // Internal calculation methods
    fn calculateSpamRate(self: *SmtpMetrics) f64 {
        if (self.counters.messages_received == 0) return 0.0;
        return @as(f64, @floatFromInt(self.counters.spam_detected)) /
            @as(f64, @floatFromInt(self.counters.messages_received)) * 100.0;
    }

    fn calculateBounceRate(self: *SmtpMetrics) f64 {
        if (self.counters.messages_sent == 0) return 0.0;
        return @as(f64, @floatFromInt(self.counters.messages_bounced)) /
            @as(f64, @floatFromInt(self.counters.messages_sent)) * 100.0;
    }

    fn calculateAuthSuccessRate(self: *SmtpMetrics) f64 {
        if (self.counters.auth_attempts == 0) return 0.0;
        return @as(f64, @floatFromInt(self.counters.auth_successes)) /
            @as(f64, @floatFromInt(self.counters.auth_attempts)) * 100.0;
    }

    fn calculateTlsRate(self: *SmtpMetrics) f64 {
        if (self.counters.connections_total == 0) return 0.0;
        return @as(f64, @floatFromInt(self.counters.connections_tls)) /
            @as(f64, @floatFromInt(self.counters.connections_total)) * 100.0;
    }

    fn calculateDkimPassRate(self: *SmtpMetrics) f64 {
        if (self.counters.dkim_checks == 0) return 0.0;
        return @as(f64, @floatFromInt(self.counters.dkim_passed)) /
            @as(f64, @floatFromInt(self.counters.dkim_checks)) * 100.0;
    }

    fn calculateDmarcPassRate(self: *SmtpMetrics) f64 {
        if (self.counters.dmarc_checks == 0) return 0.0;
        return @as(f64, @floatFromInt(self.counters.dmarc_passed)) /
            @as(f64, @floatFromInt(self.counters.dmarc_checks)) * 100.0;
    }
};

/// Counter metrics
pub const MetricCounters = struct {
    // Message counters
    messages_received: u64 = 0,
    messages_sent: u64 = 0,
    messages_bounced: u64 = 0,
    messages_deferred: u64 = 0,
    messages_scanned: u64 = 0,
    bytes_received: usize = 0,
    bytes_sent: usize = 0,

    // Bounce breakdown
    bounces_hard: u64 = 0,
    bounces_soft: u64 = 0,

    // Spam/Virus
    spam_detected: u64 = 0,
    viruses_detected: u64 = 0,

    // Authentication
    auth_attempts: u64 = 0,
    auth_successes: u64 = 0,
    auth_failures: u64 = 0,
    rate_limits_hit: u64 = 0,

    // Connections
    connections_total: u64 = 0,
    connections_tls: u64 = 0,

    // Email authentication
    dkim_checks: u64 = 0,
    dkim_passed: u64 = 0,
    dmarc_checks: u64 = 0,
    dmarc_passed: u64 = 0,
    spf_checks: u64 = 0,
};

/// Gauge metrics (current values)
pub const MetricGauges = struct {
    connections_active: usize = 0,
    queue_size: usize = 0,
    memory_used: usize = 0,
    queue_pending: usize = 0,
    queue_deferred: usize = 0,
    queue_active: usize = 0,
};

// =============================================================================
// Enhanced Metrics: Bounce Rate by Domain, Queue Histograms, Message Size
// =============================================================================

/// Domain-specific bounce tracking
pub const DomainBounceTracker = struct {
    const Self = @This();
    const DomainStats = struct {
        total_sent: u64 = 0,
        hard_bounces: u64 = 0,
        soft_bounces: u64 = 0,
        blocks: u64 = 0,

        pub fn bounceRate(self: DomainStats) f64 {
            if (self.total_sent == 0) return 0.0;
            const total_bounces = self.hard_bounces + self.soft_bounces + self.blocks;
            return @as(f64, @floatFromInt(total_bounces)) / @as(f64, @floatFromInt(self.total_sent)) * 100.0;
        }
    };

    allocator: std.mem.Allocator,
    domains: std.StringHashMap(DomainStats),
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .domains = std.StringHashMap(DomainStats).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        var iter = self.domains.keyIterator();
        while (iter.next()) |key| {
            self.allocator.free(key.*);
        }
        self.domains.deinit();
    }

    pub fn recordSent(self: *Self, domain: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.domains.getPtr(domain)) |stats| {
            stats.total_sent += 1;
        } else {
            const owned_domain = self.allocator.dupe(u8, domain) catch return;
            self.domains.put(owned_domain, DomainStats{ .total_sent = 1 }) catch {
                self.allocator.free(owned_domain);
            };
        }
    }

    pub fn recordBounce(self: *Self, domain: []const u8, bounce_type: BounceType) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.domains.getPtr(domain)) |stats| {
            switch (bounce_type) {
                .hard => stats.hard_bounces += 1,
                .soft => stats.soft_bounces += 1,
                .block => stats.blocks += 1,
                else => {},
            }
        } else {
            var new_stats = DomainStats{};
            switch (bounce_type) {
                .hard => new_stats.hard_bounces = 1,
                .soft => new_stats.soft_bounces = 1,
                .block => new_stats.blocks = 1,
                else => {},
            }
            const owned_domain = self.allocator.dupe(u8, domain) catch return;
            self.domains.put(owned_domain, new_stats) catch {
                self.allocator.free(owned_domain);
            };
        }
    }

    pub fn getBounceRate(self: *Self, domain: []const u8) f64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.domains.get(domain)) |stats| {
            return stats.bounceRate();
        }
        return 0.0;
    }

    pub fn getHighBounceRateDomains(self: *Self, threshold: f64) ![]const DomainBounceReport {
        self.mutex.lock();
        defer self.mutex.unlock();

        var reports = std.ArrayList(DomainBounceReport).init(self.allocator);
        errdefer reports.deinit();

        var iter = self.domains.iterator();
        while (iter.next()) |entry| {
            const stats = entry.value_ptr.*;
            const rate = stats.bounceRate();
            if (rate >= threshold) {
                try reports.append(.{
                    .domain = entry.key_ptr.*,
                    .bounce_rate = rate,
                    .total_sent = stats.total_sent,
                    .hard_bounces = stats.hard_bounces,
                    .soft_bounces = stats.soft_bounces,
                });
            }
        }

        return reports.toOwnedSlice();
    }
};

pub const DomainBounceReport = struct {
    domain: []const u8,
    bounce_rate: f64,
    total_sent: u64,
    hard_bounces: u64,
    soft_bounces: u64,
};

/// Queue depth histogram with configurable buckets
pub const QueueDepthHistogram = struct {
    const Self = @This();

    // Bucket boundaries: 0, 10, 50, 100, 500, 1000, 5000, 10000, 50000, inf
    buckets: [10]u64 = [_]u64{0} ** 10,
    bucket_boundaries: [9]usize = .{ 10, 50, 100, 500, 1000, 5000, 10000, 50000, 100000 },
    samples: u64 = 0,
    sum: u64 = 0,
    min: ?usize = null,
    max: ?usize = null,
    mutex: mutex_compat.Mutex = .{},

    pub fn record(self: *Self, depth: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.samples += 1;
        self.sum += depth;

        if (self.min == null or depth < self.min.?) {
            self.min = depth;
        }
        if (self.max == null or depth > self.max.?) {
            self.max = depth;
        }

        // Find bucket
        var bucket_idx: usize = self.bucket_boundaries.len;
        for (self.bucket_boundaries, 0..) |boundary, i| {
            if (depth < boundary) {
                bucket_idx = i;
                break;
            }
        }
        self.buckets[bucket_idx] += 1;
    }

    pub fn getPercentile(self: *Self, p: f64) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.samples == 0) return 0;

        const target = @as(u64, @intFromFloat(@as(f64, @floatFromInt(self.samples)) * p / 100.0));
        var cumulative: u64 = 0;

        for (self.buckets, 0..) |count, i| {
            cumulative += count;
            if (cumulative >= target) {
                if (i < self.bucket_boundaries.len) {
                    return self.bucket_boundaries[i];
                }
                return self.max orelse 0;
            }
        }
        return self.max orelse 0;
    }

    pub fn average(self: *Self) f64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.samples == 0) return 0.0;
        return @as(f64, @floatFromInt(self.sum)) / @as(f64, @floatFromInt(self.samples));
    }

    pub fn reset(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.buckets = [_]u64{0} ** 10;
        self.samples = 0;
        self.sum = 0;
        self.min = null;
        self.max = null;
    }
};

/// Message size distribution tracking
pub const MessageSizeDistribution = struct {
    const Self = @This();

    // Size buckets: 0-1KB, 1-10KB, 10-100KB, 100KB-1MB, 1-10MB, 10-50MB, 50MB+
    bucket_boundaries: [6]usize = .{ 1024, 10240, 102400, 1048576, 10485760, 52428800 },
    buckets: [7]u64 = [_]u64{0} ** 7,
    total_bytes: u64 = 0,
    total_messages: u64 = 0,
    min_size: ?usize = null,
    max_size: ?usize = null,
    mutex: mutex_compat.Mutex = .{},

    pub fn record(self: *Self, size: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.total_messages += 1;
        self.total_bytes += size;

        if (self.min_size == null or size < self.min_size.?) {
            self.min_size = size;
        }
        if (self.max_size == null or size > self.max_size.?) {
            self.max_size = size;
        }

        // Find bucket
        var bucket_idx: usize = self.bucket_boundaries.len;
        for (self.bucket_boundaries, 0..) |boundary, i| {
            if (size < boundary) {
                bucket_idx = i;
                break;
            }
        }
        self.buckets[bucket_idx] += 1;
    }

    pub fn averageSize(self: *Self) f64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.total_messages == 0) return 0.0;
        return @as(f64, @floatFromInt(self.total_bytes)) / @as(f64, @floatFromInt(self.total_messages));
    }

    pub fn getDistribution(self: *Self) SizeDistributionReport {
        self.mutex.lock();
        defer self.mutex.unlock();

        return .{
            .total_messages = self.total_messages,
            .total_bytes = self.total_bytes,
            .average_size = if (self.total_messages > 0)
                @as(f64, @floatFromInt(self.total_bytes)) / @as(f64, @floatFromInt(self.total_messages))
            else
                0.0,
            .min_size = self.min_size orelse 0,
            .max_size = self.max_size orelse 0,
            .under_1kb = self.buckets[0],
            .kb_1_to_10 = self.buckets[1],
            .kb_10_to_100 = self.buckets[2],
            .kb_100_to_1mb = self.buckets[3],
            .mb_1_to_10 = self.buckets[4],
            .mb_10_to_50 = self.buckets[5],
            .over_50mb = self.buckets[6],
        };
    }

    pub fn reset(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.buckets = [_]u64{0} ** 7;
        self.total_bytes = 0;
        self.total_messages = 0;
        self.min_size = null;
        self.max_size = null;
    }
};

pub const SizeDistributionReport = struct {
    total_messages: u64,
    total_bytes: u64,
    average_size: f64,
    min_size: usize,
    max_size: usize,
    under_1kb: u64,
    kb_1_to_10: u64,
    kb_10_to_100: u64,
    kb_100_to_1mb: u64,
    mb_1_to_10: u64,
    mb_10_to_50: u64,
    over_50mb: u64,
};

/// Extended metrics aggregator combining all enhanced metrics
pub const ExtendedMetrics = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    base_metrics: SmtpMetrics,
    domain_bounces: DomainBounceTracker,
    queue_histogram: QueueDepthHistogram,
    size_distribution: MessageSizeDistribution,

    // Per-protocol metrics
    imap_connections: u64 = 0,
    pop3_connections: u64 = 0,
    websocket_connections: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, statsd_host: ?[]const u8, statsd_port: u16, prefix: []const u8) !Self {
        return .{
            .allocator = allocator,
            .base_metrics = try SmtpMetrics.init(allocator, statsd_host, statsd_port, prefix),
            .domain_bounces = DomainBounceTracker.init(allocator),
            .queue_histogram = .{},
            .size_distribution = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.base_metrics.deinit();
        self.domain_bounces.deinit();
    }

    // Delegate to base metrics
    pub fn recordMessageReceived(self: *Self, domain: []const u8, size_bytes: usize) void {
        self.base_metrics.recordMessageReceived(domain, size_bytes);
        self.size_distribution.record(size_bytes);
    }

    pub fn recordMessageSent(self: *Self, domain: []const u8, size_bytes: usize, delivery_time_ms: u64) void {
        self.base_metrics.recordMessageSent(domain, size_bytes, delivery_time_ms);
        self.domain_bounces.recordSent(domain);
    }

    pub fn recordBounceWithDomain(self: *Self, bounce_type: BounceType, domain: []const u8) void {
        self.base_metrics.recordBounce(bounce_type, domain);
        self.domain_bounces.recordBounce(domain, bounce_type);
    }

    pub fn recordQueueDepth(self: *Self, depth: usize) void {
        self.queue_histogram.record(depth);
        self.base_metrics.updateQueueSize("main", depth);
    }

    pub fn getExtendedSnapshot(self: *Self) ExtendedMetricsSnapshot {
        return .{
            .base = self.base_metrics.getSnapshot(),
            .size_distribution = self.size_distribution.getDistribution(),
            .queue_p50 = self.queue_histogram.getPercentile(50),
            .queue_p95 = self.queue_histogram.getPercentile(95),
            .queue_p99 = self.queue_histogram.getPercentile(99),
            .queue_avg = self.queue_histogram.average(),
            .imap_connections = self.imap_connections,
            .pop3_connections = self.pop3_connections,
            .websocket_connections = self.websocket_connections,
        };
    }
};

pub const ExtendedMetricsSnapshot = struct {
    base: MetricsSnapshot,
    size_distribution: SizeDistributionReport,
    queue_p50: usize,
    queue_p95: usize,
    queue_p99: usize,
    queue_avg: f64,
    imap_connections: u64,
    pop3_connections: u64,
    websocket_connections: u64,
};

/// Histogram data for timing metrics
pub const MetricHistograms = struct {
    delivery_times: [100]u64,
    delivery_count: usize,
    scan_times: [100]u64,
    scan_count: usize,
    connection_durations: [100]u64,
    connection_count: usize,
    queue_times: [100]u64,
    queue_count: usize,
    spam_scores: [100]f64,
    spam_score_count: usize,

    pub fn init() MetricHistograms {
        return .{
            .delivery_times = [_]u64{0} ** 100,
            .delivery_count = 0,
            .scan_times = [_]u64{0} ** 100,
            .scan_count = 0,
            .connection_durations = [_]u64{0} ** 100,
            .connection_count = 0,
            .queue_times = [_]u64{0} ** 100,
            .queue_count = 0,
            .spam_scores = [_]f64{0} ** 100,
            .spam_score_count = 0,
        };
    }

    pub fn addDeliveryTime(self: *MetricHistograms, time: u64) void {
        if (self.delivery_count < 100) {
            self.delivery_times[self.delivery_count] = time;
            self.delivery_count += 1;
        }
    }

    pub fn addScanTime(self: *MetricHistograms, time: u64) void {
        if (self.scan_count < 100) {
            self.scan_times[self.scan_count] = time;
            self.scan_count += 1;
        }
    }

    pub fn addConnectionDuration(self: *MetricHistograms, duration: u64) void {
        if (self.connection_count < 100) {
            self.connection_durations[self.connection_count] = duration;
            self.connection_count += 1;
        }
    }

    pub fn addQueueTime(self: *MetricHistograms, time: u64) void {
        if (self.queue_count < 100) {
            self.queue_times[self.queue_count] = time;
            self.queue_count += 1;
        }
    }

    pub fn addSpamScore(self: *MetricHistograms, score: f64) void {
        if (self.spam_score_count < 100) {
            self.spam_scores[self.spam_score_count] = score;
            self.spam_score_count += 1;
        }
    }
};

/// Snapshot of metrics at a point in time
pub const MetricsSnapshot = struct {
    counters: MetricCounters,
    gauges: MetricGauges,
    spam_rate: f64,
    bounce_rate: f64,
    auth_success_rate: f64,
    tls_rate: f64,
    dkim_pass_rate: f64,
    dmarc_pass_rate: f64,
};

// Tests
test "metrics initialization" {
    const testing = std.testing;

    var metrics = try SmtpMetrics.init(testing.allocator, null, 8125, "smtp");
    defer metrics.deinit();

    try testing.expect(metrics.enabled);
    try testing.expectEqual(@as(u64, 0), metrics.counters.messages_received);
}

test "message metrics" {
    const testing = std.testing;

    var metrics = try SmtpMetrics.init(testing.allocator, null, 8125, "smtp");
    defer metrics.deinit();

    metrics.recordMessageReceived("example.com", 1024);
    metrics.recordMessageReceived("example.com", 2048);

    try testing.expectEqual(@as(u64, 2), metrics.counters.messages_received);
    try testing.expectEqual(@as(usize, 3072), metrics.counters.bytes_received);
}

test "spam rate calculation" {
    const testing = std.testing;

    var metrics = try SmtpMetrics.init(testing.allocator, null, 8125, "smtp");
    defer metrics.deinit();

    metrics.counters.messages_received = 100;
    metrics.counters.spam_detected = 5;

    const snapshot = metrics.getSnapshot();
    try testing.expectApproxEqAbs(@as(f64, 5.0), snapshot.spam_rate, 0.01);
}

test "auth success rate" {
    const testing = std.testing;

    var metrics = try SmtpMetrics.init(testing.allocator, null, 8125, "smtp");
    defer metrics.deinit();

    metrics.recordAuthAttempt(.plain, true);
    metrics.recordAuthAttempt(.plain, true);
    metrics.recordAuthAttempt(.plain, false);

    const snapshot = metrics.getSnapshot();
    try testing.expectApproxEqAbs(@as(f64, 66.66), snapshot.auth_success_rate, 0.1);
}

test "connection metrics" {
    const testing = std.testing;

    var metrics = try SmtpMetrics.init(testing.allocator, null, 8125, "smtp");
    defer metrics.deinit();

    metrics.recordConnection(.smtp, true);
    metrics.recordConnection(.submission, true);
    metrics.recordConnection(.smtp, false);

    try testing.expectEqual(@as(u64, 3), metrics.counters.connections_total);
    try testing.expectEqual(@as(u64, 2), metrics.counters.connections_tls);
    try testing.expectEqual(@as(usize, 3), metrics.gauges.connections_active);

    metrics.recordConnectionClosed(1000);
    try testing.expectEqual(@as(usize, 2), metrics.gauges.connections_active);
}
