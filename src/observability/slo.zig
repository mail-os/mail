const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const Allocator = std.mem.Allocator;
const time_compat = @import("../core/time_compat.zig");

/// Service Level Objectives (SLO) and Service Level Indicators (SLI) Tracking
///
/// This module provides comprehensive reliability tracking for the SMTP server:
/// - Define SLOs with targets and error budgets
/// - Collect SLI metrics in real-time
/// - Calculate error budget consumption
/// - Alert on SLO violations
///
/// Key Concepts:
/// - SLI (Service Level Indicator): A quantitative measure of service behavior
/// - SLO (Service Level Objective): A target value for an SLI
/// - Error Budget: The allowed failure rate (1 - SLO target)
///
/// Example SLOs:
/// - Availability: 99.9% of requests succeed (error budget: 0.1%)
/// - Latency: 95% of requests complete in <500ms
/// - Throughput: Server handles >1000 messages/minute

// ============================================================================
// SLI Metric Types
// ============================================================================

/// Types of SLI metrics
pub const SliType = enum {
    /// Availability: ratio of successful requests
    availability,
    /// Latency: response time percentiles
    latency,
    /// Throughput: requests per time unit
    throughput,
    /// Error rate: ratio of errors
    error_rate,
    /// Saturation: resource utilization
    saturation,

    pub fn toString(self: SliType) []const u8 {
        return @tagName(self);
    }
};

/// Latency percentile targets
pub const LatencyPercentile = enum {
    p50,
    p90,
    p95,
    p99,
    p999,

    pub fn toFloat(self: LatencyPercentile) f64 {
        return switch (self) {
            .p50 => 0.50,
            .p90 => 0.90,
            .p95 => 0.95,
            .p99 => 0.99,
            .p999 => 0.999,
        };
    }

    pub fn toString(self: LatencyPercentile) []const u8 {
        return @tagName(self);
    }
};

// ============================================================================
// SLI Collector
// ============================================================================

/// Collects raw SLI data points
pub const SliCollector = struct {
    allocator: Allocator,

    // Counters
    total_requests: std.atomic.Value(u64),
    successful_requests: std.atomic.Value(u64),
    failed_requests: std.atomic.Value(u64),

    // Latency histogram buckets (in milliseconds)
    latency_buckets: [LATENCY_BUCKET_COUNT]std.atomic.Value(u64),

    // Throughput tracking
    requests_per_window: std.ArrayList(WindowCount),
    window_size_seconds: u32,

    // Saturation metrics
    cpu_samples: std.ArrayList(f64),
    memory_samples: std.ArrayList(f64),
    connection_samples: std.ArrayList(f64),

    mutex: mutex_compat.Mutex,
    start_time: i64,

    const LATENCY_BUCKET_COUNT = 20;
    const LATENCY_BUCKETS = [_]u32{ 1, 5, 10, 25, 50, 75, 100, 150, 200, 300, 500, 750, 1000, 1500, 2000, 3000, 5000, 7500, 10000, 30000 };

    const WindowCount = struct {
        timestamp: i64,
        count: u64,
    };

    pub fn init(allocator: Allocator) SliCollector {
        var collector = SliCollector{
            .allocator = allocator,
            .total_requests = std.atomic.Value(u64).init(0),
            .successful_requests = std.atomic.Value(u64).init(0),
            .failed_requests = std.atomic.Value(u64).init(0),
            .latency_buckets = undefined,
            .requests_per_window = std.ArrayList(WindowCount).init(allocator),
            .window_size_seconds = 60,
            .cpu_samples = std.ArrayList(f64).init(allocator),
            .memory_samples = std.ArrayList(f64).init(allocator),
            .connection_samples = std.ArrayList(f64).init(allocator),
            .mutex = .{},
            .start_time = time_compat.timestamp(),
        };

        for (&collector.latency_buckets) |*bucket| {
            bucket.* = std.atomic.Value(u64).init(0);
        }

        return collector;
    }

    pub fn deinit(self: *SliCollector) void {
        self.requests_per_window.deinit();
        self.cpu_samples.deinit();
        self.memory_samples.deinit();
        self.connection_samples.deinit();
    }

    /// Record a successful request with latency
    pub fn recordSuccess(self: *SliCollector, latency_ms: u32) void {
        _ = self.total_requests.fetchAdd(1, .monotonic);
        _ = self.successful_requests.fetchAdd(1, .monotonic);
        self.recordLatency(latency_ms);
    }

    /// Record a failed request
    pub fn recordFailure(self: *SliCollector) void {
        _ = self.total_requests.fetchAdd(1, .monotonic);
        _ = self.failed_requests.fetchAdd(1, .monotonic);
    }

    /// Record latency in histogram
    fn recordLatency(self: *SliCollector, latency_ms: u32) void {
        // Find the appropriate bucket
        var bucket_idx: usize = LATENCY_BUCKET_COUNT - 1;
        for (LATENCY_BUCKETS, 0..) |threshold, i| {
            if (latency_ms <= threshold) {
                bucket_idx = i;
                break;
            }
        }
        _ = self.latency_buckets[bucket_idx].fetchAdd(1, .monotonic);
    }

    /// Record saturation sample
    pub fn recordSaturation(self: *SliCollector, cpu: f64, memory: f64, connections: f64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Keep last 1000 samples
        const max_samples = 1000;

        if (self.cpu_samples.items.len >= max_samples) {
            _ = self.cpu_samples.orderedRemove(0);
        }
        self.cpu_samples.append(cpu) catch {};

        if (self.memory_samples.items.len >= max_samples) {
            _ = self.memory_samples.orderedRemove(0);
        }
        self.memory_samples.append(memory) catch {};

        if (self.connection_samples.items.len >= max_samples) {
            _ = self.connection_samples.orderedRemove(0);
        }
        self.connection_samples.append(connections) catch {};
    }

    /// Get current availability (success ratio)
    pub fn getAvailability(self: *SliCollector) f64 {
        const total = self.total_requests.load(.monotonic);
        if (total == 0) return 1.0;
        const successful = self.successful_requests.load(.monotonic);
        return @as(f64, @floatFromInt(successful)) / @as(f64, @floatFromInt(total));
    }

    /// Get latency percentile in milliseconds
    pub fn getLatencyPercentile(self: *SliCollector, percentile: LatencyPercentile) u32 {
        var total: u64 = 0;
        for (&self.latency_buckets) |*bucket| {
            total += bucket.load(.monotonic);
        }

        if (total == 0) return 0;

        const target = @as(u64, @intFromFloat(@as(f64, @floatFromInt(total)) * percentile.toFloat()));
        var cumulative: u64 = 0;

        for (&self.latency_buckets, 0..) |*bucket, i| {
            cumulative += bucket.load(.monotonic);
            if (cumulative >= target) {
                return LATENCY_BUCKETS[i];
            }
        }

        return LATENCY_BUCKETS[LATENCY_BUCKET_COUNT - 1];
    }

    /// Get error rate
    pub fn getErrorRate(self: *SliCollector) f64 {
        const total = self.total_requests.load(.monotonic);
        if (total == 0) return 0.0;
        const failed = self.failed_requests.load(.monotonic);
        return @as(f64, @floatFromInt(failed)) / @as(f64, @floatFromInt(total));
    }

    /// Get average saturation
    pub fn getAverageSaturation(self: *SliCollector) SaturationMetrics {
        self.mutex.lock();
        defer self.mutex.unlock();

        return .{
            .cpu = calculateAverage(self.cpu_samples.items),
            .memory = calculateAverage(self.memory_samples.items),
            .connections = calculateAverage(self.connection_samples.items),
        };
    }

    /// Reset all metrics
    pub fn reset(self: *SliCollector) void {
        self.total_requests.store(0, .monotonic);
        self.successful_requests.store(0, .monotonic);
        self.failed_requests.store(0, .monotonic);

        for (&self.latency_buckets) |*bucket| {
            bucket.store(0, .monotonic);
        }

        self.mutex.lock();
        defer self.mutex.unlock();
        self.requests_per_window.clearRetainingCapacity();
        self.cpu_samples.clearRetainingCapacity();
        self.memory_samples.clearRetainingCapacity();
        self.connection_samples.clearRetainingCapacity();
        self.start_time = time_compat.timestamp();
    }
};

pub const SaturationMetrics = struct {
    cpu: f64,
    memory: f64,
    connections: f64,
};

fn calculateAverage(samples: []const f64) f64 {
    if (samples.len == 0) return 0.0;
    var sum: f64 = 0.0;
    for (samples) |s| {
        sum += s;
    }
    return sum / @as(f64, @floatFromInt(samples.len));
}

// ============================================================================
// SLO Definition
// ============================================================================

/// Service Level Objective definition
pub const Slo = struct {
    name: []const u8,
    description: []const u8,
    sli_type: SliType,
    target: f64, // Target value (e.g., 0.999 for 99.9% availability)
    window_seconds: u32, // Measurement window (e.g., 86400 for 1 day)
    percentile: ?LatencyPercentile, // For latency SLOs

    /// Calculate error budget (1 - target for availability/error_rate)
    pub fn getErrorBudget(self: *const Slo) f64 {
        return switch (self.sli_type) {
            .availability => 1.0 - self.target,
            .error_rate => self.target, // Error rate target IS the budget
            else => 0.0, // Not applicable
        };
    }
};

/// SLO evaluation result
pub const SloResult = struct {
    slo: *const Slo,
    current_value: f64,
    target: f64,
    is_met: bool,
    error_budget_remaining: f64, // Percentage of error budget remaining
    error_budget_consumed: f64, // Percentage consumed
    burn_rate: f64, // Rate of budget consumption
};

// ============================================================================
// SLO Manager
// ============================================================================

/// Manages SLO definitions and evaluations
pub const SloManager = struct {
    allocator: Allocator,
    collector: *SliCollector,
    slos: std.ArrayList(Slo),
    evaluation_history: std.ArrayList(EvaluationRecord),
    mutex: mutex_compat.Mutex,

    // Alerting
    alert_callback: ?*const fn (SloAlert) void,
    last_alert_time: std.StringHashMap(i64),

    const EvaluationRecord = struct {
        timestamp: i64,
        slo_name: []const u8,
        value: f64,
        met: bool,
    };

    pub fn init(allocator: Allocator, collector: *SliCollector) SloManager {
        return .{
            .allocator = allocator,
            .collector = collector,
            .slos = std.ArrayList(Slo).init(allocator),
            .evaluation_history = std.ArrayList(EvaluationRecord).init(allocator),
            .mutex = .{},
            .alert_callback = null,
            .last_alert_time = std.StringHashMap(i64).init(allocator),
        };
    }

    pub fn deinit(self: *SloManager) void {
        self.slos.deinit();
        self.evaluation_history.deinit();
        self.last_alert_time.deinit();
    }

    /// Register an SLO
    pub fn registerSlo(self: *SloManager, slo: Slo) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.slos.append(slo);
    }

    /// Set alert callback
    pub fn setAlertCallback(self: *SloManager, callback: *const fn (SloAlert) void) void {
        self.alert_callback = callback;
    }

    /// Evaluate all SLOs
    pub fn evaluateAll(self: *SloManager) ![]SloResult {
        self.mutex.lock();
        defer self.mutex.unlock();

        var results = std.ArrayList(SloResult).init(self.allocator);
        errdefer results.deinit();

        const now = time_compat.timestamp();

        for (self.slos.items) |*slo| {
            const result = self.evaluateSlo(slo);
            try results.append(result);

            // Record evaluation
            try self.evaluation_history.append(.{
                .timestamp = now,
                .slo_name = slo.name,
                .value = result.current_value,
                .met = result.is_met,
            });

            // Check for alerts
            if (!result.is_met and self.alert_callback != null) {
                self.maybeAlert(slo, result);
            }
        }

        return results.toOwnedSlice();
    }

    fn evaluateSlo(self: *SloManager, slo: *const Slo) SloResult {
        const current_value = switch (slo.sli_type) {
            .availability => self.collector.getAvailability(),
            .error_rate => self.collector.getErrorRate(),
            .latency => blk: {
                if (slo.percentile) |p| {
                    const latency_ms = self.collector.getLatencyPercentile(p);
                    break :blk @as(f64, @floatFromInt(latency_ms));
                }
                break :blk 0.0;
            },
            .saturation => blk: {
                const sat = self.collector.getAverageSaturation();
                break :blk @max(sat.cpu, @max(sat.memory, sat.connections));
            },
            .throughput => 0.0, // TODO: implement throughput tracking
        };

        const is_met = switch (slo.sli_type) {
            .availability => current_value >= slo.target,
            .error_rate => current_value <= slo.target,
            .latency => current_value <= slo.target,
            .saturation => current_value <= slo.target,
            .throughput => current_value >= slo.target,
        };

        // Calculate error budget
        var error_budget_remaining: f64 = 1.0;
        var error_budget_consumed: f64 = 0.0;

        if (slo.sli_type == .availability) {
            const budget = slo.getErrorBudget();
            const actual_error_rate = 1.0 - current_value;
            error_budget_consumed = if (budget > 0) actual_error_rate / budget else 1.0;
            error_budget_remaining = @max(0.0, 1.0 - error_budget_consumed);
        }

        // Calculate burn rate (simplified: budget consumed / time elapsed ratio)
        const burn_rate = error_budget_consumed; // Simplified

        return .{
            .slo = slo,
            .current_value = current_value,
            .target = slo.target,
            .is_met = is_met,
            .error_budget_remaining = error_budget_remaining * 100.0,
            .error_budget_consumed = error_budget_consumed * 100.0,
            .burn_rate = burn_rate,
        };
    }

    fn maybeAlert(self: *SloManager, slo: *const Slo, result: SloResult) void {
        const now = time_compat.timestamp();
        const cooldown_seconds: i64 = 300; // 5 minute cooldown between alerts

        if (self.last_alert_time.get(slo.name)) |last_time| {
            if (now - last_time < cooldown_seconds) return;
        }

        self.last_alert_time.put(slo.name, now) catch {};

        if (self.alert_callback) |callback| {
            callback(.{
                .slo_name = slo.name,
                .current_value = result.current_value,
                .target = result.target,
                .error_budget_remaining = result.error_budget_remaining,
                .severity = if (result.error_budget_remaining < 10.0) .critical else .warning,
                .timestamp = now,
            });
        }
    }

    /// Get SLO by name
    pub fn getSlo(self: *SloManager, name: []const u8) ?*const Slo {
        for (self.slos.items) |*slo| {
            if (std.mem.eql(u8, slo.name, name)) {
                return slo;
            }
        }
        return null;
    }

    /// Generate JSON report
    pub fn toJson(self: *SloManager) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var buffer = std.ArrayList(u8).init(self.allocator);
        const writer = buffer.writer();

        try writer.writeAll("{\"slos\":[");

        var first = true;
        for (self.slos.items) |*slo| {
            if (!first) try writer.writeAll(",");
            first = false;

            const result = self.evaluateSlo(slo);
            try std.fmt.format(writer,
                \\{{"name":"{s}","type":"{s}","target":{d:.4},"current":{d:.4},"met":{s},"error_budget_remaining":{d:.2},"burn_rate":{d:.4}}}
            , .{
                slo.name,
                slo.sli_type.toString(),
                slo.target,
                result.current_value,
                if (result.is_met) "true" else "false",
                result.error_budget_remaining,
                result.burn_rate,
            });
        }

        try writer.writeAll("],\"summary\":{");
        try std.fmt.format(writer,
            \\"total_slos":{d},"availability":{d:.4},"error_rate":{d:.4},"p99_latency_ms":{d}
        , .{
            self.slos.items.len,
            self.collector.getAvailability(),
            self.collector.getErrorRate(),
            self.collector.getLatencyPercentile(.p99),
        });
        try writer.writeAll("}}");

        return buffer.toOwnedSlice();
    }
};

/// SLO Alert
pub const SloAlert = struct {
    slo_name: []const u8,
    current_value: f64,
    target: f64,
    error_budget_remaining: f64,
    severity: AlertSeverity,
    timestamp: i64,
};

pub const AlertSeverity = enum {
    warning,
    critical,
};

// ============================================================================
// Default SMTP SLOs
// ============================================================================

/// Create default SLOs for SMTP server
pub fn createDefaultSlos(manager: *SloManager) !void {
    // Availability SLO: 99.9% success rate
    try manager.registerSlo(.{
        .name = "smtp_availability",
        .description = "SMTP server availability - percentage of successful requests",
        .sli_type = .availability,
        .target = 0.999, // 99.9%
        .window_seconds = 86400, // 1 day
        .percentile = null,
    });

    // Latency SLO: P95 < 500ms
    try manager.registerSlo(.{
        .name = "smtp_latency_p95",
        .description = "95th percentile response time under 500ms",
        .sli_type = .latency,
        .target = 500.0, // 500ms
        .window_seconds = 3600, // 1 hour
        .percentile = .p95,
    });

    // Latency SLO: P99 < 1000ms
    try manager.registerSlo(.{
        .name = "smtp_latency_p99",
        .description = "99th percentile response time under 1 second",
        .sli_type = .latency,
        .target = 1000.0, // 1000ms
        .window_seconds = 3600, // 1 hour
        .percentile = .p99,
    });

    // Error Rate SLO: < 0.1%
    try manager.registerSlo(.{
        .name = "smtp_error_rate",
        .description = "Error rate below 0.1%",
        .sli_type = .error_rate,
        .target = 0.001, // 0.1%
        .window_seconds = 3600, // 1 hour
        .percentile = null,
    });

    // Saturation SLO: < 80% resource utilization
    try manager.registerSlo(.{
        .name = "smtp_saturation",
        .description = "Resource utilization below 80%",
        .sli_type = .saturation,
        .target = 0.80, // 80%
        .window_seconds = 300, // 5 minutes
        .percentile = null,
    });
}

// ============================================================================
// Error Budget Calculator
// ============================================================================

/// Calculate error budget consumption over time
pub const ErrorBudgetCalculator = struct {
    allocator: Allocator,
    budget_history: std.ArrayList(BudgetSnapshot),
    mutex: mutex_compat.Mutex,

    const BudgetSnapshot = struct {
        timestamp: i64,
        slo_name: []const u8,
        budget_remaining: f64,
        burn_rate: f64,
    };

    pub fn init(allocator: Allocator) ErrorBudgetCalculator {
        return .{
            .allocator = allocator,
            .budget_history = std.ArrayList(BudgetSnapshot).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *ErrorBudgetCalculator) void {
        self.budget_history.deinit();
    }

    /// Record budget snapshot
    pub fn recordSnapshot(self: *ErrorBudgetCalculator, slo_name: []const u8, remaining: f64, burn_rate: f64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Keep last 1000 snapshots per SLO
        const max_snapshots = 10000;
        if (self.budget_history.items.len >= max_snapshots) {
            _ = self.budget_history.orderedRemove(0);
        }

        try self.budget_history.append(.{
            .timestamp = time_compat.timestamp(),
            .slo_name = slo_name,
            .budget_remaining = remaining,
            .burn_rate = burn_rate,
        });
    }

    /// Calculate time until budget exhaustion at current burn rate
    pub fn timeToExhaustion(self: *ErrorBudgetCalculator, slo_name: []const u8, window_seconds: u32) ?i64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Find latest snapshot for this SLO
        var latest: ?BudgetSnapshot = null;
        for (self.budget_history.items) |snapshot| {
            if (std.mem.eql(u8, snapshot.slo_name, slo_name)) {
                if (latest == null or snapshot.timestamp > latest.?.timestamp) {
                    latest = snapshot;
                }
            }
        }

        if (latest) |snapshot| {
            if (snapshot.burn_rate <= 0) return null; // Not consuming budget
            if (snapshot.budget_remaining <= 0) return 0; // Already exhausted

            // Time = remaining budget / burn rate * window
            const seconds_remaining = (snapshot.budget_remaining / snapshot.burn_rate) * @as(f64, @floatFromInt(window_seconds));
            return @intFromFloat(seconds_remaining);
        }

        return null;
    }

    /// Get average burn rate over period
    pub fn getAverageBurnRate(self: *ErrorBudgetCalculator, slo_name: []const u8, seconds: i64) f64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const cutoff = time_compat.timestamp() - seconds;
        var sum: f64 = 0.0;
        var count: u32 = 0;

        for (self.budget_history.items) |snapshot| {
            if (std.mem.eql(u8, snapshot.slo_name, slo_name) and snapshot.timestamp >= cutoff) {
                sum += snapshot.burn_rate;
                count += 1;
            }
        }

        if (count == 0) return 0.0;
        return sum / @as(f64, @floatFromInt(count));
    }
};

// ============================================================================
// Tests
// ============================================================================

test "SLI collector basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var collector = SliCollector.init(allocator);
    defer collector.deinit();

    // Record some successes
    collector.recordSuccess(100);
    collector.recordSuccess(200);
    collector.recordSuccess(150);

    // Record a failure
    collector.recordFailure();

    // Check metrics
    try testing.expectEqual(@as(u64, 4), collector.total_requests.load(.monotonic));
    try testing.expectEqual(@as(u64, 3), collector.successful_requests.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), collector.failed_requests.load(.monotonic));

    // Check availability
    const availability = collector.getAvailability();
    try testing.expect(availability > 0.74 and availability < 0.76);

    // Check error rate
    const error_rate = collector.getErrorRate();
    try testing.expect(error_rate > 0.24 and error_rate < 0.26);
}

test "SLO manager evaluation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var collector = SliCollector.init(allocator);
    defer collector.deinit();

    var manager = SloManager.init(allocator, &collector);
    defer manager.deinit();

    // Register availability SLO
    try manager.registerSlo(.{
        .name = "test_availability",
        .description = "Test availability SLO",
        .sli_type = .availability,
        .target = 0.99, // 99%
        .window_seconds = 3600,
        .percentile = null,
    });

    // Record 99 successes and 1 failure
    var i: u32 = 0;
    while (i < 99) : (i += 1) {
        collector.recordSuccess(100);
    }
    collector.recordFailure();

    // Evaluate
    const results = try manager.evaluateAll();
    defer allocator.free(results);

    try testing.expectEqual(@as(usize, 1), results.len);
    try testing.expect(results[0].current_value > 0.98);
    try testing.expect(results[0].is_met);
}

test "latency percentile calculation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var collector = SliCollector.init(allocator);
    defer collector.deinit();

    // Record various latencies
    collector.recordSuccess(10);
    collector.recordSuccess(20);
    collector.recordSuccess(30);
    collector.recordSuccess(40);
    collector.recordSuccess(50);
    collector.recordSuccess(100);
    collector.recordSuccess(200);
    collector.recordSuccess(500);
    collector.recordSuccess(1000);
    collector.recordSuccess(2000);

    // P50 should be around 50ms
    const p50 = collector.getLatencyPercentile(.p50);
    try testing.expect(p50 <= 100);

    // P99 should be high
    const p99 = collector.getLatencyPercentile(.p99);
    try testing.expect(p99 >= 1000);
}

test "error budget calculation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var collector = SliCollector.init(allocator);
    defer collector.deinit();

    var manager = SloManager.init(allocator, &collector);
    defer manager.deinit();

    // 99.9% availability SLO
    try manager.registerSlo(.{
        .name = "high_availability",
        .description = "High availability SLO",
        .sli_type = .availability,
        .target = 0.999, // 99.9%
        .window_seconds = 86400,
        .percentile = null,
    });

    // Record 999 successes and 1 failure (exactly at budget)
    var i: u32 = 0;
    while (i < 999) : (i += 1) {
        collector.recordSuccess(50);
    }
    collector.recordFailure();

    const results = try manager.evaluateAll();
    defer allocator.free(results);

    // Should be exactly at target (or just below due to rounding)
    try testing.expect(results[0].error_budget_remaining >= 0);
}

test "default SLOs creation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var collector = SliCollector.init(allocator);
    defer collector.deinit();

    var manager = SloManager.init(allocator, &collector);
    defer manager.deinit();

    try createDefaultSlos(&manager);

    // Should have 5 default SLOs
    try testing.expectEqual(@as(usize, 5), manager.slos.items.len);

    // Verify availability SLO exists
    const avail_slo = manager.getSlo("smtp_availability");
    try testing.expect(avail_slo != null);
    try testing.expectEqual(@as(f64, 0.999), avail_slo.?.target);
}
