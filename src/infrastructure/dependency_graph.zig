const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const Allocator = std.mem.Allocator;
const time_compat = @import("../core/time_compat.zig");

/// Service Dependency Graph for Graceful Degradation
///
/// This module tracks service dependencies and their health status to enable:
/// - Graceful degradation when dependencies fail
/// - Dependency-aware health checks
/// - Circuit breaking based on dependency health
/// - Feature flags based on available dependencies
///
/// Architecture:
/// ```
/// ┌─────────────────────────────────────────────────────────┐
/// │                    SMTP Server                          │
/// │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐   │
/// │  │ Core    │  │ Auth    │  │ Storage │  │ Delivery│   │
/// │  │ Service │  │ Service │  │ Service │  │ Service │   │
/// │  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘   │
/// │       │            │            │            │         │
/// │       └────────────┴─────┬──────┴────────────┘         │
/// │                          │                              │
/// │                   ┌──────┴──────┐                       │
/// │                   │ Dependency  │                       │
/// │                   │   Graph     │                       │
/// │                   └──────┬──────┘                       │
/// └──────────────────────────┼──────────────────────────────┘
///                            │
///        ┌───────────────────┼───────────────────┐
///        │                   │                   │
///   ┌────┴────┐        ┌─────┴─────┐       ┌────┴────┐
///   │Database │        │  External │       │  File   │
///   │ SQLite  │        │  Services │       │ System  │
///   └─────────┘        └───────────┘       └─────────┘
/// ```

// ============================================================================
// Service Types
// ============================================================================

/// Service identifier
pub const ServiceId = enum {
    // Core services
    smtp_server,
    health_api,
    metrics_api,
    admin_api,
    websocket,

    // Storage services
    database,
    maildir_storage,
    queue_storage,
    search_index,

    // Security services
    authentication,
    rate_limiter,
    csrf_protection,
    tls_handler,

    // Email processing services
    spf_validator,
    dkim_validator,
    dmarc_validator,
    spam_filter,
    virus_scanner,
    greylist,
    dnsbl_checker,

    // Delivery services
    relay_client,
    dns_resolver,
    webhook_notifier,

    // External integrations
    vault_secrets,
    aws_secrets,
    clamav,
    spamassassin,

    // Cluster services
    cluster_manager,
    raft_consensus,
    multi_region,

    pub fn toString(self: ServiceId) []const u8 {
        return @tagName(self);
    }
};

/// Service health status
pub const ServiceHealth = enum {
    healthy,
    degraded,
    unhealthy,
    unknown,

    pub fn toString(self: ServiceHealth) []const u8 {
        return switch (self) {
            .healthy => "healthy",
            .degraded => "degraded",
            .unhealthy => "unhealthy",
            .unknown => "unknown",
        };
    }

    pub fn toInt(self: ServiceHealth) u8 {
        return switch (self) {
            .healthy => 3,
            .degraded => 2,
            .unhealthy => 1,
            .unknown => 0,
        };
    }
};

/// Dependency criticality level
pub const Criticality = enum {
    /// Service cannot function without this dependency
    critical,
    /// Service can function but with reduced capability
    important,
    /// Service can function normally without this dependency
    optional,

    pub fn toString(self: Criticality) []const u8 {
        return @tagName(self);
    }
};

// ============================================================================
// Service Node
// ============================================================================

/// Service node in the dependency graph
pub const ServiceNode = struct {
    id: ServiceId,
    health: ServiceHealth,
    last_check: i64,
    last_healthy: i64,
    check_interval_ms: u32,
    timeout_ms: u32,
    consecutive_failures: u32,
    failure_threshold: u32,
    dependencies: std.ArrayList(Dependency),
    features_provided: std.ArrayList([]const u8),
    metadata: std.StringHashMap([]const u8),

    pub fn init(allocator: Allocator, id: ServiceId) ServiceNode {
        return .{
            .id = id,
            .health = .unknown,
            .last_check = 0,
            .last_healthy = 0,
            .check_interval_ms = 30000, // 30 seconds default
            .timeout_ms = 5000, // 5 seconds default
            .consecutive_failures = 0,
            .failure_threshold = 3,
            .dependencies = std.ArrayList(Dependency).init(allocator),
            .features_provided = std.ArrayList([]const u8).init(allocator),
            .metadata = std.StringHashMap([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *ServiceNode) void {
        self.dependencies.deinit();
        self.features_provided.deinit();
        self.metadata.deinit();
    }

    /// Check if service is available (healthy or degraded)
    pub fn isAvailable(self: *const ServiceNode) bool {
        return self.health == .healthy or self.health == .degraded;
    }

    /// Update health status
    pub fn updateHealth(self: *ServiceNode, health: ServiceHealth) void {
        const now = time_compat.timestamp();
        self.last_check = now;

        if (health == .healthy) {
            self.last_healthy = now;
            self.consecutive_failures = 0;
        } else if (health == .unhealthy) {
            self.consecutive_failures += 1;
        }

        self.health = health;
    }

    /// Check if health check is due
    pub fn needsHealthCheck(self: *const ServiceNode) bool {
        const now = time_compat.timestamp();
        const elapsed_ms: u64 = @intCast((now - self.last_check) * 1000);
        return elapsed_ms >= self.check_interval_ms;
    }
};

/// Dependency relationship
pub const Dependency = struct {
    target: ServiceId,
    criticality: Criticality,
    /// Features that require this dependency
    required_for: []const u8,
};

// ============================================================================
// Dependency Graph
// ============================================================================

/// Service Dependency Graph Manager
pub const DependencyGraph = struct {
    allocator: Allocator,
    services: std.AutoHashMap(ServiceId, ServiceNode),
    mutex: mutex_compat.Mutex,

    // Statistics
    total_health_checks: u64,
    total_failures: u64,
    last_full_check: i64,

    pub fn init(allocator: Allocator) DependencyGraph {
        return .{
            .allocator = allocator,
            .services = std.AutoHashMap(ServiceId, ServiceNode).init(allocator),
            .mutex = .{},
            .total_health_checks = 0,
            .total_failures = 0,
            .last_full_check = 0,
        };
    }

    pub fn deinit(self: *DependencyGraph) void {
        var it = self.services.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.services.deinit();
    }

    /// Register a service in the graph
    pub fn registerService(self: *DependencyGraph, id: ServiceId) !*ServiceNode {
        self.mutex.lock();
        defer self.mutex.unlock();

        const result = try self.services.getOrPut(id);
        if (!result.found_existing) {
            result.value_ptr.* = ServiceNode.init(self.allocator, id);
        }
        return result.value_ptr;
    }

    /// Add a dependency between services
    pub fn addDependency(
        self: *DependencyGraph,
        from: ServiceId,
        to: ServiceId,
        criticality: Criticality,
        required_for: []const u8,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.services.getPtr(from)) |node| {
            try node.dependencies.append(.{
                .target = to,
                .criticality = criticality,
                .required_for = required_for,
            });
        }
    }

    /// Update service health
    pub fn updateServiceHealth(self: *DependencyGraph, id: ServiceId, health: ServiceHealth) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.services.getPtr(id)) |node| {
            node.updateHealth(health);
            self.total_health_checks += 1;
            if (health == .unhealthy) {
                self.total_failures += 1;
            }
        }
    }

    /// Get service health
    pub fn getServiceHealth(self: *DependencyGraph, id: ServiceId) ServiceHealth {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.services.get(id)) |node| {
            return node.health;
        }
        return .unknown;
    }

    /// Check if a feature is available based on dependencies
    pub fn isFeatureAvailable(self: *DependencyGraph, service_id: ServiceId, feature: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const node = self.services.get(service_id) orelse return false;

        // Check if the service itself is available
        if (!node.isAvailable()) return false;

        // Check all critical dependencies for this feature
        for (node.dependencies.items) |dep| {
            if (dep.criticality == .critical) {
                if (std.mem.eql(u8, dep.required_for, feature) or std.mem.eql(u8, dep.required_for, "*")) {
                    const dep_node = self.services.get(dep.target) orelse return false;
                    if (!dep_node.isAvailable()) return false;
                }
            }
        }

        return true;
    }

    /// Get effective health considering dependencies
    pub fn getEffectiveHealth(self: *DependencyGraph, id: ServiceId) ServiceHealth {
        self.mutex.lock();
        defer self.mutex.unlock();

        const node = self.services.get(id) orelse return .unknown;

        // Start with the service's own health
        var effective = node.health;

        // Check dependencies
        for (node.dependencies.items) |dep| {
            const dep_node = self.services.get(dep.target) orelse continue;

            switch (dep.criticality) {
                .critical => {
                    // Critical dependency unhealthy -> service unhealthy
                    if (dep_node.health == .unhealthy) {
                        return .unhealthy;
                    }
                    if (dep_node.health == .degraded and effective == .healthy) {
                        effective = .degraded;
                    }
                },
                .important => {
                    // Important dependency issues -> degraded at most
                    if (dep_node.health != .healthy and effective == .healthy) {
                        effective = .degraded;
                    }
                },
                .optional => {
                    // Optional dependencies don't affect health
                },
            }
        }

        return effective;
    }

    /// Get all services with a specific health status
    pub fn getServicesByHealth(self: *DependencyGraph, health: ServiceHealth) ![]ServiceId {
        self.mutex.lock();
        defer self.mutex.unlock();

        var result = std.ArrayList(ServiceId).init(self.allocator);
        errdefer result.deinit();

        var it = self.services.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.health == health) {
                try result.append(entry.key_ptr.*);
            }
        }

        return result.toOwnedSlice();
    }

    /// Get dependency chain for a service
    pub fn getDependencyChain(self: *DependencyGraph, id: ServiceId) ![]ServiceId {
        self.mutex.lock();
        defer self.mutex.unlock();

        var result = std.ArrayList(ServiceId).init(self.allocator);
        errdefer result.deinit();

        var visited = std.AutoHashMap(ServiceId, void).init(self.allocator);
        defer visited.deinit();

        try self.collectDependencies(id, &result, &visited);

        return result.toOwnedSlice();
    }

    fn collectDependencies(
        self: *DependencyGraph,
        id: ServiceId,
        result: *std.ArrayList(ServiceId),
        visited: *std.AutoHashMap(ServiceId, void),
    ) !void {
        if (visited.contains(id)) return;
        try visited.put(id, {});

        const node = self.services.get(id) orelse return;

        for (node.dependencies.items) |dep| {
            try result.append(dep.target);
            try self.collectDependencies(dep.target, result, visited);
        }
    }

    /// Get overall system health
    pub fn getSystemHealth(self: *DependencyGraph) SystemHealthReport {
        self.mutex.lock();
        defer self.mutex.unlock();

        var report = SystemHealthReport{
            .overall_health = .healthy,
            .healthy_count = 0,
            .degraded_count = 0,
            .unhealthy_count = 0,
            .unknown_count = 0,
            .critical_services_down = std.ArrayList(ServiceId).init(self.allocator),
        };

        var it = self.services.iterator();
        while (it.next()) |entry| {
            switch (entry.value_ptr.health) {
                .healthy => report.healthy_count += 1,
                .degraded => {
                    report.degraded_count += 1;
                    if (report.overall_health == .healthy) {
                        report.overall_health = .degraded;
                    }
                },
                .unhealthy => {
                    report.unhealthy_count += 1;
                    report.overall_health = .unhealthy;
                    // Check if this is a critical service
                    if (isCriticalService(entry.key_ptr.*)) {
                        report.critical_services_down.append(entry.key_ptr.*) catch {};
                    }
                },
                .unknown => report.unknown_count += 1,
            }
        }

        return report;
    }

    /// Generate JSON status report
    pub fn toJson(self: *DependencyGraph) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var buffer = std.ArrayList(u8).init(self.allocator);
        const writer = buffer.writer();

        try writer.writeAll("{\"services\":[");

        var first = true;
        var it = self.services.iterator();
        while (it.next()) |entry| {
            if (!first) try writer.writeAll(",");
            first = false;

            try std.fmt.format(writer,
                \\{{"id":"{s}","health":"{s}","last_check":{d},"failures":{d},"dependencies":[
            , .{
                entry.key_ptr.toString(),
                entry.value_ptr.health.toString(),
                entry.value_ptr.last_check,
                entry.value_ptr.consecutive_failures,
            });

            var dep_first = true;
            for (entry.value_ptr.dependencies.items) |dep| {
                if (!dep_first) try writer.writeAll(",");
                dep_first = false;
                try std.fmt.format(writer,
                    \\{{"target":"{s}","criticality":"{s}"}}
                , .{ dep.target.toString(), dep.criticality.toString() });
            }
            try writer.writeAll("]}");
        }

        try writer.writeAll("],\"statistics\":{");
        try std.fmt.format(writer,
            \\"total_checks":{d},"total_failures":{d},"last_full_check":{d}
        , .{ self.total_health_checks, self.total_failures, self.last_full_check });
        try writer.writeAll("}}");

        return buffer.toOwnedSlice();
    }
};

/// System health report
pub const SystemHealthReport = struct {
    overall_health: ServiceHealth,
    healthy_count: u32,
    degraded_count: u32,
    unhealthy_count: u32,
    unknown_count: u32,
    critical_services_down: std.ArrayList(ServiceId),

    pub fn deinit(self: *SystemHealthReport) void {
        self.critical_services_down.deinit();
    }
};

/// Check if a service is critical for basic operation
fn isCriticalService(id: ServiceId) bool {
    return switch (id) {
        .smtp_server, .database, .authentication, .rate_limiter => true,
        else => false,
    };
}

// ============================================================================
// Graceful Degradation Manager
// ============================================================================

/// Manages graceful degradation based on dependency health
pub const DegradationManager = struct {
    allocator: Allocator,
    graph: *DependencyGraph,
    disabled_features: std.StringHashMap(DisabledFeature),
    mutex: mutex_compat.Mutex,

    pub const DisabledFeature = struct {
        feature: []const u8,
        reason: []const u8,
        disabled_at: i64,
        dependency: ServiceId,
    };

    pub fn init(allocator: Allocator, graph: *DependencyGraph) DegradationManager {
        return .{
            .allocator = allocator,
            .graph = graph,
            .disabled_features = std.StringHashMap(DisabledFeature).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *DegradationManager) void {
        self.disabled_features.deinit();
    }

    /// Check and update degradation status
    pub fn checkDegradation(self: *DegradationManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check database dependency
        if (self.graph.getServiceHealth(.database) == .unhealthy) {
            self.disableFeatureInternal("user_management", "Database unavailable", .database);
            self.disableFeatureInternal("message_storage", "Database unavailable", .database);
            self.disableFeatureInternal("search", "Database unavailable", .database);
        } else {
            self.enableFeatureInternal("user_management");
            self.enableFeatureInternal("message_storage");
            self.enableFeatureInternal("search");
        }

        // Check spam filter dependencies
        if (self.graph.getServiceHealth(.spamassassin) == .unhealthy) {
            self.disableFeatureInternal("spam_scoring", "SpamAssassin unavailable", .spamassassin);
        } else {
            self.enableFeatureInternal("spam_scoring");
        }

        // Check virus scanner
        if (self.graph.getServiceHealth(.clamav) == .unhealthy) {
            self.disableFeatureInternal("virus_scanning", "ClamAV unavailable", .clamav);
        } else {
            self.enableFeatureInternal("virus_scanning");
        }

        // Check DNS resolver
        if (self.graph.getServiceHealth(.dns_resolver) == .unhealthy) {
            self.disableFeatureInternal("outbound_delivery", "DNS resolver unavailable", .dns_resolver);
            self.disableFeatureInternal("spf_validation", "DNS resolver unavailable", .dns_resolver);
            self.disableFeatureInternal("dkim_validation", "DNS resolver unavailable", .dns_resolver);
        } else {
            self.enableFeatureInternal("outbound_delivery");
            self.enableFeatureInternal("spf_validation");
            self.enableFeatureInternal("dkim_validation");
        }
    }

    fn disableFeatureInternal(self: *DegradationManager, feature: []const u8, reason: []const u8, dep: ServiceId) void {
        if (!self.disabled_features.contains(feature)) {
            self.disabled_features.put(feature, .{
                .feature = feature,
                .reason = reason,
                .disabled_at = time_compat.timestamp(),
                .dependency = dep,
            }) catch {};
        }
    }

    fn enableFeatureInternal(self: *DegradationManager, feature: []const u8) void {
        _ = self.disabled_features.remove(feature);
    }

    /// Check if a feature is currently enabled
    pub fn isFeatureEnabled(self: *DegradationManager, feature: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return !self.disabled_features.contains(feature);
    }

    /// Get list of disabled features
    pub fn getDisabledFeatures(self: *DegradationManager) ![]DisabledFeature {
        self.mutex.lock();
        defer self.mutex.unlock();

        var result = std.ArrayList(DisabledFeature).init(self.allocator);
        var it = self.disabled_features.iterator();
        while (it.next()) |entry| {
            try result.append(entry.value_ptr.*);
        }
        return result.toOwnedSlice();
    }
};

// ============================================================================
// Default SMTP Dependency Configuration
// ============================================================================

/// Initialize dependency graph with default SMTP server dependencies
pub fn initSmtpDependencies(graph: *DependencyGraph) !void {
    // Register core services
    _ = try graph.registerService(.smtp_server);
    _ = try graph.registerService(.health_api);
    _ = try graph.registerService(.admin_api);
    _ = try graph.registerService(.database);
    _ = try graph.registerService(.authentication);
    _ = try graph.registerService(.rate_limiter);
    _ = try graph.registerService(.maildir_storage);
    _ = try graph.registerService(.queue_storage);

    // Register email processing services
    _ = try graph.registerService(.spf_validator);
    _ = try graph.registerService(.dkim_validator);
    _ = try graph.registerService(.dmarc_validator);
    _ = try graph.registerService(.spam_filter);
    _ = try graph.registerService(.greylist);
    _ = try graph.registerService(.dnsbl_checker);

    // Register delivery services
    _ = try graph.registerService(.relay_client);
    _ = try graph.registerService(.dns_resolver);
    _ = try graph.registerService(.webhook_notifier);

    // Add dependencies
    // SMTP Server dependencies
    try graph.addDependency(.smtp_server, .database, .critical, "*");
    try graph.addDependency(.smtp_server, .authentication, .critical, "auth");
    try graph.addDependency(.smtp_server, .rate_limiter, .important, "rate_limiting");
    try graph.addDependency(.smtp_server, .maildir_storage, .critical, "storage");

    // Authentication dependencies
    try graph.addDependency(.authentication, .database, .critical, "*");

    // Email validation dependencies
    try graph.addDependency(.spf_validator, .dns_resolver, .critical, "*");
    try graph.addDependency(.dkim_validator, .dns_resolver, .critical, "*");
    try graph.addDependency(.dmarc_validator, .dns_resolver, .critical, "*");
    try graph.addDependency(.dmarc_validator, .spf_validator, .important, "alignment");
    try graph.addDependency(.dmarc_validator, .dkim_validator, .important, "alignment");

    // Delivery dependencies
    try graph.addDependency(.relay_client, .dns_resolver, .critical, "*");
    try graph.addDependency(.relay_client, .queue_storage, .critical, "queue");

    // DNSBL dependencies
    try graph.addDependency(.dnsbl_checker, .dns_resolver, .critical, "*");

    // Admin API dependencies
    try graph.addDependency(.admin_api, .database, .critical, "*");
    try graph.addDependency(.admin_api, .authentication, .critical, "*");
}

// ============================================================================
// Tests
// ============================================================================

test "dependency graph basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var graph = DependencyGraph.init(allocator);
    defer graph.deinit();

    // Register services
    _ = try graph.registerService(.smtp_server);
    _ = try graph.registerService(.database);

    // Add dependency
    try graph.addDependency(.smtp_server, .database, .critical, "*");

    // Update health
    graph.updateServiceHealth(.database, .healthy);
    graph.updateServiceHealth(.smtp_server, .healthy);

    // Check health
    try testing.expectEqual(ServiceHealth.healthy, graph.getServiceHealth(.database));
    try testing.expectEqual(ServiceHealth.healthy, graph.getEffectiveHealth(.smtp_server));
}

test "effective health with unhealthy dependency" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var graph = DependencyGraph.init(allocator);
    defer graph.deinit();

    _ = try graph.registerService(.smtp_server);
    _ = try graph.registerService(.database);
    try graph.addDependency(.smtp_server, .database, .critical, "*");

    graph.updateServiceHealth(.smtp_server, .healthy);
    graph.updateServiceHealth(.database, .unhealthy);

    // SMTP should be unhealthy due to critical dependency
    try testing.expectEqual(ServiceHealth.unhealthy, graph.getEffectiveHealth(.smtp_server));
}

test "degraded with important dependency down" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var graph = DependencyGraph.init(allocator);
    defer graph.deinit();

    _ = try graph.registerService(.smtp_server);
    _ = try graph.registerService(.spam_filter);
    try graph.addDependency(.smtp_server, .spam_filter, .important, "spam_check");

    graph.updateServiceHealth(.smtp_server, .healthy);
    graph.updateServiceHealth(.spam_filter, .unhealthy);

    // SMTP should be degraded (important dependency down)
    try testing.expectEqual(ServiceHealth.degraded, graph.getEffectiveHealth(.smtp_server));
}

test "system health report" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var graph = DependencyGraph.init(allocator);
    defer graph.deinit();

    _ = try graph.registerService(.smtp_server);
    _ = try graph.registerService(.database);
    _ = try graph.registerService(.spam_filter);

    graph.updateServiceHealth(.smtp_server, .healthy);
    graph.updateServiceHealth(.database, .healthy);
    graph.updateServiceHealth(.spam_filter, .degraded);

    var report = graph.getSystemHealth();
    defer report.deinit();

    try testing.expectEqual(@as(u32, 2), report.healthy_count);
    try testing.expectEqual(@as(u32, 1), report.degraded_count);
    try testing.expectEqual(ServiceHealth.degraded, report.overall_health);
}

test "degradation manager" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var graph = DependencyGraph.init(allocator);
    defer graph.deinit();

    _ = try graph.registerService(.database);
    _ = try graph.registerService(.spamassassin);

    var degradation = DegradationManager.init(allocator, &graph);
    defer degradation.deinit();

    // Database healthy - features enabled
    graph.updateServiceHealth(.database, .healthy);
    graph.updateServiceHealth(.spamassassin, .healthy);
    degradation.checkDegradation();
    try testing.expect(degradation.isFeatureEnabled("user_management"));
    try testing.expect(degradation.isFeatureEnabled("spam_scoring"));

    // Database down - features disabled
    graph.updateServiceHealth(.database, .unhealthy);
    degradation.checkDegradation();
    try testing.expect(!degradation.isFeatureEnabled("user_management"));
}
