const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");

// =============================================================================
// Multi-Region Support - Cross-Region Replication & Failover
// =============================================================================
//
// ## Overview
// Enables SMTP server deployment across multiple geographic regions with
// automatic failover, data replication, and latency-based routing.
//
// ## Architecture
//
// ```
//                    ┌─────────────────────────┐
//                    │    Global DNS (GSLB)    │
//                    │  Route 53 / CloudFlare  │
//                    └───────────┬─────────────┘
//                                │
//         ┌──────────────────────┼──────────────────────┐
//         ▼                      ▼                      ▼
//   ┌───────────┐          ┌───────────┐          ┌───────────┐
//   │ Region A  │◀────────▶│ Region B  │◀────────▶│ Region C  │
//   │ (Primary) │   Sync   │(Secondary)│   Sync   │(Secondary)│
//   └───────────┘          └───────────┘          └───────────┘
//        │                      │                      │
//        ▼                      ▼                      ▼
//   ┌─────────┐           ┌─────────┐           ┌─────────┐
//   │  Users  │           │  Users  │           │  Users  │
//   └─────────┘           └─────────┘           └─────────┘
// ```
//
// ## Replication Strategies
//
// ### 1. Synchronous Replication (Strong Consistency)
// - Write to primary, wait for N replicas before ACK
// - Guarantees no data loss
// - Higher latency (cross-region RTT)
// - Use for: User credentials, critical config
//
// ### 2. Asynchronous Replication (Eventual Consistency)
// - Write to primary, ACK immediately
// - Replicate in background
// - Lower latency
// - Use for: Message queue, audit logs
//
// ### 3. Conflict-Free Replicated Data Types (CRDTs)
// - No coordination required
// - Automatic conflict resolution
// - Use for: Counters, sets, registers
//
// ## Failover Process
//
// ```
// 1. Health checks detect primary failure
// 2. Quorum of secondaries elect new primary
// 3. DNS updated to point to new primary
// 4. Clients automatically reconnect
// 5. Former primary rejoins as secondary when recovered
// ```
//
// ## Data Partitioning
//
// Messages are partitioned by domain for locality:
// - example.com → Region A (primary)
// - company.org → Region B (primary)
// - Each region stores replicas of other regions' data
//
// =============================================================================

/// Region configuration
pub const RegionConfig = struct {
    /// Region identifier (e.g., "us-east-1", "eu-west-1")
    id: []const u8,
    /// Display name
    name: []const u8,
    /// Primary endpoint (hostname:port)
    endpoint: []const u8,
    /// Geographic coordinates for latency estimation
    latitude: f64 = 0,
    longitude: f64 = 0,
    /// Region weight for load balancing (higher = more traffic)
    weight: u32 = 100,
    /// Maximum connections to accept
    max_connections: u32 = 10000,
    /// Is this region currently active?
    active: bool = true,
};

/// Region health status
pub const RegionHealth = enum {
    healthy, // All checks passing
    degraded, // Some checks failing
    unhealthy, // Critical checks failing
    unknown, // Unable to determine
};

/// Region status with health information
pub const RegionStatus = struct {
    config: RegionConfig,
    health: RegionHealth,
    last_health_check: i64,
    latency_ms: u32,
    active_connections: u32,
    messages_processed: u64,
    replication_lag_ms: u64,
    is_primary: bool,
};

/// Replication mode
pub const ReplicationMode = enum {
    sync, // Synchronous - wait for replicas
    async_immediate, // Async - ACK immediately, replicate later
    async_batch, // Async - batch replication for efficiency
};

/// Replication configuration
pub const ReplicationConfig = struct {
    mode: ReplicationMode = .async_immediate,
    /// Minimum replicas for sync mode
    min_replicas: u32 = 1,
    /// Timeout for sync replication (ms)
    sync_timeout_ms: u32 = 5000,
    /// Batch size for async batch mode
    batch_size: u32 = 100,
    /// Batch timeout (ms)
    batch_timeout_ms: u32 = 1000,
    /// Retry count for failed replication
    retry_count: u32 = 3,
    /// Retry delay (ms)
    retry_delay_ms: u32 = 1000,
};

/// Replication event types
pub const ReplicationEventType = enum {
    user_created,
    user_updated,
    user_deleted,
    message_queued,
    message_delivered,
    message_bounced,
    config_changed,
    domain_added,
    domain_removed,
};

/// Replication event for cross-region sync
pub const ReplicationEvent = struct {
    id: u64,
    event_type: ReplicationEventType,
    region_id: []const u8,
    timestamp: i64,
    payload: []const u8,
    checksum: u32,

    pub fn computeChecksum(data: []const u8) u32 {
        var crc: u32 = 0xFFFFFFFF;
        for (data) |byte| {
            crc ^= byte;
            for (0..8) |_| {
                if (crc & 1 != 0) {
                    crc = (crc >> 1) ^ 0xEDB88320;
                } else {
                    crc >>= 1;
                }
            }
        }
        return ~crc;
    }
};

/// Multi-region manager
pub const MultiRegionManager = struct {
    allocator: std.mem.Allocator,
    local_region: RegionConfig,
    regions: std.StringHashMap(RegionStatus),
    replication_config: ReplicationConfig,
    event_queue: std.ArrayList(ReplicationEvent),
    next_event_id: u64,
    mutex: mutex_compat.Mutex,
    is_primary: bool,

    // Statistics
    stats: MultiRegionStats,

    pub fn init(
        allocator: std.mem.Allocator,
        local_region: RegionConfig,
        replication_config: ReplicationConfig,
    ) MultiRegionManager {
        return .{
            .allocator = allocator,
            .local_region = local_region,
            .regions = std.StringHashMap(RegionStatus).init(allocator),
            .replication_config = replication_config,
            .event_queue = .empty,
            .next_event_id = 1,
            .mutex = .{},
            .is_primary = false,
            .stats = MultiRegionStats{},
        };
    }

    pub fn deinit(self: *MultiRegionManager) void {
        self.regions.deinit();
        self.event_queue.deinit(self.allocator);
    }

    /// Register a remote region
    pub fn registerRegion(self: *MultiRegionManager, config: RegionConfig) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const status = RegionStatus{
            .config = config,
            .health = .unknown,
            .last_health_check = 0,
            .latency_ms = 0,
            .active_connections = 0,
            .messages_processed = 0,
            .replication_lag_ms = 0,
            .is_primary = false,
        };

        try self.regions.put(config.id, status);
        self.stats.regions_registered += 1;
    }

    /// Update region health status
    pub fn updateRegionHealth(
        self: *MultiRegionManager,
        region_id: []const u8,
        health: RegionHealth,
        latency_ms: u32,
    ) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.regions.getPtr(region_id)) |status| {
            status.health = health;
            status.latency_ms = latency_ms;
            status.last_health_check = time_compat.timestamp();
        }
    }

    /// Get the best region for a domain (latency-based routing)
    pub fn getBestRegion(self: *MultiRegionManager, domain: []const u8) ?*const RegionStatus {
        self.mutex.lock();
        defer self.mutex.unlock();

        _ = domain; // Could use for domain affinity

        var best: ?*const RegionStatus = null;
        var best_score: u32 = std.math.maxInt(u32);

        var iter = self.regions.valueIterator();
        while (iter.next()) |status| {
            if (status.health != .healthy) continue;
            if (!status.config.active) continue;

            // Score based on latency and load
            const load_factor = if (status.config.max_connections > 0)
                (status.active_connections * 100) / status.config.max_connections
            else
                0;
            const score = status.latency_ms + load_factor;

            if (score < best_score) {
                best_score = score;
                best = status;
            }
        }

        return best;
    }

    /// Queue a replication event
    pub fn queueReplicationEvent(
        self: *MultiRegionManager,
        event_type: ReplicationEventType,
        payload: []const u8,
    ) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const event_id = self.next_event_id;
        self.next_event_id += 1;

        const event = ReplicationEvent{
            .id = event_id,
            .event_type = event_type,
            .region_id = self.local_region.id,
            .timestamp = time_compat.timestamp(),
            .payload = try self.allocator.dupe(u8, payload),
            .checksum = ReplicationEvent.computeChecksum(payload),
        };

        try self.event_queue.append(self.allocator, event);
        self.stats.events_queued += 1;

        // Trigger replication based on mode
        if (self.replication_config.mode == .sync) {
            try self.replicateSync(event);
        } else if (self.event_queue.items.len >= self.replication_config.batch_size) {
            try self.flushReplicationQueue();
        }

        return event_id;
    }

    /// Synchronous replication (waits for ACK)
    fn replicateSync(self: *MultiRegionManager, event: ReplicationEvent) !void {
        var acks: u32 = 0;
        const required_acks = self.replication_config.min_replicas;

        var iter = self.regions.valueIterator();
        while (iter.next()) |status| {
            if (!status.config.active) continue;
            if (status.health == .unhealthy) continue;

            // In production, would send HTTP/gRPC request to remote region
            // For now, simulate with logging
            std.log.info("Sync replication to {s}: event {d}", .{
                status.config.id,
                event.id,
            });

            acks += 1;
            self.stats.events_replicated += 1;

            if (acks >= required_acks) break;
        }

        if (acks < required_acks) {
            self.stats.replication_failures += 1;
            return error.InsufficientReplicas;
        }
    }

    /// Flush pending replication events
    pub fn flushReplicationQueue(self: *MultiRegionManager) !void {
        if (self.event_queue.items.len == 0) return;

        // Batch events for efficiency
        var batch = std.ArrayList(u8).init(self.allocator);
        defer batch.deinit();

        for (self.event_queue.items) |event| {
            // Serialize event
            try batch.writer().print("{d}:{d}:{s}\n", .{
                event.id,
                @intFromEnum(event.event_type),
                event.payload,
            });
        }

        // Send to all healthy regions
        var iter = self.regions.valueIterator();
        while (iter.next()) |status| {
            if (!status.config.active) continue;
            if (status.health == .unhealthy) continue;

            // Would send batch via HTTP/gRPC
            std.log.info("Batch replication to {s}: {d} events", .{
                status.config.id,
                self.event_queue.items.len,
            });

            self.stats.events_replicated += self.event_queue.items.len;
        }

        // Clear queue
        for (self.event_queue.items) |event| {
            self.allocator.free(event.payload);
        }
        self.event_queue.clearRetainingCapacity();
    }

    /// Apply a received replication event
    pub fn applyReplicationEvent(self: *MultiRegionManager, event: ReplicationEvent) !void {
        // Verify checksum
        if (ReplicationEvent.computeChecksum(event.payload) != event.checksum) {
            self.stats.checksum_failures += 1;
            return error.ChecksumMismatch;
        }

        // Apply event based on type
        switch (event.event_type) {
            .user_created, .user_updated, .user_deleted => {
                std.log.info("Applying user event from {s}", .{event.region_id});
            },
            .message_queued, .message_delivered, .message_bounced => {
                std.log.info("Applying message event from {s}", .{event.region_id});
            },
            .config_changed => {
                std.log.info("Applying config event from {s}", .{event.region_id});
            },
            .domain_added, .domain_removed => {
                std.log.info("Applying domain event from {s}", .{event.region_id});
            },
        }

        self.stats.events_applied += 1;
    }

    /// Trigger failover to this region
    pub fn triggerFailover(self: *MultiRegionManager, failed_region_id: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        std.log.warn("Triggering failover from region {s}", .{failed_region_id});

        // Mark failed region as unhealthy
        if (self.regions.getPtr(failed_region_id)) |status| {
            status.health = .unhealthy;
            status.is_primary = false;
        }

        // This region becomes primary
        self.is_primary = true;
        self.stats.failovers += 1;

        std.log.info("Region {s} is now primary", .{self.local_region.id});
    }

    /// Get region statistics
    pub fn getStats(self: *const MultiRegionManager) MultiRegionStats {
        return self.stats;
    }

    /// Get all region statuses
    pub fn getAllRegions(self: *MultiRegionManager, allocator: std.mem.Allocator) ![]RegionStatus {
        self.mutex.lock();
        defer self.mutex.unlock();

        var result = try allocator.alloc(RegionStatus, self.regions.count());
        var i: usize = 0;

        var iter = self.regions.valueIterator();
        while (iter.next()) |status| {
            result[i] = status.*;
            i += 1;
        }

        return result;
    }
};

/// Multi-region statistics
pub const MultiRegionStats = struct {
    regions_registered: u64 = 0,
    events_queued: u64 = 0,
    events_replicated: u64 = 0,
    events_applied: u64 = 0,
    replication_failures: u64 = 0,
    checksum_failures: u64 = 0,
    failovers: u64 = 0,
    health_checks: u64 = 0,
};

/// Conflict resolution strategies
pub const ConflictResolution = enum {
    last_write_wins, // Most recent timestamp wins
    first_write_wins, // Earliest timestamp wins
    merge, // Merge conflicting values
    custom, // Application-specific resolution
};

/// Conflict resolver for replication conflicts
pub const ConflictResolver = struct {
    strategy: ConflictResolution,

    pub fn init(strategy: ConflictResolution) ConflictResolver {
        return .{ .strategy = strategy };
    }

    pub fn resolve(
        self: *const ConflictResolver,
        local: ReplicationEvent,
        remote: ReplicationEvent,
    ) ReplicationEvent {
        return switch (self.strategy) {
            .last_write_wins => if (remote.timestamp > local.timestamp) remote else local,
            .first_write_wins => if (remote.timestamp < local.timestamp) remote else local,
            .merge, .custom => local, // Would need custom merge logic
        };
    }
};

/// Geographic distance calculation (Haversine formula)
pub fn calculateDistance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) f64 {
    const R = 6371.0; // Earth radius in km
    const dLat = (lat2 - lat1) * std.math.pi / 180.0;
    const dLon = (lon2 - lon1) * std.math.pi / 180.0;

    const a = @sin(dLat / 2) * @sin(dLat / 2) +
        @cos(lat1 * std.math.pi / 180.0) * @cos(lat2 * std.math.pi / 180.0) *
            @sin(dLon / 2) * @sin(dLon / 2);

    const c = 2 * std.math.atan2(@sqrt(a), @sqrt(1 - a));
    return R * c;
}

/// Estimate network latency from distance (rough approximation)
pub fn estimateLatencyMs(distance_km: f64) u32 {
    // Light travels ~200km/ms in fiber optic
    // Add 50% overhead for routing
    const base_latency = distance_km / 200.0 * 1.5;
    // Minimum latency of 1ms
    return @max(1, @as(u32, @intFromFloat(base_latency)));
}

// Tests
test "multi-region manager initialization" {
    const testing = std.testing;

    const local_region = RegionConfig{
        .id = "us-east-1",
        .name = "US East",
        .endpoint = "smtp-east.example.com:25",
        .latitude = 39.0,
        .longitude = -77.0,
    };

    var manager = MultiRegionManager.init(
        testing.allocator,
        local_region,
        ReplicationConfig{},
    );
    defer manager.deinit();

    try testing.expectEqual(@as(u64, 0), manager.stats.regions_registered);
}

test "region registration" {
    const testing = std.testing;

    const local_region = RegionConfig{
        .id = "us-east-1",
        .name = "US East",
        .endpoint = "smtp-east.example.com:25",
    };

    var manager = MultiRegionManager.init(
        testing.allocator,
        local_region,
        ReplicationConfig{},
    );
    defer manager.deinit();

    try manager.registerRegion(.{
        .id = "eu-west-1",
        .name = "EU West",
        .endpoint = "smtp-eu.example.com:25",
    });

    try testing.expectEqual(@as(u64, 1), manager.stats.regions_registered);
}

test "replication event checksum" {
    const payload = "test payload data";
    const checksum = ReplicationEvent.computeChecksum(payload);

    // Checksum should be consistent
    const checksum2 = ReplicationEvent.computeChecksum(payload);
    try std.testing.expectEqual(checksum, checksum2);

    // Different payload should have different checksum
    const checksum3 = ReplicationEvent.computeChecksum("different payload");
    try std.testing.expect(checksum != checksum3);
}

test "distance calculation" {
    // New York to London (approximately 5570 km)
    const distance = calculateDistance(40.7128, -74.0060, 51.5074, -0.1278);
    try std.testing.expect(distance > 5500 and distance < 5700);
}

test "latency estimation" {
    // 1000 km should be roughly 7-8ms
    const latency = estimateLatencyMs(1000);
    try std.testing.expect(latency >= 5 and latency <= 10);
}

test "conflict resolution" {
    const local = ReplicationEvent{
        .id = 1,
        .event_type = .user_updated,
        .region_id = "us-east-1",
        .timestamp = 1000,
        .payload = "",
        .checksum = 0,
    };

    const remote = ReplicationEvent{
        .id = 2,
        .event_type = .user_updated,
        .region_id = "eu-west-1",
        .timestamp = 2000, // More recent
        .payload = "",
        .checksum = 0,
    };

    const resolver = ConflictResolver.init(.last_write_wins);
    const resolved = resolver.resolve(local, remote);

    try std.testing.expectEqual(@as(i64, 2000), resolved.timestamp);
}
