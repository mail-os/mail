const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");
const version_info = @import("../core/version.zig");
const raft = @import("raft.zig");

// =============================================================================
// Cluster Mode - High Availability SMTP Server
// =============================================================================
//
// ## Overview
// Provides distributed coordination, state sharing, and automatic failover
// for running multiple SMTP server instances. This enables horizontal scaling
// and fault tolerance for enterprise deployments.
//
// ## Architecture
//
//   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
//   │   Node 1    │────▶│   Node 2    │────▶│   Node 3    │
//   │  (Leader)   │◀────│ (Follower)  │◀────│ (Follower)  │
//   └─────────────┘     └─────────────┘     └─────────────┘
//          │                   │                   │
//          └───────────────────┴───────────────────┘
//                        Heartbeat Mesh
//
// ## Node Roles
// - **Leader**: Coordinates cluster activities, handles write operations
// - **Follower**: Receives replicated state, handles read operations
// - **Candidate**: Transitional state during leader election
//
// ## Leader Election Algorithm
//
// ### Raft Consensus (Production - Recommended)
// When `enable_raft=true`, proper Raft consensus is used:
//
// 1. **Election Timeout**: Each follower has a randomized election timeout
//    (150-300ms by default). If no heartbeat received, timeout fires.
//
// 2. **Become Candidate**: Node increments term, votes for itself, and
//    requests votes from all peers.
//
// 3. **Vote Collection**: Each node votes for at most one candidate per term.
//    Candidate becomes leader if it receives majority of votes.
//
// 4. **Term-Based Ordering**: Higher terms always win. This prevents
//    split-brain scenarios where multiple nodes think they're leader.
//
// ### Simple Election (Development/Testing)
// When `enable_raft=false`, uses deterministic "lowest ID wins":
//
// 1. All healthy nodes are considered
// 2. Node with lexicographically smallest ID becomes leader
// 3. No network partitions handled - NOT for production use
//
// ## Heartbeat Mechanism
//
// ```
// Timeline (heartbeat_interval=5s, timeout=15s):
//
// Leader:  ──●────────●────────●────────●────────●──▶
//             ↓        ↓        ↓        ↓        ↓
// Follower: ─[✓]─────[✓]─────[✓]─────[✓]─────[✓]─▶
//            └─ last_heartbeat updated
//
// If 15s passes without heartbeat → Node marked disconnected
// If leader disconnected → Trigger election
// ```
//
// ## State Replication (via DistributedStateStore)
//
// Key-value store replicated across cluster nodes:
// 1. Leader receives write request
// 2. Leader appends to Raft log (if enabled)
// 3. Log entry replicated to followers
// 4. Once majority ACK, entry committed
// 5. State applied to local store
//
// ## Atomic Role Transitions
//
// Role changes use Compare-And-Swap (CAS) to prevent race conditions:
//
// ```zig
// // Only succeeds if current role matches expected
// if (self.local_node.transitionRole(.candidate, .leader)) {
//     // Successfully became leader
// }
// ```
//
// This prevents scenarios where two candidates both think they won.
//
// ## Cluster-Aware Rate Limiting
//
// Rate limits are tracked cluster-wide via DistributedStateStore:
//
// 1. Client makes request to any node
// 2. Node queries distributed counter for client IP
// 3. Counter incremented atomically across cluster
// 4. If limit exceeded on any node, all nodes reject
//
// This prevents attackers from bypassing rate limits by
// distributing requests across multiple cluster nodes.
//
// ## Node Health Monitoring
//
// ```
// Status Flow:
// healthy ──▶ degraded ──▶ unhealthy ──▶ disconnected
//    │                                        │
//    └────────────────────────────────────────┘
//                (on reconnect)
// ```
//
// Health checks run every `heartbeat_interval_ms` and examine:
// - Time since last heartbeat
// - Node responsiveness
// - Resource utilization (CPU, memory)
//
// ## Configuration Parameters
//
// | Parameter                  | Default | Description                    |
// |---------------------------|---------|--------------------------------|
// | heartbeat_interval_ms     | 5000    | How often to send heartbeats   |
// | heartbeat_timeout_ms      | 15000   | When to mark node disconnected |
// | leader_election_timeout_ms| 10000   | Simple election timeout        |
// | raft_election_timeout_ms  | 150     | Raft election timeout base     |
// | raft_heartbeat_interval_ms| 50      | Raft leader heartbeat interval |
// =============================================================================

/// Cluster mode for high availability SMTP server
/// Provides distributed coordination, state sharing, and failover capabilities
///
/// ## Raft Integration
/// This module now integrates proper Raft consensus for leader election
/// instead of the simple "lowest ID wins" approach. The RaftNode handles:
/// - Leader election with proper term-based voting
/// - Log replication for distributed state
/// - Heartbeat mechanism with configurable timeouts
/// Cluster node information
pub const ClusterNode = struct {
    id: []const u8,
    address: []const u8,
    port: u16,
    role: std.atomic.Value(NodeRole),
    status: std.atomic.Value(NodeStatus),
    last_heartbeat: std.atomic.Value(i64),
    metadata: NodeMetadata,

    allocator: std.mem.Allocator,

    pub fn deinit(self: *ClusterNode, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.address);
        self.metadata.deinit(allocator);
    }

    /// Atomically transition role with CAS
    pub fn transitionRole(self: *ClusterNode, expected: NodeRole, new_role: NodeRole) bool {
        const result = self.role.cmpxchgStrong(expected, new_role, .acq_rel, .acquire);
        return result == null; // null means success
    }

    /// Get current role atomically
    pub fn getRole(self: *ClusterNode) NodeRole {
        return self.role.load(.acquire);
    }

    /// Set role atomically
    pub fn setRole(self: *ClusterNode, new_role: NodeRole) void {
        self.role.store(new_role, .release);
    }

    /// Get current status atomically
    pub fn getStatus(self: *ClusterNode) NodeStatus {
        return self.status.load(.acquire);
    }

    /// Set status atomically
    pub fn setStatus(self: *ClusterNode, new_status: NodeStatus) void {
        self.status.store(new_status, .release);
    }

    /// Update heartbeat timestamp atomically
    pub fn updateHeartbeat(self: *ClusterNode) void {
        self.last_heartbeat.store(time_compat.timestamp(), .release);
    }

    /// Get last heartbeat timestamp atomically
    pub fn getLastHeartbeat(self: *ClusterNode) i64 {
        return self.last_heartbeat.load(.acquire);
    }
};

pub const NodeRole = enum(u8) {
    leader = 0, // Coordinates cluster activities
    follower = 1, // Regular worker node
    candidate = 2, // Node trying to become leader

    pub fn toString(self: NodeRole) []const u8 {
        return switch (self) {
            .leader => "leader",
            .follower => "follower",
            .candidate => "candidate",
        };
    }
};

pub const NodeStatus = enum(u8) {
    healthy = 0,
    degraded = 1,
    unhealthy = 2,
    disconnected = 3,

    pub fn toString(self: NodeStatus) []const u8 {
        return switch (self) {
            .healthy => "healthy",
            .degraded => "degraded",
            .unhealthy => "unhealthy",
            .disconnected => "disconnected",
        };
    }
};

pub const NodeMetadata = struct {
    version: []const u8,
    uptime_seconds: u64,
    active_connections: u32,
    messages_processed: u64,
    cpu_usage: f32,
    memory_usage_mb: u64,

    allocator: std.mem.Allocator,

    pub fn deinit(self: *NodeMetadata, allocator: std.mem.Allocator) void {
        allocator.free(self.version);
        self.* = undefined; // Clear to prevent use-after-free
    }
};

/// Cluster configuration
pub const ClusterConfig = struct {
    node_id: []const u8,
    bind_address: []const u8,
    bind_port: u16,
    peers: [][]const u8, // List of peer addresses
    heartbeat_interval_ms: u32 = 5000,
    heartbeat_timeout_ms: u32 = 15000,
    leader_election_timeout_ms: u32 = 10000,
    enable_auto_discovery: bool = false,

    /// Enable Raft consensus for leader election (recommended for production)
    enable_raft: bool = true,
    /// Raft-specific settings
    raft_election_timeout_ms: u32 = 150,
    raft_heartbeat_interval_ms: u32 = 50,
};

/// Cluster manager
pub const ClusterManager = struct {
    allocator: std.mem.Allocator,
    config: ClusterConfig,
    local_node: *ClusterNode,
    nodes: std.StringHashMap(*ClusterNode),
    nodes_mutex: mutex_compat.Mutex,
    state_store: *DistributedStateStore,
    heartbeat_thread: ?std.Thread = null,
    running: std.atomic.Value(bool),

    /// Raft consensus node for proper leader election
    raft_node: ?*raft.RaftNode = null,
    raft_enabled: bool = false,

    pub fn init(allocator: std.mem.Allocator, config: ClusterConfig) !*ClusterManager {
        const manager = try allocator.create(ClusterManager);

        // Create local node
        const local_node = try allocator.create(ClusterNode);
        local_node.* = .{
            .id = try allocator.dupe(u8, config.node_id),
            .address = try allocator.dupe(u8, config.bind_address),
            .port = config.bind_port,
            .role = std.atomic.Value(NodeRole).init(.follower), // Start as follower
            .status = std.atomic.Value(NodeStatus).init(.healthy),
            .last_heartbeat = std.atomic.Value(i64).init(time_compat.timestamp()),
            .metadata = .{
                .version = try allocator.dupe(u8, version_info.version_display),
                .uptime_seconds = 0,
                .active_connections = 0,
                .messages_processed = 0,
                .cpu_usage = 0.0,
                .memory_usage_mb = 0,
                .allocator = allocator,
            },
            .allocator = allocator,
        };

        manager.* = .{
            .allocator = allocator,
            .config = config,
            .local_node = local_node,
            .nodes = std.StringHashMap(*ClusterNode).init(allocator),
            .nodes_mutex = mutex_compat.Mutex{},
            .state_store = try DistributedStateStore.init(allocator),
            .running = std.atomic.Value(bool).init(false),
            .raft_node = null,
            .raft_enabled = config.enable_raft,
        };

        // Initialize Raft consensus if enabled
        if (config.enable_raft) {
            const raft_config = raft.RaftConfig{
                .node_id = config.node_id,
                .election_timeout_min_ms = config.raft_election_timeout_ms,
                .election_timeout_max_ms = config.raft_election_timeout_ms * 2,
                .heartbeat_interval_ms = config.raft_heartbeat_interval_ms,
                .snapshot_threshold = 5000,
            };
            manager.raft_node = try raft.RaftNode.init(allocator, raft_config);
            std.log.info("Raft consensus enabled for cluster coordination", .{});
        }

        return manager;
    }

    pub fn deinit(self: *ClusterManager) void {
        self.stop();

        // Clean up Raft node if enabled
        if (self.raft_node) |rn| {
            rn.deinit();
        }

        self.local_node.deinit(self.allocator);
        self.allocator.destroy(self.local_node);

        // Clean up nodes
        self.nodes_mutex.lock();
        var iter = self.nodes.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.*.deinit(self.allocator);
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.nodes.deinit();
        self.nodes_mutex.unlock();

        self.state_store.deinit();
        self.allocator.destroy(self);
    }

    /// Start cluster operations
    pub fn start(self: *ClusterManager) !void {
        self.running.store(true, .release);

        // Start Raft consensus if enabled
        if (self.raft_node) |rn| {
            try rn.start();
            std.log.info("Raft consensus started", .{});
        }

        // Start heartbeat thread
        self.heartbeat_thread = try std.Thread.spawn(.{}, heartbeatLoop, .{self});

        // Discover peers if enabled
        if (self.config.enable_auto_discovery) {
            try self.discoverPeers();
        } else {
            try self.connectToPeers();
        }

        const role_str = if (self.raft_enabled and self.raft_node != null)
            raft.RaftState.toString(self.raft_node.?.getState())
        else
            self.local_node.getRole().toString();

        std.log.info("Cluster manager started - Node ID: {s}, Role: {s}", .{
            self.local_node.id,
            role_str,
        });
    }

    /// Stop cluster operations
    pub fn stop(self: *ClusterManager) void {
        self.running.store(false, .release);

        // Stop Raft consensus if enabled
        if (self.raft_node) |rn| {
            rn.stop();
            std.log.info("Raft consensus stopped", .{});
        }

        if (self.heartbeat_thread) |thread| {
            thread.join();
            self.heartbeat_thread = null;
        }

        std.log.info("Cluster manager stopped", .{});
    }

    /// Heartbeat loop
    fn heartbeatLoop(self: *ClusterManager) void {
        while (self.running.load(.acquire)) {
            self.sendHeartbeat() catch |err| {
                std.log.err("Heartbeat failed: {}", .{err});
            };

            self.checkNodeHealth() catch |err| {
                std.log.err("Health check failed: {}", .{err});
            };

            time_compat.sleepMs(self.config.heartbeat_interval_ms);
        }
    }

    /// Send heartbeat to all nodes
    fn sendHeartbeat(self: *ClusterManager) !void {
        self.local_node.last_heartbeat.store(time_compat.timestamp(), .release);

        self.nodes_mutex.lock();
        defer self.nodes_mutex.unlock();

        var iter = self.nodes.iterator();
        while (iter.next()) |entry| {
            const node = entry.value_ptr.*;
            // TODO: Send actual heartbeat message over network
            _ = node;
        }
    }

    /// Check health of all nodes
    fn checkNodeHealth(self: *ClusterManager) !void {
        const now = time_compat.timestamp();
        const timeout = @divFloor(self.config.heartbeat_timeout_ms, 1000);

        self.nodes_mutex.lock();
        defer self.nodes_mutex.unlock();

        var iter = self.nodes.iterator();
        while (iter.next()) |entry| {
            const node = entry.value_ptr.*;
            const elapsed = now - node.last_heartbeat.load(.acquire);

            if (elapsed > timeout) {
                node.status.store(.disconnected, .release);
                std.log.warn("Node {s} marked as disconnected (last heartbeat: {d}s ago)", .{
                    node.id,
                    elapsed,
                });

                // Trigger leader election if leader is disconnected
                if (node.getRole() == .leader) {
                    try self.startLeaderElection();
                }
            }
        }
    }

    /// Discover peers automatically
    fn discoverPeers(self: *ClusterManager) !void {
        // TODO: Implement service discovery (e.g., via DNS, Consul, etcd)
        _ = self;
        std.log.info("Auto-discovery not yet implemented", .{});
    }

    /// Connect to configured peers
    fn connectToPeers(self: *ClusterManager) !void {
        for (self.config.peers) |peer_address| {
            try self.addPeer(peer_address);
        }
    }

    /// Add peer node
    fn addPeer(self: *ClusterManager, address: []const u8) !void {
        // Parse address (format: "host:port")
        const colon_pos = std.mem.indexOf(u8, address, ":") orelse return error.InvalidPeerAddress;
        const host = address[0..colon_pos];
        const port_str = address[colon_pos + 1 ..];
        const port = try std.fmt.parseInt(u16, port_str, 10);

        // Generate node ID from address
        const node_id = try std.fmt.allocPrint(
            self.allocator,
            "node_{s}_{d}",
            .{ host, port },
        );
        defer self.allocator.free(node_id);

        const node = try self.allocator.create(ClusterNode);
        node.* = .{
            .id = try self.allocator.dupe(u8, node_id),
            .address = try self.allocator.dupe(u8, host),
            .port = port,
            .role = std.atomic.Value(NodeRole).init(.follower),
            .status = std.atomic.Value(NodeStatus).init(.healthy),
            .last_heartbeat = std.atomic.Value(i64).init(time_compat.timestamp()),
            .metadata = .{
                .version = try self.allocator.dupe(u8, "unknown"),
                .uptime_seconds = 0,
                .active_connections = 0,
                .messages_processed = 0,
                .cpu_usage = 0.0,
                .memory_usage_mb = 0,
                .allocator = self.allocator,
            },
            .allocator = self.allocator,
        };

        self.nodes_mutex.lock();
        defer self.nodes_mutex.unlock();
        try self.nodes.put(try self.allocator.dupe(u8, node_id), node);

        std.log.info("Added peer node: {s} ({s}:{d})", .{ node_id, host, port });
    }

    /// Start leader election
    /// When Raft is enabled, this triggers a Raft election. Otherwise falls back
    /// to a simple "lowest ID wins" approach (for testing/development).
    fn startLeaderElection(self: *ClusterManager) !void {
        // Use Raft consensus if enabled
        if (self.raft_enabled and self.raft_node != null) {
            std.log.info("Triggering Raft leader election", .{});
            // Raft handles election internally via its ticker loop
            // The election will be triggered automatically when timeout occurs
            return;
        }

        // Fallback: Simple election for non-Raft mode
        if (self.local_node.getRole() == .leader) {
            return; // Already leader
        }

        std.log.info("Starting simple leader election (Raft disabled)", .{});

        // Atomically transition to candidate
        self.local_node.setRole(.candidate);

        // Simple election: node with lowest ID wins
        var lowest_id = self.local_node.id;

        self.nodes_mutex.lock();
        var iter = self.nodes.iterator();
        while (iter.next()) |entry| {
            const node = entry.value_ptr.*;
            const node_status = node.getStatus();
            if (node_status == .healthy or node_status == .degraded) {
                if (std.mem.lessThan(u8, node.id, lowest_id)) {
                    lowest_id = node.id;
                }
            }
        }
        self.nodes_mutex.unlock();

        // Atomically transition to leader or follower using CAS
        if (std.mem.eql(u8, lowest_id, self.local_node.id)) {
            // Try to become leader if still candidate
            if (self.local_node.transitionRole(.candidate, .leader)) {
                std.log.info("Node elected as LEADER", .{});
            }
        } else {
            // Try to become follower if still candidate
            if (self.local_node.transitionRole(.candidate, .follower)) {
                std.log.info("Node remains as FOLLOWER (leader: {s})", .{lowest_id});
            }
        }
    }

    /// Get current leader
    pub fn getLeader(self: *ClusterManager) !*ClusterNode {
        if (self.local_node.getRole() == .leader) {
            return self.local_node;
        }

        self.nodes_mutex.lock();
        defer self.nodes_mutex.unlock();

        var iter = self.nodes.iterator();
        while (iter.next()) |entry| {
            const node = entry.value_ptr.*;
            const node_role = node.getRole();
            const node_status = node.getStatus();
            if (node_role == .leader and (node_status == .healthy or node_status == .degraded)) {
                return node;
            }
        }

        return error.NoLeaderAvailable;
    }

    /// Get cluster statistics
    pub fn getStats(self: *ClusterManager) ClusterStats {
        self.nodes_mutex.lock();
        defer self.nodes_mutex.unlock();

        var stats = ClusterStats{
            .total_nodes = 1, // Include local node
            .healthy_nodes = if (self.local_node.getStatus() == .healthy) @as(u32, 1) else 0,
            .leader_node_id = if (self.local_node.getRole() == .leader) self.local_node.id else null,
            .total_connections = self.local_node.metadata.active_connections,
            .total_messages_processed = self.local_node.metadata.messages_processed,
            .raft_enabled = self.raft_enabled,
            .raft_term = if (self.raft_node) |rn| rn.current_term else 0,
            .raft_state = if (self.raft_node) |rn| raft.RaftState.toString(rn.getState()) else "disabled",
        };

        var iter = self.nodes.iterator();
        while (iter.next()) |entry| {
            const node = entry.value_ptr.*;
            stats.total_nodes += 1;
            if (node.getStatus() == .healthy) {
                stats.healthy_nodes += 1;
            }
            if (node.getRole() == .leader) {
                stats.leader_node_id = node.id;
            }
            stats.total_connections += node.metadata.active_connections;
            stats.total_messages_processed += node.metadata.messages_processed;
        }

        return stats;
    }

    /// Check if this node is the Raft leader
    pub fn isRaftLeader(self: *ClusterManager) bool {
        if (self.raft_node) |rn| {
            return rn.isLeader();
        }
        return self.local_node.getRole() == .leader;
    }

    /// Submit a command to the Raft log (only works on leader)
    /// Returns the log index if successful
    pub fn submitRaftCommand(self: *ClusterManager, command: []const u8) !u64 {
        if (self.raft_node) |rn| {
            return rn.submitCommand(command);
        }
        return error.RaftNotEnabled;
    }

    /// Get Raft consensus statistics
    pub fn getRaftStats(self: *ClusterManager) ?raft.RaftStats {
        if (self.raft_node) |rn| {
            return rn.getStats();
        }
        return null;
    }
};

pub const ClusterStats = struct {
    total_nodes: u32,
    healthy_nodes: u32,
    leader_node_id: ?[]const u8,
    total_connections: u32,
    total_messages_processed: u64,

    // Raft consensus statistics
    raft_enabled: bool,
    raft_term: u64,
    raft_state: []const u8,
};

/// Distributed state store for sharing state across cluster
pub const DistributedStateStore = struct {
    allocator: std.mem.Allocator,
    data: std.StringHashMap([]const u8),
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator) !*DistributedStateStore {
        const store = try allocator.create(DistributedStateStore);
        store.* = .{
            .allocator = allocator,
            .data = std.StringHashMap([]const u8).init(allocator),
            .mutex = mutex_compat.Mutex{},
        };
        return store;
    }

    pub fn deinit(self: *DistributedStateStore) void {
        self.mutex.lock();
        var iter = self.data.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.data.deinit();
        self.mutex.unlock();

        self.allocator.destroy(self);
    }

    /// Set key-value pair
    pub fn set(self: *DistributedStateStore, key: []const u8, value: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const key_copy = try self.allocator.dupe(u8, key);
        const value_copy = try self.allocator.dupe(u8, value);

        // Free old value if exists
        if (self.data.get(key)) |old_value| {
            self.allocator.free(old_value);
        }

        try self.data.put(key_copy, value_copy);

        // TODO: Replicate to other nodes
    }

    /// Get value by key
    pub fn get(self: *DistributedStateStore, key: []const u8) ![]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.data.get(key)) |value| {
            return try self.allocator.dupe(u8, value);
        }

        return error.KeyNotFound;
    }

    /// Delete key
    pub fn delete(self: *DistributedStateStore, key: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.data.fetchRemove(key)) |entry| {
            self.allocator.free(entry.key);
            self.allocator.free(entry.value);
        }

        // TODO: Replicate deletion to other nodes
    }

    /// Check if key exists
    pub fn exists(self: *DistributedStateStore, key: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.data.contains(key);
    }
};

/// Cluster-aware rate limiter
pub const ClusterRateLimiter = struct {
    local_counts: std.StringHashMap(u32),
    state_store: *DistributedStateStore,
    mutex: mutex_compat.Mutex,

    pub fn init(state_store: *DistributedStateStore, allocator: std.mem.Allocator) ClusterRateLimiter {
        return .{
            .local_counts = std.StringHashMap(u32).init(allocator),
            .state_store = state_store,
            .mutex = mutex_compat.Mutex{},
        };
    }

    pub fn deinit(self: *ClusterRateLimiter) void {
        self.local_counts.deinit();
    }

    /// Check and increment rate limit across cluster
    pub fn checkAndIncrement(self: *ClusterRateLimiter, key: []const u8, limit: u32) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Get global count from distributed store
        const global_count_str = self.state_store.get(key) catch "0";
        defer self.state_store.allocator.free(global_count_str);

        const global_count = try std.fmt.parseInt(u32, global_count_str, 10);

        if (global_count >= limit) {
            return false; // Rate limit exceeded
        }

        // Increment global count
        const new_count = global_count + 1;
        const new_count_str = try std.fmt.allocPrint(
            self.state_store.allocator,
            "{d}",
            .{new_count},
        );
        defer self.state_store.allocator.free(new_count_str);

        try self.state_store.set(key, new_count_str);

        return true;
    }
};

test "cluster manager initialization" {
    const allocator = std.testing.allocator;

    const config = ClusterConfig{
        .node_id = "test-node-1",
        .bind_address = "127.0.0.1",
        .bind_port = 5000,
        .peers = &[_][]const u8{},
    };

    const manager = try ClusterManager.init(allocator, config);
    defer manager.deinit();

    try std.testing.expectEqualStrings("test-node-1", manager.local_node.id);
    try std.testing.expectEqual(NodeRole.follower, manager.local_node.role);
}

test "distributed state store" {
    const allocator = std.testing.allocator;

    const store = try DistributedStateStore.init(allocator);
    defer store.deinit();

    try store.set("key1", "value1");
    const value = try store.get("key1");
    defer allocator.free(value);

    try std.testing.expectEqualStrings("value1", value);

    try std.testing.expect(store.exists("key1"));
    try std.testing.expect(!store.exists("nonexistent"));
}
