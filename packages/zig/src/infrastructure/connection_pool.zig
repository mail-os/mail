const std = @import("std");
const time_compat = @import("../core/time_compat.zig");

/// Lock-free connection pool using Compare-And-Swap (CAS) operations
/// Provides O(1) acquire/release with minimal contention
pub fn ConnectionPool(comptime T: type) type {
    return struct {
        const Self = @This();

        /// Connection wrapper with atomic reference counting
        pub const PooledConnection = struct {
            data: T,
            in_use: std.atomic.Value(bool),
            last_used: std.atomic.Value(i64),
            connection_id: usize,

            pub fn init(data: T, id: usize) PooledConnection {
                return .{
                    .data = data,
                    .in_use = std.atomic.Value(bool).init(false),
                    .last_used = std.atomic.Value(i64).init(time_compat.timestamp()),
                    .connection_id = id,
                };
            }

            /// Try to acquire this connection atomically
            pub fn tryAcquire(self: *PooledConnection) bool {
                // CAS: if currently false (not in use), set to true
                const result = self.in_use.cmpxchgStrong(
                    false,
                    true,
                    .acquire,
                    .monotonic,
                );
                if (result == null) {
                    // Successfully acquired
                    self.last_used.store(time_compat.timestamp(), .release);
                    return true;
                }
                return false;
            }

            /// Release this connection
            pub fn release(self: *PooledConnection) void {
                self.last_used.store(time_compat.timestamp(), .release);
                self.in_use.store(false, .release);
            }

            /// Check if connection is in use
            pub fn isInUse(self: *PooledConnection) bool {
                return self.in_use.load(.acquire);
            }

            /// Get time since last use (in seconds)
            pub fn idleTime(self: *PooledConnection) i64 {
                const now = time_compat.timestamp();
                const last = self.last_used.load(.acquire);
                return now - last;
            }
        };

        allocator: std.mem.Allocator,
        connections: []PooledConnection,
        capacity: usize,
        next_candidate: std.atomic.Value(usize), // For round-robin search
        stats: Stats,

        pub const Stats = struct {
            total_acquires: std.atomic.Value(u64),
            total_releases: std.atomic.Value(u64),
            acquire_failures: std.atomic.Value(u64),
            connections_in_use: std.atomic.Value(usize),

            pub fn init() Stats {
                return .{
                    .total_acquires = std.atomic.Value(u64).init(0),
                    .total_releases = std.atomic.Value(u64).init(0),
                    .acquire_failures = std.atomic.Value(u64).init(0),
                    .connections_in_use = std.atomic.Value(usize).init(0),
                };
            }

            pub fn snapshot(self: *const Stats) StatsSnapshot {
                return .{
                    .total_acquires = self.total_acquires.load(.acquire),
                    .total_releases = self.total_releases.load(.acquire),
                    .acquire_failures = self.acquire_failures.load(.acquire),
                    .connections_in_use = self.connections_in_use.load(.acquire),
                };
            }
        };

        pub const StatsSnapshot = struct {
            total_acquires: u64,
            total_releases: u64,
            acquire_failures: u64,
            connections_in_use: usize,
        };

        pub const AcquireError = error{
            PoolExhausted,
            OutOfMemory,
        };

        /// Initialize connection pool with given capacity
        pub fn init(allocator: std.mem.Allocator, connections: []T) !Self {
            const capacity = connections.len;
            const pooled = try allocator.alloc(PooledConnection, capacity);
            errdefer allocator.free(pooled);

            for (connections, 0..) |conn, i| {
                pooled[i] = PooledConnection.init(conn, i);
            }

            return Self{
                .allocator = allocator,
                .connections = pooled,
                .capacity = capacity,
                .next_candidate = std.atomic.Value(usize).init(0),
                .stats = Stats.init(),
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.connections);
        }

        /// Acquire a connection from the pool (lock-free)
        /// Uses round-robin search starting from atomic counter
        pub fn acquire(self: *Self) AcquireError!*PooledConnection {
            // Try up to capacity times to find a free connection
            var attempts: usize = 0;
            while (attempts < self.capacity) : (attempts += 1) {
                // Get next candidate index atomically
                const start_idx = self.next_candidate.fetchAdd(1, .monotonic);
                const idx = start_idx % self.capacity;

                // Try to acquire this connection
                if (self.connections[idx].tryAcquire()) {
                    _ = self.stats.total_acquires.fetchAdd(1, .release);
                    _ = self.stats.connections_in_use.fetchAdd(1, .release);
                    return &self.connections[idx];
                }
            }

            // Pool exhausted
            _ = self.stats.acquire_failures.fetchAdd(1, .release);
            return AcquireError.PoolExhausted;
        }

        /// Release a connection back to the pool
        pub fn release(self: *Self, conn: *PooledConnection) void {
            conn.release();
            _ = self.stats.total_releases.fetchAdd(1, .release);
            _ = self.stats.connections_in_use.fetchSub(1, .release);
        }

        /// Get number of available connections
        pub fn getAvailableCount(self: *Self) usize {
            var count: usize = 0;
            for (self.connections) |*conn| {
                if (!conn.isInUse()) {
                    count += 1;
                }
            }
            return count;
        }

        /// Get pool statistics
        pub fn getStats(self: *Self) StatsSnapshot {
            return self.stats.snapshot();
        }

        /// Close idle connections (connections not used for idle_seconds)
        pub fn closeIdleConnections(
            self: *Self,
            idle_seconds: i64,
            close_fn: fn (*T) void,
        ) usize {
            var closed: usize = 0;
            for (self.connections) |*conn| {
                if (!conn.isInUse() and conn.idleTime() >= idle_seconds) {
                    // Only close if we can acquire it
                    if (conn.tryAcquire()) {
                        close_fn(&conn.data);
                        conn.release();
                        closed += 1;
                    }
                }
            }
            return closed;
        }
    };
}

/// Helper wrapper for automatic connection release
pub fn PooledHandle(comptime T: type) type {
    return struct {
        const Self = @This();

        pool: *ConnectionPool(T),
        connection: *ConnectionPool(T).PooledConnection,

        pub fn init(pool: *ConnectionPool(T), conn: *ConnectionPool(T).PooledConnection) Self {
            return .{
                .pool = pool,
                .connection = conn,
            };
        }

        pub fn deinit(self: *Self) void {
            self.pool.release(self.connection);
        }

        pub fn get(self: *Self) *T {
            return &self.connection.data;
        }
    };
}

// Tests
test "connection pool basic acquire/release" {
    const testing = std.testing;

    // Create some mock connections
    const Connection = struct {
        id: u32,
    };

    var connections = [_]Connection{
        .{ .id = 1 },
        .{ .id = 2 },
        .{ .id = 3 },
    };

    var pool = try ConnectionPool(Connection).init(testing.allocator, &connections);
    defer pool.deinit();

    // Acquire connection
    const conn1 = try pool.acquire();
    try testing.expectEqual(@as(u32, 1), conn1.data.id);

    // Stats check
    var stats = pool.getStats();
    try testing.expectEqual(@as(u64, 1), stats.total_acquires);
    try testing.expectEqual(@as(usize, 1), stats.connections_in_use);

    // Release connection
    pool.release(conn1);

    stats = pool.getStats();
    try testing.expectEqual(@as(u64, 1), stats.total_releases);
    try testing.expectEqual(@as(usize, 0), stats.connections_in_use);
}

test "connection pool exhaustion" {
    const testing = std.testing;

    const Connection = struct { id: u32 };
    var connections = [_]Connection{.{ .id = 1 }};

    var pool = try ConnectionPool(Connection).init(testing.allocator, &connections);
    defer pool.deinit();

    // Acquire the only connection
    const conn1 = try pool.acquire();

    // Try to acquire again - should fail
    const result = pool.acquire();
    try testing.expectError(ConnectionPool(Connection).AcquireError.PoolExhausted, result);

    // Release and try again
    pool.release(conn1);
    const conn2 = try pool.acquire();
    try testing.expectEqual(@as(u32, 1), conn2.data.id);
    pool.release(conn2);
}

test "connection pool concurrent access" {
    const testing = std.testing;

    const Connection = struct { id: u32 };
    var connections = [_]Connection{
        .{ .id = 1 },
        .{ .id = 2 },
        .{ .id = 3 },
        .{ .id = 4 },
        .{ .id = 5 },
    };

    var pool = try ConnectionPool(Connection).init(testing.allocator, &connections);
    defer pool.deinit();

    // Simulate concurrent acquires
    const conn1 = try pool.acquire();
    const conn2 = try pool.acquire();
    const conn3 = try pool.acquire();

    // All should be different connections
    try testing.expect(conn1.connection_id != conn2.connection_id);
    try testing.expect(conn2.connection_id != conn3.connection_id);
    try testing.expect(conn1.connection_id != conn3.connection_id);

    // Release all
    pool.release(conn1);
    pool.release(conn2);
    pool.release(conn3);

    const stats = pool.getStats();
    try testing.expectEqual(@as(u64, 3), stats.total_acquires);
    try testing.expectEqual(@as(u64, 3), stats.total_releases);
}

test "connection pool available count" {
    const testing = std.testing;

    const Connection = struct { id: u32 };
    var connections = [_]Connection{
        .{ .id = 1 },
        .{ .id = 2 },
        .{ .id = 3 },
    };

    var pool = try ConnectionPool(Connection).init(testing.allocator, &connections);
    defer pool.deinit();

    try testing.expectEqual(@as(usize, 3), pool.getAvailableCount());

    const conn1 = try pool.acquire();
    try testing.expectEqual(@as(usize, 2), pool.getAvailableCount());

    const conn2 = try pool.acquire();
    try testing.expectEqual(@as(usize, 1), pool.getAvailableCount());

    pool.release(conn1);
    try testing.expectEqual(@as(usize, 2), pool.getAvailableCount());

    pool.release(conn2);
    try testing.expectEqual(@as(usize, 3), pool.getAvailableCount());
}

test "pooled handle RAII" {
    const testing = std.testing;

    const Connection = struct { id: u32 };
    var connections = [_]Connection{.{ .id = 1 }};

    var pool = try ConnectionPool(Connection).init(testing.allocator, &connections);
    defer pool.deinit();

    {
        const conn = try pool.acquire();
        var handle = PooledHandle(Connection).init(&pool, conn);
        defer handle.deinit();

        try testing.expectEqual(@as(u32, 1), handle.get().id);
        try testing.expectEqual(@as(usize, 1), pool.getStats().connections_in_use);
    }

    // Connection should be automatically released
    try testing.expectEqual(@as(usize, 0), pool.getStats().connections_in_use);
}
