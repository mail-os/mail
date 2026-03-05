const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");

/// Connection pool for SMTP relay connections
pub const ConnectionPool = struct {
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    max_connections: usize,
    idle_timeout_ms: u32,
    connections: std.ArrayList(PooledConnection),
    mutex: mutex_compat.Mutex,

    const PooledConnection = struct {
        stream: std.net.Stream,
        last_used: i64,
        in_use: bool,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
        max_connections: usize,
    ) !ConnectionPool {
        return .{
            .allocator = allocator,
            .host = try allocator.dupe(u8, host),
            .port = port,
            .max_connections = max_connections,
            .idle_timeout_ms = 60000, // 60 seconds
            .connections = std.ArrayList(PooledConnection).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *ConnectionPool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.connections.items) |*conn| {
            conn.stream.close();
        }
        self.connections.deinit();
        self.allocator.free(self.host);
    }

    /// Acquire a connection from the pool
    pub fn acquire(self: *ConnectionPool) !std.net.Stream {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.milliTimestamp();

        // Look for an idle connection
        for (self.connections.items) |*conn| {
            if (!conn.in_use) {
                // Check if connection is still valid (not timed out)
                const age_ms = now - conn.last_used;
                if (age_ms < self.idle_timeout_ms) {
                    conn.in_use = true;
                    conn.last_used = now;
                    return conn.stream;
                } else {
                    // Connection timed out, close it
                    conn.stream.close();
                    // We'll create a new one below
                    break;
                }
            }
        }

        // Create new connection if we haven't reached max
        if (self.connections.items.len < self.max_connections) {
            const address = try std.net.Address.parseIp(self.host, self.port);
            const stream = try std.net.tcpConnectToAddress(address);

            const pooled = PooledConnection{
                .stream = stream,
                .last_used = now,
                .in_use = true,
            };

            try self.connections.append(pooled);
            return stream;
        }

        // Pool exhausted, wait or error
        return error.PoolExhausted;
    }

    /// Release a connection back to the pool
    pub fn release(self: *ConnectionPool, stream: std.net.Stream) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.connections.items) |*conn| {
            if (conn.stream.handle == stream.handle) {
                conn.in_use = false;
                conn.last_used = std.time.milliTimestamp();
                return;
            }
        }
    }

    /// Close a connection and remove from pool
    pub fn closeConnection(self: *ConnectionPool, stream: std.net.Stream) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.connections.items, 0..) |*conn, i| {
            if (conn.stream.handle == stream.handle) {
                conn.stream.close();
                _ = self.connections.swapRemove(i);
                return;
            }
        }
    }

    /// Clean up idle connections
    pub fn cleanup(self: *ConnectionPool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.milliTimestamp();
        var i: usize = 0;

        while (i < self.connections.items.len) {
            const conn = &self.connections.items[i];
            if (!conn.in_use) {
                const age_ms = now - conn.last_used;
                if (age_ms >= self.idle_timeout_ms) {
                    conn.stream.close();
                    _ = self.connections.swapRemove(i);
                    continue;
                }
            }
            i += 1;
        }
    }

    /// Get pool statistics
    pub fn getStats(self: *ConnectionPool) PoolStats {
        self.mutex.lock();
        defer self.mutex.unlock();

        var stats = PoolStats{
            .total = self.connections.items.len,
            .in_use = 0,
            .idle = 0,
        };

        for (self.connections.items) |*conn| {
            if (conn.in_use) {
                stats.in_use += 1;
            } else {
                stats.idle += 1;
            }
        }

        return stats;
    }
};

pub const PoolStats = struct {
    total: usize,
    in_use: usize,
    idle: usize,
};

/// Generic resource pool
pub fn ResourcePool(comptime T: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        resources: std.ArrayList(Resource),
        create_fn: *const fn (std.mem.Allocator) anyerror!T,
        destroy_fn: *const fn (T) void,
        max_size: usize,
        mutex: mutex_compat.Mutex,

        const Resource = struct {
            value: T,
            in_use: bool,
            created_at: i64,
        };

        pub fn init(
            allocator: std.mem.Allocator,
            create_fn: *const fn (std.mem.Allocator) anyerror!T,
            destroy_fn: *const fn (T) void,
            max_size: usize,
        ) Self {
            return .{
                .allocator = allocator,
                .resources = std.ArrayList(Resource).init(allocator),
                .create_fn = create_fn,
                .destroy_fn = destroy_fn,
                .max_size = max_size,
                .mutex = .{},
            };
        }

        pub fn deinit(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            for (self.resources.items) |*res| {
                self.destroy_fn(res.value);
            }
            self.resources.deinit();
        }

        pub fn acquire(self: *Self) !T {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Find idle resource
            for (self.resources.items) |*res| {
                if (!res.in_use) {
                    res.in_use = true;
                    return res.value;
                }
            }

            // Create new resource if not at max
            if (self.resources.items.len < self.max_size) {
                const value = try self.create_fn(self.allocator);
                const res = Resource{
                    .value = value,
                    .in_use = true,
                    .created_at = std.time.milliTimestamp(),
                };
                try self.resources.append(res);
                return value;
            }

            return error.PoolExhausted;
        }

        pub fn release(self: *Self, value: T) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            for (self.resources.items) |*res| {
                // Compare by value/pointer depending on type
                if (std.meta.eql(res.value, value)) {
                    res.in_use = false;
                    return;
                }
            }
        }

        pub fn size(self: *Self) usize {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.resources.items.len;
        }
    };
}

test "connection pool stats" {
    // Note: Real network testing would require actual server
    // This is a structural test only
    const testing = std.testing;
    _ = testing;

    // Skip network test in CI
}

test "generic resource pool" {
    const testing = std.testing;

    const TestResource = struct {
        value: u32,

        fn create(allocator: std.mem.Allocator) !TestResource {
            _ = allocator;
            return TestResource{ .value = 42 };
        }

        fn destroy(self: TestResource) void {
            _ = self;
        }
    };

    var pool = ResourcePool(TestResource).init(
        testing.allocator,
        TestResource.create,
        TestResource.destroy,
        5,
    );
    defer pool.deinit();

    const res1 = try pool.acquire();
    try testing.expectEqual(@as(u32, 42), res1.value);
    try testing.expectEqual(@as(usize, 1), pool.size());

    pool.release(res1);
}
