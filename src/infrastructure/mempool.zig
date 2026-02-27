const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");

/// Memory pool for efficient allocation of fixed-size blocks
/// Reduces allocator pressure and fragmentation
pub fn MemoryPool(comptime T: type) type {
    return struct {
        const Self = @This();
        const Node = struct {
            data: T,
            next: ?*Node,
        };

        allocator: std.mem.Allocator,
        free_list: ?*Node,
        allocated_nodes: std.ArrayList(*Node),
        capacity: usize,
        available: usize,
        mutex: mutex_compat.Mutex,

        pub fn init(allocator: std.mem.Allocator, initial_capacity: usize) !Self {
            var pool = Self{
                .allocator = allocator,
                .free_list = null,
                .allocated_nodes = std.ArrayList(*Node).init(allocator),
                .capacity = initial_capacity,
                .available = 0,
                .mutex = .{},
            };

            // Pre-allocate initial capacity
            try pool.grow(initial_capacity);

            return pool;
        }

        pub fn deinit(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            for (self.allocated_nodes.items) |node| {
                self.allocator.destroy(node);
            }
            self.allocated_nodes.deinit();
        }

        /// Acquire an item from the pool
        pub fn acquire(self: *Self) !*T {
            self.mutex.lock();
            defer self.mutex.unlock();

            // If free list is empty, grow the pool
            if (self.free_list == null) {
                try self.growLocked(self.capacity);
            }

            const node = self.free_list orelse return error.PoolExhausted;
            self.free_list = node.next;
            self.available -= 1;

            return &node.data;
        }

        /// Release an item back to the pool
        pub fn release(self: *Self, item: *T) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Calculate node address from item address
            const node = @fieldParentPtr(Node, "data", item);

            node.next = self.free_list;
            self.free_list = node;
            self.available += 1;
        }

        /// Grow the pool by allocating more nodes
        fn grow(self: *Self, count: usize) !void {
            self.mutex.lock();
            defer self.mutex.unlock();

            try self.growLocked(count);
        }

        fn growLocked(self: *Self, count: usize) !void {
            for (0..count) |_| {
                const node = try self.allocator.create(Node);
                node.* = .{
                    .data = undefined,
                    .next = self.free_list,
                };

                self.free_list = node;
                try self.allocated_nodes.append(node);
            }

            self.capacity += count;
            self.available += count;
        }

        /// Get pool statistics
        pub fn getStats(self: *Self) PoolStats {
            self.mutex.lock();
            defer self.mutex.unlock();

            return .{
                .capacity = self.capacity,
                .available = self.available,
                .in_use = self.capacity - self.available,
            };
        }

        /// Reset all items in the pool (doesn't deallocate)
        pub fn reset(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Rebuild free list
            self.free_list = null;
            self.available = 0;

            for (self.allocated_nodes.items) |node| {
                node.next = self.free_list;
                self.free_list = node;
                self.available += 1;
            }
        }
    };
}

pub const PoolStats = struct {
    capacity: usize,
    available: usize,
    in_use: usize,
};

/// Buffer pool for commonly-sized buffers
pub const BufferPool = struct {
    small: MemoryPool([1024]u8), // 1 KB buffers
    medium: MemoryPool([8192]u8), // 8 KB buffers
    large: MemoryPool([65536]u8), // 64 KB buffers

    pub fn init(allocator: std.mem.Allocator, pool_size: usize) !BufferPool {
        return .{
            .small = try MemoryPool([1024]u8).init(allocator, pool_size),
            .medium = try MemoryPool([8192]u8).init(allocator, pool_size),
            .large = try MemoryPool([65536]u8).init(allocator, pool_size),
        };
    }

    pub fn deinit(self: *BufferPool) void {
        self.small.deinit();
        self.medium.deinit();
        self.large.deinit();
    }

    /// Acquire a buffer of appropriate size
    pub fn acquireBuffer(self: *BufferPool, size: usize) ![]u8 {
        if (size <= 1024) {
            const buf = try self.small.acquire();
            return buf[0..size];
        } else if (size <= 8192) {
            const buf = try self.medium.acquire();
            return buf[0..size];
        } else if (size <= 65536) {
            const buf = try self.large.acquire();
            return buf[0..size];
        } else {
            return error.BufferTooLarge;
        }
    }

    /// Release a buffer back to appropriate pool
    pub fn releaseBuffer(self: *BufferPool, buffer: []u8) void {
        if (buffer.len <= 1024) {
            const full_buf = @as(*[1024]u8, @ptrCast(buffer.ptr));
            self.small.release(full_buf);
        } else if (buffer.len <= 8192) {
            const full_buf = @as(*[8192]u8, @ptrCast(buffer.ptr));
            self.medium.release(full_buf);
        } else if (buffer.len <= 65536) {
            const full_buf = @as(*[65536]u8, @ptrCast(buffer.ptr));
            self.large.release(full_buf);
        }
    }

    pub fn getStats(self: *BufferPool) BufferPoolStats {
        return .{
            .small = self.small.getStats(),
            .medium = self.medium.getStats(),
            .large = self.large.getStats(),
        };
    }
};

pub const BufferPoolStats = struct {
    small: PoolStats,
    medium: PoolStats,
    large: PoolStats,
};

/// Arena-based memory pool for related allocations
pub const ArenaPool = struct {
    backing_allocator: std.mem.Allocator,
    arenas: std.ArrayList(*std.heap.ArenaAllocator),
    free_arenas: std.ArrayList(*std.heap.ArenaAllocator),
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator) ArenaPool {
        return .{
            .backing_allocator = allocator,
            .arenas = std.ArrayList(*std.heap.ArenaAllocator).init(allocator),
            .free_arenas = std.ArrayList(*std.heap.ArenaAllocator).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *ArenaPool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.arenas.items) |arena| {
            arena.deinit();
            self.backing_allocator.destroy(arena);
        }
        self.arenas.deinit();

        for (self.free_arenas.items) |arena| {
            arena.deinit();
            self.backing_allocator.destroy(arena);
        }
        self.free_arenas.deinit();
    }

    /// Acquire an arena allocator
    pub fn acquire(self: *ArenaPool) !std.mem.Allocator {
        self.mutex.lock();
        defer self.mutex.unlock();

        var arena: *std.heap.ArenaAllocator = undefined;

        if (self.free_arenas.items.len > 0) {
            arena = self.free_arenas.pop();
        } else {
            arena = try self.backing_allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(self.backing_allocator);
            try self.arenas.append(arena);
        }

        return arena.allocator();
    }

    /// Release an arena back to the pool
    pub fn release(self: *ArenaPool, arena_allocator: std.mem.Allocator) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Find the arena
        for (self.arenas.items) |arena| {
            if (@intFromPtr(arena.allocator().ptr) == @intFromPtr(arena_allocator.ptr)) {
                // Reset the arena
                _ = arena.reset(.retain_capacity);
                try self.free_arenas.append(arena);
                return;
            }
        }
    }
};

test "memory pool basic operations" {
    const testing = std.testing;

    const TestStruct = struct {
        value: i32,
        name: [32]u8,
    };

    var pool = try MemoryPool(TestStruct).init(testing.allocator, 10);
    defer pool.deinit();

    // Acquire items
    const item1 = try pool.acquire();
    item1.value = 42;

    const item2 = try pool.acquire();
    item2.value = 100;

    var stats = pool.getStats();
    try testing.expectEqual(@as(usize, 10), stats.capacity);
    try testing.expectEqual(@as(usize, 8), stats.available);
    try testing.expectEqual(@as(usize, 2), stats.in_use);

    // Release items
    pool.release(item1);
    pool.release(item2);

    stats = pool.getStats();
    try testing.expectEqual(@as(usize, 10), stats.available);
    try testing.expectEqual(@as(usize, 0), stats.in_use);
}

test "buffer pool" {
    const testing = std.testing;

    var pool = try BufferPool.init(testing.allocator, 5);
    defer pool.deinit();

    // Acquire small buffer
    const small = try pool.acquireBuffer(512);
    try testing.expectEqual(@as(usize, 512), small.len);

    // Acquire medium buffer
    const medium = try pool.acquireBuffer(4096);
    try testing.expectEqual(@as(usize, 4096), medium.len);

    // Acquire large buffer
    const large = try pool.acquireBuffer(32768);
    try testing.expectEqual(@as(usize, 32768), large.len);

    // Release buffers
    pool.releaseBuffer(small);
    pool.releaseBuffer(medium);
    pool.releaseBuffer(large);

    const stats = pool.getStats();
    try testing.expectEqual(@as(usize, 5), stats.small.available);
    try testing.expectEqual(@as(usize, 5), stats.medium.available);
    try testing.expectEqual(@as(usize, 5), stats.large.available);
}

test "pool growth" {
    const testing = std.testing;

    var pool = try MemoryPool(u32).init(testing.allocator, 2);
    defer pool.deinit();

    _ = try pool.acquire();
    _ = try pool.acquire();

    // Pool should grow automatically
    _ = try pool.acquire();

    const stats = pool.getStats();
    try testing.expect(stats.capacity > 2);
}

test "pool reset" {
    const testing = std.testing;

    var pool = try MemoryPool(i64).init(testing.allocator, 5);
    defer pool.deinit();

    _ = try pool.acquire();
    _ = try pool.acquire();

    var stats = pool.getStats();
    try testing.expectEqual(@as(usize, 2), stats.in_use);

    pool.reset();

    stats = pool.getStats();
    try testing.expectEqual(@as(usize, 0), stats.in_use);
    try testing.expectEqual(@as(usize, 5), stats.available);
}

test "arena pool" {
    const testing = std.testing;

    var arena_pool = ArenaPool.init(testing.allocator);
    defer arena_pool.deinit();

    // Acquire arena
    const arena1 = try arena_pool.acquire();

    // Use arena for allocations
    const str1 = try arena1.dupe(u8, "Hello, World!");
    try testing.expectEqualStrings("Hello, World!", str1);

    // Release arena (resets it)
    try arena_pool.release(arena1);

    // Acquire again (should reuse the same arena)
    const arena2 = try arena_pool.acquire();
    const str2 = try arena2.dupe(u8, "New allocation");
    try testing.expectEqualStrings("New allocation", str2);

    try arena_pool.release(arena2);
}
