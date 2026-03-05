const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const constants = @import("../core/constants.zig");

/// Thread-safe buffer pool for performance optimization
/// Reduces allocation overhead by reusing buffers
pub fn BufferPool(comptime buffer_size: usize) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        available_buffers: std.ArrayList([]u8),
        total_allocated: usize,
        max_pool_size: usize,
        mutex: mutex_compat.Mutex,
        stats: Stats,

        pub const Stats = struct {
            total_acquired: u64,
            total_released: u64,
            cache_hits: u64,
            cache_misses: u64,
            current_size: usize,
            peak_size: usize,
        };

        pub fn init(allocator: std.mem.Allocator, max_pool_size: usize) Self {
            return .{
                .allocator = allocator,
                .available_buffers = std.ArrayList([]u8).init(allocator),
                .total_allocated = 0,
                .max_pool_size = max_pool_size,
                .mutex = .{},
                .stats = .{
                    .total_acquired = 0,
                    .total_released = 0,
                    .cache_hits = 0,
                    .cache_misses = 0,
                    .current_size = 0,
                    .peak_size = 0,
                },
            };
        }

        pub fn deinit(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            for (self.available_buffers.items) |buffer| {
                self.allocator.free(buffer);
            }
            self.available_buffers.deinit();
        }

        /// Acquire a buffer from the pool
        pub fn acquire(self: *Self) ![]u8 {
            self.mutex.lock();
            defer self.mutex.unlock();

            self.stats.total_acquired += 1;

            // Try to get from pool
            if (self.available_buffers.popOrNull()) |buffer| {
                self.stats.cache_hits += 1;
                self.stats.current_size = self.available_buffers.items.len;
                // Clear buffer before returning
                @memset(buffer, 0);
                return buffer;
            }

            // Allocate new buffer
            self.stats.cache_misses += 1;
            const buffer = try self.allocator.alloc(u8, buffer_size);
            self.total_allocated += 1;

            return buffer;
        }

        /// Release a buffer back to the pool
        pub fn release(self: *Self, buffer: []u8) void {
            if (buffer.len != buffer_size) {
                // Wrong size, just free it
                self.allocator.free(buffer);
                return;
            }

            self.mutex.lock();
            defer self.mutex.unlock();

            self.stats.total_released += 1;

            // Add to pool if not full
            if (self.available_buffers.items.len < self.max_pool_size) {
                self.available_buffers.append(buffer) catch {
                    // Pool full or allocation failed, free the buffer
                    self.allocator.free(buffer);
                    return;
                };

                self.stats.current_size = self.available_buffers.items.len;
                if (self.stats.current_size > self.stats.peak_size) {
                    self.stats.peak_size = self.stats.current_size;
                }
            } else {
                // Pool full, free the buffer
                self.allocator.free(buffer);
            }
        }

        /// Get statistics
        pub fn getStats(self: *Self) Stats {
            self.mutex.lock();
            defer self.mutex.unlock();

            return self.stats;
        }

        /// Reset statistics
        pub fn resetStats(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            self.stats = .{
                .total_acquired = 0,
                .total_released = 0,
                .cache_hits = 0,
                .cache_misses = 0,
                .current_size = self.stats.current_size,
                .peak_size = self.stats.peak_size,
            };
        }

        /// Shrink pool to target size
        pub fn shrink(self: *Self, target_size: usize) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            while (self.available_buffers.items.len > target_size) {
                if (self.available_buffers.pop()) |buffer| {
                    self.allocator.free(buffer);
                }
            }

            self.stats.current_size = self.available_buffers.items.len;
        }

        /// Preallocate buffers
        pub fn preallocate(self: *Self, count: usize) !void {
            self.mutex.lock();
            defer self.mutex.unlock();

            var i: usize = 0;
            while (i < count) : (i += 1) {
                if (self.available_buffers.items.len >= self.max_pool_size) {
                    break;
                }

                const buffer = try self.allocator.alloc(u8, buffer_size);
                try self.available_buffers.append(buffer);
                self.total_allocated += 1;
            }

            self.stats.current_size = self.available_buffers.items.len;
            if (self.stats.current_size > self.stats.peak_size) {
                self.stats.peak_size = self.stats.current_size;
            }
        }
    };
}

/// Global buffer pools for common sizes
pub const GlobalBufferPools = struct {
    small: BufferPool(constants.BufferSizes.SMALL),
    medium: BufferPool(constants.BufferSizes.MEDIUM),
    large: BufferPool(constants.BufferSizes.LARGE),
    xlarge: BufferPool(constants.BufferSizes.XLARGE),

    pub fn init(allocator: std.mem.Allocator) GlobalBufferPools {
        return .{
            .small = BufferPool(constants.BufferSizes.SMALL).init(allocator, 50),
            .medium = BufferPool(constants.BufferSizes.MEDIUM).init(allocator, 100),
            .large = BufferPool(constants.BufferSizes.LARGE).init(allocator, 50),
            .xlarge = BufferPool(constants.BufferSizes.XLARGE).init(allocator, 10),
        };
    }

    pub fn deinit(self: *GlobalBufferPools) void {
        self.small.deinit();
        self.medium.deinit();
        self.large.deinit();
        self.xlarge.deinit();
    }

    pub fn acquireSmall(self: *GlobalBufferPools) ![]u8 {
        return self.small.acquire();
    }

    pub fn acquireMedium(self: *GlobalBufferPools) ![]u8 {
        return self.medium.acquire();
    }

    pub fn acquireLarge(self: *GlobalBufferPools) ![]u8 {
        return self.large.acquire();
    }

    pub fn acquireXLarge(self: *GlobalBufferPools) ![]u8 {
        return self.xlarge.acquire();
    }

    pub fn releaseSmall(self: *GlobalBufferPools, buffer: []u8) void {
        self.small.release(buffer);
    }

    pub fn releaseMedium(self: *GlobalBufferPools, buffer: []u8) void {
        self.medium.release(buffer);
    }

    pub fn releaseLarge(self: *GlobalBufferPools, buffer: []u8) void {
        self.large.release(buffer);
    }

    pub fn releaseXLarge(self: *GlobalBufferPools, buffer: []u8) void {
        self.xlarge.release(buffer);
    }

    pub fn preallocateAll(self: *GlobalBufferPools) !void {
        try self.small.preallocate(20);
        try self.medium.preallocate(50);
        try self.large.preallocate(20);
        try self.xlarge.preallocate(5);
    }

    pub fn getAllStats(self: *GlobalBufferPools) struct {
        small: BufferPool(constants.BufferSizes.SMALL).Stats,
        medium: BufferPool(constants.BufferSizes.MEDIUM).Stats,
        large: BufferPool(constants.BufferSizes.LARGE).Stats,
        xlarge: BufferPool(constants.BufferSizes.XLARGE).Stats,
    } {
        return .{
            .small = self.small.getStats(),
            .medium = self.medium.getStats(),
            .large = self.large.getStats(),
            .xlarge = self.xlarge.getStats(),
        };
    }
};

// Tests
test "buffer pool basic operations" {
    const testing = std.testing;

    var pool = BufferPool(1024).init(testing.allocator, 10);
    defer pool.deinit();

    // Acquire buffer
    const buf1 = try pool.acquire();
    try testing.expectEqual(@as(usize, 1024), buf1.len);

    // Release buffer
    pool.release(buf1);

    // Stats check
    const stats = pool.getStats();
    try testing.expectEqual(@as(u64, 1), stats.total_acquired);
    try testing.expectEqual(@as(u64, 1), stats.total_released);
    try testing.expectEqual(@as(u64, 0), stats.cache_hits);
    try testing.expectEqual(@as(u64, 1), stats.cache_misses);
}

test "buffer pool reuse" {
    const testing = std.testing;

    var pool = BufferPool(512).init(testing.allocator, 10);
    defer pool.deinit();

    // Acquire and release
    const buf1 = try pool.acquire();
    pool.release(buf1);

    // Acquire again - should reuse
    const buf2 = try pool.acquire();
    pool.release(buf2);

    const stats = pool.getStats();
    try testing.expectEqual(@as(u64, 2), stats.total_acquired);
    try testing.expectEqual(@as(u64, 1), stats.cache_hits); // Second acquire was cache hit
    try testing.expectEqual(@as(u64, 1), stats.cache_misses); // First acquire was cache miss
}

test "buffer pool max size" {
    const testing = std.testing;

    var pool = BufferPool(256).init(testing.allocator, 2);
    defer pool.deinit();

    const buf1 = try pool.acquire();
    const buf2 = try pool.acquire();
    const buf3 = try pool.acquire();

    pool.release(buf1);
    pool.release(buf2);
    pool.release(buf3); // This should be freed, not pooled

    const stats = pool.getStats();
    try testing.expectEqual(@as(usize, 2), stats.current_size); // Pool maxed at 2
}

test "buffer pool preallocate" {
    const testing = std.testing;

    var pool = BufferPool(128).init(testing.allocator, 20);
    defer pool.deinit();

    try pool.preallocate(5);

    const stats = pool.getStats();
    try testing.expectEqual(@as(usize, 5), stats.current_size);

    // Acquire should hit cache
    const buf = try pool.acquire();
    pool.release(buf);

    const stats2 = pool.getStats();
    try testing.expectEqual(@as(u64, 1), stats2.cache_hits);
}

test "global buffer pools" {
    const testing = std.testing;

    var pools = GlobalBufferPools.init(testing.allocator);
    defer pools.deinit();

    // Test different sizes
    const small = try pools.acquireSmall();
    try testing.expectEqual(@as(usize, constants.BufferSizes.SMALL), small.len);
    pools.releaseSmall(small);

    const medium = try pools.acquireMedium();
    try testing.expectEqual(@as(usize, constants.BufferSizes.MEDIUM), medium.len);
    pools.releaseMedium(medium);

    const large = try pools.acquireLarge();
    try testing.expectEqual(@as(usize, constants.BufferSizes.LARGE), large.len);
    pools.releaseLarge(large);
}

test "buffer pool shrink" {
    const testing = std.testing;

    var pool = BufferPool(64).init(testing.allocator, 10);
    defer pool.deinit();

    try pool.preallocate(8);
    try testing.expectEqual(@as(usize, 8), pool.getStats().current_size);

    pool.shrink(3);
    try testing.expectEqual(@as(usize, 3), pool.getStats().current_size);
}
