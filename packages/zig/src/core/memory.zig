const std = @import("std");
const Allocator = std.mem.Allocator;
const io_compat = @import("io_compat.zig");

/// Standardized Memory Management for SMTP Server
/// Enforces consistent RAII patterns with defer for safe resource cleanup

// =============================================================================
// RAII Wrapper - Automatic cleanup on scope exit
// =============================================================================

/// Generic RAII wrapper that automatically cleans up resources
pub fn Raii(comptime T: type) type {
    return struct {
        const Self = @This();

        value: T,
        cleanup_fn: ?*const fn (*T) void,

        pub fn init(value: T, cleanup_fn: *const fn (*T) void) Self {
            return Self{
                .value = value,
                .cleanup_fn = cleanup_fn,
            };
        }

        pub fn initNoCleanup(value: T) Self {
            return Self{
                .value = value,
                .cleanup_fn = null,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.cleanup_fn) |cleanup_func| {
                cleanup_func(&self.value);
            }
        }

        pub fn get(self: *Self) *T {
            return &self.value;
        }

        pub fn getConst(self: *const Self) *const T {
            return &self.value;
        }

        /// Release ownership without cleanup
        pub fn release(self: *Self) T {
            self.cleanup_fn = null;
            return self.value;
        }
    };
}

// =============================================================================
// Scoped Allocator - Arena with automatic cleanup
// =============================================================================

pub const ScopedAllocator = struct {
    const Self = @This();

    arena: std.heap.ArenaAllocator,

    pub fn init(child_allocator: Allocator) Self {
        return Self{
            .arena = std.heap.ArenaAllocator.init(child_allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.arena.deinit();
    }

    pub fn allocator(self: *Self) Allocator {
        return self.arena.allocator();
    }

    /// Reset arena, keeping capacity
    pub fn reset(self: *Self) void {
        _ = self.arena.reset(.retain_capacity);
    }

    /// Get memory usage stats
    pub fn stats(_: *const Self) struct { used: usize, capacity: usize } {
        // Arena doesn't expose these directly, approximate
        return .{ .used = 0, .capacity = 0 };
    }
};

// =============================================================================
// Pool Allocator - Fixed-size object pool
// =============================================================================

pub fn PoolAllocator(comptime T: type, comptime pool_size: usize) type {
    return struct {
        const Self = @This();

        storage: [pool_size]T = undefined,
        free_list: [pool_size]bool = [_]bool{true} ** pool_size,
        allocated_count: usize = 0,

        pub fn init() Self {
            return Self{};
        }

        pub fn acquire(self: *Self) ?*T {
            for (&self.free_list, 0..) |*free, i| {
                if (free.*) {
                    free.* = false;
                    self.allocated_count += 1;
                    return &self.storage[i];
                }
            }
            return null;
        }

        pub fn release(self: *Self, ptr: *T) void {
            const base = @intFromPtr(&self.storage[0]);
            const item = @intFromPtr(ptr);
            const stride = @sizeOf(T);

            if (item >= base and item < base + pool_size * stride) {
                const index = (item - base) / stride;
                if (index < pool_size and !self.free_list[index]) {
                    self.free_list[index] = true;
                    self.allocated_count -= 1;
                }
            }
        }

        pub fn availableCount(self: *const Self) usize {
            return pool_size - self.allocated_count;
        }

        pub fn allocatedCount(self: *const Self) usize {
            return self.allocated_count;
        }

        pub fn isFull(self: *const Self) bool {
            return self.allocated_count >= pool_size;
        }
    };
}

// =============================================================================
// Owned Slice - Slice with ownership tracking
// =============================================================================

pub fn OwnedSlice(comptime T: type) type {
    return struct {
        const Self = @This();

        data: []T,
        allocator: Allocator,

        pub fn init(alloc: Allocator, size: usize) !Self {
            return Self{
                .data = try alloc.alloc(T, size),
                .allocator = alloc,
            };
        }

        pub fn fromSlice(alloc: Allocator, src: []const T) !Self {
            const data = try alloc.alloc(T, src.len);
            @memcpy(data, src);
            return Self{
                .data = data,
                .allocator = alloc,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.data);
            self.data = &[_]T{};
        }

        pub fn slice(self: *const Self) []T {
            return self.data;
        }

        pub fn constSlice(self: *const Self) []const T {
            return self.data;
        }

        pub fn len(self: *const Self) usize {
            return self.data.len;
        }

        /// Transfer ownership, caller must free
        pub fn release(self: *Self) []T {
            const data = self.data;
            self.data = &[_]T{};
            return data;
        }

        /// Resize the slice
        pub fn resize(self: *Self, new_size: usize) !void {
            self.data = try self.allocator.realloc(self.data, new_size);
        }
    };
}

/// Convenience alias for owned byte slices
pub const OwnedString = OwnedSlice(u8);

// =============================================================================
// Defer Guard - Ensure cleanup even on error
// =============================================================================

pub fn DeferGuard(comptime Context: type) type {
    return struct {
        const Self = @This();

        context: Context,
        cleanup_fn: *const fn (Context) void,
        armed: bool = true,

        pub fn init(context: Context, cleanup_fn: *const fn (Context) void) Self {
            return Self{
                .context = context,
                .cleanup_fn = cleanup_fn,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.armed) {
                self.cleanup_fn(self.context);
            }
        }

        /// Disarm the guard (don't run cleanup)
        pub fn disarm(self: *Self) void {
            self.armed = false;
        }

        /// Re-arm the guard
        pub fn rearm(self: *Self) void {
            self.armed = true;
        }
    };
}

// =============================================================================
// Memory Tracker - Debug memory usage
// =============================================================================

pub const MemoryTracker = struct {
    const Self = @This();

    allocations: std.AutoHashMap(usize, AllocationInfo),
    total_allocated: usize = 0,
    total_freed: usize = 0,
    peak_usage: usize = 0,
    allocation_count: usize = 0,
    free_count: usize = 0,
    backing_allocator: Allocator,

    pub const AllocationInfo = struct {
        size: usize,
        timestamp: i64,
        source_file: ?[]const u8 = null,
        source_line: ?u32 = null,
    };

    pub fn init(backing_allocator: Allocator) Self {
        return Self{
            .allocations = std.AutoHashMap(usize, AllocationInfo).init(backing_allocator),
            .backing_allocator = backing_allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocations.deinit();
    }

    pub fn trackAllocation(self: *Self, ptr: usize, size: usize, src: ?std.builtin.SourceLocation) !void {
        try self.allocations.put(ptr, AllocationInfo{
            .size = size,
            .timestamp = std.time.timestamp(),
            .source_file = if (src) |s| s.file else null,
            .source_line = if (src) |s| s.line else null,
        });
        self.total_allocated += size;
        self.allocation_count += 1;

        const current = self.total_allocated - self.total_freed;
        if (current > self.peak_usage) {
            self.peak_usage = current;
        }
    }

    pub fn trackFree(self: *Self, ptr: usize) void {
        if (self.allocations.fetchRemove(ptr)) |entry| {
            self.total_freed += entry.value.size;
            self.free_count += 1;
        }
    }

    pub fn currentUsage(self: *const Self) usize {
        return self.total_allocated - self.total_freed;
    }

    pub fn leakCount(self: *const Self) usize {
        return self.allocations.count();
    }

    pub fn getStats(self: *const Self) Stats {
        return Stats{
            .total_allocated = self.total_allocated,
            .total_freed = self.total_freed,
            .current_usage = self.currentUsage(),
            .peak_usage = self.peak_usage,
            .allocation_count = self.allocation_count,
            .free_count = self.free_count,
            .leak_count = self.leakCount(),
        };
    }

    pub const Stats = struct {
        total_allocated: usize,
        total_freed: usize,
        current_usage: usize,
        peak_usage: usize,
        allocation_count: usize,
        free_count: usize,
        leak_count: usize,
    };

    /// Report potential memory leaks
    pub fn reportLeaks(self: *const Self, writer: anytype) !void {
        if (self.allocations.count() == 0) {
            try writer.print("No memory leaks detected.\n", .{});
            return;
        }

        try writer.print("Potential memory leaks: {d} allocations\n", .{self.allocations.count()});
        var it = self.allocations.iterator();
        while (it.next()) |entry| {
            try writer.print("  - {x}: {d} bytes", .{ entry.key_ptr.*, entry.value_ptr.size });
            if (entry.value_ptr.source_file) |file| {
                try writer.print(" at {s}:{d}", .{ file, entry.value_ptr.source_line orelse 0 });
            }
            try writer.print("\n", .{});
        }
    }
};

// =============================================================================
// Safe Buffer - Bounds-checked buffer operations
// =============================================================================

pub fn SafeBuffer(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        data: [capacity]u8 = undefined,
        len: usize = 0,

        pub fn init() Self {
            return Self{};
        }

        pub fn append(self: *Self, bytes: []const u8) !void {
            if (self.len + bytes.len > capacity) {
                return error.BufferOverflow;
            }
            @memcpy(self.data[self.len..][0..bytes.len], bytes);
            self.len += bytes.len;
        }

        pub fn appendByte(self: *Self, byte: u8) !void {
            if (self.len >= capacity) {
                return error.BufferOverflow;
            }
            self.data[self.len] = byte;
            self.len += 1;
        }

        pub fn slice(self: *const Self) []const u8 {
            return self.data[0..self.len];
        }

        pub fn mutableSlice(self: *Self) []u8 {
            return self.data[0..self.len];
        }

        pub fn remaining(self: *const Self) usize {
            return capacity - self.len;
        }

        pub fn clear(self: *Self) void {
            self.len = 0;
        }

        pub fn isFull(self: *const Self) bool {
            return self.len >= capacity;
        }

        pub fn isEmpty(self: *const Self) bool {
            return self.len == 0;
        }
    };
}

// =============================================================================
// Resource Manager - Track multiple resources
// =============================================================================

pub const ResourceManager = struct {
    const Self = @This();

    resources: std.ArrayList(Resource),
    allocator: Allocator,

    pub const Resource = struct {
        ptr: *anyopaque,
        cleanup: *const fn (*anyopaque) void,
        name: []const u8,
    };

    pub fn init(alloc: Allocator) Self {
        return Self{
            .resources = std.ArrayList(Resource).init(alloc),
            .allocator = alloc,
        };
    }

    pub fn deinit(self: *Self) void {
        // Cleanup in reverse order (LIFO)
        while (self.resources.items.len > 0) {
            const resource = self.resources.pop();
            resource.cleanup(resource.ptr);
        }
        self.resources.deinit();
    }

    pub fn register(self: *Self, ptr: *anyopaque, cleanup_fn: *const fn (*anyopaque) void, name: []const u8) !void {
        try self.resources.append(Resource{
            .ptr = ptr,
            .cleanup = cleanup_fn,
            .name = name,
        });
    }

    pub fn unregister(self: *Self, ptr: *anyopaque) bool {
        for (self.resources.items, 0..) |resource, i| {
            if (resource.ptr == ptr) {
                _ = self.resources.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    pub fn count(self: *const Self) usize {
        return self.resources.items.len;
    }
};

// =============================================================================
// Memory Utilities
// =============================================================================

pub const utils = struct {
    /// Securely zero memory (prevents optimization removal)
    pub fn secureZero(data: []u8) void {
        @memset(data, 0);
        // Memory barrier to prevent optimization
        std.atomic.fence(.seq_cst);
    }

    /// Copy with bounds checking
    pub fn safeCopy(dest: []u8, src: []const u8) !usize {
        if (src.len > dest.len) {
            return error.DestinationTooSmall;
        }
        @memcpy(dest[0..src.len], src);
        return src.len;
    }

    /// Duplicate string with allocator
    pub fn dupeString(alloc: Allocator, str: []const u8) ![]u8 {
        return try alloc.dupe(u8, str);
    }

    /// Format into buffer, return slice
    pub fn formatBuf(buf: []u8, comptime fmt: []const u8, args: anytype) ![]u8 {
        var fbs = io_compat.fixedBufferStream(buf);
        try fbs.writer().print(fmt, args);
        return fbs.getWritten();
    }

    /// Align size to power of 2
    pub fn alignSize(size: usize, alignment: usize) usize {
        return (size + alignment - 1) & ~(alignment - 1);
    }
};

// =============================================================================
// Cleanup Helpers for Common Types
// =============================================================================

pub const cleanupHelpers = struct {
    pub fn arrayList(comptime T: type) fn (*std.ArrayList(T)) void {
        return struct {
            fn deinit(list: *std.ArrayList(T)) void {
                list.deinit();
            }
        }.deinit;
    }

    pub fn hashMap(comptime K: type, comptime V: type) fn (*std.AutoHashMap(K, V)) void {
        return struct {
            fn deinit(map: *std.AutoHashMap(K, V)) void {
                map.deinit();
            }
        }.deinit;
    }

    pub fn stringHashMap(comptime V: type) fn (*std.StringHashMap(V)) void {
        return struct {
            fn deinit(map: *std.StringHashMap(V)) void {
                map.deinit();
            }
        }.deinit;
    }
};

// =============================================================================
// Tests
// =============================================================================

test "Raii automatic cleanup" {
    const TestStruct = struct {
        value: u32,
        cleaned: *bool,

        fn cleanup(self: *@This()) void {
            self.cleaned.* = true;
        }
    };

    var cleaned = false;
    {
        var raii = Raii(TestStruct).init(
            TestStruct{ .value = 42, .cleaned = &cleaned },
            TestStruct.cleanup,
        );
        defer raii.deinit();

        try std.testing.expectEqual(@as(u32, 42), raii.get().value);
    }
    try std.testing.expect(cleaned);
}

test "ScopedAllocator cleanup" {
    var scoped = ScopedAllocator.init(std.testing.allocator);
    defer scoped.deinit();

    const alloc = scoped.allocator();
    const data = try alloc.alloc(u8, 100);
    _ = data;
    // No need to free - arena handles it
}

test "PoolAllocator acquire and release" {
    var pool = PoolAllocator(u64, 4).init();

    const p1 = pool.acquire();
    try std.testing.expect(p1 != null);
    try std.testing.expectEqual(@as(usize, 1), pool.allocatedCount());

    const p2 = pool.acquire();
    try std.testing.expect(p2 != null);
    try std.testing.expectEqual(@as(usize, 2), pool.allocatedCount());

    pool.release(p1.?);
    try std.testing.expectEqual(@as(usize, 1), pool.allocatedCount());
}

test "OwnedSlice automatic cleanup" {
    var owned = try OwnedSlice(u8).init(std.testing.allocator, 10);
    defer owned.deinit();

    try std.testing.expectEqual(@as(usize, 10), owned.len());
}

test "OwnedSlice fromSlice" {
    const src = "Hello, World!";
    var owned = try OwnedSlice(u8).fromSlice(std.testing.allocator, src);
    defer owned.deinit();

    try std.testing.expectEqualStrings(src, owned.constSlice());
}

test "SafeBuffer operations" {
    var buf = SafeBuffer(16).init();

    try buf.append("Hello");
    try buf.appendByte('!');

    try std.testing.expectEqualStrings("Hello!", buf.slice());
    try std.testing.expectEqual(@as(usize, 10), buf.remaining());

    buf.clear();
    try std.testing.expect(buf.isEmpty());
}

test "SafeBuffer overflow protection" {
    var buf = SafeBuffer(4).init();

    try buf.append("Hi");
    try std.testing.expectError(error.BufferOverflow, buf.append("Hello"));
}

test "MemoryTracker stats" {
    var tracker = MemoryTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try tracker.trackAllocation(0x1000, 100, null);
    try tracker.trackAllocation(0x2000, 200, null);

    try std.testing.expectEqual(@as(usize, 300), tracker.currentUsage());
    try std.testing.expectEqual(@as(usize, 2), tracker.leakCount());

    tracker.trackFree(0x1000);
    try std.testing.expectEqual(@as(usize, 200), tracker.currentUsage());
    try std.testing.expectEqual(@as(usize, 1), tracker.leakCount());
}

test "utils.secureZero" {
    var data = [_]u8{ 1, 2, 3, 4, 5 };
    utils.secureZero(&data);

    for (data) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "utils.safeCopy" {
    var dest: [10]u8 = undefined;
    const src = "Hello";

    const copied = try utils.safeCopy(&dest, src);
    try std.testing.expectEqual(@as(usize, 5), copied);
    try std.testing.expectEqualStrings("Hello", dest[0..5]);
}

test "ResourceManager LIFO cleanup" {
    var cleanup_order = std.ArrayList(u8).init(std.testing.allocator);
    defer cleanup_order.deinit();

    const Context = struct {
        order: *std.ArrayList(u8),
        id: u8,
    };

    var ctx1 = Context{ .order = &cleanup_order, .id = 1 };
    var ctx2 = Context{ .order = &cleanup_order, .id = 2 };

    {
        var manager = ResourceManager.init(std.testing.allocator);
        defer manager.deinit();

        const cleanup_fn = struct {
            fn cleanup(ptr: *anyopaque) void {
                const ctx: *Context = @ptrCast(@alignCast(ptr));
                ctx.order.append(ctx.id) catch {};
            }
        }.cleanup;

        try manager.register(@ptrCast(&ctx1), cleanup_fn, "ctx1");
        try manager.register(@ptrCast(&ctx2), cleanup_fn, "ctx2");
    }

    // Should be LIFO: 2, 1
    try std.testing.expectEqual(@as(u8, 2), cleanup_order.items[0]);
    try std.testing.expectEqual(@as(u8, 1), cleanup_order.items[1]);
}
