const std = @import("std");

/// Zero-copy buffer management for efficient I/O
/// Reduces memory copies by using buffer slicing and referencing
pub const ZeroCopyBuffer = struct {
    allocator: std.mem.Allocator,
    backing_buffer: []u8,
    read_pos: usize,
    write_pos: usize,
    capacity: usize,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !ZeroCopyBuffer {
        const buffer = try allocator.alloc(u8, capacity);
        return .{
            .allocator = allocator,
            .backing_buffer = buffer,
            .read_pos = 0,
            .write_pos = 0,
            .capacity = capacity,
        };
    }

    pub fn deinit(self: *ZeroCopyBuffer) void {
        self.allocator.free(self.backing_buffer);
    }

    /// Get writable slice (remaining space)
    pub fn writableSlice(self: *ZeroCopyBuffer) []u8 {
        return self.backing_buffer[self.write_pos..];
    }

    /// Get readable slice (available data)
    pub fn readableSlice(self: *ZeroCopyBuffer) []const u8 {
        return self.backing_buffer[self.read_pos..self.write_pos];
    }

    /// Advance write position after writing
    pub fn advanceWrite(self: *ZeroCopyBuffer, count: usize) !void {
        if (self.write_pos + count > self.capacity) {
            return error.BufferOverflow;
        }
        self.write_pos += count;
    }

    /// Advance read position after reading
    pub fn advanceRead(self: *ZeroCopyBuffer, count: usize) !void {
        if (self.read_pos + count > self.write_pos) {
            return error.BufferUnderflow;
        }
        self.read_pos += count;
    }

    /// Compact buffer (move unread data to beginning)
    pub fn compact(self: *ZeroCopyBuffer) void {
        const unread = self.write_pos - self.read_pos;
        if (unread > 0 and self.read_pos > 0) {
            std.mem.copyForwards(u8, self.backing_buffer[0..unread], self.backing_buffer[self.read_pos..self.write_pos]);
        }
        self.read_pos = 0;
        self.write_pos = unread;
    }

    /// Reset buffer (mark all data as read)
    pub fn reset(self: *ZeroCopyBuffer) void {
        self.read_pos = 0;
        self.write_pos = 0;
    }

    /// Get available space for writing
    pub fn availableWrite(self: *ZeroCopyBuffer) usize {
        return self.capacity - self.write_pos;
    }

    /// Get available data for reading
    pub fn availableRead(self: *ZeroCopyBuffer) usize {
        return self.write_pos - self.read_pos;
    }

    /// Check if buffer is empty
    pub fn isEmpty(self: *ZeroCopyBuffer) bool {
        return self.read_pos == self.write_pos;
    }

    /// Check if buffer is full
    pub fn isFull(self: *ZeroCopyBuffer) bool {
        return self.write_pos == self.capacity;
    }

    /// Peek at data without consuming it
    pub fn peek(self: *ZeroCopyBuffer, count: usize) ![]const u8 {
        if (self.read_pos + count > self.write_pos) {
            return error.InsufficientData;
        }
        return self.backing_buffer[self.read_pos .. self.read_pos + count];
    }

    /// Find delimiter and return slice up to (but not including) it
    pub fn readUntil(self: *ZeroCopyBuffer, delimiter: u8) ?[]const u8 {
        const data = self.readableSlice();
        if (std.mem.indexOfScalar(u8, data, delimiter)) |pos| {
            return data[0..pos];
        }
        return null;
    }

    /// Consume data up to and including delimiter
    pub fn consumeUntil(self: *ZeroCopyBuffer, delimiter: u8) ![]const u8 {
        const data = self.readableSlice();
        if (std.mem.indexOfScalar(u8, data, delimiter)) |pos| {
            const result = data[0..pos];
            self.read_pos += pos + 1; // +1 to skip delimiter
            return result;
        }
        return error.DelimiterNotFound;
    }
};

/// Ring buffer for continuous zero-copy operations
pub const RingBuffer = struct {
    allocator: std.mem.Allocator,
    buffer: []u8,
    read_pos: usize,
    write_pos: usize,
    capacity: usize,
    count: usize, // Number of bytes currently in buffer

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !RingBuffer {
        const buffer = try allocator.alloc(u8, capacity);
        return .{
            .allocator = allocator,
            .buffer = buffer,
            .read_pos = 0,
            .write_pos = 0,
            .capacity = capacity,
            .count = 0,
        };
    }

    pub fn deinit(self: *RingBuffer) void {
        self.allocator.free(self.buffer);
    }

    /// Write data to ring buffer
    pub fn write(self: *RingBuffer, data: []const u8) !usize {
        const available = self.capacity - self.count;
        const to_write = @min(data.len, available);

        if (to_write == 0) {
            return error.BufferFull;
        }

        // Write in two parts if wrapping around
        if (self.write_pos + to_write > self.capacity) {
            const first_part = self.capacity - self.write_pos;
            const second_part = to_write - first_part;

            @memcpy(self.buffer[self.write_pos..self.capacity], data[0..first_part]);
            @memcpy(self.buffer[0..second_part], data[first_part..to_write]);

            self.write_pos = second_part;
        } else {
            @memcpy(self.buffer[self.write_pos .. self.write_pos + to_write], data[0..to_write]);
            self.write_pos = (self.write_pos + to_write) % self.capacity;
        }

        self.count += to_write;
        return to_write;
    }

    /// Read data from ring buffer
    pub fn read(self: *RingBuffer, dest: []u8) !usize {
        const to_read = @min(dest.len, self.count);

        if (to_read == 0) {
            return 0;
        }

        // Read in two parts if wrapping around
        if (self.read_pos + to_read > self.capacity) {
            const first_part = self.capacity - self.read_pos;
            const second_part = to_read - first_part;

            @memcpy(dest[0..first_part], self.buffer[self.read_pos..self.capacity]);
            @memcpy(dest[first_part..to_read], self.buffer[0..second_part]);

            self.read_pos = second_part;
        } else {
            @memcpy(dest[0..to_read], self.buffer[self.read_pos .. self.read_pos + to_read]);
            self.read_pos = (self.read_pos + to_read) % self.capacity;
        }

        self.count -= to_read;
        return to_read;
    }

    pub fn availableRead(self: *RingBuffer) usize {
        return self.count;
    }

    pub fn availableWrite(self: *RingBuffer) usize {
        return self.capacity - self.count;
    }

    pub fn reset(self: *RingBuffer) void {
        self.read_pos = 0;
        self.write_pos = 0;
        self.count = 0;
    }
};

/// Buffer chain for scatter-gather I/O
pub const BufferChain = struct {
    allocator: std.mem.Allocator,
    buffers: std.ArrayList([]const u8),

    pub fn init(allocator: std.mem.Allocator) BufferChain {
        return .{
            .allocator = allocator,
            .buffers = std.ArrayList([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *BufferChain) void {
        self.buffers.deinit();
    }

    /// Add a buffer to the chain (zero-copy reference)
    pub fn append(self: *BufferChain, buffer: []const u8) !void {
        try self.buffers.append(buffer);
    }

    /// Get total size of all buffers
    pub fn totalSize(self: *BufferChain) usize {
        var size: usize = 0;
        for (self.buffers.items) |buf| {
            size += buf.len;
        }
        return size;
    }

    /// Flatten buffer chain into a single buffer (requires copy)
    pub fn flatten(self: *BufferChain) ![]const u8 {
        const total = self.totalSize();
        const result = try self.allocator.alloc(u8, total);

        var offset: usize = 0;
        for (self.buffers.items) |buf| {
            @memcpy(result[offset .. offset + buf.len], buf);
            offset += buf.len;
        }

        return result;
    }

    /// Get an iterator over the buffers
    pub fn iterator(self: *BufferChain) BufferIterator {
        return .{
            .buffers = self.buffers.items,
            .index = 0,
        };
    }

    pub fn reset(self: *BufferChain) void {
        self.buffers.clearRetainingCapacity();
    }
};

pub const BufferIterator = struct {
    buffers: []const []const u8,
    index: usize,

    pub fn next(self: *BufferIterator) ?[]const u8 {
        if (self.index >= self.buffers.len) {
            return null;
        }
        const buffer = self.buffers[self.index];
        self.index += 1;
        return buffer;
    }
};

test "zero-copy buffer basic operations" {
    const testing = std.testing;

    var buf = try ZeroCopyBuffer.init(testing.allocator, 1024);
    defer buf.deinit();

    // Write data
    const writable = buf.writableSlice();
    @memcpy(writable[0..5], "Hello");
    try buf.advanceWrite(5);

    // Read data
    const readable = buf.readableSlice();
    try testing.expectEqualStrings("Hello", readable);

    try buf.advanceRead(5);
    try testing.expect(buf.isEmpty());
}

test "zero-copy buffer compact" {
    const testing = std.testing;

    var buf = try ZeroCopyBuffer.init(testing.allocator, 16);
    defer buf.deinit();

    // Write and partially read
    @memcpy(buf.writableSlice()[0..10], "HelloWorld");
    try buf.advanceWrite(10);

    try buf.advanceRead(5); // Read "Hello"

    // Compact to reclaim space
    buf.compact();

    try testing.expectEqual(@as(usize, 0), buf.read_pos);
    try testing.expectEqual(@as(usize, 5), buf.write_pos);
    try testing.expectEqualStrings("World", buf.readableSlice());
}

test "ring buffer operations" {
    const testing = std.testing;

    var ring = try RingBuffer.init(testing.allocator, 10);
    defer ring.deinit();

    // Write data
    const written = try ring.write("Hello");
    try testing.expectEqual(@as(usize, 5), written);
    try testing.expectEqual(@as(usize, 5), ring.availableRead());

    // Read data
    var read_buf: [10]u8 = undefined;
    const read_count = try ring.read(&read_buf);
    try testing.expectEqual(@as(usize, 5), read_count);
    try testing.expectEqualStrings("Hello", read_buf[0..5]);

    // Write wrapping around
    _ = try ring.write("12345");
    _ = try ring.write("67890");

    try testing.expectEqual(@as(usize, 10), ring.availableRead());
}

test "buffer chain" {
    const testing = std.testing;

    var chain = BufferChain.init(testing.allocator);
    defer chain.deinit();

    const buf1 = "Hello ";
    const buf2 = "World";
    const buf3 = "!";

    try chain.append(buf1);
    try chain.append(buf2);
    try chain.append(buf3);

    try testing.expectEqual(@as(usize, 12), chain.totalSize());

    // Flatten
    const flattened = try chain.flatten();
    defer testing.allocator.free(flattened);
    try testing.expectEqualStrings("Hello World!", flattened);

    // Iterator
    var iter = chain.iterator();
    try testing.expectEqualStrings("Hello ", iter.next().?);
    try testing.expectEqualStrings("World", iter.next().?);
    try testing.expectEqualStrings("!", iter.next().?);
    try testing.expect(iter.next() == null);
}

test "consume until delimiter" {
    const testing = std.testing;

    var buf = try ZeroCopyBuffer.init(testing.allocator, 1024);
    defer buf.deinit();

    @memcpy(buf.writableSlice()[0..11], "Hello\nWorld");
    try buf.advanceWrite(11);

    const line = try buf.consumeUntil('\n');
    try testing.expectEqualStrings("Hello", line);

    const remaining = buf.readableSlice();
    try testing.expectEqualStrings("World", remaining);
}
