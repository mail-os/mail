const std = @import("std");

/// CHUNKING extension (RFC 3030) implementation
/// Allows binary message transmission using BDAT command instead of DATA
pub const ChunkingHandler = struct {
    allocator: std.mem.Allocator,
    max_chunk_size: usize,
    max_message_size: usize,

    pub fn init(allocator: std.mem.Allocator, max_chunk_size: usize, max_message_size: usize) ChunkingHandler {
        return .{
            .allocator = allocator,
            .max_chunk_size = max_chunk_size,
            .max_message_size = max_message_size,
        };
    }

    /// Process BDAT command
    /// Format: BDAT <chunk-size> [LAST]
    pub fn handleBDAT(self: *ChunkingHandler, command: []const u8, stream: anytype) !BDATResult {
        // Parse BDAT command
        var parts = std.mem.splitScalar(u8, command, ' ');
        _ = parts.next(); // Skip "BDAT"

        const size_str = parts.next() orelse return error.InvalidBDATCommand;
        const chunk_size = try std.fmt.parseInt(usize, size_str, 10);

        // Check if this is the LAST chunk
        const is_last = blk: {
            if (parts.next()) |next_part| {
                const trimmed = std.mem.trim(u8, next_part, " \r\n");
                break :blk std.mem.eql(u8, trimmed, "LAST");
            }
            break :blk false;
        };

        // Validate chunk size
        if (chunk_size > self.max_chunk_size) {
            return error.ChunkTooLarge;
        }

        // Read the chunk data
        var chunk_data = try self.allocator.alloc(u8, chunk_size);
        errdefer self.allocator.free(chunk_data);

        var total_read: usize = 0;
        while (total_read < chunk_size) {
            const bytes_read = try stream.read(chunk_data[total_read..]);
            if (bytes_read == 0) {
                return error.UnexpectedEOF;
            }
            total_read += bytes_read;
        }

        return BDATResult{
            .chunk_data = chunk_data,
            .is_last = is_last,
            .chunk_size = chunk_size,
        };
    }

    /// Accumulate message chunks
    pub fn accumulateChunks(self: *ChunkingHandler, chunks: *std.ArrayList([]const u8)) ![]const u8 {
        // Calculate total size
        var total_size: usize = 0;
        for (chunks.items) |chunk| {
            total_size += chunk.len;
        }

        // Check against max message size
        if (total_size > self.max_message_size) {
            return error.MessageTooLarge;
        }

        // Combine all chunks
        var message = try self.allocator.alloc(u8, total_size);
        var offset: usize = 0;

        for (chunks.items) |chunk| {
            @memcpy(message[offset .. offset + chunk.len], chunk);
            offset += chunk.len;
        }

        return message;
    }

    /// Validate BDAT sequence
    pub fn validateSequence(self: *ChunkingHandler, results: []const BDATResult) !void {
        _ = self;

        if (results.len == 0) {
            return error.EmptySequence;
        }

        // Check that only the last result has is_last flag
        for (results[0 .. results.len - 1]) |result| {
            if (result.is_last) {
                return error.InvalidLastFlag;
            }
        }

        if (!results[results.len - 1].is_last) {
            return error.MissingLastFlag;
        }
    }

    /// Free chunk data
    pub fn freeChunk(self: *ChunkingHandler, chunk_data: []const u8) void {
        self.allocator.free(chunk_data);
    }
};

pub const BDATResult = struct {
    chunk_data: []const u8,
    is_last: bool,
    chunk_size: usize,
};

/// BDAT session state
pub const BDATSession = struct {
    allocator: std.mem.Allocator,
    chunks: std.ArrayList([]const u8),
    total_size: usize,
    completed: bool,

    pub fn init(allocator: std.mem.Allocator) BDATSession {
        return .{
            .allocator = allocator,
            .chunks = .{},
            .total_size = 0,
            .completed = false,
        };
    }

    pub fn deinit(self: *BDATSession) void {
        for (self.chunks.items) |chunk| {
            self.allocator.free(chunk);
        }
        self.chunks.deinit(self.allocator);
    }

    /// Add a chunk to the session
    pub fn addChunk(self: *BDATSession, chunk_data: []const u8, is_last: bool) !void {
        if (self.completed) {
            return error.SessionAlreadyCompleted;
        }

        try self.chunks.append(self.allocator, chunk_data);
        self.total_size += chunk_data.len;

        if (is_last) {
            self.completed = true;
        }
    }

    /// Get the complete message
    pub fn getMessage(self: *BDATSession) ![]const u8 {
        if (!self.completed) {
            return error.SessionNotCompleted;
        }

        var message = try self.allocator.alloc(u8, self.total_size);
        var offset: usize = 0;

        for (self.chunks.items) |chunk| {
            @memcpy(message[offset .. offset + chunk.len], chunk);
            offset += chunk.len;
        }

        return message;
    }

    pub fn reset(self: *BDATSession) void {
        for (self.chunks.items) |chunk| {
            self.allocator.free(chunk);
        }
        self.chunks.clearRetainingCapacity();
        self.total_size = 0;
        self.completed = false;
    }
};

test "BDAT command parsing" {
    const testing = std.testing;
    _ = ChunkingHandler.init(testing.allocator, 1024 * 1024, 10 * 1024 * 1024);

    // Test parsing BDAT without LAST
    const cmd1 = "BDAT 100";
    var parts = std.mem.splitScalar(u8, cmd1, ' ');
    _ = parts.next(); // Skip "BDAT"
    const size_str = parts.next() orelse return error.TestFailed;
    const chunk_size = try std.fmt.parseInt(usize, size_str, 10);
    try testing.expectEqual(@as(usize, 100), chunk_size);

    // Test parsing BDAT with LAST
    const cmd2 = "BDAT 50 LAST";
    var parts2 = std.mem.splitScalar(u8, cmd2, ' ');
    _ = parts2.next(); // Skip "BDAT"
    const size_str2 = parts2.next() orelse return error.TestFailed;
    const chunk_size2 = try std.fmt.parseInt(usize, size_str2, 10);
    try testing.expectEqual(@as(usize, 50), chunk_size2);

    const last_part = parts2.next() orelse return error.TestFailed;
    const is_last = std.mem.eql(u8, std.mem.trim(u8, last_part, " \r\n"), "LAST");
    try testing.expect(is_last);
}

test "BDAT session management" {
    const testing = std.testing;

    var session = BDATSession.init(testing.allocator);
    defer session.deinit();

    // Add first chunk
    const chunk1 = try testing.allocator.dupe(u8, "Hello, ");
    try session.addChunk(chunk1, false);

    // Add second chunk (last)
    const chunk2 = try testing.allocator.dupe(u8, "World!");
    try session.addChunk(chunk2, true);

    // Get complete message
    const message = try session.getMessage();
    defer testing.allocator.free(message);

    try testing.expectEqualStrings("Hello, World!", message);
    try testing.expectEqual(@as(usize, 13), session.total_size);
    try testing.expect(session.completed);
}

test "BDAT session reset" {
    const testing = std.testing;

    var session = BDATSession.init(testing.allocator);
    defer session.deinit();

    const chunk = try testing.allocator.dupe(u8, "Test");
    try session.addChunk(chunk, true);

    session.reset();

    try testing.expectEqual(@as(usize, 0), session.total_size);
    try testing.expect(!session.completed);
    try testing.expectEqual(@as(usize, 0), session.chunks.items.len);
}

test "chunk accumulation" {
    const testing = std.testing;
    var handler = ChunkingHandler.init(testing.allocator, 1024, 10 * 1024);

    var chunks = std.ArrayList([]const u8).init(testing.allocator);
    defer {
        for (chunks.items) |chunk| {
            testing.allocator.free(chunk);
        }
        chunks.deinit();
    }

    try chunks.append(try testing.allocator.dupe(u8, "Part1 "));
    try chunks.append(try testing.allocator.dupe(u8, "Part2 "));
    try chunks.append(try testing.allocator.dupe(u8, "Part3"));

    const message = try handler.accumulateChunks(&chunks);
    defer testing.allocator.free(message);

    try testing.expectEqualStrings("Part1 Part2 Part3", message);
}

test "validate BDAT sequence" {
    const testing = std.testing;
    var handler = ChunkingHandler.init(testing.allocator, 1024, 10 * 1024);

    // Valid sequence
    const valid_results = [_]BDATResult{
        .{ .chunk_data = &[_]u8{}, .is_last = false, .chunk_size = 10 },
        .{ .chunk_data = &[_]u8{}, .is_last = false, .chunk_size = 20 },
        .{ .chunk_data = &[_]u8{}, .is_last = true, .chunk_size = 5 },
    };
    try handler.validateSequence(&valid_results);

    // Invalid: LAST in middle
    const invalid_results = [_]BDATResult{
        .{ .chunk_data = &[_]u8{}, .is_last = false, .chunk_size = 10 },
        .{ .chunk_data = &[_]u8{}, .is_last = true, .chunk_size = 20 },
        .{ .chunk_data = &[_]u8{}, .is_last = false, .chunk_size = 5 },
    };
    try testing.expectError(error.InvalidLastFlag, handler.validateSequence(&invalid_results));

    // Invalid: Missing LAST
    const missing_last = [_]BDATResult{
        .{ .chunk_data = &[_]u8{}, .is_last = false, .chunk_size = 10 },
        .{ .chunk_data = &[_]u8{}, .is_last = false, .chunk_size = 20 },
    };
    try testing.expectError(error.MissingLastFlag, handler.validateSequence(&missing_last));
}
