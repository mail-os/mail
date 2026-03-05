const std = @import("std");

/// Streaming message parser with bounded buffers for large messages
/// Prevents memory exhaustion by parsing messages in chunks
pub const StreamingParser = struct {
    allocator: std.mem.Allocator,
    buffer: []u8,
    buffer_size: usize,
    position: usize,
    total_bytes_read: usize,
    max_message_size: usize,
    state: ParserState,
    headers_complete: bool,
    headers: std.ArrayList(Header),
    boundary: ?[]const u8,

    pub const ParserState = enum {
        reading_headers,
        reading_body,
        complete,
        error_state,
    };

    pub const Header = struct {
        name: []const u8,
        value: []const u8,

        pub fn deinit(self: *Header, allocator: std.mem.Allocator) void {
            allocator.free(self.name);
            allocator.free(self.value);
        }
    };

    pub const ParseError = error{
        MessageTooLarge,
        InvalidFormat,
        BufferOverflow,
        OutOfMemory,
    };

    /// Initialize streaming parser with bounded buffer
    pub fn init(allocator: std.mem.Allocator, buffer_size: usize, max_message_size: usize) !StreamingParser {
        const buffer = try allocator.alloc(u8, buffer_size);
        errdefer allocator.free(buffer);

        return StreamingParser{
            .allocator = allocator,
            .buffer = buffer,
            .buffer_size = buffer_size,
            .position = 0,
            .total_bytes_read = 0,
            .max_message_size = max_message_size,
            .state = .reading_headers,
            .headers_complete = false,
            .headers = std.ArrayList(Header).init(allocator),
            .boundary = null,
        };
    }

    pub fn deinit(self: *StreamingParser) void {
        self.allocator.free(self.buffer);

        for (self.headers.items) |*header| {
            header.deinit(self.allocator);
        }
        self.headers.deinit();

        if (self.boundary) |b| {
            self.allocator.free(b);
        }
    }

    /// Process a chunk of data
    pub fn processChunk(self: *StreamingParser, chunk: []const u8) !void {
        // Check total size limit
        if (self.total_bytes_read + chunk.len > self.max_message_size) {
            self.state = .error_state;
            return ParseError.MessageTooLarge;
        }

        self.total_bytes_read += chunk.len;

        // Process chunk based on current state
        switch (self.state) {
            .reading_headers => try self.processHeaderChunk(chunk),
            .reading_body => try self.processBodyChunk(chunk),
            .complete => return, // Already complete
            .error_state => return ParseError.InvalidFormat,
        }
    }

    fn processHeaderChunk(self: *StreamingParser, chunk: []const u8) !void {
        // Look for header/body separator (\r\n\r\n)
        var search_start: usize = 0;

        // Copy chunk to buffer if needed
        if (self.position + chunk.len > self.buffer_size) {
            return ParseError.BufferOverflow;
        }

        @memcpy(self.buffer[self.position .. self.position + chunk.len], chunk);
        self.position += chunk.len;

        // Search for end of headers
        const buffer_to_search = self.buffer[0..self.position];
        if (std.mem.indexOf(u8, buffer_to_search, "\r\n\r\n")) |end_of_headers| {
            // Headers are complete
            const headers_section = buffer_to_search[0..end_of_headers];
            try self.parseHeaders(headers_section);

            self.headers_complete = true;
            self.state = .reading_body;

            // Move remaining data to start of buffer
            const body_start = end_of_headers + 4; // Skip \r\n\r\n
            if (body_start < self.position) {
                const remaining = self.position - body_start;
                std.mem.copyForwards(u8, self.buffer[0..remaining], buffer_to_search[body_start..self.position]);
                self.position = remaining;
            } else {
                self.position = 0;
            }
        }
    }

    fn parseHeaders(self: *StreamingParser, headers_data: []const u8) !void {
        var lines = std.mem.splitSequence(u8, headers_data, "\r\n");

        var current_header: ?Header = null;

        while (lines.next()) |line| {
            if (line.len == 0) continue;

            // Check for continuation line (starts with whitespace)
            if (line[0] == ' ' or line[0] == '\t') {
                // Continuation of previous header
                if (current_header) |*header| {
                    const trimmed = std.mem.trim(u8, line, " \t");
                    const new_value = try std.fmt.allocPrint(
                        self.allocator,
                        "{s} {s}",
                        .{ header.value, trimmed },
                    );
                    self.allocator.free(header.value);
                    header.value = new_value;
                }
            } else {
                // New header line
                if (std.mem.indexOf(u8, line, ":")) |colon_pos| {
                    const name = std.mem.trim(u8, line[0..colon_pos], " \t");
                    const value = std.mem.trim(u8, line[colon_pos + 1 ..], " \t");

                    const header = Header{
                        .name = try self.allocator.dupe(u8, name),
                        .value = try self.allocator.dupe(u8, value),
                    };

                    try self.headers.append(header);
                    current_header = header;

                    // Check for Content-Type with boundary
                    if (std.ascii.eqlIgnoreCase(name, "content-type")) {
                        if (std.mem.indexOf(u8, value, "boundary=")) |boundary_start| {
                            const boundary_value = value[boundary_start + 9 ..];
                            // Remove quotes if present
                            const boundary_trimmed = std.mem.trim(u8, boundary_value, "\" ");
                            self.boundary = try self.allocator.dupe(u8, boundary_trimmed);
                        }
                    }
                }
            }
        }
    }

    fn processBodyChunk(self: *StreamingParser, chunk: []const u8) !void {
        // For now, just accumulate body data in buffer
        // In a full implementation, this would:
        // 1. Check for MIME boundaries if multipart
        // 2. Stream body data to storage
        // 3. Handle different encodings (base64, quoted-printable)

        if (self.position + chunk.len > self.buffer_size) {
            // Buffer full - in production, would flush to storage
            // For now, just indicate completion
            self.state = .complete;
            return;
        }

        @memcpy(self.buffer[self.position .. self.position + chunk.len], chunk);
        self.position += chunk.len;
    }

    /// Get a header value by name (case-insensitive)
    pub fn getHeader(self: *StreamingParser, name: []const u8) ?[]const u8 {
        for (self.headers.items) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) {
                return header.value;
            }
        }
        return null;
    }

    /// Get current body data
    pub fn getBodyData(self: *StreamingParser) []const u8 {
        return self.buffer[0..self.position];
    }

    /// Check if parsing is complete
    pub fn isComplete(self: *StreamingParser) bool {
        return self.state == .complete;
    }

    /// Get parsing statistics
    pub fn getStats(self: *StreamingParser) ParseStats {
        return .{
            .total_bytes_read = self.total_bytes_read,
            .headers_count = self.headers.items.len,
            .headers_complete = self.headers_complete,
            .state = self.state,
            .buffer_usage_percent = @as(f64, @floatFromInt(self.position)) / @as(f64, @floatFromInt(self.buffer_size)) * 100.0,
        };
    }
};

pub const ParseStats = struct {
    total_bytes_read: usize,
    headers_count: usize,
    headers_complete: bool,
    state: StreamingParser.ParserState,
    buffer_usage_percent: f64,
};

/// Chunked reader for processing data in fixed-size chunks
pub const ChunkedReader = struct {
    allocator: std.mem.Allocator,
    chunk_size: usize,
    parser: StreamingParser,

    pub fn init(allocator: std.mem.Allocator, chunk_size: usize, max_message_size: usize) !ChunkedReader {
        return ChunkedReader{
            .allocator = allocator,
            .chunk_size = chunk_size,
            .parser = try StreamingParser.init(allocator, chunk_size * 2, max_message_size),
        };
    }

    pub fn deinit(self: *ChunkedReader) void {
        self.parser.deinit();
    }

    /// Read and process data from reader in chunks
    pub fn readMessage(self: *ChunkedReader, reader: anytype) !void {
        var chunk_buffer = try self.allocator.alloc(u8, self.chunk_size);
        defer self.allocator.free(chunk_buffer);

        while (true) {
            const bytes_read = try reader.read(chunk_buffer);
            if (bytes_read == 0) break; // EOF

            try self.parser.processChunk(chunk_buffer[0..bytes_read]);

            if (self.parser.isComplete()) break;
        }
    }
};

test "streaming parser basic headers" {
    const testing = std.testing;

    var parser = try StreamingParser.init(testing.allocator, 4096, 1024 * 1024);
    defer parser.deinit();

    const chunk =
        \\From: sender@example.com
        \\To: recipient@example.com
        \\Subject: Test Message
        \\
        \\Hello World
    ;

    try parser.processChunk(chunk);

    try testing.expect(parser.headers_complete);
    try testing.expectEqual(@as(usize, 3), parser.headers.items.len);

    const from_header = parser.getHeader("From");
    try testing.expect(from_header != null);
    try testing.expectEqualStrings("sender@example.com", from_header.?);
}

test "streaming parser message too large" {
    const testing = std.testing;

    var parser = try StreamingParser.init(testing.allocator, 1024, 100); // Max 100 bytes
    defer parser.deinit();

    const large_chunk = "x" ** 200; // 200 bytes
    const result = parser.processChunk(large_chunk);

    try testing.expectError(StreamingParser.ParseError.MessageTooLarge, result);
}

test "streaming parser multipart boundary detection" {
    const testing = std.testing;

    var parser = try StreamingParser.init(testing.allocator, 4096, 1024 * 1024);
    defer parser.deinit();

    const chunk =
        \\Content-Type: multipart/mixed; boundary="----Boundary123"
        \\
        \\Body content
    ;

    try parser.processChunk(chunk);

    try testing.expect(parser.boundary != null);
    try testing.expectEqualStrings("----Boundary123", parser.boundary.?);
}
