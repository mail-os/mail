const std = @import("std");
const Allocator = std.mem.Allocator;

/// Zero-Copy Optimizations for SMTP Server Hot Paths
/// Minimizes allocations by using views, slices, and in-place operations

// =============================================================================
// Buffer View - Non-owning slice with metadata
// =============================================================================

pub const BufferView = struct {
    const Self = @This();

    data: []const u8,
    offset: usize = 0,
    source: Source = .unknown,

    pub const Source = enum {
        unknown,
        stack,
        heap,
        mmap,
        network,
        file,
    };

    pub fn init(data: []const u8) Self {
        return Self{ .data = data };
    }

    pub fn fromSlice(data: []const u8, source: Source) Self {
        return Self{ .data = data, .source = source };
    }

    pub fn slice(self: Self, start: usize, end: usize) Self {
        const actual_start = @min(start, self.data.len);
        const actual_end = @min(end, self.data.len);
        return Self{
            .data = self.data[actual_start..actual_end],
            .offset = self.offset + actual_start,
            .source = self.source,
        };
    }

    pub fn sliceFrom(self: Self, start: usize) Self {
        return self.slice(start, self.data.len);
    }

    pub fn sliceTo(self: Self, end: usize) Self {
        return self.slice(0, end);
    }

    pub fn len(self: Self) usize {
        return self.data.len;
    }

    pub fn isEmpty(self: Self) bool {
        return self.data.len == 0;
    }

    pub fn at(self: Self, index: usize) ?u8 {
        if (index >= self.data.len) return null;
        return self.data[index];
    }

    pub fn bytes(self: Self) []const u8 {
        return self.data;
    }

    /// Find first occurrence of needle
    pub fn indexOf(self: Self, needle: []const u8) ?usize {
        return std.mem.indexOf(u8, self.data, needle);
    }

    /// Find first occurrence of byte
    pub fn indexOfByte(self: Self, byte: u8) ?usize {
        return std.mem.indexOfScalar(u8, self.data, byte);
    }

    /// Check if starts with prefix
    pub fn startsWith(self: Self, prefix: []const u8) bool {
        return std.mem.startsWith(u8, self.data, prefix);
    }

    /// Check if ends with suffix
    pub fn endsWith(self: Self, suffix: []const u8) bool {
        return std.mem.endsWith(u8, self.data, suffix);
    }

    /// Trim whitespace from both ends (returns view, no allocation)
    pub fn trim(self: Self) Self {
        const trimmed = std.mem.trim(u8, self.data, " \t\r\n");
        const start_offset = @intFromPtr(trimmed.ptr) - @intFromPtr(self.data.ptr);
        return Self{
            .data = trimmed,
            .offset = self.offset + start_offset,
            .source = self.source,
        };
    }

    /// Split on delimiter, returning iterator of views
    pub fn split(self: Self, delimiter: []const u8) SplitIterator {
        return SplitIterator{
            .view = self,
            .delimiter = delimiter,
            .index = 0,
        };
    }

    pub const SplitIterator = struct {
        view: Self,
        delimiter: []const u8,
        index: usize,

        pub fn next(self: *SplitIterator) ?BufferView {
            if (self.index >= self.view.data.len) return null;

            const remaining = self.view.data[self.index..];
            if (std.mem.indexOf(u8, remaining, self.delimiter)) |pos| {
                const result = BufferView{
                    .data = remaining[0..pos],
                    .offset = self.view.offset + self.index,
                    .source = self.view.source,
                };
                self.index += pos + self.delimiter.len;
                return result;
            } else {
                const result = BufferView{
                    .data = remaining,
                    .offset = self.view.offset + self.index,
                    .source = self.view.source,
                };
                self.index = self.view.data.len;
                return result;
            }
        }

        pub fn rest(self: *SplitIterator) BufferView {
            return BufferView{
                .data = self.view.data[self.index..],
                .offset = self.view.offset + self.index,
                .source = self.view.source,
            };
        }
    };
};

// =============================================================================
// Ring Buffer - Fixed capacity, zero allocation after init
// =============================================================================

pub fn RingBuffer(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        buffer: [capacity]u8 = undefined,
        read_pos: usize = 0,
        write_pos: usize = 0,
        count: usize = 0,

        pub fn init() Self {
            return Self{};
        }

        pub fn write(self: *Self, data: []const u8) usize {
            var written: usize = 0;
            for (data) |byte| {
                if (self.count >= capacity) break;
                self.buffer[self.write_pos] = byte;
                self.write_pos = (self.write_pos + 1) % capacity;
                self.count += 1;
                written += 1;
            }
            return written;
        }

        pub fn read(self: *Self, dest: []u8) usize {
            var read_count: usize = 0;
            for (dest) |*byte| {
                if (self.count == 0) break;
                byte.* = self.buffer[self.read_pos];
                self.read_pos = (self.read_pos + 1) % capacity;
                self.count -= 1;
                read_count += 1;
            }
            return read_count;
        }

        pub fn peek(self: *const Self, dest: []u8) usize {
            var peek_count: usize = 0;
            var pos = self.read_pos;
            var remaining = self.count;
            for (dest) |*byte| {
                if (remaining == 0) break;
                byte.* = self.buffer[pos];
                pos = (pos + 1) % capacity;
                remaining -= 1;
                peek_count += 1;
            }
            return peek_count;
        }

        pub fn skip(self: *Self, n: usize) usize {
            const to_skip = @min(n, self.count);
            self.read_pos = (self.read_pos + to_skip) % capacity;
            self.count -= to_skip;
            return to_skip;
        }

        pub fn available(self: *const Self) usize {
            return self.count;
        }

        pub fn freeSpace(self: *const Self) usize {
            return capacity - self.count;
        }

        pub fn clear(self: *Self) void {
            self.read_pos = 0;
            self.write_pos = 0;
            self.count = 0;
        }

        /// Get contiguous readable slice (may not contain all data if wrapped)
        pub fn readableSlice(self: *const Self) []const u8 {
            if (self.count == 0) return &[_]u8{};
            const end = @min(self.read_pos + self.count, capacity);
            return self.buffer[self.read_pos..end];
        }

        /// Get contiguous writable slice
        pub fn writableSlice(self: *Self) []u8 {
            if (self.count >= capacity) return &[_]u8{};
            const end = @min(self.write_pos + (capacity - self.count), capacity);
            return self.buffer[self.write_pos..end];
        }

        /// Advance write position after external write to writableSlice
        pub fn commitWrite(self: *Self, n: usize) void {
            const actual = @min(n, capacity - self.count);
            self.write_pos = (self.write_pos + actual) % capacity;
            self.count += actual;
        }
    };
}

// =============================================================================
// Slice Pool - Reusable slice allocations
// =============================================================================

pub fn SlicePool(comptime T: type, comptime max_slices: usize, comptime slice_size: usize) type {
    return struct {
        const Self = @This();

        storage: [max_slices][slice_size]T = undefined,
        available: [max_slices]bool = [_]bool{true} ** max_slices,
        allocated_count: usize = 0,

        pub fn init() Self {
            return Self{};
        }

        pub fn acquire(self: *Self) ?[]T {
            for (&self.available, 0..) |*avail, i| {
                if (avail.*) {
                    avail.* = false;
                    self.allocated_count += 1;
                    return &self.storage[i];
                }
            }
            return null;
        }

        pub fn release(self: *Self, slice: []T) void {
            const ptr = @intFromPtr(slice.ptr);
            const base = @intFromPtr(&self.storage[0]);
            const stride = slice_size * @sizeOf(T);

            if (ptr >= base and ptr < base + max_slices * stride) {
                const index = (ptr - base) / stride;
                if (index < max_slices and !self.available[index]) {
                    self.available[index] = true;
                    self.allocated_count -= 1;
                }
            }
        }

        pub fn availableCount(self: *const Self) usize {
            return max_slices - self.allocated_count;
        }

        pub fn allocatedCount(self: *const Self) usize {
            return self.allocated_count;
        }
    };
}

// =============================================================================
// String Interner - Deduplicate strings, return views
// =============================================================================

pub const StringInterner = struct {
    const Self = @This();

    storage: std.ArrayList(u8),
    index: std.StringHashMap(StringRef),
    allocator: Allocator,

    pub const StringRef = struct {
        offset: u32,
        length: u32,
    };

    pub fn init(allocator: Allocator) Self {
        return Self{
            .storage = std.ArrayList(u8).init(allocator),
            .index = std.StringHashMap(StringRef).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.index.deinit();
        self.storage.deinit();
    }

    /// Intern a string, returning a view into deduplicated storage
    pub fn intern(self: *Self, str: []const u8) ![]const u8 {
        if (self.index.get(str)) |ref| {
            return self.storage.items[ref.offset..][0..ref.length];
        }

        const offset: u32 = @intCast(self.storage.items.len);
        const length: u32 = @intCast(str.len);

        try self.storage.appendSlice(str);

        const interned = self.storage.items[offset..][0..length];
        try self.index.put(interned, StringRef{
            .offset = offset,
            .length = length,
        });

        return interned;
    }

    /// Get interned string if it exists
    pub fn get(self: *const Self, str: []const u8) ?[]const u8 {
        if (self.index.get(str)) |ref| {
            return self.storage.items[ref.offset..][0..ref.length];
        }
        return null;
    }

    /// Total bytes stored
    pub fn totalSize(self: *const Self) usize {
        return self.storage.items.len;
    }

    /// Number of unique strings
    pub fn uniqueCount(self: *const Self) usize {
        return self.index.count();
    }
};

// =============================================================================
// Zero-Copy Parser Utilities
// =============================================================================

pub const Parser = struct {
    /// Parse SMTP command without allocation - returns views into input
    pub fn parseSmtpCommand(input: []const u8) SmtpCommand {
        var view = BufferView.init(input);

        // Trim trailing CRLF
        if (view.endsWith("\r\n")) {
            view = view.sliceTo(view.len() - 2);
        }

        // Find command verb
        const space_pos = view.indexOfByte(' ') orelse view.len();
        const verb = view.sliceTo(space_pos);
        const args = if (space_pos < view.len())
            view.sliceFrom(space_pos + 1).trim()
        else
            BufferView.init("");

        return SmtpCommand{
            .verb = verb,
            .args = args,
            .raw = BufferView.init(input),
        };
    }

    pub const SmtpCommand = struct {
        verb: BufferView,
        args: BufferView,
        raw: BufferView,

        pub fn isVerb(self: SmtpCommand, expected: []const u8) bool {
            return std.ascii.eqlIgnoreCase(self.verb.bytes(), expected);
        }
    };

    /// Parse email header without allocation - returns views
    pub fn parseHeader(line: []const u8) ?Header {
        const colon_pos = std.mem.indexOfScalar(u8, line, ':') orelse return null;

        const name = BufferView.init(line[0..colon_pos]).trim();
        const value = if (colon_pos + 1 < line.len)
            BufferView.init(line[colon_pos + 1 ..]).trim()
        else
            BufferView.init("");

        return Header{
            .name = name,
            .value = value,
            .raw = BufferView.init(line),
        };
    }

    pub const Header = struct {
        name: BufferView,
        value: BufferView,
        raw: BufferView,
    };

    /// Parse email address from angle brackets or plain
    pub fn parseEmailAddress(input: []const u8) EmailAddress {
        var view = BufferView.init(input).trim();

        // Handle <address> format
        if (view.startsWith("<")) {
            view = view.sliceFrom(1);
            if (view.indexOf(">")) |end| {
                view = view.sliceTo(end);
            }
        }

        // Find @ to split local and domain
        const at_pos = view.indexOfByte('@');

        return EmailAddress{
            .full = view,
            .local = if (at_pos) |pos| view.sliceTo(pos) else view,
            .domain = if (at_pos) |pos| view.sliceFrom(pos + 1) else BufferView.init(""),
        };
    }

    pub const EmailAddress = struct {
        full: BufferView,
        local: BufferView,
        domain: BufferView,

        pub fn isValid(self: EmailAddress) bool {
            return self.local.len() > 0 and self.domain.len() > 0;
        }
    };

    /// Parse MIME content-type without allocation
    pub fn parseContentType(input: []const u8) ContentType {
        var view = BufferView.init(input).trim();
        var result = ContentType{
            .media_type = view,
            .subtype = BufferView.init(""),
            .params = view, // Will be narrowed
        };

        // Find type/subtype separator
        if (view.indexOfByte('/')) |slash| {
            result.media_type = view.sliceTo(slash);

            const rest = view.sliceFrom(slash + 1);
            // Find parameters separator
            if (rest.indexOfByte(';')) |semi| {
                result.subtype = rest.sliceTo(semi).trim();
                result.params = rest.sliceFrom(semi + 1).trim();
            } else {
                result.subtype = rest.trim();
                result.params = BufferView.init("");
            }
        }

        return result;
    }

    pub const ContentType = struct {
        media_type: BufferView,
        subtype: BufferView,
        params: BufferView,

        pub fn getParam(self: ContentType, name: []const u8) ?BufferView {
            var params = self.params;
            var split = params.split(";");

            while (split.next()) |param| {
                const trimmed = param.trim();
                if (trimmed.indexOf("=")) |eq| {
                    const param_name = trimmed.sliceTo(eq).trim();
                    if (std.ascii.eqlIgnoreCase(param_name.bytes(), name)) {
                        var value = trimmed.sliceFrom(eq + 1).trim();
                        // Remove quotes if present
                        if (value.startsWith("\"") and value.endsWith("\"") and value.len() >= 2) {
                            value = value.slice(1, value.len() - 1);
                        }
                        return value;
                    }
                }
            }
            return null;
        }
    };
};

// =============================================================================
// In-Place Transformations
// =============================================================================

pub const Transform = struct {
    /// Convert to lowercase in-place
    pub fn toLowerInPlace(data: []u8) void {
        for (data) |*c| {
            c.* = std.ascii.toLower(c.*);
        }
    }

    /// Convert to uppercase in-place
    pub fn toUpperInPlace(data: []u8) void {
        for (data) |*c| {
            c.* = std.ascii.toUpper(c.*);
        }
    }

    /// Remove CRLF in-place, returns new length
    pub fn stripCrlfInPlace(data: []u8) usize {
        var write_pos: usize = 0;
        var i: usize = 0;

        while (i < data.len) {
            if (i + 1 < data.len and data[i] == '\r' and data[i + 1] == '\n') {
                i += 2;
            } else if (data[i] == '\r' or data[i] == '\n') {
                i += 1;
            } else {
                data[write_pos] = data[i];
                write_pos += 1;
                i += 1;
            }
        }

        return write_pos;
    }

    /// Unfold RFC 5322 headers in-place
    pub fn unfoldHeaderInPlace(data: []u8) usize {
        var write_pos: usize = 0;
        var i: usize = 0;

        while (i < data.len) {
            // Check for CRLF followed by whitespace (folding)
            if (i + 2 < data.len and data[i] == '\r' and data[i + 1] == '\n' and
                (data[i + 2] == ' ' or data[i + 2] == '\t'))
            {
                // Replace fold with single space
                data[write_pos] = ' ';
                write_pos += 1;
                i += 3; // Skip CRLF and whitespace

                // Skip any additional whitespace
                while (i < data.len and (data[i] == ' ' or data[i] == '\t')) {
                    i += 1;
                }
            } else {
                data[write_pos] = data[i];
                write_pos += 1;
                i += 1;
            }
        }

        return write_pos;
    }

    /// Decode quoted-printable in-place
    pub fn decodeQuotedPrintableInPlace(data: []u8) usize {
        var write_pos: usize = 0;
        var i: usize = 0;

        while (i < data.len) {
            if (data[i] == '=' and i + 2 < data.len) {
                // Soft line break
                if (data[i + 1] == '\r' and i + 3 < data.len and data[i + 2] == '\n') {
                    i += 3;
                    continue;
                }
                // Encoded character
                if (std.fmt.parseInt(u8, data[i + 1 .. i + 3], 16)) |byte| {
                    data[write_pos] = byte;
                    write_pos += 1;
                    i += 3;
                } else |_| {
                    data[write_pos] = data[i];
                    write_pos += 1;
                    i += 1;
                }
            } else {
                data[write_pos] = data[i];
                write_pos += 1;
                i += 1;
            }
        }

        return write_pos;
    }
};

// =============================================================================
// Scatter-Gather I/O Support
// =============================================================================

pub const IoVec = struct {
    const Self = @This();

    vecs: std.ArrayList(std.posix.iovec_const),
    total_len: usize = 0,

    pub fn init(allocator: Allocator) Self {
        return Self{
            .vecs = std.ArrayList(std.posix.iovec_const).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.vecs.deinit();
    }

    pub fn append(self: *Self, data: []const u8) !void {
        try self.vecs.append(.{
            .base = data.ptr,
            .len = data.len,
        });
        self.total_len += data.len;
    }

    pub fn clear(self: *Self) void {
        self.vecs.clearRetainingCapacity();
        self.total_len = 0;
    }

    pub fn slices(self: *const Self) []const std.posix.iovec_const {
        return self.vecs.items;
    }

    pub fn totalLength(self: *const Self) usize {
        return self.total_len;
    }
};

// =============================================================================
// Tests
// =============================================================================

test "BufferView basic operations" {
    const data = "Hello, World!";
    const view = BufferView.init(data);

    try std.testing.expectEqual(@as(usize, 13), view.len());
    try std.testing.expect(view.startsWith("Hello"));
    try std.testing.expect(view.endsWith("!"));
    try std.testing.expectEqual(@as(?usize, 7), view.indexOf("World"));
}

test "BufferView slicing" {
    const data = "Hello, World!";
    const view = BufferView.init(data);

    const hello = view.sliceTo(5);
    try std.testing.expectEqualStrings("Hello", hello.bytes());

    const world = view.slice(7, 12);
    try std.testing.expectEqualStrings("World", world.bytes());
}

test "BufferView split iterator" {
    const data = "one,two,three";
    const view = BufferView.init(data);

    var split = view.split(",");
    try std.testing.expectEqualStrings("one", split.next().?.bytes());
    try std.testing.expectEqualStrings("two", split.next().?.bytes());
    try std.testing.expectEqualStrings("three", split.next().?.bytes());
    try std.testing.expect(split.next() == null);
}

test "RingBuffer operations" {
    var ring = RingBuffer(16).init();

    const written = ring.write("Hello");
    try std.testing.expectEqual(@as(usize, 5), written);
    try std.testing.expectEqual(@as(usize, 5), ring.available());

    var buf: [10]u8 = undefined;
    const read_count = ring.read(&buf);
    try std.testing.expectEqual(@as(usize, 5), read_count);
    try std.testing.expectEqualStrings("Hello", buf[0..5]);
}

test "SlicePool acquire and release" {
    var pool = SlicePool(u8, 4, 64).init();

    const slice1 = pool.acquire();
    try std.testing.expect(slice1 != null);
    try std.testing.expectEqual(@as(usize, 1), pool.allocatedCount());

    const slice2 = pool.acquire();
    try std.testing.expect(slice2 != null);
    try std.testing.expectEqual(@as(usize, 2), pool.allocatedCount());

    pool.release(slice1.?);
    try std.testing.expectEqual(@as(usize, 1), pool.allocatedCount());
}

test "StringInterner deduplication" {
    var interner = StringInterner.init(std.testing.allocator);
    defer interner.deinit();

    const s1 = try interner.intern("hello");
    const s2 = try interner.intern("world");
    const s3 = try interner.intern("hello"); // Duplicate

    try std.testing.expectEqual(s1.ptr, s3.ptr); // Same pointer
    try std.testing.expect(s1.ptr != s2.ptr);
    try std.testing.expectEqual(@as(usize, 2), interner.uniqueCount());
}

test "Parser.parseSmtpCommand" {
    const cmd = Parser.parseSmtpCommand("MAIL FROM:<test@example.com>\r\n");

    try std.testing.expect(cmd.isVerb("MAIL"));
    try std.testing.expectEqualStrings("FROM:<test@example.com>", cmd.args.bytes());
}

test "Parser.parseHeader" {
    const header = Parser.parseHeader("Content-Type: text/plain; charset=utf-8");
    try std.testing.expect(header != null);
    try std.testing.expectEqualStrings("Content-Type", header.?.name.bytes());
    try std.testing.expectEqualStrings("text/plain; charset=utf-8", header.?.value.bytes());
}

test "Parser.parseEmailAddress" {
    const addr = Parser.parseEmailAddress("<user@example.com>");
    try std.testing.expectEqualStrings("user@example.com", addr.full.bytes());
    try std.testing.expectEqualStrings("user", addr.local.bytes());
    try std.testing.expectEqualStrings("example.com", addr.domain.bytes());
}

test "Parser.parseContentType" {
    const ct = Parser.parseContentType("text/html; charset=\"UTF-8\"; boundary=abc");
    try std.testing.expectEqualStrings("text", ct.media_type.bytes());
    try std.testing.expectEqualStrings("html", ct.subtype.bytes());

    const charset = ct.getParam("charset");
    try std.testing.expect(charset != null);
    try std.testing.expectEqualStrings("UTF-8", charset.?.bytes());
}

test "Transform.toLowerInPlace" {
    var data = "Hello World".*;
    Transform.toLowerInPlace(&data);
    try std.testing.expectEqualStrings("hello world", &data);
}

test "Transform.stripCrlfInPlace" {
    var data = "Line1\r\nLine2\r\n".*;
    const new_len = Transform.stripCrlfInPlace(&data);
    try std.testing.expectEqualStrings("Line1Line2", data[0..new_len]);
}

test "Transform.unfoldHeaderInPlace" {
    var data = "Subject: This is\r\n a folded\r\n\t header".*;
    const new_len = Transform.unfoldHeaderInPlace(&data);
    try std.testing.expectEqualStrings("Subject: This is a folded header", data[0..new_len]);
}

test "IoVec scatter gather" {
    var iov = IoVec.init(std.testing.allocator);
    defer iov.deinit();

    try iov.append("Hello, ");
    try iov.append("World!");

    try std.testing.expectEqual(@as(usize, 2), iov.slices().len);
    try std.testing.expectEqual(@as(usize, 13), iov.totalLength());
}
