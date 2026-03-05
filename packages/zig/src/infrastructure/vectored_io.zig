const std = @import("std");

/// Vectored I/O writer for efficient multi-part responses
/// Uses writev() syscall to send multiple buffers in a single system call
pub const VectoredWriter = struct {
    allocator: std.mem.Allocator,
    iovecs: std.ArrayList(std.posix.iovec_const),
    total_bytes: usize,
    max_iovecs: usize,

    pub const WriteError = error{
        TooManyVectors,
        WriteFailed,
        OutOfMemory,
    };

    /// Initialize vectored writer
    pub fn init(allocator: std.mem.Allocator) VectoredWriter {
        return .{
            .allocator = allocator,
            .iovecs = .{},
            .total_bytes = 0,
            // IOV_MAX is typically 1024 on Linux, 1024 on macOS
            .max_iovecs = 1024,
        };
    }

    pub fn deinit(self: *VectoredWriter) void {
        self.iovecs.deinit(self.allocator);
    }

    /// Add a buffer to the vector
    pub fn addBuffer(self: *VectoredWriter, buffer: []const u8) !void {
        if (self.iovecs.items.len >= self.max_iovecs) {
            return WriteError.TooManyVectors;
        }

        const iov = std.posix.iovec_const{
            .base = buffer.ptr,
            .len = buffer.len,
        };

        try self.iovecs.append(self.allocator, iov);
        self.total_bytes += buffer.len;
    }

    /// Write all buffers using writev()
    pub fn writeAll(self: *VectoredWriter, fd: std.posix.fd_t) !usize {
        if (self.iovecs.items.len == 0) {
            return 0;
        }

        var bytes_written: usize = 0;
        var iov_offset: usize = 0;

        while (iov_offset < self.iovecs.items.len) {
            const remaining_iovecs = self.iovecs.items[iov_offset..];

            // writev may not write all data in one call
            const written = try std.posix.writev(fd, remaining_iovecs);
            bytes_written += written;

            // Find how many iovecs were fully written
            var accounted: usize = 0;
            for (remaining_iovecs) |iov| {
                if (accounted + iov.len <= written) {
                    accounted += iov.len;
                    iov_offset += 1;
                } else if (accounted < written) {
                    // Partial write of this iovec - need to adjust it
                    const partial = written - accounted;
                    self.iovecs.items[iov_offset].base += partial;
                    self.iovecs.items[iov_offset].len -= partial;
                    break;
                } else {
                    break;
                }
            }

            // If nothing was written but we're not done, that's an error
            if (written == 0 and bytes_written < self.total_bytes) {
                return WriteError.WriteFailed;
            }
        }

        return bytes_written;
    }

    /// Clear all buffers
    pub fn clear(self: *VectoredWriter) void {
        self.iovecs.clearRetainingCapacity();
        self.total_bytes = 0;
    }

    /// Get total bytes queued for writing
    pub fn getTotalBytes(self: *VectoredWriter) usize {
        return self.total_bytes;
    }

    /// Get number of vectors
    pub fn getVectorCount(self: *VectoredWriter) usize {
        return self.iovecs.items.len;
    }
};

/// SMTP Response builder using vectored I/O
pub const SMTPResponseBuilder = struct {
    allocator: std.mem.Allocator,
    writer: VectoredWriter,
    buffers: std.ArrayList([]u8),

    pub fn init(allocator: std.mem.Allocator) SMTPResponseBuilder {
        return .{
            .allocator = allocator,
            .writer = VectoredWriter.init(allocator),
            .buffers = .{},
        };
    }

    pub fn deinit(self: *SMTPResponseBuilder) void {
        for (self.buffers.items) |buf| {
            self.allocator.free(buf);
        }
        self.buffers.deinit(self.allocator);
        self.writer.deinit();
    }

    /// Add a status line (e.g., "250 OK")
    pub fn addStatus(self: *SMTPResponseBuilder, code: u16, message: []const u8) !void {
        const status_line = try std.fmt.allocPrint(
            self.allocator,
            "{d} {s}\r\n",
            .{ code, message },
        );
        errdefer self.allocator.free(status_line);

        try self.buffers.append(self.allocator, status_line);
        try self.writer.addBuffer(status_line);
    }

    /// Add a multi-line status (e.g., "250-First line\r\n250 Last line")
    pub fn addMultilineStatus(self: *SMTPResponseBuilder, code: u16, lines: []const []const u8) !void {
        for (lines, 0..) |line, i| {
            const is_last = (i == lines.len - 1);
            const separator = if (is_last) " " else "-";

            const status_line = try std.fmt.allocPrint(
                self.allocator,
                "{d}{s}{s}\r\n",
                .{ code, separator, line },
            );
            errdefer self.allocator.free(status_line);

            try self.buffers.append(self.allocator, status_line);
            try self.writer.addBuffer(status_line);
        }
    }

    /// Add raw data
    pub fn addData(self: *SMTPResponseBuilder, data: []const u8) !void {
        const data_copy = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(data_copy);

        try self.buffers.append(self.allocator, data_copy);
        try self.writer.addBuffer(data_copy);
    }

    /// Send all buffered data using vectored I/O
    pub fn send(self: *SMTPResponseBuilder, fd: std.posix.fd_t) !usize {
        return self.writer.writeAll(fd);
    }

    /// Clear all buffers
    pub fn clear(self: *SMTPResponseBuilder) void {
        for (self.buffers.items) |buf| {
            self.allocator.free(buf);
        }
        self.buffers.clearRetainingCapacity();
        self.writer.clear();
    }
};

// Tests
test "vectored writer basic" {
    const testing = std.testing;

    var writer = VectoredWriter.init(testing.allocator);
    defer writer.deinit();

    const buf1 = "Hello ";
    const buf2 = "World";

    try writer.addBuffer(buf1);
    try writer.addBuffer(buf2);

    try testing.expectEqual(@as(usize, 2), writer.getVectorCount());
    try testing.expectEqual(@as(usize, 11), writer.getTotalBytes());
}

test "smtp response builder single line" {
    const testing = std.testing;

    var builder = SMTPResponseBuilder.init(testing.allocator);
    defer builder.deinit();

    try builder.addStatus(250, "OK");

    try testing.expectEqual(@as(usize, 1), builder.writer.getVectorCount());
}

test "smtp response builder multi-line" {
    const testing = std.testing;

    var builder = SMTPResponseBuilder.init(testing.allocator);
    defer builder.deinit();

    const lines = [_][]const u8{
        "smtp.example.com",
        "SIZE 10240000",
        "8BITMIME",
        "STARTTLS",
    };

    try builder.addMultilineStatus(250, &lines);

    try testing.expectEqual(@as(usize, 4), builder.writer.getVectorCount());
}

test "smtp response builder clear" {
    const testing = std.testing;

    var builder = SMTPResponseBuilder.init(testing.allocator);
    defer builder.deinit();

    try builder.addStatus(250, "OK");
    try testing.expectEqual(@as(usize, 1), builder.writer.getVectorCount());

    builder.clear();
    try testing.expectEqual(@as(usize, 0), builder.writer.getVectorCount());
    try testing.expectEqual(@as(usize, 0), builder.buffers.items.len);
}

test "vectored writer max vectors" {
    const testing = std.testing;

    var writer = VectoredWriter.init(testing.allocator);
    defer writer.deinit();

    writer.max_iovecs = 3;

    try writer.addBuffer("1");
    try writer.addBuffer("2");
    try writer.addBuffer("3");

    try testing.expectError(VectoredWriter.WriteError.TooManyVectors, writer.addBuffer("4"));
}
