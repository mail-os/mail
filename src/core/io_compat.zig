// Compatibility layer for Zig 0.16+ io changes
const std = @import("std");

// Global Io instance — set once from main(), used by compat wrappers.
var global_io: std.Io = undefined;
var io_initialized: bool = false;

pub fn initIo(io: std.Io) void {
    global_io = io;
    io_initialized = true;
}

pub fn getIo() std.Io {
    return global_io;
}

/// A simple fixed buffer stream that works like the old std.io.FixedBufferStream
pub const FixedBufferStream = struct {
    buffer: []u8,
    pos: usize = 0,

    pub fn init(buffer: []u8) FixedBufferStream {
        return .{ .buffer = buffer, .pos = 0 };
    }

    pub fn writer(self: *FixedBufferStream) Writer {
        return .{ .context = self };
    }

    pub fn getWritten(self: *const FixedBufferStream) []const u8 {
        return self.buffer[0..self.pos];
    }

    pub fn reset(self: *FixedBufferStream) void {
        self.pos = 0;
    }

    pub const Writer = struct {
        context: *FixedBufferStream,

        pub fn write(self: Writer, bytes: []const u8) error{NoSpaceLeft}!usize {
            const space = self.context.buffer.len - self.context.pos;
            const to_write = @min(bytes.len, space);
            if (to_write == 0 and bytes.len > 0) return error.NoSpaceLeft;

            @memcpy(self.context.buffer[self.context.pos..][0..to_write], bytes[0..to_write]);
            self.context.pos += to_write;
            return to_write;
        }

        pub fn writeAll(self: Writer, bytes: []const u8) error{NoSpaceLeft}!void {
            var written: usize = 0;
            while (written < bytes.len) {
                written += try self.write(bytes[written..]);
            }
        }

        pub fn print(self: Writer, comptime fmt: []const u8, args: anytype) error{NoSpaceLeft}!void {
            const remaining = self.context.buffer[self.context.pos..];
            const result = std.fmt.bufPrint(remaining, fmt, args) catch return error.NoSpaceLeft;
            self.context.pos += result.len;
        }

        pub fn writeByte(self: Writer, byte: u8) error{NoSpaceLeft}!void {
            if (self.context.pos >= self.context.buffer.len) return error.NoSpaceLeft;
            self.context.buffer[self.context.pos] = byte;
            self.context.pos += 1;
        }
    };
};

/// Create a fixed buffer stream from a buffer
pub fn fixedBufferStream(buffer: []u8) FixedBufferStream {
    return FixedBufferStream.init(buffer);
}

/// Get current timestamp in nanoseconds (compatibility for std.time.nanoTimestamp)
pub fn nanoTimestamp() i128 {
    return std.time.Instant.now().timestamp;
}

/// Get current timestamp in milliseconds
pub fn milliTimestamp() i64 {
    const ns = nanoTimestamp();
    return @intCast(@divFloor(ns, 1_000_000));
}
