const std = @import("std");
const io_compat = @import("io_compat.zig");

/// Get current Unix timestamp in seconds (Zig 0.16 compatible)
pub fn timestamp() i64 {
    const ts = std.posix.clock_gettime(.REALTIME) catch return 0;
    return ts.sec;
}

/// Get current Unix timestamp in milliseconds
pub fn milliTimestamp() i64 {
    const ts = std.posix.clock_gettime(.REALTIME) catch return 0;
    return ts.sec * 1000 + @divFloor(ts.nsec, std.time.ns_per_ms);
}

/// Get current Unix timestamp in nanoseconds
pub fn nanoTimestamp() i128 {
    const ts = std.posix.clock_gettime(.REALTIME) catch return 0;
    return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
}

/// Read entire file content into memory (Zig 0.16 compatible)
/// Replaces file.readToEndAlloc() which was removed
pub fn readFileToEnd(allocator: std.mem.Allocator, file: std.Io.File, max_size: usize) ![]u8 {
    const io = io_compat.getIo();
    const file_len = file.length(io) catch 0;
    const size: usize = @intCast(@min(file_len, max_size));
    if (size == 0) {
        // For files with unknown size (like /dev/stdin), read in chunks
        var list = std.ArrayListUnmanaged(u8){};
        errdefer list.deinit(allocator);
        var buf: [4096]u8 = undefined;
        var iov = [_][]u8{buf[0..]};
        while (true) {
            const n = file.readStreaming(io, &iov) catch break;
            if (n == 0) break;
            try list.appendSlice(allocator, buf[0..n]);
            if (list.items.len >= max_size) break;
        }
        return list.toOwnedSlice(allocator);
    }
    const data = try allocator.alloc(u8, size);
    errdefer allocator.free(data);

    const total_read = try file.readPositionalAll(io, data, 0);

    if (total_read != size) {
        allocator.free(data);
        return error.UnexpectedEndOfFile;
    }
    return data;
}

/// Sleep for the specified number of nanoseconds
pub fn sleep(nanoseconds: u64) void {
    const secs = nanoseconds / std.time.ns_per_s;
    const nsecs = nanoseconds % std.time.ns_per_s;
    var ts = std.c.timespec{
        .sec = @intCast(secs),
        .nsec = @intCast(nsecs),
    };
    _ = std.c.nanosleep(&ts, &ts);
}

/// Sleep for the specified number of milliseconds
pub fn sleepMs(milliseconds: u64) void {
    sleep(milliseconds * std.time.ns_per_ms);
}

test "timestamp returns reasonable value" {
    const ts = timestamp();
    // Should be after year 2020 (timestamp > 1577836800)
    try std.testing.expect(ts > 1577836800);
}
