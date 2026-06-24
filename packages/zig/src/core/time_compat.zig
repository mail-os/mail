const std = @import("std");
const io_compat = @import("io_compat.zig");

/// Get current Unix timestamp in seconds (Zig 0.16 compatible)
pub fn timestamp() i64 {
    var ts: std.c.timespec = undefined;
    const rc = std.c.clock_gettime(.REALTIME, &ts);
    if (rc != 0) return 0;
    return ts.sec;
}

/// Get current Unix timestamp in milliseconds
pub fn milliTimestamp() i64 {
    var ts: std.c.timespec = undefined;
    const rc = std.c.clock_gettime(.REALTIME, &ts);
    if (rc != 0) return 0;
    return ts.sec * 1000 + @divFloor(ts.nsec, std.time.ns_per_ms);
}

/// Get current Unix timestamp in nanoseconds
pub fn nanoTimestamp() i128 {
    var ts: std.c.timespec = undefined;
    const rc = std.c.clock_gettime(.REALTIME, &ts);
    if (rc != 0) return 0;
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
        var list: std.ArrayListUnmanaged(u8) = .empty;
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

/// Format a Unix timestamp as an RFC 5322 date in UTC, e.g.
/// "Tue, 24 Jun 2026 16:30:00 +0000". Caller owns the returned slice.
pub fn formatRfc5322Date(allocator: std.mem.Allocator, ts: i64) ![]const u8 {
    const days = [_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    const es: u64 = @intCast(@max(ts, 0));
    const secs_of_day: u64 = es % 86400;
    const day_num: u64 = es / 86400; // days since 1970-01-01 (Thursday)
    const hour = secs_of_day / 3600;
    const minute = (secs_of_day % 3600) / 60;
    const second = secs_of_day % 60;
    const dow = (day_num + 4) % 7; // 1970-01-01 was Thursday(4)

    // Civil-from-days (Howard Hinnant's algorithm).
    var z: i64 = @intCast(day_num);
    z += 719468;
    const era: i64 = @divFloor(if (z >= 0) z else z - 146096, 146097);
    const doe: u64 = @intCast(z - era * 146097);
    const yoe: u64 = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const y: i64 = @as(i64, @intCast(yoe)) + era * 400;
    const doy: u64 = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const mp: u64 = (5 * doy + 2) / 153;
    const d: u64 = doy - (153 * mp + 2) / 5 + 1;
    const m: u64 = if (mp < 10) mp + 3 else mp - 9;
    const year: i64 = if (m <= 2) y + 1 else y;

    return std.fmt.allocPrint(allocator, "{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} +0000", .{
        days[@intCast(dow)],
        d,
        months[m - 1],
        year,
        hour,
        minute,
        second,
    });
}

test "formatRfc5322Date formats a known epoch" {
    const a = std.testing.allocator;
    // 1700000000 = Tue, 14 Nov 2023 22:13:20 +0000
    const s = try formatRfc5322Date(a, 1700000000);
    defer a.free(s);
    try std.testing.expectEqualStrings("Tue, 14 Nov 2023 22:13:20 +0000", s);
}

test "timestamp returns reasonable value" {
    const ts = timestamp();
    // Should be after year 2020 (timestamp > 1577836800)
    try std.testing.expect(ts > 1577836800);
}
