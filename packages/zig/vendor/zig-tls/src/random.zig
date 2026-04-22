/// Cross-platform CSPRNG that works on macOS, Linux, and other targets.
const std = @import("std");
const builtin = @import("builtin");

/// Fill buffer with cryptographically secure random bytes.
pub fn fill(buf: []u8) void {
    switch (builtin.os.tag) {
        .macos, .ios, .freebsd, .netbsd, .openbsd => {
            std.c.arc4random_buf(buf.ptr, buf.len);
        },
        .linux => {
            // Use getrandom syscall directly (always available via kernel >= 3.17)
            const rc = std.os.linux.getrandom(buf.ptr, buf.len, 0);
            // Check for error: on Linux syscalls, error is indicated by
            // return value > max_usize - 4096 (i.e., negative errno)
            if (rc > std.math.maxInt(usize) - 4096) {
                // Fallback: read from /dev/urandom
                urandomFill(buf);
            }
        },
        else => {
            // Fallback for other platforms
            urandomFill(buf);
        },
    }
}

fn urandomFill(buf: []u8) void {
    const fd = std.posix.openat(std.posix.AT.FDCWD, "/dev/urandom", .{ .ACCMODE = .RDONLY }, 0) catch return;
    defer _ = std.c.close(fd);
    var pos: usize = 0;
    while (pos < buf.len) {
        const n = std.posix.read(fd, buf[pos..]) catch return;
        if (n == 0) return;
        pos += n;
    }
}

/// std.Random interface backed by this CSPRNG
pub const csprng: std.Random = .{
    .ptr = undefined,
    .fillFn = struct {
        fn f(_: *anyopaque, b: []u8) void {
            fill(b);
        }
    }.f,
};
