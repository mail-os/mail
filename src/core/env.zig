const std = @import("std");

/// Cross-compatible getenv wrapper for Zig 0.16-dev.
/// Uses libc getenv (available since all targets link libc for sqlite3).
pub fn get(name: [*:0]const u8) ?[:0]const u8 {
    const ptr = std.c.getenv(name) orelse return null;
    return std.mem.sliceTo(ptr, 0);
}

/// Like get(), but returns a duplicate allocated with the given allocator.
/// Caller must free the returned slice.
pub fn getOwned(allocator: std.mem.Allocator, name: [*:0]const u8) error{ EnvironmentVariableNotFound, OutOfMemory }![]u8 {
    const value = get(name) orelse return error.EnvironmentVariableNotFound;
    return try allocator.dupe(u8, value);
}
