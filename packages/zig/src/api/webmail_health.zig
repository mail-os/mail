//! Read only the root-owned, sanitized health artifact, never logs or secrets.
const std = @import("std");
const fs = @import("../core/fs_compat.zig");

pub fn response(allocator: std.mem.Allocator, now: i64) ![]const u8 {
    const file = fs.cwd().openFile("/var/lib/mail-health/public/status.json", .{}) catch
        return allocator.dupe(u8, "{\"available\":false,\"stale\":true}");
    defer file.close();
    const buffer = try allocator.alloc(u8, 128 * 1024 + 1);
    defer allocator.free(buffer);
    const size = try file.readAll(buffer);
    if (size > 128 * 1024) return allocator.dupe(u8, "{\"available\":false,\"stale\":true}");
    return envelope(allocator, buffer[0..size], now);
}

fn envelope(allocator: std.mem.Allocator, raw: []const u8, now: i64) ![]const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch
        return allocator.dupe(u8, "{\"available\":false,\"stale\":true}");
    defer parsed.deinit();
    if (parsed.value != .object) return allocator.dupe(u8, "{\"available\":false,\"stale\":true}");
    const checked = parsed.value.object.get("checked_at") orelse return allocator.dupe(u8, "{\"available\":false,\"stale\":true}");
    if (checked != .integer) return allocator.dupe(u8, "{\"available\":false,\"stale\":true}");
    const stale = checked.integer <= 0 or checked.integer > now + 30 or now - checked.integer > 180;
    return std.fmt.allocPrint(allocator, "{{\"available\":true,\"stale\":{s},\"report\":{s}}}", .{ if (stale) "true" else "false", raw });
}

test "health ages out, rejects future and malformed snapshots" {
    const allocator = std.testing.allocator;
    const fresh = try envelope(allocator, "{\"checked_at\":1000,\"status\":\"healthy\"}", 1100);
    defer allocator.free(fresh);
    try std.testing.expect(std.mem.indexOf(u8, fresh, "\"stale\":false") != null);
    for ([_][]const u8{ "{\"checked_at\":1000}", "{\"checked_at\":9999}", "[]", "{", "{}", "{\"checked_at\":\"1000\"}" }) |raw| {
        const result = try envelope(allocator, raw, 1300);
        defer allocator.free(result);
        try std.testing.expect(std.mem.indexOf(u8, result, "\"stale\":true") != null);
    }
}

/// Public health returns no operational details or mailbox data.
pub fn isHealthy(allocator: std.mem.Allocator, raw: []const u8) bool {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch return false;
    defer parsed.deinit();
    if (parsed.value != .object) return false;
    const stale = parsed.value.object.get("stale") orelse return false;
    if (stale != .bool or stale.bool) return false;
    const report = parsed.value.object.get("report") orelse return false;
    if (report != .object) return false;
    const status = report.object.get("status") orelse return false;
    return status == .string and std.mem.eql(u8, status.string, "healthy");
}

test "public health fails closed for stale, missing and degraded monitoring" {
    const allocator = std.testing.allocator;
    try std.testing.expect(isHealthy(allocator, "{\"stale\":false,\"report\":{\"status\":\"healthy\"}}"));
    for ([_][]const u8{ "{}", "[]", "{\"stale\":true,\"report\":{\"status\":\"healthy\"}}", "{\"stale\":false,\"report\":{\"status\":\"degraded\"}}" }) |raw| {
        try std.testing.expect(!isHealthy(allocator, raw));
    }
}

/// A read-only monitoring credential, deliberately independent of mailbox logins.
pub fn authorized(provided: ?[]const u8) bool {
    const file = fs.cwd().openFile("/var/lib/mail-health/public/read-token", .{}) catch return false;
    defer file.close();
    var token: [65]u8 = undefined;
    const size = file.readAll(&token) catch return false;
    if (size != 64) return false;
    return tokensEqual(token[0..64], provided);
}

fn tokensEqual(expected: []const u8, provided: ?[]const u8) bool {
    const value = provided orelse return false;
    if (expected.len != 64 or value.len != 64) return false;
    return std.crypto.timing_safe.eql([64]u8, expected[0..64].*, value[0..64].*);
}

test "monitoring token is exact and fails closed" {
    const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    try std.testing.expect(tokensEqual(token, token));
    for ([_]?[]const u8{ null, "", token ++ "x", "1123456789abcdef1123456789abcdef1123456789abcdef1123456789abcdef" }) |value| {
        try std.testing.expect(!tokensEqual(token, value));
    }
}
