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

pub const HealthScope = enum { availability, monitoring };

pub fn isHealthy(allocator: std.mem.Allocator, raw: []const u8, scope: HealthScope) bool {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch return false;
    defer parsed.deinit();
    if (parsed.value != .object) return false;
    const stale = parsed.value.object.get("stale") orelse return false;
    if (stale != .bool or stale.bool) return false;
    const report = parsed.value.object.get("report") orelse return false;
    if (report != .object) return false;
    const status = report.object.get("status") orelse return false;
    if (status != .string) return false;
    if (std.mem.eql(u8, status.string, "healthy")) return true;
    return scope == .availability and std.mem.eql(u8, status.string, "degraded") and
        hasOnlyIsolatedTlsError(report.object.get("checks"));
}

fn hasOnlyIsolatedTlsError(checks: ?std.json.Value) bool {
    const list = checks orelse return false;
    if (list != .array or list.array.items.len < 2) return false;
    var found = false;
    for (list.array.items) |check| {
        if (check != .object) return false;
        const ok = check.object.get("ok") orelse return false;
        if (ok != .bool) return false;
        if (ok.bool) continue;

        const name = check.object.get("name") orelse return false;
        const count = check.object.get("count") orelse return false;
        if (found or name != .string or !std.mem.eql(u8, name.string, "TLS receive errors") or
            count != .integer or count.integer != 1) return false;
        found = true;
    }
    return found;
}

test "public health fails closed for stale, missing and degraded monitoring" {
    const allocator = std.testing.allocator;
    try std.testing.expect(isHealthy(allocator, "{\"stale\":false,\"report\":{\"status\":\"healthy\"}}", .availability));
    for ([_][]const u8{ "{}", "[]", "{\"stale\":true,\"report\":{\"status\":\"healthy\"}}", "{\"stale\":false,\"report\":{\"status\":\"degraded\"}}" }) |raw| {
        try std.testing.expect(!isHealthy(allocator, raw, .availability));
    }
}

test "only public availability tolerates an isolated TLS error with passing checks" {
    const allocator = std.testing.allocator;
    const prefix = "{\"stale\":false,\"report\":{\"status\":\"degraded\",\"checks\":[";
    const passing = "{\"name\":\"IMAPS greeting and CAPABILITY\",\"ok\":true},";
    const tls_one = "{\"name\":\"TLS receive errors\",\"ok\":false,\"count\":1}";
    const suffix = "]}}";
    const isolated = prefix ++ passing ++ tls_one ++ suffix;

    try std.testing.expect(isHealthy(allocator, isolated, .availability));
    try std.testing.expect(!isHealthy(allocator, isolated, .monitoring));
    for ([_][]const u8{
        prefix ++ passing ++ "{\"name\":\"TLS receive errors\",\"ok\":false,\"count\":2}" ++ suffix,
        prefix ++ passing ++ "{\"name\":\"TLS receive errors\",\"ok\":false}" ++ suffix,
        prefix ++ "{\"name\":\"IMAPS greeting and CAPABILITY\",\"ok\":false}," ++ tls_one ++ suffix,
        prefix ++ "{\"name\":\"Mail storage write and sync\",\"ok\":false}," ++ tls_one ++ suffix,
        prefix ++ tls_one ++ suffix,
        prefix ++ "null," ++ tls_one ++ suffix,
        prefix ++ tls_one ++ "," ++ tls_one ++ suffix,
        "{\"stale\":true,\"report\":{\"status\":\"degraded\",\"checks\":[" ++ tls_one ++ suffix,
    }) |raw| {
        try std.testing.expect(!isHealthy(allocator, raw, .availability));
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
