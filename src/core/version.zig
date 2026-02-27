const std = @import("std");

/// Central version management for the mail server
/// This is the single source of truth for version information
/// When bumping versions, update this file AND build.zig.zon
/// Semantic version components
pub const version_major: u32 = 0;
pub const version_minor: u32 = 37;
pub const version_patch: u32 = 0;

/// Full version string (matches build.zig.zon)
pub const version = "0.37.0";

/// Version with 'v' prefix for display
pub const version_display = "v0.37.0";

/// Application name
pub const app_name = "SMTP Server";

/// Full application banner
pub const banner = app_name ++ " " ++ version_display;

/// Build information
pub const BuildInfo = struct {
    version: []const u8 = version,
    version_major: u32 = version_major,
    version_minor: u32 = version_minor,
    version_patch: u32 = version_patch,
    zig_version: []const u8 = @import("builtin").zig_version_string,
    build_mode: []const u8 = @tagName(@import("builtin").mode),
    target: []const u8 = @tagName(@import("builtin").cpu.arch) ++ "-" ++ @tagName(@import("builtin").os.tag),
};

/// Get build information
pub fn getBuildInfo() BuildInfo {
    return .{};
}

/// Version comparison result
pub const VersionComparison = enum {
    less_than,
    equal,
    greater_than,
};

/// Parse a version string into components
pub fn parseVersion(ver_string: []const u8) ?struct { major: u32, minor: u32, patch: u32 } {
    var parts: [3]u32 = .{ 0, 0, 0 };
    var part_idx: usize = 0;
    var start: usize = 0;

    // Skip leading 'v' if present
    const str = if (ver_string.len > 0 and ver_string[0] == 'v') ver_string[1..] else ver_string;

    for (str, 0..) |c, i| {
        if (c == '.') {
            if (part_idx >= 2) return null;
            parts[part_idx] = std.fmt.parseInt(u32, str[start..i], 10) catch return null;
            part_idx += 1;
            start = i + 1;
        }
    }

    // Parse last part
    if (start < str.len) {
        parts[part_idx] = std.fmt.parseInt(u32, str[start..], 10) catch return null;
    }

    return .{ .major = parts[0], .minor = parts[1], .patch = parts[2] };
}

/// Compare two version strings
pub fn compareVersions(a: []const u8, b: []const u8) ?VersionComparison {
    const ver_a = parseVersion(a) orelse return null;
    const ver_b = parseVersion(b) orelse return null;

    // Compare major
    if (ver_a.major < ver_b.major) return .less_than;
    if (ver_a.major > ver_b.major) return .greater_than;

    // Compare minor
    if (ver_a.minor < ver_b.minor) return .less_than;
    if (ver_a.minor > ver_b.minor) return .greater_than;

    // Compare patch
    if (ver_a.patch < ver_b.patch) return .less_than;
    if (ver_a.patch > ver_b.patch) return .greater_than;

    return .equal;
}

/// Check if a version is compatible (same major, >= minor.patch)
pub fn isCompatible(required: []const u8, current: []const u8) bool {
    const req = parseVersion(required) orelse return false;
    const cur = parseVersion(current) orelse return false;

    // Major version must match
    if (req.major != cur.major) return false;

    // Current must be >= required
    if (cur.minor > req.minor) return true;
    if (cur.minor < req.minor) return false;

    return cur.patch >= req.patch;
}

/// Check if current version meets minimum requirement
pub fn meetsMinimum(minimum: []const u8) bool {
    return switch (compareVersions(version, minimum) orelse return false) {
        .greater_than, .equal => true,
        .less_than => false,
    };
}

/// Check if current version is below maximum requirement
pub fn belowMaximum(maximum: []const u8) bool {
    return switch (compareVersions(version, maximum) orelse return false) {
        .less_than, .equal => true,
        .greater_than => false,
    };
}

/// Format version info for display
pub fn formatVersionInfo(allocator: std.mem.Allocator) ![]u8 {
    const info = getBuildInfo();
    return std.fmt.allocPrint(allocator,
        \\{s}
        \\  Version: {s}
        \\  Zig: {s}
        \\  Build: {s}
        \\  Target: {s}
    , .{
        banner,
        info.version,
        info.zig_version,
        info.build_mode,
        info.target,
    });
}

/// JSON representation of version info
pub fn toJson(allocator: std.mem.Allocator) ![]u8 {
    const info = getBuildInfo();
    return std.fmt.allocPrint(allocator,
        \\{{
        \\  "name": "{s}",
        \\  "version": "{s}",
        \\  "version_major": {d},
        \\  "version_minor": {d},
        \\  "version_patch": {d},
        \\  "zig_version": "{s}",
        \\  "build_mode": "{s}",
        \\  "target": "{s}"
        \\}}
    , .{
        app_name,
        info.version,
        info.version_major,
        info.version_minor,
        info.version_patch,
        info.zig_version,
        info.build_mode,
        info.target,
    });
}

// Tests
test "parseVersion" {
    const v1 = parseVersion("1.2.3").?;
    try std.testing.expectEqual(@as(u32, 1), v1.major);
    try std.testing.expectEqual(@as(u32, 2), v1.minor);
    try std.testing.expectEqual(@as(u32, 3), v1.patch);

    const v2 = parseVersion("v0.28.0").?;
    try std.testing.expectEqual(@as(u32, 0), v2.major);
    try std.testing.expectEqual(@as(u32, 28), v2.minor);
    try std.testing.expectEqual(@as(u32, 0), v2.patch);

    try std.testing.expect(parseVersion("invalid") == null);
}

test "compareVersions" {
    try std.testing.expectEqual(VersionComparison.equal, compareVersions("1.0.0", "1.0.0").?);
    try std.testing.expectEqual(VersionComparison.less_than, compareVersions("1.0.0", "2.0.0").?);
    try std.testing.expectEqual(VersionComparison.greater_than, compareVersions("2.0.0", "1.0.0").?);
    try std.testing.expectEqual(VersionComparison.less_than, compareVersions("1.0.0", "1.1.0").?);
    try std.testing.expectEqual(VersionComparison.greater_than, compareVersions("1.2.0", "1.1.0").?);
}

test "isCompatible" {
    try std.testing.expect(isCompatible("0.28.0", "0.28.0"));
    try std.testing.expect(isCompatible("0.28.0", "0.29.0"));
    try std.testing.expect(!isCompatible("0.28.0", "0.27.0"));
    try std.testing.expect(!isCompatible("0.28.0", "1.0.0"));
}

test "meetsMinimum" {
    try std.testing.expect(meetsMinimum("0.1.0"));
    try std.testing.expect(meetsMinimum("0.28.0"));
    try std.testing.expect(!meetsMinimum("1.0.0"));
}
