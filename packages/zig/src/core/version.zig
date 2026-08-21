const std = @import("std");
const build_options = @import("build-options");

/// Central version management for the mail server.
///
/// The version is NOT written here: it is threaded in from `build.zig.zon` via
/// the `build-options` module, so there is exactly one place a release number
/// lives and a binary can never misreport which release produced it. (This
/// file previously hardcoded its own copy and had drifted to "0.37.0" against
/// a real version of 0.3.x — the drift `mail upgrade` now depends on not
/// happening, since it compares the compiled-in version against the release
/// tag to decide whether an unattended update has anything to do.)
/// Full version string, e.g. "0.3.3".
pub const version: []const u8 = build_options.version;

/// Version with 'v' prefix for display.
pub const version_display = "v" ++ version;

/// Semantic version components, parsed from `version` at comptime.
const parsed_self = parseVersion(version) orelse
    @compileError("build.zig.zon .version is not a parsable semver: " ++ version);
pub const version_major: u32 = parsed_self.major;
pub const version_minor: u32 = parsed_self.minor;
pub const version_patch: u32 = parsed_self.patch;

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

/// True when two version spellings name the same release, tolerating the
/// leading "v" of a git tag ("0.3.3" == "v0.3.3"). Compared as strings rather
/// than parsed components so a prerelease ("v0.4.0-canary.1") is distinct from
/// its stable counterpart — `mail upgrade` uses this to decide whether an
/// unattended run can skip the download *and the service restart*.
pub fn isSameRelease(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, stripTagPrefix(a), stripTagPrefix(b));
}

fn stripTagPrefix(s: []const u8) []const u8 {
    const t = std.mem.trim(u8, s, " \t\r\n");
    if (t.len > 0 and (t[0] == 'v' or t[0] == 'V')) return t[1..];
    return t;
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

test "meetsMinimum compares against the compiled-in version" {
    // Phrased relative to `version` rather than a literal: the build's version
    // comes from build.zig.zon and changes with every release.
    try std.testing.expect(meetsMinimum("0.0.0"));
    try std.testing.expect(meetsMinimum(version));
    try std.testing.expect(!meetsMinimum("999.0.0"));
}

test "the compiled-in version is the one build.zig.zon declares" {
    try std.testing.expect(parseVersion(version) != null);
    try std.testing.expectEqual(version_major, parseVersion(version).?.major);
    try std.testing.expectEqual(version_minor, parseVersion(version).?.minor);
    try std.testing.expectEqual(version_patch, parseVersion(version).?.patch);
    try std.testing.expectEqualStrings("v" ++ version, version_display);
}

test "isSameRelease tolerates the tag prefix but not a prerelease" {
    try std.testing.expect(isSameRelease("0.3.3", "v0.3.3"));
    try std.testing.expect(isSameRelease("v0.3.3", "0.3.3"));
    try std.testing.expect(!isSameRelease("0.3.3", "v0.3.4"));
    try std.testing.expect(!isSameRelease("0.3.3", "v0.3.3-canary.1"));
}

test "compareVersions tolerates a tag prefix on either side" {
    // The upgrade command's downgrade guard compares the compiled-in version
    // (bare) against a GitHub tag ("v0.3.2"), so the prefix must not matter.
    try std.testing.expectEqual(VersionComparison.greater_than, compareVersions("0.3.3", "v0.3.2").?);
    try std.testing.expectEqual(VersionComparison.less_than, compareVersions("0.3.3", "v0.4.0").?);
    try std.testing.expectEqual(VersionComparison.equal, compareVersions("0.3.3", "v0.3.3").?);
}

test "a prerelease tag does not compare as a plain version" {
    // parseVersion cannot read "0.4.0-canary.1", so the guard sees null and
    // falls through rather than mistaking a canary for a downgrade.
    try std.testing.expect(compareVersions("0.3.3", "v0.4.0-canary.1") == null);
}
