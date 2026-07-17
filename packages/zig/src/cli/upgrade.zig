//! `mail upgrade` — gracefully update a mail server installation to the
//! latest release (or canary/prerelease) published on GitHub.
//!
//! Flow: resolve the desired release via the GitHub releases API, download
//! the platform-matching binary asset, back up the current binary, atomically
//! swap it in, and restart the systemd service when one is active.
//!
//! Examples:
//!   mail upgrade                      # latest stable release
//!   mail upgrade --canary             # newest prerelease
//!   mail upgrade --version v0.1.1     # specific tag
//!   mail upgrade --check              # report what would be installed
//!   mail upgrade --path /opt/mail/mail-server --service mail

const std = @import("std");
const cli = @import("zig-cli");
const io_compat = @import("../core/io_compat.zig");
const time_compat = @import("../core/time_compat.zig");
const builtin = @import("builtin");

const DEFAULT_REPO = "mail-os/mail";
const DEFAULT_SERVICE = "mail";

// ============================================================================
// Shell helpers (same pattern as backup.zig / user_remote.zig)
// ============================================================================

const ExecResult = struct {
    stdout: []u8,
    stderr: []u8,
    success: bool,
};

fn execCommand(allocator: std.mem.Allocator, argv: []const []const u8) !ExecResult {
    const result = try std.process.run(allocator, io_compat.getIo(), .{
        .argv = argv,
    });
    const success = switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
    return .{ .stdout = result.stdout, .stderr = result.stderr, .success = success };
}

fn freeExec(allocator: std.mem.Allocator, r: *ExecResult) void {
    allocator.free(r.stdout);
    allocator.free(r.stderr);
}

// ============================================================================
// Release metadata + selection (pure, unit-tested)
// ============================================================================

pub const Asset = struct {
    name: []const u8,
    browser_download_url: []const u8,
};

pub const Release = struct {
    tag_name: []const u8,
    prerelease: bool = false,
    assets: []Asset = &[_]Asset{},
};

/// Ensure a user-supplied version carries the leading "v" used by tags
/// ("0.1.1" -> "v0.1.1"; "v0.1.1" stays as-is).
pub fn normalizeTag(allocator: std.mem.Allocator, version: []const u8) ![]const u8 {
    if (version.len > 0 and version[0] == 'v') return allocator.dupe(u8, version);
    return std.fmt.allocPrint(allocator, "v{s}", .{version});
}

/// Pick the release to install: an explicit --version tag wins; otherwise
/// the newest prerelease (--canary) or the newest stable release. The list is
/// expected newest-first, which is how the GitHub releases API returns it.
pub fn selectRelease(releases: []const Release, version: ?[]const u8, canary: bool) ?usize {
    if (version) |v| {
        for (releases, 0..) |r, i| {
            if (std.mem.eql(u8, r.tag_name, v)) return i;
        }
        return null;
    }
    for (releases, 0..) |r, i| {
        if (r.prerelease == canary) return i;
    }
    return null;
}

/// The release asset name for the platform this binary was built for
/// (e.g. "mail-x86_64-linux.zip").
pub fn assetNameForPlatform(allocator: std.mem.Allocator) !?[]u8 {
    const arch: []const u8 = switch (builtin.cpu.arch) {
        .x86_64 => "x86_64",
        .aarch64 => "aarch64",
        else => return null,
    };
    const os: []const u8 = switch (builtin.os.tag) {
        .linux => "linux",
        .macos => "macos",
        else => return null,
    };
    return try std.fmt.allocPrint(allocator, "mail-{s}-{s}.zip", .{ arch, os });
}

/// Older releases published the x86_64 Linux build as "mail-linux-x64.zip".
fn legacyAssetAlias(allocator: std.mem.Allocator) !?[]u8 {
    if (builtin.cpu.arch == .x86_64 and builtin.os.tag == .linux) {
        return try allocator.dupe(u8, "mail-linux-x64.zip");
    }
    return null;
}

/// Find the downloadable asset for this platform within a release.
pub fn findAsset(allocator: std.mem.Allocator, release: *const Release) !?Asset {
    const wanted = (try assetNameForPlatform(allocator)) orelse return null;
    defer allocator.free(wanted);
    for (release.assets) |a| {
        if (std.mem.eql(u8, a.name, wanted)) return a;
    }
    if (try legacyAssetAlias(allocator)) |alias| {
        defer allocator.free(alias);
        for (release.assets) |a| {
            if (std.mem.eql(u8, a.name, alias)) return a;
        }
    }
    return null;
}

/// Parse the GitHub releases API response into Release records. The caller
/// owns the returned Parsed result and must call .deinit() on it.
pub fn parseReleases(allocator: std.mem.Allocator, json_body: []const u8) !std.json.Parsed([]Release) {
    return std.json.parseFromSlice([]Release, allocator, json_body, .{
        .ignore_unknown_fields = true,
    });
}

// ============================================================================
// Command wiring
// ============================================================================

pub fn setup(allocator: std.mem.Allocator) !*cli.BaseCommand {
    const cmd = try cli.BaseCommand.init(allocator, "upgrade", "Update the mail server to the latest GitHub release");

    _ = try cmd.addOption(
        cli.Option.init("canary", "canary", "Install the newest prerelease instead of stable", .bool),
    );
    _ = try cmd.addOption(
        cli.Option.init("version", "version", "Install a specific release tag (e.g. v0.1.1)", .string),
    );
    _ = try cmd.addOption(
        cli.Option.init("path", "path", "Path of the installed binary to replace", .string),
    );
    _ = try cmd.addOption(
        cli.Option.init("service", "service", "systemd service to restart (default: mail)", .string),
    );
    _ = try cmd.addOption(
        cli.Option.init("no-restart", "no-restart", "Do not restart the service after installing", .bool),
    );
    _ = try cmd.addOption(
        cli.Option.init("repo", "repo", "GitHub repo to pull releases from (default: mail-os/mail)", .string),
    );
    _ = try cmd.addOption(
        cli.Option.init("check", "check", "Only report what would be installed", .bool),
    );

    _ = cmd.setAction(upgradeAction);
    return cmd;
}

fn upgradeAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const allocator = ctx.allocator;

    const repo = ctx.getOption("repo") orelse DEFAULT_REPO;
    const service = ctx.getOption("service") orelse DEFAULT_SERVICE;
    const canary = ctx.hasOption("canary");
    const check_only = ctx.hasOption("check");
    const no_restart = ctx.hasOption("no-restart");

    // Resolve an explicit --version to the canonical tag spelling.
    var wanted_tag: ?[]const u8 = null;
    if (ctx.getOption("version")) |v| {
        wanted_tag = try normalizeTag(allocator, v);
    }
    defer if (wanted_tag) |t| allocator.free(t);

    // ------------------------------------------------------------------
    // 1. Fetch the releases list from GitHub
    // ------------------------------------------------------------------
    const api_url = try std.fmt.allocPrint(
        allocator,
        "https://api.github.com/repos/{s}/releases?per_page=20",
        .{repo},
    );
    defer allocator.free(api_url);

    std.debug.print("Checking {s} releases...\n", .{repo});
    var api_result = try execCommand(allocator, &[_][]const u8{
        "curl", "-fsSL", "--retry", "3", "-H", "Accept: application/vnd.github+json", "-H", "User-Agent: mail-cli", api_url,
    });
    defer freeExec(allocator, &api_result);
    if (!api_result.success) {
        std.debug.print("Failed to query GitHub releases: {s}\n", .{api_result.stderr});
        return error.ReleaseLookupFailed;
    }

    const parsed_releases = try parseReleases(allocator, api_result.stdout);
    defer parsed_releases.deinit();
    const releases = parsed_releases.value;
    if (releases.len == 0) {
        std.debug.print("No releases found for {s}.\n", .{repo});
        return error.NoReleaseFound;
    }

    const idx = selectRelease(releases, wanted_tag, canary) orelse {
        if (wanted_tag) |t| {
            std.debug.print("Release {s} not found in {s}.\n", .{ t, repo });
        } else if (canary) {
            std.debug.print("No canary/prerelease found for {s} (latest stable: {s}).\n", .{ repo, releases[0].tag_name });
        } else {
            std.debug.print("No stable release found for {s}.\n", .{repo});
        }
        return error.NoReleaseFound;
    };
    const release = &releases[idx];

    const channel: []const u8 = if (wanted_tag != null) "pinned" else if (canary) "canary" else "stable";
    const asset = (try findAsset(allocator, release)) orelse {
        std.debug.print("Release {s} has no binary for this platform.\n", .{release.tag_name});
        return error.NoMatchingAsset;
    };

    std.debug.print("Resolved {s} ({s}) -> {s}\n", .{ release.tag_name, channel, asset.name });
    if (check_only) {
        std.debug.print("{s}\n", .{asset.browser_download_url});
        return;
    }

    // ------------------------------------------------------------------
    // 2. Resolve the install target
    // ------------------------------------------------------------------
    const target = ctx.getOption("path") orelse detectInstallPath() orelse {
        std.debug.print("Could not locate the installed binary. Pass --path explicitly.\n", .{});
        return error.MissingInstallPath;
    };

    // ------------------------------------------------------------------
    // 3. Download + extract into a temp workspace
    // ------------------------------------------------------------------
    const tmp_dir = try std.fmt.allocPrint(allocator, "/tmp/mail-upgrade-{d}", .{time_compat.milliTimestamp()});
    defer allocator.free(tmp_dir);
    var mkdir_result = try execCommand(allocator, &[_][]const u8{ "mkdir", "-p", tmp_dir });
    defer freeExec(allocator, &mkdir_result);
    if (!mkdir_result.success) return error.TempDirFailed;
    defer {
        if (execCommand(allocator, &[_][]const u8{ "rm", "-rf", tmp_dir })) |rm_result| {
            var r = rm_result;
            freeExec(allocator, &r);
        } else |_| {}
    }

    const zip_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ tmp_dir, asset.name });
    defer allocator.free(zip_path);

    std.debug.print("Downloading {s}...\n", .{asset.browser_download_url});
    var dl_result = try execCommand(allocator, &[_][]const u8{
        "curl", "-fSL", "--retry", "3", "-o", zip_path, asset.browser_download_url,
    });
    defer freeExec(allocator, &dl_result);
    if (!dl_result.success) {
        std.debug.print("Download failed: {s}\n", .{dl_result.stderr});
        return error.DownloadFailed;
    }

    const extract_dir = try std.fmt.allocPrint(allocator, "{s}/x", .{tmp_dir});
    defer allocator.free(extract_dir);
    if (!try extractZip(allocator, zip_path, extract_dir)) {
        std.debug.print("Failed to extract {s} (need unzip or python3).\n", .{asset.name});
        return error.ExtractFailed;
    }

    // The archive ships a single file named after the asset minus ".zip".
    const binary_name = asset.name[0 .. asset.name.len - ".zip".len];
    const extracted = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ extract_dir, binary_name });
    defer allocator.free(extracted);

    var chmod_result = try execCommand(allocator, &[_][]const u8{ "chmod", "+x", extracted });
    defer freeExec(allocator, &chmod_result);
    if (!chmod_result.success) {
        std.debug.print("Extracted binary not found at {s}.\n", .{extracted});
        return error.ExtractFailed;
    }

    // ------------------------------------------------------------------
    // 4. Back up + atomically swap the binary
    // ------------------------------------------------------------------
    const backup_path = try std.fmt.allocPrint(allocator, "{s}.bak", .{target});
    defer allocator.free(backup_path);
    const staged_path = try std.fmt.allocPrint(allocator, "{s}.new", .{target});
    defer allocator.free(staged_path);

    var had_existing = false;
    {
        var stat_result = try execCommand(allocator, &[_][]const u8{ "test", "-f", target });
        defer freeExec(allocator, &stat_result);
        had_existing = stat_result.success;
    }
    if (had_existing) {
        var cp_result = try execCommand(allocator, &[_][]const u8{ "cp", "-p", target, backup_path });
        defer freeExec(allocator, &cp_result);
        if (!cp_result.success) {
            std.debug.print("Failed to back up {s}: {s}\n", .{ target, cp_result.stderr });
            return error.BackupFailed;
        }
    }

    // Stage next to the target so the final mv is an atomic same-fs rename;
    // replacing a running binary this way is safe on Linux (inode swap).
    var stage_result = try execCommand(allocator, &[_][]const u8{ "cp", extracted, staged_path });
    defer freeExec(allocator, &stage_result);
    if (!stage_result.success) {
        std.debug.print("Failed to stage new binary: {s}\n", .{stage_result.stderr});
        return error.InstallFailed;
    }
    var chmod2_result = try execCommand(allocator, &[_][]const u8{ "chmod", "755", staged_path });
    defer freeExec(allocator, &chmod2_result);

    var mv_result = try execCommand(allocator, &[_][]const u8{ "mv", "-f", staged_path, target });
    defer freeExec(allocator, &mv_result);
    if (!mv_result.success) {
        std.debug.print("Failed to install {s}: {s}\n", .{ target, mv_result.stderr });
        return error.InstallFailed;
    }

    // Best-effort: keep the original ownership when upgrading as root.
    if (had_existing) {
        var own_result = execCommand(allocator, &[_][]const u8{ "chown", "--reference", backup_path, target }) catch null;
        if (own_result) |*r| freeExec(allocator, r);
    }

    std.debug.print("Installed {s} -> {s}\n", .{ release.tag_name, target });
    if (had_existing) std.debug.print("Previous binary backed up to {s}\n", .{backup_path});

    // ------------------------------------------------------------------
    // 5. Restart the service when one is active
    // ------------------------------------------------------------------
    if (no_restart) {
        std.debug.print("Skipping service restart (--no-restart).\n", .{});
        return;
    }
    restartService(allocator, service);
}

fn restartService(allocator: std.mem.Allocator, service: []const u8) void {
    // Probe systemctl by invoking it directly: `command -v` is a shell
    // builtin and cannot be exec'd without a shell. A spawn failure here
    // means systemctl is absent (e.g. macOS or a minimal container).
    var active_result = execCommand(allocator, &[_][]const u8{ "systemctl", "is-active", "--quiet", service }) catch {
        std.debug.print("systemctl not available; restart the service manually.\n", .{});
        return;
    };
    const is_active = active_result.success;
    freeExec(allocator, &active_result);
    if (!is_active) {
        std.debug.print("Service {s} is not active; nothing to restart.\n", .{service});
        return;
    }

    var restart_result = execCommand(allocator, &[_][]const u8{ "systemctl", "restart", service }) catch {
        std.debug.print("Failed to restart {s}; please restart it manually.\n", .{service});
        return;
    };
    const ok = restart_result.success;
    const stderr_dupe = allocator.dupe(u8, restart_result.stderr) catch "";
    freeExec(allocator, &restart_result);
    defer if (stderr_dupe.len > 0) allocator.free(stderr_dupe);
    if (!ok) {
        std.debug.print("Failed to restart {s}: {s}\n", .{ service, stderr_dupe });
        return;
    }
    std.debug.print("Service {s} restarted.\n", .{service});
}

/// Default install locations, first existing one wins. MAIL_SERVER_PATH
/// overrides the search.
fn detectInstallPath() ?[]const u8 {
    if (std.c.getenv("MAIL_SERVER_PATH")) |p| {
        const path = std.mem.sliceTo(p, 0);
        if (path.len > 0) return path;
    }
    const candidates = [_][]const u8{
        "/opt/mail/mail-server",
        "/usr/local/bin/mail-server",
        "/usr/local/bin/mail",
    };
    for (candidates) |c| {
        std.Io.Dir.accessAbsolute(io_compat.getIo(), c, .{}) catch continue;
        return c;
    }
    return null;
}

/// Extract a zip archive using whatever the host offers: unzip first,
/// then python3's zipfile module (present on Amazon Linux and macOS).
fn extractZip(allocator: std.mem.Allocator, zip_path: []const u8, dest_dir: []const u8) !bool {
    var mkdir_result = try execCommand(allocator, &[_][]const u8{ "mkdir", "-p", dest_dir });
    defer freeExec(allocator, &mkdir_result);
    if (!mkdir_result.success) return false;

    var unzip_result = execCommand(allocator, &[_][]const u8{ "unzip", "-o", "-q", zip_path, "-d", dest_dir }) catch {
        return try extractZipPython(allocator, zip_path, dest_dir);
    };
    const ok = unzip_result.success;
    freeExec(allocator, &unzip_result);
    if (ok) return true;
    return try extractZipPython(allocator, zip_path, dest_dir);
}

fn extractZipPython(allocator: std.mem.Allocator, zip_path: []const u8, dest_dir: []const u8) !bool {
    var py_result = execCommand(allocator, &[_][]const u8{ "python3", "-m", "zipfile", "-e", zip_path, dest_dir }) catch {
        return false;
    };
    defer freeExec(allocator, &py_result);
    return py_result.success;
}

// ============================================================================
// Tests
// ============================================================================

test "normalizeTag adds the leading v" {
    const testing = std.testing;
    const a = try normalizeTag(testing.allocator, "0.1.1");
    defer testing.allocator.free(a);
    try testing.expectEqualStrings("v0.1.1", a);

    const b = try normalizeTag(testing.allocator, "v0.1.2");
    defer testing.allocator.free(b);
    try testing.expectEqualStrings("v0.1.2", b);
}

test "selectRelease honors version, canary and stable channels" {
    const testing = std.testing;
    const releases = [_]Release{
        .{ .tag_name = "v0.2.0-canary.1", .prerelease = true },
        .{ .tag_name = "v0.1.1", .prerelease = false },
        .{ .tag_name = "v0.1.0", .prerelease = false },
    };

    try testing.expectEqual(@as(?usize, 1), selectRelease(&releases, null, false));
    try testing.expectEqual(@as(?usize, 0), selectRelease(&releases, null, true));
    try testing.expectEqual(@as(?usize, 2), selectRelease(&releases, "v0.1.0", false));
    try testing.expectEqual(@as(?usize, null), selectRelease(&releases, "v9.9.9", false));
}

test "parseReleases reads GitHub API payloads" {
    const testing = std.testing;
    const body =
        \\[{"tag_name":"v0.1.1","prerelease":false,"draft":false,
        \\  "assets":[{"name":"mail-x86_64-linux.zip","browser_download_url":"https://example.com/a.zip","size":1}]},
        \\ {"tag_name":"v0.1.0","prerelease":true,"assets":[]}]
    ;
    const parsed = try parseReleases(testing.allocator, body);
    defer parsed.deinit();
    const releases = parsed.value;
    try testing.expectEqual(@as(usize, 2), releases.len);
    try testing.expectEqualStrings("v0.1.1", releases[0].tag_name);
    try testing.expect(!releases[0].prerelease);
    try testing.expect(releases[1].prerelease);
    try testing.expectEqual(@as(usize, 1), releases[0].assets.len);
    try testing.expectEqualStrings("mail-x86_64-linux.zip", releases[0].assets[0].name);
}

test "findAsset matches the platform asset" {
    const testing = std.testing;
    const release = Release{
        .tag_name = "v0.1.1",
        .assets = @constCast(&[_]Asset{
            .{ .name = "mail-aarch64-macos.zip", .browser_download_url = "https://example.com/mac.zip" },
            .{ .name = "mail-x86_64-linux.zip", .browser_download_url = "https://example.com/linux.zip" },
        }),
    };
    const found = (try findAsset(testing.allocator, &release)) orelse return error.TestUnexpectedResult;
    const wanted = (try assetNameForPlatform(testing.allocator)).?;
    defer testing.allocator.free(wanted);
    try testing.expectEqualStrings(wanted, found.name);
}
