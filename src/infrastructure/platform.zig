const std = @import("std");
const builtin = @import("builtin");
const env = @import("../core/env.zig");

/// Platform abstraction layer for cross-platform support
/// Provides unified interface for platform-specific operations
///
/// Supported platforms:
/// - Linux (x86_64, ARM64)
/// - Windows (x86_64, ARM64)
/// - macOS (x86_64, ARM64)
/// - FreeBSD (x86_64, ARM64)
/// - OpenBSD (x86_64, ARM64)
///
/// Features:
/// - File path handling
/// - Service/daemon management
/// - Signal handling
/// - Process management
/// - Network operations
/// - File permissions
pub const Platform = enum {
    linux,
    windows,
    macos,
    freebsd,
    openbsd,
    unknown,

    pub fn current() Platform {
        return switch (builtin.os.tag) {
            .linux => .linux,
            .windows => .windows,
            .macos => .macos,
            .freebsd => .freebsd,
            .openbsd => .openbsd,
            else => .unknown,
        };
    }

    pub fn isUnix(self: Platform) bool {
        return switch (self) {
            .linux, .macos, .freebsd, .openbsd => true,
            .windows, .unknown => false,
        };
    }

    pub fn isWindows(self: Platform) bool {
        return self == .windows;
    }

    pub fn isBSD(self: Platform) bool {
        return switch (self) {
            .freebsd, .openbsd => true,
            else => false,
        };
    }
};

pub const Architecture = enum {
    x86_64,
    aarch64,
    arm,
    riscv64,
    unknown,

    pub fn current() Architecture {
        return switch (builtin.cpu.arch) {
            .x86_64 => .x86_64,
            .aarch64 => .aarch64,
            .arm => .arm,
            .riscv64 => .riscv64,
            else => .unknown,
        };
    }

    pub fn isARM(self: Architecture) bool {
        return switch (self) {
            .aarch64, .arm => true,
            else => false,
        };
    }
};

/// Path utilities with platform-specific handling
pub const Path = struct {
    /// Get path separator for current platform
    pub fn separator() []const u8 {
        return switch (Platform.current()) {
            .windows => "\\",
            else => "/",
        };
    }

    /// Get path list separator
    pub fn listSeparator() u8 {
        return switch (Platform.current()) {
            .windows => ';',
            else => ':',
        };
    }

    /// Join path components
    pub fn join(allocator: std.mem.Allocator, parts: []const []const u8) ![]const u8 {
        return std.fs.path.join(allocator, parts);
    }

    /// Convert path to platform format
    pub fn normalize(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
        if (Platform.current() == .windows) {
            // Convert forward slashes to backslashes
            var normalized = try allocator.dupe(u8, path);
            for (normalized) |*char| {
                if (char.* == '/') char.* = '\\';
            }
            return normalized;
        }
        return allocator.dupe(u8, path);
    }

    /// Get home directory
    pub fn homeDir(allocator: std.mem.Allocator) ![]const u8 {
        if (Platform.current() == .windows) {
            // Windows: USERPROFILE or HOMEDRIVE+HOMEPATH
            return env.getOwned(allocator, "USERPROFILE") catch {
                const drive = try env.getOwned(allocator, "HOMEDRIVE");
                defer allocator.free(drive);
                const path = try env.getOwned(allocator, "HOMEPATH");
                defer allocator.free(path);
                return try std.fmt.allocPrint(allocator, "{s}{s}", .{ drive, path });
            };
        } else {
            // Unix: HOME
            return env.getOwned(allocator, "HOME");
        }
    }

    /// Get temp directory
    pub fn tempDir(allocator: std.mem.Allocator) ![]const u8 {
        if (Platform.current() == .windows) {
            return env.getOwned(allocator, "TEMP") catch {
                return env.getOwned(allocator, "TMP") catch {
                    return allocator.dupe(u8, "C:\\Windows\\Temp");
                };
            };
        } else {
            return env.getOwned(allocator, "TMPDIR") catch {
                return allocator.dupe(u8, "/tmp");
            };
        }
    }
};

/// Service/daemon management
pub const Service = struct {
    name: []const u8,
    description: []const u8,

    /// Install service (platform-specific)
    pub fn install(self: Service, allocator: std.mem.Allocator, executable_path: []const u8) !void {
        switch (Platform.current()) {
            .windows => {
                // Windows: Use sc.exe to create service
                const cmd = try std.fmt.allocPrint(
                    allocator,
                    "sc create {s} binPath= \"{s}\" DisplayName= \"{s}\" start= auto",
                    .{ self.name, executable_path, self.description },
                );
                defer allocator.free(cmd);

                var process = std.process.Child.init(&[_][]const u8{ "cmd", "/C", cmd }, allocator);
                _ = try process.spawnAndWait();
            },
            .linux => {
                // Linux: Create systemd service file
                const service_content = try std.fmt.allocPrint(
                    allocator,
                    \\[Unit]
                    \\Description={s}
                    \\After=network.target
                    \\
                    \\[Service]
                    \\Type=simple
                    \\ExecStart={s}
                    \\Restart=on-failure
                    \\
                    \\[Install]
                    \\WantedBy=multi-user.target
                    \\
                ,
                    .{ self.description, executable_path },
                );
                defer allocator.free(service_content);

                const service_path = try std.fmt.allocPrint(
                    allocator,
                    "/etc/systemd/system/{s}.service",
                    .{self.name},
                );
                defer allocator.free(service_path);

                const file = try std.fs.createFileAbsolute(service_path, .{});
                defer file.close();
                try file.writeAll(service_content);
            },
            .freebsd, .openbsd => {
                // BSD: Create rc.d script
                const rc_content = try std.fmt.allocPrint(
                    allocator,
                    \\#!/bin/sh
                    \\# PROVIDE: {s}
                    \\# REQUIRE: NETWORKING
                    \\
                    \\. /etc/rc.subr
                    \\
                    \\name="{s}"
                    \\rcvar="{s}_enable"
                    \\command="{s}"
                    \\
                    \\load_rc_config $name
                    \\run_rc_command "$1"
                    \\
                ,
                    .{ self.name, self.name, self.name, executable_path },
                );
                defer allocator.free(rc_content);

                const rc_path = try std.fmt.allocPrint(
                    allocator,
                    "/usr/local/etc/rc.d/{s}",
                    .{self.name},
                );
                defer allocator.free(rc_path);

                const file = try std.fs.createFileAbsolute(rc_path, .{});
                defer file.close();
                try file.writeAll(rc_content);
                try file.chmod(0o755);
            },
            else => return error.UnsupportedPlatform,
        }
    }

    /// Uninstall service
    pub fn uninstall(self: Service, allocator: std.mem.Allocator) !void {
        switch (Platform.current()) {
            .windows => {
                const cmd = try std.fmt.allocPrint(allocator, "sc delete {s}", .{self.name});
                defer allocator.free(cmd);

                var process = std.process.Child.init(&[_][]const u8{ "cmd", "/C", cmd }, allocator);
                _ = try process.spawnAndWait();
            },
            .linux => {
                const service_path = try std.fmt.allocPrint(
                    allocator,
                    "/etc/systemd/system/{s}.service",
                    .{self.name},
                );
                defer allocator.free(service_path);

                try std.fs.deleteFileAbsolute(service_path);
            },
            .freebsd, .openbsd => {
                const rc_path = try std.fmt.allocPrint(
                    allocator,
                    "/usr/local/etc/rc.d/{s}",
                    .{self.name},
                );
                defer allocator.free(rc_path);

                try std.fs.deleteFileAbsolute(rc_path);
            },
            else => return error.UnsupportedPlatform,
        }
    }

    /// Start service
    pub fn start(self: Service, allocator: std.mem.Allocator) !void {
        switch (Platform.current()) {
            .windows => {
                const cmd = try std.fmt.allocPrint(allocator, "sc start {s}", .{self.name});
                defer allocator.free(cmd);

                var process = std.process.Child.init(&[_][]const u8{ "cmd", "/C", cmd }, allocator);
                _ = try process.spawnAndWait();
            },
            .linux => {
                var process = std.process.Child.init(&[_][]const u8{ "systemctl", "start", self.name }, allocator);
                _ = try process.spawnAndWait();
            },
            .freebsd, .openbsd => {
                const cmd = try std.fmt.allocPrint(allocator, "service {s} start", .{self.name});
                defer allocator.free(cmd);

                var process = std.process.Child.init(&[_][]const u8{ "sh", "-c", cmd }, allocator);
                _ = try process.spawnAndWait();
            },
            else => return error.UnsupportedPlatform,
        }
    }

    /// Stop service
    pub fn stop(self: Service, allocator: std.mem.Allocator) !void {
        switch (Platform.current()) {
            .windows => {
                const cmd = try std.fmt.allocPrint(allocator, "sc stop {s}", .{self.name});
                defer allocator.free(cmd);

                var process = std.process.Child.init(&[_][]const u8{ "cmd", "/C", cmd }, allocator);
                _ = try process.spawnAndWait();
            },
            .linux => {
                var process = std.process.Child.init(&[_][]const u8{ "systemctl", "stop", self.name }, allocator);
                _ = try process.spawnAndWait();
            },
            .freebsd, .openbsd => {
                const cmd = try std.fmt.allocPrint(allocator, "service {s} stop", .{self.name});
                defer allocator.free(cmd);

                var process = std.process.Child.init(&[_][]const u8{ "sh", "-c", cmd }, allocator);
                _ = try process.spawnAndWait();
            },
            else => return error.UnsupportedPlatform,
        }
    }
};

/// Signal handling (Unix vs Windows)
pub const Signal = struct {
    /// Set up signal handler
    pub fn setupHandler(signal: std.posix.SIG, handler: *const fn (std.posix.SIG) callconv(.c) void) !void {
        if (Platform.current().isUnix()) {
            const act = std.posix.Sigaction{
                .handler = .{ .handler = handler },
                .mask = std.posix.sigemptyset(),
                .flags = 0,
            };
            std.posix.sigaction(signal, &act, null);
        } else {
            // Windows: Use SetConsoleCtrlHandler
            // Note: Different mechanism, would need Windows-specific implementation
            return error.NotImplementedOnWindows;
        }
    }

    /// Ignore signal
    pub fn ignore(signal: std.posix.system.SIG) !void {
        if (Platform.current().isUnix()) {
            const act = std.posix.Sigaction{
                .handler = .{ .handler = std.posix.SIG.IGN },
                .mask = std.posix.empty_sigset,
                .flags = 0,
            };
            try std.posix.sigaction(signal, &act, null);
        }
    }
};

/// Process utilities
pub const Process = struct {
    /// Daemonize process (Unix only)
    pub fn daemonize() !void {
        if (!Platform.current().isUnix()) {
            return error.NotSupportedOnThisPlatform;
        }

        // Fork and exit parent
        const pid = try std.posix.fork();
        if (pid > 0) {
            std.posix.exit(0);
        }

        // Create new session
        _ = try std.posix.setsid();

        // Fork again
        const pid2 = try std.posix.fork();
        if (pid2 > 0) {
            std.posix.exit(0);
        }

        // Change to root directory
        try std.posix.chdir("/");

        // Close file descriptors
        std.posix.close(0);
        std.posix.close(1);
        std.posix.close(2);
    }

    /// Get process ID
    pub fn getPid() u32 {
        if (Platform.current().isWindows()) {
            // Would use GetCurrentProcessId()
            return 0;
        } else {
            return @intCast(std.posix.getpid());
        }
    }

    /// Write PID file
    pub fn writePidFile(allocator: std.mem.Allocator, path: []const u8) !void {
        const file = try std.fs.createFileAbsolute(path, .{});
        defer file.close();

        const pid = getPid();
        const pid_str = try std.fmt.allocPrint(allocator, "{d}\n", .{pid});
        defer allocator.free(pid_str);

        try file.writeAll(pid_str);
    }
};

/// Network utilities
pub const Network = struct {
    /// Check if IPv6 is available
    pub fn hasIPv6() bool {
        // Try to create IPv6 socket
        const socket_fd = std.posix.socket(
            std.posix.AF.INET6,
            std.posix.SOCK.STREAM,
            0,
        ) catch return false;

        std.posix.close(socket_fd);
        return true;
    }

    /// Get preferred address family
    pub fn preferredAddressFamily() u32 {
        if (hasIPv6()) {
            return std.posix.AF.INET6;
        }
        return std.posix.AF.INET;
    }
};

test "platform detection" {
    const testing = std.testing;

    const platform = Platform.current();
    try testing.expect(platform != .unknown);

    const arch = Architecture.current();
    try testing.expect(arch != .unknown);
}

test "path separator" {
    const testing = std.testing;

    const sep = Path.separator();
    if (Platform.current() == .windows) {
        try testing.expectEqualStrings("\\", sep);
    } else {
        try testing.expectEqualStrings("/", sep);
    }
}

test "path list separator" {
    const testing = std.testing;

    const sep = Path.listSeparator();
    if (Platform.current() == .windows) {
        try testing.expectEqual(@as(u8, ';'), sep);
    } else {
        try testing.expectEqual(@as(u8, ':'), sep);
    }
}

test "temp directory" {
    const testing = std.testing;

    const temp = try Path.tempDir(testing.allocator);
    defer testing.allocator.free(temp);

    try testing.expect(temp.len > 0);
}

test "process ID" {
    const testing = std.testing;

    const pid = Process.getPid();
    if (!Platform.current().isWindows()) {
        try testing.expect(pid > 0);
    }
}

test "IPv6 availability" {
    const testing = std.testing;

    const has_ipv6 = Network.hasIPv6();
    _ = has_ipv6; // Just check it doesn't crash

    const af = Network.preferredAddressFamily();
    try testing.expect(af == std.posix.AF.INET or af == std.posix.AF.INET6);
}

test "platform properties" {
    const testing = std.testing;

    const platform = Platform.current();

    if (platform == .windows) {
        try testing.expect(!platform.isUnix());
        try testing.expect(platform.isWindows());
        try testing.expect(!platform.isBSD());
    } else if (platform == .linux or platform == .macos) {
        try testing.expect(platform.isUnix());
        try testing.expect(!platform.isWindows());
    } else if (platform == .freebsd or platform == .openbsd) {
        try testing.expect(platform.isUnix());
        try testing.expect(platform.isBSD());
    }
}

test "architecture properties" {
    const testing = std.testing;

    const arch = Architecture.current();

    if (arch == .aarch64 or arch == .arm) {
        try testing.expect(arch.isARM());
    } else {
        try testing.expect(!arch.isARM());
    }
}
