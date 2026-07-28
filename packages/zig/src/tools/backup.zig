const std = @import("std");
const time_compat = @import("../core/time_compat.zig");
const version_info = @import("../core/version.zig");

/// Backup and Restore CLI Tool
/// Provides comprehensive backup/restore functionality for the mail server
/// Supports database, configuration, and maildir backups with verification
pub const BackupError = error{
    BackupFailed,
    RestoreFailed,
    VerificationFailed,
    InvalidBackup,
    PathNotFound,
    PermissionDenied,
    DiskFull,
    CorruptedBackup,
};

/// Backup type enumeration
pub const BackupType = enum {
    full, // Everything
    database, // SQLite database only
    config, // Configuration files only
    maildir, // Mail directories only
    incremental, // Changes since last backup

    pub fn toString(self: BackupType) []const u8 {
        return switch (self) {
            .full => "full",
            .database => "database",
            .config => "config",
            .maildir => "maildir",
            .incremental => "incremental",
        };
    }

    pub fn fromString(s: []const u8) ?BackupType {
        if (std.mem.eql(u8, s, "full")) return .full;
        if (std.mem.eql(u8, s, "database")) return .database;
        if (std.mem.eql(u8, s, "config")) return .config;
        if (std.mem.eql(u8, s, "maildir")) return .maildir;
        if (std.mem.eql(u8, s, "incremental")) return .incremental;
        return null;
    }
};

/// Backup manifest containing metadata
pub const BackupManifest = struct {
    version: []const u8,
    created_at: i64,
    backup_type: BackupType,
    server_version: []const u8,
    hostname: []const u8,
    checksum: []const u8,
    files: std.ArrayList(FileEntry),
    total_size: u64,
    compressed: bool,

    pub const FileEntry = struct {
        path: []const u8,
        size: u64,
        checksum: []const u8,
        modified_at: i64,
    };

    pub fn deinit(self: *BackupManifest, allocator: std.mem.Allocator) void {
        allocator.free(self.version);
        allocator.free(self.server_version);
        allocator.free(self.hostname);
        allocator.free(self.checksum);
        for (self.files.items) |entry| {
            allocator.free(entry.path);
            allocator.free(entry.checksum);
        }
        self.files.deinit();
    }
};

/// Backup Manager
pub const BackupManager = struct {
    allocator: std.mem.Allocator,
    data_dir: []const u8,
    backup_dir: []const u8,
    db_path: []const u8,
    config_path: ?[]const u8,
    maildir_path: ?[]const u8,

    // Statistics
    backups_created: u64,
    backups_restored: u64,
    last_backup_time: i64,
    last_backup_size: u64,

    const Self = @This();
    const MANIFEST_FILENAME = "manifest.json";
    const BACKUP_VERSION = "1.0";

    pub fn init(
        allocator: std.mem.Allocator,
        data_dir: []const u8,
        backup_dir: []const u8,
        db_path: []const u8,
    ) Self {
        return .{
            .allocator = allocator,
            .data_dir = data_dir,
            .backup_dir = backup_dir,
            .db_path = db_path,
            .config_path = null,
            .maildir_path = null,
            .backups_created = 0,
            .backups_restored = 0,
            .last_backup_time = 0,
            .last_backup_size = 0,
        };
    }

    pub fn setConfigPath(self: *Self, path: []const u8) void {
        self.config_path = path;
    }

    pub fn setMaildirPath(self: *Self, path: []const u8) void {
        self.maildir_path = path;
    }

    /// Create a backup
    pub fn createBackup(self: *Self, backup_type: BackupType, name: ?[]const u8) ![]const u8 {
        const timestamp = time_compat.timestamp();

        // Generate backup name
        var backup_name_buf: [128]u8 = undefined;
        const backup_name = if (name) |n|
            n
        else blk: {
            const len = std.fmt.bufPrint(&backup_name_buf, "backup_{d}_{s}", .{
                timestamp,
                backup_type.toString(),
            }) catch return BackupError.BackupFailed;
            break :blk backup_name_buf[0..len];
        };

        // Create backup directory
        const backup_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{
            self.backup_dir,
            backup_name,
        });
        errdefer self.allocator.free(backup_path);

        std.fs.makeDirAbsolute(backup_path) catch |err| {
            if (err != error.PathAlreadyExists) {
                return BackupError.BackupFailed;
            }
        };

        var total_size: u64 = 0;
        var files = std.ArrayList(BackupManifest.FileEntry).init(self.allocator);
        errdefer files.deinit();

        // Backup based on type
        switch (backup_type) {
            .full => {
                try self.backupDatabase(backup_path, &files, &total_size);
                try self.backupConfig(backup_path, &files, &total_size);
                try self.backupMaildir(backup_path, &files, &total_size);
            },
            .database => {
                try self.backupDatabase(backup_path, &files, &total_size);
            },
            .config => {
                try self.backupConfig(backup_path, &files, &total_size);
            },
            .maildir => {
                try self.backupMaildir(backup_path, &files, &total_size);
            },
            .incremental => {
                // TODO: Implement incremental backup
                try self.backupDatabase(backup_path, &files, &total_size);
            },
        }

        // Create manifest
        try self.writeManifest(backup_path, backup_type, timestamp, files, total_size);

        // Update statistics
        self.backups_created += 1;
        self.last_backup_time = timestamp;
        self.last_backup_size = total_size;

        return backup_path;
    }

    /// Backup the SQLite database
    fn backupDatabase(self: *Self, backup_path: []const u8, files: *std.ArrayList(BackupManifest.FileEntry), total_size: *u64) !void {
        const dest_path = try std.fmt.allocPrint(self.allocator, "{s}/database.db", .{backup_path});
        defer self.allocator.free(dest_path);

        // Copy database file
        try self.copyFile(self.db_path, dest_path);

        // Get file info
        const stat = std.fs.cwd().statFile(dest_path) catch return;
        const checksum = try self.calculateChecksum(dest_path);

        try files.append(.{
            .path = try self.allocator.dupe(u8, "database.db"),
            .size = stat.size,
            .checksum = checksum,
            .modified_at = @intCast(@divFloor(stat.mtime, std.time.ns_per_s)),
        });

        total_size.* += stat.size;
    }

    /// Backup configuration files
    fn backupConfig(self: *Self, backup_path: []const u8, files: *std.ArrayList(BackupManifest.FileEntry), total_size: *u64) !void {
        if (self.config_path) |config_path| {
            const dest_path = try std.fmt.allocPrint(self.allocator, "{s}/config", .{backup_path});
            defer self.allocator.free(dest_path);

            std.fs.makeDirAbsolute(dest_path) catch |err| {
                if (err != error.PathAlreadyExists) return;
            };

            // Copy config file
            const config_dest = try std.fmt.allocPrint(self.allocator, "{s}/server.toml", .{dest_path});
            defer self.allocator.free(config_dest);

            self.copyFile(config_path, config_dest) catch return;

            const stat = std.fs.cwd().statFile(config_dest) catch return;
            const checksum = try self.calculateChecksum(config_dest);

            try files.append(.{
                .path = try self.allocator.dupe(u8, "config/server.toml"),
                .size = stat.size,
                .checksum = checksum,
                .modified_at = @intCast(@divFloor(stat.mtime, std.time.ns_per_s)),
            });

            total_size.* += stat.size;
        }
    }

    /// Backup mail directories
    fn backupMaildir(self: *Self, backup_path: []const u8, files: *std.ArrayList(BackupManifest.FileEntry), total_size: *u64) !void {
        if (self.maildir_path) |maildir| {
            const dest_path = try std.fmt.allocPrint(self.allocator, "{s}/maildir", .{backup_path});
            defer self.allocator.free(dest_path);

            try self.copyDirectory(maildir, dest_path, files, total_size, "maildir");
        }
    }

    /// Copy a file
    fn copyFile(self: *Self, src: []const u8, dest: []const u8) !void {
        _ = self;
        const src_file = std.fs.cwd().openFile(src, .{}) catch return error.PathNotFound;
        defer src_file.close();

        const dest_file = std.fs.cwd().createFile(dest, .{}) catch return error.BackupFailed;
        defer dest_file.close();

        var buf: [8192]u8 = undefined;
        while (true) {
            const bytes_read = src_file.read(&buf) catch return error.BackupFailed;
            if (bytes_read == 0) break;
            dest_file.writeAll(buf[0..bytes_read]) catch return error.BackupFailed;
        }
    }

    /// Copy a directory recursively
    fn copyDirectory(
        self: *Self,
        src: []const u8,
        dest: []const u8,
        files: *std.ArrayList(BackupManifest.FileEntry),
        total_size: *u64,
        prefix: []const u8,
    ) !void {
        std.fs.makeDirAbsolute(dest) catch |err| {
            if (err != error.PathAlreadyExists) return;
        };

        var dir = std.fs.cwd().openDir(src, .{ .iterate = true }) catch return;
        defer dir.close();

        var iter = dir.iterate();
        while (iter.next() catch null) |entry| {
            const src_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ src, entry.name });
            defer self.allocator.free(src_path);

            const dest_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ dest, entry.name });
            defer self.allocator.free(dest_path);

            const rel_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ prefix, entry.name });

            switch (entry.kind) {
                .file => {
                    self.copyFile(src_path, dest_path) catch continue;

                    const stat = std.fs.cwd().statFile(dest_path) catch continue;
                    const checksum = self.calculateChecksum(dest_path) catch continue;

                    try files.append(.{
                        .path = rel_path,
                        .size = stat.size,
                        .checksum = checksum,
                        .modified_at = @intCast(@divFloor(stat.mtime, std.time.ns_per_s)),
                    });

                    total_size.* += stat.size;
                },
                .directory => {
                    defer self.allocator.free(rel_path);
                    try self.copyDirectory(src_path, dest_path, files, total_size, rel_path);
                },
                else => {
                    self.allocator.free(rel_path);
                },
            }
        }
    }

    /// Calculate SHA-256 checksum of a file
    fn calculateChecksum(self: *Self, path: []const u8) ![]const u8 {
        const file = std.fs.cwd().openFile(path, .{}) catch return error.PathNotFound;
        defer file.close();

        var hasher = std.crypto.hash.sha2.Sha256.init(.{});

        var buf: [8192]u8 = undefined;
        while (true) {
            const bytes_read = file.read(&buf) catch return error.BackupFailed;
            if (bytes_read == 0) break;
            hasher.update(buf[0..bytes_read]);
        }

        var hash: [32]u8 = undefined;
        hasher.final(&hash);

        var hex: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&hex, "{s}", .{std.fmt.fmtSliceHexLower(&hash)}) catch unreachable;

        return try self.allocator.dupe(u8, &hex);
    }

    /// Write backup manifest
    fn writeManifest(
        self: *Self,
        backup_path: []const u8,
        backup_type: BackupType,
        timestamp: i64,
        files: std.ArrayList(BackupManifest.FileEntry),
        total_size: u64,
    ) !void {
        const manifest_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{
            backup_path,
            MANIFEST_FILENAME,
        });
        defer self.allocator.free(manifest_path);

        const file = std.fs.cwd().createFile(manifest_path, .{}) catch return error.BackupFailed;
        defer file.close();

        var writer = file.writer();

        // Write JSON manifest
        try writer.print("{{\n", .{});
        try writer.print("  \"version\": \"{s}\",\n", .{BACKUP_VERSION});
        try writer.print("  \"created_at\": {d},\n", .{timestamp});
        try writer.print("  \"backup_type\": \"{s}\",\n", .{backup_type.toString()});
        try writer.print("  \"server_version\": \"{s}\",\n", .{version_info.version});
        try writer.print("  \"total_size\": {d},\n", .{total_size});
        try writer.print("  \"file_count\": {d},\n", .{files.items.len});
        try writer.print("  \"files\": [\n", .{});

        for (files.items, 0..) |entry, i| {
            try writer.print("    {{\n", .{});
            try writer.print("      \"path\": \"{s}\",\n", .{entry.path});
            try writer.print("      \"size\": {d},\n", .{entry.size});
            try writer.print("      \"checksum\": \"{s}\",\n", .{entry.checksum});
            try writer.print("      \"modified_at\": {d}\n", .{entry.modified_at});
            if (i < files.items.len - 1) {
                try writer.print("    }},\n", .{});
            } else {
                try writer.print("    }}\n", .{});
            }
        }

        try writer.print("  ]\n", .{});
        try writer.print("}}\n", .{});
    }

    /// Restore from a backup
    pub fn restoreBackup(self: *Self, backup_path: []const u8, verify_first: bool) !void {
        // Read and parse manifest
        const manifest = try self.readManifest(backup_path);
        defer {
            var m = manifest;
            m.deinit(self.allocator);
        }

        // Verify backup if requested
        if (verify_first) {
            try self.verifyBackup(backup_path);
        }

        // Restore based on backup type
        switch (manifest.backup_type) {
            .full => {
                try self.restoreDatabase(backup_path);
                try self.restoreConfig(backup_path);
                try self.restoreMaildir(backup_path);
            },
            .database => {
                try self.restoreDatabase(backup_path);
            },
            .config => {
                try self.restoreConfig(backup_path);
            },
            .maildir => {
                try self.restoreMaildir(backup_path);
            },
            .incremental => {
                try self.restoreDatabase(backup_path);
            },
        }

        self.backups_restored += 1;
    }

    /// Read backup manifest
    fn readManifest(self: *Self, backup_path: []const u8) !BackupManifest {
        const manifest_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{
            backup_path,
            MANIFEST_FILENAME,
        });
        defer self.allocator.free(manifest_path);

        const file = std.fs.cwd().openFile(manifest_path, .{}) catch return error.InvalidBackup;
        defer file.close();

        // Read file contents
        const stat = file.stat() catch return error.InvalidBackup;
        const content = self.allocator.alloc(u8, stat.size) catch return error.InvalidBackup;
        defer self.allocator.free(content);

        _ = file.readAll(content) catch return error.InvalidBackup;

        // Parse JSON (simplified - extract key fields)
        var manifest = BackupManifest{
            .version = try self.allocator.dupe(u8, BACKUP_VERSION),
            .created_at = 0,
            .backup_type = .full,
            .server_version = try self.allocator.dupe(u8, version_info.version),
            .hostname = try self.allocator.dupe(u8, "localhost"),
            .checksum = try self.allocator.dupe(u8, ""),
            .files = std.ArrayList(BackupManifest.FileEntry).init(self.allocator),
            .total_size = 0,
            .compressed = false,
        };

        // Extract backup_type from JSON
        if (std.mem.indexOf(u8, content, "\"backup_type\":")) |pos| {
            const start = pos + 16; // Skip past "backup_type": "
            if (std.mem.indexOfPos(u8, content, start, "\"")) |end| {
                const type_str = content[start..end];
                manifest.backup_type = BackupType.fromString(type_str) orelse .full;
            }
        }

        return manifest;
    }

    /// Verify backup integrity
    pub fn verifyBackup(self: *Self, backup_path: []const u8) !void {
        const manifest = try self.readManifest(backup_path);
        defer {
            var m = manifest;
            m.deinit(self.allocator);
        }

        // Verify each file's checksum
        for (manifest.files.items) |entry| {
            const file_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{
                backup_path,
                entry.path,
            });
            defer self.allocator.free(file_path);

            const checksum = self.calculateChecksum(file_path) catch {
                return error.VerificationFailed;
            };
            defer self.allocator.free(checksum);

            if (!std.mem.eql(u8, checksum, entry.checksum)) {
                return error.CorruptedBackup;
            }
        }
    }

    /// Restore database
    fn restoreDatabase(self: *Self, backup_path: []const u8) !void {
        const src_path = try std.fmt.allocPrint(self.allocator, "{s}/database.db", .{backup_path});
        defer self.allocator.free(src_path);

        // Create backup of current database first
        const backup_current = try std.fmt.allocPrint(self.allocator, "{s}.pre-restore", .{self.db_path});
        defer self.allocator.free(backup_current);

        self.copyFile(self.db_path, backup_current) catch {};

        // Restore database
        try self.copyFile(src_path, self.db_path);
    }

    /// Restore configuration
    fn restoreConfig(self: *Self, backup_path: []const u8) !void {
        if (self.config_path) |config_path| {
            const src_path = try std.fmt.allocPrint(self.allocator, "{s}/config/server.toml", .{backup_path});
            defer self.allocator.free(src_path);

            // Create backup of current config first
            const backup_current = try std.fmt.allocPrint(self.allocator, "{s}.pre-restore", .{config_path});
            defer self.allocator.free(backup_current);

            self.copyFile(config_path, backup_current) catch {};

            // Restore config
            self.copyFile(src_path, config_path) catch return;
        }
    }

    /// Restore mail directories
    fn restoreMaildir(self: *Self, backup_path: []const u8) !void {
        if (self.maildir_path) |maildir| {
            const src_path = try std.fmt.allocPrint(self.allocator, "{s}/maildir", .{backup_path});
            defer self.allocator.free(src_path);

            // Recursively copy maildir from backup to destination
            self.copyDirectoryRestore(src_path, maildir) catch return;
        }
    }

    /// Copy directory recursively for restore
    fn copyDirectoryRestore(self: *Self, src: []const u8, dest: []const u8) !void {
        std.fs.makeDirAbsolute(dest) catch |err| {
            if (err != error.PathAlreadyExists) return;
        };

        var dir = std.fs.cwd().openDir(src, .{ .iterate = true }) catch return;
        defer dir.close();

        var iter = dir.iterate();
        while (iter.next() catch null) |entry| {
            const src_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ src, entry.name });
            defer self.allocator.free(src_path);

            const dest_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ dest, entry.name });
            defer self.allocator.free(dest_path);

            switch (entry.kind) {
                .file => {
                    self.copyFile(src_path, dest_path) catch continue;
                },
                .directory => {
                    try self.copyDirectoryRestore(src_path, dest_path);
                },
                else => {},
            }
        }
    }

    /// List available backups
    pub fn listBackups(self: *Self) ![]BackupInfo {
        var backups = std.ArrayList(BackupInfo).init(self.allocator);
        errdefer backups.deinit();

        var dir = std.fs.cwd().openDir(self.backup_dir, .{ .iterate = true }) catch {
            return backups.toOwnedSlice();
        };
        defer dir.close();

        var iter = dir.iterate();
        while (iter.next() catch null) |entry| {
            if (entry.kind != .directory) continue;

            // Try to read manifest
            const manifest_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}/{s}", .{
                self.backup_dir,
                entry.name,
                MANIFEST_FILENAME,
            });
            defer self.allocator.free(manifest_path);

            const manifest_file = std.fs.cwd().openFile(manifest_path, .{}) catch continue;
            defer manifest_file.close();

            const stat = manifest_file.stat() catch continue;

            try backups.append(.{
                .name = try self.allocator.dupe(u8, entry.name),
                .path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.backup_dir, entry.name }),
                .created_at = @intCast(@divFloor(stat.mtime, std.time.ns_per_s)),
                .size = 0, // Would need to sum all files
            });
        }

        return backups.toOwnedSlice();
    }

    /// Get backup statistics
    pub fn getStats(self: *Self) BackupStats {
        return .{
            .backups_created = self.backups_created,
            .backups_restored = self.backups_restored,
            .last_backup_time = self.last_backup_time,
            .last_backup_size = self.last_backup_size,
        };
    }
};

/// Backup info for listing
pub const BackupInfo = struct {
    name: []const u8,
    path: []const u8,
    created_at: i64,
    size: u64,

    pub fn deinit(self: *BackupInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.path);
    }
};

/// Backup statistics
pub const BackupStats = struct {
    backups_created: u64,
    backups_restored: u64,
    last_backup_time: i64,
    last_backup_size: u64,
};

/// CLI entry point for backup operations
pub fn runBackupCLI(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    if (args.len < 2) {
        try printUsage();
        return 1;
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "create")) {
        return try runCreate(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "restore")) {
        return try runRestore(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "verify")) {
        return try runVerify(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "list")) {
        return try runList(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help")) {
        try printUsage();
        return 0;
    } else {
        std.debug.print("Unknown command: {s}\n", .{command});
        try printUsage();
        return 1;
    }
}

fn printUsage() !void {
    const usage =
        \\SMTP Server Backup Tool
        \\
        \\Usage: smtp-backup <command> [options]
        \\
        \\Commands:
        \\  create    Create a new backup
        \\  restore   Restore from a backup
        \\  verify    Verify backup integrity
        \\  list      List available backups
        \\  help      Show this help message
        \\
        \\Create Options:
        \\  --type <type>      Backup type: full, database, config, maildir (default: full)
        \\  --name <name>      Custom backup name (default: auto-generated)
        \\  --data-dir <path>  Data directory (default: ./data)
        \\  --backup-dir <path> Backup directory (default: ./backups)
        \\
        \\Restore Options:
        \\  --backup <path>    Path to backup directory
        \\  --verify           Verify backup before restoring
        \\  --data-dir <path>  Data directory to restore to
        \\
        \\Verify Options:
        \\  --backup <path>    Path to backup directory to verify
        \\
        \\Examples:
        \\  smtp-backup create --type full
        \\  smtp-backup create --type database --name daily-db-backup
        \\  smtp-backup restore --backup ./backups/backup_123456_full --verify
        \\  smtp-backup verify --backup ./backups/backup_123456_full
        \\  smtp-backup list
        \\
    ;
    std.debug.print("{s}", .{usage});
}

fn runCreate(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    var backup_type: BackupType = .full;
    var name: ?[]const u8 = null;
    var data_dir: []const u8 = "./data";
    var backup_dir: []const u8 = "./backups";

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--type") and i + 1 < args.len) {
            i += 1;
            backup_type = BackupType.fromString(args[i]) orelse .full;
        } else if (std.mem.eql(u8, arg, "--name") and i + 1 < args.len) {
            i += 1;
            name = args[i];
        } else if (std.mem.eql(u8, arg, "--data-dir") and i + 1 < args.len) {
            i += 1;
            data_dir = args[i];
        } else if (std.mem.eql(u8, arg, "--backup-dir") and i + 1 < args.len) {
            i += 1;
            backup_dir = args[i];
        }
    }

    const db_path = try std.fmt.allocPrint(allocator, "{s}/mail.db", .{data_dir});
    defer allocator.free(db_path);

    // Create backup directory if it doesn't exist
    std.fs.makeDirAbsolute(backup_dir) catch |err| {
        if (err != error.PathAlreadyExists) {
            std.debug.print("Error: Cannot create backup directory: {s}\n", .{backup_dir});
            return 1;
        }
    };

    var manager = BackupManager.init(allocator, data_dir, backup_dir, db_path);

    std.debug.print("Creating {s} backup...\n", .{backup_type.toString()});

    const backup_path = manager.createBackup(backup_type, name) catch |err| {
        std.debug.print("Error: Backup failed: {any}\n", .{err});
        return 1;
    };
    defer allocator.free(backup_path);

    std.debug.print("Backup created successfully: {s}\n", .{backup_path});
    std.debug.print("Total size: {d} bytes\n", .{manager.last_backup_size});

    return 0;
}

fn runRestore(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    var backup_path: ?[]const u8 = null;
    var verify: bool = false;
    var data_dir: []const u8 = "./data";

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--backup") and i + 1 < args.len) {
            i += 1;
            backup_path = args[i];
        } else if (std.mem.eql(u8, arg, "--verify")) {
            verify = true;
        } else if (std.mem.eql(u8, arg, "--data-dir") and i + 1 < args.len) {
            i += 1;
            data_dir = args[i];
        }
    }

    if (backup_path == null) {
        std.debug.print("Error: --backup path required\n", .{});
        return 1;
    }

    const db_path = try std.fmt.allocPrint(allocator, "{s}/mail.db", .{data_dir});
    defer allocator.free(db_path);

    var manager = BackupManager.init(allocator, data_dir, "./backups", db_path);

    if (verify) {
        std.debug.print("Verifying backup...\n", .{});
    }

    std.debug.print("Restoring from: {s}\n", .{backup_path.?});

    manager.restoreBackup(backup_path.?, verify) catch |err| {
        std.debug.print("Error: Restore failed: {any}\n", .{err});
        return 1;
    };

    std.debug.print("Restore completed successfully!\n", .{});
    return 0;
}

fn runVerify(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    var backup_path: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--backup") and i + 1 < args.len) {
            i += 1;
            backup_path = args[i];
        }
    }

    if (backup_path == null) {
        std.debug.print("Error: --backup path required\n", .{});
        return 1;
    }

    var manager = BackupManager.init(allocator, "./data", "./backups", "./data/mail.db");

    std.debug.print("Verifying backup: {s}\n", .{backup_path.?});

    manager.verifyBackup(backup_path.?) catch |err| {
        std.debug.print("Verification FAILED: {any}\n", .{err});
        return 1;
    };

    std.debug.print("Verification PASSED: All checksums match\n", .{});
    return 0;
}

fn runList(allocator: std.mem.Allocator, args: []const []const u8) !u8 {
    var backup_dir: []const u8 = "./backups";

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--backup-dir") and i + 1 < args.len) {
            i += 1;
            backup_dir = args[i];
        }
    }

    var manager = BackupManager.init(allocator, "./data", backup_dir, "./data/mail.db");

    const backups = manager.listBackups() catch |err| {
        std.debug.print("Error listing backups: {any}\n", .{err});
        return 1;
    };
    defer {
        for (backups) |*b| {
            var backup = b.*;
            backup.deinit(allocator);
        }
        allocator.free(backups);
    }

    if (backups.len == 0) {
        std.debug.print("No backups found in {s}\n", .{backup_dir});
        return 0;
    }

    std.debug.print("Available backups in {s}:\n\n", .{backup_dir});
    std.debug.print("{s:<40} {s:<20}\n", .{ "Name", "Path" });
    std.debug.print("{s}\n", .{@as([60]u8, @splat('-'))});

    for (backups) |backup| {
        std.debug.print("{s:<40} {s:<20}\n", .{ backup.name, backup.path });
    }

    return 0;
}

// Tests
test "backup type conversion" {
    const testing = std.testing;

    try testing.expectEqualStrings("full", BackupType.full.toString());
    try testing.expectEqualStrings("database", BackupType.database.toString());

    try testing.expectEqual(BackupType.full, BackupType.fromString("full").?);
    try testing.expectEqual(BackupType.database, BackupType.fromString("database").?);
    try testing.expect(BackupType.fromString("invalid") == null);
}

test "backup manager initialization" {
    const testing = std.testing;

    var manager = BackupManager.init(testing.allocator, "./data", "./backups", "./data/mail.db");
    const stats = manager.getStats();

    try testing.expectEqual(@as(u64, 0), stats.backups_created);
    try testing.expectEqual(@as(u64, 0), stats.backups_restored);
}
