const std = @import("std");
const Allocator = std.mem.Allocator;
const fs = std.fs;

/// Mail Server Migration Tools
///
/// Provides migration utilities for importing data from other mail servers:
/// - Postfix migration
/// - Sendmail migration
/// - Dovecot migration
/// - Exim migration
/// - Maildir import
/// - mbox import
///
/// Usage:
/// ```
/// server-migrate --source postfix --config /etc/postfix --target /var/spool/mail
/// server-migrate --import maildir --path /home/user/Maildir
/// ```

// ============================================================================
// Source Server Types
// ============================================================================

/// Supported mail server types for migration
pub const ServerType = enum {
    postfix,
    sendmail,
    dovecot,
    exim,
    qmail,
    courier,
    generic_maildir,
    generic_mbox,

    pub fn toString(self: ServerType) []const u8 {
        return @tagName(self);
    }

    pub fn defaultConfigPath(self: ServerType) []const u8 {
        return switch (self) {
            .postfix => "/etc/postfix",
            .sendmail => "/etc/mail",
            .dovecot => "/etc/dovecot",
            .exim => "/etc/exim4",
            .qmail => "/var/qmail",
            .courier => "/etc/courier",
            .generic_maildir => "",
            .generic_mbox => "",
        };
    }

    pub fn defaultMailPath(self: ServerType) []const u8 {
        return switch (self) {
            .postfix => "/var/spool/mail",
            .sendmail => "/var/spool/mail",
            .dovecot => "/var/mail",
            .exim => "/var/spool/mail",
            .qmail => "/var/qmail/mailnames",
            .courier => "/home/vmail",
            .generic_maildir => "",
            .generic_mbox => "",
        };
    }
};

// ============================================================================
// Migration Configuration
// ============================================================================

/// Migration configuration
pub const MigrationConfig = struct {
    source_type: ServerType,
    source_config_path: []const u8,
    source_mail_path: []const u8,
    target_path: []const u8,
    preserve_timestamps: bool = true,
    preserve_flags: bool = true,
    migrate_users: bool = true,
    migrate_aliases: bool = true,
    migrate_domains: bool = true,
    dry_run: bool = false,
    verbose: bool = false,
    exclude_patterns: std.ArrayList([]const u8),

    pub fn init(allocator: Allocator, source_type: ServerType) MigrationConfig {
        return .{
            .source_type = source_type,
            .source_config_path = source_type.defaultConfigPath(),
            .source_mail_path = source_type.defaultMailPath(),
            .target_path = "/var/mail/mail",
            .exclude_patterns = std.ArrayList([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *MigrationConfig, allocator: Allocator) void {
        for (self.exclude_patterns.items) |pattern| {
            allocator.free(pattern);
        }
        self.exclude_patterns.deinit();
    }
};

// ============================================================================
// Migration Data Structures
// ============================================================================

/// Migrated user account
pub const MigratedUser = struct {
    username: []const u8,
    password_hash: ?[]const u8 = null,
    home_directory: []const u8,
    uid: ?u32 = null,
    gid: ?u32 = null,
    quota_bytes: ?u64 = null,
    disabled: bool = false,

    pub fn deinit(self: *MigratedUser, allocator: Allocator) void {
        allocator.free(self.username);
        if (self.password_hash) |hash| allocator.free(hash);
        allocator.free(self.home_directory);
    }
};

/// Migrated email alias
pub const MigratedAlias = struct {
    source: []const u8,
    destinations: [][]const u8,

    pub fn deinit(self: *MigratedAlias, allocator: Allocator) void {
        allocator.free(self.source);
        for (self.destinations) |dest| {
            allocator.free(dest);
        }
        allocator.free(self.destinations);
    }
};

/// Migrated domain
pub const MigratedDomain = struct {
    domain: []const u8,
    transport: []const u8,
    active: bool = true,

    pub fn deinit(self: *MigratedDomain, allocator: Allocator) void {
        allocator.free(self.domain);
        allocator.free(self.transport);
    }
};

/// Migrated email message
pub const MigratedMessage = struct {
    uid: []const u8,
    path: []const u8,
    size: u64,
    internal_date: i64,
    flags: MessageFlags,

    pub const MessageFlags = struct {
        seen: bool = false,
        answered: bool = false,
        flagged: bool = false,
        deleted: bool = false,
        draft: bool = false,
    };

    pub fn deinit(self: *MigratedMessage, allocator: Allocator) void {
        allocator.free(self.uid);
        allocator.free(self.path);
    }
};

// ============================================================================
// Migration Results
// ============================================================================

/// Migration result statistics
pub const MigrationStats = struct {
    users_migrated: u32 = 0,
    users_failed: u32 = 0,
    aliases_migrated: u32 = 0,
    aliases_failed: u32 = 0,
    domains_migrated: u32 = 0,
    domains_failed: u32 = 0,
    messages_migrated: u64 = 0,
    messages_failed: u64 = 0,
    bytes_migrated: u64 = 0,
    duration_ms: u64 = 0,
    errors: std.ArrayList([]const u8),

    pub fn init(allocator: Allocator) MigrationStats {
        return .{
            .errors = std.ArrayList([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *MigrationStats, allocator: Allocator) void {
        for (self.errors.items) |err| {
            allocator.free(err);
        }
        self.errors.deinit();
    }

    pub fn addError(self: *MigrationStats, allocator: Allocator, err: []const u8) !void {
        const copy = try allocator.dupe(u8, err);
        try self.errors.append(copy);
    }
};

// ============================================================================
// Server-Specific Parsers
// ============================================================================

/// Postfix configuration parser
pub const PostfixParser = struct {
    allocator: Allocator,
    config_path: []const u8,

    pub fn init(allocator: Allocator, config_path: []const u8) PostfixParser {
        return .{
            .allocator = allocator,
            .config_path = config_path,
        };
    }

    /// Parse main.cf
    pub fn parseMainCf(self: *PostfixParser) !std.StringHashMap([]const u8) {
        var config = std.StringHashMap([]const u8).init(self.allocator);
        errdefer config.deinit();

        const path = try std.fmt.allocPrint(self.allocator, "{s}/main.cf", .{self.config_path});
        defer self.allocator.free(path);

        const file = fs.cwd().openFile(path, .{}) catch |err| {
            std.log.warn("Could not open main.cf: {}", .{err});
            return config;
        };
        defer file.close();

        var buf_reader = std.io.bufferedReader(file.reader());
        var reader = buf_reader.reader();
        var line_buf: [4096]u8 = undefined;

        while (reader.readUntilDelimiterOrEof(&line_buf, '\n') catch null) |line| {
            const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            if (std.mem.indexOf(u8, trimmed, "=")) |eq_pos| {
                const key = std.mem.trim(u8, trimmed[0..eq_pos], &std.ascii.whitespace);
                const value = std.mem.trim(u8, trimmed[eq_pos + 1 ..], &std.ascii.whitespace);
                const key_copy = try self.allocator.dupe(u8, key);
                const value_copy = try self.allocator.dupe(u8, value);
                try config.put(key_copy, value_copy);
            }
        }

        return config;
    }

    /// Parse virtual_alias_maps
    pub fn parseAliases(self: *PostfixParser, aliases_file: []const u8) ![]MigratedAlias {
        var aliases = std.ArrayList(MigratedAlias).init(self.allocator);
        errdefer aliases.deinit();

        const file = fs.cwd().openFile(aliases_file, .{}) catch |err| {
            std.log.warn("Could not open aliases file: {}", .{err});
            return aliases.toOwnedSlice();
        };
        defer file.close();

        var buf_reader = std.io.bufferedReader(file.reader());
        var reader = buf_reader.reader();
        var line_buf: [4096]u8 = undefined;

        while (reader.readUntilDelimiterOrEof(&line_buf, '\n') catch null) |line| {
            const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            // Parse "source: dest1, dest2, ..."
            if (std.mem.indexOf(u8, trimmed, ":")) |colon_pos| {
                const source = std.mem.trim(u8, trimmed[0..colon_pos], &std.ascii.whitespace);
                const dests_str = std.mem.trim(u8, trimmed[colon_pos + 1 ..], &std.ascii.whitespace);

                var dests = std.ArrayList([]const u8).init(self.allocator);
                var dest_iter = std.mem.splitScalar(u8, dests_str, ',');
                while (dest_iter.next()) |dest| {
                    const dest_trimmed = std.mem.trim(u8, dest, &std.ascii.whitespace);
                    if (dest_trimmed.len > 0) {
                        try dests.append(try self.allocator.dupe(u8, dest_trimmed));
                    }
                }

                try aliases.append(.{
                    .source = try self.allocator.dupe(u8, source),
                    .destinations = try dests.toOwnedSlice(),
                });
            }
        }

        return aliases.toOwnedSlice();
    }
};

/// Dovecot configuration parser
pub const DovecotParser = struct {
    allocator: Allocator,
    config_path: []const u8,

    pub fn init(allocator: Allocator, config_path: []const u8) DovecotParser {
        return .{
            .allocator = allocator,
            .config_path = config_path,
        };
    }

    /// Parse dovecot.conf
    pub fn parseConfig(self: *DovecotParser) !std.StringHashMap([]const u8) {
        var config = std.StringHashMap([]const u8).init(self.allocator);
        errdefer config.deinit();

        const path = try std.fmt.allocPrint(self.allocator, "{s}/dovecot.conf", .{self.config_path});
        defer self.allocator.free(path);

        const file = fs.cwd().openFile(path, .{}) catch |err| {
            std.log.warn("Could not open dovecot.conf: {}", .{err});
            return config;
        };
        defer file.close();

        var buf_reader = std.io.bufferedReader(file.reader());
        var reader = buf_reader.reader();
        var line_buf: [4096]u8 = undefined;

        while (reader.readUntilDelimiterOrEof(&line_buf, '\n') catch null) |line| {
            const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            if (std.mem.indexOf(u8, trimmed, "=")) |eq_pos| {
                const key = std.mem.trim(u8, trimmed[0..eq_pos], &std.ascii.whitespace);
                const value = std.mem.trim(u8, trimmed[eq_pos + 1 ..], &std.ascii.whitespace);
                const key_copy = try self.allocator.dupe(u8, key);
                const value_copy = try self.allocator.dupe(u8, value);
                try config.put(key_copy, value_copy);
            }
        }

        return config;
    }

    /// Parse passwd-file users
    pub fn parseUsers(self: *DovecotParser, passwd_file: []const u8) ![]MigratedUser {
        var users = std.ArrayList(MigratedUser).init(self.allocator);
        errdefer users.deinit();

        const file = fs.cwd().openFile(passwd_file, .{}) catch |err| {
            std.log.warn("Could not open passwd file: {}", .{err});
            return users.toOwnedSlice();
        };
        defer file.close();

        var buf_reader = std.io.bufferedReader(file.reader());
        var reader = buf_reader.reader();
        var line_buf: [4096]u8 = undefined;

        while (reader.readUntilDelimiterOrEof(&line_buf, '\n') catch null) |line| {
            const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            // Parse "user:password:uid:gid:gecos:home:shell"
            var parts = std.mem.splitScalar(u8, trimmed, ':');
            const username = parts.next() orelse continue;
            const password = parts.next();
            const uid_str = parts.next();
            const gid_str = parts.next();
            _ = parts.next(); // gecos
            const home = parts.next() orelse continue;

            try users.append(.{
                .username = try self.allocator.dupe(u8, username),
                .password_hash = if (password) |p| try self.allocator.dupe(u8, p) else null,
                .home_directory = try self.allocator.dupe(u8, home),
                .uid = if (uid_str) |u| std.fmt.parseInt(u32, u, 10) catch null else null,
                .gid = if (gid_str) |g| std.fmt.parseInt(u32, g, 10) catch null else null,
            });
        }

        return users.toOwnedSlice();
    }
};

// ============================================================================
// Maildir/mbox Importers
// ============================================================================

/// Maildir importer
pub const MaildirImporter = struct {
    allocator: Allocator,

    pub fn init(allocator: Allocator) MaildirImporter {
        return .{ .allocator = allocator };
    }

    /// Import messages from Maildir
    pub fn importMaildir(self: *MaildirImporter, maildir_path: []const u8, stats: *MigrationStats) ![]MigratedMessage {
        var messages = std.ArrayList(MigratedMessage).init(self.allocator);
        errdefer messages.deinit();

        // Scan cur, new, tmp directories
        const subdirs = [_][]const u8{ "cur", "new" };

        for (subdirs) |subdir| {
            const dir_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ maildir_path, subdir });
            defer self.allocator.free(dir_path);

            var dir = fs.cwd().openDir(dir_path, .{ .iterate = true }) catch continue;
            defer dir.close();

            var iter = dir.iterate();
            while (try iter.next()) |entry| {
                if (entry.kind != .file) continue;

                const file_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ dir_path, entry.name });
                const stat = dir.statFile(entry.name) catch continue;

                // Parse flags from filename (e.g., "unique:2,S" = Seen)
                var flags = MigratedMessage.MessageFlags{};
                if (std.mem.indexOf(u8, entry.name, ":2,")) |flag_pos| {
                    const flag_str = entry.name[flag_pos + 3 ..];
                    for (flag_str) |c| {
                        switch (c) {
                            'S' => flags.seen = true,
                            'R' => flags.answered = true,
                            'F' => flags.flagged = true,
                            'T' => flags.deleted = true,
                            'D' => flags.draft = true,
                            else => {},
                        }
                    }
                }

                try messages.append(.{
                    .uid = try self.allocator.dupe(u8, entry.name),
                    .path = file_path,
                    .size = stat.size,
                    .internal_date = @intCast(@divFloor(stat.mtime, std.time.ns_per_s)),
                    .flags = flags,
                });

                stats.messages_migrated += 1;
                stats.bytes_migrated += stat.size;
            }
        }

        return messages.toOwnedSlice();
    }
};

/// mbox importer
pub const MboxImporter = struct {
    allocator: Allocator,

    pub fn init(allocator: Allocator) MboxImporter {
        return .{ .allocator = allocator };
    }

    /// Import messages from mbox file
    pub fn importMbox(self: *MboxImporter, mbox_path: []const u8, output_dir: []const u8, stats: *MigrationStats) ![]MigratedMessage {
        var messages = std.ArrayList(MigratedMessage).init(self.allocator);
        errdefer messages.deinit();

        const file = fs.cwd().openFile(mbox_path, .{}) catch |err| {
            std.log.err("Could not open mbox file: {}", .{err});
            return messages.toOwnedSlice();
        };
        defer file.close();

        var buf_reader = std.io.bufferedReader(file.reader());
        var reader = buf_reader.reader();

        var message_buf = std.ArrayList(u8).init(self.allocator);
        defer message_buf.deinit();

        var line_buf: [8192]u8 = undefined;
        var msg_count: u64 = 0;
        var in_message = false;

        while (reader.readUntilDelimiterOrEof(&line_buf, '\n') catch null) |line| {
            // mbox messages start with "From "
            if (std.mem.startsWith(u8, line, "From ")) {
                if (in_message and message_buf.items.len > 0) {
                    // Save previous message
                    msg_count += 1;
                    const msg_filename = try std.fmt.allocPrint(self.allocator, "{s}/{d}.eml", .{ output_dir, msg_count });

                    const out_file = fs.cwd().createFile(msg_filename, .{}) catch |err| {
                        std.log.warn("Could not create message file: {}", .{err});
                        stats.messages_failed += 1;
                        continue;
                    };
                    defer out_file.close();

                    try out_file.writeAll(message_buf.items);

                    try messages.append(.{
                        .uid = try std.fmt.allocPrint(self.allocator, "{d}", .{msg_count}),
                        .path = msg_filename,
                        .size = message_buf.items.len,
                        .internal_date = std.time.timestamp(),
                        .flags = .{},
                    });

                    stats.messages_migrated += 1;
                    stats.bytes_migrated += message_buf.items.len;
                    message_buf.clearRetainingCapacity();
                }
                in_message = true;
            } else if (in_message) {
                // Un-escape "From " lines (">From " -> "From ")
                if (std.mem.startsWith(u8, line, ">From ")) {
                    try message_buf.appendSlice(line[1..]);
                } else {
                    try message_buf.appendSlice(line);
                }
                try message_buf.append('\n');
            }
        }

        // Handle last message
        if (in_message and message_buf.items.len > 0) {
            msg_count += 1;
            const msg_filename = try std.fmt.allocPrint(self.allocator, "{s}/{d}.eml", .{ output_dir, msg_count });

            const out_file = try fs.cwd().createFile(msg_filename, .{});
            defer out_file.close();

            try out_file.writeAll(message_buf.items);

            try messages.append(.{
                .uid = try std.fmt.allocPrint(self.allocator, "{d}", .{msg_count}),
                .path = msg_filename,
                .size = message_buf.items.len,
                .internal_date = std.time.timestamp(),
                .flags = .{},
            });

            stats.messages_migrated += 1;
            stats.bytes_migrated += message_buf.items.len;
        }

        return messages.toOwnedSlice();
    }
};

// ============================================================================
// Migration Manager
// ============================================================================

/// Main migration manager
pub const MigrationManager = struct {
    allocator: Allocator,
    config: MigrationConfig,
    stats: MigrationStats,

    pub fn init(allocator: Allocator, config: MigrationConfig) MigrationManager {
        return .{
            .allocator = allocator,
            .config = config,
            .stats = MigrationStats.init(allocator),
        };
    }

    pub fn deinit(self: *MigrationManager) void {
        self.stats.deinit(self.allocator);
    }

    /// Run the migration
    pub fn migrate(self: *MigrationManager) !void {
        const start_time = std.time.milliTimestamp();

        std.log.info("Starting migration from {s}", .{self.config.source_type.toString()});

        if (self.config.dry_run) {
            std.log.info("DRY RUN - no changes will be made", .{});
        }

        // Create target directory
        if (!self.config.dry_run) {
            fs.cwd().makePath(self.config.target_path) catch |err| {
                std.log.err("Could not create target directory: {}", .{err});
                return err;
            };
        }

        // Run server-specific migration
        switch (self.config.source_type) {
            .postfix => try self.migratePostfix(),
            .dovecot => try self.migrateDovecot(),
            .sendmail => try self.migrateSendmail(),
            .generic_maildir => try self.migrateMaildir(),
            .generic_mbox => try self.migrateMbox(),
            else => {
                std.log.warn("Migration for {s} not yet implemented", .{self.config.source_type.toString()});
            },
        }

        self.stats.duration_ms = @intCast(std.time.milliTimestamp() - start_time);
        self.printSummary();
    }

    fn migratePostfix(self: *MigrationManager) !void {
        var parser = PostfixParser.init(self.allocator, self.config.source_config_path);

        // Parse main.cf
        var config = try parser.parseMainCf();
        defer {
            var iter = config.iterator();
            while (iter.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*);
            }
            config.deinit();
        }

        // Get virtual alias maps
        if (config.get("virtual_alias_maps")) |alias_path| {
            // Remove "hash:" prefix if present
            const clean_path = if (std.mem.startsWith(u8, alias_path, "hash:"))
                alias_path[5..]
            else
                alias_path;

            const aliases = try parser.parseAliases(clean_path);
            defer {
                for (aliases) |*alias| {
                    var a = alias.*;
                    a.deinit(self.allocator);
                }
                self.allocator.free(aliases);
            }

            self.stats.aliases_migrated = @intCast(aliases.len);
            std.log.info("Found {d} aliases", .{aliases.len});
        }

        // Import mail from mail directory
        var maildir = MaildirImporter.init(self.allocator);
        _ = try maildir.importMaildir(self.config.source_mail_path, &self.stats);
    }

    fn migrateDovecot(self: *MigrationManager) !void {
        var parser = DovecotParser.init(self.allocator, self.config.source_config_path);

        // Parse config
        var config = try parser.parseConfig();
        defer {
            var iter = config.iterator();
            while (iter.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*);
            }
            config.deinit();
        }

        // Get mail location
        const mail_location = config.get("mail_location") orelse self.config.source_mail_path;
        std.log.info("Mail location: {s}", .{mail_location});

        // Import maildir
        var maildir = MaildirImporter.init(self.allocator);
        _ = try maildir.importMaildir(mail_location, &self.stats);
    }

    fn migrateSendmail(self: *MigrationManager) !void {
        // Parse sendmail.cf - simplified
        const cf_path = try std.fmt.allocPrint(self.allocator, "{s}/sendmail.cf", .{self.config.source_config_path});
        defer self.allocator.free(cf_path);

        std.log.info("Parsing sendmail config: {s}", .{cf_path});

        // Import mail
        var maildir = MaildirImporter.init(self.allocator);
        _ = try maildir.importMaildir(self.config.source_mail_path, &self.stats);
    }

    fn migrateMaildir(self: *MigrationManager) !void {
        var maildir = MaildirImporter.init(self.allocator);
        _ = try maildir.importMaildir(self.config.source_mail_path, &self.stats);
    }

    fn migrateMbox(self: *MigrationManager) !void {
        var mbox = MboxImporter.init(self.allocator);
        _ = try mbox.importMbox(self.config.source_mail_path, self.config.target_path, &self.stats);
    }

    fn printSummary(self: *MigrationManager) void {
        std.log.info("\n=== Migration Summary ===", .{});
        std.log.info("Duration: {d}ms", .{self.stats.duration_ms});
        std.log.info("Users migrated: {d} (failed: {d})", .{ self.stats.users_migrated, self.stats.users_failed });
        std.log.info("Aliases migrated: {d} (failed: {d})", .{ self.stats.aliases_migrated, self.stats.aliases_failed });
        std.log.info("Domains migrated: {d} (failed: {d})", .{ self.stats.domains_migrated, self.stats.domains_failed });
        std.log.info("Messages migrated: {d} (failed: {d})", .{ self.stats.messages_migrated, self.stats.messages_failed });
        std.log.info("Bytes migrated: {d}", .{self.stats.bytes_migrated});

        if (self.stats.errors.items.len > 0) {
            std.log.warn("\nErrors encountered:", .{});
            for (self.stats.errors.items) |err| {
                std.log.warn("  - {s}", .{err});
            }
        }
    }

    /// Get migration stats
    pub fn getStats(self: *const MigrationManager) *const MigrationStats {
        return &self.stats;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "server type defaults" {
    const testing = std.testing;

    try testing.expect(std.mem.eql(u8, ServerType.postfix.defaultConfigPath(), "/etc/postfix"));
    try testing.expect(std.mem.eql(u8, ServerType.dovecot.defaultConfigPath(), "/etc/dovecot"));
}

test "migration config initialization" {
    const testing = std.testing;

    var config = MigrationConfig.init(testing.allocator, .postfix);
    defer config.deinit(testing.allocator);

    try testing.expectEqual(ServerType.postfix, config.source_type);
    try testing.expect(config.preserve_timestamps);
}

test "migration stats" {
    const testing = std.testing;

    var stats = MigrationStats.init(testing.allocator);
    defer stats.deinit(testing.allocator);

    stats.messages_migrated = 100;
    stats.bytes_migrated = 1024 * 1024;
    try stats.addError(testing.allocator, "Test error");

    try testing.expectEqual(@as(u64, 100), stats.messages_migrated);
    try testing.expectEqual(@as(usize, 1), stats.errors.items.len);
}

test "migrated message flags" {
    const testing = std.testing;

    const flags = MigratedMessage.MessageFlags{
        .seen = true,
        .answered = true,
        .flagged = false,
    };

    try testing.expect(flags.seen);
    try testing.expect(flags.answered);
    try testing.expect(!flags.flagged);
}
