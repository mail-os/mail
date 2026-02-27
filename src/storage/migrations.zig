const std = @import("std");
const time_compat = @import("../core/time_compat.zig");
const database = @import("database.zig");

/// Migration definition
pub const Migration = struct {
    version: u32,
    name: []const u8,
    up_sql: []const u8,
    down_sql: []const u8,
};

/// Migration manager
pub const MigrationManager = struct {
    allocator: std.mem.Allocator,
    db: *database.Database,
    migrations: []const Migration,

    pub fn init(allocator: std.mem.Allocator, db: *database.Database, migrations: []const Migration) MigrationManager {
        return .{
            .allocator = allocator,
            .db = db,
            .migrations = migrations,
        };
    }

    /// Initialize migrations table
    pub fn initMigrationsTable(self: *MigrationManager) !void {
        const schema =
            \\CREATE TABLE IF NOT EXISTS schema_migrations (
            \\    version INTEGER PRIMARY KEY,
            \\    name TEXT NOT NULL,
            \\    applied_at INTEGER NOT NULL
            \\);
        ;

        try self.db.exec(schema);
    }

    /// Get current schema version
    pub fn getCurrentVersion(self: *MigrationManager) !u32 {
        const query = "SELECT MAX(version) FROM schema_migrations";

        var stmt = try self.db.prepare(query);
        defer stmt.finalize();

        if (try stmt.step()) {
            return @intCast(stmt.columnInt64(0));
        }

        return 0;
    }

    /// Check if migration is applied
    fn isMigrationApplied(self: *MigrationManager, version: u32) !bool {
        const query = "SELECT COUNT(*) FROM schema_migrations WHERE version = ?1";

        var stmt = try self.db.prepare(query);
        defer stmt.finalize();

        try stmt.bind(1, @as(i64, @intCast(version)));

        if (try stmt.step()) {
            return stmt.columnInt64(0) > 0;
        }

        return false;
    }

    /// Record migration as applied
    fn recordMigration(self: *MigrationManager, migration: Migration) !void {
        const query =
            \\INSERT INTO schema_migrations (version, name, applied_at)
            \\VALUES (?1, ?2, ?3)
        ;

        var stmt = try self.db.prepare(query);
        defer stmt.finalize();

        try stmt.bind(1, @as(i64, @intCast(migration.version)));
        try stmt.bind(2, migration.name);
        try stmt.bind(3, time_compat.timestamp());

        _ = try stmt.step();
    }

    /// Remove migration record
    fn removeMigration(self: *MigrationManager, version: u32) !void {
        const query = "DELETE FROM schema_migrations WHERE version = ?1";

        var stmt = try self.db.prepare(query);
        defer stmt.finalize();

        try stmt.bind(1, @as(i64, @intCast(version)));
        _ = try stmt.step();
    }

    /// Apply all pending migrations
    pub fn migrateUp(self: *MigrationManager) !void {
        try self.initMigrationsTable();

        const current_version = try self.getCurrentVersion();
        var applied_count: u32 = 0;

        for (self.migrations) |migration| {
            if (migration.version > current_version) {
                // Check if already applied (defensive)
                if (try self.isMigrationApplied(migration.version)) {
                    std.log.warn("Migration {d} ({s}) already applied, skipping", .{ migration.version, migration.name });
                    continue;
                }

                std.log.info("Applying migration {d}: {s}", .{ migration.version, migration.name });

                // Execute migration in transaction
                try self.db.exec("BEGIN TRANSACTION");
                errdefer self.db.exec("ROLLBACK") catch {};

                // Execute migration SQL
                self.db.exec(migration.up_sql) catch |err| {
                    std.log.err("Migration {d} failed: {}", .{ migration.version, err });
                    try self.db.exec("ROLLBACK");
                    return err;
                };

                // Record migration
                try self.recordMigration(migration);

                try self.db.exec("COMMIT");

                applied_count += 1;
                std.log.info("Migration {d} applied successfully", .{migration.version});
            }
        }

        if (applied_count == 0) {
            std.log.info("Database is up to date (version {d})", .{current_version});
        } else {
            std.log.info("Applied {d} migrations", .{applied_count});
        }
    }

    /// Rollback last migration
    pub fn migrateDown(self: *MigrationManager) !void {
        const current_version = try self.getCurrentVersion();

        if (current_version == 0) {
            std.log.info("No migrations to rollback", .{});
            return;
        }

        // Find migration to rollback
        var migration_to_rollback: ?Migration = null;
        for (self.migrations) |migration| {
            if (migration.version == current_version) {
                migration_to_rollback = migration;
                break;
            }
        }

        if (migration_to_rollback) |migration| {
            std.log.info("Rolling back migration {d}: {s}", .{ migration.version, migration.name });

            // Execute rollback in transaction
            try self.db.exec("BEGIN TRANSACTION");
            errdefer self.db.exec("ROLLBACK") catch {};

            self.db.exec(migration.down_sql) catch |err| {
                std.log.err("Rollback of migration {d} failed: {}", .{ migration.version, err });
                try self.db.exec("ROLLBACK");
                return err;
            };

            try self.removeMigration(migration.version);

            try self.db.exec("COMMIT");

            std.log.info("Migration {d} rolled back successfully", .{migration.version});
        } else {
            std.log.err("Migration {d} not found in migration list", .{current_version});
            return error.MigrationNotFound;
        }
    }

    /// Rollback to specific version
    pub fn migrateTo(self: *MigrationManager, target_version: u32) !void {
        const current_version = try self.getCurrentVersion();

        if (target_version == current_version) {
            std.log.info("Already at version {d}", .{target_version});
            return;
        }

        if (target_version > current_version) {
            // Migrate up to target version
            for (self.migrations) |migration| {
                if (migration.version > current_version and migration.version <= target_version) {
                    std.log.info("Applying migration {d}: {s}", .{ migration.version, migration.name });

                    try self.db.exec("BEGIN TRANSACTION");
                    errdefer self.db.exec("ROLLBACK") catch {};

                    try self.db.exec(migration.up_sql);
                    try self.recordMigration(migration);

                    try self.db.exec("COMMIT");
                }
            }
        } else {
            // Migrate down to target version
            var i = self.migrations.len;
            while (i > 0) {
                i -= 1;
                const migration = self.migrations[i];

                if (migration.version > target_version and migration.version <= current_version) {
                    std.log.info("Rolling back migration {d}: {s}", .{ migration.version, migration.name });

                    try self.db.exec("BEGIN TRANSACTION");
                    errdefer self.db.exec("ROLLBACK") catch {};

                    try self.db.exec(migration.down_sql);
                    try self.removeMigration(migration.version);

                    try self.db.exec("COMMIT");
                }
            }
        }

        const new_version = try self.getCurrentVersion();
        std.log.info("Migrated to version {d}", .{new_version});
    }

    /// Get migration history
    pub fn getHistory(self: *MigrationManager, allocator: std.mem.Allocator) ![]MigrationRecord {
        const query =
            \\SELECT version, name, applied_at
            \\FROM schema_migrations
            \\ORDER BY version ASC
        ;

        var stmt = try self.db.prepare(query);
        defer stmt.finalize();

        // Count records first
        var count: usize = 0;
        while (try stmt.step()) {
            count += 1;
        }

        // Reset statement
        try stmt.reset();

        // Allocate array
        const records = try allocator.alloc(MigrationRecord, count);
        errdefer allocator.free(records);

        // Fill array
        var index: usize = 0;
        while (try stmt.step()) {
            records[index] = .{
                .version = @intCast(stmt.columnInt64(0)),
                .name = try allocator.dupe(u8, stmt.columnText(1)),
                .applied_at = stmt.columnInt64(2),
            };
            index += 1;
        }

        return records;
    }

    /// Validate migration order
    pub fn validate(self: *MigrationManager) !void {
        if (self.migrations.len == 0) return;

        var prev_version: u32 = 0;
        for (self.migrations) |migration| {
            if (migration.version <= prev_version) {
                std.log.err("Invalid migration order: {d} after {d}", .{ migration.version, prev_version });
                return error.InvalidMigrationOrder;
            }
            prev_version = migration.version;
        }

        std.log.info("Migration order validated successfully", .{});
    }
};

pub const MigrationRecord = struct {
    version: u32,
    name: []const u8,
    applied_at: i64,

    pub fn deinit(self: *MigrationRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
    }
};

/// Example migrations for the SMTP server
pub const smtp_migrations = [_]Migration{
    .{
        .version = 1,
        .name = "create_users_table",
        .up_sql =
        \\CREATE TABLE IF NOT EXISTS users (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    username TEXT UNIQUE NOT NULL,
        \\    password_hash TEXT NOT NULL,
        \\    email TEXT UNIQUE NOT NULL,
        \\    enabled INTEGER DEFAULT 1,
        \\    created_at INTEGER NOT NULL,
        \\    updated_at INTEGER NOT NULL
        \\);
        \\CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
        \\CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        ,
        .down_sql =
        \\DROP INDEX IF EXISTS idx_users_email;
        \\DROP INDEX IF EXISTS idx_users_username;
        \\DROP TABLE IF EXISTS users;
        ,
    },
    .{
        .version = 2,
        .name = "add_user_quotas",
        .up_sql =
        \\ALTER TABLE users ADD COLUMN quota_limit INTEGER DEFAULT 0;
        \\ALTER TABLE users ADD COLUMN quota_used INTEGER DEFAULT 0;
        \\ALTER TABLE users ADD COLUMN attachment_max_size INTEGER DEFAULT 0;
        \\ALTER TABLE users ADD COLUMN attachment_max_total INTEGER DEFAULT 0;
        ,
        .down_sql =
        \\-- SQLite doesn't support DROP COLUMN before 3.35
        \\-- Create a backup table and recreate without the columns
        \\CREATE TABLE users_backup AS SELECT id, username, password_hash, email, enabled, created_at, updated_at FROM users;
        \\DROP TABLE users;
        \\ALTER TABLE users_backup RENAME TO users;
        \\CREATE INDEX idx_users_username ON users(username);
        \\CREATE INDEX idx_users_email ON users(email);
        ,
    },
    .{
        .version = 3,
        .name = "create_message_queue_table",
        .up_sql =
        \\CREATE TABLE IF NOT EXISTS message_queue (
        \\    id TEXT PRIMARY KEY,
        \\    from_addr TEXT NOT NULL,
        \\    to_addr TEXT NOT NULL,
        \\    message_data TEXT NOT NULL,
        \\    status TEXT NOT NULL,
        \\    attempts INTEGER NOT NULL DEFAULT 0,
        \\    max_attempts INTEGER NOT NULL DEFAULT 5,
        \\    next_retry INTEGER NOT NULL,
        \\    created_at INTEGER NOT NULL,
        \\    updated_at INTEGER NOT NULL,
        \\    error_message TEXT
        \\);
        \\CREATE INDEX IF NOT EXISTS idx_queue_status ON message_queue(status);
        \\CREATE INDEX IF NOT EXISTS idx_queue_next_retry ON message_queue(next_retry);
        ,
        .down_sql =
        \\DROP INDEX IF EXISTS idx_queue_next_retry;
        \\DROP INDEX IF EXISTS idx_queue_status;
        \\DROP TABLE IF EXISTS message_queue;
        ,
    },
    .{
        .version = 4,
        .name = "add_soft_delete_columns",
        .up_sql =
        \\ALTER TABLE messages ADD COLUMN deleted_at INTEGER DEFAULT NULL;
        \\ALTER TABLE messages ADD COLUMN deleted_by TEXT DEFAULT NULL;
        \\CREATE INDEX IF NOT EXISTS idx_messages_deleted_at ON messages(deleted_at);
        ,
        .down_sql =
        \\DROP INDEX IF EXISTS idx_messages_deleted_at;
        \\-- SQLite < 3.35 doesn't support DROP COLUMN; recreate table without soft-delete columns
        \\CREATE TABLE messages_backup AS SELECT id, message_id, email, sender, recipients, subject, body, headers, size, received_at, flags, folder FROM messages;
        \\DROP TABLE messages;
        \\ALTER TABLE messages_backup RENAME TO messages;
        \\CREATE INDEX IF NOT EXISTS idx_messages_email ON messages(email);
        \\CREATE INDEX IF NOT EXISTS idx_messages_message_id ON messages(message_id);
        \\CREATE INDEX IF NOT EXISTS idx_messages_received_at ON messages(received_at);
        \\CREATE INDEX IF NOT EXISTS idx_messages_folder ON messages(folder);
        \\CREATE INDEX IF NOT EXISTS idx_messages_flags ON messages(flags);
        ,
    },
};

test "migration manager basic operations" {
    const testing = std.testing;

    // Create test database
    var db = try database.Database.init(testing.allocator, ":memory:");
    defer db.deinit();

    const test_migrations = [_]Migration{
        .{
            .version = 1,
            .name = "create_test_table",
            .up_sql = "CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT);",
            .down_sql = "DROP TABLE test;",
        },
        .{
            .version = 2,
            .name = "add_test_column",
            .up_sql = "ALTER TABLE test ADD COLUMN value INTEGER DEFAULT 0;",
            .down_sql = "-- Rollback handled by table recreation",
        },
    };

    var manager = MigrationManager.init(testing.allocator, &db, &test_migrations);

    // Validate migrations
    try manager.validate();

    // Apply migrations
    try manager.migrateUp();

    // Check version
    const version = try manager.getCurrentVersion();
    try testing.expectEqual(@as(u32, 2), version);

    // Rollback one migration
    try manager.migrateDown();

    const new_version = try manager.getCurrentVersion();
    try testing.expectEqual(@as(u32, 1), new_version);
}
