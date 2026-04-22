const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");
const sqlite = @import("sqlite");

pub const DatabaseError = error{
    OpenFailed,
    ExecFailed,
    PrepareFailed,
    StepFailed,
    BindFailed,
    ColumnFailed,
    NotFound,
    AlreadyExists,
};

pub const Statement = struct {
    stmt: *sqlite.sqlite3_stmt,
    allocator: std.mem.Allocator,

    pub fn finalize(self: Statement) void {
        _ = sqlite.sqlite3_finalize(self.stmt);
    }

    pub fn reset(self: Statement) !void {
        const rc = sqlite.sqlite3_reset(self.stmt);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.StepFailed;
        }
    }

    pub fn bind(self: Statement, index: usize, value: anytype) !void {
        const T = @TypeOf(value);
        const rc = switch (@typeInfo(T)) {
            .int => sqlite.sqlite3_bind_int64(self.stmt, @intCast(index), @intCast(value)),
            .comptime_int => sqlite.sqlite3_bind_int64(self.stmt, @intCast(index), @intCast(value)),
            .float => sqlite.sqlite3_bind_double(self.stmt, @intCast(index), @floatCast(value)),
            .comptime_float => sqlite.sqlite3_bind_double(self.stmt, @intCast(index), @floatCast(value)),
            .pointer => |ptr_info| blk: {
                if (ptr_info.size == .slice and ptr_info.child == u8) {
                    const text_z = try self.allocator.dupeZ(u8, value);
                    defer self.allocator.free(text_z);
                    break :blk sqlite.sqlite3_bind_text(self.stmt, @intCast(index), text_z.ptr, -1, null);
                }
                @compileError("Unsupported pointer type for binding");
            },
            else => @compileError("Unsupported type for binding"),
        };

        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.BindFailed;
        }
    }

    pub fn step(self: Statement) !bool {
        const rc = sqlite.sqlite3_step(self.stmt);
        if (rc == sqlite.SQLITE_ROW) {
            return true;
        } else if (rc == sqlite.SQLITE_DONE) {
            return false;
        } else {
            return DatabaseError.StepFailed;
        }
    }

    pub fn columnInt64(self: Statement, index: usize) i64 {
        return sqlite.sqlite3_column_int64(self.stmt, @intCast(index));
    }

    pub fn columnDouble(self: Statement, index: usize) f64 {
        return sqlite.sqlite3_column_double(self.stmt, @intCast(index));
    }

    pub fn columnText(self: Statement, index: usize) []const u8 {
        const text_ptr = sqlite.sqlite3_column_text(self.stmt, @intCast(index));
        if (text_ptr) |ptr| {
            const len = sqlite.sqlite3_column_bytes(self.stmt, @intCast(index));
            return ptr[0..@intCast(len)];
        }
        return &[_]u8{};
    }

    /// Check if column is NULL
    pub fn columnIsNull(self: Statement, index: usize) bool {
        const column_type = sqlite.sqlite3_column_type(self.stmt, @intCast(index));
        return column_type == sqlite.SQLITE_NULL;
    }

    /// Get column as Option type - returns null if SQL NULL
    pub fn columnTextOpt(self: Statement, index: usize) ?[]const u8 {
        if (self.columnIsNull(index)) {
            return null;
        }
        const text_ptr = sqlite.sqlite3_column_text(self.stmt, @intCast(index));
        if (text_ptr) |ptr| {
            const len = sqlite.sqlite3_column_bytes(self.stmt, @intCast(index));
            return ptr[0..@intCast(len)];
        }
        return null;
    }

    /// Get column as Option type - returns null if SQL NULL
    pub fn columnInt64Opt(self: Statement, index: usize) ?i64 {
        if (self.columnIsNull(index)) {
            return null;
        }
        return sqlite.sqlite3_column_int64(self.stmt, @intCast(index));
    }

    /// Get column as Option type - returns null if SQL NULL
    pub fn columnDoubleOpt(self: Statement, index: usize) ?f64 {
        if (self.columnIsNull(index)) {
            return null;
        }
        return sqlite.sqlite3_column_double(self.stmt, @intCast(index));
    }

    /// Bind NULL value
    pub fn bindNull(self: Statement, index: usize) !void {
        const rc = sqlite.sqlite3_bind_null(self.stmt, @intCast(index));
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.BindFailed;
        }
    }

    /// Bind optional value - NULL if none
    pub fn bindOpt(self: Statement, index: usize, value: anytype) !void {
        const T = @TypeOf(value);
        const type_info = @typeInfo(T);

        if (type_info == .optional) {
            if (value) |v| {
                try self.bind(index, v);
            } else {
                try self.bindNull(index);
            }
        } else {
            @compileError("bindOpt requires an optional type");
        }
    }
};

pub const User = struct {
    id: i64,
    username: []const u8,
    password_hash: []const u8,
    email: []const u8,
    enabled: bool,
    created_at: i64,
    updated_at: i64,
    digest_ha1: ?[]const u8 = null, // MD5(username:realm:password) for Digest auth

    pub fn deinit(self: *User, allocator: std.mem.Allocator) void {
        allocator.free(self.username);
        allocator.free(self.password_hash);
        allocator.free(self.email);
        if (self.digest_ha1) |ha1| allocator.free(ha1);
    }
};

pub const Database = struct {
    db: ?*sqlite.sqlite3,
    allocator: std.mem.Allocator,
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator, db_path: []const u8) !Database {
        var db: ?*sqlite.sqlite3 = null;

        // Add null terminator for C string
        const path_z = try allocator.dupeZ(u8, db_path);
        defer allocator.free(path_z);

        const rc = sqlite.sqlite3_open(path_z.ptr, &db);
        if (rc != sqlite.SQLITE_OK) {
            if (db) |d| {
                _ = sqlite.sqlite3_close(d);
            }
            return DatabaseError.OpenFailed;
        }

        var database = Database{
            .db = db,
            .allocator = allocator,
            .mutex = mutex_compat.Mutex{},
        };

        // Enable WAL mode for better concurrent read performance
        try database.enableWALMode();

        // Initialize schema
        try database.initSchema();

        return database;
    }

    pub fn deinit(self: *Database) void {
        if (self.db) |db| {
            _ = sqlite.sqlite3_close(db);
        }
    }

    /// Enable Write-Ahead Logging (WAL) mode for better concurrent read performance
    /// WAL allows readers to access the database while a write is in progress
    fn enableWALMode(self: *Database) !void {
        // Enable WAL mode
        const wal_pragma = "PRAGMA journal_mode=WAL;";
        try self.exec(wal_pragma);

        // Set synchronous mode to NORMAL for better performance with WAL
        // NORMAL is safe with WAL mode and provides good durability guarantees
        const sync_pragma = "PRAGMA synchronous=NORMAL;";
        try self.exec(sync_pragma);

        // Set a reasonable busy timeout (5 seconds)
        const timeout_pragma = "PRAGMA busy_timeout=5000;";
        try self.exec(timeout_pragma);
    }

    fn initSchema(self: *Database) !void {
        const schema =
            \\CREATE TABLE IF NOT EXISTS users (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    username TEXT UNIQUE NOT NULL,
            \\    password_hash TEXT NOT NULL,
            \\    email TEXT UNIQUE NOT NULL,
            \\    enabled INTEGER DEFAULT 1,
            \\    created_at INTEGER NOT NULL,
            \\    updated_at INTEGER NOT NULL,
            \\    quota_limit INTEGER DEFAULT 0,
            \\    quota_used INTEGER DEFAULT 0,
            \\    attachment_max_size INTEGER DEFAULT 0,
            \\    attachment_max_total INTEGER DEFAULT 0
            \\);
            \\
            \\CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            \\CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        ;

        try self.exec(schema);

        // Migration: Add quota and attachment limit columns to existing tables
        const migration =
            \\ALTER TABLE users ADD COLUMN quota_limit INTEGER DEFAULT 0;
            \\ALTER TABLE users ADD COLUMN quota_used INTEGER DEFAULT 0;
            \\ALTER TABLE users ADD COLUMN attachment_max_size INTEGER DEFAULT 0;
            \\ALTER TABLE users ADD COLUMN attachment_max_total INTEGER DEFAULT 0;
        ;

        // Try to run migration, ignore errors if columns already exist
        self.exec(migration) catch {};

        // IMAP UID persistence tables
        try self.exec(
            \\CREATE TABLE IF NOT EXISTS imap_mailboxes (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    username TEXT NOT NULL,
            \\    mailbox TEXT NOT NULL,
            \\    uidvalidity INTEGER NOT NULL,
            \\    uidnext INTEGER NOT NULL DEFAULT 1,
            \\    UNIQUE(username, mailbox)
            \\);
            \\CREATE TABLE IF NOT EXISTS imap_uids (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    username TEXT NOT NULL,
            \\    mailbox TEXT NOT NULL,
            \\    filename TEXT NOT NULL,
            \\    uid INTEGER NOT NULL,
            \\    UNIQUE(username, mailbox, filename),
            \\    UNIQUE(username, mailbox, uid)
            \\);
            \\CREATE INDEX IF NOT EXISTS idx_imap_uids_lookup ON imap_uids(username, mailbox);
            \\CREATE INDEX IF NOT EXISTS idx_imap_mailboxes_lookup ON imap_mailboxes(username, mailbox);
        );
    }

    pub fn exec(self: *Database, sql: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var errmsg: [*c]u8 = null;
        const rc = sqlite.sqlite3_exec(self.db, sql_z.ptr, null, null, @ptrCast(&errmsg));

        if (rc != sqlite.SQLITE_OK) {
            if (errmsg) |msg| {
                defer sqlite.sqlite3_free(msg);
            }
            return DatabaseError.ExecFailed;
        }
    }

    pub fn prepare(self: *Database, sql: []const u8) !Statement {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        const rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }

        return Statement{
            .stmt = stmt.?,
            .allocator = self.allocator,
        };
    }

    pub fn createUser(
        self: *Database,
        username: []const u8,
        password_hash: []const u8,
        email: []const u8,
    ) !i64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql =
            \\INSERT INTO users (username, password_hash, email, created_at, updated_at)
            \\VALUES (?1, ?2, ?3, ?4, ?5)
        ;

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const username_z = try self.allocator.dupeZ(u8, username);
        defer self.allocator.free(username_z);
        const password_z = try self.allocator.dupeZ(u8, password_hash);
        defer self.allocator.free(password_z);
        const email_z = try self.allocator.dupeZ(u8, email);
        defer self.allocator.free(email_z);

        const now = time_compat.timestamp();

        _ = sqlite.sqlite3_bind_text(stmt, 1, username_z.ptr, -1, null);
        _ = sqlite.sqlite3_bind_text(stmt, 2, password_z.ptr, -1, null);
        _ = sqlite.sqlite3_bind_text(stmt, 3, email_z.ptr, -1, null);
        _ = sqlite.sqlite3_bind_int64(stmt, 4, now);
        _ = sqlite.sqlite3_bind_int64(stmt, 5, now);

        rc = sqlite.sqlite3_step(stmt);
        if (rc != sqlite.SQLITE_DONE) {
            if (rc == sqlite.SQLITE_CONSTRAINT) {
                return DatabaseError.AlreadyExists;
            }
            return DatabaseError.StepFailed;
        }

        return sqlite.sqlite3_last_insert_rowid(self.db);
    }

    pub fn getUserByUsername(self: *Database, username: []const u8) !User {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql =
            \\SELECT id, username, password_hash, email, enabled, created_at, updated_at, digest_ha1
            \\FROM users
            \\WHERE username = ?1
        ;

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const username_z = try self.allocator.dupeZ(u8, username);
        defer self.allocator.free(username_z);

        _ = sqlite.sqlite3_bind_text(stmt, 1, username_z.ptr, -1, null);

        rc = sqlite.sqlite3_step(stmt);
        if (rc != sqlite.SQLITE_ROW) {
            return DatabaseError.NotFound;
        }

        const id = sqlite.sqlite3_column_int64(stmt, 0);
        const username_ptr = sqlite.sqlite3_column_text(stmt, 1);
        const password_ptr = sqlite.sqlite3_column_text(stmt, 2);
        const email_ptr = sqlite.sqlite3_column_text(stmt, 3);
        const enabled = sqlite.sqlite3_column_int(stmt, 4) != 0;
        const created_at = sqlite.sqlite3_column_int64(stmt, 5);
        const updated_at = sqlite.sqlite3_column_int64(stmt, 6);

        // Get digest_ha1 (may be NULL)
        const digest_ha1_ptr = sqlite.sqlite3_column_text(stmt, 7);
        const digest_ha1: ?[]const u8 = if (digest_ha1_ptr != null)
            try self.allocator.dupe(u8, std.mem.span(digest_ha1_ptr))
        else
            null;

        return User{
            .id = id,
            .username = try self.allocator.dupe(u8, std.mem.span(username_ptr)),
            .password_hash = try self.allocator.dupe(u8, std.mem.span(password_ptr)),
            .email = try self.allocator.dupe(u8, std.mem.span(email_ptr)),
            .enabled = enabled,
            .created_at = created_at,
            .updated_at = updated_at,
            .digest_ha1 = digest_ha1,
        };
    }

    pub fn updateUserPassword(self: *Database, username: []const u8, new_password_hash: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql =
            \\UPDATE users
            \\SET password_hash = ?1, updated_at = ?2
            \\WHERE username = ?3
        ;

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const password_z = try self.allocator.dupeZ(u8, new_password_hash);
        defer self.allocator.free(password_z);
        const username_z = try self.allocator.dupeZ(u8, username);
        defer self.allocator.free(username_z);

        const now = time_compat.timestamp();

        _ = sqlite.sqlite3_bind_text(stmt, 1, password_z.ptr, -1, null);
        _ = sqlite.sqlite3_bind_int64(stmt, 2, now);
        _ = sqlite.sqlite3_bind_text(stmt, 3, username_z.ptr, -1, null);

        rc = sqlite.sqlite3_step(stmt);
        if (rc != sqlite.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }
    }

    pub fn deleteUser(self: *Database, username: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql = "DELETE FROM users WHERE username = ?1";

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const username_z = try self.allocator.dupeZ(u8, username);
        defer self.allocator.free(username_z);

        _ = sqlite.sqlite3_bind_text(stmt, 1, username_z.ptr, -1, null);

        rc = sqlite.sqlite3_step(stmt);
        if (rc != sqlite.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }
    }

    pub fn setUserEnabled(self: *Database, username: []const u8, enabled: bool) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql =
            \\UPDATE users
            \\SET enabled = ?1, updated_at = ?2
            \\WHERE username = ?3
        ;

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const username_z = try self.allocator.dupeZ(u8, username);
        defer self.allocator.free(username_z);

        const now = time_compat.timestamp();

        _ = sqlite.sqlite3_bind_int(stmt, 1, if (enabled) 1 else 0);
        _ = sqlite.sqlite3_bind_int64(stmt, 2, now);
        _ = sqlite.sqlite3_bind_text(stmt, 3, username_z.ptr, -1, null);

        rc = sqlite.sqlite3_step(stmt);
        if (rc != sqlite.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }
    }

    /// Get all users from the database
    pub fn getAllUsers(self: *Database) ![]User {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql =
            \\SELECT id, username, password_hash, email, enabled, created_at, updated_at
            \\FROM users
            \\ORDER BY username ASC
        ;

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        var users = std.ArrayList(User).init(self.allocator);
        errdefer {
            for (users.items) |*user| {
                user.deinit(self.allocator);
            }
            users.deinit();
        }

        while (true) {
            rc = sqlite.sqlite3_step(stmt);
            if (rc == sqlite.SQLITE_DONE) break;
            if (rc != sqlite.SQLITE_ROW) {
                return DatabaseError.StepFailed;
            }

            const id = sqlite.sqlite3_column_int64(stmt, 0);
            const username_ptr = sqlite.sqlite3_column_text(stmt, 1);
            const password_ptr = sqlite.sqlite3_column_text(stmt, 2);
            const email_ptr = sqlite.sqlite3_column_text(stmt, 3);
            const enabled = sqlite.sqlite3_column_int(stmt, 4) != 0;
            const created_at = sqlite.sqlite3_column_int64(stmt, 5);
            const updated_at = sqlite.sqlite3_column_int64(stmt, 6);

            try users.append(User{
                .id = id,
                .username = try self.allocator.dupe(u8, std.mem.span(username_ptr)),
                .password_hash = try self.allocator.dupe(u8, std.mem.span(password_ptr)),
                .email = try self.allocator.dupe(u8, std.mem.span(email_ptr)),
                .enabled = enabled,
                .created_at = created_at,
                .updated_at = updated_at,
            });
        }

        return users.toOwnedSlice();
    }

    /// Update user email
    pub fn updateUserEmail(self: *Database, username: []const u8, new_email: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql =
            \\UPDATE users
            \\SET email = ?1, updated_at = ?2
            \\WHERE username = ?3
        ;

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const email_z = try self.allocator.dupeZ(u8, new_email);
        defer self.allocator.free(email_z);
        const username_z = try self.allocator.dupeZ(u8, username);
        defer self.allocator.free(username_z);

        const now = time_compat.timestamp();

        _ = sqlite.sqlite3_bind_text(stmt, 1, email_z.ptr, -1, null);
        _ = sqlite.sqlite3_bind_int64(stmt, 2, now);
        _ = sqlite.sqlite3_bind_text(stmt, 3, username_z.ptr, -1, null);

        rc = sqlite.sqlite3_step(stmt);
        if (rc != sqlite.SQLITE_DONE) {
            if (rc == sqlite.SQLITE_CONSTRAINT) {
                return DatabaseError.AlreadyExists;
            }
            return DatabaseError.StepFailed;
        }
    }

    // ==================== Audit Trail Operations ====================

    /// Initialize audit log table
    pub fn initAuditTable(self: *Database) !void {
        const sql =
            \\CREATE TABLE IF NOT EXISTS audit_log (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    timestamp INTEGER NOT NULL,
            \\    action TEXT NOT NULL,
            \\    actor TEXT NOT NULL,
            \\    target TEXT,
            \\    target_type TEXT,
            \\    ip_address TEXT,
            \\    details TEXT,
            \\    severity TEXT NOT NULL
            \\);
            \\CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
            \\CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
            \\CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor);
        ;

        self.mutex.lock();
        defer self.mutex.unlock();

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var errmsg: [*c]u8 = null;
        const rc = sqlite.sqlite3_exec(self.db, sql_z.ptr, null, null, &errmsg);
        if (rc != sqlite.SQLITE_OK) {
            if (errmsg != null) {
                sqlite.sqlite3_free(errmsg);
            }
            return DatabaseError.InitFailed;
        }
    }

    /// Insert an audit log entry
    pub fn insertAuditEntry(
        self: *Database,
        timestamp: i64,
        action: []const u8,
        actor: []const u8,
        target: ?[]const u8,
        target_type: ?[]const u8,
        ip_address: ?[]const u8,
        details: ?[]const u8,
        severity: []const u8,
    ) !i64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql =
            \\INSERT INTO audit_log (timestamp, action, actor, target, target_type, ip_address, details, severity)
            \\VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        ;

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        _ = sqlite.sqlite3_bind_int64(stmt, 1, timestamp);

        const action_z = try self.allocator.dupeZ(u8, action);
        defer self.allocator.free(action_z);
        _ = sqlite.sqlite3_bind_text(stmt, 2, action_z.ptr, -1, null);

        const actor_z = try self.allocator.dupeZ(u8, actor);
        defer self.allocator.free(actor_z);
        _ = sqlite.sqlite3_bind_text(stmt, 3, actor_z.ptr, -1, null);

        if (target) |t| {
            const target_z = try self.allocator.dupeZ(u8, t);
            defer self.allocator.free(target_z);
            _ = sqlite.sqlite3_bind_text(stmt, 4, target_z.ptr, -1, null);
        } else {
            _ = sqlite.sqlite3_bind_null(stmt, 4);
        }

        if (target_type) |tt| {
            const tt_z = try self.allocator.dupeZ(u8, tt);
            defer self.allocator.free(tt_z);
            _ = sqlite.sqlite3_bind_text(stmt, 5, tt_z.ptr, -1, null);
        } else {
            _ = sqlite.sqlite3_bind_null(stmt, 5);
        }

        if (ip_address) |ip| {
            const ip_z = try self.allocator.dupeZ(u8, ip);
            defer self.allocator.free(ip_z);
            _ = sqlite.sqlite3_bind_text(stmt, 6, ip_z.ptr, -1, null);
        } else {
            _ = sqlite.sqlite3_bind_null(stmt, 6);
        }

        if (details) |d| {
            const details_z = try self.allocator.dupeZ(u8, d);
            defer self.allocator.free(details_z);
            _ = sqlite.sqlite3_bind_text(stmt, 7, details_z.ptr, -1, null);
        } else {
            _ = sqlite.sqlite3_bind_null(stmt, 7);
        }

        const severity_z = try self.allocator.dupeZ(u8, severity);
        defer self.allocator.free(severity_z);
        _ = sqlite.sqlite3_bind_text(stmt, 8, severity_z.ptr, -1, null);

        rc = sqlite.sqlite3_step(stmt);
        if (rc != sqlite.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }

        return sqlite.sqlite3_last_insert_rowid(self.db);
    }

    /// Audit entry structure for queries
    pub const AuditLogEntry = struct {
        id: i64,
        timestamp: i64,
        action: []const u8,
        actor: []const u8,
        target: ?[]const u8,
        target_type: ?[]const u8,
        ip_address: ?[]const u8,
        details: ?[]const u8,
        severity: []const u8,

        pub fn deinit(self: *AuditLogEntry, allocator: std.mem.Allocator) void {
            allocator.free(self.action);
            allocator.free(self.actor);
            if (self.target) |t| allocator.free(t);
            if (self.target_type) |tt| allocator.free(tt);
            if (self.ip_address) |ip| allocator.free(ip);
            if (self.details) |d| allocator.free(d);
            allocator.free(self.severity);
        }
    };

    /// Get recent audit log entries
    pub fn getAuditEntries(self: *Database, limit: usize, offset: usize) ![]AuditLogEntry {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql =
            \\SELECT id, timestamp, action, actor, target, target_type, ip_address, details, severity
            \\FROM audit_log
            \\ORDER BY timestamp DESC
            \\LIMIT ?1 OFFSET ?2
        ;

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        _ = sqlite.sqlite3_bind_int64(stmt, 1, @intCast(limit));
        _ = sqlite.sqlite3_bind_int64(stmt, 2, @intCast(offset));

        var entries = std.ArrayList(AuditLogEntry).init(self.allocator);
        errdefer {
            for (entries.items) |*entry| {
                entry.deinit(self.allocator);
            }
            entries.deinit();
        }

        while (true) {
            rc = sqlite.sqlite3_step(stmt);
            if (rc == sqlite.SQLITE_DONE) break;
            if (rc != sqlite.SQLITE_ROW) {
                return DatabaseError.StepFailed;
            }

            const id = sqlite.sqlite3_column_int64(stmt, 0);
            const timestamp = sqlite.sqlite3_column_int64(stmt, 1);
            const action_ptr = sqlite.sqlite3_column_text(stmt, 2);
            const actor_ptr = sqlite.sqlite3_column_text(stmt, 3);
            const target_ptr = sqlite.sqlite3_column_text(stmt, 4);
            const target_type_ptr = sqlite.sqlite3_column_text(stmt, 5);
            const ip_ptr = sqlite.sqlite3_column_text(stmt, 6);
            const details_ptr = sqlite.sqlite3_column_text(stmt, 7);
            const severity_ptr = sqlite.sqlite3_column_text(stmt, 8);

            try entries.append(AuditLogEntry{
                .id = id,
                .timestamp = timestamp,
                .action = try self.allocator.dupe(u8, std.mem.span(action_ptr)),
                .actor = try self.allocator.dupe(u8, std.mem.span(actor_ptr)),
                .target = if (target_ptr != null) try self.allocator.dupe(u8, std.mem.span(target_ptr)) else null,
                .target_type = if (target_type_ptr != null) try self.allocator.dupe(u8, std.mem.span(target_type_ptr)) else null,
                .ip_address = if (ip_ptr != null) try self.allocator.dupe(u8, std.mem.span(ip_ptr)) else null,
                .details = if (details_ptr != null) try self.allocator.dupe(u8, std.mem.span(details_ptr)) else null,
                .severity = try self.allocator.dupe(u8, std.mem.span(severity_ptr)),
            });
        }

        return entries.toOwnedSlice();
    }

    /// Get audit entries count
    pub fn getAuditCount(self: *Database) !i64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql = "SELECT COUNT(*) FROM audit_log";

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        rc = sqlite.sqlite3_step(stmt);
        if (rc != sqlite.SQLITE_ROW) {
            return 0;
        }

        return sqlite.sqlite3_column_int64(stmt, 0);
    }

    /// Prune old audit entries
    pub fn pruneAuditEntries(self: *Database, before_timestamp: i64) !i64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql = "DELETE FROM audit_log WHERE timestamp < ?1";

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        _ = sqlite.sqlite3_bind_int64(stmt, 1, before_timestamp);

        rc = sqlite.sqlite3_step(stmt);
        if (rc != sqlite.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }

        return sqlite.sqlite3_changes(self.db);
    }

    // ============================================
    // Password Reset Token Operations
    // ============================================

    /// Initialize password reset tokens table
    pub fn initPasswordResetTable(self: *Database) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql =
            \\CREATE TABLE IF NOT EXISTS password_reset_tokens (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    username TEXT NOT NULL,
            \\    token_hash TEXT NOT NULL UNIQUE,
            \\    created_at INTEGER NOT NULL,
            \\    expires_at INTEGER NOT NULL,
            \\    used INTEGER DEFAULT 0,
            \\    used_at INTEGER,
            \\    ip_address TEXT,
            \\    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
            \\);
            \\CREATE INDEX IF NOT EXISTS idx_reset_token_hash ON password_reset_tokens(token_hash);
            \\CREATE INDEX IF NOT EXISTS idx_reset_username ON password_reset_tokens(username);
            \\CREATE INDEX IF NOT EXISTS idx_reset_expires ON password_reset_tokens(expires_at);
        ;

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var err_msg: [*c]u8 = null;
        const rc = sqlite.sqlite3_exec(self.db, sql_z.ptr, null, null, &err_msg);
        if (rc != sqlite.SQLITE_OK) {
            if (err_msg != null) {
                sqlite.sqlite3_free(err_msg);
            }
            return DatabaseError.ExecFailed;
        }
    }

    /// Password reset token entry
    pub const ResetTokenEntry = struct {
        id: i64,
        username: []const u8,
        token_hash: []const u8,
        created_at: i64,
        expires_at: i64,
        used: bool,
        used_at: ?i64,
        ip_address: ?[]const u8,

        pub fn deinit(self: *ResetTokenEntry, allocator: std.mem.Allocator) void {
            allocator.free(self.username);
            allocator.free(self.token_hash);
            if (self.ip_address) |ip| allocator.free(ip);
        }
    };

    /// Insert a new password reset token
    pub fn insertResetToken(
        self: *Database,
        username: []const u8,
        token_hash: []const u8,
        created_at: i64,
        expires_at: i64,
        ip_address: ?[]const u8,
    ) !i64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql =
            \\INSERT INTO password_reset_tokens (username, token_hash, created_at, expires_at, ip_address)
            \\VALUES (?1, ?2, ?3, ?4, ?5)
        ;

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const username_z = try self.allocator.dupeZ(u8, username);
        defer self.allocator.free(username_z);
        _ = sqlite.sqlite3_bind_text(stmt, 1, username_z.ptr, -1, null);

        const hash_z = try self.allocator.dupeZ(u8, token_hash);
        defer self.allocator.free(hash_z);
        _ = sqlite.sqlite3_bind_text(stmt, 2, hash_z.ptr, -1, null);

        _ = sqlite.sqlite3_bind_int64(stmt, 3, created_at);
        _ = sqlite.sqlite3_bind_int64(stmt, 4, expires_at);

        if (ip_address) |ip| {
            const ip_z = try self.allocator.dupeZ(u8, ip);
            defer self.allocator.free(ip_z);
            _ = sqlite.sqlite3_bind_text(stmt, 5, ip_z.ptr, -1, null);
        } else {
            _ = sqlite.sqlite3_bind_null(stmt, 5);
        }

        rc = sqlite.sqlite3_step(stmt);
        if (rc != sqlite.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }

        return sqlite.sqlite3_last_insert_rowid(self.db);
    }

    /// Get a reset token by its hash
    pub fn getResetTokenByHash(self: *Database, token_hash: []const u8) !ResetTokenEntry {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql =
            \\SELECT id, username, token_hash, created_at, expires_at, used, used_at, ip_address
            \\FROM password_reset_tokens
            \\WHERE token_hash = ?1
        ;

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const hash_z = try self.allocator.dupeZ(u8, token_hash);
        defer self.allocator.free(hash_z);
        _ = sqlite.sqlite3_bind_text(stmt, 1, hash_z.ptr, -1, null);

        rc = sqlite.sqlite3_step(stmt);
        if (rc != sqlite.SQLITE_ROW) {
            return DatabaseError.NotFound;
        }

        const id = sqlite.sqlite3_column_int64(stmt, 0);
        const username_ptr = sqlite.sqlite3_column_text(stmt, 1);
        const hash_ptr = sqlite.sqlite3_column_text(stmt, 2);
        const created_at = sqlite.sqlite3_column_int64(stmt, 3);
        const expires_at = sqlite.sqlite3_column_int64(stmt, 4);
        const used = sqlite.sqlite3_column_int64(stmt, 5) != 0;
        const used_at_type = sqlite.sqlite3_column_type(stmt, 6);
        const used_at: ?i64 = if (used_at_type == sqlite.SQLITE_NULL) null else sqlite.sqlite3_column_int64(stmt, 6);
        const ip_ptr = sqlite.sqlite3_column_text(stmt, 7);

        return ResetTokenEntry{
            .id = id,
            .username = try self.allocator.dupe(u8, std.mem.span(username_ptr)),
            .token_hash = try self.allocator.dupe(u8, std.mem.span(hash_ptr)),
            .created_at = created_at,
            .expires_at = expires_at,
            .used = used,
            .used_at = used_at,
            .ip_address = if (ip_ptr != null) try self.allocator.dupe(u8, std.mem.span(ip_ptr)) else null,
        };
    }

    /// Mark a reset token as used
    pub fn markResetTokenUsed(self: *Database, token_hash: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = time_compat.timestamp();
        const sql = "UPDATE password_reset_tokens SET used = 1, used_at = ?1 WHERE token_hash = ?2";

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        _ = sqlite.sqlite3_bind_int64(stmt, 1, now);

        const hash_z = try self.allocator.dupeZ(u8, token_hash);
        defer self.allocator.free(hash_z);
        _ = sqlite.sqlite3_bind_text(stmt, 2, hash_z.ptr, -1, null);

        rc = sqlite.sqlite3_step(stmt);
        if (rc != sqlite.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }
    }

    /// Invalidate all existing reset tokens for a user
    pub fn invalidateUserResetTokens(self: *Database, username: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql = "UPDATE password_reset_tokens SET used = 1 WHERE username = ?1 AND used = 0";

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const username_z = try self.allocator.dupeZ(u8, username);
        defer self.allocator.free(username_z);
        _ = sqlite.sqlite3_bind_text(stmt, 1, username_z.ptr, -1, null);

        rc = sqlite.sqlite3_step(stmt);
        if (rc != sqlite.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }
    }

    /// Prune expired reset tokens
    pub fn pruneExpiredResetTokens(self: *Database) !i64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = time_compat.timestamp();
        const sql = "DELETE FROM password_reset_tokens WHERE expires_at < ?1 OR used = 1";

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        _ = sqlite.sqlite3_bind_int64(stmt, 1, now);

        rc = sqlite.sqlite3_step(stmt);
        if (rc != sqlite.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }

        return sqlite.sqlite3_changes(self.db);
    }

    /// Check if user exists (for password reset validation)
    pub fn userExists(self: *Database, username: []const u8) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql = "SELECT 1 FROM users WHERE username = ?1";

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const username_z = try self.allocator.dupeZ(u8, username);
        defer self.allocator.free(username_z);
        _ = sqlite.sqlite3_bind_text(stmt, 1, username_z.ptr, -1, null);

        rc = sqlite.sqlite3_step(stmt);
        return rc == sqlite.SQLITE_ROW;
    }

    // ── IMAP UID persistence ──────────────────────────────────────────

    /// Get or create a mailbox record, returning (uidvalidity, uidnext).
    pub fn getOrCreateMailbox(self: *Database, username: []const u8, mailbox: []const u8) !struct { uidvalidity: i64, uidnext: i64 } {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Try to read existing
        {
            const sql = "SELECT uidvalidity, uidnext FROM imap_mailboxes WHERE username = ?1 AND mailbox = ?2";
            const sql_z = try self.allocator.dupeZ(u8, sql);
            defer self.allocator.free(sql_z);
            var stmt: ?*sqlite.sqlite3_stmt = null;
            var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
            if (rc != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
            defer _ = sqlite.sqlite3_finalize(stmt);

            const u_z = try self.allocator.dupeZ(u8, username);
            defer self.allocator.free(u_z);
            const m_z = try self.allocator.dupeZ(u8, mailbox);
            defer self.allocator.free(m_z);
            _ = sqlite.sqlite3_bind_text(stmt, 1, u_z.ptr, -1, null);
            _ = sqlite.sqlite3_bind_text(stmt, 2, m_z.ptr, -1, null);

            rc = sqlite.sqlite3_step(stmt);
            if (rc == sqlite.SQLITE_ROW) {
                return .{
                    .uidvalidity = sqlite.sqlite3_column_int64(stmt, 0),
                    .uidnext = sqlite.sqlite3_column_int64(stmt, 1),
                };
            }
        }

        // Create new mailbox with uidvalidity = current timestamp
        const uidvalidity = time_compat.timestamp();
        {
            const sql = "INSERT INTO imap_mailboxes (username, mailbox, uidvalidity, uidnext) VALUES (?1, ?2, ?3, 1)";
            const sql_z = try self.allocator.dupeZ(u8, sql);
            defer self.allocator.free(sql_z);
            var stmt: ?*sqlite.sqlite3_stmt = null;
            var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
            if (rc != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
            defer _ = sqlite.sqlite3_finalize(stmt);

            const u_z = try self.allocator.dupeZ(u8, username);
            defer self.allocator.free(u_z);
            const m_z = try self.allocator.dupeZ(u8, mailbox);
            defer self.allocator.free(m_z);
            _ = sqlite.sqlite3_bind_text(stmt, 1, u_z.ptr, -1, null);
            _ = sqlite.sqlite3_bind_text(stmt, 2, m_z.ptr, -1, null);
            _ = sqlite.sqlite3_bind_int64(stmt, 3, uidvalidity);

            rc = sqlite.sqlite3_step(stmt);
            if (rc != sqlite.SQLITE_DONE) return DatabaseError.StepFailed;
        }

        return .{ .uidvalidity = uidvalidity, .uidnext = 1 };
    }

    /// Look up the UID for a given filename. Returns null if not assigned yet.
    pub fn getUidForFile(self: *Database, username: []const u8, mailbox: []const u8, filename: []const u8) !?i64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql = "SELECT uid FROM imap_uids WHERE username = ?1 AND mailbox = ?2 AND filename = ?3";
        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);
        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
        defer _ = sqlite.sqlite3_finalize(stmt);

        const u_z = try self.allocator.dupeZ(u8, username);
        defer self.allocator.free(u_z);
        const m_z = try self.allocator.dupeZ(u8, mailbox);
        defer self.allocator.free(m_z);
        const f_z = try self.allocator.dupeZ(u8, filename);
        defer self.allocator.free(f_z);
        _ = sqlite.sqlite3_bind_text(stmt, 1, u_z.ptr, -1, null);
        _ = sqlite.sqlite3_bind_text(stmt, 2, m_z.ptr, -1, null);
        _ = sqlite.sqlite3_bind_text(stmt, 3, f_z.ptr, -1, null);

        rc = sqlite.sqlite3_step(stmt);
        if (rc == sqlite.SQLITE_ROW) {
            return sqlite.sqlite3_column_int64(stmt, 0);
        }
        return null;
    }

    /// Assign a UID to a filename and bump uidnext. Returns the assigned UID.
    pub fn assignUid(self: *Database, username: []const u8, mailbox: []const u8, filename: []const u8) !i64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Get current uidnext
        var uidnext: i64 = 1;
        {
            const sql = "SELECT uidnext FROM imap_mailboxes WHERE username = ?1 AND mailbox = ?2";
            const sql_z = try self.allocator.dupeZ(u8, sql);
            defer self.allocator.free(sql_z);
            var stmt: ?*sqlite.sqlite3_stmt = null;
            var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
            if (rc != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
            defer _ = sqlite.sqlite3_finalize(stmt);

            const u_z = try self.allocator.dupeZ(u8, username);
            defer self.allocator.free(u_z);
            const m_z = try self.allocator.dupeZ(u8, mailbox);
            defer self.allocator.free(m_z);
            _ = sqlite.sqlite3_bind_text(stmt, 1, u_z.ptr, -1, null);
            _ = sqlite.sqlite3_bind_text(stmt, 2, m_z.ptr, -1, null);

            rc = sqlite.sqlite3_step(stmt);
            if (rc == sqlite.SQLITE_ROW) {
                uidnext = sqlite.sqlite3_column_int64(stmt, 0);
            }
        }

        const uid = uidnext;

        // Insert the UID mapping
        {
            const sql = "INSERT OR IGNORE INTO imap_uids (username, mailbox, filename, uid) VALUES (?1, ?2, ?3, ?4)";
            const sql_z = try self.allocator.dupeZ(u8, sql);
            defer self.allocator.free(sql_z);
            var stmt: ?*sqlite.sqlite3_stmt = null;
            var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
            if (rc != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
            defer _ = sqlite.sqlite3_finalize(stmt);

            const u_z = try self.allocator.dupeZ(u8, username);
            defer self.allocator.free(u_z);
            const m_z = try self.allocator.dupeZ(u8, mailbox);
            defer self.allocator.free(m_z);
            const f_z = try self.allocator.dupeZ(u8, filename);
            defer self.allocator.free(f_z);
            _ = sqlite.sqlite3_bind_text(stmt, 1, u_z.ptr, -1, null);
            _ = sqlite.sqlite3_bind_text(stmt, 2, m_z.ptr, -1, null);
            _ = sqlite.sqlite3_bind_text(stmt, 3, f_z.ptr, -1, null);
            _ = sqlite.sqlite3_bind_int64(stmt, 4, uid);

            rc = sqlite.sqlite3_step(stmt);
            if (rc != sqlite.SQLITE_DONE) {
                // UNIQUE constraint — might already be assigned, read existing
                const get_sql = "SELECT uid FROM imap_uids WHERE username = ?1 AND mailbox = ?2 AND filename = ?3";
                const get_z = try self.allocator.dupeZ(u8, get_sql);
                defer self.allocator.free(get_z);
                var get_stmt: ?*sqlite.sqlite3_stmt = null;
                const get_rc = sqlite.sqlite3_prepare_v2(self.db, get_z.ptr, -1, &get_stmt, null);
                if (get_rc != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
                defer _ = sqlite.sqlite3_finalize(get_stmt);

                const u2_z = try self.allocator.dupeZ(u8, username);
                defer self.allocator.free(u2_z);
                const m2_z = try self.allocator.dupeZ(u8, mailbox);
                defer self.allocator.free(m2_z);
                const f2_z = try self.allocator.dupeZ(u8, filename);
                defer self.allocator.free(f2_z);
                _ = sqlite.sqlite3_bind_text(get_stmt, 1, u2_z.ptr, -1, null);
                _ = sqlite.sqlite3_bind_text(get_stmt, 2, m2_z.ptr, -1, null);
                _ = sqlite.sqlite3_bind_text(get_stmt, 3, f2_z.ptr, -1, null);

                const step_rc = sqlite.sqlite3_step(get_stmt);
                if (step_rc == sqlite.SQLITE_ROW) {
                    return sqlite.sqlite3_column_int64(get_stmt, 0);
                }
                return DatabaseError.StepFailed;
            }
        }

        // Bump uidnext
        {
            const sql = "UPDATE imap_mailboxes SET uidnext = ?1 WHERE username = ?2 AND mailbox = ?3";
            const sql_z = try self.allocator.dupeZ(u8, sql);
            defer self.allocator.free(sql_z);
            var stmt: ?*sqlite.sqlite3_stmt = null;
            var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
            if (rc != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
            defer _ = sqlite.sqlite3_finalize(stmt);

            const u_z = try self.allocator.dupeZ(u8, username);
            defer self.allocator.free(u_z);
            const m_z = try self.allocator.dupeZ(u8, mailbox);
            defer self.allocator.free(m_z);
            _ = sqlite.sqlite3_bind_int64(stmt, 1, uid + 1);
            _ = sqlite.sqlite3_bind_text(stmt, 2, u_z.ptr, -1, null);
            _ = sqlite.sqlite3_bind_text(stmt, 3, m_z.ptr, -1, null);

            rc = sqlite.sqlite3_step(stmt);
            if (rc != sqlite.SQLITE_DONE) return DatabaseError.StepFailed;
        }

        return uid;
    }

    /// Remove stale UID entries for files that no longer exist.
    pub fn removeStaleUids(self: *Database, username: []const u8, mailbox: []const u8, current_files: []const []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Get all filenames from the DB for this mailbox
        const sql = "SELECT id, filename FROM imap_uids WHERE username = ?1 AND mailbox = ?2";
        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);
        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
        defer _ = sqlite.sqlite3_finalize(stmt);

        const u_z = try self.allocator.dupeZ(u8, username);
        defer self.allocator.free(u_z);
        const m_z = try self.allocator.dupeZ(u8, mailbox);
        defer self.allocator.free(m_z);
        _ = sqlite.sqlite3_bind_text(stmt, 1, u_z.ptr, -1, null);
        _ = sqlite.sqlite3_bind_text(stmt, 2, m_z.ptr, -1, null);

        // Collect IDs to delete
        var ids_to_delete: std.ArrayList(i64) = .empty;
        defer ids_to_delete.deinit(self.allocator);

        while (true) {
            rc = sqlite.sqlite3_step(stmt);
            if (rc == sqlite.SQLITE_ROW) {
                const id = sqlite.sqlite3_column_int64(stmt, 0);
                const db_filename_ptr = sqlite.sqlite3_column_text(stmt, 1);
                if (db_filename_ptr) |ptr| {
                    const len = sqlite.sqlite3_column_bytes(stmt, 1);
                    const db_filename = ptr[0..@intCast(len)];
                    // Check if this file still exists in the current file list
                    var found = false;
                    for (current_files) |f| {
                        if (std.mem.eql(u8, f, db_filename)) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        ids_to_delete.append(self.allocator, id) catch {};
                    }
                }
            } else break;
        }

        // Delete stale entries
        for (ids_to_delete.items) |id| {
            const del_sql = "DELETE FROM imap_uids WHERE id = ?1";
            const del_z = self.allocator.dupeZ(u8, del_sql) catch continue;
            defer self.allocator.free(del_z);
            var del_stmt: ?*sqlite.sqlite3_stmt = null;
            const del_rc = sqlite.sqlite3_prepare_v2(self.db, del_z.ptr, -1, &del_stmt, null);
            if (del_rc != sqlite.SQLITE_OK) continue;
            defer _ = sqlite.sqlite3_finalize(del_stmt);
            _ = sqlite.sqlite3_bind_int64(del_stmt, 1, id);
            _ = sqlite.sqlite3_step(del_stmt);
        }
    }

    /// Get the current uidnext for a mailbox.
    pub fn getUidNext(self: *Database, username: []const u8, mailbox: []const u8) !i64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql = "SELECT uidnext FROM imap_mailboxes WHERE username = ?1 AND mailbox = ?2";
        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);
        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
        defer _ = sqlite.sqlite3_finalize(stmt);

        const u_z = try self.allocator.dupeZ(u8, username);
        defer self.allocator.free(u_z);
        const m_z = try self.allocator.dupeZ(u8, mailbox);
        defer self.allocator.free(m_z);
        _ = sqlite.sqlite3_bind_text(stmt, 1, u_z.ptr, -1, null);
        _ = sqlite.sqlite3_bind_text(stmt, 2, m_z.ptr, -1, null);

        rc = sqlite.sqlite3_step(stmt);
        if (rc == sqlite.SQLITE_ROW) {
            return sqlite.sqlite3_column_int64(stmt, 0);
        }
        return 1;
    }
};
