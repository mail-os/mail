const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");
const sqlite = @import("sqlite");

// SQLITE_TRANSIENT == (sqlite3_destructor_type)-1 — tells SQLite to make its own
// copy of bound text/blob at bind time. We declare sqlite3_bind_text ourselves
// with the destructor typed as an opaque ?*const anyopaque, because Zig 0.17
// refuses to materialize the misaligned function-pointer sentinel that the
// translate-c signature would require.
const sqlite3_bind_text_raw: *const fn (
    ?*sqlite.sqlite3_stmt,
    c_int,
    [*c]const u8,
    c_int,
    ?*const anyopaque,
) callconv(.c) c_int = @extern(*const fn (
    ?*sqlite.sqlite3_stmt,
    c_int,
    [*c]const u8,
    c_int,
    ?*const anyopaque,
) callconv(.c) c_int, .{ .name = "sqlite3_bind_text" });

const SQLITE_TRANSIENT_PTR: ?*const anyopaque = @ptrFromInt(std.math.maxInt(usize));

/// Surface sqlite3_bind_* failures instead of silently continuing to step()
/// with unbound/partially-bound parameters.
fn checkBind(rc: c_int) DatabaseError!void {
    if (rc != sqlite.SQLITE_OK) return DatabaseError.BindFailed;
}

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

/// Strip the Maildir `:2,FLAGS` suffix, returning the stable message identity.
///
/// The imap_uids table keys UIDs on this base name, NOT the full filename:
/// flag changes (mark read, flag, etc.) rename the file by changing the suffix,
/// so keying on the full name would churn the UID on every flag change (and made
/// IMAP, ActiveSync, and webmail disagree, since they touched the same table
/// with different key conventions). Keying on the base name makes the UID stable
/// across flag mutations and consistent across all protocols.
pub fn maildirBaseName(filename: []const u8) []const u8 {
    if (std.mem.indexOf(u8, filename, ":2,")) |pos| return filename[0..pos];
    return filename;
}

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
                    // SQLITE_TRANSIENT: SQLite copies the bytes now, so the slice
                    // need not outlive this call (and multiple text params can be
                    // bound before step without clobbering each other).
                    break :blk sqlite3_bind_text_raw(self.stmt, @intCast(index), value.ptr, @intCast(value.len), SQLITE_TRANSIENT_PTR);
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

/// A persisted webmail browser session (see webmail_sessions table).
pub const WebmailSessionRow = struct {
    session_id: []const u8,
    username: []const u8,
    email: []const u8,
    csrf_secret: []const u8,
    created_at: i64,
    last_activity: i64,
    expires_at: i64,

    pub fn deinit(self: *WebmailSessionRow, allocator: std.mem.Allocator) void {
        allocator.free(self.session_id);
        allocator.free(self.username);
        allocator.free(self.email);
        allocator.free(self.csrf_secret);
    }
};

/// LIKE pattern matching any address in `domain`: `%@<domain>` with SQLite's
/// wildcards escaped, so a domain containing `_` (a legal DNS character) does
/// not match a single arbitrary character.
fn domainLikePattern(allocator: std.mem.Allocator, domain: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "%@");
    for (domain) |c| {
        if (c == '%' or c == '_' or c == '\\') try out.append(allocator, '\\');
        try out.append(allocator, c);
    }
    return out.toOwnedSlice(allocator);
}

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

        // Enforce the FOREIGN KEY constraints declared in the schema
        // (SQLite ignores them unless this pragma is on, per connection)
        const fk_pragma = "PRAGMA foreign_keys=ON;";
        try self.exec(fk_pragma);
    }

    /// exec without taking the mutex — for use inside methods that already
    /// hold it (e.g. to wrap multiple statements in one transaction).
    fn execLocked(self: *Database, sql: [:0]const u8) !void {
        var errmsg: [*c]u8 = null;
        const rc = sqlite.sqlite3_exec(self.db, sql.ptr, null, null, @ptrCast(&errmsg));
        if (rc != sqlite.SQLITE_OK) {
            if (errmsg) |msg| sqlite.sqlite3_free(msg);
            return DatabaseError.ExecFailed;
        }
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

        // Migration: digest_ha1 holds MD5(username:realm:password) for HTTP/SMTP
        // Digest auth. getUserByUsername SELECTs it, so a fresh DB without this
        // column makes every credential check fail with PrepareFailed. Run it as
        // its own statement (sqlite3_exec stops at the first error, so it must
        // not be bundled with the quota migration above).
        self.exec("ALTER TABLE users ADD COLUMN digest_ha1 TEXT;") catch {};

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

        // Webmail browser sessions (cookie-based). Distinct from SMTP/IMAP AUTH:
        // a session_id is a random token stored as an HttpOnly cookie. Rows are
        // pruned on expiry. See src/api/webmail_session.zig.
        try self.exec(
            \\CREATE TABLE IF NOT EXISTS webmail_sessions (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    session_id TEXT UNIQUE NOT NULL,
            \\    username TEXT NOT NULL,
            \\    email TEXT NOT NULL,
            \\    csrf_secret TEXT NOT NULL,
            \\    created_at INTEGER NOT NULL,
            \\    last_activity INTEGER NOT NULL,
            \\    expires_at INTEGER NOT NULL,
            \\    ip_address TEXT,
            \\    user_agent TEXT
            \\);
            \\CREATE INDEX IF NOT EXISTS idx_webmail_sessions_sid ON webmail_sessions(session_id);
            \\CREATE INDEX IF NOT EXISTS idx_webmail_sessions_expires ON webmail_sessions(expires_at);
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

        try checkBind(sqlite.sqlite3_bind_text(stmt, 1, username_z.ptr, -1, null));
        try checkBind(sqlite.sqlite3_bind_text(stmt, 2, password_z.ptr, -1, null));
        try checkBind(sqlite.sqlite3_bind_text(stmt, 3, email_z.ptr, -1, null));
        try checkBind(sqlite.sqlite3_bind_int64(stmt, 4, now));
        try checkBind(sqlite.sqlite3_bind_int64(stmt, 5, now));

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

        try checkBind(sqlite.sqlite3_bind_text(stmt, 1, username_z.ptr, -1, null));

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

        try checkBind(sqlite.sqlite3_bind_text(stmt, 1, password_z.ptr, -1, null));
        try checkBind(sqlite.sqlite3_bind_int64(stmt, 2, now));
        try checkBind(sqlite.sqlite3_bind_text(stmt, 3, username_z.ptr, -1, null));

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

        try checkBind(sqlite.sqlite3_bind_text(stmt, 1, username_z.ptr, -1, null));

        rc = sqlite.sqlite3_step(stmt);
        if (rc != sqlite.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }
    }

    // ── Webmail browser sessions ────────────────────────────────────────────

    /// Insert a new webmail session. Caller owns the input slices.
    pub fn createWebmailSession(
        self: *Database,
        session_id: []const u8,
        username: []const u8,
        email: []const u8,
        csrf_secret: []const u8,
        expires_at: i64,
        ip_address: ?[]const u8,
        user_agent: ?[]const u8,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql =
            \\INSERT INTO webmail_sessions
            \\    (session_id, username, email, csrf_secret, created_at, last_activity, expires_at, ip_address, user_agent)
            \\VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7, ?8)
        ;

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const session_z = try self.allocator.dupeZ(u8, session_id);
        defer self.allocator.free(session_z);
        const username_z = try self.allocator.dupeZ(u8, username);
        defer self.allocator.free(username_z);
        const email_z = try self.allocator.dupeZ(u8, email);
        defer self.allocator.free(email_z);
        const csrf_z = try self.allocator.dupeZ(u8, csrf_secret);
        defer self.allocator.free(csrf_z);
        const ip_z: ?[:0]u8 = if (ip_address) |v| try self.allocator.dupeZ(u8, v) else null;
        defer if (ip_z) |v| self.allocator.free(v);
        const ua_z: ?[:0]u8 = if (user_agent) |v| try self.allocator.dupeZ(u8, v) else null;
        defer if (ua_z) |v| self.allocator.free(v);

        const now = time_compat.timestamp();

        try checkBind(sqlite.sqlite3_bind_text(stmt, 1, session_z.ptr, -1, null));
        try checkBind(sqlite.sqlite3_bind_text(stmt, 2, username_z.ptr, -1, null));
        try checkBind(sqlite.sqlite3_bind_text(stmt, 3, email_z.ptr, -1, null));
        try checkBind(sqlite.sqlite3_bind_text(stmt, 4, csrf_z.ptr, -1, null));
        try checkBind(sqlite.sqlite3_bind_int64(stmt, 5, now));
        try checkBind(sqlite.sqlite3_bind_int64(stmt, 6, expires_at));
        if (ip_z) |v| {
            try checkBind(sqlite.sqlite3_bind_text(stmt, 7, v.ptr, -1, null));
        } else {
            try checkBind(sqlite.sqlite3_bind_null(stmt, 7));
        }
        if (ua_z) |v| {
            try checkBind(sqlite.sqlite3_bind_text(stmt, 8, v.ptr, -1, null));
        } else {
            try checkBind(sqlite.sqlite3_bind_null(stmt, 8));
        }

        rc = sqlite.sqlite3_step(stmt);
        if (rc != sqlite.SQLITE_DONE) {
            if (rc == sqlite.SQLITE_CONSTRAINT) {
                return DatabaseError.AlreadyExists;
            }
            return DatabaseError.StepFailed;
        }
    }

    /// Look up a session by its token. Caller must call row.deinit(allocator).
    /// Returns DatabaseError.NotFound if no such session.
    pub fn getWebmailSession(self: *Database, session_id: []const u8) !WebmailSessionRow {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql =
            \\SELECT session_id, username, email, csrf_secret, created_at, last_activity, expires_at
            \\FROM webmail_sessions
            \\WHERE session_id = ?1
        ;

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const session_z = try self.allocator.dupeZ(u8, session_id);
        defer self.allocator.free(session_z);

        try checkBind(sqlite.sqlite3_bind_text(stmt, 1, session_z.ptr, -1, null));

        rc = sqlite.sqlite3_step(stmt);
        if (rc != sqlite.SQLITE_ROW) {
            return DatabaseError.NotFound;
        }

        const session_ptr = sqlite.sqlite3_column_text(stmt, 0);
        const username_ptr = sqlite.sqlite3_column_text(stmt, 1);
        const email_ptr = sqlite.sqlite3_column_text(stmt, 2);
        const csrf_ptr = sqlite.sqlite3_column_text(stmt, 3);
        const created_at = sqlite.sqlite3_column_int64(stmt, 4);
        const last_activity = sqlite.sqlite3_column_int64(stmt, 5);
        const expires_at = sqlite.sqlite3_column_int64(stmt, 6);

        return WebmailSessionRow{
            .session_id = try self.allocator.dupe(u8, std.mem.span(session_ptr)),
            .username = try self.allocator.dupe(u8, std.mem.span(username_ptr)),
            .email = try self.allocator.dupe(u8, std.mem.span(email_ptr)),
            .csrf_secret = try self.allocator.dupe(u8, std.mem.span(csrf_ptr)),
            .created_at = created_at,
            .last_activity = last_activity,
            .expires_at = expires_at,
        };
    }

    /// Bump last_activity and push expiry forward (sliding idle window).
    pub fn touchWebmailSession(self: *Database, session_id: []const u8, new_expires_at: i64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql =
            \\UPDATE webmail_sessions
            \\SET last_activity = ?1, expires_at = ?2
            \\WHERE session_id = ?3
        ;

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const session_z = try self.allocator.dupeZ(u8, session_id);
        defer self.allocator.free(session_z);

        const now = time_compat.timestamp();

        try checkBind(sqlite.sqlite3_bind_int64(stmt, 1, now));
        try checkBind(sqlite.sqlite3_bind_int64(stmt, 2, new_expires_at));
        try checkBind(sqlite.sqlite3_bind_text(stmt, 3, session_z.ptr, -1, null));

        rc = sqlite.sqlite3_step(stmt);
        if (rc != sqlite.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }
    }

    /// Delete a single session (logout).
    pub fn deleteWebmailSession(self: *Database, session_id: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql = "DELETE FROM webmail_sessions WHERE session_id = ?1";

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const session_z = try self.allocator.dupeZ(u8, session_id);
        defer self.allocator.free(session_z);

        try checkBind(sqlite.sqlite3_bind_text(stmt, 1, session_z.ptr, -1, null));

        rc = sqlite.sqlite3_step(stmt);
        if (rc != sqlite.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }
    }

    /// Prune all sessions whose expiry is at or before `now`.
    pub fn deleteExpiredWebmailSessions(self: *Database, now: i64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql = "DELETE FROM webmail_sessions WHERE expires_at <= ?1";

        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        try checkBind(sqlite.sqlite3_bind_int64(stmt, 1, now));

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

        try checkBind(sqlite.sqlite3_bind_int(stmt, 1, if (enabled) 1 else 0));
        try checkBind(sqlite.sqlite3_bind_int64(stmt, 2, now));
        try checkBind(sqlite.sqlite3_bind_text(stmt, 3, username_z.ptr, -1, null));

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

        try checkBind(sqlite.sqlite3_bind_text(stmt, 1, email_z.ptr, -1, null));
        try checkBind(sqlite.sqlite3_bind_int64(stmt, 2, now));
        try checkBind(sqlite.sqlite3_bind_text(stmt, 3, username_z.ptr, -1, null));

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

        try checkBind(sqlite.sqlite3_bind_int64(stmt, 1, timestamp));

        const action_z = try self.allocator.dupeZ(u8, action);
        defer self.allocator.free(action_z);
        try checkBind(sqlite.sqlite3_bind_text(stmt, 2, action_z.ptr, -1, null));

        const actor_z = try self.allocator.dupeZ(u8, actor);
        defer self.allocator.free(actor_z);
        try checkBind(sqlite.sqlite3_bind_text(stmt, 3, actor_z.ptr, -1, null));

        if (target) |t| {
            const target_z = try self.allocator.dupeZ(u8, t);
            defer self.allocator.free(target_z);
            try checkBind(sqlite.sqlite3_bind_text(stmt, 4, target_z.ptr, -1, null));
        } else {
            try checkBind(sqlite.sqlite3_bind_null(stmt, 4));
        }

        if (target_type) |tt| {
            const tt_z = try self.allocator.dupeZ(u8, tt);
            defer self.allocator.free(tt_z);
            try checkBind(sqlite.sqlite3_bind_text(stmt, 5, tt_z.ptr, -1, null));
        } else {
            try checkBind(sqlite.sqlite3_bind_null(stmt, 5));
        }

        if (ip_address) |ip| {
            const ip_z = try self.allocator.dupeZ(u8, ip);
            defer self.allocator.free(ip_z);
            try checkBind(sqlite.sqlite3_bind_text(stmt, 6, ip_z.ptr, -1, null));
        } else {
            try checkBind(sqlite.sqlite3_bind_null(stmt, 6));
        }

        if (details) |d| {
            const details_z = try self.allocator.dupeZ(u8, d);
            defer self.allocator.free(details_z);
            try checkBind(sqlite.sqlite3_bind_text(stmt, 7, details_z.ptr, -1, null));
        } else {
            try checkBind(sqlite.sqlite3_bind_null(stmt, 7));
        }

        const severity_z = try self.allocator.dupeZ(u8, severity);
        defer self.allocator.free(severity_z);
        try checkBind(sqlite.sqlite3_bind_text(stmt, 8, severity_z.ptr, -1, null));

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

        try checkBind(sqlite.sqlite3_bind_int64(stmt, 1, @intCast(limit)));
        try checkBind(sqlite.sqlite3_bind_int64(stmt, 2, @intCast(offset)));

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

        try checkBind(sqlite.sqlite3_bind_int64(stmt, 1, before_timestamp));

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
        try checkBind(sqlite.sqlite3_bind_text(stmt, 1, username_z.ptr, -1, null));

        const hash_z = try self.allocator.dupeZ(u8, token_hash);
        defer self.allocator.free(hash_z);
        try checkBind(sqlite.sqlite3_bind_text(stmt, 2, hash_z.ptr, -1, null));

        try checkBind(sqlite.sqlite3_bind_int64(stmt, 3, created_at));
        try checkBind(sqlite.sqlite3_bind_int64(stmt, 4, expires_at));

        if (ip_address) |ip| {
            const ip_z = try self.allocator.dupeZ(u8, ip);
            defer self.allocator.free(ip_z);
            try checkBind(sqlite.sqlite3_bind_text(stmt, 5, ip_z.ptr, -1, null));
        } else {
            try checkBind(sqlite.sqlite3_bind_null(stmt, 5));
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
        try checkBind(sqlite.sqlite3_bind_text(stmt, 1, hash_z.ptr, -1, null));

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

        try checkBind(sqlite.sqlite3_bind_int64(stmt, 1, now));

        const hash_z = try self.allocator.dupeZ(u8, token_hash);
        defer self.allocator.free(hash_z);
        try checkBind(sqlite.sqlite3_bind_text(stmt, 2, hash_z.ptr, -1, null));

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
        try checkBind(sqlite.sqlite3_bind_text(stmt, 1, username_z.ptr, -1, null));

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

        try checkBind(sqlite.sqlite3_bind_int64(stmt, 1, now));

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
        try checkBind(sqlite.sqlite3_bind_text(stmt, 1, username_z.ptr, -1, null));

        rc = sqlite.sqlite3_step(stmt);
        return rc == sqlite.SQLITE_ROW;
    }

    // ── Domain migration ──────────────────────────────────────────────

    /// Number of rows in `table` whose `username` sits in `domain`.
    ///
    /// Matching is done in SQL with a suffix LIKE so a large `imap_uids` is not
    /// pulled into memory just to be counted. `@` and the dot are literals
    /// here, not wildcards, so `a@bXorg` cannot match `b.org`; SQLite's LIKE
    /// only treats `%` and `_` specially, and the `_` in `b_org` is why the
    /// ESCAPE clause is needed.
    pub fn countUsernamesInDomain(self: *Database, table: []const u8, domain: []const u8) !u32 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // `table` is never user input — callers pass a literal — but build the
        // statement from a fixed set anyway rather than interpolating freely.
        const sql_text = if (std.mem.eql(u8, table, "users"))
            "SELECT COUNT(*) FROM users WHERE username LIKE ?1 ESCAPE '\\'"
        else if (std.mem.eql(u8, table, "webmail_sessions"))
            "SELECT COUNT(*) FROM webmail_sessions WHERE username LIKE ?1 ESCAPE '\\'"
        else if (std.mem.eql(u8, table, "imap_mailboxes"))
            "SELECT COUNT(*) FROM imap_mailboxes WHERE username LIKE ?1 ESCAPE '\\'"
        else if (std.mem.eql(u8, table, "imap_uids"))
            "SELECT COUNT(*) FROM imap_uids WHERE username LIKE ?1 ESCAPE '\\'"
        else
            return DatabaseError.PrepareFailed;

        const sql_z = try self.allocator.dupeZ(u8, sql_text);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        if (sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null) != sqlite.SQLITE_OK)
            return DatabaseError.PrepareFailed;
        defer _ = sqlite.sqlite3_finalize(stmt);

        const pattern = try domainLikePattern(self.allocator, domain);
        defer self.allocator.free(pattern);
        try checkBind(sqlite3_bind_text_raw(stmt, 1, pattern.ptr, @intCast(pattern.len), SQLITE_TRANSIENT_PTR));

        if (sqlite.sqlite3_step(stmt) != sqlite.SQLITE_ROW) return 0;
        return @intCast(sqlite.sqlite3_column_int64(stmt, 0));
    }

    /// Repoints every mailbox on `old_domain` at `new_domain`, in one
    /// transaction.
    ///
    /// `users`, `imap_mailboxes` and `imap_uids` all key on the full address,
    /// so they move together or not at all — a partial rename loses IMAP UIDs
    /// and makes every client re-sync from scratch. `webmail_sessions` rows are
    /// deleted rather than rewritten: a session carries a baked-in identity and
    /// re-login costs the user nothing.
    ///
    /// Callers should check for target-address collisions first (see
    /// `domain_migrate.plan`); UNIQUE(username) and UNIQUE(email) would
    /// otherwise abort the transaction mid-way.
    pub fn renameDomain(self: *Database, old_domain: []const u8, new_domain: []const u8) !u32 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const pattern = try domainLikePattern(self.allocator, old_domain);
        defer self.allocator.free(pattern);

        const suffix = try std.fmt.allocPrint(self.allocator, "@{s}", .{new_domain});
        defer self.allocator.free(suffix);

        const old_len: i64 = @intCast(old_domain.len + 1); // include the '@'

        try self.execLocked("BEGIN IMMEDIATE");
        errdefer self.execLocked("ROLLBACK") catch {};

        // `substr(x, 1, length(x) - <old_len>) || <suffix>` rebuilds the address
        // from its local part, so a local part containing '@' survives intact.
        const statements = [_][:0]const u8{
            "UPDATE users SET username = substr(username, 1, length(username) - ?3) || ?2, updated_at = strftime('%s','now') WHERE username LIKE ?1 ESCAPE '\\'",
            "UPDATE users SET email = substr(email, 1, length(email) - ?3) || ?2 WHERE email LIKE ?1 ESCAPE '\\'",
            "UPDATE imap_mailboxes SET username = substr(username, 1, length(username) - ?3) || ?2 WHERE username LIKE ?1 ESCAPE '\\'",
            "UPDATE imap_uids SET username = substr(username, 1, length(username) - ?3) || ?2 WHERE username LIKE ?1 ESCAPE '\\'",
        };

        var moved: u32 = 0;
        for (statements, 0..) |sql, i| {
            var stmt: ?*sqlite.sqlite3_stmt = null;
            if (sqlite.sqlite3_prepare_v2(self.db, sql.ptr, -1, &stmt, null) != sqlite.SQLITE_OK)
                return DatabaseError.PrepareFailed;
            defer _ = sqlite.sqlite3_finalize(stmt);

            try checkBind(sqlite3_bind_text_raw(stmt, 1, pattern.ptr, @intCast(pattern.len), SQLITE_TRANSIENT_PTR));
            try checkBind(sqlite3_bind_text_raw(stmt, 2, suffix.ptr, @intCast(suffix.len), SQLITE_TRANSIENT_PTR));
            try checkBind(sqlite.sqlite3_bind_int64(stmt, 3, old_len));

            if (sqlite.sqlite3_step(stmt) != sqlite.SQLITE_DONE) return DatabaseError.StepFailed;
            // The first statement is the authoritative mailbox count.
            if (i == 0) moved = @intCast(sqlite.sqlite3_changes(self.db));
        }

        {
            const sql: [:0]const u8 = "DELETE FROM webmail_sessions WHERE username LIKE ?1 ESCAPE '\\'";
            var stmt: ?*sqlite.sqlite3_stmt = null;
            if (sqlite.sqlite3_prepare_v2(self.db, sql.ptr, -1, &stmt, null) != sqlite.SQLITE_OK)
                return DatabaseError.PrepareFailed;
            defer _ = sqlite.sqlite3_finalize(stmt);
            try checkBind(sqlite3_bind_text_raw(stmt, 1, pattern.ptr, @intCast(pattern.len), SQLITE_TRANSIENT_PTR));
            if (sqlite.sqlite3_step(stmt) != sqlite.SQLITE_DONE) return DatabaseError.StepFailed;
        }

        try self.execLocked("COMMIT");
        return moved;
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
            try checkBind(sqlite.sqlite3_bind_text(stmt, 1, u_z.ptr, -1, null));
            try checkBind(sqlite.sqlite3_bind_text(stmt, 2, m_z.ptr, -1, null));

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
            try checkBind(sqlite.sqlite3_bind_text(stmt, 1, u_z.ptr, -1, null));
            try checkBind(sqlite.sqlite3_bind_text(stmt, 2, m_z.ptr, -1, null));
            try checkBind(sqlite.sqlite3_bind_int64(stmt, 3, uidvalidity));

            rc = sqlite.sqlite3_step(stmt);
            if (rc != sqlite.SQLITE_DONE) return DatabaseError.StepFailed;
        }

        return .{ .uidvalidity = uidvalidity, .uidnext = 1 };
    }

    /// Look up the UID for a given filename. Returns null if not assigned yet.
    pub fn getUidForFile(self: *Database, username: []const u8, mailbox: []const u8, filename: []const u8) !?i64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Key on the flag-suffix-stripped base name (see maildirBaseName).
        const base = maildirBaseName(filename);

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
        const f_z = try self.allocator.dupeZ(u8, base);
        defer self.allocator.free(f_z);
        try checkBind(sqlite.sqlite3_bind_text(stmt, 1, u_z.ptr, -1, null));
        try checkBind(sqlite.sqlite3_bind_text(stmt, 2, m_z.ptr, -1, null));
        try checkBind(sqlite.sqlite3_bind_text(stmt, 3, f_z.ptr, -1, null));

        rc = sqlite.sqlite3_step(stmt);
        if (rc == sqlite.SQLITE_ROW) {
            return sqlite.sqlite3_column_int64(stmt, 0);
        }
        return null;
    }

    /// Bulk getUidForFile/assignUid for an entire mailbox: one lock, one
    /// transaction, two prepared statements reused across all keys (instead
    /// of a prepare + autocommit round-trip per message). Returns one UID per
    /// key, in input order. Caller owns the returned slice.
    pub fn syncMailboxUids(
        self: *Database,
        allocator: std.mem.Allocator,
        username: []const u8,
        mailbox: []const u8,
        uid_keys: []const []const u8,
    ) ![]i64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const uids = try allocator.alloc(i64, uid_keys.len);
        errdefer allocator.free(uids);

        try self.execLocked("BEGIN IMMEDIATE");
        errdefer self.execLocked("ROLLBACK") catch {};

        // Current uidnext for the mailbox
        var uidnext: i64 = 1;
        {
            const sql: [:0]const u8 = "SELECT uidnext FROM imap_mailboxes WHERE username = ?1 AND mailbox = ?2";
            var stmt: ?*sqlite.sqlite3_stmt = null;
            if (sqlite.sqlite3_prepare_v2(self.db, sql.ptr, -1, &stmt, null) != sqlite.SQLITE_OK)
                return DatabaseError.PrepareFailed;
            defer _ = sqlite.sqlite3_finalize(stmt);
            try checkBind(sqlite3_bind_text_raw(stmt, 1, username.ptr, @intCast(username.len), SQLITE_TRANSIENT_PTR));
            try checkBind(sqlite3_bind_text_raw(stmt, 2, mailbox.ptr, @intCast(mailbox.len), SQLITE_TRANSIENT_PTR));
            if (sqlite.sqlite3_step(stmt) == sqlite.SQLITE_ROW) {
                uidnext = sqlite.sqlite3_column_int64(stmt, 0);
            }
        }
        const start_uidnext = uidnext;

        const sel_sql: [:0]const u8 = "SELECT uid FROM imap_uids WHERE username = ?1 AND mailbox = ?2 AND filename = ?3";
        var sel_stmt: ?*sqlite.sqlite3_stmt = null;
        if (sqlite.sqlite3_prepare_v2(self.db, sel_sql.ptr, -1, &sel_stmt, null) != sqlite.SQLITE_OK)
            return DatabaseError.PrepareFailed;
        defer _ = sqlite.sqlite3_finalize(sel_stmt);

        const ins_sql: [:0]const u8 = "INSERT OR IGNORE INTO imap_uids (username, mailbox, filename, uid) VALUES (?1, ?2, ?3, ?4)";
        var ins_stmt: ?*sqlite.sqlite3_stmt = null;
        if (sqlite.sqlite3_prepare_v2(self.db, ins_sql.ptr, -1, &ins_stmt, null) != sqlite.SQLITE_OK)
            return DatabaseError.PrepareFailed;
        defer _ = sqlite.sqlite3_finalize(ins_stmt);

        for (uid_keys, 0..) |key, i| {
            const base = maildirBaseName(key);

            _ = sqlite.sqlite3_reset(sel_stmt);
            try checkBind(sqlite3_bind_text_raw(sel_stmt, 1, username.ptr, @intCast(username.len), SQLITE_TRANSIENT_PTR));
            try checkBind(sqlite3_bind_text_raw(sel_stmt, 2, mailbox.ptr, @intCast(mailbox.len), SQLITE_TRANSIENT_PTR));
            try checkBind(sqlite3_bind_text_raw(sel_stmt, 3, base.ptr, @intCast(base.len), SQLITE_TRANSIENT_PTR));
            if (sqlite.sqlite3_step(sel_stmt) == sqlite.SQLITE_ROW) {
                uids[i] = sqlite.sqlite3_column_int64(sel_stmt, 0);
                continue;
            }

            _ = sqlite.sqlite3_reset(ins_stmt);
            try checkBind(sqlite3_bind_text_raw(ins_stmt, 1, username.ptr, @intCast(username.len), SQLITE_TRANSIENT_PTR));
            try checkBind(sqlite3_bind_text_raw(ins_stmt, 2, mailbox.ptr, @intCast(mailbox.len), SQLITE_TRANSIENT_PTR));
            try checkBind(sqlite3_bind_text_raw(ins_stmt, 3, base.ptr, @intCast(base.len), SQLITE_TRANSIENT_PTR));
            try checkBind(sqlite.sqlite3_bind_int64(ins_stmt, 4, uidnext));
            if (sqlite.sqlite3_step(ins_stmt) != sqlite.SQLITE_DONE) return DatabaseError.StepFailed;

            if (sqlite.sqlite3_changes(self.db) > 0) {
                uids[i] = uidnext;
                uidnext += 1;
            } else {
                // UNIQUE suppressed the insert (duplicate base name within
                // this batch) — fetch the UID that row already has.
                _ = sqlite.sqlite3_reset(sel_stmt);
                try checkBind(sqlite3_bind_text_raw(sel_stmt, 1, username.ptr, @intCast(username.len), SQLITE_TRANSIENT_PTR));
                try checkBind(sqlite3_bind_text_raw(sel_stmt, 2, mailbox.ptr, @intCast(mailbox.len), SQLITE_TRANSIENT_PTR));
                try checkBind(sqlite3_bind_text_raw(sel_stmt, 3, base.ptr, @intCast(base.len), SQLITE_TRANSIENT_PTR));
                if (sqlite.sqlite3_step(sel_stmt) == sqlite.SQLITE_ROW) {
                    uids[i] = sqlite.sqlite3_column_int64(sel_stmt, 0);
                } else {
                    return DatabaseError.StepFailed;
                }
            }
        }

        // Persist uidnext once for the whole batch
        if (uidnext != start_uidnext) {
            const upd_sql: [:0]const u8 = "UPDATE imap_mailboxes SET uidnext = ?1 WHERE username = ?2 AND mailbox = ?3";
            var upd_stmt: ?*sqlite.sqlite3_stmt = null;
            if (sqlite.sqlite3_prepare_v2(self.db, upd_sql.ptr, -1, &upd_stmt, null) != sqlite.SQLITE_OK)
                return DatabaseError.PrepareFailed;
            defer _ = sqlite.sqlite3_finalize(upd_stmt);
            try checkBind(sqlite.sqlite3_bind_int64(upd_stmt, 1, uidnext));
            try checkBind(sqlite3_bind_text_raw(upd_stmt, 2, username.ptr, @intCast(username.len), SQLITE_TRANSIENT_PTR));
            try checkBind(sqlite3_bind_text_raw(upd_stmt, 3, mailbox.ptr, @intCast(mailbox.len), SQLITE_TRANSIENT_PTR));
            if (sqlite.sqlite3_step(upd_stmt) != sqlite.SQLITE_DONE) return DatabaseError.StepFailed;
        }

        try self.execLocked("COMMIT");
        return uids;
    }

    /// Assign a UID to a filename and bump uidnext. Returns the assigned UID.
    pub fn assignUid(self: *Database, username: []const u8, mailbox: []const u8, filename: []const u8) !i64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // One transaction for SELECT-uidnext + INSERT + UPDATE-uidnext: a
        // single WAL commit instead of three, and the read-modify-write of
        // uidnext can't be torn by a crash between statements.
        try self.execLocked("BEGIN IMMEDIATE");
        errdefer self.execLocked("ROLLBACK") catch {};
        const uid = try self.assignUidInTxn(username, mailbox, filename);
        try self.execLocked("COMMIT");
        return uid;
    }

    fn assignUidInTxn(self: *Database, username: []const u8, mailbox: []const u8, filename: []const u8) !i64 {
        // Key on the flag-suffix-stripped base name (see maildirBaseName).
        const base = maildirBaseName(filename);

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
            try checkBind(sqlite.sqlite3_bind_text(stmt, 1, u_z.ptr, -1, null));
            try checkBind(sqlite.sqlite3_bind_text(stmt, 2, m_z.ptr, -1, null));

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
            const f_z = try self.allocator.dupeZ(u8, base);
            defer self.allocator.free(f_z);
            try checkBind(sqlite.sqlite3_bind_text(stmt, 1, u_z.ptr, -1, null));
            try checkBind(sqlite.sqlite3_bind_text(stmt, 2, m_z.ptr, -1, null));
            try checkBind(sqlite.sqlite3_bind_text(stmt, 3, f_z.ptr, -1, null));
            try checkBind(sqlite.sqlite3_bind_int64(stmt, 4, uid));

            rc = sqlite.sqlite3_step(stmt);
            if (rc != sqlite.SQLITE_DONE) return DatabaseError.StepFailed;

            // INSERT OR IGNORE returns SQLITE_DONE even when the UNIQUE(base
            // filename) constraint suppressed the insert (the row already has a
            // UID). Detect that via sqlite3_changes == 0 and return the EXISTING
            // UID without consuming a new one — otherwise re-assigning an
            // already-known message (e.g. after a flag change) would mint a new
            // UID and churn uidnext, breaking UID stability.
            if (sqlite.sqlite3_changes(self.db) == 0) {
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
                const f2_z = try self.allocator.dupeZ(u8, base);
                defer self.allocator.free(f2_z);
                try checkBind(sqlite.sqlite3_bind_text(get_stmt, 1, u2_z.ptr, -1, null));
                try checkBind(sqlite.sqlite3_bind_text(get_stmt, 2, m2_z.ptr, -1, null));
                try checkBind(sqlite.sqlite3_bind_text(get_stmt, 3, f2_z.ptr, -1, null));

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
            try checkBind(sqlite.sqlite3_bind_int64(stmt, 1, uid + 1));
            try checkBind(sqlite.sqlite3_bind_text(stmt, 2, u_z.ptr, -1, null));
            try checkBind(sqlite.sqlite3_bind_text(stmt, 3, m_z.ptr, -1, null));

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
        try checkBind(sqlite.sqlite3_bind_text(stmt, 1, u_z.ptr, -1, null));
        try checkBind(sqlite.sqlite3_bind_text(stmt, 2, m_z.ptr, -1, null));

        // Hash set of current base names so the existence check is O(1)
        // per row instead of a scan over all current files.
        var current_set = std.StringHashMap(void).init(self.allocator);
        defer current_set.deinit();
        for (current_files) |f| {
            try current_set.put(maildirBaseName(f), {});
        }

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
                    // Rows are keyed on the base name; current_files are full
                    // Maildir names, so compare on base name (a flag rename must
                    // not look like the message disappeared).
                    if (!current_set.contains(db_filename)) {
                        try ids_to_delete.append(self.allocator, id);
                    }
                }
            } else break;
        }

        if (ids_to_delete.items.len == 0) return;

        // Delete stale entries: one prepared statement, one transaction
        // (instead of a prepare + autocommit fsync per row).
        try self.execLocked("BEGIN IMMEDIATE");
        errdefer self.execLocked("ROLLBACK") catch {};

        const del_sql: [:0]const u8 = "DELETE FROM imap_uids WHERE id = ?1";
        var del_stmt: ?*sqlite.sqlite3_stmt = null;
        const del_rc = sqlite.sqlite3_prepare_v2(self.db, del_sql.ptr, -1, &del_stmt, null);
        if (del_rc != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
        defer _ = sqlite.sqlite3_finalize(del_stmt);

        for (ids_to_delete.items) |id| {
            _ = sqlite.sqlite3_reset(del_stmt);
            try checkBind(sqlite.sqlite3_bind_int64(del_stmt, 1, id));
            _ = sqlite.sqlite3_step(del_stmt);
        }

        try self.execLocked("COMMIT");
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
        try checkBind(sqlite.sqlite3_bind_text(stmt, 1, u_z.ptr, -1, null));
        try checkBind(sqlite.sqlite3_bind_text(stmt, 2, m_z.ptr, -1, null));

        rc = sqlite.sqlite3_step(stmt);
        if (rc == sqlite.SQLITE_ROW) {
            return sqlite.sqlite3_column_int64(stmt, 0);
        }
        return 1;
    }
};
