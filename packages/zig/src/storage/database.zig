const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");
const sqlite = @import("sqlite");
const categories = @import("../message/categories.zig");
const forwarding_wire = @import("../message/forwarding.zig");
const vacation_wire = @import("../message/vacation.zig");
const team_store = @import("team_store.zig");
const team_threads = @import("../api/webmail_team_threads.zig");
const shared_inbox = @import("shared_inbox.zig");
const calendar_invite = @import("../api/webmail_calendar_invite.zig");

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
    mutex: ?*mutex_compat.Mutex = null,

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
        if (self.mutex) |mutex| mutex.lock();
        defer if (self.mutex) |mutex| mutex.unlock();
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

    pub fn columnBlob(self: Statement, index: usize) []const u8 {
        const col: c_int = @intCast(index);
        const ptr = sqlite.sqlite3_column_blob(self.stmt, col) orelse return "";
        const len: usize = @intCast(sqlite.sqlite3_column_bytes(self.stmt, col));
        return @as([*]const u8, @ptrCast(ptr))[0..len];
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

    pub fn bindBlob(self: Statement, index: usize, bytes: []const u8) !void {
        // SQLITE_TRANSIENT asks SQLite to own a copy after this call returns.
        const bind_blob: *const fn (?*sqlite.sqlite3_stmt, c_int, ?*const anyopaque, c_int, ?*const anyopaque) callconv(.c) c_int = @extern(*const fn (?*sqlite.sqlite3_stmt, c_int, ?*const anyopaque, c_int, ?*const anyopaque) callconv(.c) c_int, .{ .name = "sqlite3_bind_blob" });
        try checkBind(bind_blob(self.stmt, @intCast(index), bytes.ptr, @intCast(bytes.len), SQLITE_TRANSIENT_PTR));
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
    mailbox_mutations: std.c.pthread_mutex_t = .{},

    pub fn init(allocator: std.mem.Allocator, db_path: []const u8) !Database {
        var db: ?*sqlite.sqlite3 = null;

        // Add null terminator for C string
        const path_z = try allocator.dupeSentinel(u8, db_path, 0);
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
        _ = std.c.pthread_mutex_destroy(&self.mailbox_mutations);
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

        // Mail admission may acknowledge immediately after a commit. Sync the
        // WAL at each commit so a power failure cannot undo accepted mail.
        const sync_pragma = "PRAGMA synchronous=FULL;";
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

        // Migration: a mailbox's recovery address, where a password reset link
        // is sent. `recovery_source` records who set it ('operator' for the CLI
        // and deploy provisioning, 'user' for the mailbox owner in webmail), so
        // provisioning can leave an owner's own choice alone. One statement
        // each: sqlite3_exec stops at the first error, and an existing column
        // is that error.
        self.exec("ALTER TABLE users ADD COLUMN recovery_email TEXT;") catch {};
        self.exec("ALTER TABLE users ADD COLUMN recovery_source TEXT;") catch {};

        try self.exec(
            \\CREATE TABLE IF NOT EXISTS provisioned_mailboxes (
            \\    mailbox TEXT PRIMARY KEY,
            \\    user_id INTEGER NOT NULL,
            \\    actor TEXT NOT NULL UNIQUE,
            \\    operation_id TEXT NOT NULL UNIQUE,
            \\    revision INTEGER NOT NULL,
            \\    requested_quota INTEGER NOT NULL,
            \\    requested_enabled INTEGER NOT NULL,
            \\    initial_recovery TEXT NOT NULL,
            \\    send_recipients_per_day INTEGER NOT NULL DEFAULT 0
            \\);
            \\CREATE TABLE IF NOT EXISTS provisioning_operations (
            \\    operation_id TEXT PRIMARY KEY,
            \\    mailbox TEXT NOT NULL,
            \\    revision INTEGER NOT NULL
            \\);
            \\CREATE TABLE IF NOT EXISTS eas_search_keys (
            \\    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            \\    key BLOB NOT NULL CHECK(length(key)=32)
            \\);
            \\CREATE TABLE IF NOT EXISTS mail_search_pending (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    folder TEXT NOT NULL,
            \\    basename TEXT NOT NULL,
            \\    short_root INTEGER NOT NULL,
            \\    retry_at INTEGER NOT NULL DEFAULT 0,
            \\    UNIQUE(user_id,folder,basename)
            \\);
            \\CREATE TABLE IF NOT EXISTS mail_search_checkpoints (
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    folder TEXT NOT NULL,
            \\    revision INTEGER NOT NULL,
            \\    PRIMARY KEY(user_id,folder)
            \\);
            \\CREATE TRIGGER IF NOT EXISTS mail_search_revision AFTER INSERT ON mail_search_pending
            \\BEGIN
            \\    INSERT INTO mail_search_checkpoints(user_id,folder,revision) VALUES(NEW.user_id,NEW.folder,NEW.id)
            \\    ON CONFLICT(user_id,folder) DO UPDATE SET revision=excluded.revision;
            \\END;
            \\CREATE TABLE IF NOT EXISTS mailbox_message_refs (
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    reference TEXT NOT NULL,
            \\    folder TEXT NOT NULL,
            \\    basename TEXT NOT NULL,
            \\    file_stamp TEXT NOT NULL,
            \\    next_folder TEXT,
            \\    next_basename TEXT,
            \\    next_digest TEXT,
            \\    next_junk_action TEXT,
            \\    next_junk_receipt TEXT,
            \\    next_retention_at INTEGER,
            \\    intake_folder TEXT NOT NULL DEFAULT '',
            \\    placement_reason TEXT NOT NULL DEFAULT '',
            \\    verified_author TEXT NOT NULL DEFAULT '',
            \\    calendar_history_checked INTEGER NOT NULL DEFAULT 0,
            \\    PRIMARY KEY(user_id,reference),
            \\    UNIQUE(user_id,folder,basename)
            \\);
            \\CREATE INDEX IF NOT EXISTS mailbox_message_refs_pending ON mailbox_message_refs(user_id,next_folder,next_basename) WHERE next_folder IS NOT NULL;
            \\CREATE TABLE IF NOT EXISTS mail_ews_reply_drafts (
            \\    user_id INTEGER NOT NULL,
            \\    draft_reference TEXT NOT NULL,
            \\    draft_wire_id TEXT NOT NULL,
            \\    parent_reference TEXT NOT NULL,
            \\    parent_revision TEXT NOT NULL CHECK(length(parent_revision)=64),
            \\    parent_wire_id TEXT NOT NULL,
            \\    PRIMARY KEY(user_id,draft_reference),
            \\    FOREIGN KEY(user_id,draft_reference) REFERENCES mailbox_message_refs(user_id,reference) ON DELETE CASCADE ON UPDATE CASCADE,
            \\    FOREIGN KEY(user_id,parent_reference) REFERENCES mailbox_message_refs(user_id,reference) ON DELETE CASCADE ON UPDATE CASCADE
            \\);
            \\CREATE TRIGGER IF NOT EXISTS mail_ews_reply_replaced_ref BEFORE UPDATE OF reference ON mailbox_message_refs
            \\WHEN OLD.reference<>NEW.reference BEGIN
            \\    DELETE FROM mail_ews_reply_drafts WHERE user_id=OLD.user_id AND (draft_reference=OLD.reference OR parent_reference=OLD.reference);
            \\END;
            \\CREATE TABLE IF NOT EXISTS mail_ews_draft_sends (
            \\    user_id INTEGER NOT NULL,
            \\    draft_reference TEXT NOT NULL,
            \\    content_revision TEXT NOT NULL CHECK(length(content_revision)=64),
            \\    save_copy INTEGER NOT NULL,
            \\    delivery_id TEXT NOT NULL UNIQUE,
            \\    result TEXT,
            \\    PRIMARY KEY(user_id,draft_reference,content_revision),
            \\    FOREIGN KEY(user_id,draft_reference) REFERENCES mailbox_message_refs(user_id,reference) ON DELETE CASCADE ON UPDATE CASCADE
            \\);
            \\CREATE TRIGGER IF NOT EXISTS mail_ews_draft_send_replaced_ref BEFORE UPDATE OF reference ON mailbox_message_refs
            \\WHEN OLD.reference<>NEW.reference BEGIN
            \\    DELETE FROM mail_ews_draft_sends WHERE user_id=OLD.user_id AND draft_reference=OLD.reference;
            \\END;
            \\CREATE TABLE IF NOT EXISTS mail_ews_draft_finalizations (
            \\    delivery_id TEXT PRIMARY KEY,
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    draft_reference TEXT NOT NULL,
            \\    basename TEXT NOT NULL,
            \\    content_revision TEXT NOT NULL,
            \\    save_copy INTEGER NOT NULL,
            \\    path TEXT NOT NULL,
            \\    fingerprint TEXT NOT NULL,
            \\    draft_id TEXT,
            \\    draft_revision INTEGER,
            \\    submitted_at INTEGER NOT NULL,
            \\    confirmed INTEGER NOT NULL DEFAULT 0,
            \\    retired_at INTEGER
            \\);
            \\CREATE INDEX IF NOT EXISTS mail_ews_draft_finalization_item ON mail_ews_draft_finalizations(user_id,basename,content_revision);
            \\CREATE INDEX IF NOT EXISTS mail_ews_draft_finalization_pending ON mail_ews_draft_finalizations(confirmed,delivery_id) WHERE retired_at IS NULL;
            \\CREATE INDEX IF NOT EXISTS mail_ews_draft_finalization_webmail ON mail_ews_draft_finalizations(user_id,draft_id,draft_revision) WHERE retired_at IS NULL AND draft_id IS NOT NULL;
            \\CREATE TABLE IF NOT EXISTS mail_retention_rules (
            \\    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            \\    folder TEXT,
            \\    days INTEGER NOT NULL,
            \\    revision INTEGER NOT NULL,
            \\    next_run INTEGER NOT NULL,
            \\    last_run INTEGER,
            \\    last_moved INTEGER NOT NULL DEFAULT 0
            \\);
            \\CREATE INDEX IF NOT EXISTS mail_retention_due ON mail_retention_rules(next_run,user_id) WHERE folder IS NOT NULL;
            \\CREATE TABLE IF NOT EXISTS mail_retention_previews (
            \\    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            \\    token TEXT NOT NULL,
            \\    folder TEXT NOT NULL,
            \\    days INTEGER NOT NULL,
            \\    revision INTEGER NOT NULL,
            \\    cutoff INTEGER NOT NULL,
            \\    digest TEXT NOT NULL,
            \\    expires_at INTEGER NOT NULL
            \\);
            \\CREATE TABLE IF NOT EXISTS mail_retention_moves (
            \\    user_id INTEGER NOT NULL,
            \\    reference TEXT NOT NULL,
            \\    source_folder TEXT NOT NULL,
            \\    moved_at INTEGER NOT NULL,
            \\    restored INTEGER NOT NULL DEFAULT 0,
            \\    PRIMARY KEY(user_id,reference),
            \\    FOREIGN KEY(user_id,reference) REFERENCES mailbox_message_refs(user_id,reference) ON DELETE CASCADE
            \\);
            \\CREATE INDEX IF NOT EXISTS mail_retention_recovery ON mail_retention_moves(user_id,moved_at DESC,reference) WHERE restored=0;
            \\CREATE TABLE IF NOT EXISTS mailbox_junk_feedback (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    reference TEXT NOT NULL,
            \\    receipt TEXT NOT NULL UNIQUE,
            \\    author TEXT NOT NULL COLLATE NOCASE,
            \\    action TEXT NOT NULL CHECK(action IN ('junk','not_junk')),
            \\    source_folder TEXT NOT NULL,
            \\    created_at INTEGER NOT NULL DEFAULT (unixepoch())
            \\);
            \\CREATE INDEX IF NOT EXISTS mailbox_junk_by_author ON mailbox_junk_feedback(user_id,author,id DESC) WHERE author<>'';
            \\CREATE INDEX IF NOT EXISTS mailbox_junk_by_message ON mailbox_junk_feedback(user_id,reference,id DESC);
            \\CREATE INDEX IF NOT EXISTS mailbox_junk_age ON mailbox_junk_feedback(created_at);
            \\CREATE TABLE IF NOT EXISTS webmail_search_docs (
            \\    id INTEGER PRIMARY KEY,
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    folder TEXT NOT NULL,
            \\    basename TEXT NOT NULL,
            \\    fingerprint TEXT NOT NULL,
            \\    digest TEXT NOT NULL,
            \\    sender TEXT NOT NULL,
            \\    recipient TEXT NOT NULL,
            \\    cc TEXT NOT NULL,
            \\    bcc TEXT NOT NULL,
            \\    subject TEXT NOT NULL,
            \\    sent_date TEXT NOT NULL,
            \\    message_id TEXT NOT NULL,
            \\    in_reply_to TEXT NOT NULL,
            \\    reply_chain TEXT NOT NULL,
            \\    snippet TEXT NOT NULL,
            \\    body_text TEXT NOT NULL,
            \\    attachment_metadata TEXT NOT NULL,
            \\    UNIQUE(user_id,folder,basename)
            \\);
            \\CREATE VIRTUAL TABLE IF NOT EXISTS webmail_search_text USING fts5(
            \\    sender,recipient,cc,bcc,subject,body_text,content='webmail_search_docs',tokenize='trigram'
            \\);
            \\CREATE TRIGGER IF NOT EXISTS webmail_search_insert AFTER INSERT ON webmail_search_docs BEGIN
            \\    INSERT INTO webmail_search_text(rowid,sender,recipient,cc,bcc,subject,body_text)
            \\    VALUES(new.id,new.sender,new.recipient,new.cc,new.bcc,new.subject,new.body_text);
            \\END;
            \\CREATE TRIGGER IF NOT EXISTS webmail_search_delete AFTER DELETE ON webmail_search_docs BEGIN
            \\    INSERT INTO webmail_search_text(webmail_search_text,rowid,sender,recipient,cc,bcc,subject,body_text)
            \\    VALUES('delete',old.id,old.sender,old.recipient,old.cc,old.bcc,old.subject,old.body_text);
            \\END;
            \\CREATE TRIGGER IF NOT EXISTS webmail_search_update AFTER UPDATE ON webmail_search_docs BEGIN
            \\    INSERT INTO webmail_search_text(webmail_search_text,rowid,sender,recipient,cc,bcc,subject,body_text)
            \\    VALUES('delete',old.id,old.sender,old.recipient,old.cc,old.bcc,old.subject,old.body_text);
            \\    INSERT INTO webmail_search_text(rowid,sender,recipient,cc,bcc,subject,body_text)
            \\    VALUES(new.id,new.sender,new.recipient,new.cc,new.bcc,new.subject,new.body_text);
            \\END;
            \\CREATE TABLE IF NOT EXISTS mail_private_anchors (
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    reference TEXT NOT NULL,
            \\    wire_ids TEXT NOT NULL,
            \\    PRIMARY KEY(user_id,reference)
            \\);
            \\CREATE TABLE IF NOT EXISTS mail_private_entries (
            \\    user_id INTEGER NOT NULL,
            \\    id TEXT NOT NULL DEFAULT (lower(hex(randomblob(16)))),
            \\    anchor TEXT NOT NULL,
            \\    kind TEXT NOT NULL CHECK(kind IN ('note','clip')),
            \\    body TEXT NOT NULL,
            \\    source_subject TEXT NOT NULL DEFAULT '',
            \\    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
            \\    revision INTEGER NOT NULL DEFAULT 1,
            \\    PRIMARY KEY(user_id,id),
            \\    FOREIGN KEY(user_id,anchor) REFERENCES mail_private_anchors(user_id,reference) ON DELETE CASCADE
            \\);
            \\CREATE INDEX IF NOT EXISTS mail_private_entries_anchor ON mail_private_entries(user_id,anchor);
            \\CREATE TABLE IF NOT EXISTS mail_private_labels (
            \\    user_id INTEGER NOT NULL,
            \\    anchor TEXT NOT NULL,
            \\    label TEXT NOT NULL,
            \\    revision TEXT NOT NULL,
            \\    changed_ms INTEGER NOT NULL,
            \\    PRIMARY KEY(user_id,anchor),
            \\    FOREIGN KEY(user_id,anchor) REFERENCES mail_private_anchors(user_id,reference) ON DELETE CASCADE
            \\);
            \\CREATE TABLE IF NOT EXISTS mail_private_groups (
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    id TEXT NOT NULL DEFAULT (lower(hex(randomblob(16)))),
            \\    anchors TEXT NOT NULL,
            \\    undo_until INTEGER NOT NULL,
            \\    PRIMARY KEY(user_id,id)
            \\);
            \\CREATE TABLE IF NOT EXISTS mail_private_collections (
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    id TEXT NOT NULL DEFAULT (lower(hex(randomblob(16)))),
            \\    name TEXT NOT NULL COLLATE NOCASE,
            \\    revision INTEGER NOT NULL DEFAULT 1,
            \\    PRIMARY KEY(user_id,id),
            \\    UNIQUE(user_id,name)
            \\);
            \\CREATE TABLE IF NOT EXISTS mail_private_members (
            \\    user_id INTEGER NOT NULL,
            \\    collection TEXT NOT NULL,
            \\    anchor TEXT NOT NULL,
            \\    PRIMARY KEY(user_id,collection,anchor),
            \\    FOREIGN KEY(user_id,collection) REFERENCES mail_private_collections(user_id,id) ON DELETE CASCADE,
            \\    FOREIGN KEY(user_id,anchor) REFERENCES mail_private_anchors(user_id,reference) ON DELETE CASCADE
            \\);
            \\CREATE INDEX IF NOT EXISTS mail_private_member_anchor ON mail_private_members(user_id,anchor);
            \\CREATE TABLE IF NOT EXISTS mail_attention (
            \\    user_id INTEGER NOT NULL,
            \\    reference TEXT NOT NULL,
            \\    kind TEXT NOT NULL CHECK(kind IN ('follow_up','saved','snoozed','muted','reminders')),
            \\    deadline INTEGER NOT NULL,
            \\    changed_ms INTEGER NOT NULL,
            \\    wire_ids TEXT NOT NULL,
            \\    waiting_id TEXT NOT NULL DEFAULT '',
            \\    PRIMARY KEY(user_id,reference,kind),
            \\    FOREIGN KEY(user_id,reference) REFERENCES mailbox_message_refs(user_id,reference) ON DELETE CASCADE ON UPDATE CASCADE
            \\);
            \\CREATE INDEX IF NOT EXISTS mail_attention_kind ON mail_attention(user_id,kind,deadline);
            \\CREATE TRIGGER IF NOT EXISTS mail_attention_replaced_ref BEFORE UPDATE OF reference ON mailbox_message_refs
            \\WHEN OLD.reference<>NEW.reference BEGIN
            \\    DELETE FROM mail_attention WHERE user_id=OLD.user_id AND reference=OLD.reference;
            \\END;
            \\CREATE TABLE IF NOT EXISTS mail_attention_replies (
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    parent_id TEXT NOT NULL,
            \\    last_ms INTEGER NOT NULL,
            \\    PRIMARY KEY(user_id,parent_id)
            \\);
            \\CREATE INDEX IF NOT EXISTS mail_attention_reply_retention ON mail_attention_replies(last_ms);
            \\CREATE TABLE IF NOT EXISTS mail_notification_settings (
            \\    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            \\    enabled INTEGER NOT NULL CHECK(enabled IN (0,1))
            \\);
            \\CREATE TABLE IF NOT EXISTS mail_notification_senders (
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    author TEXT NOT NULL COLLATE NOCASE,
            \\    rule TEXT NOT NULL CHECK(rule IN ('notify','quiet')),
            \\    PRIMARY KEY(user_id,author)
            \\);
            \\CREATE TABLE IF NOT EXISTS mail_notification_threads (
            \\    user_id INTEGER NOT NULL,
            \\    reference TEXT NOT NULL,
            \\    wire_ids TEXT NOT NULL,
            \\    rule TEXT NOT NULL CHECK(rule IN ('notify','quiet')),
            \\    PRIMARY KEY(user_id,reference),
            \\    FOREIGN KEY(user_id,reference) REFERENCES mailbox_message_refs(user_id,reference) ON DELETE CASCADE ON UPDATE CASCADE
            \\);
            \\CREATE TRIGGER IF NOT EXISTS mail_notification_replaced_ref BEFORE UPDATE OF reference ON mailbox_message_refs
            \\WHEN OLD.reference<>NEW.reference BEGIN
            \\    DELETE FROM mail_notification_threads WHERE user_id=OLD.user_id AND reference=OLD.reference;
            \\END;
            \\CREATE TABLE IF NOT EXISTS mail_notification_events (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    event_key TEXT NOT NULL,
            \\    folder TEXT NOT NULL,
            \\    author TEXT NOT NULL,
            \\    own_id TEXT,
            \\    parents_json TEXT NOT NULL,
            \\    created_at INTEGER NOT NULL,
            \\    claimed_at INTEGER,
            \\    UNIQUE(user_id,event_key)
            \\);
            \\CREATE INDEX IF NOT EXISTS mail_notification_pending ON mail_notification_events(user_id,id) WHERE claimed_at IS NULL;
            \\CREATE INDEX IF NOT EXISTS mail_notification_retention ON mail_notification_events(created_at);
            \\CREATE TABLE IF NOT EXISTS mail_category_settings (
            \\    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            \\    automatic INTEGER NOT NULL
            \\);
            \\CREATE TABLE IF NOT EXISTS mailbox_forwarding (
            \\    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            \\    address TEXT,
            \\    destination_id INTEGER,
            \\    pending_address TEXT,
            \\    pending_destination_id INTEGER,
            \\    code_hash BLOB,
            \\    expires_at INTEGER,
            \\    attempts INTEGER NOT NULL DEFAULT 0,
            \\    revision INTEGER NOT NULL DEFAULT 1
            \\);
            \\CREATE TABLE IF NOT EXISTS mailbox_forwarding_scopes (
            \\    user_id INTEGER PRIMARY KEY REFERENCES mailbox_forwarding(user_id) ON DELETE CASCADE,
            \\    revision INTEGER NOT NULL,
            \\    address TEXT NOT NULL,
            \\    destination_id INTEGER,
            \\    sender TEXT,
            \\    recipient TEXT,
            \\    CHECK(sender IS NOT NULL OR recipient IS NOT NULL)
            \\);
            \\CREATE TABLE IF NOT EXISTS mailbox_forwarding_requests (
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    address TEXT NOT NULL COLLATE NOCASE,
            \\    requested_at INTEGER NOT NULL
            \\);
            \\CREATE INDEX IF NOT EXISTS mailbox_forward_requests_time ON mailbox_forwarding_requests(requested_at);
            \\CREATE INDEX IF NOT EXISTS mailbox_forward_requests_owner ON mailbox_forwarding_requests(user_id,requested_at);
            \\CREATE INDEX IF NOT EXISTS mailbox_forward_requests_address ON mailbox_forwarding_requests(address,requested_at);
            \\CREATE TABLE IF NOT EXISTS mailbox_vacation (
            \\    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            \\    enabled INTEGER NOT NULL,
            \\    subject TEXT NOT NULL,
            \\    body TEXT NOT NULL,
            \\    starts_at INTEGER,
            \\    ends_at INTEGER,
            \\    revision INTEGER NOT NULL DEFAULT 1
            \\);
            \\CREATE TABLE IF NOT EXISTS mailbox_vacation_sends (
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    correspondent TEXT NOT NULL COLLATE NOCASE,
            \\    accepted_at INTEGER NOT NULL,
            \\    PRIMARY KEY(user_id,correspondent)
            \\);
            \\CREATE INDEX IF NOT EXISTS mailbox_vacation_sends_owner_time ON mailbox_vacation_sends(user_id,accepted_at);
            \\CREATE INDEX IF NOT EXISTS mailbox_vacation_sends_expiry ON mailbox_vacation_sends(accepted_at);
            \\CREATE TABLE IF NOT EXISTS mail_category_rules (
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    author TEXT NOT NULL COLLATE NOCASE,
            \\    destination TEXT NOT NULL CHECK(destination IN ('inbox','newsletters','receipts')),
            \\    PRIMARY KEY(user_id,author)
            \\);
            \\CREATE TABLE IF NOT EXISTS accepted_mail (
            \\    id TEXT PRIMARY KEY,
            \\    accepted_at INTEGER NOT NULL,
            \\    accepted_ms INTEGER NOT NULL,
            \\    envelope_from TEXT NOT NULL,
            \\    author TEXT NOT NULL,
            \\    verified_author INTEGER NOT NULL,
            \\    remote_addr TEXT NOT NULL,
            \\    mime BLOB NOT NULL,
            \\    complete INTEGER NOT NULL DEFAULT 0
            \\);
            \\CREATE TABLE IF NOT EXISTS accepted_mail_targets (
            \\    delivery_id TEXT NOT NULL REFERENCES accepted_mail(id) ON DELETE CASCADE,
            \\    ordinal INTEGER NOT NULL,
            \\    recipient TEXT NOT NULL,
            \\    mailbox TEXT NOT NULL,
            \\    mailbox_id INTEGER NOT NULL,
            \\    folder TEXT NOT NULL,
            \\    outcome TEXT NOT NULL,
            \\    queued_bytes INTEGER NOT NULL,
            \\    retry_at INTEGER NOT NULL,
            \\    attempts INTEGER NOT NULL DEFAULT 0,
            \\    is_primary INTEGER NOT NULL,
            \\    review_copy INTEGER NOT NULL DEFAULT 0,
            \\    placement_reason TEXT NOT NULL DEFAULT '',
            \\    forward_after INTEGER,
            \\    verified_forward INTEGER NOT NULL DEFAULT 0,
            \\    reply_author TEXT,
            \\    reply_from TEXT,
            \\    reply_mime BLOB,
            \\    PRIMARY KEY(delivery_id,ordinal)
            \\);
            \\CREATE INDEX IF NOT EXISTS accepted_mail_retry ON accepted_mail_targets(retry_at,delivery_id) WHERE outcome='pending';
            \\CREATE INDEX IF NOT EXISTS accepted_mail_reservations ON accepted_mail_targets(mailbox) WHERE outcome='pending';
            \\CREATE INDEX IF NOT EXISTS accepted_mail_retention ON accepted_mail(accepted_at) WHERE complete=1;
            \\CREATE TABLE IF NOT EXISTS outbound_delivery_minutes (
            \\    minute INTEGER PRIMARY KEY,
            \\    delivered INTEGER NOT NULL DEFAULT 0,
            \\    failed INTEGER NOT NULL DEFAULT 0
            \\);
            \\CREATE TABLE IF NOT EXISTS mail_calendar_day_labels (
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    day TEXT NOT NULL,
            \\    label TEXT,
            \\    revision INTEGER NOT NULL CHECK(revision > 0),
            \\    PRIMARY KEY(user_id,day)
            \\);
            \\CREATE TABLE IF NOT EXISTS mail_calendar_tasks (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    title TEXT NOT NULL,
            \\    day TEXT,
            \\    completed INTEGER NOT NULL CHECK(completed IN (0,1)),
            \\    revision INTEGER NOT NULL CHECK(revision > 0)
            \\);
            \\CREATE INDEX IF NOT EXISTS mail_calendar_tasks_owner ON mail_calendar_tasks(user_id);
            \\CREATE TABLE IF NOT EXISTS mail_snapshot_links (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    token_hash TEXT NOT NULL UNIQUE,
            \\    payload TEXT NOT NULL,
            \\    subject TEXT NOT NULL,
            \\    message_count INTEGER NOT NULL,
            \\    expires_at INTEGER NOT NULL
            \\);
            \\CREATE INDEX IF NOT EXISTS mail_snapshot_links_owner ON mail_snapshot_links(user_id,expires_at);
            \\CREATE INDEX IF NOT EXISTS mail_snapshot_links_expiry ON mail_snapshot_links(expires_at);
            \\CREATE TABLE IF NOT EXISTS mail_assistant_grants (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    integration TEXT NOT NULL,
            \\    token_hash TEXT NOT NULL UNIQUE,
            \\    read_allowed INTEGER NOT NULL,
            \\    draft_allowed INTEGER NOT NULL,
            \\    payload TEXT NOT NULL,
            \\    expires_at INTEGER NOT NULL,
            \\    revoked_at INTEGER
            \\);
            \\CREATE INDEX IF NOT EXISTS mail_assistant_owner ON mail_assistant_grants(user_id,id);
            \\CREATE INDEX IF NOT EXISTS mail_assistant_expiry ON mail_assistant_grants(expires_at);
            \\CREATE TABLE IF NOT EXISTS mail_assistant_audit (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    grant_id INTEGER NOT NULL REFERENCES mail_assistant_grants(id) ON DELETE CASCADE,
            \\    actor TEXT NOT NULL,
            \\    action TEXT NOT NULL,
            \\    outcome TEXT NOT NULL,
            \\    occurred_at INTEGER NOT NULL
            \\);
            \\CREATE INDEX IF NOT EXISTS mail_assistant_audit_grant ON mail_assistant_audit(grant_id,id);
            \\CREATE TABLE IF NOT EXISTS mail_assistant_requests (
            \\    grant_id INTEGER NOT NULL REFERENCES mail_assistant_grants(id) ON DELETE CASCADE,
            \\    request_id TEXT NOT NULL,
            \\    digest TEXT NOT NULL,
            \\    acknowledgement TEXT,
            \\    PRIMARY KEY(grant_id,request_id)
            \\);
            \\CREATE TABLE IF NOT EXISTS mail_file_links (
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    id TEXT NOT NULL,
            \\    token_hash TEXT NOT NULL UNIQUE,
            \\    filename TEXT NOT NULL,
            \\    data BLOB NOT NULL,
            \\    size INTEGER NOT NULL CHECK(size > 0 AND size = length(data)),
            \\    expires_at INTEGER NOT NULL,
            \\    PRIMARY KEY(user_id,id)
            \\);
            \\CREATE INDEX IF NOT EXISTS mail_file_links_owner ON mail_file_links(user_id,expires_at);
            \\CREATE INDEX IF NOT EXISTS mail_file_links_expiry ON mail_file_links(expires_at);
            \\CREATE TABLE IF NOT EXISTS mail_calendar_tools (
            \\    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            \\    payload TEXT NOT NULL,
            \\    revision INTEGER NOT NULL CHECK(revision > 0)
            \\);
            \\CREATE TABLE IF NOT EXISTS mail_calendar_revisions (
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    component TEXT NOT NULL,
            \\    series TEXT NOT NULL,
            \\    method TEXT NOT NULL CHECK(method IN ('request','cancel')),
            \\    future INTEGER NOT NULL,
            \\    sequence INTEGER NOT NULL,
            \\    dtstamp INTEGER NOT NULL,
            \\    occurrence_wall INTEGER,
            \\    occurrence_zone TEXT,
            \\    occurrence_day INTEGER,
            \\    PRIMARY KEY(user_id,component,method,future)
            \\);
            \\CREATE INDEX IF NOT EXISTS mail_calendar_revision_series ON mail_calendar_revisions(user_id,series);
            \\CREATE TABLE IF NOT EXISTS accepted_mail_effects (
            \\    delivery_id TEXT NOT NULL,
            \\    ordinal INTEGER NOT NULL,
            \\    filename TEXT NOT NULL,
            \\    size INTEGER NOT NULL,
            \\    indexed INTEGER NOT NULL DEFAULT 0,
            \\    notified INTEGER NOT NULL,
            \\    PRIMARY KEY(delivery_id,ordinal),
            \\    FOREIGN KEY(delivery_id,ordinal) REFERENCES accepted_mail_targets(delivery_id,ordinal) ON DELETE CASCADE
            \\);
            \\CREATE INDEX IF NOT EXISTS accepted_mail_pending_effects ON accepted_mail_effects(delivery_id,ordinal) WHERE indexed=0 OR notified=0;
            \\CREATE TABLE IF NOT EXISTS sender_screening (
            \\    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            \\    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
            \\    onboarding_pending INTEGER NOT NULL DEFAULT 0
            \\);
            \\CREATE TABLE IF NOT EXISTS sender_screening_rules (
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    author TEXT NOT NULL COLLATE NOCASE,
            \\    action TEXT NOT NULL CHECK(action IN ('allow','decline')),
            \\    forward INTEGER NOT NULL DEFAULT 1 CHECK(forward IN (0,1)),
            \\    revision INTEGER NOT NULL DEFAULT 1,
            \\    PRIMARY KEY(user_id,author)
            \\);
            \\CREATE TABLE IF NOT EXISTS sender_review_invitations (
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    author TEXT NOT NULL COLLATE NOCASE,
            \\    id TEXT NOT NULL,
            \\    expires_at INTEGER NOT NULL,
            \\    PRIMARY KEY(user_id,author),
            \\    UNIQUE(user_id,id)
            \\);
            \\CREATE TABLE IF NOT EXISTS sender_review_messages (
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    basename TEXT NOT NULL,
            \\    folder TEXT NOT NULL,
            \\    envelope_from TEXT NOT NULL,
            \\    author TEXT NOT NULL,
            \\    verified_author INTEGER NOT NULL,
            \\    recipient TEXT NOT NULL DEFAULT '',
            \\    remote_addr TEXT NOT NULL DEFAULT '',
            \\    file_stamp TEXT NOT NULL DEFAULT '',
            \\    reference TEXT,
            \\    next_folder TEXT,
            \\    operation TEXT,
            \\    forward_release INTEGER NOT NULL DEFAULT 0,
            \\    retry_at INTEGER NOT NULL DEFAULT 0,
            \\    PRIMARY KEY(user_id,basename)
            \\);
            \\CREATE TABLE IF NOT EXISTS eas_mailbox_state (
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    device_id TEXT NOT NULL,
            \\    collection_id TEXT NOT NULL,
            \\    sync_key TEXT NOT NULL,
            \\    items TEXT NOT NULL,
            \\    PRIMARY KEY (user_id, device_id, collection_id)
            \\);
            \\CREATE TABLE IF NOT EXISTS eas_mailbox_ping (
            \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            \\    device_id TEXT NOT NULL,
            \\    heartbeat INTEGER NOT NULL,
            \\    folders TEXT NOT NULL,
            \\    PRIMARY KEY (user_id, device_id)
            \\);
            \\CREATE TABLE IF NOT EXISTS eas_accepted_submissions (
            \\    username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE ON UPDATE CASCADE,
            \\    device_id TEXT NOT NULL,
            \\    client_id TEXT NOT NULL,
            \\    accepted_at INTEGER NOT NULL,
            \\    PRIMARY KEY (username, device_id, client_id)
            \\);
            \\CREATE INDEX IF NOT EXISTS idx_eas_accepted_at ON eas_accepted_submissions(username, accepted_at);
            \\CREATE TABLE IF NOT EXISTS hosted_sending_usage (
            \\    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            \\    utc_day INTEGER NOT NULL,
            \\    recipients INTEGER NOT NULL
            \\);
        );
        // The routing-only build already created these three tables. Keep
        // its review copies and default legacy rules to revision one.
        self.exec("ALTER TABLE accepted_mail_targets ADD COLUMN review_copy INTEGER") catch {};
        self.exec("ALTER TABLE accepted_mail_targets ADD COLUMN placement_reason TEXT NOT NULL DEFAULT ''") catch {};
        self.exec("ALTER TABLE accepted_mail_targets ADD COLUMN verified_forward INTEGER NOT NULL DEFAULT 0") catch {};
        self.exec("ALTER TABLE accepted_mail_targets ADD COLUMN reply_author TEXT") catch {};
        self.exec("ALTER TABLE accepted_mail_targets ADD COLUMN reply_from TEXT") catch {};
        self.exec("ALTER TABLE accepted_mail_targets ADD COLUMN reply_mime BLOB") catch {};
        self.exec("ALTER TABLE mailbox_message_refs ADD COLUMN intake_folder TEXT NOT NULL DEFAULT ''") catch {};
        self.exec("ALTER TABLE mailbox_message_refs ADD COLUMN placement_reason TEXT NOT NULL DEFAULT ''") catch {};
        self.exec("ALTER TABLE mailbox_message_refs ADD COLUMN verified_author TEXT NOT NULL DEFAULT ''") catch {};
        self.exec("ALTER TABLE mailbox_message_refs ADD COLUMN calendar_history_checked INTEGER NOT NULL DEFAULT 0") catch {};
        try self.exec("CREATE INDEX IF NOT EXISTS mailbox_calendar_history ON mailbox_message_refs(user_id,verified_author COLLATE NOCASE,reference) WHERE " ++ pending_calendar_history);
        self.exec("ALTER TABLE mailbox_message_refs ADD COLUMN next_junk_action TEXT") catch {};
        self.exec("ALTER TABLE mailbox_message_refs ADD COLUMN next_junk_receipt TEXT") catch {};
        self.exec("ALTER TABLE mailbox_message_refs ADD COLUMN next_retention_at INTEGER") catch {};
        // Finalize the feedback with the recorded Maildir handoff. This also
        // runs when a client read recovers a rename after a process restart.
        try self.exec(
            \\CREATE TRIGGER IF NOT EXISTS mailbox_junk_handoff AFTER UPDATE OF folder ON mailbox_message_refs
            \\WHEN OLD.next_junk_receipt IS NOT NULL AND OLD.folder<>NEW.folder AND OLD.next_folder=NEW.folder AND OLD.next_basename=NEW.basename
            \\BEGIN
            \\    INSERT OR IGNORE INTO mailbox_junk_feedback(user_id,reference,receipt,author,action,source_folder)
            \\      SELECT OLD.user_id,OLD.reference,OLD.next_junk_receipt,OLD.verified_author,OLD.next_junk_action,OLD.folder
            \\      WHERE OLD.next_junk_action IN ('junk','not_junk');
            \\    DELETE FROM mailbox_junk_feedback WHERE OLD.next_junk_action='undo' AND user_id=OLD.user_id AND reference=OLD.reference AND receipt=OLD.next_junk_receipt;
            \\END;
            \\CREATE TRIGGER IF NOT EXISTS mailbox_retention_handoff AFTER UPDATE OF folder ON mailbox_message_refs
            \\WHEN OLD.next_retention_at IS NOT NULL AND OLD.folder<>NEW.folder AND NEW.folder='Trash'
            \\  AND OLD.next_folder=NEW.folder AND OLD.next_basename=NEW.basename
            \\BEGIN
            \\    INSERT OR IGNORE INTO mail_retention_moves(user_id,reference,source_folder,moved_at)
            \\      VALUES(NEW.user_id,NEW.reference,OLD.folder,OLD.next_retention_at);
            \\END;
            \\CREATE TRIGGER IF NOT EXISTS mailbox_retention_recovered AFTER UPDATE OF folder ON mailbox_message_refs
            \\WHEN OLD.folder='Trash' AND NEW.folder<>OLD.folder
            \\BEGIN
            \\    UPDATE mail_retention_moves SET restored=1 WHERE user_id=NEW.user_id AND reference=NEW.reference;
            \\END;
            \\CREATE TRIGGER IF NOT EXISTS mailbox_retention_replaced_ref BEFORE UPDATE OF reference ON mailbox_message_refs
            \\WHEN OLD.reference<>NEW.reference
            \\BEGIN
            \\    DELETE FROM mail_retention_moves WHERE user_id=OLD.user_id AND reference=OLD.reference;
            \\END;
        );
        try self.exec("UPDATE accepted_mail_targets SET review_copy=(folder IN ('Screening','Declined')) WHERE review_copy IS NULL");
        self.exec("ALTER TABLE sender_screening ADD COLUMN onboarding_pending INTEGER NOT NULL DEFAULT 0") catch {};
        self.exec("ALTER TABLE sender_screening_rules ADD COLUMN revision INTEGER NOT NULL DEFAULT 1") catch {};
        for ([_][]const u8{
            "recipient TEXT NOT NULL DEFAULT ''",
            "remote_addr TEXT NOT NULL DEFAULT ''",
            "file_stamp TEXT NOT NULL DEFAULT ''",
            "reference TEXT",
            "next_folder TEXT",
            "operation TEXT",
            "forward_release INTEGER NOT NULL DEFAULT 0",
            "retry_at INTEGER NOT NULL DEFAULT 0",
        }) |column| {
            const sql = try std.fmt.allocPrint(self.allocator, "ALTER TABLE sender_review_messages ADD COLUMN {s}", .{column});
            defer self.allocator.free(sql);
            self.exec(sql) catch {};
        }
        try self.exec(
            \\CREATE INDEX IF NOT EXISTS sender_review_folder ON sender_review_messages(user_id,folder,basename);
            \\CREATE INDEX IF NOT EXISTS sender_review_author ON sender_review_messages(user_id,author COLLATE NOCASE) WHERE verified_author=1;
            \\CREATE INDEX IF NOT EXISTS sender_review_work ON sender_review_messages(retry_at,operation) WHERE operation IS NOT NULL;
        );
        self.exec("ALTER TABLE provisioned_mailboxes ADD COLUMN send_recipients_per_day INTEGER NOT NULL DEFAULT 0") catch {};
        self.exec("ALTER TABLE users ADD COLUMN recovery_updated_at INTEGER;") catch {};

        // Single-use password reset tokens (see src/api/webmail_recovery.zig).
        // Only the SHA-256 of a token is stored. Rows outlive their use for an
        // hour so the per-mailbox send limit can count them.
        //
        // No foreign key to users(username), deliberately: a username is
        // rewritten by `domain migrate` and by deploy-time username migrations,
        // and a referencing row would make that UPDATE fail. deleteUser and
        // renameDomain remove a mailbox's tokens explicitly instead.
        try self.exec(
            \\CREATE TABLE IF NOT EXISTS mailbox_reset_tokens (
            \\    token_hash TEXT PRIMARY KEY,
            \\    username TEXT NOT NULL,
            \\    recovery_email TEXT NOT NULL,
            \\    created_at INTEGER NOT NULL,
            \\    expires_at INTEGER NOT NULL,
            \\    used_at INTEGER,
            \\    ip_address TEXT
            \\);
            \\CREATE INDEX IF NOT EXISTS idx_mailbox_reset_tokens_user ON mailbox_reset_tokens(username, created_at);
        );

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
        try self.exec(@import("webmail_account_links.zig").schema);
        try self.initAuditTable();
        try self.exec(team_store.schema);
        try self.exec(shared_inbox.schema);
        try self.exec(team_threads.schema);
        var tx = try self.beginTransaction(.write);
        defer tx.deinit();
        const has_outgoing = blk: {
            const column = try tx.prepare("SELECT 1 FROM pragma_table_info('mail_team_thread_replies') WHERE name='outgoing'");
            defer column.finalize();
            break :blk try column.step();
        };
        if (!has_outgoing) try self.execLocked("ALTER TABLE mail_team_thread_replies ADD COLUMN outgoing INTEGER NOT NULL DEFAULT 0 CHECK(outgoing IN (0,1))");
        try tx.commit();
    }

    pub fn exec(self: *Database, sql: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
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
        var stmt = try self.prepareLocked(sql);
        stmt.mutex = &self.mutex;
        return stmt;
    }

    fn prepareLocked(self: *Database, sql: []const u8) !Statement {
        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
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

    pub const Transaction = struct {
        db: *Database,
        committed: bool = false,

        pub fn prepare(self: Transaction, sql: []const u8) !Statement {
            return self.db.prepareLocked(sql);
        }

        pub fn commit(self: *Transaction) !void {
            try self.db.execLocked("COMMIT");
            self.committed = true;
        }

        pub fn deinit(self: Transaction) void {
            if (!self.committed) self.db.execLocked("ROLLBACK") catch {};
            self.db.mutex.unlock();
        }
    };

    pub fn beginTransaction(self: *Database, mode: enum { read, write }) !Transaction {
        self.mutex.lock();
        errdefer self.mutex.unlock();
        try self.execLocked(if (mode == .write) "BEGIN IMMEDIATE" else "BEGIN");
        return .{ .db = self };
    }

    pub const ProvisioningChange = struct {
        mailbox: []const u8,
        actor: []const u8,
        operation_id: []const u8,
        revision: i64,
        quota_bytes: i64,
        send_recipients_per_day: i64 = 0,
        enabled: bool,
        initial_recovery: ?[]const u8 = null,
        initial_password_hash: ?[]const u8 = null,
    };

    pub const ProvisioningState = struct {
        mailbox: []const u8,
        revision: i64,
        quota_bytes: i64,
        send_recipients_per_day: i64 = 0,
        enabled: bool,
    };

    fn provisioningStateLocked(self: *Database, mailbox: []const u8, actor: []const u8) !ProvisioningState {
        const stmt = try self.prepareLocked(
            "SELECT p.revision, u.quota_limit, u.enabled, p.send_recipients_per_day FROM provisioned_mailboxes p JOIN users u ON u.id = p.user_id AND u.username = p.mailbox WHERE p.mailbox = ? AND p.actor = ?",
        );
        defer stmt.finalize();
        try stmt.bind(1, mailbox);
        try stmt.bind(2, actor);
        if (!try stmt.step()) return error.MailboxNotFound;
        return .{ .mailbox = mailbox, .revision = stmt.columnInt64(0), .quota_bytes = stmt.columnInt64(1), .enabled = stmt.columnInt64(2) != 0, .send_recipients_per_day = stmt.columnInt64(3) };
    }

    pub fn provisioningState(self: *Database, mailbox: []const u8, actor: []const u8) !ProvisioningState {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.provisioningStateLocked(mailbox, actor);
    }

    /// Commit account creation and its operation record together. Existing
    /// operator-managed accounts are never adopted by provisioning.
    pub fn applyProvisioning(self: *Database, change: ProvisioningChange) !ProvisioningState {
        self.lockMailboxes();
        defer self.unlockMailboxes();
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.execLocked("BEGIN IMMEDIATE");
        errdefer self.execLocked("ROLLBACK") catch {};
        {
            const operation = try self.prepareLocked("SELECT mailbox, revision FROM provisioning_operations WHERE operation_id = ?");
            defer operation.finalize();
            try operation.bind(1, change.operation_id);
            if (try operation.step() and (!std.mem.eql(u8, operation.columnText(0), change.mailbox) or operation.columnInt64(1) != change.revision))
                return error.OperationConflict;
        }
        const record = try self.prepareLocked(
            "SELECT actor, operation_id, revision, requested_quota, requested_enabled, initial_recovery, user_id, send_recipients_per_day FROM provisioned_mailboxes WHERE mailbox = ?",
        );
        defer record.finalize();
        try record.bind(1, change.mailbox);
        const now = time_compat.timestamp();
        if (try record.step()) {
            if (!std.mem.eql(u8, record.columnText(0), change.actor)) return error.MailboxUnavailable;
            const previous = record.columnInt64(2);
            const same_operation = std.mem.eql(u8, record.columnText(1), change.operation_id);
            if (same_operation) {
                if (previous != change.revision or record.columnInt64(3) != change.quota_bytes or record.columnInt64(7) != change.send_recipients_per_day or
                    (record.columnInt64(4) != 0) != change.enabled or
                    (change.initial_recovery != null and !std.mem.eql(u8, record.columnText(5), change.initial_recovery.?)))
                    return error.OperationConflict;
            } else {
                if (change.revision - 1 != previous) return error.StaleRevision;
                const update = try self.prepareLocked("UPDATE users SET quota_limit = ?, enabled = ?, updated_at = ? WHERE id = ? AND username = ?");
                defer update.finalize();
                try update.bind(1, change.quota_bytes);
                try update.bind(2, @as(i64, @intFromBool(change.enabled)));
                try update.bind(3, now);
                try update.bind(4, record.columnInt64(6));
                try update.bind(5, change.mailbox);
                _ = try update.step();
                if (sqlite.sqlite3_changes(self.db) == 0) return error.MailboxNotFound;
                if (!change.enabled) {
                    try self.deleteUserSessionsLocked(change.mailbox);
                    try self.deleteUserResetTokensLocked(change.mailbox);
                }
                const next = try self.prepareLocked("UPDATE provisioned_mailboxes SET operation_id = ?, revision = ?, requested_quota = ?, requested_enabled = ?, send_recipients_per_day = ? WHERE mailbox = ?");
                defer next.finalize();
                try next.bind(1, change.operation_id);
                try next.bind(2, change.revision);
                try next.bind(3, change.quota_bytes);
                try next.bind(4, @as(i64, @intFromBool(change.enabled)));
                try next.bind(5, change.send_recipients_per_day);
                try next.bind(6, change.mailbox);
                _ = try next.step();
            }
        } else {
            if (change.revision != 1) return error.StaleRevision;
            const password = change.initial_password_hash orelse return error.IncompleteCreate;
            const recovery_address = change.initial_recovery orelse return error.IncompleteCreate;
            {
                const occupied = try self.prepareLocked("SELECT 1 FROM users WHERE username = ? OR email = ? UNION ALL SELECT 1 FROM provisioned_mailboxes WHERE actor = ? LIMIT 1");
                defer occupied.finalize();
                try occupied.bind(1, change.mailbox);
                try occupied.bind(2, change.mailbox);
                try occupied.bind(3, change.actor);
                if (try occupied.step()) return error.MailboxUnavailable;
            }
            const user = try self.prepareLocked(
                "INSERT INTO users(username, email, password_hash, enabled, quota_limit, recovery_email, recovery_source, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'operator', ?, ?)",
            );
            defer user.finalize();
            try user.bind(1, change.mailbox);
            try user.bind(2, change.mailbox);
            try user.bind(3, password);
            try user.bind(4, @as(i64, @intFromBool(change.enabled)));
            try user.bind(5, change.quota_bytes);
            try user.bind(6, recovery_address);
            try user.bind(7, now);
            try user.bind(8, now);
            _ = try user.step();
            const id = sqlite.sqlite3_last_insert_rowid(self.db);
            {
                const onboarding = try self.prepareLocked("INSERT INTO sender_screening(user_id,enabled,onboarding_pending) VALUES (?1,0,1)");
                defer onboarding.finalize();
                try onboarding.bind(1, id);
                _ = try onboarding.step();
            }
            const insert = try self.prepareLocked("INSERT INTO provisioned_mailboxes (mailbox, user_id, actor, operation_id, revision, requested_quota, requested_enabled, initial_recovery, send_recipients_per_day) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
            defer insert.finalize();
            try insert.bind(1, change.mailbox);
            try insert.bind(2, id);
            try insert.bind(3, change.actor);
            try insert.bind(4, change.operation_id);
            try insert.bind(5, change.revision);
            try insert.bind(6, change.quota_bytes);
            try insert.bind(7, @as(i64, @intFromBool(change.enabled)));
            try insert.bind(8, recovery_address);
            try insert.bind(9, change.send_recipients_per_day);
            _ = try insert.step();
        }
        const operation = try self.prepareLocked("INSERT OR IGNORE INTO provisioning_operations VALUES (?, ?, ?)");
        defer operation.finalize();
        try operation.bind(1, change.operation_id);
        try operation.bind(2, change.mailbox);
        try operation.bind(3, change.revision);
        _ = try operation.step();
        const state = try self.provisioningStateLocked(change.mailbox, change.actor);
        try self.execLocked("COMMIT");
        return state;
    }

    // Take this lock before the SQLite mutex when a Maildir change must be
    // serialized with a quota check or a provisioning revision.
    pub fn lockMailboxes(self: *Database) void {
        if (std.c.pthread_mutex_lock(&self.mailbox_mutations) != .SUCCESS) unreachable;
    }

    pub fn unlockMailboxes(self: *Database) void {
        if (std.c.pthread_mutex_unlock(&self.mailbox_mutations) != .SUCCESS) unreachable;
    }

    pub const HostedLimits = struct {
        user_id: i64,
        enabled: bool,
        quota_bytes: u64,
        send_recipients_per_day: i64,
    };

    pub fn hostedLimits(self: *Database, mailbox: []const u8) !?HostedLimits {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.hostedLimitsLocked(mailbox);
    }

    fn hostedLimitsLocked(self: *Database, mailbox: []const u8) !?HostedLimits {
        const stmt = try self.prepareLocked(
            "SELECT u.id, u.enabled, u.quota_limit, p.send_recipients_per_day FROM provisioned_mailboxes p JOIN users u ON u.id = p.user_id AND u.username = p.mailbox WHERE p.mailbox = ?",
        );
        defer stmt.finalize();
        try stmt.bind(1, mailbox);
        if (!try stmt.step()) return null;
        return .{
            .user_id = stmt.columnInt64(0),
            .enabled = stmt.columnInt64(1) != 0,
            .quota_bytes = @intCast(@max(0, stmt.columnInt64(2))),
            .send_recipients_per_day = stmt.columnInt64(3),
        };
    }

    pub const HostedAccountStatus = struct {
        revision: i64,
        enabled: bool,
        requested_enabled: bool,
        quota_bytes: u64,
        requested_quota_bytes: u64,
        send_recipients_per_day: u64,
        utc_day: i64,
        counter_utc_day: ?i64,
        recipients_used_today: u64,
        recipients_remaining: ?u64,
        outbound_queue: ?struct { pending: u64, retry: u64, processing: u64 } = null,
    };

    /// Observe provisioning, recipient usage, and the active outbound queue in
    /// one read transaction. Queue counters are unavailable on pre-queue schemas.
    pub fn hostedAccountStatus(self: *Database, mailbox: []const u8, now: i64) !?HostedAccountStatus {
        var tx = try self.beginTransaction(.read);
        defer tx.deinit();
        const account = try tx.prepare(
            \\SELECT p.revision, u.enabled, p.requested_enabled, u.quota_limit, p.requested_quota,
            \\       p.send_recipients_per_day, usage.utc_day, usage.recipients, u.id
            \\FROM provisioned_mailboxes p
            \\JOIN users u ON u.id = p.user_id AND u.username = p.mailbox
            \\LEFT JOIN hosted_sending_usage usage ON usage.user_id = u.id
            \\WHERE p.mailbox = ?1
        );
        defer account.finalize();
        try account.bind(1, mailbox);
        if (!try account.step()) return null;

        const day = @divFloor(now, 86400);
        const counter_day = if (account.columnIsNull(6)) null else account.columnInt64(6);
        const allowance: u64 = @intCast(@max(0, account.columnInt64(5)));
        const used: u64 = if (counter_day == day) @intCast(@max(0, account.columnInt64(7))) else 0;
        const counter_in_future = if (counter_day) |counter| counter > day else false;
        var status: HostedAccountStatus = .{
            .revision = account.columnInt64(0),
            .enabled = account.columnInt64(1) != 0,
            .requested_enabled = account.columnInt64(2) != 0,
            .quota_bytes = @intCast(@max(0, account.columnInt64(3))),
            .requested_quota_bytes = @intCast(@max(0, account.columnInt64(4))),
            .send_recipients_per_day = allowance,
            .utc_day = day,
            .counter_utc_day = counter_day,
            .recipients_used_today = used,
            .recipients_remaining = if (allowance == 0) null else if (counter_in_future) 0 else allowance -| used,
        };
        const schema = try tx.prepare("SELECT 1 FROM pragma_table_info('message_queue') WHERE name = 'hosted_user_id'");
        defer schema.finalize();
        if (try schema.step()) {
            const queue = try tx.prepare(
                \\SELECT COUNT(CASE WHEN status = 'pending' THEN 1 END),
                \\       COUNT(CASE WHEN status = 'retry' THEN 1 END),
                \\       COUNT(CASE WHEN status = 'processing' THEN 1 END)
                \\FROM message_queue WHERE hosted_user_id = ?1 AND status IN ('pending', 'retry', 'processing')
            );
            defer queue.finalize();
            try queue.bind(1, account.columnInt64(8));
            if (!try queue.step()) return DatabaseError.StepFailed;
            status.outbound_queue = .{
                .pending = @intCast(queue.columnInt64(0)),
                .retry = @intCast(queue.columnInt64(1)),
                .processing = @intCast(queue.columnInt64(2)),
            };
        }
        try tx.commit();
        return status;
    }

    pub fn hostedSenderActive(self: *Database, user_id: i64) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const stmt = try self.prepareLocked(
            "SELECT 1 FROM provisioned_mailboxes p JOIN users u ON u.id = p.user_id AND u.username = p.mailbox WHERE u.id = ? AND u.enabled = 1",
        );
        defer stmt.finalize();
        try stmt.bind(1, user_id);
        return stmt.step();
    }

    pub const ActiveSyncReceipt = struct {
        device_id: []const u8,
        client_id: []const u8,
    };

    const eas_receipt_lifetime = 7 * 86400;

    pub fn activeSyncAccepted(self: *Database, mailbox: []const u8, receipt: ActiveSyncReceipt, now: i64) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const stmt = try self.prepareLocked(
            "SELECT 1 FROM eas_accepted_submissions WHERE username = ? AND device_id = ? AND client_id = ? AND accepted_at >= ?",
        );
        defer stmt.finalize();
        try stmt.bind(1, mailbox);
        try stmt.bind(2, receipt.device_id);
        try stmt.bind(3, receipt.client_id);
        try stmt.bind(4, now - eas_receipt_lifetime);
        return stmt.step();
    }

    /// Commit the retry receipt and the recipient debit together, before
    /// attempting delivery. Used under the mailbox mutation lock.
    pub fn acceptActiveSyncSend(self: *Database, mailbox: []const u8, receipt: ActiveSyncReceipt, recipients: usize, now: i64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.execLocked("BEGIN IMMEDIATE");
        errdefer self.execLocked("ROLLBACK") catch {};
        try self.recordActiveSyncReceiptLocked(mailbox, receipt, now);
        try self.chargeHostedSendLocked(mailbox, recipients, now);
        try self.execLocked("COMMIT");
    }

    fn recordActiveSyncReceiptLocked(self: *Database, mailbox: []const u8, receipt: ActiveSyncReceipt, now: i64) !void {
        {
            const sweep = try self.prepareLocked("DELETE FROM eas_accepted_submissions WHERE username = ? AND accepted_at < ?");
            defer sweep.finalize();
            try sweep.bind(1, mailbox);
            try sweep.bind(2, now - eas_receipt_lifetime);
            _ = try sweep.step();
        }
        {
            const insert = try self.prepareLocked("INSERT OR IGNORE INTO eas_accepted_submissions VALUES (?, ?, ?, ?)");
            defer insert.finalize();
            try insert.bind(1, mailbox);
            try insert.bind(2, receipt.device_id);
            try insert.bind(3, receipt.client_id);
            try insert.bind(4, now);
            _ = try insert.step();
            if (sqlite.sqlite3_changes(self.db) == 0) return error.MessagePreviouslySent;
        }
    }

    /// Called under the mailbox mutation lock before publishing SMTP files.
    pub fn checkHostedSend(self: *Database, mailbox: []const u8, recipients: usize, now: i64) !?i64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const limits = (try self.hostedLimitsLocked(mailbox)) orelse return null;
        if (!limits.enabled) return error.HostedSenderDisabled;
        const limit = limits.send_recipients_per_day;
        if (limit == 0) return limits.user_id;
        if (recipients > @as(u64, @intCast(limit))) return error.HostedSendingLimit;

        const stmt = try self.prepareLocked("SELECT utc_day, recipients FROM hosted_sending_usage WHERE user_id = ?");
        defer stmt.finalize();
        try stmt.bind(1, limits.user_id);
        const day = @divFloor(now, 86400);
        if (try stmt.step() and (stmt.columnInt64(0) > day or
            (stmt.columnInt64(0) == day and stmt.columnInt64(1) > limit - @as(i64, @intCast(recipients)))))
            return error.HostedSendingLimit;
        return limits.user_id;
    }

    /// Reserve the distinct envelope recipients of an accepted submission on
    /// the UTC day of dispatch. A retry of an already accepted SMTP message
    /// uses its original reservation.
    pub fn chargeHostedSend(self: *Database, mailbox: []const u8, recipients: usize, now: i64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.chargeHostedSendLocked(mailbox, recipients, now);
    }

    fn chargeHostedSendLocked(self: *Database, mailbox: []const u8, recipients: usize, now: i64) !void {
        const limits = (try self.hostedLimitsLocked(mailbox)) orelse return;
        if (!limits.enabled) return error.HostedSenderDisabled;
        const limit = limits.send_recipients_per_day;
        if (limit == 0) return; // Older provisioning clients omitted a sending allowance.
        if (recipients > @as(u64, @intCast(limit))) return error.HostedSendingLimit;

        const stmt = try self.prepareLocked(
            \\INSERT INTO hosted_sending_usage (user_id, utc_day, recipients) VALUES (?1, ?2, ?3)
            \\ON CONFLICT (user_id) DO UPDATE SET utc_day = excluded.utc_day,
            \\    recipients = CASE WHEN hosted_sending_usage.utc_day = excluded.utc_day
            \\        THEN hosted_sending_usage.recipients + excluded.recipients ELSE excluded.recipients END
            \\WHERE hosted_sending_usage.utc_day < excluded.utc_day OR
            \\    (hosted_sending_usage.utc_day = excluded.utc_day AND hosted_sending_usage.recipients <= ?4 - excluded.recipients)
        );
        defer stmt.finalize();
        try stmt.bind(1, limits.user_id);
        try stmt.bind(2, @divFloor(now, 86400));
        try stmt.bind(3, @as(i64, @intCast(recipients)));
        try stmt.bind(4, limit);
        _ = try stmt.step();
        if (sqlite.sqlite3_changes(self.db) == 0) return error.HostedSendingLimit;
    }

    pub const ForwardingSettings = struct {
        address: ?[]const u8 = null,
        pendingAddress: ?[]const u8 = null,
        expiresAt: ?i64 = null,
        revision: i64 = 0,
        scope: ForwardScope = .{},
    };

    pub const ForwardScope = struct {
        sender: ?[]const u8 = null,
        recipient: ?[]const u8 = null,

        fn restricted(self: ForwardScope) bool {
            return self.sender != null or self.recipient != null;
        }
    };

    pub const ForwardDestination = struct {
        address: []const u8,
        mailbox_id: ?i64,
        scope: ForwardScope = .{},
    };

    // A filtered destination lives outside the old address columns. Older
    // binaries suspend it, and edits made there invalidate its revision.
    const active_forward_scope =
        " LEFT JOIN mailbox_forwarding_scopes s ON s.user_id=f.user_id AND s.revision=f.revision AND f.address IS NULL ";
    const forward_address = "COALESCE(f.address,s.address)";
    const forward_destination_id = "CASE WHEN s.address IS NOT NULL THEN s.destination_id ELSE f.destination_id END";

    pub const ForwardRequest = struct {
        destination: ForwardDestination,
        hash: [32]u8,
        now: i64,
        expires: i64,
    };

    pub fn enabledMailboxId(self: *Database, user: []const u8) !?i64 {
        const stmt = try self.prepare("SELECT id FROM users WHERE username=?1 AND enabled=1");
        defer stmt.finalize();
        try stmt.bind(1, user);
        return if (try stmt.step()) stmt.columnInt64(0) else null;
    }

    pub fn forwardingSettings(self: *Database, a: std.mem.Allocator, user: []const u8) !ForwardingSettings {
        const stmt = try self.prepare("SELECT " ++ forward_address ++ ",f.pending_address,f.expires_at,f.revision,s.sender,s.recipient FROM mailbox_forwarding f JOIN users u ON u.id=f.user_id" ++ active_forward_scope ++ "WHERE u.username=?1");
        defer stmt.finalize();
        try stmt.bind(1, user);
        if (!try stmt.step()) return .{};
        return .{
            .address = if (stmt.columnTextOpt(0)) |address| try a.dupe(u8, address) else null,
            .pendingAddress = if (stmt.columnTextOpt(1)) |address| try a.dupe(u8, address) else null,
            .expiresAt = stmt.columnInt64Opt(2),
            .revision = stmt.columnInt64(3),
            .scope = try readForwardScope(a, stmt, 4),
        };
    }

    pub fn verifiedForward(self: *Database, a: std.mem.Allocator, user: []const u8) !?ForwardDestination {
        const stmt = try self.prepare("SELECT " ++ forward_address ++ "," ++ forward_destination_id ++ ",s.sender,s.recipient FROM mailbox_forwarding f JOIN users u ON u.id=f.user_id" ++ active_forward_scope ++ "WHERE u.username=?1 AND u.enabled=1 AND " ++ forward_address ++ " IS NOT NULL");
        defer stmt.finalize();
        try stmt.bind(1, user);
        if (!try stmt.step()) return null;
        return .{ .address = try a.dupe(u8, stmt.columnText(0)), .mailbox_id = stmt.columnInt64Opt(1), .scope = try readForwardScope(a, stmt, 2) };
    }

    fn readForwardScope(a: std.mem.Allocator, stmt: Statement, column: usize) !ForwardScope {
        return .{
            .sender = if (stmt.columnTextOpt(column)) |value| try a.dupe(u8, value) else null,
            .recipient = if (stmt.columnTextOpt(column + 1)) |value| try a.dupe(u8, value) else null,
        };
    }

    fn advanceForwardScopeLocked(self: *Database, user_id: i64, revision: i64) !void {
        const stmt = try self.prepareLocked("UPDATE mailbox_forwarding_scopes SET revision=revision+1 WHERE user_id=?1 AND revision=?2");
        defer stmt.finalize();
        try stmt.bind(1, user_id);
        try stmt.bind(2, revision);
        _ = try stmt.step();
    }

    fn removeForwardScopeLocked(self: *Database, user_id: i64) !void {
        const stmt = try self.prepareLocked("DELETE FROM mailbox_forwarding_scopes WHERE user_id=?1");
        defer stmt.finalize();
        try stmt.bind(1, user_id);
        _ = try stmt.step();
    }

    fn writeForwardDestinationLocked(self: *Database, user_id: i64, revision: i64, destination: ForwardDestination, confirmed: bool) !void {
        const restricted = destination.scope.restricted();
        const update = try self.prepareLocked(if (confirmed)
            \\UPDATE mailbox_forwarding SET address=?2,destination_id=?3,revision=revision+1,
            \\pending_address=NULL,pending_destination_id=NULL,code_hash=NULL,expires_at=NULL,attempts=0 WHERE user_id=?1
        else
            "UPDATE mailbox_forwarding SET address=?2,destination_id=?3,revision=revision+1 WHERE user_id=?1");
        defer update.finalize();
        try update.bind(1, user_id);
        try update.bindOpt(2, if (restricted) null else destination.address);
        try update.bindOpt(3, if (restricted) null else destination.mailbox_id);
        _ = try update.step();

        if (!restricted) return self.removeForwardScopeLocked(user_id);
        const scoped = try self.prepareLocked(
            \\INSERT INTO mailbox_forwarding_scopes(user_id,revision,address,destination_id,sender,recipient)
            \\VALUES (?1,?2,?3,?4,?5,?6)
            \\ON CONFLICT(user_id) DO UPDATE SET revision=excluded.revision,address=excluded.address,
            \\destination_id=excluded.destination_id,sender=excluded.sender,recipient=excluded.recipient
        );
        defer scoped.finalize();
        try scoped.bind(1, user_id);
        try scoped.bind(2, revision + 1);
        try scoped.bind(3, destination.address);
        try scoped.bindOpt(4, destination.mailbox_id);
        try scoped.bindOpt(5, destination.scope.sender);
        try scoped.bindOpt(6, destination.scope.recipient);
        _ = try scoped.step();
    }

    pub fn startForwardRequest(self: *Database, user: []const u8, revision: i64, request: ForwardRequest) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.execLocked("BEGIN IMMEDIATE");
        errdefer self.execLocked("ROLLBACK") catch {};
        {
            const prune = try self.prepareLocked("DELETE FROM mailbox_forwarding_requests WHERE requested_at<=?1");
            defer prune.finalize();
            try prune.bind(1, request.now - 3600);
            _ = try prune.step();
        }
        const owner = try self.prepareLocked(
            \\SELECT u.id,COALESCE(f.revision,0),
        ++ forward_address ++ "," ++ forward_destination_id ++
            \\,
            \\       (SELECT COUNT(*) FROM mailbox_forwarding_requests WHERE user_id=u.id),
            \\       (SELECT MAX(requested_at) FROM mailbox_forwarding_requests WHERE user_id=u.id),
            \\       (SELECT COUNT(*) FROM mailbox_forwarding_requests WHERE address=?2)
            \\FROM users u LEFT JOIN mailbox_forwarding f ON f.user_id=u.id
        ++ active_forward_scope ++ "WHERE u.username=?1 AND u.enabled=1");
        defer owner.finalize();
        try owner.bind(1, user);
        try owner.bind(2, request.destination.address);
        if (!try owner.step()) return error.NotFound;
        if (owner.columnInt64(1) != revision) return error.PreconditionFailed;
        if (owner.columnTextOpt(2)) |address| {
            if (std.mem.eql(u8, address, request.destination.address) and owner.columnInt64Opt(3) == request.destination.mailbox_id)
                return error.ForwardAlreadyActive;
        }
        if (owner.columnInt64(4) >= 3 or owner.columnInt64(6) >= 5 or
            (owner.columnInt64Opt(5) orelse 0) > request.now - 60) return error.ForwardRateLimited;
        const user_id = owner.columnInt64(0);
        const update = try self.prepareLocked(
            \\INSERT INTO mailbox_forwarding(user_id,pending_address,pending_destination_id,code_hash,expires_at,attempts) VALUES (?1,?2,?3,?4,?5,8)
            \\ON CONFLICT(user_id) DO UPDATE SET pending_address=excluded.pending_address,pending_destination_id=excluded.pending_destination_id,
            \\code_hash=excluded.code_hash,expires_at=excluded.expires_at,attempts=excluded.attempts,revision=revision+1
        );
        defer update.finalize();
        try update.bind(1, user_id);
        try update.bind(2, request.destination.address);
        try update.bindOpt(3, request.destination.mailbox_id);
        try update.bindBlob(4, &request.hash);
        try update.bind(5, request.expires);
        _ = try update.step();
        try self.advanceForwardScopeLocked(user_id, revision);
        const log = try self.prepareLocked("INSERT INTO mailbox_forwarding_requests(user_id,address,requested_at) VALUES (?1,?2,?3)");
        defer log.finalize();
        try log.bind(1, user_id);
        try log.bind(2, request.destination.address);
        try log.bind(3, request.now);
        _ = try log.step();
        try self.execLocked("COMMIT");
    }

    pub fn confirmForwardRequest(self: *Database, a: std.mem.Allocator, user: []const u8, revision: i64, hash: [32]u8, now: i64, scope: ?ForwardScope) !bool {
        self.lockMailboxes();
        defer self.unlockMailboxes();
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.execLocked("BEGIN IMMEDIATE");
        defer self.execLocked("ROLLBACK") catch {};
        const state = try self.prepareLocked(
            \\SELECT f.user_id,f.revision,f.code_hash,f.expires_at,f.attempts,
            \\       f.pending_destination_id IS NULL OR EXISTS(SELECT 1 FROM users v WHERE v.id=f.pending_destination_id AND v.enabled=1),
            \\       f.pending_address,f.pending_destination_id,s.sender,s.recipient
            \\FROM mailbox_forwarding f JOIN users u ON u.id=f.user_id
        ++ active_forward_scope ++ "WHERE u.username=?1 AND u.enabled=1");
        defer state.finalize();
        try state.bind(1, user);
        if (!try state.step()) return false;
        if (state.columnInt64(1) != revision) return error.PreconditionFailed;
        const stored = state.columnBlob(2);
        if (stored.len != hash.len or state.columnInt64(3) <= now or state.columnInt64(4) <= 0 or state.columnInt64(5) == 0) return false;
        const matched = std.crypto.timing_safe.eql([32]u8, stored[0..32].*, hash);
        const user_id = state.columnInt64(0);
        if (matched) {
            const destination = state.columnTextOpt(6) orelse return false;
            try self.writeForwardDestinationLocked(user_id, revision, .{
                .address = destination,
                .mailbox_id = state.columnInt64Opt(7),
                .scope = scope orelse try readForwardScope(a, state, 8),
            }, true);
        } else {
            const update = try self.prepareLocked("UPDATE mailbox_forwarding SET attempts=attempts-1 WHERE user_id=?1");
            defer update.finalize();
            try update.bind(1, user_id);
            _ = try update.step();
        }
        try self.execLocked("COMMIT");
        return matched;
    }

    pub fn setForwardingScope(self: *Database, user: []const u8, revision: i64, scope: ForwardScope) !void {
        self.lockMailboxes();
        defer self.unlockMailboxes();
        var tx = try self.beginTransaction(.write);
        defer tx.deinit();
        const state = try tx.prepare("SELECT f.user_id,f.revision," ++ forward_address ++ "," ++ forward_destination_id ++
            " FROM mailbox_forwarding f JOIN users u ON u.id=f.user_id" ++ active_forward_scope ++
            "WHERE u.username=?1 AND u.enabled=1");
        defer state.finalize();
        try state.bind(1, user);
        if (!try state.step() or state.columnInt64(1) != revision) return error.PreconditionFailed;
        const address = state.columnTextOpt(2) orelse return error.NoVerifiedForward;
        try self.writeForwardDestinationLocked(state.columnInt64(0), revision, .{
            .address = address,
            .mailbox_id = state.columnInt64Opt(3),
            .scope = scope,
        }, false);
        try tx.commit();
    }

    pub fn clearForwarding(self: *Database, user: []const u8, revision: i64, pending_only: bool) !void {
        self.lockMailboxes();
        defer self.unlockMailboxes();
        var tx = try self.beginTransaction(.write);
        defer tx.deinit();
        const stmt = try tx.prepare(if (pending_only)
            \\UPDATE mailbox_forwarding SET pending_address=NULL,pending_destination_id=NULL,code_hash=NULL,expires_at=NULL,attempts=0,revision=revision+1
            \\WHERE user_id=(SELECT id FROM users WHERE username=?1 AND enabled=1) AND revision=?2 RETURNING user_id
        else
            \\UPDATE mailbox_forwarding SET address=NULL,destination_id=NULL,pending_address=NULL,pending_destination_id=NULL,code_hash=NULL,expires_at=NULL,attempts=0,revision=revision+1
            \\WHERE user_id=(SELECT id FROM users WHERE username=?1 AND enabled=1) AND revision=?2 RETURNING user_id
        );
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, revision);
        if (!try stmt.step()) return error.PreconditionFailed;
        const user_id = stmt.columnInt64(0);
        _ = try stmt.step();
        if (pending_only) try self.advanceForwardScopeLocked(user_id, revision) else try self.removeForwardScopeLocked(user_id);
        try tx.commit();
    }

    pub const VacationSettings = struct {
        enabled: bool = false,
        subject: []const u8 = "Out of office",
        body: []const u8 = "",
        startsAt: ?i64 = null,
        endsAt: ?i64 = null,
        revision: i64 = 0,
    };

    pub fn vacationSettings(self: *Database, a: std.mem.Allocator, user: []const u8) !VacationSettings {
        const stmt = try self.prepare("SELECT v.enabled,v.subject,v.body,v.starts_at,v.ends_at,v.revision FROM mailbox_vacation v JOIN users u ON u.id=v.user_id WHERE u.username=?1");
        defer stmt.finalize();
        try stmt.bind(1, user);
        if (!try stmt.step()) return .{};
        return .{
            .enabled = stmt.columnInt64(0) != 0,
            .subject = try a.dupe(u8, stmt.columnText(1)),
            .body = try a.dupe(u8, stmt.columnText(2)),
            .startsAt = stmt.columnInt64Opt(3),
            .endsAt = stmt.columnInt64Opt(4),
            .revision = stmt.columnInt64(5),
        };
    }

    pub fn setVacationSettings(self: *Database, user: []const u8, settings: VacationSettings) !i64 {
        self.lockMailboxes();
        defer self.unlockMailboxes();
        const stmt = try self.prepare(
            \\INSERT INTO mailbox_vacation(user_id,enabled,subject,body,starts_at,ends_at)
            \\SELECT id,?2,?3,?4,?5,?6 FROM users
            \\WHERE username=?1 AND enabled=1 AND (?7=0 OR EXISTS(SELECT 1 FROM mailbox_vacation WHERE user_id=users.id))
            \\ON CONFLICT(user_id) DO UPDATE SET enabled=excluded.enabled,subject=excluded.subject,body=excluded.body,
            \\       starts_at=excluded.starts_at,ends_at=excluded.ends_at,revision=revision+1
            \\WHERE revision=?7 RETURNING revision
        );
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, @intFromBool(settings.enabled));
        try stmt.bind(3, settings.subject);
        try stmt.bind(4, settings.body);
        try stmt.bindOpt(5, settings.startsAt);
        try stmt.bindOpt(6, settings.endsAt);
        try stmt.bind(7, settings.revision);
        if (!try stmt.step()) return error.PreconditionFailed;
        return stmt.columnInt64(0);
    }

    /// Reserve a reply and its hosted debit in the delivery transaction. A
    /// cooldown is recorded for admitted replies, including pending retries.
    fn admitVacationLocked(self: *Database, user: []const u8, recipient: []const u8, now: i64) !?[]const u8 {
        const check = try self.prepareLocked(
            \\SELECT u.id,
            \\       EXISTS(SELECT 1 FROM mailbox_vacation_sends WHERE user_id=u.id AND correspondent=?2 AND accepted_at>?3),
            \\       (SELECT COUNT(*) FROM mailbox_vacation_sends WHERE user_id=u.id AND accepted_at>=?4)
            \\FROM users u JOIN mailbox_vacation v ON v.user_id=u.id AND v.enabled=1
            \\WHERE u.username=?1 AND u.enabled=1 AND (v.starts_at IS NULL OR v.starts_at<=?5) AND (v.ends_at IS NULL OR v.ends_at>?5)
        );
        defer check.finalize();
        try check.bind(1, user);
        try check.bind(2, recipient);
        try check.bind(3, now - vacation_wire.cooldown_seconds);
        try check.bind(4, @divFloor(now, 86400) * 86400);
        try check.bind(5, now);
        if (!try check.step()) return "vacation_inactive";
        if (check.columnInt64(1) != 0) return "vacation_repeat";
        if (check.columnInt64(2) >= vacation_wire.daily_limit) return "vacation_daily_limit";
        self.chargeHostedSendLocked(user, 1, now) catch |err| switch (err) {
            error.HostedSendingLimit => return "vacation_allowance",
            error.HostedSenderDisabled => return "vacation_inactive",
            else => return err,
        };
        const receipt = try self.prepareLocked(
            \\INSERT INTO mailbox_vacation_sends(user_id,correspondent,accepted_at) VALUES (?1,?2,?3)
            \\ON CONFLICT(user_id,correspondent) DO UPDATE SET accepted_at=excluded.accepted_at
        );
        defer receipt.finalize();
        try receipt.bind(1, check.columnInt64(0));
        try receipt.bind(2, recipient);
        try receipt.bind(3, now);
        _ = try receipt.step();
        return null;
    }

    pub const VacationReply = struct { author: []const u8, from: []const u8, mime: []const u8 };

    pub const DeliveryTarget = struct {
        recipient: []const u8,
        mailbox: []const u8 = "",
        folder: []const u8 = "",
        forward_owner: ?[]const u8 = null,
        forward_after: ?usize = null,
        verified_forward: bool = false,
        outbound_from: ?[]const u8 = null,
        outbound_subject: []const u8 = "",
        reply: ?VacationReply = null,
        forward_allowed: bool = true,
        review_copy: bool = false,
        placement_reason: ?categories.Reason = null,
        refusal: ?[]const u8 = null,
        interactive_remote: bool = false,
    };

    pub fn delegatedSenderAddress(self: *Database, a: std.mem.Allocator, user: []const u8, identity: i64) !?[]const u8 {
        const stmt = try self.prepare(team_store.senderIdentityQuery ++ " AND source.id=?2");
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, identity);
        if (!try stmt.step()) return null;
        return try a.dupe(u8, stmt.columnText(1));
    }

    fn requireDelegatedSenderLocked(self: *Database, user: []const u8, identity: i64, address: []const u8) !void {
        const stmt = try self.prepareLocked(team_store.senderIdentityQuery ++ " AND source.id=?2 AND source.email=?3");
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, identity);
        try stmt.bind(3, address);
        if (!try stmt.step()) return error.SenderIdentityUnavailable;
    }

    pub const ExternalSenderAdmission = struct { id: []const u8, generation: []const u8 };

    pub const TeamReplySource = struct {
        reference: []const u8,
        revision: [64]u8,
        wire_id: []const u8,
    };

    pub const SmtpSentProof = struct {
        wire_id: []const u8,
        digest: [64]u8,
    };

    pub const SmtpSentMatch = struct {
        delivery: []const u8,
        owner: []const u8,
        digest: []const u8,
        copy: []const u8,
        parent: []const u8,
        parent_revision: []const u8,
    };

    pub const NativeSentReply = struct {
        basename: []const u8,
        stamp: []const u8,
        revision: [64]u8,
        wire_id: []const u8,
    };

    pub const EwsDraftSend = struct {
        reference: []const u8,
        revision: [64]u8,
        save_copy: bool,
        path: []const u8,
        fingerprint: []const u8,
    };

    pub const EwsSendResult = enum { delivered, partial, storage_full, disabled, failed, uncertain };

    pub const EwsSendReceipt = struct {
        delivery_id: []const u8,
        save_copy: bool,
        result: ?EwsSendResult,
    };

    pub fn ewsSendReceipt(self: *Database, a: std.mem.Allocator, user: []const u8, draft: EwsDraftSend) !?EwsSendReceipt {
        const stmt = try self.prepare(
            \\SELECT delivery_id,save_copy,result FROM mail_ews_draft_sends
            \\WHERE user_id=(SELECT id FROM users WHERE username=?1) AND draft_reference=?2 AND content_revision=?3
        );
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, draft.reference);
        try stmt.bind(3, @as([]const u8, &draft.revision));
        if (!try stmt.step()) return null;
        return .{
            .delivery_id = try a.dupe(u8, stmt.columnText(0)),
            .save_copy = stmt.columnInt64(1) != 0,
            .result = if (stmt.columnIsNull(2)) null else std.meta.stringToEnum(EwsSendResult, stmt.columnText(2)) orelse .uncertain,
        };
    }

    pub fn finishEwsDraftSend(self: *Database, id: []const u8, result: EwsSendResult) !void {
        const stmt = try self.prepare("UPDATE mail_ews_draft_sends SET result=?2 WHERE delivery_id=?1 AND result IS NULL");
        defer stmt.finalize();
        try stmt.bind(1, id);
        try stmt.bind(2, @tagName(result));
        _ = try stmt.step();
    }

    pub const EwsDraftFinalization = struct {
        delivery_id: []const u8,
        user: []const u8,
        reference: []const u8,
        basename: []const u8,
        revision: []const u8,
        path: []const u8,
        fingerprint: []const u8,
        draft_id: ?[]const u8,
        draft_revision: i64,
        rowid: i64,
    };

    /// Recover local admission and confirmed remote delivery even if the EWS
    /// request stopped before recording its response.
    pub fn confirmEwsDraftFinalizations(self: *Database, id: ?[]const u8) !void {
        const stmt = try self.prepare(
            \\UPDATE mail_ews_draft_finalizations AS c SET confirmed=1
            \\WHERE retired_at IS NULL AND confirmed=0 AND (?1 IS NULL OR c.delivery_id=?1)
            \\AND (EXISTS(SELECT 1 FROM mail_ews_draft_sends s WHERE s.delivery_id=c.delivery_id AND s.result='delivered')
            \\ OR (EXISTS(SELECT 1 FROM accepted_mail_targets t WHERE t.delivery_id=c.delivery_id AND t.is_primary=1)
            \\ AND NOT EXISTS(SELECT 1 FROM accepted_mail_targets t WHERE t.delivery_id=c.delivery_id AND t.is_primary=1
            \\     AND t.outcome NOT IN ('pending','filed','remote_delivered'))))
        );
        defer stmt.finalize();
        try stmt.bindOpt(1, id);
        _ = try stmt.step();
    }

    pub fn nextEwsDraftFinalization(self: *Database, a: std.mem.Allocator, id: ?[]const u8, after: i64) !?EwsDraftFinalization {
        const stmt = try self.prepare(
            \\SELECT c.delivery_id,u.username,c.draft_reference,c.basename,c.content_revision,c.path,c.fingerprint,c.draft_id,c.draft_revision,c.rowid
            \\FROM mail_ews_draft_finalizations c JOIN users u ON u.id=c.user_id
            \\WHERE c.confirmed=1 AND c.retired_at IS NULL AND (?1 IS NULL OR c.delivery_id=?1) AND c.rowid>?2
            \\ORDER BY c.rowid LIMIT 1
        );
        defer stmt.finalize();
        try stmt.bindOpt(1, id);
        try stmt.bind(2, after);
        if (!try stmt.step()) return null;
        return .{
            .delivery_id = try a.dupe(u8, stmt.columnText(0)),
            .user = try a.dupe(u8, stmt.columnText(1)),
            .reference = try a.dupe(u8, stmt.columnText(2)),
            .basename = try a.dupe(u8, stmt.columnText(3)),
            .revision = try a.dupe(u8, stmt.columnText(4)),
            .path = try a.dupe(u8, stmt.columnText(5)),
            .fingerprint = try a.dupe(u8, stmt.columnText(6)),
            .draft_id = if (stmt.columnIsNull(7)) null else try a.dupe(u8, stmt.columnText(7)),
            .draft_revision = stmt.columnInt64(8),
            .rowid = stmt.columnInt64(9),
        };
    }

    pub fn confirmedEwsDraft(self: *Database, user: []const u8, basename: []const u8, revision: ?[]const u8) !?bool {
        const stmt = try self.prepare(
            \\SELECT save_copy FROM mail_ews_draft_finalizations
            \\WHERE user_id=(SELECT id FROM users WHERE username=?1) AND basename=?2
            \\AND (?3 IS NULL OR content_revision=?3) AND confirmed=1
            \\ORDER BY rowid DESC LIMIT 1
        );
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, basename);
        try stmt.bindOpt(3, revision);
        if (!try stmt.step()) return null;
        return stmt.columnInt64(0) != 0;
    }

    pub const DeliveryEnvelope = struct {
        id: []const u8,
        from: []const u8,
        author: []const u8 = "",
        verified_author: bool = false,
        notification_origin: []const u8 = "",
        mime: []const u8,
        accepted_at: i64,
        accepted_ms: i64,
        targets: []const DeliveryTarget,
        sender: ?[]const u8 = null,
        delegated_sender_id: ?i64 = null,
        external_sender: ?ExternalSenderAdmission = null,
        linked_account: ?[]const u8 = null,
        shared_reply: ?shared_inbox.ReplyDelivery = null,
        calendar_reply: ?calendar_invite.Revision = null,
        charge_recipients: usize = 0,
        receipt: ?ActiveSyncReceipt = null,
        ews_draft_send: ?EwsDraftSend = null,
        review_release: ?FiledCopy = null,
        team_reply_submission: ?TeamReplySource = null,
        smtp_sent_proof: ?SmtpSentProof = null,
        sent_copy_of: ?[]const u8 = null,
        native_sent_reply: ?NativeSentReply = null,
    };

    /// Reserve the hosted envelope and persist its complete routing decision
    /// before any local copy becomes visible or the SMTP transaction is acknowledged.
    pub fn acceptDelivery(self: *Database, envelope: DeliveryEnvelope) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.execLocked("BEGIN IMMEDIATE");
        errdefer self.execLocked("ROLLBACK") catch {};
        if (envelope.linked_account) |id|
            try @import("webmail_account_links.zig").requireSource(.{ .db = self }, id, envelope.sender orelse return error.LinkedAccountUnavailable, envelope.accepted_at);
        // Serialize revocation and delivery admission, before debiting the
        // actor or creating any visible recipient copies.
        if (envelope.delegated_sender_id) |identity| {
            try self.requireDelegatedSenderLocked(envelope.sender orelse return error.SenderIdentityUnavailable, identity, envelope.from);
        }
        if (envelope.external_sender) |identity| {
            const stmt = try self.prepareLocked(
                \\SELECT 1 FROM webmail_records
                \\WHERE username=?1 AND kind='external-sender-proof' AND id=?2 AND state='verified'
                \\AND json_extract(payload,'$.generation')=?3
                \\AND EXISTS(SELECT 1 FROM users WHERE username=?1 AND enabled=1)
            );
            defer stmt.finalize();
            try stmt.bind(1, envelope.sender orelse return error.ExternalSenderUnavailable);
            try stmt.bind(2, identity.id);
            try stmt.bind(3, identity.generation);
            if (!try stmt.step()) return error.ExternalSenderUnavailable;
        }
        if (envelope.shared_reply) |reply| {
            try shared_inbox.requireReplyAdmission(.{ .db = self }, envelope.sender orelse return error.SharedReplyUnavailable, envelope.from, reply);
        }
        if (envelope.calendar_reply) |revision| {
            try requireCurrentCalendarInvitation(Transaction{ .db = self }, envelope.sender orelse return error.CalendarReplyUnavailable, revision);
        }
        var hosted_sender: i64 = 0;
        if (envelope.sender) |sender| {
            if (envelope.receipt) |receipt| try self.recordActiveSyncReceiptLocked(sender, receipt, envelope.accepted_at);
            try self.chargeHostedSendLocked(sender, envelope.charge_recipients, envelope.accepted_at);
            if (try self.hostedLimitsLocked(sender)) |limits| hosted_sender = limits.user_id;
        }
        {
            const insert = try self.prepareLocked("INSERT INTO accepted_mail(id,accepted_at,mime,envelope_from,author,verified_author,remote_addr,accepted_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)");
            defer insert.finalize();
            try insert.bind(1, envelope.id);
            try insert.bind(2, envelope.accepted_at);
            try insert.bindBlob(3, envelope.mime);
            try insert.bind(4, envelope.from);
            try insert.bind(5, envelope.author);
            try insert.bind(6, @as(u8, @intFromBool(envelope.verified_author)));
            try insert.bind(7, envelope.notification_origin);
            try insert.bind(8, envelope.accepted_ms);
            _ = try insert.step();
        }
        if (envelope.ews_draft_send) |draft| {
            const stmt = try self.prepareLocked(
                \\INSERT INTO mail_ews_draft_sends(user_id,draft_reference,content_revision,save_copy,delivery_id)
                \\SELECT id,?2,?3,?4,?5 FROM users WHERE username=?1 AND enabled=1 RETURNING 1
            );
            defer stmt.finalize();
            try stmt.bind(1, envelope.sender orelse return error.InvalidMailboxPath);
            try stmt.bind(2, draft.reference);
            try stmt.bind(3, @as([]const u8, &draft.revision));
            try stmt.bind(4, @as(u8, @intFromBool(draft.save_copy)));
            try stmt.bind(5, envelope.id);
            if (!try stmt.step()) return error.HostedSenderDisabled;
            _ = try stmt.step();
            try self.recordEwsDraftFinalizationLocked(envelope, draft);
        }
        if (envelope.team_reply_submission) |parent| {
            const stmt = try self.prepareLocked(
                \\INSERT INTO mail_team_thread_submissions(delivery_id,owner_id,parent_reference,parent_revision,parent_wire_id)
                \\SELECT ?1,u.id,?3,?4,?5 FROM users u WHERE u.username=?2 AND u.enabled=1
                \\AND EXISTS(SELECT 1 FROM mail_team_thread_shares s JOIN mail_team_thread_follow_sent opted ON opted.share_id=s.id
                \\           WHERE s.owner_id=u.id)
            );
            defer stmt.finalize();
            try stmt.bind(1, envelope.id);
            try stmt.bind(2, envelope.sender orelse return error.InvalidMailboxPath);
            try stmt.bind(3, parent.reference);
            try stmt.bind(4, @as([]const u8, &parent.revision));
            try stmt.bind(5, parent.wire_id);
            _ = try stmt.step();
        }
        if (envelope.smtp_sent_proof) |proof| {
            const stmt = try self.prepareLocked(
                \\INSERT INTO mail_team_smtp_submissions(delivery_id,owner_id,wire_id,digest)
                \\SELECT delivery_id,owner_id,?2,?3 FROM mail_team_thread_submissions WHERE delivery_id=?1
            );
            defer stmt.finalize();
            try stmt.bind(1, envelope.id);
            try stmt.bind(2, proof.wire_id);
            try stmt.bind(3, @as([]const u8, &proof.digest));
            _ = try stmt.step();
        }
        if (envelope.sent_copy_of) |source| {
            const stmt = try self.prepareLocked(
                \\UPDATE mail_team_thread_submissions SET sent_id=?1 WHERE delivery_id=?2 AND sent_id IS NULL
                \\AND owner_id=(SELECT id FROM users WHERE username=?3)
            );
            defer stmt.finalize();
            try stmt.bind(1, envelope.id);
            try stmt.bind(2, source);
            try stmt.bind(3, envelope.from);
            _ = try stmt.step();
        }
        const insert = try self.prepareLocked("INSERT INTO accepted_mail_targets(delivery_id,ordinal,recipient,mailbox,folder,outcome,queued_bytes,retry_at,mailbox_id,is_primary,forward_after,review_copy,placement_reason,verified_forward,reply_author,reply_from,reply_mime) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,COALESCE((SELECT id FROM users WHERE username=?4),0),?9,?10,?11,?12,?13,?14,?15,?16)");
        defer insert.finalize();
        var has_local = false;
        for (envelope.targets, 0..) |planned, ordinal| {
            const released = if (ordinal == 0) envelope.review_release else null;
            var target = planned;
            if (envelope.review_release != null and target.forward_after == 0) target.forward_after = null;
            if (target.refusal == null and target.reply != null)
                target.refusal = try self.admitVacationLocked(target.forward_owner.?, target.recipient, envelope.accepted_at);
            const pending = target.refusal == null and target.mailbox.len > 0 and released == null;
            var outcome = target.refusal orelse if (target.interactive_remote) "remote_unattempted" else if (released != null) "filed" else if (pending) "pending" else "queued";
            if (std.mem.eql(u8, outcome, "queued")) {
                var owner = hosted_sender;
                if (target.forward_owner) |user| {
                    owner = if (try self.hostedLimitsLocked(user)) |limits| limits.user_id else 0;
                    if (target.reply == null) self.chargeHostedSendLocked(user, 1, envelope.accepted_at) catch |err| switch (err) {
                        error.HostedSendingLimit => outcome = "forward_allowance",
                        error.HostedSenderDisabled => outcome = "forward_disabled",
                        else => return err,
                    };
                }
                if (std.mem.eql(u8, outcome, "queued")) try self.queueAcceptedRemoteLocked(envelope, ordinal, target, owner);
            }
            try insert.bind(1, envelope.id);
            try insert.bind(2, ordinal);
            try insert.bind(3, target.recipient);
            try insert.bind(4, target.mailbox);
            try insert.bind(5, target.folder);
            try insert.bind(6, outcome);
            const local_bytes = if (target.reply) |reply| reply.mime.len else envelope.mime.len + if (target.verified_forward) forwarding_wire.loop_header.len else @as(usize, 0);
            try insert.bind(7, @as(usize, if (pending) local_bytes else 0));
            try insert.bind(8, envelope.accepted_at);
            try insert.bind(9, @as(u8, @intFromBool(target.forward_owner == null)));
            try insert.bindOpt(10, target.forward_after);
            try insert.bind(11, @intFromBool(target.review_copy));
            try insert.bind(12, if (target.placement_reason) |reason| @tagName(reason) else "");
            try insert.bind(13, @intFromBool(target.verified_forward));
            try insert.bindOpt(14, if (target.reply) |reply| reply.author else null);
            try insert.bindOpt(15, if (target.reply) |reply| reply.from else null);
            if (target.reply != null and pending) try insert.bindBlob(16, target.reply.?.mime) else try insert.bindNull(16);
            _ = try insert.step();
            try insert.reset();
            if (released) |file| {
                try self.recordPlacementLocked(envelope.id, @intCast(ordinal), file);
                try self.recordTeamThreadReplyLocked(envelope.id, @intCast(ordinal), file);
                try self.recordCalendarRevisionsLocked(envelope.id, @intCast(ordinal), file.calendar_revisions);
                const muted = try self.attentionArrivalLocked(envelope.id, @intCast(ordinal), file.attention);
                try self.stageDeliveryEffectsLocked(envelope.id, @intCast(ordinal), file, muted);
                try self.stageBrowserNotificationLocked(envelope.id, @intCast(ordinal), file, muted);
                const remove = try self.prepareLocked("DELETE FROM sender_review_messages WHERE user_id=(SELECT id FROM users WHERE username=?1) AND operation=?2");
                defer remove.finalize();
                try remove.bind(1, target.mailbox);
                try remove.bind(2, envelope.id);
                _ = try remove.step();
                if (sqlite.sqlite3_changes(self.db) != 1) return error.ReviewChanged;
            }
            has_local = has_local or pending;
        }
        if (envelope.native_sent_reply) |sent| {
            try self.recordNativeSentFileLocked(envelope.id, sent);
            try self.publishNativeSentReplyLocked(envelope.id);
        }
        if (!has_local) try self.compactDeliveryLocked(envelope.id);
        try self.execLocked("COMMIT");
    }

    fn recordEwsDraftFinalizationLocked(self: *Database, envelope: DeliveryEnvelope, draft: EwsDraftSend) !void {
        const user = envelope.sender orelse return error.InvalidMailboxPath;
        const basename = maildirBaseName(std.fs.path.basename(draft.path));
        const webmail_enabled = schema: {
            const stmt = try self.prepareLocked("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='webmail_records'");
            defer stmt.finalize();
            break :schema try stmt.step();
        };
        const snapshot = if (webmail_enabled) metadata: {
            const stmt = try self.prepareLocked(
                \\SELECT w.id,w.revision,w.state,
                \\EXISTS(SELECT 1 FROM webmail_records e WHERE e.username=w.username AND e.kind='draft-edit' AND e.id=w.id)
                \\FROM webmail_records w JOIN imap_uids f ON f.username=w.username AND f.mailbox='Drafts' AND f.filename=?2
                \\WHERE w.username=?1 AND w.kind='draft' AND json_extract(w.payload,'$.folder')='Drafts'
                \\AND json_extract(w.payload,'$.uid')=f.uid
            );
            defer stmt.finalize();
            try stmt.bind(1, user);
            try stmt.bind(2, basename);
            if (!try stmt.step()) break :metadata null;
            if (!std.mem.eql(u8, stmt.columnText(2), "saved") or stmt.columnInt64(3) != 0) return error.StaleDraft;
            break :metadata .{ .id = try self.allocator.dupe(u8, stmt.columnText(0)), .revision = stmt.columnInt64(1) };
        } else null;
        defer if (snapshot) |row| self.allocator.free(row.id);
        const stmt = try self.prepareLocked(
            \\INSERT INTO mail_ews_draft_finalizations(delivery_id,user_id,draft_reference,basename,content_revision,
            \\save_copy,path,fingerprint,draft_id,draft_revision,submitted_at)
            \\SELECT ?2,id,?3,?4,?5,?6,?7,?8,?9,?10,?11 FROM users WHERE username=?1
        );
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, envelope.id);
        try stmt.bind(3, draft.reference);
        try stmt.bind(4, basename);
        try stmt.bind(5, @as([]const u8, &draft.revision));
        try stmt.bind(6, @as(u8, @intFromBool(draft.save_copy)));
        try stmt.bind(7, draft.path);
        try stmt.bind(8, draft.fingerprint);
        try stmt.bindOpt(9, if (snapshot) |row| row.id else null);
        try stmt.bindOpt(10, if (snapshot) |row| row.revision else null);
        try stmt.bind(11, envelope.accepted_at);
        _ = try stmt.step();
    }

    fn queueAcceptedRemoteLocked(self: *Database, envelope: DeliveryEnvelope, ordinal: usize, target: DeliveryTarget, owner: i64) !void {
        const id = try std.fmt.allocPrint(self.allocator, "route-{s}-{d}", .{ envelope.id, ordinal });
        defer self.allocator.free(id);
        const insert = try self.prepareLocked(
            "INSERT INTO message_queue(id,from_addr,to_addr,message_data,status,next_retry,created_at,updated_at,hosted_user_id) VALUES (?1,?2,?3,?4,?7,?5,?5,?5,?6)",
        );
        defer insert.finalize();
        try insert.bind(1, id);
        try insert.bind(2, if (target.reply) |reply| reply.from else target.outbound_from orelse envelope.from);
        try insert.bind(3, target.recipient);
        const forwarded = if (target.outbound_from) |address|
            try forwarding_wire.wrap(self.allocator, address, target.recipient, target.outbound_subject, envelope.mime)
        else
            null;
        defer if (forwarded) |mime| self.allocator.free(mime);
        try insert.bindBlob(4, if (target.reply) |reply| reply.mime else forwarded orelse envelope.mime);
        try insert.bind(5, envelope.accepted_at);
        try insert.bind(6, owner);
        try insert.bind(7, @as([]const u8, if (target.forward_after == null) "pending" else "awaiting_local"));
        _ = try insert.step();
    }

    const InteractivePhase = enum { starting, delivered, failed };
    const interactive_phase_sql =
        \\UPDATE accepted_mail_targets SET outcome=?3
        \\WHERE delivery_id=?1 AND recipient=?2 AND is_primary=1 AND outcome=?4 RETURNING 1
    ;

    pub fn checkpointInteractiveRecipient(self: *Database, id: []const u8, recipient: []const u8, phase: InteractivePhase, native_sent_reply: bool) !void {
        if (native_sent_reply and phase == .delivered) {
            var tx = try self.beginTransaction(.write);
            defer tx.deinit();
            {
                const stmt = try tx.prepare(interactive_phase_sql);
                defer stmt.finalize();
                try checkpointRecipient(stmt, id, recipient, phase);
            }
            try self.publishNativeSentReplyLocked(id);
            return tx.commit();
        }
        const stmt = try self.prepare(interactive_phase_sql);
        defer stmt.finalize();
        try checkpointRecipient(stmt, id, recipient, phase);
    }

    /// The confirmed result of one remote DATA transaction applies to every
    /// accepted recipient, even if the worker stops while recording it.
    pub fn checkpointInteractiveRecipients(self: *Database, id: []const u8, recipients: []const []const u8, phase: InteractivePhase) !void {
        var tx = try self.beginTransaction(.write);
        defer tx.deinit();
        {
            const stmt = try tx.prepare(interactive_phase_sql);
            defer stmt.finalize();
            for (recipients) |recipient| {
                try checkpointRecipient(stmt, id, recipient, phase);
                try stmt.reset();
            }
        }
        try tx.commit();
    }

    fn checkpointRecipient(stmt: Statement, id: []const u8, recipient: []const u8, phase: InteractivePhase) !void {
        try stmt.bind(1, id);
        try stmt.bind(2, recipient);
        try stmt.bind(3, @as([]const u8, switch (phase) {
            .starting => "remote_unknown",
            .delivered => "remote_delivered",
            .failed => "remote_failed",
        }));
        try stmt.bind(4, @as([]const u8, if (phase == .starting) "remote_unattempted" else "remote_unknown"));
        if (!try stmt.step()) return error.NotFound;
        _ = try stmt.step();
    }

    pub const InteractiveDelivery = struct {
        delivered: usize = 0,
        failed: []const []const u8 = &.{},
        unknown: []const []const u8 = &.{},
        unattempted: bool = false,
        refused_for_limit: bool = false,
        refused_for_disabled: bool = false,
    };

    /// Inspect only the original envelope, excluding forwards and vacation replies.
    pub fn interactiveDelivery(self: *Database, a: std.mem.Allocator, id: []const u8) !?InteractiveDelivery {
        const stmt = try self.prepare(
            \\SELECT recipient,outcome FROM accepted_mail_targets
            \\WHERE delivery_id=?1 AND is_primary=1 ORDER BY ordinal
        );
        defer stmt.finalize();
        try stmt.bind(1, id);
        if (!try stmt.step()) return null;
        var result: InteractiveDelivery = .{};
        var failed: std.ArrayList([]const u8) = .empty;
        var unknown: std.ArrayList([]const u8) = .empty;
        while (true) {
            const outcome = stmt.columnText(1);
            if (std.mem.eql(u8, outcome, "pending") or std.mem.eql(u8, outcome, "filed") or std.mem.eql(u8, outcome, "remote_delivered")) {
                result.delivered += 1;
            } else if (std.mem.eql(u8, outcome, "remote_unknown")) {
                try unknown.append(a, try a.dupe(u8, stmt.columnText(0)));
            } else {
                try failed.append(a, try a.dupe(u8, stmt.columnText(0)));
                result.unattempted = result.unattempted or std.mem.eql(u8, outcome, "remote_unattempted");
                result.refused_for_disabled = result.refused_for_disabled or std.mem.eql(u8, outcome, "recipient_disabled");
                result.refused_for_limit = result.refused_for_limit or std.mem.eql(u8, outcome, "recipient_storage_full") or std.mem.eql(u8, outcome, "recipient_disabled");
            }
            if (!try stmt.step()) break;
        }
        result.failed = try failed.toOwnedSlice(a);
        result.unknown = try unknown.toOwnedSlice(a);
        return result;
    }

    pub fn hasAcceptedDelivery(self: *Database, id: []const u8) !bool {
        const stmt = try self.prepare("SELECT 1 FROM accepted_mail WHERE id=?1");
        defer stmt.finalize();
        try stmt.bind(1, id);
        return stmt.step();
    }

    pub fn hasFollowedSentReplies(self: *Database, user: []const u8) !bool {
        const stmt = try self.prepare(
            \\SELECT 1 FROM mail_team_thread_follow_sent opted JOIN mail_team_thread_shares s ON s.id=opted.share_id
            \\WHERE s.owner_id=(SELECT id FROM users WHERE username=?1 AND enabled=1) LIMIT 1
        );
        defer stmt.finalize();
        try stmt.bind(1, user);
        return stmt.step();
    }

    pub fn canFollowNativeSent(self: *Database, user: []const u8, source: TeamReplySource, recipients: []const u8) !bool {
        const stmt = try self.prepare(team_threads.check_native_sent_source_sql);
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, source.reference);
        try stmt.bind(3, @as([]const u8, &source.revision));
        try stmt.bind(4, source.wire_id);
        try stmt.bind(5, recipients);
        try stmt.bind(6, team_threads.max_followed_replies);
        return stmt.step();
    }

    pub fn hasFollowedSmtpParent(self: *Database, user: []const u8, wire_id: []const u8) !bool {
        const stmt = try self.prepare(team_threads.has_smtp_reply_parent_sql);
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, wire_id);
        try stmt.bind(3, team_threads.max_followed_replies);
        return stmt.step();
    }

    pub fn recordSmtpSentCopy(self: *Database, user: []const u8, proof: SmtpSentProof, reference: []const u8, observed_at: i64) !void {
        const stmt = try self.prepare(
            \\INSERT OR IGNORE INTO mail_team_smtp_sent_copies(owner_id,wire_id,digest,reference,observed_at)
            \\SELECT id,?2,?3,?4,?5 FROM users WHERE username=?1 AND enabled=1
        );
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, proof.wire_id);
        try stmt.bind(3, @as([]const u8, &proof.digest));
        try stmt.bind(4, reference);
        try stmt.bind(5, observed_at);
        _ = try stmt.step();
    }

    pub fn nextSmtpSentMatch(self: *Database, a: std.mem.Allocator, since: i64) !?SmtpSentMatch {
        const stmt = try self.prepare(
            \\SELECT smtp.delivery_id,owner.username,smtp.digest,copy.reference,proof.parent_reference,proof.parent_revision
        ++ " " ++ team_threads.smtp_sent_match ++ " ORDER BY source.accepted_ms,copy.observed_at LIMIT 1");
        defer stmt.finalize();
        try stmt.bind(1, since);
        if (!try stmt.step()) return null;
        return .{
            .delivery = try a.dupe(u8, stmt.columnText(0)),
            .owner = try a.dupe(u8, stmt.columnText(1)),
            .digest = try a.dupe(u8, stmt.columnText(2)),
            .copy = try a.dupe(u8, stmt.columnText(3)),
            .parent = try a.dupe(u8, stmt.columnText(4)),
            .parent_revision = try a.dupe(u8, stmt.columnText(5)),
        };
    }

    pub fn forgetSmtpSentCopy(self: *Database, user: []const u8, reference: []const u8) !void {
        const stmt = try self.prepare("DELETE FROM mail_team_smtp_sent_copies WHERE owner_id=(SELECT id FROM users WHERE username=?1) AND reference=?2");
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, reference);
        _ = try stmt.step();
    }

    pub fn forgetSmtpSentProof(self: *Database, delivery: []const u8) !void {
        const stmt = try self.prepare("DELETE FROM mail_team_smtp_submissions WHERE delivery_id=?1");
        defer stmt.finalize();
        try stmt.bind(1, delivery);
        _ = try stmt.step();
    }

    pub fn publishSmtpSentMatch(self: *Database, match: SmtpSentMatch, stamp: []const u8, revision: []const u8, since: i64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.execLocked("BEGIN IMMEDIATE");
        errdefer self.execLocked("ROLLBACK") catch {};
        {
            const stmt = try self.prepareLocked(
                \\INSERT INTO mail_team_thread_native_sent(delivery_id,reference,content_revision,wire_id)
                \\SELECT smtp.delivery_id,copy.reference,?5,smtp.wire_id
            ++ " " ++ team_threads.smtp_sent_match ++ " AND smtp.delivery_id=?2 AND r.reference=?3 AND r.file_stamp=?4");
            defer stmt.finalize();
            try stmt.bind(1, since);
            try stmt.bind(2, match.delivery);
            try stmt.bind(3, match.copy);
            try stmt.bind(4, stamp);
            try stmt.bind(5, revision);
            _ = try stmt.step();
        }
        try self.publishNativeSentReplyLocked(match.delivery);
        try self.execLocked("COMMIT");
    }

    pub fn hasFiledDelivery(self: *Database, id: []const u8) !bool {
        const stmt = try self.prepare("SELECT 1 FROM accepted_mail_targets WHERE delivery_id=?1 AND outcome='filed' LIMIT 1");
        defer stmt.finalize();
        try stmt.bind(1, id);
        return stmt.step();
    }

    pub fn reservedDeliveryBytes(self: *Database, mailbox: []const u8) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const stmt = try self.prepareLocked("SELECT COALESCE(SUM(queued_bytes),0) FROM accepted_mail_targets WHERE mailbox=?1 AND outcome='pending'");
        defer stmt.finalize();
        try stmt.bind(1, mailbox);
        if (!try stmt.step()) return error.NotFound;
        return @intCast(stmt.columnInt64(0));
    }

    pub fn linkedFileBytes(self: *Database, mailbox: []const u8, now: i64) !u64 {
        const stmt = try self.prepare(
            \\SELECT COALESCE(SUM(size),0) FROM mail_file_links
            \\WHERE user_id=(SELECT id FROM users WHERE username=?1) AND expires_at>?2
        );
        defer stmt.finalize();
        try stmt.bind(1, mailbox);
        try stmt.bind(2, now);
        if (!try stmt.step()) return error.NotFound;
        return @intCast(stmt.columnInt64(0));
    }

    pub fn finishQueuedDelivery(self: *Database, queue_id: []const u8, delivered: bool) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.execLocked("BEGIN IMMEDIATE");
        errdefer self.execLocked("ROLLBACK") catch {};
        if (std.mem.startsWith(u8, queue_id, "route-") and queue_id.len > 39 and queue_id[38] == '-') {
            const ordinal = try std.fmt.parseInt(i64, queue_id[39..], 10);
            const update = try self.prepareLocked("UPDATE accepted_mail_targets SET outcome=?3 WHERE delivery_id=?1 AND ordinal=?2 AND outcome='queued'");
            defer update.finalize();
            try update.bind(1, @as([]const u8, queue_id[6..38]));
            try update.bind(2, ordinal);
            try update.bind(3, @as([]const u8, if (delivered) "remote_delivered" else "remote_failed"));
            _ = try update.step();
        }
        {
            const remove = try self.prepareLocked("DELETE FROM message_queue WHERE id=?1 RETURNING id");
            defer remove.finalize();
            try remove.bind(1, queue_id);
            const removed = try remove.step();
            if (removed) {
                _ = try remove.step();
                try self.recordQueuedOutcomeLocked(delivered);
            }
        }
        try self.execLocked("COMMIT");
    }

    /// Record one terminal recipient outcome in the same transaction as the
    /// queue deletion. Retries and duplicate completion calls are excluded.
    fn recordQueuedOutcomeLocked(self: *Database, delivered: bool) !void {
        const minute = @divFloor(time_compat.timestamp(), 60);
        const outcome = try self.prepareLocked(
            \\INSERT INTO outbound_delivery_minutes(minute,delivered,failed) VALUES (?1,?2,?3)
            \\ON CONFLICT(minute) DO UPDATE SET delivered=delivered+excluded.delivered,failed=failed+excluded.failed
        );
        defer outcome.finalize();
        try outcome.bind(1, minute);
        try outcome.bind(2, @as(i64, @intFromBool(delivered)));
        try outcome.bind(3, @as(i64, @intFromBool(!delivered)));
        _ = try outcome.step();

        const prune = try self.prepareLocked("DELETE FROM outbound_delivery_minutes WHERE minute<?1");
        defer prune.finalize();
        try prune.bind(1, minute - 59);
        _ = try prune.step();
    }

    pub const SenderRoute = enum { allow, allow_without_forward, review, decline };

    pub const SenderReviewStatus = struct { enabled: bool = false, onboarding_pending: bool = false, pending: i64 = 0 };

    pub fn senderReviewStatus(self: *Database, user: []const u8) !SenderReviewStatus {
        const stmt = try self.prepare(
            \\SELECT COALESCE(s.enabled,0),COALESCE(s.onboarding_pending,0),
            \\       (SELECT COUNT(*) FROM sender_review_messages r WHERE r.user_id=u.id AND r.folder='Screening')
            \\FROM users u LEFT JOIN sender_screening s ON s.user_id=u.id WHERE u.username=?1
        );
        defer stmt.finalize();
        try stmt.bind(1, user);
        if (!try stmt.step()) return error.NotFound;
        return .{ .enabled = stmt.columnInt64(0) != 0, .onboarding_pending = stmt.columnInt64(1) != 0, .pending = stmt.columnInt64(2) };
    }

    pub const ScreeningSetting = enum { enable, disable, onboard };

    /// The caller holds the mailbox lock so intake sees a single policy revision.
    pub fn setSenderScreening(self: *Database, user: []const u8, setting: ScreeningSetting) !void {
        if (setting == .onboard) {
            const stmt = try self.prepare("UPDATE sender_screening SET enabled=1,onboarding_pending=0 WHERE user_id=(SELECT id FROM users WHERE username=?1) AND onboarding_pending=1");
            defer stmt.finalize();
            try stmt.bind(1, user);
            _ = try stmt.step();
            return;
        }
        const stmt = try self.prepare(
            \\INSERT INTO sender_screening(user_id,enabled,onboarding_pending) SELECT id,?2,0 FROM users WHERE username=?1
            \\ON CONFLICT(user_id) DO UPDATE SET enabled=excluded.enabled,onboarding_pending=0
        );
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, @intFromBool(setting == .enable));
        _ = try stmt.step();
    }

    pub const SenderDecision = enum { allow, decline, reset, recover };
    pub const SenderDecisionScope = union(enum) {
        author: struct { address: []const u8, revision: i64, forward: ?bool = null },
        copy: struct { basename: []const u8, reference: []const u8, stamp: []const u8 },
    };

    /// Commit the future rule and the work for existing held copies together.
    /// With a per-copy decision the caller has already checked its ETag and
    /// stamped provenance. No future rule is created for that operation.
    pub fn scheduleSenderDecision(self: *Database, user: []const u8, scope: SenderDecisionScope, decision: SenderDecision) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.execLocked("BEGIN IMMEDIATE");
        errdefer self.execLocked("ROLLBACK") catch {};
        const destination: []const u8 = switch (decision) {
            .allow, .recover => "INBOX",
            .decline => "Declined",
            .reset => "Screening",
        };
        switch (scope) {
            .copy => |copy| {
                if (decision == .reset) return error.InvalidReviewDecision;
                const stmt = try self.prepareLocked(
                    \\UPDATE sender_review_messages SET next_folder=?3,reference=?4,
                    \\  verified_author=(verified_author AND file_stamp<>''),file_stamp=?5,
                    \\  operation=lower(hex(randomblob(16))),retry_at=0,
                    \\  forward_release=(?6=1 AND NOT (verified_author=1 AND file_stamp<>'' AND EXISTS(
                    \\    SELECT 1 FROM sender_screening_rules p JOIN sender_screening s ON s.user_id=p.user_id AND s.enabled=1
                    \\    WHERE p.user_id=sender_review_messages.user_id AND p.author=sender_review_messages.author AND p.forward=0)))
                    \\WHERE user_id=(SELECT id FROM users WHERE username=?1) AND basename=?2 AND operation IS NULL AND folder<>?3
                );
                defer stmt.finalize();
                try stmt.bind(1, user);
                try stmt.bind(2, copy.basename);
                try stmt.bind(3, destination);
                try stmt.bind(4, copy.reference);
                try stmt.bind(5, copy.stamp);
                try stmt.bind(6, @intFromBool(decision == .allow));
                _ = try stmt.step();
                if (sqlite.sqlite3_changes(self.db) == 0) return error.ReviewChanged;
            },
            .author => |author| {
                if (decision == .recover) return error.InvalidReviewDecision;
                const existing = try self.prepareLocked(
                    \\SELECT COALESCE(p.revision,0),COALESCE(p.forward,1),EXISTS(
                    \\  SELECT 1 FROM sender_review_messages r WHERE r.user_id=u.id AND r.author=?2 COLLATE NOCASE
                    \\  AND r.verified_author=1 AND r.file_stamp<>'' AND r.operation IS NOT NULL)
                    \\FROM users u LEFT JOIN sender_screening_rules p ON p.user_id=u.id AND p.author=?2 WHERE u.username=?1
                );
                defer existing.finalize();
                try existing.bind(1, user);
                try existing.bind(2, author.address);
                if (!try existing.step() or existing.columnInt64(0) != author.revision) return error.ReviewChanged;
                if (existing.columnInt64(2) != 0) return error.ReviewInProgress;
                const forward = author.forward orelse (existing.columnInt64(1) != 0);
                if (decision == .reset) {
                    if (author.revision == 0) return error.ReviewChanged;
                    const delete = try self.prepareLocked("DELETE FROM sender_screening_rules WHERE user_id=(SELECT id FROM users WHERE username=?1) AND author=?2");
                    defer delete.finalize();
                    try delete.bind(1, user);
                    try delete.bind(2, author.address);
                    _ = try delete.step();
                } else {
                    const rule = try self.prepareLocked(
                        \\INSERT INTO sender_screening_rules(user_id,author,action,forward,revision)
                        \\SELECT id,?2,?3,?4,(random() & 4503599627370495)+1 FROM users WHERE username=?1
                        \\ON CONFLICT(user_id,author) DO UPDATE SET action=excluded.action,forward=excluded.forward,revision=excluded.revision
                    );
                    defer rule.finalize();
                    try rule.bind(1, user);
                    try rule.bind(2, author.address);
                    try rule.bind(3, @as([]const u8, @tagName(decision)));
                    try rule.bind(4, @intFromBool(forward));
                    _ = try rule.step();
                }
                // A saved decision supersedes any previous invitation. A
                // later reset should return the sender to ordinary review.
                const invitation = try self.prepareLocked("DELETE FROM sender_review_invitations WHERE user_id=(SELECT id FROM users WHERE username=?1) AND author=?2");
                defer invitation.finalize();
                try invitation.bind(1, user);
                try invitation.bind(2, author.address);
                _ = try invitation.step();
                const copies = try self.prepareLocked(
                    \\UPDATE sender_review_messages SET next_folder=?3,operation=lower(hex(randomblob(16))),forward_release=?4,retry_at=0
                    \\WHERE user_id=(SELECT id FROM users WHERE username=?1) AND author=?2 COLLATE NOCASE AND verified_author=1 AND file_stamp<>'' AND folder<>?3
                );
                defer copies.finalize();
                try copies.bind(1, user);
                try copies.bind(2, author.address);
                try copies.bind(3, destination);
                try copies.bind(4, @intFromBool(forward and decision == .allow));
                _ = try copies.step();
            },
        }
        try self.execLocked("COMMIT");
    }

    pub const AttentionKind = enum { follow_up, saved, snoozed, muted, reminders };
    pub const AttentionArrival = struct {
        own: ?[]const u8,
        parents_json: []const u8,
        automatic: bool,
        reply_parent: ?[]const u8 = null,
    };
    pub const FiledCopy = struct {
        basename: []const u8,
        stamp: []const u8 = "",
        size: ?usize = null,
        attention: ?AttentionArrival = null,
        notification_key: []const u8 = "",
        thread_reply_digest: ?[64]u8 = null,
        thread_reply_outgoing: bool = false,
        calendar_revisions: []const calendar_invite.Revision = &.{},
    };

    pub fn finishReviewPlacement(self: *Database, user: []const u8, operation: []const u8, placed: ?FiledCopy) !void {
        const stmt = try self.prepare(if (placed != null)
            "UPDATE sender_review_messages SET folder=next_folder,file_stamp=?3,next_folder=NULL,operation=NULL,forward_release=0,retry_at=0 WHERE user_id=(SELECT id FROM users WHERE username=?1) AND operation=?2"
        else
            "DELETE FROM sender_review_messages WHERE user_id=(SELECT id FROM users WHERE username=?1) AND operation=?2");
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, operation);
        if (placed) |file| try stmt.bind(3, file.stamp);
        _ = try stmt.step();
    }

    pub fn senderRoute(self: *Database, mailbox: []const u8, verified_author: ?[]const u8) !SenderRoute {
        self.mutex.lock();
        defer self.mutex.unlock();
        const stmt = try self.prepareLocked(
            \\SELECT r.action,r.forward,i.id IS NOT NULL FROM users u JOIN sender_screening s ON s.user_id=u.id AND s.enabled=1
            \\LEFT JOIN sender_screening_rules r ON r.user_id=u.id AND r.author=?2
            \\LEFT JOIN sender_review_invitations i ON i.user_id=u.id AND i.author=?2 AND i.expires_at>unixepoch()
            \\WHERE u.username=?1
        );
        defer stmt.finalize();
        try stmt.bind(1, mailbox);
        try stmt.bindOpt(2, verified_author);
        if (!try stmt.step()) return .allow;
        if (stmt.columnIsNull(0)) return if (stmt.columnInt64(2) != 0) .allow_without_forward else .review;
        if (std.mem.eql(u8, stmt.columnText(0), "decline")) return .decline;
        return if (stmt.columnInt64(1) != 0) .allow else .allow_without_forward;
    }

    pub const JunkDecision = enum { junk, not_junk };

    pub fn junkPreference(self: *Database, user: []const u8, verified_author: []const u8) !?JunkDecision {
        if (verified_author.len == 0) return null;
        const stmt = try self.prepare(
            \\SELECT action FROM mailbox_junk_feedback
            \\WHERE user_id=(SELECT id FROM users WHERE username=?1) AND author=?2 AND author<>'' ORDER BY id DESC LIMIT 1
        );
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, verified_author);
        return if (try stmt.step()) std.meta.stringToEnum(JunkDecision, stmt.columnText(0)) else null;
    }

    pub fn junkSource(self: *Database, a: std.mem.Allocator, user: []const u8, reference: []const u8) !?[]const u8 {
        const stmt = try self.prepare(
            \\SELECT action,source_folder FROM mailbox_junk_feedback
            \\WHERE user_id=(SELECT id FROM users WHERE username=?1) AND reference=?2 ORDER BY id DESC LIMIT 1
        );
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, reference);
        if (!try stmt.step() or !std.mem.eql(u8, stmt.columnText(0), "junk")) return null;
        return try a.dupe(u8, stmt.columnText(1));
    }

    pub fn finishDeliveryTarget(self: *Database, id: []const u8, ordinal: i64, outcome: []const u8, filed: ?FiledCopy) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.execLocked("BEGIN IMMEDIATE");
        errdefer self.execLocked("ROLLBACK") catch {};
        const update = try self.prepareLocked("UPDATE accepted_mail_targets SET outcome=?3,queued_bytes=0,reply_mime=NULL WHERE delivery_id=?1 AND ordinal=?2 AND outcome='pending'");
        defer update.finalize();
        try update.bind(1, id);
        try update.bind(2, ordinal);
        try update.bind(3, outcome);
        _ = try update.step();
        if (sqlite.sqlite3_changes(self.db) == 0) return error.NotFound;
        try self.releaseForwardTargetsLocked(id, ordinal, filed != null);
        if (filed) |file| {
            try self.recordPlacementLocked(id, ordinal, file);
            try self.recordTeamThreadReplyLocked(id, ordinal, file);
            try self.recordCalendarRevisionsLocked(id, ordinal, file.calendar_revisions);
            const muted = try self.attentionArrivalLocked(id, ordinal, file.attention);
            try self.stageDeliveryEffectsLocked(id, ordinal, file, muted);
            try self.stageBrowserNotificationLocked(id, ordinal, file, muted);
            const review = try self.prepareLocked(
                \\INSERT OR IGNORE INTO sender_review_messages(user_id,basename,folder,envelope_from,author,verified_author,recipient,remote_addr,file_stamp,
                \\  next_folder,operation,forward_release)
                \\SELECT t.mailbox_id,?3,t.folder,COALESCE(t.reply_from,m.envelope_from),COALESCE(t.reply_author,m.author),m.verified_author OR t.reply_author IS NOT NULL,t.recipient,m.remote_addr,?4,
                \\  CASE WHEN r.action='allow' THEN 'INBOX' WHEN r.action='decline' AND t.folder<>'Declined' THEN 'Declined'
                \\       WHEN r.action IS NULL AND s.enabled=1 AND t.folder='Declined' THEN 'Screening' END,
                \\  CASE WHEN r.action='allow' OR (r.action='decline' AND t.folder<>'Declined')
                \\       OR (r.action IS NULL AND s.enabled=1 AND t.folder='Declined') THEN lower(hex(randomblob(16))) END,
                \\  CASE WHEN r.action='allow' THEN r.forward ELSE 0 END
                \\FROM accepted_mail_targets t JOIN accepted_mail m ON m.id=t.delivery_id
                \\LEFT JOIN sender_screening s ON s.user_id=t.mailbox_id
                \\LEFT JOIN sender_screening_rules r ON r.user_id=t.mailbox_id AND r.author=COALESCE(t.reply_author,m.author) AND (m.verified_author=1 OR t.reply_author IS NOT NULL) AND s.enabled=1
                \\WHERE t.delivery_id=?1 AND t.ordinal=?2 AND t.mailbox_id<>0 AND t.review_copy=1
            );
            defer review.finalize();
            try review.bind(1, id);
            try review.bind(2, ordinal);
            try review.bind(3, file.basename);
            try review.bind(4, file.stamp);
            _ = try review.step();
        }
        try self.compactDeliveryLocked(id);
        try self.execLocked("COMMIT");
    }

    pub const CategoryPolicy = struct { automatic: bool = false, destination: ?categories.Destination = null };

    pub fn categoryPolicy(self: *Database, user: []const u8, author: []const u8) !CategoryPolicy {
        const stmt = try self.prepare(
            \\SELECT COALESCE(s.automatic,0),r.destination FROM users u
            \\LEFT JOIN mail_category_settings s ON s.user_id=u.id
            \\LEFT JOIN mail_category_rules r ON r.user_id=u.id AND r.author=?2
            \\WHERE u.username=?1
        );
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, author);
        if (!try stmt.step()) return .{};
        return .{
            .automatic = stmt.columnInt64(0) != 0,
            .destination = std.meta.stringToEnum(categories.Destination, stmt.columnText(1)),
        };
    }

    pub fn setCategorySettings(self: *Database, user: []const u8, automatic: bool) !void {
        const stmt = try self.prepare(
            \\INSERT INTO mail_category_settings(user_id,automatic)
            \\SELECT id,?2 FROM users WHERE username=?1
            \\ON CONFLICT(user_id) DO UPDATE SET automatic=excluded.automatic
        );
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, @intFromBool(automatic));
        _ = try stmt.step();
    }

    pub fn setCategoryRule(self: *Database, user: []const u8, author: []const u8, destination: ?categories.Destination) !void {
        const stmt = try self.prepare(if (destination != null)
            \\INSERT INTO mail_category_rules(user_id,author,destination)
            \\SELECT id,?2,?3 FROM users WHERE username=?1
            \\ON CONFLICT(user_id,author) DO UPDATE SET destination=excluded.destination
        else
            "DELETE FROM mail_category_rules WHERE user_id=(SELECT id FROM users WHERE username=?1) AND author=?2");
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, author);
        if (destination) |value| try stmt.bind(3, @tagName(value));
        _ = try stmt.step();
    }

    fn recordPlacementLocked(self: *Database, id: []const u8, ordinal: i64, file: FiledCopy) !void {
        if (file.stamp.len == 0) return;
        const stmt = try self.prepareLocked(
            \\INSERT INTO mailbox_message_refs(user_id,reference,folder,basename,file_stamp,intake_folder,placement_reason,verified_author,calendar_history_checked)
            \\SELECT t.mailbox_id,lower(hex(randomblob(16))),IIF(t.folder='new','INBOX',t.folder),?3,?4,
            \\       IIF(t.folder='new','INBOX',t.folder),t.placement_reason,COALESCE(t.reply_author,IIF(m.verified_author=1,m.author,'')),1
            \\FROM accepted_mail_targets t JOIN accepted_mail m ON m.id=t.delivery_id
            \\WHERE t.delivery_id=?1 AND t.ordinal=?2 AND t.mailbox_id<>0
            \\      AND ((t.folder='Sent' AND ?5=1)
            \\           OR ((t.folder IN ('new','Newsletters','Receipts') OR t.placement_reason IN ('junk_feedback','spam_filter'))
            \\               AND (m.verified_author=1 OR t.placement_reason<>'' OR t.reply_author IS NOT NULL)))
            \\ON CONFLICT(user_id,folder,basename) DO UPDATE SET intake_folder=excluded.intake_folder,
            \\  placement_reason=excluded.placement_reason,verified_author=excluded.verified_author,calendar_history_checked=1
            \\WHERE mailbox_message_refs.file_stamp=excluded.file_stamp
        );
        defer stmt.finalize();
        try stmt.bind(1, id);
        try stmt.bind(2, ordinal);
        try stmt.bind(3, file.basename);
        try stmt.bind(4, file.stamp);
        try stmt.bind(5, @intFromBool(file.thread_reply_outgoing));
        _ = try stmt.step();
    }

    fn recordTeamThreadReplyLocked(self: *Database, id: []const u8, ordinal: i64, file: FiledCopy) !void {
        const digest = file.thread_reply_digest orelse return;
        const arrival = file.attention orelse return;
        if (arrival.automatic or file.stamp.len == 0) return;
        const own = arrival.own orelse return;
        const parent = arrival.reply_parent orelse return;
        const stmt = try self.prepareLocked(if (file.thread_reply_outgoing) team_threads.record_sent_reply_sql else team_threads.record_reply_sql);
        defer stmt.finalize();
        try stmt.bind(1, id);
        try stmt.bind(2, ordinal);
        try stmt.bind(3, file.basename);
        try stmt.bind(4, @as([]const u8, &digest));
        try stmt.bind(5, own);
        try stmt.bind(6, parent);
        try stmt.bind(7, team_threads.max_followed_replies);
        try stmt.bind(8, file.stamp);
        _ = try stmt.step();
    }

    /// Native clients reserve an actual Sent file before acceptance. Register
    /// that exact file and its delivery in the same transaction as the receipt.
    fn recordNativeSentFileLocked(self: *Database, id: []const u8, sent: NativeSentReply) !void {
        {
            const stmt = try self.prepareLocked(
                \\INSERT OR IGNORE INTO mailbox_message_refs(user_id,reference,folder,basename,file_stamp,intake_folder,calendar_history_checked)
                \\SELECT owner_id,lower(hex(randomblob(16))),'Sent',?2,?3,'Sent',1
                \\FROM mail_team_thread_submissions WHERE delivery_id=?1
            );
            defer stmt.finalize();
            try stmt.bind(1, id);
            try stmt.bind(2, sent.basename);
            try stmt.bind(3, sent.stamp);
            _ = try stmt.step();
        }
        const stmt = try self.prepareLocked(
            \\INSERT INTO mail_team_thread_native_sent(delivery_id,reference,content_revision,wire_id)
            \\SELECT p.delivery_id,r.reference,?4,?5 FROM mail_team_thread_submissions p
            \\JOIN mailbox_message_refs r ON r.user_id=p.owner_id AND r.folder='Sent' AND r.basename=?2 AND r.file_stamp=?3
            \\WHERE p.delivery_id=?1
        );
        defer stmt.finalize();
        try stmt.bind(1, id);
        try stmt.bind(2, sent.basename);
        try stmt.bind(3, sent.stamp);
        try stmt.bind(4, @as([]const u8, &sent.revision));
        try stmt.bind(5, sent.wire_id);
        _ = try stmt.step();
    }

    fn publishNativeSentReplyLocked(self: *Database, id: []const u8) !void {
        const stmt = try self.prepareLocked(team_threads.record_native_sent_sql);
        defer stmt.finalize();
        try stmt.bind(1, id);
        try stmt.bind(2, team_threads.max_followed_replies);
        _ = try stmt.step();
    }

    const calendar_revision_insert =
        \\INSERT INTO mail_calendar_revisions(user_id,component,series,method,future,sequence,dtstamp,occurrence_wall,occurrence_zone,occurrence_day)
    ++ " SELECT ";
    const calendar_revision_values = ",?3,?4,?5,?6,?7,?8,?9,?10,?11 ";
    const calendar_revision_merge =
        \\ ON CONFLICT(user_id,component,method,future) DO UPDATE SET sequence=excluded.sequence,dtstamp=excluded.dtstamp
        \\ WHERE (excluded.sequence,excluded.dtstamp)>(mail_calendar_revisions.sequence,mail_calendar_revisions.dtstamp)
    ;

    fn recordCalendarRevisionsLocked(self: *Database, id: []const u8, ordinal: i64, revisions: []const calendar_invite.Revision) !void {
        if (revisions.len == 0) return;
        const stmt = try self.prepareLocked(calendar_revision_insert ++ "t.mailbox_id" ++ calendar_revision_values ++
            \\FROM accepted_mail_targets t JOIN accepted_mail m ON m.id=t.delivery_id
            \\WHERE t.delivery_id=?1 AND t.ordinal=?2 AND t.mailbox_id<>0 AND t.is_primary=1
            \\AND t.folder IN ('new','Newsletters','Receipts') AND m.verified_author=1
            \\AND t.placement_reason NOT IN ('spam_filter','junk_feedback')
        ++ calendar_revision_merge);
        defer stmt.finalize();
        for (revisions) |revision| {
            try stmt.bind(1, id);
            try stmt.bind(2, ordinal);
            try bindCalendarRevision(stmt, revision);
            _ = try stmt.step();
            try stmt.reset();
        }
    }

    fn bindCalendarRevision(stmt: Statement, revision: calendar_invite.Revision) !void {
        try stmt.bind(3, @as([]const u8, &revision.component));
        try stmt.bind(4, @as([]const u8, &revision.series));
        try stmt.bind(5, @tagName(revision.method));
        try stmt.bind(6, @intFromBool(revision.this_and_future));
        try stmt.bind(7, revision.sequence);
        try stmt.bind(8, revision.dtstamp);
        try bindOccurrence(stmt, 9, revision.occurrence);
    }

    pub const pending_calendar_history = "calendar_history_checked=0 AND verified_author<>'' " ++
        "AND intake_folder IN ('INBOX','Newsletters','Receipts') AND placement_reason NOT IN ('spam_filter','junk_feedback')";

    pub const CalendarHistoryScope = struct { user: []const u8, author: []const u8 };
    pub const CalendarHistoryMessage = struct {
        owner: i64,
        username: []const u8,
        attendee: []const u8,
        author: []const u8,
        reference: []const u8,
    };

    pub fn nextCalendarHistory(self: *Database, a: std.mem.Allocator, scope: ?CalendarHistoryScope) !?CalendarHistoryMessage {
        const base =
            \\SELECT u.id,u.username,u.email,m.verified_author,m.reference
            \\FROM mailbox_message_refs m JOIN users u ON u.id=m.user_id
        ++ " WHERE " ++ pending_calendar_history;
        const stmt = try self.prepare(if (scope != null)
            base ++ " AND m.user_id=(SELECT id FROM users WHERE username=?1) AND m.verified_author=?2 COLLATE NOCASE ORDER BY m.reference LIMIT 1"
        else
            base ++ " ORDER BY m.user_id,m.verified_author COLLATE NOCASE,m.reference LIMIT 1");
        defer stmt.finalize();
        if (scope) |target| {
            try stmt.bind(1, target.user);
            try stmt.bind(2, target.author);
        }
        if (!try stmt.step()) return null;
        return .{
            .owner = stmt.columnInt64(0),
            .username = try a.dupe(u8, stmt.columnText(1)),
            .attendee = try a.dupe(u8, stmt.columnText(2)),
            .author = try a.dupe(u8, stmt.columnText(3)),
            .reference = try a.dupe(u8, stmt.columnText(4)),
        };
    }

    /// Commit the revisions and the scan checkpoint together. Live delivery
    /// uses the same ordering rule, so replay or a concurrent arrival wins
    /// only when it carries a newer organizer revision.
    pub fn finishCalendarHistory(self: *Database, source: CalendarHistoryMessage, revisions: []const calendar_invite.Revision) !void {
        var tx = try self.beginTransaction(.write);
        defer tx.deinit();
        if (revisions.len != 0) {
            const stmt = try tx.prepare(calendar_revision_insert ++ "user_id" ++ calendar_revision_values ++
                "FROM mailbox_message_refs WHERE user_id=?1 AND reference=?2 AND " ++ pending_calendar_history ++ calendar_revision_merge);
            defer stmt.finalize();
            for (revisions) |revision| {
                try stmt.bind(1, source.owner);
                try stmt.bind(2, source.reference);
                try bindCalendarRevision(stmt, revision);
                _ = try stmt.step();
                try stmt.reset();
            }
        }
        const stmt = try tx.prepare("UPDATE mailbox_message_refs SET calendar_history_checked=1 WHERE user_id=?1 AND reference=?2");
        defer stmt.finalize();
        try stmt.bind(1, source.owner);
        try stmt.bind(2, source.reference);
        _ = try stmt.step();
        try tx.commit();
    }

    fn bindOccurrence(stmt: Statement, first: usize, occurrence: ?calendar_invite.WallTime) !void {
        if (occurrence) |value| {
            try stmt.bind(first, value.wall);
            try stmt.bindOpt(first + 1, value.zone);
            try stmt.bind(first + 2, @intFromBool(value.all_day));
        } else {
            for (0..3) |offset| try stmt.bindNull(first + offset);
        }
    }

    pub const InvitationDisposition = enum { current, superseded, cancelled };

    /// Compare the exact recurrence with later requests and applicable
    /// cancellations. Separate cancellation records keep whole-series and
    /// range tombstones effective even if the organizer later reopens a series.
    pub fn calendarInvitationDisposition(context: anytype, user: []const u8, revision: calendar_invite.Revision) !InvitationDisposition {
        const stmt = try context.prepare(
            \\SELECT method FROM mail_calendar_revisions
            \\WHERE user_id=(SELECT id FROM users WHERE username=?1) AND series=?2
            \\AND ((component=?3 AND future=?4) OR (method='cancel' AND occurrence_wall IS NULL)
            \\    OR (future=1 AND occurrence_wall<=?5 AND occurrence_zone IS ?6 AND occurrence_day=?7))
            \\AND ((sequence,dtstamp)>(?8,?9) OR (method='cancel' AND ?10='request' AND (sequence,dtstamp)=(?8,?9)))
            \\ORDER BY sequence DESC,dtstamp DESC,method LIMIT 1
        );
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, @as([]const u8, &revision.series));
        try stmt.bind(3, @as([]const u8, &revision.component));
        try stmt.bind(4, @intFromBool(revision.this_and_future));
        try bindOccurrence(stmt, 5, revision.occurrence);
        try stmt.bind(8, revision.sequence);
        try stmt.bind(9, revision.dtstamp);
        try stmt.bind(10, @tagName(revision.method));
        if (!try stmt.step()) return .current;
        return if (std.mem.eql(u8, stmt.columnText(0), "cancel")) .cancelled else .superseded;
    }

    pub fn requireCurrentCalendarInvitation(context: anytype, user: []const u8, revision: calendar_invite.Revision) !void {
        switch (try calendarInvitationDisposition(context, user, revision)) {
            .current => {},
            .superseded => return error.CalendarInvitationStale,
            .cancelled => return error.CalendarInvitationCancelled,
        }
    }

    fn stageDeliveryEffectsLocked(self: *Database, id: []const u8, ordinal: i64, file: FiledCopy, muted: bool) !void {
        const effect = try self.prepareLocked(
            \\INSERT OR IGNORE INTO accepted_mail_effects(delivery_id,ordinal,filename,size,notified)
            \\SELECT t.delivery_id,t.ordinal,?3,COALESCE(?6,length(m.mime)+t.verified_forward*?5),?4 OR NOT (t.is_primary AND t.folder='new')
            \\FROM accepted_mail_targets t JOIN accepted_mail m ON m.id=t.delivery_id
            \\WHERE t.delivery_id=?1 AND t.ordinal=?2 AND t.folder IN ('new','Newsletters','Receipts') AND t.outcome='filed'
        );
        defer effect.finalize();
        try effect.bind(1, id);
        try effect.bind(2, ordinal);
        try effect.bind(3, file.basename);
        try effect.bind(4, @intFromBool(muted));
        try effect.bind(5, forwarding_wire.loop_header.len);
        try effect.bindOpt(6, file.size);
        _ = try effect.step();
    }

    pub const NotificationRule = enum { default, notify, quiet };
    pub const NotificationScope = enum { sender, thread };
    pub const NotificationRules = struct {
        verified_author: []const u8,
        sender: NotificationRule = .default,
        thread: NotificationRule = .default,
    };

    pub fn browserNotificationsEnabled(self: *Database, username: []const u8) !bool {
        const stmt = try self.prepare("SELECT s.enabled FROM mail_notification_settings s JOIN users u ON u.id=s.user_id WHERE u.username=?1");
        defer stmt.finalize();
        try stmt.bind(1, username);
        return try stmt.step() and stmt.columnInt64(0) != 0;
    }

    pub fn setBrowserNotifications(self: *Database, username: []const u8, enabled: bool) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.execLocked("BEGIN IMMEDIATE");
        errdefer self.execLocked("ROLLBACK") catch {};
        const setting = try self.prepareLocked(
            \\INSERT INTO mail_notification_settings(user_id,enabled) SELECT id,?2 FROM users WHERE username=?1
            \\ON CONFLICT(user_id) DO UPDATE SET enabled=excluded.enabled
        );
        defer setting.finalize();
        try setting.bind(1, username);
        try setting.bind(2, @intFromBool(enabled));
        _ = try setting.step();
        if (!enabled) {
            const clear = try self.prepareLocked("UPDATE mail_notification_events SET claimed_at=unixepoch() WHERE user_id=(SELECT id FROM users WHERE username=?1) AND claimed_at IS NULL");
            defer clear.finalize();
            try clear.bind(1, username);
            _ = try clear.step();
            const shared = try self.prepareLocked(
                \\UPDATE mail_team_thread_replies SET notice_at=0 WHERE notice_at<>0 AND share_id IN (
                \\ SELECT s.id FROM mail_team_thread_shares s JOIN users u ON u.id=s.grantee_id WHERE u.username=?1)
            );
            defer shared.finalize();
            try shared.bind(1, username);
            _ = try shared.step();
        }
        try self.execLocked("COMMIT");
    }

    const notification_thread_match =
        " AND (reference=?2 OR EXISTS(SELECT 1 FROM json_each(wire_ids) a JOIN json_each(?3) b USING(value)))";

    pub fn browserNotificationRules(self: *Database, username: []const u8, reference: []const u8, keys: []const u8, author: []const u8) !NotificationRules {
        var rules: NotificationRules = .{ .verified_author = author };
        {
            const stmt = try self.prepare(
                "SELECT rule FROM mail_notification_threads WHERE user_id=(SELECT id FROM users WHERE username=?1)" ++
                    notification_thread_match ++ " ORDER BY rowid DESC LIMIT 1",
            );
            defer stmt.finalize();
            try stmt.bind(1, username);
            try stmt.bind(2, reference);
            try stmt.bind(3, keys);
            if (try stmt.step()) rules.thread = std.meta.stringToEnum(NotificationRule, stmt.columnText(0)) orelse .default;
        }
        if (author.len > 0) {
            const stmt = try self.prepare("SELECT rule FROM mail_notification_senders WHERE user_id=(SELECT id FROM users WHERE username=?1) AND author=?2");
            defer stmt.finalize();
            try stmt.bind(1, username);
            try stmt.bind(2, author);
            if (try stmt.step()) rules.sender = std.meta.stringToEnum(NotificationRule, stmt.columnText(0)) orelse .default;
        }
        return rules;
    }

    pub fn setBrowserNotificationRule(self: *Database, username: []const u8, reference: []const u8, keys: []const u8, author: []const u8, scope: NotificationScope, rule: NotificationRule) !void {
        if (scope == .sender) {
            if (author.len == 0) return error.UnverifiedSender;
            const stmt = try self.prepare(if (rule == .default)
                "DELETE FROM mail_notification_senders WHERE user_id=(SELECT id FROM users WHERE username=?1) AND author=?2"
            else
                \\INSERT INTO mail_notification_senders(user_id,author,rule) SELECT id,?2,?3 FROM users WHERE username=?1
                \\ON CONFLICT(user_id,author) DO UPDATE SET rule=excluded.rule
            );
            defer stmt.finalize();
            try stmt.bind(1, username);
            try stmt.bind(2, author);
            if (rule != .default) try stmt.bind(3, @tagName(rule));
            _ = try stmt.step();
            return;
        }

        self.mutex.lock();
        defer self.mutex.unlock();
        try self.execLocked("BEGIN IMMEDIATE");
        errdefer self.execLocked("ROLLBACK") catch {};
        const combined = if (rule != .default) blk: {
            const existing = try self.prepareLocked(
                \\SELECT json_group_array(value) FROM (
                \\    SELECT value FROM json_each(?3)
                \\    UNION
                \\    SELECT j.value FROM mail_notification_threads n, json_each(n.wire_ids) j
                \\    WHERE n.user_id=(SELECT id FROM users WHERE username=?1)
                ++ notification_thread_match ++ " LIMIT 192)",
            );
            defer existing.finalize();
            try existing.bind(1, username);
            try existing.bind(2, reference);
            try existing.bind(3, keys);
            if (!try existing.step()) return error.DatabaseError;
            break :blk try self.allocator.dupe(u8, existing.columnText(0));
        } else null;
        defer if (combined) |value| self.allocator.free(value);
        const clear = try self.prepareLocked(
            "DELETE FROM mail_notification_threads WHERE user_id=(SELECT id FROM users WHERE username=?1)" ++ notification_thread_match,
        );
        defer clear.finalize();
        try clear.bind(1, username);
        try clear.bind(2, reference);
        try clear.bind(3, keys);
        _ = try clear.step();
        if (combined) |value| {
            const insert = try self.prepareLocked(
                "INSERT INTO mail_notification_threads(user_id,reference,wire_ids,rule) SELECT id,?2,?3,?4 FROM users WHERE username=?1",
            );
            defer insert.finalize();
            try insert.bind(1, username);
            try insert.bind(2, reference);
            try insert.bind(3, value);
            try insert.bind(4, @tagName(rule));
            _ = try insert.step();
        }
        try self.execLocked("COMMIT");
    }

    const notification_rule =
        \\ AND COALESCE(
        \\  (SELECT t.rule FROM mail_notification_threads t WHERE t.user_id=n.user_id
        \\   AND EXISTS(SELECT 1 FROM json_each(t.wire_ids) WHERE value=n.own_id OR value IN (SELECT value FROM json_each(n.parents_json)))
        \\   ORDER BY t.rowid DESC LIMIT 1),
        \\  (SELECT s.rule FROM mail_notification_senders s WHERE s.user_id=n.user_id AND s.author=n.author),
        \\  IIF(n.folder='new','notify','quiet'))='notify'
    ;

    fn stageBrowserNotificationLocked(self: *Database, id: []const u8, ordinal: i64, file: FiledCopy, muted: bool) !void {
        const own = if (file.attention) |item| item.own else null;
        const parents = if (file.attention) |item| item.parents_json else "[]";
        if (own != null and !std.mem.eql(u8, parents, "[]")) {
            const learn = try self.prepareLocked(
                \\UPDATE mail_notification_threads AS n SET wire_ids=json_insert(wire_ids,'$[#]',?3)
                \\WHERE n.user_id=(SELECT mailbox_id FROM accepted_mail_targets
                \\  WHERE delivery_id=?1 AND ordinal=?2 AND folder IN ('new','Newsletters','Receipts'))
                \\  AND json_array_length(wire_ids)<192 AND ?3 NOT IN (SELECT value FROM json_each(wire_ids))
                \\  AND EXISTS(SELECT 1 FROM json_each(wire_ids) a JOIN json_each(?4) b USING(value))
            );
            defer learn.finalize();
            try learn.bind(1, id);
            try learn.bind(2, ordinal);
            try learn.bindOpt(3, own);
            try learn.bind(4, parents);
            _ = try learn.step();
        }
        if (muted or file.notification_key.len == 0) return;
        const record = try self.prepareLocked(
            \\WITH n AS (
            \\ SELECT t.mailbox_id AS user_id, IIF(m.verified_author=1,'v:','u:')||lower(m.author)||':'||?3 AS event_key,
            \\  t.folder, IIF(m.verified_author=1,m.author,'') AS author, ?4 AS own_id, ?5 AS parents_json
            \\ FROM accepted_mail_targets t JOIN accepted_mail m ON m.id=t.delivery_id
            \\ JOIN mail_notification_settings prefs ON prefs.user_id=t.mailbox_id AND prefs.enabled=1
            \\ WHERE t.delivery_id=?1 AND t.ordinal=?2 AND t.folder IN ('new','Newsletters','Receipts')
            \\   AND (m.verified_author=0 OR m.author<>t.mailbox COLLATE NOCASE)
            \\)
            \\INSERT OR IGNORE INTO mail_notification_events(user_id,event_key,folder,author,own_id,parents_json,created_at)
            \\SELECT user_id,event_key,folder,author,own_id,parents_json,unixepoch() FROM n WHERE 1
            ++ notification_rule,
        );
        defer record.finalize();
        try record.bind(1, id);
        try record.bind(2, ordinal);
        try record.bind(3, file.notification_key);
        try record.bindOpt(4, own);
        try record.bind(5, parents);
        _ = try record.step();
    }

    /// One database claim per delivery across tabs, restarts and devices.
    /// Return only opaque notification IDs. Mail data stays in the mailbox.
    pub fn claimBrowserNotifications(self: *Database, a: std.mem.Allocator, username: []const u8) ![]i64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.execLocked("BEGIN IMMEDIATE");
        errdefer self.execLocked("ROLLBACK") catch {};
        const stmt = try self.prepareLocked(
            \\SELECT n.id, (NOT EXISTS(SELECT 1 FROM mail_attention m WHERE m.user_id=n.user_id
            \\     AND (m.kind='muted' OR (m.kind='snoozed' AND m.deadline>unixepoch()))
            \\     AND EXISTS(SELECT 1 FROM json_each(m.wire_ids) WHERE value=n.own_id OR value IN (SELECT value FROM json_each(n.parents_json))))
            ++ notification_rule ++
                \\)
                \\FROM mail_notification_events n
                \\JOIN users u ON u.id=n.user_id JOIN mail_notification_settings s ON s.user_id=n.user_id AND s.enabled=1
                \\WHERE u.username=?1 AND n.claimed_at IS NULL AND n.created_at>=unixepoch()-180
                \\ORDER BY n.id LIMIT 10
            ,
        );
        defer stmt.finalize();
        try stmt.bind(1, username);
        var ids: std.ArrayList(i64) = .empty;
        var last: ?i64 = null;
        while (try stmt.step()) {
            last = stmt.columnInt64(0);
            if (stmt.columnInt64(1) != 0) try ids.append(a, last.?);
        }
        // Retire muted or silenced arrivals alongside the advertised IDs, so
        // a later policy change cannot turn an older delivery into an alert.
        if (last) |id| {
            const claim = try self.prepareLocked("UPDATE mail_notification_events SET claimed_at=unixepoch() WHERE user_id=(SELECT id FROM users WHERE username=?1) AND claimed_at IS NULL AND id<=?2");
            defer claim.finalize();
            try claim.bind(1, username);
            try claim.bind(2, id);
            _ = try claim.step();
        }
        const result = try ids.toOwnedSlice(a);
        try self.execLocked("COMMIT");
        return result;
    }

    const attention_match = " AND (reference=?3 OR (?4 AND EXISTS(SELECT 1 FROM json_each(wire_ids) a JOIN json_each(?5) b USING(value)))";

    // Call with the mailbox lock so a reply and a user's update have a single
    // ordering shared with Maildir publication.
    pub fn changeAttention(self: *Database, user: []const u8, reference: []const u8, kind: AttentionKind, enabled: bool, deadline: i64, changed_ms: i64, keys: []const u8, waiting_id: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.execLocked("BEGIN IMMEDIATE");
        errdefer self.execLocked("ROLLBACK") catch {};
        if (enabled and kind == .reminders) {
            const earlier = try self.prepareLocked("SELECT 1 FROM mail_attention_replies WHERE user_id=(SELECT id FROM users WHERE username=?1) AND parent_id=?2");
            defer earlier.finalize();
            try earlier.bind(1, user);
            try earlier.bind(2, waiting_id);
            if (try earlier.step()) return error.AlreadyReplied;
        }
        const threads = kind != .saved and kind != .reminders;
        const combined: ?[]const u8 = if (enabled and threads) blk: {
            const s = try self.prepareLocked(
                \\SELECT json_group_array(value) FROM (
                \\  SELECT value FROM json_each(?5)
                \\  UNION ALL
                \\  SELECT DISTINCT j.value FROM mail_attention m, json_each(m.wire_ids) j
                \\  WHERE m.user_id=(SELECT id FROM users WHERE username=?1) AND m.kind=?2
                ++ attention_match ++
                    ") AND j.value NOT IN (SELECT value FROM json_each(?5)) LIMIT 192)",
            );
            defer s.finalize();
            try s.bind(1, user);
            try s.bind(2, @tagName(kind));
            try s.bind(3, reference);
            try s.bind(4, @as(u8, 1));
            try s.bind(5, keys);
            if (!try s.step()) return error.NotFound;
            break :blk try self.allocator.dupe(u8, s.columnText(0));
        } else null;
        defer if (combined) |value| self.allocator.free(value);
        const previous = try self.prepareLocked(
            "DELETE FROM mail_attention WHERE user_id=(SELECT id FROM users WHERE username=?1) AND kind=?2" ++ attention_match ++
                " OR (kind='reminders' AND waiting_id=?6 AND ?6<>''))",
        );
        defer previous.finalize();
        try previous.bind(1, user);
        try previous.bind(2, @tagName(kind));
        try previous.bind(3, reference);
        try previous.bind(4, @intFromBool(threads));
        try previous.bind(5, keys);
        try previous.bind(6, waiting_id);
        _ = try previous.step();
        if (enabled) {
            const insert = try self.prepareLocked(
                \\INSERT INTO mail_attention(user_id,reference,kind,deadline,changed_ms,wire_ids,waiting_id)
                \\SELECT id,?2,?3,?4,?5,?6,?7 FROM users WHERE username=?1
            );
            defer insert.finalize();
            try insert.bind(1, user);
            try insert.bind(2, reference);
            try insert.bind(3, @tagName(kind));
            try insert.bind(4, deadline);
            try insert.bind(5, changed_ms);
            try insert.bind(6, combined orelse keys);
            try insert.bind(7, waiting_id);
            _ = try insert.step();
        }
        try self.execLocked("COMMIT");
    }

    pub fn clearFollowUp(self: *Database, user: []const u8, reference: []const u8, keys: []const u8, before_ms: i64) !void {
        const stmt = try self.prepare(
            "DELETE FROM mail_attention WHERE user_id=(SELECT id FROM users WHERE username=?1) AND kind=?2 AND changed_ms<=?6" ++ attention_match ++ ")",
        );
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, @as([]const u8, "follow_up"));
        try stmt.bind(3, reference);
        try stmt.bind(4, @as(u8, 1));
        try stmt.bind(5, keys);
        try stmt.bind(6, before_ms);
        _ = try stmt.step();
    }

    fn attentionArrivalLocked(self: *Database, id: []const u8, ordinal: i64, attention: ?AttentionArrival) !bool {
        const arrival = attention orelse return false;
        const event = try self.prepareLocked(
            \\SELECT t.mailbox_id,m.accepted_ms,m.author<>t.mailbox COLLATE NOCASE
            \\FROM accepted_mail_targets t JOIN accepted_mail m ON m.id=t.delivery_id
            \\WHERE t.delivery_id=?1 AND t.ordinal=?2 AND t.mailbox_id<>0 AND t.folder IN ('new','Newsletters','Receipts')
        );
        defer event.finalize();
        try event.bind(1, id);
        try event.bind(2, ordinal);
        if (!try event.step()) return false;
        const user = event.columnInt64(0);
        const received = event.columnInt64(1);
        const has_parents = !std.mem.eql(u8, arrival.parents_json, "[]");
        if (has_parents and !arrival.automatic and event.columnInt64(2) != 0) {
            const reply = try self.prepareLocked(
                \\INSERT INTO mail_attention_replies(user_id,parent_id,last_ms) SELECT ?1,value,?2 FROM json_each(?3) WHERE 1
                \\ON CONFLICT(user_id,parent_id) DO UPDATE SET last_ms=MAX(last_ms,excluded.last_ms)
            );
            defer reply.finalize();
            try reply.bind(1, user);
            try reply.bind(2, received);
            try reply.bind(3, arrival.parents_json);
            _ = try reply.step();
            const wake = try self.prepareLocked(
                \\DELETE FROM mail_attention AS m WHERE m.user_id=?1 AND m.changed_ms<=?2 AND (
                \\ (m.kind='snoozed' AND EXISTS(SELECT 1 FROM json_each(m.wire_ids) a JOIN json_each(?3) b USING(value))) OR
                \\ (m.kind='reminders' AND m.waiting_id IN (SELECT value FROM json_each(?3))))
            );
            defer wake.finalize();
            try wake.bind(1, user);
            try wake.bind(2, received);
            try wake.bind(3, arrival.parents_json);
            _ = try wake.step();
        }
        if (has_parents) if (arrival.own) |own| {
            const learn = try self.prepareLocked(
                \\UPDATE mail_attention AS m SET wire_ids=json_insert(wire_ids,'$[#]',?3)
                \\WHERE m.user_id=?1 AND m.kind IN ('muted','snoozed','follow_up') AND json_array_length(wire_ids)<192
                \\  AND ?3 NOT IN (SELECT value FROM json_each(wire_ids))
                \\  AND EXISTS(SELECT 1 FROM json_each(m.wire_ids) a JOIN json_each(?2) b USING(value))
            );
            defer learn.finalize();
            try learn.bind(1, user);
            try learn.bind(2, arrival.parents_json);
            try learn.bind(3, own);
            _ = try learn.step();
        };
        const mute = try self.prepareLocked(
            \\SELECT 1 FROM mail_attention AS m WHERE m.user_id=?1
            \\AND (m.kind='muted' OR (m.kind='snoozed' AND m.deadline>unixepoch()))
            \\AND EXISTS(SELECT 1 FROM json_each(m.wire_ids) WHERE value=?3 OR value IN (SELECT value FROM json_each(?2))) LIMIT 1
        );
        defer mute.finalize();
        try mute.bind(1, user);
        try mute.bind(2, arrival.parents_json);
        try mute.bindOpt(3, arrival.own);
        return mute.step();
    }

    fn releaseForwardTargetsLocked(self: *Database, id: []const u8, ordinal: i64, filed: bool) !void {
        const outbound_target = try self.prepareLocked("SELECT 1 FROM accepted_mail_targets WHERE delivery_id=?1 AND forward_after=?2 AND outcome='queued' LIMIT 1");
        defer outbound_target.finalize();
        try outbound_target.bind(1, id);
        try outbound_target.bind(2, ordinal);
        if (try outbound_target.step()) {
            const filters = " WHERE status='awaiting_local' AND id IN (SELECT 'route-'||delivery_id||'-'||ordinal FROM accepted_mail_targets WHERE delivery_id=?1 AND forward_after=?2 AND outcome='queued')";
            const remote = try self.prepareLocked(if (filed) "UPDATE message_queue SET status='pending'" ++ filters else "DELETE FROM message_queue" ++ filters);
            defer remote.finalize();
            try remote.bind(1, id);
            try remote.bind(2, ordinal);
            _ = try remote.step();
        }
        const local = try self.prepareLocked(
            if (filed) "UPDATE accepted_mail_targets SET forward_after=NULL WHERE delivery_id=?1 AND forward_after=?2" else "UPDATE accepted_mail_targets SET outcome='forward_source_removed',queued_bytes=0,reply_mime=NULL WHERE delivery_id=?1 AND forward_after=?2 AND outcome IN ('pending','queued')",
        );
        defer local.finalize();
        try local.bind(1, id);
        try local.bind(2, ordinal);
        _ = try local.step();
    }

    fn compactDeliveryLocked(self: *Database, id: []const u8) !void {
        const stmt = try self.prepareLocked("UPDATE accepted_mail SET complete=1,mime=x'' WHERE id=?1 AND NOT EXISTS(SELECT 1 FROM accepted_mail_targets WHERE delivery_id=?1 AND outcome='pending')");
        defer stmt.finalize();
        try stmt.bind(1, id);
        _ = try stmt.step();
    }

    pub const PendingDelivery = struct {
        id: []const u8,
        ordinal: i64,
        mailbox: []const u8,
        folder: []const u8,
        mime: []const u8,
        accepted_ms: i64,
        mailbox_removed: bool,
        attempts: u8,
        review_copy: bool,
        track_placement: bool,
        calendar_author: []const u8,
        calendar_attendee: []const u8,
        team_reply_candidate: bool = false,
        team_sent_reply_candidate: bool = false,
    };

    pub fn pendingDelivery(self: *Database, a: std.mem.Allocator, id: ?[]const u8, now: i64) !?PendingDelivery {
        self.mutex.lock();
        defer self.mutex.unlock();
        const selection =
            \\SELECT m.id,t.ordinal,t.mailbox,t.folder,COALESCE(t.reply_mime,m.mime),m.accepted_ms,
            \\       t.mailbox_id<>0 AND NOT EXISTS (SELECT 1 FROM users WHERE id=t.mailbox_id AND username=t.mailbox),t.attempts,t.review_copy,
            \\       t.mailbox_id<>0 AND (t.folder IN ('new','Newsletters','Receipts') OR t.placement_reason IN ('junk_feedback','spam_filter'))
            \\          AND (m.verified_author=1 OR t.placement_reason<>'' OR t.reply_author IS NOT NULL),t.verified_forward,
            \\       IIF(t.is_primary=1 AND t.folder IN ('new','Newsletters','Receipts') AND m.verified_author=1
            \\           AND t.placement_reason NOT IN ('spam_filter','junk_feedback'),m.author,''),
            \\       COALESCE((SELECT email FROM users WHERE id=t.mailbox_id),''),
            \\       t.is_primary=1 AND m.verified_author=1 AND t.folder IN ('new','Newsletters','Receipts')
            \\          AND EXISTS(SELECT 1 FROM mail_team_thread_shares s JOIN mail_team_thread_follow f ON f.share_id=s.id
            \\                     WHERE s.owner_id=t.mailbox_id AND m.accepted_ms>f.since_ms),
            \\       t.folder='Sent' AND EXISTS(
            \\          SELECT 1 FROM mail_team_thread_submissions proof JOIN accepted_mail source ON source.id=proof.delivery_id
            \\          JOIN mail_team_thread_shares s ON s.owner_id=proof.owner_id
            \\          JOIN mail_team_thread_follow f ON f.share_id=s.id
            \\          JOIN mail_team_thread_follow_sent opted ON opted.share_id=f.share_id
            \\          WHERE proof.sent_id=m.id AND proof.owner_id=t.mailbox_id AND source.accepted_ms>f.since_ms)
            \\FROM accepted_mail_targets t JOIN accepted_mail m ON m.id=t.delivery_id
            \\WHERE t.outcome='pending' AND t.forward_after IS NULL AND t.retry_at<=?1
        ;
        const stmt = try self.prepareLocked(if (id != null)
            selection ++ " AND t.delivery_id=?2 ORDER BY t.ordinal LIMIT 1"
        else
            selection ++ " ORDER BY t.retry_at,t.delivery_id,t.ordinal LIMIT 1");
        defer stmt.finalize();
        try stmt.bind(1, now);
        if (id) |value| try stmt.bind(2, value);
        if (!try stmt.step()) return null;
        return .{
            .id = try a.dupe(u8, stmt.columnText(0)),
            .ordinal = stmt.columnInt64(1),
            .mailbox = try a.dupe(u8, stmt.columnText(2)),
            .folder = try a.dupe(u8, stmt.columnText(3)),
            .mime = if (stmt.columnInt64(10) != 0) try std.mem.concat(a, u8, &.{ forwarding_wire.loop_header, stmt.columnBlob(4) }) else try a.dupe(u8, stmt.columnBlob(4)),
            .accepted_ms = stmt.columnInt64(5),
            .mailbox_removed = stmt.columnInt64(6) != 0,
            .attempts = @intCast(stmt.columnInt64(7)),
            .review_copy = stmt.columnInt64(8) != 0,
            .track_placement = stmt.columnInt64(9) != 0,
            .calendar_author = try a.dupe(u8, stmt.columnText(11)),
            .calendar_attendee = try a.dupe(u8, stmt.columnText(12)),
            .team_reply_candidate = stmt.columnInt64(13) != 0,
            .team_sent_reply_candidate = stmt.columnInt64(14) != 0,
        };
    }

    pub fn delayDeliveryTarget(self: *Database, target: PendingDelivery, retry_at: i64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const stmt = try self.prepareLocked("UPDATE accepted_mail_targets SET retry_at=?3,attempts=MIN(attempts+1,8) WHERE delivery_id=?1 AND ordinal=?2 AND outcome='pending'");
        defer stmt.finalize();
        try stmt.bind(1, target.id);
        try stmt.bind(2, target.ordinal);
        try stmt.bind(3, retry_at);
        _ = try stmt.step();
    }

    pub fn sweepDeliveryJournal(self: *Database, before: i64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const webmail_enabled = blk: {
            const schema = try self.prepareLocked("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='webmail_records'");
            defer schema.finalize();
            break :blk try schema.step();
        };
        const prune = "DELETE FROM accepted_mail WHERE id IN (SELECT id FROM accepted_mail WHERE complete=1 AND accepted_at<?1";
        const stmt = try self.prepareLocked(if (webmail_enabled)
            \\WITH interrupted AS MATERIALIZED (
            \\ SELECT json_extract(payload,'$.dispatch.delivery_id') AS delivery,
            \\        json_extract(payload,'$.dispatch.sent_delivery_id') AS sent
            \\ FROM webmail_records WHERE kind='outbox' AND state IN ('sending','unknown')
            \\ AND json_extract(payload,'$.result') IS NULL
            \\), protected AS (
            \\ SELECT delivery AS id FROM interrupted WHERE delivery IS NOT NULL
            \\ UNION ALL SELECT sent FROM interrupted WHERE sent IS NOT NULL
            \\)
        ++ " " ++ prune ++ " AND id NOT IN (SELECT id FROM protected) LIMIT 500)"
        else
            prune ++ " LIMIT 500)");
        defer stmt.finalize();
        try stmt.bind(1, before);
        _ = try stmt.step();
        const copies = try self.prepareLocked(
            \\DELETE FROM mail_team_smtp_sent_copies WHERE rowid IN (
            \\    SELECT rowid FROM mail_team_smtp_sent_copies WHERE observed_at<?1 LIMIT 500)
        );
        defer copies.finalize();
        try copies.bind(1, before);
        _ = try copies.step();
        const ews = try self.prepareLocked(
            \\DELETE FROM mail_ews_draft_finalizations WHERE rowid IN (
            \\ SELECT c.rowid FROM mail_ews_draft_finalizations c WHERE c.retired_at<?1
            \\ OR (c.confirmed=0 AND c.submitted_at<?1 AND NOT EXISTS(
            \\     SELECT 1 FROM mailbox_message_refs r WHERE r.user_id=c.user_id AND r.reference=c.draft_reference))
            \\ LIMIT 500)
        );
        defer ews.finalize();
        try ews.bind(1, before);
        _ = try ews.step();
        const replies = try self.prepareLocked("DELETE FROM mail_attention_replies WHERE rowid IN (SELECT rowid FROM mail_attention_replies WHERE last_ms<?1 LIMIT 500)");
        defer replies.finalize();
        try replies.bind(1, (before - 90 * 86400) * 1000);
        _ = try replies.step();
        const notices = try self.prepareLocked("DELETE FROM mail_notification_events WHERE id IN (SELECT id FROM mail_notification_events WHERE created_at<?1 LIMIT 500)");
        defer notices.finalize();
        try notices.bind(1, before);
        _ = try notices.step();
        const replies_sent = try self.prepareLocked("DELETE FROM mailbox_vacation_sends WHERE rowid IN (SELECT rowid FROM mailbox_vacation_sends WHERE accepted_at<=?1 LIMIT 500)");
        defer replies_sent.finalize();
        try replies_sent.bind(1, before);
        _ = try replies_sent.step();
        const feedback = try self.prepareLocked(
            \\DELETE FROM mailbox_junk_feedback WHERE id IN (
            \\ SELECT f.id FROM mailbox_junk_feedback f WHERE f.created_at<?1
            \\ AND (f.author='' OR EXISTS(SELECT 1 FROM mailbox_junk_feedback newer
            \\      WHERE newer.user_id=f.user_id AND newer.author=f.author AND newer.author<>'' AND newer.id>f.id AND newer.created_at<?1))
            \\ AND (NOT EXISTS(SELECT 1 FROM mailbox_message_refs m WHERE m.user_id=f.user_id AND m.reference=f.reference)
            \\      OR EXISTS(SELECT 1 FROM mailbox_junk_feedback newer WHERE newer.user_id=f.user_id AND newer.reference=f.reference AND newer.id>f.id AND newer.created_at<?1))
            \\ LIMIT 500
            \\)
        );
        defer feedback.finalize();
        try feedback.bind(1, before);
        _ = try feedback.step();
    }

    pub const DeliveryEffect = struct {
        id: []const u8,
        ordinal: i64,
        recipient: []const u8,
        mailbox: []const u8,
        mailbox_removed: bool,
        filename: []const u8,
        folder: []const u8,
        size: usize,
        from: []const u8,
        remote_addr: []const u8,
        accepted_at: i64,
        index_pending: bool,
        notice_pending: bool,
    };

    pub fn nextDeliveryEffect(self: *Database, a: std.mem.Allocator) !?DeliveryEffect {
        self.mutex.lock();
        defer self.mutex.unlock();
        const stmt = try self.prepareLocked(
            \\SELECT e.delivery_id,e.ordinal,t.recipient,COALESCE(u.username,t.mailbox),t.mailbox_id<>0 AND u.id IS NULL,e.filename,e.size,
            \\       COALESCE(t.reply_from,m.envelope_from),m.remote_addr,m.accepted_at,e.indexed=0,e.notified=0,t.folder
            \\FROM accepted_mail_effects e JOIN accepted_mail_targets t USING(delivery_id,ordinal)
            \\JOIN accepted_mail m ON m.id=e.delivery_id LEFT JOIN users u ON u.id=t.mailbox_id
            \\WHERE e.indexed=0 OR e.notified=0 ORDER BY e.delivery_id,e.ordinal LIMIT 1
        );
        defer stmt.finalize();
        if (!try stmt.step()) return null;
        return .{
            .id = try a.dupe(u8, stmt.columnText(0)),
            .ordinal = stmt.columnInt64(1),
            .recipient = try a.dupe(u8, stmt.columnText(2)),
            .mailbox = try a.dupe(u8, stmt.columnText(3)),
            .mailbox_removed = stmt.columnInt64(4) != 0,
            .filename = try a.dupe(u8, stmt.columnText(5)),
            .size = @intCast(stmt.columnInt64(6)),
            .from = try a.dupe(u8, stmt.columnText(7)),
            .remote_addr = try a.dupe(u8, stmt.columnText(8)),
            .accepted_at = stmt.columnInt64(9),
            .index_pending = stmt.columnInt64(10) != 0,
            .notice_pending = stmt.columnInt64(11) != 0,
            .folder = try a.dupe(u8, stmt.columnText(12)),
        };
    }

    pub fn finishDeliveryEffect(self: *Database, effect: DeliveryEffect) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const stmt = try self.prepareLocked("UPDATE accepted_mail_effects SET indexed=1,notified=1 WHERE delivery_id=?1 AND ordinal=?2");
        defer stmt.finalize();
        try stmt.bind(1, effect.id);
        try stmt.bind(2, effect.ordinal);
        _ = try stmt.step();
    }

    pub fn retryAcceptedDeliveriesOnStartup(self: *Database, now: i64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const stmt = try self.prepareLocked("UPDATE accepted_mail_targets SET retry_at=?1 WHERE outcome='pending' AND retry_at>?1");
        defer stmt.finalize();
        try stmt.bind(1, now);
        _ = try stmt.step();
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

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const username_z = try self.allocator.dupeSentinel(u8, username, 0);
        defer self.allocator.free(username_z);
        const password_z = try self.allocator.dupeSentinel(u8, password_hash, 0);
        defer self.allocator.free(password_z);
        const email_z = try self.allocator.dupeSentinel(u8, email, 0);
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

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const username_z = try self.allocator.dupeSentinel(u8, username, 0);
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

    /// Resolve a bare mailbox local-part to a single full-address username.
    ///
    /// This supports clients configured before per-domain mailbox isolation,
    /// while refusing ambiguous aliases such as `info` when both
    /// `info@example.com` and `info@example.net` exist. Caller owns the result.
    pub fn uniqueUsernameForLocalPart(self: *Database, local_part: []const u8, allocator: std.mem.Allocator) !?[]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql =
            \\SELECT username
            \\FROM users
            \\WHERE instr(username, '@') > 1
            \\  AND substr(username, 1, instr(username, '@') - 1) = ?1
            \\LIMIT 2
        ;
        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        if (sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null) != sqlite.SQLITE_OK)
            return DatabaseError.PrepareFailed;
        defer _ = sqlite.sqlite3_finalize(stmt);

        try checkBind(sqlite3_bind_text_raw(stmt, 1, local_part.ptr, @intCast(local_part.len), SQLITE_TRANSIENT_PTR));

        if (sqlite.sqlite3_step(stmt) != sqlite.SQLITE_ROW) return null;
        const first_ptr = sqlite.sqlite3_column_text(stmt, 0) orelse return DatabaseError.ColumnFailed;
        const first_len = sqlite.sqlite3_column_bytes(stmt, 0);
        const first = try allocator.dupe(u8, first_ptr[0..@intCast(first_len)]);
        errdefer allocator.free(first);

        if (sqlite.sqlite3_step(stmt) == sqlite.SQLITE_ROW) {
            allocator.free(first);
            return null;
        }
        return first;
    }

    pub fn updateUserPassword(self: *Database, username: []const u8, new_password_hash: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql =
            \\UPDATE users
            \\SET password_hash = ?1, updated_at = ?2
            \\WHERE username = ?3
        ;

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const password_z = try self.allocator.dupeSentinel(u8, new_password_hash, 0);
        defer self.allocator.free(password_z);
        const username_z = try self.allocator.dupeSentinel(u8, username, 0);
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
        var tx = try self.beginTransaction(.write);
        defer tx.deinit();
        try team_store.beforeAccountDeletion(tx, username);

        try self.deleteUserSessionsLocked(username);
        try self.deleteUserResetTokensLocked(username);

        const sql = "DELETE FROM users WHERE username = ?1";

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const username_z = try self.allocator.dupeSentinel(u8, username, 0);
        defer self.allocator.free(username_z);

        try checkBind(sqlite.sqlite3_bind_text(stmt, 1, username_z.ptr, -1, null));

        rc = sqlite.sqlite3_step(stmt);
        if (rc != sqlite.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }
        try tx.commit();
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

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const session_z = try self.allocator.dupeSentinel(u8, session_id, 0);
        defer self.allocator.free(session_z);
        const username_z = try self.allocator.dupeSentinel(u8, username, 0);
        defer self.allocator.free(username_z);
        const email_z = try self.allocator.dupeSentinel(u8, email, 0);
        defer self.allocator.free(email_z);
        const csrf_z = try self.allocator.dupeSentinel(u8, csrf_secret, 0);
        defer self.allocator.free(csrf_z);
        const ip_z: ?[:0]u8 = if (ip_address) |v| try self.allocator.dupeSentinel(u8, v, 0) else null;
        defer if (ip_z) |v| self.allocator.free(v);
        const ua_z: ?[:0]u8 = if (user_agent) |v| try self.allocator.dupeSentinel(u8, v, 0) else null;
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

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const session_z = try self.allocator.dupeSentinel(u8, session_id, 0);
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

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const session_z = try self.allocator.dupeSentinel(u8, session_id, 0);
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

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const session_z = try self.allocator.dupeSentinel(u8, session_id, 0);
        defer self.allocator.free(session_z);

        try checkBind(sqlite.sqlite3_bind_text(stmt, 1, session_z.ptr, -1, null));

        rc = sqlite.sqlite3_step(stmt);
        if (rc != sqlite.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }
    }

    /// Prune all sessions whose expiry is at or before `now`.
    /// Revoke every browser session after a mailbox password change.
    pub fn deleteUserWebmailSessions(self: *Database, username: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.deleteUserSessionsLocked(username);
    }

    /// Void every password reset link for a mailbox. Called when its password
    /// or recovery address changes, so an older link cannot outlive either.
    pub fn deleteUserResetTokens(self: *Database, username: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.deleteUserResetTokensLocked(username);
    }

    fn deleteUserResetTokensLocked(self: *Database, username: []const u8) !void {
        var raw: ?*sqlite.sqlite3_stmt = null;
        if (sqlite.sqlite3_prepare_v2(self.db, "DELETE FROM mailbox_reset_tokens WHERE username = ?1", -1, &raw, null) != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
        const stmt = Statement{ .stmt = raw.?, .allocator = self.allocator };
        defer stmt.finalize();
        try stmt.bind(1, username);
        _ = try stmt.step();
    }

    fn deleteUserSessionsLocked(self: *Database, username: []const u8) !void {
        var raw: ?*sqlite.sqlite3_stmt = null;
        if (sqlite.sqlite3_prepare_v2(self.db, "DELETE FROM webmail_sessions WHERE username = ?1", -1, &raw, null) != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
        const stmt = Statement{ .stmt = raw.?, .allocator = self.allocator };
        defer stmt.finalize();
        try stmt.bind(1, username);
        _ = try stmt.step();
    }

    pub fn deleteExpiredWebmailSessions(self: *Database, now: i64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const sql = "DELETE FROM webmail_sessions WHERE expires_at <= ?1";

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
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

        if (!enabled) try self.deleteUserSessionsLocked(username);

        const sql =
            \\UPDATE users
            \\SET enabled = ?1, updated_at = ?2
            \\WHERE username = ?3
        ;

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const username_z = try self.allocator.dupeSentinel(u8, username, 0);
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

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        var users: std.ArrayList(User) = .empty;
        errdefer {
            for (users.items) |*user| {
                user.deinit(self.allocator);
            }
            users.deinit(self.allocator);
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

            try users.append(self.allocator, User{
                .id = id,
                .username = try self.allocator.dupe(u8, std.mem.span(username_ptr)),
                .password_hash = try self.allocator.dupe(u8, std.mem.span(password_ptr)),
                .email = try self.allocator.dupe(u8, std.mem.span(email_ptr)),
                .enabled = enabled,
                .created_at = created_at,
                .updated_at = updated_at,
            });
        }

        return users.toOwnedSlice(self.allocator);
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

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const email_z = try self.allocator.dupeSentinel(u8, new_email, 0);
        defer self.allocator.free(email_z);
        const username_z = try self.allocator.dupeSentinel(u8, username, 0);
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

        try self.exec(sql);
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

        const stmt = try self.prepareLocked(
            \\INSERT INTO audit_log (timestamp, action, actor, target, target_type, ip_address, details, severity)
            \\VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        );
        defer stmt.finalize();
        try stmt.bind(1, timestamp);
        try stmt.bind(2, action);
        try stmt.bind(3, actor);
        try stmt.bindOpt(4, target);
        try stmt.bindOpt(5, target_type);
        try stmt.bindOpt(6, ip_address);
        try stmt.bindOpt(7, details);
        try stmt.bind(8, severity);
        _ = try stmt.step();

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

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
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

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
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

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
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

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
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

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const username_z = try self.allocator.dupeSentinel(u8, username, 0);
        defer self.allocator.free(username_z);
        try checkBind(sqlite.sqlite3_bind_text(stmt, 1, username_z.ptr, -1, null));

        const hash_z = try self.allocator.dupeSentinel(u8, token_hash, 0);
        defer self.allocator.free(hash_z);
        try checkBind(sqlite.sqlite3_bind_text(stmt, 2, hash_z.ptr, -1, null));

        try checkBind(sqlite.sqlite3_bind_int64(stmt, 3, created_at));
        try checkBind(sqlite.sqlite3_bind_int64(stmt, 4, expires_at));

        if (ip_address) |ip| {
            const ip_z = try self.allocator.dupeSentinel(u8, ip, 0);
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

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const hash_z = try self.allocator.dupeSentinel(u8, token_hash, 0);
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

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        try checkBind(sqlite.sqlite3_bind_int64(stmt, 1, now));

        const hash_z = try self.allocator.dupeSentinel(u8, token_hash, 0);
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

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const username_z = try self.allocator.dupeSentinel(u8, username, 0);
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

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
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

        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
        defer self.allocator.free(sql_z);

        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        const username_z = try self.allocator.dupeSentinel(u8, username, 0);
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

        const sql_z = try self.allocator.dupeSentinel(u8, sql_text, 0);
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
        // Older webmail tables reference username without ON UPDATE CASCADE.
        // Rewrite both sides inside one transaction and validate at commit.
        try self.execLocked("PRAGMA defer_foreign_keys=ON");

        // `substr(x, 1, length(x) - <old_len>) || <suffix>` rebuilds the address
        // from its local part, so a local part containing '@' survives intact.
        const statements = [_][:0]const u8{
            "UPDATE users SET username = substr(username, 1, length(username) - ?3) || ?2, updated_at = strftime('%s','now') WHERE username LIKE ?1 ESCAPE '\\'",
            "UPDATE users SET email = substr(email, 1, length(email) - ?3) || ?2 WHERE email LIKE ?1 ESCAPE '\\'",
            "UPDATE imap_mailboxes SET username = substr(username, 1, length(username) - ?3) || ?2 WHERE username LIKE ?1 ESCAPE '\\'",
            "UPDATE imap_uids SET username = substr(username, 1, length(username) - ?3) || ?2 WHERE username LIKE ?1 ESCAPE '\\'",
            "UPDATE provisioned_mailboxes SET mailbox = substr(mailbox, 1, length(mailbox) - ?3) || ?2 WHERE mailbox LIKE ?1 ESCAPE '\\'",
            "UPDATE provisioning_operations SET mailbox = substr(mailbox, 1, length(mailbox) - ?3) || ?2 WHERE mailbox LIKE ?1 ESCAPE '\\'",
            "UPDATE accepted_mail_targets SET mailbox = substr(mailbox, 1, length(mailbox) - ?3) || ?2 WHERE outcome = 'pending' AND mailbox LIKE ?1 ESCAPE '\\'",
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

        for ([_][]const u8{ "webmail_records", "webmail_uploads" }) |table| {
            if (!try self.schemaHasTableLocked(table)) continue;
            const sql = try std.fmt.allocPrint(self.allocator, "UPDATE {s} SET username=substr(username,1,length(username)-?3)||?2 WHERE username LIKE ?1 ESCAPE '\\'", .{table});
            defer self.allocator.free(sql);
            const update = try self.prepareLocked(sql);
            defer update.finalize();
            try update.bind(1, pattern);
            try update.bind(2, suffix);
            try update.bind(3, old_len);
            _ = try update.step();
        }

        // Sessions and reset links carry the old address, so they are voided
        // rather than rewritten. Both are cheap to obtain again.
        for ([_][:0]const u8{
            "DELETE FROM webmail_sessions WHERE username LIKE ?1 ESCAPE '\\'",
            "DELETE FROM mailbox_reset_tokens WHERE username LIKE ?1 ESCAPE '\\'",
        }) |sql| {
            var stmt: ?*sqlite.sqlite3_stmt = null;
            if (sqlite.sqlite3_prepare_v2(self.db, sql.ptr, -1, &stmt, null) != sqlite.SQLITE_OK)
                return DatabaseError.PrepareFailed;
            defer _ = sqlite.sqlite3_finalize(stmt);
            try checkBind(sqlite3_bind_text_raw(stmt, 1, pattern.ptr, @intCast(pattern.len), SQLITE_TRANSIENT_PTR));
            if (sqlite.sqlite3_step(stmt) != sqlite.SQLITE_DONE) return DatabaseError.StepFailed;
        }
        if (try self.schemaHasTableLocked("password_reset_tokens")) {
            const delete = try self.prepareLocked("DELETE FROM password_reset_tokens WHERE username LIKE ?1 ESCAPE '\\'");
            defer delete.finalize();
            try delete.bind(1, pattern);
            _ = try delete.step();
        }

        try self.execLocked("COMMIT");
        return moved;
    }

    fn schemaHasTableLocked(self: *Database, name: []const u8) !bool {
        const statement = try self.prepareLocked("SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1");
        defer statement.finalize();
        try statement.bind(1, name);
        return statement.step();
    }

    // ── IMAP UID persistence ──────────────────────────────────────────

    /// Get or create a mailbox record, returning (uidvalidity, uidnext).
    pub fn getOrCreateMailbox(self: *Database, username: []const u8, mailbox: []const u8) !struct { uidvalidity: i64, uidnext: i64 } {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Try to read existing
        {
            const sql = "SELECT uidvalidity, uidnext FROM imap_mailboxes WHERE username = ?1 AND mailbox = ?2";
            const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
            defer self.allocator.free(sql_z);
            var stmt: ?*sqlite.sqlite3_stmt = null;
            var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
            if (rc != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
            defer _ = sqlite.sqlite3_finalize(stmt);

            const u_z = try self.allocator.dupeSentinel(u8, username, 0);
            defer self.allocator.free(u_z);
            const m_z = try self.allocator.dupeSentinel(u8, mailbox, 0);
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
            const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
            defer self.allocator.free(sql_z);
            var stmt: ?*sqlite.sqlite3_stmt = null;
            var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
            if (rc != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
            defer _ = sqlite.sqlite3_finalize(stmt);

            const u_z = try self.allocator.dupeSentinel(u8, username, 0);
            defer self.allocator.free(u_z);
            const m_z = try self.allocator.dupeSentinel(u8, mailbox, 0);
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
        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
        defer self.allocator.free(sql_z);
        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
        defer _ = sqlite.sqlite3_finalize(stmt);

        const u_z = try self.allocator.dupeSentinel(u8, username, 0);
        defer self.allocator.free(u_z);
        const m_z = try self.allocator.dupeSentinel(u8, mailbox, 0);
        defer self.allocator.free(m_z);
        const f_z = try self.allocator.dupeSentinel(u8, base, 0);
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

    /// Resolve a client-visible UID within one account and mailbox.
    pub fn getFilenameForUid(self: *Database, allocator: std.mem.Allocator, user: []const u8, mailbox: []const u8, uid: i64) !?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const stmt = try self.prepareLocked(
            "SELECT filename FROM imap_uids WHERE username = ? AND mailbox = ? AND uid = ?",
        );
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, mailbox);
        try stmt.bind(3, uid);
        if (!try stmt.step()) return null;
        return try allocator.dupe(u8, stmt.columnText(0));
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

    /// A move into a mailbox is a new arrival even if this physical filename
    /// was there earlier. Never resurrect its historical UID after EXPUNGE.
    pub fn assignFreshUid(self: *Database, username: []const u8, mailbox: []const u8, filename: []const u8) !i64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.execLocked("BEGIN IMMEDIATE");
        errdefer self.execLocked("ROLLBACK") catch {};
        const sql: [:0]const u8 = "DELETE FROM imap_uids WHERE username = ?1 AND mailbox = ?2 AND filename = ?3";
        var stmt: ?*sqlite.sqlite3_stmt = null;
        if (sqlite.sqlite3_prepare_v2(self.db, sql.ptr, -1, &stmt, null) != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
        defer _ = sqlite.sqlite3_finalize(stmt);
        const user_z = try self.allocator.dupeSentinel(u8, username, 0);
        defer self.allocator.free(user_z);
        const mailbox_z = try self.allocator.dupeSentinel(u8, mailbox, 0);
        defer self.allocator.free(mailbox_z);
        const name_z = try self.allocator.dupeSentinel(u8, maildirBaseName(filename), 0);
        defer self.allocator.free(name_z);
        try checkBind(sqlite.sqlite3_bind_text(stmt, 1, user_z.ptr, -1, null));
        try checkBind(sqlite.sqlite3_bind_text(stmt, 2, mailbox_z.ptr, -1, null));
        try checkBind(sqlite.sqlite3_bind_text(stmt, 3, name_z.ptr, -1, null));
        if (sqlite.sqlite3_step(stmt) != sqlite.SQLITE_DONE) return DatabaseError.StepFailed;
        const uid = try self.assignUidInTxn(username, mailbox, filename);
        try self.execLocked("COMMIT");
        return uid;
    }

    /// Retire an unpublished destination UID without reusing its number.
    pub fn discardMoveUid(self: *Database, username: []const u8, mailbox: []const u8, uid: i64) !void {
        const stmt = try self.prepare("DELETE FROM imap_uids WHERE username=?1 AND mailbox=?2 AND uid=?3");
        defer stmt.finalize();
        try stmt.bind(1, username);
        try stmt.bind(2, mailbox);
        try stmt.bind(3, uid);
        _ = try stmt.step();
    }

    fn assignUidInTxn(self: *Database, username: []const u8, mailbox: []const u8, filename: []const u8) !i64 {
        // Key on the flag-suffix-stripped base name (see maildirBaseName).
        const base = maildirBaseName(filename);

        // UID allocation owns its parent invariant. Callers must not be able to
        // mint UID 1 repeatedly merely because a folder has not been selected
        // over IMAP yet. Existing mappings also bound UIDNEXT from below.
        {
            const sql: [:0]const u8 =
                \\INSERT INTO imap_mailboxes(username,mailbox,uidvalidity,uidnext)
                \\VALUES(?1,?2,?3,(SELECT COALESCE(MAX(uid),0)+1 FROM imap_uids WHERE username=?1 AND mailbox=?2))
                \\ON CONFLICT(username,mailbox) DO UPDATE SET uidnext=MAX(imap_mailboxes.uidnext,excluded.uidnext)
            ;
            var raw: ?*sqlite.sqlite3_stmt = null;
            if (sqlite.sqlite3_prepare_v2(self.db, sql.ptr, -1, &raw, null) != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
            const statement = Statement{ .stmt = raw.?, .allocator = self.allocator };
            defer statement.finalize();
            try statement.bind(1, username);
            try statement.bind(2, mailbox);
            try statement.bind(3, time_compat.timestamp());
            _ = try statement.step();
        }

        // Get current uidnext
        var uidnext: i64 = 1;
        {
            const sql = "SELECT uidnext FROM imap_mailboxes WHERE username = ?1 AND mailbox = ?2";
            const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
            defer self.allocator.free(sql_z);
            var stmt: ?*sqlite.sqlite3_stmt = null;
            var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
            if (rc != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
            defer _ = sqlite.sqlite3_finalize(stmt);

            const u_z = try self.allocator.dupeSentinel(u8, username, 0);
            defer self.allocator.free(u_z);
            const m_z = try self.allocator.dupeSentinel(u8, mailbox, 0);
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
            const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
            defer self.allocator.free(sql_z);
            var stmt: ?*sqlite.sqlite3_stmt = null;
            var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
            if (rc != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
            defer _ = sqlite.sqlite3_finalize(stmt);

            const u_z = try self.allocator.dupeSentinel(u8, username, 0);
            defer self.allocator.free(u_z);
            const m_z = try self.allocator.dupeSentinel(u8, mailbox, 0);
            defer self.allocator.free(m_z);
            const f_z = try self.allocator.dupeSentinel(u8, base, 0);
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
                const get_z = try self.allocator.dupeSentinel(u8, get_sql, 0);
                defer self.allocator.free(get_z);
                var get_stmt: ?*sqlite.sqlite3_stmt = null;
                const get_rc = sqlite.sqlite3_prepare_v2(self.db, get_z.ptr, -1, &get_stmt, null);
                if (get_rc != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
                defer _ = sqlite.sqlite3_finalize(get_stmt);

                const u2_z = try self.allocator.dupeSentinel(u8, username, 0);
                defer self.allocator.free(u2_z);
                const m2_z = try self.allocator.dupeSentinel(u8, mailbox, 0);
                defer self.allocator.free(m2_z);
                const f2_z = try self.allocator.dupeSentinel(u8, base, 0);
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
            const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
            defer self.allocator.free(sql_z);
            var stmt: ?*sqlite.sqlite3_stmt = null;
            var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
            if (rc != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
            defer _ = sqlite.sqlite3_finalize(stmt);

            const u_z = try self.allocator.dupeSentinel(u8, username, 0);
            defer self.allocator.free(u_z);
            const m_z = try self.allocator.dupeSentinel(u8, mailbox, 0);
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
        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
        defer self.allocator.free(sql_z);
        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
        defer _ = sqlite.sqlite3_finalize(stmt);

        const u_z = try self.allocator.dupeSentinel(u8, username, 0);
        defer self.allocator.free(u_z);
        const m_z = try self.allocator.dupeSentinel(u8, mailbox, 0);
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
        const sql_z = try self.allocator.dupeSentinel(u8, sql, 0);
        defer self.allocator.free(sql_z);
        var stmt: ?*sqlite.sqlite3_stmt = null;
        var rc = sqlite.sqlite3_prepare_v2(self.db, sql_z.ptr, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) return DatabaseError.PrepareFailed;
        defer _ = sqlite.sqlite3_finalize(stmt);

        const u_z = try self.allocator.dupeSentinel(u8, username, 0);
        defer self.allocator.free(u_z);
        const m_z = try self.allocator.dupeSentinel(u8, mailbox, 0);
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

test "hosted sending allowance rolls over at midnight UTC and survives provisioning revisions" {
    const t = std.testing;
    var db = try Database.init(t.allocator, ":memory:");
    defer db.deinit();

    var change: Database.ProvisioningChange = .{
        .mailbox = "limit@example.test",
        .actor = "signup-owned-limit",
        .operation_id = "signup-daily-limit",
        .revision = 1,
        .quota_bytes = 1024,
        .send_recipients_per_day = 2,
        .enabled = true,
        .initial_password_hash = "test-only-hash",
        .initial_recovery = "limit@recovery.test",
    };
    _ = try db.applyProvisioning(change);
    change.send_recipients_per_day = 3;
    try t.expectError(error.OperationConflict, db.applyProvisioning(change));
    try t.expectError(error.HostedSendingLimit, db.chargeHostedSend(change.mailbox, 3, 86399));
    try db.chargeHostedSend(change.mailbox, 2, 86399);
    try t.expectError(error.HostedSendingLimit, db.chargeHostedSend(change.mailbox, 1, 86399));

    change.revision = 2;
    change.operation_id = "signup-raised-limit";
    _ = try db.applyProvisioning(change);
    try db.chargeHostedSend(change.mailbox, 1, 86399);
    try t.expectError(error.HostedSendingLimit, db.chargeHostedSend(change.mailbox, 1, 86399));
    try db.chargeHostedSend(change.mailbox, 3, 86400);
    try t.expectError(error.HostedSendingLimit, db.chargeHostedSend(change.mailbox, 1, 86400));
    try t.expectError(error.HostedSendingLimit, db.chargeHostedSend(change.mailbox, 1, 86399));
}

test "provisioning owns the account, replays the latest operation, and rejects stale work" {
    var db = try Database.init(std.testing.allocator, ":memory:");
    defer db.deinit();

    const initial: Database.ProvisioningChange = .{
        .mailbox = "owner@example.test",
        .actor = "signup-owner-00001",
        .operation_id = "signup-create-0001",
        .revision = 1,
        .quota_bytes = 1024,
        .enabled = true,
        .initial_password_hash = "test-only-hash",
        .initial_recovery = "owner@recovery.test",
    };
    const created = try db.applyProvisioning(initial);
    try std.testing.expectEqual(@as(i64, 1), created.revision);
    const replay = try db.applyProvisioning(initial);
    try std.testing.expectEqualDeep(created, replay);
    var mismatch = initial;
    mismatch.quota_bytes = 2048;
    try std.testing.expectError(error.OperationConflict, db.applyProvisioning(mismatch));
    mismatch = initial;
    mismatch.actor = "signup-other-00002";
    try std.testing.expectError(error.MailboxUnavailable, db.applyProvisioning(mismatch));
    var other_address = initial;
    other_address.mailbox = "second@example.test";
    other_address.operation_id = "signup-second-0002";
    try std.testing.expectError(error.MailboxUnavailable, db.applyProvisioning(other_address));

    var suspension: Database.ProvisioningChange = .{
        .mailbox = initial.mailbox,
        .actor = initial.actor,
        .operation_id = "signup-disable-003",
        .revision = 2,
        .quota_bytes = 3072,
        .enabled = false,
    };
    try std.testing.expect(!(try db.applyProvisioning(suspension)).enabled);
    try std.testing.expectEqual(@as(i64, 3072), (try db.provisioningState(initial.mailbox, initial.actor)).quota_bytes);
    try std.testing.expectError(error.StaleRevision, db.applyProvisioning(initial));
    suspension.revision = 3;
    suspension.operation_id = initial.operation_id;
    try std.testing.expectError(error.OperationConflict, db.applyProvisioning(suspension));
    try std.testing.expectError(error.MailboxNotFound, db.provisioningState(initial.mailbox, "signup-unrelated"));

    _ = try db.createUser("operator@example.test", "unused", "operator@example.test");
    var operator = initial;
    operator.mailbox = "operator@example.test";
    operator.actor = "another-signup-owner";
    operator.operation_id = "another-signup-op";
    try std.testing.expectError(error.MailboxUnavailable, db.applyProvisioning(operator));
}
