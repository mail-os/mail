const std = @import("std");
const database = @import("database.zig");
const io = @import("../core/io_compat.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;
const encoder = std.base64.url_safe_no_pad.Encoder;

pub const Scope = enum { mail, dav, exchange };
pub const prefix = "mailapp_";
const random_bytes = 24;
const secret_len = prefix.len + encoder.calcSize(random_bytes);
pub const max_credentials = 16;

pub const schema =
    \\CREATE TABLE IF NOT EXISTS mail_client_passwords (
    \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    \\    digest BLOB NOT NULL UNIQUE,
    \\    label TEXT NOT NULL,
    \\    scope TEXT NOT NULL CHECK(scope IN ('mail', 'dav', 'exchange')),
    \\    created_at INTEGER NOT NULL
    \\);
    \\CREATE INDEX IF NOT EXISTS mail_client_passwords_user ON mail_client_passwords(user_id);
    \\CREATE TRIGGER IF NOT EXISTS invalidate_client_passwords_on_account_change
    \\AFTER UPDATE OF username, password_hash, enabled ON users
    \\WHEN OLD.username IS NOT NEW.username OR OLD.password_hash IS NOT NEW.password_hash OR OLD.enabled IS NOT NEW.enabled
    \\BEGIN
    \\    DELETE FROM mail_client_passwords WHERE user_id = OLD.id;
    \\END;
;

pub const Entry = struct { id: i64, label: []const u8, scope: Scope, created_at: i64 };
pub const Created = struct { entry: Entry, password: [secret_len]u8 };

pub fn list(db: *database.Database, a: std.mem.Allocator, username: []const u8) ![]const Entry {
    var tx = try db.beginTransaction(.read);
    defer tx.deinit();
    const rows = try tx.prepare(
        \\SELECT p.id, p.label, p.scope, p.created_at FROM mail_client_passwords p
        \\JOIN users u ON u.id = p.user_id WHERE u.username = ?1 ORDER BY p.id DESC
    );
    defer rows.finalize();
    try rows.bind(1, username);
    var entries: std.ArrayList(Entry) = .empty;
    while (try rows.step()) {
        try entries.append(a, .{
            .id = rows.columnInt64(0),
            .label = try a.dupe(u8, rows.columnText(1)),
            .scope = std.meta.stringToEnum(Scope, rows.columnText(2)) orelse return error.InvalidCredentialScope,
            .created_at = rows.columnInt64(3),
        });
    }
    return try entries.toOwnedSlice(a);
}

pub fn create(db: *database.Database, username: []const u8, session: []const u8, password_hash: []const u8, raw_label: []const u8, scope: Scope, now: i64) !Created {
    const label = std.mem.trim(u8, raw_label, " ");
    if (label.len == 0 or label.len > 80 or !std.unicode.utf8ValidateSlice(label)) return error.InvalidCredentialLabel;
    for (label) |byte| if (byte < 32 or byte == 127) return error.InvalidCredentialLabel;

    var raw: [random_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &raw);
    io.randomBytes(&raw);
    var password: [secret_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &password);
    @memcpy(password[0..prefix.len], prefix);
    _ = encoder.encode(password[prefix.len..], &raw);
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&password, &digest, .{});

    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const id = blk: {
        const insert = try tx.prepare(
            \\INSERT INTO mail_client_passwords(user_id, digest, label, scope, created_at)
            \\SELECT u.id, ?1, ?2, ?3, ?4 FROM users u
            \\JOIN webmail_sessions s ON s.username = u.username AND s.session_id = ?5
            \\LEFT JOIN provisioned_mailboxes m ON m.user_id = u.id AND m.mailbox = u.username
            \\WHERE u.username = ?6 AND u.enabled = 1 AND u.password_hash = ?7 AND s.expires_at > ?4
            \\ AND (m.service_until IS NULL OR m.service_until > ?4)
            \\ AND (SELECT COUNT(*) FROM mail_client_passwords WHERE user_id = u.id) < ?8
            \\RETURNING id
        );
        defer insert.finalize();
        try insert.bindBlob(1, &digest);
        try insert.bind(2, label);
        try insert.bind(3, @tagName(scope));
        try insert.bind(4, now);
        try insert.bind(5, session);
        try insert.bind(6, username);
        try insert.bind(7, password_hash);
        try insert.bind(8, @as(i64, max_credentials));
        if (!try insert.step()) return error.CredentialUnavailable;
        break :blk insert.columnInt64(0);
    };
    try audit(tx, username, "client_password.created", id, @tagName(scope));
    try tx.commit();
    return .{ .entry = .{ .id = id, .label = label, .scope = scope, .created_at = now }, .password = password };
}

pub fn revoke(db: *database.Database, username: []const u8, id: i64) !bool {
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    {
        const remove = try tx.prepare(
            \\DELETE FROM mail_client_passwords
            \\WHERE id = ?1 AND user_id = (SELECT id FROM users WHERE username = ?2)
            \\RETURNING id
        );
        defer remove.finalize();
        try remove.bind(1, id);
        try remove.bind(2, username);
        if (!try remove.step()) return false;
    }
    try audit(tx, username, "client_password.revoked", id, null);
    try tx.commit();
    return true;
}

fn audit(tx: database.Database.Transaction, username: []const u8, action: []const u8, id: i64, scope: ?[]const u8) !void {
    const stmt = try tx.prepare(
        \\INSERT INTO audit_log(timestamp, action, actor, target, target_type, details, severity)
        \\VALUES(unixepoch(), ?1, ?2, CAST(?3 AS TEXT), 'client_password', json_object('scope', ?4), 'info')
    );
    defer stmt.finalize();
    try stmt.bind(1, action);
    try stmt.bind(2, username);
    try stmt.bind(3, id);
    try stmt.bindOpt(4, scope);
    _ = try stmt.step();
}

pub fn authenticate(db: *database.Database, username: []const u8, password: []const u8, scope: Scope) !?i64 {
    if (password.len != secret_len or !std.mem.startsWith(u8, password, prefix)) return null;
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(password, &digest, .{});
    var tx = try db.beginTransaction(.read);
    defer tx.deinit();
    const key = try tx.prepare(
        \\SELECT p.id FROM mail_client_passwords p
        \\JOIN users u ON u.id = p.user_id
        \\LEFT JOIN provisioned_mailboxes m ON m.user_id = u.id AND m.mailbox = u.username
        \\WHERE p.digest = ?1 AND p.scope = ?2 AND u.username = ?3 AND u.enabled = 1
        \\ AND (m.read_until IS NULL OR m.read_until > unixepoch())
    );
    defer key.finalize();
    try key.bindBlob(1, &digest);
    try key.bind(2, @tagName(scope));
    try key.bind(3, username);
    return if (try key.step()) key.columnInt64(0) else null;
}

pub fn active(db: *database.Database, id: i64) !bool {
    var tx = try db.beginTransaction(.read);
    defer tx.deinit();
    const check = try tx.prepare(
        \\SELECT 1 FROM mail_client_passwords p
        \\JOIN users u ON u.id = p.user_id AND u.enabled = 1
        \\LEFT JOIN provisioned_mailboxes m ON m.user_id = u.id AND m.mailbox = u.username
        \\WHERE p.id = ?1 AND (m.read_until IS NULL OR m.read_until > unixepoch())
    );
    defer check.finalize();
    try check.bind(1, id);
    return check.step();
}
