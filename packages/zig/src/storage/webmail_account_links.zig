//! A verified secondary mailbox attached to one browser session.
const std = @import("std");
const database = @import("database.zig");

pub const max_links = 4;
pub const schema =
    \\CREATE TABLE IF NOT EXISTS webmail_account_links (
    \\ id TEXT PRIMARY KEY,
    \\ owner_session TEXT NOT NULL REFERENCES webmail_sessions(session_id) ON DELETE CASCADE,
    \\ source_session TEXT NOT NULL UNIQUE REFERENCES webmail_sessions(session_id) ON DELETE CASCADE,
    \\ source_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    \\ UNIQUE(owner_session, source_user_id)
    \\);
    \\CREATE TRIGGER IF NOT EXISTS webmail_account_link_cleanup AFTER DELETE ON webmail_account_links
    \\BEGIN
    \\ DELETE FROM webmail_sessions WHERE session_id=OLD.source_session;
    \\END;
;

pub const Account = struct {
    id: []const u8,
    username: []const u8,
    address: []const u8,
};
pub const Source = struct {
    account: Account,
    private_session: []const u8,
};

const available =
    \\SELECT l.id,u.username,u.email,l.source_session
    \\FROM webmail_account_links l
    \\JOIN webmail_sessions root ON root.session_id=l.owner_session
    \\JOIN users owner ON owner.username=root.username AND owner.enabled=1
    \\JOIN webmail_sessions source ON source.session_id=l.source_session
    \\JOIN users u ON u.id=l.source_user_id AND u.username=source.username AND u.enabled=1
    \\WHERE root.expires_at>?1 AND source.expires_at>?1
;

fn readAccount(a: std.mem.Allocator, stmt: database.Statement) !Account {
    return .{
        .id = try a.dupe(u8, stmt.columnText(0)),
        .username = try a.dupe(u8, stmt.columnText(1)),
        .address = try a.dupe(u8, stmt.columnText(2)),
    };
}

pub fn list(a: std.mem.Allocator, db: *database.Database, owner: []const u8, now: i64) ![]Account {
    const stmt = try db.prepare(available ++ " AND l.owner_session=?2 ORDER BY u.username");
    defer stmt.finalize();
    try stmt.bind(1, now);
    try stmt.bind(2, owner);
    var accounts: std.ArrayList(Account) = .empty;
    while (try stmt.step()) try accounts.append(a, try readAccount(a, stmt));
    return accounts.toOwnedSlice(a);
}

pub fn resolve(a: std.mem.Allocator, db: *database.Database, owner: []const u8, id: []const u8, now: i64) !Source {
    const stmt = try db.prepare(available ++ " AND l.owner_session=?2 AND l.id=?3");
    defer stmt.finalize();
    try stmt.bind(1, now);
    try stmt.bind(2, owner);
    try stmt.bind(3, id);
    if (!try stmt.step()) return error.LinkedAccountUnavailable;
    return .{ .account = try readAccount(a, stmt), .private_session = try a.dupe(u8, stmt.columnText(3)) };
}

pub fn requireSource(tx: database.Database.Transaction, id: []const u8, user: []const u8, now: i64) !void {
    const stmt = try tx.prepare(available ++ " AND l.id=?2 AND u.username=?3");
    defer stmt.finalize();
    try stmt.bind(1, now);
    try stmt.bind(2, id);
    try stmt.bind(3, user);
    if (!try stmt.step()) return error.LinkedAccountUnavailable;
}

pub fn create(db: *database.Database, owner: []const u8, source: []const u8, id: []const u8, now: i64) !void {
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    {
        const clean = try tx.prepare(
            \\DELETE FROM webmail_account_links
            \\WHERE owner_session=?1 AND NOT EXISTS(
            \\ SELECT 1 FROM webmail_sessions source JOIN users u ON u.username=source.username AND u.enabled=1
            \\ WHERE source.session_id=source_session AND source.expires_at>?2)
        );
        defer clean.finalize();
        try clean.bind(1, owner);
        try clean.bind(2, now);
        _ = try clean.step();
    }
    {
        const existing = try tx.prepare(
            \\SELECT count(*),COALESCE(max(source_session IN (
            \\ SELECT same.session_id FROM webmail_sessions same
            \\ WHERE same.username=(SELECT username FROM webmail_sessions WHERE session_id=?2))),0)
            \\FROM webmail_account_links WHERE owner_session=?1
        );
        defer existing.finalize();
        try existing.bind(1, owner);
        try existing.bind(2, source);
        if (!try existing.step()) unreachable;
        if (existing.columnInt64(1) != 0) return error.AccountAlreadyLinked;
        if (existing.columnInt64(0) >= max_links) return error.LinkedAccountLimit;
    }
    {
        const add = try tx.prepare(
            \\INSERT INTO webmail_account_links(id,owner_session,source_session,source_user_id)
            \\SELECT ?3,root.session_id,source.session_id,u.id
            \\FROM webmail_sessions root,webmail_sessions source
            \\JOIN users u ON u.username=source.username AND u.enabled=1
            \\WHERE root.session_id=?1 AND source.session_id=?2 AND root.username<>source.username
            \\AND root.expires_at>?4 AND source.expires_at>?4 RETURNING id
        );
        defer add.finalize();
        try add.bind(1, owner);
        try add.bind(2, source);
        try add.bind(3, id);
        try add.bind(4, now);
        if (!try add.step()) return error.LinkedAccountUnavailable;
        _ = try add.step();
    }
    try tx.commit();
}

pub fn remove(db: *database.Database, owner: []const u8, id: []const u8) !void {
    const stmt = try db.prepare("DELETE FROM webmail_account_links WHERE owner_session=?1 AND id=?2 RETURNING id");
    defer stmt.finalize();
    try stmt.bind(1, owner);
    try stmt.bind(2, id);
    if (!try stmt.step()) return error.LinkedAccountUnavailable;
    _ = try stmt.step();
}
