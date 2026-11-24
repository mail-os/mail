//! Operator-only directory actions for a self-hosted Mail installation.
const std = @import("std");
const database = @import("database.zig");
const time = @import("../core/time_compat.zig");

const page_size = 25;

pub const Operator = struct {
    id: i64,
    username: []const u8,
    session: []const u8,
};

const Entry = struct { id: i64, email: []const u8, username: []const u8, enabled: bool };
const Page = struct { mailboxes: []Entry, next: ?i64 };

fn allowed(tx: database.Database.Transaction, operator: Operator, password_hash: ?[]const u8, now: i64) !bool {
    const stmt = try tx.prepare(
        \\SELECT 1 FROM users u JOIN webmail_sessions s ON s.username = u.username
        \\WHERE u.id = ?1 AND u.username = ?2 AND s.session_id = ?3 AND s.expires_at > ?4
        \\ AND u.enabled = 1 AND (?5 IS NULL OR u.password_hash = ?5)
        \\ AND NOT EXISTS (SELECT 1 FROM provisioned_mailboxes)
        \\ AND NOT EXISTS (SELECT 1 FROM hosted_domain_retirements)
    );
    defer stmt.finalize();
    try stmt.bind(1, operator.id);
    try stmt.bind(2, operator.username);
    try stmt.bind(3, operator.session);
    try stmt.bind(4, now);
    try stmt.bindOpt(5, password_hash);
    return stmt.step();
}

pub fn canManage(db: *database.Database, operator: Operator) !bool {
    var tx = try db.beginTransaction(.read);
    defer tx.deinit();
    const granted = try allowed(tx, operator, null, time.timestamp());
    try tx.commit();
    return granted;
}

pub fn list(a: std.mem.Allocator, db: *database.Database, operator: Operator, after: i64) !Page {
    var tx = try db.beginTransaction(.read);
    defer tx.deinit();
    if (!try allowed(tx, operator, null, time.timestamp())) return error.OperatorUnavailable;
    var entries: std.ArrayList(Entry) = .empty;
    var next: ?i64 = null;
    {
        const rows = try tx.prepare("SELECT id, email, username, enabled FROM users WHERE id < ?1 ORDER BY id DESC LIMIT ?2");
        defer rows.finalize();
        try rows.bind(1, if (after == 0) std.math.maxInt(i64) else after);
        try rows.bind(2, @as(i64, page_size + 1));
        while (try rows.step()) {
            if (entries.items.len == page_size) {
                next = entries.items[page_size - 1].id;
                break;
            }
            try entries.append(a, .{
                .id = rows.columnInt64(0),
                .email = try a.dupe(u8, rows.columnText(1)),
                .username = try a.dupe(u8, rows.columnText(2)),
                .enabled = rows.columnInt64(3) != 0,
            });
        }
    }
    try tx.commit();
    return .{ .mailboxes = try entries.toOwnedSlice(a), .next = next };
}

pub fn create(db: *database.Database, operator: Operator, operator_hash: []const u8, mailbox: []const u8, password_hash: []const u8) !i64 {
    const now = time.timestamp();
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    if (!try allowed(tx, operator, operator_hash, now)) return error.OperatorUnavailable;
    const id = blk: {
        const stmt = try tx.prepare(
            \\INSERT INTO users (username, password_hash, email, created_at, updated_at)
            \\SELECT ?1, ?2, ?1, ?3, ?3 WHERE NOT EXISTS (
            \\ SELECT 1 FROM users WHERE lower(username) = ?1 OR lower(email) = ?1
            \\)
            \\RETURNING id
        );
        defer stmt.finalize();
        try stmt.bind(1, mailbox);
        try stmt.bind(2, password_hash);
        try stmt.bind(3, now);
        if (!try stmt.step()) return error.MailboxExists;
        break :blk stmt.columnInt64(0);
    };
    {
        const audit = try tx.prepare(
            \\INSERT INTO audit_log(timestamp, action, actor, target, target_type, severity)
            \\VALUES(?1, 'mailbox.created', ?2, ?3, 'mailbox', 'info')
        );
        defer audit.finalize();
        try audit.bind(1, now);
        try audit.bind(2, operator.username);
        try audit.bind(3, mailbox);
        _ = try audit.step();
    }
    try tx.commit();
    return id;
}
