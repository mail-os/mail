//! Freeze reviewed hosted mailboxes while retaining their files and identity records.
const std = @import("std");
const Database = @import("database.zig").Database;

pub const Mailbox = struct {
    mailbox: []const u8,
    actor: ?[]const u8,
    revision: ?i64,
    retirement_id: ?[]const u8 = null,
};

pub const Receipt = struct {
    version: u8 = 1,
    id: []const u8,
    domain: []const u8,
    inventory_sha256: []const u8,
    operator: []const u8,
    retired_at: i64,
    mailbox_count: usize,
};

fn bind(tx: Database.Transaction, sql: []const u8, args: anytype) !@import("database.zig").Statement {
    const stmt = try tx.prepare(sql);
    errdefer stmt.finalize();
    inline for (args, 1..) |arg, i| try stmt.bind(i, arg);
    return stmt;
}

fn execute(tx: Database.Transaction, sql: []const u8, args: anytype) !void {
    const stmt = try bind(tx, sql, args);
    defer stmt.finalize();
    _ = try stmt.step();
}

fn exists(tx: Database.Transaction, sql: []const u8, args: anytype) !bool {
    const stmt = try bind(tx, sql, args);
    defer stmt.finalize();
    return stmt.step();
}

fn tableExists(tx: Database.Transaction, table: []const u8) !bool {
    return exists(tx, "SELECT 1 FROM sqlite_schema WHERE name=?1 AND type='table'", .{table});
}

fn receiptIn(tx: Database.Transaction, allocator: std.mem.Allocator, id: []const u8) !?Receipt {
    const row = try bind(tx, "SELECT domain,inventory_sha256,operator,retired_at,mailbox_count FROM hosted_domain_retirements WHERE id=?1", .{id});
    defer row.finalize();
    if (!try row.step()) return null;
    return .{ .id = id, .domain = try allocator.dupe(u8, row.columnText(0)), .inventory_sha256 = try allocator.dupe(u8, row.columnText(1)), .operator = try allocator.dupe(u8, row.columnText(2)), .retired_at = row.columnInt64(3), .mailbox_count = @intCast(row.columnInt64(4)) };
}

pub fn receipt(allocator: std.mem.Allocator, db: *Database, id: []const u8) !?Receipt {
    var tx = try db.beginTransaction(.read);
    defer tx.deinit();
    const result = try receiptIn(tx, allocator, id);
    try tx.commit();
    return result;
}

pub fn retire(allocator: std.mem.Allocator, db: *Database, id: []const u8, domain: []const u8, digest: []const u8, operator: []const u8, now: i64, reviewed: []const Mailbox) !Receipt {
    db.lockMailboxes();
    defer db.unlockMailboxes();
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();

    if (try receiptIn(tx, allocator, id)) |recorded| {
        if (!std.mem.eql(u8, domain, recorded.domain) or !std.mem.eql(u8, digest, recorded.inventory_sha256))
            return error.RetirementConflict;
        try tx.commit();
        return recorded;
    }

    var expected: std.StringHashMapUnmanaged(Mailbox) = .empty;
    defer expected.deinit(allocator);
    for (reviewed) |item| {
        if (item.retirement_id != null) continue;
        if (item.actor == null or item.revision == null) return error.UnmanagedMailbox;
        if (try expected.fetchPut(allocator, item.mailbox, item) != null) return error.InvalidInventory;
    }
    if (expected.count() == 0) return error.NoMailboxes;

    const items = try bind(tx,
        \\SELECT u.id,u.username,p.actor,p.revision FROM users u
        \\LEFT JOIN provisioned_mailboxes p ON p.user_id=u.id AND p.mailbox=u.username
        \\LEFT JOIN hosted_retired_mailboxes r ON r.user_id=u.id
        \\WHERE substr(u.username,-length(?1)-1)=('@'||?1) COLLATE NOCASE AND r.user_id IS NULL
    , .{domain});
    defer items.finalize();
    const has_queue = try tableExists(tx, "message_queue");
    const has_outbox = try tableExists(tx, "webmail_records");
    const has_recovery = try tableExists(tx, "password_reset_tokens");

    var matched: std.ArrayList(struct { mailbox: []const u8, user: i64 }) = .empty;
    defer matched.deinit(allocator);
    while (try items.step()) {
        const mailbox = items.columnText(1);
        const actor = items.columnTextOpt(2) orelse return error.UnmanagedMailbox;
        const entry = expected.get(mailbox) orelse return error.InventoryChanged;
        if (!std.mem.eql(u8, actor, entry.actor.?) or items.columnInt64(3) != entry.revision.?) return error.InventoryChanged;
        const user = items.columnInt64(0);
        if (try exists(tx, "SELECT 1 FROM accepted_mail_targets WHERE outcome='pending' AND (mailbox_id=?1 OR recipient=?2) LIMIT 1", .{ user, mailbox }))
            return error.PendingDelivery;
        if (has_queue and try exists(tx, "SELECT 1 FROM message_queue WHERE hosted_user_id=?1 AND status IN ('pending','retry','processing') LIMIT 1", .{user}))
            return error.PendingDelivery;
        if (has_outbox and try exists(tx, "SELECT 1 FROM webmail_records WHERE username=?1 AND kind='outbox' AND state IN ('pending','sending','unknown') LIMIT 1", .{mailbox}))
            return error.PendingDelivery;
        try matched.append(allocator, .{ .mailbox = entry.mailbox, .user = user });
    }
    const count = matched.items.len;
    if (count != expected.count()) return error.InventoryChanged;

    try execute(tx, "INSERT INTO hosted_domain_retirements VALUES (?1,?2,?3,?4,?5,?6)", .{ id, domain, digest, operator, now, count });
    for (matched.items) |item| {
        try execute(tx, "INSERT INTO hosted_retired_mailboxes VALUES (?1,?2,?3)", .{ item.mailbox, item.user, id });
        try execute(tx, "UPDATE users SET enabled=0,updated_at=?1 WHERE id=?2", .{ now, item.user });
        try execute(tx, "DELETE FROM webmail_sessions WHERE username=?1", .{item.mailbox});
        if (has_recovery) try execute(tx, "DELETE FROM password_reset_tokens WHERE username=?1", .{item.mailbox});
    }

    try execute(tx,
        \\INSERT INTO audit_log(timestamp,action,actor,target,target_type,details,severity)
        \\VALUES(?1,'hosted.domain.retire',?2,?3,'hosted_domain',json_object('operation_id',?4,'mailbox_count',?5),'info')
    , .{ now, operator, domain, id, count });
    try tx.commit();
    return .{ .id = id, .domain = domain, .inventory_sha256 = digest, .operator = operator, .retired_at = now, .mailbox_count = count };
}
