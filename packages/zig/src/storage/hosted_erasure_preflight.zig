//! Record the native mailbox identity and outstanding work for an erasure review.
const std = @import("std");
const Database = @import("database.zig").Database;

pub const Observation = struct {
    identity: struct {
        native_user_id: i64,
        initial_provisioning_operation: ?[]const u8,
        provisioning_revision: i64,
    },
    access: struct {
        state: Database.MailboxAccess,
        window: ?Database.AccessWindow,
        sending_held_since: ?i64,
        retirement_id: ?[]const u8,
    },
    delivery: struct {
        pending_local_targets: u64,
        remote_unattempted_targets: u64,
        remote_unconfirmed_targets: u64,
        legacy_remote_envelope_matches: u64,
    },
    outbound_queue: ?OutboundQueue,
    webmail_outbox: ?WebmailOutbox,
};

const OutboundQueue = struct { active_owned: ?u64, unattributed_address_matches: u64 };
const WebmailOutbox = struct { in_progress: u64, needs_review: u64 };

pub fn observe(a: std.mem.Allocator, db: *Database, mailbox: []const u8, expected_actor: []const u8, now: i64) !Observation {
    var tx = try db.beginTransaction(.read);
    defer tx.deinit();
    const account = try tx.prepare(
        \\SELECT u.id,p.revision,u.enabled,p.service_until,p.read_until,h.placed_at,r.retirement_id,
        \\ (SELECT CASE WHEN count(*)=1 THEN min(operation_id) END FROM provisioning_operations
        \\   WHERE mailbox=p.mailbox AND revision=1)
        \\FROM provisioned_mailboxes p JOIN users u ON u.id=p.user_id AND u.username=p.mailbox
        \\LEFT JOIN hosted_sending_holds h ON h.user_id=u.id
        \\LEFT JOIN hosted_retired_mailboxes r ON r.user_id=u.id
        \\WHERE p.mailbox=?1 AND p.actor=?2
    );
    defer account.finalize();
    try account.bind(1, mailbox);
    try account.bind(2, expected_actor);
    if (!try account.step()) return error.ManagedMailboxNotFound;
    const user = account.columnInt64(0);
    const window = Database.scanAccessWindow(account, 3);

    const work = try tx.prepare(
        \\SELECT count(CASE WHEN t.outcome='pending' AND (t.mailbox_id=?1 OR d.hosted_sender_id=?1) THEN 1 END),
        \\       count(CASE WHEN t.outcome='remote_unattempted' AND d.hosted_sender_id=?1 THEN 1 END),
        \\       count(CASE WHEN t.outcome='remote_unknown' AND d.hosted_sender_id=?1 THEN 1 END),
        \\       count(CASE WHEN t.outcome<>'pending' AND d.hosted_sender_id IS NULL AND d.envelope_from=?2 COLLATE NOCASE THEN 1 END)
        \\FROM accepted_mail_targets t JOIN accepted_mail d ON d.id=t.delivery_id
        \\WHERE t.outcome IN ('pending','remote_unattempted','remote_unknown')
    );
    defer work.finalize();
    try work.bind(1, user);
    try work.bind(2, mailbox);
    if (!try work.step()) return error.StepFailed;

    const result: Observation = .{
        .identity = .{
            .native_user_id = user,
            .provisioning_revision = account.columnInt64(1),
            .initial_provisioning_operation = if (account.columnTextOpt(7)) |id| try a.dupe(u8, id) else null,
        },
        .access = .{
            .state = Database.mailboxAccessAt(account.columnInt64(2) != 0, window, now),
            .window = window,
            .sending_held_since = if (account.columnIsNull(5)) null else account.columnInt64(5),
            .retirement_id = if (account.columnTextOpt(6)) |id| try a.dupe(u8, id) else null,
        },
        .delivery = .{
            .pending_local_targets = @intCast(work.columnInt64(0)),
            .remote_unattempted_targets = @intCast(work.columnInt64(1)),
            .remote_unconfirmed_targets = @intCast(work.columnInt64(2)),
            .legacy_remote_envelope_matches = @intCast(work.columnInt64(3)),
        },
        .outbound_queue = try observeQueue(tx, user, mailbox),
        .webmail_outbox = try observeOutbox(tx, mailbox),
    };
    try tx.commit();
    return result;
}

fn hasSchema(tx: Database.Transaction, query: []const u8) !bool {
    const row = try tx.prepare(query);
    defer row.finalize();
    return row.step();
}

fn observeQueue(tx: Database.Transaction, user: i64, mailbox: []const u8) !?OutboundQueue {
    if (!try hasSchema(tx, "SELECT 1 FROM sqlite_schema WHERE name='message_queue' AND type='table'")) return null;
    const attributed = try hasSchema(tx, "SELECT 1 FROM pragma_table_info('message_queue') WHERE name='hosted_user_id'");
    const exact_address = "(from_addr=?2 COLLATE NOCASE OR to_addr=?2 COLLATE NOCASE)";
    const scope = " FROM message_queue WHERE status IN ('awaiting_local','pending','retry','processing')";
    const row = try tx.prepare(if (attributed)
        "SELECT count(CASE WHEN hosted_user_id=?1 THEN 1 END),count(CASE WHEN COALESCE(hosted_user_id,0)=0 AND " ++ exact_address ++ " THEN 1 END)" ++ scope
    else
        "SELECT NULL,count(CASE WHEN " ++ exact_address ++ " THEN 1 END)" ++ scope);
    defer row.finalize();
    if (attributed) try row.bind(1, user);
    try row.bind(2, mailbox);
    if (!try row.step()) return error.StepFailed;
    return .{
        .active_owned = if (attributed) @intCast(row.columnInt64(0)) else null,
        .unattributed_address_matches = @intCast(row.columnInt64(1)),
    };
}

fn observeOutbox(tx: Database.Transaction, mailbox: []const u8) !?WebmailOutbox {
    if (!try hasSchema(tx, "SELECT 1 FROM sqlite_schema WHERE name='webmail_records' AND type='table'")) return null;
    const row = try tx.prepare(
        \\SELECT count(CASE WHEN state IN ('pending','sending') THEN 1 END),
        \\       count(CASE WHEN state IN ('unknown','partial','sent_unfiled','failed') THEN 1 END)
        \\FROM webmail_records WHERE username=?1 AND kind='outbox'
    );
    defer row.finalize();
    try row.bind(1, mailbox);
    if (!try row.step()) return error.StepFailed;
    return .{ .in_progress = @intCast(row.columnInt64(0)), .needs_review = @intCast(row.columnInt64(1)) };
}
