//! Revoke a reserved mailbox's combined-inbox links and residual browser sessions.
const std = @import("std");
const database = @import("database.zig");
const Database = database.Database;
const maildir = @import("hosted_erasure_maildir.zig");
const private_sqlite = @import("hosted_erasure_sqlite.zig");
const review_store = @import("hosted_erasure_review.zig");
const time = @import("../core/time_compat.zig");

const Receipt = struct {
    version: u8 = 1,
    state: []const u8 = "linked_sessions_revoked_other_data_pending",
    mailbox: []const u8,
    request_id: []const u8,
    start_audit_id: i64,
    audit_id: i64,
    links_revoked: i64,
    remaining_mailbox_sessions_removed: i64,
};

const target_links =
    "l.source_user_id=?1 OR l.owner_session IN (SELECT session_id FROM webmail_sessions WHERE username=?2)" ++
    " OR l.source_session IN (SELECT session_id FROM webmail_sessions WHERE username=?2)";

fn bindScope(row: database.Statement, owner: i64, mailbox: []const u8) !void {
    try row.bind(1, owner);
    try row.bind(2, mailbox);
}

fn requireRevocable(tx: Database.Transaction, owner: i64, mailbox: []const u8) !void {
    // A link's source is minted for that link. Refuse a stale ownership
    // mapping or any session whose deletion would cascade into another link
    // or an MFA enrollment. The private step already removed the target MFA.
    const unsafe = try tx.prepare(
        \\SELECT 1 FROM webmail_account_links l
        \\LEFT JOIN webmail_sessions root ON root.session_id=l.owner_session
        \\LEFT JOIN webmail_sessions source ON source.session_id=l.source_session
        \\LEFT JOIN users u ON u.id=l.source_user_id
        \\WHERE (
    ++ target_links ++
        \\) AND (root.session_id IS NULL OR source.session_id IS NULL OR u.id IS NULL
        \\    OR source.username<>u.username OR root.username=source.username
        \\    OR EXISTS (SELECT 1 FROM webmail_account_links other WHERE other.owner_session=l.source_session)
        \\    OR EXISTS (SELECT 1 FROM webmail_mfa_enrollment e WHERE e.session_id=l.source_session)
        \\    OR EXISTS (SELECT 1 FROM webmail_mfa_enrollment e WHERE root.username=?2 AND e.session_id=l.owner_session))
        \\LIMIT 1
    );
    defer unsafe.finalize();
    try bindScope(unsafe, owner, mailbox);
    if (try unsafe.step()) return error.ErasureLinkedSessionOwnershipUnresolved;

    {
        const outbox = try tx.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='webmail_records'");
        defer outbox.finalize();
        if (!try outbox.step()) return;
    }

    // A peer can have queued a send using the delegated session. Keep the
    // link until the status is resolved so the operation cannot silently
    // change the dispatch result. Older outbox records omit linked_account.
    const pending = try tx.prepare(
        \\SELECT 1 FROM webmail_account_links l
        \\JOIN webmail_sessions source ON source.session_id=l.source_session
        \\JOIN webmail_records r ON r.username=source.username AND r.kind='outbox'
        \\WHERE (
    ++ target_links ++
        \\) AND r.state NOT IN ('sent','cancelled')
        \\AND CASE WHEN json_valid(r.payload) THEN json_extract(r.payload,'$.linked_account')=l.id ELSE 1 END
        \\LIMIT 1
    );
    defer pending.finalize();
    try bindScope(pending, owner, mailbox);
    if (try pending.step()) return error.ErasureLinkedDeliveryUnresolved;
}

fn verifyRemoved(tx: Database.Transaction, owner: i64, mailbox: []const u8) !void {
    const remaining = try tx.prepare(
        "SELECT 1 FROM webmail_account_links l WHERE " ++ target_links ++
            " UNION ALL SELECT 1 FROM webmail_sessions WHERE username=?2 LIMIT 1",
    );
    defer remaining.finalize();
    try bindScope(remaining, owner, mailbox);
    if (try remaining.step()) return error.ErasureLinkedSessionsRemain;
}

fn revokeLinks(tx: Database.Transaction, owner: i64, mailbox: []const u8) !i64 {
    const deleted = try tx.prepare("DELETE FROM webmail_account_links AS l WHERE " ++ target_links ++ " RETURNING source_session");
    defer deleted.finalize();
    try bindScope(deleted, owner, mailbox);
    var count: i64 = 0;
    while (try deleted.step()) {
        const source = try tx.prepare("SELECT 1 FROM webmail_sessions WHERE session_id=?1");
        defer source.finalize();
        try source.bind(1, deleted.columnText(0));
        if (try source.step()) return error.ErasureLinkedSessionsRemain;
        count += 1;
    }
    return count;
}

fn removeMailboxSessions(tx: Database.Transaction, mailbox: []const u8) !i64 {
    const deleted = try tx.prepare("DELETE FROM webmail_sessions WHERE username=?1 RETURNING id");
    defer deleted.finalize();
    try deleted.bind(1, mailbox);
    var count: i64 = 0;
    while (try deleted.step()) count += 1;
    return count;
}

fn existingReceipt(tx: Database.Transaction, review: review_store.Review, start_id: i64) !?Receipt {
    const row = try tx.prepare(
        \\SELECT s.completion_audit_id,s.links_revoked,s.remaining_mailbox_sessions_removed,a.id
        \\FROM hosted_erasure_link_steps s
        \\LEFT JOIN audit_log a ON a.id=s.completion_audit_id
        \\AND a.action='hosted.erasure.links.revoked' AND a.target=?2 AND a.target_type='hosted_mailbox'
        \\AND json_extract(a.details,'$.start_audit_id')=s.start_audit_id
        \\AND json_extract(a.details,'$.request_id')=?3
        \\AND json_extract(a.details,'$.links_revoked')=s.links_revoked
        \\AND json_extract(a.details,'$.remaining_mailbox_sessions_removed')=s.remaining_mailbox_sessions_removed
        \\WHERE s.start_audit_id=?1
    );
    defer row.finalize();
    try row.bind(1, start_id);
    try row.bind(2, review.mailbox);
    try row.bind(3, review.request_id);
    if (!try row.step()) return null;
    if (row.columnIsNull(3)) return error.InvalidErasureJournal;
    return .{
        .mailbox = review.mailbox,
        .request_id = review.request_id,
        .start_audit_id = start_id,
        .audit_id = row.columnInt64(0),
        .links_revoked = row.columnInt64(1),
        .remaining_mailbox_sessions_removed = row.columnInt64(2),
    };
}

pub fn erase(a: std.mem.Allocator, io: std.Io, db: *Database, review: review_store.Review, start_id: i64, operator: []const u8, mail_root: []const u8) !Receipt {
    try review.validate();
    if (start_id < 1) return error.InvalidErasureStartAuditId;
    var root = try maildir.openLockedRoot(a, io, mail_root);
    defer root.close(io);

    try db.exec("PRAGMA secure_delete=ON; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON");
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const now = time.timestamp();
    const observation = try review_store.requireStarted(a, tx, review, start_id, now);
    try maildir.requireRemoved(a, io, tx, root, review.mailbox, start_id);
    const owner = observation.identity.native_user_id;
    try private_sqlite.requireRemoved(tx, review, start_id, owner);
    if (try existingReceipt(tx, review, start_id)) |receipt| {
        try verifyRemoved(tx, owner, review.mailbox);
        try tx.commit();
        return receipt;
    }

    try requireRevocable(tx, owner, review.mailbox);
    const links = try revokeLinks(tx, owner, review.mailbox);
    const sessions = try removeMailboxSessions(tx, review.mailbox);
    try verifyRemoved(tx, owner, review.mailbox);

    const details = try std.json.Stringify.valueAlloc(a, .{
        .start_audit_id = start_id,
        .request_id = review.request_id,
        .case_reference = review.case_reference,
        .identity = observation.identity,
        .links_revoked = links,
        .remaining_mailbox_sessions_removed = sessions,
    }, .{});
    const id = try review_store.writeAudit(tx, "hosted.erasure.links.revoked", review.mailbox, operator, now, details);
    const journal = try tx.prepare(
        \\INSERT INTO hosted_erasure_link_steps(start_audit_id,completion_audit_id,links_revoked,remaining_mailbox_sessions_removed)
        \\VALUES(?1,?2,?3,?4)
    );
    defer journal.finalize();
    try journal.bind(1, start_id);
    try journal.bind(2, id);
    try journal.bind(3, links);
    try journal.bind(4, sessions);
    if (try journal.step()) return error.StepFailed;
    try tx.commit();
    return .{
        .mailbox = review.mailbox,
        .request_id = review.request_id,
        .start_audit_id = start_id,
        .audit_id = id,
        .links_revoked = links,
        .remaining_mailbox_sessions_removed = sessions,
    };
}
