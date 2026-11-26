//! Erase reviewed, mailbox-private records without deleting the account.
const std = @import("std");
const database = @import("database.zig");
const Database = database.Database;
const maildir = @import("hosted_erasure_maildir.zig");
const review_store = @import("hosted_erasure_review.zig");
const time = @import("../core/time_compat.zig");

const Receipt = struct {
    version: u8 = 1,
    state: []const u8 = "private_sqlite_removed_other_data_pending",
    mailbox: []const u8,
    request_id: []const u8,
    start_audit_id: i64,
    audit_id: i64,
    records_deleted: i64,
};

const Scope = struct {
    table: []const u8,
    predicate: []const u8 = "user_id=?1",
    key: enum { owner, mailbox, mailbox_and_owner } = .owner,
    optional: bool = false,
};

// Keep the allowlist and receipt version stable. Shared resources, operation
// journals and records referenced by delivery ledgers have separate lifecycles.
const scopes = [_]Scope{
    .{ .table = "mail_client_passwords" },
    .{ .table = "webmail_mfa_enrollment" },
    .{ .table = "webmail_mfa_recovery_codes" },
    .{ .table = "webmail_mfa_session_tickets" },
    .{ .table = "webmail_mfa_factors" },
    .{ .table = "hosted_sign_in_factors", .predicate = "digest IN (SELECT digest FROM hosted_sign_in_proofs WHERE user_id=?1)" },
    .{ .table = "hosted_sign_in_proofs" },
    .{ .table = "mailbox_reset_tokens", .predicate = "username=?1", .key = .mailbox },
    .{ .table = "password_reset_tokens", .predicate = "username=?1", .key = .mailbox, .optional = true },
    // An account-link deletion triggers deletion of its source session, which
    // can belong to another user. Reconcile those links before erasing them.
    .{ .table = "webmail_sessions", .key = .mailbox_and_owner, .predicate = "username=?1 AND NOT EXISTS (SELECT 1 FROM webmail_account_links l" ++
        " WHERE l.owner_session=webmail_sessions.session_id OR l.source_session=webmail_sessions.session_id)" ++
        " AND NOT EXISTS (SELECT 1 FROM webmail_mfa_enrollment e" ++
        " WHERE e.session_id=webmail_sessions.session_id AND e.user_id<>?2)" },
    .{ .table = "mail_snapshot_links" },
    .{ .table = "mail_file_links" },
    .{ .table = "mail_attention" },
    .{ .table = "mail_attention_replies" },
    .{ .table = "mail_notification_settings" },
    .{ .table = "mail_notification_senders" },
    .{ .table = "mail_notification_threads" },
    .{ .table = "mail_notification_events" },
    .{ .table = "mail_category_settings" },
    .{ .table = "mail_category_rules" },
    .{ .table = "mail_calendar_day_labels" },
    .{ .table = "mail_calendar_tasks" },
    .{ .table = "mail_calendar_tools" },
    .{ .table = "eas_mailbox_state" },
    .{ .table = "eas_mailbox_ping" },
    .{ .table = "eas_folder_stamp_aliases" },
    .{ .table = "ews_item_sync" },
    .{ .table = "imap_uids", .predicate = "username=?1", .key = .mailbox },
    .{ .table = "imap_mailboxes", .predicate = "username=?1", .key = .mailbox },
    // Deleting mailbox rows can create generation tombstones.
    .{ .table = "imap_mailbox_generations", .predicate = "username=?1", .key = .mailbox },
};

fn bindOwner(row: database.Statement, scope: Scope, owner: i64, mailbox: []const u8) !void {
    switch (scope.key) {
        .owner => try row.bind(1, owner),
        .mailbox => try row.bind(1, mailbox),
        .mailbox_and_owner => {
            try row.bind(1, mailbox);
            try row.bind(2, owner);
        },
    }
}

fn tableExists(tx: Database.Transaction, table: []const u8) !bool {
    const row = try tx.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1");
    defer row.finalize();
    try row.bind(1, table);
    return row.step();
}

fn countOwned(tx: Database.Transaction, comptime scope: Scope, owner: i64, mailbox: []const u8) !i64 {
    const row = try tx.prepare("SELECT count(*) FROM " ++ scope.table ++ " WHERE " ++ scope.predicate);
    defer row.finalize();
    try bindOwner(row, scope, owner, mailbox);
    if (!try row.step()) return error.StepFailed;
    return row.columnInt64(0);
}

fn deleteOwned(tx: Database.Transaction, comptime scope: Scope, owner: i64, mailbox: []const u8) !void {
    const row = try tx.prepare("DELETE FROM " ++ scope.table ++ " WHERE " ++ scope.predicate);
    defer row.finalize();
    try bindOwner(row, scope, owner, mailbox);
    if (try row.step()) return error.StepFailed;
}

fn verifyRemoved(tx: Database.Transaction, owner: i64, mailbox: []const u8) !void {
    inline for (scopes) |scope| {
        if (!scope.optional or try tableExists(tx, scope.table)) {
            if (try countOwned(tx, scope, owner, mailbox) != 0) return error.ErasurePrivateSqliteRecordsRemain;
        }
    }
}

fn existingReceipt(tx: Database.Transaction, review: review_store.Review, start_id: i64) !?Receipt {
    const row = try tx.prepare(
        \\SELECT s.completion_audit_id,s.records_deleted,a.id
        \\FROM hosted_erasure_sqlite_steps s
        \\LEFT JOIN audit_log a ON a.id=s.completion_audit_id
        \\AND a.action='hosted.erasure.sqlite.private.removed' AND a.target=?2 AND a.target_type='hosted_mailbox'
        \\AND json_extract(a.details,'$.start_audit_id')=s.start_audit_id
        \\AND json_extract(a.details,'$.request_id')=?3
        \\AND json_extract(a.details,'$.records_deleted')=s.records_deleted
        \\WHERE s.start_audit_id=?1
    );
    defer row.finalize();
    try row.bind(1, start_id);
    try row.bind(2, review.mailbox);
    try row.bind(3, review.request_id);
    if (!try row.step()) return null;
    if (row.columnIsNull(2)) return error.InvalidErasureJournal;
    return .{
        .mailbox = review.mailbox,
        .request_id = review.request_id,
        .start_audit_id = start_id,
        .audit_id = row.columnInt64(0),
        .records_deleted = row.columnInt64(1),
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
    if (try existingReceipt(tx, review, start_id)) |receipt| {
        try verifyRemoved(tx, owner, review.mailbox);
        try tx.commit();
        return receipt;
    }

    var deleted: i64 = 0;
    inline for (scopes) |scope| {
        if (!scope.optional or try tableExists(tx, scope.table)) {
            const count = try countOwned(tx, scope, owner, review.mailbox);
            if (count != 0) {
                try deleteOwned(tx, scope, owner, review.mailbox);
                // Check child scopes while their ownership keys still exist.
                if (try countOwned(tx, scope, owner, review.mailbox) != 0) return error.ErasurePrivateSqliteRecordsRemain;
                deleted = try std.math.add(i64, deleted, count);
            }
        }
    }
    try verifyRemoved(tx, owner, review.mailbox);

    const details = try std.json.Stringify.valueAlloc(a, .{
        .start_audit_id = start_id,
        .request_id = review.request_id,
        .case_reference = review.case_reference,
        .identity = observation.identity,
        .records_deleted = deleted,
    }, .{});
    const id = try review_store.writeAudit(tx, "hosted.erasure.sqlite.private.removed", review.mailbox, operator, now, details);
    const row = try tx.prepare(
        \\INSERT INTO hosted_erasure_sqlite_steps(start_audit_id,completion_audit_id,records_deleted)
        \\VALUES(?1,?2,?3)
    );
    defer row.finalize();
    try row.bind(1, start_id);
    try row.bind(2, id);
    try row.bind(3, deleted);
    if (try row.step()) return error.StepFailed;
    try tx.commit();

    return .{
        .mailbox = review.mailbox,
        .request_id = review.request_id,
        .start_audit_id = start_id,
        .audit_id = id,
        .records_deleted = deleted,
    };
}
