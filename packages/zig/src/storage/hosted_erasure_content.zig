//! Remove live mailbox-private content and record the data that still needs disposition.
const std = @import("std");
const native_sqlite = @import("sqlite");
const database = @import("database.zig");
const links = @import("hosted_erasure_links.zig");
const maildir = @import("hosted_erasure_maildir.zig");
const review_store = @import("hosted_erasure_review.zig");
const search = @import("hosted_erasure_search.zig");
const shared = @import("hosted_erasure_shared_sqlite.zig");
const sqlite = @import("hosted_erasure_sqlite.zig");
const time = @import("../core/time_compat.zig");

const Allocator = std.mem.Allocator;
const Tx = database.Database.Transaction;
const action = "hosted.erasure.sqlite.content.removed";
const Count = struct { table: []const u8, rows: i64 };
pub const Proofs = struct {
    maildir: i64,
    local_search: i64,
    private_sqlite: i64,
    shared_sqlite: i64,
    linked_sessions: i64,
};
const Record = struct {
    verified: Proofs,
    removed: []const Count,
    retained_at_commit: []const Count,
};
pub const Receipt = struct {
    version: u8 = 1,
    state: []const u8 = "private_content_removed_retention_pending",
    mailbox: []const u8,
    request_id: []const u8,
    start_audit_id: i64,
    audit_id: i64,
    receipt: Record,
    outstanding_evidence: []const []const u8 = &.{
        "dav_and_external_search_disposition",
        "active_retained_records_disposition",
        "sqlite_wal_and_historical_pages",
        "backup_catalog_and_restore_verification",
        "hosted_billing_and_support_disposition",
    },
};
const Scope = struct {
    table: []const u8,
    where: []const u8 = "user_id=?1",
    key: enum { owner, mailbox, both } = .owner,
    optional: bool = false,
};

const private_records =
    \\username=?1 AND (kind IN ('undo','preferences') OR
    \\ (kind IN ('draft','draft-edit') AND CASE WHEN json_valid(payload) THEN
    \\   json_type(payload,'$.message')='object'
    \\   AND COALESCE(json_type(payload,'$.message.sharedReply'),'null')='null'
    \\   AND COALESCE(json_type(payload,'$.message.senderId'),'null')='null'
    \\ ELSE 0 END))
;
const unused_uploads =
    \\username=?1 AND NOT EXISTS (
    \\ SELECT 1 FROM webmail_records r
    \\ WHERE r.username=?1 AND CASE WHEN NOT json_valid(r.payload) THEN 1 ELSE EXISTS (
    \\   SELECT 1 FROM json_each(r.payload,'$.message.attachments') a
    \\   WHERE CASE WHEN a.type='object' THEN json_extract(a.value,'$.uploadId') END=webmail_uploads.id
    \\ ) END)
;
const unused_refs =
    \\user_id=?1
    \\AND NOT EXISTS (SELECT 1 FROM mail_shared_reply_claims c WHERE c.source_id=?1 AND c.reference=mailbox_message_refs.reference)
    \\AND NOT EXISTS (SELECT 1 FROM mail_ews_draft_sends e WHERE e.user_id=?1 AND e.draft_reference=mailbox_message_refs.reference)
    \\AND NOT EXISTS (SELECT 1 FROM mail_ews_draft_finalizations f WHERE f.user_id=?1 AND f.draft_reference=mailbox_message_refs.reference)
;
const accepted =
    \\(hosted_sender_id=?1 OR (hosted_sender_id IS NULL AND envelope_from=?2 COLLATE NOCASE) OR
    \\ EXISTS (SELECT 1 FROM accepted_mail_targets t WHERE t.delivery_id=accepted_mail.id AND (t.mailbox_id=?1 OR t.mailbox=?2 COLLATE NOCASE)))
;

// Delete dependent rows first so receipts count them before any cascade.
const removable = [_]Scope{
    .{ .table = "webmail_records", .where = private_records, .key = .mailbox, .optional = true },
    .{ .table = "webmail_uploads", .where = unused_uploads, .key = .mailbox, .optional = true },
    .{ .table = "mail_private_entries" },
    .{ .table = "mail_private_labels" },
    .{ .table = "mail_private_groups" },
    .{ .table = "mail_private_anchors" },
    .{ .table = "mail_retention_moves" },
    .{ .table = "mail_retention_previews" },
    .{ .table = "mail_retention_rules" },
    .{ .table = "mailbox_junk_feedback" },
    .{ .table = "mailbox_forwarding_scopes" },
    .{ .table = "mailbox_forwarding" },
    .{ .table = "mailbox_forwarding_requests" },
    .{ .table = "mailbox_vacation" },
    .{ .table = "sender_review_messages" },
    .{ .table = "sender_review_invitations" },
    .{ .table = "sender_screening_rules" },
    .{ .table = "sender_screening" },
    .{ .table = "mail_ews_reply_drafts" },
    .{ .table = "mail_search_pending" },
    .{ .table = "mail_search_checkpoints" },
    .{ .table = "mailbox_message_refs", .where = unused_refs },
};
const retained = [_]Scope{
    .{ .table = "webmail_records", .where = "username=?1", .key = .mailbox, .optional = true },
    .{ .table = "webmail_uploads", .where = "username=?1", .key = .mailbox, .optional = true },
    .{ .table = "mailbox_message_refs" },
    .{ .table = "mail_ews_draft_sends" },
    .{ .table = "mail_ews_draft_finalizations" },
    .{ .table = "eas_accepted_submissions", .where = "username=?1", .key = .mailbox },
    .{ .table = "accepted_mail", .where = accepted, .key = .both },
    .{ .table = "accepted_mail_targets", .where = "delivery_id IN (SELECT id FROM accepted_mail WHERE " ++ accepted ++ ")", .key = .both },
    .{ .table = "message_queue", .where = "hosted_user_id=?1 OR (hosted_user_id=0 AND (from_addr=?2 COLLATE NOCASE OR to_addr=?2 COLLATE NOCASE))", .key = .both, .optional = true },
    .{ .table = "mailbox_vacation_sends" },
    .{ .table = "mail_shared_reply_claims", .where = "source_id=?1 OR actor_id=?1" },
    .{ .table = "mail_team_members" },
    .{ .table = "mail_assistant_grants" },
    .{ .table = "mail_assistant_audit", .where = "grant_id IN (SELECT id FROM mail_assistant_grants WHERE user_id=?1)" },
    .{ .table = "mail_assistant_requests", .where = "grant_id IN (SELECT id FROM mail_assistant_grants WHERE user_id=?1)" },
    .{ .table = "hosted_sending_usage" },
    .{ .table = "provisioned_mailboxes" },
    .{ .table = "users", .where = "id=?1" },
};

// Additional identified records that can outlive live message removal.
const closeout_retained = [_]Scope{
    .{ .table = "provisioning_operations", .where = "mailbox=?1", .key = .mailbox },
    .{ .table = "audit_log", .where = "target=?1 AND target_type='hosted_mailbox' AND action<>'hosted.erasure.closeout.recorded'", .key = .mailbox },
    .{ .table = "hosted_mailbox_activity" },
    .{ .table = "hosted_sending_holds" },
    .{ .table = "hosted_retired_mailboxes" },
    .{ .table = "mail_calendar_revisions" },
    .{ .table = "mail_team_owner_handoffs", .where = "departing=?1 OR successor=?1", .key = .mailbox },
    .{ .table = "mail_team_invitations", .where = "inviter_id=?1 OR recipient_id=?1" },
    .{ .table = "mail_team_calendar_share_epochs", .where = "source_id=?1 OR grantee_id=?1" },
    .{ .table = "mail_team_thread_comments", .where = "author_id=?1" },
    .{ .table = "mail_team_thread_submissions", .where = "owner_id=?1" },
    .{ .table = "mail_team_thread_native_sent", .where = "delivery_id IN (SELECT delivery_id FROM mail_team_thread_submissions WHERE owner_id=?1)" },
    .{ .table = "mail_team_smtp_submissions", .where = "owner_id=?1" },
    .{ .table = "mail_team_smtp_sent_copies", .where = "owner_id=?1" },
};

pub const Retained = struct {
    table: []const u8,
    rows: usize,
    sha256: [64]u8,
};

pub fn snapshotRetained(a: Allocator, tx: Tx, owner: i64, mailbox: []const u8) ![]const Retained {
    var remaining: std.ArrayList(Retained) = .empty;
    inline for (retained ++ closeout_retained) |scope| {
        if (!scope.optional or try hasTable(tx, scope.table)) {
            const row = try tx.prepare("SELECT * FROM " ++ scope.table ++ " WHERE " ++ scope.where ++ " ORDER BY rowid");
            defer row.finalize();
            try bind(row, scope, owner, mailbox);
            const columns: usize = @intCast(native_sqlite.sqlite3_column_count(row.stmt));
            var count_rows: usize = 0;
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(scope.table);
            while (try row.step()) {
                count_rows += 1;
                for (0..columns) |column| {
                    const kind: u8 = @intCast(native_sqlite.sqlite3_column_type(row.stmt, @intCast(column)));
                    const value = row.columnBlob(column);
                    var size: [8]u8 = undefined;
                    std.mem.writeInt(u64, &size, value.len, .big);
                    hash.update(&.{kind});
                    hash.update(&size);
                    hash.update(value);
                }
            }
            if (count_rows != 0) try remaining.append(a, .{
                .table = scope.table,
                .rows = count_rows,
                .sha256 = std.fmt.bytesToHex(hash.finalResult(), .lower),
            });
        }
    }
    return remaining.toOwnedSlice(a);
}

fn bind(row: database.Statement, comptime scope: Scope, owner: i64, mailbox: []const u8) !void {
    switch (scope.key) {
        .owner => try row.bind(1, owner),
        .mailbox => try row.bind(1, mailbox),
        .both => {
            try row.bind(1, owner);
            try row.bind(2, mailbox);
        },
    }
}

fn hasTable(tx: Tx, name: []const u8) !bool {
    const row = try tx.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1");
    defer row.finalize();
    try row.bind(1, name);
    return row.step();
}

fn count(tx: Tx, comptime scope: Scope, owner: i64, mailbox: []const u8) !i64 {
    if (scope.optional and !try hasTable(tx, scope.table)) return 0;
    const row = try tx.prepare("SELECT count(*) FROM " ++ scope.table ++ " WHERE " ++ scope.where);
    defer row.finalize();
    try bind(row, scope, owner, mailbox);
    if (!try row.step()) return error.StepFailed;
    return row.columnInt64(0);
}

fn remove(tx: Tx, comptime scope: Scope, owner: i64, mailbox: []const u8) !Count {
    const before = try count(tx, scope, owner, mailbox);
    if (before != 0) {
        const row = try tx.prepare("DELETE FROM " ++ scope.table ++ " WHERE " ++ scope.where);
        defer row.finalize();
        try bind(row, scope, owner, mailbox);
        if (try row.step()) return error.StepFailed;
    }
    return .{ .table = scope.table, .rows = before };
}

fn stepAudit(tx: Tx, comptime step: []const u8, start: i64) !i64 {
    // Called after the step's verifier checks the receipt and the live store.
    const row = try tx.prepare("SELECT completion_audit_id FROM hosted_erasure_" ++ step ++ "_steps WHERE start_audit_id=?1");
    defer row.finalize();
    try row.bind(1, start);
    return if (try row.step()) row.columnInt64(0) else error.InvalidErasureJournal;
}

fn prior(a: Allocator, tx: Tx, review: review_store.Review, start: i64, owner: i64, proofs: Proofs) !?Receipt {
    const row = try tx.prepare("SELECT id,json_extract(details,'$.receipt') FROM audit_log WHERE action='" ++ action ++
        "' AND target=?1 AND target_type='hosted_mailbox' " ++
        \\AND json_extract(details,'$.start_audit_id')=?2 AND json_extract(details,'$.request_id')=?3
        \\AND json_extract(details,'$.native_user_id')=?4 ORDER BY id LIMIT 2
    );
    defer row.finalize();
    try row.bind(1, review.mailbox);
    try row.bind(2, start);
    try row.bind(3, review.request_id);
    try row.bind(4, owner);
    if (!try row.step()) return null;
    const record = try std.json.parseFromSliceLeaky(Record, a, row.columnText(1), .{ .allocate = .alloc_always });
    const id = row.columnInt64(0);
    if (try row.step() or !std.meta.eql(proofs, record.verified)) return error.InvalidErasureJournal;
    return .{
        .mailbox = review.mailbox,
        .request_id = review.request_id,
        .start_audit_id = start,
        .audit_id = id,
        .receipt = record,
    };
}

pub fn verifyRemoved(tx: Tx, owner: i64, mailbox: []const u8) !void {
    inline for (removable) |scope| {
        if (try count(tx, scope, owner, mailbox) != 0) return error.ErasurePrivateContentRemains;
    }
}

fn prerequisites(a: Allocator, io: std.Io, tx: Tx, root: std.Io.Dir, review: review_store.Review, start: i64, owner: i64) !Proofs {
    try review_store.verifyLocalOperationsDrained(tx, owner);
    try maildir.requireRemoved(a, io, tx, root, review.mailbox, start);
    try search.requireRemoved(tx, review, start, owner);
    try sqlite.requireRemoved(tx, review, start, owner);
    const proofs: Proofs = .{
        .maildir = try stepAudit(tx, "maildir", start),
        .local_search = try stepAudit(tx, "search", start),
        .private_sqlite = try stepAudit(tx, "sqlite", start),
        .shared_sqlite = try shared.requireRemoved(a, tx, review, start, owner),
        .linked_sessions = try links.requireRemoved(tx, review, start, owner),
    };
    if (try hasTable(tx, "webmail_uploads") and !try hasTable(tx, "webmail_records"))
        return error.ErasureWebmailSchemaIncomplete;

    return proofs;
}

pub fn requireVerified(a: Allocator, io: std.Io, tx: Tx, root: std.Io.Dir, review: review_store.Review, start: i64, owner: i64) !Receipt {
    const proofs = try prerequisites(a, io, tx, root, review, start, owner);
    const receipt = (try prior(a, tx, review, start, owner, proofs)) orelse return error.ErasurePrivateContentPending;
    try verifyRemoved(tx, owner, review.mailbox);
    return receipt;
}

pub fn erase(a: Allocator, io: std.Io, db: *database.Database, review: review_store.Review, start: i64, operator: []const u8, mail_root: []const u8) !Receipt {
    try review.validate();
    if (start < 1) return error.InvalidErasureStartAuditId;
    var root = try maildir.openLockedRoot(a, io, mail_root);
    defer root.close(io);

    try db.exec("PRAGMA secure_delete=ON; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON");
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const now = time.timestamp();
    const observation = try review_store.requireStarted(a, tx, review, start, now);
    const owner = observation.identity.native_user_id;
    const proofs = try prerequisites(a, io, tx, root, review, start, owner);
    if (try prior(a, tx, review, start, owner, proofs)) |receipt| {
        try verifyRemoved(tx, owner, review.mailbox);
        try tx.commit();
        return receipt;
    }

    const removed = try a.alloc(Count, removable.len);
    inline for (removable, 0..) |scope, index| removed[index] = try remove(tx, scope, owner, review.mailbox);
    try verifyRemoved(tx, owner, review.mailbox);
    const remaining = try a.alloc(Count, retained.len);
    inline for (retained, 0..) |scope, index| remaining[index] = .{
        .table = scope.table,
        .rows = try count(tx, scope, owner, review.mailbox),
    };
    const record: Record = .{ .verified = proofs, .removed = removed, .retained_at_commit = remaining };
    const details = try std.json.Stringify.valueAlloc(a, .{
        .start_audit_id = start,
        .request_id = review.request_id,
        .native_user_id = owner,
        .case_reference = review.case_reference,
        .receipt = record,
    }, .{});
    const id = try review_store.writeAudit(tx, action, review.mailbox, operator, now, details);
    try tx.commit();
    return .{
        .mailbox = review.mailbox,
        .request_id = review.request_id,
        .start_audit_id = start,
        .audit_id = id,
        .receipt = record,
    };
}
