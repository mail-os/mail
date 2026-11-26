//! Remove the reserved mailbox's active SQLite search records in one transaction.
const std = @import("std");
const Database = @import("database.zig").Database;
const maildir = @import("hosted_erasure_maildir.zig");
const review_store = @import("hosted_erasure_review.zig");
const time = @import("../core/time_compat.zig");

const Receipt = struct {
    version: u8 = 1,
    state: []const u8 = "local_search_removed_other_stores_pending",
    mailbox: []const u8,
    request_id: []const u8,
    start_audit_id: i64,
    audit_id: i64,
    search_documents: i64,
    eas_search_keys: i64,
};

fn existingReceipt(tx: Database.Transaction, review: review_store.Review, start_id: i64) !?Receipt {
    const row = try tx.prepare(
        \\SELECT s.completion_audit_id,s.search_documents,s.eas_search_keys,a.id
        \\FROM hosted_erasure_search_steps s
        \\LEFT JOIN audit_log a ON a.id=s.completion_audit_id
        \\AND a.action='hosted.erasure.search.removed' AND a.target=?2 AND a.target_type='hosted_mailbox'
        \\AND json_extract(a.details,'$.start_audit_id')=s.start_audit_id
        \\AND json_extract(a.details,'$.request_id')=?3
        \\AND json_extract(a.details,'$.search_documents')=s.search_documents
        \\AND json_extract(a.details,'$.eas_search_keys')=s.eas_search_keys
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
        .search_documents = row.columnInt64(1),
        .eas_search_keys = row.columnInt64(2),
    };
}

fn countOwned(tx: Database.Transaction, comptime table: []const u8, owner: i64) !i64 {
    const row = try tx.prepare("SELECT count(*) FROM " ++ table ++ " WHERE user_id=?1");
    defer row.finalize();
    try row.bind(1, owner);
    if (!try row.step()) return error.StepFailed;
    return row.columnInt64(0);
}

fn deleteOwned(tx: Database.Transaction, comptime table: []const u8, owner: i64) !void {
    const row = try tx.prepare("DELETE FROM " ++ table ++ " WHERE user_id=?1");
    defer row.finalize();
    try row.bind(1, owner);
    if (try row.step()) return error.StepFailed;
}

fn verifySearchRemoved(tx: Database.Transaction, owner: i64) !void {
    if (try countOwned(tx, "webmail_search_docs", owner) != 0 or try countOwned(tx, "eas_search_keys", owner) != 0)
        return error.ErasureSearchRecordsRemain;

    // rank=1 checks the external-content FTS postings against the content
    // table. A missing delete trigger or stale posting must roll back the purge.
    const check = try tx.prepare("INSERT INTO webmail_search_text(webmail_search_text,rank) VALUES('integrity-check',1)");
    defer check.finalize();
    if (try check.step()) return error.StepFailed;
}

pub fn erase(a: std.mem.Allocator, io: std.Io, db: *Database, review: review_store.Review, start_id: i64, operator: []const u8, mail_root: []const u8) !Receipt {
    try review.validate();
    if (start_id < 1) return error.InvalidErasureStartAuditId;
    var root = try maildir.openLockedRoot(a, io, mail_root);
    defer root.close(io);

    // Overwrite deleted ordinary SQLite cells where SQLite can safely do so.
    // Reconcile older WAL pages and FTS segments as separate stores.
    try db.exec("PRAGMA secure_delete=ON");
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const now = time.timestamp();
    const observation = try review_store.requireStarted(a, tx, review, start_id, now);
    try maildir.requireRemoved(a, io, tx, root, review.mailbox, start_id);
    const owner = observation.identity.native_user_id;
    if (try existingReceipt(tx, review, start_id)) |receipt| {
        try verifySearchRemoved(tx, owner);
        try tx.commit();
        return receipt;
    }

    const documents = try countOwned(tx, "webmail_search_docs", owner);
    const keys = try countOwned(tx, "eas_search_keys", owner);
    try deleteOwned(tx, "webmail_search_docs", owner);
    try deleteOwned(tx, "eas_search_keys", owner);
    try verifySearchRemoved(tx, owner);

    const details = try std.json.Stringify.valueAlloc(a, .{
        .start_audit_id = start_id,
        .request_id = review.request_id,
        .case_reference = review.case_reference,
        .identity = observation.identity,
        .search_documents = documents,
        .eas_search_keys = keys,
    }, .{});
    const id = try review_store.writeAudit(tx, "hosted.erasure.search.removed", review.mailbox, operator, now, details);
    const row = try tx.prepare(
        \\INSERT INTO hosted_erasure_search_steps(start_audit_id,completion_audit_id,search_documents,eas_search_keys)
        \\VALUES(?1,?2,?3,?4)
    );
    defer row.finalize();
    try row.bind(1, start_id);
    try row.bind(2, id);
    try row.bind(3, documents);
    try row.bind(4, keys);
    if (try row.step()) return error.StepFailed;
    try tx.commit();

    return .{
        .mailbox = review.mailbox,
        .request_id = review.request_id,
        .start_audit_id = start_id,
        .audit_id = id,
        .search_documents = documents,
        .eas_search_keys = keys,
    };
}
