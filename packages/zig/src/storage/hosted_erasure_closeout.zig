//! Verify native removal and record approved dispositions for the remaining evidence.
const std = @import("std");
const database = @import("database.zig");
const content = @import("hosted_erasure_content.zig");
const dav = @import("hosted_erasure_dav.zig");
const inventory = @import("hosted_erasure_inventory.zig");
const maildir = @import("hosted_erasure_maildir.zig");
const preflight = @import("hosted_erasure_preflight.zig");
const review_store = @import("hosted_erasure_review.zig");
const typesense = @import("hosted_erasure_typesense.zig");
const refs = @import("message_refs.zig");
const time = @import("../core/time_compat.zig");

const Allocator = std.mem.Allocator;
const Tx = database.Database.Transaction;
const action = "hosted.erasure.closeout.recorded";
const Disposition = struct {
    state: enum { removed, retention_required, retained_until },
    reference: []const u8,
    retain_until: ?i64 = null,
};
const BackupEvidence = struct {
    disposition: Disposition,
    retained_snapshots: usize,
    restore_verification_reference: ?[]const u8 = null,
};
const RetainedRecord = struct {
    table: []const u8,
    disposition: Disposition,
};
pub const Decision = struct {
    version: u8,
    scope_sha256: [64]u8,
    approval_reference: []const u8,
    external_search_reference: []const u8,
    sqlite_scope_reference: []const u8,
    sqlite_history: Disposition,
    backups: BackupEvidence,
    hosted_billing: Disposition,
    support_records: Disposition,
    retained_records: []const RetainedRecord,
};
const NativeProofs = struct {
    previous_steps: content.Proofs,
    private_content_audit_id: i64,
    dav_audit_id: ?i64,
    typesense_audit_id: ?i64,
};
const Scope = struct {
    mailbox: []const u8,
    request_id: []const u8,
    start_audit_id: i64,
    native_user_id: i64,
    verified: NativeProofs,
    retained_records: []const content.Retained,
    sqlite_tables_requiring_scope_review: []const []const u8,
};
const Record = struct {
    scope: Scope,
    decision: Decision,
    recorded_at: i64,
};
const Report = struct {
    version: u8 = 1,
    state: []const u8,
    scope_sha256: [64]u8,
    scope: Scope,
    audit_id: ?i64 = null,
    recorded_at: ?i64 = null,
    decision: ?Decision = null,
};

fn inspect(a: Allocator, io: std.Io, tx: Tx, root: std.Io.Dir, review: review_store.Review, start: i64, dav_path: ?[]const u8, now: i64) !Scope {
    const observation = try review_store.requireStarted(a, tx, review, start, now);
    const owner = observation.identity.native_user_id;
    const receipt = try content.requireVerified(a, io, tx, root, review, start, owner);
    const dav_audit = try dav.requireVerified(a, io, tx, review, start, owner, dav_path);
    const search_audit = try typesense.requireVerified(a, io, tx, review, start, owner);

    const known = try content.snapshotRetained(a, tx, owner, review.mailbox);
    const observed = try inventory.observeSqlite(a, tx, review.mailbox, owner);
    var needs_review: std.ArrayList([]const u8) = .empty;
    for (observed.unscoped_tables) |table| {
        for (known) |entry| {
            if (std.mem.eql(u8, entry.table, table)) break;
        } else try needs_review.append(a, table);
    }
    for (observed.tables) |entry| {
        if (entry.matching_rows == 0) continue;
        for (known) |retained| {
            if (std.mem.eql(u8, retained.table, entry.table)) break;
        } else try needs_review.append(a, entry.table);
    }

    return .{
        .mailbox = review.mailbox,
        .request_id = review.request_id,
        .start_audit_id = start,
        .native_user_id = owner,
        .verified = .{
            .previous_steps = receipt.receipt.verified,
            .private_content_audit_id = receipt.audit_id,
            .dav_audit_id = dav_audit,
            .typesense_audit_id = search_audit,
        },
        .retained_records = known,
        .sqlite_tables_requiring_scope_review = try needs_review.toOwnedSlice(a),
    };
}

fn validateDisposition(value: Disposition, now: i64, allow_removed: bool) !void {
    if (!preflight.validCaseReference(value.reference)) return error.InvalidErasureCloseoutReference;
    switch (value.state) {
        .removed => if (!allow_removed or value.retain_until != null) return error.InvalidErasureCloseoutDisposition,
        .retention_required => if (value.retain_until != null) return error.InvalidErasureCloseoutDisposition,
        .retained_until => if ((value.retain_until orelse 0) <= now) return error.ErasureCloseoutRetentionExpired,
    }
}

fn validateDecision(decision: Decision, scope: Scope, now: i64) !void {
    if (decision.version != 1 or
        !preflight.validCaseReference(decision.approval_reference) or
        !preflight.validCaseReference(decision.external_search_reference) or
        !preflight.validCaseReference(decision.sqlite_scope_reference)) return error.InvalidErasureCloseoutReference;

    try validateDisposition(decision.sqlite_history, now, true);
    try validateDisposition(decision.hosted_billing, now, true);
    try validateDisposition(decision.support_records, now, true);
    try validateDisposition(decision.backups.disposition, now, true);
    if (decision.backups.restore_verification_reference) |reference| {
        if (!preflight.validCaseReference(reference)) return error.InvalidErasureCloseoutReference;
    }
    if (decision.backups.retained_snapshots == 0) {
        if (decision.backups.disposition.state != .removed) return error.InvalidErasureCloseoutDisposition;
    } else {
        if (decision.backups.disposition.state == .removed) return error.InvalidErasureCloseoutDisposition;
        if (decision.backups.restore_verification_reference == null) return error.ErasureCloseoutRestoreProofRequired;
    }

    if (decision.retained_records.len != scope.retained_records.len) return error.ErasureCloseoutRetentionScopeMismatch;
    for (scope.retained_records) |expected| {
        var matches: usize = 0;
        for (decision.retained_records) |actual| {
            if (!std.mem.eql(u8, expected.table, actual.table)) continue;
            try validateDisposition(actual.disposition, now, false);
            matches += 1;
        }
        if (matches != 1) return error.ErasureCloseoutRetentionScopeMismatch;
    }
}

fn existing(a: Allocator, tx: Tx, report: Report, decision: Decision) !?Report {
    const row = try tx.prepare(
        \\SELECT id,details FROM audit_log WHERE action='hosted.erasure.closeout.recorded'
        \\AND target=?1 AND target_type='hosted_mailbox'
        \\AND json_extract(details,'$.scope.start_audit_id')=?2
        \\AND json_extract(details,'$.scope.request_id')=?3
        \\AND json_extract(details,'$.scope.native_user_id')=?4
        \\AND json_extract(details,'$.decision.approval_reference')=?5 ORDER BY id LIMIT 2
    );
    defer row.finalize();
    try row.bind(1, report.scope.mailbox);
    try row.bind(2, report.scope.start_audit_id);
    try row.bind(3, report.scope.request_id);
    try row.bind(4, report.scope.native_user_id);
    try row.bind(5, decision.approval_reference);
    if (!try row.step()) return null;
    const id = row.columnInt64(0);
    const record = try std.json.parseFromSliceLeaky(Record, a, row.columnText(1), .{ .allocate = .alloc_always });
    if (try row.step()) return error.InvalidErasureJournal;
    const proposed = try std.json.Stringify.valueAlloc(a, Record{
        .scope = report.scope,
        .decision = decision,
        .recorded_at = record.recorded_at,
    }, .{});
    const recorded = try std.json.Stringify.valueAlloc(a, record, .{});
    if (!std.mem.eql(u8, proposed, recorded)) return error.ErasureCloseoutApprovalConflict;
    var result = report;
    result.state = "hosted_erasure_disposition_recorded";
    result.audit_id = id;
    result.recorded_at = record.recorded_at;
    result.decision = record.decision;
    return result;
}

pub fn reconcile(a: Allocator, io: std.Io, db: *database.Database, review: review_store.Review, start: i64, actor: []const u8, mail_root: []const u8, dav_path: ?[]const u8, decision: ?Decision) !Report {
    try review.validate();
    if (start < 1) return error.InvalidErasureStartAuditId;
    var root = try maildir.openLockedRoot(a, io, mail_root);
    defer root.close(io);
    if (decision != null) try db.exec("PRAGMA synchronous=FULL");

    // The index integrity check requires a write transaction, including when
    // inspecting the current scope. Without an approval it is rolled back.
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const now = time.timestamp();
    const scope = try inspect(a, io, tx, root, review, start, dav_path, now);
    var report: Report = .{
        .state = "hosted_erasure_closeout_review_pending",
        .scope_sha256 = refs.digest(try std.json.Stringify.valueAlloc(a, scope, .{})),
        .scope = scope,
    };
    const approved = decision orelse return report;
    if (!std.mem.eql(u8, &approved.scope_sha256, &report.scope_sha256)) return error.ErasureCloseoutScopeChanged;
    if (try existing(a, tx, report, approved)) |prior| return prior;
    try validateDecision(approved, scope, now);
    const details = try std.json.Stringify.valueAlloc(a, Record{
        .scope = scope,
        .decision = approved,
        .recorded_at = now,
    }, .{});
    report.audit_id = try review_store.writeAudit(tx, action, review.mailbox, actor, now, details);
    try tx.commit();
    report.state = "hosted_erasure_disposition_recorded";
    report.recorded_at = now;
    report.decision = approved;
    return report;
}
