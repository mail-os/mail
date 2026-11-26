//! Disposition of live shared SQLite edges after the reviewed backing is removed.
const std = @import("std");
const Database = @import("database.zig").Database;
const backing = @import("hosted_erasure_inventory.zig");
const maildir = @import("hosted_erasure_maildir.zig");
const calendar = @import("hosted_erasure_calendar_copy.zig");
const evidence = @import("hosted_erasure_thread_evidence.zig");
const review_store = @import("hosted_erasure_review.zig");
const shared = @import("hosted_erasure_shared.zig");
const preflight = @import("hosted_erasure_preflight.zig");
const time = @import("../core/time_compat.zig");
const Allocator = std.mem.Allocator;
const Tx = Database.Transaction;
const Hash = std.crypto.hash.sha2.Sha256;

pub const Decision = struct {
    version: u8,
    scope_sha256: []const u8,
    approval_reference: []const u8,
};

const Grant = struct { team_id: []const u8, source_id: i64, grantee_id: i64, scope: []const u8, resource: []const u8 };
const Reply = struct {
    actor_id: i64,
    source_user_id: ?[]const u8,
    team_id: ?[]const u8,
    id: []const u8,
    kind: []const u8,
    state: []const u8,
    delivery_id: ?[]const u8 = null,
    sent_delivery_id: ?[]const u8 = null,
};
const Releases = struct { maildir: ?i64 = null, calendar: ?i64 = null };
const Counts = struct {
    threads: usize = 0,
    calendars: usize = 0,
    grants: usize = 0,
    collections: usize = 0,
    collection_members: usize = 0,
    inbox_stages: usize = 0,
    inbox_workflow: usize = 0,
    peer_assignments: usize = 0,
};
const Plan = struct {
    version: u8 = 1,
    start_audit_id: i64,
    scope_sha256: [64]u8,
    removed: Counts,
    releases: Releases,
    shared_edges: []const backing.SharedBacking,
    grants: []const Grant,
    retained_drafts_and_outbox: []const Reply,
    retained_reply_claims: []const Reply,
    unresolved_claims: []const evidence.UnresolvedReply,
    unresolved_outbox: bool,
};
const Record = struct {
    version: u8 = 1,
    scope_sha256: [64]u8,
    approval_reference: []const u8,
    maildir_release_audit_id: ?i64,
    calendar_release_audit_id: ?i64,
    removed: Counts,
    removed_shared_edges: []const backing.SharedBacking,
    removed_grants: []const Grant,
    retained_drafts_and_outbox: []const Reply,
    retained_reply_claims: []const Reply,
};
const Result = struct { plan: ?Plan = null, audit_id: ?i64 = null, receipt: ?Record = null };

const scopes = .{
    .{ "threads", "mail_team_thread_shares", "owner_id=?1 OR grantee_id=?1", "id,team_id,owner_id,grantee_id,subject,downloads" },
    .{ "calendars", "mail_team_calendar_shares", "source_id=?1 OR grantee_id=?1", "team_id,source_id,grantee_id,calendar_share_id,access" },
    .{ "grants", "mail_team_grants", "source_id=?1 OR grantee_id=?1", "team_id,source_id,grantee_id,scope,resource" },
    .{ "collections", "mail_private_collections", "user_id=?1", "id,name,revision" },
    .{ "collection_members", "mail_private_members", "user_id=?1", "collection,anchor" },
    .{ "inbox_workflow", "mail_shared_inbox_state", "source_id=?1", "team_id,reference,assignee_id,stage_id,resolved,revision,changed_by,changed_at,action" },
    .{ "inbox_stages", "mail_shared_inbox_stages", "source_id=?1", "id,team_id,name,sender,revision,retired_at" },
};
const assignments = "assignee_id=?1 AND source_id<>?1";

fn hashRow(hash: *Hash, value: []const u8) void {
    var size: [8]u8 = undefined;
    std.mem.writeInt(u64, &size, value.len, .big);
    hash.update(&size);
    hash.update(value);
}

fn fingerprint(tx: Tx, owner: i64, hash: *Hash, comptime table: []const u8, comptime scope: []const u8, comptime fields: []const u8) !usize {
    const statement = try tx.prepare("SELECT json_array(" ++ fields ++ ") FROM " ++ table ++ " WHERE " ++ scope ++ " ORDER BY rowid");
    defer statement.finalize();
    try statement.bind(1, owner);
    hashRow(hash, table);
    var count: usize = 0;
    while (try statement.step()) {
        hash.update(&.{1});
        hashRow(hash, statement.columnText(0));
        count += 1;
    }
    hash.update(&.{0});
    return count;
}

fn grantList(a: Allocator, tx: Tx, owner: i64) ![]const Grant {
    const statement = try tx.prepare(
        \\SELECT team_id,source_id,grantee_id,scope,resource FROM mail_team_grants
        \\WHERE source_id=?1 OR grantee_id=?1 ORDER BY team_id,source_id,grantee_id,scope,resource
    );
    defer statement.finalize();
    try statement.bind(1, owner);
    var grants: std.ArrayList(Grant) = .empty;
    while (try statement.step()) try grants.append(a, .{
        .team_id = try a.dupe(u8, statement.columnText(0)),
        .source_id = statement.columnInt64(1),
        .grantee_id = statement.columnInt64(2),
        .scope = try a.dupe(u8, statement.columnText(3)),
        .resource = try a.dupe(u8, statement.columnText(4)),
    });
    return grants.toOwnedSlice(a);
}

const claim_scope = "source_id=?1 OR actor_id=?1";
const reply_rows =
    \\ FROM webmail_records r JOIN users u ON u.username=r.username
    \\ LEFT JOIN mail_shared_reply_claims c ON r.kind='outbox' AND c.actor_id=u.id AND c.send_id=r.id
    \\ WHERE r.kind IN ('draft','outbox') AND (c.source_id=?1 OR c.actor_id=?1 OR
    \\ CASE WHEN json_valid(r.payload) THEN json_type(r.payload,'$.message.sharedReply')='object'
    \\  AND (u.id=?1 OR json_extract(r.payload,'$.message.sharedReply.sourceId')=CAST(?1 AS TEXT)) ELSE 0 END)
;
const ProtectedReplies = struct {
    claims: []const Reply,
    documents: []const Reply,
    unresolved_outbox: bool,
    fingerprint_sha256: [64]u8,
};

fn collectReplies(a: Allocator, tx: Tx, owner: i64) !ProtectedReplies {
    var hash = Hash.init(.{});
    _ = try fingerprint(tx, owner, &hash, "mail_shared_reply_claims", claim_scope, "source_id,reference,team_id,actor_id,actor,send_id,state,due_at");
    const claims = try tx.prepare("SELECT actor_id,send_id,state,CAST(source_id AS TEXT),team_id FROM mail_shared_reply_claims WHERE " ++ claim_scope ++ " ORDER BY actor_id,send_id");
    defer claims.finalize();
    try claims.bind(1, owner);
    var records: std.ArrayList(Reply) = .empty;
    while (try claims.step()) try records.append(a, .{
        .actor_id = claims.columnInt64(0),
        .source_user_id = try a.dupe(u8, claims.columnText(3)),
        .team_id = try a.dupe(u8, claims.columnText(4)),
        .id = try a.dupe(u8, claims.columnText(1)),
        .kind = "reply_claim",
        .state = try a.dupe(u8, claims.columnText(2)),
    });

    const exists = try tx.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='webmail_records'");
    defer exists.finalize();
    var documents: std.ArrayList(Reply) = .empty;
    var unresolved_outbox = false;
    if (try exists.step()) {
        const rows = try tx.prepare(
            \\SELECT u.id,r.id,r.kind,r.state,json_array(u.id,r.id,r.kind,r.state,r.revision,r.due_at,r.expires_at,r.payload),
            \\ r.kind='outbox' AND r.state NOT IN ('sent','cancelled','failed'),
            \\ COALESCE(CAST(c.source_id AS TEXT),json_extract(r.payload,'$.message.sharedReply.sourceId')),
            \\ COALESCE(c.team_id,json_extract(r.payload,'$.message.sharedReply.team')),
            \\ json_extract(r.payload,'$.dispatch.delivery_id'),json_extract(r.payload,'$.dispatch.sent_delivery_id')
        ++ reply_rows ++ " ORDER BY u.id,r.kind,r.id");
        defer rows.finalize();
        try rows.bind(1, owner);
        while (try rows.step()) {
            hashRow(&hash, rows.columnText(4));
            unresolved_outbox = unresolved_outbox or rows.columnInt64(5) != 0;
            try documents.append(a, .{
                .actor_id = rows.columnInt64(0),
                .source_user_id = if (rows.columnTextOpt(6)) |source| try a.dupe(u8, source) else null,
                .team_id = if (rows.columnTextOpt(7)) |team| try a.dupe(u8, team) else null,
                .id = try a.dupe(u8, rows.columnText(1)),
                .kind = try a.dupe(u8, rows.columnText(2)),
                .state = try a.dupe(u8, rows.columnText(3)),
                .delivery_id = if (rows.columnTextOpt(8)) |id| try a.dupe(u8, id) else null,
                .sent_delivery_id = if (rows.columnTextOpt(9)) |id| try a.dupe(u8, id) else null,
            });
        }
    }
    return .{
        .claims = try records.toOwnedSlice(a),
        .documents = try documents.toOwnedSlice(a),
        .unresolved_outbox = unresolved_outbox,
        .fingerprint_sha256 = std.fmt.bytesToHex(hash.finalResult(), .lower),
    };
}

fn collectPlan(a: Allocator, tx: Tx, review: review_store.Review, start: i64, owner: i64, protected: ProtectedReplies) !Plan {
    const edges = try backing.observeSharedBacking(a, tx, owner);
    const grants = try grantList(a, tx, owner);
    const pending = try evidence.unresolvedReplies(a, tx, owner);
    const releases: Releases = if (pending.len == 0 and !protected.unresolved_outbox) .{
        .maildir = try maildir.requireSharedRecordsRelease(a, tx, review, start, owner),
        .calendar = try requireCalendarRelease(a, tx, review, start, owner, edges),
    } else .{};
    var hash = Hash.init(.{});
    hashRow(&hash, "hosted-erasure-shared-sqlite-v1");
    hashRow(&hash, try std.json.Stringify.valueAlloc(a, .{ start, owner, edges, releases }, .{}));
    hashRow(&hash, &protected.fingerprint_sha256);
    var counts: Counts = .{};
    inline for (scopes) |scope| @field(counts, scope[0]) = try fingerprint(tx, owner, &hash, scope[1], scope[2], scope[3]);
    counts.peer_assignments = try fingerprint(tx, owner, &hash, "mail_shared_inbox_state", assignments, "team_id,source_id,reference,assignee_id,stage_id,resolved,revision,changed_by,changed_at,action");
    for (edges) |edge| {
        if (edge.kind == .calendar) continue;
        const source = if (edge.role == .source) owner else edge.peer_user_id;
        const thread = try evidence.collect(a, tx, source, &.{edge});
        hashRow(&hash, &thread[0].records_sha256);
    }
    return .{
        .start_audit_id = start,
        .scope_sha256 = std.fmt.bytesToHex(hash.finalResult(), .lower),
        .removed = counts,
        .releases = releases,
        .shared_edges = edges,
        .grants = grants,
        .retained_drafts_and_outbox = protected.documents,
        .retained_reply_claims = protected.claims,
        .unresolved_claims = pending,
        .unresolved_outbox = protected.unresolved_outbox,
    };
}

fn requireCalendarRelease(a: Allocator, tx: Tx, review: review_store.Review, start: i64, owner: i64, edges: []const backing.SharedBacking) !?i64 {
    const outgoing = for (edges) |edge| {
        if (edge.kind == .calendar and edge.role == .source) break true;
    } else false;
    if (!outgoing) return null;
    const release = (try shared.requireRelease(a, tx, review, start, owner, .dav)) orelse return error.ErasureSharedReleaseRequired;
    const row = try tx.prepare(
        \\SELECT json_extract(a.details,'$.retained_calendar_copy_proof')
        \\FROM hosted_erasure_dav_steps s JOIN audit_log a ON a.id=s.completion_audit_id
        \\WHERE s.start_audit_id=?1 AND a.action='hosted.erasure.dav.removed'
        \\AND a.target=?2 AND a.target_type='hosted_mailbox'
        \\AND json_extract(a.details,'$.start_audit_id')=?1 AND json_extract(a.details,'$.request_id')=?3
    );
    defer row.finalize();
    try row.bind(1, start);
    try row.bind(2, review.mailbox);
    try row.bind(3, review.request_id);
    if (!try row.step()) return error.ErasureDavPending;
    if (row.columnIsNull(0) != (release.copies.len == 0)) return error.ErasureSharedScopeChanged;
    if (row.columnTextOpt(0)) |raw| {
        const proof = try std.json.parseFromSliceLeaky(calendar.Proof, a, raw, .{});
        if (proof.approval_audit_id != release.audit_id) return error.ErasureSharedScopeChanged;
        try shared.requireRecordedCalendarProof(a, tx, review, start, owner, proof);
    }
    return release.audit_id;
}

fn apply(tx: Tx, owner: i64, now: i64) !void {
    inline for (scopes) |scope| {
        const row = try tx.prepare("DELETE FROM " ++ scope[1] ++ " WHERE " ++ scope[2]);
        defer row.finalize();
        try row.bind(1, owner);
        if (try row.step()) return error.StepFailed;
    }
    const detach = try tx.prepare(
        "UPDATE mail_shared_inbox_state SET assignee_id=NULL,revision=revision+1,changed_by=NULL,changed_at=?2,action='access_removed' WHERE " ++ assignments,
    );
    defer detach.finalize();
    try detach.bind(1, owner);
    try detach.bind(2, now);
    if (try detach.step()) return error.StepFailed;
}

fn verifyRemoved(tx: Tx, owner: i64) !void {
    inline for (scopes) |scope| {
        const row = try tx.prepare("SELECT 1 FROM " ++ scope[1] ++ " WHERE " ++ scope[2] ++ " LIMIT 1");
        defer row.finalize();
        try row.bind(1, owner);
        if (try row.step()) return error.ErasureSharedRecordsRemain;
    }
    const row = try tx.prepare("SELECT 1 FROM mail_shared_inbox_state WHERE " ++ assignments ++ " LIMIT 1");
    defer row.finalize();
    try row.bind(1, owner);
    if (try row.step()) return error.ErasureSharedRecordsRemain;
}

fn priorResult(a: Allocator, tx: Tx, review: review_store.Review, start: i64, owner: i64) !?Result {
    const row = try tx.prepare(
        \\SELECT id,json_extract(details,'$.receipt') FROM audit_log
        \\WHERE action='hosted.erasure.shared.sqlite' AND target=?1 AND target_type='hosted_mailbox'
        \\AND json_extract(details,'$.start_audit_id')=?2 AND json_extract(details,'$.request_id')=?3
        \\AND json_extract(details,'$.native_user_id')=?4 ORDER BY id LIMIT 2
    );
    defer row.finalize();
    try row.bind(1, review.mailbox);
    try row.bind(2, start);
    try row.bind(3, review.request_id);
    try row.bind(4, owner);
    if (!try row.step()) return null;
    const result: Result = .{
        .audit_id = row.columnInt64(0),
        .receipt = try std.json.parseFromSliceLeaky(Record, a, row.columnText(1), .{ .allocate = .alloc_always }),
    };
    if (try row.step()) return error.InvalidErasureJournal;
    return result;
}

pub fn requireRemoved(a: Allocator, tx: Tx, review: review_store.Review, start: i64, owner: i64) !i64 {
    const prior = (try priorResult(a, tx, review, start, owner)) orelse return error.ErasureSharedSqlitePending;
    try verifyRemoved(tx, owner);
    if ((try evidence.unresolvedReplies(a, tx, owner)).len != 0 or (try collectReplies(a, tx, owner)).unresolved_outbox)
        return error.ErasureSharedRepliesUnresolved;
    return prior.audit_id.?;
}

pub fn reconcile(a: Allocator, io: std.Io, db: *Database, review: review_store.Review, start: i64, operator: []const u8, mail_root: []const u8, decision: ?Decision) !Result {
    try review.validate();
    if (start < 1) return error.InvalidErasureStartAuditId;
    if (decision) |approved| {
        if (approved.version != 1 or !preflight.validCaseReference(approved.approval_reference))
            return error.InvalidErasureSharedDecision;
    }
    var root = try maildir.openLockedRoot(a, io, mail_root);
    defer root.close(io);
    if (decision != null)
        try db.exec("PRAGMA secure_delete=ON; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON");
    var tx = try db.beginTransaction(if (decision == null) .read else .write);
    defer tx.deinit();
    const now = time.timestamp();
    const observation = try review_store.requireStarted(a, tx, review, start, now);
    const owner = observation.identity.native_user_id;
    try maildir.requireRemoved(a, io, tx, root, review.mailbox, start);

    if (try priorResult(a, tx, review, start, owner)) |prior| {
        try verifyRemoved(tx, owner);
        if (decision) |approved| {
            const recorded = prior.receipt.?;
            if (!std.mem.eql(u8, approved.scope_sha256, &recorded.scope_sha256) or
                !std.mem.eql(u8, approved.approval_reference, recorded.approval_reference))
                return error.ErasureSharedScopeChanged;
        }
        try tx.commit();
        return prior;
    }

    const protected = try collectReplies(a, tx, owner);
    const plan = try collectPlan(a, tx, review, start, owner, protected);
    const approved = decision orelse {
        try tx.commit();
        return .{ .plan = plan };
    };
    if (!std.mem.eql(u8, approved.scope_sha256, &plan.scope_sha256)) return error.ErasureSharedScopeChanged;
    if (plan.unresolved_claims.len != 0 or plan.unresolved_outbox) return error.ErasureSharedRepliesUnresolved;
    try apply(tx, owner, now);
    try verifyRemoved(tx, owner);
    const verified = try collectReplies(a, tx, owner);
    if (!std.mem.eql(u8, &protected.fingerprint_sha256, &verified.fingerprint_sha256)) return error.ErasureSharedReplyEvidenceChanged;
    const receipt: Record = .{
        .scope_sha256 = plan.scope_sha256,
        .approval_reference = approved.approval_reference,
        .maildir_release_audit_id = plan.releases.maildir,
        .calendar_release_audit_id = plan.releases.calendar,
        .removed = plan.removed,
        .removed_shared_edges = plan.shared_edges,
        .removed_grants = plan.grants,
        .retained_drafts_and_outbox = plan.retained_drafts_and_outbox,
        .retained_reply_claims = plan.retained_reply_claims,
    };
    const details = try std.json.Stringify.valueAlloc(a, .{
        .start_audit_id = start,
        .request_id = review.request_id,
        .native_user_id = owner,
        .case_reference = review.case_reference,
        .receipt = receipt,
    }, .{});
    const id = try review_store.writeAudit(tx, "hosted.erasure.shared.sqlite", review.mailbox, operator, now, details);
    try tx.commit();
    return .{ .audit_id = id, .receipt = receipt };
}
