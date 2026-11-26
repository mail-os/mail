//! Require case approval for removing data used by another mailbox's grant.
const std = @import("std");
const Database = @import("database.zig").Database;
const thread_evidence = @import("hosted_erasure_thread_evidence.zig");
const calendar_copy = @import("hosted_erasure_calendar_copy.zig");
const inventory = @import("hosted_erasure_inventory.zig");
const preflight = @import("hosted_erasure_preflight.zig");
const review_store = @import("hosted_erasure_review.zig");
const time = @import("../core/time_compat.zig");
const Allocator = std.mem.Allocator;

pub const Store = enum { maildir, dav };

const Disposition = enum { release_source, release_source_with_calendar_copies };

pub const Decision = struct {
    version: u8,
    scope_sha256: []const u8,
    disposition: Disposition,
    approval_reference: []const u8,
    retained_calendar_copies: []const calendar_copy.Copy = &.{},
};

const Delegation = struct {
    team_id: []const u8,
    peer_user_id: i64,
};

const Scope = struct {
    store: Store,
    reviewed: []const inventory.SharedBacking,
    current: []const inventory.SharedBacking,
    source_delegations: []const Delegation,
    review_inventory_has_share_details: bool,

    fn requiresDecision(self: Scope) bool {
        return self.reviewed.len != 0 or self.current.len != 0 or self.source_delegations.len != 0;
    }
};

fn digestForScope(a: Allocator, scope: Scope, threads: []const thread_evidence.Thread) ![64]u8 {
    // Preserve legacy digests for Calendar and for Maildir without a live
    // thread or collection. Only the scope with new evidence needs approval.
    const content = if (threads.len == 0)
        try std.json.Stringify.valueAlloc(a, scope, .{})
    else
        try std.json.Stringify.valueAlloc(a, .{ .scope = scope, .thread_records = threads }, .{});
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(content, &hash, .{});
    return std.fmt.bytesToHex(hash, .lower);
}

fn sourceShares(a: Allocator, shares: []const inventory.SharedBacking, store: Store) ![]const inventory.SharedBacking {
    var source: std.ArrayList(inventory.SharedBacking) = .empty;
    for (shares) |share| {
        if (share.role == .source and (share.kind == .calendar) == (store == .dav))
            try source.append(a, share);
    }
    return source.toOwnedSlice(a);
}

fn sourceDelegations(a: Allocator, tx: Database.Transaction, owner: i64, store: Store) ![]const Delegation {
    if (store != .maildir) return &.{};
    const rows = try tx.prepare(
        \\SELECT team_id,grantee_id FROM mail_team_grants
        \\WHERE source_id=?1 AND scope='mailbox'
        \\ORDER BY team_id,grantee_id
    );
    defer rows.finalize();
    try rows.bind(1, owner);
    var grants: std.ArrayList(Delegation) = .empty;
    while (try rows.step()) try grants.append(a, .{
        .team_id = try a.dupe(u8, rows.columnText(0)),
        .peer_user_id = rows.columnInt64(1),
    });
    return grants.toOwnedSlice(a);
}

fn collect(a: Allocator, tx: Database.Transaction, review: review_store.Review, owner: i64, store: Store) !Scope {
    const reviewed = try review_store.reviewedSharedBacking(a, tx, review);
    const live = try inventory.observeSharedBacking(a, tx, owner);
    return .{
        .store = store,
        .reviewed = if (reviewed) |shares| try sourceShares(a, shares, store) else &.{},
        .current = try sourceShares(a, live, store),
        .source_delegations = try sourceDelegations(a, tx, owner, store),
        .review_inventory_has_share_details = reviewed != null,
    };
}

pub const Report = struct {
    version: u8 = 1,
    mailbox: []const u8,
    request_id: []const u8,
    start_audit_id: i64,
    requires_approval: bool,
    scope_sha256: []const u8,
    scope: Scope,
    thread_records: []const thread_evidence.Thread,
    unresolved_shared_replies: usize,
    shared_reply_dependencies: []const thread_evidence.UnresolvedReply,
    audit_id: ?i64 = null,
};

fn validateCopies(scope: Scope, disposition: Disposition, copies: []const calendar_copy.Copy) !void {
    if (disposition == .release_source) {
        if (copies.len != 0) return error.InvalidErasureSharedDecision;
        return;
    }
    if (scope.store != .dav or copies.len == 0) return error.InvalidErasureSharedDecision;
    for (copies, 0..) |copy, index| {
        if (copy.destination_calendar_id < 1) return error.InvalidErasureSharedDecision;
        const may_read = for (scope.current) |grant| {
            if (grant.peer_user_id == copy.peer_user_id and std.mem.eql(u8, grant.share_id, copy.source_share_id) and
                (std.mem.eql(u8, grant.access, "viewer") or std.mem.eql(u8, grant.access, "editor"))) break true;
        } else false;
        if (!may_read) return error.ErasureCalendarCopyNotAuthorized;
        for (copies[0..index]) |previous| {
            if (previous.destination_calendar_id == copy.destination_calendar_id or
                (previous.peer_user_id == copy.peer_user_id and std.mem.eql(u8, previous.source_share_id, copy.source_share_id)))
                return error.InvalidErasureSharedDecision;
        }
    }
}

pub fn inspect(a: Allocator, db: *Database, review: review_store.Review, start_id: i64, store: Store, operator: []const u8, decision: ?Decision) !Report {
    try review.validate();
    if (start_id < 1) return error.InvalidErasureStartAuditId;
    var tx = try db.beginTransaction(if (decision == null) .read else .write);
    defer tx.deinit();
    const now = time.timestamp();
    const active = try review_store.requireStarted(a, tx, review, start_id, now);
    const scope = try collect(a, tx, review, active.identity.native_user_id, store);
    const threads = if (store == .maildir) try thread_evidence.collect(a, tx, active.identity.native_user_id, scope.current) else &.{};
    const pending = if (store == .maildir) try thread_evidence.unresolvedReplies(a, tx, active.identity.native_user_id) else &.{};
    const digest = try digestForScope(a, scope, threads);
    var result: Report = .{
        .mailbox = review.mailbox,
        .request_id = review.request_id,
        .start_audit_id = start_id,
        .requires_approval = scope.requiresDecision(),
        .scope_sha256 = try a.dupe(u8, &digest),
        .scope = scope,
        .thread_records = threads,
        .unresolved_shared_replies = pending.len,
        .shared_reply_dependencies = pending,
    };
    if (decision) |approved| {
        if (pending.len != 0) return error.ErasureSharedRepliesUnresolved;
        if (approved.version != 1 or !preflight.validCaseReference(approved.approval_reference) or !result.requires_approval)
            return error.InvalidErasureSharedDecision;
        if (!std.mem.eql(u8, approved.scope_sha256, &digest)) return error.ErasureSharedScopeChanged;
        try validateCopies(scope, approved.disposition, approved.retained_calendar_copies);
        const details = try std.json.Stringify.valueAlloc(a, .{
            .start_audit_id = start_id,
            .request_id = review.request_id,
            .case_reference = review.case_reference,
            .native_user_id = active.identity.native_user_id,
            .store = store,
            .scope_sha256 = result.scope_sha256,
            .disposition = approved.disposition,
            .approval_reference = approved.approval_reference,
            .scope = scope,
            .thread_records = if (threads.len != 0) threads else null,
            .retained_calendar_copies = if (approved.retained_calendar_copies.len != 0) approved.retained_calendar_copies else null,
        }, .{});
        const existing = try tx.prepare(
            \\SELECT id FROM audit_log WHERE action='hosted.erasure.shared.source_release'
            \\AND target=?1 AND target_type='hosted_mailbox'
            \\AND json_remove(details,'$.retained_calendar_copies','$.thread_records')=
            \\    json_remove(?2,'$.retained_calendar_copies','$.thread_records')
            \\AND coalesce(json_extract(details,'$.retained_calendar_copies'),'[]')=
            \\    coalesce(json_extract(?2,'$.retained_calendar_copies'),'[]')
            \\AND coalesce(json_extract(details,'$.thread_records'),'[]')=coalesce(json_extract(?2,'$.thread_records'),'[]')
            \\ORDER BY id LIMIT 1
        );
        defer existing.finalize();
        try existing.bind(1, review.mailbox);
        try existing.bind(2, details);
        result.audit_id = if (try existing.step()) existing.columnInt64(0) else try review_store.writeAudit(tx, "hosted.erasure.shared.source_release", review.mailbox, operator, now, details);
    }
    try tx.commit();
    return result;
}

pub const Release = struct {
    audit_id: i64,
    copies: []const calendar_copy.Copy,
};

pub fn requireRelease(a: Allocator, tx: Database.Transaction, review: review_store.Review, start_id: i64, owner: i64, store: Store) !?Release {
    const scope = try collect(a, tx, review, owner, store);
    if (store == .maildir and (try thread_evidence.unresolvedReplies(a, tx, owner)).len != 0) return error.ErasureSharedRepliesUnresolved;
    if (!scope.requiresDecision()) return null;
    const threads = if (store == .maildir) try thread_evidence.collect(a, tx, owner, scope.current) else &.{};
    const digest = try digestForScope(a, scope, threads);
    const approved = try tx.prepare(
        \\SELECT id,json_extract(details,'$.disposition'),coalesce(json_extract(details,'$.retained_calendar_copies'),'[]')
        \\FROM audit_log WHERE action='hosted.erasure.shared.source_release'
        \\AND target=?1 AND target_type='hosted_mailbox'
        \\AND json_extract(details,'$.start_audit_id')=?2 AND json_extract(details,'$.request_id')=?3
        \\AND json_extract(details,'$.native_user_id')=?4 AND json_extract(details,'$.store')=?5
        \\AND json_extract(details,'$.scope_sha256')=?6
        \\ORDER BY id DESC LIMIT 1
    );
    defer approved.finalize();
    try approved.bind(1, review.mailbox);
    try approved.bind(2, start_id);
    try approved.bind(3, review.request_id);
    try approved.bind(4, owner);
    try approved.bind(5, @tagName(store));
    const digest_text: []const u8 = &digest;
    try approved.bind(6, digest_text);
    if (!try approved.step()) return error.ErasureSharedReleaseRequired;
    const disposition = std.meta.stringToEnum(Disposition, approved.columnText(1)) orelse return error.InvalidErasureSharedDecision;
    const copies = try std.json.parseFromSliceLeaky([]const calendar_copy.Copy, a, approved.columnText(2), .{ .allocate = .alloc_always });
    try validateCopies(scope, disposition, copies);
    return .{ .audit_id = approved.columnInt64(0), .copies = copies };
}

pub fn requireRecordedCalendarProof(a: Allocator, tx: Database.Transaction, review: review_store.Review, start_id: i64, owner: i64, proof: calendar_copy.Proof) !void {
    const row = try tx.prepare(
        \\SELECT json_extract(details,'$.retained_calendar_copies')
        \\FROM audit_log WHERE id=?1 AND action='hosted.erasure.shared.source_release'
        \\AND target=?2 AND target_type='hosted_mailbox'
        \\AND json_extract(details,'$.start_audit_id')=?3 AND json_extract(details,'$.request_id')=?4
        \\AND json_extract(details,'$.native_user_id')=?5 AND json_extract(details,'$.store')='dav'
        \\AND json_extract(details,'$.disposition')='release_source_with_calendar_copies'
    );
    defer row.finalize();
    try row.bind(1, proof.approval_audit_id);
    try row.bind(2, review.mailbox);
    try row.bind(3, start_id);
    try row.bind(4, review.request_id);
    try row.bind(5, owner);
    if (!try row.step() or row.columnIsNull(0)) return error.InvalidErasureJournal;
    const requested = try std.json.parseFromSliceLeaky([]const calendar_copy.Copy, a, row.columnText(0), .{});
    if (requested.len == 0 or requested.len != proof.copies.len) return error.InvalidErasureJournal;
    for (requested, proof.copies) |copy, verified| {
        if (copy.peer_user_id != verified.copy.peer_user_id or copy.destination_calendar_id != verified.copy.destination_calendar_id or
            !std.mem.eql(u8, copy.source_share_id, verified.copy.source_share_id)) return error.InvalidErasureJournal;
        for (verified.resources_sha256) |byte| if (!std.ascii.isHex(byte)) return error.InvalidErasureJournal;
    }
}
