//! Require case approval for removing data used by another mailbox's grant.
const std = @import("std");
const Database = @import("database.zig").Database;
const inventory = @import("hosted_erasure_inventory.zig");
const preflight = @import("hosted_erasure_preflight.zig");
const review_store = @import("hosted_erasure_review.zig");
const time = @import("../core/time_compat.zig");
const Allocator = std.mem.Allocator;

pub const Store = enum { maildir, dav };

pub const Decision = struct {
    version: u8,
    scope_sha256: []const u8,
    disposition: enum { release_source },
    approval_reference: []const u8,
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

    fn digest(self: Scope, a: Allocator) ![64]u8 {
        const content = try std.json.Stringify.valueAlloc(a, self, .{});
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(content, &hash, .{});
        return std.fmt.bytesToHex(hash, .lower);
    }
};

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
    audit_id: ?i64 = null,
};

pub fn inspect(a: Allocator, db: *Database, review: review_store.Review, start_id: i64, store: Store, operator: []const u8, decision: ?Decision) !Report {
    try review.validate();
    if (start_id < 1) return error.InvalidErasureStartAuditId;
    var tx = try db.beginTransaction(if (decision == null) .read else .write);
    defer tx.deinit();
    const now = time.timestamp();
    const active = try review_store.requireStarted(a, tx, review, start_id, now);
    const scope = try collect(a, tx, review, active.identity.native_user_id, store);
    const digest = try scope.digest(a);
    var result: Report = .{
        .mailbox = review.mailbox,
        .request_id = review.request_id,
        .start_audit_id = start_id,
        .requires_approval = scope.requiresDecision(),
        .scope_sha256 = try a.dupe(u8, &digest),
        .scope = scope,
    };
    if (decision) |approved| {
        if (approved.version != 1 or !preflight.validCaseReference(approved.approval_reference) or !result.requires_approval)
            return error.InvalidErasureSharedDecision;
        if (!std.mem.eql(u8, approved.scope_sha256, &digest)) return error.ErasureSharedScopeChanged;
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
        }, .{});
        const existing = try tx.prepare(
            \\SELECT id FROM audit_log WHERE action='hosted.erasure.shared.source_release'
            \\AND target=?1 AND target_type='hosted_mailbox' AND details=?2 ORDER BY id LIMIT 1
        );
        defer existing.finalize();
        try existing.bind(1, review.mailbox);
        try existing.bind(2, details);
        result.audit_id = if (try existing.step()) existing.columnInt64(0) else try review_store.writeAudit(tx, "hosted.erasure.shared.source_release", review.mailbox, operator, now, details);
    }
    try tx.commit();
    return result;
}

pub fn requireRelease(a: Allocator, tx: Database.Transaction, review: review_store.Review, start_id: i64, owner: i64, store: Store) !void {
    const scope = try collect(a, tx, review, owner, store);
    if (!scope.requiresDecision()) return;
    const digest = try scope.digest(a);
    const approved = try tx.prepare(
        \\SELECT 1 FROM audit_log WHERE action='hosted.erasure.shared.source_release'
        \\AND target=?1 AND target_type='hosted_mailbox'
        \\AND json_extract(details,'$.start_audit_id')=?2 AND json_extract(details,'$.request_id')=?3
        \\AND json_extract(details,'$.native_user_id')=?4 AND json_extract(details,'$.store')=?5
        \\AND json_extract(details,'$.scope_sha256')=?6 AND json_extract(details,'$.disposition')='release_source'
        \\LIMIT 1
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
}
