//! Check an isolated Mail backup against the current, independently supplied lifecycle database.
const std = @import("std");
const database = @import("database.zig");
const content = @import("hosted_erasure_content.zig");
const dav = @import("hosted_erasure_dav.zig");
const preflight = @import("hosted_erasure_preflight.zig");
const links = @import("hosted_erasure_links.zig");
const maildir = @import("hosted_erasure_maildir.zig");
const refs = @import("message_refs.zig");
const review_store = @import("hosted_erasure_review.zig");
const search = @import("hosted_erasure_search.zig");
const shared = @import("hosted_erasure_shared_sqlite.zig");
const private_sqlite = @import("hosted_erasure_sqlite.zig");
const clock = @import("../core/time_compat.zig");
const writer = @import("../core/maildir_writer.zig");

const Allocator = std.mem.Allocator;
const Tx = database.Database.Transaction;
const Hash = std.crypto.hash.sha2.Sha256;
const Dir = std.Io.Dir;
const Receipt = struct {
    version: u8 = 1,
    state: []const u8 = "erasure_restore_verified",
    source: []const u8 = "separate_current_smtp_database",
    checked_at: i64,
    reservations_checked: usize,
    authority_sha256: [64]u8,
    newest_reservation_audit_id: ?i64,
};

fn hashValue(hash: *Hash, value: []const u8) void {
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, value.len, .big);
    hash.update(&length);
    hash.update(value);
}

fn reservationCount(tx: Tx, current: bool) !i64 {
    const table = try tx.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='hosted_erasure_operations'");
    defer table.finalize();
    if (!try table.step()) {
        if (current) return error.RestoreErasureAuthoritySchemaMissing;
        return 0;
    }

    const row = try tx.prepare("SELECT count(*) FROM hosted_erasure_operations");
    defer row.finalize();
    if (!try row.step()) return error.StepFailed;
    return row.columnInt64(0);
}

fn verifyAuthorityLineage(current: Tx, restored: Tx) !void {
    const table = try restored.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='provisioned_mailboxes'");
    defer table.finalize();
    if (!try table.step()) return;

    // A newly initialized recovery server must not stand in for the original
    // authority. An existing hosted assignment anchors both databases to the
    // same lifecycle, even when the case journal has no rows yet.
    const assignments = try restored.prepare(
        \\SELECT p.mailbox,p.user_id,p.actor,o.operation_id FROM provisioned_mailboxes p
        \\LEFT JOIN provisioning_operations o ON o.mailbox=p.mailbox AND o.revision=1
        \\ORDER BY p.mailbox
    );
    defer assignments.finalize();
    if (!try assignments.step()) return;
    const match = try current.prepare(
        \\SELECT 1 FROM provisioned_mailboxes p JOIN provisioning_operations o ON o.mailbox=p.mailbox AND o.revision=1
        \\WHERE p.mailbox=?1 AND p.user_id=?2 AND p.actor=?3 AND o.operation_id=?4
    );
    defer match.finalize();
    while (true) {
        if (assignments.columnTextOpt(3)) |operation| {
            try match.reset();
            try match.bind(1, assignments.columnText(0));
            try match.bind(2, assignments.columnInt64(1));
            try match.bind(3, assignments.columnText(2));
            try match.bind(4, operation);
            if (try match.step()) return;
        }
        if (!try assignments.step()) return error.RestoreErasureAuthorityLineageMismatch;
    }
}

fn readReview(a: Allocator, row: database.Statement) !review_store.Review {
    const raw = row.columnTextOpt(4) orelse return error.RestoreErasureAuthorityInvalid;
    const review = try std.json.parseFromSliceLeaky(review_store.Review, a, raw, .{ .allocate = .alloc_always });
    try review.validate();
    if (!std.mem.eql(u8, review.mailbox, row.columnText(0)) or !std.mem.eql(u8, review.request_id, row.columnText(1)))
        return error.RestoreErasureAuthorityInvalid;
    return review;
}

fn audit(a: Allocator, tx: Tx, mailbox: []const u8, start: i64, action: []const u8) !?[]const u8 {
    const row = try tx.prepare(
        \\SELECT json_array(id,details) FROM audit_log
        \\WHERE target_type='hosted_mailbox' AND target=?1 AND action=?2
        \\AND json_extract(details,'$.start_audit_id')=?3 ORDER BY id LIMIT 2
    );
    defer row.finalize();
    try row.bind(1, mailbox);
    try row.bind(2, action);
    try row.bind(3, start);
    if (!try row.step()) return null;
    const found = try a.dupe(u8, row.columnText(0));
    if (try row.step()) return error.InvalidErasureJournal;
    return found;
}

fn matchAudit(a: Allocator, authority: Tx, restored: Tx, mailbox: []const u8, start: i64, action: []const u8, hash: *Hash) !void {
    const recorded = (try audit(a, authority, mailbox, start, action)) orelse return error.RestoreErasureAuthorityIncomplete;
    const candidate = (try audit(a, restored, mailbox, start, action)) orelse return error.RestoreErasureReconciliationRequired;
    if (!std.mem.eql(u8, recorded, candidate)) return error.RestoreErasureReconciliationRequired;
    hashValue(hash, action);
    hashValue(hash, recorded);
}

fn matchReservation(a: Allocator, tx: Tx, review: review_store.Review, start: i64, owner: i64, now: i64) !preflight.Identity {
    // Check all matching rows, including an ID reassigned to another address
    // and duplicate username/email attribution that could revive the address.
    const users = try tx.prepare("SELECT 1 FROM users WHERE id<>?1 AND (username=?2 COLLATE NOCASE OR email=?2 COLLATE NOCASE)");
    defer users.finalize();
    try users.bind(1, owner);
    try users.bind(2, review.mailbox);
    if (try users.step()) return error.RestoreErasureIdentityChanged;
    const observation = try review_store.requireStarted(a, tx, review, start, now);
    if (observation.identity.native_user_id != owner) return error.RestoreErasureIdentityChanged;
    return observation.identity;
}

fn verifyDav(a: Allocator, authority: Tx, restored: Tx, restored_dav: ?Tx, review: review_store.Review, start: i64, owner: i64, hash: *Hash) !void {
    const previous = try review_store.reviewedDav(a, authority, review);
    if (previous.state != .not_configured) {
        if (restored_dav == null) return error.RestoreErasureDavRequired;
        try matchAudit(a, authority, restored, review.mailbox, start, "hosted.erasure.dav.removed", hash);
        const step = try restored.prepare(
            \\SELECT s.owner_id,a.id FROM hosted_erasure_dav_steps s JOIN audit_log a ON a.id=s.completion_audit_id
            \\WHERE s.start_audit_id=?1 AND a.action='hosted.erasure.dav.removed' AND a.target=?2
            \\AND a.target_type='hosted_mailbox' AND json_extract(a.details,'$.start_audit_id')=?1
        );
        defer step.finalize();
        try step.bind(1, start);
        try step.bind(2, review.mailbox);
        if (!try step.step() or step.columnInt64Opt(0) != previous.owner_id)
            return error.RestoreErasureReconciliationRequired;
    }
    if (restored_dav) |tx| {
        const short = review.mailbox[0 .. std.mem.indexOfScalar(u8, review.mailbox, '@') orelse return error.RestoreErasureAuthorityInvalid];
        try dav.verifyRemoved(a, tx, review.mailbox, owner, short, previous.owner_id);
    }
}

pub fn verify(a: Allocator, io: std.Io, authority_path: []const u8, restored_path: []const u8, restored_maildir: []const u8, dav_path: ?[]const u8, legacy: bool) !Receipt {
    const authority_stamp = try refs.fileStamp(a, authority_path);
    const restore_stamp = try refs.fileStamp(a, restored_path);
    if (std.mem.eql(u8, authority_stamp, restore_stamp)) return error.RestoreErasureAuthorityMustBeSeparate;

    var root = try Dir.cwd().openDir(io, restored_maildir, .{ .iterate = true, .follow_symlinks = false });
    defer root.close(io);
    try writer.lock(root.handle);

    var authority = try database.Database.openReadOnly(a, authority_path);
    defer authority.deinit();
    var current = try authority.beginTransaction(.read);
    defer current.deinit();
    const count = try reservationCount(current, true);
    if (legacy and count != 0) return error.RestoreErasureRequiresIsolatedPromotion;

    // The search verifier runs SQLite's FTS integrity command. The write
    // transaction is always rolled back, including after successful checks.
    var candidate = try database.Database.openReadWriteExisting(a, restored_path);
    defer candidate.deinit();
    var restored = try candidate.beginTransaction(.write);
    defer restored.deinit();
    if (try reservationCount(restored, false) != count) return error.RestoreErasureReconciliationRequired;
    try verifyAuthorityLineage(current, restored);
    if (count != 0) {
        const triggers = try restored.prepare(
            \\SELECT count(*) FROM sqlite_schema WHERE type='trigger' AND name IN
            \\('hosted_erasure_account_insert','hosted_erasure_account_update','hosted_erasure_provisioning_update')
        );
        defer triggers.finalize();
        if (!try triggers.step() or triggers.columnInt64(0) != 3) return error.RestoreErasureReservationProtectionMissing;
    }

    const dav_stamp = if (dav_path) |path| try refs.fileStamp(a, path) else null;
    if (dav_stamp) |stamp| {
        if (std.mem.eql(u8, stamp, authority_stamp) or std.mem.eql(u8, stamp, restore_stamp))
            return error.RestoreErasureDatabaseAlias;
    }
    var dav_db = if (dav_path) |path| try database.Database.openReadOnly(a, path) else null;
    defer if (dav_db) |*db| db.deinit();
    var restored_dav = if (dav_db) |*db| try db.beginTransaction(.read) else null;
    defer if (restored_dav) |*tx| tx.deinit();
    const now = clock.timestamp();
    var hash = Hash.init(.{});
    hashValue(&hash, "mail-erasure-restore-v1");
    var newest: ?i64 = null;
    const cases = try current.prepare(
        \\SELECT o.mailbox,o.request_id,o.native_user_id,o.start_audit_id,
        \\ CASE WHEN a.id IS NOT NULL AND p.user_id=o.native_user_id THEN
        \\  json_set(json_remove(a.details,'$.identity'),'$.mailbox',a.target,'$.assignment_actor',p.actor) END
        \\FROM hosted_erasure_operations o
        \\LEFT JOIN audit_log a ON a.id=o.review_audit_id AND a.target=o.mailbox
        \\ AND a.target_type='hosted_mailbox' AND a.action='hosted.erasure.review.accepted'
        \\LEFT JOIN provisioned_mailboxes p ON p.mailbox=o.mailbox
        \\ORDER BY o.start_audit_id
    );
    defer cases.finalize();
    while (try cases.step()) {
        const review = try readReview(a, cases);
        const owner = cases.columnInt64(2);
        const start = cases.columnInt64(3);
        const identity = try matchReservation(a, current, review, start, owner, now);
        if (!identity.eql(try matchReservation(a, restored, review, start, owner, now)))
            return error.RestoreErasureIdentityChanged;
        try review_store.verifyLocalOperationsDrained(restored, owner);
        hashValue(&hash, try std.json.Stringify.valueAlloc(a, identity, .{}));
        hashValue(&hash, cases.columnText(4));
        for ([_][]const u8{
            "hosted.erasure.maildir.removed",
            "hosted.erasure.search.removed",
            "hosted.erasure.sqlite.private.removed",
            "hosted.erasure.shared.sqlite",
            "hosted.erasure.links.revoked",
            "hosted.erasure.sqlite.content.removed",
        }) |action| try matchAudit(a, current, restored, review.mailbox, start, action, &hash);
        try maildir.requireRestoredAbsent(a, io, restored, root, review.mailbox, start);
        try search.requireRemoved(restored, review, start, owner);
        try private_sqlite.requireRemoved(restored, review, start, owner);
        _ = try shared.requireRemoved(a, restored, review, start, owner);
        _ = try links.requireRemoved(restored, review, start, owner);
        try content.verifyRemoved(restored, owner, review.mailbox);
        try verifyDav(a, current, restored, restored_dav, review, start, owner, &hash);
        newest = start;
    }
    if (!std.mem.eql(u8, authority_stamp, try refs.fileStamp(a, authority_path)) or
        !std.mem.eql(u8, restore_stamp, try refs.fileStamp(a, restored_path))) return error.RestoreErasureDatabaseChanged;

    if (dav_path) |path| {
        if (!std.mem.eql(u8, dav_stamp.?, try refs.fileStamp(a, path))) return error.RestoreErasureDatabaseChanged;
    }

    return .{
        .checked_at = now,
        .reservations_checked = @intCast(count),
        .authority_sha256 = std.fmt.bytesToHex(hash.finalResult(), .lower),
        .newest_reservation_audit_id = newest,
    };
}
