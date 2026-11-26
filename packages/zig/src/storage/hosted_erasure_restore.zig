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
pub const Digest = [64]u8;
const steps = [_][]const u8{
    "hosted.erasure.maildir.removed",
    "hosted.erasure.search.removed",
    "hosted.erasure.sqlite.private.removed",
    "hosted.erasure.shared.sqlite",
    "hosted.erasure.links.revoked",
    "hosted.erasure.sqlite.content.removed",
};
const Case = struct {
    start_audit_id: i64,
    identity_sha256: Digest,
    review_sha256: Digest,
    steps_sha256: [steps.len]?Digest,
    dav_configured: bool,
    dav_owner_id: ?i64,
    dav_sha256: ?Digest,
};
pub const Snapshot = struct {
    observed_at: i64,
    assignments: []const Digest,
    cases: []const Case,
};
pub const Receipt = struct {
    version: u8 = 1,
    state: []const u8 = "erasure_restore_verified",
    source: []const u8 = "separate_current_smtp_database",
    checked_at: i64,
    authority_observed_at: i64,
    checkpoint_sha256: ?Digest = null,
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

fn assignments(tx: Tx) !?database.Statement {
    const table = try tx.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='provisioned_mailboxes'");
    defer table.finalize();
    if (!try table.step()) return null;
    return try tx.prepare(
        \\SELECT CASE WHEN count(o.operation_id)=1 THEN json_array(p.mailbox,p.user_id,p.actor,min(o.operation_id)) END
        \\FROM provisioned_mailboxes p LEFT JOIN provisioning_operations o ON o.mailbox=p.mailbox AND o.revision=1
        \\GROUP BY p.mailbox,p.user_id,p.actor ORDER BY p.mailbox
    );
}

fn lineage(a: Allocator, tx: Tx) ![]const Digest {
    const row = (try assignments(tx)) orelse return &.{};
    defer row.finalize();
    var anchors: std.ArrayList(Digest) = .empty;
    while (try row.step()) {
        if (row.columnTextOpt(0)) |identity| try anchors.append(a, refs.digest(identity));
    }
    return anchors.toOwnedSlice(a);
}

fn verifyAuthorityLineage(a: Allocator, anchors: []const Digest, restored: Tx) !void {
    const row = (try assignments(restored)) orelse return;
    defer row.finalize();
    if (!try row.step()) return;
    var trusted: std.AutoHashMapUnmanaged(Digest, void) = .empty;
    defer trusted.deinit(a);
    for (anchors) |anchor| try trusted.put(a, anchor, {});
    while (true) {
        if (row.columnTextOpt(0)) |identity| {
            if (trusted.contains(refs.digest(identity))) return;
        }
        if (!try row.step()) return error.RestoreErasureAuthorityLineageMismatch;
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

fn audit(tx: Tx, mailbox: []const u8, start: i64, action: []const u8) !?Digest {
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
    const found = refs.digest(row.columnText(0));
    if (try row.step()) return error.InvalidErasureJournal;
    return found;
}

fn matchAudit(restored: Tx, mailbox: []const u8, start: i64, action: []const u8, expected: ?Digest, hash: *Hash) !void {
    const recorded = expected orelse return error.RestoreErasureAuthorityIncomplete;
    const candidate = (try audit(restored, mailbox, start, action)) orelse return error.RestoreErasureReconciliationRequired;
    if (!std.mem.eql(u8, &recorded, &candidate)) return error.RestoreErasureReconciliationRequired;
    hashValue(hash, action);
    hashValue(hash, &recorded);
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

fn verifyDav(a: Allocator, proof: Case, restored: Tx, restored_dav: ?Tx, review: review_store.Review, start: i64, owner: i64, hash: *Hash) !void {
    if (proof.dav_configured) {
        if (restored_dav == null) return error.RestoreErasureDavRequired;
        try matchAudit(restored, review.mailbox, start, "hosted.erasure.dav.removed", proof.dav_sha256, hash);
        const step = try restored.prepare(
            \\SELECT s.owner_id,a.id FROM hosted_erasure_dav_steps s JOIN audit_log a ON a.id=s.completion_audit_id
            \\WHERE s.start_audit_id=?1 AND a.action='hosted.erasure.dav.removed' AND a.target=?2
            \\AND a.target_type='hosted_mailbox' AND json_extract(a.details,'$.start_audit_id')=?1
        );
        defer step.finalize();
        try step.bind(1, start);
        try step.bind(2, review.mailbox);
        if (!try step.step() or step.columnInt64Opt(0) != proof.dav_owner_id)
            return error.RestoreErasureReconciliationRequired;
    }
    if (restored_dav) |tx| {
        const short = review.mailbox[0 .. std.mem.indexOfScalar(u8, review.mailbox, '@') orelse return error.RestoreErasureAuthorityInvalid];
        try dav.verifyRemoved(a, tx, review.mailbox, owner, short, proof.dav_owner_id);
    }
}

fn caseRows(tx: Tx) !database.Statement {
    return tx.prepare(
        \\SELECT o.mailbox,o.request_id,o.native_user_id,o.start_audit_id,
        \\ CASE WHEN a.id IS NOT NULL AND p.user_id=o.native_user_id THEN
        \\  json_set(json_remove(a.details,'$.identity'),'$.mailbox',a.target,'$.assignment_actor',p.actor) END
        \\FROM hosted_erasure_operations o
        \\LEFT JOIN audit_log a ON a.id=o.review_audit_id AND a.target=o.mailbox
        \\ AND a.target_type='hosted_mailbox' AND a.action='hosted.erasure.review.accepted'
        \\LEFT JOIN provisioned_mailboxes p ON p.mailbox=o.mailbox
        \\ORDER BY o.start_audit_id
    );
}

pub fn capture(a: Allocator, path: []const u8) !Snapshot {
    const stamp = try refs.fileStamp(a, path);
    var db = try database.Database.openReadOnly(a, path);
    defer db.deinit();
    var tx = try db.beginTransaction(.read);
    defer tx.deinit();
    const time = clock.timestamp();
    const count = try reservationCount(tx, true);
    const proofs = try a.alloc(Case, @intCast(count));
    if (proofs.len != 0) {
        const row = try caseRows(tx);
        defer row.finalize();
        for (proofs) |*proof| {
            if (!try row.step()) return error.RestoreErasureAuthorityInvalid;
            const review = try readReview(a, row);
            const start = row.columnInt64(3);
            const identity = try matchReservation(a, tx, review, start, row.columnInt64(2), time);
            const previous = try review_store.reviewedDav(a, tx, review);
            proof.* = .{
                .start_audit_id = start,
                .identity_sha256 = refs.digest(try std.json.Stringify.valueAlloc(a, identity, .{})),
                .review_sha256 = refs.digest(try std.json.Stringify.valueAlloc(a, review, .{})),
                .steps_sha256 = undefined,
                .dav_configured = previous.state != .not_configured,
                .dav_owner_id = previous.owner_id,
                .dav_sha256 = try audit(tx, review.mailbox, start, "hosted.erasure.dav.removed"),
            };
            for (steps, &proof.steps_sha256) |step, *value| value.* = try audit(tx, review.mailbox, start, step);
        }
        if (try row.step()) return error.RestoreErasureAuthorityInvalid;
    }
    const anchors = try lineage(a, tx);
    if (!std.mem.eql(u8, stamp, try refs.fileStamp(a, path))) return error.RestoreErasureDatabaseChanged;
    return .{ .observed_at = time, .assignments = anchors, .cases = proofs };
}

pub fn verify(a: Allocator, io: std.Io, authority_path: []const u8, restored_path: []const u8, restored_maildir: []const u8, dav_path: ?[]const u8, legacy: bool) !Receipt {
    const authority_stamp = try refs.fileStamp(a, authority_path);
    const restore_stamp = try refs.fileStamp(a, restored_path);
    if (std.mem.eql(u8, authority_stamp, restore_stamp)) return error.RestoreErasureAuthorityMustBeSeparate;
    if (dav_path) |path| {
        if (std.mem.eql(u8, authority_stamp, try refs.fileStamp(a, path))) return error.RestoreErasureDatabaseAlias;
    }
    const snapshot = try capture(a, authority_path);
    if (legacy and snapshot.cases.len != 0) return error.RestoreErasureRequiresIsolatedPromotion;
    const receipt = try verifySnapshot(a, io, snapshot, restored_path, restored_maildir, dav_path);
    if (!std.mem.eql(u8, authority_stamp, try refs.fileStamp(a, authority_path))) return error.RestoreErasureDatabaseChanged;
    return receipt;
}

pub fn verifySnapshot(a: Allocator, io: std.Io, snapshot: Snapshot, restored_path: []const u8, restored_maildir: []const u8, dav_path: ?[]const u8) !Receipt {
    const restore_stamp = try refs.fileStamp(a, restored_path);
    var root = try Dir.cwd().openDir(io, restored_maildir, .{ .iterate = true, .follow_symlinks = false });
    defer root.close(io);
    try writer.lock(root.handle);

    // The search verifier runs SQLite's FTS integrity command. The write
    // transaction is always rolled back, including after successful checks.
    var candidate = try database.Database.openReadWriteExisting(a, restored_path);
    defer candidate.deinit();
    var restored = try candidate.beginTransaction(.write);
    defer restored.deinit();
    if (try reservationCount(restored, false) != snapshot.cases.len) return error.RestoreErasureReconciliationRequired;
    try verifyAuthorityLineage(a, snapshot.assignments, restored);
    if (snapshot.cases.len != 0) {
        const triggers = try restored.prepare(
            \\SELECT count(*) FROM sqlite_schema WHERE type='trigger' AND name IN
            \\('hosted_erasure_account_insert','hosted_erasure_account_update','hosted_erasure_provisioning_update')
        );
        defer triggers.finalize();
        if (!try triggers.step() or triggers.columnInt64(0) != 3) return error.RestoreErasureReservationProtectionMissing;
    }

    const dav_stamp = if (dav_path) |path| try refs.fileStamp(a, path) else null;
    if (dav_stamp) |stamp| {
        if (std.mem.eql(u8, stamp, restore_stamp))
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
    if (snapshot.cases.len != 0) {
        const cases = try caseRows(restored);
        defer cases.finalize();
        for (snapshot.cases) |proof| {
            if (!try cases.step()) return error.RestoreErasureReconciliationRequired;
            const review = try readReview(a, cases);
            const owner = cases.columnInt64(2);
            const start = cases.columnInt64(3);
            if (start != proof.start_audit_id) return error.RestoreErasureReconciliationRequired;
            const identity = try matchReservation(a, restored, review, start, owner, now);
            const identity_sha = refs.digest(try std.json.Stringify.valueAlloc(a, identity, .{}));
            if (!std.mem.eql(u8, &proof.identity_sha256, &identity_sha)) return error.RestoreErasureIdentityChanged;
            const review_sha = refs.digest(try std.json.Stringify.valueAlloc(a, review, .{}));
            if (!std.mem.eql(u8, &proof.review_sha256, &review_sha)) return error.RestoreErasureReconciliationRequired;
            try review_store.verifyLocalOperationsDrained(restored, owner);
            hashValue(&hash, &identity_sha);
            hashValue(&hash, &review_sha);
            for (steps, proof.steps_sha256) |action, fingerprint|
                try matchAudit(restored, review.mailbox, start, action, fingerprint, &hash);
            try maildir.requireRestoredAbsent(a, io, restored, root, review.mailbox, start);
            try search.requireRemoved(restored, review, start, owner);
            try private_sqlite.requireRemoved(restored, review, start, owner);
            _ = try shared.requireRemoved(a, restored, review, start, owner);
            _ = try links.requireRemoved(restored, review, start, owner);
            try content.verifyRemoved(restored, owner, review.mailbox);
            try verifyDav(a, proof, restored, restored_dav, review, start, owner, &hash);
            newest = start;
        }
        if (try cases.step()) return error.RestoreErasureReconciliationRequired;
    }
    if (!std.mem.eql(u8, restore_stamp, try refs.fileStamp(a, restored_path))) return error.RestoreErasureDatabaseChanged;

    if (dav_path) |path| {
        if (!std.mem.eql(u8, dav_stamp.?, try refs.fileStamp(a, path))) return error.RestoreErasureDatabaseChanged;
    }

    return .{
        .checked_at = now,
        .authority_observed_at = snapshot.observed_at,
        .reservations_checked = snapshot.cases.len,
        .authority_sha256 = std.fmt.bytesToHex(hash.finalResult(), .lower),
        .newest_reservation_audit_id = newest,
    };
}
