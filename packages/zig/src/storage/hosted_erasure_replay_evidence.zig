//! Compare completed recovery cases without copying mailbox content into the authority.
const std = @import("std");
const database = @import("database.zig");
const refs = @import("message_refs.zig");
const preflight = @import("hosted_erasure_preflight.zig");
const review_store = @import("hosted_erasure_review.zig");
const archive = @import("retained_thread_store.zig");
const calendar = @import("hosted_erasure_calendar_copy.zig");

const Allocator = std.mem.Allocator;
const Tx = database.Database.Transaction;
const Digest = [64]u8;
pub const Fingerprints = struct { identity: Digest, peer_copies: Digest };
const ThreadCopy = struct { share_id: []const u8, peer_user_id: i64, sha256: Digest };

pub fn caseIdentity(a: Allocator, review: review_store.Review, identity: preflight.Identity) !Digest {
    const initial = identity.initial_provisioning_operation orelse return error.RestoreErasureIdentityChanged;
    // Billing revisions can advance after a backup. The assignment and case
    // identity must survive independently of local audit sequence numbers.
    const json = try std.json.Stringify.valueAlloc(a, .{
        review.mailbox, review.assignment_actor, review.request_id, review.case_reference, identity.native_user_id, initial,
    }, .{});
    return refs.digest(json);
}

fn peerErased(tx: Tx, peer: i64) !bool {
    // The caller verifies every case in the candidate before accepting it.
    const row = try tx.prepare(
        \\SELECT 1 FROM hosted_erasure_operations o JOIN audit_log a ON a.target=o.mailbox
        \\ AND a.action='hosted.erasure.sqlite.content.removed' AND a.target_type='hosted_mailbox'
        \\ AND json_extract(a.details,'$.start_audit_id')=o.start_audit_id
        \\WHERE o.native_user_id=?1
    );
    defer row.finalize();
    try row.bind(1, peer);
    return row.step();
}

fn threadCopies(a: Allocator, tx: Tx, mailbox: []const u8, start: i64, verify_live: bool, digests: *std.ArrayList(Digest)) !void {
    const approval = (try archive.chosen(tx, start)) orelse return;
    const row = try tx.prepare(
        \\SELECT json_extract(details,'$.archives') FROM audit_log
        \\WHERE action='hosted.erasure.threads.archived' AND target=?1 AND target_type='hosted_mailbox'
        \\AND json_extract(details,'$.start_audit_id')=?2 AND json_extract(details,'$.approval_audit_id')=?3
        \\ORDER BY id LIMIT 2
    );
    defer row.finalize();
    try row.bind(1, mailbox);
    try row.bind(2, start);
    try row.bind(3, approval);
    if (!try row.step()) return error.InvalidErasureJournal;
    const copies = try std.json.parseFromSliceLeaky([]const ThreadCopy, a, row.columnText(0), .{ .allocate = .alloc_always });
    if (copies.len == 0 or try row.step()) return error.InvalidErasureJournal;
    for (copies) |copy| {
        if (verify_live and !try peerErased(tx, copy.peer_user_id)) {
            const current = (try archive.existing(tx, .{
                .source_share_id = copy.share_id,
                .peer_user_id = copy.peer_user_id,
            }, approval)) orelse return error.RestoreErasurePeerCopyMissing;
            if (!std.mem.eql(u8, &current, &copy.sha256)) return error.RestoreErasurePeerCopyChanged;
        }
        const normalized = try std.json.Stringify.valueAlloc(a, .{ "thread", copy.share_id, copy.peer_user_id, copy.sha256 }, .{});
        try digests.append(a, refs.digest(normalized));
    }
}

fn calendarCopies(a: Allocator, tx: Tx, dav: ?Tx, mailbox: []const u8, start: i64, verify_live: bool, digests: *std.ArrayList(Digest)) !void {
    const row = try tx.prepare(
        \\SELECT json_extract(details,'$.retained_calendar_copy_proof') FROM audit_log
        \\WHERE action='hosted.erasure.dav.removed' AND target=?1 AND target_type='hosted_mailbox'
        \\AND json_extract(details,'$.start_audit_id')=?2 ORDER BY id LIMIT 2
    );
    defer row.finalize();
    try row.bind(1, mailbox);
    try row.bind(2, start);
    if (!try row.step()) return;
    const text = row.columnTextOpt(0);
    const proof = if (text) |raw|
        try std.json.parseFromSliceLeaky(calendar.Proof, a, raw, .{ .allocate = .alloc_always })
    else
        null;
    if (try row.step()) return error.InvalidErasureJournal;
    if (proof) |record| for (record.copies) |copy| {
        if (verify_live and !try peerErased(tx, copy.copy.peer_user_id))
            try calendar.verifyRetained(dav orelse return error.RestoreErasureDavRequired, copy);
        // Destination IDs can be allocated again on replay. The source share,
        // recipient and exact retained event fingerprint must stay the same.
        const normalized = try std.json.Stringify.valueAlloc(a, .{
            "calendar", copy.copy.source_share_id, copy.copy.peer_user_id, copy.resources, copy.resources_sha256,
        }, .{});
        try digests.append(a, refs.digest(normalized));
    };
}

fn lessThan(_: void, left: Digest, right: Digest) bool {
    return std.mem.order(u8, &left, &right) == .lt;
}

pub fn capture(a: Allocator, tx: Tx, dav: ?Tx, review: review_store.Review, start: i64, identity: preflight.Identity, verify_live: bool) !Fingerprints {
    var digests: std.ArrayList(Digest) = .empty;
    defer digests.deinit(a);
    try threadCopies(a, tx, review.mailbox, start, verify_live, &digests);
    try calendarCopies(a, tx, dav, review.mailbox, start, verify_live, &digests);
    std.mem.sort(Digest, digests.items, {}, lessThan);
    return .{ .identity = try caseIdentity(a, review, identity), .peer_copies = refs.digest(std.mem.sliceAsBytes(digests.items)) };
}
