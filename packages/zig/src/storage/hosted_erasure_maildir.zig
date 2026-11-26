//! Reconcile the canonical Maildir of one reserved hosted mailbox offline.
const builtin = @import("builtin");
const std = @import("std");
const Database = @import("database.zig").Database;
const inventory = @import("hosted_erasure_inventory.zig");
const shared = @import("hosted_erasure_shared.zig");
const review_store = @import("hosted_erasure_review.zig");
const retained = @import("retained_thread_store.zig");
const threads = @import("../api/webmail_team_threads.zig");
const message_refs = @import("message_refs.zig");
const durable = @import("../core/durable_maildir.zig");
const io_compat = @import("../core/io_compat.zig");
const writer = @import("../core/maildir_writer.zig");
const time = @import("../core/time_compat.zig");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Phase = enum { planned, removing, complete };

const Step = struct {
    nonce: []const u8,
    root_stamp: []const u8,
    mailbox_stamp: ?[]const u8,
    phase: Phase,
    completion: ?i64 = null,
};

const Receipt = struct {
    version: u8 = 1,
    state: []const u8 = "maildir_removed_other_stores_pending",
    mailbox: []const u8,
    request_id: []const u8,
    start_audit_id: i64,
    audit_id: i64,
};

fn loadStep(a: Allocator, tx: Database.Transaction, start_id: i64) !?Step {
    const row = try tx.prepare(
        "SELECT nonce,root_stamp,mailbox_stamp,phase,completion_audit_id FROM hosted_erasure_maildir_steps WHERE start_audit_id=?1",
    );
    defer row.finalize();
    try row.bind(1, start_id);
    if (!try row.step()) return null;
    const nonce = row.columnText(0);
    if (nonce.len != 32) return error.InvalidErasureJournal;
    for (nonce) |byte| if (!std.ascii.isHex(byte)) return error.InvalidErasureJournal;
    const phase = std.meta.stringToEnum(Phase, row.columnText(3)) orelse return error.InvalidErasureJournal;
    const completion = if (row.columnIsNull(4)) null else row.columnInt64(4);
    if ((phase == .complete) != (completion != null)) return error.InvalidErasureJournal;
    return .{
        .nonce = try a.dupe(u8, nonce),
        .root_stamp = try a.dupe(u8, row.columnText(1)),
        .mailbox_stamp = if (row.columnTextOpt(2)) |stamp| try a.dupe(u8, stamp) else null,
        .phase = phase,
        .completion = completion,
    };
}

fn mountId(fd: std.c.fd_t, path: ?[:0]const u8) !u64 {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var stat: linux.Statx = std.mem.zeroes(linux.Statx);
        const result = linux.statx(fd, path orelse "", if (path == null) linux.AT.EMPTY_PATH else linux.AT.SYMLINK_NOFOLLOW, .{ .MNT_ID = true }, &stat);
        if (linux.errno(result) != .SUCCESS or !stat.mask.MNT_ID) return error.ErasureMountUnverified;
        return stat.mnt_id;
    }
    var stat: std.c.Stat = undefined;
    const result = if (path) |name| std.c.fstatat(fd, name, &stat, std.c.AT.SYMLINK_NOFOLLOW) else std.c.fstat(fd, &stat);
    if (result != 0) return error.ErasureMountUnverified;
    return @bitCast(@as(i64, stat.dev));
}

fn stampDirectory(a: Allocator, io: std.Io, root: Dir, name: []const u8, mount: u64) !?[]const u8 {
    var directory = root.openDir(io, name, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer directory.close(io);
    if (try mountId(directory.handle, null) != mount) return error.ErasureMountUnverified;
    return try message_refs.directoryHandleStamp(a, directory.handle);
}

fn sameStamp(first: ?[]const u8, second: ?[]const u8) bool {
    if (first) |stamp| return if (second) |other| std.mem.eql(u8, stamp, other) else false;
    return second == null;
}

fn walk(io: std.Io, dir: Dir, mount: u64, depth: usize, remove: bool) !void {
    if (depth > 16) return error.MaildirDepthLimit;
    if (try mountId(dir.handle, null) != mount) return error.ErasureMountUnverified;
    var entries = dir.iterate();
    while (try entries.next(io)) |entry| {
        var name_buffer: [4096]u8 = undefined;
        const name = try std.fmt.bufPrintSentinel(&name_buffer, "{s}", .{entry.name}, 0);
        if (try mountId(dir.handle, name) != mount) return error.ErasureMountUnverified;
        const stat = try dir.statFile(io, name, .{ .follow_symlinks = false });
        switch (stat.kind) {
            .file => {
                if (stat.nlink != 1) return error.SharedMaildirEntry;
                if (remove) try dir.deleteFile(io, name);
            },
            .directory => {
                {
                    var child = try dir.openDir(io, name, .{ .iterate = true, .follow_symlinks = false });
                    defer child.close(io);
                    try walk(io, child, mount, depth + 1, remove);
                }
                if (remove) try dir.deleteDir(io, name);
            },
            else => return error.InventoryUnresolved,
        }
    }
    if (remove) try durable.syncFd(dir.handle);
}

fn walkMailbox(a: Allocator, io: std.Io, root: Dir, name: []const u8, stamp: []const u8, mount: u64, remove: bool) !void {
    var dir = try root.openDir(io, name, .{ .iterate = true, .follow_symlinks = false });
    defer dir.close(io);
    if (!std.mem.eql(u8, stamp, try message_refs.directoryHandleStamp(a, dir.handle))) return error.ErasureDirectoryChanged;
    try walk(io, dir, mount, 0, remove);
}

fn markRemoving(tx: Database.Transaction, start_id: i64) !void {
    const row = try tx.prepare("UPDATE hosted_erasure_maildir_steps SET phase='removing' WHERE start_audit_id=?1 AND phase='planned'");
    defer row.finalize();
    try row.bind(1, start_id);
    if (try row.step()) return error.StepFailed;
}

pub fn openLockedRoot(a: Allocator, io: std.Io, mail_root: []const u8) !Dir {
    // A Linux path-only descriptor cannot take flock or sync directory entries.
    var root = try Dir.cwd().openDir(io, "mail", .{ .iterate = true });
    errdefer root.close(io);
    try writer.lock(root.handle);
    var configured = try Dir.cwd().openDir(io, mail_root, .{});
    defer configured.close(io);
    const root_stamp = try message_refs.directoryHandleStamp(a, root.handle);
    if (!std.mem.eql(u8, root_stamp, try message_refs.directoryHandleStamp(a, configured.handle)))
        return error.ErasureDirectoryChanged;
    return root;
}

/// Recheck the recorded removal while the caller holds the same writer lock.
pub fn requireRemoved(a: Allocator, io: std.Io, tx: Database.Transaction, root: Dir, mailbox: []const u8, start_id: i64) !void {
    const step = (try loadStep(a, tx, start_id)) orelse return error.ErasureMaildirPending;
    const completion = step.completion orelse return error.ErasureMaildirPending;
    const audit = try tx.prepare(
        \\SELECT id FROM audit_log WHERE id=?1 AND action='hosted.erasure.maildir.removed'
        \\AND target=?2 AND target_type='hosted_mailbox' AND json_extract(details,'$.start_audit_id')=?3
    );
    defer audit.finalize();
    try audit.bind(1, completion);
    try audit.bind(2, mailbox);
    try audit.bind(3, start_id);
    if (!try audit.step()) return error.InvalidErasureJournal;
    const root_stamp = try message_refs.directoryHandleStamp(a, root.handle);
    if (!std.mem.eql(u8, root_stamp, step.root_stamp)) return error.ErasureDirectoryChanged;
    const staged = try std.fmt.allocPrint(a, ".hosted-erasure-{d}-{s}", .{ start_id, step.nonce });
    const short = mailbox[0 .. std.mem.indexOfScalar(u8, mailbox, '@') orelse return error.InvalidErasureMailbox];
    for ([_][]const u8{ mailbox, staged, short }) |name| {
        _ = root.statFile(io, name, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        return error.ErasureDirectoryChanged;
    }
}

const ArchiveProof = struct {
    share_id: []const u8,
    peer_user_id: i64,
    sha256: [64]u8,
};

const ArchiveReceipt = struct {
    mailbox: []const u8,
    start_audit_id: i64,
    approval_audit_id: i64,
    audit_id: i64,
    archives: []ArchiveProof,
};

fn ensureArchives(a: Allocator, tx: Database.Transaction, release: shared.Release, now: i64) !void {
    for (release.archives) |item| _ = try retained.accessiblePeer(a, tx, item.peer_user_id, now);
}

fn requireRelease(a: Allocator, tx: Database.Transaction, review: review_store.Review, start_id: i64, owner: i64) !?i64 {
    const release = (try shared.requireRelease(a, tx, review, start_id, owner, .maildir)) orelse return null;
    if (release.archives.len == 0) return null;
    try ensureArchives(a, tx, release, time.timestamp());
    _ = (try archiveReceipt(a, tx, review.mailbox, start_id, release)) orelse return error.ErasureThreadArchivePending;
    return release.audit_id;
}

/// Recheck authorization before removing live SQLite parents that used
/// the completed Maildir. The archived copies have independent ownership.
pub fn requireSharedRecordsRelease(a: Allocator, tx: Database.Transaction, review: review_store.Review, start_id: i64, owner: i64) !?i64 {
    const chosen = try retained.chosen(tx, start_id);
    const release = (try shared.requireRelease(a, tx, review, start_id, owner, .maildir)) orelse {
        if (chosen != null) return error.ErasureSharedScopeChanged;
        return null;
    };
    if (release.archives.len != 0) {
        if (chosen != release.audit_id) return error.ErasureSharedScopeChanged;
        _ = (try archiveReceipt(a, tx, review.mailbox, start_id, release)) orelse return error.ErasureThreadArchivePending;
    } else if (chosen != null) return error.ErasureSharedScopeChanged;
    return release.audit_id;
}

/// Stage immutable copies while the approved source is still available. The
/// reader can discover them only after the audited Maildir removal succeeds.
pub fn retainThreads(a: Allocator, io: std.Io, db: *Database, review: review_store.Review, start_id: i64, operator: []const u8, mail_root: []const u8, dav_path: ?[]const u8, junk: []const u8) !ArchiveReceipt {
    try review.validate();
    if (start_id < 1) return error.InvalidErasureStartAuditId;
    var root = try openLockedRoot(a, io, mail_root);
    defer root.close(io);
    const mount = try mountId(root.handle, null);
    const step = blk: {
        var tx = try db.beginTransaction(.read);
        defer tx.deinit();
        const now = time.timestamp();
        const observation = try review_store.requireStarted(a, tx, review, start_id, now);
        const owner = observation.identity.native_user_id;
        if (try loadStep(a, tx, start_id)) |completed| {
            if (completed.phase == .complete) {
                try requireRemoved(a, io, tx, root, review.mailbox, start_id);
                const chosen = (try retained.chosen(tx, start_id)) orelse return error.ErasureThreadArchiveNotAuthorized;
                const release = try shared.recordedArchiveRelease(a, tx, review, start_id, owner, chosen);
                const receipt = (try archiveReceipt(a, tx, review.mailbox, start_id, release)) orelse return error.InvalidErasureJournal;
                try tx.commit();
                return receipt;
            }
        }
        const release = (try shared.requireRelease(a, tx, review, start_id, owner, .maildir)) orelse
            return error.ErasureThreadArchiveNotAuthorized;
        if (release.archives.len == 0) return error.ErasureThreadArchiveNotAuthorized;
        const peers = try a.alloc([]const u8, release.archives.len);
        for (release.archives, peers) |item, *peer| peer.* = try retained.accessiblePeer(a, tx, item.peer_user_id, now);
        const prior = try archiveReceipt(a, tx, review.mailbox, start_id, release);
        try tx.commit();
        if (prior) |receipt| return receipt;
        break :blk .{ .owner = owner, .release = release, .peers = peers };
    };

    const before = (try stampDirectory(a, io, root, review.mailbox, mount)) orelse return error.ErasureDirectoryChanged;
    const sampled = try inventory.collect(a, io, db, review.mailbox, review.assignment_actor, "mail", dav_path);
    {
        var tx = try db.beginTransaction(.read);
        defer tx.deinit();
        const observation = try review_store.requireStarted(a, tx, review, start_id, time.timestamp());
        try review_store.verifyCurrent(a, tx, review, observation, sampled);
        try tx.commit();
    }
    try walkMailbox(a, io, root, review.mailbox, before, mount, false);
    const payloads = try a.alloc([]const u8, step.release.archives.len);
    var remaining: usize = retained.max_bytes;
    for (step.release.archives, step.peers, payloads) |item, peer, *payload| {
        payload.* = try threads.capture(a, db, peer, item.source_share_id, step.owner, junk, remaining);
        remaining -= payload.len;
    }
    try walkMailbox(a, io, root, review.mailbox, before, mount, false);

    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const now = time.timestamp();
    const observation = try review_store.requireStarted(a, tx, review, start_id, now);
    const release = (try shared.requireRelease(a, tx, review, start_id, observation.identity.native_user_id, .maildir)) orelse
        return error.ErasureSharedScopeChanged;
    if (release.audit_id != step.release.audit_id or observation.identity.native_user_id != step.owner)
        return error.ErasureSharedScopeChanged;
    try retained.discardSuperseded(tx, start_id, release.audit_id);
    const proofs = try a.alloc(ArchiveProof, release.archives.len);
    for (release.archives, step.peers, payloads, proofs) |item, peer, payload, *proof| {
        if (!std.mem.eql(u8, peer, try retained.accessiblePeer(a, tx, item.peer_user_id, now)))
            return error.ErasureSharedScopeChanged;
        proof.* = .{ .share_id = item.source_share_id, .peer_user_id = item.peer_user_id, .sha256 = try retained.save(tx, item, release.audit_id, payload) };
    }
    const details = try std.json.Stringify.valueAlloc(a, .{
        .start_audit_id = start_id,
        .approval_audit_id = release.audit_id,
        .request_id = review.request_id,
        .archives = proofs,
    }, .{});
    const audit = try review_store.writeAudit(tx, "hosted.erasure.threads.archived", review.mailbox, operator, now, details);
    try tx.commit();
    return .{ .mailbox = review.mailbox, .start_audit_id = start_id, .approval_audit_id = release.audit_id, .audit_id = audit, .archives = proofs };
}

fn archiveReceipt(a: Allocator, tx: Database.Transaction, mailbox: []const u8, start: i64, release: shared.Release) !?ArchiveReceipt {
    const row = try tx.prepare(
        \\SELECT id,json_extract(details,'$.archives') FROM audit_log
        \\WHERE action='hosted.erasure.threads.archived' AND target=?1 AND target_type='hosted_mailbox'
        \\ AND json_extract(details,'$.start_audit_id')=?2 AND json_extract(details,'$.approval_audit_id')=?3
    );
    defer row.finalize();
    try row.bind(1, mailbox);
    try row.bind(2, start);
    try row.bind(3, release.audit_id);
    if (!try row.step()) return null;
    const proofs = try std.json.parseFromSliceLeaky([]ArchiveProof, a, row.columnText(1), .{ .allocate = .alloc_always });
    if (proofs.len != release.archives.len) return error.ErasureThreadArchiveInvalid;
    for (proofs, release.archives) |proof, item| {
        const hash = (try retained.existing(tx, item, release.audit_id)) orelse return error.ErasureThreadArchiveInvalid;
        if (proof.peer_user_id != item.peer_user_id or !std.mem.eql(u8, proof.share_id, item.source_share_id) or
            !std.mem.eql(u8, &proof.sha256, &hash)) return error.ErasureThreadArchiveInvalid;
    }
    return .{ .mailbox = mailbox, .start_audit_id = start, .approval_audit_id = release.audit_id, .audit_id = row.columnInt64(0), .archives = proofs };
}

pub fn erase(a: Allocator, io: std.Io, db: *Database, review: review_store.Review, start_id: i64, operator: []const u8, mail_root: []const u8, dav_path: ?[]const u8) !Receipt {
    try review.validate();
    if (start_id < 1) return error.InvalidErasureStartAuditId;
    var root = try openLockedRoot(a, io, mail_root);
    defer root.close(io);
    const mount = try mountId(root.handle, null);
    const root_stamp = try message_refs.directoryHandleStamp(a, root.handle);
    const sampled = try inventory.collect(a, io, db, review.mailbox, review.assignment_actor, "mail", dav_path);

    var resumed_plan = false;
    var step = blk: {
        var tx = try db.beginTransaction(.write);
        defer tx.deinit();
        const observation = try review_store.requireStarted(a, tx, review, start_id, time.timestamp());
        if (try loadStep(a, tx, start_id)) |existing| {
            resumed_plan = existing.phase == .planned;
            if (resumed_plan and existing.mailbox_stamp != null)
                _ = try requireRelease(a, tx, review, start_id, observation.identity.native_user_id);
            try tx.commit();
            break :blk existing;
        }

        try review_store.verifyCurrent(a, tx, review, observation, sampled);
        const stamp = try stampDirectory(a, io, root, review.mailbox, mount);
        if ((stamp != null) != (sampled.maildir.state == .observed)) return error.ErasureDirectoryChanged;
        if (stamp) |value| {
            _ = try requireRelease(a, tx, review, start_id, observation.identity.native_user_id);
            try walkMailbox(a, io, root, review.mailbox, value, mount, false);
        }
        var bytes: [16]u8 = undefined;
        io_compat.randomBytes(&bytes);
        const nonce = try a.dupe(u8, &std.fmt.bytesToHex(bytes, .lower));
        const row = try tx.prepare(
            \\INSERT INTO hosted_erasure_maildir_steps(start_audit_id,nonce,root_stamp,mailbox_stamp,phase)
            \\VALUES(?1,?2,?3,?4,'planned')
        );
        defer row.finalize();
        try row.bind(1, start_id);
        try row.bind(2, nonce);
        try row.bind(3, root_stamp);
        try row.bindOpt(4, stamp);
        if (try row.step()) return error.StepFailed;
        try tx.commit();
        break :blk Step{ .nonce = nonce, .root_stamp = root_stamp, .mailbox_stamp = stamp, .phase = .planned };
    };

    if (!std.mem.eql(u8, root_stamp, step.root_stamp)) return error.ErasureDirectoryChanged;
    if (sampled.maildir.legacy_short_name_present != false) return error.InventoryUnresolved;
    const staged_name = try std.fmt.allocPrint(a, ".hosted-erasure-{d}-{s}", .{ start_id, step.nonce });
    const live = try stampDirectory(a, io, root, review.mailbox, mount);
    var staged = try stampDirectory(a, io, root, staged_name, mount);
    if (step.phase == .planned) {
        if (step.mailbox_stamp) |stamp| {
            if (sameStamp(live, stamp) and staged == null) {
                if (resumed_plan) {
                    var tx = try db.beginTransaction(.read);
                    defer tx.deinit();
                    const observation = try review_store.requireStarted(a, tx, review, start_id, time.timestamp());
                    try review_store.verifyCurrent(a, tx, review, observation, sampled);
                    try tx.commit();
                }
                try walkMailbox(a, io, root, review.mailbox, stamp, mount, false);
                try Dir.renamePreserve(root, review.mailbox, root, staged_name, io);
                staged = try stampDirectory(a, io, root, staged_name, mount);
            } else if (live != null) return error.ErasureDirectoryChanged;
            if (!sameStamp(staged, stamp)) return error.ErasureDirectoryChanged;
        } else if (live != null or staged != null) return error.ErasureDirectoryChanged;

        try durable.syncFd(root.handle);
        var tx = try db.beginTransaction(.write);
        defer tx.deinit();
        const observation = try review_store.requireStarted(a, tx, review, start_id, time.timestamp());
        if (step.mailbox_stamp != null) {
            const approval = try requireRelease(a, tx, review, start_id, observation.identity.native_user_id);
            if (approval) |id| try retained.choose(tx, start_id, id);
            try retained.discardSuperseded(tx, start_id, approval);
        }
        try markRemoving(tx, start_id);
        try tx.commit();
        step.phase = .removing;
    } else if (live != null) return error.ErasureDirectoryChanged;

    if (step.phase == .removing) {
        var tx = try db.beginTransaction(.write);
        defer tx.deinit();
        const now = time.timestamp();
        const observation = try review_store.requireStarted(a, tx, review, start_id, now);
        if (staged) |stamp| {
            if (!sameStamp(staged, step.mailbox_stamp)) return error.ErasureDirectoryChanged;
            const approved = try requireRelease(a, tx, review, start_id, observation.identity.native_user_id);
            if (approved != try retained.chosen(tx, start_id)) return error.ErasureSharedScopeChanged;
            try walkMailbox(a, io, root, staged_name, stamp, mount, false);
            try walkMailbox(a, io, root, staged_name, stamp, mount, true);
            try root.deleteDir(io, staged_name);
        }
        try durable.syncFd(root.handle);
        if (try stampDirectory(a, io, root, review.mailbox, mount) != null or
            try stampDirectory(a, io, root, staged_name, mount) != null) return error.ErasureDirectoryChanged;

        const details = try std.json.Stringify.valueAlloc(a, .{
            .start_audit_id = start_id,
            .request_id = review.request_id,
            .case_reference = review.case_reference,
            .identity = observation.identity,
        }, .{});
        const id = try review_store.writeAudit(tx, "hosted.erasure.maildir.removed", review.mailbox, operator, now, details);
        const row = try tx.prepare(
            "UPDATE hosted_erasure_maildir_steps SET phase='complete',completion_audit_id=?2 WHERE start_audit_id=?1 AND phase='removing'",
        );
        defer row.finalize();
        try row.bind(1, start_id);
        try row.bind(2, id);
        if (try row.step()) return error.StepFailed;
        try tx.commit();
        step.completion = id;
    } else if (staged != null) return error.ErasureDirectoryChanged;
    return .{ .mailbox = review.mailbox, .request_id = review.request_id, .start_audit_id = start_id, .audit_id = step.completion.? };
}
