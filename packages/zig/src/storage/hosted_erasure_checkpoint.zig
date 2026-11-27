//! Sign redacted lifecycle evidence for a recovery host without the original SQLite database.
const std = @import("std");
const maildir_store = @import("hosted_erasure_maildir.zig");
const database = @import("database.zig");
const replay_evidence = @import("hosted_erasure_replay_evidence.zig");
const review_store = @import("hosted_erasure_review.zig");
const restore = @import("hosted_erasure_restore.zig");
const preflight = @import("hosted_erasure_preflight.zig");
const refs = @import("message_refs.zig");
const clock = @import("../core/time_compat.zig");

const Allocator = std.mem.Allocator;
const Ed25519 = std.crypto.sign.Ed25519;
const purpose = "mail.erasure.authority.v1";
const Replay = struct {
    original_checkpoint_sha256: restore.Digest,
    approval_reference: []const u8,
};
const Payload = struct {
    purpose: []const u8 = purpose,
    scope: []const u8,
    state: restore.Snapshot,
    replay: ?Replay = null,
};
pub const Document = struct {
    payload: Payload,
    public_key: restore.Digest,
    signature: [Ed25519.Signature.encoded_length * 2]u8,
};

const WireDocument = struct {
    payload: std.json.Value,
    public_key: restore.Digest,
    signature: [Ed25519.Signature.encoded_length * 2]u8,
};
const Authenticated = struct { payload: Payload, digest: restore.Digest };
const TargetReceipt = struct {
    state: []const u8 = "erasure_replay_target_verified",
    checkpoint_sha256: restore.Digest,
    source_start_audit_id: i64,
};
const ReplayChain = struct {
    version: u8 = 1,
    state: []const u8 = "erasure_replay_chain_verified",
    scope: []const u8,
    source_checkpoint_sha256: restore.Digest,
    replay_checkpoint_sha256: restore.Digest,
    source_observed_at: i64,
    replay_observed_at: i64,
    case_sha256: restore.Digest,
    source_start_audit_id: i64,
    replay_start_audit_id: i64,
    recovery_approval_reference: []const u8,
};
pub const ReplayChainReceipt = struct {
    evidence: ReplayChain,
    evidence_sha256: restore.Digest,
};
pub const Pin = struct {
    scope: []const u8,
    public_key: []const u8,
    sha256: []const u8,
    not_before: i64,
};
pub const ReplayChainInput = struct {
    source_checkpoint_path: []const u8,
    replay_checkpoint_path: []const u8,
    pin: Pin,
    replay_sha256: []const u8,
};

fn read(a: Allocator, io: std.Io, path: []const u8, limit: u64, comptime private: bool) ![]u8 {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{ .follow_symlinks = false, .allow_directory = false });
    defer file.close(io);
    const info = try file.stat(io);
    if (info.kind != .file or info.size == 0 or info.size > limit) return error.InvalidErasureCheckpointFile;
    if (private and info.permissions.toMode() & 0o077 != 0) return error.ErasureCheckpointKeyNotPrivate;
    const bytes = try a.alloc(u8, @intCast(info.size));
    errdefer a.free(bytes);
    var input_buffer: [4096]u8 = undefined;
    var input = file.reader(io, &input_buffer);
    try input.interface.readSliceAll(bytes);
    return bytes;
}

fn decode(comptime length: usize, value: []const u8) ![length]u8 {
    if (value.len != length * 2) return error.InvalidErasureCheckpointEncoding;
    var result: [length]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch return error.InvalidErasureCheckpointEncoding;
    return result;
}

pub fn seal(a: Allocator, io: std.Io, authority: []const u8, scope: []const u8, seed_path: []const u8) !Document {
    if (!preflight.validCaseReference(scope)) return error.InvalidErasureCheckpointScope;
    return sign(a, io, .{ .scope = scope, .state = try restore.capture(a, authority) }, seed_path, null);
}

fn sign(a: Allocator, io: std.Io, payload: Payload, seed_path: []const u8, expected_key: ?[]const u8) !Document {
    const raw = try read(a, io, seed_path, 128, true);
    defer std.crypto.secureZero(u8, raw);
    var seed = try decode(Ed25519.KeyPair.seed_length, std.mem.trim(u8, raw, &std.ascii.whitespace));
    defer std.crypto.secureZero(u8, &seed);
    var key = try Ed25519.KeyPair.generateDeterministic(seed);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key.secret_key));

    const public_key = std.fmt.bytesToHex(key.public_key.toBytes(), .lower);
    if (expected_key) |expected| {
        if (!std.mem.eql(u8, expected, &public_key)) return error.ErasureCheckpointKeyMismatch;
    }
    const bytes = try std.json.Stringify.valueAlloc(a, payload, .{});
    var noise: [Ed25519.noise_length]u8 = undefined;
    io.random(&noise);
    const signature = try key.sign(bytes, noise);
    return .{
        .payload = payload,
        .public_key = public_key,
        .signature = std.fmt.bytesToHex(signature.toBytes(), .lower),
    };
}

fn authenticate(a: Allocator, io: std.Io, path: []const u8, pin: Pin) !Authenticated {
    if (!preflight.validCaseReference(pin.scope) or pin.not_before < 1) return error.InvalidErasureCheckpointPin;
    const bytes = try read(a, io, path, 64 * 1024 * 1024, false);
    const digest = refs.digest(bytes);
    if (!std.mem.eql(u8, &digest, pin.sha256)) return error.ErasureCheckpointPinMismatch;
    const document = try std.json.parseFromSliceLeaky(WireDocument, a, bytes, .{});
    if (!std.mem.eql(u8, &document.public_key, pin.public_key)) return error.ErasureCheckpointKeyMismatch;
    const key = try Ed25519.PublicKey.fromBytes(try decode(Ed25519.PublicKey.encoded_length, pin.public_key));
    const signature = Ed25519.Signature.fromBytes(try decode(Ed25519.Signature.encoded_length, &document.signature));
    // Verify the fields actually signed by the publisher before decoding into
    // a newer schema. Defaults added after publication must not change them.
    const message = try std.json.Stringify.valueAlloc(a, document.payload, .{});
    signature.verifyStrict(message, key) catch return error.InvalidErasureCheckpointSignature;
    const payload = try std.json.parseFromSliceLeaky(Payload, a, message, .{});
    if (!std.mem.eql(u8, payload.purpose, purpose) or !std.mem.eql(u8, payload.scope, pin.scope))
        return error.InvalidErasureCheckpointScope;
    if (payload.state.observed_at < pin.not_before or payload.state.observed_at > clock.timestamp())
        return error.ErasureCheckpointStale;
    return .{ .payload = payload, .digest = digest };
}

pub fn verify(a: Allocator, io: std.Io, path: []const u8, pin: Pin, restored_db: []const u8, maildir: []const u8, dav: ?[]const u8) !restore.Receipt {
    const authority = try authenticate(a, io, path, pin);
    var receipt = if (authority.payload.replay != null)
        try restore.verifyReplaySnapshot(a, io, authority.payload.state, restored_db, maildir, dav)
    else
        try restore.verifySnapshot(a, io, authority.payload.state, restored_db, maildir, dav);
    receipt.source = "signed_erasure_checkpoint";
    receipt.checkpoint_sha256 = authority.digest;
    if (authority.payload.replay) |replay| {
        receipt.source = "signed_erasure_replay";
        receipt.replayed_from_sha256 = replay.original_checkpoint_sha256;
        receipt.recovery_approval_reference = replay.approval_reference;
    }
    return receipt;
}

pub fn checkReplayTarget(a: Allocator, io: std.Io, path: []const u8, pin: Pin, restored_db: []const u8, review_path: []const u8, isolate_maildir: ?[]const u8) !TargetReceipt {
    const authority = try authenticate(a, io, path, pin);
    const raw = try read(a, io, review_path, 8192, true);
    const review = try std.json.parseFromSliceLeaky(review_store.Review, a, raw, .{});
    try review.validate();
    const stamp = try refs.fileStamp(a, restored_db);
    if (isolate_maildir != null and !std.mem.eql(u8, stamp, try refs.fileStamp(a, "smtp.db")))
        return error.RestoreErasureIsolationRootMismatch;
    var root = if (isolate_maildir) |path_to_lock| try maildir_store.openLockedRoot(a, io, path_to_lock) else null;
    defer if (root) |*lock| lock.close(io);
    var db = if (isolate_maildir != null)
        try database.Database.openReadWriteExisting(a, restored_db)
    else
        try database.Database.openReadOnly(a, restored_db);
    defer db.deinit();
    var tx = try db.beginTransaction(if (isolate_maildir == null) .read else .write);
    defer tx.deinit();
    const now = clock.timestamp();
    const assignment = try preflight.identify(a, tx, review.mailbox, review.assignment_actor, now);
    try restore.requireSingleAddress(tx, review.mailbox, assignment.identity.native_user_id);
    const expected = try replay_evidence.caseIdentity(a, review, assignment.identity);
    for (authority.payload.state.cases) |original| {
        const proof = original.replay orelse continue;
        if (!std.mem.eql(u8, &proof.identity, &expected)) continue;
        if (!restore.caseComplete(original)) return error.RestoreErasureAuthorityIncomplete;
        if (!std.mem.eql(u8, stamp, try refs.fileStamp(a, restored_db))) return error.RestoreErasureDatabaseChanged;
        if (isolate_maildir != null) {
            // Linked sessions are the subject of their own reviewed step.
            // Quiescing the restored mailbox must not cascade their deletion.
            const update = try tx.prepare(
                \\UPDATE users SET enabled=0,updated_at=?1 WHERE id=?2 AND enabled<>0 RETURNING id
            );
            defer update.finalize();
            try update.bind(1, now);
            try update.bind(2, assignment.identity.native_user_id);
            if (try update.step()) {
                if (try update.step()) return error.StepFailed;
                const details = try std.json.Stringify.valueAlloc(a, .{
                    .checkpoint_sha256 = authority.digest,
                    .source_start_audit_id = original.start_audit_id,
                    .request_id = review.request_id,
                }, .{});
                _ = try review_store.writeAudit(tx, "hosted.erasure.restore.isolated", review.mailbox, "local-recovery", now, details);
            }
        }
        try tx.commit();
        return .{
            .state = if (isolate_maildir != null) "erasure_replay_target_isolated" else "erasure_replay_target_verified",
            .checkpoint_sha256 = authority.digest,
            .source_start_audit_id = original.start_audit_id,
        };
    }
    return error.RestoreErasureReplayCaseMismatch;
}

fn requireReplayCoverage(a: Allocator, original: restore.Snapshot, candidate: restore.Snapshot) !void {
    if (original.cases.len == 0 or original.cases.len != candidate.cases.len)
        return error.RestoreErasureReplayCaseMismatch;
    var cases: std.AutoHashMapUnmanaged(restore.Digest, restore.Case) = .empty;
    defer cases.deinit(a);
    for (original.cases) |record| {
        if (!restore.caseComplete(record)) return error.RestoreErasureAuthorityIncomplete;
        const proof = record.replay orelse return error.RestoreErasureReplayEvidenceMissing;
        const entry = try cases.getOrPut(a, proof.identity);
        if (entry.found_existing) return error.RestoreErasureReplayCaseMismatch;
        entry.value_ptr.* = record;
    }
    for (candidate.cases) |record| {
        if (!restore.caseComplete(record)) return error.RestoreErasureReconciliationRequired;
        const proof = record.replay orelse return error.RestoreErasureReplayEvidenceMissing;
        const source = (cases.fetchRemove(proof.identity) orelse return error.RestoreErasureReplayCaseMismatch).value;
        if (source.dav_configured and !record.dav_configured) return error.RestoreErasureDavRequired;
        if (!std.mem.eql(u8, &source.replay.?.peer_copies, &proof.peer_copies))
            return error.RestoreErasurePeerCopyChanged;
    }
}

pub fn sealReplay(a: Allocator, io: std.Io, path: []const u8, pin: Pin, restored_db: []const u8, maildir: []const u8, dav: ?[]const u8, seed_path: []const u8, approval_reference: []const u8) !Document {
    if (!preflight.validCaseReference(approval_reference)) return error.InvalidErasureReplayApproval;
    const original = try authenticate(a, io, path, pin);
    const snapshot = try restore.capture(a, restored_db);
    if (snapshot.observed_at < original.payload.state.observed_at) return error.ErasureCheckpointStale;
    try requireReplayCoverage(a, original.payload.state, snapshot);
    _ = try restore.verifyReplaySnapshot(a, io, snapshot, restored_db, maildir, dav);
    return sign(a, io, .{
        .scope = pin.scope,
        .state = snapshot,
        .replay = .{ .original_checkpoint_sha256 = original.digest, .approval_reference = approval_reference },
    }, seed_path, pin.public_key);
}

pub fn verifyReplayChain(a: Allocator, io: std.Io, path: []const u8, pin: Pin, replay_path: []const u8, replay_sha256: []const u8, authority_db: []const u8, review_path: []const u8) !ReplayChainReceipt {
    const raw = try read(a, io, review_path, 8192, true);
    const review = try std.json.parseFromSliceLeaky(review_store.Review, a, raw, .{});
    try review.validate();
    var db = try database.Database.openReadOnly(a, authority_db);
    defer db.deinit();
    var tx = try db.beginTransaction(.read);
    defer tx.deinit();
    return verifyReplayChainInTransaction(a, io, tx, review, clock.timestamp(), .{
        .source_checkpoint_path = path,
        .replay_checkpoint_path = replay_path,
        .pin = pin,
        .replay_sha256 = replay_sha256,
    });
}

pub fn verifyReplayChainInTransaction(a: Allocator, io: std.Io, tx: database.Database.Transaction, review: review_store.Review, now: i64, input: ReplayChainInput) !ReplayChainReceipt {
    const original = try authenticate(a, io, input.source_checkpoint_path, input.pin);
    const recovered = try authenticate(a, io, input.replay_checkpoint_path, .{
        .scope = input.pin.scope,
        .public_key = input.pin.public_key,
        .sha256 = input.replay_sha256,
        .not_before = original.payload.state.observed_at,
    });
    const replay = recovered.payload.replay orelse return error.MissingErasureReplayEvidence;
    if (!std.mem.eql(u8, &original.digest, &replay.original_checkpoint_sha256))
        return error.RestoreErasureReplaySourceMismatch;
    if (!preflight.validCaseReference(replay.approval_reference)) return error.InvalidErasureReplayApproval;
    try requireReplayCoverage(a, original.payload.state, recovered.payload.state);

    const assignment = try preflight.identify(a, tx, review.mailbox, review.assignment_actor, now);
    try restore.requireSingleAddress(tx, review.mailbox, assignment.identity.native_user_id);
    const identity = try replay_evidence.caseIdentity(a, review, assignment.identity);

    const source_case = for (original.payload.state.cases) |record| {
        if (std.mem.eql(u8, &record.replay.?.identity, &identity)) break record;
    } else return error.RestoreErasureReplayCaseMismatch;
    const replay_case = for (recovered.payload.state.cases) |record| {
        if (std.mem.eql(u8, &record.replay.?.identity, &identity)) break record;
    } else return error.RestoreErasureReplayCaseMismatch;
    _ = try review_store.requireStarted(a, tx, review, source_case.start_audit_id, now);

    const evidence: ReplayChain = .{
        .scope = input.pin.scope,
        .source_checkpoint_sha256 = original.digest,
        .replay_checkpoint_sha256 = recovered.digest,
        .source_observed_at = original.payload.state.observed_at,
        .replay_observed_at = recovered.payload.state.observed_at,
        .case_sha256 = identity,
        .source_start_audit_id = source_case.start_audit_id,
        .replay_start_audit_id = replay_case.start_audit_id,
        .recovery_approval_reference = replay.approval_reference,
    };
    return .{
        .evidence = evidence,
        .evidence_sha256 = try replayEvidenceDigest(a, evidence),
    };
}

pub fn replayEvidenceDigest(a: Allocator, evidence: ReplayChain) !restore.Digest {
    return refs.digest(try std.json.Stringify.valueAlloc(a, evidence, .{}));
}
