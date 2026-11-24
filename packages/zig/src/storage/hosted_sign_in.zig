//! Single-use browser sign-in proofs issued by the private hosted control plane.
const std = @import("std");
const database = @import("database.zig");
const PasswordHasher = @import("../auth/password.zig").PasswordHasher;
const time = @import("../core/time_compat.zig");
const mfa = @import("webmail_mfa.zig");
const security = @import("../auth/security.zig");
const Tx = database.Database.Transaction;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const ttl_seconds = 120;
pub const schema =
    \\CREATE TABLE IF NOT EXISTS hosted_sign_in_proofs (
    \\    digest BLOB PRIMARY KEY NOT NULL,
    \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    \\    actor TEXT NOT NULL,
    \\    expires_at INTEGER NOT NULL
    \\);
    \\CREATE TABLE IF NOT EXISTS hosted_sign_in_factors (
    \\    digest BLOB PRIMARY KEY REFERENCES hosted_sign_in_proofs(digest) ON DELETE CASCADE,
    \\    previous_session TEXT
    \\);
    \\CREATE INDEX IF NOT EXISTS hosted_sign_in_expiry ON hosted_sign_in_proofs(expires_at);
    \\CREATE INDEX IF NOT EXISTS hosted_sign_in_user ON hosted_sign_in_proofs(user_id);
    \\CREATE TRIGGER IF NOT EXISTS invalidate_hosted_sign_in_on_user_change
    \\AFTER UPDATE OF username, password_hash, enabled ON users
    \\WHEN OLD.username IS NOT NEW.username OR OLD.password_hash IS NOT NEW.password_hash OR OLD.enabled IS NOT NEW.enabled
    \\BEGIN
    \\    DELETE FROM hosted_sign_in_proofs WHERE user_id = OLD.id;
    \\END;
    \\CREATE TRIGGER IF NOT EXISTS invalidate_hosted_sign_in_on_assignment_change
    \\AFTER UPDATE OF mailbox, actor, user_id ON provisioned_mailboxes
    \\WHEN OLD.mailbox IS NOT NEW.mailbox OR OLD.actor IS NOT NEW.actor OR OLD.user_id IS NOT NEW.user_id
    \\BEGIN
    \\    DELETE FROM hosted_sign_in_proofs WHERE user_id = OLD.user_id;
    \\END;
    \\CREATE TRIGGER IF NOT EXISTS invalidate_hosted_sign_in_on_assignment_removal
    \\AFTER DELETE ON provisioned_mailboxes
    \\BEGIN
    \\    DELETE FROM hosted_sign_in_proofs WHERE user_id = OLD.user_id;
    \\END;
;

pub const IssueRequest = struct {
    mailbox: []const u8,
    actor: []const u8,
    password: ?[]const u8 = null,
};

fn verifyActivationPassword(db: *database.Database, a: std.mem.Allocator, input: IssueRequest, password: []const u8) ![]const u8 {
    if (password.len < 12 or password.len > 1024) return error.InvalidActivationPassword;
    const hash = blk: {
        var tx = try db.beginTransaction(.read);
        defer tx.deinit();
        const lookup = try tx.prepare(
            \\SELECT u.password_hash FROM provisioned_mailboxes p
            \\JOIN users u ON u.id = p.user_id AND u.username = p.mailbox
            \\WHERE p.mailbox = ?1 AND p.actor = ?2 AND u.enabled = 1
            \\  AND (p.read_until IS NULL OR p.read_until > unixepoch())
        );
        defer lookup.finalize();
        try lookup.bind(1, input.mailbox);
        try lookup.bind(2, input.actor);
        if (!try lookup.step()) return error.MailboxNotFound;
        break :blk try a.dupe(u8, lookup.columnText(0));
    };
    errdefer a.free(hash);
    // Argon2 runs outside the database lock. Issuance rechecks the verified
    // hash inside the write so a concurrent password reset fences this proof.
    var hasher = PasswordHasher.init(a);
    if (!try hasher.verifyPassword(password, hash)) return error.InvalidActivationPassword;
    return hash;
}

pub fn issue(db: *database.Database, a: std.mem.Allocator, proof: []const u8, input: IssueRequest) !i64 {
    const password_hash = if (input.password) |password| try verifyActivationPassword(db, a, input, password) else null;
    defer if (password_hash) |hash| a.free(hash);
    var hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(proof, &hash, .{});
    const now = time.timestamp();
    const expires = now + ttl_seconds;
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    {
        const sweep = try tx.prepare("DELETE FROM hosted_sign_in_proofs WHERE expires_at <= ?1");
        defer sweep.finalize();
        try sweep.bind(1, now);
        _ = try sweep.step();
    }
    {
        const proof_row = try tx.prepare(
            \\INSERT INTO hosted_sign_in_proofs(digest, user_id, actor, expires_at)
            \\SELECT ?1, u.id, p.actor, ?2 FROM provisioned_mailboxes p
            \\JOIN users u ON u.id = p.user_id AND u.username = p.mailbox
            \\WHERE p.mailbox = ?3 AND p.actor = ?4 AND u.enabled = 1
            \\  AND (p.read_until IS NULL OR p.read_until > ?5)
            \\  AND (?6 IS NULL OR u.password_hash = ?6)
            \\RETURNING user_id
        );
        defer proof_row.finalize();
        try proof_row.bindBlob(1, &hash);
        try proof_row.bind(2, expires);
        try proof_row.bind(3, input.mailbox);
        try proof_row.bind(4, input.actor);
        try proof_row.bind(5, now);
        try proof_row.bindOpt(6, password_hash);
        if (!try proof_row.step()) return error.MailboxNotFound;
    }
    try tx.commit();
    return expires;
}

const Digest = [Sha256.digest_length]u8;

fn factorDigest(token: []const u8) Digest {
    var hash = Sha256.init(.{});
    hash.update("hosted-webmail-factor:");
    hash.update(token);
    return hash.finalResult();
}

const eligible =
    \\ FROM hosted_sign_in_proofs h
    \\JOIN provisioned_mailboxes p ON p.user_id = h.user_id AND p.actor = h.actor
    \\JOIN users u ON u.id = h.user_id AND u.username = p.mailbox
    \\WHERE h.digest = ?1 AND h.expires_at > ?2 AND u.enabled = 1
    \\  AND (p.read_until IS NULL OR p.read_until > ?2)
;

fn consume(tx: Tx, digest: *const Digest) !void {
    const stmt = try tx.prepare("DELETE FROM hosted_sign_in_proofs WHERE digest = ?1");
    defer stmt.finalize();
    try stmt.bindBlob(1, digest);
    _ = try stmt.step();
}

pub const SessionRequest = struct {
    session: []const u8,
    csrf: []const u8,
    previous: ?[]const u8,
    now: i64,
    expires: i64,
};

fn startSession(tx: Tx, digest: *const Digest, input: SessionRequest, previous: ?[]const u8) !void {
    {
        const stmt = try tx.prepare(
            \\INSERT INTO webmail_sessions(session_id, username, email, csrf_secret, created_at, last_activity, expires_at)
            \\SELECT ?3, u.username, u.email, ?4, ?2, ?2, ?5
        ++ eligible ++ " RETURNING session_id");
        defer stmt.finalize();
        try stmt.bindBlob(1, digest);
        try stmt.bind(2, input.now);
        try stmt.bind(3, input.session);
        try stmt.bind(4, input.csrf);
        try stmt.bind(5, input.expires);
        if (!try stmt.step()) return error.InvalidProof;
    }
    const retire = try tx.prepare("DELETE FROM webmail_sessions WHERE session_id = ?1 OR session_id = ?2");
    defer retire.finalize();
    try retire.bindOpt(1, input.previous);
    try retire.bindOpt(2, previous);
    _ = try retire.step();
}

/// Spend the website proof on a session or a distinct, short-lived factor challenge.
pub fn exchange(db: *database.Database, proof: []const u8, challenge: []const u8, input: SessionRequest) !enum { session, factor } {
    var hash: Digest = undefined;
    Sha256.hash(proof, &hash, .{});
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const user_id = blk: {
        const stmt = try tx.prepare("SELECT u.id" ++ eligible);
        defer stmt.finalize();
        try stmt.bindBlob(1, &hash);
        try stmt.bind(2, input.now);
        if (!try stmt.step()) return error.InvalidProof;
        break :blk stmt.columnInt64(0);
    };
    const factor = try mfa.enabled(tx, user_id);
    if (factor) {
        const pending = factorDigest(challenge);
        {
            const stmt = try tx.prepare("UPDATE hosted_sign_in_proofs SET digest = ?1, expires_at = ?2 WHERE digest = ?3");
            defer stmt.finalize();
            try stmt.bindBlob(1, &pending);
            try stmt.bind(2, input.now + ttl_seconds);
            try stmt.bindBlob(3, &hash);
            _ = try stmt.step();
        }
        {
            const stmt = try tx.prepare("INSERT INTO hosted_sign_in_factors(digest, previous_session) VALUES (?1, ?2)");
            defer stmt.finalize();
            try stmt.bindBlob(1, &pending);
            try stmt.bindOpt(2, input.previous);
            _ = try stmt.step();
        }
    } else {
        try startSession(tx, &hash, input, null);
        try consume(tx, &hash);
    }
    try tx.commit();
    return if (factor) .factor else .session;
}

pub fn finishFactor(db: *database.Database, a: std.mem.Allocator, challenge: []const u8, code: []const u8, input: SessionRequest, key: ?*const mfa.Key, limiter: *security.RateLimiter) !void {
    const digest = factorDigest(challenge);
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const pending = blk: {
        const stmt = try tx.prepare("SELECT u.id, (SELECT f.previous_session FROM hosted_sign_in_factors f WHERE f.digest = h.digest)" ++ eligible ++
            " AND EXISTS (SELECT 1 FROM hosted_sign_in_factors f WHERE f.digest = h.digest)");
        defer stmt.finalize();
        try stmt.bindBlob(1, &digest);
        try stmt.bind(2, input.now);
        if (!try stmt.step()) return error.InvalidProof;
        break :blk .{ stmt.columnInt64(0), if (stmt.columnTextOpt(1)) |value| try a.dupe(u8, value) else null };
    };
    defer if (pending[1]) |old| a.free(old);
    if (!try mfa.enabled(tx, pending[0])) return error.InvalidProof;
    try mfa.limitAttempt(limiter, pending[0]);
    try mfa.authorizeSession(tx, key, pending[0], code, input.session, input.now);
    try startSession(tx, &digest, input, pending[1]);
    try consume(tx, &digest);
    try tx.commit();
}
