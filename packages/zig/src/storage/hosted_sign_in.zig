//! Single-use browser sign-in proofs issued by the private hosted control plane.
const std = @import("std");
const database = @import("database.zig");
const PasswordHasher = @import("../auth/password.zig").PasswordHasher;
const time = @import("../core/time_compat.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const ttl_seconds = 120;
pub const schema =
    \\CREATE TABLE IF NOT EXISTS hosted_sign_in_proofs (
    \\    digest BLOB PRIMARY KEY NOT NULL,
    \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    \\    actor TEXT NOT NULL,
    \\    expires_at INTEGER NOT NULL
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

pub fn exchange(db: *database.Database, proof: []const u8, session: []const u8, csrf: []const u8, previous: ?[]const u8, now: i64, session_expires: i64) !void {
    var hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(proof, &hash, .{});
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    {
        const add = try tx.prepare(
            \\INSERT INTO webmail_sessions(session_id, username, email, csrf_secret, created_at, last_activity, expires_at)
            \\SELECT ?1, u.username, u.email, ?2, ?3, ?3, ?4 FROM hosted_sign_in_proofs h
            \\JOIN provisioned_mailboxes p ON p.user_id = h.user_id AND p.actor = h.actor
            \\JOIN users u ON u.id = h.user_id AND u.username = p.mailbox
            \\WHERE h.digest = ?5 AND h.expires_at > ?3 AND u.enabled = 1
            \\  AND (p.read_until IS NULL OR p.read_until > ?3)
            \\RETURNING session_id
        );
        defer add.finalize();
        try add.bind(1, session);
        try add.bind(2, csrf);
        try add.bind(3, now);
        try add.bind(4, session_expires);
        try add.bindBlob(5, &hash);
        if (!try add.step()) return error.InvalidProof;
    }
    {
        const consume = try tx.prepare("DELETE FROM hosted_sign_in_proofs WHERE digest = ?1");
        defer consume.finalize();
        try consume.bindBlob(1, &hash);
        _ = try consume.step();
    }
    if (previous) |old| {
        const retire = try tx.prepare("DELETE FROM webmail_sessions WHERE session_id = ?1");
        defer retire.finalize();
        try retire.bind(1, old);
        _ = try retire.step();
    }
    try tx.commit();
}
