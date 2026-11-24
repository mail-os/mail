//! Durable verifier for interactive webmail sign-in. Callers authenticate the
//! primary credential and rate-limit attempts before consuming a factor.
const std = @import("std");
const database = @import("database.zig");
const random = @import("../core/io_compat.zig");
const Cipher = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const Hmac = std.crypto.auth.hmac.HmacSha1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const security = @import("../auth/security.zig");
const Tx = database.Database.Transaction;

pub const Key = [Cipher.key_length]u8;
const Secret = [20]u8;
const Sealed = [Cipher.nonce_length + Cipher.tag_length + @sizeOf(Secret)]u8;
pub const recovery_count = 10;
pub const RecoveryCodes = [recovery_count][32]u8;
const enrollment_ttl = 10 * 60;
const step_seconds = 30;

pub const schema =
    \\CREATE TABLE IF NOT EXISTS webmail_mfa_factors (
    \\    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    \\    secret BLOB NOT NULL,
    \\    last_step INTEGER NOT NULL
    \\);
    \\CREATE TABLE IF NOT EXISTS webmail_mfa_enrollment (
    \\    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    \\    session_id TEXT NOT NULL REFERENCES webmail_sessions(session_id) ON DELETE CASCADE,
    \\    secret BLOB NOT NULL,
    \\    expires_at INTEGER NOT NULL
    \\);
    \\CREATE TABLE IF NOT EXISTS webmail_mfa_recovery_codes (
    \\    user_id INTEGER NOT NULL REFERENCES webmail_mfa_factors(user_id) ON DELETE CASCADE,
    \\    digest BLOB NOT NULL,
    \\    PRIMARY KEY (user_id, digest)
    \\);
    \\CREATE TABLE IF NOT EXISTS webmail_mfa_session_tickets (
    \\    session_id TEXT PRIMARY KEY NOT NULL,
    \\    user_id INTEGER NOT NULL REFERENCES webmail_mfa_factors(user_id) ON DELETE CASCADE
    \\);
    \\CREATE TRIGGER IF NOT EXISTS enforce_webmail_mfa_session_insert
    \\BEFORE INSERT ON webmail_sessions
    \\WHEN EXISTS (
    \\    SELECT 1 FROM webmail_mfa_factors f JOIN users u ON u.id = f.user_id
    \\    WHERE u.username = NEW.username
    \\)
    \\BEGIN
    \\    SELECT RAISE(ABORT, 'webmail session requires verified second factor') WHERE NOT EXISTS (
    \\        SELECT 1 FROM webmail_mfa_session_tickets t JOIN users u ON u.id = t.user_id
    \\        WHERE t.session_id = NEW.session_id AND u.username = NEW.username
    \\    );
    \\    DELETE FROM webmail_mfa_session_tickets WHERE session_id = NEW.session_id;
    \\END;
;

fn associatedData(user_id: i64) [23]u8 {
    var bytes: [23]u8 = undefined;
    bytes[0..15].* = "webmail-mfa-v1:".*;
    std.mem.writeInt(i64, bytes[15..23], user_id, .big);
    return bytes;
}

fn seal(secret: *const Secret, key: *const Key, user_id: i64) Sealed {
    var nonce: [Cipher.nonce_length]u8 = undefined;
    random.randomBytes(&nonce);
    var output: Sealed = undefined;
    output[0..Cipher.nonce_length].* = nonce;
    Cipher.encrypt(output[Cipher.nonce_length + Cipher.tag_length ..], output[Cipher.nonce_length..][0..Cipher.tag_length], secret, &associatedData(user_id), nonce, key.*);
    return output;
}

fn unseal(bytes: []const u8, key: *const Key, user_id: i64, secret: *Secret) !void {
    if (bytes.len != @sizeOf(Sealed)) return error.MfaUnavailable;
    const nonce = bytes[0..Cipher.nonce_length].*;
    const tag = bytes[Cipher.nonce_length..][0..Cipher.tag_length].*;
    Cipher.decrypt(secret, bytes[Cipher.nonce_length + Cipher.tag_length ..], tag, &associatedData(user_id), nonce, key.*) catch
        return error.MfaUnavailable;
}

fn base32(secret: Secret) [32]u8 {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    var output: [32]u8 = undefined;
    for (0..4) |group| {
        const bits = std.mem.readInt(u40, secret[group * 5 ..][0..5], .big);
        for (0..8) |digit| {
            const shift: u6 = @intCast(35 - digit * 5);
            output[group * 8 + digit] = alphabet[(bits >> shift) & 31];
        }
    }
    return output;
}

fn totp(secret: *const Secret, step: i64) [6]u8 {
    var counter: [8]u8 = undefined;
    std.mem.writeInt(i64, &counter, step, .big);
    var digest: [Hmac.mac_length]u8 = undefined;
    Hmac.create(&digest, &counter, secret);
    const offset = digest[digest.len - 1] & 15;
    const number = std.mem.readInt(u32, digest[offset..][0..4], .big) & 0x7fffffff;
    var remaining = number % 1_000_000;
    var code: [6]u8 = undefined;
    for (0..code.len) |i| {
        code[code.len - 1 - i] = '0' + @as(u8, @intCast(remaining % 10));
        remaining /= 10;
    }
    return code;
}

fn matchingStep(secret: *const Secret, code: []const u8, now: i64, previous: i64) ?i64 {
    if (code.len != 6 or now < 0) return null;
    const current = @divFloor(now, step_seconds);
    for ([_]i64{ current, current - 1, current + 1 }) |step| {
        if (step < 0 or step <= previous) continue;
        if (std.crypto.timing_safe.eql([6]u8, totp(secret, step), code[0..6].*)) return step;
    }
    return null;
}

fn recoveryDigest(code: []const u8) ?[Sha256.digest_length]u8 {
    if (code.len != 32) return null;
    var normalized: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &normalized);
    for (code, &normalized) |byte, *out| {
        if (!std.ascii.isHex(byte)) return null;
        out.* = std.ascii.toLower(byte);
    }
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&normalized, &digest, .{});
    return digest;
}

pub fn limitAttempt(limiter: *security.RateLimiter, user_id: i64) !void {
    var buffer: [32]u8 = undefined;
    const rate_key = try std.fmt.bufPrint(&buffer, "webmail-factor:{d}", .{user_id});
    if (!try limiter.checkAndIncrementUser(rate_key)) return error.AuthenticationRateLimited;
}

pub fn enabled(tx: Tx, user_id: i64) !bool {
    const stmt = try tx.prepare("SELECT 1 FROM webmail_mfa_factors WHERE user_id = ?1");
    defer stmt.finalize();
    try stmt.bind(1, user_id);
    return stmt.step();
}

pub fn requireCurrentPassword(tx: Tx, user: database.User) !void {
    const stmt = try tx.prepare("SELECT 1 FROM users WHERE id = ?1 AND username = ?2 AND enabled AND password_hash = ?3");
    defer stmt.finalize();
    try stmt.bind(1, user.id);
    try stmt.bind(2, user.username);
    try stmt.bind(3, user.password_hash);
    if (!try stmt.step()) return error.InvalidEnrollment;
}

fn requireOwnerSession(tx: Tx, user_id: i64, session: []const u8, now: i64) !void {
    const stmt = try tx.prepare(
        \\SELECT 1 FROM users u JOIN webmail_sessions s ON s.username = u.username
        \\WHERE u.id = ?1 AND s.session_id = ?2 AND s.expires_at > ?3 AND u.enabled
    );
    defer stmt.finalize();
    try stmt.bind(1, user_id);
    try stmt.bind(2, session);
    try stmt.bind(3, now);
    if (!try stmt.step()) return error.InvalidEnrollment;
}

pub fn beginEnrollment(tx: Tx, key: *const Key, user_id: i64, session: []const u8, now: i64) ![32]u8 {
    try requireOwnerSession(tx, user_id, session, now);
    if (try enabled(tx, user_id)) return error.AlreadyEnrolled;
    var secret: Secret = undefined;
    defer std.crypto.secureZero(u8, &secret);
    random.randomBytes(&secret);
    const encrypted = seal(&secret, key, user_id);
    const stmt = try tx.prepare(
        \\INSERT INTO webmail_mfa_enrollment (user_id, session_id, secret, expires_at) VALUES (?1, ?2, ?3, ?4)
        \\ON CONFLICT(user_id) DO UPDATE SET session_id = excluded.session_id, secret = excluded.secret, expires_at = excluded.expires_at
    );
    defer stmt.finalize();
    try stmt.bind(1, user_id);
    try stmt.bind(2, session);
    try stmt.bindBlob(3, &encrypted);
    try stmt.bind(4, now + enrollment_ttl);
    _ = try stmt.step();
    return base32(secret);
}

pub fn confirmEnrollment(tx: Tx, key: *const Key, user_id: i64, session: []const u8, code: []const u8, now: i64) !RecoveryCodes {
    try requireOwnerSession(tx, user_id, session, now);
    if (try enabled(tx, user_id)) return error.AlreadyEnrolled;
    var encrypted: Sealed = undefined;
    {
        const stmt = try tx.prepare("SELECT secret FROM webmail_mfa_enrollment WHERE user_id = ?1 AND session_id = ?2 AND expires_at > ?3");
        defer stmt.finalize();
        try stmt.bind(1, user_id);
        try stmt.bind(2, session);
        try stmt.bind(3, now);
        if (!try stmt.step()) return error.InvalidEnrollment;
        const bytes = stmt.columnBlob(0);
        if (bytes.len != encrypted.len) return error.MfaUnavailable;
        encrypted = bytes[0..@sizeOf(Sealed)].*;
    }

    var secret: Secret = undefined;
    defer std.crypto.secureZero(u8, &secret);
    try unseal(&encrypted, key, user_id, &secret);
    const step = matchingStep(&secret, code, now, -1) orelse return error.InvalidFactor;
    {
        const stmt = try tx.prepare("INSERT INTO webmail_mfa_factors (user_id, secret, last_step) VALUES (?1, ?2, ?3)");
        defer stmt.finalize();
        try stmt.bind(1, user_id);
        try stmt.bindBlob(2, &encrypted);
        try stmt.bind(3, step);
        _ = try stmt.step();
    }
    {
        const stmt = try tx.prepare("DELETE FROM webmail_mfa_enrollment WHERE user_id = ?1");
        defer stmt.finalize();
        try stmt.bind(1, user_id);
        _ = try stmt.step();
    }

    var codes: RecoveryCodes = undefined;
    errdefer std.crypto.secureZero(u8, std.mem.asBytes(&codes));
    for (&codes) |*recovery_code| {
        var entropy: [16]u8 = undefined;
        defer std.crypto.secureZero(u8, &entropy);
        random.randomBytes(&entropy);
        recovery_code.* = std.fmt.bytesToHex(entropy, .lower);
        const stmt = try tx.prepare("INSERT INTO webmail_mfa_recovery_codes (user_id, digest) VALUES (?1, ?2)");
        defer stmt.finalize();
        try stmt.bind(1, user_id);
        try stmt.bindBlob(2, &recoveryDigest(recovery_code).?);
        _ = try stmt.step();
    }
    try retireOtherSessions(tx, user_id, session);
    return codes;
}

/// Verify and consume under the same write transaction that creates the
/// session. An aborted session insert also rolls back the factor consumption.
pub fn consume(tx: Tx, key: ?*const Key, user_id: i64, credential: ?[]const u8, now: i64) !void {
    var last_step: i64 = undefined;
    var encrypted: Sealed = undefined;
    {
        const stmt = try tx.prepare("SELECT secret, last_step FROM webmail_mfa_factors WHERE user_id = ?1");
        defer stmt.finalize();
        try stmt.bind(1, user_id);
        if (!try stmt.step()) return;
        const bytes = stmt.columnBlob(0);
        if (bytes.len != encrypted.len) return error.MfaUnavailable;
        encrypted = bytes[0..@sizeOf(Sealed)].*;
        last_step = stmt.columnInt64(1);
    }
    const code = std.mem.trim(u8, credential orelse return error.FactorRequired, " \t\r\n");
    if (code.len == 0) return error.FactorRequired;
    if (recoveryDigest(code)) |digest| {
        const stmt = try tx.prepare("DELETE FROM webmail_mfa_recovery_codes WHERE user_id = ?1 AND digest = ?2 RETURNING user_id");
        defer stmt.finalize();
        try stmt.bind(1, user_id);
        try stmt.bindBlob(2, &digest);
        if (!try stmt.step()) return error.InvalidFactor;
        return;
    }
    if (code.len != 6) return error.InvalidFactor;
    var secret: Secret = undefined;
    defer std.crypto.secureZero(u8, &secret);
    try unseal(&encrypted, key orelse return error.MfaUnavailable, user_id, &secret);
    const step = matchingStep(&secret, code, now, last_step) orelse return error.InvalidFactor;
    const stmt = try tx.prepare("UPDATE webmail_mfa_factors SET last_step = ?1 WHERE user_id = ?2 AND last_step < ?1 RETURNING user_id");
    defer stmt.finalize();
    try stmt.bind(1, step);
    try stmt.bind(2, user_id);
    if (!try stmt.step()) return error.InvalidFactor;
}

/// The insert trigger also runs when a previous binary opens this database.
/// It spends this ticket on exactly one insert in the factor transaction.
pub fn authorizeSession(tx: Tx, key: ?*const Key, user_id: i64, credential: ?[]const u8, session_id: []const u8, now: i64) !void {
    try consume(tx, key, user_id, credential, now);
    const stmt = try tx.prepare(
        \\INSERT INTO webmail_mfa_session_tickets (session_id, user_id)
        \\SELECT ?1, user_id FROM webmail_mfa_factors WHERE user_id = ?2
    );
    defer stmt.finalize();
    try stmt.bind(1, session_id);
    try stmt.bind(2, user_id);
    _ = try stmt.step();
}

fn retireOtherSessions(tx: Tx, user_id: i64, keep: []const u8) !void {
    const stmt = try tx.prepare("DELETE FROM webmail_sessions WHERE username = (SELECT username FROM users WHERE id = ?1) AND session_id <> ?2");
    defer stmt.finalize();
    try stmt.bind(1, user_id);
    try stmt.bind(2, keep);
    _ = try stmt.step();
}

pub fn disable(tx: Tx, key: ?*const Key, user_id: i64, session: []const u8, code: []const u8, now: i64) !void {
    try requireOwnerSession(tx, user_id, session, now);
    if (!try enabled(tx, user_id)) return error.InvalidEnrollment;
    try consume(tx, key, user_id, code, now);
    const stmt = try tx.prepare("DELETE FROM webmail_mfa_factors WHERE user_id = ?1");
    defer stmt.finalize();
    try stmt.bind(1, user_id);
    _ = try stmt.step();
    try retireOtherSessions(tx, user_id, session);
}

test "webmail MFA RFC 6238 six-digit projections, setup encoding, and time step replay" {
    const secret: Secret = "12345678901234567890".*;
    try std.testing.expectEqualStrings("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", &base32(secret));
    const cases = [_]struct { time: i64, code: []const u8 }{
        .{ .time = 59, .code = "287082" },
        .{ .time = 1_111_111_109, .code = "081804" },
        .{ .time = 1_234_567_890, .code = "005924" },
        .{ .time = 20_000_000_000, .code = "353130" },
    };
    for (cases) |item| {
        const step = @divFloor(item.time, step_seconds);
        try std.testing.expectEqualStrings(item.code, &totp(&secret, step));
        try std.testing.expectEqual(@as(?i64, step), matchingStep(&secret, item.code, item.time + 30, step - 1));
        try std.testing.expect(matchingStep(&secret, item.code, item.time + 60, step - 1) == null);
        try std.testing.expect(matchingStep(&secret, item.code, item.time, step) == null);
    }
}

fn pendingSecret(tx: Tx, key: *const Key, user_id: i64) !Secret {
    const stmt = try tx.prepare("SELECT secret FROM webmail_mfa_enrollment WHERE user_id = ?1");
    defer stmt.finalize();
    try stmt.bind(1, user_id);
    try std.testing.expect(try stmt.step());
    var secret: Secret = undefined;
    try unseal(stmt.columnBlob(0), key, user_id, &secret);
    return secret;
}

test "webmail MFA enrollment is session-bound and expires" {
    var db = try database.Database.init(std.testing.allocator, ":memory:");
    defer db.deinit();
    const name = "enrollment@example.test";
    const user_id = try db.createUser(name, "unused", name);
    try db.createWebmailSession("owner", name, name, "csrf1", 20_000, null, null);
    try db.createWebmailSession("other", name, name, "csrf2", 20_000, null, null);
    const key: Key = @splat(7);
    const now = 12_000;

    {
        var tx = try db.beginTransaction(.write);
        defer tx.deinit();
        _ = try beginEnrollment(tx, &key, user_id, "owner", now);
        const secret = try pendingSecret(tx, &key, user_id);
        const code = totp(&secret, now / step_seconds);
        try std.testing.expectError(error.InvalidEnrollment, confirmEnrollment(tx, &key, user_id, "other", &code, now));
        try std.testing.expectError(error.InvalidEnrollment, confirmEnrollment(tx, &key, user_id, "owner", &code, now + enrollment_ttl));
        try std.testing.expect(!try enabled(tx, user_id));
        const codes = try confirmEnrollment(tx, &key, user_id, "owner", &code, now);
        try std.testing.expectEqual(recovery_count, codes.len);
        try std.testing.expect(try enabled(tx, user_id));
        try std.testing.expectError(error.AlreadyEnrolled, beginEnrollment(tx, &key, user_id, "owner", now));
        try std.testing.expectError(error.InvalidEnrollment, requireOwnerSession(tx, user_id, "other", now));
        try requireOwnerSession(tx, user_id, "owner", now);
        try tx.commit();
    }
    // The legacy insert reports SQLite's trigger constraint as AlreadyExists.
    try std.testing.expectError(error.AlreadyExists, db.createWebmailSession("legacy", name, name, "csrf3", 20_000, null, null));
    try std.testing.expectError(error.NotFound, db.getWebmailSession("legacy"));
    const unrelated = "unprotected@example.test";
    _ = try db.createUser(unrelated, "unused", unrelated);
    try db.createWebmailSession("unprotected", unrelated, unrelated, "csrf4", 20_000, null, null);
}

test "webmail MFA consumes OTP and recovery codes transactionally and restores access after device loss" {
    var db = try database.Database.init(std.testing.allocator, ":memory:");
    defer db.deinit();
    const name = "owner@example.test";
    const user_id = try db.createUser(name, "unused", name);
    const other_name = "other@example.test";
    const other_id = try db.createUser(other_name, "unused", other_name);
    try db.createWebmailSession("owner", name, name, "csrf1", 20_000, null, null);
    try db.createWebmailSession("other", other_name, other_name, "csrf2", 20_000, null, null);
    const key: Key = @splat(19);
    const wrong_key: Key = @splat(20);
    const now = 12_000;
    const step = now / step_seconds;
    var secret: Secret = undefined;
    var codes: RecoveryCodes = undefined;
    {
        var tx = try db.beginTransaction(.write);
        defer tx.deinit();
        _ = try beginEnrollment(tx, &key, user_id, "owner", now);
        secret = try pendingSecret(tx, &key, user_id);
        codes = try confirmEnrollment(tx, &key, user_id, "owner", &totp(&secret, step), now);
        _ = try beginEnrollment(tx, &key, other_id, "other", now);
        const other_secret = try pendingSecret(tx, &key, other_id);
        _ = try confirmEnrollment(tx, &key, other_id, "other", &totp(&other_secret, step), now);
        try tx.commit();
    }
    const next = totp(&secret, step + 1);
    {
        var tx = try db.beginTransaction(.write);
        defer tx.deinit();
        try std.testing.expectError(error.FactorRequired, consume(tx, &key, user_id, null, now));
        try std.testing.expectError(error.InvalidFactor, consume(tx, &key, user_id, &totp(&secret, step), now));
        try std.testing.expectError(error.MfaUnavailable, consume(tx, &wrong_key, user_id, &next, now + 30));
        try consume(tx, &key, user_id, &next, now + 30);
        try consume(tx, &key, user_id, &codes[0], now + 30);
        // Simulate a session insert that fails and rolls back.
    }
    {
        var tx = try db.beginTransaction(.write);
        defer tx.deinit();
        try consume(tx, &key, user_id, &next, now + 30);
        try std.testing.expectError(error.InvalidFactor, consume(tx, &key, other_id, &codes[0], now + 30));
        try consume(tx, null, user_id, &codes[0], now + 30);
        try tx.commit();
    }
    {
        var tx = try db.beginTransaction(.write);
        defer tx.deinit();
        try std.testing.expectError(error.InvalidFactor, consume(tx, &key, user_id, &next, now + 30));
        try std.testing.expectError(error.InvalidFactor, consume(tx, &key, user_id, &codes[0], now + 30));
        try disable(tx, null, user_id, "owner", &codes[1], now + 30);
        try std.testing.expect(!try enabled(tx, user_id));
        try std.testing.expect(try enabled(tx, other_id));
        const still_saved = try tx.prepare("SELECT 1 FROM webmail_mfa_recovery_codes WHERE user_id = ?1");
        defer still_saved.finalize();
        try still_saved.bind(1, user_id);
        try std.testing.expect(!try still_saved.step());
        try tx.commit();
    }
}
