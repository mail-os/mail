//! Mailbox recovery: a per-mailbox recovery address and the password reset
//! links sent to it.
//!
//! A mailbox may name one address outside itself where a reset link can be
//! sent. Anyone can ask for a reset by mailbox address; the answer is the same
//! whether or not the mailbox exists or has a recovery address, and the link
//! goes only to the recovery address, never to whoever asked.
//!
//! Who set the address is recorded in `users.recovery_source`:
//!   - `operator`: the `user:local recovery` CLI, which deploy provisioning uses
//!   - `user`:     the mailbox owner, in webmail settings
//! Provisioning with the `initial` policy leaves a `user` value alone, so a
//! redeploy does not undo a change the owner made. `managed` always applies.
//!
//! Reset tokens are 32 random bytes, sent as 64 hex characters. Only their
//! SHA-256 is stored (`mailbox_reset_tokens`). A token is single use, expires
//! after `token_ttl_seconds`, and is voided when a newer one is issued, when
//! the password changes by any route, and when the recovery address changes.

const std = @import("std");
const database = @import("../storage/database.zig");
const auth_mod = @import("../auth/auth.zig");
const io_compat = @import("../core/io_compat.zig");
const compose = @import("webmail_compose.zig");

/// How long a reset link stays usable.
pub const token_ttl_seconds: i64 = 30 * 60;
/// At most this many reset emails per mailbox per hour, whoever asks.
pub const max_links_per_hour: i64 = 3;
/// And never two within this many seconds of each other.
pub const min_link_interval_seconds: i64 = 60;
/// Token length on the wire: 32 bytes as lowercase hex.
pub const token_hex_len = 64;
/// The bounds the webmail password change already enforces.
pub const min_password_len = 12;
pub const max_password_len = 1024;

pub const RecoveryError = error{
    InvalidAddress,
    SameAsMailbox,
    UserNotFound,
};

pub const Source = enum {
    operator,
    user,

    pub fn parse(text: []const u8) ?Source {
        if (std.mem.eql(u8, text, "operator")) return .operator;
        if (std.mem.eql(u8, text, "user")) return .user;
        return null;
    }
};

pub const Policy = enum {
    /// Set the address unless the mailbox owner has set their own.
    initial,
    /// Always set the address.
    managed,

    pub fn parse(text: []const u8) ?Policy {
        if (std.mem.eql(u8, text, "initial")) return .initial;
        if (std.mem.eql(u8, text, "managed")) return .managed;
        return null;
    }
};

pub const Recovery = struct {
    /// null when the mailbox has none.
    address: ?[]const u8,
    source: ?Source,
    updated_at: ?i64,
};

// ── Recovery address ─────────────────────────────────────────────────────────

/// Trim and check a recovery address for `mailbox`. Returns the trimmed slice
/// (borrowed from `address`). The mailbox itself is refused: a reset link sent
/// to the mailbox you cannot open is no recovery at all.
pub fn validateAddress(mailbox: []const u8, address: []const u8) RecoveryError![]const u8 {
    const trimmed = std.mem.trim(u8, address, " \t\r\n");
    if (trimmed.len == 0 or trimmed.len > 254) return RecoveryError.InvalidAddress;
    if (!compose.isSafeAddress(trimmed)) return RecoveryError.InvalidAddress;
    const at = std.mem.indexOfScalar(u8, trimmed, '@').?;
    // A domain needs a dot; `user@localhost` is not somewhere a person reads mail.
    if (std.mem.indexOfScalar(u8, trimmed[at + 1 ..], '.') == null) return RecoveryError.InvalidAddress;
    if (std.ascii.eqlIgnoreCase(trimmed, mailbox)) return RecoveryError.SameAsMailbox;
    return trimmed;
}

/// The mailbox's recovery address, or null when the mailbox does not exist.
pub fn get(allocator: std.mem.Allocator, db: *database.Database, username: []const u8) !?Recovery {
    const s = try db.prepare("SELECT recovery_email, recovery_source, recovery_updated_at FROM users WHERE username = ?1");
    defer s.finalize();
    try s.bind(1, username);
    if (!try s.step()) return null;
    const address = s.columnTextOpt(0);
    const source = s.columnTextOpt(1);
    return Recovery{
        .address = if (address) |a| (if (a.len == 0) null else try allocator.dupe(u8, a)) else null,
        .source = if (source) |text| Source.parse(text) else null,
        .updated_at = s.columnInt64Opt(2),
    };
}

/// Set (or, with null, clear) a mailbox's recovery address. Outstanding reset
/// links are voided: they were sent to the previous address.
pub fn set(db: *database.Database, username: []const u8, address: ?[]const u8, source: Source, now: i64) !void {
    const value: ?[]const u8 = if (address) |a| try validateAddress(username, a) else null;
    const s = try db.prepare(
        \\UPDATE users SET recovery_email = ?2, recovery_source = ?3, recovery_updated_at = ?4
        \\WHERE username = ?1 RETURNING username
    );
    defer s.finalize();
    try s.bind(1, username);
    try s.bindOpt(2, value);
    try s.bind(3, @tagName(source));
    try s.bind(4, now);
    if (!try s.step()) return RecoveryError.UserNotFound;
    try db.deleteUserResetTokens(username);
}

pub const ApplyResult = enum {
    /// The address was written.
    updated,
    /// It already had this address.
    unchanged,
    /// The owner set their own and the policy is `initial`, so it was kept.
    kept_owner_choice,
};

/// What deploy provisioning calls: make the mailbox's recovery address
/// `address`, subject to `policy`. Idempotent.
pub fn apply(allocator: std.mem.Allocator, db: *database.Database, username: []const u8, address: []const u8, policy: Policy, now: i64) !ApplyResult {
    const wanted = try validateAddress(username, address);
    const current = (try get(allocator, db, username)) orelse return RecoveryError.UserNotFound;
    defer if (current.address) |a| allocator.free(a);
    if (current.address) |existing| {
        if (std.ascii.eqlIgnoreCase(existing, wanted)) return .unchanged;
    }
    if (policy == .initial and current.source == .user) return .kept_owner_choice;
    try set(db, username, wanted, .operator, now);
    return .updated;
}

// ── Reset tokens ─────────────────────────────────────────────────────────────

/// Hex SHA-256 of a token: what is stored and looked up.
pub fn hashToken(token: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(token, &digest, .{});
    return hexLower(32, digest);
}

fn hexLower(comptime n: usize, bytes: [n]u8) [n * 2]u8 {
    const digits = "0123456789abcdef";
    var out: [n * 2]u8 = undefined;
    for (bytes, 0..) |byte, i| {
        out[i * 2] = digits[byte >> 4];
        out[i * 2 + 1] = digits[byte & 15];
    }
    return out;
}

/// A token as it arrives from a browser: exactly 64 lowercase hex characters.
/// Anything else is rejected before it costs a database lookup.
pub fn wellFormedToken(token: []const u8) bool {
    if (token.len != token_hex_len) return false;
    for (token) |c| if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) return false;
    return true;
}

pub const Issue = union(enum) {
    /// A link should be sent to `recovery`.
    issued: struct { token: [token_hex_len]u8, recovery: []const u8 },
    /// Nothing is sent. These are distinguished for the server log only;
    /// the HTTP answer is the same for all of them.
    unknown_mailbox,
    disabled,
    no_recovery,
    throttled,
};

/// Issue a reset token for `username` (a canonical mailbox key), unless the
/// mailbox is unknown, disabled, has no recovery address, or has had too many
/// links recently. A new token voids the mailbox's earlier unused ones.
pub fn issue(allocator: std.mem.Allocator, db: *database.Database, username: []const u8, ip: ?[]const u8, now: i64) !Issue {
    var recovery: []const u8 = undefined;
    {
        const s = try db.prepare("SELECT enabled, recovery_email FROM users WHERE username = ?1");
        defer s.finalize();
        try s.bind(1, username);
        if (!try s.step()) return .unknown_mailbox;
        if (s.columnInt64(0) == 0) return .disabled;
        const address = s.columnTextOpt(1) orelse return .no_recovery;
        if (address.len == 0) return .no_recovery;
        recovery = try allocator.dupe(u8, address);
    }
    errdefer allocator.free(recovery);

    // Old rows are only kept for the count below.
    {
        const s = try db.prepare("DELETE FROM mailbox_reset_tokens WHERE created_at < ?1");
        defer s.finalize();
        try s.bind(1, now - 24 * 60 * 60);
        _ = try s.step();
    }
    {
        const s = try db.prepare("SELECT COUNT(*), MAX(created_at) FROM mailbox_reset_tokens WHERE username = ?1 AND created_at > ?2");
        defer s.finalize();
        try s.bind(1, username);
        try s.bind(2, now - 60 * 60);
        if (try s.step()) {
            const recent = s.columnInt64(0);
            const last = s.columnInt64Opt(1);
            const too_soon = if (last) |at| now - at < min_link_interval_seconds else false;
            if (recent >= max_links_per_hour or too_soon) {
                allocator.free(recovery);
                return .throttled;
            }
        }
    }
    {
        const s = try db.prepare("UPDATE mailbox_reset_tokens SET used_at = ?2 WHERE username = ?1 AND used_at IS NULL");
        defer s.finalize();
        try s.bind(1, username);
        try s.bind(2, now);
        _ = try s.step();
    }

    var random: [32]u8 = undefined;
    io_compat.randomBytes(&random);
    const token = hexLower(32, random);
    const hash = hashToken(&token);
    {
        const s = try db.prepare(
            \\INSERT INTO mailbox_reset_tokens (token_hash, username, recovery_email, created_at, expires_at, ip_address)
            \\VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        );
        defer s.finalize();
        try s.bind(1, @as([]const u8, &hash));
        try s.bind(2, username);
        try s.bind(3, recovery);
        try s.bind(4, now);
        try s.bind(5, now + token_ttl_seconds);
        try s.bindOpt(6, ip);
        _ = try s.step();
    }
    return .{ .issued = .{ .token = token, .recovery = recovery } };
}

/// The mailbox a usable token belongs to, or null. Does not consume it.
pub fn lookup(allocator: std.mem.Allocator, db: *database.Database, token: []const u8, now: i64) !?[]const u8 {
    if (!wellFormedToken(token)) return null;
    const hash = hashToken(token);
    const s = try db.prepare(
        \\SELECT t.username FROM mailbox_reset_tokens t JOIN users u ON u.username = t.username
        \\WHERE t.token_hash = ?1 AND t.used_at IS NULL AND t.expires_at > ?2 AND u.enabled = 1
    );
    defer s.finalize();
    try s.bind(1, @as([]const u8, &hash));
    try s.bind(2, now);
    if (!try s.step()) return null;
    return try allocator.dupe(u8, s.columnText(0));
}

pub const Completed = struct {
    username: []const u8,
    /// Where the link was sent, for the confirmation notice.
    recovery: []const u8,
};

/// Spend a token and set the mailbox's new password. Returns null when the
/// token is unknown, used, expired, or its mailbox is gone or disabled.
///
/// The token is marked used by a single conditional UPDATE before anything
/// else happens, so two concurrent submissions of one link cannot both win.
pub fn complete(allocator: std.mem.Allocator, db: *database.Database, auth: *auth_mod.AuthBackend, token: []const u8, new_password: []const u8, now: i64) !?Completed {
    if (!wellFormedToken(token)) return null;
    const hash = hashToken(token);
    var username: []const u8 = undefined;
    var recovery: []const u8 = undefined;
    {
        const s = try db.prepare(
            \\UPDATE mailbox_reset_tokens SET used_at = ?2
            \\WHERE token_hash = ?1 AND used_at IS NULL AND expires_at > ?2
            \\RETURNING username, recovery_email
        );
        defer s.finalize();
        try s.bind(1, @as([]const u8, &hash));
        try s.bind(2, now);
        if (!try s.step()) return null;
        username = try allocator.dupe(u8, s.columnText(0));
        recovery = try allocator.dupe(u8, s.columnText(1));
    }
    errdefer {
        allocator.free(username);
        allocator.free(recovery);
    }
    {
        const s = try db.prepare("SELECT enabled FROM users WHERE username = ?1");
        defer s.finalize();
        try s.bind(1, username);
        if (!try s.step() or s.columnInt64(0) == 0) {
            allocator.free(username);
            allocator.free(recovery);
            return null;
        }
    }
    // Hashes the password, signs out every browser session, and voids the
    // mailbox's other reset links.
    try auth.changePassword(username, new_password);
    return .{ .username = username, .recovery = recovery };
}

// ── Messages ─────────────────────────────────────────────────────────────────

/// The domain a mailbox belongs to, falling back to the server's hostname for
/// a legacy bare username.
fn mailboxDomain(username: []const u8, hostname: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, username, '@')) |at| return username[at + 1 ..];
    return hostname;
}

/// The address the server writes from about `username`: `no-reply@` the
/// mailbox's own domain, so it is DKIM-signed with that domain's key and
/// aligns with its SPF and DMARC, exactly like mail the mailbox sends itself.
pub fn senderFor(allocator: std.mem.Allocator, username: []const u8, hostname: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator, "no-reply@{s}", .{mailboxDomain(username, hostname)});
}

fn validHost(host: []const u8) bool {
    if (host.len == 0 or host.len > 253) return false;
    for (host) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '.' or c == '-' or c == ':')) return false;
    }
    return true;
}

/// Where a reset link points.
///
/// Never simply the request's Host: that is client-controlled, and a link
/// built from it would carry the token to whatever server the requester named
/// (reset poisoning). The request's host is used only when it is one of ours
/// for this mailbox: `mail.<mailbox domain>` (the tenant's own webmail name)
/// or the server's hostname. Otherwise the server's hostname.
pub fn linkBase(allocator: std.mem.Allocator, request_host: ?[]const u8, username: []const u8, hostname: []const u8, https: bool) ![]const u8 {
    const scheme = if (https) "https" else "http";
    if (request_host) |raw| {
        const host = try std.ascii.allocLowerString(allocator, std.mem.trim(u8, raw, " \t"));
        defer allocator.free(host);
        if (validHost(host)) {
            const name = if (std.mem.indexOfScalar(u8, host, ':')) |colon| host[0..colon] else host;
            const domain = mailboxDomain(username, hostname);
            const tenant = std.mem.startsWith(u8, name, "mail.") and std.ascii.eqlIgnoreCase(name["mail.".len..], domain);
            if (tenant or std.ascii.eqlIgnoreCase(name, hostname))
                return std.fmt.allocPrint(allocator, "{s}://{s}", .{ scheme, host });
        }
    }
    return std.fmt.allocPrint(allocator, "{s}://{s}", .{ scheme, hostname });
}

/// The link itself. The token rides in the fragment, which browsers do not
/// send to servers, so it stays out of gateway and access logs.
pub fn resetLink(allocator: std.mem.Allocator, base: []const u8, token: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{s}/reset#token={s}", .{ base, token });
}

pub const ResetMail = struct {
    username: []const u8,
    recovery: []const u8,
    link: []const u8,
    ip: ?[]const u8 = null,
    hostname: []const u8,
};

pub fn resetMessage(allocator: std.mem.Allocator, m: ResetMail) !compose.Message {
    const to = try allocator.alloc([]const u8, 1);
    to[0] = m.recovery;
    const origin = if (m.ip) |ip| try std.fmt.allocPrint(allocator, "\nThe request came from {s}.\n", .{ip}) else "";
    return .{
        .from = try senderFor(allocator, m.username, m.hostname),
        .to = to,
        .subject = try std.fmt.allocPrint(allocator, "Reset the password for {s}", .{m.username}),
        .text_body = try std.fmt.allocPrint(allocator,
            \\Someone asked to reset the password for the mailbox {s}.
            \\This address is its recovery address.
            \\
            \\To choose a new password, open this link within {d} minutes:
            \\
            \\{s}
            \\
            \\The link works once. If you did not ask for this, ignore this
            \\email: the password stays as it is.
            \\{s}
        , .{ m.username, @divTrunc(token_ttl_seconds, 60), m.link, origin }),
        .auto_submitted = true,
    };
}

pub fn passwordResetNotice(allocator: std.mem.Allocator, username: []const u8, recovery: []const u8, hostname: []const u8) !compose.Message {
    const to = try allocator.alloc([]const u8, 1);
    to[0] = recovery;
    return .{
        .from = try senderFor(allocator, username, hostname),
        .to = to,
        .subject = try std.fmt.allocPrint(allocator, "The password for {s} was reset", .{username}),
        .text_body = try std.fmt.allocPrint(allocator,
            \\The password for the mailbox {s} was just reset with a link
            \\sent to this address. Every webmail session was signed out, and
            \\mail apps need the new password.
            \\
            \\If this was not you, someone can read this inbox: secure it, then
            \\ask the mail administrator to reset the mailbox password.
            \\
        , .{username}),
        .auto_submitted = true,
    };
}

pub fn recoveryChangedNotice(allocator: std.mem.Allocator, username: []const u8, previous: []const u8, hostname: []const u8) !compose.Message {
    const to = try allocator.alloc([]const u8, 1);
    to[0] = previous;
    return .{
        .from = try senderFor(allocator, username, hostname),
        .to = to,
        .subject = try std.fmt.allocPrint(allocator, "The recovery address for {s} changed", .{username}),
        .text_body = try std.fmt.allocPrint(allocator,
            \\This address is no longer the recovery address for the mailbox
            \\{s}. It was changed in webmail by someone signed in with the
            \\mailbox password.
            \\
            \\If this was not you, ask the mail administrator to reset the
            \\mailbox password.
            \\
        , .{username}),
        .auto_submitted = true,
    };
}

// ── Tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn testDb() !database.Database {
    return database.Database.init(testing.allocator, ":memory:");
}

test "validateAddress trims, refuses the mailbox itself and malformed input" {
    try testing.expectEqualStrings("pawel@outlook.de", try validateAddress("pawel@hq.training", "  pawel@outlook.de "));
    try testing.expectError(RecoveryError.SameAsMailbox, validateAddress("pawel@hq.training", "Pawel@HQ.training"));
    try testing.expectError(RecoveryError.InvalidAddress, validateAddress("a@b.test", ""));
    try testing.expectError(RecoveryError.InvalidAddress, validateAddress("a@b.test", "no-at-sign"));
    try testing.expectError(RecoveryError.InvalidAddress, validateAddress("a@b.test", "x@localhost"));
    try testing.expectError(RecoveryError.InvalidAddress, validateAddress("a@b.test", "x@y.test\r\nBcc: evil@z.test"));
    try testing.expectError(RecoveryError.InvalidAddress, validateAddress("a@b.test", "<x@y.test>"));
}

test "recovery address: set, read back, clear, and provisioning policies" {
    var db = try testDb();
    defer db.deinit();
    const a = testing.allocator;
    _ = try db.createUser("pawel@hq.test", "hash", "pawel@hq.test");

    const none = (try get(a, &db, "pawel@hq.test")).?;
    try testing.expect(none.address == null);
    try testing.expect(none.source == null);
    try testing.expect((try get(a, &db, "nobody@hq.test")) == null);

    // First deploy sets it; the second is a no-op.
    try testing.expectEqual(ApplyResult.updated, try apply(a, &db, "pawel@hq.test", "pawel@outlook.test", .initial, 100));
    try testing.expectEqual(ApplyResult.unchanged, try apply(a, &db, "pawel@hq.test", "PAWEL@outlook.test", .initial, 101));
    // Config changing an operator-set address is applied even under `initial`.
    try testing.expectEqual(ApplyResult.updated, try apply(a, &db, "pawel@hq.test", "pawel@gmail.test", .initial, 102));

    // The owner changes it in webmail: `initial` keeps their choice...
    try set(&db, "pawel@hq.test", "pawel@proton.test", .user, 103);
    try testing.expectEqual(ApplyResult.kept_owner_choice, try apply(a, &db, "pawel@hq.test", "pawel@gmail.test", .initial, 104));
    {
        const r = (try get(a, &db, "pawel@hq.test")).?;
        defer a.free(r.address.?);
        try testing.expectEqualStrings("pawel@proton.test", r.address.?);
        try testing.expectEqual(Source.user, r.source.?);
        try testing.expectEqual(@as(i64, 103), r.updated_at.?);
    }
    // ...and `managed` overrides it.
    try testing.expectEqual(ApplyResult.updated, try apply(a, &db, "pawel@hq.test", "pawel@gmail.test", .managed, 105));
    {
        const r = (try get(a, &db, "pawel@hq.test")).?;
        defer a.free(r.address.?);
        try testing.expectEqualStrings("pawel@gmail.test", r.address.?);
        try testing.expectEqual(Source.operator, r.source.?);
    }
    // An owner who clears it is also respected by `initial`.
    try set(&db, "pawel@hq.test", null, .user, 106);
    try testing.expectEqual(ApplyResult.kept_owner_choice, try apply(a, &db, "pawel@hq.test", "pawel@gmail.test", .initial, 107));
    try testing.expect((try get(a, &db, "pawel@hq.test")).?.address == null);

    try testing.expectError(RecoveryError.UserNotFound, apply(a, &db, "nobody@hq.test", "x@y.test", .managed, 108));
    try testing.expectError(RecoveryError.UserNotFound, set(&db, "nobody@hq.test", "x@y.test", .operator, 108));
    try testing.expectError(RecoveryError.SameAsMailbox, apply(a, &db, "pawel@hq.test", "pawel@hq.test", .managed, 108));
}

test "issue answers nothing for unknown, disabled and recovery-less mailboxes" {
    var db = try testDb();
    defer db.deinit();
    const a = testing.allocator;
    _ = try db.createUser("plain@hq.test", "hash", "plain@hq.test");
    _ = try db.createUser("off@hq.test", "hash", "off@hq.test");
    try set(&db, "off@hq.test", "off@else.test", .operator, 1);
    try db.setUserEnabled("off@hq.test", false);

    try testing.expect((try issue(a, &db, "ghost@hq.test", null, 1000)) == .unknown_mailbox);
    try testing.expect((try issue(a, &db, "plain@hq.test", null, 1000)) == .no_recovery);
    try testing.expect((try issue(a, &db, "off@hq.test", null, 1000)) == .disabled);
}

test "a reset link works once, expires, and the newest one voids the older" {
    var db = try testDb();
    defer db.deinit();
    var auth = auth_mod.AuthBackend.init(testing.allocator, &db);
    defer auth.deinit();
    const a = testing.allocator;
    _ = try auth.createUser("chris@hq.test", "old-password-123", "chris@hq.test");
    try set(&db, "chris@hq.test", "chris@else.test", .operator, 1);

    const first = try issue(a, &db, "chris@hq.test", "203.0.113.9", 1000);
    try testing.expect(first == .issued);
    defer a.free(first.issued.recovery);
    try testing.expectEqualStrings("chris@else.test", first.issued.recovery);
    const t1 = first.issued.token;
    try testing.expect(wellFormedToken(&t1));

    {
        const who = (try lookup(a, &db, &t1, 1001)).?;
        defer a.free(who);
        try testing.expectEqualStrings("chris@hq.test", who);
    }
    // Expired.
    try testing.expect((try lookup(a, &db, &t1, 1000 + token_ttl_seconds)) == null);
    try testing.expect((try complete(a, &db, &auth, &t1, "new-password-456", 1000 + token_ttl_seconds)) == null);

    // A second request, after the minimum interval, voids the first link.
    const second = try issue(a, &db, "chris@hq.test", null, 1000 + min_link_interval_seconds);
    try testing.expect(second == .issued);
    defer a.free(second.issued.recovery);
    const t2 = second.issued.token;
    try testing.expect(!std.mem.eql(u8, &t1, &t2));
    try testing.expect((try lookup(a, &db, &t1, 1070)) == null);

    const done = (try complete(a, &db, &auth, &t2, "new-password-456", 1070)).?;
    defer {
        a.free(done.username);
        a.free(done.recovery);
    }
    try testing.expectEqualStrings("chris@hq.test", done.username);
    try testing.expectEqualStrings("chris@else.test", done.recovery);
    try testing.expect(try auth.verifyCredentials("chris@hq.test", "new-password-456"));
    try testing.expect(!try auth.verifyCredentials("chris@hq.test", "old-password-123"));

    // Used once; malformed tokens never reach the database.
    try testing.expect((try complete(a, &db, &auth, &t2, "another-password-789", 1071)) == null);
    try testing.expect((try lookup(a, &db, "not-a-token", 1071)) == null);
    const uppercase: [64]u8 = @splat('A');
    try testing.expect((try lookup(a, &db, &uppercase, 1071)) == null);
}

test "reset links are rate limited per mailbox" {
    var db = try testDb();
    defer db.deinit();
    const a = testing.allocator;
    _ = try db.createUser("rate@hq.test", "hash", "rate@hq.test");
    try set(&db, "rate@hq.test", "rate@else.test", .operator, 1);

    var now: i64 = 10_000;
    var sent: usize = 0;
    // Too soon after the previous one.
    const r0 = try issue(a, &db, "rate@hq.test", null, now);
    if (r0 == .issued) {
        a.free(r0.issued.recovery);
        sent += 1;
    }
    try testing.expect((try issue(a, &db, "rate@hq.test", null, now + 1)) == .throttled);
    // Spaced out, the hourly cap still holds.
    while (sent < max_links_per_hour) {
        now += min_link_interval_seconds;
        const r = try issue(a, &db, "rate@hq.test", null, now);
        try testing.expect(r == .issued);
        a.free(r.issued.recovery);
        sent += 1;
    }
    now += min_link_interval_seconds;
    try testing.expect((try issue(a, &db, "rate@hq.test", null, now)) == .throttled);
    // An hour after the first, one is allowed again.
    const later = try issue(a, &db, "rate@hq.test", null, 10_000 + 60 * 60 + 1);
    try testing.expect(later == .issued);
    a.free(later.issued.recovery);
}

test "changing the password or the recovery address voids outstanding links" {
    var db = try testDb();
    defer db.deinit();
    var auth = auth_mod.AuthBackend.init(testing.allocator, &db);
    defer auth.deinit();
    const a = testing.allocator;
    _ = try auth.createUser("void@hq.test", "old-password-123", "void@hq.test");
    try set(&db, "void@hq.test", "void@else.test", .operator, 1);

    const r1 = try issue(a, &db, "void@hq.test", null, 1000);
    defer a.free(r1.issued.recovery);
    try auth.changePassword("void@hq.test", "changed-in-webmail-1");
    try testing.expect((try lookup(a, &db, &r1.issued.token, 1001)) == null);

    const r2 = try issue(a, &db, "void@hq.test", null, 2000);
    defer a.free(r2.issued.recovery);
    try set(&db, "void@hq.test", "void@new.test", .user, 2001);
    try testing.expect((try complete(a, &db, &auth, &r2.issued.token, "attacker-password-1", 2002)) == null);

    // Deleting the mailbox removes its tokens with it.
    const r3 = try issue(a, &db, "void@hq.test", null, 3000);
    defer a.free(r3.issued.recovery);
    try db.deleteUser("void@hq.test");
    try testing.expect((try lookup(a, &db, &r3.issued.token, 3001)) == null);
}

test "linkBase only trusts hosts that belong to the mailbox or the server" {
    const a = testing.allocator;
    const cases = [_]struct { host: ?[]const u8, want: []const u8 }{
        .{ .host = "mail.hq.training", .want = "https://mail.hq.training" },
        .{ .host = "MAIL.HQ.TRAINING", .want = "https://mail.hq.training" },
        .{ .host = "mail.stacksjs.com", .want = "https://mail.stacksjs.com" },
        // Another tenant's webmail name, an attacker's host, junk, nothing.
        .{ .host = "mail.wildloop.org", .want = "https://mail.stacksjs.com" },
        .{ .host = "evil.example", .want = "https://mail.stacksjs.com" },
        .{ .host = "mail.hq.training.evil.example", .want = "https://mail.stacksjs.com" },
        .{ .host = "mail.hq.training/@evil.example", .want = "https://mail.stacksjs.com" },
        .{ .host = null, .want = "https://mail.stacksjs.com" },
    };
    for (cases) |c| {
        const got = try linkBase(a, c.host, "pawel@hq.training", "mail.stacksjs.com", true);
        defer a.free(got);
        try testing.expectEqualStrings(c.want, got);
    }
    // Local development keeps the port it was reached on.
    const dev = try linkBase(a, "localhost:8099", "dev@localhost", "localhost", false);
    defer a.free(dev);
    try testing.expectEqualStrings("http://localhost:8099", dev);
}

test "the reset email goes to the recovery address from the mailbox's own domain" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const token: [64]u8 = @splat('a');
    const link = try resetLink(a, "https://mail.hq.training", &token);
    try testing.expectEqualStrings("https://mail.hq.training/reset#token=" ++ token, link);
    const msg = try resetMessage(a, .{ .username = "pawel@hq.training", .recovery = "pawel@outlook.test", .link = link, .ip = "203.0.113.9", .hostname = "mail.stacksjs.com" });
    try testing.expectEqualStrings("no-reply@hq.training", msg.from);
    try testing.expectEqual(@as(usize, 1), msg.to.len);
    try testing.expectEqualStrings("pawel@outlook.test", msg.to[0]);
    try testing.expect(std.mem.indexOf(u8, msg.text_body, link) != null);
    try testing.expect(std.mem.indexOf(u8, msg.text_body, "30 minutes") != null);
    try testing.expect(std.mem.indexOf(u8, msg.text_body, "203.0.113.9") != null);
    const raw = try compose.buildMime(a, msg, 1700000000, "<t@hq.training>");
    try testing.expect(std.mem.indexOf(u8, raw, "From: no-reply@hq.training\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, raw, "To: pawel@outlook.test\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, raw, "Auto-Submitted: auto-generated\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, raw, link) != null);

    const notice = try passwordResetNotice(a, "pawel@hq.training", "pawel@outlook.test", "mail.stacksjs.com");
    try testing.expectEqualStrings("pawel@outlook.test", notice.to[0]);
    _ = try compose.buildMime(a, notice, 1, "<n@hq.training>");
    const changed = try recoveryChangedNotice(a, "legacy", "old@else.test", "mail.stacksjs.com");
    try testing.expectEqualStrings("no-reply@mail.stacksjs.com", changed.from);
    _ = try compose.buildMime(a, changed, 1, "<c@hq.training>");
}
