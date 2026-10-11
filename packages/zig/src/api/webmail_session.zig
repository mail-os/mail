//! Browser session management for webmail.
//!
//! Distinct from SMTP/IMAP AUTH: a session is a random opaque token handed to
//! the browser as an `HttpOnly` cookie and persisted in the `webmail_sessions`
//! SQLite table (see database.zig). Login verifies credentials with the shared
//! AuthBackend (Argon2id), then mints a session. Each session also carries a
//! CSRF secret that the SPA echoes back in a header on mutating requests.
//!
//! Sliding expiry: every validated request pushes `expires_at` forward by
//! `idle_ttl_seconds`, capped by nothing here (absolute cap can be layered on
//! later). Expired rows are pruned lazily on validation and can be swept via
//! `db.deleteExpiredWebmailSessions`.

const std = @import("std");
const io_compat = @import("../core/io_compat.zig");
const time_compat = @import("../core/time_compat.zig");
const database = @import("../storage/database.zig");
const auth_mod = @import("../auth/auth.zig");

/// 32 random bytes -> 64 hex chars. Plenty of entropy for an opaque token.
pub const token_bytes_len = 32;
pub const token_hex_len = token_bytes_len * 2;

/// Default idle window: a session stays valid as long as it's used at least
/// this often. 7 days is a reasonable webmail default.
pub const default_idle_ttl_seconds: i64 = 7 * 24 * 60 * 60;

/// Cookie name for the session token.
pub const cookie_name = "webmail_session";

pub const SessionError = error{
    InvalidCredentials,
    SessionNotFound,
    SessionExpired,
};

/// A live, validated session returned to handlers. Owns its strings.
pub const Session = struct {
    session_id: []const u8,
    username: []const u8,
    email: []const u8,
    csrf_secret: []const u8,

    pub fn deinit(self: *Session, allocator: std.mem.Allocator) void {
        allocator.free(self.session_id);
        allocator.free(self.username);
        allocator.free(self.email);
        allocator.free(self.csrf_secret);
    }
};

pub const SessionManager = struct {
    allocator: std.mem.Allocator,
    db: *database.Database,
    auth: *auth_mod.AuthBackend,
    idle_ttl_seconds: i64 = default_idle_ttl_seconds,
    /// When true, the Secure attribute is added to cookies (HTTPS only). For
    /// local dev over plain HTTP this is false so the cookie is still set.
    secure_cookies: bool = true,

    pub fn init(
        allocator: std.mem.Allocator,
        db: *database.Database,
        auth: *auth_mod.AuthBackend,
    ) SessionManager {
        return .{ .allocator = allocator, .db = db, .auth = auth };
    }

    /// Verify credentials and create a new session. On success returns a
    /// Session the caller owns (call deinit). The username is normalized the
    /// same way AuthBackend does (canonical mailbox key) so the session and Maildir
    /// lookups agree.
    pub fn login(
        self: *SessionManager,
        username: []const u8,
        password: []const u8,
        ip_address: ?[]const u8,
        user_agent: ?[]const u8,
    ) !Session {
        const ok = try self.auth.verifyCredentials(username, password);
        if (!ok) return SessionError.InvalidCredentials;

        // Use the same canonical key as IMAP and SMTP. Domains distinguish
        // hosted accounts and must never be discarded from a session identity.
        const local = try self.auth.canonicalUsername(username, self.allocator);
        defer self.allocator.free(local);

        // Resolve the canonical email from the user record; fall back to the
        // raw username if the lookup fails for any reason.
        const email_buf = blk: {
            if (self.db.getUserByUsername(local)) |user_val| {
                var user = user_val;
                defer user.deinit(self.allocator);
                break :blk try self.allocator.dupe(u8, user.email);
            } else |_| {
                break :blk try self.allocator.dupe(u8, username);
            }
        };
        errdefer self.allocator.free(email_buf);

        const session_id = try generateToken(self.allocator);
        errdefer self.allocator.free(session_id);
        const csrf_secret = try generateToken(self.allocator);
        errdefer self.allocator.free(csrf_secret);

        const username_dup = try self.allocator.dupe(u8, local);
        errdefer self.allocator.free(username_dup);

        const expires_at = time_compat.timestamp() + self.idle_ttl_seconds;

        try self.db.createWebmailSession(
            session_id,
            username_dup,
            email_buf,
            csrf_secret,
            expires_at,
            ip_address,
            user_agent,
        );

        return Session{
            .session_id = session_id,
            .username = username_dup,
            .email = email_buf,
            .csrf_secret = csrf_secret,
        };
    }

    /// Validate a session token. Returns the Session (caller owns) on success.
    /// Expired sessions are deleted and reported as SessionExpired.
    pub fn validate(self: *SessionManager, session_id: []const u8) !Session {
        var row = self.db.getWebmailSession(session_id) catch |err| {
            if (err == database.DatabaseError.NotFound) return SessionError.SessionNotFound;
            return err;
        };
        defer row.deinit(self.allocator);

        const now = time_compat.timestamp();
        if (row.expires_at <= now) {
            self.db.deleteWebmailSession(session_id) catch {};
            return SessionError.SessionExpired;
        }

        // Administrative deletion or disablement also ends browser access.
        var user = self.db.getUserByUsername(row.username) catch |err| {
            if (err != database.DatabaseError.NotFound) return err;
            self.logout(session_id);
            return SessionError.SessionNotFound;
        };
        defer user.deinit(self.allocator);
        if (!user.enabled) {
            self.logout(session_id);
            return SessionError.SessionNotFound;
        }

        // Sliding expiry: push the window forward. Best-effort.
        self.db.touchWebmailSession(session_id, now + self.idle_ttl_seconds) catch {};

        return Session{
            .session_id = try self.allocator.dupe(u8, row.session_id),
            .username = try self.allocator.dupe(u8, row.username),
            .email = try self.allocator.dupe(u8, row.email),
            .csrf_secret = try self.allocator.dupe(u8, row.csrf_secret),
        };
    }

    /// Revoke a session (logout). Idempotent.
    pub fn logout(self: *SessionManager, session_id: []const u8) void {
        self.db.deleteWebmailSession(session_id) catch {};
    }

    /// Sweep expired sessions. Cheap; safe to call periodically.
    pub fn sweep(self: *SessionManager) void {
        self.db.deleteExpiredWebmailSessions(time_compat.timestamp()) catch {};
    }

    /// Build the Set-Cookie header value for a freshly minted session.
    /// Caller owns the returned slice.
    pub fn buildSetCookie(self: *SessionManager, session_id: []const u8) ![]u8 {
        const secure = if (self.secure_cookies) "; Secure" else "";
        return std.fmt.allocPrint(
            self.allocator,
            "{s}={s}; HttpOnly; SameSite=Lax; Path=/; Max-Age={d}{s}",
            .{ cookie_name, session_id, self.idle_ttl_seconds, secure },
        );
    }

    /// Build the Set-Cookie header that clears the session cookie (logout).
    pub fn buildClearCookie(self: *SessionManager) ![]u8 {
        const secure = if (self.secure_cookies) "; Secure" else "";
        return std.fmt.allocPrint(
            self.allocator,
            "{s}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{s}",
            .{ cookie_name, secure },
        );
    }
};

/// Parse the session token from a Cookie header value, or null if absent.
/// Handles multiple cookies: "a=1; webmail_session=abc; b=2".
pub fn parseSessionCookie(cookie_header: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, cookie_header, ';');
    while (it.next()) |pair_raw| {
        const pair = std.mem.trim(u8, pair_raw, " \t");
        if (std.mem.indexOfScalar(u8, pair, '=')) |eq| {
            const name = pair[0..eq];
            if (std.mem.eql(u8, name, cookie_name)) {
                return pair[eq + 1 ..];
            }
        }
    }
    return null;
}

/// Generate a random hex token. Caller owns the returned slice.
fn generateToken(allocator: std.mem.Allocator) ![]u8 {
    var raw: [token_bytes_len]u8 = undefined;
    io_compat.randomBytes(&raw);
    const out = try allocator.alloc(u8, token_hex_len);
    const hex_chars = "0123456789abcdef";
    for (raw, 0..) |b, i| {
        out[i * 2] = hex_chars[b >> 4];
        out[i * 2 + 1] = hex_chars[b & 0x0f];
    }
    return out;
}

// ── Tests ───────────────────────────────────────────────────────────────────

test "parseSessionCookie finds the session among others" {
    const t = std.testing;
    try t.expectEqualStrings("abc123", parseSessionCookie("foo=1; webmail_session=abc123; bar=2").?);
    try t.expectEqualStrings("xyz", parseSessionCookie("webmail_session=xyz").?);
    try t.expect(parseSessionCookie("foo=1; bar=2") == null);
    try t.expect(parseSessionCookie("") == null);
}

test "sessions preserve canonical full-address identities across hosted domains" {
    const t = std.testing;
    var db = try database.Database.init(t.allocator, ":memory:");
    defer db.deinit();
    var auth = auth_mod.AuthBackend.init(t.allocator, &db);
    defer auth.deinit();
    _ = try auth.createUser("pawel@hq.training", "temporary-password", "pawel@hq.training");
    _ = try auth.createUser("pawel@other.example", "other-password", "pawel@other.example");
    var manager = SessionManager.init(t.allocator, &db, &auth);
    var session = try manager.login("pawel@hq.training", "temporary-password", null, null);
    defer session.deinit(t.allocator);
    try t.expectEqualStrings("pawel@hq.training", session.username);
    try t.expectEqualStrings("pawel@hq.training", session.email);
    try t.expectError(SessionError.InvalidCredentials, manager.login("pawel@other.example", "temporary-password", null, null));
    try t.expectError(SessionError.InvalidCredentials, manager.login("pawel", "temporary-password", null, null));
    var other = try manager.login("pawel@other.example", "other-password", null, null);
    defer other.deinit(t.allocator);
    try auth.changePassword(session.username, "replacement-password");
    var unaffected = try manager.validate(other.session_id);
    defer unaffected.deinit(t.allocator);
    try t.expectEqualStrings("pawel@other.example", unaffected.username);
    try t.expectError(SessionError.SessionNotFound, manager.validate(session.session_id));
    try t.expect(!try auth.verifyCredentials("pawel@hq.training", "temporary-password"));
    try t.expect(try auth.verifyCredentials("pawel@hq.training", "replacement-password"));
    try t.expect(try auth.verifyCredentials("pawel@other.example", "other-password"));
}

test "generateToken produces hex of expected length" {
    const t = std.testing;
    const tok = try generateToken(t.allocator);
    defer t.allocator.free(tok);
    try t.expectEqual(@as(usize, token_hex_len), tok.len);
    for (tok) |c| {
        try t.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

test "sessions are revoked when an account is disabled or deleted" {
    const t = std.testing;
    var db = try database.Database.init(t.allocator, ":memory:");
    defer db.deinit();
    var auth = auth_mod.AuthBackend.init(t.allocator, &db);
    defer auth.deinit();
    _ = try auth.createUser("lifecycle@example.com", "test-password", "lifecycle@example.com");
    var manager = SessionManager.init(t.allocator, &db, &auth);
    var disabled = try manager.login("lifecycle@example.com", "test-password", null, null);
    defer disabled.deinit(t.allocator);
    try db.setUserEnabled(disabled.username, false);
    try db.setUserEnabled(disabled.username, true);
    try t.expectError(SessionError.SessionNotFound, manager.validate(disabled.session_id));
    var deleted = try manager.login("lifecycle@example.com", "test-password", null, null);
    defer deleted.deinit(t.allocator);
    try db.deleteUser(deleted.username);
    _ = try auth.createUser("lifecycle@example.com", "new-password", "lifecycle@example.com");
    try t.expectError(SessionError.SessionNotFound, manager.validate(deleted.session_id));
}
