const std = @import("std");
const time_compat = @import("../core/time_compat.zig");

/// Secure Password Reset System
/// Implements token-based password reset with expiration
/// Follows OWASP guidelines for secure password reset

/// Password reset token entry
pub const ResetToken = struct {
    id: i64,
    username: []const u8,
    token_hash: []const u8, // Store hash, not plaintext
    created_at: i64,
    expires_at: i64,
    used: bool,
    used_at: ?i64,
    ip_address: ?[]const u8,

    pub fn deinit(self: *ResetToken, allocator: std.mem.Allocator) void {
        allocator.free(self.username);
        allocator.free(self.token_hash);
        if (self.ip_address) |ip| allocator.free(ip);
    }

    pub fn isExpired(self: *const ResetToken) bool {
        return time_compat.timestamp() > self.expires_at;
    }

    pub fn isValid(self: *const ResetToken) bool {
        return !self.used and !self.isExpired();
    }
};

/// Password Reset Manager
pub const PasswordResetManager = struct {
    allocator: std.mem.Allocator,
    db: *anyopaque, // Database pointer
    token_expiry_minutes: u32,
    max_attempts_per_hour: u32,
    mutex: std.Thread.Mutex,

    // Statistics
    tokens_generated: u64,
    tokens_used: u64,
    tokens_expired: u64,
    invalid_attempts: u64,

    const Self = @This();

    /// Default token expiry: 1 hour
    const DEFAULT_EXPIRY_MINUTES: u32 = 60;
    /// Default max attempts per hour per IP
    const DEFAULT_MAX_ATTEMPTS: u32 = 5;
    /// Token length in bytes (before hex encoding)
    const TOKEN_BYTES: usize = 32;

    pub fn init(allocator: std.mem.Allocator, db: *anyopaque) Self {
        return .{
            .allocator = allocator,
            .db = db,
            .token_expiry_minutes = DEFAULT_EXPIRY_MINUTES,
            .max_attempts_per_hour = DEFAULT_MAX_ATTEMPTS,
            .mutex = .{},
            .tokens_generated = 0,
            .tokens_used = 0,
            .tokens_expired = 0,
            .invalid_attempts = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
        // No cleanup needed
    }

    /// Generate a secure random token
    pub fn generateToken(self: *Self) ![TOKEN_BYTES * 2]u8 {
        _ = self;
        var random_bytes: [TOKEN_BYTES]u8 = undefined;

        // Use cryptographically secure random
        std.c.arc4random_buf(&random_bytes, random_bytes.len);

        // Convert to hex string
        var hex_token: [TOKEN_BYTES * 2]u8 = undefined;
        _ = std.fmt.bufPrint(&hex_token, "{s}", .{std.fmt.fmtSliceHexLower(&random_bytes)}) catch unreachable;

        return hex_token;
    }

    /// Hash a token for storage (using SHA-256)
    pub fn hashToken(token: []const u8) [64]u8 {
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(token, &hash, .{});

        var hex_hash: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&hex_hash, "{s}", .{std.fmt.fmtSliceHexLower(&hash)}) catch unreachable;

        return hex_hash;
    }

    /// Request a password reset for a user
    /// Returns the plaintext token (to be sent via email)
    /// Stores only the hashed token in the database
    pub fn requestReset(
        self: *Self,
        username: []const u8,
        ip_address: ?[]const u8,
    ) ![]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Generate secure token
        const token = try self.generateToken();
        const token_hash = hashToken(&token);

        const now = time_compat.timestamp();
        const expires_at = now + @as(i64, @intCast(self.token_expiry_minutes)) * 60;

        // Invalidate any existing tokens for this user
        try self.invalidateExistingTokens(username);

        // Store the hashed token
        try self.storeToken(username, &token_hash, now, expires_at, ip_address);

        self.tokens_generated += 1;

        // Return the plaintext token (caller sends this via email)
        const result = try self.allocator.alloc(u8, token.len);
        @memcpy(result, &token);
        return result;
    }

    /// Verify a reset token and return the associated username
    pub fn verifyToken(self: *Self, token: []const u8) ![]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const token_hash = hashToken(token);

        // Look up token in database
        const reset_token = self.getTokenByHash(&token_hash) catch |err| {
            self.invalid_attempts += 1;
            return err;
        };
        defer {
            var mutable_token = reset_token;
            mutable_token.deinit(self.allocator);
        }

        if (!reset_token.isValid()) {
            self.invalid_attempts += 1;
            if (reset_token.isExpired()) {
                self.tokens_expired += 1;
                return error.TokenExpired;
            }
            return error.TokenAlreadyUsed;
        }

        // Return username (caller must free)
        return try self.allocator.dupe(u8, reset_token.username);
    }

    /// Complete a password reset
    pub fn completeReset(
        self: *Self,
        token: []const u8,
        new_password_hash: []const u8,
    ) ![]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const token_hash = hashToken(token);

        // Verify token is valid
        const reset_token = self.getTokenByHash(&token_hash) catch |err| {
            self.invalid_attempts += 1;
            return err;
        };
        defer {
            var mutable_token = reset_token;
            mutable_token.deinit(self.allocator);
        }

        if (!reset_token.isValid()) {
            self.invalid_attempts += 1;
            if (reset_token.isExpired()) {
                self.tokens_expired += 1;
                return error.TokenExpired;
            }
            return error.TokenAlreadyUsed;
        }

        // Update password in database
        try self.updatePassword(reset_token.username, new_password_hash);

        // Mark token as used
        try self.markTokenUsed(&token_hash);

        self.tokens_used += 1;

        // Return username for confirmation
        return try self.allocator.dupe(u8, reset_token.username);
    }

    /// Store a reset token in the database
    fn storeToken(
        self: *Self,
        username: []const u8,
        token_hash: []const u8,
        created_at: i64,
        expires_at: i64,
        ip_address: ?[]const u8,
    ) !void {
        // This would call database.insertResetToken()
        // For now, we'll define the interface
        _ = self;
        _ = username;
        _ = token_hash;
        _ = created_at;
        _ = expires_at;
        _ = ip_address;
    }

    /// Get a token by its hash
    fn getTokenByHash(self: *Self, token_hash: []const u8) !ResetToken {
        // This would call database.getResetTokenByHash()
        _ = self;
        _ = token_hash;
        return error.TokenNotFound;
    }

    /// Mark a token as used
    fn markTokenUsed(self: *Self, token_hash: []const u8) !void {
        // This would call database.markResetTokenUsed()
        _ = self;
        _ = token_hash;
    }

    /// Invalidate existing tokens for a user
    fn invalidateExistingTokens(self: *Self, username: []const u8) !void {
        // This would call database.invalidateResetTokens()
        _ = self;
        _ = username;
    }

    /// Update user password
    fn updatePassword(self: *Self, username: []const u8, password_hash: []const u8) !void {
        // This would call database.updateUserPassword()
        _ = self;
        _ = username;
        _ = password_hash;
    }

    /// Prune expired tokens from the database
    pub fn pruneExpiredTokens(self: *Self) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Would call database.pruneExpiredResetTokens()
        return 0;
    }

    /// Get statistics
    pub fn getStats(self: *Self) ResetStats {
        return .{
            .tokens_generated = self.tokens_generated,
            .tokens_used = self.tokens_used,
            .tokens_expired = self.tokens_expired,
            .invalid_attempts = self.invalid_attempts,
            .token_expiry_minutes = self.token_expiry_minutes,
        };
    }
};

/// Password reset statistics
pub const ResetStats = struct {
    tokens_generated: u64,
    tokens_used: u64,
    tokens_expired: u64,
    invalid_attempts: u64,
    token_expiry_minutes: u32,
};

/// SQL schema for password_reset_tokens table
pub const schema =
    \\CREATE TABLE IF NOT EXISTS password_reset_tokens (
    \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    username TEXT NOT NULL,
    \\    token_hash TEXT NOT NULL UNIQUE,
    \\    created_at INTEGER NOT NULL,
    \\    expires_at INTEGER NOT NULL,
    \\    used INTEGER DEFAULT 0,
    \\    used_at INTEGER,
    \\    ip_address TEXT,
    \\    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    \\);
    \\
    \\CREATE INDEX IF NOT EXISTS idx_reset_token_hash ON password_reset_tokens(token_hash);
    \\CREATE INDEX IF NOT EXISTS idx_reset_username ON password_reset_tokens(username);
    \\CREATE INDEX IF NOT EXISTS idx_reset_expires ON password_reset_tokens(expires_at);
;

// Tests
test "token generation" {
    const testing = std.testing;

    var db: u8 = 0;
    var manager = PasswordResetManager.init(testing.allocator, &db);
    defer manager.deinit();

    const token1 = try manager.generateToken();
    const token2 = try manager.generateToken();

    // Tokens should be different
    try testing.expect(!std.mem.eql(u8, &token1, &token2));

    // Tokens should be 64 hex characters
    try testing.expectEqual(@as(usize, 64), token1.len);
}

test "token hashing" {
    const testing = std.testing;

    const token = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    const hash1 = PasswordResetManager.hashToken(token);
    const hash2 = PasswordResetManager.hashToken(token);

    // Same token should produce same hash
    try testing.expectEqualSlices(u8, &hash1, &hash2);

    // Hash should be 64 hex characters (SHA-256)
    try testing.expectEqual(@as(usize, 64), hash1.len);
}

test "token expiration check" {
    const testing = std.testing;

    const now = time_compat.timestamp();

    var expired_token = ResetToken{
        .id = 1,
        .username = "test",
        .token_hash = "hash",
        .created_at = now - 7200, // 2 hours ago
        .expires_at = now - 3600, // Expired 1 hour ago
        .used = false,
        .used_at = null,
        .ip_address = null,
    };

    try testing.expect(expired_token.isExpired());
    try testing.expect(!expired_token.isValid());

    var valid_token = ResetToken{
        .id = 2,
        .username = "test2",
        .token_hash = "hash2",
        .created_at = now,
        .expires_at = now + 3600, // Expires in 1 hour
        .used = false,
        .used_at = null,
        .ip_address = null,
    };

    try testing.expect(!valid_token.isExpired());
    try testing.expect(valid_token.isValid());
}

test "statistics tracking" {
    const testing = std.testing;

    var db: u8 = 0;
    var manager = PasswordResetManager.init(testing.allocator, &db);
    defer manager.deinit();

    const stats = manager.getStats();
    try testing.expectEqual(@as(u64, 0), stats.tokens_generated);
    try testing.expectEqual(@as(u32, 60), stats.token_expiry_minutes);
}
