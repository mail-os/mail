const std = @import("std");
const io_compat = @import("../core/io_compat.zig");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");
const crypto = std.crypto;

/// CSRF token manager for protecting against Cross-Site Request Forgery attacks
pub const CSRFManager = struct {
    allocator: std.mem.Allocator,
    tokens: std.StringHashMap(TokenData),
    mutex: mutex_compat.Mutex,
    token_lifetime_seconds: i64,

    const TokenData = struct {
        expires_at: i64,
        used: bool,
    };

    const TOKEN_LENGTH = 32;
    const DEFAULT_LIFETIME = 3600; // 1 hour
    // Hard cap on outstanding tokens so the map can't grow without bound
    // under flood load (each entry is ~60 bytes of key + TokenData).
    const MAX_TOKENS = 50_000;

    pub fn init(allocator: std.mem.Allocator) CSRFManager {
        return .{
            .allocator = allocator,
            .tokens = std.StringHashMap(TokenData).init(allocator),
            .mutex = mutex_compat.Mutex{},
            .token_lifetime_seconds = DEFAULT_LIFETIME,
        };
    }

    pub fn deinit(self: *CSRFManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.tokens.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.tokens.deinit();
    }

    /// Generate a new CSRF token
    pub fn generateToken(self: *CSRFManager) ![]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Generate random token
        var token_bytes: [TOKEN_LENGTH]u8 = undefined;
        io_compat.randomBytes(&token_bytes);

        // Encode as base64 for safe transmission
        const encoder = std.base64.url_safe_no_pad.Encoder;
        const token_b64_len = encoder.calcSize(TOKEN_LENGTH);
        const token = try self.allocator.alloc(u8, token_b64_len);
        const encoded = encoder.encode(token, &token_bytes);

        const now = time_compat.timestamp();
        const expires_at = now + self.token_lifetime_seconds;

        // Bound the map: at the cap, sweep expired tokens; if everything is
        // still live (flood), evict an arbitrary batch — bounded memory wins
        // over honoring every outstanding form token under attack load.
        if (self.tokens.count() >= MAX_TOKENS) {
            self.removeExpiredLocked();
            if (self.tokens.count() >= MAX_TOKENS) self.evictBatchLocked(MAX_TOKENS / 10);
        }

        // Store token with expiration
        try self.tokens.put(try self.allocator.dupe(u8, encoded), .{
            .expires_at = expires_at,
            .used = false,
        });

        return token;
    }

    /// Validate and consume a CSRF token (one-time use)
    pub fn validateToken(self: *CSRFManager, token: []const u8) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = time_compat.timestamp();

        // Check if token exists
        const entry = self.tokens.getEntry(token) orelse return false;

        // Check if expired
        if (entry.value_ptr.expires_at < now) {
            // Remove expired token
            self.allocator.free(entry.key_ptr.*);
            _ = self.tokens.remove(token);
            return false;
        }

        // Check if already used
        if (entry.value_ptr.used) {
            return false;
        }

        // Mark as used (one-time use)
        entry.value_ptr.used = true;

        // Remove token after use for security
        self.allocator.free(entry.key_ptr.*);
        _ = self.tokens.remove(token);

        return true;
    }

    /// Validate token but don't consume it (for idempotent operations)
    pub fn checkToken(self: *CSRFManager, token: []const u8) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = time_compat.timestamp();

        const entry = self.tokens.getEntry(token) orelse return false;

        // Check if expired
        if (entry.value_ptr.expires_at < now) {
            return false;
        }

        // Check if already used
        if (entry.value_ptr.used) {
            return false;
        }

        return true;
    }

    /// Cleanup expired tokens (call with mutex held)
    /// Remove all expired tokens. (The old variant removed every token —
    /// expired or not — once its removal budget was reached, and freed each
    /// key before calling remove() with it.)
    fn removeExpiredLocked(self: *CSRFManager) void {
        const now = time_compat.timestamp();

        var to_remove: std.ArrayList([]const u8) = .empty;
        defer to_remove.deinit(self.allocator);

        var it = self.tokens.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.expires_at < now) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch break;
            }
        }

        for (to_remove.items) |key| {
            _ = self.tokens.remove(key);
            self.allocator.free(key);
        }
    }

    /// Evict up to `n` arbitrary tokens (used only when the cap is hit while
    /// every entry is still live).
    fn evictBatchLocked(self: *CSRFManager, n: usize) void {
        var to_remove: std.ArrayList([]const u8) = .empty;
        defer to_remove.deinit(self.allocator);

        var it = self.tokens.iterator();
        while (it.next()) |entry| {
            if (to_remove.items.len >= n) break;
            to_remove.append(self.allocator, entry.key_ptr.*) catch break;
        }

        for (to_remove.items) |key| {
            _ = self.tokens.remove(key);
            self.allocator.free(key);
        }
    }

    /// Get statistics
    pub fn getStats(self: *CSRFManager) struct { total: usize, active: usize } {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = time_compat.timestamp();
        var active: usize = 0;

        var it = self.tokens.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.expires_at >= now and !entry.value_ptr.used) {
                active += 1;
            }
        }

        return .{
            .total = self.tokens.count(),
            .active = active,
        };
    }
};

test "CSRF token generation and validation" {
    const testing = std.testing;
    var manager = CSRFManager.init(testing.allocator);
    defer manager.deinit();

    // Generate token
    const token = try manager.generateToken();
    defer testing.allocator.free(token);

    // Token should be valid
    try testing.expect(try manager.validateToken(token));

    // Token should not be valid after use (one-time use)
    try testing.expect(!try manager.validateToken(token));
}

test "CSRF token expiration" {
    const testing = std.testing;
    var manager = CSRFManager.init(testing.allocator);
    manager.token_lifetime_seconds = -1; // Already expired
    defer manager.deinit();

    const token = try manager.generateToken();
    defer testing.allocator.free(token);

    // Token should be expired
    try testing.expect(!try manager.validateToken(token));
}

test "CSRF check token without consuming" {
    const testing = std.testing;
    var manager = CSRFManager.init(testing.allocator);
    defer manager.deinit();

    const token = try manager.generateToken();
    defer testing.allocator.free(token);

    // Check token (doesn't consume)
    try testing.expect(try manager.checkToken(token));

    // Token should still be valid
    try testing.expect(try manager.checkToken(token));

    // Now validate (consumes)
    try testing.expect(try manager.validateToken(token));

    // Token should be gone
    try testing.expect(!try manager.checkToken(token));
}
