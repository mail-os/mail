const std = @import("std");
const io_compat = @import("../core/io_compat.zig");
const posix = std.posix;
const database = @import("../storage/database.zig");
const password_mod = @import("password.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;
const mutex_compat = @import("../core/mutex_compat.zig");

/// Get current unix timestamp in seconds
fn getCurrentTimestamp() i64 {
    var ts: std.c.timespec = undefined;
    const rc = std.c.clock_gettime(.REALTIME, &ts);
    if (rc != 0) return 0;
    return ts.sec;
}

/// Convert bytes to lowercase hex string
fn bytesToHex(bytes: []const u8, out: []u8) void {
    const hex_chars = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[i * 2] = hex_chars[b >> 4];
        out[i * 2 + 1] = hex_chars[b & 0x0f];
    }
}

/// Constant-time byte comparison to prevent timing attacks.
/// Returns true if a and b are equal. Both slices must be the same length.
pub fn constantTimeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| {
        diff |= x ^ y;
    }
    return diff == 0;
}

pub const Credentials = struct {
    username: []const u8,
    password: []const u8,
};

/// HTTP Digest Authentication parameters (RFC 7616)
pub const DigestAuthParams = struct {
    username: []const u8,
    realm: []const u8,
    nonce: []const u8,
    uri: []const u8,
    response: []const u8,
    qop: ?[]const u8 = null,
    nc: ?[]const u8 = null,
    cnonce: ?[]const u8 = null,
    algorithm: ?[]const u8 = null,

    pub fn deinit(self: *DigestAuthParams, allocator: std.mem.Allocator) void {
        allocator.free(self.username);
        allocator.free(self.realm);
        allocator.free(self.nonce);
        allocator.free(self.uri);
        allocator.free(self.response);
        if (self.qop) |q| allocator.free(q);
        if (self.nc) |n| allocator.free(n);
        if (self.cnonce) |c| allocator.free(c);
        if (self.algorithm) |a| allocator.free(a);
    }
};

/// Nonce manager for Digest authentication
pub const NonceManager = struct {
    allocator: std.mem.Allocator,
    nonces: std.StringHashMap(i64), // nonce -> creation timestamp
    max_age_seconds: i64 = 300, // 5 minutes
    generation_count: u32 = 0,
    max_nonces: u32 = 4096, // Hard cap to prevent unbounded growth
    mutex: mutex_compat.Mutex = .{}, // Thread safety for concurrent connections

    pub fn init(allocator: std.mem.Allocator) NonceManager {
        return .{
            .allocator = allocator,
            .nonces = std.StringHashMap(i64).init(allocator),
        };
    }

    pub fn deinit(self: *NonceManager) void {
        var iter = self.nonces.keyIterator();
        while (iter.next()) |key| {
            self.allocator.free(key.*);
        }
        self.nonces.deinit();
    }

    /// Generate a new cryptographically random nonce (no predictable components)
    pub fn generateNonce(self: *NonceManager) ![]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var random_bytes: [32]u8 = undefined;
        io_compat.randomBytes(&random_bytes);

        const now = getCurrentTimestamp();

        // Nonce is purely random hex — no timestamp or other predictable data
        var hex_buf: [64]u8 = undefined;
        bytesToHex(&random_bytes, &hex_buf);

        const nonce = try self.allocator.dupe(u8, &hex_buf);

        // Deterministic cleanup every 64 generations (instead of random sampling)
        self.generation_count +%= 1;
        if (self.generation_count % 64 == 0 and self.nonces.count() > 0) {
            self.cleanupLocked();
        }

        // Hard cap: if still over limit after cleanup, reject to prevent memory exhaustion
        if (self.nonces.count() >= self.max_nonces) {
            self.cleanupLocked();
            if (self.nonces.count() >= self.max_nonces) {
                self.allocator.free(nonce);
                return error.TooManyNonces;
            }
        }

        try self.nonces.put(nonce, now);
        return nonce;
    }

    /// Validate a nonce (check it exists and hasn't expired)
    pub fn validateNonce(self: *NonceManager, nonce: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const created = self.nonces.get(nonce) orelse return false;
        const now = getCurrentTimestamp();
        return (now - created) < self.max_age_seconds;
    }

    /// Remove a used nonce (for one-time use)
    pub fn invalidateNonce(self: *NonceManager, nonce: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.nonces.fetchRemove(nonce)) |entry| {
            self.allocator.free(entry.key);
        }
    }

    /// Cleanup expired nonces (public, acquires lock)
    pub fn cleanup(self: *NonceManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.cleanupLocked();
    }

    /// Cleanup expired nonces (internal, caller must hold lock)
    fn cleanupLocked(self: *NonceManager) void {
        const now = getCurrentTimestamp();
        var to_remove: std.ArrayList([]const u8) = .empty;
        defer to_remove.deinit(self.allocator);

        var iter = self.nonces.iterator();
        while (iter.next()) |entry| {
            if ((now - entry.value_ptr.*) >= self.max_age_seconds) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            if (self.nonces.fetchRemove(key)) |entry| {
                self.allocator.free(entry.key);
            }
        }
    }
};

pub const AuthBackend = struct {
    db: *database.Database,
    password_hasher: password_mod.PasswordHasher,
    allocator: std.mem.Allocator,
    nonce_manager: NonceManager,
    verify_cache: VerifyCache,

    /// Cache of recent successful password verifications. Mail clients
    /// reconnect constantly (IMAP polling, IDLE drops, per-message SMTP
    /// submission), and every login costs a full 64MB Argon2id KDF
    /// (hundreds of ms). A cache entry is SHA-256(process salt, username,
    /// password, stored hash): binding the STORED hash means a password
    /// change or reset invalidates the entry implicitly, and the
    /// per-process random salt keeps entries useless outside this process.
    /// Only successes are cached; failures always pay full KDF cost.
    const VerifyCache = struct {
        const ttl_seconds: i64 = 600;
        const max_entries = 1024;

        map: std.AutoHashMap([32]u8, i64),
        salt: [32]u8,
        mutex: mutex_compat.Mutex = .{},

        fn init(allocator: std.mem.Allocator) VerifyCache {
            var salt: [32]u8 = undefined;
            io_compat.randomBytes(&salt);
            return .{
                .map = std.AutoHashMap([32]u8, i64).init(allocator),
                .salt = salt,
            };
        }

        fn deinit(self: *VerifyCache) void {
            self.map.deinit();
        }

        fn key(self: *VerifyCache, username: []const u8, pass: []const u8, stored_hash: []const u8) [32]u8 {
            var h = Sha256.init(.{});
            h.update(&self.salt);
            h.update(username);
            h.update(&[_]u8{0});
            h.update(pass);
            h.update(&[_]u8{0});
            h.update(stored_hash);
            var out: [32]u8 = undefined;
            h.final(&out);
            return out;
        }

        fn check(self: *VerifyCache, k: [32]u8) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.map.get(k)) |expires| {
                if (getCurrentTimestamp() < expires) return true;
                _ = self.map.remove(k);
            }
            return false;
        }

        fn insert(self: *VerifyCache, k: [32]u8) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            const now = getCurrentTimestamp();
            if (self.map.count() >= max_entries) {
                // Evict expired entries; if everything is still live, drop
                // the whole cache — wrong logins then just pay the KDF again.
                var expired: std.ArrayList([32]u8) = .empty;
                defer expired.deinit(self.map.allocator);
                var it = self.map.iterator();
                while (it.next()) |entry| {
                    if (now >= entry.value_ptr.*) {
                        expired.append(self.map.allocator, entry.key_ptr.*) catch break;
                    }
                }
                for (expired.items) |ek| _ = self.map.remove(ek);
                if (self.map.count() >= max_entries) self.map.clearRetainingCapacity();
            }
            self.map.put(k, now + ttl_seconds) catch {};
        }
    };

    pub fn init(allocator: std.mem.Allocator, db: *database.Database) AuthBackend {
        return .{
            .db = db,
            .password_hasher = password_mod.PasswordHasher.init(allocator),
            .allocator = allocator,
            .nonce_manager = NonceManager.init(allocator),
            .verify_cache = VerifyCache.init(allocator),
        };
    }

    pub fn deinit(self: *AuthBackend) void {
        self.nonce_manager.deinit();
        self.verify_cache.deinit();
    }

    /// Resolve a login or recipient address to the canonical mailbox key (the
    /// `username` a maildir is stored under). A full address that is itself a
    /// registered username (a per-domain isolated mailbox, e.g.
    /// `info@example.com`) resolves to itself, so `info@a.com` and `info@b.com`
    /// are distinct accounts. Otherwise it falls back to the local-part, which
    /// keeps the legacy single-namespace behaviour and lets a user log in with
    /// either `chris` or `chris@any-hosted-domain`. Caller owns the result.
    pub fn canonicalUsername(self: *AuthBackend, address: []const u8, allocator: std.mem.Allocator) ![]const u8 {
        if (std.mem.indexOf(u8, address, "@")) |at_pos| {
            if (self.db.userExists(address) catch false)
                return allocator.dupe(u8, address);
            return allocator.dupe(u8, address[0..at_pos]);
        }
        return allocator.dupe(u8, address);
    }

    pub fn verifyCredentials(self: *AuthBackend, username: []const u8, password: []const u8) !bool {
        // Normalize username to the canonical mailbox key — a registered full
        // address (per-domain isolated mailbox) authenticates as itself; any
        // other "user@domain" falls back to the local-part. See canonicalUsername.
        const normalized_username = blk: {
            if (std.mem.indexOf(u8, username, "@")) |at_pos| {
                if (self.db.userExists(username) catch false) break :blk username;
                break :blk username[0..at_pos];
            }
            break :blk username;
        };

        // Get user from database
        var user = self.db.getUserByUsername(normalized_username) catch |err| {
            if (err == database.DatabaseError.NotFound) {
                // User not found. Returning immediately here leaks the username's
                // existence via timing (a real user runs a ~100-500ms Argon2
                // verify; a missing one would return in microseconds). Burn an
                // equivalent Argon2 KDF against the supplied password so both
                // paths cost roughly the same, then report failure.
                self.dummyVerify(password);
                return false;
            }
            return err;
        };
        defer user.deinit(self.allocator);

        // Check if user is enabled. Same timing concern as not-found: equalize
        // the cost before returning so disabled accounts aren't distinguishable.
        if (!user.enabled) {
            self.dummyVerify(password);
            return false;
        }

        // Serve repeat logins from the verification cache (skips the
        // ~100-500ms Argon2 KDF for reconnecting clients). The user row was
        // still fetched above, so disabled accounts never hit this path, and
        // the key binds user.password_hash so a changed password misses.
        const cache_key = self.verify_cache.key(normalized_username, password, user.password_hash);
        if (self.verify_cache.check(cache_key)) return true;

        // Verify password
        const ok = try self.password_hasher.verifyPassword(password, user.password_hash);
        if (ok) self.verify_cache.insert(cache_key);
        return ok;
    }

    /// Run a throwaway Argon2 KDF to match the timing of a real password verify.
    /// Used on the user-not-found / disabled paths to prevent username
    /// enumeration via response timing. The result is intentionally discarded.
    fn dummyVerify(self: *AuthBackend, password: []const u8) void {
        const h = self.password_hasher.hashPassword(password) catch return;
        self.allocator.free(h);
    }

    pub fn createUser(self: *AuthBackend, username: []const u8, password: []const u8, email: []const u8) !i64 {
        // Hash the password
        const password_hash = try self.password_hasher.hashPassword(password);
        defer self.allocator.free(password_hash);

        // Create user in database
        return try self.db.createUser(username, password_hash, email);
    }

    pub fn changePassword(self: *AuthBackend, username: []const u8, new_password: []const u8) !void {
        // Hash the new password
        const password_hash = try self.password_hasher.hashPassword(new_password);
        defer self.allocator.free(password_hash);

        // Update in database
        try self.db.updateUserPassword(username, password_hash);
    }

    /// Verify HTTP Basic Auth header and return username if valid
    /// Format: "Basic <base64(username:password)>"
    pub fn verifyBasicAuth(self: *AuthBackend, auth_header: []const u8) !?[]const u8 {
        // Check for "Basic " prefix
        if (!std.mem.startsWith(u8, auth_header, "Basic ")) {
            return null;
        }

        // Extract base64 part
        const encoded = std.mem.trimStart(u8, auth_header[6..], " ");

        // Decode credentials
        const creds = try decodeBasicAuthCredentials(self.allocator, encoded);
        defer {
            self.allocator.free(creds.username);
            self.allocator.free(creds.password);
        }

        // Verify credentials
        const valid = try self.verifyCredentials(creds.username, creds.password);
        if (!valid) {
            return null;
        }

        // Return username
        return try self.allocator.dupe(u8, creds.username);
    }

    /// Verify HTTP Digest Auth header and return username if valid
    /// Supports both SHA-256 (RFC 7616, preferred) and MD5 (RFC 2617, legacy fallback)
    pub fn verifyDigestAuth(self: *AuthBackend, auth_header: []const u8, method: []const u8, realm: []const u8) !?[]const u8 {
        const log = @import("../core/logger.zig");

        // Check for "Digest " prefix
        if (!std.mem.startsWith(u8, auth_header, "Digest ")) {
            log.warn("Digest auth: missing 'Digest ' prefix", .{});
            return null;
        }

        // Parse Digest parameters
        var params = try parseDigestAuthHeader(self.allocator, auth_header[7..]);
        defer params.deinit(self.allocator);

        // SECURITY: Only log username, never log hashes, nonces, or responses
        log.info("Digest auth: attempt for user={s}", .{params.username});

        // Verify realm matches (constant-time to avoid leaking realm info)
        if (params.realm.len != realm.len or !constantTimeEql(params.realm, realm)) {
            log.warn("Digest auth: realm mismatch", .{});
            return null;
        }

        // Verify nonce is valid
        if (!self.nonce_manager.validateNonce(params.nonce)) {
            log.warn("Digest auth: invalid/expired nonce", .{});
            return null;
        }

        // Normalize username - extract local part if email
        const normalized_username = blk: {
            if (std.mem.indexOf(u8, params.username, "@")) |at_pos| {
                break :blk params.username[0..at_pos];
            }
            break :blk params.username;
        };

        // Get user from database
        var user = self.db.getUserByUsername(normalized_username) catch |err| {
            if (err == database.DatabaseError.NotFound) {
                log.warn("Digest auth: failed for user", .{});
                return null;
            }
            return err;
        };
        defer user.deinit(self.allocator);

        if (!user.enabled) {
            log.warn("Digest auth: user disabled", .{});
            return null;
        }

        // Determine algorithm: prefer SHA-256, fall back to MD5
        const use_sha256 = if (params.algorithm) |algo|
            std.ascii.eqlIgnoreCase(algo, "SHA-256")
        else
            false;

        // Get the stored HA1 for Digest auth
        const ha1 = user.digest_ha1 orelse {
            log.warn("Digest auth: no HA1 stored for user", .{});
            return null;
        };

        // Expected response length: 64 for SHA-256, 32 for MD5
        const expected_len: usize = if (use_sha256) 64 else 32;

        // Compute HA2 = Hash(method:uri)
        var ha2_input_buf: [512]u8 = undefined;
        const ha2_input = std.fmt.bufPrint(&ha2_input_buf, "{s}:{s}", .{ method, params.uri }) catch return null;

        var ha2_hex: [64]u8 = undefined;
        if (use_sha256) {
            var ha2_hash: [32]u8 = undefined;
            Sha256.hash(ha2_input, &ha2_hash, .{});
            bytesToHex(&ha2_hash, &ha2_hex);
        } else {
            var ha2_hash: [16]u8 = undefined;
            std.crypto.hash.Md5.hash(ha2_input, &ha2_hash, .{});
            bytesToHex(&ha2_hash, ha2_hex[0..32]);
        }

        // Compute expected response based on qop
        var expected_response_buf: [1024]u8 = undefined;
        var expected_response: []const u8 = undefined;

        if (params.qop) |qop| {
            const nc = params.nc orelse return null;
            const cnonce = params.cnonce orelse return null;

            expected_response = std.fmt.bufPrint(&expected_response_buf, "{s}:{s}:{s}:{s}:{s}:{s}", .{
                ha1,
                params.nonce,
                nc,
                cnonce,
                qop,
                ha2_hex[0..expected_len],
            }) catch return null;
        } else {
            expected_response = std.fmt.bufPrint(&expected_response_buf, "{s}:{s}:{s}", .{
                ha1,
                params.nonce,
                ha2_hex[0..expected_len],
            }) catch return null;
        }

        // Hash the expected response string
        var expected_hex: [64]u8 = undefined;
        if (use_sha256) {
            var expected_hash: [32]u8 = undefined;
            Sha256.hash(expected_response, &expected_hash, .{});
            bytesToHex(&expected_hash, &expected_hex);
        } else {
            var expected_hash: [16]u8 = undefined;
            std.crypto.hash.Md5.hash(expected_response, &expected_hash, .{});
            bytesToHex(&expected_hash, expected_hex[0..32]);
        }

        // SECURITY: Zero the intermediate buffers containing hash material
        @memset(&ha2_input_buf, 0);
        @memset(&expected_response_buf, 0);

        // Normalize client response to lowercase
        var client_response_lower: [64]u8 = undefined;
        if (params.response.len != expected_len) {
            log.warn("Digest auth: response wrong length", .{});
            return null;
        }
        for (params.response, 0..) |c, i| {
            client_response_lower[i] = if (c >= 'A' and c <= 'F') c + 32 else c;
        }

        // SECURITY: Constant-time comparison to prevent timing attacks
        if (!constantTimeEql(expected_hex[0..expected_len], client_response_lower[0..expected_len])) {
            log.warn("Digest auth: failed for user", .{});
            return null;
        }

        log.info("Digest auth: success", .{});

        // Mark nonce as used (prevents replay attacks)
        self.nonce_manager.invalidateNonce(params.nonce);

        return try self.allocator.dupe(u8, normalized_username);
    }

    /// Generate a new nonce for Digest authentication
    pub fn generateNonce(self: *AuthBackend) ![]const u8 {
        return try self.nonce_manager.generateNonce();
    }
};

/// Decode SASL PLAIN base64 authentication (SMTP/IMAP/POP3)
/// Format: base64(\0username\0password)
pub fn decodeBase64Auth(allocator: std.mem.Allocator, encoded: []const u8) !Credentials {
    // Decode base64 authentication string
    const decoder = std.base64.standard.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(encoded);

    const decoded = try allocator.alloc(u8, decoded_len);
    defer {
        // SECURITY: Zero decoded credentials before freeing to prevent memory disclosure
        @memset(decoded, 0);
        allocator.free(decoded);
    }

    try decoder.decode(decoded, encoded);

    // Parse credentials in format: \0username\0password
    var parts = std.mem.splitSequence(u8, decoded, "\x00");
    _ = parts.next(); // Skip first empty part

    const username = parts.next() orelse return error.InvalidAuthFormat;
    const password = parts.next() orelse return error.InvalidAuthFormat;

    return Credentials{
        .username = try allocator.dupe(u8, username),
        .password = try allocator.dupe(u8, password),
    };
}

/// Decode HTTP Basic Auth credentials
/// Format: base64(username:password)
pub fn decodeBasicAuthCredentials(allocator: std.mem.Allocator, encoded: []const u8) !Credentials {
    // Decode base64 string
    const decoder = std.base64.standard.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(encoded);

    const decoded = try allocator.alloc(u8, decoded_len);
    defer {
        // SECURITY: Zero decoded credentials before freeing to prevent memory disclosure
        @memset(decoded, 0);
        allocator.free(decoded);
    }

    try decoder.decode(decoded, encoded);

    // Parse credentials in format: username:password
    const colon_pos = std.mem.indexOf(u8, decoded, ":") orelse return error.InvalidAuthFormat;
    const username = decoded[0..colon_pos];
    const password = decoded[colon_pos + 1 ..];

    return Credentials{
        .username = try allocator.dupe(u8, username),
        .password = try allocator.dupe(u8, password),
    };
}

/// Parse HTTP Digest Authentication header
/// Format: key1="value1", key2="value2", ...
pub fn parseDigestAuthHeader(allocator: std.mem.Allocator, header: []const u8) !DigestAuthParams {
    var username: ?[]const u8 = null;
    var realm: ?[]const u8 = null;
    var nonce: ?[]const u8 = null;
    var uri: ?[]const u8 = null;
    var response: ?[]const u8 = null;
    var qop: ?[]const u8 = null;
    var nc: ?[]const u8 = null;
    var cnonce: ?[]const u8 = null;
    var algorithm: ?[]const u8 = null;

    // Parse comma-separated key="value" pairs
    var pos: usize = 0;
    while (pos < header.len) {
        // Skip whitespace and commas
        while (pos < header.len and (header[pos] == ' ' or header[pos] == ',' or header[pos] == '\t')) {
            pos += 1;
        }
        if (pos >= header.len) break;

        // Find key
        const key_start = pos;
        while (pos < header.len and header[pos] != '=' and header[pos] != ' ') {
            pos += 1;
        }
        const key = header[key_start..pos];

        // Skip '='
        while (pos < header.len and (header[pos] == '=' or header[pos] == ' ')) {
            pos += 1;
        }
        if (pos >= header.len) break;

        // Parse value (quoted or unquoted)
        var value: []const u8 = undefined;
        if (header[pos] == '"') {
            pos += 1; // Skip opening quote
            const value_start = pos;
            while (pos < header.len and header[pos] != '"') {
                // Handle escaped quotes (backslash-escaped)
                if (header[pos] == '\\' and pos + 1 < header.len) {
                    pos += 2; // Skip escaped character
                    continue;
                }
                pos += 1;
            }
            value = header[value_start..pos];
            if (pos < header.len) pos += 1; // Skip closing quote
        } else {
            const value_start = pos;
            while (pos < header.len and header[pos] != ',' and header[pos] != ' ') {
                pos += 1;
            }
            value = header[value_start..pos];
        }

        // Store parsed value
        if (std.mem.eql(u8, key, "username")) {
            username = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "realm")) {
            realm = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "nonce")) {
            nonce = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "uri")) {
            uri = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "response")) {
            response = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "qop")) {
            qop = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "nc")) {
            nc = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "cnonce")) {
            cnonce = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "algorithm")) {
            algorithm = try allocator.dupe(u8, value);
        }
    }

    // Validate required fields
    if (username == null or realm == null or nonce == null or uri == null or response == null) {
        if (username) |u| allocator.free(u);
        if (realm) |r| allocator.free(r);
        if (nonce) |n| allocator.free(n);
        if (uri) |u| allocator.free(u);
        if (response) |r| allocator.free(r);
        if (qop) |q| allocator.free(q);
        if (nc) |n| allocator.free(n);
        if (cnonce) |c| allocator.free(c);
        if (algorithm) |a| allocator.free(a);
        return error.InvalidAuthFormat;
    }

    return DigestAuthParams{
        .username = username.?,
        .realm = realm.?,
        .nonce = nonce.?,
        .uri = uri.?,
        .response = response.?,
        .qop = qop,
        .nc = nc,
        .cnonce = cnonce,
        .algorithm = algorithm,
    };
}

// =============================================================================
// Password Reset Flow
// =============================================================================

/// Password reset token
pub const ResetToken = struct {
    token: [32]u8,
    token_hash: [32]u8, // Stored hash for verification
    username: []const u8,
    email: []const u8,
    created_at: i64,
    expires_at: i64,
    used: bool,
    ip_address: ?[]const u8,

    pub fn deinit(self: *ResetToken, allocator: std.mem.Allocator) void {
        allocator.free(self.username);
        allocator.free(self.email);
        if (self.ip_address) |ip| allocator.free(ip);
    }

    /// Generate token string for URL
    pub fn toUrlToken(self: *const ResetToken, allocator: std.mem.Allocator) ![]u8 {
        var hex_buf: [64]u8 = undefined;
        bytesToHex(&self.token, &hex_buf);
        return try allocator.dupe(u8, &hex_buf);
    }

    /// Check if token is expired
    pub fn isExpired(self: *const ResetToken, current_time: i64) bool {
        return current_time > self.expires_at;
    }

    /// Check if token is valid (not used and not expired)
    pub fn isValid(self: *const ResetToken, current_time: i64) bool {
        return !self.used and !self.isExpired(current_time);
    }
};

/// Rate limiting for password reset requests
pub const ResetRateLimiter = struct {
    allocator: std.mem.Allocator,
    attempts: std.StringHashMap(AttemptInfo),
    max_attempts_per_hour: u32,
    lockout_duration_minutes: u32,

    const AttemptInfo = struct {
        count: u32,
        first_attempt: i64,
        last_attempt: i64,
        locked_until: ?i64,
    };

    pub fn init(allocator: std.mem.Allocator, max_attempts: u32, lockout_minutes: u32) ResetRateLimiter {
        return .{
            .allocator = allocator,
            .attempts = std.StringHashMap(AttemptInfo).init(allocator),
            .max_attempts_per_hour = max_attempts,
            .lockout_duration_minutes = lockout_minutes,
        };
    }

    pub fn deinit(self: *ResetRateLimiter) void {
        var iter = self.attempts.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.attempts.deinit();
    }

    /// Check if a request is allowed
    pub fn checkAllowed(self: *ResetRateLimiter, identifier: []const u8) RateLimitResult {
        const now = getCurrentTimestamp();

        if (self.attempts.getPtr(identifier)) |info| {
            // Check if locked out
            if (info.locked_until) |locked_until| {
                if (now < locked_until) {
                    return .{
                        .allowed = false,
                        .reason = .locked_out,
                        .retry_after = @intCast(locked_until - now),
                    };
                }
                // Lockout expired, reset
                info.locked_until = null;
                info.count = 0;
                info.first_attempt = now;
            }

            // Check if window expired (1 hour)
            if (now - info.first_attempt > 3600) {
                info.count = 0;
                info.first_attempt = now;
            }

            // Check if max attempts exceeded
            if (info.count >= self.max_attempts_per_hour) {
                info.locked_until = now + @as(i64, self.lockout_duration_minutes) * 60;
                return .{
                    .allowed = false,
                    .reason = .too_many_attempts,
                    .retry_after = @as(u32, self.lockout_duration_minutes) * 60,
                };
            }
        }

        return .{
            .allowed = true,
            .reason = .allowed,
            .retry_after = 0,
        };
    }

    /// Record an attempt
    pub fn recordAttempt(self: *ResetRateLimiter, identifier: []const u8) !void {
        const now = getCurrentTimestamp();

        const result = try self.attempts.getOrPut(identifier);
        if (result.found_existing) {
            result.value_ptr.count += 1;
            result.value_ptr.last_attempt = now;
        } else {
            result.key_ptr.* = try self.allocator.dupe(u8, identifier);
            result.value_ptr.* = .{
                .count = 1,
                .first_attempt = now,
                .last_attempt = now,
                .locked_until = null,
            };
        }
    }

    /// Clear attempts for an identifier (after successful reset)
    pub fn clearAttempts(self: *ResetRateLimiter, identifier: []const u8) void {
        if (self.attempts.fetchRemove(identifier)) |entry| {
            self.allocator.free(entry.key);
        }
    }
};

pub const RateLimitResult = struct {
    allowed: bool,
    reason: RateLimitReason,
    retry_after: u32, // seconds

    pub const RateLimitReason = enum {
        allowed,
        too_many_attempts,
        locked_out,
    };
};

/// Password reset manager
pub const PasswordResetManager = struct {
    allocator: std.mem.Allocator,
    db: *database.Database,
    rate_limiter: ResetRateLimiter,
    tokens: std.StringHashMap(ResetToken),
    config: ResetConfig,
    audit_callback: ?*const fn (event: AuditEvent) void,

    pub const ResetConfig = struct {
        token_expiry_minutes: u32 = 30,
        max_attempts_per_hour: u32 = 5,
        lockout_duration_minutes: u32 = 60,
        min_password_length: u32 = 8,
        require_special_char: bool = true,
        require_number: bool = true,
        require_uppercase: bool = true,
    };

    pub const AuditEvent = struct {
        event_type: EventType,
        username: []const u8,
        email: ?[]const u8,
        ip_address: ?[]const u8,
        success: bool,
        details: ?[]const u8,
        timestamp: i64,

        pub const EventType = enum {
            reset_requested,
            reset_completed,
            reset_failed,
            token_expired,
            rate_limited,
        };
    };

    pub fn init(allocator: std.mem.Allocator, db: *database.Database, config: ResetConfig) PasswordResetManager {
        return .{
            .allocator = allocator,
            .db = db,
            .rate_limiter = ResetRateLimiter.init(allocator, config.max_attempts_per_hour, config.lockout_duration_minutes),
            .tokens = std.StringHashMap(ResetToken).init(allocator),
            .config = config,
            .audit_callback = null,
        };
    }

    pub fn deinit(self: *PasswordResetManager) void {
        var iter = self.tokens.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            var token = entry.value_ptr.*;
            token.deinit(self.allocator);
        }
        self.tokens.deinit();
        self.rate_limiter.deinit();
    }

    /// Set audit callback
    pub fn setAuditCallback(self: *PasswordResetManager, callback: *const fn (AuditEvent) void) void {
        self.audit_callback = callback;
    }

    /// Request a password reset
    pub fn requestReset(
        self: *PasswordResetManager,
        email: []const u8,
        ip_address: ?[]const u8,
    ) !ResetRequestResult {
        const now = getCurrentTimestamp();

        // Check rate limiting by email
        const rate_result = self.rate_limiter.checkAllowed(email);
        if (!rate_result.allowed) {
            self.emitAudit(.{
                .event_type = .rate_limited,
                .username = "",
                .email = email,
                .ip_address = ip_address,
                .success = false,
                .details = "Rate limit exceeded",
                .timestamp = now,
            });

            return ResetRequestResult{
                .success = false,
                .token = null,
                .error_code = .rate_limited,
                .retry_after = rate_result.retry_after,
            };
        }

        // Record attempt
        try self.rate_limiter.recordAttempt(email);

        // Look up user by email
        const user = self.db.getUserByEmail(email) catch |err| {
            if (err == database.DatabaseError.NotFound) {
                // Don't reveal that email doesn't exist - return success anyway
                // but don't actually create a token
                return ResetRequestResult{
                    .success = true, // Pretend success
                    .token = null,
                    .error_code = null,
                    .retry_after = 0,
                };
            }
            return err;
        };
        defer {
            var u = user;
            u.deinit(self.allocator);
        }

        // Generate secure token
        var token_bytes: [32]u8 = undefined;
        io_compat.randomBytes(&token_bytes);

        // Hash token for storage
        var token_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&token_bytes, &token_hash, .{});

        const token = ResetToken{
            .token = token_bytes,
            .token_hash = token_hash,
            .username = try self.allocator.dupe(u8, user.username),
            .email = try self.allocator.dupe(u8, email),
            .created_at = now,
            .expires_at = now + @as(i64, self.config.token_expiry_minutes) * 60,
            .used = false,
            .ip_address = if (ip_address) |ip| try self.allocator.dupe(u8, ip) else null,
        };

        // Opportunistic sweep: nothing calls cleanupExpiredTokens
        // periodically, so expired/used tokens would otherwise accumulate
        // until process restart.
        if (self.tokens.count() >= 1024) _ = self.cleanupExpiredTokens();

        // Store token (keyed by hash)
        var hash_hex: [64]u8 = undefined;
        bytesToHex(&token_hash, &hash_hex);
        const key = try self.allocator.dupe(u8, &hash_hex);
        try self.tokens.put(key, token);

        self.emitAudit(.{
            .event_type = .reset_requested,
            .username = user.username,
            .email = email,
            .ip_address = ip_address,
            .success = true,
            .details = null,
            .timestamp = now,
        });

        return ResetRequestResult{
            .success = true,
            .token = token_bytes,
            .error_code = null,
            .retry_after = 0,
        };
    }

    /// Complete password reset with token
    pub fn completeReset(
        self: *PasswordResetManager,
        token_hex: []const u8,
        new_password: []const u8,
        ip_address: ?[]const u8,
    ) !ResetCompleteResult {
        const now = getCurrentTimestamp();

        // Decode token
        if (token_hex.len != 64) {
            return ResetCompleteResult{
                .success = false,
                .error_code = .invalid_token,
            };
        }

        var token_bytes: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&token_bytes, token_hex) catch {
            return ResetCompleteResult{
                .success = false,
                .error_code = .invalid_token,
            };
        };

        // Hash to find stored token
        var token_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&token_bytes, &token_hash, .{});

        var hash_hex: [64]u8 = undefined;
        bytesToHex(&token_hash, &hash_hex);

        // Look up token
        const token_ptr = self.tokens.getPtr(&hash_hex) orelse {
            return ResetCompleteResult{
                .success = false,
                .error_code = .invalid_token,
            };
        };

        // Check if valid
        if (!token_ptr.isValid(now)) {
            if (token_ptr.isExpired(now)) {
                self.emitAudit(.{
                    .event_type = .token_expired,
                    .username = token_ptr.username,
                    .email = token_ptr.email,
                    .ip_address = ip_address,
                    .success = false,
                    .details = "Token expired",
                    .timestamp = now,
                });

                return ResetCompleteResult{
                    .success = false,
                    .error_code = .token_expired,
                };
            }

            return ResetCompleteResult{
                .success = false,
                .error_code = .token_used,
            };
        }

        // Validate new password
        const password_valid = self.validatePassword(new_password);
        if (!password_valid.valid) {
            return ResetCompleteResult{
                .success = false,
                .error_code = .weak_password,
            };
        }

        // Hash and update password
        var hasher = password_mod.PasswordHasher.init(self.allocator);
        const password_hash = try hasher.hashPassword(new_password);
        defer self.allocator.free(password_hash);

        self.db.updateUserPassword(token_ptr.username, password_hash) catch |err| {
            self.emitAudit(.{
                .event_type = .reset_failed,
                .username = token_ptr.username,
                .email = token_ptr.email,
                .ip_address = ip_address,
                .success = false,
                .details = "Database update failed",
                .timestamp = now,
            });
            return err;
        };

        // Mark token as used
        token_ptr.used = true;

        // Clear rate limiting for this email
        self.rate_limiter.clearAttempts(token_ptr.email);

        self.emitAudit(.{
            .event_type = .reset_completed,
            .username = token_ptr.username,
            .email = token_ptr.email,
            .ip_address = ip_address,
            .success = true,
            .details = null,
            .timestamp = now,
        });

        return ResetCompleteResult{
            .success = true,
            .error_code = null,
        };
    }

    /// Validate password against policy
    pub fn validatePassword(self: *PasswordResetManager, password: []const u8) PasswordValidation {
        var issues = std.ArrayList([]const u8).init(self.allocator);

        if (password.len < self.config.min_password_length) {
            issues.append("Password too short") catch {};
        }

        if (self.config.require_uppercase) {
            var has_upper = false;
            for (password) |c| {
                if (c >= 'A' and c <= 'Z') {
                    has_upper = true;
                    break;
                }
            }
            if (!has_upper) {
                issues.append("Requires uppercase letter") catch {};
            }
        }

        if (self.config.require_number) {
            var has_number = false;
            for (password) |c| {
                if (c >= '0' and c <= '9') {
                    has_number = true;
                    break;
                }
            }
            if (!has_number) {
                issues.append("Requires number") catch {};
            }
        }

        if (self.config.require_special_char) {
            var has_special = false;
            const special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~";
            for (password) |c| {
                if (std.mem.indexOfScalar(u8, special_chars, c) != null) {
                    has_special = true;
                    break;
                }
            }
            if (!has_special) {
                issues.append("Requires special character") catch {};
            }
        }

        return PasswordValidation{
            .valid = issues.items.len == 0,
            .issues = issues.toOwnedSlice() catch &[_][]const u8{},
        };
    }

    /// Clean up expired tokens
    pub fn cleanupExpiredTokens(self: *PasswordResetManager) usize {
        const now = getCurrentTimestamp();
        var removed: usize = 0;

        var iter = self.tokens.iterator();
        var to_remove: std.ArrayList([]const u8) = .empty;
        defer to_remove.deinit(self.allocator);

        while (iter.next()) |entry| {
            if (entry.value_ptr.isExpired(now) or entry.value_ptr.used) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            if (self.tokens.fetchRemove(key)) |entry| {
                self.allocator.free(entry.key);
                var token = entry.value;
                token.deinit(self.allocator);
                removed += 1;
            }
        }

        return removed;
    }

    /// Emit audit event
    fn emitAudit(self: *PasswordResetManager, event: AuditEvent) void {
        if (self.audit_callback) |callback| {
            callback(event);
        }
    }
};

pub const ResetRequestResult = struct {
    success: bool,
    token: ?[32]u8, // Only returned for email sending
    error_code: ?ResetErrorCode,
    retry_after: u32, // seconds
};

pub const ResetCompleteResult = struct {
    success: bool,
    error_code: ?ResetErrorCode,
};

pub const ResetErrorCode = enum {
    rate_limited,
    invalid_token,
    token_expired,
    token_used,
    weak_password,
    user_not_found,
    database_error,
};

pub const PasswordValidation = struct {
    valid: bool,
    issues: []const []const u8,
};

/// Email notification for password reset
pub const ResetEmailNotifier = struct {
    allocator: std.mem.Allocator,
    smtp_host: []const u8,
    smtp_port: u16,
    from_address: []const u8,
    base_url: []const u8,

    pub fn init(
        allocator: std.mem.Allocator,
        smtp_host: []const u8,
        smtp_port: u16,
        from_address: []const u8,
        base_url: []const u8,
    ) ResetEmailNotifier {
        return .{
            .allocator = allocator,
            .smtp_host = smtp_host,
            .smtp_port = smtp_port,
            .from_address = from_address,
            .base_url = base_url,
        };
    }

    /// Send password reset email
    pub fn sendResetEmail(
        self: *ResetEmailNotifier,
        to_email: []const u8,
        username: []const u8,
        token: [32]u8,
        expiry_minutes: u32,
    ) !void {
        var token_hex: [64]u8 = undefined;
        bytesToHex(&token, &token_hex);

        const reset_link = try std.fmt.allocPrint(self.allocator, "{s}/reset-password?token={s}", .{
            self.base_url,
            &token_hex,
        });
        defer self.allocator.free(reset_link);

        const body = try std.fmt.allocPrint(self.allocator,
            \\Hello {s},
            \\
            \\You have requested a password reset for your account.
            \\
            \\Click the link below to reset your password:
            \\{s}
            \\
            \\This link will expire in {d} minutes.
            \\
            \\If you did not request this reset, please ignore this email.
            \\
            \\Security Notice: Never share this link with anyone.
        , .{ username, reset_link, expiry_minutes });
        defer self.allocator.free(body);

        // In a real implementation, this would send via SMTP
        // For now, the body is formatted but not sent
        _ = to_email;
    }

    /// Send confirmation email after password change
    pub fn sendConfirmationEmail(
        self: *ResetEmailNotifier,
        to_email: []const u8,
        username: []const u8,
        ip_address: ?[]const u8,
    ) !void {
        const body = try std.fmt.allocPrint(self.allocator,
            \\Hello {s},
            \\
            \\Your password has been successfully changed.
            \\
            \\If you did not make this change, please contact support immediately.
            \\
            \\IP Address: {s}
            \\Time: {d}
        , .{
            username,
            ip_address orelse "Unknown",
            getCurrentTimestamp(),
        });
        defer self.allocator.free(body);

        // Would send via SMTP - body is formatted but not sent in this stub
        _ = to_email;
    }
};

// Tests
test "rate limiter" {
    const testing = std.testing;

    var limiter = ResetRateLimiter.init(testing.allocator, 3, 60);
    defer limiter.deinit();

    // First 3 attempts should be allowed
    try testing.expect(limiter.checkAllowed("test@example.com").allowed);
    try limiter.recordAttempt("test@example.com");
    try testing.expect(limiter.checkAllowed("test@example.com").allowed);
    try limiter.recordAttempt("test@example.com");
    try testing.expect(limiter.checkAllowed("test@example.com").allowed);
    try limiter.recordAttempt("test@example.com");

    // 4th attempt should be rate limited
    const result = limiter.checkAllowed("test@example.com");
    try testing.expect(!result.allowed);
    try testing.expectEqual(RateLimitResult.RateLimitReason.too_many_attempts, result.reason);
}

test "reset token validation" {
    var token = ResetToken{
        .token = undefined,
        .token_hash = undefined,
        .username = "testuser",
        .email = "test@example.com",
        .created_at = 1000,
        .expires_at = 2000,
        .used = false,
        .ip_address = null,
    };

    // Valid token
    try std.testing.expect(token.isValid(1500));

    // Expired token
    try std.testing.expect(!token.isValid(2500));

    // Used token
    token.used = true;
    try std.testing.expect(!token.isValid(1500));
}
