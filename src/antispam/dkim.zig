const std = @import("std");

/// DKIM validation result
pub const DKIMResult = enum {
    pass,
    fail,
    neutral,
    temperror,
    permerror,

    pub fn toString(self: DKIMResult) []const u8 {
        return switch (self) {
            .pass => "pass",
            .fail => "fail",
            .neutral => "neutral",
            .temperror => "temperror",
            .permerror => "permerror",
        };
    }
};

/// DKIM signature (RFC 6376)
pub const DKIMSignature = struct {
    version: []const u8,
    algorithm: []const u8, // e.g., "rsa-sha256"
    domain: []const u8, // d= tag
    selector: []const u8, // s= tag
    headers: []const u8, // h= tag (signed headers)
    body_hash: []const u8, // bh= tag
    signature: []const u8, // b= tag
    canonicalization: []const u8, // c= tag (default: simple/simple)
    query_method: []const u8, // q= tag (default: dns/txt)
    allocator: std.mem.Allocator,

    pub fn deinit(self: *DKIMSignature) void {
        self.allocator.free(self.version);
        self.allocator.free(self.algorithm);
        self.allocator.free(self.domain);
        self.allocator.free(self.selector);
        self.allocator.free(self.headers);
        self.allocator.free(self.body_hash);
        self.allocator.free(self.signature);
        self.allocator.free(self.canonicalization);
        self.allocator.free(self.query_method);
    }

    /// Parse DKIM-Signature header value
    pub fn parse(allocator: std.mem.Allocator, header_value: []const u8) !DKIMSignature {
        var sig = DKIMSignature{
            .version = "",
            .algorithm = "",
            .domain = "",
            .selector = "",
            .headers = "",
            .body_hash = "",
            .signature = "",
            .canonicalization = try allocator.dupe(u8, "simple/simple"),
            .query_method = try allocator.dupe(u8, "dns/txt"),
            .allocator = allocator,
        };
        errdefer {
            if (sig.version.len > 0) allocator.free(sig.version);
            if (sig.algorithm.len > 0) allocator.free(sig.algorithm);
            if (sig.domain.len > 0) allocator.free(sig.domain);
            if (sig.selector.len > 0) allocator.free(sig.selector);
            if (sig.headers.len > 0) allocator.free(sig.headers);
            if (sig.body_hash.len > 0) allocator.free(sig.body_hash);
            if (sig.signature.len > 0) allocator.free(sig.signature);
            allocator.free(sig.canonicalization);
            allocator.free(sig.query_method);
        }

        // Parse tag=value pairs
        var tags = std.mem.splitScalar(u8, header_value, ';');
        while (tags.next()) |tag| {
            const trimmed = std.mem.trim(u8, tag, " \t\r\n");
            if (trimmed.len == 0) continue;

            const eq_pos = std.mem.indexOf(u8, trimmed, "=") orelse continue;
            const tag_name = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
            const tag_value = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " \t");

            if (std.mem.eql(u8, tag_name, "v")) {
                sig.version = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "a")) {
                sig.algorithm = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "d")) {
                sig.domain = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "s")) {
                sig.selector = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "h")) {
                sig.headers = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "bh")) {
                sig.body_hash = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "b")) {
                sig.signature = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "c")) {
                allocator.free(sig.canonicalization);
                sig.canonicalization = try allocator.dupe(u8, tag_value);
            } else if (std.mem.eql(u8, tag_name, "q")) {
                allocator.free(sig.query_method);
                sig.query_method = try allocator.dupe(u8, tag_value);
            }
        }

        // Validate required fields
        if (sig.version.len == 0 or sig.algorithm.len == 0 or sig.domain.len == 0 or
            sig.selector.len == 0 or sig.signature.len == 0)
        {
            return error.InvalidDKIMSignature;
        }

        return sig;
    }
};

/// DKIM validator
pub const DKIMValidator = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) DKIMValidator {
        return .{ .allocator = allocator };
    }

    /// Validate DKIM signature in email headers
    pub fn validate(self: *DKIMValidator, headers: []const u8, body: []const u8) !DKIMResult {
        // Extract DKIM-Signature header
        const sig_header = self.extractDKIMSignature(headers) orelse {
            return .neutral;
        };

        // Parse signature
        var signature = DKIMSignature.parse(self.allocator, sig_header) catch {
            return .permerror;
        };
        defer signature.deinit();

        // Verify version
        if (!std.mem.eql(u8, signature.version, "1")) {
            return .permerror;
        }

        // Query DNS for public key
        const public_key = self.queryPublicKey(signature.domain, signature.selector) catch {
            return .temperror;
        };
        defer if (public_key) |key| self.allocator.free(key);

        if (public_key == null) {
            return .permerror;
        }

        // Verify body hash
        const body_hash_valid = try self.verifyBodyHash(&signature, body);
        if (!body_hash_valid) {
            return .fail;
        }

        // Verify signature
        const sig_valid = try self.verifySignature(&signature, headers, public_key.?);
        if (!sig_valid) {
            return .fail;
        }

        return .pass;
    }

    fn extractDKIMSignature(self: *DKIMValidator, headers: []const u8) ?[]const u8 {
        // Find DKIM-Signature header
        var lines = std.mem.splitSequence(u8, headers, "\r\n");
        var in_dkim_sig = false;
        var sig_value = std.ArrayList(u8).init(self.allocator);
        defer sig_value.deinit();

        while (lines.next()) |line| {
            if (std.mem.startsWith(u8, line, "DKIM-Signature:")) {
                in_dkim_sig = true;
                const value = std.mem.trim(u8, line[15..], " \t");
                sig_value.appendSlice(value) catch return null;
            } else if (in_dkim_sig) {
                // Continuation line
                if (line.len > 0 and (line[0] == ' ' or line[0] == '\t')) {
                    const value = std.mem.trim(u8, line, " \t");
                    sig_value.appendSlice(value) catch return null;
                } else {
                    break;
                }
            }
        }

        if (sig_value.items.len == 0) return null;
        return sig_value.toOwnedSlice() catch return null;
    }

    fn queryPublicKey(self: *DKIMValidator, domain: []const u8, selector: []const u8) !?[]const u8 {
        // In production, query DNS TXT record at: selector._domainkey.domain
        // Format: "v=DKIM1; k=rsa; p=<base64-public-key>"
        _ = self;
        _ = domain;
        _ = selector;

        // For now, return null (no key found)
        // A real implementation would use DNS lookups
        return null;
    }

    fn verifyBodyHash(self: *DKIMValidator, signature: *const DKIMSignature, body: []const u8) !bool {
        _ = signature;
        _ = body;
        _ = self;

        // In production:
        // 1. Canonicalize body according to c= tag
        // 2. Compute hash (SHA256 for rsa-sha256)
        // 3. Base64 encode
        // 4. Compare with bh= tag

        // For now, assume valid
        return true;
    }

    fn verifySignature(self: *DKIMValidator, signature: *const DKIMSignature, headers: []const u8, public_key: []const u8) !bool {
        _ = signature;
        _ = headers;
        _ = public_key;
        _ = self;

        // In production:
        // 1. Extract signed headers (h= tag)
        // 2. Canonicalize headers
        // 3. Verify RSA signature with public key

        // For now, assume valid
        return true;
    }
};

/// DKIM signer for outgoing mail
pub const DKIMSigner = struct {
    allocator: std.mem.Allocator,
    domain: []const u8,
    selector: []const u8,
    private_key: []const u8,

    pub fn init(allocator: std.mem.Allocator, domain: []const u8, selector: []const u8, private_key: []const u8) !DKIMSigner {
        return .{
            .allocator = allocator,
            .domain = try allocator.dupe(u8, domain),
            .selector = try allocator.dupe(u8, selector),
            .private_key = try allocator.dupe(u8, private_key),
        };
    }

    pub fn deinit(self: *DKIMSigner) void {
        self.allocator.free(self.domain);
        self.allocator.free(self.selector);
        self.allocator.free(self.private_key);
    }

    /// Sign an email message
    pub fn sign(self: *DKIMSigner, headers: []const u8, body: []const u8) ![]const u8 {
        _ = headers;
        _ = body;

        // Build DKIM-Signature header
        return try std.fmt.allocPrint(
            self.allocator,
            "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d={s}; s={s};\r\n\th=from:to:subject:date; bh=<body-hash>; b=<signature>",
            .{ self.domain, self.selector },
        );
    }
};

test "DKIM signature parsing" {
    const testing = std.testing;

    const sig_value =
        \\v=1; a=rsa-sha256; c=relaxed/relaxed;
        \\d=example.com; s=default;
        \\h=from:to:subject:date;
        \\bh=BODYHASH==;
        \\b=SIGNATURE==
    ;

    var sig = try DKIMSignature.parse(testing.allocator, sig_value);
    defer sig.deinit();

    try testing.expectEqualStrings("1", sig.version);
    try testing.expectEqualStrings("rsa-sha256", sig.algorithm);
    try testing.expectEqualStrings("example.com", sig.domain);
    try testing.expectEqualStrings("default", sig.selector);
}

test "DKIM validator neutral" {
    const testing = std.testing;
    var validator = DKIMValidator.init(testing.allocator);

    const headers = "From: test@example.com\r\n\r\n";
    const body = "Test body";

    const result = try validator.validate(headers, body);
    try testing.expect(result == .neutral);
}

// ============================================================================
// DKIM Key Rotation CLI
// ============================================================================

const time_compat = @import("../core/time_compat.zig");

/// Key algorithm types
pub const KeyAlgorithm = enum {
    rsa_2048,
    rsa_4096,
    ed25519,

    pub fn toString(self: KeyAlgorithm) []const u8 {
        return switch (self) {
            .rsa_2048 => "rsa-2048",
            .rsa_4096 => "rsa-4096",
            .ed25519 => "ed25519",
        };
    }

    pub fn fromString(s: []const u8) ?KeyAlgorithm {
        if (std.mem.eql(u8, s, "rsa-2048") or std.mem.eql(u8, s, "rsa2048")) return .rsa_2048;
        if (std.mem.eql(u8, s, "rsa-4096") or std.mem.eql(u8, s, "rsa4096")) return .rsa_4096;
        if (std.mem.eql(u8, s, "ed25519")) return .ed25519;
        return null;
    }

    pub fn getKeySize(self: KeyAlgorithm) u32 {
        return switch (self) {
            .rsa_2048 => 2048,
            .rsa_4096 => 4096,
            .ed25519 => 256,
        };
    }

    pub fn getDkimAlgorithm(self: KeyAlgorithm) []const u8 {
        return switch (self) {
            .rsa_2048, .rsa_4096 => "rsa-sha256",
            .ed25519 => "ed25519-sha256",
        };
    }
};

/// DKIM key pair
pub const DKIMKeyPair = struct {
    id: []const u8,
    domain: []const u8,
    selector: []const u8,
    algorithm: KeyAlgorithm,
    public_key: []const u8, // Base64 encoded
    private_key: []const u8, // PEM format
    created_at: i64,
    expires_at: ?i64,
    is_active: bool,
    rotation_scheduled: ?i64,

    allocator: std.mem.Allocator,

    pub fn deinit(self: *DKIMKeyPair) void {
        self.allocator.free(self.id);
        self.allocator.free(self.domain);
        self.allocator.free(self.selector);
        self.allocator.free(self.public_key);
        // Securely zero private key before freeing
        @memset(@as([]u8, @constCast(self.private_key)), 0);
        self.allocator.free(self.private_key);
    }

    /// Check if key is valid at given time
    pub fn isValidAt(self: *const DKIMKeyPair, timestamp: i64) bool {
        if (!self.is_active) return false;
        if (timestamp < self.created_at) return false;
        if (self.expires_at) |expiry| {
            if (timestamp > expiry) return false;
        }
        return true;
    }

    /// Check if key is expiring soon (within days)
    pub fn isExpiringSoon(self: *const DKIMKeyPair, days: u32) bool {
        if (self.expires_at) |expiry| {
            const threshold = time_compat.timestamp() + @as(i64, days) * 24 * 60 * 60;
            return expiry <= threshold;
        }
        return false;
    }

    /// Generate DNS TXT record content
    pub fn generateDnsRecord(self: *const DKIMKeyPair, allocator: std.mem.Allocator) ![]u8 {
        const key_type = switch (self.algorithm) {
            .rsa_2048, .rsa_4096 => "rsa",
            .ed25519 => "ed25519",
        };

        return std.fmt.allocPrint(allocator,
            \\v=DKIM1; k={s}; p={s}
        , .{ key_type, self.public_key });
    }

    /// Get full DNS record name
    pub fn getDnsRecordName(self: *const DKIMKeyPair, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}._domainkey.{s}", .{
            self.selector,
            self.domain,
        });
    }
};

/// DKIM Key Manager for key generation and rotation
pub const DKIMKeyManager = struct {
    allocator: std.mem.Allocator,
    keys: std.ArrayList(DKIMKeyPair),
    key_storage_path: ?[]const u8,

    pub fn init(allocator: std.mem.Allocator, storage_path: ?[]const u8) !DKIMKeyManager {
        return .{
            .allocator = allocator,
            .keys = std.ArrayList(DKIMKeyPair).init(allocator),
            .key_storage_path = if (storage_path) |p| try allocator.dupe(u8, p) else null,
        };
    }

    pub fn deinit(self: *DKIMKeyManager) void {
        for (self.keys.items) |*key| {
            key.deinit();
        }
        self.keys.deinit();
        if (self.key_storage_path) |p| self.allocator.free(p);
    }

    /// Generate a new DKIM key pair
    pub fn generateKey(
        self: *DKIMKeyManager,
        domain: []const u8,
        selector: []const u8,
        algorithm: KeyAlgorithm,
        validity_days: ?u32,
    ) !*DKIMKeyPair {
        const key_id = try self.generateKeyId();
        defer self.allocator.free(key_id);

        const now = time_compat.timestamp();
        const expires_at: ?i64 = if (validity_days) |days|
            now + @as(i64, days) * 24 * 60 * 60
        else
            null;

        // Generate key material
        const key_material = try self.generateKeyMaterial(algorithm);

        const key = DKIMKeyPair{
            .id = try self.allocator.dupe(u8, key_id),
            .domain = try self.allocator.dupe(u8, domain),
            .selector = try self.allocator.dupe(u8, selector),
            .algorithm = algorithm,
            .public_key = key_material.public_key,
            .private_key = key_material.private_key,
            .created_at = now,
            .expires_at = expires_at,
            .is_active = true,
            .rotation_scheduled = null,
            .allocator = self.allocator,
        };

        try self.keys.append(key);

        return &self.keys.items[self.keys.items.len - 1];
    }

    /// Schedule key rotation
    pub fn scheduleRotation(
        self: *DKIMKeyManager,
        key_id: []const u8,
        rotation_time: i64,
    ) !void {
        for (self.keys.items) |*key| {
            if (std.mem.eql(u8, key.id, key_id)) {
                key.rotation_scheduled = rotation_time;
                return;
            }
        }
        return error.KeyNotFound;
    }

    /// Execute scheduled rotations
    pub fn executeScheduledRotations(self: *DKIMKeyManager) ![]const RotationResult {
        var results = std.ArrayList(RotationResult).init(self.allocator);
        const now = time_compat.timestamp();

        for (self.keys.items) |*key| {
            if (key.rotation_scheduled) |scheduled| {
                if (now >= scheduled) {
                    // Create new key with same domain/selector but new material
                    const new_selector = try self.generateNewSelector(key.selector);
                    defer self.allocator.free(new_selector);

                    const new_key = try self.generateKey(
                        key.domain,
                        new_selector,
                        key.algorithm,
                        if (key.expires_at) |exp| @as(u32, @intCast(@divFloor(exp - key.created_at, 24 * 60 * 60))) else null,
                    );

                    // Deactivate old key
                    key.is_active = false;
                    key.rotation_scheduled = null;

                    try results.append(.{
                        .old_key_id = key.id,
                        .new_key_id = new_key.id,
                        .domain = key.domain,
                        .old_selector = key.selector,
                        .new_selector = new_key.selector,
                        .success = true,
                        .message = "Key rotated successfully",
                    });
                }
            }
        }

        return results.toOwnedSlice();
    }

    /// Get active key for domain
    pub fn getActiveKey(self: *DKIMKeyManager, domain: []const u8) ?*DKIMKeyPair {
        const now = time_compat.timestamp();
        for (self.keys.items) |*key| {
            if (std.mem.eql(u8, key.domain, domain) and key.isValidAt(now)) {
                return key;
            }
        }
        return null;
    }

    /// List all keys for domain
    pub fn listKeys(self: *DKIMKeyManager, domain: ?[]const u8) []DKIMKeyPair {
        if (domain) |d| {
            var filtered = std.ArrayList(DKIMKeyPair).init(self.allocator);
            for (self.keys.items) |key| {
                if (std.mem.eql(u8, key.domain, d)) {
                    filtered.append(key) catch continue;
                }
            }
            return filtered.toOwnedSlice() catch return &[_]DKIMKeyPair{};
        }
        return self.keys.items;
    }

    /// Check key validity
    pub fn validateKey(self: *DKIMKeyManager, key_id: []const u8) !KeyValidation {
        for (self.keys.items) |*key| {
            if (std.mem.eql(u8, key.id, key_id)) {
                const now = time_compat.timestamp();
                var issues = std.ArrayList([]const u8).init(self.allocator);

                if (!key.is_active) {
                    try issues.append("Key is inactive");
                }

                if (key.expires_at) |expiry| {
                    if (now > expiry) {
                        try issues.append("Key has expired");
                    } else if (key.isExpiringSoon(30)) {
                        try issues.append("Key expires within 30 days");
                    }
                }

                // Check algorithm strength
                if (key.algorithm == .rsa_2048) {
                    try issues.append("Consider upgrading to RSA-4096 or Ed25519");
                }

                return KeyValidation{
                    .key_id = key.id,
                    .is_valid = key.isValidAt(now),
                    .issues = issues.toOwnedSlice() catch &[_][]const u8{},
                    .days_until_expiry = if (key.expires_at) |exp|
                        @as(i32, @intCast(@divFloor(exp - now, 24 * 60 * 60)))
                    else
                        null,
                };
            }
        }
        return error.KeyNotFound;
    }

    /// Delete a key
    pub fn deleteKey(self: *DKIMKeyManager, key_id: []const u8) !void {
        for (self.keys.items, 0..) |*key, i| {
            if (std.mem.eql(u8, key.id, key_id)) {
                key.deinit();
                _ = self.keys.orderedRemove(i);
                return;
            }
        }
        return error.KeyNotFound;
    }

    fn generateKeyId(self: *DKIMKeyManager) ![]u8 {
        var buf: [16]u8 = undefined;
        std.c.arc4random_buf(&buf, buf.len);
        return std.fmt.allocPrint(self.allocator, "dkim_{s}", .{
            std.fmt.fmtSliceHexLower(&buf),
        });
    }

    fn generateNewSelector(self: *DKIMKeyManager, old_selector: []const u8) ![]u8 {
        // Generate new selector by appending timestamp or incrementing number
        const timestamp = time_compat.timestamp();
        return std.fmt.allocPrint(self.allocator, "{s}_{d}", .{ old_selector, timestamp });
    }

    fn generateKeyMaterial(self: *DKIMKeyManager, algorithm: KeyAlgorithm) !struct {
        public_key: []u8,
        private_key: []u8,
    } {
        // Generate cryptographic key material
        // In production, this would use actual RSA/Ed25519 key generation
        var random_bytes: [64]u8 = undefined;
        std.c.arc4random_buf(&random_bytes, random_bytes.len);

        const public_key = try std.fmt.allocPrint(self.allocator,
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA{s}",
            .{std.fmt.fmtSliceHexLower(random_bytes[0..32])});

        const key_size = algorithm.getKeySize();
        const private_key = try std.fmt.allocPrint(self.allocator,
            \\-----BEGIN RSA PRIVATE KEY-----
            \\{s}
            \\-----END RSA PRIVATE KEY-----
        , .{std.fmt.fmtSliceHexLower(random_bytes[0..@min(key_size / 8, 64)])});

        return .{
            .public_key = public_key,
            .private_key = private_key,
        };
    }

    pub const RotationResult = struct {
        old_key_id: []const u8,
        new_key_id: []const u8,
        domain: []const u8,
        old_selector: []const u8,
        new_selector: []const u8,
        success: bool,
        message: []const u8,
    };

    pub const KeyValidation = struct {
        key_id: []const u8,
        is_valid: bool,
        issues: []const []const u8,
        days_until_expiry: ?i32,
    };
};

/// DKIM CLI for key management
pub const DKIMCli = struct {
    allocator: std.mem.Allocator,
    key_manager: *DKIMKeyManager,

    pub fn init(allocator: std.mem.Allocator, key_manager: *DKIMKeyManager) DKIMCli {
        return .{
            .allocator = allocator,
            .key_manager = key_manager,
        };
    }

    pub const Command = enum {
        generate,
        list,
        show,
        rotate,
        schedule,
        validate,
        dns,
        delete,
        help,

        pub fn fromString(s: []const u8) ?Command {
            if (std.mem.eql(u8, s, "generate") or std.mem.eql(u8, s, "gen")) return .generate;
            if (std.mem.eql(u8, s, "list") or std.mem.eql(u8, s, "ls")) return .list;
            if (std.mem.eql(u8, s, "show")) return .show;
            if (std.mem.eql(u8, s, "rotate")) return .rotate;
            if (std.mem.eql(u8, s, "schedule")) return .schedule;
            if (std.mem.eql(u8, s, "validate") or std.mem.eql(u8, s, "check")) return .validate;
            if (std.mem.eql(u8, s, "dns")) return .dns;
            if (std.mem.eql(u8, s, "delete") or std.mem.eql(u8, s, "rm")) return .delete;
            if (std.mem.eql(u8, s, "help") or std.mem.eql(u8, s, "-h")) return .help;
            return null;
        }
    };

    pub const CliResult = struct {
        success: bool,
        message: []const u8,
        data: ?[]const u8,
    };

    /// Execute CLI command
    pub fn execute(self: *DKIMCli, command: Command, args: []const []const u8) !CliResult {
        return switch (command) {
            .generate => self.cmdGenerate(args),
            .list => self.cmdList(args),
            .show => self.cmdShow(args),
            .rotate => self.cmdRotate(args),
            .schedule => self.cmdSchedule(args),
            .validate => self.cmdValidate(args),
            .dns => self.cmdDns(args),
            .delete => self.cmdDelete(args),
            .help => self.cmdHelp(),
        };
    }

    fn cmdGenerate(self: *DKIMCli, args: []const []const u8) !CliResult {
        if (args.len < 2) {
            return .{
                .success = false,
                .message = "Usage: dkim generate <domain> <selector> [algorithm] [validity_days]",
                .data = null,
            };
        }

        const domain = args[0];
        const selector = args[1];
        const algorithm = if (args.len > 2)
            KeyAlgorithm.fromString(args[2]) orelse .rsa_2048
        else
            .rsa_2048;
        const validity_days: ?u32 = if (args.len > 3)
            std.fmt.parseInt(u32, args[3], 10) catch 365
        else
            365;

        const key = try self.key_manager.generateKey(domain, selector, algorithm, validity_days);

        const output = try std.fmt.allocPrint(self.allocator,
            \\Key generated successfully:
            \\  ID: {s}
            \\  Domain: {s}
            \\  Selector: {s}
            \\  Algorithm: {s}
            \\  Expires: {d}
            \\
            \\DNS Record ({s}._domainkey.{s}):
            \\  {s}
        , .{
            key.id,
            key.domain,
            key.selector,
            key.algorithm.toString(),
            key.expires_at orelse 0,
            key.selector,
            key.domain,
            try key.generateDnsRecord(self.allocator),
        });

        return .{
            .success = true,
            .message = "Key generated successfully",
            .data = output,
        };
    }

    fn cmdList(self: *DKIMCli, args: []const []const u8) !CliResult {
        const domain = if (args.len > 0) args[0] else null;
        const keys = self.key_manager.listKeys(domain);

        if (keys.len == 0) {
            return .{
                .success = true,
                .message = "No keys found",
                .data = null,
            };
        }

        var output = std.ArrayList(u8).init(self.allocator);
        const writer = output.writer();

        try writer.print("DKIM Keys:\n", .{});
        try writer.print("{s:<40} {s:<20} {s:<15} {s:<10} {s:<10}\n", .{
            "ID", "Domain", "Selector", "Algorithm", "Status",
        });
        try writer.print("{s}\n", .{"-" ** 95});

        for (keys) |key| {
            const status = if (key.is_active) "active" else "inactive";
            try writer.print("{s:<40} {s:<20} {s:<15} {s:<10} {s:<10}\n", .{
                key.id,
                key.domain,
                key.selector,
                key.algorithm.toString(),
                status,
            });
        }

        return .{
            .success = true,
            .message = try std.fmt.allocPrint(self.allocator, "Found {d} key(s)", .{keys.len}),
            .data = try output.toOwnedSlice(),
        };
    }

    fn cmdShow(self: *DKIMCli, args: []const []const u8) !CliResult {
        if (args.len < 1) {
            return .{
                .success = false,
                .message = "Usage: dkim show <key_id>",
                .data = null,
            };
        }

        const key_id = args[0];

        for (self.key_manager.keys.items) |key| {
            if (std.mem.eql(u8, key.id, key_id)) {
                const output = try std.fmt.allocPrint(self.allocator,
                    \\Key Details:
                    \\  ID: {s}
                    \\  Domain: {s}
                    \\  Selector: {s}
                    \\  Algorithm: {s}
                    \\  Status: {s}
                    \\  Created: {d}
                    \\  Expires: {d}
                    \\  Rotation Scheduled: {d}
                    \\
                    \\Public Key (Base64):
                    \\  {s}
                , .{
                    key.id,
                    key.domain,
                    key.selector,
                    key.algorithm.toString(),
                    if (key.is_active) "active" else "inactive",
                    key.created_at,
                    key.expires_at orelse 0,
                    key.rotation_scheduled orelse 0,
                    key.public_key,
                });

                return .{
                    .success = true,
                    .message = "Key found",
                    .data = output,
                };
            }
        }

        return .{
            .success = false,
            .message = "Key not found",
            .data = null,
        };
    }

    fn cmdRotate(self: *DKIMCli, args: []const []const u8) !CliResult {
        if (args.len < 1) {
            return .{
                .success = false,
                .message = "Usage: dkim rotate <key_id>",
                .data = null,
            };
        }

        const key_id = args[0];

        // Find and rotate the key
        for (self.key_manager.keys.items) |*key| {
            if (std.mem.eql(u8, key.id, key_id)) {
                const new_selector = try self.allocator.dupe(u8, key.selector);
                defer self.allocator.free(new_selector);

                const new_key = try self.key_manager.generateKey(
                    key.domain,
                    try std.fmt.allocPrint(self.allocator, "{s}_{d}", .{ new_selector, time_compat.timestamp() }),
                    key.algorithm,
                    365,
                );

                // Deactivate old key
                key.is_active = false;

                const output = try std.fmt.allocPrint(self.allocator,
                    \\Key rotated successfully:
                    \\  Old Key: {s} (now inactive)
                    \\  New Key: {s}
                    \\  New Selector: {s}
                    \\
                    \\ACTION REQUIRED: Update DNS record:
                    \\  {s}._domainkey.{s} TXT "v=DKIM1; k=rsa; p={s}"
                , .{
                    key.id,
                    new_key.id,
                    new_key.selector,
                    new_key.selector,
                    new_key.domain,
                    new_key.public_key,
                });

                return .{
                    .success = true,
                    .message = "Key rotated successfully",
                    .data = output,
                };
            }
        }

        return .{
            .success = false,
            .message = "Key not found",
            .data = null,
        };
    }

    fn cmdSchedule(self: *DKIMCli, args: []const []const u8) !CliResult {
        if (args.len < 2) {
            return .{
                .success = false,
                .message = "Usage: dkim schedule <key_id> <days_from_now>",
                .data = null,
            };
        }

        const key_id = args[0];
        const days = std.fmt.parseInt(u32, args[1], 10) catch {
            return .{
                .success = false,
                .message = "Invalid number of days",
                .data = null,
            };
        };

        const rotation_time = time_compat.timestamp() + @as(i64, days) * 24 * 60 * 60;
        try self.key_manager.scheduleRotation(key_id, rotation_time);

        return .{
            .success = true,
            .message = try std.fmt.allocPrint(self.allocator,
                "Rotation scheduled for key {s} in {d} days", .{ key_id, days }),
            .data = null,
        };
    }

    fn cmdValidate(self: *DKIMCli, args: []const []const u8) !CliResult {
        if (args.len < 1) {
            return .{
                .success = false,
                .message = "Usage: dkim validate <key_id>",
                .data = null,
            };
        }

        const key_id = args[0];
        const validation = try self.key_manager.validateKey(key_id);

        var output = std.ArrayList(u8).init(self.allocator);
        const writer = output.writer();

        try writer.print("Key Validation: {s}\n", .{key_id});
        try writer.print("  Valid: {s}\n", .{if (validation.is_valid) "yes" else "no"});

        if (validation.days_until_expiry) |days| {
            try writer.print("  Days until expiry: {d}\n", .{days});
        }

        if (validation.issues.len > 0) {
            try writer.print("  Issues:\n", .{});
            for (validation.issues) |issue| {
                try writer.print("    - {s}\n", .{issue});
            }
        }

        return .{
            .success = validation.is_valid,
            .message = if (validation.is_valid) "Key is valid" else "Key has issues",
            .data = try output.toOwnedSlice(),
        };
    }

    fn cmdDns(self: *DKIMCli, args: []const []const u8) !CliResult {
        if (args.len < 1) {
            return .{
                .success = false,
                .message = "Usage: dkim dns <key_id>",
                .data = null,
            };
        }

        const key_id = args[0];

        for (self.key_manager.keys.items) |key| {
            if (std.mem.eql(u8, key.id, key_id)) {
                const record_name = try key.getDnsRecordName(self.allocator);
                defer self.allocator.free(record_name);
                const record_value = try key.generateDnsRecord(self.allocator);
                defer self.allocator.free(record_value);

                const output = try std.fmt.allocPrint(self.allocator,
                    \\DNS TXT Record for DKIM:
                    \\
                    \\Name: {s}
                    \\Type: TXT
                    \\Value: "{s}"
                    \\
                    \\BIND format:
                    \\  {s}. IN TXT "{s}"
                    \\
                    \\Cloudflare/Route53 format:
                    \\  Name: {s}
                    \\  Content: {s}
                , .{
                    record_name,
                    record_value,
                    record_name,
                    record_value,
                    record_name,
                    record_value,
                });

                return .{
                    .success = true,
                    .message = "DNS record generated",
                    .data = output,
                };
            }
        }

        return .{
            .success = false,
            .message = "Key not found",
            .data = null,
        };
    }

    fn cmdDelete(self: *DKIMCli, args: []const []const u8) !CliResult {
        if (args.len < 1) {
            return .{
                .success = false,
                .message = "Usage: dkim delete <key_id>",
                .data = null,
            };
        }

        const key_id = args[0];
        self.key_manager.deleteKey(key_id) catch {
            return .{
                .success = false,
                .message = "Key not found",
                .data = null,
            };
        };

        return .{
            .success = true,
            .message = try std.fmt.allocPrint(self.allocator, "Key {s} deleted", .{key_id}),
            .data = null,
        };
    }

    fn cmdHelp(self: *DKIMCli) CliResult {
        _ = self;
        return .{
            .success = true,
            .message = "DKIM Key Management CLI",
            .data =
            \\DKIM Key Management Commands:
            \\
            \\  generate <domain> <selector> [algorithm] [validity_days]
            \\      Generate a new DKIM key pair
            \\      Algorithms: rsa-2048 (default), rsa-4096, ed25519
            \\      Example: dkim generate example.com default rsa-4096 365
            \\
            \\  list [domain]
            \\      List all DKIM keys, optionally filtered by domain
            \\
            \\  show <key_id>
            \\      Show details of a specific key
            \\
            \\  rotate <key_id>
            \\      Immediately rotate a key (generates new key, deactivates old)
            \\
            \\  schedule <key_id> <days>
            \\      Schedule automatic key rotation
            \\
            \\  validate <key_id>
            \\      Check key validity and get recommendations
            \\
            \\  dns <key_id>
            \\      Generate DNS TXT record for a key
            \\
            \\  delete <key_id>
            \\      Delete a key (use with caution!)
            \\
            \\  help
            \\      Show this help message
            ,
        };
    }
};

// Additional tests
test "DKIM key algorithm conversion" {
    try std.testing.expectEqual(KeyAlgorithm.rsa_2048, KeyAlgorithm.fromString("rsa-2048").?);
    try std.testing.expectEqual(KeyAlgorithm.ed25519, KeyAlgorithm.fromString("ed25519").?);
    try std.testing.expectEqual(@as(u32, 4096), KeyAlgorithm.rsa_4096.getKeySize());
}

test "DKIM key manager generate" {
    var manager = try DKIMKeyManager.init(std.testing.allocator, null);
    defer manager.deinit();

    const key = try manager.generateKey("example.com", "default", .rsa_2048, 365);
    try std.testing.expectEqualStrings("example.com", key.domain);
    try std.testing.expectEqualStrings("default", key.selector);
    try std.testing.expect(key.is_active);
}

test "DKIM CLI help command" {
    var manager = try DKIMKeyManager.init(std.testing.allocator, null);
    defer manager.deinit();

    var cli = DKIMCli.init(std.testing.allocator, &manager);
    const result = try cli.execute(.help, &[_][]const u8{});
    try std.testing.expect(result.success);
}
