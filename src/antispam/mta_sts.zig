const std = @import("std");
const time_compat = @import("../core/time_compat.zig");

// =============================================================================
// MTA-STS (Mail Transfer Agent Strict Transport Security) - RFC 8461
// =============================================================================
//
// MTA-STS allows mail service providers to declare their ability to receive
// TLS-secured SMTP connections, and to specify whether sending SMTP servers
// should refuse to deliver to MX hosts that do not offer TLS with a trusted
// certificate.
//
// Flow: 1) Query _mta-sts.<domain> TXT record  2) Fetch policy from
// https://mta-sts.<domain>/.well-known/mta-sts.txt  3) Validate MX hostname
// against policy patterns  4) Enforce or report TLS failures
// =============================================================================

/// MTA-STS policy mode (RFC 8461 Section 5)
pub const MTASTSMode = enum {
    enforce, // MUST NOT deliver without valid TLS
    testing, // Report failures via TLS-RPT but deliver anyway
    none, // Domain does not implement MTA-STS

    pub fn toString(self: MTASTSMode) []const u8 {
        return switch (self) {
            .enforce => "enforce",
            .testing => "testing",
            .none => "none",
        };
    }

    pub fn fromString(s: []const u8) ?MTASTSMode {
        if (std.ascii.eqlIgnoreCase(s, "enforce")) return .enforce;
        if (std.ascii.eqlIgnoreCase(s, "testing")) return .testing;
        if (std.ascii.eqlIgnoreCase(s, "none")) return .none;
        return null;
    }
};

/// Result of MTA-STS policy evaluation
pub const MTASTSResult = enum {
    pass,
    fail,
    no_policy,
    policy_fetch_error,
    temperror,

    pub fn toString(self: MTASTSResult) []const u8 {
        return switch (self) {
            .pass => "pass",
            .fail => "fail",
            .no_policy => "no_policy",
            .policy_fetch_error => "policy_fetch_error",
            .temperror => "temperror",
        };
    }

    /// Whether mail delivery should proceed given this result and the policy mode
    pub fn shouldDeliver(self: MTASTSResult, mode: MTASTSMode) bool {
        return switch (self) {
            .pass, .no_policy, .policy_fetch_error, .temperror => true,
            .fail => mode != .enforce,
        };
    }
};

/// Represents an MTA-STS policy (RFC 8461 Section 3.2)
pub const MTASTSPolicy = struct {
    version: []const u8,
    mode: MTASTSMode,
    mx_patterns: std.ArrayList([]const u8),
    max_age: u64,
    policy_id: []const u8,
    fetched_at: i64,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) MTASTSPolicy {
        return .{
            .version = "",
            .mode = .none,
            .mx_patterns = .{},
            .max_age = 0,
            .policy_id = "",
            .fetched_at = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *MTASTSPolicy) void {
        if (self.version.len > 0) self.allocator.free(self.version);
        for (self.mx_patterns.items) |pattern| self.allocator.free(pattern);
        self.mx_patterns.deinit(self.allocator);
        if (self.policy_id.len > 0) self.allocator.free(self.policy_id);
    }

    pub fn isExpired(self: *const MTASTSPolicy) bool {
        if (self.fetched_at == 0 or self.max_age == 0) return true;
        return time_compat.timestamp() > self.fetched_at + @as(i64, @intCast(self.max_age));
    }

    pub fn isExpiringSoon(self: *const MTASTSPolicy, within_seconds: u64) bool {
        if (self.fetched_at == 0 or self.max_age == 0) return true;
        const expiry = self.fetched_at + @as(i64, @intCast(self.max_age));
        return (expiry - time_compat.timestamp()) < @as(i64, @intCast(within_seconds));
    }

    pub fn remainingTTL(self: *const MTASTSPolicy) u64 {
        if (self.fetched_at == 0 or self.max_age == 0) return 0;
        const now = time_compat.timestamp();
        const expiry = self.fetched_at + @as(i64, @intCast(self.max_age));
        if (now >= expiry) return 0;
        return @intCast(expiry - now);
    }

    pub fn format(self: *const MTASTSPolicy, allocator: std.mem.Allocator) ![]u8 {
        var out: std.ArrayList(u8) = .{};
        errdefer out.deinit(allocator);
        try out.print(allocator, "version: {s}\nmode: {s}\n", .{ self.version, self.mode.toString() });
        for (self.mx_patterns.items) |p| try out.print(allocator, "mx: {s}\n", .{p});
        try out.print(allocator, "max_age: {d}\n", .{self.max_age});
        return out.toOwnedSlice(allocator);
    }
};

/// Represents a _mta-sts DNS TXT record (v=STSv1; id=...)
pub const MTASTSDnsRecord = struct {
    version: []const u8,
    id: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *MTASTSDnsRecord) void {
        self.allocator.free(self.version);
        self.allocator.free(self.id);
    }

    /// Parse "v=STSv1; id=20240101T000000"
    pub fn parse(allocator: std.mem.Allocator, record: []const u8) !MTASTSDnsRecord {
        var dns_rec = MTASTSDnsRecord{ .version = "", .id = "", .allocator = allocator };
        errdefer {
            if (dns_rec.version.len > 0) allocator.free(dns_rec.version);
            if (dns_rec.id.len > 0) allocator.free(dns_rec.id);
        }

        var parts = std.mem.splitScalar(u8, record, ';');
        while (parts.next()) |part| {
            const trimmed = std.mem.trim(u8, part, " \t\r\n");
            if (trimmed.len == 0) continue;
            const eq = std.mem.indexOf(u8, trimmed, "=") orelse continue;
            const key = std.mem.trim(u8, trimmed[0..eq], " \t");
            const val = std.mem.trim(u8, trimmed[eq + 1 ..], " \t");

            if (std.mem.eql(u8, key, "v")) {
                dns_rec.version = try allocator.dupe(u8, val);
            } else if (std.mem.eql(u8, key, "id")) {
                dns_rec.id = try allocator.dupe(u8, val);
            }
        }

        if (dns_rec.version.len == 0 or !std.mem.eql(u8, dns_rec.version, "STSv1"))
            return error.InvalidMTASTSRecord;
        if (dns_rec.id.len == 0) return error.InvalidMTASTSRecord;
        return dns_rec;
    }

    pub fn formatRecord(self: *const MTASTSDnsRecord, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "v={s}; id={s}", .{ self.version, self.id });
    }
};

/// Cache for MTA-STS policies keyed by domain with TTL based on max_age
pub const MTASTSPolicyCache = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMap(CacheEntry),
    mutex: std.Thread.Mutex,
    max_entries: usize,

    const CacheEntry = struct {
        policy: MTASTSPolicy,
        dns_record_id: []const u8,

        pub fn deinit(self: *CacheEntry, allocator: std.mem.Allocator) void {
            self.policy.deinit();
            allocator.free(self.dns_record_id);
        }
    };

    pub fn init(allocator: std.mem.Allocator) MTASTSPolicyCache {
        return initWithCapacity(allocator, 10000);
    }

    pub fn initWithCapacity(allocator: std.mem.Allocator, max: usize) MTASTSPolicyCache {
        return .{
            .allocator = allocator,
            .entries = std.StringHashMap(CacheEntry).init(allocator),
            .mutex = .{},
            .max_entries = max,
        };
    }

    pub fn deinit(self: *MTASTSPolicyCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
            kv.value_ptr.deinit(self.allocator);
        }
        self.entries.deinit();
    }

    pub fn put(self: *MTASTSPolicyCache, domain: []const u8, policy: MTASTSPolicy, dns_id: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.entries.fetchRemove(domain)) |removed| {
            self.allocator.free(removed.key);
            var entry = removed.value;
            entry.deinit(self.allocator);
        }
        if (self.entries.count() >= self.max_entries) try self.evictExpiredLocked();

        const key = try self.allocator.dupe(u8, domain);
        errdefer self.allocator.free(key);
        try self.entries.put(key, .{
            .policy = policy,
            .dns_record_id = try self.allocator.dupe(u8, dns_id),
        });
    }

    pub fn get(self: *MTASTSPolicyCache, domain: []const u8) ?*const MTASTSPolicy {
        self.mutex.lock();
        defer self.mutex.unlock();
        const entry = self.entries.getPtr(domain) orelse return null;
        if (entry.policy.isExpired()) return null;
        return &entry.policy;
    }

    pub fn getEvenIfExpired(self: *MTASTSPolicyCache, domain: []const u8) ?*const MTASTSPolicy {
        self.mutex.lock();
        defer self.mutex.unlock();
        const entry = self.entries.getPtr(domain) orelse return null;
        return &entry.policy;
    }

    pub fn isPolicyUpdated(self: *MTASTSPolicyCache, domain: []const u8, current_id: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const entry = self.entries.getPtr(domain) orelse return true;
        return !std.mem.eql(u8, entry.dns_record_id, current_id);
    }

    pub fn remove(self: *MTASTSPolicyCache, domain: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.entries.fetchRemove(domain)) |removed| {
            self.allocator.free(removed.key);
            var entry = removed.value;
            entry.deinit(self.allocator);
        }
    }

    pub fn cleanup(self: *MTASTSPolicyCache) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.evictExpiredLocked();
    }

    pub fn count(self: *MTASTSPolicyCache) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.entries.count();
    }

    pub const CacheStats = struct {
        total_entries: usize,
        expired_entries: usize,
        enforce_entries: usize,
        testing_entries: usize,
        none_entries: usize,
    };

    pub fn getStats(self: *MTASTSPolicyCache) CacheStats {
        self.mutex.lock();
        defer self.mutex.unlock();
        var stats = CacheStats{
            .total_entries = self.entries.count(),
            .expired_entries = 0,
            .enforce_entries = 0,
            .testing_entries = 0,
            .none_entries = 0,
        };
        var it = self.entries.valueIterator();
        while (it.next()) |e| {
            if (e.policy.isExpired()) stats.expired_entries += 1;
            switch (e.policy.mode) {
                .enforce => stats.enforce_entries += 1,
                .testing => stats.testing_entries += 1,
                .none => stats.none_entries += 1,
            }
        }
        return stats;
    }

    fn evictExpiredLocked(self: *MTASTSPolicyCache) !void {
        var to_remove: std.ArrayList([]const u8) = .{};
        defer to_remove.deinit(self.allocator);
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.policy.isExpired()) try to_remove.append(self.allocator, kv.key_ptr.*);
        }
        for (to_remove.items) |domain| {
            if (self.entries.fetchRemove(domain)) |removed| {
                self.allocator.free(removed.key);
                var entry = removed.value;
                entry.deinit(self.allocator);
            }
        }
    }
};

/// MTA-STS validator for checking domains and MX hostnames against policies
pub const MTASTSValidator = struct {
    allocator: std.mem.Allocator,
    cache: MTASTSPolicyCache,
    dns_timeout_ms: u32,

    pub fn init(allocator: std.mem.Allocator) MTASTSValidator {
        return .{
            .allocator = allocator,
            .cache = MTASTSPolicyCache.init(allocator),
            .dns_timeout_ms = 5000,
        };
    }

    pub fn deinit(self: *MTASTSValidator) void {
        self.cache.deinit();
    }

    /// Check whether a domain has an MTA-STS policy (queries DNS + fetches policy)
    pub fn checkPolicy(self: *MTASTSValidator, domain: []const u8) !?MTASTSPolicy {
        if (self.cache.get(domain)) |cached| return try self.clonePolicy(cached);

        const dns_record = self.queryDnsRecord(domain) catch |err| {
            return switch (err) {
                error.DnsTimeout, error.DnsTemporaryFailure => error.DnsTemporaryFailure,
                else => null,
            };
        };
        if (dns_record == null) return null;

        var record = dns_record.?;
        defer record.deinit();

        if (!self.cache.isPolicyUpdated(domain, record.id)) {
            if (self.cache.getEvenIfExpired(domain)) |cached| return try self.clonePolicy(cached);
        }

        var policy = self.fetchPolicy(domain) catch return null;
        if (policy.policy_id.len > 0) self.allocator.free(policy.policy_id);
        policy.policy_id = try self.allocator.dupe(u8, record.id);

        const cache_copy = try self.clonePolicy(&policy);
        try self.cache.put(domain, cache_copy, record.id);
        return policy;
    }

    /// Fetch policy from https://mta-sts.<domain>/.well-known/mta-sts.txt
    /// Stubbed HTTP: returns mock policy for known test domains.
    pub fn fetchPolicy(self: *MTASTSValidator, domain: []const u8) !MTASTSPolicy {
        const mock = self.getMockPolicyText(domain) orelse return error.PolicyFetchFailed;
        return self.parsePolicy(mock);
    }

    /// Parse MTA-STS policy text (version/mode/mx/max_age key-value lines)
    pub fn parsePolicy(self: *MTASTSValidator, text: []const u8) !MTASTSPolicy {
        var policy = MTASTSPolicy.init(self.allocator);
        errdefer policy.deinit();

        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, std.mem.trimEnd(u8, raw, "\r"), " \t");
            if (line.len == 0) continue;
            const colon = std.mem.indexOf(u8, line, ":") orelse continue;
            const key = std.mem.trim(u8, line[0..colon], " \t");
            const val = std.mem.trim(u8, line[colon + 1 ..], " \t");

            if (std.mem.eql(u8, key, "version")) {
                if (policy.version.len > 0) self.allocator.free(policy.version);
                policy.version = try self.allocator.dupe(u8, val);
            } else if (std.mem.eql(u8, key, "mode")) {
                policy.mode = MTASTSMode.fromString(val) orelse return error.InvalidPolicyMode;
            } else if (std.mem.eql(u8, key, "mx")) {
                if (!isValidMxPattern(val)) return error.InvalidMxPattern;
                try policy.mx_patterns.append(self.allocator, try self.allocator.dupe(u8, val));
            } else if (std.mem.eql(u8, key, "max_age")) {
                policy.max_age = std.fmt.parseInt(u64, val, 10) catch return error.InvalidMaxAge;
                if (policy.max_age > 31557600) return error.InvalidMaxAge;
            }
        }

        if (policy.version.len == 0 or !std.mem.eql(u8, policy.version, "STSv1"))
            return error.InvalidPolicyVersion;
        if (policy.mode != .none and policy.mx_patterns.items.len == 0)
            return error.MissingMxPatterns;
        if (policy.max_age == 0 and policy.mode != .none)
            return error.InvalidMaxAge;

        policy.fetched_at = time_compat.timestamp();
        return policy;
    }

    /// Validate MX hostname against policy MX patterns
    pub fn validateMX(self: *MTASTSValidator, mx_hostname: []const u8, policy: *const MTASTSPolicy) bool {
        _ = self;
        for (policy.mx_patterns.items) |pattern| {
            if (matchesMxPattern(mx_hostname, pattern)) return true;
        }
        return false;
    }

    /// Returns whether TLS should be required for delivery to this domain
    pub fn shouldEnforceTLS(self: *MTASTSValidator, domain: []const u8) !bool {
        if (self.cache.get(domain)) |cached| return cached.mode == .enforce;
        const maybe = self.checkPolicy(domain) catch return false;
        if (maybe) |p| {
            var policy = p;
            defer policy.deinit();
            return policy.mode == .enforce;
        }
        return false;
    }

    /// Full validation: check policy and validate MX hostname
    pub fn validate(self: *MTASTSValidator, domain: []const u8, mx_hostname: []const u8) !MTASTSResult {
        const maybe = self.checkPolicy(domain) catch |err| {
            return switch (err) {
                error.DnsTemporaryFailure => .temperror,
                else => .policy_fetch_error,
            };
        };
        if (maybe == null) return .no_policy;
        var policy = maybe.?;
        defer policy.deinit();
        return if (self.validateMX(mx_hostname, &policy)) .pass else .fail;
    }

    // -- internal helpers --

    fn queryDnsRecord(self: *MTASTSValidator, domain: []const u8) !?MTASTSDnsRecord {
        _ = self;
        _ = domain;
        return null; // Stubbed; production would query _mta-sts.<domain> TXT
    }

    fn getMockPolicyText(self: *MTASTSValidator, domain: []const u8) ?[]const u8 {
        _ = self;
        if (std.mem.eql(u8, domain, "example.com"))
            return "version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.com\nmax_age: 86400\n";
        if (std.mem.eql(u8, domain, "testing.example.com"))
            return "version: STSv1\nmode: testing\nmx: *.testing.example.com\nmax_age: 604800\n";
        if (std.mem.eql(u8, domain, "nomail.example.com"))
            return "version: STSv1\nmode: none\nmax_age: 86400\n";
        return null;
    }

    fn clonePolicy(self: *MTASTSValidator, src: *const MTASTSPolicy) !MTASTSPolicy {
        var p = MTASTSPolicy.init(self.allocator);
        errdefer p.deinit();
        p.version = try self.allocator.dupe(u8, src.version);
        p.mode = src.mode;
        p.max_age = src.max_age;
        p.policy_id = try self.allocator.dupe(u8, src.policy_id);
        p.fetched_at = src.fetched_at;
        for (src.mx_patterns.items) |pat| try p.mx_patterns.append(self.allocator, try self.allocator.dupe(u8, pat));
        return p;
    }
};

// =============================================================================
// Pattern matching
// =============================================================================

/// Match MX hostname against a pattern. Wildcards (*.example.com) match exactly
/// one DNS label prefix. Case-insensitive.
pub fn matchesMxPattern(hostname: []const u8, pattern: []const u8) bool {
    if (hostname.len == 0 or pattern.len == 0) return false;
    if (std.ascii.eqlIgnoreCase(hostname, pattern)) return true;

    if (std.mem.startsWith(u8, pattern, "*.")) {
        const suffix = pattern[1..]; // ".example.com"
        if (hostname.len <= suffix.len) return false;
        const host_suffix = hostname[hostname.len - suffix.len ..];
        if (!std.ascii.eqlIgnoreCase(host_suffix, suffix)) return false;
        const prefix = hostname[0 .. hostname.len - suffix.len];
        return prefix.len > 0 and std.mem.indexOf(u8, prefix, ".") == null;
    }
    return false;
}

pub fn isValidMxPattern(pattern: []const u8) bool {
    if (pattern.len == 0) return false;
    if (std.mem.startsWith(u8, pattern, "*.")) {
        const rest = pattern[2..];
        if (rest.len == 0 or std.mem.indexOf(u8, rest, ".") == null) return false;
        return isValidHostnameChars(rest);
    }
    return isValidHostnameChars(pattern);
}

fn isValidHostnameChars(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '.' and c != '-') return false;
    }
    return s[0] != '.' and s[0] != '-' and s[s.len - 1] != '.' and s[s.len - 1] != '-';
}

/// Extract policy domain from hostname (simplified; production would use PSL)
pub fn extractPolicyDomain(hostname: []const u8) []const u8 {
    var dot_count: usize = 0;
    var last_dot: usize = 0;
    var second_last_dot: usize = 0;
    for (hostname, 0..) |c, i| {
        if (c == '.') {
            dot_count += 1;
            second_last_dot = last_dot;
            last_dot = i;
        }
    }
    if (dot_count <= 1) return hostname;
    return hostname[second_last_dot + 1 ..];
}

// =============================================================================
// Tests
// =============================================================================

test "MTASTSMode toString and fromString" {
    try std.testing.expectEqualStrings("enforce", MTASTSMode.enforce.toString());
    try std.testing.expectEqualStrings("testing", MTASTSMode.testing.toString());
    try std.testing.expectEqualStrings("none", MTASTSMode.none.toString());
    try std.testing.expectEqual(MTASTSMode.enforce, MTASTSMode.fromString("enforce").?);
    try std.testing.expectEqual(MTASTSMode.enforce, MTASTSMode.fromString("ENFORCE").?);
    try std.testing.expect(MTASTSMode.fromString("invalid") == null);
}

test "MTASTSResult toString and shouldDeliver" {
    try std.testing.expectEqualStrings("pass", MTASTSResult.pass.toString());
    try std.testing.expectEqualStrings("fail", MTASTSResult.fail.toString());
    try std.testing.expectEqualStrings("temperror", MTASTSResult.temperror.toString());

    // pass always delivers
    try std.testing.expect(MTASTSResult.pass.shouldDeliver(.enforce));
    // fail blocks only in enforce
    try std.testing.expect(!MTASTSResult.fail.shouldDeliver(.enforce));
    try std.testing.expect(MTASTSResult.fail.shouldDeliver(.testing));
    try std.testing.expect(MTASTSResult.fail.shouldDeliver(.none));
    // temperror always delivers
    try std.testing.expect(MTASTSResult.temperror.shouldDeliver(.enforce));
}

test "MTASTSDnsRecord parse valid" {
    var rec = try MTASTSDnsRecord.parse(std.testing.allocator, "v=STSv1; id=20240101T000000");
    defer rec.deinit();
    try std.testing.expectEqualStrings("STSv1", rec.version);
    try std.testing.expectEqualStrings("20240101T000000", rec.id);
}

test "MTASTSDnsRecord parse with spaces" {
    var rec = try MTASTSDnsRecord.parse(std.testing.allocator, "  v=STSv1 ;  id=abc123  ");
    defer rec.deinit();
    try std.testing.expectEqualStrings("abc123", rec.id);
}

test "MTASTSDnsRecord parse invalid" {
    try std.testing.expectError(error.InvalidMTASTSRecord, MTASTSDnsRecord.parse(std.testing.allocator, "v=STSv2; id=abc"));
    try std.testing.expectError(error.InvalidMTASTSRecord, MTASTSDnsRecord.parse(std.testing.allocator, "v=STSv1"));
}

test "MTASTSDnsRecord format" {
    var rec = try MTASTSDnsRecord.parse(std.testing.allocator, "v=STSv1; id=20240101T000000");
    defer rec.deinit();
    const fmt = try rec.formatRecord(std.testing.allocator);
    defer std.testing.allocator.free(fmt);
    try std.testing.expectEqualStrings("v=STSv1; id=20240101T000000", fmt);
}

test "parsePolicy basic enforce" {
    var v = MTASTSValidator.init(std.testing.allocator);
    defer v.deinit();
    var p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.com\nmax_age: 86400\n");
    defer p.deinit();
    try std.testing.expectEqualStrings("STSv1", p.version);
    try std.testing.expectEqual(MTASTSMode.enforce, p.mode);
    try std.testing.expectEqual(@as(usize, 2), p.mx_patterns.items.len);
    try std.testing.expectEqualStrings("mail.example.com", p.mx_patterns.items[0]);
    try std.testing.expectEqualStrings("*.example.com", p.mx_patterns.items[1]);
    try std.testing.expectEqual(@as(u64, 86400), p.max_age);
}

test "parsePolicy testing mode" {
    var v = MTASTSValidator.init(std.testing.allocator);
    defer v.deinit();
    var p = try v.parsePolicy("version: STSv1\nmode: testing\nmx: *.example.org\nmax_age: 604800\n");
    defer p.deinit();
    try std.testing.expectEqual(MTASTSMode.testing, p.mode);
}

test "parsePolicy none mode (no mx required)" {
    var v = MTASTSValidator.init(std.testing.allocator);
    defer v.deinit();
    var p = try v.parsePolicy("version: STSv1\nmode: none\nmax_age: 86400\n");
    defer p.deinit();
    try std.testing.expectEqual(MTASTSMode.none, p.mode);
    try std.testing.expectEqual(@as(usize, 0), p.mx_patterns.items.len);
}

test "parsePolicy CRLF line endings" {
    var v = MTASTSValidator.init(std.testing.allocator);
    defer v.deinit();
    var p = try v.parsePolicy("version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmax_age: 86400\r\n");
    defer p.deinit();
    try std.testing.expectEqualStrings("STSv1", p.version);
}

test "parsePolicy extra whitespace" {
    var v = MTASTSValidator.init(std.testing.allocator);
    defer v.deinit();
    var p = try v.parsePolicy("  version:  STSv1\n  mode:  enforce\n  mx:  mail.example.com\n  max_age:  3600\n");
    defer p.deinit();
    try std.testing.expectEqual(@as(u64, 3600), p.max_age);
}

test "parsePolicy errors" {
    var v = MTASTSValidator.init(std.testing.allocator);
    defer v.deinit();
    try std.testing.expectError(error.InvalidPolicyVersion, v.parsePolicy("version: STSv2\nmode: enforce\nmx: m.ex.com\nmax_age: 86400\n"));
    try std.testing.expectError(error.InvalidPolicyVersion, v.parsePolicy("mode: enforce\nmx: m.ex.com\nmax_age: 86400\n"));
    try std.testing.expectError(error.InvalidPolicyMode, v.parsePolicy("version: STSv1\nmode: invalid\nmx: m.ex.com\nmax_age: 86400\n"));
    try std.testing.expectError(error.MissingMxPatterns, v.parsePolicy("version: STSv1\nmode: enforce\nmax_age: 86400\n"));
    try std.testing.expectError(error.InvalidMaxAge, v.parsePolicy("version: STSv1\nmode: enforce\nmx: m.ex.com\nmax_age: 999999999\n"));
    try std.testing.expectError(error.InvalidMaxAge, v.parsePolicy("version: STSv1\nmode: enforce\nmx: m.ex.com\nmax_age: 0\n"));
}

test "parsePolicy multiple mx patterns" {
    var v = MTASTSValidator.init(std.testing.allocator);
    defer v.deinit();
    var p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: m1.ex.com\nmx: m2.ex.com\nmx: *.bk.ex.com\nmx: *.ex.com\nmax_age: 86400\n");
    defer p.deinit();
    try std.testing.expectEqual(@as(usize, 4), p.mx_patterns.items.len);
}

test "matchesMxPattern exact" {
    try std.testing.expect(matchesMxPattern("mail.example.com", "mail.example.com"));
    try std.testing.expect(matchesMxPattern("MAIL.EXAMPLE.COM", "mail.example.com"));
    try std.testing.expect(!matchesMxPattern("other.example.com", "mail.example.com"));
}

test "matchesMxPattern wildcard single label" {
    try std.testing.expect(matchesMxPattern("mail.example.com", "*.example.com"));
    try std.testing.expect(matchesMxPattern("mx1.example.com", "*.example.com"));
    try std.testing.expect(matchesMxPattern("MAIL.EXAMPLE.COM", "*.example.com"));
}

test "matchesMxPattern wildcard no match bare domain" {
    try std.testing.expect(!matchesMxPattern("example.com", "*.example.com"));
}

test "matchesMxPattern wildcard no match multi-level" {
    try std.testing.expect(!matchesMxPattern("sub.mail.example.com", "*.example.com"));
    try std.testing.expect(!matchesMxPattern("a.b.example.com", "*.example.com"));
}

test "matchesMxPattern wildcard subdomain pattern" {
    try std.testing.expect(matchesMxPattern("mx1.mail.example.com", "*.mail.example.com"));
    try std.testing.expect(!matchesMxPattern("mail.example.com", "*.mail.example.com"));
}

test "matchesMxPattern empty strings" {
    try std.testing.expect(!matchesMxPattern("", "mail.example.com"));
    try std.testing.expect(!matchesMxPattern("mail.example.com", ""));
    try std.testing.expect(!matchesMxPattern("", ""));
}

test "validateMX against policy" {
    var v = MTASTSValidator.init(std.testing.allocator);
    defer v.deinit();
    var p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.com\nmax_age: 86400\n");
    defer p.deinit();

    try std.testing.expect(v.validateMX("mail.example.com", &p));
    try std.testing.expect(v.validateMX("mx1.example.com", &p));
    try std.testing.expect(!v.validateMX("mail.evil.com", &p));
    try std.testing.expect(!v.validateMX("sub.mail.example.com", &p));
}

test "MTASTSPolicy expiry" {
    var v = MTASTSValidator.init(std.testing.allocator);
    defer v.deinit();
    var p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: m.ex.com\nmax_age: 86400\n");
    defer p.deinit();
    try std.testing.expect(!p.isExpired());
    try std.testing.expect(p.remainingTTL() > 0);
    try std.testing.expect(p.remainingTTL() <= 86400);

    // Default empty policy is expired
    var empty = MTASTSPolicy.init(std.testing.allocator);
    defer empty.deinit();
    try std.testing.expect(empty.isExpired());
    try std.testing.expectEqual(@as(u64, 0), empty.remainingTTL());
}

test "MTASTSPolicy isExpiringSoon" {
    var v = MTASTSValidator.init(std.testing.allocator);
    defer v.deinit();
    var p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: m.ex.com\nmax_age: 60\n");
    defer p.deinit();
    try std.testing.expect(p.isExpiringSoon(3600)); // 60s TTL is within 3600s
    try std.testing.expect(!p.isExpiringSoon(30)); // 60s TTL is NOT within 30s
}

test "MTASTSPolicy format" {
    var v = MTASTSValidator.init(std.testing.allocator);
    defer v.deinit();
    var p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.com\nmax_age: 86400\n");
    defer p.deinit();
    const fmt = try p.format(std.testing.allocator);
    defer std.testing.allocator.free(fmt);
    try std.testing.expect(std.mem.indexOf(u8, fmt, "version: STSv1") != null);
    try std.testing.expect(std.mem.indexOf(u8, fmt, "mode: enforce") != null);
    try std.testing.expect(std.mem.indexOf(u8, fmt, "mx: *.example.com") != null);
}

test "cache put and get" {
    var v = MTASTSValidator.init(std.testing.allocator);
    defer v.deinit();
    const p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: m.ex.com\nmax_age: 86400\n");
    try v.cache.put("example.com", p, "id123");
    const cached = v.cache.get("example.com");
    try std.testing.expect(cached != null);
    try std.testing.expectEqual(MTASTSMode.enforce, cached.?.mode);
}

test "cache miss" {
    var c = MTASTSPolicyCache.init(std.testing.allocator);
    defer c.deinit();
    try std.testing.expect(c.get("nonexistent.com") == null);
}

test "cache remove" {
    var v = MTASTSValidator.init(std.testing.allocator);
    defer v.deinit();
    const p = try v.parsePolicy("version: STSv1\nmode: testing\nmx: *.ex.org\nmax_age: 86400\n");
    try v.cache.put("ex.org", p, "id1");
    try std.testing.expect(v.cache.get("ex.org") != null);
    v.cache.remove("ex.org");
    try std.testing.expect(v.cache.get("ex.org") == null);
}

test "cache replace existing" {
    var v = MTASTSValidator.init(std.testing.allocator);
    defer v.deinit();
    const p1 = try v.parsePolicy("version: STSv1\nmode: testing\nmx: *.ex.com\nmax_age: 86400\n");
    const p2 = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: m.ex.com\nmax_age: 604800\n");
    try v.cache.put("ex.com", p1, "id1");
    try v.cache.put("ex.com", p2, "id2");
    const cached = v.cache.get("ex.com");
    try std.testing.expect(cached != null);
    try std.testing.expectEqual(MTASTSMode.enforce, cached.?.mode);
    try std.testing.expectEqual(@as(usize, 1), v.cache.count());
}

test "cache isPolicyUpdated" {
    var v = MTASTSValidator.init(std.testing.allocator);
    defer v.deinit();
    const p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: m.ex.com\nmax_age: 86400\n");
    try v.cache.put("ex.com", p, "id_v1");
    try std.testing.expect(!v.cache.isPolicyUpdated("ex.com", "id_v1"));
    try std.testing.expect(v.cache.isPolicyUpdated("ex.com", "id_v2"));
    try std.testing.expect(v.cache.isPolicyUpdated("unknown.com", "id_v1"));
}

test "cache getStats" {
    var v = MTASTSValidator.init(std.testing.allocator);
    defer v.deinit();
    const p1 = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: m.ex.com\nmax_age: 86400\n");
    const p2 = try v.parsePolicy("version: STSv1\nmode: testing\nmx: *.test.com\nmax_age: 86400\n");
    try v.cache.put("ex.com", p1, "id1");
    try v.cache.put("test.com", p2, "id2");
    const stats = v.cache.getStats();
    try std.testing.expectEqual(@as(usize, 2), stats.total_entries);
    try std.testing.expectEqual(@as(usize, 1), stats.enforce_entries);
    try std.testing.expectEqual(@as(usize, 1), stats.testing_entries);
}

test "cache getEvenIfExpired" {
    var v = MTASTSValidator.init(std.testing.allocator);
    defer v.deinit();
    var p = MTASTSPolicy.init(std.testing.allocator);
    p.version = try std.testing.allocator.dupe(u8, "STSv1");
    p.mode = .enforce;
    try p.mx_patterns.append(std.testing.allocator, try std.testing.allocator.dupe(u8, "m.ex.com"));
    p.max_age = 1;
    p.fetched_at = time_compat.timestamp() - 100;
    p.policy_id = try std.testing.allocator.dupe(u8, "old");
    try v.cache.put("ex.com", p, "old");
    try std.testing.expect(v.cache.get("ex.com") == null); // expired
    try std.testing.expect(v.cache.getEvenIfExpired("ex.com") != null); // still there
}

test "fetchPolicy mock domains" {
    var v = MTASTSValidator.init(std.testing.allocator);
    defer v.deinit();

    var p1 = try v.fetchPolicy("example.com");
    defer p1.deinit();
    try std.testing.expectEqual(MTASTSMode.enforce, p1.mode);

    var p2 = try v.fetchPolicy("testing.example.com");
    defer p2.deinit();
    try std.testing.expectEqual(MTASTSMode.testing, p2.mode);

    var p3 = try v.fetchPolicy("nomail.example.com");
    defer p3.deinit();
    try std.testing.expectEqual(MTASTSMode.none, p3.mode);

    try std.testing.expectError(error.PolicyFetchFailed, v.fetchPolicy("unknown.example.com"));
}

test "isValidMxPattern" {
    try std.testing.expect(isValidMxPattern("mail.example.com"));
    try std.testing.expect(isValidMxPattern("*.example.com"));
    try std.testing.expect(isValidMxPattern("*.mail.example.com"));
    try std.testing.expect(!isValidMxPattern(""));
    try std.testing.expect(!isValidMxPattern("*."));
    try std.testing.expect(!isValidMxPattern("*.com"));
    try std.testing.expect(!isValidMxPattern(".example.com"));
}

test "extractPolicyDomain" {
    try std.testing.expectEqualStrings("example.com", extractPolicyDomain("mail.example.com"));
    try std.testing.expectEqualStrings("example.com", extractPolicyDomain("mx1.mail.example.com"));
    try std.testing.expectEqualStrings("example.com", extractPolicyDomain("example.com"));
    try std.testing.expectEqualStrings("localhost", extractPolicyDomain("localhost"));
}

test "end-to-end parse and validate" {
    var v = MTASTSValidator.init(std.testing.allocator);
    defer v.deinit();
    var p = try v.fetchPolicy("example.com");
    defer p.deinit();
    try std.testing.expect(v.validateMX("mail.example.com", &p));
    try std.testing.expect(v.validateMX("mx1.example.com", &p));
    try std.testing.expect(!v.validateMX("mail.evil.com", &p));
    try std.testing.expect(!v.validateMX("sub.mail.example.com", &p));
    try std.testing.expectEqual(MTASTSMode.enforce, p.mode);
}

test "end-to-end cache workflow" {
    var v = MTASTSValidator.init(std.testing.allocator);
    defer v.deinit();
    const p = try v.fetchPolicy("example.com");
    try v.cache.put("example.com", p, "20240101T000000");
    const cached = v.cache.get("example.com");
    try std.testing.expect(cached != null);
    try std.testing.expect(v.validateMX("mail.example.com", cached.?));
    try std.testing.expect(!v.validateMX("bad.evil.com", cached.?));
    try std.testing.expect(!v.cache.isPolicyUpdated("example.com", "20240101T000000"));
    try std.testing.expect(v.cache.isPolicyUpdated("example.com", "20240201T000000"));
    v.cache.remove("example.com");
    try std.testing.expect(v.cache.get("example.com") == null);
}
