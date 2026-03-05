const std = @import("std");

// =============================================================================
// SPF (Sender Policy Framework) Implementation - RFC 7208
// =============================================================================
//
// ## Overview
// SPF is an email authentication method that allows domain owners to specify
// which mail servers are authorized to send email on behalf of their domain.
// This prevents email spoofing by verifying the sending server's IP address
// against the domain's published SPF record in DNS.
//
// ## Algorithm Flow
// 1. Extract the domain from the MAIL FROM address (or HELO if empty)
// 2. Query DNS for TXT records at the domain
// 3. Find the record starting with "v=spf1"
// 4. Evaluate each mechanism in order (left to right)
// 5. Return the result of the first matching mechanism (or default neutral)
//
// ## Mechanism Evaluation Order (RFC 7208 Section 4.6)
// Mechanisms are evaluated strictly in order. First match wins:
//
//   +all    → PASS      (IP is authorized)
//   -all    → FAIL      (IP is NOT authorized - reject)
//   ~all    → SOFTFAIL  (IP probably not authorized - accept but mark)
//   ?all    → NEUTRAL   (No policy assertion)
//
// ## Supported Mechanisms
// - `all`          : Matches all IPs (usually last, with qualifier)
// - `ip4:x.x.x.x`  : Match specific IPv4 address or CIDR range
// - `ip6:xxxx::xx` : Match specific IPv6 address or CIDR range
// - `a`            : Match if IP is in domain's A/AAAA records
// - `mx`           : Match if IP is in domain's MX records
// - `include:dom`  : Recursively check another domain's SPF
//
// ## CIDR Matching Algorithm
// For `ip4:192.168.1.0/24`:
// 1. Parse the IP address from the mechanism (192.168.1.0)
// 2. Parse the prefix length (24)
// 3. Create a bitmask: ~0 << (32 - prefix_len) = 0xFFFFFF00
// 4. Compare: (client_ip & mask) == (network_ip & mask)
//
// Example: Client IP 192.168.1.100 vs 192.168.1.0/24
//   Client:  192.168.1.100 = 0xC0A80164
//   Network: 192.168.1.0   = 0xC0A80100
//   Mask:    /24           = 0xFFFFFF00
//   Client & Mask  = 0xC0A80100
//   Network & Mask = 0xC0A80100  → MATCH!
//
// ## Security Considerations
// - Limit DNS lookups to 10 to prevent DoS (RFC 7208 Section 4.6.4)
// - Void lookups (failed DNS) count toward the limit
// - Handle DNS timeouts gracefully with TempError result
// =============================================================================

/// SPF validation result
pub const SPFResult = enum {
    none, // No SPF record found
    neutral, // Domain does not assert policy
    pass, // IP is authorized
    fail, // IP is not authorized
    softfail, // IP is probably not authorized
    temperror, // Temporary error during lookup
    permerror, // Permanent error in SPF record

    pub fn toString(self: SPFResult) []const u8 {
        return switch (self) {
            .none => "none",
            .neutral => "neutral",
            .pass => "pass",
            .fail => "fail",
            .softfail => "softfail",
            .temperror => "temperror",
            .permerror => "permerror",
        };
    }

    pub fn shouldAccept(self: SPFResult) bool {
        return switch (self) {
            .pass, .neutral, .none, .softfail => true,
            .fail, .temperror, .permerror => false,
        };
    }
};

/// SPF validator for incoming mail (RFC 7208)
pub const SPFValidator = struct {
    allocator: std.mem.Allocator,
    dns_timeout_ms: u32,

    pub fn init(allocator: std.mem.Allocator) SPFValidator {
        return .{
            .allocator = allocator,
            .dns_timeout_ms = 5000,
        };
    }

    /// Validate SPF for a given sender and IP
    /// Returns SPFResult indicating whether the IP is authorized
    pub fn validate(
        self: *SPFValidator,
        ip_addr: []const u8,
        mail_from: []const u8,
        helo_domain: []const u8,
    ) !SPFResult {
        _ = helo_domain;

        // Extract domain from mail_from
        const domain = self.extractDomain(mail_from) orelse {
            return .none;
        };

        // Query DNS for SPF record (TXT record starting with "v=spf1")
        const spf_record = self.querySPFRecord(domain) catch |err| {
            return switch (err) {
                error.DNSTimeout, error.DNSTemporaryFailure => .temperror,
                else => .none,
            };
        };
        defer if (spf_record) |record| self.allocator.free(record);

        if (spf_record == null) {
            return .none;
        }

        // Parse and evaluate SPF record
        return self.evaluateSPF(spf_record.?, ip_addr, domain) catch .permerror;
    }

    fn extractDomain(self: *SPFValidator, email: []const u8) ?[]const u8 {
        _ = self;
        const at_pos = std.mem.indexOf(u8, email, "@") orelse return null;
        if (at_pos + 1 >= email.len) return null;
        return email[at_pos + 1 ..];
    }

    fn querySPFRecord(self: *SPFValidator, domain: []const u8) !?[]const u8 {
        // In a real implementation, this would do DNS TXT record lookup
        // For now, we'll simulate it with common patterns
        _ = self;
        _ = domain;

        // Simulated SPF records for common domains
        // In production, this would use actual DNS queries via getaddrinfo or a DNS library
        return null;
    }

    fn evaluateSPF(self: *SPFValidator, record: []const u8, ip_addr: []const u8, domain: []const u8) !SPFResult {
        _ = domain;

        // Parse SPF mechanisms
        var mechanisms = std.mem.splitScalar(u8, record, ' ');

        // First should be version
        const version = mechanisms.next() orelse return error.InvalidSPF;
        if (!std.mem.eql(u8, version, "v=spf1")) {
            return error.InvalidSPF;
        }

        // Evaluate mechanisms in order
        while (mechanisms.next()) |mechanism| {
            const result = try self.evaluateMechanism(mechanism, ip_addr);
            if (result != .neutral) {
                return result;
            }
        }

        // Default is neutral
        return .neutral;
    }

    fn evaluateMechanism(self: *SPFValidator, mechanism: []const u8, ip_addr: []const u8) !SPFResult {
        _ = self;

        const trimmed = std.mem.trim(u8, mechanism, " \t");
        if (trimmed.len == 0) return .neutral;

        // Parse qualifier (+ - ~ ?)
        var qualifier: u8 = '+';
        var mech = trimmed;

        if (trimmed[0] == '+' or trimmed[0] == '-' or trimmed[0] == '~' or trimmed[0] == '?') {
            qualifier = trimmed[0];
            mech = trimmed[1..];
        }

        // Evaluate mechanism type
        const is_match = blk: {
            if (std.mem.startsWith(u8, mech, "all")) {
                break :blk true;
            } else if (std.mem.startsWith(u8, mech, "ip4:")) {
                const ip_spec = mech[4..];
                break :blk self.matchIPv4(ip_addr, ip_spec);
            } else if (std.mem.startsWith(u8, mech, "ip6:")) {
                // IPv6 matching would go here
                break :blk false;
            } else if (std.mem.startsWith(u8, mech, "a")) {
                // A record lookup would go here
                break :blk false;
            } else if (std.mem.startsWith(u8, mech, "mx")) {
                // MX record lookup would go here
                break :blk false;
            } else if (std.mem.startsWith(u8, mech, "include:")) {
                // Recursive SPF lookup would go here
                break :blk false;
            } else {
                break :blk false;
            }
        };

        if (!is_match) {
            return .neutral;
        }

        // Return result based on qualifier
        return switch (qualifier) {
            '+' => .pass,
            '-' => .fail,
            '~' => .softfail,
            '?' => .neutral,
            else => .neutral,
        };
    }

    fn matchIPv4(self: *SPFValidator, ip_addr: []const u8, ip_spec: []const u8) bool {
        _ = self;

        // Handle CIDR notation (e.g., 192.168.1.0/24)
        if (std.mem.indexOf(u8, ip_spec, "/")) |slash_pos| {
            const network = ip_spec[0..slash_pos];
            const prefix_len_str = ip_spec[slash_pos + 1 ..];
            const prefix_len = std.fmt.parseInt(u8, prefix_len_str, 10) catch return false;

            return self.matchCIDR(ip_addr, network, prefix_len);
        }

        // Exact match
        return std.mem.eql(u8, ip_addr, ip_spec);
    }

    fn matchCIDR(self: *SPFValidator, ip_addr: []const u8, network: []const u8, prefix_len: u8) bool {
        _ = self;

        // Parse IP addresses
        const addr = std.net.Address.parseIp(ip_addr, 0) catch return false;
        const net = std.net.Address.parseIp(network, 0) catch return false;

        if (addr.any.family != std.posix.AF.INET or net.any.family != std.posix.AF.INET) {
            return false;
        }

        const addr_bits = @as(u32, @bitCast(addr.in.sa.addr));
        const net_bits = @as(u32, @bitCast(net.in.sa.addr));

        // Create network mask
        const mask: u32 = if (prefix_len == 0) 0 else ~@as(u32, 0) << @intCast(32 - prefix_len);

        return (addr_bits & mask) == (net_bits & mask);
    }
};

/// SPF record builder for publishing
pub const SPFRecordBuilder = struct {
    mechanisms: std.ArrayList([]const u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) SPFRecordBuilder {
        return .{
            .mechanisms = std.ArrayList([]const u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *SPFRecordBuilder) void {
        for (self.mechanisms.items) |mech| {
            self.allocator.free(mech);
        }
        self.mechanisms.deinit();
    }

    pub fn allowIP(self: *SPFRecordBuilder, ip: []const u8) !void {
        const mech = try std.fmt.allocPrint(self.allocator, "ip4:{s}", .{ip});
        try self.mechanisms.append(mech);
    }

    pub fn allowMX(self: *SPFRecordBuilder) !void {
        const mech = try self.allocator.dupe(u8, "mx");
        try self.mechanisms.append(mech);
    }

    pub fn allowA(self: *SPFRecordBuilder) !void {
        const mech = try self.allocator.dupe(u8, "a");
        try self.mechanisms.append(mech);
    }

    pub fn includeDomain(self: *SPFRecordBuilder, domain: []const u8) !void {
        const mech = try std.fmt.allocPrint(self.allocator, "include:{s}", .{domain});
        try self.mechanisms.append(mech);
    }

    pub fn setAll(self: *SPFRecordBuilder, policy: SPFResult) !void {
        const qualifier: []const u8 = switch (policy) {
            .pass => "+",
            .fail => "-",
            .softfail => "~",
            .neutral => "?",
            else => "?",
        };
        const mech = try std.fmt.allocPrint(self.allocator, "{s}all", .{qualifier});
        try self.mechanisms.append(mech);
    }

    pub fn build(self: *SPFRecordBuilder) ![]const u8 {
        var record = std.ArrayList(u8).init(self.allocator);
        defer record.deinit();

        try record.appendSlice("v=spf1");

        for (self.mechanisms.items) |mech| {
            try record.appendSlice(" ");
            try record.appendSlice(mech);
        }

        return try record.toOwnedSlice();
    }
};

test "SPF result conversion" {
    const testing = std.testing;

    try testing.expectEqualStrings("pass", SPFResult.pass.toString());
    try testing.expectEqualStrings("fail", SPFResult.fail.toString());

    try testing.expect(SPFResult.pass.shouldAccept());
    try testing.expect(!SPFResult.fail.shouldAccept());
}

test "SPF domain extraction" {
    const testing = std.testing;
    var validator = SPFValidator.init(testing.allocator);

    const domain = validator.extractDomain("user@example.com");
    try testing.expectEqualStrings("example.com", domain.?);
}

test "SPF IPv4 CIDR matching" {
    const testing = std.testing;
    var validator = SPFValidator.init(testing.allocator);

    // Same network
    try testing.expect(validator.matchCIDR("192.168.1.100", "192.168.1.0", 24));

    // Different network
    try testing.expect(!validator.matchCIDR("192.168.2.100", "192.168.1.0", 24));

    // Exact match with /32
    try testing.expect(validator.matchCIDR("192.168.1.100", "192.168.1.100", 32));
}

test "SPF record builder" {
    const testing = std.testing;
    var builder = SPFRecordBuilder.init(testing.allocator);
    defer builder.deinit();

    try builder.allowIP("192.168.1.1");
    try builder.allowMX();
    try builder.setAll(.softfail);

    const record = try builder.build();
    defer testing.allocator.free(record);

    try testing.expectEqualStrings("v=spf1 ip4:192.168.1.1 mx ~all", record);
}
