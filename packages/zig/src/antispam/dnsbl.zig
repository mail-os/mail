const std = @import("std");
const dns_cache = @import("dns_cache.zig");
const spf = @import("spf.zig");

/// DNSBL checker for spam prevention
pub const DnsblChecker = struct {
    allocator: std.mem.Allocator,
    blacklists: []const []const u8,

    /// Common public DNSBLs
    pub const DEFAULT_BLACKLISTS = [_][]const u8{
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "b.barracudacentral.org",
        "dnsbl.sorbs.net",
    };

    pub fn init(allocator: std.mem.Allocator, blacklists: ?[]const []const u8) DnsblChecker {
        return .{
            .allocator = allocator,
            .blacklists = blacklists orelse &DEFAULT_BLACKLISTS,
        };
    }

    /// Check if an IP address is listed in any DNSBL
    /// Returns true if the IP is blacklisted
    pub fn isBlacklisted(self: *DnsblChecker, ip_addr: []const u8) !bool {
        // IPv4: reversed-octet queries
        if (parseIpv4(ip_addr)) |octets| {
            for (self.blacklists) |blacklist| {
                if (try self.checkBlacklist(octets, blacklist)) {
                    return true;
                }
            }
            return false;
        }

        // IPv6: nibble-reversed queries (RFC 5782 §2.4)
        if (spf.parseIp6(ip_addr)) |bytes| {
            for (self.blacklists) |blacklist| {
                if (try self.checkBlacklist6(bytes, blacklist)) {
                    return true;
                }
            }
        }

        return false;
    }

    /// Check a single blacklist for an IPv6 address: each of the 32 nibbles
    /// reversed and dot-separated, e.g. 2001:db8::1 ->
    /// 1.0.0.0....8.b.d.0.1.0.0.2.<blacklist>
    fn checkBlacklist6(self: *DnsblChecker, bytes: [16]u8, blacklist: []const u8) !bool {
        var query: std.ArrayList(u8) = .empty;
        defer query.deinit(self.allocator);

        const hex = "0123456789abcdef";
        var i: usize = 16;
        while (i > 0) {
            i -= 1;
            try query.append(self.allocator, hex[bytes[i] & 0x0f]);
            try query.append(self.allocator, '.');
            try query.append(self.allocator, hex[bytes[i] >> 4]);
            try query.append(self.allocator, '.');
        }
        try query.appendSlice(self.allocator, blacklist);

        var key_buf: [384]u8 = undefined;
        const cache_key: ?[]const u8 = std.fmt.bufPrint(&key_buf, "dnsbl:{s}", .{query.items}) catch null;
        if (cache_key) |key| {
            switch (dns_cache.get(self.allocator, key)) {
                .hit => |v| {
                    defer self.allocator.free(v);
                    return v.len == 1 and v[0] == '1';
                },
                .negative, .miss => {},
            }
        }

        const result = self.lookupDns(query.items) catch return false;

        if (cache_key) |key| {
            dns_cache.put(key, if (result) "1" else "0", if (result) dns_cache.positive_ttl else dns_cache.negative_ttl);
        }

        return result;
    }

    fn parseIpv4(ip: []const u8) ?[4]u8 {
        var result: [4]u8 = undefined;
        var idx: usize = 0;
        var octet: u16 = 0;
        var digits: u8 = 0;

        for (ip) |c| {
            if (c == '.') {
                if (digits == 0 or idx >= 3) return null;
                result[idx] = @intCast(octet);
                idx += 1;
                octet = 0;
                digits = 0;
            } else if (c >= '0' and c <= '9') {
                octet = octet * 10 + (c - '0');
                if (octet > 255) return null;
                digits += 1;
                if (digits > 3) return null;
            } else {
                return null;
            }
        }
        if (digits == 0 or idx != 3) return null;
        result[3] = @intCast(octet);
        return result;
    }

    /// Check a single blacklist for an IP
    /// DNSBL format: reverse the IP octets and append blacklist domain
    /// Example: 1.2.3.4 becomes 4.3.2.1.zen.spamhaus.org
    fn checkBlacklist(self: *DnsblChecker, octets: [4]u8, blacklist: []const u8) !bool {
        // Create reversed IP query
        const query = try std.fmt.allocPrint(
            self.allocator,
            "{d}.{d}.{d}.{d}.{s}",
            .{ octets[3], octets[2], octets[1], octets[0], blacklist },
        );
        defer self.allocator.free(query);

        // Serve repeat lookups for the same IP from the process-wide cache —
        // a reconnecting sender otherwise costs one blocking getaddrinfo per
        // blacklist per connection.
        var key_buf: [320]u8 = undefined;
        const cache_key: ?[]const u8 = std.fmt.bufPrint(&key_buf, "dnsbl:{s}", .{query}) catch null;
        if (cache_key) |key| {
            switch (dns_cache.get(self.allocator, key)) {
                .hit => |v| {
                    defer self.allocator.free(v);
                    return v.len == 1 and v[0] == '1';
                },
                .negative, .miss => {},
            }
        }

        // Try to resolve the DNS query
        // If it resolves (returns any A record), the IP is blacklisted
        const result = self.lookupDns(query) catch {
            // DNS lookup failed - treat as not blacklisted
            return false;
        };

        if (cache_key) |key| {
            dns_cache.put(key, if (result) "1" else "0", if (result) dns_cache.positive_ttl else dns_cache.negative_ttl);
        }

        return result;
    }

    /// Perform DNS lookup using getaddrinfo.
    /// Returns true only if the query resolves to an A record inside 127.0.0.0/8.
    ///
    /// Per the DNSBL convention (RFC 5782 §2.1), a "listed" answer is an A record
    /// in 127.0.0.0/8 (the specific low octets encode the listing reason). Any
    /// other resolution -- and in particular a wildcard/parking answer outside
    /// 127/8 -- MUST NOT be treated as a hit, otherwise a DNSBL that returns a
    /// catch-all address would cause every IP to be flagged as blacklisted.
    fn lookupDns(self: *DnsblChecker, hostname: []const u8) !bool {
        // Add null terminator for C string
        const hostname_z = try self.allocator.dupeZ(u8, hostname);
        defer self.allocator.free(hostname_z);

        // Try to resolve the hostname (A records only)
        var result: ?*std.c.addrinfo = null;
        const hints = std.mem.zeroInit(std.c.addrinfo, .{
            .family = std.posix.AF.INET,
            .socktype = std.posix.SOCK.STREAM,
        });

        const rc = std.c.getaddrinfo(hostname_z.ptr, null, &hints, &result);
        defer if (result) |r| std.c.freeaddrinfo(r);

        // rc != 0 means the name did not resolve (NXDOMAIN etc.) => not listed.
        if (@intFromEnum(rc) != 0) return false;

        // Walk the result list and look for an A record in 127.0.0.0/8.
        var node = result;
        while (node) |n| : (node = n.next) {
            if (n.family != std.posix.AF.INET) continue;
            const sa = n.addr orelse continue;
            const sin: *const std.posix.sockaddr.in = @ptrCast(@alignCast(sa));
            // sin.addr is the IPv4 address in network byte order; the first byte
            // of its in-memory representation is the most-significant octet.
            const octets = std.mem.toBytes(sin.addr);
            if (octets[0] != 127) continue;
            // 127.255.255.0/24 is reserved by Spamhaus (and others) for ERROR
            // responses, NOT listings — e.g. 127.255.255.254 (query volume
            // exceeded) / .253 (public-resolver block) / .252 (typo) / .255
            // (banned). Treating those as a listing would flag EVERY sender the
            // moment the resolver gets rate-limited, so they must be ignored.
            if (octets[1] == 255 and octets[2] == 255) continue;
            return true;
        }

        // Resolved, but no answer was a real listing => not blacklisted.
        return false;
    }
};

test "DNSBL IP reversal" {
    const testing = std.testing;

    // Test IP reversal logic
    const octets: [4]u8 = .{ 127, 0, 0, 1 };
    const query = try std.fmt.allocPrint(
        testing.allocator,
        "{d}.{d}.{d}.{d}.zen.spamhaus.org",
        .{ octets[3], octets[2], octets[1], octets[0] },
    );
    defer testing.allocator.free(query);

    try testing.expectEqualStrings("1.0.0.127.zen.spamhaus.org", query);
}
