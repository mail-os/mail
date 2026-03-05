const std = @import("std");

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
        // Parse IP address into octets
        const octets = parseIpv4(ip_addr) orelse return false;

        // Check each blacklist
        for (self.blacklists) |blacklist| {
            if (try self.checkBlacklist(octets, blacklist)) {
                return true;
            }
        }

        return false;
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

        // Try to resolve the DNS query
        // If it resolves (returns any A record), the IP is blacklisted
        const result = self.lookupDns(query) catch {
            // DNS lookup failed - treat as not blacklisted
            return false;
        };

        return result;
    }

    /// Perform DNS lookup using getaddrinfo
    /// Returns true if the query resolves (IP is blacklisted)
    fn lookupDns(self: *DnsblChecker, hostname: []const u8) !bool {
        // Add null terminator for C string
        const hostname_z = try self.allocator.dupeZ(u8, hostname);
        defer self.allocator.free(hostname_z);

        // Try to resolve the hostname
        var result: ?*std.c.addrinfo = null;
        const hints = std.mem.zeroInit(std.c.addrinfo, .{
            .family = std.posix.AF.INET,
            .socktype = std.posix.SOCK.STREAM,
        });

        const rc = std.c.getaddrinfo(hostname_z.ptr, null, &hints, &result);
        defer if (result) |r| std.c.freeaddrinfo(r);

        // If rc == 0, the hostname resolved (IP is blacklisted)
        // If rc != 0, lookup failed (IP is not blacklisted)
        return @intFromEnum(rc) == 0;
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
