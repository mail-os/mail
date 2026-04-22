const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");

/// DNS Resolver with validation for address family and result verification
/// Provides safe wrappers around std.net.getAddressList with proper error handling
pub const DNSResolver = struct {
    allocator: std.mem.Allocator,
    timeout_ms: u64,
    max_retries: u32,
    stats: Stats,

    pub const Stats = struct {
        queries: std.atomic.Value(u64),
        successes: std.atomic.Value(u64),
        failures: std.atomic.Value(u64),
        timeouts: std.atomic.Value(u64),

        pub fn init() Stats {
            return .{
                .queries = std.atomic.Value(u64).init(0),
                .successes = std.atomic.Value(u64).init(0),
                .failures = std.atomic.Value(u64).init(0),
                .timeouts = std.atomic.Value(u64).init(0),
            };
        }

        pub fn snapshot(self: *const Stats) StatsSnapshot {
            return .{
                .queries = self.queries.load(.acquire),
                .successes = self.successes.load(.acquire),
                .failures = self.failures.load(.acquire),
                .timeouts = self.timeouts.load(.acquire),
            };
        }
    };

    pub const StatsSnapshot = struct {
        queries: u64,
        successes: u64,
        failures: u64,
        timeouts: u64,

        pub fn successRate(self: StatsSnapshot) f64 {
            if (self.queries == 0) return 0.0;
            return @as(f64, @floatFromInt(self.successes)) / @as(f64, @floatFromInt(self.queries)) * 100.0;
        }
    };

    pub const ResolutionError = error{
        InvalidHostname,
        ResolutionFailed,
        NoAddressFound,
        AddressFamilyMismatch,
        Timeout,
        OutOfMemory,
    };

    pub const AddressFamily = enum {
        any,
        ipv4_only,
        ipv6_only,
        ipv4_preferred,
        ipv6_preferred,
    };

    pub const ResolvedAddress = struct {
        address: std.net.Address,
        hostname: []const u8,
        family: std.posix.sa_family_t,

        pub fn isIPv4(self: ResolvedAddress) bool {
            return self.family == std.posix.AF.INET;
        }

        pub fn isIPv6(self: ResolvedAddress) bool {
            return self.family == std.posix.AF.INET6;
        }

        pub fn format(
            self: ResolvedAddress,
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = fmt;
            _ = options;
            try writer.print("{s} -> {}", .{ self.hostname, self.address });
        }
    };

    pub fn init(allocator: std.mem.Allocator) DNSResolver {
        return .{
            .allocator = allocator,
            .timeout_ms = 5000, // 5 seconds default
            .max_retries = 2,
            .stats = Stats.init(),
        };
    }

    /// Resolve hostname to address with family validation
    pub fn resolve(
        self: *DNSResolver,
        hostname: []const u8,
        port: u16,
        family: AddressFamily,
    ) ResolutionError!ResolvedAddress {
        _ = self.stats.queries.fetchAdd(1, .release);

        // Validate hostname
        if (hostname.len == 0 or hostname.len > 255) {
            _ = self.stats.failures.fetchAdd(1, .release);
            return ResolutionError.InvalidHostname;
        }

        // Try to resolve
        var attempt: u32 = 0;
        while (attempt <= self.max_retries) : (attempt += 1) {
            const result = self.resolveAttempt(hostname, port, family) catch |err| {
                if (attempt == self.max_retries) {
                    _ = self.stats.failures.fetchAdd(1, .release);
                    return err;
                }
                // Retry on failure — use C nanosleep (Zig 0.16-dev removed std.Thread.sleep)
                const retry_ts = std.c.timespec{ .sec = 0, .nsec = 100_000_000 };
                _ = std.c.nanosleep(&retry_ts, null);
                continue;
            };

            _ = self.stats.successes.fetchAdd(1, .release);
            return result;
        }

        _ = self.stats.failures.fetchAdd(1, .release);
        return ResolutionError.ResolutionFailed;
    }

    fn resolveAttempt(
        self: *DNSResolver,
        hostname: []const u8,
        port: u16,
        family: AddressFamily,
    ) ResolutionError!ResolvedAddress {
        // Use getAddressList for resolution
        const address_list = std.net.getAddressList(
            self.allocator,
            hostname,
            port,
        ) catch |err| {
            return switch (err) {
                error.OutOfMemory => ResolutionError.OutOfMemory,
                else => ResolutionError.ResolutionFailed,
            };
        };
        defer address_list.deinit();

        if (address_list.addrs.len == 0) {
            return ResolutionError.NoAddressFound;
        }

        // Find address matching the requested family
        const selected_addr = switch (family) {
            .any => address_list.addrs[0],
            .ipv4_only => blk: {
                for (address_list.addrs) |addr| {
                    if (addr.any.family == std.posix.AF.INET) {
                        break :blk addr;
                    }
                }
                return ResolutionError.AddressFamilyMismatch;
            },
            .ipv6_only => blk: {
                for (address_list.addrs) |addr| {
                    if (addr.any.family == std.posix.AF.INET6) {
                        break :blk addr;
                    }
                }
                return ResolutionError.AddressFamilyMismatch;
            },
            .ipv4_preferred => blk: {
                // Try to find IPv4 first
                for (address_list.addrs) |addr| {
                    if (addr.any.family == std.posix.AF.INET) {
                        break :blk addr;
                    }
                }
                // Fall back to first address
                break :blk address_list.addrs[0];
            },
            .ipv6_preferred => blk: {
                // Try to find IPv6 first
                for (address_list.addrs) |addr| {
                    if (addr.any.family == std.posix.AF.INET6) {
                        break :blk addr;
                    }
                }
                // Fall back to first address
                break :blk address_list.addrs[0];
            },
        };

        return .{
            .address = selected_addr,
            .hostname = hostname,
            .family = selected_addr.any.family,
        };
    }

    /// Resolve multiple hostnames in parallel (for MX records, etc.)
    pub fn resolveMultiple(
        self: *DNSResolver,
        hostnames: []const []const u8,
        port: u16,
        family: AddressFamily,
    ) ![]ResolvedAddress {
        const results = try self.allocator.alloc(ResolvedAddress, hostnames.len);
        errdefer self.allocator.free(results);

        var success_count: usize = 0;
        for (hostnames, 0..) |hostname, i| {
            results[i] = self.resolve(hostname, port, family) catch |err| {
                // Log error but continue with other hostnames
                std.log.warn("Failed to resolve {s}: {}", .{ hostname, err });
                continue;
            };
            success_count += 1;
        }

        if (success_count == 0) {
            self.allocator.free(results);
            return ResolutionError.NoAddressFound;
        }

        // Trim to successful results
        if (success_count < hostnames.len) {
            const trimmed = try self.allocator.realloc(results, success_count);
            return trimmed;
        }

        return results;
    }

    /// Get resolver statistics
    pub fn getStats(self: *DNSResolver) StatsSnapshot {
        return self.stats.snapshot();
    }

    /// Validate that a resolved address matches expected criteria
    pub fn validateAddress(
        address: ResolvedAddress,
        expected_family: ?AddressFamily,
    ) bool {
        if (expected_family) |family| {
            switch (family) {
                .ipv4_only => return address.isIPv4(),
                .ipv6_only => return address.isIPv6(),
                .any, .ipv4_preferred, .ipv6_preferred => return true,
            }
        }
        return true;
    }
};

/// Cache for DNS results with TTL expiration
pub const DNSCache = struct {
    allocator: std.mem.Allocator,
    cache: std.StringHashMap(CacheEntry),
    mutex: mutex_compat.Mutex,
    default_ttl_seconds: u64,

    const CacheEntry = struct {
        address: std.net.Address,
        expires_at: i64,
        family: std.posix.sa_family_t,

        pub fn isExpired(self: CacheEntry) bool {
            return time_compat.timestamp() >= self.expires_at;
        }
    };

    pub fn init(allocator: std.mem.Allocator, ttl_seconds: u64) DNSCache {
        return .{
            .allocator = allocator,
            .cache = std.StringHashMap(CacheEntry).init(allocator),
            .mutex = .{},
            .default_ttl_seconds = ttl_seconds,
        };
    }

    pub fn deinit(self: *DNSCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.cache.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.cache.deinit();
    }

    /// Get cached address if not expired
    pub fn get(self: *DNSCache, hostname: []const u8) ?std.net.Address {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.cache.get(hostname)) |entry| {
            if (!entry.isExpired()) {
                return entry.address;
            }
            // Remove expired entry
            if (self.cache.fetchRemove(hostname)) |removed| {
                self.allocator.free(removed.key);
            }
        }

        return null;
    }

    /// Store address in cache
    pub fn put(
        self: *DNSCache,
        hostname: []const u8,
        address: std.net.Address,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const hostname_copy = try self.allocator.dupe(u8, hostname);
        errdefer self.allocator.free(hostname_copy);

        const expires_at = time_compat.timestamp() + @as(i64, @intCast(self.default_ttl_seconds));

        try self.cache.put(hostname_copy, .{
            .address = address,
            .expires_at = expires_at,
            .family = address.any.family,
        });
    }

    /// Clean up expired entries
    pub fn cleanup(self: *DNSCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var to_remove: std.ArrayList([]const u8) = .empty;
        defer to_remove.deinit(self.allocator);

        var it = self.cache.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.isExpired()) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            if (self.cache.fetchRemove(key)) |removed| {
                self.allocator.free(removed.key);
            }
        }
    }
};

// Tests
test "dns resolver basic" {
    const testing = std.testing;

    var resolver = DNSResolver.init(testing.allocator);

    // Resolve localhost
    const result = try resolver.resolve("localhost", 25, .any);
    try testing.expect(result.address.any.family == std.posix.AF.INET or
        result.address.any.family == std.posix.AF.INET6);

    const stats = resolver.getStats();
    try testing.expectEqual(@as(u64, 1), stats.queries);
    try testing.expectEqual(@as(u64, 1), stats.successes);
}

test "dns resolver ipv4 only" {
    const testing = std.testing;

    var resolver = DNSResolver.init(testing.allocator);

    const result = try resolver.resolve("localhost", 25, .ipv4_only);
    try testing.expect(result.isIPv4());
    try testing.expectEqual(std.posix.AF.INET, result.family);
}

test "dns resolver invalid hostname" {
    const testing = std.testing;

    var resolver = DNSResolver.init(testing.allocator);

    const result = resolver.resolve("", 25, .any);
    try testing.expectError(DNSResolver.ResolutionError.InvalidHostname, result);

    const stats = resolver.getStats();
    try testing.expectEqual(@as(u64, 1), stats.failures);
}

test "dns cache basic" {
    const testing = std.testing;

    var cache = DNSCache.init(testing.allocator, 60);
    defer cache.deinit();

    const addr = try std.net.Address.parseIp4("127.0.0.1", 25);

    try cache.put("localhost", addr);

    const cached = cache.get("localhost");
    try testing.expect(cached != null);
    try testing.expect(cached.?.eql(addr));
}

test "dns cache expiration" {
    const testing = std.testing;

    var cache = DNSCache.init(testing.allocator, 1); // 1 second TTL
    defer cache.deinit();

    const addr = try std.net.Address.parseIp4("127.0.0.1", 25);
    try cache.put("localhost", addr);

    // Should be cached
    try testing.expect(cache.get("localhost") != null);

    // Wait for expiration
    const wait_ts = std.c.timespec{ .sec = 1, .nsec = 100_000_000 };
    _ = std.c.nanosleep(&wait_ts, null);

    // Should be expired
    try testing.expect(cache.get("localhost") == null);
}
