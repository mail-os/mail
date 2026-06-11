const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");

pub const RateLimiter = struct {
    allocator: std.mem.Allocator,
    ip_counters: std.StringHashMap(RateCounter),
    user_counters: std.StringHashMap(RateCounter),
    window_seconds: u64,
    max_requests: u32,
    max_requests_per_user: u32,
    cleanup_interval_seconds: u64,
    mutex: mutex_compat.Mutex,
    cleanup_thread: ?std.Thread,
    should_stop: std.atomic.Value(bool),
    // Opportunistic-sweep counter: every N operations, expired counters are
    // removed inline. (The old "time bucket" cleanup machinery stored
    // borrowed identifier slices that could alias freed session buffers and
    // was never wired up; counters grew until restart.)
    ops_since_sweep: u32,

    const RateCounter = struct {
        count: u32,
        window_start: i64,
        last_request: i64,
    };

    /// Run an inline sweep after this many checkAndIncrement* calls.
    const sweep_every_ops: u32 = 4096;

    pub fn init(allocator: std.mem.Allocator, window_seconds: u64, max_requests: u32, max_requests_per_user: u32, cleanup_interval_seconds: u64) RateLimiter {
        return RateLimiter{
            .allocator = allocator,
            .ip_counters = std.StringHashMap(RateCounter).init(allocator),
            .user_counters = std.StringHashMap(RateCounter).init(allocator),
            .window_seconds = window_seconds,
            .max_requests = max_requests,
            .max_requests_per_user = max_requests_per_user,
            .cleanup_interval_seconds = cleanup_interval_seconds,
            .mutex = mutex_compat.Mutex{},
            .cleanup_thread = null,
            .should_stop = std.atomic.Value(bool).init(false),
            .ops_since_sweep = 0,
        };
    }

    /// Start automatic cleanup in background thread
    pub fn startAutomaticCleanup(self: *RateLimiter) !void {
        if (self.cleanup_thread != null) {
            return error.CleanupAlreadyRunning;
        }

        self.should_stop.store(false, .monotonic);
        self.cleanup_thread = try std.Thread.spawn(.{}, cleanupWorker, .{self});
    }

    /// Stop automatic cleanup
    pub fn stopAutomaticCleanup(self: *RateLimiter) void {
        if (self.cleanup_thread) |thread| {
            self.should_stop.store(true, .monotonic);
            thread.join();
            self.cleanup_thread = null;
        }
    }

    fn cleanupWorker(self: *RateLimiter) void {
        // Use configurable cleanup interval
        const cleanup_interval_ns = self.cleanup_interval_seconds * std.time.ns_per_s;

        while (!self.should_stop.load(.monotonic)) {
            // Sleep in smaller intervals to allow quick shutdown
            var remaining = cleanup_interval_ns;
            while (remaining > 0 and !self.should_stop.load(.monotonic)) {
                const sleep_time = @min(remaining, 10 * std.time.ns_per_s);
                time_compat.sleep(sleep_time);
                remaining -= sleep_time;
            }

            if (!self.should_stop.load(.monotonic)) {
                self.cleanup();
            }
        }
    }

    pub fn deinit(self: *RateLimiter) void {
        // Stop cleanup thread if running
        self.stopAutomaticCleanup();

        // Clean up IP counters
        var ip_it = self.ip_counters.iterator();
        while (ip_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.ip_counters.deinit();

        // Clean up user counters
        var user_it = self.user_counters.iterator();
        while (user_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.user_counters.deinit();
    }

    pub fn checkAndIncrement(self: *RateLimiter, ip: []const u8) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = time_compat.timestamp();
        self.maybeSweepLocked(now);

        if (self.ip_counters.get(ip)) |counter| {
            const elapsed = now - counter.window_start;

            if (elapsed >= self.window_seconds) {
                // Reset window
                try self.ip_counters.put(ip, RateCounter{
                    .count = 1,
                    .window_start = now,
                    .last_request = now,
                });
                return true;
            } else if (counter.count >= self.max_requests) {
                // Rate limit exceeded
                return false;
            } else {
                // Increment counter
                try self.ip_counters.put(ip, RateCounter{
                    .count = counter.count +| 1,
                    .window_start = counter.window_start,
                    .last_request = now,
                });
                return true;
            }
        } else {
            // New IP
            const ip_copy = try self.allocator.dupe(u8, ip);
            try self.ip_counters.put(ip_copy, RateCounter{
                .count = 1,
                .window_start = now,
                .last_request = now,
            });
            return true;
        }
    }

    /// Check and increment rate limit for authenticated user
    pub fn checkAndIncrementUser(self: *RateLimiter, user: []const u8) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = time_compat.timestamp();
        self.maybeSweepLocked(now);

        if (self.user_counters.get(user)) |counter| {
            const elapsed = now - counter.window_start;

            if (elapsed >= self.window_seconds) {
                // Reset window
                try self.user_counters.put(user, RateCounter{
                    .count = 1,
                    .window_start = now,
                    .last_request = now,
                });
                return true;
            } else if (counter.count >= self.max_requests_per_user) {
                // Rate limit exceeded
                return false;
            } else {
                // Increment counter
                try self.user_counters.put(user, RateCounter{
                    .count = counter.count +| 1,
                    .window_start = counter.window_start,
                    .last_request = now,
                });
                return true;
            }
        } else {
            // New user
            const user_copy = try self.allocator.dupe(u8, user);
            try self.user_counters.put(user_copy, RateCounter{
                .count = 1,
                .window_start = now,
                .last_request = now,
            });
            return true;
        }
    }

    /// Inline sweep every `sweep_every_ops` operations so stale counters
    /// (one per unique client IP / user, forever) can't grow unboundedly
    /// even when no background cleanup thread is running. Caller holds the
    /// mutex.
    fn maybeSweepLocked(self: *RateLimiter, now: i64) void {
        self.ops_since_sweep +%= 1;
        if (self.ops_since_sweep < sweep_every_ops) return;
        self.ops_since_sweep = 0;
        self.sweepLocked(now);
    }

    fn sweepLocked(self: *RateLimiter, now: i64) void {
        const cutoff = now - @as(i64, @intCast(self.window_seconds * 2));

        var stale: std.ArrayList([]const u8) = .empty;
        defer stale.deinit(self.allocator);

        var ip_it = self.ip_counters.iterator();
        while (ip_it.next()) |entry| {
            if (entry.value_ptr.last_request < cutoff) {
                stale.append(self.allocator, entry.key_ptr.*) catch break;
            }
        }
        for (stale.items) |key| {
            if (self.ip_counters.fetchRemove(key)) |removed| {
                self.allocator.free(removed.key);
            }
        }
        stale.clearRetainingCapacity();

        var user_it = self.user_counters.iterator();
        while (user_it.next()) |entry| {
            if (entry.value_ptr.last_request < cutoff) {
                stale.append(self.allocator, entry.key_ptr.*) catch break;
            }
        }
        for (stale.items) |key| {
            if (self.user_counters.fetchRemove(key)) |removed| {
                self.allocator.free(removed.key);
            }
        }
    }

    pub fn getRemainingRequests(self: *RateLimiter, ip: []const u8) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = time_compat.timestamp();

        if (self.ip_counters.get(ip)) |counter| {
            const elapsed = now - counter.window_start;

            if (elapsed >= self.window_seconds) {
                return self.max_requests;
            } else if (counter.count >= self.max_requests) {
                return 0;
            } else {
                return self.max_requests - counter.count;
            }
        }

        return self.max_requests;
    }

    /// Get remaining requests for authenticated user
    pub fn getRemainingRequestsUser(self: *RateLimiter, user: []const u8) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = time_compat.timestamp();

        if (self.user_counters.get(user)) |counter| {
            const elapsed = now - counter.window_start;

            if (elapsed >= self.window_seconds) {
                return self.max_requests_per_user;
            } else if (counter.count >= self.max_requests_per_user) {
                return 0;
            } else {
                return self.max_requests_per_user - counter.count;
            }
        }

        return self.max_requests_per_user;
    }

    /// Clean up old rate limit entries (call periodically)
    /// O(1) cleanup using bucket-based approach instead of O(n) iteration
    pub fn cleanup(self: *RateLimiter) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.sweepLocked(time_compat.timestamp());
    }

    pub fn getStats(self: *RateLimiter) struct { tracked_ips: usize, tracked_users: usize, total_requests: u64, total_user_requests: u64 } {
        self.mutex.lock();
        defer self.mutex.unlock();

        var total: u64 = 0;
        var ip_it = self.ip_counters.valueIterator();
        while (ip_it.next()) |counter| {
            total += counter.count;
        }

        var user_total: u64 = 0;
        var user_it = self.user_counters.valueIterator();
        while (user_it.next()) |counter| {
            user_total += counter.count;
        }

        return .{
            .tracked_ips = self.ip_counters.count(),
            .tracked_users = self.user_counters.count(),
            .total_requests = total,
            .total_user_requests = user_total,
        };
    }
};

pub fn validateEmailAddress(email: []const u8) bool {
    // RFC 5321 / RFC 5322 email validation
    if (email.len == 0 or email.len > 254) return false;

    // SECURITY: Reject null bytes and control characters
    for (email) |c| {
        if (c < 32 or c == 127 or c == 0) return false;
    }

    const at_pos = std.mem.indexOf(u8, email, "@") orelse return false;

    // Reject multiple @ signs
    if (std.mem.lastIndexOf(u8, email, "@") != at_pos) return false;

    if (at_pos == 0 or at_pos == email.len - 1) return false;

    const local_part = email[0..at_pos];
    const domain_part = email[at_pos + 1 ..];

    if (local_part.len == 0 or local_part.len > 64) return false;
    if (domain_part.len == 0 or domain_part.len > 255) return false;

    // Reject leading/trailing dots in local part
    if (local_part[0] == '.' or local_part[local_part.len - 1] == '.') return false;

    // Reject consecutive dots in local part
    if (std.mem.indexOf(u8, local_part, "..") != null) return false;

    // Domain validation
    // Must have at least one dot
    if (std.mem.indexOf(u8, domain_part, ".") == null) return false;

    // Reject leading/trailing dots and hyphens in domain
    if (domain_part[0] == '.' or domain_part[domain_part.len - 1] == '.') return false;
    if (domain_part[0] == '-' or domain_part[domain_part.len - 1] == '-') return false;

    // Reject consecutive dots in domain
    if (std.mem.indexOf(u8, domain_part, "..") != null) return false;

    // Validate domain characters (letters, digits, hyphens, dots)
    for (domain_part) |c| {
        const valid = (c >= 'a' and c <= 'z') or
            (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or
            c == '.' or c == '-';
        if (!valid) return false;
    }

    return true;
}

pub fn sanitizeInput(input: []const u8) bool {
    // Check for common injection patterns
    if (std.mem.indexOf(u8, input, "\x00") != null) return false; // Null bytes

    // Block ALL CRLF sequences to prevent header injection
    if (std.mem.indexOf(u8, input, "\r\n") != null) return false;
    if (std.mem.indexOf(u8, input, "\n") != null) return false;
    if (std.mem.indexOf(u8, input, "\r") != null) return false;

    return true;
}

pub fn isValidHostname(hostname: []const u8) bool {
    if (hostname.len == 0 or hostname.len > 255) return false;

    // Check for valid characters
    for (hostname) |c| {
        const valid = (c >= 'a' and c <= 'z') or
            (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or
            c == '.' or c == '-';

        if (!valid) return false;
    }

    return true;
}
