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
    // Bucket-based tracking for O(1) cleanup
    time_buckets: std.AutoHashMap(i64, std.ArrayList([]const u8)),
    bucket_size_seconds: u64,

    const RateCounter = struct {
        count: u32,
        window_start: i64,
        last_request: i64,
        bucket_key: i64, // Which time bucket this entry belongs to
    };

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
            .time_buckets = std.AutoHashMap(i64, std.ArrayList([]const u8)).init(allocator),
            .bucket_size_seconds = window_seconds * 2, // Buckets are 2x window size
        };
    }

    /// Calculate which time bucket a timestamp belongs to
    fn getBucketKey(self: *RateLimiter, timestamp: i64) i64 {
        return @divFloor(timestamp, @as(i64, @intCast(self.bucket_size_seconds)));
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
                std.time.sleep(sleep_time);
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

        // Clean up time buckets
        var bucket_it = self.time_buckets.iterator();
        while (bucket_it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.time_buckets.deinit();
    }

    pub fn checkAndIncrement(self: *RateLimiter, ip: []const u8) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = time_compat.timestamp();
        const bucket_key = self.getBucketKey(now);

        if (self.ip_counters.get(ip)) |counter| {
            const elapsed = now - counter.window_start;

            if (elapsed >= self.window_seconds) {
                // Reset window - update bucket tracking
                try self.addToBucket(bucket_key, ip);
                try self.ip_counters.put(ip, RateCounter{
                    .count = 1,
                    .window_start = now,
                    .last_request = now,
                    .bucket_key = bucket_key,
                });
                return true;
            } else if (counter.count >= self.max_requests) {
                // Rate limit exceeded
                return false;
            } else {
                // Increment counter - update bucket if changed
                if (counter.bucket_key != bucket_key) {
                    try self.addToBucket(bucket_key, ip);
                }
                try self.ip_counters.put(ip, RateCounter{
                    .count = counter.count +| 1,
                    .window_start = counter.window_start,
                    .last_request = now,
                    .bucket_key = bucket_key,
                });
                return true;
            }
        } else {
            // New IP - add to bucket
            const ip_copy = try self.allocator.dupe(u8, ip);
            try self.addToBucket(bucket_key, ip_copy);
            try self.ip_counters.put(ip_copy, RateCounter{
                .count = 1,
                .window_start = now,
                .last_request = now,
                .bucket_key = bucket_key,
            });
            return true;
        }
    }

    /// Add an IP/user to a time bucket for efficient cleanup
    fn addToBucket(self: *RateLimiter, bucket_key: i64, identifier: []const u8) !void {
        const bucket_result = try self.time_buckets.getOrPut(bucket_key);
        if (!bucket_result.found_existing) {
            // In Zig 0.15, ArrayList is initialized with {} instead of init()
            bucket_result.value_ptr.* = .{};
        }

        // Only add if not already in bucket
        for (bucket_result.value_ptr.items) |item| {
            if (std.mem.eql(u8, item, identifier)) {
                return;
            }
        }

        try bucket_result.value_ptr.append(self.allocator, identifier);
    }

    /// Check and increment rate limit for authenticated user
    pub fn checkAndIncrementUser(self: *RateLimiter, user: []const u8) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = time_compat.timestamp();
        const bucket_key = self.getBucketKey(now);

        if (self.user_counters.get(user)) |counter| {
            const elapsed = now - counter.window_start;

            if (elapsed >= self.window_seconds) {
                // Reset window
                try self.addToBucket(bucket_key, user);
                try self.user_counters.put(user, RateCounter{
                    .count = 1,
                    .window_start = now,
                    .last_request = now,
                    .bucket_key = bucket_key,
                });
                return true;
            } else if (counter.count >= self.max_requests_per_user) {
                // Rate limit exceeded
                return false;
            } else {
                // Increment counter
                if (counter.bucket_key != bucket_key) {
                    try self.addToBucket(bucket_key, user);
                }
                try self.user_counters.put(user, RateCounter{
                    .count = counter.count +| 1,
                    .window_start = counter.window_start,
                    .last_request = now,
                    .bucket_key = bucket_key,
                });
                return true;
            }
        } else {
            // New user
            const user_copy = try self.allocator.dupe(u8, user);
            try self.addToBucket(bucket_key, user_copy);
            try self.user_counters.put(user_copy, RateCounter{
                .count = 1,
                .window_start = now,
                .last_request = now,
                .bucket_key = bucket_key,
            });
            return true;
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

        const now = time_compat.timestamp();

        // Calculate cutoff bucket - anything before this should be removed
        const cutoff_time = now - @as(i64, @intCast(self.window_seconds * 2));
        const cutoff_bucket = self.getBucketKey(cutoff_time);

        var buckets_to_remove = std.ArrayList(i64).init(self.allocator);
        defer buckets_to_remove.deinit();

        // Identify old buckets for removal
        var bucket_it = self.time_buckets.iterator();
        while (bucket_it.next()) |entry| {
            if (entry.key_ptr.* < cutoff_bucket) {
                buckets_to_remove.append(entry.key_ptr.*) catch continue;
            }
        }

        // Remove old entries from old buckets
        for (buckets_to_remove.items) |bucket_key| {
            if (self.time_buckets.fetchRemove(bucket_key)) |removed_bucket| {
                // Remove all IPs/users in this bucket from counters
                for (removed_bucket.value.items) |identifier| {
                    // Check if it's still in IP counters
                    if (self.ip_counters.fetchRemove(identifier)) |removed_ip| {
                        self.allocator.free(removed_ip.key);
                    }
                    // Check if it's still in user counters
                    if (self.user_counters.fetchRemove(identifier)) |removed_user| {
                        self.allocator.free(removed_user.key);
                    }
                }
                removed_bucket.value.deinit(self.allocator);
            }
        }
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
