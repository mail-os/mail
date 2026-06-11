//! Process-wide TTL cache for antispam DNS answers (DKIM public keys,
//! SPF/DMARC TXT records, DNSBL verdicts).
//!
//! These records change rarely, but without a cache every inbound message
//! re-queries DNS for the same names — on a busy server that is hundreds of
//! blocking UDP round-trips per minute for identical answers, all paid on
//! SMTP connection threads. Entries are capped and expired lazily; only
//! successful lookups are cached (transient DNS failures are not).
const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");

/// TTLs in seconds. Positive answers live longer than negative ones so a
/// freshly published record (e.g. a new DKIM selector) is picked up quickly.
pub const positive_ttl: i64 = 3600;
pub const negative_ttl: i64 = 300;

const max_entries = 4096;

const Entry = struct {
    value: ?[]u8, // null = cached negative result ("no record")
    expires_at: i64,
};

var mutex: mutex_compat.Mutex = .{};
var map: ?std.StringHashMap(Entry) = null;

// The cache is process-global, so it uses the libc allocator directly
// (always available — we link libc for sqlite3).
const gpa = std.heap.c_allocator;

pub const Lookup = union(enum) {
    miss,
    negative,
    /// Caller owns the slice (duplicated with the caller's allocator).
    hit: []u8,
};

/// Look up `key`. On `.hit` the value is duplicated with `allocator` and
/// owned by the caller.
pub fn get(allocator: std.mem.Allocator, key: []const u8) Lookup {
    mutex.lock();
    defer mutex.unlock();

    var m = &(map orelse return .miss);
    const entry = m.getEntry(key) orelse return .miss;
    if (time_compat.timestamp() >= entry.value_ptr.expires_at) {
        const stored_key = entry.key_ptr.*;
        if (entry.value_ptr.value) |v| gpa.free(v);
        _ = m.remove(key);
        gpa.free(stored_key);
        return .miss;
    }
    if (entry.value_ptr.value) |v| {
        const copy = allocator.dupe(u8, v) catch return .miss;
        return .{ .hit = copy };
    }
    return .negative;
}

/// Insert/replace `key`. `value == null` caches a negative answer.
/// Best-effort: allocation failures or a full cache simply skip caching.
pub fn put(key: []const u8, value: ?[]const u8, ttl: i64) void {
    mutex.lock();
    defer mutex.unlock();

    if (map == null) map = std.StringHashMap(Entry).init(gpa);
    var m = &map.?;

    const now = time_compat.timestamp();

    // At capacity and inserting a new key: evict expired entries; if
    // nothing expired, skip the insert rather than grow unboundedly.
    if (m.count() >= max_entries and !m.contains(key)) {
        sweepExpiredLocked(m, now);
        if (m.count() >= max_entries) return;
    }

    const value_copy: ?[]u8 = if (value) |v| (gpa.dupe(u8, v) catch return) else null;
    const key_copy = gpa.dupe(u8, key) catch {
        if (value_copy) |v| gpa.free(v);
        return;
    };

    const gop = m.getOrPut(key_copy) catch {
        if (value_copy) |v| gpa.free(v);
        gpa.free(key_copy);
        return;
    };
    if (gop.found_existing) {
        // Map keeps its original key; ours is redundant.
        gpa.free(key_copy);
        if (gop.value_ptr.value) |old| gpa.free(old);
    }
    gop.value_ptr.* = .{ .value = value_copy, .expires_at = now + ttl };
}

fn sweepExpiredLocked(m: *std.StringHashMap(Entry), now: i64) void {
    var expired_keys: std.ArrayList([]const u8) = .empty;
    defer expired_keys.deinit(gpa);

    var it = m.iterator();
    while (it.next()) |entry| {
        if (now >= entry.value_ptr.expires_at) {
            expired_keys.append(gpa, entry.key_ptr.*) catch break;
        }
    }
    for (expired_keys.items) |k| {
        if (m.fetchRemove(k)) |removed| {
            if (removed.value.value) |v| gpa.free(v);
            gpa.free(removed.key);
        }
    }
}

test "dns cache put/get/negative" {
    const testing = std.testing;

    put("test:positive", "hello", 60);
    switch (get(testing.allocator, "test:positive")) {
        .hit => |v| {
            defer testing.allocator.free(v);
            try testing.expectEqualStrings("hello", v);
        },
        else => return error.TestExpectedHit,
    }

    put("test:negative", null, 60);
    try testing.expect(get(testing.allocator, "test:negative") == .negative);

    try testing.expect(get(testing.allocator, "test:missing") == .miss);

    // Expired entries are treated as misses.
    put("test:expired", "x", -1);
    try testing.expect(get(testing.allocator, "test:expired") == .miss);
}
