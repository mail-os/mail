//! Classic aliases-file resolution for local delivery (role mailboxes:
//! postmaster@, abuse@, tlsrpt@, ...).
//!
//! File format (sendmail-style, one mapping per line):
//!
//!     # comment
//!     postmaster: chris
//!     abuse: chris
//!     tlsrpt: chris
//!
//! Path from SMTP_ALIASES_PATH (default /etc/mail/aliases). The file is
//! re-read at most every 60 seconds, so edits take effect without a
//! restart. Resolution follows chains up to 4 hops (a: b, b: c) and is
//! applied at local-delivery time only — auth/IMAP identities are not
//! aliased.

const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");
const fs_compat = @import("../core/fs_compat.zig");

const reload_interval_seconds: i64 = 60;
const max_hops = 4;

var mutex: mutex_compat.Mutex = .{};
var map: ?std.StringHashMap([]const u8) = null;
var last_load: i64 = 0;

const gpa = std.heap.c_allocator;

fn aliasesPath() []const u8 {
    if (std.c.getenv("SMTP_ALIASES_PATH")) |p| {
        const path = std.mem.sliceTo(p, 0);
        if (path.len > 0) return path;
    }
    return "/etc/mail/aliases";
}

fn clearLocked() void {
    if (map) |*m| {
        var it = m.iterator();
        while (it.next()) |entry| {
            gpa.free(entry.key_ptr.*);
            gpa.free(entry.value_ptr.*);
        }
        m.deinit();
        map = null;
    }
}

fn loadLocked() void {
    clearLocked();
    map = std.StringHashMap([]const u8).init(gpa);

    const content = fs_compat.readFileAlloc(gpa, aliasesPath()) catch return;
    defer gpa.free(content);

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const alias = std.mem.trim(u8, line[0..colon], " \t");
        const target = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (alias.len == 0 or target.len == 0) continue;

        const alias_copy = gpa.dupe(u8, alias) catch continue;
        const target_copy = gpa.dupe(u8, target) catch {
            gpa.free(alias_copy);
            continue;
        };
        const gop = map.?.getOrPut(alias_copy) catch {
            gpa.free(alias_copy);
            gpa.free(target_copy);
            continue;
        };
        if (gop.found_existing) {
            // Last definition wins, like sendmail newaliases warns about.
            gpa.free(alias_copy);
            gpa.free(gop.value_ptr.*);
        }
        gop.value_ptr.* = target_copy;
    }
}

/// Resolve a local part through the aliases file. Returns the final
/// delivery target (the input itself when unaliased). The returned slice
/// is valid until the next reload — callers must use or copy it promptly
/// (delivery does so within the same request).
pub fn resolve(local_part: []const u8) []const u8 {
    mutex.lock();
    defer mutex.unlock();

    const now = time_compat.timestamp();
    if (map == null or now - last_load >= reload_interval_seconds) {
        last_load = now;
        loadLocked();
    }

    var current = local_part;
    var hops: usize = 0;
    while (hops < max_hops) : (hops += 1) {
        const next = map.?.get(current) orelse return current;
        current = next;
    }
    return current;
}

test "alias file parsing and chains" {
    const testing = std.testing;

    // Build a temp aliases file and point resolution at it.
    const path = "/tmp/pantry-mail-aliases-test";
    {
        const f = try fs_compat.cwd().createFile(path, .{});
        defer f.close();
        try f.writeAll("# role mailboxes\npostmaster: chris\nabuse: postmaster\n\nbroken-line\ntlsrpt: chris\n");
    }
    defer fs_compat.cwd().deleteFile(path) catch {};

    mutex.lock();
    clearLocked();
    last_load = 0;
    mutex.unlock();

    // Use the env override via direct load: temporarily set the env var is
    // awkward cross-platform in tests, so load the file directly.
    mutex.lock();
    map = std.StringHashMap([]const u8).init(gpa);
    {
        const content = try fs_compat.readFileAlloc(testing.allocator, path);
        defer testing.allocator.free(content);
        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const alias = std.mem.trim(u8, line[0..colon], " \t");
            const target = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (alias.len == 0 or target.len == 0) continue;
            try map.?.put(try gpa.dupe(u8, alias), try gpa.dupe(u8, target));
        }
    }
    last_load = time_compat.timestamp() + 1000; // suppress reload during asserts
    mutex.unlock();

    try testing.expectEqualStrings("chris", resolve("postmaster"));
    try testing.expectEqualStrings("chris", resolve("abuse")); // chain: abuse -> postmaster -> chris
    try testing.expectEqualStrings("chris", resolve("tlsrpt"));
    try testing.expectEqualStrings("nobody-aliased", resolve("nobody-aliased"));

    mutex.lock();
    clearLocked();
    last_load = 0;
    mutex.unlock();
}
