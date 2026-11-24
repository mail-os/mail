//! Per-client EWS cursors. Keep one acknowledged item set and one retry
//! response per cursor, so paging does not retain a copy of every snapshot.
const std = @import("std");
const database = @import("../../storage/database.zig");
const io = @import("../../core/io_compat.zig");
const time = @import("../../core/time_compat.zig");

const day = 24 * 60 * 60;
const lifetime = 30 * day;
const cursors_per_folder = 16;
const key_prefix = "RVcB"; // Base64 of 'E', 'W', version 1.
const key_entropy = 21;
const key_size = key_prefix.len + std.base64.standard.Encoder.calcSize(key_entropy);

pub const Item = struct {
    id: []const u8,
    // Calendar and contact items have no read flag.
    seen: ?bool = null,

    pub fn lessThan(_: void, left: Item, right: Item) bool {
        return std.mem.order(u8, left.id, right.id) == .lt;
    }
};

pub const Change = struct {
    kind: enum { create, delete, read_flag },
    item: Item,
};

pub const Page = struct {
    changes: []const Change,
    items: []const Item,
    last: bool,
};

/// Merge id-sorted sets. The next cursor records only changes included in this
/// page. New input on a later page is always compared with that exact set.
pub fn page(a: std.mem.Allocator, known: []const Item, current: []const Item, limit: usize) !Page {
    var changes: std.ArrayList(Change) = .empty;
    var items: std.ArrayList(Item) = .empty;
    var old: usize = 0;
    var new: usize = 0;
    while (old < known.len or new < current.len) {
        const order: std.math.Order = if (old == known.len) .gt else if (new == current.len) .lt else std.mem.order(u8, known[old].id, current[new].id);
        const change: ?Change = switch (order) {
            .lt => .{ .kind = .delete, .item = known[old] },
            .gt => .{ .kind = .create, .item = current[new] },
            .eq => if (known[old].seen != current[new].seen) .{ .kind = .read_flag, .item = current[new] } else null,
        };
        if (change) |entry| {
            if (changes.items.len == limit) {
                try items.appendSlice(a, known[old..]);
                return .{ .changes = changes.items, .items = items.items, .last = false };
            }
            try changes.append(a, entry);
        }
        if (order != .gt) old += 1;
        if (order != .lt) {
            try items.append(a, current[new]);
            new += 1;
        }
    }
    return .{ .changes = changes.items, .items = items.items, .last = true };
}

pub fn newKey(a: std.mem.Allocator) ![]const u8 {
    var random: [key_entropy]u8 = undefined;
    io.randomBytes(&random);
    const key = try a.alloc(u8, key_size);
    @memcpy(key[0..key_prefix.len], key_prefix);
    _ = std.base64.standard.Encoder.encode(key[key_prefix.len..], &random);
    return key;
}

pub const Saved = union(enum) {
    current: struct { items: []const Item, touched_at: i64 },
    replay: []const u8,
};

pub const Cursor = struct {
    db: *database.Database,
    user_id: i64,
    folder: []const u8,

    pub fn load(self: Cursor, a: std.mem.Allocator, key: []const u8, limit: usize) !?Saved {
        if (key.len != key_size or !std.mem.startsWith(u8, key, key_prefix)) return null;
        const stmt = try self.db.prepare(
            \\SELECT sync_key,items,touched_at,previous_response,previous_count
            \\FROM ews_item_sync WHERE user_id=?1 AND folder=?2 AND touched_at>?4
            \\AND (sync_key=?3 OR previous_key=?3)
        );
        defer stmt.finalize();
        try self.bindScope(stmt);
        try stmt.bind(3, key);
        try stmt.bind(4, time.timestamp() - lifetime);
        if (!try stmt.step()) return null;
        if (!std.mem.eql(u8, key, stmt.columnText(0))) {
            if (stmt.columnInt64(4) > @as(i64, @intCast(limit))) return null;
            return .{ .replay = try a.dupe(u8, stmt.columnText(3)) };
        }
        return .{ .current = .{
            .items = try std.json.parseFromSliceLeaky([]Item, a, stmt.columnText(1), .{ .allocate = .alloc_always }),
            .touched_at = stmt.columnInt64(2),
        } };
    }

    pub fn create(self: Cursor, key: []const u8, items: []const u8) !void {
        const now = time.timestamp();
        var tx = try self.db.beginTransaction(.write);
        defer tx.deinit();
        {
            const expire = try tx.prepare("DELETE FROM ews_item_sync WHERE touched_at<=?1");
            defer expire.finalize();
            try expire.bind(1, now - lifetime);
            _ = try expire.step();
        }
        {
            const add = try tx.prepare("INSERT INTO ews_item_sync(user_id,folder,sync_key,items,touched_at) VALUES(?1,?2,?3,?4,?5)");
            defer add.finalize();
            try self.bindScope(add);
            try add.bind(3, key);
            try add.bind(4, items);
            try add.bind(5, now);
            _ = try add.step();
        }
        {
            const trim = try tx.prepare(
                \\DELETE FROM ews_item_sync WHERE id IN (
                \\    SELECT id FROM ews_item_sync WHERE user_id=?1 AND folder=?2
                \\    ORDER BY touched_at DESC,id DESC LIMIT -1 OFFSET ?3
                \\)
            );
            defer trim.finalize();
            try self.bindScope(trim);
            try trim.bind(3, cursors_per_folder);
            _ = try trim.step();
        }
        try tx.commit();
    }

    pub fn advance(self: Cursor, previous: []const u8, key: []const u8, items: []const u8, response: []const u8, count: usize) !bool {
        var tx = try self.db.beginTransaction(.write);
        defer tx.deinit();
        const stmt = try tx.prepare(
            \\UPDATE ews_item_sync SET sync_key=?3,items=?4,previous_key=?5,previous_response=?6,
            \\    previous_count=?7,touched_at=?8
            \\WHERE user_id=?1 AND folder=?2 AND sync_key=?5 AND touched_at>?9 RETURNING id
        );
        defer stmt.finalize();
        try self.bindScope(stmt);
        try stmt.bind(3, key);
        try stmt.bind(4, items);
        try stmt.bind(5, previous);
        try stmt.bind(6, response);
        try stmt.bind(7, count);
        const now = time.timestamp();
        try stmt.bind(8, now);
        try stmt.bind(9, now - lifetime);
        if (!try stmt.step()) return false;
        // Finish the statement to surface any error committing this update.
        _ = try stmt.step();
        try tx.commit();
        return true;
    }

    pub fn touch(self: Cursor, key: []const u8, touched_at: i64) !void {
        const now = time.timestamp();
        if (touched_at > now - day) return;
        const stmt = try self.db.prepare("UPDATE ews_item_sync SET touched_at=?4 WHERE user_id=?1 AND folder=?2 AND sync_key=?3");
        defer stmt.finalize();
        try self.bindScope(stmt);
        try stmt.bind(3, key);
        try stmt.bind(4, now);
        _ = try stmt.step();
    }

    fn bindScope(self: Cursor, stmt: database.Statement) !void {
        try stmt.bind(1, self.user_id);
        try stmt.bind(2, self.folder);
    }
};
