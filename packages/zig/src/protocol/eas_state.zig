//! The collection key and the items acknowledged with it advance as one row.
//! Legacy unscoped rows are left unread so a downgrade can reopen the database.
const std = @import("std");
const database = @import("../storage/database.zig");
const io_compat = @import("../core/io_compat.zig");

pub const Items = std.StringHashMapUnmanaged([]const u8);
pub const Snapshot = struct { key: []const u8, items: Items };
pub const Ping = struct { heartbeat: u64, folders: []const []const u8 };
const Entry = struct { id: []const u8, tag: []const u8 };

pub const Account = struct {
    db: *database.Database,
    user_id: i64,
    device_id: []const u8,

    fn bind(self: Account, stmt: database.Statement, collection: []const u8) !void {
        try stmt.bind(1, self.user_id);
        try stmt.bind(2, self.device_id);
        try stmt.bind(3, collection);
    }

    pub fn load(self: Account, a: std.mem.Allocator, collection: []const u8) !?Snapshot {
        const stmt = try self.db.prepare("SELECT sync_key,items FROM eas_mailbox_state WHERE user_id=?1 AND device_id=?2 AND collection_id=?3");
        defer stmt.finalize();
        try self.bind(stmt, collection);
        if (!try stmt.step()) return null;
        const entries = try std.json.parseFromSliceLeaky([]Entry, a, stmt.columnText(1), .{ .allocate = .alloc_always });
        var snapshot: Snapshot = .{ .key = try a.dupe(u8, stmt.columnText(0)), .items = .empty };
        try snapshot.items.ensureTotalCapacity(a, @intCast(entries.len));
        for (entries) |entry| snapshot.items.putAssumeCapacity(entry.id, entry.tag);
        return snapshot;
    }

    pub fn reset(self: Account, collection: []const u8, key: []const u8) !void {
        const stmt = try self.db.prepare(
            \\INSERT INTO eas_mailbox_state(user_id,device_id,collection_id,sync_key,items)
            \\VALUES (?1,?2,?3,?4,'[]')
            \\ON CONFLICT(user_id,device_id,collection_id) DO UPDATE SET sync_key=excluded.sync_key,items=excluded.items
        );
        defer stmt.finalize();
        try self.bind(stmt, collection);
        try stmt.bind(4, key);
        _ = try stmt.step();
    }

    pub fn advance(self: Account, a: std.mem.Allocator, collection: []const u8, previous: []const u8, key: []const u8, items: Items) !void {
        const entries = try a.alloc(Entry, items.count());
        var iterator = items.iterator();
        for (entries) |*entry| {
            const pair = iterator.next().?;
            entry.* = .{ .id = pair.key_ptr.*, .tag = pair.value_ptr.* };
        }
        const snapshot = try std.json.Stringify.valueAlloc(a, entries, .{});
        const stmt = try self.db.prepare(
            \\UPDATE eas_mailbox_state SET sync_key=?4,items=?5
            \\WHERE user_id=?1 AND device_id=?2 AND collection_id=?3 AND sync_key=?6 RETURNING 1
        );
        defer stmt.finalize();
        try self.bind(stmt, collection);
        try stmt.bind(4, key);
        try stmt.bind(5, snapshot);
        try stmt.bind(6, previous);
        if (!try stmt.step()) return error.InvalidSyncKey;
        _ = try stmt.step();
    }

    pub fn ping(self: Account, a: std.mem.Allocator, heartbeat: ?u64, folders: ?[]const []const u8) !?Ping {
        const updating = heartbeat != null or folders != null;
        const sql = if (!updating)
            "SELECT heartbeat,folders FROM eas_mailbox_ping WHERE user_id=?1 AND device_id=?2"
        else if (heartbeat != null and folders != null)
            \\INSERT INTO eas_mailbox_ping(user_id,device_id,heartbeat,folders) VALUES (?1,?2,?3,?4)
            \\ON CONFLICT(user_id,device_id) DO UPDATE SET heartbeat=excluded.heartbeat,folders=excluded.folders
            \\RETURNING heartbeat,folders
        else
            \\UPDATE eas_mailbox_ping SET heartbeat=COALESCE(?3,heartbeat),folders=COALESCE(?4,folders)
            \\WHERE user_id=?1 AND device_id=?2 RETURNING heartbeat,folders
        ;
        const stmt = try self.db.prepare(sql);
        defer stmt.finalize();
        try stmt.bind(1, self.user_id);
        try stmt.bind(2, self.device_id);
        if (updating) {
            try stmt.bindOpt(3, heartbeat);
            if (folders) |ids| {
                try stmt.bind(4, try std.json.Stringify.valueAlloc(a, ids, .{}));
            } else try stmt.bindNull(4);
        }
        if (!try stmt.step()) return null;
        const settings = Ping{
            .heartbeat = @intCast(stmt.columnInt64(0)),
            .folders = try std.json.parseFromSliceLeaky([]const []const u8, a, stmt.columnText(1), .{ .allocate = .alloc_always }),
        };
        if (updating) _ = try stmt.step();
        return settings;
    }
};

pub fn newKey(a: std.mem.Allocator) ![]const u8 {
    var random: [16]u8 = undefined;
    io_compat.randomBytes(&random);
    return std.fmt.allocPrint(a, "m1-{s}", .{&std.fmt.bytesToHex(random, .lower)});
}
