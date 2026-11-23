//! The collection key and the items acknowledged with it advance as one row.
//! Legacy unscoped rows are left unread so a downgrade can reopen the database.
const std = @import("std");
const database = @import("../storage/database.zig");
const io_compat = @import("../core/io_compat.zig");
const time = @import("../core/time_compat.zig");
const folder_edits = @import("../storage/folder_edits.zig");

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
        return self.replace(collection, key, "[]");
    }

    pub fn resetSnapshot(self: Account, a: std.mem.Allocator, collection: []const u8, key: []const u8, items: Items) !void {
        return self.replace(collection, key, try encodeItems(a, items));
    }

    fn replace(self: Account, collection: []const u8, key: []const u8, items: []const u8) !void {
        const stmt = try self.db.prepare(
            \\INSERT INTO eas_mailbox_state(user_id,device_id,collection_id,sync_key,items)
            \\VALUES (?1,?2,?3,?4,?5)
            \\ON CONFLICT(user_id,device_id,collection_id) DO UPDATE SET sync_key=excluded.sync_key,items=excluded.items
        );
        defer stmt.finalize();
        try self.bind(stmt, collection);
        try stmt.bind(4, key);
        try stmt.bind(5, items);
        _ = try stmt.step();
    }

    fn encodeItems(a: std.mem.Allocator, items: Items) ![]const u8 {
        const entries = try a.alloc(Entry, items.count());
        var iterator = items.iterator();
        for (entries) |*entry| {
            const pair = iterator.next().?;
            entry.* = .{ .id = pair.key_ptr.*, .tag = pair.value_ptr.* };
        }
        return std.json.Stringify.valueAlloc(a, entries, .{});
    }

    const advance_sql =
        \\UPDATE eas_mailbox_state SET sync_key=?4,items=?5
        \\WHERE user_id=?1 AND device_id=?2 AND collection_id=?3 AND sync_key=?6 RETURNING 1
    ;

    pub fn advance(self: Account, a: std.mem.Allocator, collection: []const u8, previous: []const u8, key: []const u8, items: Items) !void {
        const snapshot = try encodeItems(a, items);
        const stmt = try self.db.prepare(advance_sql);
        defer stmt.finalize();
        try self.applyAdvance(stmt, collection, previous, key, snapshot);
    }

    /// Publish a newly created Maildir for IMAP and webmail in the same
    /// transaction that advances this device's folder hierarchy.
    pub fn registerFolder(self: Account, a: std.mem.Allocator, collection: []const u8, previous: []const u8, key: []const u8, items: Items, user: []const u8, folder: []const u8) !void {
        const snapshot = try encodeItems(a, items);
        var tx = try self.db.beginTransaction(.write);
        defer tx.deinit();
        const record = try tx.prepare(
            \\INSERT INTO imap_mailboxes(username,mailbox,uidvalidity,uidnext)
            \\VALUES(?1,?2,MAX(?3,COALESCE((SELECT uidvalidity+1 FROM imap_mailbox_generations WHERE username=?1 AND mailbox=?2),0)),1)
            \\ON CONFLICT(username,mailbox) DO UPDATE SET uidvalidity=MAX(imap_mailboxes.uidvalidity+1,excluded.uidvalidity),uidnext=1
        );
        defer record.finalize();
        try record.bind(1, user);
        try record.bind(2, folder);
        try record.bind(3, time.timestamp());
        _ = try record.step();
        const old_uids = try tx.prepare("DELETE FROM imap_uids WHERE username=?1 AND mailbox=?2");
        defer old_uids.finalize();
        try old_uids.bind(1, user);
        try old_uids.bind(2, folder);
        _ = try old_uids.step();

        const stmt = try tx.prepare(advance_sql);
        defer stmt.finalize();
        try self.applyAdvance(stmt, collection, previous, key, snapshot);
        try tx.commit();
    }

    pub fn editFolder(self: Account, a: std.mem.Allocator, collection: []const u8, previous: []const u8, key: []const u8, items: Items, user: []const u8, folder_id: []const u8, edit: folder_edits.Edit) !void {
        const snapshot = try encodeItems(a, items);
        var tx = try self.db.beginTransaction(.write);
        defer tx.deinit();
        try edit.applyMetadata(tx, user);
        if (edit.destination == null) {
            const stmt = try tx.prepare("DELETE FROM eas_mailbox_state WHERE user_id=?1 AND collection_id=?2");
            defer stmt.finalize();
            try stmt.bind(1, self.user_id);
            try stmt.bind(2, folder_id);
            _ = try stmt.step();
        }
        const stmt = try tx.prepare(advance_sql);
        defer stmt.finalize();
        try self.applyAdvance(stmt, collection, previous, key, snapshot);
        try tx.commit();
    }

    fn applyAdvance(self: Account, stmt: database.Statement, collection: []const u8, previous: []const u8, key: []const u8, snapshot: []const u8) !void {
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
