//! Preserve mailbox-scoped references across a copy to a new filesystem.
//! The backup DB records hashes only for files that still match the original
//! delivery identity. Restore rebinds those rows after checking the bytes.
const std = @import("std");
const database = @import("database.zig");
const refs = @import("message_refs.zig");
const fs = @import("../core/fs_compat.zig");
const Allocator = std.mem.Allocator;

pub const Capture = struct { recorded: usize = 0, unavailable: usize = 0 };

const entries =
    \\SELECT 0 AS kind,r.user_id,u.username,r.folder,r.basename,r.reference,r.file_stamp
    \\FROM mailbox_message_refs r JOIN users u ON r.user_id=u.id WHERE r.file_stamp<>''
    \\UNION ALL
    \\SELECT 1,r.user_id,u.username,r.folder,r.basename,r.basename,r.file_stamp
    \\FROM sender_review_messages r JOIN users u ON r.user_id=u.id WHERE r.file_stamp<>''
    \\ORDER BY 3,4,5,1
;

fn pathSegment(value: []const u8) bool {
    if (value.len == 0 or std.mem.eql(u8, value, ".") or std.mem.eql(u8, value, "..")) return false;
    for (value) |byte| if (byte < 32 or byte == 127 or byte == '/' or byte == '\\') return false;
    return true;
}

const FolderFiles = struct {
    arena: std.heap.ArenaAllocator,
    username: []const u8 = "",
    folder: []const u8 = "",
    paths: std.StringHashMapUnmanaged(?[]const u8) = .empty,

    fn include(self: *FolderFiles, dir: []const u8) !void {
        const a = self.arena.allocator();
        const names = fs.listEmlFiles(a, dir) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        for (names) |name| {
            const row = try self.paths.getOrPut(a, database.maildirBaseName(name));
            row.value_ptr.* = if (row.found_existing) null else try std.fs.path.join(a, &.{ dir, name });
        }
    }

    fn path(self: *FolderFiles, root: []const u8, username: []const u8, folder: []const u8, basename: []const u8) !?[]const u8 {
        if (!pathSegment(username) or !pathSegment(folder) or !pathSegment(basename)) return error.InvalidBackupMailboxPath;
        if (!std.mem.eql(u8, self.username, username) or !std.mem.eql(u8, self.folder, folder)) {
            _ = self.arena.reset(.retain_capacity);
            const a = self.arena.allocator();
            self.username = try a.dupe(u8, username);
            self.folder = try a.dupe(u8, folder);
            self.paths = .empty;
            if (std.ascii.eqlIgnoreCase(folder, "INBOX")) {
                try self.include(try std.fs.path.join(a, &.{ root, username, "new" }));
                try self.include(try std.fs.path.join(a, &.{ root, username, "cur" }));
            } else {
                try self.include(try std.fs.path.join(a, &.{ root, username, folder }));
            }
        }
        return self.paths.get(basename) orelse null;
    }
};

const File = struct { stamp: []const u8, hash: [32]u8 };

fn readFile(a: Allocator, path: []const u8, expected: ?[]const u8) !?File {
    const first = refs.fileFingerprint(a, path) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    if (expected) |stamp| if (!std.mem.eql(u8, stamp, first.stamp)) return null;
    const file = fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close();
    const opened = try refs.openFileFingerprint(a, file.handle);
    if (!std.mem.eql(u8, first.fingerprint, opened.fingerprint)) return null;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var size: u64 = 0;
    var buffer: [64 * 1024]u8 = undefined;
    while (true) {
        const count = std.c.read(file.handle, &buffer, buffer.len);
        if (count < 0) {
            if (std.c._errno().* == @backingInt(std.c.E.INTR)) continue;
            return error.BackupFileReadFailed;
        }
        if (count == 0) break;
        const length: usize = @intCast(count);
        size += length;
        hash.update(buffer[0..length]);
    }
    const last = refs.fileFingerprint(a, path) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    const after_read = try refs.openFileFingerprint(a, file.handle);
    if (size != first.size or !std.mem.eql(u8, first.fingerprint, after_read.fingerprint) or
        !std.mem.eql(u8, first.fingerprint, last.fingerprint)) return null;
    return .{ .stamp = last.stamp, .hash = hash.finalResult() };
}

/// The database is the backup copy. This operation reads the source Maildir
/// and records identities in the copy without altering the live registry.
pub fn capture(db: *database.Database, a: Allocator, mail_root: []const u8) !Capture {
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS backup_message_identities (
        \\  kind INTEGER NOT NULL CHECK(kind IN (0,1)),
        \\  user_id INTEGER NOT NULL,
        \\  folder TEXT NOT NULL,
        \\  basename TEXT NOT NULL,
        \\  reference TEXT NOT NULL,
        \\  original_stamp TEXT NOT NULL,
        \\  digest BLOB NOT NULL CHECK(length(digest)=32),
        \\  PRIMARY KEY(kind,user_id,folder,basename)
        \\);
    );
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const clear = try tx.prepare("DELETE FROM backup_message_identities");
    defer clear.finalize();
    _ = try clear.step();
    const list = try tx.prepare(entries);
    defer list.finalize();
    const insert = try tx.prepare("INSERT INTO backup_message_identities VALUES (?,?,?,?,?,?,?)");
    defer insert.finalize();

    var cache: FolderFiles = .{ .arena = std.heap.ArenaAllocator.init(a) };
    defer cache.arena.deinit();
    var scratch = std.heap.ArenaAllocator.init(a);
    defer scratch.deinit();
    var result: Capture = .{};
    while (try list.step()) {
        _ = scratch.reset(.retain_capacity);
        const stamp = list.columnText(6);
        const path = try cache.path(mail_root, list.columnText(2), list.columnText(3), list.columnText(4));
        const file = if (path) |name| try readFile(scratch.allocator(), name, stamp) else null;
        if (file) |identity| {
            try insert.bind(1, list.columnInt64(0));
            try insert.bind(2, list.columnInt64(1));
            try insert.bind(3, list.columnText(3));
            try insert.bind(4, list.columnText(4));
            try insert.bind(5, list.columnText(5));
            try insert.bind(6, stamp);
            try insert.bindBlob(7, &identity.hash);
            _ = try insert.step();
            try insert.reset();
            result.recorded += 1;
        } else {
            result.unavailable += 1;
        }
    }
    try tx.commit();
    return result;
}

/// Rebind all authenticated files together. A missing or changed file fails
/// the restore check and rolls back every reference update for this archive.
pub fn rebind(db: *database.Database, a: Allocator, mail_root: []const u8) !usize {
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const list = try tx.prepare(
        \\SELECT m.kind,m.user_id,u.username,m.folder,m.basename,m.reference,m.original_stamp,m.digest
        \\FROM backup_message_identities m LEFT JOIN users u ON m.user_id=u.id
        \\ORDER BY u.username,m.folder,m.basename,m.kind
    );
    var cache: FolderFiles = .{ .arena = std.heap.ArenaAllocator.init(a) };
    defer cache.arena.deinit();
    var scratch = std.heap.ArenaAllocator.init(a);
    defer scratch.deinit();
    var rebound: usize = 0;
    {
        defer list.finalize();
        const message = try tx.prepare(
            \\UPDATE mailbox_message_refs SET file_stamp=?6 WHERE user_id=?1 AND folder=?2 AND basename=?3
            \\ AND reference=?4 AND file_stamp=?5 RETURNING user_id
        );
        defer message.finalize();
        const review = try tx.prepare(
            \\UPDATE sender_review_messages SET file_stamp=?6 WHERE user_id=?1 AND folder=?2 AND basename=?3
            \\ AND basename=?4 AND file_stamp=?5 RETURNING user_id
        );
        defer review.finalize();
        while (try list.step()) {
            _ = scratch.reset(.retain_capacity);
            const path = (try cache.path(mail_root, list.columnText(2), list.columnText(3), list.columnText(4))) orelse return error.BackupFileMissing;
            const file = (try readFile(scratch.allocator(), path, null)) orelse return error.BackupFileMissing;
            if (!std.mem.eql(u8, &file.hash, list.columnBlob(7))) return error.BackupFileMismatch;
            const update = switch (list.columnInt64(0)) {
                0 => message,
                1 => review,
                else => return error.InvalidBackupIdentity,
            };
            try update.bind(1, list.columnInt64(1));
            try update.bind(2, list.columnText(3));
            try update.bind(3, list.columnText(4));
            try update.bind(4, list.columnText(5));
            try update.bind(5, list.columnText(6));
            try update.bind(6, file.stamp);
            if (!try update.step()) return error.BackupIdentityMissing;
            _ = try update.step();
            try update.reset();
            rebound += 1;
        }
    }
    const remove = try tx.prepare("DROP TABLE backup_message_identities");
    defer remove.finalize();
    _ = try remove.step();
    try tx.commit();
    return rebound;
}
