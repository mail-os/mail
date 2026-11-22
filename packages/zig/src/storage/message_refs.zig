//! Mailbox-scoped references are independent of IMAP UID and Message-ID.
//! The mailbox mutation lock covers registry changes and their file operations.
const builtin = @import("builtin");
const std = @import("std");
const database = @import("database.zig");
const fs = @import("../core/fs_compat.zig");
const io = @import("../core/io_compat.zig");

const Allocator = std.mem.Allocator;
const owner = "user_id=(SELECT id FROM users WHERE username=?1)";
const columns = "SELECT reference,folder,basename,file_stamp,next_folder,next_basename,next_digest FROM mailbox_message_refs WHERE " ++ owner;

pub const Location = struct { folder: []const u8, basename: []const u8 };
pub const Pending = struct { location: Location, digest: []const u8 };
pub const Entry = struct { id: []const u8, location: Location, stamp: []const u8, pending: ?Pending };
pub const JunkChange = struct {
    action: enum { junk, not_junk, undo },
    receipt: []const u8,
};

pub fn valid(id: []const u8) bool {
    if (id.len != 32) return false;
    for (id) |byte| if (!std.ascii.isHex(byte)) return false;
    return true;
}

pub fn location(folder: []const u8, filename: []const u8) Location {
    return .{ .folder = if (std.ascii.eqlIgnoreCase(folder, "INBOX")) "INBOX" else folder, .basename = database.maildirBaseName(filename) };
}

pub fn digest(raw: []const u8) [64]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &hash, .{});
    return std.fmt.bytesToHex(hash, .lower);
}

/// Birth time distinguishes reused inodes. On filesystems without it, the
/// modification time gives Maildir's immutable files the same property.
pub fn fileStamp(a: Allocator, path: []const u8) ![]const u8 {
    return (try fileIdentity(a, path, false)).stamp;
}

pub const FileIdentity = struct { stamp: []const u8, fingerprint: []const u8, size: u64 };

/// Search also checks modification time and size to recover from externally
/// repaired or replaced files while preserving the existing reference stamp.
pub fn fileFingerprint(a: Allocator, path: []const u8) !FileIdentity {
    return fileIdentity(a, path, true);
}

fn fileIdentity(a: Allocator, path: []const u8, fingerprint: bool) !FileIdentity {
    const file = try a.dupeSentinel(u8, path, 0);
    defer a.free(file);
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var stat: linux.Statx = std.mem.zeroes(linux.Statx);
        const result = linux.statx(linux.AT.FDCWD, file, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true, .INO = true, .BTIME = true, .MTIME = true, .SIZE = fingerprint }, &stat);
        if (linux.errno(result) != .SUCCESS or !stat.mask.INO or !stat.mask.TYPE or !std.c.S.ISREG(stat.mode)) return error.FileNotFound;
        if (!stat.mask.BTIME and !stat.mask.MTIME) return error.FileNotFound;
        const born = if (stat.mask.BTIME) stat.btime else stat.mtime;
        const stamp = try std.fmt.allocPrint(a, "{d}:{d}:{d}:{d}:{d}", .{ stat.dev_major, stat.dev_minor, stat.ino, born.sec, born.nsec });
        return .{
            .stamp = stamp,
            .fingerprint = if (fingerprint) try std.fmt.allocPrint(a, "{s}:{d}:{d}:{d}", .{ stamp, stat.mtime.sec, stat.mtime.nsec, stat.size }) else "",
            .size = stat.size,
        };
    }
    var stat: std.c.Stat = undefined;
    if (std.c.fstatat(std.c.AT.FDCWD, file, &stat, std.c.AT.SYMLINK_NOFOLLOW) != 0 or !std.c.S.ISREG(stat.mode)) return error.FileNotFound;
    const born = if (@hasDecl(std.c.Stat, "birthtime")) stat.birthtime() else stat.mtime();
    const timestamp = if (born.sec == 0 and born.nsec == 0) stat.mtime() else born;
    const stamp = try std.fmt.allocPrint(a, "{d}:{d}:{d}:{d}", .{ stat.dev, stat.ino, timestamp.sec, timestamp.nsec });
    return .{
        .stamp = stamp,
        .fingerprint = if (fingerprint) try std.fmt.allocPrint(a, "{s}:{d}:{d}:{d}", .{ stamp, stat.mtime().sec, stat.mtime().nsec, stat.size }) else "",
        .size = @intCast(@max(stat.size, 0)),
    };
}

fn read(a: Allocator, s: database.Statement) !Entry {
    return .{
        .id = try a.dupe(u8, s.columnText(0)),
        .location = .{ .folder = try a.dupe(u8, s.columnText(1)), .basename = try a.dupe(u8, s.columnText(2)) },
        .stamp = try a.dupe(u8, s.columnText(3)),
        .pending = if (s.columnIsNull(4)) null else .{
            .location = .{ .folder = try a.dupe(u8, s.columnText(4)), .basename = try a.dupe(u8, s.columnText(5)) },
            .digest = try a.dupe(u8, s.columnText(6)),
        },
    };
}

pub fn lookup(a: Allocator, db: *database.Database, user: []const u8, id: []const u8) !?Entry {
    const s = try db.prepare(columns ++ " AND reference=?2");
    defer s.finalize();
    try s.bind(1, user);
    try s.bind(2, id);
    if (!try s.step()) return null;
    return try read(a, s);
}

pub const Placement = struct {
    original_folder: []const u8,
    reason: []const u8,
    verified_author: []const u8,
};

pub fn placement(a: Allocator, db: *database.Database, user: []const u8, id: []const u8) !?Placement {
    const s = try db.prepare("SELECT intake_folder,placement_reason,verified_author FROM mailbox_message_refs WHERE " ++ owner ++ " AND reference=?2 AND intake_folder<>''");
    defer s.finalize();
    try s.bind(1, user);
    try s.bind(2, id);
    if (!try s.step()) return null;
    return .{
        .original_folder = try a.dupe(u8, s.columnText(0)),
        .reason = try a.dupe(u8, s.columnText(1)),
        .verified_author = try a.dupe(u8, s.columnText(2)),
    };
}

pub fn pendingAt(a: Allocator, db: *database.Database, user: []const u8, target: Location) !?Entry {
    const s = try db.prepare(columns ++ " AND next_folder=?2 AND next_basename=?3");
    defer s.finalize();
    try s.bind(1, user);
    try s.bind(2, target.folder);
    try s.bind(3, target.basename);
    if (!try s.step()) return null;
    return try read(a, s);
}

fn stillAtSource(a: Allocator, user: []const u8, entry: Entry) !bool {
    const directories: []const []const u8 = if (std.mem.eql(u8, entry.location.folder, "INBOX")) &.{ "new", "cur" } else &.{entry.location.folder};
    for (directories) |folder| {
        const dir = try std.fmt.allocPrint(a, "mail/{s}/{s}", .{ user, folder });
        const files = fs.listEmlFiles(a, dir) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        for (files) |name| {
            if (!std.mem.eql(u8, entry.location.basename, database.maildirBaseName(name))) continue;
            const path = try std.fmt.allocPrint(a, "{s}/{s}", .{ dir, name });
            const stamp = fileStamp(a, path) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => return err,
            };
            if (std.mem.eql(u8, entry.stamp, stamp)) return true;
        }
    }
    return false;
}

pub fn recoverAt(a: Allocator, db: *database.Database, user: []const u8, at: Location, stamp: []const u8, checksum: []const u8) !?[]const u8 {
    const entry = (try pendingAt(a, db, user, at)) orelse return null;
    if (!std.mem.eql(u8, checksum, entry.pending.?.digest) or try stillAtSource(a, user, entry)) return null;
    try finish(db, user, entry.id, at, stamp);
    return entry.id;
}

pub fn issue(a: Allocator, db: *database.Database, user: []const u8, target: Location, stamp: []const u8) ![]const u8 {
    {
        const s = try db.prepare("SELECT reference FROM mailbox_message_refs WHERE " ++ owner ++ " AND folder=?2 AND basename=?3 AND file_stamp=?4");
        defer s.finalize();
        try s.bind(1, user);
        try s.bind(2, target.folder);
        try s.bind(3, target.basename);
        try s.bind(4, stamp);
        if (try s.step()) return try a.dupe(u8, s.columnText(0));
    }
    var bytes: [16]u8 = undefined;
    io.randomBytes(&bytes);
    const id = try a.dupe(u8, &std.fmt.bytesToHex(bytes, .lower));
    const s = try db.prepare(
        \\INSERT INTO mailbox_message_refs(user_id,reference,folder,basename,file_stamp)
        \\SELECT id,?5,?2,?3,?4 FROM users WHERE username=?1
        \\ON CONFLICT(user_id,folder,basename) DO UPDATE SET reference=excluded.reference,
        \\file_stamp=excluded.file_stamp,next_folder=NULL,next_basename=NULL,next_digest=NULL,
        \\next_junk_action=NULL,next_junk_receipt=NULL,
        \\intake_folder='',placement_reason='',verified_author=''
        \\RETURNING reference
    );
    defer s.finalize();
    try s.bind(1, user);
    try s.bind(2, target.folder);
    try s.bind(3, target.basename);
    try s.bind(4, stamp);
    try s.bind(5, id);
    if (!try s.step()) return error.NotFound;
    _ = try s.step();
    return id;
}

/// Record the destination before changing the filesystem. The caller can
/// finish immediately, or a later read can recover the handoff by its digest.
pub fn stage(a: Allocator, db: *database.Database, user: []const u8, source: Location, path: []const u8, target: Location, bytes: ?[]const u8) !?[]const u8 {
    return stageMove(a, db, user, source, path, target, bytes, null);
}

pub fn stageMove(a: Allocator, db: *database.Database, user: []const u8, source: Location, path: []const u8, target: Location, bytes: ?[]const u8, junk: ?JunkChange) !?[]const u8 {
    const stamp = try fileStamp(a, path);
    const registered: ?[]const u8 = blk: {
        const get = try db.prepare("SELECT reference,file_stamp FROM mailbox_message_refs WHERE " ++ owner ++ " AND folder=?2 AND basename=?3");
        defer get.finalize();
        try get.bind(1, user);
        try get.bind(2, source.folder);
        try get.bind(3, source.basename);
        if (!try get.step() or !std.mem.eql(u8, get.columnText(1), stamp)) break :blk null;
        break :blk try a.dupe(u8, get.columnText(0));
    };
    const id = registered orelse blk: {
        if (try pendingAt(a, db, user, source) == null) return null;
        const current_raw = try fs.readFileAlloc(a, path);
        break :blk (try recoverAt(a, db, user, source, stamp, &digest(current_raw))) orelse return null;
    };
    const raw = bytes orelse try fs.readFileAlloc(a, path);
    const checksum = digest(raw);
    const s = try db.prepare("UPDATE mailbox_message_refs SET next_folder=?3,next_basename=?4,next_digest=?5,next_junk_action=?6,next_junk_receipt=?7 WHERE " ++ owner ++ " AND reference=?2");
    defer s.finalize();
    try s.bind(1, user);
    try s.bind(2, id);
    try s.bind(3, target.folder);
    try s.bind(4, target.basename);
    try s.bind(5, @as([]const u8, &checksum));
    try s.bindOpt(6, if (junk) |change| @as(?[]const u8, @tagName(change.action)) else null);
    try s.bindOpt(7, if (junk) |change| change.receipt else null);
    _ = try s.step();
    return id;
}

pub fn finish(db: *database.Database, user: []const u8, id: []const u8, target: Location, stamp: []const u8) !void {
    const s = try db.prepare("UPDATE OR REPLACE mailbox_message_refs SET folder=?3,basename=?4,file_stamp=?5,next_folder=NULL,next_basename=NULL,next_digest=NULL,next_junk_action=NULL,next_junk_receipt=NULL WHERE " ++ owner ++ " AND reference=?2");
    defer s.finalize();
    try s.bind(1, user);
    try s.bind(2, id);
    try s.bind(3, target.folder);
    try s.bind(4, target.basename);
    try s.bind(5, stamp);
    _ = try s.step();
}

pub fn finishFile(a: Allocator, db: *database.Database, user: []const u8, id: []const u8, target: Location, path: []const u8) void {
    const stamp = fileStamp(a, path) catch |err| {
        std.log.warn("message reference could not stat its new file: {}", .{err});
        return;
    };
    defer a.free(stamp);
    finish(db, user, id, target, stamp) catch |err| std.log.warn("message reference handoff needs recovery: {}", .{err});
}

pub fn cancel(db: *database.Database, user: []const u8, id: []const u8) void {
    const s = db.prepare("UPDATE mailbox_message_refs SET next_folder=NULL,next_basename=NULL,next_digest=NULL,next_junk_action=NULL,next_junk_receipt=NULL WHERE " ++ owner ++ " AND reference=?2") catch return;
    defer s.finalize();
    s.bind(1, user) catch return;
    s.bind(2, id) catch return;
    _ = s.step() catch return;
}

pub fn forget(db: *database.Database, user: []const u8, source: Location) !void {
    const s = try db.prepare("DELETE FROM mailbox_message_refs WHERE " ++ owner ++ " AND folder=?2 AND basename=?3");
    defer s.finalize();
    try s.bind(1, user);
    try s.bind(2, source.folder);
    try s.bind(3, source.basename);
    _ = try s.step();
    try forgetReviewCopy(db, user, source);
}

/// A manual move or expunge takes the copy out of the review queue. A
/// journaled decision keeps its row until the placement is checkpointed.
pub fn forgetReviewCopy(db: *database.Database, user: []const u8, source: Location) !void {
    if (!std.mem.eql(u8, source.folder, "Screening") and !std.mem.eql(u8, source.folder, "Declined")) return;
    const stmt = try db.prepare("DELETE FROM sender_review_messages WHERE " ++ owner ++ " AND folder=?2 AND basename=?3 AND operation IS NULL");
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bind(2, source.folder);
    try stmt.bind(3, source.basename);
    _ = try stmt.step();
}

pub fn renameFolder(db: *database.Database, user: []const u8, source: []const u8, destination: []const u8) !void {
    const s = try db.prepare("UPDATE OR REPLACE mailbox_message_refs SET folder=CASE WHEN folder=?2 THEN ?3 ELSE folder END, next_folder=CASE WHEN next_folder=?2 THEN ?3 ELSE next_folder END WHERE " ++ owner ++ " AND (folder=?2 OR next_folder=?2)");
    defer s.finalize();
    try s.bind(1, user);
    try s.bind(2, source);
    try s.bind(3, destination);
    _ = try s.step();
    const feedback = try db.prepare("UPDATE mailbox_junk_feedback SET source_folder=?3 WHERE " ++ owner ++ " AND source_folder=?2");
    defer feedback.finalize();
    try feedback.bind(1, user);
    try feedback.bind(2, source);
    try feedback.bind(3, destination);
    _ = try feedback.step();
}
