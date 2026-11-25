//! Durable reconciliation of Typesense documents after local Maildir writes.
const std = @import("std");
const database = @import("../storage/database.zig");
const message_refs = @import("../storage/message_refs.zig");
const folders = @import("../storage/maildir_folders.zig");
const io_compat = @import("../core/io_compat.zig");
const path_rules = @import("../core/maildir_path.zig");
const typesense = @import("typesense.zig");

const Allocator = std.mem.Allocator;
const Database = database.Database;
const Dir = std.Io.Dir;

/// The caller holds the mailbox mutation lock and records every affected
/// location before writing. A failed or interrupted move is reconciled from
/// the same filesystem as a completed move.
pub fn markLocked(db: *Database, user: []const u8, short_root: bool, locations: []const message_refs.Location) !void {
    if (!typesense.enabled() or locations.len == 0) return;
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const stmt = try tx.prepare(
        \\INSERT OR REPLACE INTO mail_search_pending(user_id,folder,basename,short_root)
        \\SELECT id,?2,?3,?4 FROM users WHERE username=?1
    );
    defer stmt.finalize();
    for (locations) |location| {
        try stmt.reset();
        try stmt.bind(1, user);
        try stmt.bind(2, location.folder);
        try stmt.bind(3, location.basename);
        try stmt.bind(4, @as(i64, @intFromBool(short_root)));
        _ = try stmt.step();
    }
    try tx.commit();
}

pub fn markFolderEditLocked(a: Allocator, db: *Database, user: []const u8, short_root: bool, root: Dir, layout: folders.Layout, source: []const u8, destination: ?[]const u8) !void {
    if (!typesense.enabled()) return;
    const io = io_compat.getIo();
    const physical = if (layout == .maildir_plus) try std.fmt.allocPrint(a, ".{s}", .{source}) else source;
    const folder = (try folders.open(io, root, physical)) orelse return error.FileNotFound;
    defer folder.close(io);
    var locations: std.ArrayList(message_refs.Location) = .empty;
    if (layout == .flat) try markDirectory(a, io, folder, source, destination, &locations);
    for ([_][]const u8{ "cur", "new" }) |slot| {
        const dir = (try folders.open(io, folder, slot)) orelse continue;
        defer dir.close(io);
        try markDirectory(a, io, dir, source, destination, &locations);
    }
    try markLocked(db, user, short_root, locations.items);
}

fn markDirectory(a: Allocator, io: std.Io, dir: Dir, source: []const u8, destination: ?[]const u8, locations: *std.ArrayList(message_refs.Location)) !void {
    var entries = dir.iterate();
    while (try entries.next(io)) |entry| {
        if (entry.kind != .file) continue;
        const base = database.maildirBaseName(entry.name);
        if (!std.mem.endsWith(u8, base, ".eml")) continue;
        const basename = try a.dupe(u8, base);
        try locations.append(a, .{ .folder = source, .basename = basename });
        if (destination) |name| try locations.append(a, .{ .folder = name, .basename = basename });
    }
}

/// Queue a live rebuild. Only the delivery-effects worker publishes documents,
/// so rebuild work and ordinary mailbox mutations share the same checkpoints.
pub fn queueReindex(allocator: Allocator, db: *Database) !usize {
    if (!typesense.enabled()) return error.Disabled;
    const io = io_compat.getIo();
    const mail = (try folders.openRoot(io)) orelse return error.FileNotFound;
    defer mail.close(io);
    const users = try db.getAllUsers();
    defer {
        for (users) |*user| user.deinit(db.allocator);
        db.allocator.free(users);
    }
    var queued: usize = 0;
    for (users) |user| {
        try path_rules.validate(user.username);
        const root = (try folders.open(io, mail, user.username)) orelse continue;
        defer root.close(io);
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var inbox: std.ArrayList(message_refs.Location) = .empty;
        for ([_][]const u8{ "new", "cur" }) |slot| {
            const dir = (try folders.open(io, root, slot)) orelse continue;
            defer dir.close(io);
            try markDirectory(a, io, dir, "INBOX", null, &inbox);
        }
        try markLocked(db, user.username, false, inbox.items);
        var entries = root.iterate();
        while (try entries.next(io)) |entry| {
            const name = entry.name;
            if (std.ascii.eqlIgnoreCase(name, "INBOX") or std.mem.eql(u8, name, "new") or
                std.mem.eql(u8, name, "cur") or std.mem.eql(u8, name, "tmp")) continue;
            folders.validateName(name) catch continue;
            const layout = (try folders.layout(io, root, name)) orelse continue;
            var folder_arena = std.heap.ArenaAllocator.init(allocator);
            defer folder_arena.deinit();
            // Another writer can rename the folder between layout and open.
            // That writer already queues the affected message locations.
            markFolderEditLocked(folder_arena.allocator(), db, user.username, false, root, layout, name, null) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => return err,
            };
        }
        queued += 1;
    }
    return queued;
}

/// A pending write bypasses the external index in the affected search scope.
/// The scope's revision detects a write that starts and finishes during a query.
pub fn searchEpoch(db: *Database, user: []const u8, mailbox: ?[]const u8) !?i64 {
    const stmt = try db.prepare(
        \\WITH owner(id) AS (SELECT id FROM users WHERE username=?1)
        \\SELECT CASE WHEN EXISTS (
        \\  SELECT 1 FROM mail_search_pending WHERE user_id=(SELECT id FROM owner) AND (?2 IS NULL OR folder=?2)
        \\) THEN NULL ELSE COALESCE((
        \\  SELECT MAX(revision) FROM mail_search_checkpoints WHERE user_id=(SELECT id FROM owner) AND (?2 IS NULL OR folder=?2)
        \\),0) END
    );
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bindOpt(2, mailbox);
    if (!try stmt.step()) return null;
    return stmt.columnInt64Opt(0);
}

const Pending = struct {
    id: i64,
    user: []const u8,
    folder: []const u8,
    basename: []const u8,
    short_root: bool,
};

fn next(a: Allocator, db: *Database, now: i64) !?Pending {
    const stmt = try db.prepare(
        \\SELECT p.id,u.username,p.folder,p.basename,p.short_root FROM mail_search_pending p
        \\JOIN users u ON u.id=p.user_id WHERE p.retry_at<=?1 ORDER BY p.id LIMIT 1
    );
    defer stmt.finalize();
    try stmt.bind(1, now);
    if (!try stmt.step()) return null;
    return .{
        .id = stmt.columnInt64(0),
        .user = try a.dupe(u8, stmt.columnText(1)),
        .folder = try a.dupe(u8, stmt.columnText(2)),
        .basename = try a.dupe(u8, stmt.columnText(3)),
        .short_root = stmt.columnInt64(4) != 0,
    };
}

/// Called by the single delivery-effects worker. The network operation runs
/// without the mailbox lock. A concurrent write replaces the row with a new
/// ID, so an older result cannot checkpoint that newer write.
pub fn reconcileOne(a: Allocator, db: *Database, now: i64) !bool {
    const row = (try next(a, db, now)) orelse return false;
    reconcile(a, db, row) catch |err| {
        const retry = try db.prepare("UPDATE mail_search_pending SET retry_at=?2 WHERE id=?1");
        defer retry.finalize();
        try retry.bind(1, row.id);
        try retry.bind(2, now + 5);
        _ = try retry.step();
        return err;
    };
    const done = try db.prepare("DELETE FROM mail_search_pending WHERE id=?1");
    defer done.finalize();
    try done.bind(1, row.id);
    _ = try done.step();
    return true;
}

fn reconcile(a: Allocator, db: *Database, row: Pending) !void {
    if (try snapshot(a, db, row)) |raw| {
        try typesense.indexRawMessage(a, row.user, row.folder, row.basename, raw);
    } else {
        try typesense.deleteIndexedMessage(a, row.user, row.folder, row.basename);
    }
}

fn snapshot(a: Allocator, db: *Database, row: Pending) !?[]const u8 {
    db.lockMailboxes();
    defer db.unlockMailboxes();
    const root = if (row.short_root) blk: {
        const short = row.user[0 .. std.mem.indexOfScalar(u8, row.user, '@') orelse row.user.len];
        if (try db.userExists(short)) return null;
        const owner = (try db.uniqueUsernameForLocalPart(short, a)) orelse return null;
        if (!std.mem.eql(u8, owner, row.user)) return null;
        break :blk short;
    } else row.user;
    try path_rules.validate(root);
    try folders.validateName(row.folder);
    if (row.basename.len == 0 or std.mem.indexOfAny(u8, row.basename, "/\x00") != null or
        std.mem.eql(u8, row.basename, ".") or std.mem.eql(u8, row.basename, "..")) return error.InvalidMaildirPath;
    const io = io_compat.getIo();
    const mail = (try folders.openRoot(io)) orelse return null;
    defer mail.close(io);
    const mailbox = (try folders.open(io, mail, root)) orelse return null;
    defer mailbox.close(io);
    if (std.mem.eql(u8, row.folder, "INBOX")) return readSlots(a, io, mailbox, row.basename);
    const layout = (try folders.layout(io, mailbox, row.folder)) orelse return null;
    const name = if (layout == .maildir_plus) try std.fmt.allocPrint(a, ".{s}", .{row.folder}) else row.folder;
    const folder = (try folders.open(io, mailbox, name)) orelse return null;
    defer folder.close(io);
    if (layout == .maildir_plus) return readSlots(a, io, folder, row.basename);
    return (try readMessage(a, io, folder, row.basename)) orelse try readSlots(a, io, folder, row.basename);
}

fn readSlots(a: Allocator, io: std.Io, folder: Dir, basename: []const u8) !?[]const u8 {
    for ([_][]const u8{ "new", "cur" }) |slot| {
        const dir = (try folders.open(io, folder, slot)) orelse continue;
        defer dir.close(io);
        if (try readMessage(a, io, dir, basename)) |raw| return raw;
    }
    return null;
}

fn readMessage(a: Allocator, io: std.Io, dir: Dir, basename: []const u8) !?[]const u8 {
    if (try readFile(a, io, dir, basename)) |raw| return raw;
    var entries = dir.iterate();
    while (try entries.next(io)) |entry| {
        if (entry.kind != .file or !std.mem.eql(u8, database.maildirBaseName(entry.name), basename)) continue;
        if (try readFile(a, io, dir, entry.name)) |raw| return raw;
    }
    return null;
}

fn readFile(a: Allocator, io: std.Io, dir: Dir, name: []const u8) !?[]const u8 {
    const before = dir.statFile(io, name, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    if (before.kind != .file) return null;
    const file = dir.openFile(io, name, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close(io);
    const stat = try file.stat(io);
    if (stat.kind != .file) return error.MaildirChangedDuringIndex;
    const raw = try a.alloc(u8, @intCast(@min(stat.size, 256 * 1024)));
    var read_buffer: [4096]u8 = undefined;
    var reader = file.reader(io, &read_buffer);
    return raw[0..try reader.interface.readSliceShort(raw)];
}
