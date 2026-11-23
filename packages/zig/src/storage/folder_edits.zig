//! Journal a whole-folder rename or removal across Maildir and SQLite.
const std = @import("std");
const database = @import("database.zig");
const folders = @import("maildir_folders.zig");
const refs = @import("message_refs.zig");
const paths = @import("../core/maildir_path.zig");
const durable = @import("../core/durable_maildir.zig");
const io_compat = @import("../core/io_compat.zig");
const time = @import("../core/time_compat.zig");
const index = @import("../search/maildir_index.zig");

const Allocator = std.mem.Allocator;
const Database = database.Database;
const Dir = std.Io.Dir;

pub const Edit = struct {
    id: []const u8,
    root_name: []const u8,
    source: []const u8,
    destination: ?[]const u8,
    stamp: []const u8,
    layout: folders.Layout,
    committed: bool = false,

    pub fn init(a: Allocator, root: Dir, root_name: []const u8, source: []const u8, destination: ?[]const u8) !Edit {
        try paths.validate(root_name);
        if (destination) |name| try folders.validateName(name);
        const layout = (try folders.layout(io_compat.getIo(), root, source)) orelse return error.FileNotFound;
        const physical = try physicalName(a, source, layout);
        const path = try std.fmt.allocPrint(a, "mail/{s}/{s}", .{ root_name, physical });
        var nonce: [16]u8 = undefined;
        io_compat.randomBytes(&nonce);
        return .{
            .id = try a.dupe(u8, &std.fmt.bytesToHex(nonce, .lower)),
            .root_name = root_name,
            .source = source,
            .destination = destination,
            .stamp = try refs.directoryStamp(a, path),
            .layout = layout,
        };
    }

    /// Hold the mailbox mutation lock through stage, metadata commit and settle.
    pub fn stage(self: Edit, a: Allocator, db: *Database, root: Dir, user: []const u8) !void {
        try index.markFolderEditLocked(a, db, user, !std.mem.eql(u8, user, self.root_name), root, self.layout, self.source, self.destination);
        try self.record(db);
        errdefer self.finish(a, db, root);
        try self.apply(a, root);
    }

    fn record(self: Edit, db: *Database) !void {
        const stmt = try db.prepare("INSERT INTO eas_folder_edits(id,mailbox_root,source,destination,stamp,maildir_plus) VALUES(?1,?2,?3,?4,?5,?6)");
        defer stmt.finalize();
        try stmt.bind(1, self.id);
        try stmt.bind(2, self.root_name);
        try stmt.bind(3, self.source);
        try stmt.bindOpt(4, self.destination);
        try stmt.bind(5, self.stamp);
        try stmt.bind(6, @as(i64, @intFromBool(self.layout == .maildir_plus)));
        _ = try stmt.step();
    }

    fn apply(self: Edit, a: Allocator, root: Dir) !void {
        const io = io_compat.getIo();
        const location = try self.locations(a);
        if (self.destination) |name| {
            // A case-only rename can name the same directory on a Mac. The
            // actual publish below still refuses to replace any other object.
            try requireUnused(a, io, root, name, self.source);
        }
        try Dir.renamePreserve(root, location.source, root, location.staged, io);
        if (self.layout == .maildir_plus) try root.deleteFile(io, self.source);
        if (self.destination) |name| {
            try requireUnused(a, io, root, name, null);
            try Dir.renamePreserve(root, location.staged, root, location.destination.?, io);
            if (self.layout == .maildir_plus) try ensureAlias(a, io, root, name);
        }
        try durable.syncDirectory(a, location.root);
    }

    /// Commit the shared metadata and this journal checkpoint together with
    /// any protocol-specific state the caller adds to the transaction.
    pub fn applyMetadata(self: Edit, tx: Database.Transaction, user: []const u8) !void {
        const retired = self.destination orelse self.source;
        for ([_][]const u8{
            "DELETE FROM imap_uids WHERE username=?1 AND mailbox=?2",
            "DELETE FROM imap_mailboxes WHERE username=?1 AND mailbox=?2",
            "DELETE FROM mailbox_message_refs WHERE user_id=(SELECT id FROM users WHERE username=?1) AND folder=?2",
            "UPDATE mailbox_message_refs SET next_folder=NULL,next_basename=NULL,next_digest=NULL,next_junk_action=NULL,next_junk_receipt=NULL,next_retention_at=NULL WHERE user_id=(SELECT id FROM users WHERE username=?1) AND next_folder=?2",
        }) |sql| {
            const stmt = try tx.prepare(sql);
            defer stmt.finalize();
            try stmt.bind(1, user);
            try stmt.bind(2, retired);
            _ = try stmt.step();
        }
        if (self.destination) |destination| {
            const source = try tx.prepare(
                \\INSERT INTO imap_mailboxes(username,mailbox,uidvalidity,uidnext)
                \\VALUES(?1,?2,MAX(?3,COALESCE((SELECT uidvalidity+1 FROM imap_mailbox_generations WHERE username=?1 AND mailbox=?2),0)),
                \\       (SELECT COALESCE(MAX(uid),0)+1 FROM imap_uids WHERE username=?1 AND mailbox=?2))
                \\ON CONFLICT(username,mailbox) DO NOTHING
            );
            defer source.finalize();
            try source.bind(1, user);
            try source.bind(2, self.source);
            try source.bind(3, time.timestamp());
            _ = try source.step();
            for ([_][]const u8{
                \\UPDATE imap_mailboxes SET mailbox=?3,uidvalidity=MAX(uidvalidity,COALESCE((SELECT uidvalidity+1 FROM imap_mailbox_generations WHERE username=?1 AND mailbox=?3),0))
                \\WHERE username=?1 AND mailbox=?2
                ,
                "UPDATE imap_uids SET mailbox=?3 WHERE username=?1 AND mailbox=?2",
            }) |sql| {
                const stmt = try tx.prepare(sql);
                defer stmt.finalize();
                try stmt.bind(1, user);
                try stmt.bind(2, self.source);
                try stmt.bind(3, destination);
                _ = try stmt.step();
            }
            try refs.renameFolderIn(tx, user, self.source, destination);
        }
        const checkpoint = try tx.prepare("UPDATE eas_folder_edits SET committed=1 WHERE id=?1 AND committed=0 RETURNING 1");
        defer checkpoint.finalize();
        try checkpoint.bind(1, self.id);
        if (!try checkpoint.step()) return error.FolderEditConflict;
        _ = try checkpoint.step();
    }

    pub fn finish(self: Edit, a: Allocator, db: *Database, root: Dir) void {
        self.settle(a, db, root) catch |err| std.log.warn("could not settle mailbox folder edit: {}", .{err});
    }

    /// A committed delete can be purged. Before commit, restore the original
    /// directory and alias, including after an interrupted case-only rename.
    fn settle(self: Edit, a: Allocator, db: *Database, root: Dir) !void {
        const io = io_compat.getIo();
        const location = try self.locations(a);
        if (self.committed) {
            if (self.destination == null and try matches(a, io, root, location.root, location.staged, self.stamp)) {
                try root.deleteTree(io, location.staged);
                try durable.syncDirectory(a, location.root);
            }
        } else {
            if (!try matches(a, io, root, location.root, location.source, self.stamp)) {
                if (!try matches(a, io, root, location.root, location.staged, self.stamp)) {
                    const destination = location.destination orelse return error.FolderEditConflict;
                    if (!try matches(a, io, root, location.root, destination, self.stamp)) return error.FolderEditConflict;
                    if (self.layout == .maildir_plus) try removeAlias(a, io, root, self.destination.?);
                    try Dir.renamePreserve(root, destination, root, location.staged, io);
                }
                try Dir.renamePreserve(root, location.staged, root, location.source, io);
            }
            if (self.layout == .maildir_plus) try ensureAlias(a, io, root, self.source);
            try durable.syncDirectory(a, location.root);
        }
        try self.forget(db);
    }

    fn forget(self: Edit, db: *Database) !void {
        const stmt = try db.prepare("DELETE FROM eas_folder_edits WHERE id=?1");
        defer stmt.finalize();
        try stmt.bind(1, self.id);
        _ = try stmt.step();
    }

    const Locations = struct { root: []const u8, source: []const u8, staged: []const u8, destination: ?[]const u8 };

    fn locations(self: Edit, a: Allocator) !Locations {
        try paths.validate(self.root_name);
        try paths.validate(self.id);
        try folders.validateName(self.source);
        if (self.destination) |name| try folders.validateName(name);
        return .{
            .root = try std.fmt.allocPrint(a, "mail/{s}", .{self.root_name}),
            .source = try physicalName(a, self.source, self.layout),
            .staged = try std.fmt.allocPrint(a, ".pending-folder-{s}", .{self.id}),
            .destination = if (self.destination) |name| try physicalName(a, name, self.layout) else null,
        };
    }
};

pub fn physicalName(a: Allocator, name: []const u8, layout: folders.Layout) ![]const u8 {
    return if (layout == .maildir_plus) try std.fmt.allocPrint(a, ".{s}", .{name}) else name;
}

pub fn requireUnused(a: Allocator, io: std.Io, root: Dir, name: []const u8, except: ?[]const u8) !void {
    for ([_]folders.Layout{ .flat, .maildir_plus }) |layout| {
        if (layout == .maildir_plus and name.len == 255) continue;
        const candidate = try physicalName(a, name, layout);
        const found = root.statFile(io, candidate, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        if (except) |source| {
            const original = try physicalName(a, source, layout);
            if (root.statFile(io, original, .{ .follow_symlinks = false })) |stat| {
                if (stat.inode == found.inode) continue;
            } else |err| if (err != error.FileNotFound) return err;
        }
        return error.PathAlreadyExists;
    }
}

fn matches(a: Allocator, io: std.Io, root: Dir, path: []const u8, name: []const u8, stamp: []const u8) !bool {
    // Exact spelling distinguishes the before and after names on a volume
    // that resolves either spelling to the same inode.
    var entries = root.iterate();
    while (try entries.next(io)) |entry| {
        if (!std.mem.eql(u8, entry.name, name)) continue;
        if (entry.kind != .directory) return false;
        const candidate = try std.fmt.allocPrint(a, "{s}/{s}", .{ path, name });
        return std.mem.eql(u8, stamp, try refs.directoryStamp(a, candidate));
    }
    return false;
}

fn ensureAlias(a: Allocator, io: std.Io, root: Dir, name: []const u8) !void {
    const expected = try std.fmt.allocPrint(a, ".{s}/cur", .{name});
    root.symLink(io, expected, name, .{ .is_directory = true }) catch |err| switch (err) {
        error.PathAlreadyExists => {
            var target: [512]u8 = undefined;
            const length = try root.readLink(io, name, &target);
            if (!std.mem.eql(u8, expected, target[0..length])) return error.FolderEditConflict;
        },
        else => return err,
    };
}

fn removeAlias(a: Allocator, io: std.Io, root: Dir, name: []const u8) !void {
    var target: [512]u8 = undefined;
    const length = root.readLink(io, name, &target) catch |err| switch (err) {
        error.FileNotFound, error.NotLink => return,
        else => return err,
    };
    if (std.mem.eql(u8, try std.fmt.allocPrint(a, ".{s}/cur", .{name}), target[0..length])) try root.deleteFile(io, name);
}

/// Restore unfinished edits before listeners start, and retry cleanup for any
/// committed deletion that could not remove its staged directory immediately.
pub fn recover(allocator: Allocator, db: *Database) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    db.lockMailboxes();
    defer db.unlockMailboxes();
    var edits: std.ArrayList(Edit) = .empty;
    {
        const stmt = try db.prepare("SELECT id,mailbox_root,source,destination,stamp,maildir_plus,committed FROM eas_folder_edits ORDER BY id");
        defer stmt.finalize();
        while (try stmt.step()) {
            try edits.append(a, .{
                .id = try a.dupe(u8, stmt.columnText(0)),
                .root_name = try a.dupe(u8, stmt.columnText(1)),
                .source = try a.dupe(u8, stmt.columnText(2)),
                .destination = if (stmt.columnTextOpt(3)) |value| try a.dupe(u8, value) else null,
                .stamp = try a.dupe(u8, stmt.columnText(4)),
                .layout = if (stmt.columnInt64(5) == 1) .maildir_plus else .flat,
                .committed = stmt.columnInt64(6) == 1,
            });
        }
    }
    const io = io_compat.getIo();
    for (edits.items) |edit| {
        const location = try edit.locations(a);
        const root = (try folders.open(io, .cwd(), location.root)) orelse {
            if (!edit.committed) return error.FolderEditConflict;
            try edit.forget(db);
            continue;
        };
        defer root.close(io);
        try edit.settle(a, db, root);
    }
}
