//! Journal a whole-folder rename or removal across Maildir and SQLite.
const std = @import("std");
const database = @import("database.zig");
const folders = @import("maildir_folders.zig");
const refs = @import("message_refs.zig");
const paths = @import("../core/maildir_path.zig");
const durable = @import("../core/durable_maildir.zig");
const io_compat = @import("../core/io_compat.zig");

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

    /// Call with the mailbox mutation lock held, before changing the filesystem.
    pub fn record(self: Edit, db: *Database) !void {
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

    pub fn apply(self: Edit, a: Allocator, root: Dir) !void {
        const io = io_compat.getIo();
        const location = try self.locations(a);
        if (self.destination) |name| {
            // A case-only rename can name the same directory on a Mac. The
            // actual publish below still refuses to replace any other object.
            if (!std.ascii.eqlIgnoreCase(name, self.source)) try requireUnused(a, io, root, name, null);
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

    /// A committed delete can be purged. Before commit, restore the original
    /// directory and alias, including after an interrupted case-only rename.
    pub fn settle(self: Edit, a: Allocator, db: *Database, root: Dir) !void {
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
        try paths.validate(self.source);
        if (self.destination) |name| try paths.validate(name);
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
