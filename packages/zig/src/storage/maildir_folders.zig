//! Resolve visible Maildir folders without following arbitrary symlinks.
const std = @import("std");
const Dir = std.Io.Dir;

pub const Layout = enum { flat, maildir_plus };

/// IMAP accepts flat folder names, including names outside webmail's narrower
/// display rules. Alias resolution still requires a single safe component.
pub fn validateName(name: []const u8) !void {
    if (name.len == 0 or name.len > 255 or name[0] == '.' or
        std.mem.indexOfAny(u8, name, "/\\\x00") != null or std.mem.indexOf(u8, name, "..") != null)
        return error.InvalidMailboxPath;
}

/// Recover the on-disk spelling for an IMAP name on case-insensitive volumes.
pub fn storedName(a: std.mem.Allocator, io: std.Io, root: Dir, name: []const u8) ![]const u8 {
    try validateName(name);
    const stat = try root.statFile(io, name, .{ .follow_symlinks = false });
    var alternate: ?[]const u8 = null;
    var entries = root.iterate();
    while (try entries.next(io)) |entry| {
        if (std.mem.eql(u8, entry.name, name)) return name;
        if (entry.inode != stat.inode or entry.kind != stat.kind) continue;
        validateName(entry.name) catch continue;
        alternate = try a.dupe(u8, entry.name);
    }
    return alternate orelse error.FileNotFound;
}

pub fn open(io: std.Io, parent: Dir, path: []const u8) !?Dir {
    return parent.openDir(io, path, .{ .iterate = true, .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir, error.SymLinkLoop => null,
        else => return err,
    };
}

/// The operator can link the entire spool to a managed volume. Account and
/// folder directories below this anchor still use open() without following links.
pub fn openRoot(io: std.Io) !?Dir {
    return Dir.cwd().openDir(io, "mail", .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => null,
        else => return err,
    };
}

pub fn layout(io: std.Io, root: Dir, name: []const u8) !?Layout {
    try validateName(name);
    const info = root.statFile(io, name, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    if (info.kind == .directory) return .flat;
    if (info.kind != .sym_link or name.len >= 255) return null;

    var target_buffer: [512]u8 = undefined;
    const target = root.readLink(io, name, &target_buffer) catch |err| switch (err) {
        error.FileNotFound, error.NotLink => return null,
        else => return err,
    };
    var canonical_buffer: [256]u8 = undefined;
    const canonical = try std.fmt.bufPrint(&canonical_buffer, ".{s}", .{name});
    var expected_buffer: [260]u8 = undefined;
    const expected = try std.fmt.bufPrint(&expected_buffer, "{s}/cur", .{canonical});
    if (!std.mem.eql(u8, target_buffer[0..target], expected)) return null;

    const container = (try open(io, root, canonical)) orelse return null;
    defer container.close(io);
    const cur = (try open(io, container, "cur")) orelse return null;
    cur.close(io);
    return .maildir_plus;
}
