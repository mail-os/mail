//! Resolve visible Maildir folders without following arbitrary symlinks.
const std = @import("std");
const path_rules = @import("../core/maildir_path.zig");
const Dir = std.Io.Dir;

pub const Layout = enum { flat, maildir_plus };

pub fn open(io: std.Io, parent: Dir, path: []const u8) !?Dir {
    return parent.openDir(io, path, .{ .iterate = true, .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => null,
        else => return err,
    };
}

pub fn layout(io: std.Io, root: Dir, name: []const u8) !?Layout {
    try path_rules.validate(name);
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
