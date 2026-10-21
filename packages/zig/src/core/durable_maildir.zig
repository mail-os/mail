//! Publish complete, synced Maildir messages before SMTP acknowledges delivery.
//! A hard link publishes without replacing an existing message. Failures after
//! publication preserve the message; the sender can retry rather than lose it.
const std = @import("std");
const fs = @import("fs_compat.zig");
extern "c" fn fsync(fd: std.c.fd_t) c_int;
extern "c" fn link(old: [*:0]const u8, new: [*:0]const u8) c_int;
extern "c" fn mkdtemp(template: [*:0]u8) ?[*:0]u8;

fn syncFd(fd: std.c.fd_t) !void {
    while (fsync(fd) != 0) {
        const err: std.c.E = @fromBackingInt(@intCast(std.c._errno().*));
        if (err != .INTR) return error.MaildirSyncFailed;
    }
}

fn syncDir(allocator: std.mem.Allocator, path: []const u8) !void {
    const z = try allocator.dupeSentinel(u8, path, 0);
    defer allocator.free(z);
    const fd = std.c.open(z, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, @as(std.c.mode_t, 0));
    if (fd < 0) return error.MaildirSyncFailed;
    defer _ = std.c.close(fd);
    try syncFd(fd);
}

pub fn write(allocator: std.mem.Allocator, path: []const u8, data: []const u8) !void {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return error.InvalidMaildirPath;
    const directory = path[0..slash];
    const temporary = try std.fmt.allocPrint(allocator, "{s}/.pending-{s}", .{ directory, path[slash + 1 ..] });
    defer allocator.free(temporary);
    const file = try fs.cwd().createFileExclusive(temporary);
    defer file.close();
    defer fs.cwd().deleteFile(temporary) catch {};
    try file.writeAll(data);
    try syncFd(file.handle);
    const src = try allocator.dupeSentinel(u8, temporary, 0);
    defer allocator.free(src);
    const dst = try allocator.dupeSentinel(u8, path, 0);
    defer allocator.free(dst);
    if (link(src, dst) != 0) return error.MaildirPublishFailed;
    // Sync the destination and its parent chain, including newly made mailboxes.
    var current = directory;
    while (current.len > 0) {
        try syncDir(allocator, current);
        const parent = std.mem.lastIndexOfScalar(u8, current, '/') orelse break;
        current = current[0..parent];
    }
    try syncDir(allocator, if (std.mem.startsWith(u8, path, "/")) "/" else ".");
}

test "durable publication preserves an existing message and cleans failed temporary writes" {
    const allocator = std.testing.allocator;
    var template = "/tmp/mail-durable-XXXXXX".*;
    const directory_z = mkdtemp(&template) orelse return error.TemporaryDirectoryFailed;
    defer _ = std.c.rmdir(directory_z);
    const directory = std.mem.span(directory_z);
    const path = try std.fmt.allocPrint(allocator, "{s}/message.eml", .{directory});
    defer allocator.free(path);
    defer fs.cwd().deleteFile(path) catch {};
    try write(allocator, path, "original message");
    try std.testing.expectError(error.MaildirPublishFailed, write(allocator, path, "replacement"));
    const contents = try fs.readFileAlloc(allocator, path);
    defer allocator.free(contents);
    try std.testing.expectEqualStrings("original message", contents);
    const temporary = try std.fmt.allocPrint(allocator, "{s}/.pending-message.eml", .{directory});
    defer allocator.free(temporary);
    try std.testing.expectError(error.FileNotFound, fs.cwd().access(temporary, .{}));
    try std.testing.expectError(error.SystemResources, write(allocator, "/does-not-exist-stacks-mail/new/message.eml", "unaccepted"));
}
