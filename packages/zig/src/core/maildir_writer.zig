//! Hold writer locks on the Maildir and canonical SMTP database path.
const std = @import("std");
const fs = @import("fs_compat.zig");
const io_compat = @import("io_compat.zig");

extern "c" fn flock(fd: std.c.fd_t, operation: c_int) c_int;

pub fn lock(fd: std.c.fd_t) !void {
    while (true) {
        switch (std.posix.errno(flock(fd, std.posix.LOCK.EX | std.posix.LOCK.NB))) {
            .SUCCESS => return,
            .INTR => continue,
            .AGAIN => return error.MaildirWriterActive,
            else => return error.MaildirWriterLockFailed,
        }
    }
}

/// Keep the Maildir's inode locked until every listener and worker has stopped.
pub fn openForDaemon() !std.c.fd_t {
    switch (std.posix.errno(std.c.mkdir("mail", 0o755))) {
        .SUCCESS, .EXIST => {},
        else => return error.MaildirWriterDirectoryUnavailable,
    }
    const fd = std.c.open("mail", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true });
    if (fd < 0) return error.MaildirWriterDirectoryUnavailable;
    errdefer _ = std.c.close(fd);
    try lock(fd);
    return fd;
}

pub fn openDatabaseForDaemon(allocator: std.mem.Allocator, path: []const u8) !?std.c.fd_t {
    // SQLite uses private state for these special filenames.
    if (path.len == 0 or std.mem.eql(u8, path, ":memory:")) return null;
    const path_z = try allocator.dupeSentinel(u8, path, 0);
    defer allocator.free(path_z);

    const database_fd = std.c.open(path_z.ptr, .{ .ACCMODE = .RDWR, .CREAT = true, .CLOEXEC = true }, @as(std.c.mode_t, 0o644));
    if (database_fd < 0) return error.DatabaseWriterFileUnavailable;
    defer _ = std.c.close(database_fd);
    const io = io_compat.getIo();
    const database_file: std.Io.File = .{ .handle = database_fd, .flags = .{ .nonblocking = false } };
    const database_stat = database_file.stat(io) catch return error.DatabaseWriterFileUnavailable;
    if (database_stat.kind != .file) return error.DatabaseWriterFileUnavailable;
    // SQLite WAL sidecars cannot be shared safely through hard-link aliases.
    if (database_stat.nlink != 1) return error.DatabaseWriterPathNotUnique;

    const resolved = fs.cwd().realpathAlloc(allocator, path) catch return error.DatabaseWriterFileUnavailable;
    defer allocator.free(resolved);
    const lock_path = try std.fmt.allocPrintSentinel(allocator, "{s}.mail-writer.lock", .{resolved}, 0);
    defer allocator.free(lock_path);

    // Lock a separate file so SQLite can use the database's own locking protocol.
    const fd = std.c.open(lock_path.ptr, .{ .ACCMODE = .RDONLY, .CREAT = true, .CLOEXEC = true, .NOFOLLOW = true }, @as(std.c.mode_t, 0o644));
    if (fd < 0) return error.DatabaseWriterLockFailed;
    errdefer _ = std.c.close(fd);
    const lock_file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
    const lock_stat = lock_file.stat(io) catch return error.DatabaseWriterLockFailed;
    if (lock_stat.kind != .file or lock_stat.nlink != 1)
        return error.DatabaseWriterLockFailed;
    lock(fd) catch |err| switch (err) {
        error.MaildirWriterActive => return error.DatabaseWriterActive,
        else => return error.DatabaseWriterLockFailed,
    };
    return fd;
}
