//! Hold one writer lock on the inode of the configured Maildir.
const std = @import("std");

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
