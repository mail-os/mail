//! Enforcement at the shared hosted Maildir write boundary.
const std = @import("std");
const builtin = @import("builtin");
const db_mod = @import("database.zig");
const fs = @import("../core/fs_compat.zig");
const maildir_path = @import("../core/maildir_path.zig");
const durable_maildir = @import("../core/durable_maildir.zig");
const time = @import("../core/time_compat.zig");

const StorageReservations = struct {
    pending_delivery_bytes: u64,
    linked_file_bytes: u64,
};

fn storageReservations(db: *db_mod.Database, mailbox: []const u8, now: i64) !StorageReservations {
    return .{
        .pending_delivery_bytes = try db.reservedDeliveryBytes(mailbox),
        .linked_file_bytes = try db.linkedFileBytes(mailbox, now),
    };
}

fn mailboxRoot(mailbox: []const u8, buffer: []u8) ![:0]u8 {
    try maildir_path.validate(mailbox);
    return std.fmt.bufPrintSentinel(buffer, "mail/{s}", .{mailbox}, 0);
}

pub const ObservedStorage = struct {
    maildir_bytes: u64,
    pending_delivery_bytes: u64,
    linked_file_bytes: u64,
    remaining_bytes: u64,
};

/// A host-local observation using the same byte accounting as admission.
pub fn observeStorage(db: *db_mod.Database, mailbox: []const u8, quota: u64, now: i64) !ObservedStorage {
    var buffer: [4096]u8 = undefined;
    const root = try mailboxRoot(mailbox, &buffer);
    const stored = try countBytes(root, std.math.maxInt(u64), 0);
    const reserved = try storageReservations(db, mailbox, now);
    return .{
        .maildir_bytes = stored,
        .pending_delivery_bytes = reserved.pending_delivery_bytes,
        .linked_file_bytes = reserved.linked_file_bytes,
        .remaining_bytes = quota -| stored -| reserved.pending_delivery_bytes -| reserved.linked_file_bytes,
    };
}

/// Call with the mailbox mutation lock held. Credit is the size of a file
/// replaced in place, so saving a smaller draft works even at the limit.
pub fn checkStorage(db: *db_mod.Database, user: []const u8, bytes: u64, replaced: ?[]const u8) !void {
    const limits = (try db.hostedLimits(user)) orelse return;
    const now = time.timestamp();
    switch (limits.accessAt(now)) {
        .full => {},
        .disabled => return error.HostedRecipientDisabled,
        .read_only => return error.HostedRecipientReadOnly,
        .expired => return error.HostedRecipientExpired,
    }
    var root_buf: [4096]u8 = undefined;
    const root = try mailboxRoot(user, &root_buf);
    const credit = if (replaced) |path| try fs.getFileSize(path) else 0;
    if (bytes <= credit) return;
    const reserved = try storageReservations(db, user, now);
    const committed = std.math.add(u64, reserved.pending_delivery_bytes, reserved.linked_file_bytes) catch return error.HostedStorageFull;
    const growth = std.math.add(u64, bytes - credit, committed) catch return error.HostedStorageFull;
    if (growth > limits.quota_bytes) return error.HostedStorageFull;
    _ = try countBytes(root, limits.quota_bytes - growth, 0);
}

const EntryStat = struct { mode: u32, size: u64 };

fn statNoFollow(path: [:0]const u8) !?EntryStat {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var stat = std.mem.zeroes(linux.Statx);
        const result = linux.statx(linux.AT.FDCWD, path, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true, .SIZE = true }, &stat);
        return switch (linux.errno(result)) {
            .SUCCESS => if (stat.mask.TYPE and stat.mask.SIZE) .{ .mode = stat.mode, .size = stat.size } else error.MaildirUsageUnavailable,
            .NOENT => null,
            else => error.MaildirUsageUnavailable,
        };
    }
    var stat: std.c.Stat = undefined;
    const result = std.c.fstatat(std.c.AT.FDCWD, path, &stat, std.c.AT.SYMLINK_NOFOLLOW);
    return switch (std.c.errno(result)) {
        .SUCCESS => .{ .mode = stat.mode, .size = @intCast(stat.size) },
        .NOENT => null,
        else => error.MaildirUsageUnavailable,
    };
}

fn countBytes(path: [:0]const u8, allowance: u64, depth: usize) !u64 {
    if (depth > 8) return error.MaildirUsageUnavailable;
    const root_stat = (try statNoFollow(path)) orelse return 0;
    if (!std.c.S.ISDIR(root_stat.mode)) return error.MaildirUsageUnavailable;
    const dir = std.c.opendir(path) orelse return error.MaildirUsageUnavailable;
    defer _ = std.c.closedir(dir);

    var remaining = allowance;
    while (true) {
        std.c._errno().* = 0;
        const entry = std.c.readdir(dir) orelse {
            if (std.c._errno().* != 0) return error.MaildirUsageUnavailable;
            break;
        };
        const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&entry.name)), 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        var buf: [4096]u8 = undefined;
        const child = try std.fmt.bufPrintSentinel(&buf, "{s}/{s}", .{ path, name }, 0);
        const stat = (try statNoFollow(child)) orelse continue;
        if (std.c.S.ISDIR(stat.mode)) {
            remaining -= try countBytes(child, remaining, depth + 1);
        } else if (std.c.S.ISREG(stat.mode) and name[0] != '.' and
            (std.mem.endsWith(u8, name, ".eml") or std.mem.indexOf(u8, name, ".eml:") != null))
        {
            if (stat.size > remaining) return error.HostedStorageFull;
            remaining -= stat.size;
        }
    }
    return allowance - remaining;
}

pub fn write(db: ?*db_mod.Database, allocator: std.mem.Allocator, user: []const u8, path: []const u8, data: []const u8) !void {
    try writeWithMtime(db, allocator, user, path, data, null);
}

pub fn writeWithMtime(db: ?*db_mod.Database, allocator: std.mem.Allocator, user: []const u8, path: []const u8, data: []const u8, mtime: ?i64) !void {
    if (db) |database| database.lockMailboxes();
    defer if (db) |database| database.unlockMailboxes();
    if (db) |database| try checkStorage(database, user, data.len, null);
    try durable_maildir.writeWithMtime(allocator, path, data, mtime);
}
