//! Follow authenticated submissions only after the client files the same MIME
//! in its own Sent folder and every primary recipient has a confirmed outcome.
const std = @import("std");
const Database = @import("../storage/database.zig").Database;
const evidence = @import("../message/smtp_sent.zig");
const fs = @import("../core/fs_compat.zig");
const maildir = @import("../api/webmail_maildir.zig");
const maildir_path = @import("../core/maildir_path.zig");
const refs = @import("../storage/message_refs.zig");
const snapshots = @import("../api/webmail_snapshots.zig");
const thread_ids = @import("../message/thread_ids.zig");
const time = @import("../core/time_compat.zig");

const Allocator = std.mem.Allocator;

pub fn capture(a: Allocator, db: *Database, user: []const u8, raw: []const u8, envelope: ?[]const []const u8) !?evidence.Evidence {
    if (!try db.hasFollowedSentReplies(user)) return null;
    var account = try db.getUserByUsername(user);
    defer account.deinit(db.allocator);
    var proof = (try evidence.inspect(a, raw, account.email, envelope)) orelse return null;
    if (!try db.hasFollowedSmtpParent(user, proof.parent)) return null;
    // SMTP adds trace and scanner headers to this buffer after capture.
    proof.wire_id = try a.dupe(u8, proof.wire_id);
    proof.parent = try a.dupe(u8, proof.parent);
    return proof;
}

/// Called under the mailbox lock. Count the wire ID in every physical folder,
/// including copies that were never opened in webmail or eligible for sharing.
pub fn source(a: Allocator, db: *Database, user: []const u8, parent: []const u8, recipients: []const []const u8, junk: []const u8) !?Database.TeamReplySource {
    try maildir_path.validate(user);
    const root = try std.fmt.allocPrintSentinel(a, "mail/{s}", .{user}, 0);
    const directory = std.c.opendir(root) orelse return null;
    defer _ = std.c.closedir(directory);

    var found: ?struct { folder: []const u8, path: []const u8 } = null;
    var header: [32 * 1024]u8 = undefined;
    while (std.c.readdir(directory)) |entry| {
        if (entry.type != std.c.DT.DIR and entry.type != std.c.DT.UNKNOWN) continue;
        const name: [*:0]const u8 = @ptrCast(&entry.name);
        const dir = std.mem.sliceTo(name, 0);
        maildir_path.validate(dir) catch continue;
        var scratch = std.heap.ArenaAllocator.init(a);
        defer scratch.deinit();
        const tmp = scratch.allocator();
        const subdir = try std.fmt.allocPrint(tmp, "{s}/{s}", .{ root, dir });
        const files = fs.listEmlFiles(tmp, subdir) catch |err| {
            if (entry.type == std.c.DT.UNKNOWN and err == error.FileNotFound) continue;
            return err;
        };
        for (files) |filename| {
            var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
            const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ subdir, filename });
            const file = try fs.cwd().openFile(path, .{});
            defer file.close();
            const bytes = (try readHeader(file, &header)) orelse return null;
            if (!thread_ids.containsOwnId(bytes, parent)) continue;
            if (found != null) return null;
            const folder = if (std.mem.eql(u8, dir, "new") or std.mem.eql(u8, dir, "cur")) "INBOX" else dir;
            if (!maildir.isValidFolderName(folder) or !snapshots.canShareFile(folder, maildir.flagsFrom(filename), junk)) return null;
            found = .{ .folder = try a.dupe(u8, folder), .path = try a.dupe(u8, path) };
        }
    }
    const original = found orelse return null;
    const stamp = try refs.fileStamp(a, original.path);
    const location = refs.location(original.folder, std.fs.path.basename(original.path));
    const reference = (try refs.findAt(a, db, user, location, stamp)) orelse return null;
    const raw = try fs.readFileAlloc(a, original.path);
    const cut = evidence.headerLength(raw) orelse return null;
    const ids = try thread_ids.parse(a, raw[0..cut]);
    if (ids.message_id_fields != 1 or ids.message_ids != 1 or !std.mem.eql(u8, ids.own orelse return null, parent)) return null;
    const result: Database.TeamReplySource = .{ .reference = reference, .revision = refs.digest(raw), .wire_id = parent };
    if (!try db.canFollowNativeSent(user, result, try std.json.Stringify.valueAlloc(a, recipients, .{}))) return null;
    return result;
}

fn readHeader(file: fs.File, buffer: []u8) !?[]const u8 {
    var length: usize = 0;
    while (length < buffer.len) {
        const chunk = buffer[length..@min(length + 4096, buffer.len)];
        const count = std.c.read(file.handle, chunk.ptr, chunk.len);
        if (count < 0) return error.SmtpReplyHeaderReadFailed;
        if (count == 0) return buffer[0..length];
        length += @intCast(count);
        if (evidence.headerLength(buffer[0..length])) |end| return buffer[0..end];
    }
    // An incomplete header could still contain a duplicate Message-ID.
    return null;
}

/// Record a client observation only after IMAP has synced the Sent file.
pub fn observeCopy(a: Allocator, db: *Database, user: []const u8, path: []const u8, raw: []const u8) !void {
    const proof = (try capture(a, db, user, raw, null)) orelse return;
    const stamp = try refs.fileStamp(a, path);
    const reference = try refs.issue(a, db, user, refs.location("Sent", std.fs.path.basename(path)), stamp);
    try db.recordSmtpSentCopy(user, .{ .wire_id = proof.wire_id, .digest = proof.digest }, reference, time.timestamp());
}

/// Either observation can arrive first, including across restart. Run outside
/// SMTP and IMAP request handling so preview publication never holds a client
/// response while waiting for another protocol or a remote provider.
pub fn reconcile(allocator: Allocator, db: *Database, since: i64, junk: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    for (0..12) |_| {
        _ = arena.reset(.retain_capacity);
        const a = arena.allocator();
        db.lockMailboxes();
        defer db.unlockMailboxes();
        const match = (try db.nextSmtpSentMatch(a, since)) orelse return;

        const copy = (try resolve(a, db, match.owner, match.copy)) orelse {
            try db.forgetSmtpSentCopy(match.owner, match.copy);
            continue;
        };
        const flags = maildir.flagsFrom(copy.file.name);
        const digest = evidence.fingerprint(copy.raw);
        if (!std.mem.eql(u8, copy.folder, "Sent") or flags.deleted or flags.draft or !std.mem.eql(u8, &digest, match.digest)) {
            try db.forgetSmtpSentCopy(match.owner, match.copy);
            continue;
        }
        const parent = (try resolve(a, db, match.owner, match.parent)) orelse {
            try db.forgetSmtpSentProof(match.delivery);
            continue;
        };
        const parent_revision = refs.digest(parent.raw);
        if (!snapshots.canShareFile(parent.folder, maildir.flagsFrom(parent.file.name), junk) or
            !std.mem.eql(u8, &parent_revision, match.parent_revision))
        {
            try db.forgetSmtpSentProof(match.delivery);
            continue;
        }
        const revision = refs.digest(copy.raw);
        try db.publishSmtpSentMatch(match, copy.stamp, &revision, since);
    }
}

fn resolve(a: Allocator, db: *Database, user: []const u8, reference: []const u8) !?maildir.ReferencedFile {
    return maildir.resolveReferenceFileLocked(a, db, user, reference) catch |err| switch (err) {
        error.MessageNotFound, error.FileNotFound => null,
        else => return err,
    };
}
