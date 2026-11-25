//! Retire the compose record once its native Maildir draft is expunged.
const std = @import("std");
const database = @import("../storage/database.zig");
const refs = @import("../storage/message_refs.zig");
const durable = @import("../core/durable_maildir.zig");
const fs = @import("../core/fs_compat.zig");
const thread_ids = @import("../message/thread_ids.zig");
const store = @import("webmail_store.zig");

const kind = "draft-expunge";
const Intent = struct {
    directory: []const u8,
    directory_stamp: []const u8,
    folder: []const u8,
    basename: []const u8,
    uid: i64,
};
const Match = struct { record: store.Record, uid: i64 };

/// Only a draft at this UID whose MIME identifies the same compose document
/// can retire the record. A copied file or a stale UID mapping is insufficient.
fn matchingDraft(a: std.mem.Allocator, db: *database.Database, user: []const u8, at: refs.Location, path: []const u8) !?Match {
    const uid = (try db.getUidForFile(user, at.folder, at.basename)) orelse return null;
    if (!try store.managesDraftAt(db, user, at.folder, uid)) return null;
    const identity = try refs.fileFingerprint(a, path);
    const file = try fs.cwd().openFile(path, .{});
    defer file.close();
    // The generated Message-ID follows the address lists and subject.
    var buffer: [128 * 1024]u8 = undefined;
    const length: usize = @intCast(@min(buffer.len, identity.size));
    const read = try file.readAll(buffer[0..length]);
    if (read != length) return error.DraftHeaderReadFailed;
    const headers = try thread_ids.parse(a, buffer[0..read]);
    if (headers.message_id_fields != 1 or headers.message_ids != 1) return null;
    const message_id = headers.own orelse return null;
    const prefix = "<draft.";
    if (!std.mem.startsWith(u8, message_id, prefix)) return null;
    const at_sign = std.mem.indexOfScalarPos(u8, message_id, prefix.len, '@') orelse return null;
    const id = message_id[prefix.len..at_sign];
    if (!store.validId(id)) return null;
    const row = store.get(a, db, user, "draft", id) catch |err| switch (err) {
        store.StoreError.NotFound => return null,
        else => return err,
    };
    const location = try std.json.parseFromSliceLeaky(struct { uid: i64, folder: []const u8 }, a, row.payload, .{ .ignore_unknown_fields = true });
    if (location.uid != uid or !std.mem.eql(u8, location.folder, at.folder)) return null;
    return .{ .record = row, .uid = uid };
}

/// The IMAP caller holds the mailbox lock. Record the intent before unlinking
/// and make the directory change durable before dropping the SQLite record.
pub fn remove(a: std.mem.Allocator, db: *database.Database, user: []const u8, at: refs.Location, path: []const u8) !void {
    const matched = (try matchingDraft(a, db, user, at, path)) orelse return fs.cwd().deleteFile(path);
    const row = matched.record;
    const directory = std.fs.path.dirname(path) orelse return error.InvalidMaildirPath;
    const resolved = try fs.cwd().realpathAlloc(a, directory);
    const intent: Intent = .{
        .directory = directory,
        .directory_stamp = try refs.directoryStamp(a, resolved),
        .folder = at.folder,
        .basename = at.basename,
        .uid = matched.uid,
    };
    const payload = try std.json.Stringify.valueAlloc(a, intent, .{});
    _ = try store.put(db, .{
        .username = user,
        .kind = kind,
        .id = row.id,
        .payload = payload,
        .state = "pending",
        .revision = 0,
        .due_at = row.revision,
        .expires_at = 0,
    }, 0);
    fs.cwd().deleteFile(path) catch |err| {
        store.remove(db, user, kind, row.id) catch {};
        return err;
    };
    // IMAP has removed the file. The intent persists if either checkpoint
    // fails, so startup can finish without repeating the unlink.
    checkpoint(a, db, user, row.id, row.revision, intent) catch |err|
        std.log.warn("draft expunge metadata needs recovery: {}", .{err});
}

fn checkpoint(a: std.mem.Allocator, db: *database.Database, user: []const u8, id: []const u8, revision: i64, intent: Intent) !void {
    try durable.syncDirectory(a, intent.directory);
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const removed = removed: {
        const stmt = try tx.prepare(
            \\DELETE FROM webmail_records
            \\ WHERE username=?1 AND id=?2 AND kind='draft' AND revision>=?3
            \\ AND json_extract(payload,'$.folder')=?4 AND json_extract(payload,'$.uid')=?5
            \\ RETURNING id
        );
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, id);
        try stmt.bind(3, revision);
        try stmt.bind(4, intent.folder);
        try stmt.bind(5, intent.uid);
        const deleted = try stmt.step();
        if (deleted) _ = try stmt.step();
        break :removed deleted;
    };
    const cleanup = try tx.prepare(
        \\DELETE FROM webmail_records WHERE username=?1 AND id=?2
        \\ AND (kind='draft-expunge' OR (kind='draft-edit' AND ?3=1))
    );
    defer cleanup.finalize();
    try cleanup.bind(1, user);
    try cleanup.bind(2, id);
    try cleanup.bind(3, @as(i64, @intFromBool(removed)));
    _ = try cleanup.step();
    try tx.commit();
}

pub fn recover(db: *database.Database) !void {
    db.lockMailboxes();
    defer db.unlockMailboxes();
    var cursor: i64 = 0;
    while (true) {
        var arena = std.heap.ArenaAllocator.init(db.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const pending = (try store.nextDraftIntent(a, db, kind, &cursor)) orelse return;
        recoverOne(a, db, pending) catch |err| std.log.warn("could not recover draft expunge: {}", .{err});
    }
}

fn recoverOne(a: std.mem.Allocator, db: *database.Database, pending: store.Record) !void {
    const intent = try std.json.parseFromSliceLeaky(Intent, a, pending.payload, .{});
    const resolved = try fs.cwd().realpathAlloc(a, intent.directory);
    const stamp = try refs.directoryStamp(a, resolved);
    if (!std.mem.eql(u8, stamp, intent.directory_stamp)) return error.DraftDirectoryChanged;
    for (try fs.listEmlFilesUnsorted(a, intent.directory)) |file| {
        // The expunge did not complete, or the flags changed since it began.
        if (std.mem.eql(u8, database.maildirBaseName(file), intent.basename))
            return store.remove(db, pending.username, kind, pending.id);
    }
    try checkpoint(a, db, pending.username, pending.id, pending.due_at, intent);
}
