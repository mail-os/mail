//! Retire only the draft snapshot admitted by EWS. The confirmation survives
//! both removal of its Maildir identity and interruption during cleanup.
const std = @import("std");
const database = @import("../storage/database.zig");
const durable = @import("../core/durable_maildir.zig");
const fs = @import("../core/fs_compat.zig");
const maildir_path = @import("../core/maildir_path.zig");
const refs = @import("../storage/message_refs.zig");
const time = @import("../core/time_compat.zig");

pub fn replay(db: *database.Database, user: []const u8, basename: []const u8, revision: ?[]const u8, save_copy: bool) !bool {
    const saved = (try db.confirmedEwsDraft(user, basename, revision)) orelse return false;
    if (saved != save_copy) return error.EwsSendSettingsChanged;
    return true;
}

/// The delivery journal can prove acceptance independently of an EWS reply
/// or a live draft. Keep the sweep bounded and give each item its own arena.
pub fn finalize(a: std.mem.Allocator, db: *database.Database, id: ?[]const u8) !void {
    try db.confirmEwsDraftFinalizations(id);
    var cursor: i64 = 0;
    for (0..32) |_| {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const scratch = arena.allocator();
        db.lockMailboxes();
        defer db.unlockMailboxes();
        const job = (try db.nextEwsDraftFinalization(scratch, id, cursor)) orelse return;
        cursor = job.rowid;
        retire(scratch, db, job) catch |err|
            std.log.warn("EWS draft cleanup for {s} needs recovery: {}", .{ job.delivery_id, err });
    }
}

fn directoryFor(a: std.mem.Allocator, db: *database.Database, job: database.Database.EwsDraftFinalization) !?[]const u8 {
    try maildir_path.validate(job.user);
    try maildir_path.validate(job.basename);
    const base = try std.fmt.allocPrint(a, "mail/{s}/Drafts", .{job.user});
    const directory = std.fs.path.dirname(job.path) orelse return null;
    if (isDraftDirectory(directory, base)) return directory;
    const at = std.mem.indexOfScalar(u8, job.user, '@') orelse return null;
    const legacy = job.user[0..at];
    try maildir_path.validate(legacy);
    const legacy_base = try std.fmt.allocPrint(a, "mail/{s}/Drafts", .{legacy});
    if (!isDraftDirectory(directory, legacy_base) or try db.userExists(legacy)) return null;
    const owner = (try db.uniqueUsernameForLocalPart(legacy, a)) orelse return null;
    return if (std.mem.eql(u8, owner, job.user)) directory else null;
}

fn isDraftDirectory(directory: []const u8, base: []const u8) bool {
    if (!std.mem.startsWith(u8, directory, base)) return false;
    const sub = directory[base.len..];
    return sub.len == 0 or std.mem.eql(u8, sub, "/new") or std.mem.eql(u8, sub, "/cur");
}

fn retire(a: std.mem.Allocator, db: *database.Database, job: database.Database.EwsDraftFinalization) !void {
    const directory = try directoryFor(a, db, job);
    const reference = try refs.lookup(a, db, job.user, job.reference);
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    if (directory != null and reference != null and
        std.mem.eql(u8, reference.?.location.folder, "Drafts") and
        std.mem.eql(u8, reference.?.location.basename, job.basename) and reference.?.pending == null)
    {
        if (try retireFile(a, tx, job, directory.?)) {
            const stmt = try tx.prepare(
                \\DELETE FROM mailbox_message_refs WHERE reference=?2 AND folder='Drafts'
                \\AND user_id=(SELECT id FROM users WHERE username=?1)
            );
            defer stmt.finalize();
            try stmt.bind(1, job.user);
            try stmt.bind(2, job.reference);
            _ = try stmt.step();
        }
    }
    const stmt = try tx.prepare("UPDATE mail_ews_draft_finalizations SET retired_at=?2 WHERE delivery_id=?1");
    defer stmt.finalize();
    try stmt.bind(1, job.delivery_id);
    try stmt.bind(2, time.timestamp());
    _ = try stmt.step();
    try tx.commit();
}

fn retireFile(a: std.mem.Allocator, tx: database.Database.Transaction, job: database.Database.EwsDraftFinalization, directory: []const u8) !bool {
    if (job.draft_id) |id| {
        const stmt = try tx.prepare(
            \\SELECT state,revision,EXISTS(SELECT 1 FROM webmail_records e WHERE e.username=?1 AND e.kind='draft-edit' AND e.id=?2)
            \\FROM webmail_records WHERE username=?1 AND kind='draft' AND id=?2
        );
        defer stmt.finalize();
        try stmt.bind(1, job.user);
        try stmt.bind(2, id);
        if (!try stmt.step() or !std.mem.eql(u8, stmt.columnText(0), "saved") or
            stmt.columnInt64(1) != job.draft_revision or stmt.columnInt64(2) != 0) return false;
    }

    const base = if (std.mem.endsWith(u8, directory, "/Drafts")) directory else std.fs.path.dirname(directory).?;
    const dirs = [_][]const u8{ base, try std.fmt.allocPrint(a, "{s}/new", .{base}), try std.fmt.allocPrint(a, "{s}/cur", .{base}) };
    var candidate: ?[]const u8 = null;
    for (dirs) |dir| {
        const files = fs.listEmlFiles(a, dir) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        for (files) |name| {
            if (!std.mem.eql(u8, database.maildirBaseName(name), job.basename)) continue;
            if (candidate != null) return false;
            candidate = try std.fmt.allocPrint(a, "{s}/{s}", .{ dir, name });
        }
    }
    if (candidate) |file| {
        const identity = try refs.fileFingerprint(a, file);
        if (!std.mem.eql(u8, identity.fingerprint, job.fingerprint)) return false;
        const raw = try fs.readFileAlloc(a, file);
        if (!std.mem.eql(u8, &refs.digest(raw), job.revision)) return false;
        try fs.cwd().deleteFile(file);
    }
    // The file can already be absent after a stop between unlink and commit.
    try durable.syncDirectory(a, if (candidate) |file| std.fs.path.dirname(file).? else directory);
    if (job.draft_id) |id| {
        const stmt = try tx.prepare("DELETE FROM webmail_records WHERE username=?1 AND kind='draft' AND id=?2 AND revision=?3 AND state='saved'");
        defer stmt.finalize();
        try stmt.bind(1, job.user);
        try stmt.bind(2, id);
        try stmt.bind(3, job.draft_revision);
        _ = try stmt.step();
    }
    return true;
}
