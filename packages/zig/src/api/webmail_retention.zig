//! Opt-in mailbox cleanup. A preview authorizes a rolling rule, and each
//! Maildir handoff records a recoverable Trash move for the stable reference.
const std = @import("std");
const database = @import("../storage/database.zig");
const maildir = @import("webmail_maildir.zig");
const refs = @import("../storage/message_refs.zig");
const imap = @import("../protocol/imap.zig");
const fs = @import("../core/fs_compat.zig");
const store = @import("webmail_store.zig");

const Allocator = std.mem.Allocator;
const Database = database.Database;
const owner = "user_id=(SELECT id FROM users WHERE username=?1 AND enabled=1)";
const move_batch = 10;
const preview_size = 8;
const page_size = 20;

pub const Folder = enum { INBOX, Newsletters, Receipts, Archive };
pub const Policy = struct { folder: Folder, days: i64 };
pub const Rule = struct {
    policy: ?Policy = null,
    revision: i64 = 0,
    next_run: ?i64 = null,
    last_run: ?i64 = null,
    last_moved: i64 = 0,
};
const Example = struct { subject: []const u8, received_at: i64 };
pub const Preview = struct {
    token: []const u8,
    policy: Policy,
    total: usize,
    examples: []const Example,
    expires_at: i64,
};
const Recoverable = struct { reference: []const u8, subject: []const u8, source_folder: []const u8, moved_at: i64 };
pub const Status = struct { rule: Rule, recoverable: []const Recoverable, page: usize, has_more: bool };

fn loadRule(db: *Database, user: []const u8) !Rule {
    const stmt = try db.prepare("SELECT folder,days,revision,next_run,last_run,last_moved FROM mail_retention_rules WHERE " ++ owner);
    defer stmt.finalize();
    try stmt.bind(1, user);
    if (!try stmt.step()) return .{};
    const folder = if (stmt.columnTextOpt(0)) |value| std.meta.stringToEnum(Folder, value) else null;
    return .{
        .policy = if (folder) |name| .{ .folder = name, .days = stmt.columnInt64(1) } else null,
        .revision = stmt.columnInt64(2),
        .next_run = if (folder != null) stmt.columnInt64(3) else null,
        .last_run = stmt.columnInt64Opt(4),
        .last_moved = stmt.columnInt64(5),
    };
}

fn saveRule(db: *Database, user: []const u8, policy: ?Policy, now: i64) !void {
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const stmt = try tx.prepare(
        \\INSERT INTO mail_retention_rules(user_id,folder,days,revision,next_run)
        \\ SELECT id,?2,?3,1,?4 FROM users WHERE username=?1 AND enabled=1
        \\ON CONFLICT(user_id) DO UPDATE SET folder=excluded.folder,days=excluded.days,
        \\  revision=revision+1,next_run=excluded.next_run,last_run=NULL,last_moved=0
        \\RETURNING revision
    );
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bindOpt(2, if (policy) |item| @as(?[]const u8, @tagName(item.folder)) else null);
    try stmt.bind(3, if (policy) |item| item.days else 0);
    try stmt.bind(4, now);
    if (!try stmt.step()) return error.NotFound;
    _ = try stmt.step();
    const clear = try tx.prepare("DELETE FROM mail_retention_previews WHERE " ++ owner);
    defer clear.finalize();
    try clear.bind(1, user);
    _ = try clear.step();
    try tx.commit();
}

fn protectedFiles(a: Allocator, db: *Database, user: []const u8, folder: Folder) !std.StringHashMapUnmanaged(void) {
    const stmt = try db.prepare(
        \\SELECT m.basename FROM mailbox_message_refs m
        \\WHERE m.user_id=(SELECT id FROM users WHERE username=?1) AND m.folder=?2 AND (
        \\ EXISTS(SELECT 1 FROM mail_retention_moves r WHERE r.user_id=m.user_id AND r.reference=m.reference)
        \\ OR EXISTS(SELECT 1 FROM mail_attention t WHERE t.user_id=m.user_id AND t.reference=m.reference)
        \\ OR EXISTS(SELECT 1 FROM mail_private_anchors p WHERE p.user_id=m.user_id AND p.reference=m.reference)
        \\)
    );
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bind(2, @tagName(folder));
    var protected: std.StringHashMapUnmanaged(void) = .empty;
    while (try stmt.step()) try protected.put(a, try a.dupe(u8, stmt.columnText(0)), {});
    return protected;
}

fn receivedAt(name: []const u8) ?i64 {
    if (imap.storedInternalDate(name)) |stamp| return stamp;
    const millis = imap.parseMessageSortKey(name);
    // The delivery and APPEND paths give new Maildir files a millisecond
    // prefix. Unrecognized legacy names do not establish an arrival date.
    return if (millis >= 100_000_000_000) @divFloor(millis, 1000) else null;
}

const Candidate = struct { file: maildir.FileRef, received_at: i64 };
const Scan = struct { total: usize, files: []const Candidate, digest: [64]u8 };

fn scan(a: Allocator, db: *Database, user: []const u8, folder: Folder, cutoff: i64, limit: usize, complete: bool) !Scan {
    const protected = try protectedFiles(a, db, user, folder);
    var digest = std.crypto.hash.sha2.Sha256.init(.{});
    var files: std.ArrayList(Candidate) = .empty;
    var total: usize = 0;
    for (try maildir.collectFiles(a, user, @tagName(folder))) |file| {
        const flags = maildir.flagsFrom(file.name);
        if (!flags.seen or flags.flagged or flags.draft or flags.deleted) continue;
        const received = receivedAt(file.name) orelse continue;
        if (received >= cutoff or protected.contains(database.maildirBaseName(file.name))) continue;
        total += 1;
        if (complete) {
            digest.update(file.name);
            digest.update("\x00");
        }
        if (files.items.len < limit) try files.append(a, .{ .file = file, .received_at = received });
        if (!complete and files.items.len == limit) break;
    }
    return .{ .total = total, .files = files.items, .digest = std.fmt.bytesToHex(digest.finalResult(), .lower) };
}

fn subject(a: Allocator, file: maildir.FileRef) ![]const u8 {
    const path = try std.fmt.allocPrint(a, "{s}/{s}", .{ file.dir, file.name });
    const handle = try fs.cwd().openFile(path, .{});
    defer handle.close();
    var bytes: [16 * 1024]u8 = undefined;
    const len = try handle.readAll(&bytes);
    const raw = bytes[0..len];
    const end = std.mem.indexOf(u8, raw, "\r\n\r\n") orelse std.mem.indexOf(u8, raw, "\n\n") orelse raw.len;
    const headers = try maildir.reviewHeaders(a, raw[0..end]);
    return if (std.unicode.utf8ValidateSlice(headers.subject)) headers.subject else "";
}

pub fn preview(a: Allocator, db: *Database, user: []const u8, policy: Policy, revision: i64, now: i64) !Preview {
    if (policy.days != 30 and policy.days != 90 and policy.days != 180) return error.InvalidRetentionPolicy;
    db.lockMailboxes();
    defer db.unlockMailboxes();
    if ((try loadRule(db, user)).revision != revision) return error.RetentionChanged;
    const cutoff = now - policy.days * 86400;
    const selected = try scan(a, db, user, policy.folder, cutoff, preview_size, true);
    const examples = try a.alloc(Example, selected.files.len);
    for (selected.files, examples) |entry, *output| {
        output.* = .{ .subject = subject(a, entry.file) catch "", .received_at = entry.received_at };
    }
    const token = try store.newId(a);
    const expires = now + 600;
    const stmt = try db.prepare(
        \\INSERT INTO mail_retention_previews(user_id,token,folder,days,revision,cutoff,digest,expires_at)
        \\ SELECT id,?2,?3,?4,?5,?6,?7,?8 FROM users WHERE username=?1 AND enabled=1
        \\ON CONFLICT(user_id) DO UPDATE SET token=excluded.token,folder=excluded.folder,days=excluded.days,
        \\ revision=excluded.revision,cutoff=excluded.cutoff,digest=excluded.digest,expires_at=excluded.expires_at
        \\RETURNING token
    );
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bind(2, token);
    try stmt.bind(3, @tagName(policy.folder));
    try stmt.bind(4, policy.days);
    try stmt.bind(5, revision);
    try stmt.bind(6, cutoff);
    try stmt.bind(7, @as([]const u8, &selected.digest));
    try stmt.bind(8, expires);
    if (!try stmt.step()) return error.NotFound;
    _ = try stmt.step();
    return .{ .token = token, .policy = policy, .total = selected.total, .examples = examples, .expires_at = expires };
}

pub fn enable(a: Allocator, db: *Database, user: []const u8, token: []const u8, revision: i64, now: i64) !Rule {
    db.lockMailboxes();
    defer db.unlockMailboxes();
    if ((try loadRule(db, user)).revision != revision) return error.RetentionChanged;
    const approved = blk: {
        const stmt = try db.prepare("SELECT folder,days,cutoff,digest FROM mail_retention_previews WHERE " ++ owner ++ " AND token=?2 AND revision=?3 AND expires_at>?4");
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, token);
        try stmt.bind(3, revision);
        try stmt.bind(4, now);
        if (!try stmt.step()) return error.RetentionPreviewRequired;
        break :blk .{
            .policy = Policy{ .folder = std.meta.stringToEnum(Folder, stmt.columnText(0)) orelse return error.InvalidRetentionPolicy, .days = stmt.columnInt64(1) },
            .cutoff = stmt.columnInt64(2),
            .digest = try a.dupe(u8, stmt.columnText(3)),
        };
    };
    const current = try scan(a, db, user, approved.policy.folder, approved.cutoff, 0, true);
    if (!std.mem.eql(u8, approved.digest, &current.digest)) return error.RetentionPreviewRequired;
    try saveRule(db, user, approved.policy, now);
    return loadRule(db, user);
}

pub fn disable(db: *Database, user: []const u8, revision: i64, now: i64) !Rule {
    db.lockMailboxes();
    defer db.unlockMailboxes();
    if ((try loadRule(db, user)).revision != revision) return error.RetentionChanged;
    try saveRule(db, user, null, now);
    return loadRule(db, user);
}

fn recoverHandoffs(a: Allocator, db: *Database, user: []const u8) !void {
    var pending: std.ArrayList([]const u8) = .empty;
    {
        const stmt = try db.prepare("SELECT reference FROM mailbox_message_refs WHERE " ++ owner ++ " AND next_retention_at IS NOT NULL LIMIT ?2");
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, move_batch);
        while (try stmt.step()) try pending.append(a, try a.dupe(u8, stmt.columnText(0)));
    }
    for (pending.items) |reference| {
        var scratch = std.heap.ArenaAllocator.init(a);
        defer scratch.deinit();
        const file = maildir.resolveVersioned(scratch.allocator(), db, user, reference) catch |err| switch (err) {
            maildir.MaildirError.MessageNotFound, error.FileNotFound => continue,
            else => return err,
        };
        if (!std.mem.eql(u8, file.locator.folder, "Trash")) refs.cancel(db, user, reference);
    }
}

pub fn status(a: Allocator, db: *Database, user: []const u8, page: usize) !Status {
    const offset = std.math.mul(usize, page -| 1, page_size) catch return error.InvalidRetentionPolicy;
    if (offset > std.math.maxInt(i64) - page_size) return error.InvalidRetentionPolicy;
    db.lockMailboxes();
    defer db.unlockMailboxes();
    try recoverHandoffs(a, db, user);
    const rule = try loadRule(db, user);
    const stmt = try db.prepare(
        \\SELECT r.reference,r.source_folder,r.moved_at,m.basename,m.file_stamp
        \\FROM mail_retention_moves r JOIN mailbox_message_refs m ON m.user_id=r.user_id AND m.reference=r.reference
        \\WHERE r.user_id=(SELECT id FROM users WHERE username=?1 AND enabled=1) AND r.restored=0 AND m.folder='Trash'
        \\ORDER BY r.moved_at DESC,r.reference LIMIT ?2 OFFSET ?3
    );
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bind(2, page_size + 1);
    try stmt.bind(3, offset);
    var rows: std.ArrayList(Recoverable) = .empty;
    var trash: std.StringHashMapUnmanaged(maildir.FileRef) = .empty;
    var scanned = false;
    var seen: usize = 0;
    while (try stmt.step()) {
        seen += 1;
        if (seen > page_size) break;
        if (!scanned) {
            for (try maildir.collectFiles(a, user, "Trash")) |file| try trash.put(a, database.maildirBaseName(file.name), file);
            scanned = true;
        }
        const file = trash.get(stmt.columnText(3)) orelse continue;
        const path = try std.fmt.allocPrint(a, "{s}/{s}", .{ file.dir, file.name });
        const stamp = refs.fileStamp(a, path) catch continue;
        if (!std.mem.eql(u8, stamp, stmt.columnText(4))) continue;
        try rows.append(a, .{
            .reference = try a.dupe(u8, stmt.columnText(0)),
            .source_folder = try a.dupe(u8, stmt.columnText(1)),
            .moved_at = stmt.columnInt64(2),
            .subject = subject(a, file) catch "",
        });
    }
    return .{ .rule = rule, .recoverable = rows.items, .page = page, .has_more = seen > page_size };
}

pub fn restore(a: Allocator, db: *Database, user: []const u8, reference: []const u8) !bool {
    if (!refs.valid(reference)) return error.NotFound;
    db.lockMailboxes();
    defer db.unlockMailboxes();
    const location = try maildir.resolveVersioned(a, db, user, reference);
    const stmt = try db.prepare("SELECT source_folder,restored FROM mail_retention_moves WHERE " ++ owner ++ " AND reference=?2");
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bind(2, reference);
    if (!try stmt.step()) return error.NotFound;
    if (stmt.columnInt64(1) != 0) return false;
    if (!std.mem.eql(u8, location.locator.folder, "Trash")) return error.RetentionChanged;
    const folder = std.meta.stringToEnum(Folder, stmt.columnText(0)) orelse return error.InvalidRetentionPolicy;
    _ = try maildir.moveMessageLocked(a, db, user, "Trash", location.locator.uid, @tagName(folder));
    return true;
}

/// One due account per turn. Yield between batches to keep delivery and
/// other mailbox mutations ahead of the rest of a cleanup backlog.
pub fn runDue(a: Allocator, db: *Database, now: i64) !void {
    const user = blk: {
        const stmt = try db.prepare(
            \\SELECT u.username FROM mail_retention_rules r JOIN users u ON u.id=r.user_id AND u.enabled=1
            \\WHERE r.folder IS NOT NULL AND r.next_run<=?1 ORDER BY r.next_run,r.user_id LIMIT 1
        );
        defer stmt.finalize();
        try stmt.bind(1, now);
        if (!try stmt.step()) return;
        break :blk try a.dupe(u8, stmt.columnText(0));
    };
    db.lockMailboxes();
    defer db.unlockMailboxes();
    const rule = try loadRule(db, user);
    const policy = rule.policy orelse return;
    if (rule.next_run.? > now) return;
    // Advance the schedule before touching files so a failed scan does not
    // continually retry ahead of other mailboxes.
    try finishRun(db, user, now + 300, now, 0);
    try recoverHandoffs(a, db, user);
    const selected = try scan(a, db, user, policy.folder, now - policy.days * 86400, move_batch, false);
    var moved: usize = 0;
    for (selected.files) |candidate| {
        var scratch = std.heap.ArenaAllocator.init(a);
        defer scratch.deinit();
        maildir.moveForRetentionLocked(scratch.allocator(), db, user, @tagName(policy.folder), candidate.file, now) catch |err| {
            std.log.warn("Mailbox retention move deferred: {}", .{err});
            continue;
        };
        moved += 1;
    }
    const delay: i64 = if (moved == move_batch) 30 else if (moved < selected.total) 300 else 3600;
    try finishRun(db, user, now + delay, now, moved);
}

fn finishRun(db: *Database, user: []const u8, next: i64, now: i64, moved: usize) !void {
    const stmt = try db.prepare("UPDATE mail_retention_rules SET next_run=?2,last_run=?3,last_moved=?4 WHERE " ++ owner);
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bind(2, next);
    try stmt.bind(3, now);
    try stmt.bind(4, moved);
    _ = try stmt.step();
}
