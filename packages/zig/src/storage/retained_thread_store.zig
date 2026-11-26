//! Store immutable, recipient-owned copies independently of the live grant.
const std = @import("std");
const database = @import("database.zig");
const threads = @import("../api/webmail_team_threads.zig");
const mime = @import("../api/webmail_mime.zig");
const Allocator = std.mem.Allocator;
const Database = database.Database;
const Transaction = Database.Transaction;

pub const schema =
    \\CREATE TABLE IF NOT EXISTS mail_retained_thread_archives (
    \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    \\    share_id TEXT NOT NULL, approval_id INTEGER NOT NULL,
    \\    document TEXT NOT NULL CHECK(json_valid(document)),
    \\    sha256 TEXT NOT NULL CHECK(length(sha256)=64),
    \\    PRIMARY KEY(user_id,share_id,approval_id)
    \\);
    \\CREATE INDEX IF NOT EXISTS mail_retained_thread_approval ON mail_retained_thread_archives(approval_id);
    \\CREATE TABLE IF NOT EXISTS hosted_erasure_thread_archive_steps (
    \\    start_audit_id INTEGER PRIMARY KEY REFERENCES hosted_erasure_maildir_steps(start_audit_id),
    \\    approval_id INTEGER NOT NULL UNIQUE
    \\);
;

pub const Selection = struct { source_share_id: []const u8, peer_user_id: i64 };
pub const max_bytes = 32 * 1024 * 1024;
const peer_max_bytes = 64 * 1024 * 1024;
const ParseOptions: std.json.ParseOptions = .{ .allocate = .alloc_always };

fn checksum(bytes: []const u8) [64]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
    return std.fmt.bytesToHex(hash, .lower);
}

fn verifiedChecksum(document: []const u8, expected: []const u8) ![64]u8 {
    const hash = checksum(document);
    if (!std.mem.eql(u8, &hash, expected)) return error.ErasureThreadArchiveInvalid;
    return hash;
}

fn bindSelection(row: database.Statement, selection: Selection, approval: i64) !void {
    try row.bind(1, selection.peer_user_id);
    try row.bind(2, selection.source_share_id);
    try row.bind(3, approval);
}

pub fn accessiblePeer(a: Allocator, tx: Transaction, peer: i64, now: i64) ![]const u8 {
    const row = try tx.prepare(
        \\SELECT username FROM users u WHERE id=?1 AND enabled=1 AND NOT EXISTS (
        \\ SELECT 1 FROM provisioned_mailboxes p WHERE p.user_id=u.id AND p.read_until<=?2
        \\)
    );
    defer row.finalize();
    try row.bind(1, peer);
    try row.bind(2, now);
    if (!try row.step()) return error.ErasureThreadArchivePeerUnavailable;
    return a.dupe(u8, row.columnText(0));
}

pub fn existing(tx: Transaction, selection: Selection, approval: i64) !?[64]u8 {
    const row = try tx.prepare(
        "SELECT document,sha256 FROM mail_retained_thread_archives WHERE user_id=?1 AND share_id=?2 AND approval_id=?3",
    );
    defer row.finalize();
    try bindSelection(row, selection, approval);
    if (!try row.step()) return null;
    return try verifiedChecksum(row.columnText(0), row.columnText(1));
}

pub fn save(tx: Transaction, selection: Selection, approval: i64, document: []const u8) ![64]u8 {
    if (document.len > max_bytes) return error.ErasureThreadArchiveTooLarge;
    const hash = checksum(document);
    if (try existing(tx, selection, approval)) |current| {
        if (!std.mem.eql(u8, &current, &hash)) return error.ErasureThreadArchiveChanged;
        return hash;
    }
    const row = try tx.prepare(
        \\INSERT INTO mail_retained_thread_archives(user_id,share_id,approval_id,document,sha256)
        \\SELECT ?1,?2,?3,?4,?5 WHERE
        \\COALESCE((SELECT sum(length(CAST(document AS BLOB))) FROM mail_retained_thread_archives WHERE user_id=?1),0)
        \\+ length(CAST(?4 AS BLOB))<=?6 RETURNING 1
    );
    defer row.finalize();
    try bindSelection(row, selection, approval);
    try row.bind(4, document);
    try row.bind(5, @as([]const u8, &hash));
    try row.bind(6, @as(i64, peer_max_bytes));
    if (!try row.step()) return error.ErasureThreadArchiveTooLarge;
    _ = try row.step();
    return hash;
}

/// Remove staged documents for superseded decisions. Keep their case receipts.
pub fn discardSuperseded(tx: Transaction, start: i64, keep: ?i64) !void {
    const row = try tx.prepare(
        \\DELETE FROM mail_retained_thread_archives WHERE (?2 IS NULL OR approval_id<>?2) AND approval_id IN (
        \\ SELECT id FROM audit_log WHERE action='hosted.erasure.shared.source_release' AND target_type='hosted_mailbox'
        \\ AND json_extract(details,'$.start_audit_id')=?1 AND json_extract(details,'$.store')='maildir'
        \\)
    );
    defer row.finalize();
    try row.bind(1, start);
    try row.bindOpt(2, keep);
    if (try row.step()) return error.InvalidErasureJournal;
}

pub fn chosen(tx: Transaction, start: i64) !?i64 {
    const row = try tx.prepare("SELECT approval_id FROM hosted_erasure_thread_archive_steps WHERE start_audit_id=?1");
    defer row.finalize();
    try row.bind(1, start);
    return if (try row.step()) row.columnInt64(0) else null;
}

pub fn choose(tx: Transaction, start: i64, approval: i64) !void {
    const row = try tx.prepare("INSERT INTO hosted_erasure_thread_archive_steps(start_audit_id,approval_id) VALUES(?1,?2)");
    defer row.finalize();
    try row.bind(1, start);
    try row.bind(2, approval);
    if (try row.step()) return error.InvalidErasureJournal;
}

const completed =
    \\ FROM mail_retained_thread_archives r
    \\ JOIN hosted_erasure_thread_archive_steps t ON t.approval_id=r.approval_id
    \\ JOIN hosted_erasure_maildir_steps m ON m.start_audit_id=t.start_audit_id AND m.phase='complete'
;

const authorized = completed ++ " JOIN users u ON u.id=r.user_id WHERE u.username=?1 AND u.enabled=1";

pub const PortableRows = struct {
    row: database.Statement,

    pub const Entry = struct { id: []const u8, document: []const u8 };

    pub fn close(self: PortableRows) void {
        self.row.finalize();
    }

    /// The strings are valid until the next read or until the cursor closes.
    pub fn next(self: PortableRows) !?Entry {
        if (!try self.row.step()) return null;
        const document = self.row.columnText(1);
        _ = try verifiedChecksum(document, self.row.columnText(2));
        return .{ .id = self.row.columnText(0), .document = document };
    }
};

/// Authorized operator export can read the recipient's completed copies even
/// when that recipient's own browser sessions have been suspended.
pub fn portableRows(db: *Database, owner: i64) !PortableRows {
    const row = try db.prepare("SELECT r.share_id,r.document,r.sha256" ++ completed ++ " WHERE r.user_id=?1 ORDER BY r.share_id");
    errdefer row.finalize();
    try row.bind(1, owner);
    return .{ .row = row };
}

pub fn available(db: *Database, actor: []const u8) !bool {
    const row = try db.prepare("SELECT 1" ++ authorized ++ " LIMIT 1");
    defer row.finalize();
    try row.bind(1, actor);
    return row.step();
}

pub fn appendGrants(a: Allocator, db: *Database, actor: []const u8, live: []const threads.Grant) ![]threads.Grant {
    const rows = try db.prepare("SELECT json_extract(r.document,'$.grant')" ++ authorized ++ " ORDER BY r.approval_id DESC,r.share_id");
    defer rows.finalize();
    try rows.bind(1, actor);
    var result: std.ArrayList(threads.Grant) = .empty;
    try result.appendSlice(a, live);
    while (try rows.step()) try result.append(a, try std.json.parseFromSliceLeaky(threads.Grant, a, rows.columnText(0), ParseOptions));
    return result.toOwnedSlice(a);
}

pub fn detail(a: Allocator, db: *Database, actor: []const u8, id: []const u8, needle: []const u8, before: ?i64) !threads.Detail {
    if (before != null and before.? < 1) return error.InvalidThreadShare;
    const row = try db.prepare(
        \\SELECT json_extract(r.document,'$.grant'),json_extract(r.document,'$.comments'),
        \\ (SELECT p.value FROM json_each(r.document,'$.pages') p WHERE json_extract(p.value,'$.before')=?3)
    ++ authorized ++ " AND r.share_id=?2");
    defer row.finalize();
    try row.bind(1, actor);
    try row.bind(2, id);
    try row.bind(3, before orelse 0);
    if (!try row.step()) return error.ThreadShareUnavailable;
    if (row.columnIsNull(2)) return error.InvalidThreadShare;
    const grant = try std.json.parseFromSliceLeaky(threads.Grant, a, row.columnText(0), ParseOptions);
    return threads.retainedDetail(a, grant, row.columnText(1), row.columnText(2), actor, needle);
}

pub fn attachment(a: Allocator, db: *Database, actor: []const u8, id: []const u8, ref: []const u8, index: usize) !mime.AttachmentInfo {
    const ordinal = std.math.cast(i64, index) orelse return error.ThreadShareUnavailable;
    const row = try db.prepare(
        \\SELECT (SELECT p.value FROM json_each(r.document,'$.parts') p
        \\ WHERE json_extract(p.value,'$.reference')=?3 AND json_extract(p.value,'$.index')=?4)
    ++ authorized ++ " AND r.share_id=?2 AND json_extract(r.document,'$.grant.downloads')=1");
    defer row.finalize();
    try row.bind(1, actor);
    try row.bind(2, id);
    try row.bind(3, ref);
    try row.bind(4, ordinal);
    if (!try row.step() or row.columnIsNull(0)) return error.ThreadShareUnavailable;
    const part = try std.json.parseFromSliceLeaky(threads.RetainedPart, a, row.columnText(0), ParseOptions);
    const decoder = std.base64.standard.Decoder;
    const size = try decoder.calcSizeForSlice(part.encoded);
    const data = try a.alloc(u8, size);
    try decoder.decode(data, part.encoded);
    return .{ .filename = part.filename, .content_type = part.content_type, .size = size, .data = data };
}
