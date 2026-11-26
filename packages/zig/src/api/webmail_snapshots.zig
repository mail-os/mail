//! Fixed, owner-authorized text snapshots. A viewer capability never resolves
//! a live mailbox reference. Only the digest of that capability is stored.
const std = @import("std");
const database = @import("../storage/database.zig");
const message_refs = @import("../storage/message_refs.zig");
const teams = @import("../storage/team_store.zig");
const link_tokens = @import("webmail_link_tokens.zig");
const html_text = @import("../antispam/html_text.zig");
const maildir = @import("webmail_maildir.zig");

pub const max_messages = 10;
pub const max_bytes = 128 * 1024;
pub const max_links = 20;

pub const Message = struct {
    subject: []const u8,
    from: []const u8,
    timestamp: i64,
    text: []const u8,
};

pub const Prepared = struct { messages: []Message, payload: []const u8, digest: [64]u8 };
pub const Link = struct { id: i64, subject: []const u8, message_count: i64, expires_at: i64 };
pub const Issued = struct { link: Link, token: [64]u8 };
pub const View = struct { payload: []const u8, expires_at: i64 };

pub fn canShare(msg: maildir.MessageDetail, junk_folder: []const u8) bool {
    return canShareFile(msg.folder, msg.flags, junk_folder);
}

pub fn canShareFile(folder: []const u8, flags: maildir.Flags, junk_folder: []const u8) bool {
    return maildir.isPersonalFolder(folder) and !flags.deleted and !flags.draft and
        !std.ascii.eqlIgnoreCase(folder, "Trash") and !std.ascii.eqlIgnoreCase(folder, "Junk") and
        !std.ascii.eqlIgnoreCase(folder, junk_folder);
}

pub fn plainText(a: std.mem.Allocator, msg: maildir.MessageDetail) ![]const u8 {
    if (msg.text_body.len != 0 or msg.html_body.len == 0) return msg.text_body;
    const buffer = try a.alloc(u8, @min(msg.html_body.len, max_bytes + 1));
    return std.mem.trim(u8, html_text.extract(msg.html_body, buffer), " ");
}

pub fn prepare(a: std.mem.Allocator, db: *database.Database, owner: []const u8, references: []const []const u8, junk_folder: []const u8) !Prepared {
    if (references.len == 0 or references.len > max_messages) return error.InvalidSnapshotSelection;
    for (references, 0..) |reference, index| {
        if (!message_refs.valid(reference)) return error.InvalidSnapshotSelection;
        for (references[0..index]) |previous| {
            if (std.mem.eql(u8, previous, reference)) return error.InvalidSnapshotSelection;
        }
    }

    const messages = try a.alloc(Message, references.len);
    var source_bytes: usize = 0;
    for (references, messages) |reference, *message| {
        // Release raw MIME and attachments after copying the public fields.
        var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer scratch.deinit();
        const msg = try maildir.getByReference(scratch.allocator(), db, owner, reference);
        if (!canShare(msg, junk_folder)) return error.MessageNotFound;
        const text = try plainText(scratch.allocator(), msg);
        for ([_][]const u8{ msg.subject, msg.from, text }) |field| {
            if (field.len > max_bytes - source_bytes) return error.SnapshotTooLarge;
            if (!std.unicode.utf8ValidateSlice(field)) return error.SnapshotTextUnavailable;
            source_bytes += field.len;
        }
        message.* = .{
            .subject = try a.dupe(u8, msg.subject),
            .from = try a.dupe(u8, msg.from),
            .timestamp = msg.timestamp,
            .text = try a.dupe(u8, text),
        };
    }
    const payload = try std.json.Stringify.valueAlloc(a, messages, .{});
    if (payload.len > max_bytes) return error.SnapshotTooLarge;
    return .{ .messages = messages, .payload = payload, .digest = link_tokens.digest(payload) };
}

pub fn create(db: *database.Database, owner: []const u8, prepared: Prepared, lifetime: i64, now: i64) !Issued {
    if (!link_tokens.validLifetime(lifetime)) return error.InvalidSnapshotLifetime;
    const token = link_tokens.new();
    const token_hash = link_tokens.digest(&token);
    const expires_at = now + lifetime;
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const user_id = (try teams.activeMailboxId(tx, owner)) orelse return error.SnapshotOwnerUnavailable;
    const id = blk: {
        const stmt = try tx.prepare(
            \\INSERT INTO mail_snapshot_links(user_id,token_hash,payload,subject,message_count,expires_at)
            \\SELECT ?1,?2,?3,?4,?5,?6
            \\WHERE (SELECT count(*) FROM mail_snapshot_links WHERE user_id=?1 AND expires_at>?7) < ?8
            \\RETURNING id
        );
        defer stmt.finalize();
        try stmt.bind(1, user_id);
        try stmt.bind(2, @as([]const u8, &token_hash));
        try stmt.bind(3, prepared.payload);
        try stmt.bind(4, prepared.messages[0].subject);
        try stmt.bind(5, prepared.messages.len);
        try stmt.bind(6, expires_at);
        try stmt.bind(7, now);
        try stmt.bind(8, @as(i64, max_links));
        if (!try stmt.step()) return error.TooManySnapshotLinks;
        break :blk stmt.columnInt64(0);
    };
    try tx.commit();
    return .{ .token = token, .link = .{
        .id = id,
        .subject = prepared.messages[0].subject,
        .message_count = @intCast(prepared.messages.len),
        .expires_at = expires_at,
    } };
}

pub fn list(a: std.mem.Allocator, db: *database.Database, owner: []const u8, now: i64) ![]Link {
    const stmt = try db.prepare(
        \\SELECT id,subject,message_count,expires_at FROM mail_snapshot_links
        \\WHERE user_id=(SELECT id FROM users WHERE username=?1 AND enabled=1) AND expires_at>?2 ORDER BY id DESC
    );
    defer stmt.finalize();
    try stmt.bind(1, owner);
    try stmt.bind(2, now);
    var links: std.ArrayList(Link) = .empty;
    while (try stmt.step()) try links.append(a, .{
        .id = stmt.columnInt64(0),
        .subject = try a.dupe(u8, stmt.columnText(1)),
        .message_count = stmt.columnInt64(2),
        .expires_at = stmt.columnInt64(3),
    });
    return links.toOwnedSlice(a);
}

pub fn read(a: std.mem.Allocator, db: *database.Database, token: []const u8, now: i64) !?View {
    if (!link_tokens.valid(token)) return null;
    const hash = link_tokens.digest(token);
    const stmt = try db.prepare(
        \\SELECT link.payload,link.expires_at FROM mail_snapshot_links AS link JOIN users ON users.id=link.user_id
        \\WHERE link.token_hash=?1 AND link.expires_at>?2 AND users.enabled=1
    );
    defer stmt.finalize();
    try stmt.bind(1, @as([]const u8, &hash));
    try stmt.bind(2, now);
    if (!try stmt.step()) return null;
    return .{ .payload = try a.dupe(u8, stmt.columnText(0)), .expires_at = stmt.columnInt64(1) };
}

pub fn revoke(db: *database.Database, owner: []const u8, id: i64) !bool {
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const stmt = try tx.prepare(
        \\DELETE FROM mail_snapshot_links WHERE id=?2 AND user_id=(SELECT id FROM users WHERE username=?1 AND enabled=1) RETURNING id
    );
    defer stmt.finalize();
    try stmt.bind(1, owner);
    try stmt.bind(2, id);
    if (!try stmt.step()) return false;
    _ = try stmt.step();
    try tx.commit();
    return true;
}

pub fn sweep(db: *database.Database, now: i64) !void {
    const stmt = try db.prepare("DELETE FROM mail_snapshot_links WHERE expires_at <= ?1");
    defer stmt.finalize();
    try stmt.bind(1, now);
    _ = try stmt.step();
}
