//! Identity-bound conversations shared between two mailboxes in the same team.
const std = @import("std");
const ascii = @import("ascii-compat");
const database = @import("../storage/database.zig");
const message_refs = @import("../storage/message_refs.zig");
const thread_ids = @import("../message/thread_ids.zig");
const teams = @import("../storage/team_store.zig");
const maildir = @import("webmail_maildir.zig");
const store = @import("webmail_store.zig");
const snapshots = @import("webmail_snapshots.zig");
const link_tokens = @import("webmail_link_tokens.zig");

const Allocator = std.mem.Allocator;
const Database = database.Database;
const Statement = database.Statement;
const max_shares = 30;
const max_comments = 64;
pub const max_followed_replies: i64 = 40;
const max_reply_text = 8192;
const collection_page_size = 20;
const max_collection_parts = 24;

pub const schema =
    \\CREATE TABLE IF NOT EXISTS mail_team_thread_shares (
    \\    id TEXT PRIMARY KEY NOT NULL,
    \\    team_id TEXT NOT NULL,
    \\    owner_id INTEGER NOT NULL,
    \\    grantee_id INTEGER NOT NULL,
    \\    subject TEXT NOT NULL,
    \\    downloads INTEGER NOT NULL CHECK(downloads IN (0,1)),
    \\    CHECK(owner_id<>grantee_id),
    \\    FOREIGN KEY(team_id,owner_id) REFERENCES mail_team_members(team_id,user_id) ON DELETE CASCADE,
    \\    FOREIGN KEY(team_id,grantee_id) REFERENCES mail_team_members(team_id,user_id) ON DELETE CASCADE
    \\);
    \\CREATE INDEX IF NOT EXISTS mail_team_thread_owner ON mail_team_thread_shares(owner_id);
    \\CREATE INDEX IF NOT EXISTS mail_team_thread_grantee ON mail_team_thread_shares(grantee_id);
    \\CREATE TABLE IF NOT EXISTS mail_team_collection_shares (
    \\    share_id TEXT PRIMARY KEY NOT NULL REFERENCES mail_team_thread_shares(id) ON DELETE CASCADE,
    \\    owner_id INTEGER NOT NULL,
    \\    collection_id TEXT NOT NULL,
    \\    FOREIGN KEY(owner_id,collection_id) REFERENCES mail_private_collections(user_id,id) ON DELETE CASCADE
    \\);
    \\CREATE INDEX IF NOT EXISTS mail_team_collection_owner ON mail_team_collection_shares(owner_id,collection_id);
    \\CREATE TRIGGER IF NOT EXISTS mail_team_collection_delete BEFORE DELETE ON mail_private_collections BEGIN
    \\    DELETE FROM mail_team_thread_shares WHERE id IN (SELECT share_id FROM mail_team_collection_shares
    \\        WHERE owner_id=OLD.user_id AND collection_id=OLD.id);
    \\END;
    \\CREATE TABLE IF NOT EXISTS mail_team_thread_messages (
    \\    share_id TEXT NOT NULL REFERENCES mail_team_thread_shares(id) ON DELETE CASCADE,
    \\    reference TEXT NOT NULL,
    \\    content_revision TEXT NOT NULL,
    \\    PRIMARY KEY(share_id,reference)
    \\);
    \\CREATE TABLE IF NOT EXISTS mail_team_thread_comments (
    \\    id INTEGER PRIMARY KEY,
    \\    share_id TEXT NOT NULL REFERENCES mail_team_thread_shares(id) ON DELETE CASCADE,
    \\    author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    \\    written_at INTEGER NOT NULL,
    \\    text TEXT NOT NULL
    \\);
    \\CREATE INDEX IF NOT EXISTS mail_team_thread_comment_share ON mail_team_thread_comments(share_id);
    \\CREATE TABLE IF NOT EXISTS mail_team_thread_follow (
    \\    share_id TEXT PRIMARY KEY NOT NULL REFERENCES mail_team_thread_shares(id) ON DELETE CASCADE,
    \\    since_ms INTEGER NOT NULL,
    \\    authors TEXT NOT NULL CHECK(json_valid(authors)),
    \\    anchors TEXT NOT NULL CHECK(json_valid(anchors))
    \\);
    \\CREATE TABLE IF NOT EXISTS mail_team_thread_replies (
    \\    share_id TEXT NOT NULL REFERENCES mail_team_thread_follow(share_id) ON DELETE CASCADE,
    \\    reference TEXT NOT NULL,
    \\    content_revision TEXT NOT NULL,
    \\    wire_id TEXT NOT NULL,
    \\    notice_at INTEGER NOT NULL DEFAULT 0,
    \\    PRIMARY KEY(share_id,reference),
    \\    UNIQUE(share_id,wire_id)
    \\);
;

// Run after the journal has registered the exact filed copy. Automatic mail
// follows a direct parent, from one of the senders seen in the owner's preview.
pub const record_reply_sql =
    \\INSERT OR IGNORE INTO mail_team_thread_replies(share_id,reference,content_revision,wire_id,notice_at)
    \\SELECT s.id,r.reference,?4,?5,
    \\ CASE WHEN m.author<>grantee.username COLLATE NOCASE
    \\       AND EXISTS(SELECT 1 FROM mail_notification_settings WHERE user_id=s.grantee_id AND enabled=1)
    \\      THEN unixepoch() ELSE 0 END
    \\FROM accepted_mail_targets t JOIN accepted_mail m ON m.id=t.delivery_id
    \\JOIN mailbox_message_refs r ON r.user_id=t.mailbox_id
    \\ AND r.folder=IIF(t.folder='new','INBOX',t.folder) AND r.basename=?3 AND r.file_stamp=?8
    \\JOIN mail_team_thread_shares s ON s.owner_id=t.mailbox_id
    \\JOIN mail_team_thread_follow f ON f.share_id=s.id
    \\JOIN users owner ON owner.id=s.owner_id AND owner.enabled=1
    \\JOIN users grantee ON grantee.id=s.grantee_id AND grantee.enabled=1
    \\WHERE t.delivery_id=?1 AND t.ordinal=?2 AND t.is_primary=1 AND t.verified_forward=0
    \\ AND t.folder IN ('new','Newsletters','Receipts') AND t.placement_reason NOT IN ('spam_filter','junk_feedback')
    \\ AND m.verified_author=1 AND m.accepted_ms>f.since_ms AND m.author<>owner.username COLLATE NOCASE
    \\ AND EXISTS(SELECT 1 FROM json_each(f.authors) WHERE value=m.author COLLATE NOCASE)
    \\ AND NOT EXISTS(SELECT 1 FROM json_each(f.anchors) WHERE value=?5)
    \\ AND (EXISTS(SELECT 1 FROM json_each(f.anchors) WHERE value=?6)
    \\      OR EXISTS(SELECT 1 FROM mail_team_thread_replies p WHERE p.share_id=s.id AND p.wire_id=?6))
    \\ AND (SELECT count(*) FROM mail_team_thread_replies p WHERE p.share_id=s.id)<?7
;

const authorized =
    \\ FROM mail_team_thread_shares s
    \\ JOIN users owner ON owner.id=s.owner_id AND owner.enabled=1
    \\ JOIN users grantee ON grantee.id=s.grantee_id
    \\ LEFT JOIN mail_team_collection_shares link ON link.share_id=s.id
    \\ LEFT JOIN mail_private_collections c ON c.user_id=s.owner_id AND c.id=link.collection_id
    \\ WHERE (owner.username=?1 OR (grantee.username=?1 AND grantee.enabled=1))
    \\ AND (link.share_id IS NULL OR c.id IS NOT NULL)
;
const share_fields =
    \\SELECT s.id,s.team_id,owner.username,grantee.username,COALESCE(c.name,s.subject),s.downloads,
    \\ COALESCE((SELECT authors FROM mail_team_thread_follow WHERE share_id=s.id),'[]'),
    \\ (SELECT count(*) FROM mail_team_thread_replies WHERE share_id=s.id),c.id
;

pub const Grant = struct {
    id: []const u8,
    team: []const u8,
    owner: []const u8,
    grantee: []const u8,
    subject: []const u8,
    downloads: bool,
    followingAuthors: []const []const u8,
    replyLimitReached: bool,
    collectionId: ?[]const u8 = null,
};
const Selection = struct { reference: []const u8, revision: [64]u8, reply: bool = false };
const Attachment = struct { index: usize, filename: []const u8, size: usize };
const Message = struct {
    reference: []const u8,
    subject: []const u8,
    from: []const u8,
    timestamp: i64,
    text: []const u8,
    attachments: []Attachment,
    verifiedReply: bool = false,
    truncated: bool = false,
};
const Comment = struct { author: []const u8, writtenAt: i64, text: []const u8 };
pub const Prepared = struct {
    selection: []Selection,
    messages: []Message,
    digest: [64]u8,
    downloads: bool,
    authors: []const []const u8,
    anchors: []const []const u8,
};
pub const Detail = struct { grant: Grant, messages: []Message, comments: []Comment, next: ?i64 = null };
const Collection = struct { id: []const u8, name: []const u8, revision: i64 };
const CollectionEntry = struct { position: i64, reference: []const u8 };
const CollectionPage = struct { messages: []Message, next: ?i64 };
pub const CollectionPreview = struct { collection: Collection, page: CollectionPage, digest: [64]u8 };

fn bind(stmt: Statement, args: anytype) !void {
    inline for (args, 1..) |value, i| try stmt.bind(i, value);
}

fn readGrant(a: Allocator, stmt: Statement) !Grant {
    return .{
        .id = try a.dupe(u8, stmt.columnText(0)),
        .team = try a.dupe(u8, stmt.columnText(1)),
        .owner = try a.dupe(u8, stmt.columnText(2)),
        .grantee = try a.dupe(u8, stmt.columnText(3)),
        .subject = try a.dupe(u8, stmt.columnText(4)),
        .downloads = stmt.columnInt64(5) != 0,
        .followingAuthors = try std.json.parseFromSliceLeaky([]const []const u8, a, stmt.columnText(6), .{ .allocate = .alloc_always }),
        .replyLimitReached = stmt.columnInt64(7) >= max_followed_replies,
        .collectionId = if (stmt.columnIsNull(8)) null else try a.dupe(u8, stmt.columnText(8)),
    };
}

pub fn list(a: Allocator, db: *Database, actor: []const u8) ![]Grant {
    const stmt = try db.prepare(share_fields ++ authorized ++ " ORDER BY s.rowid DESC");
    defer stmt.finalize();
    try stmt.bind(1, actor);
    var out: std.ArrayList(Grant) = .empty;
    while (try stmt.step()) try out.append(a, try readGrant(a, stmt));
    return out.toOwnedSlice(a);
}

pub fn available(db: *Database, actor: []const u8) !bool {
    const stmt = try db.prepare(
        \\SELECT 1 FROM mail_team_members m JOIN users u ON u.id=m.user_id
        \\WHERE u.username=?1 AND u.enabled=1 LIMIT 1
    );
    defer stmt.finalize();
    try stmt.bind(1, actor);
    return stmt.step();
}

fn lookup(a: Allocator, tx: Database.Transaction, actor: []const u8, id: []const u8) !Grant {
    const stmt = try tx.prepare(share_fields ++ authorized ++ " AND s.id=?2");
    defer stmt.finalize();
    try bind(stmt, .{ actor, id });
    if (!try stmt.step()) return error.ThreadShareUnavailable;
    return readGrant(a, stmt);
}

pub fn requireGrant(a: Allocator, db: *Database, actor: []const u8, id: []const u8) !Grant {
    var tx = try db.beginTransaction(.read);
    defer tx.deinit();
    const grant = try lookup(a, tx, actor, id);
    try tx.commit();
    return grant;
}

fn downloadable(part: maildir.AttachmentInfo) bool {
    // Attached messages can expose their own envelope headers and drafts.
    return part.content_id.len == 0 and !std.ascii.startsWithIgnoreCase(part.content_type, "message/") and
        !std.ascii.endsWithIgnoreCase(part.filename, ".eml") and !std.ascii.endsWithIgnoreCase(part.filename, ".msg");
}

fn collectionDownloadable(part: maildir.AttachmentInfo, index: usize) bool {
    return index < max_collection_parts and part.filename.len <= 512 and
        std.unicode.utf8ValidateSlice(part.filename) and downloadable(part);
}

fn project(a: Allocator, scratch: Allocator, item: maildir.MessageDetail, downloads: bool, remaining: *usize) !Message {
    const text = try snapshots.plainText(scratch, item);
    for ([_][]const u8{ item.subject, item.from, text }) |field| {
        if (field.len > remaining.*) return error.ThreadShareTooLarge;
        if (!std.unicode.utf8ValidateSlice(field)) return error.InvalidThreadShare;
        remaining.* -= field.len;
    }
    var attachments: std.ArrayList(Attachment) = .empty;
    if (downloads) for (item.attachments, 0..) |part, index| {
        if (!downloadable(part) or !std.unicode.utf8ValidateSlice(part.filename)) continue;
        if (part.filename.len > remaining.* or remaining.* - part.filename.len < 64) return error.ThreadShareTooLarge;
        remaining.* -= part.filename.len + 64;
        try attachments.append(a, .{ .index = index, .filename = try a.dupe(u8, part.filename), .size = part.size });
    };
    return .{
        .reference = try a.dupe(u8, item.version.?.reference),
        .subject = try a.dupe(u8, item.subject),
        .from = try a.dupe(u8, item.from),
        .timestamp = item.timestamp,
        .text = try a.dupe(u8, text),
        .attachments = try attachments.toOwnedSlice(a),
    };
}

fn appendUnique(a: Allocator, values: *std.ArrayList([]const u8), value: []const u8) !void {
    for (values.items) |current| if (std.mem.eql(u8, current, value)) return;
    try values.append(a, try a.dupe(u8, value));
}

pub fn prepare(a: Allocator, db: *Database, actor: []const u8, refs: []const []const u8, downloads: bool, follow: bool, junk: []const u8) !Prepared {
    if (refs.len == 0 or refs.len > snapshots.max_messages) return error.InvalidThreadShare;
    const messages = try a.alloc(Message, refs.len);
    const selection = try a.alloc(Selection, refs.len);
    var remaining: usize = snapshots.max_bytes;
    var authors: std.ArrayList([]const u8) = .empty;
    var anchors: std.ArrayList([]const u8) = .empty;
    for (refs, 0..) |ref, i| {
        if (!message_refs.valid(ref)) return error.InvalidThreadShare;
        for (refs[0..i]) |previous| if (std.mem.eql(u8, ref, previous)) return error.InvalidThreadShare;
        var work = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer work.deinit();
        const scratch = work.allocator();
        const item = try maildir.getByReference(scratch, db, actor, ref);
        if (!snapshots.canShare(item, junk)) return error.ThreadShareUnavailable;
        messages[i] = try project(a, scratch, item, downloads, &remaining);
        selection[i] = .{ .reference = ref, .revision = item.version.?.content_revision };
        if (follow) {
            var ids: thread_ids.Iterator = .{ .text = item.message_id };
            if (ids.next()) |id| try appendUnique(a, &anchors, id);
            if (try message_refs.placement(scratch, db, actor, ref)) |placement| {
                if (placement.verified_author.len != 0 and !std.ascii.eqlIgnoreCase(placement.verified_author, actor))
                    try appendUnique(a, &authors, try std.ascii.allocLowerString(scratch, placement.verified_author));
            }
        }
    }
    if (follow and (authors.items.len == 0 or anchors.items.len == 0)) return error.ThreadFollowUnavailable;
    const payload = try std.json.Stringify.valueAlloc(a, .{
        .selection = selection,
        .downloads = downloads,
        .authors = authors.items,
        .anchors = anchors.items,
    }, .{});
    return .{
        .selection = selection,
        .messages = messages,
        .digest = link_tokens.digest(payload),
        .downloads = downloads,
        .authors = try authors.toOwnedSlice(a),
        .anchors = try anchors.toOwnedSlice(a),
    };
}

fn insertGrant(tx: Database.Transaction, id: []const u8, actor: []const u8, team: []const u8, grantee: []const u8, subject: []const u8, downloads: bool) !void {
    if (!teams.validTeamId(team) or grantee.len == 0 or grantee.len > 320 or std.mem.eql(u8, actor, grantee))
        return error.InvalidThreadShare;
    const stmt = try tx.prepare(
        \\INSERT INTO mail_team_thread_shares(id,team_id,owner_id,grantee_id,subject,downloads)
        \\SELECT ?1,?2,owner.id,grantee.id,?5,?6
        \\FROM users owner JOIN mail_team_members own ON own.user_id=owner.id AND own.team_id=?2
        \\JOIN mail_team_members member ON member.team_id=own.team_id AND member.user_id<>own.user_id
        \\JOIN users grantee ON grantee.id=member.user_id
        \\WHERE owner.username=?3 AND owner.enabled=1 AND grantee.username=?4 AND grantee.enabled=1
        \\AND (SELECT count(*) FROM mail_team_thread_shares WHERE owner_id=owner.id)<?7
        \\RETURNING id
    );
    defer stmt.finalize();
    try bind(stmt, .{ id, team, actor, grantee, subject, @intFromBool(downloads), @as(i64, max_shares) });
    if (!try stmt.step()) return error.ThreadShareGrantUnavailable;
}

pub fn create(a: Allocator, db: *Database, actor: []const u8, team: []const u8, grantee: []const u8, prepared: Prepared, now_ms: i64) !Grant {
    const id = try store.newId(a);
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    try insertGrant(tx, id, actor, team, grantee, prepared.messages[0].subject, prepared.downloads);
    {
        const stmt = try tx.prepare("INSERT INTO mail_team_thread_messages(share_id,reference,content_revision) VALUES(?1,?2,?3)");
        defer stmt.finalize();
        for (prepared.selection) |item| {
            try bind(stmt, .{ id, item.reference, @as([]const u8, &item.revision) });
            _ = try stmt.step();
            try stmt.reset();
        }
    }
    if (prepared.authors.len != 0) {
        const stmt = try tx.prepare("INSERT INTO mail_team_thread_follow(share_id,since_ms,authors,anchors) VALUES(?1,?2,?3,?4)");
        defer stmt.finalize();
        const authors = try std.json.Stringify.valueAlloc(a, prepared.authors, .{});
        const anchors = try std.json.Stringify.valueAlloc(a, prepared.anchors, .{});
        try bind(stmt, .{ id, now_ms, authors, anchors });
        _ = try stmt.step();
    }
    const grant = try lookup(a, tx, actor, id);
    try tx.commit();
    return grant;
}

fn readCollection(a: Allocator, tx: Database.Transaction, actor: []const u8, id: []const u8) !Collection {
    const stmt = try tx.prepare(
        \\SELECT c.name,c.revision FROM mail_private_collections c JOIN users o ON o.id=c.user_id
        \\WHERE o.username=?1 AND o.enabled=1 AND c.id=?2
    );
    defer stmt.finalize();
    try bind(stmt, .{ actor, id });
    if (!try stmt.step()) return error.ThreadShareUnavailable;
    return .{ .id = id, .name = try a.dupe(u8, stmt.columnText(0)), .revision = stmt.columnInt64(1) };
}

fn collectionDigest(a: Allocator, collection: Collection, downloads: bool) ![64]u8 {
    const payload = try std.json.Stringify.valueAlloc(a, .{ .collection = collection, .downloads = downloads }, .{});
    return link_tokens.digest(payload);
}

pub fn createCollection(a: Allocator, db: *Database, actor: []const u8, team: []const u8, grantee: []const u8, collection_id: []const u8, downloads: bool, expected: []const u8) !Grant {
    if (!message_refs.valid(collection_id)) return error.InvalidThreadShare;
    const id = try store.newId(a);
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const collection = try readCollection(a, tx, actor, collection_id);
    const digest = try collectionDigest(a, collection, downloads);
    if (!std.mem.eql(u8, &digest, expected)) return error.ThreadShareChanged;
    try insertGrant(tx, id, actor, team, grantee, collection.name, downloads);
    {
        const stmt = try tx.prepare(
            \\INSERT INTO mail_team_collection_shares(share_id,owner_id,collection_id)
            \\SELECT id,owner_id,?2 FROM mail_team_thread_shares WHERE id=?1
            \\AND NOT EXISTS(SELECT 1 FROM mail_team_collection_shares l
            \\    JOIN mail_team_thread_shares current ON current.id=l.share_id
            \\    JOIN mail_team_thread_shares newest ON newest.id=?1
            \\    WHERE l.owner_id=newest.owner_id AND l.collection_id=?2
            \\      AND current.team_id=newest.team_id AND current.grantee_id=newest.grantee_id)
            \\RETURNING share_id
        );
        defer stmt.finalize();
        try bind(stmt, .{ id, collection_id });
        if (!try stmt.step()) return error.CollectionAlreadyShared;
    }
    const grant = try lookup(a, tx, actor, id);
    try tx.commit();
    return grant;
}

pub fn revoke(db: *Database, actor: []const u8, id: []const u8) !void {
    const stmt = try db.prepare(
        \\DELETE FROM mail_team_thread_shares WHERE id=?2
        \\AND owner_id=(SELECT id FROM users WHERE username=?1 AND enabled=1) RETURNING id
    );
    defer stmt.finalize();
    try bind(stmt, .{ actor, id });
    if (!try stmt.step()) return error.ThreadShareUnavailable;
}

fn selected(a: Allocator, tx: Database.Transaction, id: []const u8, ref: ?[]const u8) ![]Selection {
    const stmt = try tx.prepare(
        \\SELECT reference,content_revision,0 AS reply,rowid AS arrival FROM mail_team_thread_messages
        \\WHERE share_id=?1 AND (?2 IS NULL OR reference=?2)
        \\UNION ALL
        \\SELECT reference,content_revision,1 AS reply,rowid AS arrival FROM mail_team_thread_replies
        \\WHERE share_id=?1 AND ?2 IS NULL
        \\ORDER BY reply,arrival
    );
    defer stmt.finalize();
    try stmt.bind(1, id);
    try stmt.bindOpt(2, ref);
    var out: std.ArrayList(Selection) = .empty;
    while (try stmt.step()) {
        const revision = stmt.columnText(1);
        if (revision.len != 64) return error.InvalidThreadShare;
        try out.append(a, .{
            .reference = try a.dupe(u8, stmt.columnText(0)),
            .revision = revision[0..64].*,
            .reply = stmt.columnInt64(2) != 0,
        });
    }
    return out.toOwnedSlice(a);
}

fn matchesSearch(subject: []const u8, from: []const u8, text: []const u8, needle: []const u8) bool {
    return needle.len == 0 or ascii.indexOfIgnoreCase(subject, needle) != null or
        ascii.indexOfIgnoreCase(from, needle) != null or ascii.indexOfIgnoreCase(text, needle) != null;
}

fn excerpt(msg: maildir.MessageDetail, text: []const u8, reply: bool) Message {
    var end = @min(text.len, max_reply_text);
    while (end != 0 and end < text.len and text[end] & 0xc0 == 0x80) end -= 1;
    // Sender or subject fields can be large too. Keep the shared reader
    // available when an automatic arrival exceeds the manual preview budget.
    const subject = if (msg.subject.len <= 1024 and std.unicode.utf8ValidateSlice(msg.subject)) msg.subject else "";
    const from = if (msg.from.len <= 1024 and std.unicode.utf8ValidateSlice(msg.from)) msg.from else "";
    const valid = std.unicode.utf8ValidateSlice(text[0..end]);
    return .{
        .reference = msg.version.?.reference,
        .subject = subject,
        .from = from,
        .timestamp = msg.timestamp,
        .text = if (valid) text[0..end] else "",
        .attachments = &.{},
        .verifiedReply = reply,
        .truncated = end < text.len or !valid,
    };
}

fn copyExcerpt(a: Allocator, excerpted: Message) !Message {
    var copy = excerpted;
    copy.reference = try a.dupe(u8, excerpted.reference);
    copy.subject = try a.dupe(u8, excerpted.subject);
    copy.from = try a.dupe(u8, excerpted.from);
    copy.text = try a.dupe(u8, excerpted.text);
    return copy;
}

fn collectionEntries(a: Allocator, tx: Database.Transaction, owner: []const u8, collection: []const u8, before: ?i64) ![]CollectionEntry {
    // Exact owner additions are the grant scope. Never traverse the private
    // conversation graph or trust an incoming message's References here.
    const stmt = try tx.prepare(
        \\SELECT m.rowid,m.anchor FROM mail_private_members m JOIN users o ON o.id=m.user_id
        \\WHERE o.username=?1 AND m.collection=?2 AND (?3 IS NULL OR m.rowid<?3)
        \\ORDER BY m.rowid DESC LIMIT ?4
    );
    defer stmt.finalize();
    try bind(stmt, .{ owner, collection });
    try stmt.bindOpt(3, before);
    try stmt.bind(4, @as(i64, collection_page_size + 1));
    var entries: std.ArrayList(CollectionEntry) = .empty;
    while (try stmt.step()) try entries.append(a, .{
        .position = stmt.columnInt64(0),
        .reference = try a.dupe(u8, stmt.columnText(1)),
    });
    return entries.toOwnedSlice(a);
}

fn collectionMessage(a: Allocator, db: *Database, owner: []const u8, reference: []const u8, junk: []const u8) !maildir.MessageDetail {
    const msg = try maildir.getByReference(a, db, owner, reference);
    if (!snapshots.canShare(msg, junk)) return error.ThreadShareUnavailable;
    return msg;
}

fn collectionPage(a: Allocator, db: *Database, owner: []const u8, entries: []const CollectionEntry, downloads: bool, needle: []const u8, junk: []const u8) !CollectionPage {
    var messages: std.ArrayList(Message) = .empty;
    const count = @min(entries.len, collection_page_size);
    for (entries[0..count]) |entry| {
        var work = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer work.deinit();
        const scratch = work.allocator();
        const msg = collectionMessage(scratch, db, owner, entry.reference, junk) catch |err| switch (err) {
            error.ThreadShareUnavailable, maildir.MaildirError.MessageNotFound, error.FileNotFound => continue,
            else => return err,
        };
        const preview = excerpt(msg, try snapshots.plainText(scratch, msg), false);
        if (!matchesSearch(preview.subject, preview.from, preview.text, needle)) continue;
        var projected = try copyExcerpt(a, preview);
        var parts: std.ArrayList(Attachment) = .empty;
        if (downloads) for (msg.attachments[0..@min(msg.attachments.len, max_collection_parts)], 0..) |part, index| {
            if (collectionDownloadable(part, index)) try parts.append(a, .{
                .index = index,
                .filename = try a.dupe(u8, part.filename),
                .size = part.size,
            });
        };
        projected.attachments = try parts.toOwnedSlice(a);
        try messages.append(a, projected);
    }
    return .{
        .messages = try messages.toOwnedSlice(a),
        .next = if (entries.len > count) entries[count - 1].position else null,
    };
}

pub fn previewCollection(a: Allocator, db: *Database, actor: []const u8, id: []const u8, downloads: bool, junk: []const u8) !CollectionPreview {
    if (!message_refs.valid(id)) return error.InvalidThreadShare;
    const result = blk: {
        var tx = try db.beginTransaction(.read);
        defer tx.deinit();
        const collection = try readCollection(a, tx, actor, id);
        const entries = try collectionEntries(a, tx, actor, id, null);
        try tx.commit();
        break :blk .{ .collection = collection, .entries = entries };
    };
    return .{
        .collection = result.collection,
        .digest = try collectionDigest(a, result.collection, downloads),
        .page = try collectionPage(a, db, actor, result.entries, downloads, "", junk),
    };
}

fn canReadCollectionEntry(stmt: Statement, owner: []const u8, collection: []const u8, ref: []const u8) !bool {
    try bind(stmt, .{ owner, collection, ref });
    const found = try stmt.step();
    try stmt.reset();
    return found;
}

fn collectionPermission(tx: Database.Transaction) !Statement {
    return tx.prepare(
        \\SELECT 1 FROM mail_private_members m JOIN users o ON o.id=m.user_id
        \\WHERE o.username=?1 AND m.collection=?2 AND m.anchor=?3
    );
}

fn loadMessage(a: Allocator, db: *Database, owner: []const u8, item: Selection, junk: []const u8) !maildir.MessageDetail {
    const msg = try maildir.getByReference(a, db, owner, item.reference);
    if (!snapshots.canShare(msg, junk) or !std.mem.eql(u8, &msg.version.?.content_revision, &item.revision))
        return error.ThreadShareUnavailable;
    return msg;
}

fn comments(a: Allocator, tx: Database.Transaction, id: []const u8) ![]Comment {
    const stmt = try tx.prepare(
        \\SELECT users.username,c.written_at,c.text FROM mail_team_thread_comments c
        \\JOIN users ON users.id=c.author_id WHERE c.share_id=?1 ORDER BY c.id
    );
    defer stmt.finalize();
    try stmt.bind(1, id);
    var out: std.ArrayList(Comment) = .empty;
    while (try stmt.step()) try out.append(a, .{
        .author = try a.dupe(u8, stmt.columnText(0)),
        .writtenAt = stmt.columnInt64(1),
        .text = try a.dupe(u8, stmt.columnText(2)),
    });
    return out.toOwnedSlice(a);
}

pub fn detail(a: Allocator, db: *Database, actor: []const u8, id: []const u8, needle: []const u8, before: ?i64, junk: []const u8) !Detail {
    if (needle.len > 256 or !std.unicode.utf8ValidateSlice(needle) or (before != null and before.? < 1)) return error.InvalidThreadShare;
    const result = blk: {
        var tx = try db.beginTransaction(.read);
        defer tx.deinit();
        const grant = try lookup(a, tx, actor, id);
        if (grant.collectionId == null and before != null) return error.InvalidThreadShare;
        const items = if (grant.collectionId == null) try selected(a, tx, id, null) else &.{};
        const entries = if (grant.collectionId) |collection| try collectionEntries(a, tx, grant.owner, collection, before) else &.{};
        const notes = try comments(a, tx, id);
        try tx.commit();
        break :blk .{ .grant = grant, .items = items, .entries = entries, .notes = notes };
    };
    if (result.grant.collectionId) |collection| {
        const page = try collectionPage(a, db, result.grant.owner, result.entries, result.grant.downloads, needle, junk);
        var tx = try db.beginTransaction(.read);
        defer tx.deinit();
        const grant = try lookup(a, tx, actor, id);
        var kept: usize = 0;
        {
            const membership = try collectionPermission(tx);
            defer membership.finalize();
            for (page.messages) |msg| {
                if (!try canReadCollectionEntry(membership, grant.owner, collection, msg.reference)) continue;
                page.messages[kept] = msg;
                kept += 1;
            }
        }
        try tx.commit();
        return .{ .grant = grant, .messages = page.messages[0..kept], .comments = result.notes, .next = page.next };
    }
    var messages: std.ArrayList(Message) = .empty;
    var remaining: usize = snapshots.max_bytes;
    for (result.items) |item| {
        var work = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer work.deinit();
        const scratch = work.allocator();
        const msg = loadMessage(scratch, db, result.grant.owner, item, junk) catch |err| switch (err) {
            error.ThreadShareUnavailable, maildir.MaildirError.MessageNotFound, error.FileNotFound => continue,
            else => return err,
        };
        if (item.reply) {
            const reply = excerpt(msg, try snapshots.plainText(scratch, msg), true);
            if (matchesSearch(reply.subject, reply.from, reply.text, needle))
                try messages.append(a, try copyExcerpt(a, reply));
            continue;
        }
        const projected = try project(a, scratch, msg, result.grant.downloads, &remaining);
        if (!matchesSearch(projected.subject, projected.from, projected.text, needle)) continue;
        try messages.append(a, projected);
    }
    _ = try requireGrant(a, db, actor, id);
    return .{ .grant = result.grant, .messages = try messages.toOwnedSlice(a), .comments = result.notes };
}

const notice_access =
    \\ FROM mail_team_thread_replies r
    \\ JOIN mail_team_thread_shares s ON s.id=r.share_id
    \\ JOIN users owner ON owner.id=s.owner_id AND owner.enabled=1
    \\ JOIN users grantee ON grantee.id=s.grantee_id AND grantee.enabled=1
    \\ JOIN mail_notification_settings prefs ON prefs.user_id=grantee.id AND prefs.enabled=1
    \\ WHERE grantee.username=?1 AND r.notice_at>=unixepoch()-180
;
const Notice = struct { id: i64, grant: []const u8, owner: []const u8, item: Selection };

fn pendingNotices(a: Allocator, db: *Database, actor: []const u8) ![]Notice {
    const stmt = try db.prepare("SELECT r.rowid,r.share_id,owner.username,r.reference,r.content_revision" ++ notice_access ++ " ORDER BY r.rowid LIMIT 10");
    defer stmt.finalize();
    try stmt.bind(1, actor);
    var out: std.ArrayList(Notice) = .empty;
    while (try stmt.step()) {
        const revision = stmt.columnText(4);
        if (revision.len != 64) return error.InvalidThreadShare;
        try out.append(a, .{
            .id = stmt.columnInt64(0),
            .grant = try a.dupe(u8, stmt.columnText(1)),
            .owner = try a.dupe(u8, stmt.columnText(2)),
            .item = .{ .reference = try a.dupe(u8, stmt.columnText(3)), .revision = revision[0..64].*, .reply = true },
        });
    }
    return out.toOwnedSlice(a);
}

/// Notify once, with no subject or sender in the browser push payload. Check
/// the pinned reply before claiming it and confirm membership again when
/// consuming the notice, so offboarding can invalidate a pending claim.
pub fn claimReplyNotices(a: Allocator, db: *Database, actor: []const u8, junk: []const u8) !usize {
    const pending = try pendingNotices(a, db, actor);
    var count: usize = 0;
    for (pending) |notice| {
        var work = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer work.deinit();
        const item = loadMessage(work.allocator(), db, notice.owner, notice.item, junk);
        const visible = if (item) |_| true else |err| switch (err) {
            error.ThreadShareUnavailable, maildir.MaildirError.MessageNotFound, error.FileNotFound => false,
            else => return err,
        };
        const stmt = try db.prepare(
            "UPDATE mail_team_thread_replies SET notice_at=0 WHERE rowid IN (SELECT r.rowid" ++ notice_access ++
                " AND r.rowid=?2 AND r.share_id=?3 AND r.reference=?4 AND r.content_revision=?5) RETURNING rowid",
        );
        defer stmt.finalize();
        try bind(stmt, .{ actor, notice.id, notice.grant, notice.item.reference, @as([]const u8, &notice.item.revision) });
        if (try stmt.step() and visible) count += 1;
    }
    return count;
}

pub fn attachment(a: Allocator, db: *Database, actor: []const u8, id: []const u8, ref: []const u8, index: usize, junk: []const u8) !maildir.AttachmentInfo {
    const result = blk: {
        var tx = try db.beginTransaction(.read);
        defer tx.deinit();
        const grant = try lookup(a, tx, actor, id);
        if (!grant.downloads) return error.ThreadShareUnavailable;
        const item = if (grant.collectionId) |collection| item: {
            const membership = try collectionPermission(tx);
            defer membership.finalize();
            if (!try canReadCollectionEntry(membership, grant.owner, collection, ref)) return error.ThreadShareUnavailable;
            break :item null;
        } else item: {
            const exact = try selected(a, tx, id, ref);
            if (exact.len != 1) return error.ThreadShareUnavailable;
            break :item exact[0];
        };
        try tx.commit();
        break :blk .{ .grant = grant, .item = item };
    };
    if (result.item) |item| {
        const msg = try loadMessage(a, db, result.grant.owner, item, junk);
        if (index >= msg.attachments.len or !downloadable(msg.attachments[index])) return error.ThreadShareUnavailable;
        _ = try requireGrant(a, db, actor, id);
        return msg.attachments[index];
    }
    const msg = try collectionMessage(a, db, result.grant.owner, ref, junk);
    if (index >= msg.attachments.len or !collectionDownloadable(msg.attachments[index], index)) return error.ThreadShareUnavailable;
    var tx = try db.beginTransaction(.read);
    defer tx.deinit();
    const grant = try lookup(a, tx, actor, id);
    const collection = grant.collectionId orelse return error.ThreadShareUnavailable;
    if (!grant.downloads) return error.ThreadShareUnavailable;
    {
        const membership = try collectionPermission(tx);
        defer membership.finalize();
        if (!try canReadCollectionEntry(membership, grant.owner, collection, ref)) return error.ThreadShareUnavailable;
    }
    try tx.commit();
    return msg.attachments[index];
}

pub fn addComment(a: Allocator, db: *Database, actor: []const u8, id: []const u8, value: []const u8, now: i64) !void {
    const text = std.mem.trim(u8, value, " \t\r\n");
    if (text.len == 0 or text.len > 2000 or !std.unicode.utf8ValidateSlice(text)) return error.InvalidThreadShare;
    for (text) |byte| if ((byte < 32 and byte != '\n' and byte != '\r' and byte != '\t') or byte == 127) return error.InvalidThreadShare;
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    _ = try lookup(a, tx, actor, id);
    {
        const stmt = try tx.prepare(
            \\INSERT INTO mail_team_thread_comments(share_id,author_id,written_at,text)
            \\SELECT ?1,id,?3,?4 FROM users WHERE username=?2
            \\AND (SELECT count(*) FROM mail_team_thread_comments WHERE share_id=?1)<?5
            \\RETURNING id
        );
        defer stmt.finalize();
        try bind(stmt, .{ id, actor, now, text, @as(i64, max_comments) });
        if (!try stmt.step()) return error.ThreadShareCommentLimit;
    }
    try tx.commit();
}
