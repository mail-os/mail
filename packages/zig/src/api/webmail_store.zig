//! Account-scoped webmail state. Conditional SQL makes retries idempotent and
//! keeps queued sends cancellable only before the server dispatch deadline.
const std = @import("std");
const database = @import("../storage/database.zig");
const calendar_invite = @import("webmail_calendar_invite.zig");
const shared_inbox = @import("../storage/shared_inbox.zig");
const io_compat = @import("../core/io_compat.zig");

pub const StoreError = error{ Conflict, NotFound, StorageLimit, DraftStorageLimit, OutboxStorageLimit };
pub const terminal_retention = 7 * 86400;
pub const hosted_outbox_count = 1024;
// Up to 100 bounded envelope addresses may be repeated in the delivery result.
const outbox_result_reserve = 64 * 1024;
pub const Record = struct {
    username: []const u8,
    kind: []const u8,
    id: []const u8,
    payload: []const u8,
    state: []const u8,
    revision: i64,
    due_at: i64,
    expires_at: i64,
};
pub const Upload = struct {
    id: []const u8,
    filename: []const u8,
    content_type: []const u8,
    data: []const u8,
    content_id: []const u8 = "",
    inline_part: bool = false,
};

pub fn initSchema(db: *database.Database) !void {
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS webmail_records (
        \\ username TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL,
        \\ payload TEXT NOT NULL, state TEXT NOT NULL, revision INTEGER NOT NULL,
        \\ due_at INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL DEFAULT 0,
        \\ PRIMARY KEY(username, kind, id),
        \\ FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
        \\);
        \\CREATE INDEX IF NOT EXISTS webmail_pending ON webmail_records(kind,state,due_at);
        \\CREATE INDEX IF NOT EXISTS webmail_outbox_time ON webmail_records(username,due_at,id) WHERE kind='outbox';
        \\CREATE INDEX IF NOT EXISTS webmail_record_expiry ON webmail_records(expires_at) WHERE expires_at>0;
        \\CREATE TABLE IF NOT EXISTS webmail_uploads (
        \\ username TEXT NOT NULL, id TEXT NOT NULL, filename TEXT NOT NULL,
        \\ content_type TEXT NOT NULL, data BLOB NOT NULL, size INTEGER NOT NULL,
        \\ expires_at INTEGER NOT NULL, mime TEXT NOT NULL DEFAULT '{}', PRIMARY KEY(username,id),
        \\ FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
        \\);
        \\CREATE INDEX IF NOT EXISTS webmail_upload_expiry ON webmail_uploads(expires_at);
        \\CREATE TRIGGER IF NOT EXISTS webmail_enqueue_draft AFTER INSERT ON webmail_records
        \\WHEN new.kind='outbox' AND new.state='pending' AND json_valid(new.payload)
        \\BEGIN
        \\ UPDATE webmail_records SET state='queued',revision=revision+1
        \\ WHERE username=new.username AND kind='draft' AND state='saved'
        \\ AND id=json_extract(new.payload,'$.message.draftId')
        \\ AND revision=json_extract(new.payload,'$.message.draftRevision');
        \\END;
        \\CREATE TRIGGER IF NOT EXISTS webmail_cancel_queued_draft AFTER UPDATE OF state ON webmail_records
        \\WHEN old.kind='outbox' AND old.state='pending' AND new.state='cancelled' AND json_valid(old.payload)
        \\BEGIN
        \\ UPDATE webmail_records SET state='saved',revision=revision+1
        \\ WHERE username=old.username AND kind='draft' AND state='queued'
        \\ AND id=json_extract(old.payload,'$.message.draftId');
        \\END;
        \\CREATE TRIGGER IF NOT EXISTS webmail_outbox_shared_reply AFTER UPDATE OF state ON webmail_records
        \\WHEN NEW.kind='outbox' AND NEW.state<>OLD.state
        \\BEGIN
        \\ UPDATE mail_shared_reply_claims SET state=CASE NEW.state
        \\   WHEN 'sending' THEN 'sending' WHEN 'unknown' THEN 'review' ELSE 'replied' END
        \\ WHERE actor_id=(SELECT id FROM users WHERE username=NEW.username)
        \\ AND send_id=NEW.id AND NEW.state IN ('sending','unknown','sent','sent_unfiled','partial');
        \\ DELETE FROM mail_shared_reply_claims WHERE actor_id=(SELECT id FROM users WHERE username=NEW.username)
        \\ AND send_id=NEW.id AND NEW.state IN ('cancelled','failed');
        \\END;
        \\CREATE TRIGGER IF NOT EXISTS webmail_outbox_calendar_rsvp AFTER UPDATE OF state ON webmail_records
        \\WHEN NEW.kind='outbox' AND NEW.state<>OLD.state AND json_valid(NEW.payload)
        \\BEGIN
        \\ UPDATE webmail_records SET state=NEW.state,revision=revision+1
        \\ WHERE username=NEW.username AND kind='calendar-rsvp'
        \\ AND id=json_extract(NEW.payload,'$.calendarReply.key')
        \\ AND json_extract(payload,'$.sendId')=NEW.id;
        \\END;
        \\CREATE TRIGGER IF NOT EXISTS webmail_cancel_revoked_shared_replies AFTER DELETE ON mail_team_grants
        \\WHEN OLD.scope IN ('mailbox','sender') AND OLD.resource=''
        \\BEGIN
        \\ UPDATE webmail_records SET state='cancelled',revision=revision+1,expires_at=unixepoch()+604800,
        \\   payload=json_set(payload,'$.error_message','Team access changed before delivery. The shared reply was cancelled.')
        \\ WHERE kind='outbox' AND state='pending' AND username=(SELECT username FROM users WHERE id=OLD.grantee_id)
        \\ AND EXISTS(SELECT 1 FROM mail_shared_reply_claims r WHERE r.actor_id=OLD.grantee_id
        \\   AND r.team_id=OLD.team_id AND r.source_id=OLD.source_id AND r.send_id=webmail_records.id AND r.state='queued');
        \\END;
    );
    const has_mime_column = blk: {
        const s = try db.prepare("SELECT 1 FROM pragma_table_info('webmail_uploads') WHERE name='mime'");
        defer s.finalize();
        break :blk try s.step();
    };
    if (!has_mime_column) try db.exec("ALTER TABLE webmail_uploads ADD COLUMN mime TEXT NOT NULL DEFAULT '{}'");
}

pub fn newId(allocator: std.mem.Allocator) ![]const u8 {
    var bytes: [16]u8 = undefined;
    io_compat.randomBytes(&bytes);
    const output = try allocator.alloc(u8, 32);
    const digits = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        output[index * 2] = digits[byte >> 4];
        output[index * 2 + 1] = digits[byte & 15];
    }
    return output;
}

pub fn validId(id: []const u8) bool {
    if (id.len < 16 or id.len > 64) return false;
    for (id) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-') return false;
    return true;
}

fn readRecord(allocator: std.mem.Allocator, statement: database.Statement) !Record {
    return .{
        .username = try allocator.dupe(u8, statement.columnText(0)),
        .kind = try allocator.dupe(u8, statement.columnText(1)),
        .id = try allocator.dupe(u8, statement.columnText(2)),
        .payload = try allocator.dupe(u8, statement.columnText(3)),
        .state = try allocator.dupe(u8, statement.columnText(4)),
        .revision = statement.columnInt64(5),
        .due_at = statement.columnInt64(6),
        .expires_at = statement.columnInt64(7),
    };
}

pub fn get(allocator: std.mem.Allocator, db: *database.Database, user: []const u8, kind: []const u8, id: []const u8) !Record {
    const s = try db.prepare("SELECT username,kind,id,payload,state,revision,due_at,expires_at FROM webmail_records WHERE username=?1 AND kind=?2 AND id=?3");
    defer s.finalize();
    try s.bind(1, user);
    try s.bind(2, kind);
    try s.bind(3, id);
    if (!try s.step()) return StoreError.NotFound;
    return readRecord(allocator, s);
}

pub fn list(allocator: std.mem.Allocator, db: *database.Database, user: []const u8, kind: []const u8, limit: usize) ![]Record {
    const s = try db.prepare("SELECT username,kind,id,payload,state,revision,due_at,expires_at FROM webmail_records WHERE username=?1 AND kind=?2 ORDER BY (state IN ('pending','sending','unknown')) DESC,rowid DESC LIMIT ?3");
    defer s.finalize();
    try s.bind(1, user);
    try s.bind(2, kind);
    try s.bind(3, @min(limit, 200));
    var rows: std.ArrayList(Record) = .empty;
    while (try s.step()) try rows.append(allocator, try readRecord(allocator, s));
    return rows.toOwnedSlice(allocator);
}

pub const OutboxView = enum { overview, upcoming, review, history };
pub const OutboxCounts = struct { upcoming: i64, review: i64, history: i64 };
pub const OutboxSummary = struct {
    id: []const u8,
    state: []const u8,
    dueAt: i64,
    scheduled: bool,
    calendarRsvp: bool,
    message: struct { subject: []const u8, to: []const []const u8 },
    result: std.json.Value,
    @"error": ?[]const u8,
};
pub const OutboxPage = struct {
    items: []const OutboxSummary,
    counts: OutboxCounts,
    nextCursor: ?[]const u8,
    tracked: ?OutboxSummary,
};

const upcoming_states = "state IN ('pending','sending')";
const review_states = "state IN ('unknown','failed','partial','sent_unfiled')";
const history_states = "state IN ('sent','cancelled','resolved')";
const outbox_page_size = 20;

fn outboxPageSql(comptime filter: []const u8, comptime key: []const u8, comptime ascending: bool) []const u8 {
    const scope = " FROM webmail_records WHERE username=?1 AND kind='outbox'";
    const order = if (ascending) " ASC" else " DESC";
    const compare = if (ascending) ">" else "<";
    // Resolve the cursor within the same account and SQLite read snapshot as
    // the counts and page. The cursor's record can move to a different view.
    return "WITH anchor AS (SELECT " ++ key ++ ",id" ++ scope ++ " AND id=?2)," ++
        " totals AS (SELECT COUNT(*) FILTER (WHERE " ++ upcoming_states ++ ") AS upcoming," ++
        " COUNT(*) FILTER (WHERE " ++ review_states ++ ") AS review," ++
        " COUNT(*) FILTER (WHERE " ++ history_states ++ ") AS history" ++ scope ++ ")," ++
        " page AS (SELECT id" ++ scope ++ " AND (" ++ filter ++ ")" ++
        " AND (?2 IS NULL OR (" ++ key ++ ",id)" ++ compare ++ "(SELECT * FROM anchor))" ++
        " ORDER BY " ++ key ++ order ++ ",id" ++ order ++ " LIMIT ?4)," ++
        " ids AS (SELECT id,0 AS tracked FROM page UNION ALL SELECT id,1" ++ scope ++ " AND id=?3)" ++
        " SELECT upcoming,review,history,?2 IS NULL OR EXISTS(SELECT 1 FROM anchor)," ++
        " ids.tracked,r.id,r.state,r.due_at," ++
        " CASE WHEN json_valid(r.payload) THEN json_extract(r.payload,'$.message.subject') END," ++
        " CASE WHEN json_valid(r.payload) THEN json_extract(r.payload,'$.message.to') END," ++
        " CASE WHEN json_valid(r.payload) THEN json_extract(r.payload,'$.scheduled') OR json_extract(r.payload,'$.message.scheduleAt') IS NOT NULL END," ++
        " CASE WHEN json_valid(r.payload) THEN json_extract(r.payload,'$.result') END," ++
        " CASE WHEN json_valid(r.payload) THEN json_extract(r.payload,'$.error_message') END," ++
        " CASE WHEN json_valid(r.payload) THEN json_type(r.payload,'$.calendarReply')='object' END" ++
        " FROM totals LEFT JOIN ids ON 1 LEFT JOIN webmail_records r ON r.username=?1 AND r.kind='outbox' AND r.id=ids.id" ++
        " ORDER BY ids.tracked,r." ++ key ++ order ++ ",r.id" ++ order;
}

pub fn outboxPage(a: std.mem.Allocator, db: *database.Database, user: []const u8, view: OutboxView, after: ?[]const u8, track: ?[]const u8) !OutboxPage {
    const s = try db.prepare(switch (view) {
        .overview => outboxPageSql("0", "due_at", true),
        .upcoming => outboxPageSql(upcoming_states, "due_at", true),
        .review => outboxPageSql(review_states, "due_at", false),
        .history => outboxPageSql(history_states, "expires_at", false),
    });
    defer s.finalize();
    try s.bind(1, user);
    try s.bindOpt(2, after);
    try s.bindOpt(3, track);
    try s.bind(4, outbox_page_size + 1);
    if (!try s.step()) unreachable; // Counts always produce a row.
    if (s.columnInt64(3) == 0) return StoreError.NotFound;
    const counts = OutboxCounts{ .upcoming = s.columnInt64(0), .review = s.columnInt64(1), .history = s.columnInt64(2) };
    var items: std.ArrayList(OutboxSummary) = .empty;
    var tracked: ?OutboxSummary = null;
    var next: ?[]const u8 = null;
    while (true) {
        const id = s.columnText(5);
        if (id.len == 0) break;
        if (s.columnInt64(4) != 0) {
            tracked = try readOutboxSummary(a, s);
        } else if (items.items.len == outbox_page_size) {
            next = items.items[items.items.len - 1].id;
        } else {
            try items.append(a, try readOutboxSummary(a, s));
        }
        if (!try s.step()) break;
    }
    return .{ .items = items.items, .counts = counts, .nextCursor = next, .tracked = tracked };
}

fn readOutboxSummary(a: std.mem.Allocator, s: database.Statement) !OutboxSummary {
    const recipients = s.columnText(9);
    const result = s.columnText(11);
    const message_error = s.columnText(12);
    return .{
        .id = try a.dupe(u8, s.columnText(5)),
        .state = try a.dupe(u8, s.columnText(6)),
        .dueAt = s.columnInt64(7),
        .scheduled = s.columnInt64(10) != 0,
        .calendarRsvp = s.columnInt64(13) != 0,
        .message = .{
            .subject = try a.dupe(u8, s.columnText(8)),
            .to = if (recipients.len == 0) &.{} else try std.json.parseFromSliceLeaky([]const []const u8, a, recipients, .{ .allocate = .alloc_always }),
        },
        .result = if (result.len == 0) .null else try std.json.parseFromSliceLeaky(std.json.Value, a, result, .{ .allocate = .alloc_always }),
        .@"error" = if (message_error.len == 0) null else try a.dupe(u8, message_error),
    };
}

pub fn findDraft(allocator: std.mem.Allocator, db: *database.Database, user: []const u8, folder: []const u8, uid: i64) !Record {
    const s = try db.prepare("SELECT username,kind,id,payload,state,revision,due_at,expires_at FROM webmail_records WHERE username=?1 AND kind='draft' AND json_extract(payload,'$.uid')=?2 AND json_extract(payload,'$.folder')=?3 LIMIT 1");
    defer s.finalize();
    try s.bind(1, user);
    try s.bind(2, uid);
    try s.bind(3, folder);
    if (!try s.step()) return StoreError.NotFound;
    return readRecord(allocator, s);
}

pub fn nextDraftEdit(a: std.mem.Allocator, db: *database.Database, cursor: *i64) !?Record {
    const s = try db.prepare("SELECT username,kind,id,payload,state,revision,due_at,expires_at,rowid FROM webmail_records WHERE kind='draft-edit' AND rowid>?1 ORDER BY rowid LIMIT 1");
    defer s.finalize();
    try s.bind(1, cursor.*);
    if (!try s.step()) return null;
    cursor.* = s.columnInt64(8);
    return try readRecord(a, s);
}

/// The webmail draft document and its MIME file must change together.
/// Other protocols call this while holding the mailbox mutation lock.
pub fn managesDraftFile(db: *database.Database, user: []const u8, filename: []const u8) !bool {
    const uid = (try db.getUidForFile(user, "Drafts", filename)) orelse return false;
    return managesDraftAt(db, user, "Drafts", uid);
}

pub fn managesDraftAt(db: *database.Database, user: []const u8, folder: []const u8, uid: i64) !bool {
    {
        const schema = try db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='webmail_records'");
        defer schema.finalize();
        if (!try schema.step()) return false;
    }
    const stmt = try db.prepare("SELECT 1 FROM webmail_records WHERE username=?1 AND kind='draft' AND json_extract(payload,'$.folder')=?2 AND json_extract(payload,'$.uid')=?3 LIMIT 1");
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bind(2, folder);
    try stmt.bind(3, uid);
    return stmt.step();
}

pub fn accountAttachmentLimits(db: *database.Database, user: []const u8) !struct { file: i64, total: i64 } {
    const s = try db.prepare("SELECT attachment_max_size,attachment_max_total FROM users WHERE username=?1");
    defer s.finalize();
    try s.bind(1, user);
    if (!try s.step()) return StoreError.NotFound;
    return .{ .file = s.columnInt64(0), .total = s.columnInt64(1) };
}

/// The caller serializes webmail mutations through the service, including the
/// corresponding Maildir write. Growth is refused without evicting old rows.
const recordCapacitySql =
    \\SELECT COALESCE(SUM(bytes),0), COUNT(*), MAX(CASE WHEN id=?3 THEN bytes END)
    \\FROM (SELECT id,length(CAST(payload AS BLOB)) +
    \\ CASE WHEN state IN ('pending','sending','unknown') THEN ?4 ELSE 0 END AS bytes
    \\ FROM webmail_records WHERE username=?1 AND kind=?2)
;

pub fn checkRecordCapacity(db: *database.Database, row: Record, max_bytes: usize, max_count: usize) !void {
    const outbox = std.mem.eql(u8, row.kind, "outbox");
    const reserve: usize = if (outbox) outbox_result_reserve else 0;
    const s = try db.prepare(recordCapacitySql);
    defer s.finalize();
    try s.bind(1, row.username);
    try s.bind(2, row.kind);
    try s.bind(3, row.id);
    try s.bind(4, reserve);
    if (!try s.step()) unreachable;
    const old_bytes = s.columnInt64Opt(2);
    const previous: usize = @intCast(old_bytes orelse 0);
    const total: usize = @intCast(s.columnInt64(0));
    const count: usize = @intCast(s.columnInt64(1));
    const needed = row.payload.len + reserve;
    if (old_bytes != null and needed <= previous) return;
    if ((old_bytes == null and count >= max_count) or needed > max_bytes -| (total - previous)) {
        return if (outbox) StoreError.OutboxStorageLimit else StoreError.DraftStorageLimit;
    }
}

const putSql =
    \\INSERT INTO webmail_records(username,kind,id,payload,state,revision,due_at,expires_at)
    \\SELECT ?1,?2,?3,?4,?5,1,?6,?7 WHERE ?8=0 OR EXISTS
    \\(SELECT 1 FROM webmail_records WHERE username=?1 AND kind=?2 AND id=?3 AND revision=?8)
    \\ON CONFLICT(username,kind,id) DO UPDATE SET payload=excluded.payload,
    \\state=excluded.state,revision=webmail_records.revision+1,
    \\due_at=excluded.due_at,expires_at=excluded.expires_at
    \\WHERE webmail_records.revision=?8
    \\RETURNING revision
;

/// expected=0 creates; an existing record needs its last acknowledged revision.
pub fn put(db: *database.Database, row: Record, expected: i64) !i64 {
    const s = try db.prepare(putSql);
    defer s.finalize();
    return putWith(s, row, expected);
}

fn putWith(s: database.Statement, row: Record, expected: i64) !i64 {
    try s.bind(1, row.username);
    try s.bind(2, row.kind);
    try s.bind(3, row.id);
    try s.bind(4, row.payload);
    try s.bind(5, row.state);
    try s.bind(6, row.due_at);
    try s.bind(7, row.expires_at);
    try s.bind(8, expected);
    if (!try s.step()) return StoreError.Conflict;
    const revision = s.columnInt64(0);
    _ = try s.step();
    return revision;
}

pub fn remove(db: *database.Database, user: []const u8, kind: []const u8, id: []const u8) !void {
    const s = try db.prepare("DELETE FROM webmail_records WHERE username=?1 AND kind=?2 AND id=?3");
    defer s.finalize();
    try s.bind(1, user);
    try s.bind(2, kind);
    try s.bind(3, id);
    _ = try s.step();
}

/// Atomic claim also works when two HTTP listeners share the database.
pub fn claimDue(allocator: std.mem.Allocator, db: *database.Database, now: i64) !?Record {
    const s = try db.prepare(
        \\UPDATE webmail_records SET state='sending',revision=revision+1
        \\WHERE rowid=(SELECT r.rowid FROM webmail_records r WHERE kind='outbox' AND state='pending' AND due_at<=?1
        \\AND NOT EXISTS (SELECT 1 FROM mailbox_message_refs m JOIN users u ON u.id=m.user_id
        \\   WHERE u.username=r.username AND m.verified_author=CASE WHEN json_valid(r.payload) THEN
        \\      CASE WHEN json_type(r.payload,'$.calendarReply')='object' THEN json_extract(r.payload,'$.message.to[0]') END
        \\   END COLLATE NOCASE
    ++ " AND " ++ database.Database.pending_calendar_history ++ ") " ++
        \\ORDER BY due_at LIMIT 1) AND state='pending'
        \\RETURNING username,kind,id,payload,state,revision,due_at,expires_at
    );
    defer s.finalize();
    try s.bind(1, now);
    if (!try s.step()) return null;
    const row = try readRecord(allocator, s);
    _ = try s.step();
    return row;
}

/// Admission and freezing the associated draft share the insert transaction.
const enqueueSql =
    \\INSERT INTO webmail_records(username,kind,id,payload,state,revision,due_at,expires_at)
    \\SELECT ?1,'outbox',?2,?3,'pending',1,?4,0 WHERE ?5 IS NULL OR EXISTS
    \\(SELECT 1 FROM webmail_records WHERE username=?1 AND kind='draft' AND id=?5 AND state='saved' AND revision=?6
    \\ AND NOT EXISTS(SELECT 1 FROM mail_ews_draft_finalizations c JOIN users u ON u.id=c.user_id
    \\     WHERE u.username=?1 AND c.draft_id=?5 AND c.draft_revision=?6 AND c.retired_at IS NULL))
    \\ON CONFLICT(username,kind,id) DO NOTHING RETURNING revision
;

pub fn enqueue(db: *database.Database, row: Record, draft_id: ?[]const u8, draft_revision: i64) !i64 {
    const s = try db.prepare(enqueueSql);
    defer s.finalize();
    return enqueueWith(s, row, draft_id, draft_revision);
}

pub fn enqueueShared(db: *database.Database, row: Record, draft_id: []const u8, draft_revision: i64, context: shared_inbox.ReplyContext) !i64 {
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    try shared_inbox.reserveReply(tx, row.username, context, row.id, row.due_at);
    const s = try tx.prepare(enqueueSql);
    defer s.finalize();
    const revision = try enqueueWith(s, row, draft_id, draft_revision);
    try tx.commit();
    return revision;
}

pub fn enqueueCalendarReply(db: *database.Database, row: Record, receipt: Record, revision: calendar_invite.Revision) !void {
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    try database.Database.requireCurrentCalendarInvitation(tx, row.username, revision);
    const ledger = try tx.prepare(putSql);
    defer ledger.finalize();
    _ = try putWith(ledger, receipt, receipt.revision);
    const send = try tx.prepare(enqueueSql);
    defer send.finalize();
    _ = try enqueueWith(send, row, null, 0);
    try tx.commit();
}

/// Publish the entire reply batch and its retry receipt in a single write.
pub fn enqueueReplyBatch(db: *database.Database, from: []const u8, receipt: Record, rows: []const Record, hosted_budget: ?usize) !void {
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    {
        const account = try tx.prepare("SELECT 1 FROM users WHERE username=?1 AND email=?2 AND enabled=1");
        defer account.finalize();
        try account.bind(1, receipt.username);
        try account.bind(2, from);
        if (!try account.step()) return error.ReplyBatchAccountChanged;
    }
    if (hosted_budget) |budget| {
        const capacity = try tx.prepare(recordCapacitySql);
        defer capacity.finalize();
        try capacity.bind(1, receipt.username);
        try capacity.bind(2, @as([]const u8, "outbox"));
        try capacity.bind(3, @as([]const u8, ""));
        try capacity.bind(4, outbox_result_reserve);
        if (!try capacity.step()) unreachable;
        const bytes: usize = @intCast(capacity.columnInt64(0));
        const count: usize = @intCast(capacity.columnInt64(1));
        var needed: usize = 0;
        for (rows) |row| needed += row.payload.len + outbox_result_reserve;
        if (needed > budget -| bytes or rows.len > hosted_outbox_count -| count) return StoreError.OutboxStorageLimit;
    }
    {
        const ledger = try tx.prepare(putSql);
        defer ledger.finalize();
        _ = try putWith(ledger, receipt, 0);
    }
    const send = try tx.prepare(enqueueSql);
    defer send.finalize();
    for (rows) |row| {
        _ = try enqueueWith(send, row, null, 0);
        try send.reset();
    }
    try tx.commit();
}

fn enqueueWith(s: database.Statement, row: Record, draft_id: ?[]const u8, draft_revision: i64) !i64 {
    try s.bind(1, row.username);
    try s.bind(2, row.id);
    try s.bind(3, row.payload);
    try s.bind(4, row.due_at);
    try s.bindOpt(5, draft_id);
    try s.bind(6, draft_revision);
    if (!try s.step()) return StoreError.Conflict;
    const revision = s.columnInt64(0);
    _ = try s.step();
    return revision;
}

pub fn cancelSend(allocator: std.mem.Allocator, db: *database.Database, user: []const u8, id: []const u8, now: i64) !Record {
    const s = try db.prepare(
        \\UPDATE webmail_records SET state='cancelled',revision=revision+1,expires_at=?4
        \\WHERE username=?1 AND kind='outbox' AND id=?2 AND state='pending' AND due_at>?3
        \\RETURNING username,kind,id,payload,state,revision,due_at,expires_at
    );
    defer s.finalize();
    try s.bind(1, user);
    try s.bind(2, id);
    try s.bind(3, now);
    try s.bind(4, now + terminal_retention);
    if (!try s.step()) return StoreError.Conflict;
    const row = try readRecord(allocator, s);
    _ = try s.step();
    return row;
}

/// An interrupted SMTP exchange cannot safely be retried automatically.
pub fn recoverInterrupted(db: *database.Database) !void {
    try db.exec("UPDATE webmail_records SET state='unknown',revision=revision+1 WHERE kind='outbox' AND state='sending'");
}

pub fn nextInterruptedDelivery(a: std.mem.Allocator, db: *database.Database, cursor: *i64) !?Record {
    const stmt = try db.prepare(
        \\SELECT username,kind,r.id,payload,state,revision,due_at,expires_at,r.rowid
        \\FROM webmail_records AS r
        \\WHERE kind='outbox' AND state='unknown' AND json_extract(r.payload,'$.result') IS NULL AND r.rowid>?1
        \\AND (json_type(r.payload,'$.message.sharedReply')='object' OR json_type(r.payload,'$.calendarReply')='object' OR EXISTS(
        \\  SELECT 1 FROM accepted_mail AS m WHERE m.id=json_extract(r.payload,'$.dispatch.delivery_id')))
        \\ORDER BY r.rowid LIMIT 1
    );
    defer stmt.finalize();
    try stmt.bind(1, cursor.*);
    if (!try stmt.step()) return null;
    cursor.* = stmt.columnInt64(8);
    return try readRecord(a, stmt);
}

pub fn addUpload(db: *database.Database, user: []const u8, upload: Upload, now: i64, max_staged_bytes: usize, max_count: usize) !void {
    const s = try db.prepare(
        \\INSERT INTO webmail_uploads(username,id,filename,content_type,data,size,expires_at,mime)
        \\SELECT ?1,?2,?3,?4,?5,?6,?7,json_object('contentId',?10,'inline',?11) WHERE
        \\(SELECT COALESCE(SUM(size),0)+?6<=?8 AND COUNT(*)<?9 FROM webmail_uploads WHERE username=?1)
        \\RETURNING id
    );
    defer s.finalize();
    try s.bind(1, user);
    try s.bind(2, upload.id);
    try s.bind(3, upload.filename);
    try s.bind(4, upload.content_type);
    try s.bindBlob(5, upload.data);
    try s.bind(6, upload.data.len);
    try s.bind(7, now + 86400);
    try s.bind(8, max_staged_bytes);
    try s.bind(9, max_count);
    try s.bind(10, upload.content_id);
    try s.bind(11, @as(i64, @intFromBool(upload.inline_part)));
    if (!try s.step()) return StoreError.StorageLimit;
    _ = try s.step();
}

pub fn getUpload(allocator: std.mem.Allocator, db: *database.Database, user: []const u8, id: []const u8) !Upload {
    const s = try db.prepare("SELECT id,filename,content_type,data,json_extract(mime,'$.contentId'),json_extract(mime,'$.inline') FROM webmail_uploads WHERE username=?1 AND id=?2");
    defer s.finalize();
    try s.bind(1, user);
    try s.bind(2, id);
    if (!try s.step()) return StoreError.NotFound;
    return .{
        .id = try allocator.dupe(u8, s.columnText(0)),
        .filename = try allocator.dupe(u8, s.columnText(1)),
        .content_type = try allocator.dupe(u8, s.columnText(2)),
        .data = try allocator.dupe(u8, s.columnText(3)),
        .content_id = try allocator.dupe(u8, s.columnText(4)),
        .inline_part = s.columnInt64(5) != 0,
    };
}

const join_attachments = "FROM webmail_records AS r, " ++
    "json_each(CASE WHEN json_valid(r.payload) THEN r.payload END,'$.message.attachments') AS attachment";
const attachment_id = "CASE WHEN attachment.type='object' THEN json_extract(attachment.value,'$.uploadId') END";

pub fn removeUpload(db: *database.Database, user: []const u8, id: []const u8) !void {
    const s = try db.prepare(
        "DELETE FROM webmail_uploads WHERE username=?1 AND id=?2 AND NOT EXISTS (SELECT 1 " ++ join_attachments ++
            " WHERE r.username=?1 AND r.kind IN ('draft','outbox','draft-edit') AND " ++ attachment_id ++ "=?2)",
    );
    defer s.finalize();
    try s.bind(1, user);
    try s.bind(2, id);
    _ = try s.step();
}

pub fn sweep(db: *database.Database, now: i64, user: ?[]const u8) !void {
    {
        const records = try db.prepare("DELETE FROM webmail_records WHERE expires_at>0 AND expires_at<=?1 AND state NOT IN ('pending','sending','unknown') AND (?2='' OR username=?2)");
        defer records.finalize();
        try records.bind(1, now);
        try records.bind(2, user orelse "");
        _ = try records.step();
    }
    const uploads = try db.prepare(
        // Parse each mailbox record once, and only when it has expired uploads.
        "WITH refs(username,id) AS MATERIALIZED (SELECT DISTINCT r.username," ++ attachment_id ++ " " ++ join_attachments ++
            \\ WHERE r.kind IN ('draft','outbox','draft-edit') AND (?2='' OR r.username=?2)
            \\ AND EXISTS (SELECT 1 FROM webmail_uploads AS u WHERE u.username=r.username AND u.expires_at<=?1))
            \\DELETE FROM webmail_uploads WHERE expires_at<=?1 AND (?2='' OR username=?2)
            \\ AND NOT EXISTS (SELECT 1 FROM refs WHERE refs.username=webmail_uploads.username AND refs.id=webmail_uploads.id)
        ,
    );
    defer uploads.finalize();
    try uploads.bind(1, now);
    try uploads.bind(2, user orelse "");
    _ = try uploads.step();
}

test "draft revisions, queued-send claims and cancellation are account-scoped" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var db = try database.Database.init(t.allocator, ":memory:");
    defer db.deinit();
    try initSchema(&db);
    _ = try db.createUser("one@example.com", "test-hash", "one@example.com");
    var draft = Record{ .username = "one@example.com", .kind = "draft", .id = "1234567890123456", .payload = "incomplete@", .state = "saved", .revision = 0, .due_at = 0, .expires_at = 0 };
    try t.expectEqual(@as(i64, 1), try put(&db, draft, 0));
    try t.expectError(StoreError.Conflict, put(&db, draft, 0));
    draft.payload = "new body";
    try t.expectEqual(@as(i64, 2), try put(&db, draft, 1));
    try t.expectError(StoreError.NotFound, get(a, &db, "two@example.com", "draft", draft.id));
    try t.expectEqualStrings("new body", (try get(a, &db, draft.username, "draft", draft.id)).payload);
    var missing = draft;
    missing.id = "9234567890123456";
    try t.expectError(StoreError.Conflict, put(&db, missing, 1));
    var send = draft;
    send.kind = "outbox";
    send.state = "pending";
    send.due_at = 110;
    _ = try put(&db, send, 0);
    try t.expectError(StoreError.Conflict, cancelSend(a, &db, "two@example.com", send.id, 100));
    try t.expect(try claimDue(a, &db, 109) == null);
    _ = try cancelSend(a, &db, send.username, send.id, 109);
    try t.expect(try claimDue(a, &db, 120) == null);
    send.id = "2234567890123456";
    _ = try put(&db, send, 0);
    try t.expectError(StoreError.Conflict, cancelSend(a, &db, send.username, send.id, 110));
    try t.expectEqualStrings("sending", (try claimDue(a, &db, 110)).?.state);
    try t.expect(try claimDue(a, &db, 110) == null);
    try recoverInterrupted(&db);
    try t.expectEqualStrings("unknown", (try get(a, &db, send.username, "outbox", send.id)).state);
}

test "binary uploads preserve bytes, ownership and staged storage limits" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var db = try database.Database.init(t.allocator, ":memory:");
    defer db.deinit();
    try initSchema(&db);
    _ = try db.createUser("one@example.com", "test-hash", "one@example.com");
    const upload = Upload{ .id = "1234567890123456", .filename = "bytes.bin", .content_type = "application/octet-stream", .data = &.{ 0, 255, 128, 13, 10 } };
    try addUpload(&db, "one@example.com", upload, 100, 5, 10);
    try t.expectEqualSlices(u8, upload.data, (try getUpload(a, &db, "one@example.com", upload.id)).data);
    try t.expectError(StoreError.NotFound, getUpload(a, &db, "two@example.com", upload.id));
    var next = upload;
    next.id = "2234567890123456";
    try t.expectError(StoreError.StorageLimit, addUpload(&db, "one@example.com", next, 100, 5, 10));
    try removeUpload(&db, "two@example.com", upload.id);
    _ = try getUpload(a, &db, "one@example.com", upload.id);
    try sweep(&db, 86501, null);
    try t.expectError(StoreError.NotFound, getUpload(a, &db, "one@example.com", upload.id));
}
