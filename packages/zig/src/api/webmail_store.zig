//! Account-scoped webmail state. Conditional SQL makes retries idempotent and
//! keeps queued sends cancellable only before the server dispatch deadline.
const std = @import("std");
const database = @import("../storage/database.zig");
const io_compat = @import("../core/io_compat.zig");

pub const StoreError = error{ Conflict, NotFound, StorageLimit };
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
pub const Upload = struct { id: []const u8, filename: []const u8, content_type: []const u8, data: []const u8 };

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
        \\CREATE TABLE IF NOT EXISTS webmail_uploads (
        \\ username TEXT NOT NULL, id TEXT NOT NULL, filename TEXT NOT NULL,
        \\ content_type TEXT NOT NULL, data BLOB NOT NULL, size INTEGER NOT NULL,
        \\ expires_at INTEGER NOT NULL, PRIMARY KEY(username,id),
        \\ FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
        \\);
    );
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
    const s = try db.prepare("SELECT username,kind,id,payload,state,revision,due_at,expires_at FROM webmail_records WHERE username=?1 AND kind=?2 ORDER BY rowid DESC LIMIT ?3");
    defer s.finalize();
    try s.bind(1, user);
    try s.bind(2, kind);
    try s.bind(3, @min(limit, 200));
    var rows: std.ArrayList(Record) = .empty;
    while (try s.step()) try rows.append(allocator, try readRecord(allocator, s));
    return rows.toOwnedSlice(allocator);
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

pub fn accountAttachmentLimits(db: *database.Database, user: []const u8) !struct { file: i64, total: i64 } {
    const s = try db.prepare("SELECT attachment_max_size,attachment_max_total FROM users WHERE username=?1");
    defer s.finalize();
    try s.bind(1, user);
    if (!try s.step()) return StoreError.NotFound;
    return .{ .file = s.columnInt64(0), .total = s.columnInt64(1) };
}

/// expected=0 creates; an existing record needs its last acknowledged revision.
pub fn put(db: *database.Database, row: Record, expected: i64) !i64 {
    const s = try db.prepare(
        \\INSERT INTO webmail_records(username,kind,id,payload,state,revision,due_at,expires_at)
        \\SELECT ?1,?2,?3,?4,?5,1,?6,?7 WHERE ?8=0 OR EXISTS
        \\(SELECT 1 FROM webmail_records WHERE username=?1 AND kind=?2 AND id=?3 AND revision=?8)
        \\ON CONFLICT(username,kind,id) DO UPDATE SET payload=excluded.payload,
        \\state=excluded.state,revision=webmail_records.revision+1,
        \\due_at=excluded.due_at,expires_at=excluded.expires_at
        \\WHERE webmail_records.revision=?8
        \\RETURNING revision
    );
    defer s.finalize();
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
        \\WHERE rowid=(SELECT rowid FROM webmail_records WHERE kind='outbox'
        \\AND state='pending' AND due_at<=?1 ORDER BY due_at LIMIT 1) AND state='pending'
        \\RETURNING username,kind,id,payload,state,revision,due_at,expires_at
    );
    defer s.finalize();
    try s.bind(1, now);
    if (!try s.step()) return null;
    const row = try readRecord(allocator, s);
    _ = try s.step();
    return row;
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
    try s.bind(4, now + 7 * 86400);
    if (!try s.step()) return StoreError.Conflict;
    const row = try readRecord(allocator, s);
    _ = try s.step();
    return row;
}

/// An interrupted SMTP exchange cannot safely be retried automatically.
pub fn recoverInterrupted(db: *database.Database) !void {
    try db.exec("UPDATE webmail_records SET state='unknown',revision=revision+1 WHERE kind='outbox' AND state='sending'");
}

pub fn addUpload(db: *database.Database, user: []const u8, upload: Upload, now: i64, max_staged_bytes: usize) !void {
    const s = try db.prepare(
        \\INSERT INTO webmail_uploads(username,id,filename,content_type,data,size,expires_at)
        \\SELECT ?1,?2,?3,?4,?5,?6,?7 WHERE
        \\(SELECT COALESCE(SUM(size),0) FROM webmail_uploads WHERE username=?1)+?6<=?8
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
    if (!try s.step()) return StoreError.StorageLimit;
    _ = try s.step();
}

pub fn getUpload(allocator: std.mem.Allocator, db: *database.Database, user: []const u8, id: []const u8) !Upload {
    const s = try db.prepare("SELECT id,filename,content_type,data FROM webmail_uploads WHERE username=?1 AND id=?2");
    defer s.finalize();
    try s.bind(1, user);
    try s.bind(2, id);
    if (!try s.step()) return StoreError.NotFound;
    return .{
        .id = try allocator.dupe(u8, s.columnText(0)),
        .filename = try allocator.dupe(u8, s.columnText(1)),
        .content_type = try allocator.dupe(u8, s.columnText(2)),
        .data = try allocator.dupe(u8, s.columnText(3)),
    };
}

pub fn removeUpload(db: *database.Database, user: []const u8, id: []const u8) !void {
    const s = try db.prepare(
        \\DELETE FROM webmail_uploads WHERE username=?1 AND id=?2 AND NOT EXISTS
        \\(SELECT 1 FROM webmail_records WHERE username=?1 AND kind IN ('draft','outbox') AND instr(payload,?2)>0)
    );
    defer s.finalize();
    try s.bind(1, user);
    try s.bind(2, id);
    _ = try s.step();
}

pub fn sweep(db: *database.Database, now: i64) !void {
    var s = try db.prepare("DELETE FROM webmail_records WHERE expires_at>0 AND expires_at<=?1 AND state NOT IN ('pending','sending','unknown')");
    try s.bind(1, now);
    _ = try s.step();
    s.finalize();
    s = try db.prepare(
        \\DELETE FROM webmail_uploads WHERE expires_at<=?1 AND NOT EXISTS
        \\(SELECT 1 FROM webmail_records WHERE webmail_records.username=webmail_uploads.username
        \\AND kind IN ('draft','outbox') AND instr(payload,webmail_uploads.id)>0)
    );
    defer s.finalize();
    try s.bind(1, now);
    _ = try s.step();
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
    try addUpload(&db, "one@example.com", upload, 100, 5);
    try t.expectEqualSlices(u8, upload.data, (try getUpload(a, &db, "one@example.com", upload.id)).data);
    try t.expectError(StoreError.NotFound, getUpload(a, &db, "two@example.com", upload.id));
    var next = upload;
    next.id = "2234567890123456";
    try t.expectError(StoreError.StorageLimit, addUpload(&db, "one@example.com", next, 100, 5));
    try removeUpload(&db, "two@example.com", upload.id);
    _ = try getUpload(a, &db, "one@example.com", upload.id);
    try sweep(&db, 86501);
    try t.expectError(StoreError.NotFound, getUpload(a, &db, "one@example.com", upload.id));
}
