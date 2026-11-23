//! Download-only capabilities for files sent outside MIME. Held under the
//! mailbox lock, admission competes with every other hosted storage write.
const std = @import("std");
const database = @import("../storage/database.zig");
const hosted = @import("../storage/hosted_limits.zig");
const teams = @import("../storage/team_store.zig");
const tokens = @import("webmail_link_tokens.zig");

pub const path = "/webmail/api/file-links";
pub const max_file_bytes = 24 * 1024 * 1024;
pub const max_account_bytes = 96 * 1024 * 1024;
pub const max_links = 20;

pub const File = struct { filename: []const u8, size: i64, expires_at: i64 };
pub const Link = struct { id: []const u8, filename: []const u8, size: i64, expires_at: i64 };
pub const Issued = struct { file: File, token: [64]u8 };
pub const Download = struct { file: File, data: []const u8 };

pub fn uploadLimit(db: *database.Database, user: []const u8) !usize {
    const limits = (try db.hostedLimits(user)) orelse return max_file_bytes;
    return if (limits.enabled) @intCast(@min(limits.quota_bytes, max_file_bytes)) else 0;
}

pub fn validId(id: []const u8) bool {
    if (id.len != 32) return false;
    for (id) |byte| if (!std.ascii.isHex(byte) or std.ascii.isUpper(byte)) return false;
    return true;
}

pub fn create(db: *database.Database, user: []const u8, id: []const u8, filename: []const u8, data: []const u8, lifetime: i64, now: i64) !Issued {
    if (data.len == 0 or data.len > max_file_bytes or !tokens.validLifetime(lifetime)) return error.InvalidLinkedFile;
    db.lockMailboxes();
    defer db.unlockMailboxes();
    {
        const stmt = try db.prepare("SELECT 1 FROM mail_file_links WHERE user_id=(SELECT id FROM users WHERE username=?1 AND enabled=1) AND id=?2");
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, id);
        if (try stmt.step()) return error.FileLinkAlreadyCreated;
    }
    try hosted.checkStorage(db, user, data.len, null);
    const token = tokens.new();
    const hash = tokens.digest(&token);
    const expires_at = now + lifetime;
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const owner = (try teams.activeMailboxId(tx, user)) orelse return error.FileLinkOwnerUnavailable;
    {
        const stmt = try tx.prepare(
            \\INSERT INTO mail_file_links(user_id,id,token_hash,filename,data,size,expires_at)
            \\SELECT ?1,?2,?3,?4,?5,?6,?7 WHERE (
            \\ SELECT COALESCE(SUM(size),0)+?6<=?8 AND COUNT(*)<?9
            \\ FROM mail_file_links WHERE user_id=?1 AND expires_at>?10
            \\) RETURNING id
        );
        defer stmt.finalize();
        try stmt.bind(1, owner);
        try stmt.bind(2, id);
        try stmt.bind(3, @as([]const u8, &hash));
        try stmt.bind(4, filename);
        try stmt.bindBlob(5, data);
        try stmt.bind(6, data.len);
        try stmt.bind(7, expires_at);
        try stmt.bind(8, @as(i64, max_account_bytes));
        try stmt.bind(9, @as(i64, max_links));
        try stmt.bind(10, now);
        if (!try stmt.step()) return error.FileLinkStorageLimit;
    }
    try tx.commit();
    return .{ .token = token, .file = .{ .filename = filename, .size = @intCast(data.len), .expires_at = expires_at } };
}

pub fn list(a: std.mem.Allocator, db: *database.Database, user: []const u8, now: i64) ![]Link {
    const stmt = try db.prepare(
        \\SELECT id,filename,size,expires_at FROM mail_file_links
        \\WHERE user_id=(SELECT id FROM users WHERE username=?1 AND enabled=1) AND expires_at>?2
        \\ORDER BY expires_at DESC, id
    );
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bind(2, now);
    var rows: std.ArrayList(Link) = .empty;
    while (try stmt.step()) try rows.append(a, .{
        .id = try a.dupe(u8, stmt.columnText(0)),
        .filename = try a.dupe(u8, stmt.columnText(1)),
        .size = stmt.columnInt64(2),
        .expires_at = stmt.columnInt64(3),
    });
    return rows.toOwnedSlice(a);
}

pub fn read(a: std.mem.Allocator, db: *database.Database, token: []const u8, now: i64, include_bytes: bool) !?Download {
    if (!tokens.valid(token)) return null;
    const hash = tokens.digest(token);
    // The metadata path never requests the BLOB.
    const fields = "SELECT link.filename,link.size,link.expires_at";
    const lookup = " FROM mail_file_links AS link JOIN users ON users.id=link.user_id " ++
        "WHERE link.token_hash=?1 AND link.expires_at>?2 AND users.enabled=1";
    const stmt = try db.prepare(if (include_bytes) fields ++ ",link.data" ++ lookup else fields ++ lookup);
    defer stmt.finalize();
    try stmt.bind(1, @as([]const u8, &hash));
    try stmt.bind(2, now);
    if (!try stmt.step()) return null;
    return .{
        .file = .{ .filename = try a.dupe(u8, stmt.columnText(0)), .size = stmt.columnInt64(1), .expires_at = stmt.columnInt64(2) },
        .data = if (include_bytes) try a.dupe(u8, stmt.columnBlob(3)) else "",
    };
}

pub fn revoke(db: *database.Database, user: []const u8, id: []const u8) !bool {
    const stmt = try db.prepare(
        \\DELETE FROM mail_file_links WHERE id=?2 AND user_id=(SELECT id FROM users WHERE username=?1 AND enabled=1) RETURNING id
    );
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bind(2, id);
    return stmt.step();
}

pub fn sweep(db: *database.Database, now: i64) !void {
    const stmt = try db.prepare("DELETE FROM mail_file_links WHERE expires_at <= ?1");
    defer stmt.finalize();
    try stmt.bind(1, now);
    _ = try stmt.step();
}
