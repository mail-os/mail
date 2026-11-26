//! Verify a peer-owned copy of the original calendar's share-visible resources.
const std = @import("std");
const Database = @import("database.zig").Database;
const CalDavStore = @import("caldav_store.zig").CalDavStore;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Copy = struct {
    source_share_id: []const u8,
    peer_user_id: i64,
    destination_calendar_id: i64,
};

pub const VerifiedCopy = struct {
    copy: Copy,
    resources: usize,
    resources_sha256: [64]u8,
};

pub const Proof = struct {
    approval_audit_id: i64,
    copies: []const VerifiedCopy,
};

fn requireAccessiblePeer(tx: Database.Transaction, peer: i64, now: i64) !void {
    const row = try tx.prepare(
        \\SELECT 1 FROM users u WHERE id=?1 AND enabled=1 AND NOT EXISTS (
        \\ SELECT 1 FROM provisioned_mailboxes p WHERE p.user_id=u.id AND p.read_until<=?2
        \\)
    );
    defer row.finalize();
    try row.bind(1, peer);
    try row.bind(2, now);
    if (!try row.step()) return error.ErasureCalendarCopyPeerUnavailable;
}

fn events(tx: Database.Transaction, calendar: i64) !@import("database.zig").Statement {
    const rows = try tx.prepare("SELECT CAST(uid AS BLOB),CAST(ics_data AS BLOB) FROM dav_events WHERE calendar_id=?1 ORDER BY CAST(uid AS BLOB),id");
    errdefer rows.finalize();
    try rows.bind(1, calendar);
    return rows;
}

fn appendHash(hash: *Sha256, value: []const u8) void {
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, value.len, .big);
    hash.update(&length);
    hash.update(value);
}

fn verifyCopy(a: Allocator, dav: Database.Transaction, source_id: i64, copy: Copy) !VerifiedCopy {
    const calendars = try dav.prepare(
        \\SELECT s.id,s.timezone,d.timezone FROM dav_calendars s
        \\JOIN dav_users owner ON owner.id=s.user_id AND owner.mailbox_id=?1
        \\JOIN dav_calendars d ON d.id=?3 AND d.id<>s.id
        \\JOIN dav_users peer ON peer.id=d.user_id AND peer.mailbox_id=?4
        \\WHERE s.share_id=?2
    );
    defer calendars.finalize();
    try calendars.bind(1, source_id);
    try calendars.bind(2, copy.source_share_id);
    try calendars.bind(3, copy.destination_calendar_id);
    try calendars.bind(4, copy.peer_user_id);
    if (!try calendars.step()) return error.ErasureCalendarCopyOwnershipUnresolved;
    const source_calendar = calendars.columnInt64(0);
    const timezone = calendars.columnText(1);
    if (timezone.len == 0 or !std.mem.eql(u8, timezone, calendars.columnText(2))) return error.ErasureCalendarCopyMismatch;
    var hash = Sha256.init(.{});
    appendHash(&hash, timezone);
    if (try calendars.step()) return error.ErasureCalendarCopyOwnershipUnresolved;

    const source = try events(dav, source_calendar);
    defer source.finalize();
    const destination = try events(dav, copy.destination_calendar_id);
    defer destination.finalize();
    var resources: usize = 0;
    while (try source.step()) {
        const bytes = source.columnBlob(1);
        // Use the same visibility rule that shared CalDAV uses for event data.
        if (!CalDavStore.publicCalendarResource(a, bytes)) continue;
        const uid = source.columnBlob(0);
        if (uid.len == 0 or !try destination.step() or
            !std.mem.eql(u8, uid, destination.columnBlob(0)) or
            !std.mem.eql(u8, bytes, destination.columnBlob(1)))
            return error.ErasureCalendarCopyMismatch;
        appendHash(&hash, uid);
        appendHash(&hash, bytes);
        resources += 1;
    }
    // Dedicated retained calendars cannot contain any extra event, including
    // a private event from the original calendar.
    if (try destination.step()) return error.ErasureCalendarCopyMismatch;
    return .{ .copy = copy, .resources = resources, .resources_sha256 = std.fmt.bytesToHex(hash.finalResult(), .lower) };
}

pub fn verify(a: Allocator, authority: Database.Transaction, dav: Database.Transaction, source_id: i64, copies: []const Copy, now: i64) ![]const VerifiedCopy {
    const verified = try a.alloc(VerifiedCopy, copies.len);
    for (copies, verified) |copy, *result| {
        try requireAccessiblePeer(authority, copy.peer_user_id, now);
        result.* = try verifyCopy(a, dav, source_id, copy);
    }
    return verified;
}
