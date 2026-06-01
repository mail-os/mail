//! UID consistency tests: the imap_uids table keys on the Maildir base name, so
//! a message's UID is stable across flag changes (which rename the :2,FLAGS
//! suffix) and identical whether looked up by base or flag-suffixed name. This
//! is what keeps webmail, IMAP, and ActiveSync agreeing on message identity.
const std = @import("std");
const database = @import("storage/database.zig");

test "UID is stable across flag-suffix renames" {
    const allocator = std.testing.allocator;
    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    _ = try db.getOrCreateMailbox("alice", "INBOX");

    // Assign a UID to the bare (no-flags) filename.
    const uid1 = try db.assignUid("alice", "INBOX", "1700000000.msg.eml");

    // Looking it up by the SAME name returns the same UID.
    try std.testing.expectEqual(uid1, (try db.getUidForFile("alice", "INBOX", "1700000000.msg.eml")).?);

    // After a flag change the file becomes "...eml:2,S" — the UID must NOT change.
    try std.testing.expectEqual(uid1, (try db.getUidForFile("alice", "INBOX", "1700000000.msg.eml:2,S")).?);

    // And assigning against the flag-suffixed name returns the SAME UID (no new row).
    try std.testing.expectEqual(uid1, try db.assignUid("alice", "INBOX", "1700000000.msg.eml:2,FS"));
}

test "distinct messages get distinct stable UIDs" {
    const allocator = std.testing.allocator;
    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();
    _ = try db.getOrCreateMailbox("alice", "INBOX");

    const a = try db.assignUid("alice", "INBOX", "1700000000.a.eml");
    const b = try db.assignUid("alice", "INBOX", "1700000100.b.eml");
    try std.testing.expect(a != b);
    // Re-lookup by flag-suffixed names still resolves correctly.
    try std.testing.expectEqual(a, (try db.getUidForFile("alice", "INBOX", "1700000000.a.eml:2,S")).?);
    try std.testing.expectEqual(b, (try db.getUidForFile("alice", "INBOX", "1700000100.b.eml:2,RS")).?);
}

test "removeStaleUids keeps flag-renamed files, drops truly gone ones" {
    const allocator = std.testing.allocator;
    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();
    _ = try db.getOrCreateMailbox("alice", "INBOX");

    const uid_a = try db.assignUid("alice", "INBOX", "1700000000.a.eml");
    _ = try db.assignUid("alice", "INBOX", "1700000100.b.eml");

    // Current files: 'a' now flag-suffixed, 'b' gone entirely.
    const current = [_][]const u8{"1700000000.a.eml:2,S"};
    try db.removeStaleUids("alice", "INBOX", &current);

    // 'a' survived with its original UID (matched by base name despite the suffix).
    try std.testing.expectEqual(uid_a, (try db.getUidForFile("alice", "INBOX", "1700000000.a.eml")).?);
    // 'b' was pruned.
    try std.testing.expect((try db.getUidForFile("alice", "INBOX", "1700000100.b.eml")) == null);
}

test "maildirBaseName strips the suffix" {
    try std.testing.expectEqualStrings("123.msg.eml", database.maildirBaseName("123.msg.eml:2,FS"));
    try std.testing.expectEqualStrings("123.msg.eml", database.maildirBaseName("123.msg.eml"));
}
