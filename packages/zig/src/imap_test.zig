const std = @import("std");
const testing = std.testing;
const imap = @import("protocol/imap.zig");

// =============================================================================
// SequenceIterator tests
// =============================================================================

test "SequenceIterator - single number" {
    var iter = imap.SequenceIterator.init("3", 10);
    try testing.expectEqual(@as(?u32, 3), iter.next());
    try testing.expectEqual(@as(?u32, null), iter.next());
}

test "SequenceIterator - single number star" {
    var iter = imap.SequenceIterator.init("*", 5);
    try testing.expectEqual(@as(?u32, 5), iter.next());
    try testing.expectEqual(@as(?u32, null), iter.next());
}

test "SequenceIterator - range" {
    var iter = imap.SequenceIterator.init("2:5", 10);
    try testing.expectEqual(@as(?u32, 2), iter.next());
    try testing.expectEqual(@as(?u32, 3), iter.next());
    try testing.expectEqual(@as(?u32, 4), iter.next());
    try testing.expectEqual(@as(?u32, 5), iter.next());
    try testing.expectEqual(@as(?u32, null), iter.next());
}

test "SequenceIterator - range with star" {
    var iter = imap.SequenceIterator.init("3:*", 5);
    try testing.expectEqual(@as(?u32, 3), iter.next());
    try testing.expectEqual(@as(?u32, 4), iter.next());
    try testing.expectEqual(@as(?u32, 5), iter.next());
    try testing.expectEqual(@as(?u32, null), iter.next());
}

test "SequenceIterator - comma separated" {
    var iter = imap.SequenceIterator.init("1,3,5", 10);
    try testing.expectEqual(@as(?u32, 1), iter.next());
    try testing.expectEqual(@as(?u32, 3), iter.next());
    try testing.expectEqual(@as(?u32, 5), iter.next());
    try testing.expectEqual(@as(?u32, null), iter.next());
}

test "SequenceIterator - mixed ranges and singles" {
    var iter = imap.SequenceIterator.init("1:3,7,9:10", 10);
    try testing.expectEqual(@as(?u32, 1), iter.next());
    try testing.expectEqual(@as(?u32, 2), iter.next());
    try testing.expectEqual(@as(?u32, 3), iter.next());
    try testing.expectEqual(@as(?u32, 7), iter.next());
    try testing.expectEqual(@as(?u32, 9), iter.next());
    try testing.expectEqual(@as(?u32, 10), iter.next());
    try testing.expectEqual(@as(?u32, null), iter.next());
}

test "SequenceIterator - out of range filtered" {
    // Numbers > max_seq should be skipped
    var iter = imap.SequenceIterator.init("1,5,15", 10);
    try testing.expectEqual(@as(?u32, 1), iter.next());
    try testing.expectEqual(@as(?u32, 5), iter.next());
    // 15 > 10 (max_seq), so it's skipped
    try testing.expectEqual(@as(?u32, null), iter.next());
}

test "SequenceIterator - zero filtered" {
    // 0 is not a valid sequence number (1-based)
    var iter = imap.SequenceIterator.init("0", 10);
    try testing.expectEqual(@as(?u32, null), iter.next());
}

test "SequenceIterator - zero range filtered (regression for crash)" {
    // This was the crash case: uidSetToSeqSet returned "0:0" when no UIDs matched,
    // SequenceIterator.next() yielded seq=0, then idx = seq - 1 caused unsigned underflow
    var iter = imap.SequenceIterator.init("0:0", 10);
    try testing.expectEqual(@as(?u32, null), iter.next());
}

test "SequenceIterator - range exceeding max_seq clamped" {
    var iter = imap.SequenceIterator.init("8:15", 10);
    try testing.expectEqual(@as(?u32, 8), iter.next());
    try testing.expectEqual(@as(?u32, 9), iter.next());
    try testing.expectEqual(@as(?u32, 10), iter.next());
    // 11-15 filtered out
    try testing.expectEqual(@as(?u32, null), iter.next());
}

test "SequenceIterator - empty file count" {
    var iter = imap.SequenceIterator.init("1:*", 0);
    // max_seq=0, so nothing is valid
    try testing.expectEqual(@as(?u32, null), iter.next());
}

test "SequenceIterator - reverse range" {
    var iter = imap.SequenceIterator.init("5:3", 10);
    // Reverse ranges: yields 3, 4, 5
    var results: [10]u32 = undefined;
    var count: usize = 0;
    while (iter.next()) |val| {
        results[count] = val;
        count += 1;
    }
    try testing.expect(count == 3);
    // All three values should be present (3, 4, 5)
    var has3 = false;
    var has4 = false;
    var has5 = false;
    for (results[0..count]) |v| {
        if (v == 3) has3 = true;
        if (v == 4) has4 = true;
        if (v == 5) has5 = true;
    }
    try testing.expect(has3);
    try testing.expect(has4);
    try testing.expect(has5);
}

test "SequenceIterator - single star with empty mailbox" {
    var iter = imap.SequenceIterator.init("*", 0);
    // max_seq=0, * maps to 0, which is < 1 so filtered
    try testing.expectEqual(@as(?u32, null), iter.next());
}

// =============================================================================
// MaildirFlags tests
// =============================================================================

test "MaildirFlags - parse seen flag" {
    const flags = imap.MaildirFlags.fromFilename("1234.eml:2,S");
    try testing.expect(flags.seen);
    try testing.expect(!flags.answered);
    try testing.expect(!flags.flagged);
    try testing.expect(!flags.draft);
    try testing.expect(!flags.deleted);
}

test "MaildirFlags - parse multiple flags" {
    const flags = imap.MaildirFlags.fromFilename("msg.eml:2,DFRS");
    try testing.expect(flags.seen);
    try testing.expect(flags.answered);
    try testing.expect(flags.flagged);
    try testing.expect(flags.draft);
    try testing.expect(!flags.deleted);
}

test "MaildirFlags - parse all flags" {
    const flags = imap.MaildirFlags.fromFilename("msg.eml:2,DFRST");
    try testing.expect(flags.seen);
    try testing.expect(flags.answered);
    try testing.expect(flags.flagged);
    try testing.expect(flags.draft);
    try testing.expect(flags.deleted);
}

test "MaildirFlags - no flags suffix" {
    const flags = imap.MaildirFlags.fromFilename("msg.eml");
    try testing.expect(!flags.seen);
    try testing.expect(!flags.answered);
    try testing.expect(!flags.flagged);
    try testing.expect(!flags.draft);
    try testing.expect(!flags.deleted);
}

test "MaildirFlags - empty flags after colon" {
    const flags = imap.MaildirFlags.fromFilename("msg.eml:2,");
    try testing.expect(!flags.seen);
    try testing.expect(!flags.answered);
}

test "MaildirFlags - baseName strips flag suffix" {
    try testing.expectEqualStrings("msg.eml", imap.MaildirFlags.baseName("msg.eml:2,S"));
    try testing.expectEqualStrings("msg.eml", imap.MaildirFlags.baseName("msg.eml:2,DFRS"));
    try testing.expectEqualStrings("msg.eml", imap.MaildirFlags.baseName("msg.eml"));
}

test "MaildirFlags - toImapString" {
    var flags = imap.MaildirFlags{ .seen = true, .flagged = true };
    var buf: [256]u8 = undefined;
    const result = flags.toImapString(&buf);
    try testing.expect(std.mem.indexOf(u8, result, "\\Seen") != null);
    try testing.expect(std.mem.indexOf(u8, result, "\\Flagged") != null);
}

test "MaildirFlags - toImapString empty" {
    var flags = imap.MaildirFlags{};
    var buf: [256]u8 = undefined;
    const result = flags.toImapString(&buf);
    try testing.expectEqual(@as(usize, 0), result.len);
}

test "MaildirFlags - toSuffix" {
    var flags = imap.MaildirFlags{ .seen = true, .answered = true };
    var buf: [16]u8 = undefined;
    const result = flags.toSuffix(&buf);
    try testing.expectEqualStrings(":2,RS", result);
}

test "MaildirFlags - toSuffix alphabetical order" {
    // Maildir spec requires flags in alphabetical order: D, F, R, S, T
    var flags = imap.MaildirFlags{ .deleted = true, .flagged = true, .answered = true, .seen = true, .draft = true };
    var buf: [16]u8 = undefined;
    const result = flags.toSuffix(&buf);
    try testing.expectEqualStrings(":2,DFRST", result);
}

test "MaildirFlags - applyAction add flags" {
    var flags = imap.MaildirFlags{};
    flags.applyAction("+FLAGS (\\Seen)");
    try testing.expect(flags.seen);
    try testing.expect(!flags.flagged);

    flags.applyAction("+FLAGS (\\Flagged)");
    try testing.expect(flags.seen);
    try testing.expect(flags.flagged);
}

test "MaildirFlags - applyAction remove flags" {
    var flags = imap.MaildirFlags{ .seen = true, .flagged = true };
    flags.applyAction("-FLAGS (\\Seen)");
    try testing.expect(!flags.seen);
    try testing.expect(flags.flagged);
}

test "MaildirFlags - roundtrip parse-format-parse" {
    const original_name = "msg.eml:2,FRS";
    const flags = imap.MaildirFlags.fromFilename(original_name);
    try testing.expect(flags.seen);
    try testing.expect(flags.answered);
    try testing.expect(flags.flagged);

    var suffix_buf: [16]u8 = undefined;
    const suffix = flags.toSuffix(&suffix_buf);

    // Reconstruct filename
    var name_buf: [256]u8 = undefined;
    const base = imap.MaildirFlags.baseName(original_name);
    const new_name = std.fmt.bufPrint(&name_buf, "{s}{s}", .{ base, suffix }) catch unreachable;

    // Parse again and verify
    const flags2 = imap.MaildirFlags.fromFilename(new_name);
    try testing.expect(flags2.seen);
    try testing.expect(flags2.answered);
    try testing.expect(flags2.flagged);
    try testing.expect(!flags2.draft);
    try testing.expect(!flags2.deleted);
}

// =============================================================================
// IMAP command parsing tests
// =============================================================================

test "ImapCommand - fromString basic commands" {
    try testing.expectEqual(imap.ImapCommand.login, imap.ImapCommand.fromString("LOGIN").?);
    try testing.expectEqual(imap.ImapCommand.select, imap.ImapCommand.fromString("SELECT").?);
    try testing.expectEqual(imap.ImapCommand.fetch, imap.ImapCommand.fromString("FETCH").?);
    try testing.expectEqual(imap.ImapCommand.store, imap.ImapCommand.fromString("STORE").?);
    try testing.expectEqual(imap.ImapCommand.copy, imap.ImapCommand.fromString("COPY").?);
    try testing.expectEqual(imap.ImapCommand.uid, imap.ImapCommand.fromString("UID").?);
    try testing.expectEqual(imap.ImapCommand.idle, imap.ImapCommand.fromString("IDLE").?);
    try testing.expectEqual(imap.ImapCommand.list, imap.ImapCommand.fromString("LIST").?);
    try testing.expectEqual(imap.ImapCommand.logout, imap.ImapCommand.fromString("LOGOUT").?);
    try testing.expectEqual(imap.ImapCommand.capability, imap.ImapCommand.fromString("CAPABILITY").?);
    try testing.expectEqual(imap.ImapCommand.noop, imap.ImapCommand.fromString("NOOP").?);
    try testing.expectEqual(imap.ImapCommand.close, imap.ImapCommand.fromString("CLOSE").?);
    try testing.expectEqual(imap.ImapCommand.expunge, imap.ImapCommand.fromString("EXPUNGE").?);
    try testing.expectEqual(imap.ImapCommand.search, imap.ImapCommand.fromString("SEARCH").?);
    try testing.expectEqual(imap.ImapCommand.create, imap.ImapCommand.fromString("CREATE").?);
    try testing.expectEqual(imap.ImapCommand.delete, imap.ImapCommand.fromString("DELETE").?);
    try testing.expectEqual(imap.ImapCommand.subscribe, imap.ImapCommand.fromString("SUBSCRIBE").?);
    try testing.expectEqual(imap.ImapCommand.unsubscribe, imap.ImapCommand.fromString("UNSUBSCRIBE").?);
    try testing.expectEqual(imap.ImapCommand.starttls, imap.ImapCommand.fromString("STARTTLS").?);
    try testing.expectEqual(imap.ImapCommand.authenticate, imap.ImapCommand.fromString("AUTHENTICATE").?);
    try testing.expectEqual(imap.ImapCommand.append, imap.ImapCommand.fromString("APPEND").?);
    try testing.expectEqual(imap.ImapCommand.move, imap.ImapCommand.fromString("MOVE").?);
    try testing.expectEqual(imap.ImapCommand.namespace, imap.ImapCommand.fromString("NAMESPACE").?);
}

test "ImapCommand - fromString unknown returns null" {
    try testing.expect(imap.ImapCommand.fromString("UNKNOWN") == null);
    try testing.expect(imap.ImapCommand.fromString("NOTACOMMAND") == null);
    try testing.expect(imap.ImapCommand.fromString("") == null);
}
