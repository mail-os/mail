// IMAP STARTTLS and SELECT Test Suite
// Tests for STARTTLS command parsing, standard mailbox handling in SELECT,
// and ImapCommand.fromString case-insensitive parsing.

const std = @import("std");
const testing = std.testing;
const imap = @import("mail").imap;

// =============================================================================
// ImapCommand.fromString — STARTTLS parsing
// =============================================================================

test "fromString parses STARTTLS" {
    const cmd = imap.ImapCommand.fromString("STARTTLS");
    try testing.expect(cmd != null);
    try testing.expect(cmd.? == .starttls);
}

test "fromString parses starttls case-insensitive" {
    const variants = [_][]const u8{ "starttls", "Starttls", "StartTLS", "STARTTLS", "startTLS" };
    for (variants) |v| {
        const cmd = imap.ImapCommand.fromString(v);
        try testing.expect(cmd != null);
        try testing.expect(cmd.? == .starttls);
    }
}

// =============================================================================
// ImapCommand.fromString — all IMAP commands
// =============================================================================

test "fromString parses all standard IMAP commands" {
    const cases = .{
        .{ "CAPABILITY", imap.ImapCommand.capability },
        .{ "NOOP", imap.ImapCommand.noop },
        .{ "LOGOUT", imap.ImapCommand.logout },
        .{ "STARTTLS", imap.ImapCommand.starttls },
        .{ "AUTHENTICATE", imap.ImapCommand.authenticate },
        .{ "LOGIN", imap.ImapCommand.login },
        .{ "SELECT", imap.ImapCommand.select },
        .{ "EXAMINE", imap.ImapCommand.examine },
        .{ "CREATE", imap.ImapCommand.create },
        .{ "DELETE", imap.ImapCommand.delete },
        .{ "RENAME", imap.ImapCommand.rename },
        .{ "SUBSCRIBE", imap.ImapCommand.subscribe },
        .{ "UNSUBSCRIBE", imap.ImapCommand.unsubscribe },
        .{ "LIST", imap.ImapCommand.list },
        .{ "XLIST", imap.ImapCommand.xlist },
        .{ "LSUB", imap.ImapCommand.lsub },
        .{ "STATUS", imap.ImapCommand.status },
        .{ "APPEND", imap.ImapCommand.append },
        .{ "CHECK", imap.ImapCommand.check },
        .{ "CLOSE", imap.ImapCommand.close },
        .{ "EXPUNGE", imap.ImapCommand.expunge },
        .{ "SEARCH", imap.ImapCommand.search },
        .{ "FETCH", imap.ImapCommand.fetch },
        .{ "STORE", imap.ImapCommand.store },
        .{ "COPY", imap.ImapCommand.copy },
        .{ "UID", imap.ImapCommand.uid },
        .{ "IDLE", imap.ImapCommand.idle },
        .{ "NAMESPACE", imap.ImapCommand.namespace },
        .{ "ENABLE", imap.ImapCommand.enable },
        .{ "ID", imap.ImapCommand.id },
    };

    inline for (cases) |case| {
        const cmd = imap.ImapCommand.fromString(case[0]);
        try testing.expect(cmd != null);
        try testing.expect(cmd.? == case[1]);
    }
}

test "fromString returns null for unknown commands" {
    try testing.expect(imap.ImapCommand.fromString("UNKNOWN") == null);
    try testing.expect(imap.ImapCommand.fromString("FOOBAR") == null);
    try testing.expect(imap.ImapCommand.fromString("") == null);
    try testing.expect(imap.ImapCommand.fromString("SELEC") == null);
}

test "fromString is case-insensitive for all commands" {
    // Test lowercase, mixed case for a few representative commands
    const cases = [_]struct { input: []const u8, expected: imap.ImapCommand }{
        .{ .input = "select", .expected = .select },
        .{ .input = "Select", .expected = .select },
        .{ .input = "login", .expected = .login },
        .{ .input = "Login", .expected = .login },
        .{ .input = "fetch", .expected = .fetch },
        .{ .input = "FETCH", .expected = .fetch },
        .{ .input = "idle", .expected = .idle },
        .{ .input = "Idle", .expected = .idle },
        .{ .input = "capability", .expected = .capability },
    };

    for (cases) |case| {
        const cmd = imap.ImapCommand.fromString(case.input);
        try testing.expect(cmd != null);
        try testing.expect(cmd.? == case.expected);
    }
}

// =============================================================================
// ImapState enum
// =============================================================================

test "ImapState has all expected values" {
    // Verify the four IMAP states exist (RFC 3501 Section 3)
    const states = [_]imap.ImapState{
        .not_authenticated,
        .authenticated,
        .selected,
        .logout,
    };
    // Each state should be distinct
    for (states, 0..) |s_a, i| {
        for (states[i + 1 ..]) |s_b| {
            try testing.expect(s_a != s_b);
        }
    }
}

// =============================================================================
// FolderType — standard mailboxes used in SELECT
// =============================================================================

test "standard mailbox FolderTypes have correct names" {
    // These are the mailboxes that handleSelect creates directories for
    try testing.expectEqualStrings("INBOX", imap.FolderType.inbox.getName());
    try testing.expectEqualStrings("Sent", imap.FolderType.sent.getName());
    try testing.expectEqualStrings("Drafts", imap.FolderType.drafts.getName());
    try testing.expectEqualStrings("Trash", imap.FolderType.trash.getName());
    try testing.expectEqualStrings("Junk", imap.FolderType.junk.getName());
    try testing.expectEqualStrings("Archive", imap.FolderType.archive.getName());
}

test "standard mailbox FolderTypes have SPECIAL-USE attributes" {
    // RFC 6154 SPECIAL-USE attributes
    try testing.expect(std.mem.indexOf(u8, imap.FolderType.sent.getAttributes(), "\\Sent") != null);
    try testing.expect(std.mem.indexOf(u8, imap.FolderType.drafts.getAttributes(), "\\Drafts") != null);
    try testing.expect(std.mem.indexOf(u8, imap.FolderType.trash.getAttributes(), "\\Trash") != null);
    try testing.expect(std.mem.indexOf(u8, imap.FolderType.junk.getAttributes(), "\\Junk") != null);
    try testing.expect(std.mem.indexOf(u8, imap.FolderType.archive.getAttributes(), "\\Archive") != null);
}

test "standard mailboxes are not virtual" {
    // Physical mailboxes that store .eml files on disk
    try testing.expect(!imap.FolderType.inbox.isVirtual());
    try testing.expect(!imap.FolderType.sent.isVirtual());
    try testing.expect(!imap.FolderType.drafts.isVirtual());
    try testing.expect(!imap.FolderType.trash.isVirtual());
    try testing.expect(!imap.FolderType.junk.isVirtual());
    try testing.expect(!imap.FolderType.archive.isVirtual());
}

// =============================================================================
// Mailbox struct
// =============================================================================

test "Mailbox.init creates valid mailbox" {
    var mbox = try imap.Mailbox.init(testing.allocator, "INBOX", "/tmp/test/INBOX");
    defer mbox.deinit(testing.allocator);

    try testing.expectEqualStrings("INBOX", mbox.name);
    try testing.expectEqualStrings("/tmp/test/INBOX", mbox.path);
    try testing.expectEqual(@as(usize, 0), mbox.exists);
    try testing.expectEqual(@as(usize, 0), mbox.recent);
}

test "Mailbox.init for Sent folder" {
    var mbox = try imap.Mailbox.init(testing.allocator, "Sent", "/tmp/test/Sent");
    defer mbox.deinit(testing.allocator);

    try testing.expectEqualStrings("Sent", mbox.name);
}

// =============================================================================
// MessageFlags
// =============================================================================

test "MessageFlags.toString includes set flags" {
    const flags = imap.MessageFlags{
        .seen = true,
        .answered = true,
        .flagged = false,
        .deleted = false,
        .draft = true,
        .recent = false,
    };

    const result = try flags.toString(testing.allocator);
    defer testing.allocator.free(result);
    try testing.expect(std.mem.indexOf(u8, result, "\\Seen") != null);
    try testing.expect(std.mem.indexOf(u8, result, "\\Answered") != null);
    try testing.expect(std.mem.indexOf(u8, result, "\\Draft") != null);
    try testing.expect(std.mem.indexOf(u8, result, "\\Flagged") == null);
    try testing.expect(std.mem.indexOf(u8, result, "\\Deleted") == null);
}

test "MessageFlags.toString empty flags" {
    const flags = imap.MessageFlags{
        .seen = false,
        .answered = false,
        .flagged = false,
        .deleted = false,
        .draft = false,
        .recent = false,
    };

    const result = try flags.toString(testing.allocator);
    defer testing.allocator.free(result);
    // Should contain just "()" with no flag names
    try testing.expectEqualStrings("()", result);
}

// =============================================================================
// ImapCapability
// =============================================================================

test "ImapCapability.toString returns correct strings" {
    try testing.expectEqualStrings("IMAP4rev1", imap.ImapCapability.imap4rev1.toString());
    try testing.expectEqualStrings("STARTTLS", imap.ImapCapability.starttls.toString());
    try testing.expectEqualStrings("IDLE", imap.ImapCapability.idle.toString());
    try testing.expectEqualStrings("NAMESPACE", imap.ImapCapability.namespace.toString());
}

test "STARTTLS capability is listed" {
    // Verify STARTTLS exists as a capability enum value
    const cap = imap.ImapCapability.starttls;
    try testing.expectEqualStrings("STARTTLS", cap.toString());
}

// =============================================================================
// MaildirFlags — flag parsing, persistence, and COPY/MOVE flag preservation
// =============================================================================

test "MaildirFlags.fromFilename parses :2,S as Seen" {
    const flags = imap.MaildirFlags.fromFilename("1772259313773.eml:2,S");
    try testing.expect(flags.seen);
    try testing.expect(!flags.answered);
    try testing.expect(!flags.flagged);
    try testing.expect(!flags.draft);
    try testing.expect(!flags.deleted);
}

test "MaildirFlags.fromFilename parses multiple flags" {
    const flags = imap.MaildirFlags.fromFilename("msg.eml:2,FRS");
    try testing.expect(flags.seen);
    try testing.expect(flags.answered); // R = Replied/Answered
    try testing.expect(flags.flagged);
    try testing.expect(!flags.draft);
    try testing.expect(!flags.deleted);
}

test "MaildirFlags.fromFilename parses all flags" {
    const flags = imap.MaildirFlags.fromFilename("msg.eml:2,DFRST");
    try testing.expect(flags.draft);
    try testing.expect(flags.flagged);
    try testing.expect(flags.answered);
    try testing.expect(flags.seen);
    try testing.expect(flags.deleted);
}

test "MaildirFlags.fromFilename returns empty flags for no suffix" {
    const flags = imap.MaildirFlags.fromFilename("1772259313773.eml");
    try testing.expect(!flags.seen);
    try testing.expect(!flags.answered);
    try testing.expect(!flags.flagged);
    try testing.expect(!flags.draft);
    try testing.expect(!flags.deleted);
}

test "MaildirFlags.baseName strips flag suffix" {
    try testing.expectEqualStrings("msg.eml", imap.MaildirFlags.baseName("msg.eml:2,S"));
    try testing.expectEqualStrings("msg.eml", imap.MaildirFlags.baseName("msg.eml:2,DFRST"));
    try testing.expectEqualStrings("msg.eml", imap.MaildirFlags.baseName("msg.eml"));
}

test "MaildirFlags.toSuffix generates correct Maildir suffix" {
    var flags = imap.MaildirFlags{};
    flags.seen = true;
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings(":2,S", flags.toSuffix(&buf));
}

test "MaildirFlags.toSuffix alphabetical order per Maildir spec" {
    var flags = imap.MaildirFlags{
        .draft = true,
        .flagged = true,
        .answered = true,
        .seen = true,
        .deleted = true,
    };
    var buf: [16]u8 = undefined;
    // Maildir spec requires alphabetical order: D, F, R, S, T
    try testing.expectEqualStrings(":2,DFRST", flags.toSuffix(&buf));
}

test "MaildirFlags round-trip: parse then regenerate preserves flags" {
    // This is the exact scenario for COPY/MOVE: read flags from source filename,
    // then generate a new filename with the same flags.
    const source = "1772259313773.eml:2,S";
    const flags = imap.MaildirFlags.fromFilename(source);
    var suffix_buf: [16]u8 = undefined;
    const suffix = flags.toSuffix(&suffix_buf);

    // The new destination filename should have the same :2,S suffix
    try testing.expectEqualStrings(":2,S", suffix);
    try testing.expect(flags.seen);
}

test "MaildirFlags round-trip preserves multiple flags (archive read+flagged email)" {
    const source = "msg.eml:2,FS";
    const flags = imap.MaildirFlags.fromFilename(source);
    var suffix_buf: [16]u8 = undefined;
    const suffix = flags.toSuffix(&suffix_buf);

    try testing.expectEqualStrings(":2,FS", suffix);
    try testing.expect(flags.seen);
    try testing.expect(flags.flagged);
}

test "MaildirFlags.toImapString formats correctly" {
    var flags = imap.MaildirFlags{ .seen = true, .flagged = true };
    var buf: [256]u8 = undefined;
    const result = flags.toImapString(&buf);
    try testing.expect(std.mem.indexOf(u8, result, "\\Seen") != null);
    try testing.expect(std.mem.indexOf(u8, result, "\\Flagged") != null);
}

test "MaildirFlags.toImapString empty flags" {
    var flags = imap.MaildirFlags{};
    var buf: [256]u8 = undefined;
    const result = flags.toImapString(&buf);
    try testing.expectEqual(@as(usize, 0), result.len);
}

test "MaildirFlags.applyAction adds flags with +FLAGS" {
    var flags = imap.MaildirFlags{ .seen = true };
    flags.applyAction("+FLAGS (\\Flagged \\Answered)");
    try testing.expect(flags.seen); // preserved
    try testing.expect(flags.flagged); // added
    try testing.expect(flags.answered); // added
}

test "MaildirFlags.applyAction removes flags with -FLAGS" {
    var flags = imap.MaildirFlags{ .seen = true, .flagged = true };
    flags.applyAction("-FLAGS (\\Seen)");
    try testing.expect(!flags.seen); // removed
    try testing.expect(flags.flagged); // preserved
}

test "MaildirFlags.applyAction replaces all flags with FLAGS" {
    var flags = imap.MaildirFlags{ .seen = true, .flagged = true, .answered = true };
    flags.applyAction("FLAGS (\\Deleted)");
    try testing.expect(!flags.seen);
    try testing.expect(!flags.flagged);
    try testing.expect(!flags.answered);
    try testing.expect(flags.deleted);
}

test "MOVE capability is advertised" {
    const cap = imap.ImapCapability.move;
    try testing.expectEqualStrings("MOVE", cap.toString());
}

test "fromString parses MOVE command" {
    const cmd = imap.ImapCommand.fromString("MOVE");
    try testing.expect(cmd != null);
    try testing.expect(cmd.? == .move);
}
