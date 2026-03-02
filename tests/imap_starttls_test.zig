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
