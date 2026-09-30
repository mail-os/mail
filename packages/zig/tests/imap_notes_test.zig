// IMAP Notes Folder Test Suite
// Tests for the Notes folder type added to support Apple Notes sync via IMAP.
// Apple Notes uses a special IMAP "Notes" folder with X-Uniform-Type-Identifier
// headers on messages.

const std = @import("std");
const testing = std.testing;
const imap = @import("mail").imap;

// =============================================================================
// FolderType.notes Tests
// =============================================================================

test "FolderType.notes has correct name" {
    const name = imap.FolderType.notes.getName();
    try testing.expectEqualStrings("Notes", name);
}

test "FolderType.notes has correct attributes" {
    const attrs = imap.FolderType.notes.getAttributes();
    try testing.expectEqualStrings("\\HasNoChildren", attrs);
}

test "FolderType.notes is not virtual" {
    // Notes stores real messages (Apple Notes are IMAP messages with special headers)
    try testing.expect(!imap.FolderType.notes.isVirtual());
}

test "FolderType.notes appears in GmailFolders array" {
    var found = false;
    for (imap.GmailFolders) |folder| {
        if (folder == .notes) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

// =============================================================================
// GmailFolders Completeness Tests
// =============================================================================

test "GmailFolders includes all standard categories" {
    // Verify all expected folder types are present
    const expected = [_]imap.FolderType{
        .inbox,
        .starred,
        .important,
        .sent,
        .drafts,
        .all_mail,
        .junk,
        .trash,
        .archive,
        .notes,
        .social,
        .forums,
        .updates,
        .promotions,
    };

    for (expected) |expected_type| {
        var found = false;
        for (imap.GmailFolders) |folder| {
            if (folder == expected_type) {
                found = true;
                break;
            }
        }
        try testing.expect(found);
    }
}

test "GmailFolders has expected count" {
    // 14 folders: inbox, starred, important, sent, drafts, all_mail,
    //             junk, trash, archive, notes, social, forums, updates, promotions
    try testing.expectEqual(@as(usize, 14), imap.GmailFolders.len);
}

// =============================================================================
// FolderType Enum Distinctness Tests
// =============================================================================

test "all FolderType names are distinct and non-empty" {
    const all_types = [_]imap.FolderType{
        .inbox,
        .sent,
        .drafts,
        .trash,
        .junk,
        .archive,
        .all_mail,
        .starred,
        .important,
        .social,
        .forums,
        .updates,
        .promotions,
        .notes,
    };

    // Check all names are non-empty (except .regular which is "")
    for (all_types) |ft| {
        const name = ft.getName();
        try testing.expect(name.len > 0);
    }

    // Check no two types have the same name
    for (all_types, 0..) |ft_a, i| {
        for (all_types[i + 1 ..]) |ft_b| {
            const name_a = ft_a.getName();
            const name_b = ft_b.getName();
            try testing.expect(!std.mem.eql(u8, name_a, name_b));
        }
    }
}

test "virtual folders are only starred, important, and all_mail" {
    try testing.expect(imap.FolderType.starred.isVirtual());
    try testing.expect(imap.FolderType.important.isVirtual());
    try testing.expect(imap.FolderType.all_mail.isVirtual());

    // All others should not be virtual
    try testing.expect(!imap.FolderType.inbox.isVirtual());
    try testing.expect(!imap.FolderType.sent.isVirtual());
    try testing.expect(!imap.FolderType.drafts.isVirtual());
    try testing.expect(!imap.FolderType.trash.isVirtual());
    try testing.expect(!imap.FolderType.junk.isVirtual());
    try testing.expect(!imap.FolderType.archive.isVirtual());
    try testing.expect(!imap.FolderType.notes.isVirtual());
    try testing.expect(!imap.FolderType.social.isVirtual());
    try testing.expect(!imap.FolderType.forums.isVirtual());
    try testing.expect(!imap.FolderType.updates.isVirtual());
    try testing.expect(!imap.FolderType.promotions.isVirtual());
    try testing.expect(!imap.FolderType.regular.isVirtual());
}

// =============================================================================
// Notes Folder Position Test
// =============================================================================

test "Notes folder appears after archive and before social categories" {
    // Find indices
    var notes_idx: ?usize = null;
    var archive_idx: ?usize = null;
    var social_idx: ?usize = null;

    for (imap.GmailFolders, 0..) |folder, idx| {
        if (folder == .notes) notes_idx = idx;
        if (folder == .archive) archive_idx = idx;
        if (folder == .social) social_idx = idx;
    }

    try testing.expect(notes_idx != null);
    try testing.expect(archive_idx != null);
    try testing.expect(social_idx != null);

    // Notes should come after archive
    try testing.expect(notes_idx.? > archive_idx.?);
    // Notes should come before social
    try testing.expect(notes_idx.? < social_idx.?);
}
