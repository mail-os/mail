const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");
const database = @import("database.zig");
const filter = @import("../message/filter.zig");

/// Database storage backend for email messages
/// Stores entire email messages in SQLite database
/// Provides fast indexing and querying capabilities
pub const DatabaseStorage = struct {
    allocator: std.mem.Allocator,
    db: *database.Database,
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator, db: *database.Database) !DatabaseStorage {
        var storage = DatabaseStorage{
            .allocator = allocator,
            .db = db,
            .mutex = .{},
        };

        // Initialize schema if not exists
        try storage.initSchema();

        return storage;
    }

    pub fn deinit(self: *DatabaseStorage) void {
        _ = self;
    }

    /// Initialize database schema for message storage
    fn initSchema(self: *DatabaseStorage) !void {
        const schema =
            \\CREATE TABLE IF NOT EXISTS messages (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    message_id TEXT UNIQUE NOT NULL,
            \\    email TEXT NOT NULL,
            \\    sender TEXT NOT NULL,
            \\    recipients TEXT NOT NULL,
            \\    subject TEXT,
            \\    body TEXT NOT NULL,
            \\    headers TEXT,
            \\    size INTEGER NOT NULL,
            \\    received_at INTEGER NOT NULL,
            \\    flags INTEGER DEFAULT 0,
            \\    folder TEXT DEFAULT 'INBOX',
            \\    deleted_at INTEGER DEFAULT NULL,
            \\    deleted_by TEXT DEFAULT NULL
            \\);
            \\
            \\CREATE INDEX IF NOT EXISTS idx_messages_email ON messages(email);
            \\CREATE INDEX IF NOT EXISTS idx_messages_message_id ON messages(message_id);
            \\CREATE INDEX IF NOT EXISTS idx_messages_received_at ON messages(received_at);
            \\CREATE INDEX IF NOT EXISTS idx_messages_folder ON messages(folder);
            \\CREATE INDEX IF NOT EXISTS idx_messages_flags ON messages(flags);
            \\CREATE INDEX IF NOT EXISTS idx_messages_deleted_at ON messages(deleted_at);
            \\
            \\CREATE TABLE IF NOT EXISTS attachments (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    message_id INTEGER NOT NULL,
            \\    filename TEXT NOT NULL,
            \\    content_type TEXT,
            \\    size INTEGER NOT NULL,
            \\    data BLOB NOT NULL,
            \\    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
            \\);
            \\
            \\CREATE INDEX IF NOT EXISTS idx_attachments_message_id ON attachments(message_id);
        ;

        try self.db.exec(schema);

        // Defensive migration: add soft-delete columns to existing databases
        self.db.exec("ALTER TABLE messages ADD COLUMN deleted_at INTEGER DEFAULT NULL") catch {};
        self.db.exec("ALTER TABLE messages ADD COLUMN deleted_by TEXT DEFAULT NULL") catch {};
        self.db.exec("CREATE INDEX IF NOT EXISTS idx_messages_deleted_at ON messages(deleted_at)") catch {};
    }

    /// Store a message in the database
    pub fn storeMessage(
        self: *DatabaseStorage,
        email: []const u8,
        message_id: []const u8,
        sender: []const u8,
        recipients: []const []const u8,
        subject: ?[]const u8,
        headers: []const u8,
        body: []const u8,
    ) !i64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Join recipients into comma-separated string
        var recipients_str = std.ArrayList(u8).init(self.allocator);
        defer recipients_str.deinit(self.allocator);

        for (recipients, 0..) |recipient, i| {
            try recipients_str.appendSlice(self.allocator, recipient);
            if (i < recipients.len - 1) {
                try recipients_str.append(self.allocator, ',');
            }
        }

        const size = body.len;
        const received_at = time_compat.timestamp();

        const query =
            \\INSERT INTO messages (message_id, email, sender, recipients, subject, body, headers, size, received_at)
            \\VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ;

        var stmt = try self.db.prepare(query);
        defer stmt.finalize();

        try stmt.bind(1, message_id);
        try stmt.bind(2, email);
        try stmt.bind(3, sender);
        try stmt.bind(4, recipients_str.items);
        try stmt.bind(5, subject orelse "");
        try stmt.bind(6, body);
        try stmt.bind(7, headers);
        try stmt.bind(8, @as(i64, @intCast(size)));
        try stmt.bind(9, received_at);

        try stmt.step();

        return self.db.lastInsertRowId();
    }

    /// Store a message with automatic Gmail-style categorization
    /// Parses headers and categorizes into Social, Forums, Updates, Promotions, or INBOX
    pub fn storeMessageWithCategory(
        self: *DatabaseStorage,
        email: []const u8,
        message_id: []const u8,
        sender: []const u8,
        recipients: []const []const u8,
        subject: ?[]const u8,
        headers: []const u8,
        body: []const u8,
    ) !i64 {
        // Parse headers into a hashmap for categorization
        var headers_map = std.StringHashMap([]const u8).init(self.allocator);
        defer headers_map.deinit();

        // Track allocated keys so we can free them after categorization
        var allocated_keys = std.ArrayList([]u8).init(self.allocator);
        defer {
            for (allocated_keys.items) |key_to_free| {
                self.allocator.free(key_to_free);
            }
            allocated_keys.deinit(self.allocator);
        }

        // Parse header lines (simple parsing: "Header-Name: value")
        var header_iter = std.mem.splitSequence(u8, headers, "\r\n");
        while (header_iter.next()) |line| {
            if (line.len == 0) continue;
            // Find the colon separator
            if (std.mem.indexOf(u8, line, ":")) |colon_pos| {
                const key = std.mem.trim(u8, line[0..colon_pos], " \t");
                const value = if (colon_pos + 1 < line.len)
                    std.mem.trim(u8, line[colon_pos + 1 ..], " \t")
                else
                    "";
                // Store lowercase key for case-insensitive matching
                var lower_key = try self.allocator.alloc(u8, key.len);
                for (key, 0..) |c, i| {
                    lower_key[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
                }
                try headers_map.put(lower_key, value);
                try allocated_keys.append(self.allocator, lower_key);
            }
        }

        // Categorize the email
        const category = filter.categorizeEmail(sender, &headers_map);

        // Map category to folder name
        const folder = switch (category) {
            .social => "Social",
            .forums => "Forums",
            .updates => "Updates",
            .promotions => "Promotions",
            .primary => "INBOX",
        };

        // Store the message with the determined folder
        self.mutex.lock();
        defer self.mutex.unlock();

        // Join recipients into comma-separated string
        var recipients_str = std.ArrayList(u8).init(self.allocator);
        defer recipients_str.deinit(self.allocator);

        for (recipients, 0..) |recipient, i| {
            try recipients_str.appendSlice(self.allocator, recipient);
            if (i < recipients.len - 1) {
                try recipients_str.append(self.allocator, ',');
            }
        }

        const size = body.len;
        const received_at = time_compat.timestamp();

        const query =
            \\INSERT INTO messages (message_id, email, sender, recipients, subject, body, headers, size, received_at, folder)
            \\VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ;

        var stmt = try self.db.prepare(query);
        defer stmt.finalize();

        try stmt.bind(1, message_id);
        try stmt.bind(2, email);
        try stmt.bind(3, sender);
        try stmt.bind(4, recipients_str.items);
        try stmt.bind(5, subject orelse "");
        try stmt.bind(6, body);
        try stmt.bind(7, headers);
        try stmt.bind(8, @as(i64, @intCast(size)));
        try stmt.bind(9, received_at);
        try stmt.bind(10, folder);

        try stmt.step();

        return self.db.lastInsertRowId();
    }

    /// Retrieve a message by ID (excludes soft-deleted messages)
    pub fn retrieveMessage(
        self: *DatabaseStorage,
        email: []const u8,
        message_id: []const u8,
    ) !?StoredMessage {
        self.mutex.lock();
        defer self.mutex.unlock();

        const query =
            \\SELECT id, sender, recipients, subject, body, headers, size, received_at, flags, folder
            \\FROM messages
            \\WHERE email = ? AND message_id = ? AND deleted_at IS NULL
        ;

        var stmt = try self.db.prepare(query);
        defer stmt.finalize();

        try stmt.bind(1, email);
        try stmt.bind(2, message_id);

        if (try stmt.step()) {
            const message = StoredMessage{
                .id = try stmt.columnInt64(0),
                .message_id = try self.allocator.dupe(u8, message_id),
                .email = try self.allocator.dupe(u8, email),
                .sender = try self.allocator.dupe(u8, try stmt.columnText(1)),
                .recipients = try self.parseRecipients(try stmt.columnText(2)),
                .subject = blk: {
                    const subj = try stmt.columnText(3);
                    if (subj.len == 0) break :blk null;
                    break :blk try self.allocator.dupe(u8, subj);
                },
                .body = try self.allocator.dupe(u8, try stmt.columnText(4)),
                .headers = try self.allocator.dupe(u8, try stmt.columnText(5)),
                .size = @intCast(try stmt.columnInt64(6)),
                .received_at = try stmt.columnInt64(7),
                .flags = @intCast(try stmt.columnInt64(8)),
                .folder = try self.allocator.dupe(u8, try stmt.columnText(9)),
            };

            return message;
        }

        return null;
    }

    /// List messages for an email address (excludes soft-deleted messages)
    pub fn listMessages(
        self: *DatabaseStorage,
        email: []const u8,
        folder: ?[]const u8,
        limit: usize,
        offset: usize,
    ) ![]StoredMessage {
        self.mutex.lock();
        defer self.mutex.unlock();

        const query = if (folder) |_|
            \\SELECT id, message_id, sender, recipients, subject, size, received_at, flags, folder
            \\FROM messages
            \\WHERE email = ? AND folder = ? AND deleted_at IS NULL
            \\ORDER BY received_at DESC
            \\LIMIT ? OFFSET ?
        else
            \\SELECT id, message_id, sender, recipients, subject, size, received_at, flags, folder
            \\FROM messages
            \\WHERE email = ? AND deleted_at IS NULL
            \\ORDER BY received_at DESC
            \\LIMIT ? OFFSET ?
        ;

        var stmt = try self.db.prepare(query);
        defer stmt.finalize();

        try stmt.bind(1, email);
        if (folder) |f| {
            try stmt.bind(2, f);
            try stmt.bind(3, @as(i64, @intCast(limit)));
            try stmt.bind(4, @as(i64, @intCast(offset)));
        } else {
            try stmt.bind(2, @as(i64, @intCast(limit)));
            try stmt.bind(3, @as(i64, @intCast(offset)));
        }

        var messages = std.ArrayList(StoredMessage).init(self.allocator);

        while (try stmt.step()) {
            const message = StoredMessage{
                .id = try stmt.columnInt64(0),
                .message_id = try self.allocator.dupe(u8, try stmt.columnText(1)),
                .email = try self.allocator.dupe(u8, email),
                .sender = try self.allocator.dupe(u8, try stmt.columnText(2)),
                .recipients = try self.parseRecipients(try stmt.columnText(3)),
                .subject = blk: {
                    const subj = try stmt.columnText(4);
                    if (subj.len == 0) break :blk null;
                    break :blk try self.allocator.dupe(u8, subj);
                },
                .body = "",
                .headers = "",
                .size = @intCast(try stmt.columnInt64(5)),
                .received_at = try stmt.columnInt64(6),
                .flags = @intCast(try stmt.columnInt64(7)),
                .folder = try self.allocator.dupe(u8, try stmt.columnText(8)),
            };

            try messages.append(self.allocator, message);
        }

        return try messages.toOwnedSlice(self.allocator);
    }

    /// Soft-delete a message (marks with deleted_at timestamp instead of removing)
    pub fn deleteMessage(
        self: *DatabaseStorage,
        email: []const u8,
        message_id: []const u8,
    ) !void {
        return self.softDeleteMessage(email, message_id, "system");
    }

    /// Soft-delete a message with the identity of who deleted it
    pub fn softDeleteMessage(
        self: *DatabaseStorage,
        email: []const u8,
        message_id: []const u8,
        deleted_by: []const u8,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const query =
            \\UPDATE messages SET deleted_at = ?, deleted_by = ?
            \\WHERE email = ? AND message_id = ? AND deleted_at IS NULL
        ;

        var stmt = try self.db.prepare(query);
        defer stmt.finalize();

        try stmt.bind(1, time_compat.timestamp());
        try stmt.bind(2, deleted_by);
        try stmt.bind(3, email);
        try stmt.bind(4, message_id);

        _ = try stmt.step();
    }

    /// Permanently delete a message from the database (admin/GDPR purge only)
    pub fn purgeMessage(
        self: *DatabaseStorage,
        email: []const u8,
        message_id: []const u8,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const query =
            \\DELETE FROM messages WHERE email = ? AND message_id = ?
        ;

        var stmt = try self.db.prepare(query);
        defer stmt.finalize();

        try stmt.bind(1, email);
        try stmt.bind(2, message_id);

        _ = try stmt.step();
    }

    /// Restore a soft-deleted message (undo soft-delete)
    pub fn restoreMessage(
        self: *DatabaseStorage,
        email: []const u8,
        message_id: []const u8,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const query =
            \\UPDATE messages SET deleted_at = NULL, deleted_by = NULL
            \\WHERE email = ? AND message_id = ? AND deleted_at IS NOT NULL
        ;

        var stmt = try self.db.prepare(query);
        defer stmt.finalize();

        try stmt.bind(1, email);
        try stmt.bind(2, message_id);

        _ = try stmt.step();
    }

    /// List soft-deleted messages for admin UI
    pub fn listDeletedMessages(
        self: *DatabaseStorage,
        email: []const u8,
        limit: usize,
        offset: usize,
    ) ![]StoredMessage {
        self.mutex.lock();
        defer self.mutex.unlock();

        const query =
            \\SELECT id, message_id, sender, recipients, subject, size, received_at, flags, folder, deleted_at, deleted_by
            \\FROM messages
            \\WHERE email = ? AND deleted_at IS NOT NULL
            \\ORDER BY deleted_at DESC
            \\LIMIT ? OFFSET ?
        ;

        var stmt = try self.db.prepare(query);
        defer stmt.finalize();

        try stmt.bind(1, email);
        try stmt.bind(2, @as(i64, @intCast(limit)));
        try stmt.bind(3, @as(i64, @intCast(offset)));

        var messages = std.ArrayList(StoredMessage).init(self.allocator);

        while (try stmt.step()) {
            const message = StoredMessage{
                .id = stmt.columnInt64(0),
                .message_id = try self.allocator.dupe(u8, stmt.columnText(1)),
                .email = try self.allocator.dupe(u8, email),
                .sender = try self.allocator.dupe(u8, stmt.columnText(2)),
                .recipients = try self.parseRecipients(stmt.columnText(3)),
                .subject = blk: {
                    const subj = stmt.columnText(4);
                    if (subj.len == 0) break :blk null;
                    break :blk try self.allocator.dupe(u8, subj);
                },
                .body = "",
                .headers = "",
                .size = @intCast(stmt.columnInt64(5)),
                .received_at = stmt.columnInt64(6),
                .flags = @intCast(stmt.columnInt64(7)),
                .folder = try self.allocator.dupe(u8, stmt.columnText(8)),
                .deleted_at = stmt.columnInt64Opt(9),
                .deleted_by = blk: {
                    const db = stmt.columnTextOpt(10);
                    if (db) |d| break :blk try self.allocator.dupe(u8, d);
                    break :blk null;
                },
            };

            try messages.append(self.allocator, message);
        }

        return try messages.toOwnedSlice(self.allocator);
    }

    /// Move message to folder
    pub fn moveMessage(
        self: *DatabaseStorage,
        email: []const u8,
        message_id: []const u8,
        folder: []const u8,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const query =
            \\UPDATE messages SET folder = ? WHERE email = ? AND message_id = ?
        ;

        var stmt = try self.db.prepare(query);
        defer stmt.finalize();

        try stmt.bind(1, folder);
        try stmt.bind(2, email);
        try stmt.bind(3, message_id);

        try stmt.step();
    }

    /// Set message flags
    pub fn setFlags(
        self: *DatabaseStorage,
        email: []const u8,
        message_id: []const u8,
        flags: MessageFlags,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const query =
            \\UPDATE messages SET flags = ? WHERE email = ? AND message_id = ?
        ;

        var stmt = try self.db.prepare(query);
        defer stmt.finalize();

        try stmt.bind(1, @as(i64, @intCast(flags.toInt())));
        try stmt.bind(2, email);
        try stmt.bind(3, message_id);

        try stmt.step();
    }

    /// Get message count for an email (excludes soft-deleted messages)
    pub fn getMessageCount(
        self: *DatabaseStorage,
        email: []const u8,
        folder: ?[]const u8,
    ) !usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        const query = if (folder) |_|
            \\SELECT COUNT(*) FROM messages WHERE email = ? AND folder = ? AND deleted_at IS NULL
        else
            \\SELECT COUNT(*) FROM messages WHERE email = ? AND deleted_at IS NULL
        ;

        var stmt = try self.db.prepare(query);
        defer stmt.finalize();

        try stmt.bind(1, email);
        if (folder) |f| {
            try stmt.bind(2, f);
        }

        if (try stmt.step()) {
            return @intCast(try stmt.columnInt64(0));
        }

        return 0;
    }

    /// Search messages (excludes soft-deleted messages)
    pub fn searchMessages(
        self: *DatabaseStorage,
        email: []const u8,
        query_text: []const u8,
        limit: usize,
    ) ![]StoredMessage {
        self.mutex.lock();
        defer self.mutex.unlock();

        const query =
            \\SELECT id, message_id, sender, recipients, subject, size, received_at, flags, folder
            \\FROM messages
            \\WHERE email = ? AND (subject LIKE ? OR body LIKE ? OR sender LIKE ?) AND deleted_at IS NULL
            \\ORDER BY received_at DESC
            \\LIMIT ?
        ;

        var stmt = try self.db.prepare(query);
        defer stmt.finalize();

        const search_pattern = try std.fmt.allocPrint(self.allocator, "%{s}%", .{query_text});
        defer self.allocator.free(search_pattern);

        try stmt.bind(1, email);
        try stmt.bind(2, search_pattern);
        try stmt.bind(3, search_pattern);
        try stmt.bind(4, search_pattern);
        try stmt.bind(5, @as(i64, @intCast(limit)));

        var messages = std.ArrayList(StoredMessage).init(self.allocator);

        while (try stmt.step()) {
            const message = StoredMessage{
                .id = try stmt.columnInt64(0),
                .message_id = try self.allocator.dupe(u8, try stmt.columnText(1)),
                .email = try self.allocator.dupe(u8, email),
                .sender = try self.allocator.dupe(u8, try stmt.columnText(2)),
                .recipients = try self.parseRecipients(try stmt.columnText(3)),
                .subject = blk: {
                    const subj = try stmt.columnText(4);
                    if (subj.len == 0) break :blk null;
                    break :blk try self.allocator.dupe(u8, subj);
                },
                .body = "",
                .headers = "",
                .size = @intCast(try stmt.columnInt64(5)),
                .received_at = try stmt.columnInt64(6),
                .flags = @intCast(try stmt.columnInt64(7)),
                .folder = try self.allocator.dupe(u8, try stmt.columnText(8)),
            };

            try messages.append(self.allocator, message);
        }

        return try messages.toOwnedSlice(self.allocator);
    }

    /// Helper to parse recipients string
    fn parseRecipients(self: *DatabaseStorage, recipients_str: []const u8) ![][]const u8 {
        var recipients = std.ArrayList([]const u8).init(self.allocator);

        var iter = std.mem.splitScalar(u8, recipients_str, ',');
        while (iter.next()) |recipient| {
            try recipients.append(self.allocator, try self.allocator.dupe(u8, recipient));
        }

        return try recipients.toOwnedSlice(self.allocator);
    }
};

/// Stored message structure
pub const StoredMessage = struct {
    id: i64,
    message_id: []const u8,
    email: []const u8,
    sender: []const u8,
    recipients: [][]const u8,
    subject: ?[]const u8,
    body: []const u8,
    headers: []const u8,
    size: usize,
    received_at: i64,
    flags: u32,
    folder: []const u8,
    deleted_at: ?i64 = null,
    deleted_by: ?[]const u8 = null,

    pub fn deinit(self: *StoredMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.message_id);
        allocator.free(self.email);
        allocator.free(self.sender);
        for (self.recipients) |recipient| {
            allocator.free(recipient);
        }
        allocator.free(self.recipients);
        if (self.subject) |subj| {
            allocator.free(subj);
        }
        allocator.free(self.body);
        allocator.free(self.headers);
        allocator.free(self.folder);
        if (self.deleted_by) |db| {
            allocator.free(db);
        }
    }
};

/// Message flags (IMAP-style)
pub const MessageFlags = struct {
    seen: bool = false,
    answered: bool = false,
    flagged: bool = false,
    deleted: bool = false,
    draft: bool = false,

    pub fn toInt(self: MessageFlags) u32 {
        var flags: u32 = 0;
        if (self.seen) flags |= 0x01;
        if (self.answered) flags |= 0x02;
        if (self.flagged) flags |= 0x04;
        if (self.deleted) flags |= 0x08;
        if (self.draft) flags |= 0x10;
        return flags;
    }

    pub fn fromInt(flags: u32) MessageFlags {
        return .{
            .seen = (flags & 0x01) != 0,
            .answered = (flags & 0x02) != 0,
            .flagged = (flags & 0x04) != 0,
            .deleted = (flags & 0x08) != 0,
            .draft = (flags & 0x10) != 0,
        };
    }
};

test "database storage initialization" {
    const testing = std.testing;

    var db = try database.Database.init(testing.allocator, ":memory:");
    defer db.deinit();
    try db.initSchema();

    var storage = try DatabaseStorage.init(testing.allocator, &db);
    defer storage.deinit();

    // Schema should be created
    try testing.expect(true);
}

test "store and retrieve message" {
    const testing = std.testing;

    var db = try database.Database.init(testing.allocator, ":memory:");
    defer db.deinit();
    try db.initSchema();

    var storage = try DatabaseStorage.init(testing.allocator, &db);
    defer storage.deinit();

    const recipients = [_][]const u8{"recipient@example.com"};
    const msg_id = try storage.storeMessage(
        "user@example.com",
        "msg-12345",
        "sender@example.com",
        &recipients,
        "Test Subject",
        "From: sender@example.com\r\n",
        "Test message body",
    );

    try testing.expect(msg_id > 0);

    // Retrieve the message
    const message = try storage.retrieveMessage("user@example.com", "msg-12345");
    try testing.expect(message != null);

    if (message) |msg| {
        var msg_copy = msg;
        defer msg_copy.deinit(testing.allocator);

        try testing.expectEqualStrings("sender@example.com", msg.sender);
        try testing.expectEqualStrings("Test Subject", msg.subject.?);
        try testing.expectEqualStrings("Test message body", msg.body);
    }
}

test "message flags" {
    const testing = std.testing;

    const flags = MessageFlags{
        .seen = true,
        .flagged = true,
    };

    const flags_int = flags.toInt();
    try testing.expectEqual(@as(u32, 0x05), flags_int);

    const restored = MessageFlags.fromInt(flags_int);
    try testing.expect(restored.seen);
    try testing.expect(restored.flagged);
    try testing.expect(!restored.answered);
}

test "list messages" {
    const testing = std.testing;

    var db = try database.Database.init(testing.allocator, ":memory:");
    defer db.deinit();
    try db.initSchema();

    var storage = try DatabaseStorage.init(testing.allocator, &db);
    defer storage.deinit();

    // Store multiple messages
    const recipients = [_][]const u8{"recipient@example.com"};
    _ = try storage.storeMessage("user@example.com", "msg-1", "sender1@example.com", &recipients, "Subject 1", "", "Body 1");
    _ = try storage.storeMessage("user@example.com", "msg-2", "sender2@example.com", &recipients, "Subject 2", "", "Body 2");

    const messages = try storage.listMessages("user@example.com", null, 10, 0);
    defer {
        for (messages) |*msg| {
            msg.deinit(testing.allocator);
        }
        testing.allocator.free(messages);
    }

    try testing.expectEqual(@as(usize, 2), messages.len);
}

test "delete message (soft-delete)" {
    const testing = std.testing;

    var db = try database.Database.init(testing.allocator, ":memory:");
    defer db.deinit();
    try db.initSchema();

    var storage = try DatabaseStorage.init(testing.allocator, &db);
    defer storage.deinit();

    const recipients = [_][]const u8{"recipient@example.com"};
    _ = try storage.storeMessage("user@example.com", "msg-delete", "sender@example.com", &recipients, "Delete Me", "", "Body");

    // Soft-delete the message
    try storage.deleteMessage("user@example.com", "msg-delete");

    // retrieveMessage should return null (filtered by deleted_at IS NULL)
    const message = try storage.retrieveMessage("user@example.com", "msg-delete");
    try testing.expect(message == null);

    // Message should appear in deleted messages list
    const deleted = try storage.listDeletedMessages("user@example.com", 10, 0);
    defer {
        for (deleted) |*msg| {
            msg.deinit(testing.allocator);
        }
        testing.allocator.free(deleted);
    }
    try testing.expectEqual(@as(usize, 1), deleted.len);
    try testing.expectEqualStrings("msg-delete", deleted[0].message_id);
    try testing.expect(deleted[0].deleted_at != null);

    // Message count should be 0 (soft-deleted messages excluded)
    const count = try storage.getMessageCount("user@example.com", null);
    try testing.expectEqual(@as(usize, 0), count);
}

test "restore soft-deleted message" {
    const testing = std.testing;

    var db = try database.Database.init(testing.allocator, ":memory:");
    defer db.deinit();
    try db.initSchema();

    var storage = try DatabaseStorage.init(testing.allocator, &db);
    defer storage.deinit();

    const recipients = [_][]const u8{"recipient@example.com"};
    _ = try storage.storeMessage("user@example.com", "msg-restore", "sender@example.com", &recipients, "Restore Me", "", "Body");

    // Soft-delete then restore
    try storage.deleteMessage("user@example.com", "msg-restore");
    try storage.restoreMessage("user@example.com", "msg-restore");

    // Message should be visible again
    const message = try storage.retrieveMessage("user@example.com", "msg-restore");
    try testing.expect(message != null);
    if (message) |msg| {
        var msg_copy = msg;
        defer msg_copy.deinit(testing.allocator);
        try testing.expectEqualStrings("Restore Me", msg.subject.?);
    }
}

test "purge message (hard delete)" {
    const testing = std.testing;

    var db = try database.Database.init(testing.allocator, ":memory:");
    defer db.deinit();
    try db.initSchema();

    var storage = try DatabaseStorage.init(testing.allocator, &db);
    defer storage.deinit();

    const recipients = [_][]const u8{"recipient@example.com"};
    _ = try storage.storeMessage("user@example.com", "msg-purge", "sender@example.com", &recipients, "Purge Me", "", "Body");

    // Soft-delete first, then purge
    try storage.deleteMessage("user@example.com", "msg-purge");
    try storage.purgeMessage("user@example.com", "msg-purge");

    // Should not appear in deleted messages either
    const deleted = try storage.listDeletedMessages("user@example.com", 10, 0);
    defer testing.allocator.free(deleted);
    try testing.expectEqual(@as(usize, 0), deleted.len);
}

test "message count" {
    const testing = std.testing;

    var db = try database.Database.init(testing.allocator, ":memory:");
    defer db.deinit();
    try db.initSchema();

    var storage = try DatabaseStorage.init(testing.allocator, &db);
    defer storage.deinit();

    const recipients = [_][]const u8{"recipient@example.com"};
    _ = try storage.storeMessage("user@example.com", "msg-count-1", "sender@example.com", &recipients, "Subject", "", "Body");
    _ = try storage.storeMessage("user@example.com", "msg-count-2", "sender@example.com", &recipients, "Subject", "", "Body");

    const count = try storage.getMessageCount("user@example.com", null);
    try testing.expectEqual(@as(usize, 2), count);
}

test "store message with category - social" {
    const testing = std.testing;

    var db = try database.Database.init(testing.allocator, ":memory:");
    defer db.deinit();
    try db.initSchema();

    var storage = try DatabaseStorage.init(testing.allocator, &db);
    defer storage.deinit();

    const recipients = [_][]const u8{"user@example.com"};
    const headers = "From: notifications@facebook.com\r\nTo: user@example.com\r\nSubject: You have a new friend request\r\n";

    const msg_id = try storage.storeMessageWithCategory(
        "user@example.com",
        "msg-social-1",
        "notifications@facebook.com",
        &recipients,
        "You have a new friend request",
        headers,
        "Check out your friend request!",
    );

    try testing.expect(msg_id > 0);

    // Verify it was categorized as Social
    const message = try storage.retrieveMessage("user@example.com", "msg-social-1");
    try testing.expect(message != null);

    if (message) |msg| {
        var msg_copy = msg;
        defer msg_copy.deinit(testing.allocator);

        try testing.expectEqualStrings("Social", msg.folder);
    }
}

test "store message with category - updates (github)" {
    const testing = std.testing;

    var db = try database.Database.init(testing.allocator, ":memory:");
    defer db.deinit();
    try db.initSchema();

    var storage = try DatabaseStorage.init(testing.allocator, &db);
    defer storage.deinit();

    const recipients = [_][]const u8{"user@example.com"};
    // Even with "notifications@" in the address, github.com domain should put this in Updates
    const headers = "From: notifications@github.com\r\nTo: user@example.com\r\nSubject: [repo] New PR comment\r\n";

    const msg_id = try storage.storeMessageWithCategory(
        "user@example.com",
        "msg-updates-1",
        "notifications@github.com",
        &recipients,
        "[repo] New PR comment",
        headers,
        "Someone commented on your PR.",
    );

    try testing.expect(msg_id > 0);

    // Verify it was categorized as Updates, not Social
    const message = try storage.retrieveMessage("user@example.com", "msg-updates-1");
    try testing.expect(message != null);

    if (message) |msg| {
        var msg_copy = msg;
        defer msg_copy.deinit(testing.allocator);

        try testing.expectEqualStrings("Updates", msg.folder);
    }
}

test "store message with category - primary (regular email)" {
    const testing = std.testing;

    var db = try database.Database.init(testing.allocator, ":memory:");
    defer db.deinit();
    try db.initSchema();

    var storage = try DatabaseStorage.init(testing.allocator, &db);
    defer storage.deinit();

    const recipients = [_][]const u8{"user@example.com"};
    const headers = "From: colleague@company.com\r\nTo: user@example.com\r\nSubject: Meeting tomorrow\r\n";

    const msg_id = try storage.storeMessageWithCategory(
        "user@example.com",
        "msg-primary-1",
        "colleague@company.com",
        &recipients,
        "Meeting tomorrow",
        headers,
        "Let's meet at 3pm.",
    );

    try testing.expect(msg_id > 0);

    // Verify it was categorized as primary (INBOX)
    const message = try storage.retrieveMessage("user@example.com", "msg-primary-1");
    try testing.expect(message != null);

    if (message) |msg| {
        var msg_copy = msg;
        defer msg_copy.deinit(testing.allocator);

        try testing.expectEqualStrings("INBOX", msg.folder);
    }
}
