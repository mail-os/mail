const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");
const path_sanitizer = @import("../core/path_sanitizer.zig");

/// mbox format email storage (RFC 4155)
/// Traditional Unix mailbox format where messages are stored in a single file
pub const MboxStorage = struct {
    allocator: std.mem.Allocator,
    mbox_path: []const u8,
    mutex: mutex_compat.Mutex,

    /// Initialize mbox storage with path validation
    /// If mbox_path is relative, it will be validated against the current working directory
    /// If mbox_path is absolute, it will be used as-is (should be pre-validated by caller)
    pub fn init(allocator: std.mem.Allocator, mbox_path: []const u8) !MboxStorage {
        // Validate and sanitize the path if it appears to be relative
        const sanitized_path = if (std.fs.path.isAbsolute(mbox_path))
            try allocator.dupe(u8, mbox_path)
        else blk: {
            // For relative paths, sanitize against current directory
            const cwd = try std.fs.cwd().realpathAlloc(allocator, ".");
            defer allocator.free(cwd);

            const sanitized = path_sanitizer.PathSanitizer.sanitizePath(allocator, cwd, mbox_path) catch |err| {
                std.log.err("Invalid mbox path: {s} - {}", .{ mbox_path, err });
                return error.InvalidMboxPath;
            };
            break :blk sanitized;
        };

        return .{
            .allocator = allocator,
            .mbox_path = sanitized_path,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *MboxStorage) void {
        self.allocator.free(self.mbox_path);
    }

    /// Append a message to the mbox file
    pub fn appendMessage(self: *MboxStorage, message: []const u8, from: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const file = try std.fs.cwd().openFile(self.mbox_path, .{
            .mode = .read_write,
        }) catch blk: {
            // File doesn't exist, create it
            break :blk try std.fs.cwd().createFile(self.mbox_path, .{
                .read = true,
            });
        };
        defer file.close();

        // Seek to end of file
        try file.seekFromEnd(0);

        // Write mbox separator line
        const timestamp = time_compat.timestamp();
        const date_str = try self.formatDate(timestamp);
        defer self.allocator.free(date_str);

        const separator = try std.fmt.allocPrint(
            self.allocator,
            "From {s} {s}\n",
            .{ from, date_str },
        );
        defer self.allocator.free(separator);

        try file.writeAll(separator);

        // Write message with escaped "From " lines
        const escaped = try self.escapeFromLines(message);
        defer self.allocator.free(escaped);

        try file.writeAll(escaped);

        // Ensure message ends with newline
        if (escaped.len == 0 or escaped[escaped.len - 1] != '\n') {
            try file.writeAll("\n");
        }

        // Add blank line between messages
        try file.writeAll("\n");
    }

    /// Read all messages from the mbox file
    pub fn readMessages(self: *MboxStorage) ![]MboxMessage {
        self.mutex.lock();
        defer self.mutex.unlock();

        const file = try std.fs.cwd().openFile(self.mbox_path, .{});
        defer file.close();

        const content = try time_compat.readFileToEnd(self.allocator, file, 100 * 1024 * 1024); // 100MB max
        defer self.allocator.free(content);

        return try self.parseMessages(content);
    }

    /// Read a specific message by index
    pub fn readMessage(self: *MboxStorage, index: usize) !MboxMessage {
        const messages = try self.readMessages();
        defer self.freeMessages(messages);

        if (index >= messages.len) {
            return error.MessageNotFound;
        }

        // Duplicate the message data
        return MboxMessage{
            .from = try self.allocator.dupe(u8, messages[index].from),
            .date = try self.allocator.dupe(u8, messages[index].date),
            .content = try self.allocator.dupe(u8, messages[index].content),
            .allocator = self.allocator,
        };
    }

    /// Count messages in the mbox file
    pub fn countMessages(self: *MboxStorage) !usize {
        const messages = try self.readMessages();
        defer self.freeMessages(messages);
        return messages.len;
    }

    /// Delete a message by index (rewrites the entire file)
    pub fn deleteMessage(self: *MboxStorage, index: usize) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var messages = try self.readMessages();
        defer self.freeMessages(messages);

        if (index >= messages.len) {
            return error.MessageNotFound;
        }

        // Remove the message
        var new_messages = std.ArrayList(MboxMessage).init(self.allocator);
        defer new_messages.deinit();

        for (messages, 0..) |msg, i| {
            if (i != index) {
                try new_messages.append(msg);
            }
        }

        // Rewrite the file
        try self.rewriteMbox(new_messages.items);
    }

    fn parseMessages(self: *MboxStorage, content: []const u8) ![]MboxMessage {
        var messages = std.ArrayList(MboxMessage).init(self.allocator);
        errdefer {
            for (messages.items) |*msg| {
                msg.deinit();
            }
            messages.deinit();
        }

        var lines = std.mem.splitSequence(u8, content, "\n");
        var current_from: ?[]const u8 = null;
        var current_date: ?[]const u8 = null;
        var current_content = std.ArrayList(u8).init(self.allocator);
        defer current_content.deinit();

        while (lines.next()) |line| {
            if (std.mem.startsWith(u8, line, "From ")) {
                // Save previous message if exists
                if (current_from != null and current_date != null) {
                    const msg = MboxMessage{
                        .from = current_from.?,
                        .date = current_date.?,
                        .content = try current_content.toOwnedSlice(),
                        .allocator = self.allocator,
                    };
                    try messages.append(msg);
                    current_content = std.ArrayList(u8).init(self.allocator);
                }

                // Parse new message header
                // Format: "From sender@example.com Wed Oct 23 12:00:00 2024"
                var parts = std.mem.splitScalar(u8, line[5..], ' ');
                const from = parts.next() orelse continue;
                const rest = parts.rest();

                current_from = try self.allocator.dupe(u8, from);
                current_date = try self.allocator.dupe(u8, rest);
            } else if (current_from != null) {
                // Unescape ">From " lines
                if (std.mem.startsWith(u8, line, ">From ")) {
                    try current_content.appendSlice(line[1..]);
                } else {
                    try current_content.appendSlice(line);
                }
                try current_content.append('\n');
            }
        }

        // Save last message
        if (current_from != null and current_date != null) {
            const msg = MboxMessage{
                .from = current_from.?,
                .date = current_date.?,
                .content = try current_content.toOwnedSlice(),
                .allocator = self.allocator,
            };
            try messages.append(msg);
        }

        return try messages.toOwnedSlice();
    }

    fn rewriteMbox(self: *MboxStorage, messages: []const MboxMessage) !void {
        const file = try std.fs.cwd().createFile(self.mbox_path, .{});
        defer file.close();

        for (messages) |msg| {
            const separator = try std.fmt.allocPrint(
                self.allocator,
                "From {s} {s}\n",
                .{ msg.from, msg.date },
            );
            defer self.allocator.free(separator);

            try file.writeAll(separator);
            try file.writeAll(msg.content);

            if (msg.content.len == 0 or msg.content[msg.content.len - 1] != '\n') {
                try file.writeAll("\n");
            }
            try file.writeAll("\n");
        }
    }

    fn escapeFromLines(self: *MboxStorage, message: []const u8) ![]const u8 {
        var escaped = std.ArrayList(u8).init(self.allocator);
        defer escaped.deinit();

        var lines = std.mem.splitSequence(u8, message, "\n");
        var first = true;

        while (lines.next()) |line| {
            if (!first) try escaped.append('\n');
            first = false;

            // Escape lines starting with "From "
            if (std.mem.startsWith(u8, line, "From ")) {
                try escaped.append('>');
            }
            try escaped.appendSlice(line);
        }

        return try escaped.toOwnedSlice();
    }

    fn formatDate(self: *MboxStorage, timestamp: i64) ![]const u8 {
        _ = self;
        _ = timestamp;
        // Simplified date format for mbox
        // Real implementation would use proper Unix date format
        return try self.allocator.dupe(u8, "Wed Oct 23 12:00:00 2024");
    }

    pub fn freeMessages(self: *MboxStorage, messages: []MboxMessage) void {
        for (messages) |*msg| {
            msg.deinit();
        }
        self.allocator.free(messages);
    }
};

pub const MboxMessage = struct {
    from: []const u8,
    date: []const u8,
    content: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *MboxMessage) void {
        self.allocator.free(self.from);
        self.allocator.free(self.date);
        self.allocator.free(self.content);
    }
};

test "mbox append and read" {
    const testing = std.testing;

    const test_mbox = "/tmp/test.mbox";
    defer std.fs.cwd().deleteFile(test_mbox) catch {};

    var storage = try MboxStorage.init(testing.allocator, test_mbox);
    defer storage.deinit();

    // Append a message
    const message = "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nBody";
    try storage.appendMessage(message, "sender@example.com");

    // Read messages
    const messages = try storage.readMessages();
    defer storage.freeMessages(messages);

    try testing.expectEqual(@as(usize, 1), messages.len);
    try testing.expect(std.mem.indexOf(u8, messages[0].content, "Subject: Test") != null);
}

test "mbox From line escaping" {
    const testing = std.testing;
    var storage = try MboxStorage.init(testing.allocator, "/tmp/test2.mbox");
    defer storage.deinit();

    const message = "From sender\nFrom another line\nBody";
    const escaped = try storage.escapeFromLines(message);
    defer testing.allocator.free(escaped);

    try testing.expect(std.mem.indexOf(u8, escaped, ">From sender") != null);
    try testing.expect(std.mem.indexOf(u8, escaped, ">From another") != null);
}
