const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

// =============================================================================
// Email Thread/Conversation View
// =============================================================================
//
// ## Overview
// Groups related emails into conversations using standard email headers:
// - Message-ID: Unique identifier for each email
// - In-Reply-To: References the Message-ID being replied to
// - References: List of all Message-IDs in the conversation chain
//
// ## Thread Algorithm
// Uses the JWZ threading algorithm (RFC 5256) for proper thread grouping:
// 1. Build ID table from Message-ID headers
// 2. Link messages using In-Reply-To and References
// 3. Create parent-child relationships
// 4. Handle orphans and missing messages
//
// =============================================================================

/// Thread-related errors
pub const ThreadError = error{
    InvalidMessageId,
    ThreadNotFound,
    MessageNotFound,
    CircularReference,
    OutOfMemory,
};

/// Email message header info needed for threading
pub const MessageHeader = struct {
    id: []const u8,
    message_id: ?[]const u8,
    in_reply_to: ?[]const u8,
    references: ?[]const u8,
    subject: []const u8,
    from: []const u8,
    date: i64,
    is_read: bool,
    has_attachments: bool,
    preview: ?[]const u8,
};

/// A message within a thread
pub const ThreadedMessage = struct {
    header: MessageHeader,
    children: std.ArrayList(*ThreadedMessage),
    parent: ?*ThreadedMessage,
    depth: usize,
    is_collapsed: bool,

    pub fn init(allocator: std.mem.Allocator, header: MessageHeader) !*ThreadedMessage {
        const self = try allocator.create(ThreadedMessage);
        self.* = .{
            .header = header,
            .children = std.ArrayList(*ThreadedMessage).init(allocator),
            .parent = null,
            .depth = 0,
            .is_collapsed = false,
        };
        return self;
    }

    pub fn deinit(self: *ThreadedMessage, allocator: std.mem.Allocator) void {
        for (self.children.items) |child| {
            child.deinit(allocator);
        }
        self.children.deinit();
        allocator.destroy(self);
    }

    pub fn addChild(self: *ThreadedMessage, child: *ThreadedMessage) !void {
        child.parent = self;
        child.depth = self.depth + 1;
        try self.children.append(child);
    }

    /// Get total count of messages in this subtree
    pub fn getMessageCount(self: *const ThreadedMessage) usize {
        var count: usize = 1;
        for (self.children.items) |child| {
            count += child.getMessageCount();
        }
        return count;
    }

    /// Get count of unread messages in this subtree
    pub fn getUnreadCount(self: *const ThreadedMessage) usize {
        var count: usize = if (!self.header.is_read) 1 else 0;
        for (self.children.items) |child| {
            count += child.getUnreadCount();
        }
        return count;
    }

    /// Get the most recent date in this subtree
    pub fn getLatestDate(self: *const ThreadedMessage) i64 {
        var latest = self.header.date;
        for (self.children.items) |child| {
            const child_latest = child.getLatestDate();
            if (child_latest > latest) {
                latest = child_latest;
            }
        }
        return latest;
    }

    /// Flatten thread into array with depth info
    pub fn flatten(self: *const ThreadedMessage, allocator: std.mem.Allocator) ![]FlattenedMessage {
        var result = std.ArrayList(FlattenedMessage).init(allocator);
        errdefer result.deinit();
        try self.flattenRecursive(&result);
        return result.toOwnedSlice();
    }

    fn flattenRecursive(self: *const ThreadedMessage, result: *std.ArrayList(FlattenedMessage)) !void {
        try result.append(.{
            .header = self.header,
            .depth = self.depth,
            .has_children = self.children.items.len > 0,
            .is_collapsed = self.is_collapsed,
        });

        // Sort children by date
        var sorted_children = try result.allocator.alloc(*ThreadedMessage, self.children.items.len);
        defer result.allocator.free(sorted_children);
        @memcpy(sorted_children, self.children.items);

        std.mem.sort(*ThreadedMessage, sorted_children, {}, struct {
            fn lessThan(_: void, a: *ThreadedMessage, b: *ThreadedMessage) bool {
                return a.header.date < b.header.date;
            }
        }.lessThan);

        for (sorted_children) |child| {
            try child.flattenRecursive(result);
        }
    }
};

/// Flattened message for display
pub const FlattenedMessage = struct {
    header: MessageHeader,
    depth: usize,
    has_children: bool,
    is_collapsed: bool,
};

/// Email thread/conversation
pub const EmailThread = struct {
    id: []const u8,
    subject: []const u8,
    root: *ThreadedMessage,
    participants: std.ArrayList([]const u8),
    message_count: usize,
    unread_count: usize,
    latest_date: i64,
    has_attachments: bool,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, root: *ThreadedMessage) !*EmailThread {
        const self = try allocator.create(EmailThread);

        // Generate thread ID from root message
        var hasher = Sha256.init(.{});
        if (root.header.message_id) |mid| {
            hasher.update(mid);
        } else {
            hasher.update(root.header.id);
        }
        var hash: [32]u8 = undefined;
        hasher.final(&hash);

        var thread_id: [16]u8 = undefined;
        @memcpy(&thread_id, hash[0..16]);

        const id = try std.fmt.allocPrint(allocator, "thread_{}", .{
            std.fmt.fmtSliceHexLower(&thread_id),
        });

        // Normalize subject (remove Re:, Fwd:, etc.)
        const subject = try allocator.dupe(u8, normalizeSubject(root.header.subject));

        self.* = .{
            .id = id,
            .subject = subject,
            .root = root,
            .participants = std.ArrayList([]const u8).init(allocator),
            .message_count = root.getMessageCount(),
            .unread_count = root.getUnreadCount(),
            .latest_date = root.getLatestDate(),
            .has_attachments = false,
            .allocator = allocator,
        };

        // Collect participants
        try self.collectParticipants(root);

        return self;
    }

    pub fn deinit(self: *EmailThread) void {
        self.allocator.free(self.id);
        self.allocator.free(self.subject);
        for (self.participants.items) |p| {
            self.allocator.free(p);
        }
        self.participants.deinit();
        self.root.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    fn collectParticipants(self: *EmailThread, msg: *ThreadedMessage) !void {
        // Add sender if not already present
        var found = false;
        for (self.participants.items) |p| {
            if (std.mem.eql(u8, p, msg.header.from)) {
                found = true;
                break;
            }
        }
        if (!found) {
            const p = try self.allocator.dupe(u8, msg.header.from);
            try self.participants.append(p);
        }

        // Check for attachments
        if (msg.header.has_attachments) {
            self.has_attachments = true;
        }

        // Recurse into children
        for (msg.children.items) |child| {
            try self.collectParticipants(child);
        }
    }

    /// Get flattened view of all messages
    pub fn getMessages(self: *const EmailThread) ![]FlattenedMessage {
        return self.root.flatten(self.allocator);
    }

    /// Convert to JSON
    pub fn toJson(self: *const EmailThread, allocator: std.mem.Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        errdefer buffer.deinit();
        const writer = buffer.writer();

        try writer.writeAll("{");
        try writer.print("\"id\":\"{s}\",", .{self.id});
        try writer.print("\"subject\":\"{s}\",", .{escapeJson(self.subject)});
        try writer.print("\"message_count\":{d},", .{self.message_count});
        try writer.print("\"unread_count\":{d},", .{self.unread_count});
        try writer.print("\"latest_date\":{d},", .{self.latest_date});
        try writer.print("\"has_attachments\":{s},", .{if (self.has_attachments) "true" else "false"});

        // Participants
        try writer.writeAll("\"participants\":[");
        for (self.participants.items, 0..) |p, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print("\"{s}\"", .{escapeJson(p)});
        }
        try writer.writeAll("],");

        // Messages
        try writer.writeAll("\"messages\":");
        const messages = try self.getMessages();
        defer allocator.free(messages);
        try writeMessagesJson(writer, messages);

        try writer.writeAll("}");

        return buffer.toOwnedSlice();
    }
};

/// Thread manager for building and caching threads
pub const ThreadManager = struct {
    allocator: std.mem.Allocator,
    id_to_message: std.StringHashMap(*ThreadedMessage),
    threads: std.ArrayList(*EmailThread),
    config: ThreadConfig,

    pub const ThreadConfig = struct {
        /// Maximum thread depth
        max_depth: usize = 50,
        /// Whether to show deleted messages in threads
        show_deleted: bool = false,
        /// Sort threads by latest message date
        sort_by_latest: bool = true,
        /// Group by normalized subject when no references
        group_by_subject: bool = true,
    };

    pub fn init(allocator: std.mem.Allocator, config: ThreadConfig) ThreadManager {
        return .{
            .allocator = allocator,
            .id_to_message = std.StringHashMap(*ThreadedMessage).init(allocator),
            .threads = std.ArrayList(*EmailThread).init(allocator),
            .config = config,
        };
    }

    pub fn deinit(self: *ThreadManager) void {
        for (self.threads.items) |thread| {
            thread.deinit();
        }
        self.threads.deinit();
        self.id_to_message.deinit();
    }

    /// Build threads from a list of messages
    pub fn buildThreads(self: *ThreadManager, messages: []const MessageHeader) !void {
        // Step 1: Create ThreadedMessage for each message and index by Message-ID
        for (messages) |header| {
            const msg = try ThreadedMessage.init(self.allocator, header);
            if (header.message_id) |mid| {
                try self.id_to_message.put(mid, msg);
            }
        }

        // Step 2: Link messages using In-Reply-To and References
        var it = self.id_to_message.iterator();
        while (it.next()) |entry| {
            const msg = entry.value_ptr.*;

            // Try In-Reply-To first
            if (msg.header.in_reply_to) |reply_to| {
                if (self.id_to_message.get(reply_to)) |parent| {
                    if (!isCircular(parent, msg)) {
                        try parent.addChild(msg);
                        continue;
                    }
                }
            }

            // Try References (last one is immediate parent)
            if (msg.header.references) |refs| {
                var last_ref: ?[]const u8 = null;
                var ref_it = std.mem.splitSequence(u8, refs, " ");
                while (ref_it.next()) |ref| {
                    if (ref.len > 0) {
                        last_ref = ref;
                    }
                }
                if (last_ref) |ref| {
                    if (self.id_to_message.get(ref)) |parent| {
                        if (!isCircular(parent, msg)) {
                            try parent.addChild(msg);
                        }
                    }
                }
            }
        }

        // Step 3: Group by subject if enabled
        if (self.config.group_by_subject) {
            try self.groupBySubject();
        }

        // Step 4: Find root messages and create EmailThreads
        it = self.id_to_message.iterator();
        while (it.next()) |entry| {
            const msg = entry.value_ptr.*;
            if (msg.parent == null) {
                const thread = try EmailThread.init(self.allocator, msg);
                try self.threads.append(thread);
            }
        }

        // Step 5: Sort threads by latest date
        if (self.config.sort_by_latest) {
            std.mem.sort(*EmailThread, self.threads.items, {}, struct {
                fn lessThan(_: void, a: *EmailThread, b: *EmailThread) bool {
                    return a.latest_date > b.latest_date; // Descending
                }
            }.lessThan);
        }
    }

    fn groupBySubject(self: *ThreadManager) !void {
        // Group orphan messages by normalized subject
        var subject_map = std.StringHashMap(*ThreadedMessage).init(self.allocator);
        defer subject_map.deinit();

        var it = self.id_to_message.iterator();
        while (it.next()) |entry| {
            const msg = entry.value_ptr.*;
            if (msg.parent == null) {
                const norm_subject = normalizeSubject(msg.header.subject);
                if (subject_map.get(norm_subject)) |existing| {
                    // Link to existing thread root by date
                    if (msg.header.date < existing.header.date) {
                        // msg is older, it becomes parent
                        if (!isCircular(msg, existing)) {
                            try msg.addChild(existing);
                            try subject_map.put(norm_subject, msg);
                        }
                    } else {
                        // existing is older, keep it as parent
                        if (!isCircular(existing, msg)) {
                            try existing.addChild(msg);
                        }
                    }
                } else {
                    try subject_map.put(norm_subject, msg);
                }
            }
        }
    }

    /// Get thread by ID
    pub fn getThread(self: *const ThreadManager, thread_id: []const u8) ?*EmailThread {
        for (self.threads.items) |thread| {
            if (std.mem.eql(u8, thread.id, thread_id)) {
                return thread;
            }
        }
        return null;
    }

    /// Get all threads
    pub fn getThreads(self: *const ThreadManager) []*EmailThread {
        return self.threads.items;
    }

    /// Get thread containing a specific message
    pub fn getThreadByMessageId(self: *const ThreadManager, message_id: []const u8) ?*EmailThread {
        if (self.id_to_message.get(message_id)) |msg| {
            // Find root
            var root = msg;
            while (root.parent) |parent| {
                root = parent;
            }
            // Find thread with this root
            for (self.threads.items) |thread| {
                if (thread.root == root) {
                    return thread;
                }
            }
        }
        return null;
    }

    /// Get thread summary for list view
    pub fn getThreadSummaries(self: *const ThreadManager, allocator: std.mem.Allocator) ![]ThreadSummary {
        var summaries = try allocator.alloc(ThreadSummary, self.threads.items.len);
        for (self.threads.items, 0..) |thread, i| {
            summaries[i] = .{
                .id = thread.id,
                .subject = thread.subject,
                .message_count = thread.message_count,
                .unread_count = thread.unread_count,
                .latest_date = thread.latest_date,
                .has_attachments = thread.has_attachments,
                .participants = thread.participants.items,
                .preview = if (thread.root.header.preview) |p| p else "",
            };
        }
        return summaries;
    }
};

/// Thread summary for list views
pub const ThreadSummary = struct {
    id: []const u8,
    subject: []const u8,
    message_count: usize,
    unread_count: usize,
    latest_date: i64,
    has_attachments: bool,
    participants: []const []const u8,
    preview: []const u8,

    pub fn toJson(self: *const ThreadSummary, allocator: std.mem.Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        errdefer buffer.deinit();
        const writer = buffer.writer();

        try writer.writeAll("{");
        try writer.print("\"id\":\"{s}\",", .{self.id});
        try writer.print("\"subject\":\"{s}\",", .{escapeJson(self.subject)});
        try writer.print("\"message_count\":{d},", .{self.message_count});
        try writer.print("\"unread_count\":{d},", .{self.unread_count});
        try writer.print("\"latest_date\":{d},", .{self.latest_date});
        try writer.print("\"has_attachments\":{s},", .{if (self.has_attachments) "true" else "false"});
        try writer.print("\"preview\":\"{s}\",", .{escapeJson(self.preview)});

        try writer.writeAll("\"participants\":[");
        for (self.participants, 0..) |p, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print("\"{s}\"", .{escapeJson(p)});
        }
        try writer.writeAll("]}");

        return buffer.toOwnedSlice();
    }
};

// =============================================================================
// Helper Functions
// =============================================================================

/// Normalize subject by removing Re:, Fwd:, etc.
pub fn normalizeSubject(subject: []const u8) []const u8 {
    var s = subject;

    // Strip leading whitespace
    while (s.len > 0 and (s[0] == ' ' or s[0] == '\t')) {
        s = s[1..];
    }

    // Remove common prefixes
    const prefixes = [_][]const u8{
        "Re: ",
        "RE: ",
        "re: ",
        "Fwd: ",
        "FWD: ",
        "fwd: ",
        "Fw: ",
        "FW: ",
        "fw: ",
        "Re:",
        "RE:",
        "re:",
        "Fwd:",
        "FWD:",
        "fwd:",
        "Fw:",
        "FW:",
        "fw:",
        "[SPAM] ",
        "[spam] ",
    };

    var changed = true;
    while (changed) {
        changed = false;
        for (prefixes) |prefix| {
            if (std.mem.startsWith(u8, s, prefix)) {
                s = s[prefix.len..];
                changed = true;
                break;
            }
        }

        // Strip leading whitespace again
        while (s.len > 0 and (s[0] == ' ' or s[0] == '\t')) {
            s = s[1..];
        }
    }

    return if (s.len > 0) s else subject;
}

/// Check for circular reference
fn isCircular(potential_parent: *ThreadedMessage, child: *ThreadedMessage) bool {
    var current: ?*ThreadedMessage = potential_parent;
    while (current) |c| {
        if (c == child) return true;
        current = c.parent;
    }
    return false;
}

/// Escape string for JSON
fn escapeJson(s: []const u8) []const u8 {
    // For now, return as-is (production would need proper escaping)
    return s;
}

/// Write messages array as JSON
fn writeMessagesJson(writer: anytype, messages: []const FlattenedMessage) !void {
    try writer.writeAll("[");
    for (messages, 0..) |msg, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.writeAll("{");
        try writer.print("\"id\":\"{s}\",", .{msg.header.id});
        try writer.print("\"subject\":\"{s}\",", .{escapeJson(msg.header.subject)});
        try writer.print("\"from\":\"{s}\",", .{escapeJson(msg.header.from)});
        try writer.print("\"date\":{d},", .{msg.header.date});
        try writer.print("\"is_read\":{s},", .{if (msg.header.is_read) "true" else "false"});
        try writer.print("\"has_attachments\":{s},", .{if (msg.header.has_attachments) "true" else "false"});
        try writer.print("\"depth\":{d},", .{msg.depth});
        try writer.print("\"has_children\":{s},", .{if (msg.has_children) "true" else "false"});
        try writer.print("\"is_collapsed\":{s}", .{if (msg.is_collapsed) "true" else "false"});
        if (msg.header.preview) |preview| {
            try writer.print(",\"preview\":\"{s}\"", .{escapeJson(preview)});
        }
        try writer.writeAll("}");
    }
    try writer.writeAll("]");
}

// =============================================================================
// Tests
// =============================================================================

test "normalizeSubject removes prefixes" {
    try std.testing.expectEqualStrings("Hello World", normalizeSubject("Re: Hello World"));
    try std.testing.expectEqualStrings("Hello World", normalizeSubject("RE: Hello World"));
    try std.testing.expectEqualStrings("Hello World", normalizeSubject("Fwd: Hello World"));
    try std.testing.expectEqualStrings("Hello World", normalizeSubject("Re: Fwd: Hello World"));
    try std.testing.expectEqualStrings("Hello World", normalizeSubject("Re: Re: Re: Hello World"));
    try std.testing.expectEqualStrings("Hello World", normalizeSubject("  Re: Hello World"));
    try std.testing.expectEqualStrings("Hello", normalizeSubject("Hello"));
}

test "ThreadedMessage basic operations" {
    const allocator = std.testing.allocator;

    const header1 = MessageHeader{
        .id = "msg1",
        .message_id = "<msg1@example.com>",
        .in_reply_to = null,
        .references = null,
        .subject = "Test Subject",
        .from = "alice@example.com",
        .date = 1000,
        .is_read = false,
        .has_attachments = false,
        .preview = "Preview text",
    };

    const header2 = MessageHeader{
        .id = "msg2",
        .message_id = "<msg2@example.com>",
        .in_reply_to = "<msg1@example.com>",
        .references = null,
        .subject = "Re: Test Subject",
        .from = "bob@example.com",
        .date = 2000,
        .is_read = true,
        .has_attachments = true,
        .preview = "Reply text",
    };

    var msg1 = try ThreadedMessage.init(allocator, header1);
    defer msg1.deinit(allocator);

    var msg2 = try ThreadedMessage.init(allocator, header2);
    // msg2 will be freed by msg1.deinit() since it becomes a child

    try msg1.addChild(msg2);

    try std.testing.expectEqual(@as(usize, 2), msg1.getMessageCount());
    try std.testing.expectEqual(@as(usize, 1), msg1.getUnreadCount());
    try std.testing.expectEqual(@as(i64, 2000), msg1.getLatestDate());
    try std.testing.expectEqual(@as(usize, 1), msg2.depth);
}

test "ThreadManager builds threads correctly" {
    const allocator = std.testing.allocator;

    var manager = ThreadManager.init(allocator, .{});
    defer manager.deinit();

    const messages = [_]MessageHeader{
        .{
            .id = "msg1",
            .message_id = "<msg1@example.com>",
            .in_reply_to = null,
            .references = null,
            .subject = "Thread 1",
            .from = "alice@example.com",
            .date = 1000,
            .is_read = false,
            .has_attachments = false,
            .preview = null,
        },
        .{
            .id = "msg2",
            .message_id = "<msg2@example.com>",
            .in_reply_to = "<msg1@example.com>",
            .references = "<msg1@example.com>",
            .subject = "Re: Thread 1",
            .from = "bob@example.com",
            .date = 2000,
            .is_read = true,
            .has_attachments = false,
            .preview = null,
        },
        .{
            .id = "msg3",
            .message_id = "<msg3@example.com>",
            .in_reply_to = null,
            .references = null,
            .subject = "Thread 2",
            .from = "charlie@example.com",
            .date = 3000,
            .is_read = false,
            .has_attachments = true,
            .preview = null,
        },
    };

    try manager.buildThreads(&messages);

    // Should have 2 threads (Thread 1 with 2 messages, Thread 2 with 1)
    try std.testing.expectEqual(@as(usize, 2), manager.threads.items.len);
}

test "ThreadSummary toJson" {
    const allocator = std.testing.allocator;

    const participants = [_][]const u8{ "alice@example.com", "bob@example.com" };
    const summary = ThreadSummary{
        .id = "thread_123",
        .subject = "Test Thread",
        .message_count = 5,
        .unread_count = 2,
        .latest_date = 1699999999,
        .has_attachments = true,
        .participants = &participants,
        .preview = "Hello world...",
    };

    const json = try summary.toJson(allocator);
    defer allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"id\":\"thread_123\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"message_count\":5") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"has_attachments\":true") != null);
}
