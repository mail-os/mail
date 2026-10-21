const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");
const database = @import("../storage/database.zig");

/// Queue message status
pub const MessageStatus = enum {
    pending,
    processing,
    delivered,
    failed,
    retry,

    pub fn toString(self: MessageStatus) []const u8 {
        return switch (self) {
            .pending => "pending",
            .processing => "processing",
            .delivered => "delivered",
            .failed => "failed",
            .retry => "retry",
        };
    }

    pub fn fromString(str: []const u8) !MessageStatus {
        if (std.mem.eql(u8, str, "pending")) return .pending;
        if (std.mem.eql(u8, str, "processing")) return .processing;
        if (std.mem.eql(u8, str, "delivered")) return .delivered;
        if (std.mem.eql(u8, str, "failed")) return .failed;
        if (std.mem.eql(u8, str, "retry")) return .retry;
        return error.InvalidStatus;
    }
};

/// Queued message
pub const QueuedMessage = struct {
    id: []const u8,
    from: []const u8,
    to: []const u8,
    data: []const u8,
    status: MessageStatus,
    attempts: u32,
    max_attempts: u32,
    next_retry: i64, // Unix timestamp
    created_at: i64,
    updated_at: i64,
    error_message: ?[]const u8,

    pub fn deinit(self: *QueuedMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.from);
        allocator.free(self.to);
        allocator.free(self.data);
        if (self.error_message) |err| {
            allocator.free(err);
        }
    }
};

/// Message queue for outbound delivery with database persistence
pub const MessageQueue = struct {
    allocator: std.mem.Allocator,
    messages: std.ArrayList(*QueuedMessage) = .empty,
    // id -> index into `messages`, so markDelivered/markForRetry are O(1)
    // instead of a scan over the whole queue per delivered message. Keys
    // alias msg.id and entries are removed before the message is freed.
    index: std.StringHashMapUnmanaged(usize) = .empty,
    mutex: mutex_compat.Mutex,
    next_id: u64,
    db: ?*database.Database, // Optional database for persistence

    pub fn init(allocator: std.mem.Allocator) MessageQueue {
        return .{
            .allocator = allocator,
            .messages = .empty,
            .mutex = .{},
            .next_id = 1,
            .db = null,
        };
    }

    /// Initialize with database persistence
    pub fn initWithDB(allocator: std.mem.Allocator, db: *database.Database) !MessageQueue {
        var queue = MessageQueue{
            .allocator = allocator,
            .messages = .empty,
            .mutex = .{},
            .next_id = 1,
            .db = db,
        };

        errdefer queue.deinit();
        // Initialize database schema
        try queue.initSchema();

        // Load existing messages from database
        try queue.loadFromDB();

        return queue;
    }

    /// Initialize queue database schema
    fn initSchema(self: *MessageQueue) !void {
        if (self.db) |db| {
            const schema =
                \\CREATE TABLE IF NOT EXISTS message_queue (
                \\    id TEXT PRIMARY KEY,
                \\    from_addr TEXT NOT NULL,
                \\    to_addr TEXT NOT NULL,
                \\    message_data TEXT NOT NULL,
                \\    status TEXT NOT NULL,
                \\    attempts INTEGER NOT NULL DEFAULT 0,
                \\    max_attempts INTEGER NOT NULL DEFAULT 5,
                \\    next_retry INTEGER NOT NULL,
                \\    created_at INTEGER NOT NULL,
                \\    updated_at INTEGER NOT NULL,
                \\    error_message TEXT
                \\);
                \\
                \\CREATE INDEX IF NOT EXISTS idx_queue_status ON message_queue(status);
                \\CREATE INDEX IF NOT EXISTS idx_queue_next_retry ON message_queue(next_retry);
            ;

            try db.exec(schema);
        }
    }

    /// Load messages from database into memory
    fn loadFromDB(self: *MessageQueue) !void {
        if (self.db) |db| {
            const query =
                \\SELECT id, from_addr, to_addr, message_data, status, attempts,
                \\       max_attempts, next_retry, created_at, updated_at, error_message
                \\FROM message_queue
                \\WHERE status IN ('pending', 'retry', 'processing')
                \\ORDER BY created_at ASC
            ;

            var stmt = try db.prepare(query);
            defer stmt.finalize();

            var max_id: u64 = 0;

            while (try stmt.step()) {
                const msg = try self.allocator.create(QueuedMessage);
                errdefer self.allocator.destroy(msg);

                const id = stmt.columnText(0);
                const from_addr = stmt.columnText(1);
                const to_addr = stmt.columnText(2);
                const message_data = stmt.columnText(3);
                const status_str = stmt.columnText(4);
                const error_msg_text = stmt.columnText(10);

                const owned_id = try self.allocator.dupe(u8, id);
                errdefer self.allocator.free(owned_id);
                const owned_from = try self.allocator.dupe(u8, from_addr);
                errdefer self.allocator.free(owned_from);
                const owned_to = try self.allocator.dupe(u8, to_addr);
                errdefer self.allocator.free(owned_to);
                const owned_data = try self.allocator.dupe(u8, message_data);
                errdefer self.allocator.free(owned_data);
                const owned_error = if (error_msg_text.len > 0) try self.allocator.dupe(u8, error_msg_text) else null;
                errdefer if (owned_error) |value| self.allocator.free(value);
                const status = try MessageStatus.fromString(status_str);
                msg.* = .{
                    .id = owned_id,
                    .from = owned_from,
                    .to = owned_to,
                    .data = owned_data,
                    .status = if (status == .processing) .pending else status,
                    .attempts = @intCast(stmt.columnInt64(5)),
                    .max_attempts = @intCast(stmt.columnInt64(6)),
                    .next_retry = stmt.columnInt64(7),
                    .created_at = stmt.columnInt64(8),
                    .updated_at = stmt.columnInt64(9),
                    .error_message = owned_error,
                };

                try self.messages.append(self.allocator, msg);
                errdefer _ = self.messages.pop();
                try self.index.put(self.allocator, msg.id, self.messages.items.len - 1);

                // Track highest ID for next_id
                if (std.fmt.parseInt(u64, id, 10)) |id_num| {
                    if (id_num > max_id) max_id = id_num;
                } else |_| {}
            }

            self.next_id = max_id + 1;
        }
    }

    /// Persist message to database
    fn persistMessage(self: *MessageQueue, msg: *const QueuedMessage) !void {
        if (self.db) |db| {
            const sql =
                \\INSERT OR REPLACE INTO message_queue
                \\(id, from_addr, to_addr, message_data, status, attempts, max_attempts,
                \\ next_retry, created_at, updated_at, error_message)
                \\VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            ;

            var stmt = try db.prepare(sql);
            defer stmt.finalize();

            try stmt.bind(1, msg.id);
            try stmt.bind(2, msg.from);
            try stmt.bind(3, msg.to);
            try stmt.bind(4, msg.data);
            try stmt.bind(5, msg.status.toString());
            try stmt.bind(6, @as(i64, @intCast(msg.attempts)));
            try stmt.bind(7, @as(i64, @intCast(msg.max_attempts)));
            try stmt.bind(8, msg.next_retry);
            try stmt.bind(9, msg.created_at);
            try stmt.bind(10, msg.updated_at);
            try stmt.bind(11, msg.error_message orelse "");

            _ = try stmt.step();
        }
    }

    /// Delete message from database
    fn deleteFromDB(self: *MessageQueue, id: []const u8) !void {
        if (self.db) |db| {
            const sql = "DELETE FROM message_queue WHERE id = ?1";

            var stmt = try db.prepare(sql);
            defer stmt.finalize();

            try stmt.bind(1, id);
            _ = try stmt.step();
        }
    }

    pub fn deinit(self: *MessageQueue) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.messages.items) |msg| {
            msg.deinit(self.allocator);
            self.allocator.destroy(msg);
        }
        self.messages.deinit(self.allocator);
        self.index.deinit(self.allocator);
    }

    /// Enqueue a new message for delivery
    pub fn enqueue(
        self: *MessageQueue,
        from: []const u8,
        to: []const u8,
        data: []const u8,
    ) ![]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const id = try std.fmt.allocPrint(self.allocator, "{d}", .{self.next_id});
        self.next_id += 1;
        errdefer self.allocator.free(id);

        const msg = try self.allocator.create(QueuedMessage);
        errdefer self.allocator.destroy(msg);

        const now = time_compat.timestamp();

        const owned_from = try self.allocator.dupe(u8, from);
        errdefer self.allocator.free(owned_from);
        const owned_to = try self.allocator.dupe(u8, to);
        errdefer self.allocator.free(owned_to);
        const owned_data = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(owned_data);

        msg.* = .{
            .id = id,
            .from = owned_from,
            .to = owned_to,
            .data = owned_data,
            .status = .pending,
            .attempts = 0,
            .max_attempts = 5,
            .next_retry = now,
            .created_at = now,
            .updated_at = now,
            .error_message = null,
        };

        try self.messages.append(self.allocator, msg);
        errdefer _ = self.messages.pop();
        try self.index.put(self.allocator, msg.id, self.messages.items.len - 1);
        errdefer _ = self.index.remove(msg.id);

        // Persist to database
        try self.persistMessage(msg);

        return id;
    }

    /// Remove `messages.items[i]`, keeping the id index consistent with the
    /// swapRemove (the last element moves into slot i). Frees the message.
    fn removeAt(self: *MessageQueue, i: usize) void {
        const msg = self.messages.items[i];
        _ = self.index.remove(msg.id);
        _ = self.messages.swapRemove(i);
        if (i < self.messages.items.len) {
            // The previously-last message now lives at index i.
            self.index.put(self.allocator, self.messages.items[i].id, i) catch {};
        }
        msg.deinit(self.allocator);
        self.allocator.destroy(msg);
    }

    /// Get next message ready for delivery
    pub fn getNextPending(self: *MessageQueue) ?*QueuedMessage {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = time_compat.timestamp();

        for (self.messages.items) |msg| {
            if ((msg.status == .pending or msg.status == .retry) and msg.next_retry <= now) {
                msg.status = .processing;
                msg.attempts += 1;
                msg.updated_at = now;

                // Persist status change
                self.persistMessage(msg) catch |err| {
                    std.log.err("Failed to persist message status: {}", .{err});
                };

                return msg;
            }
        }

        return null;
    }

    /// Mark message as delivered
    pub fn markDelivered(self: *MessageQueue, id: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const i = self.index.get(id) orelse return error.MessageNotFound;
        const msg = self.messages.items[i];
        msg.status = .delivered;
        msg.updated_at = time_compat.timestamp();

        // Delete from database
        try self.deleteFromDB(id);

        // Remove from queue after successful delivery
        self.removeAt(i);
    }

    /// What markForRetry decided for a failed delivery.
    pub const RetryDisposition = enum {
        /// Another attempt is scheduled (exponential backoff).
        scheduled,
        /// Max attempts exhausted: the message was recorded as failed and
        /// removed from the active queue. Callers should emit a DSN.
        permanent,
    };

    /// Mark message as failed for retry
    pub fn markForRetry(self: *MessageQueue, id: []const u8, error_msg: []const u8) !RetryDisposition {
        self.mutex.lock();
        defer self.mutex.unlock();

        const i = self.index.get(id) orelse return error.MessageNotFound;
        const msg = self.messages.items[i];
        const now = time_compat.timestamp();

        // A failed allocation or disk update must release the worker's claim.
        // Keep the prior owned error string, but make this message retryable.
        errdefer {
            msg.status = .retry;
            msg.next_retry = now + 60;
            msg.updated_at = now;
        }

        const next_error = try self.allocator.dupe(u8, error_msg);
        errdefer self.allocator.free(next_error);
        var updated = msg.*;
        updated.error_message = next_error;
        updated.updated_at = now;

        if (msg.attempts >= msg.max_attempts) {
            updated.status = .failed;
            try self.persistMessage(&updated);
            try self.deleteFromDB(id);
            self.removeAt(i);
            self.allocator.free(next_error);
            return .permanent;
        } else {
            const backoff_seconds: i64 = @as(i64, @intCast(std.math.pow(u32, 2, msg.attempts))) * 60;
            updated.status = .retry;
            updated.next_retry = now + backoff_seconds;
            try self.persistMessage(&updated);
            if (msg.error_message) |old| self.allocator.free(old);
            msg.* = updated;
            return .scheduled;
        }
    }

    /// Get queue statistics
    pub fn getStats(self: *MessageQueue) QueueStats {
        self.mutex.lock();
        defer self.mutex.unlock();

        var stats = QueueStats{
            .total = self.messages.items.len,
            .pending = 0,
            .processing = 0,
            .retry = 0,
        };

        for (self.messages.items) |msg| {
            switch (msg.status) {
                .pending => stats.pending += 1,
                .processing => stats.processing += 1,
                .retry => stats.retry += 1,
                else => {},
            }
        }

        return stats;
    }

    /// Get all messages (for debugging/admin)
    pub fn listMessages(self: *MessageQueue, allocator: std.mem.Allocator) ![]QueuedMessage {
        self.mutex.lock();
        defer self.mutex.unlock();

        var list = try allocator.alloc(QueuedMessage, self.messages.items.len);
        for (self.messages.items, 0..) |msg, i| {
            list[i] = .{
                .id = try allocator.dupe(u8, msg.id),
                .from = try allocator.dupe(u8, msg.from),
                .to = try allocator.dupe(u8, msg.to),
                .data = try allocator.dupe(u8, msg.data),
                .status = msg.status,
                .attempts = msg.attempts,
                .max_attempts = msg.max_attempts,
                .next_retry = msg.next_retry,
                .created_at = msg.created_at,
                .updated_at = msg.updated_at,
                .error_message = if (msg.error_message) |err| try allocator.dupe(u8, err) else null,
            };
        }

        return list;
    }
};

pub const QueueStats = struct {
    total: usize,
    pending: usize,
    processing: usize,
    retry: usize,
};

test "message queue basic operations" {
    const testing = std.testing;
    var queue = MessageQueue.init(testing.allocator);
    defer queue.deinit();

    // Enqueue message
    const id = try queue.enqueue("sender@example.com", "recipient@example.com", "Test message");
    try testing.expect(id.len > 0);

    // Get next pending
    const msg = queue.getNextPending().?;
    try testing.expectEqualStrings("sender@example.com", msg.from);
    try testing.expect(msg.status == .processing);

    // Mark as delivered
    try queue.markDelivered(id);

    // Queue should be empty now
    try testing.expectEqual(@as(usize, 0), queue.messages.items.len);
}

test "message queue retry logic" {
    const testing = std.testing;
    var queue = MessageQueue.init(testing.allocator);
    defer queue.deinit();

    const id = try queue.enqueue("sender@example.com", "recipient@example.com", "Test message");

    _ = queue.getNextPending().?;
    try std.testing.expectEqual(MessageQueue.RetryDisposition.scheduled, try queue.markForRetry(id, "Connection failed"));

    const stats = queue.getStats();
    try testing.expectEqual(@as(usize, 1), stats.retry);
}

fn allocationFailureEnqueue(a: std.mem.Allocator) !void {
    var queue = MessageQueue.init(a);
    defer queue.deinit();
    _ = try queue.enqueue("from@example.com", "to@example.com", "body");
}

test "security: enqueue handles every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFailureEnqueue, .{});
}

test "security: retry retains the previous error after allocation failure" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var queue = MessageQueue.init(failing.allocator());
    defer queue.deinit();
    const id = try queue.enqueue("from@example.com", "to@example.com", "body");
    _ = try queue.markForRetry(id, "old error");
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, queue.markForRetry(id, "new error"));
    try std.testing.expectEqualStrings("old error", queue.messages.items[0].error_message.?);
}

test "security: failed queue persistence leaves no linked message" {
    var db = try database.Database.init(std.testing.allocator, ":memory:");
    defer db.deinit();
    var queue = try MessageQueue.initWithDB(std.testing.allocator, &db);
    defer queue.deinit();
    try db.exec("DROP TABLE message_queue");
    if (queue.enqueue("from@example.com", "to@example.com", "body")) |_| return error.ExpectedPersistenceFailure else |_| {}
    try std.testing.expectEqual(@as(usize, 0), queue.messages.items.len);
    try std.testing.expectEqual(@as(u32, 0), queue.index.count());
}

test "security: retry persistence failure releases the worker claim" {
    var db = try database.Database.init(std.testing.allocator, ":memory:");
    defer db.deinit();
    var queue = try MessageQueue.initWithDB(std.testing.allocator, &db);
    defer queue.deinit();
    const id = try queue.enqueue("from@example.com", "to@example.com", "body");
    _ = queue.getNextPending();
    try db.exec("DROP TABLE message_queue");
    if (queue.markForRetry(id, "temporary failure")) |_| return error.ExpectedPersistenceFailure else |_| {}
    try std.testing.expectEqual(MessageStatus.retry, queue.messages.items[0].status);
}

test "security: restart recovers persisted worker claims" {
    const a = std.testing.allocator;
    var db = try database.Database.init(a, ":memory:");
    defer db.deinit();
    {
        var queue = try MessageQueue.initWithDB(a, &db);
        defer queue.deinit();
        _ = try queue.enqueue("from@example.com", "to@example.com", "body");
        try db.exec("UPDATE message_queue SET status = 'processing'");
    }
    var restored = try MessageQueue.initWithDB(a, &db);
    defer restored.deinit();
    try std.testing.expect(restored.getNextPending() != null);
}

fn allocationFailureLoad(a: std.mem.Allocator, db: *database.Database) !void {
    var queue = try MessageQueue.initWithDB(a, db);
    defer queue.deinit();
}

test "security: queue reload releases every partial allocation" {
    const a = std.testing.allocator;
    var db = try database.Database.init(a, ":memory:");
    defer db.deinit();
    {
        var queue = try MessageQueue.initWithDB(a, &db);
        defer queue.deinit();
        _ = try queue.enqueue("from@example.com", "to@example.com", "body");
        _ = try queue.enqueue("from@example.com", "to@example.com", "another");
    }
    try std.testing.checkAllAllocationFailures(a, allocationFailureLoad, .{&db});
}
