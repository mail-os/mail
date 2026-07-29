const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");

/// Time-series filesystem storage for email messages
/// Organizes messages by date hierarchy: year/month/day/<message-id>.eml
/// Each email is stored as a separate file
/// Simple, grep-able, backup-friendly, encryption-ready
///
/// Directory structure:
/// /data/
///   2025/
///     01/
///       23/
///         msg-abc123.eml
///         msg-def456.eml
///     01/
///       24/
///         msg-xyz789.eml
///
/// Benefits:
/// - Easy to backup (just copy directories)
/// - Easy to archive (move old year directories)
/// - Easy to grep/search with standard tools
/// - Easy to encrypt (per-file or per-directory encryption)
/// - No database corruption issues
/// - Human-readable structure
/// - Perfect for compliance/auditing
pub const TimeSeriesStorage = struct {
    allocator: std.mem.Allocator,
    base_path: []const u8,
    compress: bool, // Optional gzip compression
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator, base_path: []const u8, compress: bool) !TimeSeriesStorage {
        // Create base directory if it doesn't exist
        std.fs.cwd().makePath(base_path) catch |err| {
            if (err != error.PathAlreadyExists) {
                return err;
            }
        };

        return .{
            .allocator = allocator,
            .base_path = try allocator.dupe(u8, base_path),
            .compress = compress,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *TimeSeriesStorage) void {
        self.allocator.free(self.base_path);
    }

    /// Store a message with current timestamp
    pub fn storeMessage(
        self: *TimeSeriesStorage,
        message_id: []const u8,
        content: []const u8,
    ) ![]const u8 {
        return try self.storeMessageAt(message_id, content, null);
    }

    /// Store a message with specific timestamp
    pub fn storeMessageAt(
        self: *TimeSeriesStorage,
        message_id: []const u8,
        content: []const u8,
        timestamp: ?i64,
    ) ![]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const ts = timestamp orelse time_compat.timestamp();
        const date = try self.getDateFromTimestamp(ts);

        // Create directory path: base/year/month/day
        const dir_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{d:0>4}/{d:0>2}/{d:0>2}",
            .{ self.base_path, date.year, date.month, date.day },
        );
        defer self.allocator.free(dir_path);

        // Create directory structure
        try std.fs.cwd().makePath(dir_path);

        // Sanitize message_id for filename
        const safe_id = try self.sanitizeFilename(message_id);
        defer self.allocator.free(safe_id);

        // Create file path
        const extension = if (self.compress) ".eml.gz" else ".eml";
        const file_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}{s}",
            .{ dir_path, safe_id, extension },
        );

        // Write message to file
        const file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();

        if (self.compress) {
            // Would use gzip compression here
            // For now, just write as-is
            try file.writeAll(content);
        } else {
            try file.writeAll(content);
        }

        // Set file permissions (rw-r--r--)
        try file.chmod(0o644);

        return file_path;
    }

    /// Retrieve a message by ID and date
    pub fn retrieveMessage(
        self: *TimeSeriesStorage,
        message_id: []const u8,
        year: u16,
        month: u8,
        day: u8,
    ) ![]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const safe_id = try self.sanitizeFilename(message_id);
        defer self.allocator.free(safe_id);

        const extension = if (self.compress) ".eml.gz" else ".eml";
        const file_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{d:0>4}/{d:0>2}/{d:0>2}/{s}{s}",
            .{ self.base_path, year, month, day, safe_id, extension },
        );
        defer self.allocator.free(file_path);

        const file = try std.fs.cwd().openFile(file_path, .{});
        defer file.close();

        const size = (try file.stat()).size;
        const content = try self.allocator.alloc(u8, size);

        _ = try file.readAll(content);

        if (self.compress) {
            // Would decompress here
            return content;
        }

        return content;
    }

    /// Find message by ID (searches recent days)
    pub fn findMessage(
        self: *TimeSeriesStorage,
        message_id: []const u8,
        max_days_back: u32,
    ) !?MessageLocation {
        const now = time_compat.timestamp();

        var day_offset: u32 = 0;
        while (day_offset < max_days_back) : (day_offset += 1) {
            const ts = now - @as(i64, day_offset) * 86400;
            const date = try self.getDateFromTimestamp(ts);

            const safe_id = try self.sanitizeFilename(message_id);
            defer self.allocator.free(safe_id);

            const extension = if (self.compress) ".eml.gz" else ".eml";
            const file_path = try std.fmt.allocPrint(
                self.allocator,
                "{s}/{d:0>4}/{d:0>2}/{d:0>2}/{s}{s}",
                .{ self.base_path, date.year, date.month, date.day, safe_id, extension },
            );
            defer self.allocator.free(file_path);

            // Check if file exists
            const file = std.fs.cwd().openFile(file_path, .{}) catch |err| {
                if (err == error.FileNotFound) {
                    continue;
                }
                return err;
            };
            file.close();

            return MessageLocation{
                .year = date.year,
                .month = date.month,
                .day = date.day,
                .message_id = try self.allocator.dupe(u8, message_id),
            };
        }

        return null;
    }

    /// List messages for a specific day
    pub fn listMessagesForDay(
        self: *TimeSeriesStorage,
        year: u16,
        month: u8,
        day: u8,
    ) ![]MessageInfo {
        self.mutex.lock();
        defer self.mutex.unlock();

        const dir_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{d:0>4}/{d:0>2}/{d:0>2}",
            .{ self.base_path, year, month, day },
        );
        defer self.allocator.free(dir_path);

        var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch |err| {
            if (err == error.FileNotFound) {
                return &[_]MessageInfo{};
            }
            return err;
        };
        defer dir.close();

        var messages = std.ArrayList(MessageInfo).init(self.allocator);

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .file) continue;

            // Parse filename (remove .eml or .eml.gz extension)
            const name = entry.name;
            const message_id = if (std.mem.endsWith(u8, name, ".eml.gz"))
                name[0 .. name.len - 7]
            else if (std.mem.endsWith(u8, name, ".eml"))
                name[0 .. name.len - 4]
            else
                continue;

            const file_path = try std.fmt.allocPrint(
                self.allocator,
                "{s}/{s}",
                .{ dir_path, name },
            );
            defer self.allocator.free(file_path);

            const stat = try std.fs.cwd().statFile(file_path);

            const info = MessageInfo{
                .message_id = try self.allocator.dupe(u8, message_id),
                .year = year,
                .month = month,
                .day = day,
                .size = stat.size,
                .modified = stat.mtime,
            };

            try messages.append(self.allocator, info);
        }

        return try messages.toOwnedSlice(self.allocator);
    }

    /// List messages for a date range
    pub fn listMessagesInRange(
        self: *TimeSeriesStorage,
        start_ts: i64,
        end_ts: i64,
    ) ![]MessageInfo {
        var messages = std.ArrayList(MessageInfo).init(self.allocator);

        const start_date = try self.getDateFromTimestamp(start_ts);
        const end_date = try self.getDateFromTimestamp(end_ts);

        // Iterate through each day in range
        var current_ts = start_ts;
        while (current_ts <= end_ts) : (current_ts += 86400) {
            const date = try self.getDateFromTimestamp(current_ts);

            const day_messages = try self.listMessagesForDay(date.year, date.month, date.day);
            defer {
                for (day_messages) |*msg| {
                    msg.deinit(self.allocator);
                }
                self.allocator.free(day_messages);
            }

            for (day_messages) |msg| {
                try messages.append(self.allocator, try msg.clone(self.allocator));
            }
        }

        _ = start_date;
        _ = end_date;

        return try messages.toOwnedSlice(self.allocator);
    }

    /// Delete a message
    pub fn deleteMessage(
        self: *TimeSeriesStorage,
        message_id: []const u8,
        year: u16,
        month: u8,
        day: u8,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const safe_id = try self.sanitizeFilename(message_id);
        defer self.allocator.free(safe_id);

        const extension = if (self.compress) ".eml.gz" else ".eml";
        const file_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{d:0>4}/{d:0>2}/{d:0>2}/{s}{s}",
            .{ self.base_path, year, month, day, safe_id, extension },
        );
        defer self.allocator.free(file_path);

        try std.fs.cwd().deleteFile(file_path);
    }

    /// Archive old messages (move to archive directory)
    pub fn archiveOlderThan(
        self: *TimeSeriesStorage,
        days_old: u32,
        archive_path: []const u8,
    ) !usize {
        _ = archive_path;

        const cutoff_ts = time_compat.timestamp() - @as(i64, days_old) * 86400;
        const cutoff_date = try self.getDateFromTimestamp(cutoff_ts);

        // Would iterate through directories older than cutoff
        // and move them to archive location

        _ = cutoff_date;

        return 0; // Count of archived messages
    }

    /// Get storage statistics
    pub fn getStats(self: *TimeSeriesStorage) !StorageStats {
        var stats = StorageStats{};

        // Walk directory tree and count files/sizes
        var walker = try std.fs.cwd().openDir(self.base_path, .{ .iterate = true });
        defer walker.close();

        // Would recursively count files and sizes

        return stats;
    }

    /// Helper: Convert timestamp to date
    fn getDateFromTimestamp(self: *TimeSeriesStorage, timestamp: i64) !Date {
        _ = self;

        const epoch_seconds: u64 = @intCast(timestamp);
        const epoch_days = epoch_seconds / 86400;
        const year_day = std.time.epoch.EpochDay{ .day = epoch_days };
        const year_and_day = year_day.calculateYearDay();
        const month_day = year_and_day.calculateMonthDay();

        return Date{
            .year = @intCast(year_and_day.year),
            .month = @intFromEnum(month_day.month),
            .day = month_day.day_index + 1,
        };
    }

    /// Helper: Sanitize filename (remove dangerous characters)
    fn sanitizeFilename(self: *TimeSeriesStorage, input: []const u8) ![]const u8 {
        var sanitized = try std.ArrayList(u8).initCapacity(self.allocator, input.len);

        for (input) |char| {
            switch (char) {
                'a'...'z', 'A'...'Z', '0'...'9', '-', '_', '.' => {
                    try sanitized.append(self.allocator, char);
                },
                '/', '\\', ' ' => {
                    try sanitized.append(self.allocator, '_');
                },
                else => {
                    // Skip dangerous characters
                },
            }
        }

        return try sanitized.toOwnedSlice(self.allocator);
    }
};

pub const Date = struct {
    year: u16,
    month: u8,
    day: u8,
};

pub const MessageLocation = struct {
    year: u16,
    month: u8,
    day: u8,
    message_id: []const u8,

    pub fn deinit(self: *MessageLocation, allocator: std.mem.Allocator) void {
        allocator.free(self.message_id);
    }
};

pub const MessageInfo = struct {
    message_id: []const u8,
    year: u16,
    month: u8,
    day: u8,
    size: u64,
    modified: i128,

    pub fn deinit(self: *MessageInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.message_id);
    }

    pub fn clone(self: *const MessageInfo, allocator: std.mem.Allocator) !MessageInfo {
        return MessageInfo{
            .message_id = try allocator.dupe(u8, self.message_id),
            .year = self.year,
            .month = self.month,
            .day = self.day,
            .size = self.size,
            .modified = self.modified,
        };
    }
};

pub const StorageStats = struct {
    total_messages: usize = 0,
    total_size: u64 = 0,
    oldest_year: ?u16 = null,
    newest_year: ?u16 = null,
};

test "time-series storage initialization" {
    const testing = std.testing;

    const tmp_dir = "/tmp/timeseries-test";
    std.fs.cwd().deleteTree(tmp_dir) catch {};

    var storage = try TimeSeriesStorage.init(testing.allocator, tmp_dir, false);
    defer storage.deinit();
    defer std.fs.cwd().deleteTree(tmp_dir) catch {};

    try testing.expectEqualStrings(tmp_dir, storage.base_path);
}

test "store and retrieve message" {
    const testing = std.testing;

    const tmp_dir = "/tmp/timeseries-test-store";
    std.fs.cwd().deleteTree(tmp_dir) catch {};

    var storage = try TimeSeriesStorage.init(testing.allocator, tmp_dir, false);
    defer storage.deinit();
    defer std.fs.cwd().deleteTree(tmp_dir) catch {};

    const message_id = "test-message-123";
    const content = "From: sender@example.com\r\nTo: recipient@example.com\r\n\r\nTest body";

    const file_path = try storage.storeMessage(message_id, content);
    defer testing.allocator.free(file_path);

    // Verify file was created
    try testing.expect(file_path.len > 0);

    // Get today's date for retrieval
    const now = time_compat.timestamp();
    const date = try storage.getDateFromTimestamp(now);

    const retrieved = try storage.retrieveMessage(message_id, date.year, date.month, date.day);
    defer testing.allocator.free(retrieved);

    try testing.expectEqualStrings(content, retrieved);
}

test "sanitize filename" {
    const testing = std.testing;

    const tmp_dir = "/tmp/timeseries-test-sanitize";
    var storage = try TimeSeriesStorage.init(testing.allocator, tmp_dir, false);
    defer storage.deinit();

    const unsafe = "test/message\\with spaces.txt";
    const safe = try storage.sanitizeFilename(unsafe);
    defer testing.allocator.free(safe);

    try testing.expectEqualStrings("test_message_with_spaces.txt", safe);
}

test "list messages for day" {
    const testing = std.testing;

    const tmp_dir = "/tmp/timeseries-test-list";
    std.fs.cwd().deleteTree(tmp_dir) catch {};

    var storage = try TimeSeriesStorage.init(testing.allocator, tmp_dir, false);
    defer storage.deinit();
    defer std.fs.cwd().deleteTree(tmp_dir) catch {};

    // Store multiple messages
    _ = try storage.storeMessage("msg1", "Content 1");
    _ = try storage.storeMessage("msg2", "Content 2");

    const now = time_compat.timestamp();
    const date = try storage.getDateFromTimestamp(now);

    const messages = try storage.listMessagesForDay(date.year, date.month, date.day);
    defer {
        for (messages) |*msg| {
            msg.deinit(testing.allocator);
        }
        testing.allocator.free(messages);
    }

    try testing.expectEqual(@as(usize, 2), messages.len);
}

test "find message by ID" {
    const testing = std.testing;

    const tmp_dir = "/tmp/timeseries-test-find";
    std.fs.cwd().deleteTree(tmp_dir) catch {};

    var storage = try TimeSeriesStorage.init(testing.allocator, tmp_dir, false);
    defer storage.deinit();
    defer std.fs.cwd().deleteTree(tmp_dir) catch {};

    const message_id = "findable-message";
    _ = try storage.storeMessage(message_id, "Test content");

    const location = try storage.findMessage(message_id, 7);
    try testing.expect(location != null);

    if (location) |loc| {
        var loc_copy = loc;
        defer loc_copy.deinit(testing.allocator);
        try testing.expectEqualStrings(message_id, loc.message_id);
    }
}

test "delete message" {
    const testing = std.testing;

    const tmp_dir = "/tmp/timeseries-test-delete";
    std.fs.cwd().deleteTree(tmp_dir) catch {};

    var storage = try TimeSeriesStorage.init(testing.allocator, tmp_dir, false);
    defer storage.deinit();
    defer std.fs.cwd().deleteTree(tmp_dir) catch {};

    const message_id = "delete-me";
    _ = try storage.storeMessage(message_id, "Content to delete");

    const now = time_compat.timestamp();
    const date = try storage.getDateFromTimestamp(now);

    try storage.deleteMessage(message_id, date.year, date.month, date.day);

    // Verify deleted
    const result = storage.retrieveMessage(message_id, date.year, date.month, date.day);
    try testing.expectError(error.FileNotFound, result);
}
