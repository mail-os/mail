// Message Search with FTS5 Full-Text Search
// Provides fast, full-text search across email messages

const std = @import("std");
const database = @import("../storage/database.zig");
const logger = @import("../core/logger.zig");
const sqlite = @cImport({
    @cInclude("sqlite3.h");
});

/// Message search engine with FTS5 support
pub const MessageSearch = struct {
    allocator: std.mem.Allocator,
    db: *database.Database,
    fts_enabled: bool,

    const Self = @This();

    pub const SearchOptions = struct {
        email: ?[]const u8 = null,
        folder: ?[]const u8 = null,
        from_date: ?i64 = null,
        to_date: ?i64 = null,
        has_attachments: ?bool = null,
        limit: usize = 100,
        offset: usize = 0,
        sort_by: SortBy = .received_desc,
    };

    pub const SortBy = enum {
        received_asc,
        received_desc,
        relevance, // Only for FTS queries
        sender_asc,
        sender_desc,
        subject_asc,
        subject_desc,
    };

    pub const SearchResult = struct {
        id: i64,
        message_id: []const u8,
        email: []const u8,
        sender: []const u8,
        recipients: []const u8,
        subject: []const u8,
        body_snippet: []const u8,
        received_at: i64,
        size: i64,
        folder: []const u8,
        relevance_score: ?f64 = null,

        pub fn deinit(self: *SearchResult, allocator: std.mem.Allocator) void {
            allocator.free(self.message_id);
            allocator.free(self.email);
            allocator.free(self.sender);
            allocator.free(self.recipients);
            allocator.free(self.subject);
            allocator.free(self.body_snippet);
            allocator.free(self.folder);
        }
    };

    pub fn init(allocator: std.mem.Allocator, db: *database.Database) !Self {
        var self = Self{
            .allocator = allocator,
            .db = db,
            .fts_enabled = false,
        };

        // Try to enable FTS5
        self.fts_enabled = self.enableFTS() catch false;

        return self;
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// Enable FTS5 full-text search
    fn enableFTS(self: *Self) !bool {
        // Create FTS5 virtual table if it doesn't exist
        const fts_schema =
            \\CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
            \\    sender,
            \\    subject,
            \\    body,
            \\    content='messages',
            \\    content_rowid='id',
            \\    tokenize='porter unicode61'
            \\);
            \\
            \\-- Triggers to keep FTS index in sync
            \\CREATE TRIGGER IF NOT EXISTS messages_fts_insert AFTER INSERT ON messages BEGIN
            \\    INSERT INTO messages_fts(rowid, sender, subject, body)
            \\    VALUES (new.id, new.sender, new.subject, new.body);
            \\END;
            \\
            \\CREATE TRIGGER IF NOT EXISTS messages_fts_delete AFTER DELETE ON messages BEGIN
            \\    DELETE FROM messages_fts WHERE rowid = old.id;
            \\END;
            \\
            \\CREATE TRIGGER IF NOT EXISTS messages_fts_update AFTER UPDATE ON messages BEGIN
            \\    DELETE FROM messages_fts WHERE rowid = old.id;
            \\    INSERT INTO messages_fts(rowid, sender, subject, body)
            \\    VALUES (new.id, new.sender, new.subject, new.body);
            \\END;
        ;

        self.db.exec(fts_schema) catch |err| {
            logger.warn("Could not enable FTS5: {}", .{err});
            return false;
        };

        return true;
    }

    /// Rebuild FTS5 index from existing messages
    pub fn rebuildIndex(self: *Self) !void {
        if (!self.fts_enabled) return error.FTSNotEnabled;

        // Clear existing index
        try self.db.exec("DELETE FROM messages_fts;");

        // Rebuild from messages table
        const rebuild_query =
            \\INSERT INTO messages_fts(rowid, sender, subject, body)
            \\SELECT id, sender, subject, body FROM messages;
        ;

        try self.db.exec(rebuild_query);
    }

    /// Search messages with full-text query
    pub fn search(
        self: *Self,
        query: []const u8,
        options: SearchOptions,
    ) !std.array_list.Managed(SearchResult) {
        var results = std.array_list.Managed(SearchResult).init(self.allocator);
        errdefer {
            for (results.items) |*result| {
                result.deinit(self.allocator);
            }
            results.deinit();
        }

        if (self.fts_enabled and query.len > 0) {
            // Use FTS5 for full-text search
            try self.searchWithFTS(query, options, &results);
        } else {
            // Fall back to LIKE-based search
            try self.searchWithLike(query, options, &results);
        }

        return results;
    }

    /// Search using FTS5 (fast, relevance-ranked)
    fn searchWithFTS(
        self: *Self,
        query: []const u8,
        options: SearchOptions,
        results: *std.array_list.Managed(SearchResult),
    ) !void {
        var sql = std.array_list.Managed(u8).init(self.allocator);
        defer sql.deinit();

        try sql.appendSlice(
            \\SELECT
            \\    m.id,
            \\    m.message_id,
            \\    m.email,
            \\    m.sender,
            \\    m.recipients,
            \\    m.subject,
            \\    snippet(messages_fts, 2, '<b>', '</b>', '...', 32) as body_snippet,
            \\    m.received_at,
            \\    m.size,
            \\    m.folder,
            \\    rank
            \\FROM messages m
            \\JOIN messages_fts ON messages_fts.rowid = m.id
            \\WHERE messages_fts MATCH ?
        );

        // Add additional filters
        if (options.email != null) {
            try sql.appendSlice(" AND m.email = ?");
        }
        if (options.folder != null) {
            try sql.appendSlice(" AND m.folder = ?");
        }
        if (options.from_date != null) {
            try sql.appendSlice(" AND m.received_at >= ?");
        }
        if (options.to_date != null) {
            try sql.appendSlice(" AND m.received_at <= ?");
        }
        if (options.has_attachments != null) {
            try sql.appendSlice(" AND EXISTS (SELECT 1 FROM attachments WHERE message_id = m.id)");
        }

        // Add ordering
        switch (options.sort_by) {
            .relevance => try sql.appendSlice(" ORDER BY rank"),
            .received_desc => try sql.appendSlice(" ORDER BY m.received_at DESC"),
            .received_asc => try sql.appendSlice(" ORDER BY m.received_at ASC"),
            .sender_desc => try sql.appendSlice(" ORDER BY m.sender DESC"),
            .sender_asc => try sql.appendSlice(" ORDER BY m.sender ASC"),
            .subject_desc => try sql.appendSlice(" ORDER BY m.subject DESC"),
            .subject_asc => try sql.appendSlice(" ORDER BY m.subject ASC"),
        }

        // Add pagination
        try sql.appendSlice(" LIMIT ? OFFSET ?");

        var stmt = try self.db.prepare(sql.items);
        defer stmt.finalize();

        // Bind parameters
        var param_index: usize = 1;
        try stmt.bind(param_index, query);
        param_index += 1;

        if (options.email) |email| {
            try stmt.bind(param_index, email);
            param_index += 1;
        }
        if (options.folder) |folder| {
            try stmt.bind(param_index, folder);
            param_index += 1;
        }
        if (options.from_date) |from_date| {
            try stmt.bind(param_index, from_date);
            param_index += 1;
        }
        if (options.to_date) |to_date| {
            try stmt.bind(param_index, to_date);
            param_index += 1;
        }

        try stmt.bind(param_index, @as(i64, @intCast(options.limit)));
        param_index += 1;
        try stmt.bind(param_index, @as(i64, @intCast(options.offset)));

        // Fetch results
        while (try stmt.step()) {
            const result = SearchResult{
                .id = stmt.columnInt64(0),
                .message_id = try self.allocator.dupe(u8, stmt.columnText(1)),
                .email = try self.allocator.dupe(u8, stmt.columnText(2)),
                .sender = try self.allocator.dupe(u8, stmt.columnText(3)),
                .recipients = try self.allocator.dupe(u8, stmt.columnText(4)),
                .subject = try self.allocator.dupe(u8, stmt.columnText(5)),
                .body_snippet = try self.allocator.dupe(u8, stmt.columnText(6)),
                .received_at = stmt.columnInt64(7),
                .size = stmt.columnInt64(8),
                .folder = try self.allocator.dupe(u8, stmt.columnText(9)),
                .relevance_score = stmt.columnDouble(10),
            };

            try results.append(result);
        }
    }

    /// Search using LIKE (fallback, slower)
    fn searchWithLike(
        self: *Self,
        query: []const u8,
        options: SearchOptions,
        results: *std.array_list.Managed(SearchResult),
    ) !void {
        var sql = std.array_list.Managed(u8).init(self.allocator);
        defer sql.deinit();

        try sql.appendSlice(
            \\SELECT
            \\    id,
            \\    message_id,
            \\    email,
            \\    sender,
            \\    recipients,
            \\    subject,
            \\    substr(body, 1, 200) as body_snippet,
            \\    received_at,
            \\    size,
            \\    folder
            \\FROM messages
            \\WHERE 1=1
        );

        // Add search conditions
        if (query.len > 0) {
            try sql.appendSlice(
                \\ AND (
                \\     sender LIKE ? OR
                \\     recipients LIKE ? OR
                \\     subject LIKE ? OR
                \\     body LIKE ?
                \\ )
            );
        }

        // Add additional filters
        if (options.email != null) {
            try sql.appendSlice(" AND email = ?");
        }
        if (options.folder != null) {
            try sql.appendSlice(" AND folder = ?");
        }
        if (options.from_date != null) {
            try sql.appendSlice(" AND received_at >= ?");
        }
        if (options.to_date != null) {
            try sql.appendSlice(" AND received_at <= ?");
        }
        if (options.has_attachments != null) {
            try sql.appendSlice(" AND EXISTS (SELECT 1 FROM attachments WHERE message_id = messages.id)");
        }

        // Add ordering
        switch (options.sort_by) {
            .relevance, .received_desc => try sql.appendSlice(" ORDER BY received_at DESC"),
            .received_asc => try sql.appendSlice(" ORDER BY received_at ASC"),
            .sender_desc => try sql.appendSlice(" ORDER BY sender DESC"),
            .sender_asc => try sql.appendSlice(" ORDER BY sender ASC"),
            .subject_desc => try sql.appendSlice(" ORDER BY subject DESC"),
            .subject_asc => try sql.appendSlice(" ORDER BY subject ASC"),
        }

        // Add pagination
        try sql.appendSlice(" LIMIT ? OFFSET ?");

        var stmt = try self.db.prepare(sql.items);
        defer stmt.finalize();

        // Bind parameters
        var param_index: usize = 1;

        if (query.len > 0) {
            const like_pattern = try std.fmt.allocPrint(self.allocator, "%{s}%", .{query});
            defer self.allocator.free(like_pattern);

            try stmt.bind(param_index, like_pattern);
            param_index += 1;
            try stmt.bind(param_index, like_pattern);
            param_index += 1;
            try stmt.bind(param_index, like_pattern);
            param_index += 1;
            try stmt.bind(param_index, like_pattern);
            param_index += 1;
        }

        if (options.email) |email| {
            try stmt.bind(param_index, email);
            param_index += 1;
        }
        if (options.folder) |folder| {
            try stmt.bind(param_index, folder);
            param_index += 1;
        }
        if (options.from_date) |from_date| {
            try stmt.bind(param_index, from_date);
            param_index += 1;
        }
        if (options.to_date) |to_date| {
            try stmt.bind(param_index, to_date);
            param_index += 1;
        }

        try stmt.bind(param_index, @as(i64, @intCast(options.limit)));
        param_index += 1;
        try stmt.bind(param_index, @as(i64, @intCast(options.offset)));

        // Fetch results
        while (try stmt.step()) {
            const result = SearchResult{
                .id = stmt.columnInt64(0),
                .message_id = try self.allocator.dupe(u8, stmt.columnText(1)),
                .email = try self.allocator.dupe(u8, stmt.columnText(2)),
                .sender = try self.allocator.dupe(u8, stmt.columnText(3)),
                .recipients = try self.allocator.dupe(u8, stmt.columnText(4)),
                .subject = try self.allocator.dupe(u8, stmt.columnText(5)),
                .body_snippet = try self.allocator.dupe(u8, stmt.columnText(6)),
                .received_at = stmt.columnInt64(7),
                .size = stmt.columnInt64(8),
                .folder = try self.allocator.dupe(u8, stmt.columnText(9)),
                .relevance_score = null,
            };

            try results.append(result);
        }
    }

    /// Search by sender
    pub fn searchBySender(
        self: *Self,
        sender: []const u8,
        options: SearchOptions,
    ) !std.array_list.Managed(SearchResult) {
        const query = try std.fmt.allocPrint(self.allocator, "sender:{s}", .{sender});
        defer self.allocator.free(query);

        return try self.search(query, options);
    }

    /// Search by subject
    pub fn searchBySubject(
        self: *Self,
        subject: []const u8,
        options: SearchOptions,
    ) !std.array_list.Managed(SearchResult) {
        const query = try std.fmt.allocPrint(self.allocator, "subject:{s}", .{subject});
        defer self.allocator.free(query);

        return try self.search(query, options);
    }

    /// Search by date range
    pub fn searchByDateRange(
        self: *Self,
        from_date: i64,
        to_date: i64,
    ) !std.array_list.Managed(SearchResult) {
        var opts = SearchOptions{};
        opts.from_date = from_date;
        opts.to_date = to_date;

        return try self.search("", opts);
    }

    /// Get search statistics
    pub fn getStatistics(self: *Self) !SearchStatistics {
        const query =
            \\SELECT
            \\    COUNT(*) as total_messages,
            \\    SUM(size) as total_size,
            \\    MIN(received_at) as oldest_message,
            \\    MAX(received_at) as newest_message,
            \\    COUNT(DISTINCT sender) as unique_senders,
            \\    COUNT(DISTINCT folder) as total_folders
            \\FROM messages
        ;

        var stmt = try self.db.prepare(query);
        defer stmt.finalize();

        if (try stmt.step()) {
            return SearchStatistics{
                .total_messages = @intCast(stmt.columnInt64(0)),
                .total_size = @intCast(stmt.columnInt64(1)),
                .oldest_message = stmt.columnInt64(2),
                .newest_message = stmt.columnInt64(3),
                .unique_senders = @intCast(stmt.columnInt64(4)),
                .total_folders = @intCast(stmt.columnInt64(5)),
                .fts_enabled = self.fts_enabled,
            };
        }

        return error.NoResults;
    }
};

pub const SearchStatistics = struct {
    total_messages: usize,
    total_size: usize,
    oldest_message: i64,
    newest_message: i64,
    unique_senders: usize,
    total_folders: usize,
    fts_enabled: bool,
};

// Tests

test "MessageSearch: Initialize with FTS5" {
    const allocator = std.testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    var search = try MessageSearch.init(allocator, &db);
    defer search.deinit();

    try std.testing.expect(search.fts_enabled);
}

test "MessageSearch: Search with empty query" {
    const allocator = std.testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    var search = try MessageSearch.init(allocator, &db);
    defer search.deinit();

    var results = try search.search("", .{});
    defer {
        for (results.items) |*result| {
            result.deinit(allocator);
        }
        results.deinit();
    }

    try std.testing.expect(results.items.len == 0);
}

test "MessageSearch: Get statistics" {
    const allocator = std.testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    var search = try MessageSearch.init(allocator, &db);
    defer search.deinit();

    const stats = try search.getStatistics();
    try std.testing.expect(stats.total_messages == 0);
    try std.testing.expect(stats.fts_enabled);
}
