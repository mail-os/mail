const std = @import("std");
pub const search = @import("api/search.zig");
pub const database = @import("storage/database.zig");
pub const env = @import("core/env.zig");

pub fn searchCommand(
    engine: *search.MessageSearch,
    allocator: std.mem.Allocator,
    query: []const u8,
    options: search.MessageSearch.SearchOptions,
) !void {
    std.debug.print("Searching for: {s}\n", .{query});
    if (options.email) |email| {
        std.debug.print("  Email: {s}\n", .{email});
    }
    if (options.folder) |folder| {
        std.debug.print("  Folder: {s}\n", .{folder});
    }
    std.debug.print("\n", .{});

    var results = try engine.search(query, options);
    defer {
        for (results.items) |*result| {
            result.deinit(allocator);
        }
        results.deinit();
    }

    std.debug.print("Found {d} result(s):\n\n", .{results.items.len});

    for (results.items, 0..) |result, idx| {
        std.debug.print("---\n", .{});
        std.debug.print("[{d}] Message ID: {s}\n", .{ idx + 1, result.message_id });
        std.debug.print("From: {s}\n", .{result.sender});
        std.debug.print("To: {s}\n", .{result.recipients});
        std.debug.print("Subject: {s}\n", .{result.subject});
        std.debug.print("Date: {d} (Unix timestamp)\n", .{result.received_at});
        std.debug.print("Size: {d} bytes\n", .{result.size});
        std.debug.print("Folder: {s}\n", .{result.folder});

        if (result.relevance_score) |score| {
            std.debug.print("Relevance: {d:.2}\n", .{score});
        }

        std.debug.print("\nSnippet:\n{s}\n\n", .{result.body_snippet});
    }

    if (results.items.len == 0) {
        std.debug.print("No messages found.\n", .{});
    }
}

pub fn senderCommand(
    engine: *search.MessageSearch,
    allocator: std.mem.Allocator,
    sender: []const u8,
    options: search.MessageSearch.SearchOptions,
) !void {
    std.debug.print("Searching for messages from: {s}\n\n", .{sender});

    var results = try engine.searchBySender(sender, options);
    defer {
        for (results.items) |*result| {
            result.deinit(allocator);
        }
        results.deinit();
    }

    std.debug.print("Found {d} message(s) from {s}\n\n", .{ results.items.len, sender });

    for (results.items, 0..) |result, idx| {
        std.debug.print("[{d}] {s} | {s}\n", .{ idx + 1, result.subject, result.message_id });
    }
}

pub fn subjectCommand(
    engine: *search.MessageSearch,
    allocator: std.mem.Allocator,
    subject: []const u8,
    options: search.MessageSearch.SearchOptions,
) !void {
    std.debug.print("Searching for messages with subject: {s}\n\n", .{subject});

    var results = try engine.searchBySubject(subject, options);
    defer {
        for (results.items) |*result| {
            result.deinit(allocator);
        }
        results.deinit();
    }

    std.debug.print("Found {d} message(s)\n\n", .{results.items.len});

    for (results.items, 0..) |result, idx| {
        std.debug.print("[{d}] From: {s} | {s}\n", .{ idx + 1, result.sender, result.message_id });
    }
}

pub fn dateRangeCommand(
    engine: *search.MessageSearch,
    allocator: std.mem.Allocator,
    from_date: i64,
    to_date: i64,
) !void {
    std.debug.print("Searching for messages from {d} to {d}\n\n", .{ from_date, to_date });

    var results = try engine.searchByDateRange(from_date, to_date);
    defer {
        for (results.items) |*result| {
            result.deinit(allocator);
        }
        results.deinit();
    }

    std.debug.print("Found {d} message(s)\n\n", .{results.items.len});

    for (results.items, 0..) |result, idx| {
        std.debug.print("[{d}] {d} | {s} | {s}\n", .{
            idx + 1,
            result.received_at,
            result.sender,
            result.subject,
        });
    }
}

pub fn statsCommand(engine: *search.MessageSearch) !void {
    std.debug.print("Database Statistics:\n", .{});
    std.debug.print("===\n\n", .{});

    const stats = try engine.getStatistics();

    std.debug.print("Total Messages: {d}\n", .{stats.total_messages});
    std.debug.print("Total Size: {d} bytes ({d:.2} MB)\n", .{
        stats.total_size,
        @as(f64, @floatFromInt(stats.total_size)) / 1024.0 / 1024.0,
    });
    std.debug.print("Unique Senders: {d}\n", .{stats.unique_senders});
    std.debug.print("Total Folders: {d}\n", .{stats.total_folders});
    std.debug.print("\nOldest Message: {d} (Unix timestamp)\n", .{stats.oldest_message});
    std.debug.print("Newest Message: {d} (Unix timestamp)\n", .{stats.newest_message});
    std.debug.print("\nFTS5 Full-Text Search: {s}\n", .{if (stats.fts_enabled) "ENABLED" else "DISABLED"});

    std.debug.print("\n", .{});
}

pub fn rebuildIndexCommand(engine: *search.MessageSearch) !void {
    std.debug.print("Rebuilding FTS5 search index...\n", .{});

    engine.rebuildIndex() catch |err| {
        std.debug.print("Error rebuilding index: {}\n", .{err});
        return err;
    };

    std.debug.print("Index rebuilt successfully\n", .{});
}

pub fn parseSortBy(sort_str: []const u8) !search.MessageSearch.SortBy {
    if (std.mem.eql(u8, sort_str, "received-asc")) return .received_asc;
    if (std.mem.eql(u8, sort_str, "received-desc")) return .received_desc;
    if (std.mem.eql(u8, sort_str, "relevance")) return .relevance;
    if (std.mem.eql(u8, sort_str, "sender-asc")) return .sender_asc;
    if (std.mem.eql(u8, sort_str, "sender-desc")) return .sender_desc;
    if (std.mem.eql(u8, sort_str, "subject-asc")) return .subject_asc;
    if (std.mem.eql(u8, sort_str, "subject-desc")) return .subject_desc;

    return error.InvalidSortField;
}
