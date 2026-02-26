// Search CLI - Command-line tool for searching email messages
// Usage: search-cli <command> [options]

const std = @import("std");
const search = @import("api/search.zig");
const database = @import("storage/database.zig");
const env = @import("core/env.zig");

pub fn main(init: std.process.Init) !void {
    const io_compat = @import("core/io_compat.zig");
    io_compat.initIo(init.io);

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const args = try init.minimal.args.toSlice(arena.allocator());

    if (args.len < 2) {
        try printUsage();
        return;
    }

    const command = args[1];

    // Get database path from environment or use default
    const db_path = env.get("SMTP_DB_PATH") orelse "smtp.db";

    var db = try database.Database.init(allocator, db_path);
    defer db.deinit();

    var search_engine = try search.MessageSearch.init(allocator, &db);
    defer search_engine.deinit();

    if (std.mem.eql(u8, command, "search")) {
        try searchCommand(&search_engine, allocator, args);
    } else if (std.mem.eql(u8, command, "sender")) {
        try senderCommand(&search_engine, allocator, args);
    } else if (std.mem.eql(u8, command, "subject")) {
        try subjectCommand(&search_engine, allocator, args);
    } else if (std.mem.eql(u8, command, "date-range")) {
        try dateRangeCommand(&search_engine, allocator, args);
    } else if (std.mem.eql(u8, command, "stats")) {
        try statsCommand(&search_engine, allocator);
    } else if (std.mem.eql(u8, command, "rebuild-index")) {
        try rebuildIndexCommand(&search_engine, allocator);
    } else {
        std.debug.print("Unknown command: {s}\n\n", .{command});
        try printUsage();
    }
}

fn printUsage() !void {
    std.debug.print(
        \\Search CLI - Email Message Search Tool
        \\
        \\Usage: search-cli <command> [options]
        \\
        \\Commands:
        \\  search <query> [--email <email>] [--folder <folder>] [--limit <n>]
        \\      Search messages using full-text search
        \\      Query syntax for FTS5:
        \\        - Words: "hello world" (AND by default)
        \\        - Phrases: '"exact phrase"'
        \\        - OR: "hello OR world"
        \\        - NOT: "hello NOT world"
        \\        - Field-specific: "sender:john" or "subject:meeting"
        \\
        \\  sender <sender> [--limit <n>]
        \\      Search messages by sender
        \\
        \\  subject <subject> [--limit <n>]
        \\      Search messages by subject
        \\
        \\  date-range <from-date> <to-date> [--email <email>]
        \\      Search messages by date range (Unix timestamps)
        \\
        \\  stats
        \\      Show search statistics and database info
        \\
        \\  rebuild-index
        \\      Rebuild the FTS5 search index
        \\
        \\Options:
        \\  --email <email>       Filter by email address
        \\  --folder <folder>     Filter by folder (default: INBOX)
        \\  --limit <n>           Limit results (default: 100)
        \\  --offset <n>          Skip N results (default: 0)
        \\  --sort <field>        Sort by: received-asc, received-desc (default),
        \\                        relevance, sender-asc, sender-desc,
        \\                        subject-asc, subject-desc
        \\  --from-date <ts>      Filter from date (Unix timestamp)
        \\  --to-date <ts>        Filter to date (Unix timestamp)
        \\  --attachments         Only show messages with attachments
        \\
        \\Environment Variables:
        \\  SMTP_DB_PATH         Path to SQLite database (default: smtp.db)
        \\
        \\Examples:
        \\  # Search for "meeting" in all fields
        \\  search-cli search meeting
        \\
        \\  # Search for exact phrase
        \\  search-cli search '"project update"'
        \\
        \\  # Search in subject only
        \\  search-cli search 'subject:invoice'
        \\
        \\  # Search by sender
        \\  search-cli sender john@example.com --limit 50
        \\
        \\  # Date range search
        \\  search-cli date-range 1698796800 1701388800
        \\
        \\  # Advanced query with filters
        \\  search-cli search "urgent OR important" --email user@example.com --attachments
        \\
        \\  # Show statistics
        \\  search-cli stats
        \\
        \\  # Rebuild search index
        \\  search-cli rebuild-index
        \\
    , .{});
}

fn searchCommand(
    engine: *search.MessageSearch,
    allocator: std.mem.Allocator,
    args: []const [:0]const u8,
) !void {
    if (args.len < 3) {
        std.debug.print("Error: Missing search query\n", .{});
        std.debug.print("Usage: search-cli search <query> [options]\n", .{});
        return;
    }

    const query = args[2];

    // Parse options
    var options = search.MessageSearch.SearchOptions{};
    var i: usize = 3;

    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "--email") and i + 1 < args.len) {
            options.email = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--folder") and i + 1 < args.len) {
            options.folder = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--limit") and i + 1 < args.len) {
            options.limit = try std.fmt.parseInt(usize, args[i + 1], 10);
            i += 1;
        } else if (std.mem.eql(u8, arg, "--offset") and i + 1 < args.len) {
            options.offset = try std.fmt.parseInt(usize, args[i + 1], 10);
            i += 1;
        } else if (std.mem.eql(u8, arg, "--from-date") and i + 1 < args.len) {
            options.from_date = try std.fmt.parseInt(i64, args[i + 1], 10);
            i += 1;
        } else if (std.mem.eql(u8, arg, "--to-date") and i + 1 < args.len) {
            options.to_date = try std.fmt.parseInt(i64, args[i + 1], 10);
            i += 1;
        } else if (std.mem.eql(u8, arg, "--attachments")) {
            options.has_attachments = true;
        } else if (std.mem.eql(u8, arg, "--sort") and i + 1 < args.len) {
            options.sort_by = parseSortBy(args[i + 1]) catch .received_desc;
            i += 1;
        }
    }

    // Perform search
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

    // Print results
    std.debug.print("Found {d} result(s):\n\n", .{results.items.len});

    for (results.items, 0..) |result, idx| {
        std.debug.print("─────────────────────────────────────────────────────────────\n", .{});
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

fn senderCommand(
    engine: *search.MessageSearch,
    allocator: std.mem.Allocator,
    args: []const [:0]const u8,
) !void {
    if (args.len < 3) {
        std.debug.print("Error: Missing sender\n", .{});
        std.debug.print("Usage: search-cli sender <sender> [options]\n", .{});
        return;
    }

    const sender = args[2];

    var options = search.MessageSearch.SearchOptions{};

    // Parse additional options
    var i: usize = 3;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--limit") and i + 1 < args.len) {
            options.limit = try std.fmt.parseInt(usize, args[i + 1], 10);
            i += 1;
        }
    }

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

fn subjectCommand(
    engine: *search.MessageSearch,
    allocator: std.mem.Allocator,
    args: []const [:0]const u8,
) !void {
    if (args.len < 3) {
        std.debug.print("Error: Missing subject\n", .{});
        std.debug.print("Usage: search-cli subject <subject> [options]\n", .{});
        return;
    }

    const subject = args[2];

    var options = search.MessageSearch.SearchOptions{};

    var i: usize = 3;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--limit") and i + 1 < args.len) {
            options.limit = try std.fmt.parseInt(usize, args[i + 1], 10);
            i += 1;
        }
    }

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

fn dateRangeCommand(
    engine: *search.MessageSearch,
    allocator: std.mem.Allocator,
    args: []const [:0]const u8,
) !void {
    if (args.len < 4) {
        std.debug.print("Error: Missing date range\n", .{});
        std.debug.print("Usage: search-cli date-range <from-date> <to-date>\n", .{});
        return;
    }

    const from_date = try std.fmt.parseInt(i64, args[2], 10);
    const to_date = try std.fmt.parseInt(i64, args[3], 10);

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

fn statsCommand(
    engine: *search.MessageSearch,
    allocator: std.mem.Allocator,
) !void {
    _ = allocator;

    std.debug.print("Database Statistics:\n", .{});
    std.debug.print("═══════════════════════════════════════════════════════════\n\n", .{});

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
    std.debug.print("\nFTS5 Full-Text Search: {s}\n", .{if (stats.fts_enabled) "ENABLED ✓" else "DISABLED ✗"});

    std.debug.print("\n", .{});
}

fn rebuildIndexCommand(
    engine: *search.MessageSearch,
    allocator: std.mem.Allocator,
) !void {
    _ = allocator;

    std.debug.print("Rebuilding FTS5 search index...\n", .{});

    engine.rebuildIndex() catch |err| {
        std.debug.print("Error rebuilding index: {}\n", .{err});
        return err;
    };

    std.debug.print("✓ Index rebuilt successfully\n", .{});
}

fn parseSortBy(sort_str: []const u8) !search.MessageSearch.SortBy {
    if (std.mem.eql(u8, sort_str, "received-asc")) return .received_asc;
    if (std.mem.eql(u8, sort_str, "received-desc")) return .received_desc;
    if (std.mem.eql(u8, sort_str, "relevance")) return .relevance;
    if (std.mem.eql(u8, sort_str, "sender-asc")) return .sender_asc;
    if (std.mem.eql(u8, sort_str, "sender-desc")) return .sender_desc;
    if (std.mem.eql(u8, sort_str, "subject-asc")) return .subject_asc;
    if (std.mem.eql(u8, sort_str, "subject-desc")) return .subject_desc;

    return error.InvalidSortField;
}
