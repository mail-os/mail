const std = @import("std");
const cli = @import("zig-cli");
const search_cli = @import("../search_cli.zig");
const typesense = @import("../search/typesense.zig");
const fs_compat = @import("../core/fs_compat.zig");

fn withSearchEngine(comptime action: fn (*cli.BaseCommand.ParseContext, *search_cli.search.MessageSearch) anyerror!void) cli.BaseCommand.CommandAction {
    return struct {
        fn wrapper(ctx: *cli.BaseCommand.ParseContext) anyerror!void {
            const allocator = ctx.allocator;
            const db_path = search_cli.env.get("SMTP_DB_PATH") orelse "smtp.db";
            var db = try search_cli.database.Database.init(allocator, db_path);
            defer db.deinit();
            var engine = try search_cli.search.MessageSearch.init(allocator, &db);
            defer engine.deinit();
            try action(ctx, &engine);
        }
    }.wrapper;
}

fn searchAction(ctx: *cli.BaseCommand.ParseContext, engine: *search_cli.search.MessageSearch) !void {
    const allocator = ctx.allocator;
    const query = ctx.getArgument(0) orelse {
        std.debug.print("Error: search query is required\nUsage: mail search <query> [options]\n", .{});
        return;
    };

    var options = search_cli.search.MessageSearch.SearchOptions{};
    if (ctx.getOption("email")) |v| options.email = v;
    if (ctx.getOption("folder")) |v| options.folder = v;
    if (ctx.getOption("limit")) |v| options.limit = std.fmt.parseInt(usize, v, 10) catch 100;
    if (ctx.getOption("offset")) |v| options.offset = std.fmt.parseInt(usize, v, 10) catch 0;
    if (ctx.getOption("from-date")) |v| options.from_date = std.fmt.parseInt(i64, v, 10) catch null;
    if (ctx.getOption("to-date")) |v| options.to_date = std.fmt.parseInt(i64, v, 10) catch null;
    if (ctx.hasOption("attachments")) options.has_attachments = true;
    if (ctx.getOption("sort")) |v| options.sort_by = search_cli.parseSortBy(v) catch .received_desc;

    try search_cli.searchCommand(engine, allocator, query, options);
}

fn senderAction(ctx: *cli.BaseCommand.ParseContext, engine: *search_cli.search.MessageSearch) !void {
    const allocator = ctx.allocator;
    const sender = ctx.getArgument(0) orelse {
        std.debug.print("Error: sender is required\nUsage: mail search sender <sender>\n", .{});
        return;
    };

    var options = search_cli.search.MessageSearch.SearchOptions{};
    if (ctx.getOption("limit")) |v| options.limit = std.fmt.parseInt(usize, v, 10) catch 100;

    try search_cli.senderCommand(engine, allocator, sender, options);
}

fn subjectAction(ctx: *cli.BaseCommand.ParseContext, engine: *search_cli.search.MessageSearch) !void {
    const allocator = ctx.allocator;
    const subject = ctx.getArgument(0) orelse {
        std.debug.print("Error: subject is required\nUsage: mail search subject <subject>\n", .{});
        return;
    };

    var options = search_cli.search.MessageSearch.SearchOptions{};
    if (ctx.getOption("limit")) |v| options.limit = std.fmt.parseInt(usize, v, 10) catch 100;

    try search_cli.subjectCommand(engine, allocator, subject, options);
}

fn dateRangeAction(ctx: *cli.BaseCommand.ParseContext, engine: *search_cli.search.MessageSearch) !void {
    const allocator = ctx.allocator;
    const from_str = ctx.getArgument(0) orelse {
        std.debug.print("Error: from-date is required\nUsage: mail search date-range <from> <to>\n", .{});
        return;
    };
    const to_str = ctx.getArgument(1) orelse {
        std.debug.print("Error: to-date is required\nUsage: mail search date-range <from> <to>\n", .{});
        return;
    };

    const from_date = std.fmt.parseInt(i64, from_str, 10) catch {
        std.debug.print("Error: invalid from-date: {s}\n", .{from_str});
        return;
    };
    const to_date = std.fmt.parseInt(i64, to_str, 10) catch {
        std.debug.print("Error: invalid to-date: {s}\n", .{to_str});
        return;
    };

    try search_cli.dateRangeCommand(engine, allocator, from_date, to_date);
}

fn statsAction(_: *cli.BaseCommand.ParseContext, engine: *search_cli.search.MessageSearch) !void {
    try search_cli.statsCommand(engine);
}

fn rebuildIndexAction(_: *cli.BaseCommand.ParseContext, engine: *search_cli.search.MessageSearch) !void {
    try search_cli.rebuildIndexCommand(engine);
}

/// Backfill the Typesense index from the Maildir tree: every message in
/// mail/{user}/{folder} is parsed and upserted. new/ and cur/ map to
/// INBOX, matching how the server names mailboxes at index time.
fn typesenseReindexAction(ctx: *cli.BaseCommand.ParseContext) anyerror!void {
    const allocator = ctx.allocator;

    if (!typesense.enabled()) {
        std.debug.print("Error: TYPESENSE_API_KEY is not set (TYPESENSE_HOST/TYPESENSE_PORT optional)\n", .{});
        return;
    }

    const root = ctx.getOption("root") orelse "mail";
    var indexed: usize = 0;
    var failed: usize = 0;

    const root_z = try allocator.dupeZ(u8, root);
    defer allocator.free(root_z);
    const root_dir = std.c.opendir(root_z.ptr) orelse {
        std.debug.print("Error: cannot open maildir root {s}\n", .{root});
        return;
    };
    defer _ = std.c.closedir(root_dir);

    while (std.c.readdir(root_dir)) |user_entry| {
        const user_ptr: [*:0]const u8 = @ptrCast(&user_entry.name);
        const user = std.mem.sliceTo(user_ptr, 0);
        if (user.len == 0 or user[0] == '.') continue;

        const user_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ root, user });
        defer allocator.free(user_path);
        const user_path_z = try allocator.dupeZ(u8, user_path);
        defer allocator.free(user_path_z);

        const user_dir = std.c.opendir(user_path_z.ptr) orelse continue;
        defer _ = std.c.closedir(user_dir);

        while (std.c.readdir(user_dir)) |folder_entry| {
            const folder_ptr: [*:0]const u8 = @ptrCast(&folder_entry.name);
            const folder = std.mem.sliceTo(folder_ptr, 0);
            if (folder.len == 0 or folder[0] == '.' or std.mem.eql(u8, folder, "tmp")) continue;

            const mailbox = if (std.mem.eql(u8, folder, "new") or std.mem.eql(u8, folder, "cur"))
                "INBOX"
            else
                folder;

            const folder_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ user_path, folder });
            defer allocator.free(folder_path);

            const files = fs_compat.listEmlFiles(allocator, folder_path) catch continue;
            defer {
                for (files) |f| allocator.free(f);
                allocator.free(files);
            }

            for (files) |filename| {
                const full_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ folder_path, filename });
                defer allocator.free(full_path);
                const content = fs_compat.readFileAlloc(allocator, full_path) catch {
                    failed += 1;
                    continue;
                };
                defer allocator.free(content);

                typesense.indexRawMessage(allocator, user, mailbox, filename, content) catch {
                    failed += 1;
                    continue;
                };
                indexed += 1;
            }
        }
    }

    std.debug.print("Typesense reindex complete: {d} indexed, {d} failed\n", .{ indexed, failed });
}

fn addSearchOptions(cmd: *cli.BaseCommand) !void {
    _ = try cmd.addOption(cli.Option.init("email", "email", "Filter by email address", .string));
    _ = try cmd.addOption(cli.Option.init("folder", "folder", "Filter by folder", .string));
    _ = try cmd.addOption(cli.Option.init("limit", "limit", "Limit results (default: 100)", .string));
    _ = try cmd.addOption(cli.Option.init("offset", "offset", "Skip N results", .string));
    _ = try cmd.addOption(cli.Option.init("from-date", "from-date", "Filter from date (Unix timestamp)", .string));
    _ = try cmd.addOption(cli.Option.init("to-date", "to-date", "Filter to date (Unix timestamp)", .string));
    _ = try cmd.addOption(cli.Option.init("attachments", "attachments", "Only show messages with attachments", .bool));
    _ = try cmd.addOption(cli.Option.init("sort", "sort", "Sort by: received-asc, received-desc, relevance, sender-asc, etc.", .string));
}

pub fn setup(allocator: std.mem.Allocator) !*cli.BaseCommand {
    const cmd = try cli.BaseCommand.init(allocator, "search", "Email message search");

    // Default search (also the root action when given a query as argument)
    _ = try cmd.addArgument(cli.Argument.init("query", "Search query", .string).withRequired(false));
    try addSearchOptions(cmd);
    _ = cmd.setAction(withSearchEngine(searchAction));

    // search sender
    const sender_cmd = try cli.BaseCommand.init(allocator, "sender", "Search by sender");
    _ = try sender_cmd.addArgument(cli.Argument.init("sender", "Sender address", .string));
    _ = try sender_cmd.addOption(cli.Option.init("limit", "limit", "Limit results", .string));
    _ = sender_cmd.setAction(withSearchEngine(senderAction));
    _ = try cmd.addCommand(sender_cmd);

    // search subject
    const subject_cmd = try cli.BaseCommand.init(allocator, "subject", "Search by subject");
    _ = try subject_cmd.addArgument(cli.Argument.init("subject", "Subject text", .string));
    _ = try subject_cmd.addOption(cli.Option.init("limit", "limit", "Limit results", .string));
    _ = subject_cmd.setAction(withSearchEngine(subjectAction));
    _ = try cmd.addCommand(subject_cmd);

    // search date-range
    const date_cmd = try cli.BaseCommand.init(allocator, "date-range", "Search by date range");
    _ = try date_cmd.addArgument(cli.Argument.init("from", "From date (Unix timestamp)", .string));
    _ = try date_cmd.addArgument(cli.Argument.init("to", "To date (Unix timestamp)", .string));
    _ = try date_cmd.addOption(cli.Option.init("email", "email", "Filter by email", .string));
    _ = date_cmd.setAction(withSearchEngine(dateRangeAction));
    _ = try cmd.addCommand(date_cmd);

    // search stats
    const stats_cmd = try cli.BaseCommand.init(allocator, "stats", "Show search statistics");
    _ = stats_cmd.setAction(withSearchEngine(statsAction));
    _ = try cmd.addCommand(stats_cmd);

    // search rebuild-index
    const rebuild_cmd = try cli.BaseCommand.init(allocator, "rebuild-index", "Rebuild the FTS5 search index");
    _ = rebuild_cmd.setAction(withSearchEngine(rebuildIndexAction));
    _ = try cmd.addCommand(rebuild_cmd);

    // search reindex — backfill the Typesense index from the Maildir
    const reindex_cmd = try cli.BaseCommand.init(allocator, "reindex", "Backfill the Typesense index from the Maildir");
    _ = try reindex_cmd.addOption(cli.Option.init("root", "root", "Maildir root (default: mail)", .string));
    _ = reindex_cmd.setAction(typesenseReindexAction);
    _ = try cmd.addCommand(reindex_cmd);

    return cmd;
}
