const std = @import("std");
const database = @import("storage/database.zig");
const migrations = @import("storage/migrations.zig");
const env = @import("core/env.zig");

pub fn main(init: std.process.Init.Minimal) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse arguments
    var arg_it = try init.args.iterateAllocator(allocator);
    defer arg_it.deinit();

    // Skip program name
    _ = arg_it.next();

    // Get command
    const command = arg_it.next() orelse {
        printHelp();
        return error.MissingCommand;
    };

    // Get database path
    const db_path = env.get("SMTP_DB_PATH") orelse "./smtp.db";

    // Initialize database
    var db = try database.Database.init(allocator, db_path);
    defer db.deinit();

    // Initialize migration manager with SMTP migrations
    var manager = migrations.MigrationManager.init(allocator, &db, &migrations.smtp_migrations);

    // Execute command
    if (std.mem.eql(u8, command, "up")) {
        try manager.migrateUp();
        std.debug.print("✓ Migrations applied successfully\n", .{});
    } else if (std.mem.eql(u8, command, "down")) {
        try manager.migrateDown();
        std.debug.print("✓ Migration rolled back successfully\n", .{});
    } else if (std.mem.eql(u8, command, "status")) {
        try showStatus(&manager);
    } else if (std.mem.eql(u8, command, "history")) {
        try showHistory(&manager, allocator);
    } else if (std.mem.eql(u8, command, "validate")) {
        try manager.validate();
        std.debug.print("✓ Migration order is valid\n", .{});
    } else if (std.mem.eql(u8, command, "to")) {
        const version_str = arg_it.next() orelse {
            std.debug.print("Error: 'to' command requires a version number\n", .{});
            return error.MissingVersion;
        };
        const version = try std.fmt.parseInt(u32, version_str, 10);
        try manager.migrateTo(version);
        std.debug.print("✓ Migrated to version {d}\n", .{version});
    } else {
        std.debug.print("Unknown command: {s}\n", .{command});
        printHelp();
        return error.UnknownCommand;
    }
}

fn showStatus(manager: *migrations.MigrationManager) !void {
    const current_version = try manager.getCurrentVersion();
    const total_migrations = migrations.smtp_migrations.len;

    std.debug.print("\n=== Migration Status ===\n", .{});
    std.debug.print("Current version: {d}\n", .{current_version});
    std.debug.print("Total migrations: {d}\n", .{total_migrations});

    var pending: u32 = 0;
    for (migrations.smtp_migrations) |migration| {
        if (migration.version > current_version) {
            pending += 1;
        }
    }

    std.debug.print("Pending migrations: {d}\n", .{pending});

    if (pending > 0) {
        std.debug.print("\nPending migrations:\n", .{});
        for (migrations.smtp_migrations) |migration| {
            if (migration.version > current_version) {
                std.debug.print("  {d}: {s}\n", .{ migration.version, migration.name });
            }
        }
    } else {
        std.debug.print("\n✓ Database is up to date\n", .{});
    }
}

fn showHistory(manager: *migrations.MigrationManager, allocator: std.mem.Allocator) !void {
    try manager.initMigrationsTable();

    const records = try manager.getHistory(allocator);
    defer {
        for (records) |*record| {
            allocator.free(record.name);
        }
        allocator.free(records);
    }

    if (records.len == 0) {
        std.debug.print("\nNo migrations have been applied yet.\n", .{});
        return;
    }

    std.debug.print("\n=== Migration History ===\n", .{});
    std.debug.print("{s:<10} {s:<30} {s}\n", .{ "Version", "Name", "Applied At" });
    std.debug.print("{s}\n", .{"-" ** 70});

    for (records) |record| {
        const timestamp = @as(i64, @intCast(record.applied_at));
        const dt = formatTimestamp(timestamp);
        std.debug.print("{d:<10} {s:<30} {s}\n", .{ record.version, record.name, dt });
    }
}

fn formatTimestamp(timestamp: i64) [19]u8 {
    const epoch_seconds: u64 = @intCast(timestamp);
    const epoch_day = std.time.epoch.EpochDay{ .day = @intCast(epoch_seconds / 86400) };
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    const seconds_today = epoch_seconds % 86400;
    const hours = seconds_today / 3600;
    const minutes = (seconds_today % 3600) / 60;
    const seconds = seconds_today % 60;

    var buf: [19]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        hours,
        minutes,
        seconds,
    }) catch |err| {
        std.debug.panic("Failed to format timestamp: {}", .{err});
    };

    return buf;
}

fn printHelp() void {
    const help_text =
        \\Migration CLI - Database migration manager for SMTP server
        \\
        \\USAGE:
        \\    migrate-cli <COMMAND> [OPTIONS]
        \\
        \\COMMANDS:
        \\    up              Apply all pending migrations
        \\    down            Rollback the last migration
        \\    to <VERSION>    Migrate to a specific version (up or down)
        \\    status          Show current migration status
        \\    history         Show migration history
        \\    validate        Validate migration order
        \\
        \\ENVIRONMENT:
        \\    SMTP_DB_PATH    Path to database file (default: ./smtp.db)
        \\
        \\EXAMPLES:
        \\    # Apply all pending migrations
        \\    migrate-cli up
        \\
        \\    # Rollback last migration
        \\    migrate-cli down
        \\
        \\    # Migrate to specific version
        \\    migrate-cli to 2
        \\
        \\    # Show migration status
        \\    migrate-cli status
        \\
        \\    # Show migration history
        \\    migrate-cli history
        \\
        \\    # Validate migrations
        \\    migrate-cli validate
        \\
    ;
    std.debug.print("{s}\n", .{help_text});
}
