const std = @import("std");
pub const database = @import("storage/database.zig");
pub const migrations = @import("storage/migrations.zig");

pub fn showStatus(manager: *migrations.MigrationManager) !void {
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
        std.debug.print("\nDatabase is up to date\n", .{});
    }
}

pub fn showHistory(manager: *migrations.MigrationManager, allocator: std.mem.Allocator) !void {
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
    std.debug.print("{s}\n", .{@as([70]u8, @splat('-'))});

    for (records) |record| {
        const timestamp = @as(i64, @intCast(record.applied_at));
        const dt = formatTimestamp(timestamp);
        std.debug.print("{d:<10} {s:<30} {s}\n", .{ record.version, record.name, dt });
    }
}

pub fn formatTimestamp(timestamp: i64) [19]u8 {
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
