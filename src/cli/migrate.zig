const std = @import("std");
const cli = @import("zig-cli");
const migrate_cli = @import("../migrate_cli.zig");
const env = @import("../core/env.zig");

fn upAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const db_path = env.get("SMTP_DB_PATH") orelse "./smtp.db";
    var db = try migrate_cli.database.Database.init(ctx.allocator, db_path);
    defer db.deinit();
    var manager = migrate_cli.migrations.MigrationManager.init(ctx.allocator, &db, &migrate_cli.migrations.smtp_migrations);
    try manager.migrateUp();
    std.debug.print("Migrations applied successfully\n", .{});
}

fn downAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const db_path = env.get("SMTP_DB_PATH") orelse "./smtp.db";
    var db = try migrate_cli.database.Database.init(ctx.allocator, db_path);
    defer db.deinit();
    var manager = migrate_cli.migrations.MigrationManager.init(ctx.allocator, &db, &migrate_cli.migrations.smtp_migrations);
    try manager.migrateDown();
    std.debug.print("Migration rolled back successfully\n", .{});
}

fn statusAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const db_path = env.get("SMTP_DB_PATH") orelse "./smtp.db";
    var db = try migrate_cli.database.Database.init(ctx.allocator, db_path);
    defer db.deinit();
    var manager = migrate_cli.migrations.MigrationManager.init(ctx.allocator, &db, &migrate_cli.migrations.smtp_migrations);
    try migrate_cli.showStatus(&manager);
}

fn historyAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const allocator = ctx.allocator;
    const db_path = env.get("SMTP_DB_PATH") orelse "./smtp.db";
    var db = try migrate_cli.database.Database.init(allocator, db_path);
    defer db.deinit();
    var manager = migrate_cli.migrations.MigrationManager.init(allocator, &db, &migrate_cli.migrations.smtp_migrations);
    try migrate_cli.showHistory(&manager, allocator);
}

fn validateAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const db_path = env.get("SMTP_DB_PATH") orelse "./smtp.db";
    var db = try migrate_cli.database.Database.init(ctx.allocator, db_path);
    defer db.deinit();
    var manager = migrate_cli.migrations.MigrationManager.init(ctx.allocator, &db, &migrate_cli.migrations.smtp_migrations);
    try manager.validate();
    std.debug.print("Migration order is valid\n", .{});
}

fn toAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const version_str = ctx.getArgument(0) orelse {
        std.debug.print("Error: version number is required\nUsage: mail migrate to <version>\n", .{});
        return;
    };
    const version = std.fmt.parseInt(u32, version_str, 10) catch {
        std.debug.print("Error: invalid version number: {s}\n", .{version_str});
        return;
    };
    const db_path = env.get("SMTP_DB_PATH") orelse "./smtp.db";
    var db = try migrate_cli.database.Database.init(ctx.allocator, db_path);
    defer db.deinit();
    var manager = migrate_cli.migrations.MigrationManager.init(ctx.allocator, &db, &migrate_cli.migrations.smtp_migrations);
    try manager.migrateTo(version);
    std.debug.print("Migrated to version {d}\n", .{version});
}

pub fn setup(allocator: std.mem.Allocator) !*cli.BaseCommand {
    const cmd = try cli.BaseCommand.init(allocator, "migrate", "Database migration management");

    const up_cmd = try cli.BaseCommand.init(allocator, "up", "Apply all pending migrations");
    _ = up_cmd.setAction(upAction);
    _ = try cmd.addCommand(up_cmd);

    const down_cmd = try cli.BaseCommand.init(allocator, "down", "Rollback the last migration");
    _ = down_cmd.setAction(downAction);
    _ = try cmd.addCommand(down_cmd);

    const status_cmd = try cli.BaseCommand.init(allocator, "status", "Show current migration status");
    _ = status_cmd.setAction(statusAction);
    _ = try cmd.addCommand(status_cmd);

    const history_cmd = try cli.BaseCommand.init(allocator, "history", "Show migration history");
    _ = history_cmd.setAction(historyAction);
    _ = try cmd.addCommand(history_cmd);

    const validate_cmd = try cli.BaseCommand.init(allocator, "validate", "Validate migration order");
    _ = validate_cmd.setAction(validateAction);
    _ = try cmd.addCommand(validate_cmd);

    const to_cmd = try cli.BaseCommand.init(allocator, "to", "Migrate to a specific version");
    _ = try to_cmd.addArgument(cli.Argument.init("version", "Target version number", .string));
    _ = to_cmd.setAction(toAction);
    _ = try cmd.addCommand(to_cmd);

    return cmd;
}
