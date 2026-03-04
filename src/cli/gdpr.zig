const std = @import("std");
const cli = @import("zig-cli");
const gdpr_cli = @import("../gdpr_cli.zig");

fn exportAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const allocator = ctx.allocator;
    const username = ctx.getArgument(0) orelse {
        std.debug.print("Error: username is required\nUsage: mail gdpr export <username> [output_file]\n", .{});
        return;
    };
    const output_file = ctx.getArgument(1);

    const db_path = gdpr_cli.env.get("SMTP_DB_PATH") orelse "smtp.db";
    var manager = try gdpr_cli.gdpr.GDPRManager.init(allocator, db_path);
    defer manager.deinit();

    try gdpr_cli.exportCommand(&manager, allocator, username, output_file);
}

fn deleteAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const allocator = ctx.allocator;
    const username = ctx.getArgument(0) orelse {
        std.debug.print("Error: username is required\nUsage: mail gdpr delete <username>\n", .{});
        return;
    };

    const db_path = gdpr_cli.env.get("SMTP_DB_PATH") orelse "smtp.db";
    var manager = try gdpr_cli.gdpr.GDPRManager.init(allocator, db_path);
    defer manager.deinit();

    try gdpr_cli.deleteCommand(&manager, username);
}

fn logAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const allocator = ctx.allocator;
    const username = ctx.getArgument(0) orelse {
        std.debug.print("Error: username is required\nUsage: mail gdpr log <username> <action> <ip>\n", .{});
        return;
    };
    const action = ctx.getArgument(1) orelse {
        std.debug.print("Error: action is required\nUsage: mail gdpr log <username> <action> <ip>\n", .{});
        return;
    };
    const ip_address = ctx.getArgument(2) orelse {
        std.debug.print("Error: IP address is required\nUsage: mail gdpr log <username> <action> <ip>\n", .{});
        return;
    };

    const db_path = gdpr_cli.env.get("SMTP_DB_PATH") orelse "smtp.db";
    var manager = try gdpr_cli.gdpr.GDPRManager.init(allocator, db_path);
    defer manager.deinit();

    try gdpr_cli.logCommand(&manager, username, action, ip_address);
}

pub fn setup(allocator: std.mem.Allocator) !*cli.BaseCommand {
    const cmd = try cli.BaseCommand.init(allocator, "gdpr", "GDPR data protection commands");

    const export_cmd = try cli.BaseCommand.init(allocator, "export", "Export all user data to JSON");
    _ = try export_cmd.addArgument(cli.Argument.init("username", "Username to export", .string));
    _ = try export_cmd.addArgument(cli.Argument.init("output_file", "Output file path (optional)", .string).withRequired(false));
    _ = export_cmd.setAction(exportAction);
    _ = try cmd.addCommand(export_cmd);

    const delete_cmd = try cli.BaseCommand.init(allocator, "delete", "Delete all user data permanently");
    _ = try delete_cmd.addArgument(cli.Argument.init("username", "Username to delete", .string));
    _ = delete_cmd.setAction(deleteAction);
    _ = try cmd.addCommand(delete_cmd);

    const log_cmd = try cli.BaseCommand.init(allocator, "log", "Log GDPR data access");
    _ = try log_cmd.addArgument(cli.Argument.init("username", "Username", .string));
    _ = try log_cmd.addArgument(cli.Argument.init("action", "Access action", .string));
    _ = try log_cmd.addArgument(cli.Argument.init("ip", "IP address", .string));
    _ = log_cmd.setAction(logAction);
    _ = try cmd.addCommand(log_cmd);

    return cmd;
}
