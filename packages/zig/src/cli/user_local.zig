const std = @import("std");
const cli = @import("zig-cli");
const user_cli = @import("../user_cli.zig");
const database = @import("../storage/database.zig");
const auth = @import("../auth/auth.zig");
const env = @import("../core/env.zig");

fn withDb(comptime action: fn (*cli.BaseCommand.ParseContext, *database.Database, *auth.AuthBackend) anyerror!void) cli.BaseCommand.CommandAction {
    return struct {
        fn wrapper(ctx: *cli.BaseCommand.ParseContext) anyerror!void {
            const allocator = ctx.allocator;
            const db_path = env.get("SMTP_DB_PATH") orelse "./smtp.db";
            var db = try database.Database.init(allocator, db_path);
            defer db.deinit();
            var auth_backend = auth.AuthBackend.init(allocator, &db);
            try action(ctx, &db, &auth_backend);
        }
    }.wrapper;
}

fn createAction(ctx: *cli.BaseCommand.ParseContext, _: *database.Database, auth_backend: *auth.AuthBackend) !void {
    const username = ctx.getArgument(0) orelse {
        std.debug.print("Error: username is required\nUsage: mail user:local create <username> <password> <email>\n", .{});
        return;
    };
    const password = ctx.getArgument(1) orelse {
        std.debug.print("Error: password is required\nUsage: mail user:local create <username> <password> <email>\n", .{});
        return;
    };
    const email_arg = ctx.getArgument(2) orelse {
        std.debug.print("Error: email is required\nUsage: mail user:local create <username> <password> <email>\n", .{});
        return;
    };
    try user_cli.createUser(auth_backend, username, password, email_arg);
}

fn deleteAction(ctx: *cli.BaseCommand.ParseContext, db: *database.Database, _: *auth.AuthBackend) !void {
    const username = ctx.getArgument(0) orelse {
        std.debug.print("Error: username is required\nUsage: mail user:local delete <username>\n", .{});
        return;
    };
    try user_cli.deleteUser(db, username);
}

fn disableAction(ctx: *cli.BaseCommand.ParseContext, db: *database.Database, _: *auth.AuthBackend) !void {
    const username = ctx.getArgument(0) orelse {
        std.debug.print("Error: username is required\nUsage: mail user:local disable <username>\n", .{});
        return;
    };
    try user_cli.setUserEnabled(db, username, false);
}

fn enableAction(ctx: *cli.BaseCommand.ParseContext, db: *database.Database, _: *auth.AuthBackend) !void {
    const username = ctx.getArgument(0) orelse {
        std.debug.print("Error: username is required\nUsage: mail user:local enable <username>\n", .{});
        return;
    };
    try user_cli.setUserEnabled(db, username, true);
}

fn infoAction(ctx: *cli.BaseCommand.ParseContext, db: *database.Database, _: *auth.AuthBackend) !void {
    const allocator = ctx.allocator;
    const username = ctx.getArgument(0) orelse {
        std.debug.print("Error: username is required\nUsage: mail user:local info <username>\n", .{});
        return;
    };
    try user_cli.userInfo(db, allocator, username);
}

fn verifyAction(ctx: *cli.BaseCommand.ParseContext, _: *database.Database, auth_backend: *auth.AuthBackend) !void {
    const username = ctx.getArgument(0) orelse {
        std.debug.print("Error: username is required\nUsage: mail user:local verify <username> <password>\n", .{});
        return;
    };
    const password = ctx.getArgument(1) orelse {
        std.debug.print("Error: password is required\nUsage: mail user:local verify <username> <password>\n", .{});
        return;
    };
    try user_cli.verifyUser(auth_backend, username, password);
}

fn changePasswordAction(ctx: *cli.BaseCommand.ParseContext, _: *database.Database, auth_backend: *auth.AuthBackend) !void {
    const username = ctx.getArgument(0) orelse {
        std.debug.print("Error: username is required\nUsage: mail user:local change-password <username> <password>\n", .{});
        return;
    };
    const password = ctx.getArgument(1) orelse {
        std.debug.print("Error: password is required\nUsage: mail user:local change-password <username> <password>\n", .{});
        return;
    };
    try user_cli.changePassword(auth_backend, username, password);
}

pub fn setup(allocator: std.mem.Allocator) !*cli.BaseCommand {
    const cmd = try cli.BaseCommand.init(allocator, "user:local", "Local user management (direct DB access)");

    // create
    const create_cmd = try cli.BaseCommand.init(allocator, "create", "Create a new user locally");
    _ = try create_cmd.addArgument(cli.Argument.init("username", "Username", .string));
    _ = try create_cmd.addArgument(cli.Argument.init("password", "Password", .string));
    _ = try create_cmd.addArgument(cli.Argument.init("email", "Email address", .string));
    _ = create_cmd.setAction(withDb(createAction));
    _ = try cmd.addCommand(create_cmd);

    // delete
    const delete_cmd = try cli.BaseCommand.init(allocator, "delete", "Delete a user");
    _ = try delete_cmd.addArgument(cli.Argument.init("username", "Username to delete", .string));
    _ = delete_cmd.setAction(withDb(deleteAction));
    _ = try cmd.addCommand(delete_cmd);

    // disable
    const disable_cmd = try cli.BaseCommand.init(allocator, "disable", "Disable a user account");
    _ = try disable_cmd.addArgument(cli.Argument.init("username", "Username to disable", .string));
    _ = disable_cmd.setAction(withDb(disableAction));
    _ = try cmd.addCommand(disable_cmd);

    // enable
    const enable_cmd = try cli.BaseCommand.init(allocator, "enable", "Enable a user account");
    _ = try enable_cmd.addArgument(cli.Argument.init("username", "Username to enable", .string));
    _ = enable_cmd.setAction(withDb(enableAction));
    _ = try cmd.addCommand(enable_cmd);

    // info
    const info_cmd = try cli.BaseCommand.init(allocator, "info", "Show user information");
    _ = try info_cmd.addArgument(cli.Argument.init("username", "Username to query", .string));
    _ = info_cmd.setAction(withDb(infoAction));
    _ = try cmd.addCommand(info_cmd);

    // verify
    const verify_cmd = try cli.BaseCommand.init(allocator, "verify", "Verify user credentials");
    _ = try verify_cmd.addArgument(cli.Argument.init("username", "Username", .string));
    _ = try verify_cmd.addArgument(cli.Argument.init("password", "Password", .string));
    _ = verify_cmd.setAction(withDb(verifyAction));
    _ = try cmd.addCommand(verify_cmd);

    // change-password
    const change_pw_cmd = try cli.BaseCommand.init(allocator, "change-password", "Change user password");
    _ = try change_pw_cmd.addArgument(cli.Argument.init("username", "Username", .string));
    _ = try change_pw_cmd.addArgument(cli.Argument.init("password", "New password", .string));
    _ = change_pw_cmd.setAction(withDb(changePasswordAction));
    _ = try cmd.addCommand(change_pw_cmd);

    return cmd;
}
