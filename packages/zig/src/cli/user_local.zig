const std = @import("std");
const cli = @import("zig-cli");
const user_cli = @import("../user_cli.zig");
const database = @import("../storage/database.zig");
const auth = @import("../auth/auth.zig");
const env = @import("../core/env.zig");
const recovery = @import("../api/webmail_recovery.zig");

const max_input_password_bytes = 4096;
const PasswordInput = [max_input_password_bytes + 1]u8;
const password_input_signals = [_]std.posix.SIG{ .HUP, .INT, .QUIT, .TERM, .TSTP };
var saved_terminal: std.posix.termios = undefined;

fn restoreTerminalOnSignal(signal: std.posix.SIG) callconv(.c) void {
    _ = std.c.tcsetattr(std.posix.STDIN_FILENO, .NOW, &saved_terminal);
    std.c._exit(@intCast(128 + @backingInt(signal)));
}

fn readPasswordLine(buffer: *PasswordInput) ![]const u8 {
    var length: usize = 0;
    var byte: [1]u8 = undefined;
    defer std.crypto.secureZero(u8, &byte);
    while (try std.posix.read(std.posix.STDIN_FILENO, &byte) != 0 and byte[0] != '\n') {
        if (length == buffer.len) return error.PasswordTooLong;
        buffer[length] = byte[0];
        length += 1;
    }
    if (length > 0 and buffer[length - 1] == '\r') length -= 1;
    if (length > max_input_password_bytes) return error.PasswordTooLong;
    if (length == 0) return error.EmptyPassword;
    return buffer[0..length];
}

fn promptPassword(buffer: *PasswordInput, prompt: []const u8) ![]const u8 {
    const stdin = std.posix.STDIN_FILENO;
    if (std.c.isatty(stdin) == 0) return readPasswordLine(buffer);

    saved_terminal = try std.posix.tcgetattr(stdin);
    const action = std.posix.Sigaction{
        .handler = .{ .handler = restoreTerminalOnSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    var previous: [password_input_signals.len]std.posix.Sigaction = undefined;
    for (password_input_signals, &previous) |signal, *old| std.posix.sigaction(signal, &action, old);
    defer for (password_input_signals, &previous) |signal, *old| std.posix.sigaction(signal, old, null);

    var hidden = saved_terminal;
    hidden.lflag.ECHO = false;
    hidden.lflag.ECHONL = false;
    try std.posix.tcsetattr(stdin, .FLUSH, hidden);
    defer std.posix.tcsetattr(stdin, .NOW, saved_terminal) catch {};

    std.debug.print("{s}: ", .{prompt});
    defer std.debug.print("\n", .{});
    return readPasswordLine(buffer);
}

fn passwordInput(ctx: *cli.BaseCommand.ParseContext, provided: ?[]const u8, buffer: *PasswordInput, prompt: []const u8) ![]const u8 {
    if (provided) |password| {
        if (ctx.hasOption("password-stdin")) {
            std.debug.print("Error: supply a password argument or --password-stdin\n", .{});
            return error.ConflictingPasswordSources;
        }
        return password;
    }
    return promptPassword(buffer, prompt) catch |err| {
        switch (err) {
            error.EmptyPassword => std.debug.print("Error: standard input did not contain a password\n", .{}),
            error.PasswordTooLong => std.debug.print("Error: password exceeds {d} bytes\n", .{max_input_password_bytes}),
            else => {},
        }
        return err;
    };
}

fn addPasswordStdinOption(cmd: *cli.BaseCommand) !void {
    _ = try cmd.addOption(cli.Option.init("password-stdin", "password-stdin", "Read one password line from standard input", .bool));
}

fn withDb(comptime action: fn (*cli.BaseCommand.ParseContext, *database.Database, *auth.AuthBackend) anyerror!void) cli.BaseCommand.CommandAction {
    return struct {
        fn wrapper(ctx: *cli.BaseCommand.ParseContext) anyerror!void {
            const allocator = ctx.allocator;
            const db_path = env.get("SMTP_DB_PATH") orelse "./smtp.db";
            var db = try database.Database.init(allocator, db_path);
            defer db.deinit();
            var auth_backend = auth.AuthBackend.init(allocator, &db);
            defer auth_backend.deinit();
            try action(ctx, &db, &auth_backend);
        }
    }.wrapper;
}

fn createAction(ctx: *cli.BaseCommand.ParseContext, _: *database.Database, auth_backend: *auth.AuthBackend) !void {
    const username = ctx.getArgument(0) orelse {
        std.debug.print("Error: username is required\nUsage: mail user:local create <username> [<password> [<email>]] [--password <pw> | --password-stdin] [--email <email>]\n", .{});
        return error.MissingArgument;
    };

    var input: PasswordInput = undefined;
    defer std.crypto.secureZero(u8, &input);
    const password = try passwordInput(ctx, ctx.getOption("password") orelse ctx.getArgument(1), &input, "New password");

    const email = ctx.getOption("email") orelse ctx.getArgument(2);
    const derived = if (email == null and std.mem.indexOfScalar(u8, username, '@') == null)
        try std.fmt.allocPrint(ctx.allocator, "{s}@{s}", .{ username, env.get("DOMAIN") orelse "localhost" })
    else
        null;
    defer if (derived) |address| ctx.allocator.free(address);
    try user_cli.createUser(auth_backend, username, password, email orelse derived orelse username);
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
        std.debug.print("Error: username is required\nUsage: mail user:local verify <username> [<password> | --password-stdin]\n", .{});
        return error.MissingArgument;
    };
    var input: PasswordInput = undefined;
    defer std.crypto.secureZero(u8, &input);
    const password = try passwordInput(ctx, ctx.getArgument(1), &input, "Password");
    try user_cli.verifyUser(auth_backend, username, password);
}

/// Whether `change-password` may replace a password that is already set.
///
/// Only when the caller says so with `--force`. Application deploys used to
/// call this on every run with whatever `MAIL_PASSWORD_<LOCALPART>` their own
/// environment held, and an app that had copied another project's mail config
/// replaced real people's passwords on a shared box: their mail clients were
/// locked out until the old hashes were restored from a backup. Those deploy
/// tools are pinned in apps that are not upgraded together, so the refusal has
/// to live here, where every version of them ends up. An operator resetting a
/// password means it and passes `--force`; a tool that manages a service
/// account's credential on purpose does the same.
pub fn replacePassword(auth_backend: *auth.AuthBackend, username: []const u8, password: []const u8, force: bool) !void {
    if (!force) {
        std.debug.print(
            "Error: refusing to replace the password of '{s}' without --force.\n" ++
                "A mailbox's password belongs to the person who uses it; a deploy that\n" ++
                "replaces it locks their mail clients out. Pass --force to reset it on purpose.\n",
            .{username},
        );
        return error.PasswordReplaceRefused;
    }
    try user_cli.changePassword(auth_backend, username, password);
}

pub const change_password_usage = "Usage: mail user:local change-password <username> [<password> | --password-stdin] --force\n";

fn changePasswordAction(ctx: *cli.BaseCommand.ParseContext, db: *database.Database, auth_backend: *auth.AuthBackend) !void {
    const username = ctx.getArgument(0) orelse {
        std.debug.print("Error: username is required\n{s}", .{change_password_usage});
        return error.MissingArgument;
    };

    const force = ctx.hasOption("force");
    // Refused before the password is read, so nothing is consumed from stdin
    // and the answer is the same whichever way the password was passed.
    if (!force) return replacePassword(auth_backend, username, "", false);

    var input: PasswordInput = undefined;
    defer std.crypto.secureZero(u8, &input);
    const password = try passwordInput(ctx, ctx.getArgument(1), &input, "New password");

    var user = db.getUserByUsername(username) catch |err| {
        if (err == database.DatabaseError.NotFound) std.debug.print("Error: user '{s}' not found\n", .{username});
        return err;
    };
    defer user.deinit(ctx.allocator);
    try replacePassword(auth_backend, username, password, force);
}

fn recoveryAction(ctx: *cli.BaseCommand.ParseContext, db: *database.Database, _: *auth.AuthBackend) !void {
    const usage = "Usage: mail user:local recovery <username> [<address>] [--policy initial|managed] [--clear]\n";
    const username = ctx.getArgument(0) orelse {
        std.debug.print("Error: username is required\n{s}", .{usage});
        return error.MissingArgument;
    };
    const address = ctx.getArgument(1);
    if (ctx.hasOption("clear")) {
        if (address != null) {
            std.debug.print("Error: give an address or --clear, not both\n{s}", .{usage});
            return error.InvalidArgument;
        }
        return user_cli.recoveryCommand(db, ctx.allocator, username, .clear);
    }
    const wanted = address orelse return user_cli.recoveryCommand(db, ctx.allocator, username, .show);
    const policy_name = ctx.getOption("policy") orelse "managed";
    const policy = recovery.Policy.parse(policy_name) orelse {
        std.debug.print("Error: --policy must be 'initial' or 'managed'\n{s}", .{usage});
        return error.InvalidArgument;
    };
    return user_cli.recoveryCommand(db, ctx.allocator, username, .{ .apply = .{ .address = wanted, .policy = policy } });
}

pub fn setup(allocator: std.mem.Allocator) !*cli.BaseCommand {
    const cmd = try cli.BaseCommand.init(allocator, "user:local", "Local user management (direct DB access)");

    // create
    const create_cmd = try cli.BaseCommand.init(allocator, "create", "Create a new user locally");
    _ = try create_cmd.addArgument(cli.Argument.init("username", "Username", .string));
    _ = try create_cmd.addArgument(cli.Argument.init("password_pos", "Password (omit to read standard input)", .string).withRequired(false));
    _ = try create_cmd.addArgument(cli.Argument.init("email_pos", "Email address (positional)", .string).withRequired(false));
    _ = try create_cmd.addOption(
        cli.Option.init("password", "password", "Password for the new user", .string)
            .withShort('p'),
    );
    _ = try create_cmd.addOption(
        cli.Option.init("email", "email", "Email address (defaults to the username or username@DOMAIN)", .string)
            .withShort('e'),
    );
    try addPasswordStdinOption(create_cmd);
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
    _ = try verify_cmd.addArgument(cli.Argument.init("password", "Password (omit to read standard input)", .string).withRequired(false));
    try addPasswordStdinOption(verify_cmd);
    _ = verify_cmd.setAction(withDb(verifyAction));
    _ = try cmd.addCommand(verify_cmd);

    // change-password
    const change_pw_cmd = try cli.BaseCommand.init(allocator, "change-password", "Change user password");
    _ = try change_pw_cmd.addArgument(cli.Argument.init("username", "Username", .string));
    _ = try change_pw_cmd.addArgument(cli.Argument.init("password", "New password (omit to read standard input)", .string).withRequired(false));
    try addPasswordStdinOption(change_pw_cmd);
    _ = try change_pw_cmd.addOption(
        cli.Option.init("force", "force", "Replace the existing password (required: without it the command refuses)", .bool),
    );
    _ = change_pw_cmd.setAction(withDb(changePasswordAction));
    _ = try cmd.addCommand(change_pw_cmd);

    // recovery
    const recovery_cmd = try cli.BaseCommand.init(allocator, "recovery", "Show, set or clear a mailbox's password recovery address");
    _ = try recovery_cmd.addArgument(cli.Argument.init("username", "Mailbox (full address)", .string));
    _ = try recovery_cmd.addArgument(cli.Argument.init("address", "Recovery address to set (omit to show the current one)", .string).withRequired(false));
    _ = try recovery_cmd.addOption(
        cli.Option.init("policy", "policy", "managed (default): always set it; initial: keep an address the mailbox owner set in webmail", .string),
    );
    _ = try recovery_cmd.addOption(
        cli.Option.init("clear", "clear", "Remove the recovery address", .bool),
    );
    _ = recovery_cmd.setAction(withDb(recoveryAction));
    _ = try cmd.addCommand(recovery_cmd);

    return cmd;
}
