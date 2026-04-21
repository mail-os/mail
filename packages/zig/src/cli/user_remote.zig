const std = @import("std");
const cli = @import("zig-cli");
const io_compat = @import("../core/io_compat.zig");

const USER_CLI_PATH = "/opt/mail/mail";

// ============================================================================
// Helpers
// ============================================================================

const ExecResult = struct {
    stdout: []u8,
    stderr: []u8,
    success: bool,
};

fn execCommand(allocator: std.mem.Allocator, argv: []const []const u8) !ExecResult {
    const result = try std.process.run(allocator, io_compat.getIo(), .{
        .argv = argv,
    });
    const success = switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
    return .{ .stdout = result.stdout, .stderr = result.stderr, .success = success };
}

fn getInstanceId(ctx: *cli.BaseCommand.ParseContext, allocator: std.mem.Allocator) ![]const u8 {
    if (ctx.getOption("instance-id")) |id| {
        return id;
    }

    const env_val = std.c.getenv("MAIL_INSTANCE_ID");
    if (env_val) |ptr| {
        const id = std.mem.sliceTo(ptr, 0);
        if (id.len > 0) return id;
    }

    const detect_argv = &[_][]const u8{
        "aws",                         "ec2",
        "describe-instances",          "--filters",
        "Name=tag:Name,Values=*mail*", "Name=instance-state-name,Values=running",
        "--query",                     "Reservations[0].Instances[0].InstanceId",
        "--output",                    "text",
    };

    const result = execCommand(allocator, detect_argv) catch {
        std.debug.print("Failed to auto-detect instance ID. Provide --instance-id or set MAIL_INSTANCE_ID.\n", .{});
        return error.MissingInstanceId;
    };
    defer allocator.free(result.stderr);

    if (!result.success or result.stdout.len == 0 or std.mem.startsWith(u8, result.stdout, "None")) {
        allocator.free(result.stdout);
        std.debug.print("Could not find a running mail server instance. Provide --instance-id or set MAIL_INSTANCE_ID.\n", .{});
        return error.MissingInstanceId;
    }

    const trimmed = std.mem.trim(u8, result.stdout, &std.ascii.whitespace);
    if (trimmed.len != result.stdout.len) {
        const duped = try allocator.dupe(u8, trimmed);
        allocator.free(result.stdout);
        return duped;
    }

    return result.stdout;
}

fn runRemoteCommand(allocator: std.mem.Allocator, instance_id: []const u8, remote_cmd: []const u8) !ExecResult {
    const send_argv = &[_][]const u8{
        "aws",                "ssm",
        "send-command",       "--instance-ids",
        instance_id,          "--document-name",
        "AWS-RunShellScript", "--parameters",
        remote_cmd,           "--query",
        "Command.CommandId",  "--output",
        "text",
    };

    const send_result = try execCommand(allocator, send_argv);
    defer allocator.free(send_result.stderr);

    if (!send_result.success) {
        std.debug.print("Failed to send SSM command: {s}\n", .{send_result.stderr});
        allocator.free(send_result.stdout);
        return error.SsmCommandFailed;
    }

    const command_id = std.mem.trim(u8, send_result.stdout, &std.ascii.whitespace);
    defer allocator.free(send_result.stdout);

    var attempt: u32 = 0;
    while (attempt < 30) : (attempt += 1) {
        const ts = std.c.timespec{ .sec = 1, .nsec = 0 };
        _ = std.c.nanosleep(&ts, null);

        const get_argv = &[_][]const u8{
            "aws",                    "ssm",
            "get-command-invocation", "--command-id",
            command_id,               "--instance-id",
            instance_id,              "--output",
            "json",
        };

        const get_result = try execCommand(allocator, get_argv);

        if (!get_result.success) {
            allocator.free(get_result.stdout);
            allocator.free(get_result.stderr);
            continue;
        }
        allocator.free(get_result.stderr);

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, get_result.stdout, .{}) catch {
            allocator.free(get_result.stdout);
            continue;
        };
        defer parsed.deinit();
        allocator.free(get_result.stdout);

        const root = parsed.value.object;
        const status = root.get("StatusDetails") orelse continue;
        const status_str = status.string;

        if (std.mem.eql(u8, status_str, "Success") or std.mem.eql(u8, status_str, "Failed")) {
            const stdout_content = if (root.get("StandardOutputContent")) |v| v.string else "";
            const stderr_content = if (root.get("StandardErrorContent")) |v| v.string else "";

            return .{
                .stdout = try allocator.dupe(u8, stdout_content),
                .stderr = try allocator.dupe(u8, stderr_content),
                .success = std.mem.eql(u8, status_str, "Success"),
            };
        }
    }

    std.debug.print("Timed out waiting for remote command to complete.\n", .{});
    return error.CommandTimeout;
}

fn buildRemoteParams(allocator: std.mem.Allocator, args: []const []const u8) ![]const u8 {
    var cmd_parts = std.ArrayList(u8){};
    defer cmd_parts.deinit(allocator);

    try cmd_parts.appendSlice(allocator, "commands=[\"");
    try cmd_parts.appendSlice(allocator, USER_CLI_PATH);
    for (args) |arg| {
        try cmd_parts.append(allocator, ' ');
        try cmd_parts.appendSlice(allocator, arg);
    }
    try cmd_parts.appendSlice(allocator, "\"]");

    return try allocator.dupe(u8, cmd_parts.items);
}

fn generatePassword(allocator: std.mem.Allocator) ![]const u8 {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%&*";
    var password: [24]u8 = undefined;
    io_compat.getIo().random(&password);
    for (&password) |*byte| {
        byte.* = charset[byte.* % charset.len];
    }
    return try allocator.dupe(u8, &password);
}

fn writeStdout(msg: []const u8) void {
    var buf: [4096]u8 = undefined;
    var file_writer = std.Io.File.stdout().writerStreaming(std.Options.debug_io, &buf);
    const w = &file_writer.interface;
    w.writeAll(msg) catch {};
    w.flush() catch {};
}

fn printStdout(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    var file_writer = std.Io.File.stdout().writerStreaming(std.Options.debug_io, &buf);
    const w = &file_writer.interface;
    w.print(fmt, args) catch {};
    w.flush() catch {};
}

// ============================================================================
// Command Actions
// ============================================================================

fn createAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const allocator = ctx.allocator;
    const email = ctx.getArgument(0) orelse {
        std.debug.print("Error: email address is required\nUsage: mail user create <email> [--password <pw>]\n", .{});
        return;
    };

    const instance_id = try getInstanceId(ctx, allocator);
    const password = ctx.getOption("password") orelse try generatePassword(allocator);

    const username = if (std.mem.indexOf(u8, email, "@")) |at_pos|
        email[0..at_pos]
    else
        email;

    const remote_params = try buildRemoteParams(allocator, &.{ "user:local", "create", username, password, email });
    defer allocator.free(remote_params);

    printStdout("Creating user {s}...\n", .{email});
    const result = try runRemoteCommand(allocator, instance_id, remote_params);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.success) {
        printStdout("User created successfully!\n", .{});
        printStdout("  Email:    {s}\n", .{email});
        printStdout("  Username: {s}\n", .{username});
        printStdout("  Password: {s}\n", .{password});
    } else {
        std.debug.print("Failed to create user:\n", .{});
        if (result.stderr.len > 0) std.debug.print("{s}", .{result.stderr});
        if (result.stdout.len > 0) writeStdout(result.stdout);
    }
}

fn deleteAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const allocator = ctx.allocator;
    const username = ctx.getArgument(0) orelse {
        std.debug.print("Error: username is required\nUsage: mail user delete <username>\n", .{});
        return;
    };

    const instance_id = try getInstanceId(ctx, allocator);
    const remote_params = try buildRemoteParams(allocator, &.{ "user:local", "delete", username });
    defer allocator.free(remote_params);

    printStdout("Deleting user {s}...\n", .{username});
    const result = try runRemoteCommand(allocator, instance_id, remote_params);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.success) {
        printStdout("User '{s}' deleted successfully.\n", .{username});
    } else {
        std.debug.print("Failed to delete user:\n", .{});
        if (result.stderr.len > 0) std.debug.print("{s}", .{result.stderr});
        if (result.stdout.len > 0) writeStdout(result.stdout);
    }
}

fn disableAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const allocator = ctx.allocator;
    const username = ctx.getArgument(0) orelse {
        std.debug.print("Error: username is required\nUsage: mail user disable <username>\n", .{});
        return;
    };

    const instance_id = try getInstanceId(ctx, allocator);
    const remote_params = try buildRemoteParams(allocator, &.{ "user:local", "disable", username });
    defer allocator.free(remote_params);

    printStdout("Disabling user {s}...\n", .{username});
    const result = try runRemoteCommand(allocator, instance_id, remote_params);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.success) {
        printStdout("User '{s}' disabled successfully.\n", .{username});
    } else {
        std.debug.print("Failed to disable user:\n", .{});
        if (result.stderr.len > 0) std.debug.print("{s}", .{result.stderr});
        if (result.stdout.len > 0) writeStdout(result.stdout);
    }
}

fn enableAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const allocator = ctx.allocator;
    const username = ctx.getArgument(0) orelse {
        std.debug.print("Error: username is required\nUsage: mail user enable <username>\n", .{});
        return;
    };

    const instance_id = try getInstanceId(ctx, allocator);
    const remote_params = try buildRemoteParams(allocator, &.{ "user:local", "enable", username });
    defer allocator.free(remote_params);

    printStdout("Enabling user {s}...\n", .{username});
    const result = try runRemoteCommand(allocator, instance_id, remote_params);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.success) {
        printStdout("User '{s}' enabled successfully.\n", .{username});
    } else {
        std.debug.print("Failed to enable user:\n", .{});
        if (result.stderr.len > 0) std.debug.print("{s}", .{result.stderr});
        if (result.stdout.len > 0) writeStdout(result.stdout);
    }
}

fn infoAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const allocator = ctx.allocator;
    const username = ctx.getArgument(0) orelse {
        std.debug.print("Error: username is required\nUsage: mail user info <username>\n", .{});
        return;
    };

    const instance_id = try getInstanceId(ctx, allocator);
    const remote_params = try buildRemoteParams(allocator, &.{ "user:local", "info", username });
    defer allocator.free(remote_params);

    const result = try runRemoteCommand(allocator, instance_id, remote_params);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.success) {
        if (result.stdout.len > 0) writeStdout(result.stdout);
    } else {
        std.debug.print("Failed to get user info:\n", .{});
        if (result.stderr.len > 0) std.debug.print("{s}", .{result.stderr});
        if (result.stdout.len > 0) writeStdout(result.stdout);
    }
}

fn verifyAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const allocator = ctx.allocator;
    const username = ctx.getArgument(0) orelse {
        std.debug.print("Error: username is required\nUsage: mail user verify <username> <password>\n", .{});
        return;
    };
    const password = ctx.getArgument(1) orelse {
        std.debug.print("Error: password is required\nUsage: mail user verify <username> <password>\n", .{});
        return;
    };

    const instance_id = try getInstanceId(ctx, allocator);
    const remote_params = try buildRemoteParams(allocator, &.{ "user:local", "verify", username, password });
    defer allocator.free(remote_params);

    const result = try runRemoteCommand(allocator, instance_id, remote_params);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.success) {
        if (result.stdout.len > 0) writeStdout(result.stdout);
    } else {
        std.debug.print("Credential verification failed.\n", .{});
        if (result.stderr.len > 0) std.debug.print("{s}", .{result.stderr});
    }
}

fn changePasswordAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const allocator = ctx.allocator;
    const username = ctx.getArgument(0) orelse {
        std.debug.print("Error: username is required\nUsage: mail user change-password <username> <password>\n", .{});
        return;
    };
    const password = ctx.getArgument(1) orelse {
        std.debug.print("Error: password is required\nUsage: mail user change-password <username> <password>\n", .{});
        return;
    };

    const instance_id = try getInstanceId(ctx, allocator);
    const remote_params = try buildRemoteParams(allocator, &.{ "user:local", "change-password", username, password });
    defer allocator.free(remote_params);

    printStdout("Changing password for {s}...\n", .{username});
    const result = try runRemoteCommand(allocator, instance_id, remote_params);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.success) {
        printStdout("Password changed successfully for user '{s}'.\n", .{username});
    } else {
        std.debug.print("Failed to change password:\n", .{});
        if (result.stderr.len > 0) std.debug.print("{s}", .{result.stderr});
        if (result.stdout.len > 0) writeStdout(result.stdout);
    }
}

// ============================================================================
// Command Setup
// ============================================================================

fn addCommonOptions(cmd: *cli.BaseCommand) !void {
    _ = try cmd.addOption(
        cli.Option.init("instance-id", "instance-id", "EC2 instance ID (overrides auto-detection)", .string),
    );
    _ = try cmd.addOption(
        cli.Option.init("env", "env", "Target environment (default: production)", .string)
            .withDefault("production"),
    );
}

pub fn setup(allocator: std.mem.Allocator) !*cli.BaseCommand {
    const user_cmd = try cli.BaseCommand.init(allocator, "user", "Remote user management commands (via SSM)");

    // user create
    const create_cmd = try cli.BaseCommand.init(allocator, "create", "Create a new mail user");
    _ = try create_cmd.addArgument(cli.Argument.init("email", "Email address for the new user", .string));
    _ = try create_cmd.addOption(
        cli.Option.init("password", "password", "Password (auto-generated if not provided)", .string)
            .withShort('p'),
    );
    try addCommonOptions(create_cmd);
    _ = create_cmd.setAction(createAction);
    _ = try user_cmd.addCommand(create_cmd);

    // user delete
    const delete_cmd = try cli.BaseCommand.init(allocator, "delete", "Delete a mail user");
    _ = try delete_cmd.addArgument(cli.Argument.init("username", "Username to delete", .string));
    try addCommonOptions(delete_cmd);
    _ = delete_cmd.setAction(deleteAction);
    _ = try user_cmd.addCommand(delete_cmd);

    // user disable
    const disable_cmd = try cli.BaseCommand.init(allocator, "disable", "Disable a mail user account");
    _ = try disable_cmd.addArgument(cli.Argument.init("username", "Username to disable", .string));
    try addCommonOptions(disable_cmd);
    _ = disable_cmd.setAction(disableAction);
    _ = try user_cmd.addCommand(disable_cmd);

    // user enable
    const enable_cmd = try cli.BaseCommand.init(allocator, "enable", "Enable a mail user account");
    _ = try enable_cmd.addArgument(cli.Argument.init("username", "Username to enable", .string));
    try addCommonOptions(enable_cmd);
    _ = enable_cmd.setAction(enableAction);
    _ = try user_cmd.addCommand(enable_cmd);

    // user info
    const info_cmd = try cli.BaseCommand.init(allocator, "info", "Show user information");
    _ = try info_cmd.addArgument(cli.Argument.init("username", "Username to query", .string));
    try addCommonOptions(info_cmd);
    _ = info_cmd.setAction(infoAction);
    _ = try user_cmd.addCommand(info_cmd);

    // user verify
    const verify_cmd = try cli.BaseCommand.init(allocator, "verify", "Verify user credentials");
    _ = try verify_cmd.addArgument(cli.Argument.init("username", "Username to verify", .string));
    _ = try verify_cmd.addArgument(cli.Argument.init("password", "Password to verify", .string));
    try addCommonOptions(verify_cmd);
    _ = verify_cmd.setAction(verifyAction);
    _ = try user_cmd.addCommand(verify_cmd);

    // user change-password
    const change_pw_cmd = try cli.BaseCommand.init(allocator, "change-password", "Change user password");
    _ = try change_pw_cmd.addArgument(cli.Argument.init("username", "Username", .string));
    _ = try change_pw_cmd.addArgument(cli.Argument.init("password", "New password", .string));
    try addCommonOptions(change_pw_cmd);
    _ = change_pw_cmd.setAction(changePasswordAction);
    _ = try user_cmd.addCommand(change_pw_cmd);

    return user_cmd;
}
