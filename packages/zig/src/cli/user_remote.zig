const std = @import("std");
const cli = @import("zig-cli");
const io_compat = @import("../core/io_compat.zig");

const password_input = @import("password_input.zig");

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
    var cmd_parts: std.ArrayList(u8) = .empty;
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

const CredentialAction = enum { create, verify, rotate };

fn credentialTarget(ctx: *cli.BaseCommand.ParseContext) ![]const u8 {
    const host = ctx.getOption("ssh-target");
    const instance = ctx.getOption("instance-id");
    if (host != null and instance != null) {
        std.debug.print("Error: specify one of --ssh-target or --instance-id\n", .{});
        return error.ConflictingTargets;
    }
    const configured = if (std.c.getenv("MAIL_INSTANCE_ID")) |value| std.mem.sliceTo(value, 0) else "";
    const target = host orelse instance orelse configured;
    if (target.len == 0) {
        std.debug.print("Error: specify --ssh-target, --instance-id, or MAIL_INSTANCE_ID for credential operations\n", .{});
        return error.MissingSshTarget;
    }
    if (target[0] == '-') return error.InvalidSshTarget;
    for (target) |c| {
        if (!std.ascii.isAlphanumeric(c) and std.mem.indexOfScalar(u8, "._-@:+[]", c) == null)
            return error.InvalidSshTarget;
    }
    return target;
}

/// ssh passes the remote command to a shell. Quote each public operand,
/// including apostrophes in mailbox names and paths.
fn appendShellArg(a: std.mem.Allocator, command: *std.ArrayList(u8), value: []const u8) !void {
    try command.appendSlice(a, " '");
    for (value) |byte| {
        if (byte == 39) try command.appendSlice(a, "'\\''") else try command.append(a, byte);
    }
    try command.append(a, 39);
}

fn sendCredential(io: std.Io, stdin: std.Io.File, password: []const u8) !void {
    const ignore = std.posix.Sigaction{ .handler = .{ .handler = std.posix.SIG.IGN }, .mask = std.posix.sigemptyset(), .flags = 0 };
    var previous: std.posix.Sigaction = undefined;
    std.posix.sigaction(.PIPE, &ignore, &previous);
    defer std.posix.sigaction(.PIPE, &previous, null);
    try stdin.writeStreamingAll(io, password);
    // The receiver removes this CR. Any CR already in the password survives.
    try stdin.writeStreamingAll(io, "\r\n");
}

fn credentialAction(comptime operation: CredentialAction) cli.BaseCommand.CommandAction {
    return struct {
        fn run(ctx: *cli.BaseCommand.ParseContext) !void {
            const a = ctx.allocator;
            const target = try credentialTarget(ctx);
            const account = ctx.getArgument(0) orelse return error.MissingArgument;
            const username = if (operation == .create)
                account[0 .. std.mem.indexOfScalar(u8, account, '@') orelse account.len]
            else
                account;
            if (username.len == 0 or username[0] == '-') return error.InvalidUsername;
            const dir = ctx.getOption("remote-dir") orelse "/opt/mail";
            if (!std.fs.path.isAbsolute(dir)) return error.InvalidRemoteDirectory;

            var command: std.ArrayList(u8) = .empty;
            defer command.deinit(a);
            try command.appendSlice(a, "cd");
            try appendShellArg(a, &command, dir);
            try command.appendSlice(a, " || exit 1; " ++
                "if [ -f ./mail-server ] && [ -x ./mail-server ]; then binary=./mail-server; " ++
                "else binary=./mail; fi; exec");
            if (ctx.getOption("run-as")) |remote_user| {
                if (remote_user.len == 0 or remote_user[0] == '-') return error.InvalidRemoteUser;
                try command.appendSlice(a, " sudo -n -u");
                try appendShellArg(a, &command, remote_user);
                try command.appendSlice(a, " --");
            }
            try command.appendSlice(a, " \"$binary\" user:local ");
            try command.appendSlice(a, switch (operation) {
                .create => "create",
                .verify => "verify",
                .rotate => "change-password",
            });
            try appendShellArg(a, &command, username);
            try command.appendSlice(a, " --remote-stdin");
            switch (operation) {
                .create => {
                    try command.appendSlice(a, " --email");
                    try appendShellArg(a, &command, account);
                },
                .verify => {},
                // This action is an explicit operator reset, as in the SSM CLI.
                .rotate => try command.appendSlice(a, " --force"),
            }

            var argv: std.ArrayList([]const u8) = .empty;
            defer argv.deinit(a);
            try argv.appendSlice(a, &.{ "ssh", "-T", "-S", "none", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", "-o", "StdinNull=no" });
            if (ctx.getOption("ssh-config")) |path| try argv.appendSlice(a, &.{ "-F", path });
            try argv.appendSlice(a, &.{ "--", target, command.items });

            const prompt = try std.fmt.allocPrint(a, "{s} for {s} on {s}", .{ if (operation == .verify) "Password" else "New password", account, target });
            defer a.free(prompt);
            var input: password_input.Buffer = undefined;
            defer std.crypto.secureZero(u8, &input);
            const supplied = if (operation == .create) ctx.getOption("password") else ctx.getArgument(1);
            const password = try password_input.read(ctx, supplied, &input, prompt);
            try password_input.validateForwarded(password);

            const io = io_compat.getIo();
            var child = try std.process.spawn(io, .{ .argv = argv.items, .stdin = .pipe });
            defer child.kill(io);
            const stdin = child.stdin.?;
            const sent = sendCredential(io, stdin, password);
            stdin.close(io);
            child.stdin = null;
            std.crypto.secureZero(u8, &input);
            const term = try child.wait(io);
            switch (term) {
                .exited => |code| {
                    if (code == 0) return sent;
                    if (code != 255) return error.RemoteCredentialCommandFailed;
                },
                else => {},
            }
            std.debug.print("SSH connection to {s} failed. Check the remote outcome before retrying.\n", .{target});
            return error.SshCredentialConnectionFailed;
        }
    }.run;
}

fn addCredentialOptions(cmd: *cli.BaseCommand) !void {
    _ = try cmd.addOption(cli.Option.init("ssh-target", "ssh-target", "OpenSSH host or user@host", .string));
    _ = try cmd.addOption(cli.Option.init("instance-id", "instance-id", "EC2 instance ID configured in OpenSSH", .string));
    _ = try cmd.addOption(cli.Option.init("ssh-config", "ssh-config", "Path to an alternate OpenSSH config", .string));
    _ = try cmd.addOption(cli.Option.init("remote-dir", "remote-dir", "Absolute Mail directory on the host (default: /opt/mail)", .string));
    _ = try cmd.addOption(cli.Option.init("run-as", "run-as", "Remote operating-system account to select with noninteractive sudo", .string));
    _ = try cmd.addOption(cli.Option.init("env", "env", "Legacy environment label", .string));
    try password_input.addOption(cmd);
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
    const user_cmd = try cli.BaseCommand.init(allocator, "user", "Remote user management via SSH and SSM");

    // user create
    const create_cmd = try cli.BaseCommand.init(allocator, "create", "Create a new mail user");
    _ = try create_cmd.addArgument(cli.Argument.init("email", "Email address for the new user", .string));
    _ = try create_cmd.addOption(
        cli.Option.init("password", "password", "Legacy password argument (omit to read standard input)", .string)
            .withShort('p'),
    );
    try addCredentialOptions(create_cmd);
    _ = create_cmd.setAction(credentialAction(.create));
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
    _ = try verify_cmd.addArgument(cli.Argument.init("password", "Password to verify (omit to read standard input)", .string).withRequired(false));
    try addCredentialOptions(verify_cmd);
    _ = verify_cmd.setAction(credentialAction(.verify));
    _ = try user_cmd.addCommand(verify_cmd);

    // user change-password
    const change_pw_cmd = try cli.BaseCommand.init(allocator, "change-password", "Change user password");
    _ = try change_pw_cmd.addArgument(cli.Argument.init("username", "Username", .string));
    _ = try change_pw_cmd.addArgument(cli.Argument.init("password", "New password (omit to read standard input)", .string).withRequired(false));
    try addCredentialOptions(change_pw_cmd);
    _ = change_pw_cmd.setAction(credentialAction(.rotate));
    _ = try user_cmd.addCommand(change_pw_cmd);

    return user_cmd;
}
