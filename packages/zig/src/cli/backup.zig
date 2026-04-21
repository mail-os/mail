const std = @import("std");
const cli = @import("zig-cli");
const io_compat = @import("../core/io_compat.zig");

const MAIL_CLI_PATH = "/opt/mail/packages/zig/zig-out/bin/mail";

// Default paths on the server
const DATA_DIR = "/var/lib/mail";
const MAIL_DIR = "/var/spool/mail";
const CONFIG_DIR = "/etc/mail";

// ============================================================================
// Helpers (shared with user_remote.zig pattern)
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

fn runRemoteCommandWithTimeout(allocator: std.mem.Allocator, instance_id: []const u8, remote_cmd: []const u8, max_attempts: u32) !ExecResult {
    const send_argv = &[_][]const u8{
        "aws",                "ssm",
        "send-command",       "--instance-ids",
        instance_id,          "--document-name",
        "AWS-RunShellScript", "--parameters",
        remote_cmd,           "--timeout-seconds",
        "600",                "--query",
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
    while (attempt < max_attempts) : (attempt += 1) {
        const ts = std.c.timespec{ .sec = 2, .nsec = 0 };
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

        if (attempt % 15 == 14) {
            printStdout("  Still waiting... ({d}s elapsed)\n", .{(attempt + 1) * 2});
        }
    }

    std.debug.print("Timed out waiting for remote command to complete.\n", .{});
    return error.CommandTimeout;
}

fn writeStdout(msg: []const u8) void {
    var buf: [8192]u8 = undefined;
    var file_writer = std.Io.File.stdout().writerStreaming(std.Options.debug_io, &buf);
    const w = &file_writer.interface;
    w.writeAll(msg) catch {};
    w.flush() catch {};
}

fn printStdout(comptime fmt: []const u8, args: anytype) void {
    var buf: [8192]u8 = undefined;
    var file_writer = std.Io.File.stdout().writerStreaming(std.Options.debug_io, &buf);
    const w = &file_writer.interface;
    w.print(fmt, args) catch {};
    w.flush() catch {};
}

fn getBucketName(allocator: std.mem.Allocator, env: []const u8) ![]const u8 {
    // Get the S3 bucket from CloudFormation stack outputs
    const stack_name = try std.fmt.allocPrint(allocator, "mail-server-{s}", .{env});
    defer allocator.free(stack_name);

    const argv = &[_][]const u8{
        "aws",                                                     "cloudformation",
        "describe-stacks",                                         "--stack-name",
        stack_name,                                                "--query",
        "Stacks[0].Outputs[?OutputKey=='BucketName'].OutputValue", "--output",
        "text",
    };

    const result = execCommand(allocator, argv) catch {
        // Fallback: try to find the bucket by prefix
        return try findBucketByPrefix(allocator, env);
    };
    defer allocator.free(result.stderr);

    if (result.success and result.stdout.len > 0 and !std.mem.startsWith(u8, result.stdout, "None")) {
        const trimmed = std.mem.trim(u8, result.stdout, &std.ascii.whitespace);
        if (trimmed.len != result.stdout.len) {
            const duped = try allocator.dupe(u8, trimmed);
            allocator.free(result.stdout);
            return duped;
        }
        return result.stdout;
    }
    allocator.free(result.stdout);

    return try findBucketByPrefix(allocator, env);
}

fn findBucketByPrefix(allocator: std.mem.Allocator, env: []const u8) ![]const u8 {
    const prefix = try std.fmt.allocPrint(allocator, "mail-server-emails-{s}", .{env});
    defer allocator.free(prefix);

    const argv = &[_][]const u8{
        "aws",     "s3api",                                                                                       "list-buckets",
        "--query", try std.fmt.allocPrint(allocator, "Buckets[?starts_with(Name, '{s}')].Name | [0]", .{prefix}), "--output",
        "text",
    };

    const result = execCommand(allocator, argv) catch {
        std.debug.print("Failed to find S3 bucket. Ensure AWS credentials are configured.\n", .{});
        return error.SsmCommandFailed;
    };
    defer allocator.free(result.stderr);

    if (result.success and result.stdout.len > 0 and !std.mem.startsWith(u8, result.stdout, "None")) {
        const trimmed = std.mem.trim(u8, result.stdout, &std.ascii.whitespace);
        if (trimmed.len != result.stdout.len) {
            const duped = try allocator.dupe(u8, trimmed);
            allocator.free(result.stdout);
            return duped;
        }
        return result.stdout;
    }
    allocator.free(result.stdout);

    std.debug.print("Could not find S3 bucket for backups. Create one or specify via --bucket.\n", .{});
    return error.SsmCommandFailed;
}

// ============================================================================
// Command Actions
// ============================================================================

fn createAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const allocator = ctx.allocator;
    const env = ctx.getOption("env") orelse "production";
    const instance_id = try getInstanceId(ctx, allocator);

    // Determine bucket
    const bucket = if (ctx.getOption("bucket")) |b| b else try getBucketName(allocator, env);

    printStdout("Creating backup on instance {s}...\n", .{instance_id});
    printStdout("  Backup bucket: {s}\n", .{bucket});

    // Build the backup shell script to run remotely
    const backup_script = try std.fmt.allocPrint(allocator,
        \\commands=["set -e; TIMESTAMP=$(date +%Y%m%d-%H%M%S); BACKUP_DIR=/tmp/mail-backup-$TIMESTAMP; mkdir -p $BACKUP_DIR; echo 'Stopping mail service...'; systemctl stop mail 2>/dev/null || true; sleep 2; echo 'Backing up database...'; cp -a {0s}/mail.db $BACKUP_DIR/ 2>/dev/null || cp -a {0s}/smtp.db $BACKUP_DIR/ 2>/dev/null || echo 'No database found'; echo 'Backing up mailboxes...'; tar czf $BACKUP_DIR/mailboxes.tar.gz -C {1s} . 2>/dev/null || echo 'No mailboxes found'; echo 'Backing up config...'; tar czf $BACKUP_DIR/config.tar.gz -C {2s} . 2>/dev/null || echo 'No config found'; echo 'Creating backup archive...'; tar czf /tmp/mail-backup-$TIMESTAMP.tar.gz -C /tmp mail-backup-$TIMESTAMP; echo 'Uploading to S3...'; aws s3 cp /tmp/mail-backup-$TIMESTAMP.tar.gz s3://{3s}/backups/mail-backup-$TIMESTAMP.tar.gz; echo 'Restarting mail service...'; systemctl start mail 2>/dev/null || true; rm -rf $BACKUP_DIR /tmp/mail-backup-$TIMESTAMP.tar.gz; echo 'BACKUP_ID=mail-backup-'$TIMESTAMP; echo 'Backup complete!'"]
    , .{ DATA_DIR, MAIL_DIR, CONFIG_DIR, bucket });
    defer allocator.free(backup_script);

    const result = try runRemoteCommandWithTimeout(allocator, instance_id, backup_script, 150);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.success) {
        printStdout("\nBackup completed successfully!\n", .{});
        if (result.stdout.len > 0) writeStdout(result.stdout);
    } else {
        std.debug.print("Backup failed!\n", .{});
        if (result.stderr.len > 0) std.debug.print("{s}", .{result.stderr});
        if (result.stdout.len > 0) writeStdout(result.stdout);
    }
}

fn restoreAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const allocator = ctx.allocator;
    const backup_id = ctx.getArgument(0) orelse {
        std.debug.print("Error: backup-id is required\nUsage: mail backup restore <backup-id> [--instance-id <id>] [--env <env>]\n", .{});
        return;
    };
    const env = ctx.getOption("env") orelse "production";
    const instance_id = try getInstanceId(ctx, allocator);
    const bucket = if (ctx.getOption("bucket")) |b| b else try getBucketName(allocator, env);

    printStdout("Restoring backup {s} on instance {s}...\n", .{ backup_id, instance_id });
    printStdout("  Source bucket: {s}\n", .{bucket});

    const restore_script = try std.fmt.allocPrint(allocator,
        \\commands=["set -e; BACKUP_ID={0s}; echo 'Downloading backup from S3...'; aws s3 cp s3://{1s}/backups/$BACKUP_ID.tar.gz /tmp/$BACKUP_ID.tar.gz; echo 'Stopping mail service...'; systemctl stop mail 2>/dev/null || true; sleep 2; echo 'Extracting backup...'; cd /tmp && tar xzf $BACKUP_ID.tar.gz; BACKUP_DIR=/tmp/$BACKUP_ID; echo 'Restoring database...'; if [ -f $BACKUP_DIR/mail.db ]; then cp -a $BACKUP_DIR/mail.db {2s}/mail.db; chown mail-server:mail-server {2s}/mail.db 2>/dev/null || true; echo 'Database restored (mail.db)'; elif [ -f $BACKUP_DIR/smtp.db ]; then cp -a $BACKUP_DIR/smtp.db {2s}/mail.db; chown mail-server:mail-server {2s}/mail.db 2>/dev/null || true; echo 'Database restored (smtp.db -> mail.db)'; else echo 'No database in backup'; fi; echo 'Restoring mailboxes...'; if [ -f $BACKUP_DIR/mailboxes.tar.gz ]; then tar xzf $BACKUP_DIR/mailboxes.tar.gz -C {3s}; chown -R mail-server:mail-server {3s} 2>/dev/null || true; echo 'Mailboxes restored'; else echo 'No mailboxes in backup'; fi; echo 'Restoring config...'; if [ -f $BACKUP_DIR/config.tar.gz ]; then tar xzf $BACKUP_DIR/config.tar.gz -C {4s}; chown -R mail-server:mail-server {4s} 2>/dev/null || true; echo 'Config restored'; else echo 'No config in backup'; fi; echo 'Starting mail service...'; systemctl start mail 2>/dev/null || true; sleep 3; systemctl is-active mail && echo 'Mail service is running' || echo 'WARNING: Mail service failed to start'; rm -rf /tmp/$BACKUP_ID /tmp/$BACKUP_ID.tar.gz; echo 'Restore complete!'"]
    , .{ backup_id, bucket, DATA_DIR, MAIL_DIR, CONFIG_DIR });
    defer allocator.free(restore_script);

    const result = try runRemoteCommandWithTimeout(allocator, instance_id, restore_script, 150);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.success) {
        printStdout("\nRestore completed successfully!\n", .{});
        if (result.stdout.len > 0) writeStdout(result.stdout);
    } else {
        std.debug.print("Restore failed!\n", .{});
        if (result.stderr.len > 0) std.debug.print("{s}", .{result.stderr});
        if (result.stdout.len > 0) writeStdout(result.stdout);
    }
}

fn listAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const allocator = ctx.allocator;
    const env = ctx.getOption("env") orelse "production";
    const bucket = if (ctx.getOption("bucket")) |b| b else try getBucketName(allocator, env);

    printStdout("Listing backups in s3://{s}/backups/...\n\n", .{bucket});

    const argv = &[_][]const u8{
        "aws",              "s3",
        "ls",               try std.fmt.allocPrint(allocator, "s3://{s}/backups/", .{bucket}),
        "--human-readable",
    };

    const result = try execCommand(allocator, argv);
    defer allocator.free(result.stderr);

    if (result.success) {
        if (result.stdout.len > 0) {
            writeStdout(result.stdout);
        } else {
            printStdout("No backups found.\n", .{});
        }
    } else {
        std.debug.print("Failed to list backups: {s}\n", .{result.stderr});
    }
    allocator.free(result.stdout);
}

fn statusAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const allocator = ctx.allocator;
    const instance_id = try getInstanceId(ctx, allocator);

    printStdout("Checking mail server status on {s}...\n\n", .{instance_id});

    const status_script =
        \\commands=["echo '=== Service Status ==='; systemctl is-active mail 2>/dev/null && echo 'Mail service: RUNNING' || echo 'Mail service: STOPPED'; echo ''; echo '=== Disk Usage ==='; df -h /var/lib/mail /var/spool/mail 2>/dev/null || df -h /; echo ''; echo '=== Database ==='; ls -lh /var/lib/mail/mail.db 2>/dev/null || echo 'No database found'; echo ''; echo '=== Mailbox Count ==='; find /var/spool/mail -type f 2>/dev/null | wc -l | xargs -I{} echo '{} messages'; echo ''; echo '=== Config ==='; ls -la /etc/mail/ 2>/dev/null || echo 'No config directory'; echo ''; echo '=== TLS Certificates ==='; ls -la /etc/mail/mail.crt /etc/mail/mail.key /etc/letsencrypt/live/*/fullchain.pem 2>/dev/null || echo 'No TLS certificates found'; echo ''; echo '=== Service Uptime ==='; systemctl show mail --property=ActiveEnterTimestamp 2>/dev/null || echo 'Unknown'"]
    ;

    const result = try runRemoteCommandWithTimeout(allocator, instance_id, status_script, 30);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.success) {
        if (result.stdout.len > 0) writeStdout(result.stdout);
    } else {
        std.debug.print("Failed to get status:\n", .{});
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
    _ = try cmd.addOption(
        cli.Option.init("bucket", "bucket", "S3 bucket for backups (auto-detected from stack)", .string),
    );
}

pub fn setup(allocator: std.mem.Allocator) !*cli.BaseCommand {
    const backup_cmd = try cli.BaseCommand.init(allocator, "backup", "Backup and restore mail server data");

    // backup create
    const create_cmd = try cli.BaseCommand.init(allocator, "create", "Create a backup of database, mailboxes, and config");
    try addCommonOptions(create_cmd);
    _ = create_cmd.setAction(createAction);
    _ = try backup_cmd.addCommand(create_cmd);

    // backup restore
    const restore_cmd = try cli.BaseCommand.init(allocator, "restore", "Restore from a backup");
    _ = try restore_cmd.addArgument(cli.Argument.init("backup-id", "Backup ID (e.g. mail-backup-20240101-120000)", .string));
    try addCommonOptions(restore_cmd);
    _ = restore_cmd.setAction(restoreAction);
    _ = try backup_cmd.addCommand(restore_cmd);

    // backup list
    const list_cmd = try cli.BaseCommand.init(allocator, "list", "List available backups");
    try addCommonOptions(list_cmd);
    _ = list_cmd.setAction(listAction);
    _ = try backup_cmd.addCommand(list_cmd);

    // backup status
    const status_cmd = try cli.BaseCommand.init(allocator, "status", "Check mail server data status");
    _ = try status_cmd.addOption(
        cli.Option.init("instance-id", "instance-id", "EC2 instance ID (overrides auto-detection)", .string),
    );
    _ = try status_cmd.addOption(
        cli.Option.init("env", "env", "Target environment (default: production)", .string)
            .withDefault("production"),
    );
    _ = status_cmd.setAction(statusAction);
    _ = try backup_cmd.addCommand(status_cmd);

    return backup_cmd;
}
