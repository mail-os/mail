const std = @import("std");
const cli = @import("zig-cli");
const user_cli = @import("../user_cli.zig");
const database = @import("../storage/database.zig");
const auth = @import("../auth/auth.zig");
const env = @import("../core/env.zig");
const recovery = @import("../api/webmail_recovery.zig");
const mailbox_export = @import("../storage/mailbox_export.zig");
const calendar_workflow = @import("../storage/calendar_workflow_transfer.zig");
const hosted_limits = @import("../storage/hosted_limits.zig");
const erasure_preflight = @import("../storage/hosted_erasure_preflight.zig");
const erasure_export = @import("../storage/hosted_erasure_export.zig");
const erasure_inventory = @import("../storage/hosted_erasure_inventory.zig");
const erasure_review = @import("../storage/hosted_erasure_review.zig");
const io_compat = @import("../core/io_compat.zig");
const time = @import("../core/time_compat.zig");

const password_input = @import("password_input.zig");

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

    var input: password_input.Buffer = undefined;
    defer std.crypto.secureZero(u8, &input);
    const password = try password_input.read(ctx, ctx.getOption("password") orelse ctx.getArgument(1), &input, "New password");

    const email = ctx.getOption("email") orelse ctx.getArgument(2);
    const derived = if (email == null and std.mem.indexOfScalar(u8, username, '@') == null)
        try std.fmt.allocPrint(ctx.allocator, "{s}@{s}", .{ username, env.get("DOMAIN") orelse "localhost" })
    else
        null;
    defer if (derived) |address| ctx.allocator.free(address);
    const created = try user_cli.createUser(auth_backend, username, password, email orelse derived orelse username);
    if (!created and ctx.hasOption("remote-stdin")) return error.UserAlreadyExists;
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

fn hostedStatusAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const mailbox = ctx.getArgument(0) orelse return error.MissingArgument;
    const allocator = ctx.allocator;
    const io = io_compat.getIo();
    const path = env.get("SMTP_DB_PATH") orelse "./smtp.db";
    try std.Io.Dir.cwd().access(io, path, .{});
    var db = try database.Database.init(allocator, path);
    defer db.deinit();

    const now = time.timestamp();
    const account = (try db.hostedAccountStatus(mailbox, now)) orelse return error.ManagedMailboxNotFound;
    const storage = try hosted_limits.observeStorage(&db, mailbox, account.quota_bytes, now);
    var actor_buffer: [64]u8 = undefined;
    const actor = try std.fmt.bufPrint(&actor_buffer, "local-operator:{d}", .{std.c.geteuid()});
    const audit_id = try db.insertAuditEntry(now, "hosted.status", actor, mailbox, "hosted_mailbox", null, null, "info");

    var buffer: [4096]u8 = undefined;
    var output = std.Io.File.stdout().writerStreaming(io, &buffer);
    try std.json.Stringify.value(.{
        .version = @as(u8, 1),
        .mailbox = mailbox,
        .observed_at = now,
        .account = account,
        .storage = storage,
        .audit_id = audit_id,
    }, .{ .whitespace = .indent_2 }, &output.interface);
    try output.interface.writeByte('\n');
    try output.interface.flush();
}

fn hostedErasurePreflightAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const mailbox = ctx.getArgument(0) orelse return error.MissingArgument;
    const expected_actor = ctx.getArgument(1) orelse return error.MissingArgument;
    const case_reference = ctx.getArgument(2) orelse return error.MissingArgument;
    if (!erasure_preflight.validCaseReference(case_reference)) return error.InvalidCaseReference;

    const io = io_compat.getIo();
    const path = env.get("SMTP_DB_PATH") orelse "./smtp.db";
    try std.Io.Dir.cwd().access(io, path, .{});
    var db = try database.Database.init(ctx.allocator, path);
    defer db.deinit();
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const now = time.timestamp();
    const observation = try erasure_preflight.observe(a, &db, mailbox, expected_actor, now);
    const details = try std.json.Stringify.valueAlloc(a, .{ .case_reference = case_reference, .identity = observation.identity }, .{});
    var actor_buffer: [64]u8 = undefined;
    const actor = try std.fmt.bufPrint(&actor_buffer, "local-operator:{d}", .{std.c.geteuid()});
    const audit_id = try db.insertAuditEntry(now, "hosted.erasure.preflight", actor, mailbox, "hosted_mailbox", null, details, "info");

    var buffer: [4096]u8 = undefined;
    var output = std.Io.File.stdout().writerStreaming(io, &buffer);
    try std.json.Stringify.value(.{
        .version = @as(u8, 1),
        .mailbox = mailbox,
        .case_reference = case_reference,
        .observed_at = now,
        .observation = observation,
        .audit_id = audit_id,
    }, .{ .whitespace = .indent_2 }, &output.interface);
    try output.interface.writeByte('\n');
    try output.interface.flush();
}

fn hostedErasureInventoryAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const mailbox = ctx.getArgument(0) orelse return error.MissingArgument;
    const expected_actor = ctx.getArgument(1) orelse return error.MissingArgument;
    const case_reference = ctx.getArgument(2) orelse return error.MissingArgument;
    if (!erasure_preflight.validCaseReference(case_reference)) return error.InvalidCaseReference;

    const io = io_compat.getIo();
    var db = try database.Database.openReadWriteExisting(ctx.allocator, env.get("SMTP_DB_PATH") orelse "./smtp.db");
    defer db.deinit();
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const inventory = try erasure_inventory.collect(a, io, &db, mailbox, expected_actor, env.get("MAIL_ROOT") orelse "mail", env.get("CALDAV_DB_PATH"));
    var actor_buffer: [64]u8 = undefined;
    const operator = try std.fmt.bufPrint(&actor_buffer, "local-operator:{d}", .{std.c.geteuid()});
    const audit_id = try erasure_inventory.record(a, &db, inventory, mailbox, expected_actor, operator, case_reference);

    var buffer: [4096]u8 = undefined;
    var output = std.Io.File.stdout().writerStreaming(io, &buffer);
    try std.json.Stringify.value(.{
        .version = @as(u8, 1),
        .mailbox = mailbox,
        .case_reference = case_reference,
        .inventory = inventory,
        .audit_id = audit_id,
    }, .{ .whitespace = .indent_2 }, &output.interface);
    try output.interface.writeByte('\n');
    try output.interface.flush();
}

fn hostedSendingHoldAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const mailbox = ctx.getArgument(0) orelse return error.MissingArgument;
    const action = ctx.getArgument(1) orelse return error.MissingArgument;
    const reference = ctx.getArgument(2) orelse return error.MissingArgument;
    const held = if (std.mem.eql(u8, action, "place"))
        true
    else if (std.mem.eql(u8, action, "release"))
        false
    else
        return error.InvalidHoldAction;
    var actor_buffer: [64]u8 = undefined;
    const actor = try std.fmt.bufPrint(&actor_buffer, "local-operator:{d}", .{std.c.geteuid()});
    const path = env.get("SMTP_DB_PATH") orelse "./smtp.db";
    try std.Io.Dir.cwd().access(io_compat.getIo(), path, .{});
    var db = try database.Database.init(ctx.allocator, path);
    defer db.deinit();
    const changed = try db.setHostedSendingHold(mailbox, held, actor, reference);
    const output = if (changed)
        (if (held) "Sending hold placed.\n" else "Sending hold released.\n")
    else
        (if (held) "Sending hold is already in place.\n" else "No sending hold is in place.\n");
    std.debug.print("{s}", .{output});
}

fn exportOptions() mailbox_export.Options {
    const dav_path = env.get("CALDAV_DB_PATH");
    return .{
        .mail_root = env.get("MAIL_ROOT") orelse "mail",
        .dav_path = dav_path orelse "./caldav.db",
        .require_dav = dav_path != null,
    };
}

fn exportAction(ctx: *cli.BaseCommand.ParseContext, db: *database.Database, _: *auth.AuthBackend) !void {
    const username = ctx.getArgument(0) orelse return error.MissingArgument;
    const destination = ctx.getArgument(1) orelse return error.MissingArgument;
    try mailbox_export.write(ctx.allocator, io_compat.getIo(), db, username, destination, exportOptions());
    std.debug.print("Mailbox export saved to {s}\n", .{destination});
}

fn hostedErasureExportAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const review_path = ctx.getArgument(0) orelse return error.MissingArgument;
    const destination = ctx.getArgument(1) orelse return error.MissingArgument;
    const io = io_compat.getIo();
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const raw = try std.Io.Dir.cwd().readFileAlloc(io, review_path, a, .limited(8192));
    const review = try std.json.parseFromSliceLeaky(erasure_export.Review, a, raw, .{});

    const path = env.get("SMTP_DB_PATH") orelse "./smtp.db";
    try std.Io.Dir.cwd().access(io, path, .{});
    var db = try database.Database.init(ctx.allocator, path);
    defer db.deinit();
    var actor_buffer: [64]u8 = undefined;
    const operator = try std.fmt.bufPrint(&actor_buffer, "local-operator:{d}", .{std.c.geteuid()});
    const receipt = try erasure_export.write(a, io, &db, review, operator, destination, exportOptions());

    var buffer: [4096]u8 = undefined;
    var output = std.Io.File.stdout().writerStreaming(io, &buffer);
    try std.json.Stringify.value(receipt, .{ .whitespace = .indent_2 }, &output.interface);
    try output.interface.writeByte('\n');
    try output.interface.flush();
}

fn readPrivateReview(a: std.mem.Allocator, io: std.Io, review_path: []const u8, privacy_error: anyerror) ![]const u8 {
    const review_file = try std.Io.Dir.cwd().openFile(io, review_path, .{ .follow_symlinks = false });
    defer review_file.close(io);
    const stat = try review_file.stat(io);
    if (stat.kind != .file or stat.permissions.toMode() & 0o077 != 0 or stat.size > 8192)
        return privacy_error;
    var input_buffer: [4096]u8 = undefined;
    var input = review_file.reader(io, &input_buffer);
    const raw = try a.alloc(u8, @intCast(stat.size));
    try input.interface.readSliceAll(raw);
    return raw;
}

fn hostedErasureHandoffAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const review_path = ctx.getArgument(0) orelse return error.MissingArgument;
    const source = ctx.getArgument(1) orelse return error.MissingArgument;
    const destination = ctx.getArgument(2) orelse return error.MissingArgument;
    const io = io_compat.getIo();
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const raw = try readPrivateReview(a, io, review_path, error.ExportHandoffReviewNotPrivate);
    const review = try std.json.parseFromSliceLeaky(erasure_export.Handoff, a, raw, .{});

    const path = env.get("SMTP_DB_PATH") orelse "./smtp.db";
    try std.Io.Dir.cwd().access(io, path, .{});
    var db = try database.Database.init(ctx.allocator, path);
    defer db.deinit();
    var actor_buffer: [64]u8 = undefined;
    const operator = try std.fmt.bufPrint(&actor_buffer, "local-operator:{d}", .{std.c.geteuid()});
    const receipt = try erasure_export.handoffArchive(a, io, &db, review, operator, source, destination);

    var buffer: [4096]u8 = undefined;
    var output = std.Io.File.stdout().writerStreaming(io, &buffer);
    try std.json.Stringify.value(receipt, .{ .whitespace = .indent_2 }, &output.interface);
    try output.interface.writeByte('\n');
    try output.interface.flush();
}

fn hostedErasureReviewAction(ctx: *cli.BaseCommand.ParseContext) !void {
    try hostedErasureApproval(ctx, null);
}

fn hostedErasureBeginAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const audit = ctx.getArgument(1) orelse return error.MissingArgument;
    const audit_id = std.fmt.parseInt(i64, audit, 10) catch return error.InvalidErasureReviewAuditId;
    try hostedErasureApproval(ctx, audit_id);
}

fn hostedErasureApproval(ctx: *cli.BaseCommand.ParseContext, review_audit_id: ?i64) !void {
    const review_path = ctx.getArgument(0) orelse return error.MissingArgument;
    const io = io_compat.getIo();
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const raw = try readPrivateReview(a, io, review_path, error.ErasureReviewNotPrivate);
    const review = try std.json.parseFromSliceLeaky(erasure_review.Review, a, raw, .{});

    var db = try database.Database.openReadWriteExisting(ctx.allocator, env.get("SMTP_DB_PATH") orelse "./smtp.db");
    defer db.deinit();
    var actor_buffer: [64]u8 = undefined;
    const operator = try std.fmt.bufPrint(&actor_buffer, "local-operator:{d}", .{std.c.geteuid()});
    const mail_root = env.get("MAIL_ROOT") orelse "mail";
    const dav_path = env.get("CALDAV_DB_PATH");
    var buffer: [4096]u8 = undefined;
    var output = std.Io.File.stdout().writerStreaming(io, &buffer);
    if (review_audit_id) |id| {
        const receipt = try erasure_review.begin(a, io, &db, review, id, operator, mail_root, dav_path);
        try std.json.Stringify.value(receipt, .{ .whitespace = .indent_2 }, &output.interface);
    } else {
        const receipt = try erasure_review.record(a, io, &db, review, operator, mail_root, dav_path);
        try std.json.Stringify.value(receipt, .{ .whitespace = .indent_2 }, &output.interface);
    }
    try output.interface.writeByte('\n');
    try output.interface.flush();
}

fn importCalendarWorkflowAction(ctx: *cli.BaseCommand.ParseContext, db: *database.Database, _: *auth.AuthBackend) !void {
    const username = ctx.getArgument(0) orelse return error.MissingArgument;
    const path = ctx.getArgument(1) orelse return error.MissingArgument;
    const io = io_compat.getIo();
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var buffer: [16 * 1024]u8 = undefined;
    var input = file.reader(io, &buffer);
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var json = std.json.Reader.init(a, &input.interface);
    defer json.deinit();
    const document = try std.json.parseFromTokenSourceLeaky(calendar_workflow.Document, a, &json, .{});
    try calendar_workflow.restore(a, db, username, document);
    std.debug.print("Restored Calendar workflow for {s}\n", .{username});
}

fn verifyAction(ctx: *cli.BaseCommand.ParseContext, _: *database.Database, auth_backend: *auth.AuthBackend) !void {
    const username = ctx.getArgument(0) orelse {
        std.debug.print("Error: username is required\nUsage: mail user:local verify <username> [<password> | --password-stdin]\n", .{});
        return error.MissingArgument;
    };
    var input: password_input.Buffer = undefined;
    defer std.crypto.secureZero(u8, &input);
    const password = try password_input.read(ctx, ctx.getArgument(1), &input, "Password");
    const valid = try user_cli.verifyUser(auth_backend, username, password);
    if (!valid and ctx.hasOption("remote-stdin")) return error.InvalidCredentials;
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

    var input: password_input.Buffer = undefined;
    defer std.crypto.secureZero(u8, &input);
    const password = try password_input.read(ctx, ctx.getArgument(1), &input, "New password");

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
    try password_input.addRemoteOption(create_cmd);
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

    const hosted_status_cmd = try cli.BaseCommand.init(allocator, "hosted-status", "Audit and report a hosted mailbox's current usage and provisioning state");
    _ = try hosted_status_cmd.addArgument(cli.Argument.init("username", "Canonical hosted mailbox username", .string));
    _ = hosted_status_cmd.setAction(hostedStatusAction);
    _ = try cmd.addCommand(hosted_status_cmd);

    const preflight_cmd = try cli.BaseCommand.init(allocator, "hosted-erasure-preflight", "Audit a hosted mailbox identity and outstanding work before an erasure review");
    _ = try preflight_cmd.addArgument(cli.Argument.init("username", "Canonical hosted mailbox username", .string).withRequired(true));
    _ = try preflight_cmd.addArgument(cli.Argument.init("provisioning-actor", "Expected assignment actor from the private provisioning record", .string).withRequired(true));
    _ = try preflight_cmd.addArgument(cli.Argument.init("case-reference", "Non-sensitive erasure case identifier", .string).withRequired(true));
    _ = preflight_cmd.setAction(hostedErasurePreflightAction);
    _ = try cmd.addCommand(preflight_cmd);

    const inventory_cmd = try cli.BaseCommand.init(allocator, "hosted-erasure-inventory", "Audit retained Mail stores for a hosted erasure review");
    _ = try inventory_cmd.addArgument(cli.Argument.init("username", "Canonical hosted mailbox username", .string).withRequired(true));
    _ = try inventory_cmd.addArgument(cli.Argument.init("actor", "Expected provisioning assignment", .string).withRequired(true));
    _ = try inventory_cmd.addArgument(cli.Argument.init("case", "Private support case reference", .string).withRequired(true));
    _ = inventory_cmd.setAction(hostedErasureInventoryAction);
    _ = try cmd.addCommand(inventory_cmd);

    const sending_hold_cmd = try cli.BaseCommand.init(allocator, "hosted-sending-hold", "Place or release an audited sending hold on a hosted mailbox");
    _ = try sending_hold_cmd.addArgument(cli.Argument.init("username", "Canonical hosted mailbox username", .string).withRequired(true));
    _ = try sending_hold_cmd.addArgument(cli.Argument.init("action", "place or release", .string).withRequired(true));
    _ = try sending_hold_cmd.addArgument(cli.Argument.init("case-reference", "Non-sensitive case reference for the audit log", .string).withRequired(true));
    _ = sending_hold_cmd.setAction(hostedSendingHoldAction);
    _ = try cmd.addCommand(sending_hold_cmd);

    const hosted_export_cmd = try cli.BaseCommand.init(allocator, "hosted-erasure-export", "Prepare an audited private archive for a reviewed hosted exit");
    _ = try hosted_export_cmd.addArgument(cli.Argument.init("review", "Private reviewed hosted export JSON file", .string).withRequired(true));
    _ = try hosted_export_cmd.addArgument(cli.Argument.init("output", "Path for a new private archive", .string).withRequired(true));
    _ = hosted_export_cmd.setAction(hostedErasureExportAction);
    _ = try cmd.addCommand(hosted_export_cmd);

    const hosted_handoff_cmd = try cli.BaseCommand.init(allocator, "hosted-erasure-handoff", "Verify the approved recipient and expiry before staging a private export");
    _ = try hosted_handoff_cmd.addArgument(cli.Argument.init("handoff", "Private reviewed handoff JSON file", .string).withRequired(true));
    _ = try hosted_handoff_cmd.addArgument(cli.Argument.init("archive", "Prepared private mailbox archive", .string).withRequired(true));
    _ = try hosted_handoff_cmd.addArgument(cli.Argument.init("output", "Path for the verified private handoff", .string).withRequired(true));
    _ = hosted_handoff_cmd.setAction(hostedErasureHandoffAction);
    _ = try cmd.addCommand(hosted_handoff_cmd);

    const erasure_review_cmd = try cli.BaseCommand.init(allocator, "hosted-erasure-review", "Record approved erasure evidence with the mailbox data retained");
    _ = try erasure_review_cmd.addArgument(cli.Argument.init("review", "Private erasure review JSON file", .string).withRequired(true));
    _ = erasure_review_cmd.setAction(hostedErasureReviewAction);
    _ = try cmd.addCommand(erasure_review_cmd);

    const erasure_begin_cmd = try cli.BaseCommand.init(allocator, "hosted-erasure-begin", "Reserve a reviewed mailbox for erasure with its data retained");
    _ = try erasure_begin_cmd.addArgument(cli.Argument.init("review", "Private erasure review JSON file", .string).withRequired(true));
    _ = try erasure_begin_cmd.addArgument(cli.Argument.init("review-audit-id", "Audit ID of the accepted erasure review", .string).withRequired(true));
    _ = erasure_begin_cmd.setAction(hostedErasureBeginAction);
    _ = try cmd.addCommand(erasure_begin_cmd);

    const export_cmd = try cli.BaseCommand.init(allocator, "export", "Export a mailbox to a portable TAR archive");
    _ = try export_cmd.addArgument(cli.Argument.init("username", "Canonical mailbox username", .string));
    _ = try export_cmd.addArgument(cli.Argument.init("output", "Path for a new private archive", .string));
    _ = export_cmd.setAction(withDb(exportAction));
    _ = try cmd.addCommand(export_cmd);

    const import_workflow_cmd = try cli.BaseCommand.init(allocator, "import-calendar-workflow", "Restore private Calendar data from a mailbox export");
    _ = try import_workflow_cmd.addArgument(cli.Argument.init("username", "Canonical destination mailbox username", .string));
    _ = try import_workflow_cmd.addArgument(cli.Argument.init("input", "Path to the extracted CalendarWorkflow.json", .string));
    _ = import_workflow_cmd.setAction(withDb(importCalendarWorkflowAction));
    _ = try cmd.addCommand(import_workflow_cmd);

    // verify
    const verify_cmd = try cli.BaseCommand.init(allocator, "verify", "Verify user credentials");
    _ = try verify_cmd.addArgument(cli.Argument.init("username", "Username", .string));
    _ = try verify_cmd.addArgument(cli.Argument.init("password", "Password (omit to read standard input)", .string).withRequired(false));
    try password_input.addRemoteOption(verify_cmd);
    _ = verify_cmd.setAction(withDb(verifyAction));
    _ = try cmd.addCommand(verify_cmd);

    // change-password
    const change_pw_cmd = try cli.BaseCommand.init(allocator, "change-password", "Change user password");
    _ = try change_pw_cmd.addArgument(cli.Argument.init("username", "Username", .string));
    _ = try change_pw_cmd.addArgument(cli.Argument.init("password", "New password (omit to read standard input)", .string).withRequired(false));
    try password_input.addRemoteOption(change_pw_cmd);
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
