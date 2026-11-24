const std = @import("std");
const cli = @import("zig-cli");
const database = @import("../storage/database.zig");
const env = @import("../core/env.zig");
const config = @import("../core/config.zig");
const mailbox_domains = @import("../core/mailbox_domains.zig");
const inventory = @import("../storage/hosted_domain_inventory.zig");
const retirement = @import("../storage/hosted_domain_retirement.zig");
const io_compat = @import("../core/io_compat.zig");
const time = @import("../core/time_compat.zig");
const dm = @import("../domain_migrate.zig");

fn openDb(allocator: std.mem.Allocator) !database.Database {
    const db_path = env.get("SMTP_DB_PATH") orelse "./smtp.db";
    return database.Database.init(allocator, db_path);
}

fn planOptions() dm.PlanOptions {
    return .{
        .mail_root = env.get("MAIL_ROOT") orelse "mail",
        .forwards_path = env.get("MAIL_FORWARDS_PATH") orelse "forwards.json",
        .dkim_dir = env.get("MAIL_DKIM_DIR") orelse "dkim",
    };
}

fn listAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const allocator = ctx.allocator;
    var db = try openDb(allocator);
    defer db.deinit();

    const counts = try dm.listDomains(allocator, &db);
    defer dm.freeDomainCounts(allocator, counts);

    if (counts.len == 0) {
        std.debug.print("No mailboxes.\n", .{});
        return;
    }

    std.debug.print("{s: <40} {s: >9}\n", .{ "DOMAIN", "MAILBOXES" });
    for (counts) |c|
        std.debug.print("{s: <40} {d: >9}\n", .{ c.domain, c.mailboxes });
}

fn inventoryAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const input = ctx.getArgument(0) orelse return error.MissingArgument;
    if (!dm.isValidDomain(input)) return error.InvalidDomain;
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const domain = try std.ascii.allocLowerString(allocator, input);
    var db = try database.Database.openReadOnly(allocator, env.get("SMTP_DB_PATH") orelse "./smtp.db");
    defer db.deinit();
    const cfg = try config.loadConfig(allocator, .{});
    const routing: inventory.Routing = .{
        .local = cfg.isLocalDomain(domain),
        .exact_mailboxes = mailbox_domains.contains(cfg.exact_mailbox_domains, domain),
        .additional_provisioning = mailbox_domains.contains(env.get("SMTP_PROVISIONING_ADDITIONAL_DOMAINS"), domain),
        .catch_all = cfg.catch_all,
    };
    const io = io_compat.getIo();
    var buffer: [4096]u8 = undefined;
    var output = std.Io.File.stdout().writerStreaming(io, &buffer);
    try inventory.write(allocator, &db, domain, time.timestamp(), routing, io, &output.interface);
}

fn retireAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const id = ctx.getArgument(0) orelse return error.MissingArgument;
    const path = ctx.getArgument(1) orelse return error.MissingArgument;
    if (id.len < 16 or id.len > 64) return error.InvalidOperationId;
    for (id) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return error.InvalidOperationId;
    if (ctx.getOption("yes") == null) return error.ExplicitApprovalRequired;

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = io_compat.getIo();
    const source = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(16 * 1024 * 1024));
    const report = try std.json.parseFromSliceLeaky(struct {
        version: u8,
        domain: []const u8,
        mailboxes: []const retirement.Mailbox,
    }, allocator, source, .{ .ignore_unknown_fields = true });
    if (report.version != 1 or !dm.isValidDomain(report.domain)) return error.InvalidInventory;
    const domain = try std.ascii.allocLowerString(allocator, report.domain);
    const cfg = try config.loadConfig(allocator, .{});
    if (!cfg.isLocalDomain(domain) or cfg.catch_all or !mailbox_domains.contains(cfg.exact_mailbox_domains, domain) or
        !mailbox_domains.contains(env.get("SMTP_PROVISIONING_ADDITIONAL_DOMAINS"), domain) or
        std.ascii.eqlIgnoreCase(env.get("SMTP_PROVISIONING_DOMAIN") orelse "", domain)) return error.NotAdditionalHostedDomain;

    var bytes: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &bytes, .{});
    const hash = std.fmt.bytesToHex(bytes, .lower);
    const operator = try std.fmt.allocPrint(allocator, "local-operator:{d}", .{std.c.geteuid()});
    try std.Io.Dir.cwd().access(io, env.get("SMTP_DB_PATH") orelse "./smtp.db", .{});
    var db = try openDb(allocator);
    defer db.deinit();
    const receipt = try retirement.retire(allocator, &db, id, domain, &hash, operator, time.timestamp(), report.mailboxes);
    var buffer: [1024]u8 = undefined;
    var output = std.Io.File.stdout().writerStreaming(io, &buffer);
    try std.json.Stringify.value(receipt, .{ .whitespace = .indent_2 }, &output.interface);
    try output.interface.writeByte('\n');
    try output.interface.flush();
}

fn migrateAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const allocator = ctx.allocator;

    const old_domain = ctx.getArgument(0) orelse {
        std.debug.print("Error: old domain is required\nUsage: mail domain migrate <old-domain> <new-domain> [--yes]\n", .{});
        return;
    };
    const new_domain = ctx.getArgument(1) orelse {
        std.debug.print("Error: new domain is required\nUsage: mail domain migrate <old-domain> <new-domain> [--yes]\n", .{});
        return;
    };

    var db = try openDb(allocator);
    defer db.deinit();

    const options = planOptions();

    var plan = dm.plan(allocator, &db, old_domain, new_domain, options) catch |err| {
        switch (err) {
            dm.Error.InvalidDomain => std.debug.print("Error: '{s}' or '{s}' is not a valid domain.\n", .{ old_domain, new_domain }),
            dm.Error.SameDomain => std.debug.print("Error: source and target are the same domain.\n", .{}),
            dm.Error.NoMailboxes => std.debug.print("No mailboxes on '{s}'. Nothing to migrate.\nRun `mail domain list` to see which domains are in use.\n", .{old_domain}),
            dm.Error.TargetAddressExists => std.debug.print("Error: a mailbox already exists on '{s}' with the same local part.\nMerge or delete it first. Usernames and emails are unique.\n", .{new_domain}),
            else => std.debug.print("Error: {}\n", .{err}),
        }
        return;
    };
    defer plan.deinit();

    // Always show the plan. It is the whole point of splitting plan from apply:
    // a domain rename is not reversible by re-running it backwards once mail
    // has been delivered to the new addresses.
    std.debug.print("\nMigrating {s} -> {s}\n\n", .{ old_domain, new_domain });

    std.debug.print("  Mailboxes ({d}):\n", .{plan.mailboxes.len});
    for (plan.mailboxes) |m| {
        const note = if (m.has_maildir) "" else "   (no maildir on disk)";
        std.debug.print("    {s} -> {s}{s}\n", .{ m.from, m.to, note });
    }

    if (plan.forwards.len > 0) {
        std.debug.print("\n  Forwarding rules ({d}):\n", .{plan.forwards.len});
        for (plan.forwards) |f| {
            const side = if (f.is_destination) "destination" else "mailbox";
            std.debug.print("    {s: <11} {s} -> {s}\n", .{ side, f.from, f.to });
        }
    }

    if (plan.sessions_invalidated > 0)
        std.debug.print("\n  Webmail sessions invalidated: {d} (users sign in again)\n", .{plan.sessions_invalidated});

    if (plan.needs_dkim_key) {
        std.debug.print(
            \\
            \\  DKIM: {s} has a signing key, {s} does not. Generate one and publish
            \\        its TXT record before sending, or mail from the new domain
            \\        arrives unsigned and is likely to be filtered.
            \\
        , .{ old_domain, new_domain });
    }

    std.debug.print(
        \\
        \\  Still to do by hand, on the server and at the registrar:
        \\    - add {s} to SMTP_LOCAL_DOMAINS (and remove {s} once mail has drained)
        \\    - MX, SPF and DMARC records for {s}
        \\    - keep {s} accepting mail until senders have moved
        \\
    , .{ new_domain, old_domain, new_domain, old_domain });

    if (ctx.getOption("yes") == null) {
        std.debug.print("\nNothing changed. Re-run with --yes to apply.\n", .{});
        return;
    }

    const result = try dm.apply(allocator, &db, &plan, options);

    std.debug.print("\nMigrated {d} mailbox(es).\n", .{result.mailboxes_moved});
    std.debug.print("  maildirs renamed: {d}\n", .{result.maildirs_renamed});
    if (result.forwards_rewritten > 0)
        std.debug.print("  forwarding rules rewritten: {d}\n", .{result.forwards_rewritten});

    if (result.maildirs_failed > 0) {
        std.debug.print(
            \\
            \\  WARNING: {d} maildir(s) could not be renamed. The database now points
            \\  at the new addresses, so that mail is unreachable until the
            \\  directories are moved by hand under {s}/.
            \\
        , .{ result.maildirs_failed, options.mail_root });
    }
}

pub fn setup(allocator: std.mem.Allocator) !*cli.BaseCommand {
    const cmd = try cli.BaseCommand.init(allocator, "domain", "Inspect and migrate mail domains");

    const list_cmd = try cli.BaseCommand.init(allocator, "list", "List domains with mailboxes on this server");
    _ = list_cmd.setAction(listAction);
    _ = try cmd.addCommand(list_cmd);

    const inventory_cmd = try cli.BaseCommand.init(allocator, "inventory", "Print a read-only JSON inventory of a hosted domain");
    _ = try inventory_cmd.addArgument(cli.Argument.init("domain", "Domain to inspect", .string));
    _ = inventory_cmd.setAction(inventoryAction);
    _ = try cmd.addCommand(inventory_cmd);

    const retire_cmd = try cli.BaseCommand.init(allocator, "retire", "Disable reviewed hosted mailboxes and reserve their retained addresses");
    _ = try retire_cmd.addArgument(cli.Argument.init("operation-id", "Retirement operation ID for safe retries", .string));
    _ = try retire_cmd.addArgument(cli.Argument.init("inventory", "Reviewed JSON from mail domain inventory", .string));
    _ = try retire_cmd.addOption(cli.Option.init("yes", "yes", "Apply the reviewed retirement", .bool));
    _ = retire_cmd.setAction(retireAction);
    _ = try cmd.addCommand(retire_cmd);

    const migrate_cmd = try cli.BaseCommand.init(
        allocator,
        "migrate",
        "Move every mailbox from one domain to another (shows a plan; --yes applies)",
    );
    _ = try migrate_cmd.addArgument(cli.Argument.init("old-domain", "Domain to migrate from", .string));
    _ = try migrate_cmd.addArgument(cli.Argument.init("new-domain", "Domain to migrate to", .string));
    _ = try migrate_cmd.addOption(
        cli.Option.init("yes", "yes", "Apply the migration instead of only printing the plan", .bool),
    );
    _ = migrate_cmd.setAction(migrateAction);
    _ = try cmd.addCommand(migrate_cmd);

    return cmd;
}
