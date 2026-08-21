const std = @import("std");
const cli = @import("zig-cli");
const io_compat = @import("core/io_compat.zig");

// Subcommand modules
const serve = @import("cli/serve.zig");
const user_remote = @import("cli/user_remote.zig");
const user_local = @import("cli/user_local.zig");
const migrate_mod = @import("cli/migrate.zig");
const domain_mod = @import("cli/domain.zig");
const gdpr_mod = @import("cli/gdpr.zig");
const search_mod = @import("cli/search.zig");
const benchmark_mod = @import("cli/benchmark.zig");
const backup_mod = @import("cli/backup.zig");
const upgrade_mod = @import("cli/upgrade.zig");
const version_mod = @import("cli/version.zig");
const version = @import("core/version.zig");

pub fn main(init: std.process.Init) !void {
    io_compat.initIo(init.io);

    const allocator = init.gpa;

    // Build root command with all subcommands
    const root_cmd = try cli.BaseCommand.init(allocator, "mail", "Mail server management CLI");
    defer {
        root_cmd.deinit();
        allocator.destroy(root_cmd);
    }

    _ = try root_cmd.addCommand(try serve.setup(allocator));
    _ = try root_cmd.addCommand(try user_remote.setup(allocator));
    _ = try root_cmd.addCommand(try user_local.setup(allocator));
    _ = try root_cmd.addCommand(try migrate_mod.setup(allocator));
    _ = try root_cmd.addCommand(try domain_mod.setup(allocator));
    _ = try root_cmd.addCommand(try gdpr_mod.setup(allocator));
    _ = try root_cmd.addCommand(try search_mod.setup(allocator));
    _ = try root_cmd.addCommand(try benchmark_mod.setup(allocator));
    _ = try root_cmd.addCommand(try backup_mod.setup(allocator));
    _ = try root_cmd.addCommand(try upgrade_mod.setup(allocator));
    _ = try root_cmd.addCommand(try version_mod.setup(allocator));

    // Collect args (skip program name)
    var args_list: std.ArrayList([]const u8) = .empty;
    defer args_list.deinit(allocator);

    var args_iter = std.process.Args.Iterator.init(init.minimal.args);
    _ = args_iter.skip(); // skip program name
    while (args_iter.next()) |arg| {
        try args_list.append(allocator, arg);
    }

    // Show help if no args provided
    if (args_list.items.len == 0) {
        var help = cli.Help.init(allocator);
        try help.generate(root_cmd, "mail", version.version);
        return;
    }

    var parser = cli.Parser.init(allocator);
    parser.parse(root_cmd, args_list.items) catch |err| {
        switch (err) {
            error.MissingInstanceId, error.SsmCommandFailed, error.CommandTimeout => {},
            else => std.debug.print("Error: {}\n", .{err}),
        }
        std.process.exit(1);
    };
}
