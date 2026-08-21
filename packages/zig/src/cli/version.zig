//! `mail version` — print the release this binary was built from.
//!
//! Exists so an operator (and, more importantly, an unattended `mail upgrade`
//! run) can answer "what is actually installed?" without guessing from a file
//! date. `--short` prints the bare number for scripts.

const std = @import("std");
const cli = @import("zig-cli");
const version = @import("../core/version.zig");

pub fn setup(allocator: std.mem.Allocator) !*cli.BaseCommand {
    const cmd = try cli.BaseCommand.init(allocator, "version", "Print the installed mail server version");
    _ = try cmd.addOption(
        cli.Option.init("short", "short", "Print just the version number", .bool),
    );
    _ = cmd.setAction(versionAction);
    return cmd;
}

fn versionAction(ctx: *cli.BaseCommand.ParseContext) !void {
    if (ctx.hasOption("short")) {
        std.debug.print("{s}\n", .{version.version});
        return;
    }
    const info = version.getBuildInfo();
    std.debug.print("mail {s} ({s}, zig {s}, {s})\n", .{
        version.version_display,
        info.target,
        info.zig_version,
        info.build_mode,
    });
}
