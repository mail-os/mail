const std = @import("std");
const cli = @import("zig-cli");
const server = @import("../main.zig");
const args_parser = @import("../core/args.zig");
const logger = @import("../core/logger.zig");

pub fn setup(allocator: std.mem.Allocator) !*cli.BaseCommand {
    const cmd = try cli.BaseCommand.init(allocator, "serve", "Start the mail server daemon");

    _ = try cmd.addOption(
        cli.Option.init("config", "config", "Path to configuration file", .string).withShort('c'),
    );
    _ = try cmd.addOption(
        cli.Option.init("host", "host", "Host to bind to (default: 0.0.0.0)", .string),
    );
    _ = try cmd.addOption(
        cli.Option.init("port", "port", "Port to listen on (default: 2525)", .string).withShort('p'),
    );
    _ = try cmd.addOption(
        cli.Option.init("log-level", "log-level", "Log level (debug|info|warn|error|critical)", .string),
    );
    _ = try cmd.addOption(
        cli.Option.init("log-file", "log-file", "Path to log file", .string),
    );
    _ = try cmd.addOption(
        cli.Option.init("max-connections", "max-connections", "Maximum concurrent connections", .string),
    );
    _ = try cmd.addOption(
        cli.Option.init("validate-only", "validate-only", "Validate configuration and exit", .bool),
    );
    _ = try cmd.addOption(
        cli.Option.init("enable-tls", "enable-tls", "Enable TLS/STARTTLS support", .bool),
    );
    _ = try cmd.addOption(
        cli.Option.init("disable-tls", "disable-tls", "Disable TLS/STARTTLS support", .bool),
    );
    _ = try cmd.addOption(
        cli.Option.init("enable-auth", "enable-auth", "Enable SMTP authentication", .bool),
    );
    _ = try cmd.addOption(
        cli.Option.init("disable-auth", "disable-auth", "Disable SMTP authentication", .bool),
    );

    _ = cmd.setAction(serveAction);
    return cmd;
}

fn parseLogLevel(str: []const u8) ?logger.LogLevel {
    if (std.ascii.eqlIgnoreCase(str, "debug")) return .debug;
    if (std.ascii.eqlIgnoreCase(str, "info")) return .info;
    if (std.ascii.eqlIgnoreCase(str, "warn")) return .warn;
    if (std.ascii.eqlIgnoreCase(str, "error")) return .err;
    if (std.ascii.eqlIgnoreCase(str, "critical")) return .critical;
    return null;
}

fn serveAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const allocator = ctx.allocator;

    var args = args_parser.Args{};

    if (ctx.getOption("config")) |v| args.config_file = try allocator.dupe(u8, v);
    if (ctx.getOption("host")) |v| args.host = try allocator.dupe(u8, v);
    if (ctx.getOption("port")) |v| args.port = std.fmt.parseInt(u16, v, 10) catch null;
    if (ctx.getOption("log-level")) |v| args.log_level = parseLogLevel(v);
    if (ctx.getOption("log-file")) |v| args.log_file = try allocator.dupe(u8, v);
    if (ctx.getOption("max-connections")) |v| args.max_connections = std.fmt.parseInt(usize, v, 10) catch null;

    if (ctx.hasOption("validate-only")) args.validate_only = true;
    if (ctx.hasOption("enable-tls")) args.enable_tls = true;
    if (ctx.hasOption("disable-tls")) args.enable_tls = false;
    if (ctx.hasOption("enable-auth")) args.enable_auth = true;
    if (ctx.hasOption("disable-auth")) args.enable_auth = false;

    defer args.deinit(allocator);

    try server.run(allocator, args);
}
