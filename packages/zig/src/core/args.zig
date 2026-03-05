const std = @import("std");
const logger = @import("logger.zig");
const version_info = @import("version.zig");

pub const Args = struct {
    config_file: ?[]const u8 = null,
    host: ?[]const u8 = null,
    port: ?u16 = null,
    log_level: ?logger.LogLevel = null,
    log_file: ?[]const u8 = null,
    max_connections: ?usize = null,
    enable_tls: ?bool = null,
    enable_auth: ?bool = null,
    help: bool = false,
    version: bool = false,
    validate_only: bool = false,

    pub fn deinit(self: *Args, allocator: std.mem.Allocator) void {
        if (self.config_file) |path| allocator.free(path);
        if (self.host) |h| allocator.free(h);
        if (self.log_file) |path| allocator.free(path);
    }
};

pub fn parseArgs(allocator: std.mem.Allocator, process_args: std.process.Args) !Args {
    var args = Args{};
    var arg_it = try process_args.iterateAllocator(allocator);
    defer arg_it.deinit();

    // Skip program name
    _ = arg_it.next();

    while (arg_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            args.help = true;
        } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            args.version = true;
        } else if (std.mem.eql(u8, arg, "--config") or std.mem.eql(u8, arg, "-c")) {
            const value = arg_it.next() orelse {
                std.debug.print("Error: --config requires a value\n", .{});
                return error.MissingArgValue;
            };
            args.config_file = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, arg, "--host")) {
            const value = arg_it.next() orelse {
                std.debug.print("Error: --host requires a value\n", .{});
                return error.MissingArgValue;
            };
            args.host = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, arg, "--port") or std.mem.eql(u8, arg, "-p")) {
            const value = arg_it.next() orelse {
                std.debug.print("Error: --port requires a value\n", .{});
                return error.MissingArgValue;
            };
            args.port = std.fmt.parseInt(u16, value, 10) catch {
                std.debug.print("Error: Invalid port number: {s}\n", .{value});
                return error.InvalidPort;
            };
        } else if (std.mem.eql(u8, arg, "--log-level")) {
            const value = arg_it.next() orelse {
                std.debug.print("Error: --log-level requires a value\n", .{});
                return error.MissingArgValue;
            };
            args.log_level = parseLogLevel(value) catch {
                std.debug.print("Error: Invalid log level: {s}\n", .{value});
                std.debug.print("Valid levels: debug, info, warn, error, critical\n", .{});
                return error.InvalidLogLevel;
            };
        } else if (std.mem.eql(u8, arg, "--log-file")) {
            const value = arg_it.next() orelse {
                std.debug.print("Error: --log-file requires a value\n", .{});
                return error.MissingArgValue;
            };
            args.log_file = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, arg, "--max-connections")) {
            const value = arg_it.next() orelse {
                std.debug.print("Error: --max-connections requires a value\n", .{});
                return error.MissingArgValue;
            };
            args.max_connections = std.fmt.parseInt(usize, value, 10) catch {
                std.debug.print("Error: Invalid max-connections value: {s}\n", .{value});
                return error.InvalidMaxConnections;
            };
        } else if (std.mem.eql(u8, arg, "--enable-tls")) {
            args.enable_tls = true;
        } else if (std.mem.eql(u8, arg, "--disable-tls")) {
            args.enable_tls = false;
        } else if (std.mem.eql(u8, arg, "--enable-auth")) {
            args.enable_auth = true;
        } else if (std.mem.eql(u8, arg, "--disable-auth")) {
            args.enable_auth = false;
        } else if (std.mem.eql(u8, arg, "--validate-only")) {
            args.validate_only = true;
        } else {
            std.debug.print("Unknown argument: {s}\n", .{arg});
            std.debug.print("Use --help for usage information\n", .{});
            return error.UnknownArgument;
        }
    }

    return args;
}

fn parseLogLevel(str: []const u8) !logger.LogLevel {
    if (std.ascii.eqlIgnoreCase(str, "debug")) return .debug;
    if (std.ascii.eqlIgnoreCase(str, "info")) return .info;
    if (std.ascii.eqlIgnoreCase(str, "warn")) return .warn;
    if (std.ascii.eqlIgnoreCase(str, "error")) return .err;
    if (std.ascii.eqlIgnoreCase(str, "critical")) return .critical;
    return error.InvalidLogLevel;
}

pub fn printHelp() void {
    const help_text =
        \\SMTP Server - High-performance SMTP server written in Zig
        \\
        \\USAGE:
        \\    mail [OPTIONS]
        \\
        \\OPTIONS:
        \\    -h, --help              Show this help message
        \\    -v, --version           Show version information
        \\    -c, --config <FILE>     Path to configuration file
        \\    -p, --port <PORT>       Port to listen on (default: 2525)
        \\    --host <HOST>           Host to bind to (default: 0.0.0.0)
        \\    --log-level <LEVEL>     Set log level (debug|info|warn|error|critical)
        \\    --log-file <FILE>       Path to log file (default: mail.log)
        \\    --max-connections <N>   Maximum concurrent connections (default: 100)
        \\    --enable-tls            Enable TLS/STARTTLS support
        \\    --disable-tls           Disable TLS/STARTTLS support
        \\    --enable-auth           Enable SMTP authentication
        \\    --disable-auth          Disable SMTP authentication
        \\    --validate-only         Validate configuration and exit without starting server
        \\
        \\EXAMPLES:
        \\    # Start server on custom port
        \\    mail --port 2525
        \\
        \\    # Enable debug logging
        \\    mail --log-level debug
        \\
        \\    # Use custom config file
        \\    mail --config /etc/smtp/config.json
        \\
        \\    # Limit connections
        \\    mail --max-connections 50
        \\
        \\    # Validate configuration without starting server
        \\    mail --validate-only
        \\
    ;
    std.debug.print("{s}\n", .{help_text});
}

pub fn printVersion() void {
    const info = version_info.getBuildInfo();
    std.debug.print("{s}\n", .{version_info.banner});
    std.debug.print("Built with Zig {s}\n", .{info.zig_version});
    std.debug.print("Build mode: {s}\n", .{info.build_mode});
    std.debug.print("Target: {s}\n", .{info.target});
}
