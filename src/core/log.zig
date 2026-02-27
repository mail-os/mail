const std = @import("std");
const mutex_compat = @import("mutex_compat.zig");
const Allocator = std.mem.Allocator;
const io_compat = @import("io_compat.zig");

/// Centralized Logger for SMTP Server
/// Replaces all std.debug.print with structured, configurable logging

// =============================================================================
// Log Levels
// =============================================================================

pub const Level = enum(u8) {
    trace = 0,
    debug = 1,
    info = 2,
    warn = 3,
    err = 4,
    fatal = 5,

    pub fn toString(self: Level) []const u8 {
        return switch (self) {
            .trace => "TRACE",
            .debug => "DEBUG",
            .info => "INFO",
            .warn => "WARN",
            .err => "ERROR",
            .fatal => "FATAL",
        };
    }

    pub fn toColor(self: Level) []const u8 {
        return switch (self) {
            .trace => "\x1b[90m", // Gray
            .debug => "\x1b[36m", // Cyan
            .info => "\x1b[32m", // Green
            .warn => "\x1b[33m", // Yellow
            .err => "\x1b[31m", // Red
            .fatal => "\x1b[35m", // Magenta
        };
    }
};

// =============================================================================
// Log Format
// =============================================================================

pub const Format = enum {
    /// Human-readable format for development
    text,
    /// JSON format for log aggregation (ELK, Splunk, etc.)
    json,
    /// Compact format for production
    compact,
};

// =============================================================================
// Log Output
// =============================================================================

pub const Output = enum {
    /// Write to stderr (default)
    stderr,
    /// Write to stdout
    stdout,
    /// Write to file
    file,
    /// Write to syslog
    syslog,
    /// Discard all output
    null,
};

// =============================================================================
// Logger Configuration
// =============================================================================

pub const Config = struct {
    /// Minimum level to log
    level: Level = .info,
    /// Output format
    format: Format = .text,
    /// Output destination
    output: Output = .stderr,
    /// Include timestamps
    timestamps: bool = true,
    /// Include source location
    source_location: bool = false,
    /// Include colors (for text format)
    colors: bool = true,
    /// Component name filter (null = all)
    component_filter: ?[]const u8 = null,
    /// Log file path (for file output)
    file_path: ?[]const u8 = null,
    /// Maximum log file size before rotation
    max_file_size: usize = 100 * 1024 * 1024, // 100MB
    /// Number of rotated files to keep
    max_rotated_files: u8 = 5,
};

// =============================================================================
// Logger Instance
// =============================================================================

pub const Logger = struct {
    const Self = @This();

    config: Config,
    file: ?std.Io.File = null,
    mutex: mutex_compat.Mutex = .{},
    allocator: ?Allocator = null,
    file_offset: u64 = 0,

    // Context fields for structured logging
    context: struct {
        component: ?[]const u8 = null,
        session_id: ?[]const u8 = null,
        client_ip: ?[]const u8 = null,
        user: ?[]const u8 = null,
        request_id: ?[]const u8 = null,
    } = .{},

    pub fn init(config: Config) Self {
        var logger = Self{ .config = config };

        if (config.output == .file) {
            if (config.file_path) |path| {
                const io = io_compat.getIo();
                const f = std.Io.Dir.cwd().createFile(io, path, .{ .truncate = false }) catch null;
                logger.file = f;
                if (f) |file| {
                    logger.file_offset = file.length(io) catch 0;
                }
            }
        }

        return logger;
    }

    pub fn deinit(self: *Self) void {
        if (self.file) |f| {
            f.close(io_compat.getIo());
        }
    }

    /// Create a child logger with additional context
    pub fn withComponent(self: *const Self, component: []const u8) Self {
        var child = self.*;
        child.context.component = component;
        return child;
    }

    pub fn withSession(self: *const Self, session_id: []const u8) Self {
        var child = self.*;
        child.context.session_id = session_id;
        return child;
    }

    pub fn withClient(self: *const Self, client_ip: []const u8) Self {
        var child = self.*;
        child.context.client_ip = client_ip;
        return child;
    }

    pub fn withUser(self: *const Self, user: []const u8) Self {
        var child = self.*;
        child.context.user = user;
        return child;
    }

    pub fn withRequestId(self: *const Self, request_id: []const u8) Self {
        var child = self.*;
        child.context.request_id = request_id;
        return child;
    }

    // =============================================================================
    // Logging Methods
    // =============================================================================

    pub fn trace(self: *Self, comptime fmt: []const u8, args: anytype) void {
        self.log(.trace, fmt, args, null);
    }

    pub fn debug(self: *Self, comptime fmt: []const u8, args: anytype) void {
        self.log(.debug, fmt, args, null);
    }

    pub fn info(self: *Self, comptime fmt: []const u8, args: anytype) void {
        self.log(.info, fmt, args, null);
    }

    pub fn warn(self: *Self, comptime fmt: []const u8, args: anytype) void {
        self.log(.warn, fmt, args, null);
    }

    pub fn err(self: *Self, comptime fmt: []const u8, args: anytype) void {
        self.log(.err, fmt, args, null);
    }

    pub fn fatal(self: *Self, comptime fmt: []const u8, args: anytype) void {
        self.log(.fatal, fmt, args, null);
    }

    // With source location
    pub fn traceSrc(self: *Self, comptime fmt: []const u8, args: anytype, src: std.builtin.SourceLocation) void {
        self.log(.trace, fmt, args, src);
    }

    pub fn debugSrc(self: *Self, comptime fmt: []const u8, args: anytype, src: std.builtin.SourceLocation) void {
        self.log(.debug, fmt, args, src);
    }

    pub fn infoSrc(self: *Self, comptime fmt: []const u8, args: anytype, src: std.builtin.SourceLocation) void {
        self.log(.info, fmt, args, src);
    }

    pub fn warnSrc(self: *Self, comptime fmt: []const u8, args: anytype, src: std.builtin.SourceLocation) void {
        self.log(.warn, fmt, args, src);
    }

    pub fn errSrc(self: *Self, comptime fmt: []const u8, args: anytype, src: std.builtin.SourceLocation) void {
        self.log(.err, fmt, args, src);
    }

    pub fn fatalSrc(self: *Self, comptime fmt: []const u8, args: anytype, src: std.builtin.SourceLocation) void {
        self.log(.fatal, fmt, args, src);
    }

    // =============================================================================
    // Core Logging Implementation
    // =============================================================================

    fn log(self: *Self, level: Level, comptime fmt: []const u8, args: anytype, src: ?std.builtin.SourceLocation) void {
        // Check level filter
        if (@intFromEnum(level) < @intFromEnum(self.config.level)) return;

        // Check component filter
        if (self.config.component_filter) |filter| {
            if (self.context.component) |comp| {
                if (!std.mem.eql(u8, comp, filter)) return;
            } else {
                return;
            }
        }

        // Skip if output is null
        if (self.config.output == .null) return;

        self.mutex.lock();
        defer self.mutex.unlock();

        var buf: [4096]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();

        switch (self.config.format) {
            .text => self.formatText(writer, level, fmt, args, src) catch return,
            .json => self.formatJson(writer, level, fmt, args, src) catch return,
            .compact => self.formatCompact(writer, level, fmt, args, src) catch return,
        }

        const output = fbs.getWritten();
        self.writeOutput(output);
    }

    fn formatText(
        self: *const Self,
        writer: anytype,
        level: Level,
        comptime fmt: []const u8,
        args: anytype,
        src: ?std.builtin.SourceLocation,
    ) !void {
        const reset = "\x1b[0m";

        // Timestamp
        if (self.config.timestamps) {
            const ts = std.time.timestamp();
            const secs: u64 = @intCast(@mod(ts, 86400));
            const hours = secs / 3600;
            const mins = (secs % 3600) / 60;
            const seconds = secs % 60;
            try writer.print("{d:0>2}:{d:0>2}:{d:0>2} ", .{ hours, mins, seconds });
        }

        // Level with color
        if (self.config.colors) {
            try writer.print("{s}[{s}]{s} ", .{ level.toColor(), level.toString(), reset });
        } else {
            try writer.print("[{s}] ", .{level.toString()});
        }

        // Component
        if (self.context.component) |comp| {
            if (self.config.colors) {
                try writer.print("\x1b[34m[{s}]{s} ", .{ comp, reset });
            } else {
                try writer.print("[{s}] ", .{comp});
            }
        }

        // Message
        try writer.print(fmt, args);

        // Context fields
        if (self.context.session_id) |sid| {
            try writer.print(" session={s}", .{sid});
        }
        if (self.context.client_ip) |ip| {
            try writer.print(" client={s}", .{ip});
        }
        if (self.context.user) |u| {
            try writer.print(" user={s}", .{u});
        }
        if (self.context.request_id) |rid| {
            try writer.print(" request_id={s}", .{rid});
        }

        // Source location
        if (self.config.source_location) {
            if (src) |s| {
                try writer.print(" at {s}:{d}", .{ s.file, s.line });
            }
        }

        try writer.writeByte('\n');
    }

    fn formatJson(
        self: *const Self,
        writer: anytype,
        level: Level,
        comptime fmt: []const u8,
        args: anytype,
        src: ?std.builtin.SourceLocation,
    ) !void {
        try writer.writeAll("{");

        // Timestamp
        if (self.config.timestamps) {
            try writer.print("\"timestamp\":{d},", .{std.time.timestamp()});
        }

        // Level
        try writer.print("\"level\":\"{s}\",", .{level.toString()});

        // Component
        if (self.context.component) |comp| {
            try writer.print("\"component\":\"{s}\",", .{comp});
        }

        // Message
        try writer.writeAll("\"message\":\"");
        // Escape the formatted message
        var msg_buf: [2048]u8 = undefined;
        var msg_fbs = io_compat.fixedBufferStream(&msg_buf);
        try msg_fbs.writer().print(fmt, args);
        const msg = msg_fbs.getWritten();
        for (msg) |c| {
            switch (c) {
                '"' => try writer.writeAll("\\\""),
                '\\' => try writer.writeAll("\\\\"),
                '\n' => try writer.writeAll("\\n"),
                '\r' => try writer.writeAll("\\r"),
                '\t' => try writer.writeAll("\\t"),
                else => try writer.writeByte(c),
            }
        }
        try writer.writeAll("\"");

        // Context
        if (self.context.session_id) |sid| {
            try writer.print(",\"session_id\":\"{s}\"", .{sid});
        }
        if (self.context.client_ip) |ip| {
            try writer.print(",\"client_ip\":\"{s}\"", .{ip});
        }
        if (self.context.user) |u| {
            try writer.print(",\"user\":\"{s}\"", .{u});
        }
        if (self.context.request_id) |rid| {
            try writer.print(",\"request_id\":\"{s}\"", .{rid});
        }

        // Source
        if (self.config.source_location) {
            if (src) |s| {
                try writer.print(",\"file\":\"{s}\",\"line\":{d}", .{ s.file, s.line });
            }
        }

        try writer.writeAll("}\n");
    }

    fn formatCompact(
        self: *const Self,
        writer: anytype,
        level: Level,
        comptime fmt: []const u8,
        args: anytype,
        src: ?std.builtin.SourceLocation,
    ) !void {
        _ = src;

        // Level initial
        const level_char: u8 = switch (level) {
            .trace => 'T',
            .debug => 'D',
            .info => 'I',
            .warn => 'W',
            .err => 'E',
            .fatal => 'F',
        };
        try writer.writeByte(level_char);
        try writer.writeByte(' ');

        // Timestamp (compact)
        if (self.config.timestamps) {
            const ts = std.time.timestamp();
            const secs: u64 = @intCast(@mod(ts, 86400));
            try writer.print("{d:0>5} ", .{secs});
        }

        // Component (short)
        if (self.context.component) |comp| {
            const short = if (comp.len > 8) comp[0..8] else comp;
            try writer.print("{s}: ", .{short});
        }

        // Message
        try writer.print(fmt, args);
        try writer.writeByte('\n');
    }

    fn writeOutput(self: *Self, data: []const u8) void {
        switch (self.config.output) {
            .stderr => {
                _ = std.c.write(2, data.ptr, data.len);
            },
            .stdout => {
                _ = std.c.write(1, data.ptr, data.len);
            },
            .file => {
                if (self.file) |f| {
                    f.writePositionalAll(io_compat.getIo(), data, self.file_offset) catch {};
                    self.file_offset += data.len;
                }
            },
            .syslog => {
                // Syslog implementation would go here
                _ = std.c.write(2, data.ptr, data.len);
            },
            .null => {},
        }
    }
};

// =============================================================================
// Global Logger Instance
// =============================================================================

var global_logger: ?Logger = null;
var global_mutex: mutex_compat.Mutex = .{};

pub fn initGlobal(config: Config) void {
    global_mutex.lock();
    defer global_mutex.unlock();

    if (global_logger) |*logger| {
        logger.deinit();
    }
    global_logger = Logger.init(config);
}

pub fn deinitGlobal() void {
    global_mutex.lock();
    defer global_mutex.unlock();

    if (global_logger) |*logger| {
        logger.deinit();
        global_logger = null;
    }
}

pub fn getGlobal() *Logger {
    global_mutex.lock();
    defer global_mutex.unlock();

    if (global_logger == null) {
        global_logger = Logger.init(.{});
    }
    return &global_logger.?;
}

// =============================================================================
// Convenience Functions (replace std.debug.print)
// =============================================================================

pub fn trace(comptime fmt: []const u8, args: anytype) void {
    getGlobal().trace(fmt, args);
}

pub fn debug(comptime fmt: []const u8, args: anytype) void {
    getGlobal().debug(fmt, args);
}

pub fn info(comptime fmt: []const u8, args: anytype) void {
    getGlobal().info(fmt, args);
}

pub fn warn(comptime fmt: []const u8, args: anytype) void {
    getGlobal().warn(fmt, args);
}

pub fn err(comptime fmt: []const u8, args: anytype) void {
    getGlobal().err(fmt, args);
}

pub fn fatal(comptime fmt: []const u8, args: anytype) void {
    getGlobal().fatal(fmt, args);
}

// =============================================================================
// Scoped Logger - Component-specific logging
// =============================================================================

pub fn scoped(comptime component: []const u8) type {
    return struct {
        pub fn trace(comptime fmt: []const u8, args: anytype) void {
            var logger = getGlobal().withComponent(component);
            logger.trace(fmt, args);
        }

        pub fn debug(comptime fmt: []const u8, args: anytype) void {
            var logger = getGlobal().withComponent(component);
            logger.debug(fmt, args);
        }

        pub fn info(comptime fmt: []const u8, args: anytype) void {
            var logger = getGlobal().withComponent(component);
            logger.info(fmt, args);
        }

        pub fn warn(comptime fmt: []const u8, args: anytype) void {
            var logger = getGlobal().withComponent(component);
            logger.warn(fmt, args);
        }

        pub fn err(comptime fmt: []const u8, args: anytype) void {
            var logger = getGlobal().withComponent(component);
            logger.err(fmt, args);
        }

        pub fn fatal(comptime fmt: []const u8, args: anytype) void {
            var logger = getGlobal().withComponent(component);
            logger.fatal(fmt, args);
        }
    };
}

// =============================================================================
// Migration Helper - Drop-in replacement for std.debug.print
// =============================================================================

/// Drop-in replacement for std.debug.print
/// Usage: const print = @import("log.zig").print;
pub fn print(comptime fmt: []const u8, args: anytype) void {
    debug(fmt, args);
}

// =============================================================================
// Tests
// =============================================================================

test "Logger levels" {
    var logger = Logger.init(.{
        .level = .warn,
        .output = .null,
    });
    defer logger.deinit();

    // These should be filtered out
    logger.trace("trace message", .{});
    logger.debug("debug message", .{});
    logger.info("info message", .{});

    // These should be logged (but output is null)
    logger.warn("warn message", .{});
    logger.err("error message", .{});
}

test "Logger with context" {
    var logger = Logger.init(.{
        .output = .null,
    });
    defer logger.deinit();

    var ctx_logger = logger.withComponent("smtp").withSession("abc123").withClient("192.168.1.1");
    ctx_logger.info("test message", .{});
}

test "Scoped logger" {
    initGlobal(.{ .output = .null });
    defer deinitGlobal();

    const smtp_log = scoped("smtp");
    smtp_log.info("connection established", .{});
}

test "JSON format" {
    var logger = Logger.init(.{
        .format = .json,
        .output = .null,
        .timestamps = false,
    });
    defer logger.deinit();

    logger.info("test message with \"quotes\"", .{});
}

test "Compact format" {
    var logger = Logger.init(.{
        .format = .compact,
        .output = .null,
    });
    defer logger.deinit();

    logger.info("compact test", .{});
}

test "Global logger" {
    initGlobal(.{ .output = .null });
    defer deinitGlobal();

    info("global info: {d}", .{42});
    warn("global warning: {s}", .{"test"});
}
