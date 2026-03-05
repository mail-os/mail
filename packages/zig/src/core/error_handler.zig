const std = @import("std");
const Allocator = std.mem.Allocator;
const io_compat = @import("io_compat.zig");

/// Centralized Error Handling for SMTP Server
/// Provides consistent error handling, logging, recovery, and reporting

// =============================================================================
// Error Categories
// =============================================================================

pub const ErrorCategory = enum {
    /// Network-related errors (connection, timeout, DNS)
    network,
    /// Protocol errors (invalid commands, malformed data)
    protocol,
    /// Authentication/authorization failures
    auth,
    /// Storage errors (disk, database)
    storage,
    /// Resource exhaustion (memory, connections, queue)
    resource,
    /// Configuration errors
    config,
    /// Security violations
    security,
    /// Internal/programming errors
    internal,
    /// External service errors (ClamAV, SpamAssassin)
    external,
    /// Unknown/uncategorized
    unknown,
};

pub const ErrorSeverity = enum {
    /// Debug information, not a real error
    debug,
    /// Informational, expected condition
    info,
    /// Warning, degraded but functional
    warning,
    /// Error, operation failed
    err,
    /// Critical, service degraded
    critical,
    /// Fatal, service must stop
    fatal,

    pub fn toLogLevel(self: ErrorSeverity) std.log.Level {
        return switch (self) {
            .debug => .debug,
            .info => .info,
            .warning => .warn,
            .err => .err,
            .critical => .err,
            .fatal => .err,
        };
    }
};

// =============================================================================
// Error Context
// =============================================================================

pub const ErrorContext = struct {
    const Self = @This();

    /// Error category for routing and handling
    category: ErrorCategory = .unknown,

    /// Severity level
    severity: ErrorSeverity = .err,

    /// Source location
    source_file: ?[]const u8 = null,
    source_line: ?u32 = null,
    source_fn: ?[]const u8 = null,

    /// Operation context
    operation: ?[]const u8 = null,
    component: ?[]const u8 = null,

    /// Request context
    session_id: ?[]const u8 = null,
    client_ip: ?[]const u8 = null,
    user: ?[]const u8 = null,

    /// Error details
    message: ?[]const u8 = null,
    underlying_error: ?anyerror = null,

    /// Timing
    timestamp: i64 = 0,
    duration_ns: ?u64 = null,

    /// Recovery information
    is_retryable: bool = false,
    retry_after_ms: ?u64 = null,
    recovery_action: ?RecoveryAction = null,

    pub const RecoveryAction = enum {
        none,
        retry,
        reconnect,
        skip,
        rollback,
        failover,
        restart,
        alert,
    };

    pub fn init() Self {
        return Self{
            .timestamp = std.time.timestamp(),
        };
    }

    pub fn withCategory(self: Self, category: ErrorCategory) Self {
        var ctx = self;
        ctx.category = category;
        return ctx;
    }

    pub fn withSeverity(self: Self, severity: ErrorSeverity) Self {
        var ctx = self;
        ctx.severity = severity;
        return ctx;
    }

    pub fn withSource(self: Self, src: std.builtin.SourceLocation) Self {
        var ctx = self;
        ctx.source_file = src.file;
        ctx.source_line = src.line;
        ctx.source_fn = src.fn_name;
        return ctx;
    }

    pub fn withOperation(self: Self, operation: []const u8) Self {
        var ctx = self;
        ctx.operation = operation;
        return ctx;
    }

    pub fn withComponent(self: Self, component: []const u8) Self {
        var ctx = self;
        ctx.component = component;
        return ctx;
    }

    pub fn withSession(self: Self, session_id: []const u8) Self {
        var ctx = self;
        ctx.session_id = session_id;
        return ctx;
    }

    pub fn withClient(self: Self, client_ip: []const u8) Self {
        var ctx = self;
        ctx.client_ip = client_ip;
        return ctx;
    }

    pub fn withUser(self: Self, user: []const u8) Self {
        var ctx = self;
        ctx.user = user;
        return ctx;
    }

    pub fn withMessage(self: Self, message: []const u8) Self {
        var ctx = self;
        ctx.message = message;
        return ctx;
    }

    pub fn withError(self: Self, err: anyerror) Self {
        var ctx = self;
        ctx.underlying_error = err;
        return ctx;
    }

    pub fn withRetry(self: Self, after_ms: u64) Self {
        var ctx = self;
        ctx.is_retryable = true;
        ctx.retry_after_ms = after_ms;
        ctx.recovery_action = .retry;
        return ctx;
    }

    pub fn withRecovery(self: Self, action: RecoveryAction) Self {
        var ctx = self;
        ctx.recovery_action = action;
        return ctx;
    }

    pub fn withDuration(self: Self, duration_ns: u64) Self {
        var ctx = self;
        ctx.duration_ns = duration_ns;
        return ctx;
    }
};

// =============================================================================
// Error Handler
// =============================================================================

pub const ErrorHandler = struct {
    const Self = @This();

    allocator: Allocator,
    config: Config,
    hooks: std.ArrayList(ErrorHook),
    metrics: ErrorMetrics,
    recent_errors: RingBuffer,

    pub const Config = struct {
        /// Maximum errors to keep in recent buffer
        max_recent_errors: u32 = 100,
        /// Enable stack traces for debug builds
        capture_stack_traces: bool = true,
        /// Log all errors
        log_all_errors: bool = true,
        /// Alert threshold for error rate
        alert_threshold_per_minute: u32 = 100,
        /// Categories to suppress logging
        suppressed_categories: []const ErrorCategory = &[_]ErrorCategory{},
        /// Minimum severity to log
        min_log_severity: ErrorSeverity = .info,
    };

    pub const ErrorHook = *const fn (ctx: ErrorContext) void;

    const RingBuffer = struct {
        entries: []ErrorEntry,
        write_pos: usize = 0,
        count: usize = 0,

        const ErrorEntry = struct {
            context: ErrorContext,
            allocated_message: ?[]u8 = null,
        };

        fn init(allocator: Allocator, capacity: usize) !RingBuffer {
            return RingBuffer{
                .entries = try allocator.alloc(ErrorEntry, capacity),
            };
        }

        fn deinit(self: *RingBuffer, allocator: Allocator) void {
            for (self.entries) |*entry| {
                if (entry.allocated_message) |msg| {
                    allocator.free(msg);
                }
            }
            allocator.free(self.entries);
        }

        fn push(self: *RingBuffer, entry: ErrorEntry) void {
            self.entries[self.write_pos] = entry;
            self.write_pos = (self.write_pos + 1) % self.entries.len;
            if (self.count < self.entries.len) {
                self.count += 1;
            }
        }
    };

    pub fn init(allocator: Allocator, config: Config) !Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .hooks = std.ArrayList(ErrorHook).init(allocator),
            .metrics = ErrorMetrics.init(),
            .recent_errors = try RingBuffer.init(allocator, config.max_recent_errors),
        };
    }

    pub fn deinit(self: *Self) void {
        self.recent_errors.deinit(self.allocator);
        self.hooks.deinit();
    }

    /// Register an error hook
    pub fn addHook(self: *Self, hook: ErrorHook) !void {
        try self.hooks.append(hook);
    }

    /// Handle an error with full context
    pub fn handle(self: *Self, ctx: ErrorContext) void {
        // Update metrics
        self.metrics.record(ctx);

        // Check suppression
        for (self.config.suppressed_categories) |cat| {
            if (cat == ctx.category) return;
        }

        // Check severity
        if (@intFromEnum(ctx.severity) < @intFromEnum(self.config.min_log_severity)) return;

        // Log the error
        if (self.config.log_all_errors) {
            self.logError(ctx);
        }

        // Store in recent buffer
        self.recent_errors.push(.{ .context = ctx });

        // Call hooks
        for (self.hooks.items) |hook| {
            hook(ctx);
        }
    }

    /// Quick error handling with minimal context
    pub fn handleError(self: *Self, err: anyerror, src: std.builtin.SourceLocation) void {
        const ctx = ErrorContext.init()
            .withError(err)
            .withSource(src)
            .withCategory(categorizeError(err))
            .withSeverity(severityForError(err));
        self.handle(ctx);
    }

    /// Handle error with operation context
    pub fn handleOperationError(
        self: *Self,
        err: anyerror,
        operation: []const u8,
        component: []const u8,
        src: std.builtin.SourceLocation,
    ) void {
        const ctx = ErrorContext.init()
            .withError(err)
            .withSource(src)
            .withOperation(operation)
            .withComponent(component)
            .withCategory(categorizeError(err))
            .withSeverity(severityForError(err));
        self.handle(ctx);
    }

    /// Get error metrics
    pub fn getMetrics(self: *const Self) ErrorMetrics {
        return self.metrics;
    }

    /// Reset error metrics
    pub fn resetMetrics(self: *Self) void {
        self.metrics = ErrorMetrics.init();
    }

    fn logError(self: *Self, ctx: ErrorContext) void {
        _ = self;
        const level = ctx.severity.toLogLevel();

        // Build log message
        var buf: [1024]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();

        writer.print("[{s}] ", .{@tagName(ctx.category)}) catch {};

        if (ctx.component) |comp| {
            writer.print("{s}: ", .{comp}) catch {};
        }

        if (ctx.operation) |op| {
            writer.print("{s} - ", .{op}) catch {};
        }

        if (ctx.message) |msg| {
            writer.print("{s}", .{msg}) catch {};
        } else if (ctx.underlying_error) |err| {
            writer.print("{s}", .{@errorName(err)}) catch {};
        }

        if (ctx.session_id) |sid| {
            writer.print(" [session={s}]", .{sid}) catch {};
        }

        if (ctx.client_ip) |ip| {
            writer.print(" [client={s}]", .{ip}) catch {};
        }

        if (ctx.source_file) |file| {
            writer.print(" at {s}:{d}", .{ file, ctx.source_line orelse 0 }) catch {};
        }

        const message = fbs.getWritten();
        std.log.scoped(.error_handler).log(level, "{s}", .{message});
    }

    fn categorizeError(err: anyerror) ErrorCategory {
        const error_name = @errorName(err);

        // Network errors
        if (std.mem.indexOf(u8, error_name, "Connection") != null or
            std.mem.indexOf(u8, error_name, "Socket") != null or
            std.mem.indexOf(u8, error_name, "Network") != null or
            std.mem.indexOf(u8, error_name, "Timeout") != null or
            std.mem.indexOf(u8, error_name, "DNS") != null)
        {
            return .network;
        }

        // Auth errors
        if (std.mem.indexOf(u8, error_name, "Auth") != null or
            std.mem.indexOf(u8, error_name, "Permission") != null or
            std.mem.indexOf(u8, error_name, "Access") != null)
        {
            return .auth;
        }

        // Storage errors
        if (std.mem.indexOf(u8, error_name, "File") != null or
            std.mem.indexOf(u8, error_name, "Disk") != null or
            std.mem.indexOf(u8, error_name, "Storage") != null or
            std.mem.indexOf(u8, error_name, "Database") != null)
        {
            return .storage;
        }

        // Resource errors
        if (std.mem.indexOf(u8, error_name, "OutOf") != null or
            std.mem.indexOf(u8, error_name, "Exhausted") != null or
            std.mem.indexOf(u8, error_name, "Limit") != null)
        {
            return .resource;
        }

        // Security errors
        if (std.mem.indexOf(u8, error_name, "Security") != null or
            std.mem.indexOf(u8, error_name, "Injection") != null or
            std.mem.indexOf(u8, error_name, "Traversal") != null)
        {
            return .security;
        }

        return .unknown;
    }

    fn severityForError(err: anyerror) ErrorSeverity {
        const error_name = @errorName(err);

        // Critical errors
        if (std.mem.indexOf(u8, error_name, "OutOfMemory") != null or
            std.mem.indexOf(u8, error_name, "Corrupt") != null)
        {
            return .critical;
        }

        // Security violations are high severity
        if (std.mem.indexOf(u8, error_name, "Security") != null or
            std.mem.indexOf(u8, error_name, "Injection") != null)
        {
            return .critical;
        }

        // Auth failures are warnings (expected)
        if (std.mem.indexOf(u8, error_name, "Auth") != null) {
            return .warning;
        }

        return .err;
    }
};

// =============================================================================
// Error Metrics
// =============================================================================

pub const ErrorMetrics = struct {
    const Self = @This();

    total_errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    errors_by_category: [std.meta.fields(ErrorCategory).len]std.atomic.Value(u64) = init: {
        var arr: [std.meta.fields(ErrorCategory).len]std.atomic.Value(u64) = undefined;
        for (&arr) |*v| {
            v.* = std.atomic.Value(u64).init(0);
        }
        break :init arr;
    },
    errors_by_severity: [std.meta.fields(ErrorSeverity).len]std.atomic.Value(u64) = init: {
        var arr: [std.meta.fields(ErrorSeverity).len]std.atomic.Value(u64) = undefined;
        for (&arr) |*v| {
            v.* = std.atomic.Value(u64).init(0);
        }
        break :init arr;
    },
    last_error_time: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),
    retryable_errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn init() Self {
        return Self{};
    }

    pub fn record(self: *Self, ctx: ErrorContext) void {
        _ = self.total_errors.fetchAdd(1, .monotonic);
        _ = self.errors_by_category[@intFromEnum(ctx.category)].fetchAdd(1, .monotonic);
        _ = self.errors_by_severity[@intFromEnum(ctx.severity)].fetchAdd(1, .monotonic);
        self.last_error_time.store(ctx.timestamp, .monotonic);

        if (ctx.is_retryable) {
            _ = self.retryable_errors.fetchAdd(1, .monotonic);
        }
    }

    pub fn getTotalErrors(self: *const Self) u64 {
        return self.total_errors.load(.monotonic);
    }

    pub fn getErrorsByCategory(self: *const Self, category: ErrorCategory) u64 {
        return self.errors_by_category[@intFromEnum(category)].load(.monotonic);
    }

    pub fn getErrorsBySeverity(self: *const Self, severity: ErrorSeverity) u64 {
        return self.errors_by_severity[@intFromEnum(severity)].load(.monotonic);
    }

    pub fn getCriticalErrors(self: *const Self) u64 {
        return self.getErrorsBySeverity(.critical) + self.getErrorsBySeverity(.fatal);
    }
};

// =============================================================================
// Error Builder - Fluent API for creating errors
// =============================================================================

pub const ErrorBuilder = struct {
    const Self = @This();

    handler: *ErrorHandler,
    context: ErrorContext,

    pub fn init(handler: *ErrorHandler) Self {
        return Self{
            .handler = handler,
            .context = ErrorContext.init(),
        };
    }

    pub fn category(self: Self, cat: ErrorCategory) Self {
        var builder = self;
        builder.context = builder.context.withCategory(cat);
        return builder;
    }

    pub fn severity(self: Self, sev: ErrorSeverity) Self {
        var builder = self;
        builder.context = builder.context.withSeverity(sev);
        return builder;
    }

    pub fn source(self: Self, src: std.builtin.SourceLocation) Self {
        var builder = self;
        builder.context = builder.context.withSource(src);
        return builder;
    }

    pub fn operation(self: Self, op: []const u8) Self {
        var builder = self;
        builder.context = builder.context.withOperation(op);
        return builder;
    }

    pub fn component(self: Self, comp: []const u8) Self {
        var builder = self;
        builder.context = builder.context.withComponent(comp);
        return builder;
    }

    pub fn session(self: Self, sid: []const u8) Self {
        var builder = self;
        builder.context = builder.context.withSession(sid);
        return builder;
    }

    pub fn client(self: Self, ip: []const u8) Self {
        var builder = self;
        builder.context = builder.context.withClient(ip);
        return builder;
    }

    pub fn user(self: Self, usr: []const u8) Self {
        var builder = self;
        builder.context = builder.context.withUser(usr);
        return builder;
    }

    pub fn message(self: Self, msg: []const u8) Self {
        var builder = self;
        builder.context = builder.context.withMessage(msg);
        return builder;
    }

    pub fn err(self: Self, e: anyerror) Self {
        var builder = self;
        builder.context = builder.context.withError(e);
        return builder;
    }

    pub fn retryable(self: Self, after_ms: u64) Self {
        var builder = self;
        builder.context = builder.context.withRetry(after_ms);
        return builder;
    }

    pub fn recovery(self: Self, action: ErrorContext.RecoveryAction) Self {
        var builder = self;
        builder.context = builder.context.withRecovery(action);
        return builder;
    }

    pub fn emit(self: Self) void {
        self.handler.handle(self.context);
    }

    pub fn emitAndReturn(self: Self, e: anyerror) anyerror {
        self.handler.handle(self.context);
        return e;
    }
};

// =============================================================================
// Result Type with Error Context
// =============================================================================

pub fn Result(comptime T: type) type {
    return union(enum) {
        ok: T,
        err: struct {
            error_value: anyerror,
            context: ErrorContext,
        },

        const Self = @This();

        pub fn success(value: T) Self {
            return Self{ .ok = value };
        }

        pub fn failure(e: anyerror, ctx: ErrorContext) Self {
            return Self{ .err = .{ .error_value = e, .context = ctx } };
        }

        pub fn isOk(self: Self) bool {
            return self == .ok;
        }

        pub fn isErr(self: Self) bool {
            return self == .err;
        }

        pub fn unwrap(self: Self) !T {
            switch (self) {
                .ok => |value| return value,
                .err => |e| return e.error_value,
            }
        }

        pub fn unwrapOr(self: Self, default: T) T {
            return switch (self) {
                .ok => |value| value,
                .err => default,
            };
        }

        pub fn map(self: Self, comptime f: fn (T) T) Self {
            return switch (self) {
                .ok => |value| Self{ .ok = f(value) },
                .err => self,
            };
        }

        pub fn getError(self: Self) ?anyerror {
            return switch (self) {
                .ok => null,
                .err => |e| e.error_value,
            };
        }

        pub fn getContext(self: Self) ?ErrorContext {
            return switch (self) {
                .ok => null,
                .err => |e| e.context,
            };
        }
    };
}

// =============================================================================
// Retry Helper
// =============================================================================

pub const RetryConfig = struct {
    max_attempts: u32 = 3,
    initial_delay_ms: u64 = 100,
    max_delay_ms: u64 = 10000,
    multiplier: f64 = 2.0,
    jitter: bool = true,
};

pub fn retry(
    comptime T: type,
    config: RetryConfig,
    handler: *ErrorHandler,
    operation: []const u8,
    f: *const fn () anyerror!T,
) anyerror!T {
    var delay_ms = config.initial_delay_ms;
    var attempts: u32 = 0;

    while (attempts < config.max_attempts) : (attempts += 1) {
        if (f()) |result| {
            return result;
        } else |err| {
            const is_last = attempts + 1 >= config.max_attempts;

            handler.handle(ErrorContext.init()
                .withError(err)
                .withOperation(operation)
                .withMessage(if (is_last) "max retries exceeded" else "retrying")
                .withSeverity(if (is_last) .err else .warning)
                .withRetry(delay_ms));

            if (is_last) {
                return err;
            }

            // Sleep before retry
            std.time.sleep(delay_ms * std.time.ns_per_ms);

            // Exponential backoff
            const new_delay: u64 = @intFromFloat(@as(f64, @floatFromInt(delay_ms)) * config.multiplier);
            delay_ms = @min(new_delay, config.max_delay_ms);
        }
    }

    return error.MaxRetriesExceeded;
}

// =============================================================================
// Convenience Functions
// =============================================================================

/// Create a new error builder
pub fn newError(handler: *ErrorHandler) ErrorBuilder {
    return ErrorBuilder.init(handler);
}

/// Quick network error
pub fn networkError(handler: *ErrorHandler, err: anyerror, op: []const u8, src: std.builtin.SourceLocation) void {
    newError(handler)
        .category(.network)
        .severity(.err)
        .err(err)
        .operation(op)
        .source(src)
        .retryable(1000)
        .emit();
}

/// Quick auth error
pub fn authError(handler: *ErrorHandler, user_id: []const u8, reason: []const u8, src: std.builtin.SourceLocation) void {
    newError(handler)
        .category(.auth)
        .severity(.warning)
        .user(user_id)
        .message(reason)
        .source(src)
        .emit();
}

/// Quick security error
pub fn securityError(handler: *ErrorHandler, client_ip: []const u8, reason: []const u8, src: std.builtin.SourceLocation) void {
    newError(handler)
        .category(.security)
        .severity(.critical)
        .client(client_ip)
        .message(reason)
        .source(src)
        .recovery(.alert)
        .emit();
}

// =============================================================================
// Tests
// =============================================================================

test "ErrorContext builder" {
    const ctx = ErrorContext.init()
        .withCategory(.network)
        .withSeverity(.err)
        .withOperation("connect")
        .withComponent("smtp")
        .withClient("192.168.1.1");

    try std.testing.expectEqual(ErrorCategory.network, ctx.category);
    try std.testing.expectEqual(ErrorSeverity.err, ctx.severity);
    try std.testing.expectEqualStrings("connect", ctx.operation.?);
    try std.testing.expectEqualStrings("smtp", ctx.component.?);
    try std.testing.expectEqualStrings("192.168.1.1", ctx.client_ip.?);
}

test "ErrorHandler basic usage" {
    var handler = try ErrorHandler.init(std.testing.allocator, .{});
    defer handler.deinit();

    handler.handleError(error.OutOfMemory, @src());

    const metrics = handler.getMetrics();
    try std.testing.expectEqual(@as(u64, 1), metrics.getTotalErrors());
}

test "ErrorMetrics recording" {
    var metrics = ErrorMetrics.init();

    metrics.record(ErrorContext.init().withCategory(.network).withSeverity(.err));
    metrics.record(ErrorContext.init().withCategory(.network).withSeverity(.warning));
    metrics.record(ErrorContext.init().withCategory(.auth).withSeverity(.warning));

    try std.testing.expectEqual(@as(u64, 3), metrics.getTotalErrors());
    try std.testing.expectEqual(@as(u64, 2), metrics.getErrorsByCategory(.network));
    try std.testing.expectEqual(@as(u64, 1), metrics.getErrorsByCategory(.auth));
}

test "ErrorBuilder fluent API" {
    var handler = try ErrorHandler.init(std.testing.allocator, .{});
    defer handler.deinit();

    ErrorBuilder.init(&handler)
        .category(.protocol)
        .severity(.warning)
        .operation("MAIL FROM")
        .component("smtp")
        .message("invalid sender")
        .emit();

    try std.testing.expectEqual(@as(u64, 1), handler.getMetrics().getTotalErrors());
}

test "Result type" {
    const success_result = Result(u32).success(42);
    try std.testing.expect(success_result.isOk());
    try std.testing.expectEqual(@as(u32, 42), try success_result.unwrap());

    const fail_result = Result(u32).failure(error.InvalidInput, ErrorContext.init());
    try std.testing.expect(fail_result.isErr());
    try std.testing.expectEqual(@as(u32, 0), fail_result.unwrapOr(0));
}
