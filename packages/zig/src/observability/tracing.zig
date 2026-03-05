const std = @import("std");
const io_compat = @import("../core/io_compat.zig");
const logger = @import("../core/logger.zig");

/// OpenTelemetry trace context
pub const TraceContext = struct {
    trace_id: [16]u8,
    span_id: [8]u8,
    trace_flags: u8,
    allocator: std.mem.Allocator,
    parent_span_id: ?[8]u8,

    pub fn init(allocator: std.mem.Allocator) !TraceContext {
        var trace_id: [16]u8 = undefined;
        var span_id: [8]u8 = undefined;

        // Generate random trace and span IDs
        io_compat.randomBytes(&trace_id);
        io_compat.randomBytes(&span_id);

        return .{
            .trace_id = trace_id,
            .span_id = span_id,
            .trace_flags = 0x01, // Sampled
            .allocator = allocator,
            .parent_span_id = null,
        };
    }

    pub fn initWithParent(allocator: std.mem.Allocator, parent: *const TraceContext) !TraceContext {
        var span_id: [8]u8 = undefined;
        io_compat.randomBytes(&span_id);

        return .{
            .trace_id = parent.trace_id,
            .span_id = span_id,
            .trace_flags = parent.trace_flags,
            .allocator = allocator,
            .parent_span_id = parent.span_id,
        };
    }

    /// Format trace ID as hex string
    pub fn traceIdHex(self: *const TraceContext, allocator: std.mem.Allocator) ![]const u8 {
        return try std.fmt.allocPrint(allocator, "{x}", .{std.fmt.fmtSliceHexLower(&self.trace_id)});
    }

    /// Format span ID as hex string
    pub fn spanIdHex(self: *const TraceContext, allocator: std.mem.Allocator) ![]const u8 {
        return try std.fmt.allocPrint(allocator, "{x}", .{std.fmt.fmtSliceHexLower(&self.span_id)});
    }

    /// Parse W3C traceparent header
    pub fn fromTraceparent(allocator: std.mem.Allocator, traceparent: []const u8) !TraceContext {
        // Format: 00-trace_id-span_id-trace_flags
        var it = std.mem.split(u8, traceparent, "-");

        const version = it.next() orelse return error.InvalidTraceparent;
        if (!std.mem.eql(u8, version, "00")) return error.UnsupportedVersion;

        const trace_id_str = it.next() orelse return error.InvalidTraceparent;
        const span_id_str = it.next() orelse return error.InvalidTraceparent;
        const flags_str = it.next() orelse return error.InvalidTraceparent;

        var trace_id: [16]u8 = undefined;
        var span_id: [8]u8 = undefined;

        _ = try std.fmt.hexToBytes(&trace_id, trace_id_str);
        _ = try std.fmt.hexToBytes(&span_id, span_id_str);
        const trace_flags = try std.fmt.parseInt(u8, flags_str, 16);

        return .{
            .trace_id = trace_id,
            .span_id = span_id,
            .trace_flags = trace_flags,
            .allocator = allocator,
            .parent_span_id = null,
        };
    }

    /// Generate W3C traceparent header
    pub fn toTraceparent(self: *const TraceContext, allocator: std.mem.Allocator) ![]const u8 {
        var trace_id_hex: [32]u8 = undefined;
        var span_id_hex: [16]u8 = undefined;

        _ = std.fmt.bufPrint(&trace_id_hex, "{x}", .{std.fmt.fmtSliceHexLower(&self.trace_id)}) catch |err| {
            std.debug.panic("Failed to format trace ID: {}", .{err});
        };
        _ = std.fmt.bufPrint(&span_id_hex, "{x}", .{std.fmt.fmtSliceHexLower(&self.span_id)}) catch |err| {
            std.debug.panic("Failed to format span ID: {}", .{err});
        };

        return try std.fmt.allocPrint(
            allocator,
            "00-{s}-{s}-{x:0>2}",
            .{ trace_id_hex, span_id_hex, self.trace_flags },
        );
    }
};

/// Span kind enumeration
pub const SpanKind = enum {
    internal,
    server,
    client,
    producer,
    consumer,

    pub fn toString(self: SpanKind) []const u8 {
        return switch (self) {
            .internal => "INTERNAL",
            .server => "SERVER",
            .client => "CLIENT",
            .producer => "PRODUCER",
            .consumer => "CONSUMER",
        };
    }
};

/// Span status
pub const SpanStatus = enum {
    unset,
    ok,
    @"error",

    pub fn toString(self: SpanStatus) []const u8 {
        return switch (self) {
            .unset => "UNSET",
            .ok => "OK",
            .@"error" => "ERROR",
        };
    }
};

/// Span attribute
pub const SpanAttribute = struct {
    key: []const u8,
    value: union(enum) {
        string: []const u8,
        int: i64,
        float: f64,
        bool: bool,
    },

    pub fn string(key: []const u8, value: []const u8) SpanAttribute {
        return .{ .key = key, .value = .{ .string = value } };
    }

    pub fn int(key: []const u8, value: i64) SpanAttribute {
        return .{ .key = key, .value = .{ .int = value } };
    }

    pub fn float(key: []const u8, value: f64) SpanAttribute {
        return .{ .key = key, .value = .{ .float = value } };
    }

    pub fn boolean(key: []const u8, value: bool) SpanAttribute {
        return .{ .key = key, .value = .{ .bool = value } };
    }
};

/// Trace span
pub const Span = struct {
    context: TraceContext,
    name: []const u8,
    kind: SpanKind,
    start_time: i64,
    end_time: ?i64,
    status: SpanStatus,
    attributes: std.ArrayList(SpanAttribute),
    events: std.ArrayList(SpanEvent),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, name: []const u8, kind: SpanKind) !Span {
        return .{
            .context = try TraceContext.init(allocator),
            .name = try allocator.dupe(u8, name),
            .kind = kind,
            .start_time = std.time.nanoTimestamp(),
            .end_time = null,
            .status = .unset,
            .attributes = std.ArrayList(SpanAttribute).init(allocator),
            .events = std.ArrayList(SpanEvent).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn initWithContext(allocator: std.mem.Allocator, name: []const u8, kind: SpanKind, context: TraceContext) !Span {
        return .{
            .context = context,
            .name = try allocator.dupe(u8, name),
            .kind = kind,
            .start_time = std.time.nanoTimestamp(),
            .end_time = null,
            .status = .unset,
            .attributes = std.ArrayList(SpanAttribute).init(allocator),
            .events = std.ArrayList(SpanEvent).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Span) void {
        self.allocator.free(self.name);
        self.attributes.deinit();
        self.events.deinit();
    }

    pub fn end(self: *Span) void {
        self.end_time = std.time.nanoTimestamp();
    }

    pub fn setStatus(self: *Span, status: SpanStatus) void {
        self.status = status;
    }

    pub fn setAttribute(self: *Span, attr: SpanAttribute) !void {
        try self.attributes.append(attr);
    }

    pub fn addEvent(self: *Span, name: []const u8) !void {
        try self.events.append(.{
            .name = name,
            .timestamp = std.time.nanoTimestamp(),
            .attributes = std.ArrayList(SpanAttribute).init(self.allocator),
        });
    }

    pub fn addEventWithAttributes(self: *Span, name: []const u8, attributes: []const SpanAttribute) !void {
        var event_attrs = std.ArrayList(SpanAttribute).init(self.allocator);
        try event_attrs.appendSlice(attributes);

        try self.events.append(.{
            .name = name,
            .timestamp = std.time.nanoTimestamp(),
            .attributes = event_attrs,
        });
    }

    /// Get duration in microseconds
    pub fn durationMicros(self: *const Span) i64 {
        const end_time = self.end_time orelse std.time.nanoTimestamp();
        return @divFloor(end_time - self.start_time, 1000);
    }

    /// Get duration in milliseconds
    pub fn durationMillis(self: *const Span) i64 {
        return @divFloor(self.durationMicros(), 1000);
    }
};

/// Span event
pub const SpanEvent = struct {
    name: []const u8,
    timestamp: i64,
    attributes: std.ArrayList(SpanAttribute),
};

/// Tracer for creating spans
pub const Tracer = struct {
    allocator: std.mem.Allocator,
    service_name: []const u8,
    enabled: bool,

    pub fn init(allocator: std.mem.Allocator, service_name: []const u8, enabled: bool) !Tracer {
        return .{
            .allocator = allocator,
            .service_name = try allocator.dupe(u8, service_name),
            .enabled = enabled,
        };
    }

    pub fn deinit(self: *Tracer) void {
        self.allocator.free(self.service_name);
    }

    pub fn startSpan(self: *Tracer, name: []const u8, kind: SpanKind) !Span {
        if (!self.enabled) {
            return error.TracingDisabled;
        }
        return try Span.init(self.allocator, name, kind);
    }

    pub fn startSpanWithContext(self: *Tracer, name: []const u8, kind: SpanKind, parent: *const TraceContext) !Span {
        if (!self.enabled) {
            return error.TracingDisabled;
        }
        const context = try TraceContext.initWithParent(self.allocator, parent);
        return try Span.initWithContext(self.allocator, name, kind, context);
    }
};

/// Simple console exporter for testing
pub const ConsoleExporter = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) ConsoleExporter {
        return .{ .allocator = allocator };
    }

    pub fn exportSpan(self: *ConsoleExporter, span: *const Span) !void {
        const trace_id = try span.context.traceIdHex(self.allocator);
        defer self.allocator.free(trace_id);

        const span_id = try span.context.spanIdHex(self.allocator);
        defer self.allocator.free(span_id);

        logger.debug(
            "[TRACE] span={s} trace_id={s} span_id={s} kind={s} status={s} duration_ms={d}",
            .{
                span.name,
                trace_id,
                span_id,
                span.kind.toString(),
                span.status.toString(),
                span.durationMillis(),
            },
        );

        for (span.attributes.items) |attr| {
            switch (attr.value) {
                .string => |v| logger.debug("  {s}={s}", .{ attr.key, v }),
                .int => |v| logger.debug("  {s}={d}", .{ attr.key, v }),
                .float => |v| logger.debug("  {s}={d}", .{ attr.key, v }),
                .bool => |v| logger.debug("  {s}={}", .{ attr.key, v }),
            }
        }
    }
};

test "trace context creation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const ctx = try TraceContext.init(allocator);
    try testing.expect(ctx.trace_id.len == 16);
    try testing.expect(ctx.span_id.len == 8);
    try testing.expectEqual(@as(u8, 0x01), ctx.trace_flags);
}

test "span creation and lifecycle" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var span = try Span.init(allocator, "test.span", .server);
    defer span.deinit();

    try testing.expect(span.end_time == null);
    try span.setAttribute(SpanAttribute.string("key", "value"));

    span.end();
    try testing.expect(span.end_time != null);
    try testing.expect(span.durationMicros() >= 0);
}

test "tracer span creation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var tracer = try Tracer.init(allocator, "test-service", true);
    defer tracer.deinit();

    var span = try tracer.startSpan("test.operation", .internal);
    defer span.deinit();

    try span.setAttribute(SpanAttribute.int("count", 42));
    span.end();

    try testing.expectEqual(SpanStatus.unset, span.status);
}
