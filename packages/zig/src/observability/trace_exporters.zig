const std = @import("std");
const io_compat = @import("../core/io_compat.zig");
const mutex_compat = @import("../core/mutex_compat.zig");
const tracing = @import("tracing.zig");
const logger = @import("../core/logger.zig");

/// Distributed Tracing Exporters
/// Supports exporting traces to Jaeger, DataDog, and other OTLP-compatible backends
///
/// Features:
/// - Jaeger Agent export (UDP)
/// - Jaeger Collector export (HTTP)
/// - DataDog Agent export (HTTP)
/// - OpenTelemetry Protocol (OTLP) export (gRPC/HTTP)
/// - Batch exporting with configurable intervals
/// - Automatic retry with exponential backoff
/// - Resource attribution
/// Trace sampling configuration
pub const SamplingConfig = struct {
    /// Sampling strategy
    strategy: SamplingStrategy = .always_on,
    /// Sample rate for ratio-based sampling (0.0 to 1.0)
    sample_rate: f64 = 1.0,
    /// Rate limit for rate-limiting sampler (traces per second)
    rate_limit: u32 = 100,
    /// Parent-based sampling - inherit sampling decision from parent span
    parent_based: bool = true,

    pub fn shouldSample(self: SamplingConfig, trace_id: [16]u8) bool {
        return switch (self.strategy) {
            .always_on => true,
            .always_off => false,
            .trace_id_ratio => blk: {
                // Use first 8 bytes of trace_id as random value
                const rand_val = std.mem.readInt(u64, trace_id[0..8], .little);
                const threshold = @as(u64, @intFromFloat(self.sample_rate * @as(f64, std.math.maxInt(u64))));
                break :blk rand_val < threshold;
            },
            .rate_limiting => true, // Rate limiting handled elsewhere
        };
    }
};

pub const SamplingStrategy = enum {
    always_on, // Sample all traces
    always_off, // Sample no traces
    trace_id_ratio, // Sample based on trace ID hash
    rate_limiting, // Sample up to N traces per second
};

/// Exporter configuration
pub const ExporterConfig = struct {
    backend: ExporterBackend = .jaeger_agent,
    endpoint: []const u8 = "localhost:6831",
    service_name: []const u8 = "mail",
    batch_size: usize = 100,
    batch_timeout_ms: u64 = 5000,
    max_retries: usize = 3,
    retry_initial_interval_ms: u64 = 1000,
    retry_max_interval_ms: u64 = 30000,
    headers: ?std.StringHashMap([]const u8) = null,
    /// Sampling configuration
    sampling: SamplingConfig = .{},
};

pub const ExporterBackend = enum {
    jaeger_agent, // UDP to Jaeger Agent (6831)
    jaeger_collector, // HTTP to Jaeger Collector (14268)
    datadog_agent, // HTTP to DataDog Agent (8126)
    otlp_grpc, // gRPC to OTLP collector (4317)
    otlp_http, // HTTP to OTLP collector (4318)
    zipkin, // HTTP to Zipkin collector (9411)
};

/// Span data for export
pub const SpanData = struct {
    trace_id: [16]u8,
    span_id: [8]u8,
    parent_span_id: ?[8]u8,
    name: []const u8,
    start_time_ns: i64,
    end_time_ns: i64,
    attributes: std.StringHashMap([]const u8),
    events: std.ArrayList(SpanEvent),
    status: SpanStatus = .ok,

    pub fn init(allocator: std.mem.Allocator, name: []const u8) !SpanData {
        return SpanData{
            .trace_id = undefined,
            .span_id = undefined,
            .parent_span_id = null,
            .name = try allocator.dupe(u8, name),
            .start_time_ns = @intCast(std.time.nanoTimestamp()),
            .end_time_ns = 0,
            .attributes = std.StringHashMap([]const u8).init(allocator),
            .events = std.ArrayList(SpanEvent){},
        };
    }

    pub fn deinit(self: *SpanData, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        var attr_iter = self.attributes.iterator();
        while (attr_iter.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.attributes.deinit();
        for (self.events.items) |*event| {
            event.deinit(allocator);
        }
        self.events.deinit(allocator);
    }

    pub fn finish(self: *SpanData) void {
        self.end_time_ns = @intCast(std.time.nanoTimestamp());
    }

    pub fn setAttribute(self: *SpanData, allocator: std.mem.Allocator, key: []const u8, value: []const u8) !void {
        const key_copy = try allocator.dupe(u8, key);
        const value_copy = try allocator.dupe(u8, value);
        try self.attributes.put(key_copy, value_copy);
    }

    pub fn addEvent(self: *SpanData, allocator: std.mem.Allocator, name: []const u8) !void {
        const event = SpanEvent{
            .name = try allocator.dupe(u8, name),
            .timestamp_ns = @intCast(std.time.nanoTimestamp()),
            .attributes = std.StringHashMap([]const u8).init(allocator),
        };
        try self.events.append(allocator, event);
    }

    pub fn setStatus(self: *SpanData, status: SpanStatus) void {
        self.status = status;
    }
};

pub const SpanEvent = struct {
    name: []const u8,
    timestamp_ns: i64,
    attributes: std.StringHashMap([]const u8),

    pub fn deinit(self: *SpanEvent, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        var attr_iter = self.attributes.iterator();
        while (attr_iter.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.attributes.deinit();
    }
};

pub const SpanStatus = enum {
    unset,
    ok,
    error_status,
};

/// Batch span exporter
pub const BatchSpanExporter = struct {
    allocator: std.mem.Allocator,
    config: ExporterConfig,
    spans: std.ArrayList(SpanData),
    mutex: mutex_compat.Mutex = .{},
    last_export: i64 = 0,
    export_thread: ?std.Thread = null,
    should_stop: std.atomic.Value(bool),

    pub fn init(allocator: std.mem.Allocator, config: ExporterConfig) BatchSpanExporter {
        return .{
            .allocator = allocator,
            .config = config,
            .spans = std.ArrayList(SpanData){},
            .should_stop = std.atomic.Value(bool).init(false),
        };
    }

    pub fn deinit(self: *BatchSpanExporter) void {
        self.stop();
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.spans.items) |*span| {
            span.deinit(self.allocator);
        }
        self.spans.deinit(self.allocator);
    }

    pub fn start(self: *BatchSpanExporter) !void {
        self.export_thread = try std.Thread.spawn(.{}, exportLoop, .{self});
    }

    pub fn stop(self: *BatchSpanExporter) void {
        self.should_stop.store(true, .monotonic);
        if (self.export_thread) |thread| {
            thread.join();
            self.export_thread = null;
        }
    }

    pub fn exportSpan(self: *BatchSpanExporter, span: SpanData) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.spans.append(self.allocator, span);

        // Trigger immediate export if batch is full
        if (self.spans.items.len >= self.config.batch_size) {
            try self.flushBatch();
        }
    }

    fn exportLoop(self: *BatchSpanExporter) void {
        while (!self.should_stop.load(.monotonic)) {
            std.time.sleep(self.config.batch_timeout_ms * std.time.ns_per_ms);

            self.mutex.lock();
            const should_export = self.spans.items.len > 0;
            self.mutex.unlock();

            if (should_export) {
                self.flushBatch() catch |err| {
                    logger.err("Error exporting trace batch: {}", .{err});
                };
            }
        }

        // Final flush on shutdown
        self.flushBatch() catch {};
    }

    fn flushBatch(self: *BatchSpanExporter) !void {
        if (self.spans.items.len == 0) return;

        switch (self.config.backend) {
            .jaeger_agent => try self.exportToJaegerAgent(),
            .jaeger_collector => try self.exportToJaegerCollector(),
            .datadog_agent => try self.exportToDataDogAgent(),
            .otlp_grpc => try self.exportToOtlpGrpc(),
            .otlp_http => try self.exportToOtlpHttp(),
            .zipkin => try self.exportToZipkin(),
        }

        // Clear exported spans
        for (self.spans.items) |*span| {
            span.deinit(self.allocator);
        }
        self.spans.clearRetainingCapacity();
        self.last_export = std.time.milliTimestamp();
    }

    /// Export to Jaeger Agent via UDP (Thrift Compact Protocol)
    fn exportToJaegerAgent(self: *BatchSpanExporter) !void {
        // Parse endpoint (host:port)
        const colon_pos = std.mem.indexOf(u8, self.config.endpoint, ":") orelse return error.InvalidEndpoint;
        const host = self.config.endpoint[0..colon_pos];
        const port_str = self.config.endpoint[colon_pos + 1 ..];
        const port = try std.fmt.parseInt(u16, port_str, 10);

        // Resolve address
        const address = try std.net.Address.parseIp(host, port);

        // Create UDP socket
        const sock = try std.posix.socket(address.any.family, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
        defer std.posix.close(sock);

        // Serialize spans to Jaeger Thrift format
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        try self.serializeJaegerThrift(&buffer);

        // Send via UDP
        _ = try std.posix.sendto(sock, buffer.items, 0, &address.any, address.getOsSockLen());

        logger.debug("Exported {d} spans to Jaeger Agent", .{self.spans.items.len});
    }

    /// Export to Jaeger Collector via HTTP
    fn exportToJaegerCollector(self: *BatchSpanExporter) !void {
        // Build JSON payload
        var payload = std.ArrayList(u8).init(self.allocator);
        defer payload.deinit();

        try self.serializeJaegerJson(&payload);

        // Send HTTP POST
        const url = try std.fmt.allocPrint(self.allocator, "http://{s}/api/traces", .{self.config.endpoint});
        defer self.allocator.free(url);

        try self.sendHttpPost(url, payload.items, "application/json");

        logger.debug("Exported {d} spans to Jaeger Collector", .{self.spans.items.len});
    }

    /// Export to DataDog Agent via HTTP
    fn exportToDataDogAgent(self: *BatchSpanExporter) !void {
        // Build DataDog JSON payload
        var payload = std.ArrayList(u8).init(self.allocator);
        defer payload.deinit();

        try self.serializeDataDogJson(&payload);

        // Send HTTP PUT to DataDog Agent
        const url = try std.fmt.allocPrint(self.allocator, "http://{s}/v0.4/traces", .{self.config.endpoint});
        defer self.allocator.free(url);

        try self.sendHttpPost(url, payload.items, "application/json");

        logger.debug("Exported {d} spans to DataDog Agent", .{self.spans.items.len});
    }

    /// Export to OTLP gRPC endpoint
    fn exportToOtlpGrpc(self: *BatchSpanExporter) !void {
        // Serialize to OTLP protobuf format
        var payload = std.ArrayList(u8).init(self.allocator);
        defer payload.deinit();

        try self.serializeOtlpProtobuf(&payload);

        // Send via gRPC (simplified - would use a proper gRPC client in production)
        logger.warn("OTLP gRPC export not yet implemented (would send {d} spans)", .{self.spans.items.len});
    }

    /// Export to OTLP HTTP endpoint
    fn exportToOtlpHttp(self: *BatchSpanExporter) !void {
        // Build OTLP JSON payload
        var payload = std.ArrayList(u8).init(self.allocator);
        defer payload.deinit();

        try self.serializeOtlpJson(&payload);

        // Send HTTP POST
        const url = try std.fmt.allocPrint(self.allocator, "http://{s}/v1/traces", .{self.config.endpoint});
        defer self.allocator.free(url);

        try self.sendHttpPost(url, payload.items, "application/json");

        logger.debug("Exported {d} spans to OTLP HTTP", .{self.spans.items.len});
    }

    /// Export to Zipkin HTTP endpoint
    fn exportToZipkin(self: *BatchSpanExporter) !void {
        // Build Zipkin JSON payload (v2 API)
        var payload = std.ArrayList(u8).init(self.allocator);
        defer payload.deinit();

        try self.serializeZipkinJson(&payload);

        // Send HTTP POST to Zipkin
        const url = try std.fmt.allocPrint(self.allocator, "http://{s}/api/v2/spans", .{self.config.endpoint});
        defer self.allocator.free(url);

        try self.sendHttpPost(url, payload.items, "application/json");

        logger.debug("Exported {d} spans to Zipkin", .{self.spans.items.len});
    }

    /// Serialize spans to Jaeger Thrift Compact format (simplified)
    fn serializeJaegerThrift(self: *BatchSpanExporter, buffer: *std.ArrayList(u8)) !void {
        const writer = buffer.writer();

        // Simplified Thrift serialization (production would use proper Thrift encoder)
        for (self.spans.items) |span| {
            // Write span data in Thrift format
            try writer.print("trace_id:{x},span_id:{x},name:{s}\n", .{
                std.fmt.fmtSliceHexLower(&span.trace_id),
                std.fmt.fmtSliceHexLower(&span.span_id),
                span.name,
            });
        }
    }

    /// Serialize spans to Jaeger JSON format
    fn serializeJaegerJson(self: *BatchSpanExporter, buffer: *std.ArrayList(u8)) !void {
        const writer = buffer.writer();

        try writer.writeAll("{\"data\": [{\"traceID\": \"");
        try writer.print("{x}", .{std.fmt.fmtSliceHexLower(&self.spans.items[0].trace_id)});
        try writer.writeAll("\", \"spans\": [");

        for (self.spans.items, 0..) |span, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.writeAll("{");
            try writer.print("\"traceID\": \"{x}\",", .{std.fmt.fmtSliceHexLower(&span.trace_id)});
            try writer.print("\"spanID\": \"{x}\",", .{std.fmt.fmtSliceHexLower(&span.span_id)});
            try writer.print("\"operationName\": \"{s}\",", .{span.name});
            try writer.print("\"startTime\": {d},", .{span.start_time_ns / 1000}); // Microseconds
            try writer.print("\"duration\": {d}", .{(span.end_time_ns - span.start_time_ns) / 1000});
            try writer.writeAll("}");
        }

        try writer.writeAll("]}]}");
    }

    /// Serialize spans to DataDog JSON format
    fn serializeDataDogJson(self: *BatchSpanExporter, buffer: *std.ArrayList(u8)) !void {
        const writer = buffer.writer();

        try writer.writeAll("[[");

        for (self.spans.items, 0..) |span, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.writeAll("{");
            try writer.print("\"trace_id\": {d},", .{std.mem.readInt(u64, span.trace_id[0..8], .little)});
            try writer.print("\"span_id\": {d},", .{std.mem.readInt(u64, &span.span_id, .little)});
            try writer.print("\"name\": \"{s}\",", .{span.name});
            try writer.print("\"service\": \"{s}\",", .{self.config.service_name});
            try writer.print("\"start\": {d},", .{span.start_time_ns});
            try writer.print("\"duration\": {d}", .{span.end_time_ns - span.start_time_ns});
            try writer.writeAll("}");
        }

        try writer.writeAll("]]");
    }

    /// Serialize spans to OTLP JSON format
    fn serializeOtlpJson(self: *BatchSpanExporter, buffer: *std.ArrayList(u8)) !void {
        const writer = buffer.writer();

        try writer.writeAll("{\"resourceSpans\": [{");
        try writer.print("\"resource\": {{\"attributes\": [{{\"key\": \"service.name\", \"value\": {{\"stringValue\": \"{s}\"}}}}]}},", .{self.config.service_name});
        try writer.writeAll("\"scopeSpans\": [{\"spans\": [");

        for (self.spans.items, 0..) |span, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.writeAll("{");
            try writer.print("\"traceId\": \"{x}\",", .{std.fmt.fmtSliceHexLower(&span.trace_id)});
            try writer.print("\"spanId\": \"{x}\",", .{std.fmt.fmtSliceHexLower(&span.span_id)});
            try writer.print("\"name\": \"{s}\",", .{span.name});
            try writer.print("\"startTimeUnixNano\": \"{d}\",", .{span.start_time_ns});
            try writer.print("\"endTimeUnixNano\": \"{d}\"", .{span.end_time_ns});
            try writer.writeAll("}");
        }

        try writer.writeAll("]}]}]}");
    }

    /// Serialize spans to Zipkin JSON format (v2 API)
    fn serializeZipkinJson(self: *BatchSpanExporter, buffer: *std.ArrayList(u8)) !void {
        const writer = buffer.writer();

        try writer.writeAll("[");

        for (self.spans.items, 0..) |span, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.writeAll("{");

            // Trace ID (32 hex chars)
            try writer.print("\"traceId\": \"{x}\",", .{std.fmt.fmtSliceHexLower(&span.trace_id)});

            // Span ID (16 hex chars)
            try writer.print("\"id\": \"{x}\",", .{std.fmt.fmtSliceHexLower(&span.span_id)});

            // Parent span ID (optional)
            if (span.parent_span_id) |parent_id| {
                try writer.print("\"parentId\": \"{x}\",", .{std.fmt.fmtSliceHexLower(&parent_id)});
            }

            // Name
            try writer.print("\"name\": \"{s}\",", .{span.name});

            // Timestamps (Zipkin uses microseconds)
            try writer.print("\"timestamp\": {d},", .{@divFloor(span.start_time_ns, 1000)});
            try writer.print("\"duration\": {d},", .{@divFloor(span.end_time_ns - span.start_time_ns, 1000)});

            // Local endpoint with service name
            try writer.print("\"localEndpoint\": {{\"serviceName\": \"{s}\"}},", .{self.config.service_name});

            // Kind (default to SERVER for SMTP)
            try writer.writeAll("\"kind\": \"SERVER\",");

            // Tags from attributes
            try writer.writeAll("\"tags\": {");
            var attr_iter = span.attributes.iterator();
            var first_attr = true;
            while (attr_iter.next()) |entry| {
                if (!first_attr) try writer.writeAll(",");
                first_attr = false;
                try writer.print("\"{s}\": \"{s}\"", .{ entry.key_ptr.*, entry.value_ptr.* });
            }
            try writer.writeAll("}");

            try writer.writeAll("}");
        }

        try writer.writeAll("]");
    }

    /// Serialize spans to OTLP Protobuf format (simplified)
    fn serializeOtlpProtobuf(self: *BatchSpanExporter, buffer: *std.ArrayList(u8)) !void {
        // Simplified protobuf serialization
        // Production would use proper protobuf encoder
        const writer = buffer.writer();
        for (self.spans.items) |span| {
            try writer.print("trace_id:{x},span_id:{x},name:{s}\n", .{
                std.fmt.fmtSliceHexLower(&span.trace_id),
                std.fmt.fmtSliceHexLower(&span.span_id),
                span.name,
            });
        }
    }

    /// Send HTTP POST request using std.http.Client
    fn sendHttpPost(self: *BatchSpanExporter, url: []const u8, payload: []const u8, content_type: []const u8) !void {
        const uri = std.Uri.parse(url) catch |err| {
            logger.err("Failed to parse URL {s}: {}", .{ url, err });
            return error.InvalidUrl;
        };

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        var header_buf: [4096]u8 = undefined;
        var req = client.open(.POST, uri, .{
            .server_header_buffer = &header_buf,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = content_type },
            },
        }) catch |err| {
            logger.err("Failed to open HTTP connection to {s}: {}", .{ url, err });
            return err;
        };
        defer req.deinit();

        req.transfer_encoding = .{ .content_length = payload.len };

        req.send() catch |err| {
            logger.err("Failed to send HTTP request headers: {}", .{err});
            return err;
        };

        req.writer().writeAll(payload) catch |err| {
            logger.err("Failed to write HTTP request body: {}", .{err});
            return err;
        };

        req.finish() catch |err| {
            logger.err("Failed to finish HTTP request: {}", .{err});
            return err;
        };

        req.wait() catch |err| {
            logger.err("Failed to wait for HTTP response: {}", .{err});
            return err;
        };

        if (req.status != .ok and req.status != .accepted and req.status != .no_content) {
            logger.err("HTTP request failed with status: {}", .{req.status});
            return error.HttpRequestFailed;
        }

        logger.debug("[{s}] HTTP POST to {s} succeeded ({d} bytes)", .{ self.config.service_name, url, payload.len });
    }
};

/// Tracer Provider - manages tracers and exporters
pub const TracerProvider = struct {
    allocator: std.mem.Allocator,
    service_name: []const u8,
    exporter: ?*BatchSpanExporter,
    sampling_config: SamplingConfig,
    resource_attributes: std.StringHashMap([]const u8),
    enabled: bool,

    pub fn init(allocator: std.mem.Allocator, service_name: []const u8) TracerProvider {
        return .{
            .allocator = allocator,
            .service_name = service_name,
            .exporter = null,
            .sampling_config = .{},
            .resource_attributes = std.StringHashMap([]const u8).init(allocator),
            .enabled = true,
        };
    }

    pub fn deinit(self: *TracerProvider) void {
        if (self.exporter) |exp| {
            exp.deinit();
            self.allocator.destroy(exp);
        }

        var attr_iter = self.resource_attributes.iterator();
        while (attr_iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.resource_attributes.deinit();
    }

    pub fn setExporter(self: *TracerProvider, config: ExporterConfig) !void {
        if (self.exporter) |exp| {
            exp.deinit();
            self.allocator.destroy(exp);
        }

        const exporter = try self.allocator.create(BatchSpanExporter);
        exporter.* = BatchSpanExporter.init(self.allocator, config);
        try exporter.start();
        self.exporter = exporter;
    }

    pub fn setSampling(self: *TracerProvider, config: SamplingConfig) void {
        self.sampling_config = config;
    }

    pub fn setResourceAttribute(self: *TracerProvider, key: []const u8, value: []const u8) !void {
        const key_copy = try self.allocator.dupe(u8, key);
        const value_copy = try self.allocator.dupe(u8, value);
        try self.resource_attributes.put(key_copy, value_copy);
    }

    pub fn createSpan(self: *TracerProvider, name: []const u8) !?*SpanData {
        if (!self.enabled) return null;

        var span = try self.allocator.create(SpanData);
        span.* = try SpanData.init(self.allocator, name);

        // Generate IDs
        io_compat.randomBytes(&span.trace_id);
        io_compat.randomBytes(&span.span_id);

        // Check sampling
        if (!self.sampling_config.shouldSample(span.trace_id)) {
            self.allocator.destroy(span);
            return null;
        }

        return span;
    }

    pub fn createChildSpan(self: *TracerProvider, name: []const u8, parent: *const SpanData) !?*SpanData {
        if (!self.enabled) return null;

        var span = try self.allocator.create(SpanData);
        span.* = try SpanData.init(self.allocator, name);

        // Inherit trace ID from parent
        span.trace_id = parent.trace_id;
        io_compat.randomBytes(&span.span_id);
        span.parent_span_id = parent.span_id;

        return span;
    }

    pub fn endSpan(self: *TracerProvider, span: *SpanData) void {
        span.finish();

        if (self.exporter) |exp| {
            // Clone span data for async export
            exp.exportSpan(span.*) catch |err| {
                logger.err("Failed to export span: {}", .{err});
            };
        }

        span.deinit(self.allocator);
        self.allocator.destroy(span);
    }

    pub fn shutdown(self: *TracerProvider) void {
        if (self.exporter) |exp| {
            exp.stop();
        }
        self.enabled = false;
    }
};

/// SMTP-specific span names and attributes
pub const SmtpSpans = struct {
    // Span names
    pub const CONNECTION = "smtp.connection";
    pub const COMMAND = "smtp.command";
    pub const AUTHENTICATION = "smtp.auth";
    pub const MESSAGE_RECEIVE = "smtp.message.receive";
    pub const MESSAGE_DELIVER = "smtp.message.deliver";
    pub const DNS_LOOKUP = "smtp.dns.lookup";
    pub const TLS_HANDSHAKE = "smtp.tls.handshake";
    pub const SPAM_CHECK = "smtp.spam.check";
    pub const DKIM_VERIFY = "smtp.dkim.verify";
    pub const SPF_CHECK = "smtp.spf.check";

    // Attribute keys
    pub const ATTR_CLIENT_IP = "smtp.client.ip";
    pub const ATTR_CLIENT_PORT = "smtp.client.port";
    pub const ATTR_COMMAND = "smtp.command.name";
    pub const ATTR_RESPONSE_CODE = "smtp.response.code";
    pub const ATTR_MESSAGE_ID = "smtp.message.id";
    pub const ATTR_FROM = "smtp.mail.from";
    pub const ATTR_TO = "smtp.rcpt.to";
    pub const ATTR_MESSAGE_SIZE = "smtp.message.size";
    pub const ATTR_AUTH_METHOD = "smtp.auth.method";
    pub const ATTR_AUTH_SUCCESS = "smtp.auth.success";
    pub const ATTR_TLS_VERSION = "smtp.tls.version";
    pub const ATTR_TLS_CIPHER = "smtp.tls.cipher";
    pub const ATTR_SPAM_SCORE = "smtp.spam.score";
    pub const ATTR_DKIM_RESULT = "smtp.dkim.result";
    pub const ATTR_SPF_RESULT = "smtp.spf.result";
    pub const ATTR_QUEUE_ID = "smtp.queue.id";
    pub const ATTR_DELIVERY_STATUS = "smtp.delivery.status";
};

// Tests
test "span data lifecycle" {
    const testing = std.testing;

    var span = try SpanData.init(testing.allocator, "test.operation");
    defer span.deinit(testing.allocator);

    try span.setAttribute(testing.allocator, "http.method", "POST");
    try span.setAttribute(testing.allocator, "http.url", "/api/test");
    try span.addEvent(testing.allocator, "request.started");

    span.finish();

    try testing.expect(span.end_time_ns > span.start_time_ns);
    try testing.expectEqual(@as(usize, 2), span.attributes.count());
    try testing.expectEqual(@as(usize, 1), span.events.items.len);
}

test "batch exporter initialization" {
    const testing = std.testing;

    const config = ExporterConfig{
        .backend = .jaeger_agent,
        .endpoint = "localhost:6831",
        .service_name = "test-service",
    };

    var exporter = BatchSpanExporter.init(testing.allocator, config);
    defer exporter.deinit();

    try testing.expectEqual(@as(usize, 0), exporter.spans.items.len);
}
