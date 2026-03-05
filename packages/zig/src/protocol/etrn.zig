const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");

/// ETRN extension (RFC 1985)
/// Extended Turn - allows remote sites to request queue processing
/// Used when a site wants the server to process its outbound queue
///
/// Command format:
///   ETRN [@<node>][#<queue>][<domain>]
///
/// Examples:
///   ETRN example.com        - Process queue for example.com
///   ETRN @node1.example.com - Process queue for specific node
///   ETRN #queue1            - Process specific named queue
///
/// Response codes:
///   250 OK, queue processing started
///   251 OK, no messages waiting
///   252 OK, cannot process queue (try later)
///   253 OK, pending messages for node <node>
///   458 Unable to queue messages
///   459 Node <node> not allowed
///   500 Syntax error
pub const ETRNHandler = struct {
    allocator: std.mem.Allocator,
    queue_dir: []const u8,
    allowed_domains: std.StringHashMap(void),
    max_queue_size: usize,
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator, queue_dir: []const u8, max_queue_size: usize) !ETRNHandler {
        return .{
            .allocator = allocator,
            .queue_dir = try allocator.dupe(u8, queue_dir),
            .allowed_domains = std.StringHashMap(void).init(allocator),
            .max_queue_size = max_queue_size,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *ETRNHandler) void {
        var iter = self.allowed_domains.keyIterator();
        while (iter.next()) |key| {
            self.allocator.free(key.*);
        }
        self.allowed_domains.deinit();
        self.allocator.free(self.queue_dir);
    }

    /// Add a domain to the allowed list
    pub fn allowDomain(self: *ETRNHandler, domain: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const domain_copy = try self.allocator.dupe(u8, domain);
        try self.allowed_domains.put(domain_copy, {});
    }

    /// Remove a domain from the allowed list
    pub fn disallowDomain(self: *ETRNHandler, domain: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.allowed_domains.fetchRemove(domain)) |entry| {
            self.allocator.free(entry.key);
        }
    }

    /// Check if a domain is allowed to use ETRN
    pub fn isDomainAllowed(self: *ETRNHandler, domain: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.allowed_domains.contains(domain);
    }

    /// Parse ETRN command argument
    pub fn parseArgument(self: *ETRNHandler, arg: []const u8) !ETRNRequest {
        _ = self;

        if (arg.len == 0) {
            return error.InvalidArgument;
        }

        var request = ETRNRequest{
            .request_type = .domain,
            .target = "",
        };

        if (arg[0] == '@') {
            // @node format - specific node
            request.request_type = .node;
            request.target = arg[1..];
        } else if (arg[0] == '#') {
            // #queue format - named queue
            request.request_type = .queue;
            request.target = arg[1..];
        } else {
            // domain format
            request.request_type = .domain;
            request.target = arg;
        }

        // Validate target is not empty
        if (request.target.len == 0) {
            return error.InvalidArgument;
        }

        return request;
    }

    /// Process ETRN request
    pub fn processRequest(self: *ETRNHandler, request: ETRNRequest) !ETRNResponse {
        // Check if domain is allowed
        if (request.request_type == .domain) {
            if (!self.isDomainAllowed(request.target)) {
                return ETRNResponse{
                    .code = 459,
                    .message = try std.fmt.allocPrint(
                        self.allocator,
                        "Node {s} not allowed",
                        .{request.target},
                    ),
                };
            }
        }

        // Count messages in queue for this target
        const message_count = try self.countQueuedMessages(request);

        if (message_count == 0) {
            return ETRNResponse{
                .code = 251,
                .message = try std.fmt.allocPrint(
                    self.allocator,
                    "OK, no messages waiting for {s}",
                    .{request.target},
                ),
            };
        }

        // Try to start queue processing
        const started = try self.startQueueProcessing(request);

        if (started) {
            return ETRNResponse{
                .code = 250,
                .message = try std.fmt.allocPrint(
                    self.allocator,
                    "OK, queuing for {s} started ({d} messages)",
                    .{ request.target, message_count },
                ),
            };
        } else {
            return ETRNResponse{
                .code = 252,
                .message = try std.fmt.allocPrint(
                    self.allocator,
                    "OK, pending messages for node {s}",
                    .{request.target},
                ),
            };
        }
    }

    /// Count messages in queue for a target
    fn countQueuedMessages(self: *ETRNHandler, request: ETRNRequest) !usize {
        _ = request;

        // In a real implementation, this would:
        // 1. Open queue directory
        // 2. Count files matching the target domain/node/queue
        // 3. Return count

        // Placeholder
        const queue_path = try std.fs.cwd().openDir(self.queue_dir, .{ .iterate = true }) catch {
            return 0;
        };
        defer queue_path.close();

        var count: usize = 0;
        var iter = queue_path.iterate();
        while (try iter.next()) |_| {
            count += 1;
        }

        return count;
    }

    /// Start queue processing for a target
    fn startQueueProcessing(self: *ETRNHandler, request: ETRNRequest) !bool {
        _ = self;
        _ = request;

        // In a real implementation, this would:
        // 1. Spawn a background task/thread
        // 2. Process each message in the queue
        // 3. Attempt delivery to the target
        // 4. Remove successfully delivered messages
        // 5. Retry failed messages according to policy

        // Placeholder - assume we can start processing
        return true;
    }

    /// Get EHLO capability string
    pub fn getCapability(self: *ETRNHandler) []const u8 {
        _ = self;
        return "ETRN";
    }
};

/// Type of ETRN request
pub const ETRNRequestType = enum {
    domain, // Domain name (e.g., example.com)
    node, // Specific node (e.g., @mail.example.com)
    queue, // Named queue (e.g., #queue1)
};

/// Parsed ETRN request
pub const ETRNRequest = struct {
    request_type: ETRNRequestType,
    target: []const u8,

    pub fn toString(self: ETRNRequest, allocator: std.mem.Allocator) ![]const u8 {
        return switch (self.request_type) {
            .domain => try allocator.dupe(u8, self.target),
            .node => try std.fmt.allocPrint(allocator, "@{s}", .{self.target}),
            .queue => try std.fmt.allocPrint(allocator, "#{s}", .{self.target}),
        };
    }
};

/// ETRN response
pub const ETRNResponse = struct {
    code: u16,
    message: []const u8,

    pub fn deinit(self: *ETRNResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.message);
    }

    pub fn format(self: ETRNResponse, allocator: std.mem.Allocator) ![]const u8 {
        return try std.fmt.allocPrint(allocator, "{d} {s}\r\n", .{ self.code, self.message });
    }
};

/// Queue processor for ETRN
pub const QueueProcessor = struct {
    allocator: std.mem.Allocator,
    queue_dir: []const u8,
    processing: bool,
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator, queue_dir: []const u8) !QueueProcessor {
        return .{
            .allocator = allocator,
            .queue_dir = try allocator.dupe(u8, queue_dir),
            .processing = false,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *QueueProcessor) void {
        self.allocator.free(self.queue_dir);
    }

    /// Start processing queue for a domain
    pub fn processQueue(self: *QueueProcessor, domain: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.processing) {
            return error.AlreadyProcessing;
        }

        self.processing = true;
        defer self.processing = false;

        // In a real implementation:
        // 1. Read queue directory
        // 2. Filter messages for target domain
        // 3. Attempt delivery for each message
        // 4. Update queue state

        _ = domain;
    }

    pub fn isProcessing(self: *QueueProcessor) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.processing;
    }
};

/// ETRN statistics
pub const ETRNStats = struct {
    total_requests: usize = 0,
    successful_starts: usize = 0,
    no_messages: usize = 0,
    denied: usize = 0,
    errors: usize = 0,
};

test "parse ETRN domain argument" {
    const testing = std.testing;

    var handler = try ETRNHandler.init(testing.allocator, "/tmp/queue", 1000);
    defer handler.deinit();

    const request = try handler.parseArgument("example.com");
    try testing.expectEqual(ETRNRequestType.domain, request.request_type);
    try testing.expectEqualStrings("example.com", request.target);
}

test "parse ETRN node argument" {
    const testing = std.testing;

    var handler = try ETRNHandler.init(testing.allocator, "/tmp/queue", 1000);
    defer handler.deinit();

    const request = try handler.parseArgument("@mail.example.com");
    try testing.expectEqual(ETRNRequestType.node, request.request_type);
    try testing.expectEqualStrings("mail.example.com", request.target);
}

test "parse ETRN queue argument" {
    const testing = std.testing;

    var handler = try ETRNHandler.init(testing.allocator, "/tmp/queue", 1000);
    defer handler.deinit();

    const request = try handler.parseArgument("#queue1");
    try testing.expectEqual(ETRNRequestType.queue, request.request_type);
    try testing.expectEqualStrings("queue1", request.target);
}

test "invalid ETRN argument" {
    const testing = std.testing;

    var handler = try ETRNHandler.init(testing.allocator, "/tmp/queue", 1000);
    defer handler.deinit();

    // Empty argument
    const result = handler.parseArgument("");
    try testing.expectError(error.InvalidArgument, result);

    // Only prefix
    const result2 = handler.parseArgument("@");
    try testing.expectError(error.InvalidArgument, result2);
}

test "allow and check domain" {
    const testing = std.testing;

    var handler = try ETRNHandler.init(testing.allocator, "/tmp/queue", 1000);
    defer handler.deinit();

    try handler.allowDomain("example.com");
    try testing.expect(handler.isDomainAllowed("example.com"));
    try testing.expect(!handler.isDomainAllowed("other.com"));
}

test "disallow domain" {
    const testing = std.testing;

    var handler = try ETRNHandler.init(testing.allocator, "/tmp/queue", 1000);
    defer handler.deinit();

    try handler.allowDomain("example.com");
    try testing.expect(handler.isDomainAllowed("example.com"));

    try handler.disallowDomain("example.com");
    try testing.expect(!handler.isDomainAllowed("example.com"));
}

test "ETRN request to string" {
    const testing = std.testing;

    const domain_req = ETRNRequest{
        .request_type = .domain,
        .target = "example.com",
    };
    const domain_str = try domain_req.toString(testing.allocator);
    defer testing.allocator.free(domain_str);
    try testing.expectEqualStrings("example.com", domain_str);

    const node_req = ETRNRequest{
        .request_type = .node,
        .target = "mail.example.com",
    };
    const node_str = try node_req.toString(testing.allocator);
    defer testing.allocator.free(node_str);
    try testing.expectEqualStrings("@mail.example.com", node_str);
}

test "ETRN response formatting" {
    const testing = std.testing;

    var response = ETRNResponse{
        .code = 250,
        .message = try testing.allocator.dupe(u8, "OK, queuing started"),
    };
    defer response.deinit(testing.allocator);

    const formatted = try response.format(testing.allocator);
    defer testing.allocator.free(formatted);

    try testing.expectEqualStrings("250 OK, queuing started\r\n", formatted);
}

test "queue processor" {
    const testing = std.testing;

    var processor = try QueueProcessor.init(testing.allocator, "/tmp/queue");
    defer processor.deinit();

    try testing.expect(!processor.isProcessing());
}

test "get ETRN capability" {
    const testing = std.testing;

    var handler = try ETRNHandler.init(testing.allocator, "/tmp/queue", 1000);
    defer handler.deinit();

    const capability = handler.getCapability();
    try testing.expectEqualStrings("ETRN", capability);
}
