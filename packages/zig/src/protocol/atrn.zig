const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");

/// ATRN extension (RFC 2645)
/// Authenticated TURN - allows authenticated queue processing with role reversal
/// More secure alternative to ETRN for dial-up and intermittent connections
///
/// Command format:
///   ATRN <domain1>[,<domain2>...]
///
/// Examples:
///   ATRN example.com
///   ATRN example.com,sub.example.com
///
/// Response codes:
///   250 OK, starting queue delivery
///   450 Requested mail action not taken
///   451 Requested action aborted: local error
///   453 You have no mail
///   502 Command not implemented
///   530 Authentication required
///
/// Protocol flow:
/// 1. Client authenticates (AUTH command)
/// 2. Client sends ATRN with authorized domains
/// 3. Server reverses roles and delivers queued mail
/// 4. Server closes connection when done
pub const ATRNHandler = struct {
    allocator: std.mem.Allocator,
    queue_dir: []const u8,
    authorized_domains: std.StringHashMap([]const u8), // domain -> authenticated_user
    require_auth: bool,
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator, queue_dir: []const u8, require_auth: bool) !ATRNHandler {
        return .{
            .allocator = allocator,
            .queue_dir = try allocator.dupe(u8, queue_dir),
            .authorized_domains = std.StringHashMap([]const u8).init(allocator),
            .require_auth = require_auth,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *ATRNHandler) void {
        var iter = self.authorized_domains.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.authorized_domains.deinit();
        self.allocator.free(self.queue_dir);
    }

    /// Authorize a user to perform ATRN for specific domains
    pub fn authorizeDomain(self: *ATRNHandler, username: []const u8, domain: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const domain_copy = try self.allocator.dupe(u8, domain);
        const username_copy = try self.allocator.dupe(u8, username);

        try self.authorized_domains.put(domain_copy, username_copy);
    }

    /// Revoke domain authorization
    pub fn revokeDomain(self: *ATRNHandler, domain: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.authorized_domains.fetchRemove(domain)) |entry| {
            self.allocator.free(entry.key);
            self.allocator.free(entry.value);
        }
    }

    /// Check if user is authorized for a domain
    pub fn isAuthorized(self: *ATRNHandler, username: []const u8, domain: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.authorized_domains.get(domain)) |authorized_user| {
            return std.mem.eql(u8, username, authorized_user);
        }
        return false;
    }

    /// Parse ATRN command argument (comma-separated domains)
    pub fn parseArgument(self: *ATRNHandler, arg: []const u8) ![][]const u8 {
        if (arg.len == 0) {
            return error.InvalidArgument;
        }

        var domains = std.ArrayList([]const u8).init(self.allocator);

        var iter = std.mem.splitScalar(u8, arg, ',');
        while (iter.next()) |domain| {
            const trimmed = std.mem.trim(u8, domain, " \t");
            if (trimmed.len == 0) {
                continue;
            }
            try domains.append(self.allocator, try self.allocator.dupe(u8, trimmed));
        }

        if (domains.items.len == 0) {
            domains.deinit(self.allocator);
            return error.NoDomains;
        }

        return try domains.toOwnedSlice(self.allocator);
    }

    /// Process ATRN request
    pub fn processRequest(
        self: *ATRNHandler,
        authenticated_user: ?[]const u8,
        domains: []const []const u8,
    ) !ATRNResponse {
        // Check authentication requirement
        if (self.require_auth and authenticated_user == null) {
            return ATRNResponse{
                .code = 530,
                .message = try self.allocator.dupe(u8, "Authentication required"),
                .can_proceed = false,
            };
        }

        // Verify user is authorized for all requested domains
        if (authenticated_user) |user| {
            for (domains) |domain| {
                if (!self.isAuthorized(user, domain)) {
                    return ATRNResponse{
                        .code = 450,
                        .message = try std.fmt.allocPrint(
                            self.allocator,
                            "Not authorized for domain {s}",
                            .{domain},
                        ),
                        .can_proceed = false,
                    };
                }
            }
        }

        // Count queued messages for these domains
        var total_messages: usize = 0;
        for (domains) |domain| {
            total_messages += try self.countQueuedMessages(domain);
        }

        if (total_messages == 0) {
            return ATRNResponse{
                .code = 453,
                .message = try self.allocator.dupe(u8, "You have no mail"),
                .can_proceed = false,
            };
        }

        // Ready to start queue delivery
        return ATRNResponse{
            .code = 250,
            .message = try std.fmt.allocPrint(
                self.allocator,
                "OK, {d} messages queued for delivery",
                .{total_messages},
            ),
            .can_proceed = true,
        };
    }

    /// Count messages in queue for a domain
    fn countQueuedMessages(self: *ATRNHandler, domain: []const u8) !usize {
        _ = domain;

        // In a real implementation, this would:
        // 1. Open queue directory
        // 2. Count files for this domain
        // 3. Return count

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

    /// Get EHLO capability string
    pub fn getCapability(self: *ATRNHandler) []const u8 {
        _ = self;
        return "ATRN";
    }
};

/// ATRN response
pub const ATRNResponse = struct {
    code: u16,
    message: []const u8,
    can_proceed: bool, // Whether role reversal should occur

    pub fn deinit(self: *ATRNResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.message);
    }

    pub fn format(self: ATRNResponse, allocator: std.mem.Allocator) ![]const u8 {
        return try std.fmt.allocPrint(allocator, "{d} {s}\r\n", .{ self.code, self.message });
    }
};

/// Role reversal manager for ATRN
/// Handles the protocol reversal where server becomes client
pub const RoleReversalManager = struct {
    allocator: std.mem.Allocator,
    queue_dir: []const u8,
    in_reversal: bool,
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator, queue_dir: []const u8) !RoleReversalManager {
        return .{
            .allocator = allocator,
            .queue_dir = try allocator.dupe(u8, queue_dir),
            .in_reversal = false,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *RoleReversalManager) void {
        self.allocator.free(self.queue_dir);
    }

    /// Start role reversal
    pub fn startReversal(self: *RoleReversalManager) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.in_reversal) {
            return error.AlreadyInReversal;
        }

        self.in_reversal = true;
    }

    /// End role reversal
    pub fn endReversal(self: *RoleReversalManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.in_reversal = false;
    }

    pub fn isInReversal(self: *RoleReversalManager) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.in_reversal;
    }

    /// Deliver queued messages for domains
    pub fn deliverQueue(
        self: *RoleReversalManager,
        domains: []const []const u8,
    ) !DeliveryStats {
        _ = domains;

        // In a real implementation:
        // 1. Read queue directory
        // 2. Filter messages for requested domains
        // 3. Deliver each message via SMTP
        // 4. Track success/failure
        // 5. Remove successfully delivered messages

        // Placeholder
        _ = self;

        return DeliveryStats{
            .total_messages = 0,
            .delivered = 0,
            .failed = 0,
        };
    }
};

pub const DeliveryStats = struct {
    total_messages: usize,
    delivered: usize,
    failed: usize,
};

/// ATRN session state
pub const ATRNSession = struct {
    domains: [][]const u8,
    authenticated_user: []const u8,
    started_at: i64,
    messages_delivered: usize,

    pub fn deinit(self: *ATRNSession, allocator: std.mem.Allocator) void {
        for (self.domains) |domain| {
            allocator.free(domain);
        }
        allocator.free(self.domains);
        allocator.free(self.authenticated_user);
    }
};

/// ATRN statistics
pub const ATRNStats = struct {
    total_requests: usize = 0,
    successful_reversals: usize = 0,
    auth_failures: usize = 0,
    no_mail_responses: usize = 0,
    messages_delivered: usize = 0,
};

test "parse ATRN single domain" {
    const testing = std.testing;

    var handler = try ATRNHandler.init(testing.allocator, "/tmp/queue", true);
    defer handler.deinit();

    const domains = try handler.parseArgument("example.com");
    defer {
        for (domains) |domain| {
            testing.allocator.free(domain);
        }
        testing.allocator.free(domains);
    }

    try testing.expectEqual(@as(usize, 1), domains.len);
    try testing.expectEqualStrings("example.com", domains[0]);
}

test "parse ATRN multiple domains" {
    const testing = std.testing;

    var handler = try ATRNHandler.init(testing.allocator, "/tmp/queue", true);
    defer handler.deinit();

    const domains = try handler.parseArgument("example.com,sub.example.com,other.com");
    defer {
        for (domains) |domain| {
            testing.allocator.free(domain);
        }
        testing.allocator.free(domains);
    }

    try testing.expectEqual(@as(usize, 3), domains.len);
    try testing.expectEqualStrings("example.com", domains[0]);
    try testing.expectEqualStrings("sub.example.com", domains[1]);
    try testing.expectEqualStrings("other.com", domains[2]);
}

test "invalid ATRN argument" {
    const testing = std.testing;

    var handler = try ATRNHandler.init(testing.allocator, "/tmp/queue", true);
    defer handler.deinit();

    const result = handler.parseArgument("");
    try testing.expectError(error.InvalidArgument, result);
}

test "authorize and check domain" {
    const testing = std.testing;

    var handler = try ATRNHandler.init(testing.allocator, "/tmp/queue", true);
    defer handler.deinit();

    try handler.authorizeDomain("user1", "example.com");
    try testing.expect(handler.isAuthorized("user1", "example.com"));
    try testing.expect(!handler.isAuthorized("user2", "example.com"));
    try testing.expect(!handler.isAuthorized("user1", "other.com"));
}

test "revoke domain authorization" {
    const testing = std.testing;

    var handler = try ATRNHandler.init(testing.allocator, "/tmp/queue", true);
    defer handler.deinit();

    try handler.authorizeDomain("user1", "example.com");
    try testing.expect(handler.isAuthorized("user1", "example.com"));

    try handler.revokeDomain("example.com");
    try testing.expect(!handler.isAuthorized("user1", "example.com"));
}

test "ATRN requires authentication" {
    const testing = std.testing;

    var handler = try ATRNHandler.init(testing.allocator, "/tmp/queue", true);
    defer handler.deinit();

    const domains = [_][]const u8{"example.com"};
    var response = try handler.processRequest(null, &domains);
    defer response.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 530), response.code);
    try testing.expect(!response.can_proceed);
}

test "ATRN with authorization" {
    const testing = std.testing;

    var handler = try ATRNHandler.init(testing.allocator, "/tmp/queue", true);
    defer handler.deinit();

    try handler.authorizeDomain("user1", "example.com");

    const domains = [_][]const u8{"example.com"};
    var response = try handler.processRequest("user1", &domains);
    defer response.deinit(testing.allocator);

    // Should get 453 (no mail) or 250 (has mail)
    try testing.expect(response.code == 453 or response.code == 250);
}

test "ATRN unauthorized domain" {
    const testing = std.testing;

    var handler = try ATRNHandler.init(testing.allocator, "/tmp/queue", true);
    defer handler.deinit();

    try handler.authorizeDomain("user1", "example.com");

    const domains = [_][]const u8{"other.com"};
    var response = try handler.processRequest("user1", &domains);
    defer response.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 450), response.code);
    try testing.expect(!response.can_proceed);
}

test "role reversal manager" {
    const testing = std.testing;

    var manager = try RoleReversalManager.init(testing.allocator, "/tmp/queue");
    defer manager.deinit();

    try testing.expect(!manager.isInReversal());

    try manager.startReversal();
    try testing.expect(manager.isInReversal());

    manager.endReversal();
    try testing.expect(!manager.isInReversal());
}

test "ATRN response formatting" {
    const testing = std.testing;

    var response = ATRNResponse{
        .code = 250,
        .message = try testing.allocator.dupe(u8, "OK, 5 messages queued"),
        .can_proceed = true,
    };
    defer response.deinit(testing.allocator);

    const formatted = try response.format(testing.allocator);
    defer testing.allocator.free(formatted);

    try testing.expectEqualStrings("250 OK, 5 messages queued\r\n", formatted);
}

test "get ATRN capability" {
    const testing = std.testing;

    var handler = try ATRNHandler.init(testing.allocator, "/tmp/queue", true);
    defer handler.deinit();

    const capability = handler.getCapability();
    try testing.expectEqualStrings("ATRN", capability);
}
