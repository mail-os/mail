const std = @import("std");
const time_compat = @import("../core/time_compat.zig");

/// Mailing list management and message distribution
pub const MailingList = struct {
    allocator: std.mem.Allocator,
    name: []const u8,
    address: []const u8, // List address (e.g., list@example.com)
    description: []const u8,
    subscribers: std.StringHashMap(Subscriber),
    settings: ListSettings,
    mutex: std.Thread.Mutex,

    pub fn init(
        allocator: std.mem.Allocator,
        name: []const u8,
        address: []const u8,
        description: []const u8,
    ) !MailingList {
        return .{
            .allocator = allocator,
            .name = try allocator.dupe(u8, name),
            .address = try allocator.dupe(u8, address),
            .description = try allocator.dupe(u8, description),
            .subscribers = std.StringHashMap(Subscriber).init(allocator),
            .settings = ListSettings{},
            .mutex = .{},
        };
    }

    pub fn deinit(self: *MailingList) void {
        self.allocator.free(self.name);
        self.allocator.free(self.address);
        self.allocator.free(self.description);

        var it = self.subscribers.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.subscribers.deinit();
    }

    /// Subscribe an email address to the list
    pub fn subscribe(self: *MailingList, email: []const u8, name: ?[]const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const key = try self.allocator.dupe(u8, email);
        errdefer self.allocator.free(key);

        const subscriber = Subscriber{
            .email = email,
            .name = name,
            .subscribed_at = time_compat.timestamp(),
            .enabled = true,
            .digest_mode = false,
        };

        try self.subscribers.put(key, subscriber);
    }

    /// Unsubscribe an email address from the list
    pub fn unsubscribe(self: *MailingList, email: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.subscribers.fetchRemove(email)) |kv| {
            self.allocator.free(kv.key);
        } else {
            return error.NotSubscribed;
        }
    }

    /// Check if an email is subscribed
    pub fn isSubscribed(self: *MailingList, email: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.subscribers.contains(email);
    }

    /// Get list of all subscribers
    pub fn getSubscribers(self: *MailingList) [][]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var list = std.ArrayList([]const u8).init(self.allocator);

        var it = self.subscribers.iterator();
        while (it.next()) |entry| {
            list.append(entry.key_ptr.*) catch continue;
        }

        return list.toOwnedSlice() catch &[_][]const u8{};
    }

    /// Check if sender is allowed to post
    pub fn canPost(self: *MailingList, sender: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        return switch (self.settings.post_policy) {
            .anyone => true,
            .subscribers_only => self.subscribers.contains(sender),
            .moderated => false, // Would check moderator list
        };
    }

    /// Process incoming message to the list
    pub fn processMessage(self: *MailingList, from: []const u8, message: []const u8) !DistributionResult {
        if (!self.canPost(from)) {
            return DistributionResult{
                .status = .rejected,
                .reason = "Sender not authorized to post to this list",
                .recipients = &[_][]const u8{},
            };
        }

        // Add list headers
        const modified_message = try self.addListHeaders(message);
        defer self.allocator.free(modified_message);

        // Get active subscribers
        const recipients = self.getActiveSubscribers();

        return DistributionResult{
            .status = .distributed,
            .reason = null,
            .recipients = recipients,
        };
    }

    /// Add standard mailing list headers (RFC 2369)
    fn addListHeaders(self: *MailingList, message: []const u8) ![]const u8 {
        var headers = std.ArrayList(u8).init(self.allocator);
        defer headers.deinit();

        // Add list headers before original message
        try std.fmt.format(headers.writer(), "List-Id: {s} <{s}>\r\n", .{ self.name, self.address });
        try std.fmt.format(headers.writer(), "List-Post: <mailto:{s}>\r\n", .{self.address});
        try std.fmt.format(headers.writer(), "List-Help: <mailto:{s}?subject=help>\r\n", .{self.address});
        try std.fmt.format(headers.writer(), "List-Subscribe: <mailto:{s}?subject=subscribe>\r\n", .{self.address});
        try std.fmt.format(headers.writer(), "List-Unsubscribe: <mailto:{s}?subject=unsubscribe>\r\n", .{self.address});

        // RFC 8058: One-Click List-Unsubscribe (Gmail/Yahoo requirement)
        // When List-Unsubscribe-Post is present, mail clients can unsubscribe
        // with a single click without opening a browser or composing an email.
        try std.fmt.format(headers.writer(), "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n", .{});

        // Subject prefix
        if (self.settings.subject_prefix) |prefix| {
            // Would need to parse and modify Subject header
            try std.fmt.format(headers.writer(), "X-List-Prefix: [{s}]\r\n", .{prefix});
        }

        try headers.appendSlice(message);

        return try headers.toOwnedSlice();
    }

    /// Get list of active (enabled) subscribers
    fn getActiveSubscribers(self: *MailingList) [][]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var list = std.ArrayList([]const u8).init(self.allocator);

        var it = self.subscribers.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.enabled and !entry.value_ptr.digest_mode) {
                list.append(entry.key_ptr.*) catch continue;
            }
        }

        return list.toOwnedSlice() catch &[_][]const u8{};
    }

    /// Get subscriber count
    pub fn getSubscriberCount(self: *MailingList) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.subscribers.count();
    }

    /// Enable/disable a subscriber without unsubscribing
    pub fn setSubscriberStatus(self: *MailingList, email: []const u8, enabled: bool) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.subscribers.getPtr(email)) |subscriber| {
            subscriber.enabled = enabled;
        } else {
            return error.NotSubscribed;
        }
    }
};

pub const Subscriber = struct {
    email: []const u8,
    name: ?[]const u8,
    subscribed_at: i64,
    enabled: bool,
    digest_mode: bool, // Receive digest instead of individual messages
};

pub const ListSettings = struct {
    post_policy: PostPolicy = .subscribers_only,
    subject_prefix: ?[]const u8 = null,
    max_message_size: usize = 10 * 1024 * 1024, // 10 MB default
    archive_messages: bool = true,
    moderate_first_post: bool = false,
};

pub const PostPolicy = enum {
    anyone, // Anyone can post
    subscribers_only, // Only subscribers can post
    moderated, // All posts require moderation
};

pub const DistributionResult = struct {
    status: DistributionStatus,
    reason: ?[]const u8,
    recipients: [][]const u8,
};

pub const DistributionStatus = enum {
    distributed,
    rejected,
    held_for_moderation,
};

/// Mailing list manager - manages multiple lists
pub const MailingListManager = struct {
    allocator: std.mem.Allocator,
    lists: std.StringHashMap(*MailingList),
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator) MailingListManager {
        return .{
            .allocator = allocator,
            .lists = std.StringHashMap(*MailingList).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *MailingListManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.lists.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.lists.deinit();
    }

    /// Create a new mailing list
    pub fn createList(
        self: *MailingListManager,
        name: []const u8,
        address: []const u8,
        description: []const u8,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.lists.contains(address)) {
            return error.ListAlreadyExists;
        }

        const list = try self.allocator.create(MailingList);
        errdefer self.allocator.destroy(list);

        list.* = try MailingList.init(self.allocator, name, address, description);

        const key = try self.allocator.dupe(u8, address);
        try self.lists.put(key, list);
    }

    /// Get a mailing list by address
    pub fn getList(self: *MailingListManager, address: []const u8) ?*MailingList {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.lists.get(address);
    }

    /// Delete a mailing list
    pub fn deleteList(self: *MailingListManager, address: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.lists.fetchRemove(address)) |kv| {
            self.allocator.free(kv.key);
            kv.value.deinit();
            self.allocator.destroy(kv.value);
        } else {
            return error.ListNotFound;
        }
    }

    /// Check if an address is a mailing list
    pub fn isList(self: *MailingListManager, address: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.lists.contains(address);
    }

    /// Get all list addresses
    pub fn getAllLists(self: *MailingListManager) [][]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var addresses = std.ArrayList([]const u8).init(self.allocator);

        var it = self.lists.iterator();
        while (it.next()) |entry| {
            addresses.append(entry.key_ptr.*) catch continue;
        }

        return addresses.toOwnedSlice() catch &[_][]const u8{};
    }
};

test "mailing list creation" {
    const testing = std.testing;

    var list = try MailingList.init(
        testing.allocator,
        "Dev Team",
        "dev@example.com",
        "Development team mailing list",
    );
    defer list.deinit();

    try testing.expectEqualStrings("Dev Team", list.name);
    try testing.expectEqualStrings("dev@example.com", list.address);
    try testing.expectEqual(@as(usize, 0), list.getSubscriberCount());
}

test "subscribe and unsubscribe" {
    const testing = std.testing;

    var list = try MailingList.init(
        testing.allocator,
        "Test List",
        "test@example.com",
        "Test mailing list",
    );
    defer list.deinit();

    // Subscribe
    try list.subscribe("user1@example.com", null);
    try testing.expect(list.isSubscribed("user1@example.com"));
    try testing.expectEqual(@as(usize, 1), list.getSubscriberCount());

    // Subscribe another
    try list.subscribe("user2@example.com", null);
    try testing.expectEqual(@as(usize, 2), list.getSubscriberCount());

    // Unsubscribe
    try list.unsubscribe("user1@example.com");
    try testing.expect(!list.isSubscribed("user1@example.com"));
    try testing.expectEqual(@as(usize, 1), list.getSubscriberCount());
}

test "post policy enforcement" {
    const testing = std.testing;

    var list = try MailingList.init(
        testing.allocator,
        "Test List",
        "test@example.com",
        "Test mailing list",
    );
    defer list.deinit();

    // Default: subscribers only
    try testing.expect(!list.canPost("nonsubscriber@example.com"));

    try list.subscribe("subscriber@example.com", null);
    try testing.expect(list.canPost("subscriber@example.com"));

    // Change to anyone can post
    list.settings.post_policy = .anyone;
    try testing.expect(list.canPost("nonsubscriber@example.com"));
}

test "mailing list manager" {
    const testing = std.testing;

    var manager = MailingListManager.init(testing.allocator);
    defer manager.deinit();

    // Create list
    try manager.createList("Dev Team", "dev@example.com", "Development team");
    try testing.expect(manager.isList("dev@example.com"));

    // Get list
    const list = manager.getList("dev@example.com");
    try testing.expect(list != null);
    try testing.expectEqualStrings("Dev Team", list.?.name);

    // Subscribe to list
    try list.?.subscribe("user@example.com", null);
    try testing.expectEqual(@as(usize, 1), list.?.getSubscriberCount());

    // Delete list
    try manager.deleteList("dev@example.com");
    try testing.expect(!manager.isList("dev@example.com"));
}

test "subscriber status management" {
    const testing = std.testing;

    var list = try MailingList.init(
        testing.allocator,
        "Test List",
        "test@example.com",
        "Test mailing list",
    );
    defer list.deinit();

    try list.subscribe("user@example.com", null);

    // Disable subscriber
    try list.setSubscriberStatus("user@example.com", false);

    // Still subscribed, but won't receive messages
    try testing.expect(list.isSubscribed("user@example.com"));

    // Re-enable
    try list.setSubscriberStatus("user@example.com", true);
}
