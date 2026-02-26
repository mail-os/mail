const std = @import("std");

// =============================================================================
// Read Receipts / Message Disposition Notifications (MDN)
// =============================================================================
//
// ## Overview
// Implements RFC 8098 (Message Disposition Notification) for read receipts.
// Allows senders to request and track when recipients open their emails.
//
// ## Headers Used
// - Disposition-Notification-To: Request a read receipt
// - Disposition-Notification-Options: Additional options
// - Original-Message-ID: Reference to original message
//
// =============================================================================

/// Read receipt errors
pub const ReceiptError = error{
    ReceiptNotFound,
    InvalidMessageId,
    AlreadySent,
    RecipientDenied,
    OutOfMemory,
};

/// Receipt request status
pub const ReceiptStatus = enum {
    /// Receipt requested but not yet sent
    pending,
    /// Recipient opened the message
    read,
    /// Recipient explicitly denied sending receipt
    denied,
    /// Receipt sent successfully
    sent,
    /// Message was deleted without reading
    deleted,
    /// Receipt request expired
    expired,

    pub fn toString(self: ReceiptStatus) []const u8 {
        return switch (self) {
            .pending => "Pending",
            .read => "Read",
            .denied => "Denied",
            .sent => "Sent",
            .deleted => "Deleted",
            .expired => "Expired",
        };
    }
};

/// Disposition type for MDN
pub const DispositionType = enum {
    /// Message was displayed to user
    displayed,
    /// Message was deleted without display
    deleted,
    /// Message was dispatched (forwarded/redirected)
    dispatched,
    /// Message was processed (by automated system)
    processed,

    pub fn toString(self: DispositionType) []const u8 {
        return switch (self) {
            .displayed => "displayed",
            .deleted => "deleted",
            .dispatched => "dispatched",
            .processed => "processed",
        };
    }
};

/// Read receipt request
pub const ReadReceiptRequest = struct {
    /// Unique ID for this request
    id: []const u8,
    /// Message-ID of the original message
    message_id: []const u8,
    /// Subject of the original message
    subject: []const u8,
    /// Sender who requested the receipt
    sender: []const u8,
    /// Recipient who should send the receipt
    recipient: []const u8,
    /// Current status
    status: ReceiptStatus,
    /// When the request was created
    requested_at: i64,
    /// When the message was read (if applicable)
    read_at: ?i64,
    /// When the receipt was sent (if applicable)
    sent_at: ?i64,
    /// User agent that read the message
    user_agent: ?[]const u8,

    pub fn toJson(self: *const ReadReceiptRequest, allocator: std.mem.Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        errdefer buffer.deinit();
        const writer = buffer.writer();

        try writer.writeAll("{");
        try writer.print("\"id\":\"{s}\",", .{self.id});
        try writer.print("\"message_id\":\"{s}\",", .{self.message_id});
        try writer.print("\"subject\":\"{s}\",", .{escapeJson(self.subject)});
        try writer.print("\"sender\":\"{s}\",", .{self.sender});
        try writer.print("\"recipient\":\"{s}\",", .{self.recipient});
        try writer.print("\"status\":\"{s}\",", .{self.status.toString()});
        try writer.print("\"requested_at\":{d},", .{self.requested_at});

        if (self.read_at) |t| {
            try writer.print("\"read_at\":{d},", .{t});
        } else {
            try writer.writeAll("\"read_at\":null,");
        }

        if (self.sent_at) |t| {
            try writer.print("\"sent_at\":{d}", .{t});
        } else {
            try writer.writeAll("\"sent_at\":null");
        }

        try writer.writeAll("}");
        return buffer.toOwnedSlice();
    }
};

/// Read receipt manager
pub const ReadReceiptManager = struct {
    allocator: std.mem.Allocator,
    /// Outgoing requests (we requested receipts)
    outgoing: std.StringHashMap(ReadReceiptRequest),
    /// Incoming requests (others requested receipts from us)
    incoming: std.StringHashMap(ReadReceiptRequest),
    config: ReceiptConfig,

    pub const ReceiptConfig = struct {
        /// Auto-send receipts when messages are read
        auto_send: bool = false,
        /// Ask before sending receipts
        ask_before_send: bool = true,
        /// Never send receipts
        never_send: bool = false,
        /// Expiry time for pending requests (seconds)
        expiry_time: i64 = 7 * 24 * 60 * 60, // 7 days
    };

    pub fn init(allocator: std.mem.Allocator, config: ReceiptConfig) ReadReceiptManager {
        return .{
            .allocator = allocator,
            .outgoing = std.StringHashMap(ReadReceiptRequest).init(allocator),
            .incoming = std.StringHashMap(ReadReceiptRequest).init(allocator),
            .config = config,
        };
    }

    pub fn deinit(self: *ReadReceiptManager) void {
        var out_it = self.outgoing.iterator();
        while (out_it.next()) |entry| {
            self.freeRequest(entry.key_ptr.*, entry.value_ptr.*);
        }
        self.outgoing.deinit();

        var in_it = self.incoming.iterator();
        while (in_it.next()) |entry| {
            self.freeRequest(entry.key_ptr.*, entry.value_ptr.*);
        }
        self.incoming.deinit();
    }

    fn freeRequest(self: *ReadReceiptManager, key: []const u8, req: ReadReceiptRequest) void {
        self.allocator.free(key);
        self.allocator.free(req.id);
        self.allocator.free(req.message_id);
        self.allocator.free(req.subject);
        self.allocator.free(req.sender);
        self.allocator.free(req.recipient);
        if (req.user_agent) |ua| self.allocator.free(ua);
    }

    /// Request a read receipt for an outgoing message
    pub fn requestReceipt(
        self: *ReadReceiptManager,
        message_id: []const u8,
        subject: []const u8,
        sender: []const u8,
        recipient: []const u8,
    ) ![]const u8 {
        var rand_bytes: [8]u8 = undefined;
        std.c.arc4random_buf(&rand_bytes, rand_bytes.len);
        const timestamp = std.time.timestamp();

        const id = try std.fmt.allocPrint(self.allocator, "rcpt_{x}_{x}", .{
            @as(u64, @intCast(timestamp)),
            std.mem.readInt(u64, &rand_bytes, .big),
        });
        errdefer self.allocator.free(id);

        const request = ReadReceiptRequest{
            .id = id,
            .message_id = try self.allocator.dupe(u8, message_id),
            .subject = try self.allocator.dupe(u8, subject),
            .sender = try self.allocator.dupe(u8, sender),
            .recipient = try self.allocator.dupe(u8, recipient),
            .status = .pending,
            .requested_at = timestamp,
            .read_at = null,
            .sent_at = null,
            .user_agent = null,
        };

        const key = try self.allocator.dupe(u8, id);
        try self.outgoing.put(key, request);

        return id;
    }

    /// Record an incoming read receipt request
    pub fn recordIncoming(
        self: *ReadReceiptManager,
        message_id: []const u8,
        subject: []const u8,
        sender: []const u8,
        recipient: []const u8,
    ) ![]const u8 {
        var rand_bytes: [8]u8 = undefined;
        std.c.arc4random_buf(&rand_bytes, rand_bytes.len);
        const timestamp = std.time.timestamp();

        const id = try std.fmt.allocPrint(self.allocator, "in_rcpt_{x}_{x}", .{
            @as(u64, @intCast(timestamp)),
            std.mem.readInt(u64, &rand_bytes, .big),
        });
        errdefer self.allocator.free(id);

        const request = ReadReceiptRequest{
            .id = id,
            .message_id = try self.allocator.dupe(u8, message_id),
            .subject = try self.allocator.dupe(u8, subject),
            .sender = try self.allocator.dupe(u8, sender),
            .recipient = try self.allocator.dupe(u8, recipient),
            .status = .pending,
            .requested_at = timestamp,
            .read_at = null,
            .sent_at = null,
            .user_agent = null,
        };

        const key = try self.allocator.dupe(u8, id);
        try self.incoming.put(key, request);

        return id;
    }

    /// Mark a message as read (for incoming requests)
    pub fn markRead(self: *ReadReceiptManager, request_id: []const u8, user_agent: ?[]const u8) !void {
        if (self.incoming.getPtr(request_id)) |req| {
            req.status = .read;
            req.read_at = std.time.timestamp();
            if (user_agent) |ua| {
                if (req.user_agent) |old| self.allocator.free(old);
                req.user_agent = try self.allocator.dupe(u8, ua);
            }
        } else {
            return ReceiptError.ReceiptNotFound;
        }
    }

    /// Send a read receipt (for incoming requests)
    pub fn sendReceipt(self: *ReadReceiptManager, request_id: []const u8) !void {
        if (self.incoming.getPtr(request_id)) |req| {
            if (req.status == .sent) return ReceiptError.AlreadySent;
            if (self.config.never_send) return ReceiptError.RecipientDenied;

            req.status = .sent;
            req.sent_at = std.time.timestamp();
        } else {
            return ReceiptError.ReceiptNotFound;
        }
    }

    /// Deny sending a receipt
    pub fn denyReceipt(self: *ReadReceiptManager, request_id: []const u8) !void {
        if (self.incoming.getPtr(request_id)) |req| {
            req.status = .denied;
        } else {
            return ReceiptError.ReceiptNotFound;
        }
    }

    /// Update outgoing receipt status (when we receive a receipt)
    pub fn updateOutgoing(self: *ReadReceiptManager, message_id: []const u8, status: ReceiptStatus) !void {
        var it = self.outgoing.iterator();
        while (it.next()) |entry| {
            if (std.mem.eql(u8, entry.value_ptr.message_id, message_id)) {
                entry.value_ptr.status = status;
                if (status == .read or status == .sent) {
                    entry.value_ptr.read_at = std.time.timestamp();
                }
                return;
            }
        }
        return ReceiptError.ReceiptNotFound;
    }

    /// Get all outgoing (sent) requests
    pub fn getOutgoing(self: *const ReadReceiptManager, allocator: std.mem.Allocator) ![]const ReadReceiptRequest {
        var result = try allocator.alloc(ReadReceiptRequest, self.outgoing.count());
        var i: usize = 0;

        var it = self.outgoing.iterator();
        while (it.next()) |entry| {
            result[i] = entry.value_ptr.*;
            i += 1;
        }

        return result;
    }

    /// Get all incoming requests
    pub fn getIncoming(self: *const ReadReceiptManager, allocator: std.mem.Allocator) ![]const ReadReceiptRequest {
        var result = try allocator.alloc(ReadReceiptRequest, self.incoming.count());
        var i: usize = 0;

        var it = self.incoming.iterator();
        while (it.next()) |entry| {
            result[i] = entry.value_ptr.*;
            i += 1;
        }

        return result;
    }

    /// Get pending incoming requests
    pub fn getPendingIncoming(self: *const ReadReceiptManager, allocator: std.mem.Allocator) ![]const ReadReceiptRequest {
        var count: usize = 0;
        var it = self.incoming.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.status == .pending or entry.value_ptr.status == .read) {
                count += 1;
            }
        }

        var result = try allocator.alloc(ReadReceiptRequest, count);
        var i: usize = 0;

        it = self.incoming.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.status == .pending or entry.value_ptr.status == .read) {
                result[i] = entry.value_ptr.*;
                i += 1;
            }
        }

        return result;
    }

    /// Clean up expired requests
    pub fn cleanupExpired(self: *ReadReceiptManager) usize {
        const now = std.time.timestamp();
        var removed: usize = 0;

        // Clean outgoing
        var keys_to_remove = std.ArrayList([]const u8).init(self.allocator);
        defer keys_to_remove.deinit();

        var it = self.outgoing.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.status == .pending) {
                if (now - entry.value_ptr.requested_at > self.config.expiry_time) {
                    keys_to_remove.append(entry.key_ptr.*) catch continue;
                }
            }
        }

        for (keys_to_remove.items) |key| {
            if (self.outgoing.fetchRemove(key)) |entry| {
                self.freeRequest(entry.key, entry.value);
                removed += 1;
            }
        }

        return removed;
    }

    /// Generate MDN email content
    pub fn generateMDN(
        self: *ReadReceiptManager,
        request: *const ReadReceiptRequest,
        disposition: DispositionType,
    ) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\From: {s}
            \\To: {s}
            \\Subject: Read: {s}
            \\MIME-Version: 1.0
            \\Content-Type: multipart/report; report-type=disposition-notification
            \\
            \\This is a message disposition notification.
            \\
            \\The message sent on {d} to {s}
            \\with subject "{s}"
            \\has been {s}.
            \\
            \\Original-Message-ID: {s}
            \\Disposition: automatic-action/MDN-sent-automatically; {s}
        , .{
            request.recipient,
            request.sender,
            request.subject,
            request.requested_at,
            request.recipient,
            request.subject,
            disposition.toString(),
            request.message_id,
            disposition.toString(),
        });
    }

    /// Get statistics
    pub fn getStats(self: *const ReadReceiptManager) ReceiptStats {
        var pending_out: usize = 0;
        var read_out: usize = 0;

        var out_it = self.outgoing.iterator();
        while (out_it.next()) |entry| {
            if (entry.value_ptr.status == .pending) pending_out += 1;
            if (entry.value_ptr.status == .read or entry.value_ptr.status == .sent) read_out += 1;
        }

        var pending_in: usize = 0;
        var in_it = self.incoming.iterator();
        while (in_it.next()) |entry| {
            if (entry.value_ptr.status == .pending or entry.value_ptr.status == .read) pending_in += 1;
        }

        return .{
            .outgoing_total = self.outgoing.count(),
            .outgoing_pending = pending_out,
            .outgoing_read = read_out,
            .incoming_total = self.incoming.count(),
            .incoming_pending = pending_in,
        };
    }
};

/// Receipt statistics
pub const ReceiptStats = struct {
    outgoing_total: usize,
    outgoing_pending: usize,
    outgoing_read: usize,
    incoming_total: usize,
    incoming_pending: usize,
};

/// Generate Disposition-Notification-To header
pub fn generateReceiptHeader(sender_email: []const u8, allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator, "Disposition-Notification-To: {s}", .{sender_email});
}

/// Parse Disposition-Notification-To header
pub fn parseReceiptHeader(header_value: []const u8) []const u8 {
    var value = header_value;
    // Remove angle brackets if present
    if (std.mem.startsWith(u8, value, "<")) value = value[1..];
    if (value.len > 0 and value[value.len - 1] == '>') value = value[0 .. value.len - 1];
    return std.mem.trim(u8, value, " \t");
}

fn escapeJson(s: []const u8) []const u8 {
    return s;
}

// =============================================================================
// Tests
// =============================================================================

test "ReadReceiptManager request and update" {
    const allocator = std.testing.allocator;

    var manager = ReadReceiptManager.init(allocator, .{});
    defer manager.deinit();

    const id = try manager.requestReceipt(
        "<msg123@example.com>",
        "Test Subject",
        "sender@example.com",
        "recipient@example.com",
    );

    const requests = try manager.getOutgoing(allocator);
    defer allocator.free(requests);

    try std.testing.expectEqual(@as(usize, 1), requests.len);
    try std.testing.expectEqual(ReceiptStatus.pending, requests[0].status);

    try manager.updateOutgoing("<msg123@example.com>", .read);

    const updated = try manager.getOutgoing(allocator);
    defer allocator.free(updated);

    try std.testing.expectEqual(ReceiptStatus.read, updated[0].status);
    _ = id;
}

test "ReadReceiptManager incoming flow" {
    const allocator = std.testing.allocator;

    var manager = ReadReceiptManager.init(allocator, .{});
    defer manager.deinit();

    const id = try manager.recordIncoming(
        "<msg456@example.com>",
        "Incoming Test",
        "sender@example.com",
        "me@example.com",
    );

    try manager.markRead(id, "Mozilla/5.0");
    try manager.sendReceipt(id);

    const incoming = try manager.getIncoming(allocator);
    defer allocator.free(incoming);

    try std.testing.expectEqual(ReceiptStatus.sent, incoming[0].status);
    try std.testing.expect(incoming[0].read_at != null);
    try std.testing.expect(incoming[0].sent_at != null);
}

test "ReceiptStatus toString" {
    try std.testing.expectEqualStrings("Pending", ReceiptStatus.pending.toString());
    try std.testing.expectEqualStrings("Read", ReceiptStatus.read.toString());
}

test "parseReceiptHeader" {
    try std.testing.expectEqualStrings("test@example.com", parseReceiptHeader("<test@example.com>"));
    try std.testing.expectEqualStrings("test@example.com", parseReceiptHeader("  test@example.com  "));
}
