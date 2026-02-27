const std = @import("std");
const io_compat = @import("../core/io_compat.zig");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");
const net = std.net;
const Allocator = std.mem.Allocator;
const crypto = std.crypto;
const logger = @import("../core/logger.zig");

/// WebSocket Protocol Implementation (RFC 6455)
/// Provides real-time bidirectional communication for notifications

// ============================================================================
// Configuration
// ============================================================================

pub const WebSocketConfig = struct {
    port: u16 = 8080,
    ssl_port: u16 = 8443,
    enable_ssl: bool = true,
    max_connections: usize = 1000,
    ping_interval_seconds: u64 = 30,
    connection_timeout_seconds: u64 = 300,
    max_message_size: usize = 1024 * 1024, // 1 MB
    compression: bool = false, // permessage-deflate extension
};

// ============================================================================
// WebSocket Frame
// ============================================================================

pub const OpCode = enum(u8) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
};

pub const Frame = struct {
    fin: bool,
    rsv1: bool = false,
    rsv2: bool = false,
    rsv3: bool = false,
    opcode: OpCode,
    masked: bool,
    payload_length: u64,
    masking_key: ?[4]u8 = null,
    payload: []u8,

    pub fn deinit(self: *Frame, allocator: Allocator) void {
        allocator.free(self.payload);
    }
};

// ============================================================================
// WebSocket State
// ============================================================================

pub const WebSocketState = enum {
    connecting,
    open,
    closing,
    closed,
};

// ============================================================================
// Notification Events
// ============================================================================

pub const NotificationEvent = union(enum) {
    // Email events
    new_email: struct {
        message_id: []const u8,
        from: []const u8,
        subject: []const u8,
        folder: []const u8,
    },
    email_deleted: struct {
        message_id: []const u8,
        folder: []const u8,
    },
    email_moved: struct {
        message_id: []const u8,
        from_folder: []const u8,
        to_folder: []const u8,
    },
    email_read: struct {
        message_id: []const u8,
        folder: []const u8,
    },
    email_starred: struct {
        message_id: []const u8,
        starred: bool,
    },

    // Folder events
    folder_created: struct {
        folder_id: []const u8,
        folder_name: []const u8,
    },
    folder_deleted: struct {
        folder_id: []const u8,
    },
    folder_renamed: struct {
        folder_id: []const u8,
        old_name: []const u8,
        new_name: []const u8,
    },

    // Calendar events
    calendar_event_added: struct {
        event_id: []const u8,
        summary: []const u8,
        start_time: i64,
    },
    calendar_event_updated: struct {
        event_id: []const u8,
        summary: []const u8,
    },
    calendar_event_deleted: struct {
        event_id: []const u8,
    },

    // Contact events
    contact_added: struct {
        contact_id: []const u8,
        display_name: []const u8,
    },
    contact_updated: struct {
        contact_id: []const u8,
    },
    contact_deleted: struct {
        contact_id: []const u8,
    },

    // Server events
    sync_started: struct {
        sync_type: []const u8,
    },
    sync_completed: struct {
        sync_type: []const u8,
        items_synced: usize,
    },
    quota_warning: struct {
        used_bytes: u64,
        total_bytes: u64,
        percentage: f64,
    },
};

// ============================================================================
// WebSocket Session
// ============================================================================

pub const WebSocketSession = struct {
    allocator: Allocator,
    stream: net.Stream,
    state: WebSocketState,
    username: ?[]const u8 = null,
    subscriptions: std.ArrayList([]const u8), // Event types to receive
    last_ping: i64,
    last_pong: i64,
    config: WebSocketConfig,

    pub fn init(allocator: Allocator, stream: net.Stream, config: WebSocketConfig) !WebSocketSession {
        return WebSocketSession{
            .allocator = allocator,
            .stream = stream,
            .state = .connecting,
            .subscriptions = std.ArrayList([]const u8){},
            .last_ping = time_compat.timestamp(),
            .config = config,
            .last_pong = time_compat.timestamp(),
        };
    }

    pub fn deinit(self: *WebSocketSession) void {
        for (self.subscriptions.items) |sub| {
            self.allocator.free(sub);
        }
        self.subscriptions.deinit(self.allocator);
        if (self.username) |username| {
            self.allocator.free(username);
        }
    }

    /// Perform WebSocket handshake
    pub fn handshake(self: *WebSocketSession) !void {
        var buffer: [4096]u8 = undefined;
        const bytes_read = try self.stream.read(&buffer);

        if (bytes_read == 0) {
            return error.ConnectionClosed;
        }

        const request = buffer[0..bytes_read];

        // Parse HTTP headers
        var lines = std.mem.splitScalar(u8, request, '\n');
        const request_line = lines.next() orelse return error.InvalidRequest;

        // Verify it's a GET request to WebSocket endpoint
        if (!std.mem.startsWith(u8, request_line, "GET ")) {
            return error.InvalidMethod;
        }

        var websocket_key: ?[]const u8 = null;
        var upgrade_header: ?[]const u8 = null;
        var connection_header: ?[]const u8 = null;
        var version_header: ?[]const u8 = null;

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
            if (trimmed.len == 0) break;

            if (std.mem.startsWith(u8, trimmed, "Sec-WebSocket-Key:")) {
                websocket_key = std.mem.trim(u8, trimmed[18..], &std.ascii.whitespace);
            } else if (std.mem.startsWith(u8, trimmed, "Upgrade:")) {
                upgrade_header = std.mem.trim(u8, trimmed[8..], &std.ascii.whitespace);
            } else if (std.mem.startsWith(u8, trimmed, "Connection:")) {
                connection_header = std.mem.trim(u8, trimmed[11..], &std.ascii.whitespace);
            } else if (std.mem.startsWith(u8, trimmed, "Sec-WebSocket-Version:")) {
                version_header = std.mem.trim(u8, trimmed[22..], &std.ascii.whitespace);
            }
        }

        // Validate handshake headers
        if (websocket_key == null) return error.MissingWebSocketKey;
        if (upgrade_header == null or !std.mem.eql(u8, upgrade_header.?, "websocket")) {
            return error.InvalidUpgradeHeader;
        }
        if (version_header == null or !std.mem.eql(u8, version_header.?, "13")) {
            return error.UnsupportedVersion;
        }

        // Generate Sec-WebSocket-Accept
        const accept_key = try self.generateAcceptKey(websocket_key.?);
        defer self.allocator.free(accept_key);

        // Send handshake response
        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 101 Switching Protocols\r\n" ++
                "Upgrade: websocket\r\n" ++
                "Connection: Upgrade\r\n" ++
                "Sec-WebSocket-Accept: {s}\r\n" ++
                "\r\n",
            .{accept_key},
        );
        defer self.allocator.free(response);

        _ = try self.stream.write(response);
        self.state = .open;

        logger.debug("WebSocket handshake completed", .{});
    }

    /// Generate Sec-WebSocket-Accept key
    fn generateAcceptKey(self: *WebSocketSession, key: []const u8) ![]u8 {
        const magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

        // Concatenate key + magic string
        const concat = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ key, magic_string });
        defer self.allocator.free(concat);

        // SHA-1 hash
        var hash: [20]u8 = undefined;
        crypto.hash.Sha1.hash(concat, &hash, .{});

        // Base64 encode
        const encoder = std.base64.standard.Encoder;
        const encoded_len = encoder.calcSize(hash.len);
        const encoded = try self.allocator.alloc(u8, encoded_len);
        _ = encoder.encode(encoded, &hash);

        return encoded;
    }

    /// Read a WebSocket frame
    pub fn readFrame(self: *WebSocketSession) !Frame {
        var buffer: [14]u8 = undefined;

        // Read first 2 bytes
        var bytes_read = try self.stream.read(buffer[0..2]);
        if (bytes_read < 2) return error.ConnectionClosed;

        const byte1 = buffer[0];
        const byte2 = buffer[1];

        const fin = (byte1 & 0x80) != 0;
        const rsv1 = (byte1 & 0x40) != 0;
        const rsv2 = (byte1 & 0x20) != 0;
        const rsv3 = (byte1 & 0x10) != 0;
        const opcode_val = byte1 & 0x0F;
        const masked = (byte2 & 0x80) != 0;
        var payload_len: u64 = @as(u64, byte2 & 0x7F);

        const opcode: OpCode = switch (opcode_val) {
            0x0 => .continuation,
            0x1 => .text,
            0x2 => .binary,
            0x8 => .close,
            0x9 => .ping,
            0xA => .pong,
            else => return error.InvalidOpCode,
        };

        // Extended payload length
        if (payload_len == 126) {
            bytes_read = try self.stream.read(buffer[0..2]);
            if (bytes_read < 2) return error.ConnectionClosed;
            payload_len = std.mem.readInt(u16, buffer[0..2], .big);
        } else if (payload_len == 127) {
            bytes_read = try self.stream.read(buffer[0..8]);
            if (bytes_read < 8) return error.ConnectionClosed;
            payload_len = std.mem.readInt(u64, buffer[0..8], .big);
        }

        // Validate payload size against configured maximum
        if (payload_len > self.config.max_message_size) {
            std.log.warn("WebSocket message too large: {d} bytes (max: {d})", .{ payload_len, self.config.max_message_size });
            try self.sendClose(1009, "Message too large");
            return error.MessageTooLarge;
        }

        // Additional safety check: prevent unreasonably large messages (16MB absolute max)
        const absolute_max: usize = 16 * 1024 * 1024;
        if (payload_len > absolute_max) {
            std.log.err("WebSocket message exceeds absolute maximum: {d} bytes", .{payload_len});
            try self.sendClose(1009, "Message too large");
            return error.MessageTooLarge;
        }

        // Read masking key if present
        var masking_key: ?[4]u8 = null;
        if (masked) {
            bytes_read = try self.stream.read(buffer[0..4]);
            if (bytes_read < 4) return error.ConnectionClosed;
            masking_key = buffer[0..4].*;
        }

        // Read payload
        const payload = try self.allocator.alloc(u8, @intCast(payload_len));
        errdefer self.allocator.free(payload);

        var total_read: usize = 0;
        while (total_read < payload_len) {
            const n = try self.stream.read(payload[total_read..]);
            if (n == 0) return error.ConnectionClosed;
            total_read += n;
        }

        // Unmask payload if masked
        if (masked and masking_key != null) {
            for (payload, 0..) |*byte, i| {
                byte.* ^= masking_key.?[i % 4];
            }
        }

        return Frame{
            .fin = fin,
            .rsv1 = rsv1,
            .rsv2 = rsv2,
            .rsv3 = rsv3,
            .opcode = opcode,
            .masked = masked,
            .payload_length = payload_len,
            .masking_key = masking_key,
            .payload = payload,
        };
    }

    /// Send a WebSocket frame
    pub fn sendFrame(self: *WebSocketSession, opcode: OpCode, payload: []const u8) !void {
        var frame_header = std.ArrayList(u8){};
        defer frame_header.deinit(self.allocator);

        // First byte: FIN + RSV + OpCode
        const byte1: u8 = 0x80 | @intFromEnum(opcode); // FIN=1, RSV=0, OpCode
        try frame_header.append(self.allocator, byte1);

        // Second byte: MASK + Payload length
        const payload_len = payload.len;
        if (payload_len < 126) {
            try frame_header.append(self.allocator, @intCast(payload_len));
        } else if (payload_len < 65536) {
            try frame_header.append(self.allocator, 126);
            const len_bytes = std.mem.toBytes(@as(u16, @intCast(payload_len)));
            try frame_header.appendSlice(self.allocator, &[_]u8{ len_bytes[1], len_bytes[0] });
        } else {
            try frame_header.append(self.allocator, 127);
            const len_bytes = std.mem.toBytes(@as(u64, payload_len));
            for (0..8) |i| {
                try frame_header.append(self.allocator, len_bytes[7 - i]);
            }
        }

        // Send frame header + payload
        _ = try self.stream.write(frame_header.items);
        _ = try self.stream.write(payload);
    }

    /// Send text message
    pub fn sendText(self: *WebSocketSession, message: []const u8) !void {
        try self.sendFrame(.text, message);
    }

    /// Send JSON message
    pub fn sendJson(self: *WebSocketSession, data: anytype) !void {
        var buffer = std.ArrayList(u8){};
        defer buffer.deinit(self.allocator);

        const writer = buffer.writer(self.allocator);
        try std.json.stringify(data, .{}, writer);
        try self.sendText(buffer.items);
    }

    /// Send ping
    pub fn sendPing(self: *WebSocketSession) !void {
        self.last_ping = time_compat.timestamp();
        try self.sendFrame(.ping, "");
    }

    /// Send pong
    pub fn sendPong(self: *WebSocketSession) !void {
        self.last_pong = time_compat.timestamp();
        try self.sendFrame(.pong, "");
    }

    /// Send close frame
    pub fn sendClose(self: *WebSocketSession, code: u16, reason: []const u8) !void {
        var close_payload = std.ArrayList(u8){};
        defer close_payload.deinit(self.allocator);

        // Add close code (big-endian u16)
        const code_bytes = std.mem.toBytes(code);
        try close_payload.appendSlice(self.allocator, &[_]u8{ code_bytes[1], code_bytes[0] });
        try close_payload.appendSlice(self.allocator, reason);

        try self.sendFrame(.close, close_payload.items);
        self.state = .closing;
    }

    /// Subscribe to event type
    pub fn subscribe(self: *WebSocketSession, event_type: []const u8) !void {
        const event_copy = try self.allocator.dupe(u8, event_type);
        try self.subscriptions.append(self.allocator, event_copy);
        logger.debug("WebSocket subscribed to: {s}", .{event_type});
    }

    /// Check if subscribed to event type
    pub fn isSubscribed(self: *WebSocketSession, event_type: []const u8) bool {
        for (self.subscriptions.items) |sub| {
            if (std.mem.eql(u8, sub, event_type)) return true;
        }
        return false;
    }
};

// ============================================================================
// Notification Manager
// ============================================================================

pub const NotificationManager = struct {
    allocator: Allocator,
    sessions: std.ArrayList(*WebSocketSession),
    sessions_mutex: mutex_compat.Mutex,

    pub fn init(allocator: Allocator) NotificationManager {
        return NotificationManager{
            .allocator = allocator,
            .sessions = std.ArrayList(*WebSocketSession){},
            .sessions_mutex = mutex_compat.Mutex{},
        };
    }

    pub fn deinit(self: *NotificationManager) void {
        self.sessions_mutex.lock();
        defer self.sessions_mutex.unlock();

        self.sessions.deinit(self.allocator);
    }

    /// Register a new session
    pub fn registerSession(self: *NotificationManager, session: *WebSocketSession) !void {
        self.sessions_mutex.lock();
        defer self.sessions_mutex.unlock();

        try self.sessions.append(self.allocator, session);
    }

    /// Unregister a session
    pub fn unregisterSession(self: *NotificationManager, session: *WebSocketSession) void {
        self.sessions_mutex.lock();
        defer self.sessions_mutex.unlock();

        for (self.sessions.items, 0..) |s, i| {
            if (s == session) {
                _ = self.sessions.swapRemove(i);
                break;
            }
        }
    }

    /// Broadcast notification to all subscribed sessions
    pub fn broadcast(self: *NotificationManager, event: NotificationEvent) !void {
        self.sessions_mutex.lock();
        defer self.sessions_mutex.unlock();

        const event_type = @tagName(event);

        var json_buffer = std.ArrayList(u8){};
        defer json_buffer.deinit(self.allocator);

        // Serialize event to JSON
        const Event = struct {
            type: []const u8,
            timestamp: i64,
            data: NotificationEvent,
        };

        const json_event = Event{
            .type = event_type,
            .timestamp = time_compat.timestamp(),
            .data = event,
        };

        const writer = json_buffer.writer(self.allocator);
        try std.json.stringify(json_event, .{}, writer);

        // Send to all subscribed sessions
        for (self.sessions.items) |session| {
            if (session.state != .open) continue;
            if (!session.isSubscribed(event_type) and !session.isSubscribed("*")) continue;

            session.sendText(json_buffer.items) catch |err| {
                logger.err("WebSocket failed to send to session: {}", .{err});
            };
        }
    }
};

// ============================================================================
// WebSocket Server
// ============================================================================

pub const WebSocketServer = struct {
    allocator: Allocator,
    config: WebSocketConfig,
    server: ?net.Server = null,
    running: std.atomic.Value(bool),
    notification_manager: NotificationManager,

    pub fn init(allocator: Allocator, config: WebSocketConfig) WebSocketServer {
        return WebSocketServer{
            .allocator = allocator,
            .config = config,
            .running = std.atomic.Value(bool).init(false),
            .notification_manager = NotificationManager.init(allocator),
        };
    }

    pub fn deinit(self: *WebSocketServer) void {
        self.stop();
        self.notification_manager.deinit();
    }

    /// Start the WebSocket server
    pub fn start(self: *WebSocketServer) !void {
        const address = try net.Address.parseIp("0.0.0.0", self.config.port);

        self.server = try address.listen(.{
            .reuse_address = true,
            .reuse_port = true,
        });

        self.running.store(true, .seq_cst);

        logger.info("WebSocket server started on port {d}", .{self.config.port});

        while (self.running.load(.seq_cst)) {
            const connection = self.server.?.accept() catch |err| {
                logger.err("WebSocket accept error: {}", .{err});
                continue;
            };

            // Handle connection in new thread
            const thread = try std.Thread.spawn(.{}, handleConnection, .{ self, connection.stream });
            thread.detach();
        }
    }

    /// Stop the server
    pub fn stop(self: *WebSocketServer) void {
        self.running.store(false, .seq_cst);
        if (self.server) |*server| {
            server.deinit();
            self.server = null;
        }
    }

    /// Handle WebSocket connection
    fn handleConnection(self: *WebSocketServer, stream: net.Stream) void {
        defer stream.close();

        var session = WebSocketSession.init(self.allocator, stream, self.config) catch |err| {
            logger.err("WebSocket session init error: {}", .{err});
            return;
        };
        defer session.deinit();

        // Perform handshake
        session.handshake() catch |err| {
            logger.err("WebSocket handshake error: {}", .{err});
            return;
        };

        // Register session
        self.notification_manager.registerSession(&session) catch return;
        defer self.notification_manager.unregisterSession(&session);

        // Handle messages
        while (session.state == .open) {
            var frame = session.readFrame() catch |err| {
                logger.err("WebSocket read frame error: {}", .{err});
                break;
            };
            defer frame.deinit(self.allocator);

            switch (frame.opcode) {
                .text => {
                    // Handle text message (e.g., subscription requests)
                    self.handleTextMessage(&session, frame.payload) catch |err| {
                        logger.err("WebSocket handle message error: {}", .{err});
                    };
                },
                .binary => {
                    // Handle binary message
                },
                .close => {
                    session.sendClose(1000, "Normal closure") catch {};
                    break;
                },
                .ping => {
                    session.sendPong() catch {};
                },
                .pong => {
                    session.last_pong = time_compat.timestamp();
                },
                else => {},
            }
        }

        logger.debug("WebSocket session ended", .{});
    }

    /// Handle text message from client
    fn handleTextMessage(self: *WebSocketServer, session: *WebSocketSession, message: []const u8) !void {
        // Parse JSON message
        const Message = struct {
            action: []const u8,
            event_type: ?[]const u8 = null,
        };

        const parsed = std.json.parseFromSlice(
            Message,
            self.allocator,
            message,
            .{},
        ) catch {
            const ErrorResponse = struct {
                @"error": []const u8,
            };
            try session.sendJson(ErrorResponse{ .@"error" = "Invalid JSON" });
            return;
        };
        defer parsed.deinit();

        const msg = parsed.value;

        if (std.mem.eql(u8, msg.action, "subscribe")) {
            if (msg.event_type) |event_type| {
                try session.subscribe(event_type);
                const SubscribeResponse = struct {
                    status: []const u8,
                    event_type: []const u8,
                };
                try session.sendJson(SubscribeResponse{
                    .status = "subscribed",
                    .event_type = event_type,
                });
            }
        } else if (std.mem.eql(u8, msg.action, "ping")) {
            const PingResponse = struct {
                status: []const u8,
                timestamp: i64,
            };
            try session.sendJson(PingResponse{
                .status = "pong",
                .timestamp = time_compat.timestamp(),
            });
        }
    }

    /// Get notification manager
    pub fn getNotificationManager(self: *WebSocketServer) *NotificationManager {
        return &self.notification_manager;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "WebSocket server initialization" {
    const testing = std.testing;

    const config = WebSocketConfig{};
    var server = WebSocketServer.init(testing.allocator, config);
    defer server.deinit();

    try testing.expect(!server.running.load(.seq_cst));
}

test "WebSocket accept key generation" {
    const testing = std.testing;

    const address = try net.Address.parseIp("127.0.0.1", 0);
    var listener = try address.listen(.{});
    defer listener.deinit();

    // Create a mock connection for testing
    const listen_addr = listener.listen_address;
    const connect_thread = try std.Thread.spawn(.{}, struct {
        fn connect(addr: net.Address) void {
            const stream = net.tcpConnectToAddress(addr) catch return;
            defer stream.close();
            std.Thread.sleep(100 * std.time.ns_per_ms);
        }
    }.connect, .{listen_addr});

    const conn = try listener.accept();
    defer conn.stream.close();

    const test_config = WebSocketConfig{};
    var session = try WebSocketSession.init(testing.allocator, conn.stream, test_config);
    defer session.deinit();

    // Generate random WebSocket key for testing
    var key_buf: [16]u8 = undefined;
    io_compat.randomBytes(&key_buf);

    const encoder = std.base64.standard.Encoder;
    var encoded_key: [encoder.calcSize(key_buf.len)]u8 = undefined;
    const key = encoder.encode(&encoded_key, &key_buf);

    const accept = try session.generateAcceptKey(key);
    defer testing.allocator.free(accept);

    // Just verify that the accept key is generated (24 bytes base64 encoded)
    try testing.expect(accept.len > 0);

    connect_thread.join();
}

test "OpCode enum values" {
    const testing = std.testing;

    try testing.expectEqual(@as(u8, 0x1), @intFromEnum(OpCode.text));
    try testing.expectEqual(@as(u8, 0x2), @intFromEnum(OpCode.binary));
    try testing.expectEqual(@as(u8, 0x8), @intFromEnum(OpCode.close));
    try testing.expectEqual(@as(u8, 0x9), @intFromEnum(OpCode.ping));
    try testing.expectEqual(@as(u8, 0xA), @intFromEnum(OpCode.pong));
}

test "Notification manager" {
    const testing = std.testing;

    var manager = NotificationManager.init(testing.allocator);
    defer manager.deinit();

    try testing.expectEqual(@as(usize, 0), manager.sessions.items.len);
}

// ============================================================================
// Email Delivery Status Events
// ============================================================================

/// Email delivery status for real-time tracking
pub const DeliveryStatus = enum {
    queued,
    sending,
    sent,
    delivered,
    bounced,
    deferred,
    failed,
    spam_rejected,
    virus_rejected,

    pub fn toString(self: DeliveryStatus) []const u8 {
        return switch (self) {
            .queued => "queued",
            .sending => "sending",
            .sent => "sent",
            .delivered => "delivered",
            .bounced => "bounced",
            .deferred => "deferred",
            .failed => "failed",
            .spam_rejected => "spam_rejected",
            .virus_rejected => "virus_rejected",
        };
    }
};

/// Delivery event for tracking email progress
pub const DeliveryEvent = struct {
    message_id: []const u8,
    recipient: []const u8,
    status: DeliveryStatus,
    timestamp: i64,
    details: ?DeliveryDetails,

    pub const DeliveryDetails = struct {
        smtp_code: ?u16 = null,
        smtp_message: ?[]const u8 = null,
        mx_server: ?[]const u8 = null,
        attempt_number: u32 = 1,
        next_retry: ?i64 = null,
        bounce_type: ?BounceType = null,
        error_message: ?[]const u8 = null,
    };

    pub const BounceType = enum {
        hard, // Permanent failure
        soft, // Temporary failure
        block, // Blocked by recipient
        spam, // Marked as spam
        policy, // Policy violation
    };

    pub fn toJson(self: *const DeliveryEvent, allocator: Allocator) ![]u8 {
        var output = std.ArrayList(u8).init(allocator);
        const writer = output.writer();

        try writer.print(
            \\{{
            \\  "type": "delivery_status",
            \\  "message_id": "{s}",
            \\  "recipient": "{s}",
            \\  "status": "{s}",
            \\  "timestamp": {d}
        , .{
            self.message_id,
            self.recipient,
            self.status.toString(),
            self.timestamp,
        });

        if (self.details) |details| {
            try writer.print(",\n  \"details\": {{", .{});

            if (details.smtp_code) |code| {
                try writer.print("\n    \"smtp_code\": {d}", .{code});
            }
            if (details.mx_server) |mx| {
                try writer.print(",\n    \"mx_server\": \"{s}\"", .{mx});
            }
            try writer.print(",\n    \"attempt\": {d}", .{details.attempt_number});

            if (details.next_retry) |next| {
                try writer.print(",\n    \"next_retry\": {d}", .{next});
            }
            if (details.error_message) |err| {
                try writer.print(",\n    \"error\": \"{s}\"", .{err});
            }

            try writer.print("\n  }}", .{});
        }

        try writer.print("\n}}", .{});
        return output.toOwnedSlice();
    }
};

// ============================================================================
// Event Stream Manager
// ============================================================================

/// Event categories for filtering
pub const EventCategory = enum {
    email,
    delivery,
    folder,
    calendar,
    contact,
    server,
    security,
    all,

    pub fn fromEventType(event_type: []const u8) EventCategory {
        if (std.mem.startsWith(u8, event_type, "email_") or
            std.mem.startsWith(u8, event_type, "new_email"))
        {
            return .email;
        }
        if (std.mem.startsWith(u8, event_type, "delivery_")) return .delivery;
        if (std.mem.startsWith(u8, event_type, "folder_")) return .folder;
        if (std.mem.startsWith(u8, event_type, "calendar_")) return .calendar;
        if (std.mem.startsWith(u8, event_type, "contact_")) return .contact;
        if (std.mem.startsWith(u8, event_type, "sync_") or
            std.mem.startsWith(u8, event_type, "quota_"))
        {
            return .server;
        }
        if (std.mem.startsWith(u8, event_type, "security_") or
            std.mem.startsWith(u8, event_type, "auth_"))
        {
            return .security;
        }
        return .all;
    }
};

/// Subscription filter for fine-grained event control
pub const SubscriptionFilter = struct {
    categories: std.EnumSet(EventCategory),
    message_ids: ?std.ArrayList([]const u8) = null,
    folders: ?std.ArrayList([]const u8) = null,
    senders: ?std.ArrayList([]const u8) = null,

    pub fn init() SubscriptionFilter {
        return .{
            .categories = std.EnumSet(EventCategory).initEmpty(),
        };
    }

    pub fn subscribeToCategory(self: *SubscriptionFilter, category: EventCategory) void {
        self.categories.insert(category);
    }

    pub fn subscribeToAll(self: *SubscriptionFilter) void {
        self.categories.insert(.all);
    }

    pub fn matches(self: *const SubscriptionFilter, event_type: []const u8) bool {
        if (self.categories.contains(.all)) return true;

        const category = EventCategory.fromEventType(event_type);
        return self.categories.contains(category);
    }
};

/// Event stream with batching and reconnection support
pub const EventStream = struct {
    allocator: Allocator,
    session: *WebSocketSession,
    filter: SubscriptionFilter,
    pending_events: std.ArrayList([]u8),
    batch_size: usize,
    batch_timeout_ms: u64,
    last_batch_time: i64,
    sequence_number: u64,
    replay_buffer: std.ArrayList(ReplayableEvent),
    max_replay_buffer: usize,

    const ReplayableEvent = struct {
        sequence: u64,
        timestamp: i64,
        event_json: []u8,
    };

    pub fn init(allocator: Allocator, session: *WebSocketSession) EventStream {
        return .{
            .allocator = allocator,
            .session = session,
            .filter = SubscriptionFilter.init(),
            .pending_events = std.ArrayList([]u8).init(allocator),
            .batch_size = 10,
            .batch_timeout_ms = 100,
            .last_batch_time = time_compat.timestamp(),
            .sequence_number = 0,
            .replay_buffer = std.ArrayList(ReplayableEvent).init(allocator),
            .max_replay_buffer = 1000,
        };
    }

    pub fn deinit(self: *EventStream) void {
        for (self.pending_events.items) |event| {
            self.allocator.free(event);
        }
        self.pending_events.deinit();

        for (self.replay_buffer.items) |event| {
            self.allocator.free(event.event_json);
        }
        self.replay_buffer.deinit();
    }

    /// Queue an event for delivery
    pub fn queueEvent(self: *EventStream, event_json: []const u8) !void {
        const event_copy = try self.allocator.dupe(u8, event_json);
        try self.pending_events.append(event_copy);

        // Add to replay buffer
        self.sequence_number += 1;
        try self.replay_buffer.append(.{
            .sequence = self.sequence_number,
            .timestamp = time_compat.timestamp(),
            .event_json = try self.allocator.dupe(u8, event_json),
        });

        // Prune old events from replay buffer
        while (self.replay_buffer.items.len > self.max_replay_buffer) {
            const removed = self.replay_buffer.orderedRemove(0);
            self.allocator.free(removed.event_json);
        }

        // Check if batch should be flushed
        if (self.pending_events.items.len >= self.batch_size) {
            try self.flushBatch();
        }
    }

    /// Flush pending events as a batch
    pub fn flushBatch(self: *EventStream) !void {
        if (self.pending_events.items.len == 0) return;

        var batch = std.ArrayList(u8).init(self.allocator);
        defer batch.deinit();

        const writer = batch.writer();
        try writer.print("{{\"type\":\"event_batch\",\"count\":{d},\"sequence\":{d},\"events\":[", .{
            self.pending_events.items.len,
            self.sequence_number,
        });

        for (self.pending_events.items, 0..) |event, i| {
            if (i > 0) try writer.print(",", .{});
            try writer.print("{s}", .{event});
        }

        try writer.print("]}}", .{});

        // Send batch
        try self.session.sendText(batch.items);

        // Clear pending events
        for (self.pending_events.items) |event| {
            self.allocator.free(event);
        }
        self.pending_events.clearRetainingCapacity();
        self.last_batch_time = time_compat.timestamp();
    }

    /// Replay events from sequence number for reconnection
    pub fn replayFromSequence(self: *EventStream, from_sequence: u64) !void {
        var replay_count: usize = 0;

        for (self.replay_buffer.items) |event| {
            if (event.sequence > from_sequence) {
                try self.session.sendText(event.event_json);
                replay_count += 1;
            }
        }

        // Send replay complete message
        const msg = try std.fmt.allocPrint(self.allocator, "{{\"type\":\"replay_complete\",\"replayed\":{d},\"current_sequence\":{d}}}", .{ replay_count, self.sequence_number });
        defer self.allocator.free(msg);

        try self.session.sendText(msg);
    }
};

/// Delivery event tracker for real-time updates
pub const DeliveryTracker = struct {
    allocator: Allocator,
    notification_manager: *NotificationManager,
    tracked_messages: std.StringHashMap(TrackedMessage),
    mutex: mutex_compat.Mutex,

    const TrackedMessage = struct {
        message_id: []const u8,
        recipients: std.ArrayList(RecipientStatus),
        created_at: i64,
        last_update: i64,
    };

    const RecipientStatus = struct {
        recipient: []const u8,
        status: DeliveryStatus,
        last_update: i64,
    };

    pub fn init(allocator: Allocator, notification_manager: *NotificationManager) DeliveryTracker {
        return .{
            .allocator = allocator,
            .notification_manager = notification_manager,
            .tracked_messages = std.StringHashMap(TrackedMessage).init(allocator),
            .mutex = mutex_compat.Mutex{},
        };
    }

    pub fn deinit(self: *DeliveryTracker) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var iter = self.tracked_messages.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.recipients.deinit();
        }
        self.tracked_messages.deinit();
    }

    /// Start tracking a message
    pub fn trackMessage(self: *DeliveryTracker, message_id: []const u8, recipients: []const []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = time_compat.timestamp();
        var recipient_list = std.ArrayList(RecipientStatus).init(self.allocator);

        for (recipients) |recipient| {
            try recipient_list.append(.{
                .recipient = try self.allocator.dupe(u8, recipient),
                .status = .queued,
                .last_update = now,
            });
        }

        try self.tracked_messages.put(try self.allocator.dupe(u8, message_id), .{
            .message_id = message_id,
            .recipients = recipient_list,
            .created_at = now,
            .last_update = now,
        });

        // Broadcast queued status for each recipient
        for (recipients) |recipient| {
            try self.broadcastDeliveryEvent(message_id, recipient, .queued, null);
        }
    }

    /// Update delivery status
    pub fn updateStatus(
        self: *DeliveryTracker,
        message_id: []const u8,
        recipient: []const u8,
        status: DeliveryStatus,
        details: ?DeliveryEvent.DeliveryDetails,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.tracked_messages.getPtr(message_id)) |tracked| {
            for (tracked.recipients.items) |*r| {
                if (std.mem.eql(u8, r.recipient, recipient)) {
                    r.status = status;
                    r.last_update = time_compat.timestamp();
                    tracked.last_update = r.last_update;
                    break;
                }
            }
        }

        try self.broadcastDeliveryEvent(message_id, recipient, status, details);
    }

    fn broadcastDeliveryEvent(
        self: *DeliveryTracker,
        message_id: []const u8,
        recipient: []const u8,
        status: DeliveryStatus,
        details: ?DeliveryEvent.DeliveryDetails,
    ) !void {
        const event = DeliveryEvent{
            .message_id = message_id,
            .recipient = recipient,
            .status = status,
            .timestamp = time_compat.timestamp(),
            .details = details,
        };

        const json = try event.toJson(self.allocator);
        defer self.allocator.free(json);

        // Broadcast through notification manager
        try self.notification_manager.broadcast(.{
            .sync_started = .{ .sync_type = "delivery_update" },
        });
    }

    /// Get current status of a message
    pub fn getMessageStatus(self: *DeliveryTracker, message_id: []const u8) ?MessageDeliveryStatus {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.tracked_messages.get(message_id)) |tracked| {
            var delivered: u32 = 0;
            var failed: u32 = 0;
            var pending: u32 = 0;

            for (tracked.recipients.items) |r| {
                switch (r.status) {
                    .delivered => delivered += 1,
                    .failed, .bounced, .spam_rejected, .virus_rejected => failed += 1,
                    else => pending += 1,
                }
            }

            return .{
                .message_id = message_id,
                .total_recipients = @intCast(tracked.recipients.items.len),
                .delivered = delivered,
                .failed = failed,
                .pending = pending,
                .created_at = tracked.created_at,
                .last_update = tracked.last_update,
            };
        }

        return null;
    }

    pub const MessageDeliveryStatus = struct {
        message_id: []const u8,
        total_recipients: u32,
        delivered: u32,
        failed: u32,
        pending: u32,
        created_at: i64,
        last_update: i64,
    };
};

// ============================================================================
// Event Stream Tests
// ============================================================================

test "delivery status enum" {
    const testing = std.testing;

    try testing.expectEqualStrings("queued", DeliveryStatus.queued.toString());
    try testing.expectEqualStrings("delivered", DeliveryStatus.delivered.toString());
    try testing.expectEqualStrings("bounced", DeliveryStatus.bounced.toString());
}

test "event category classification" {
    const testing = std.testing;

    try testing.expectEqual(EventCategory.email, EventCategory.fromEventType("email_deleted"));
    try testing.expectEqual(EventCategory.email, EventCategory.fromEventType("new_email"));
    try testing.expectEqual(EventCategory.folder, EventCategory.fromEventType("folder_created"));
    try testing.expectEqual(EventCategory.calendar, EventCategory.fromEventType("calendar_event_added"));
    try testing.expectEqual(EventCategory.server, EventCategory.fromEventType("sync_completed"));
}

test "subscription filter" {
    const testing = std.testing;

    var filter = SubscriptionFilter.init();
    filter.subscribeToCategory(.email);
    filter.subscribeToCategory(.delivery);

    try testing.expect(filter.matches("email_deleted"));
    try testing.expect(filter.matches("new_email"));
    try testing.expect(!filter.matches("folder_created"));
    try testing.expect(!filter.matches("calendar_event_added"));

    filter.subscribeToAll();
    try testing.expect(filter.matches("anything"));
}

test "delivery event json" {
    const testing = std.testing;

    const event = DeliveryEvent{
        .message_id = "msg123",
        .recipient = "user@example.com",
        .status = .delivered,
        .timestamp = 1700000000,
        .details = .{
            .smtp_code = 250,
            .mx_server = "mx.example.com",
            .attempt_number = 1,
        },
    };

    const json = try event.toJson(testing.allocator);
    defer testing.allocator.free(json);

    try testing.expect(std.mem.indexOf(u8, json, "msg123") != null);
    try testing.expect(std.mem.indexOf(u8, json, "delivered") != null);
    try testing.expect(std.mem.indexOf(u8, json, "250") != null);
}
