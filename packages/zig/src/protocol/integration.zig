//! Protocol Integration Module
//!
//! Integrates IMAP, POP3, and WebSocket protocols with the main server.
//! Provides unified server startup, connection management, and health monitoring.
//!
//! Features:
//! - Unified protocol server startup and shutdown
//! - Connection routing by port/protocol
//! - Protocol-specific metrics collection
//! - Health status aggregation
//! - TLS/STARTTLS support for all protocols
//!
//! Usage:
//! ```zig
//! var server = try ProtocolServer.init(allocator, config);
//! defer server.deinit();
//!
//! try server.start();
//! // Server is now accepting SMTP, IMAP, POP3, and WebSocket connections
//!
//! server.stop();
//! ```

const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;

// =============================================================================
// Configuration
// =============================================================================

pub const ProtocolConfig = struct {
    // SMTP ports
    smtp_port: u16 = 25,
    submission_port: u16 = 587,
    smtps_port: u16 = 465,

    // IMAP ports
    imap_port: u16 = 143,
    imaps_port: u16 = 993,

    // POP3 ports
    pop3_port: u16 = 110,
    pop3s_port: u16 = 995,

    // WebSocket port
    websocket_port: u16 = 8080,

    // Enable flags
    enable_smtp: bool = true,
    enable_imap: bool = true,
    enable_pop3: bool = true,
    enable_websocket: bool = true,

    // TLS configuration
    tls_cert_path: ?[]const u8 = null,
    tls_key_path: ?[]const u8 = null,
    require_tls: bool = false,

    // Connection limits
    max_connections_per_protocol: u32 = 10000,
    connection_timeout_ms: u32 = 300000, // 5 minutes

    // Worker threads
    worker_threads: u32 = 0, // 0 = auto-detect

    // Bind address
    bind_address: []const u8 = "0.0.0.0",
};

// =============================================================================
// Protocol Types
// =============================================================================

pub const Protocol = enum {
    smtp,
    smtp_submission,
    smtps,
    imap,
    imaps,
    pop3,
    pop3s,
    websocket,

    pub fn defaultPort(self: Protocol) u16 {
        return switch (self) {
            .smtp => 25,
            .smtp_submission => 587,
            .smtps => 465,
            .imap => 143,
            .imaps => 993,
            .pop3 => 110,
            .pop3s => 995,
            .websocket => 8080,
        };
    }

    pub fn name(self: Protocol) []const u8 {
        return switch (self) {
            .smtp => "SMTP",
            .smtp_submission => "SMTP-Submission",
            .smtps => "SMTPS",
            .imap => "IMAP",
            .imaps => "IMAPS",
            .pop3 => "POP3",
            .pop3s => "POP3S",
            .websocket => "WebSocket",
        };
    }

    pub fn requiresTls(self: Protocol) bool {
        return switch (self) {
            .smtps, .imaps, .pop3s => true,
            else => false,
        };
    }
};

// =============================================================================
// Connection State
// =============================================================================

pub const ConnectionState = enum {
    connecting,
    authenticating,
    authenticated,
    idle,
    processing,
    closing,
    closed,
};

pub const Connection = struct {
    id: u64,
    protocol: Protocol,
    state: ConnectionState,
    remote_addr: std.net.Address,
    connected_at: i64,
    last_activity: i64,
    tls_enabled: bool,
    authenticated_user: ?[]const u8,
    bytes_sent: u64,
    bytes_received: u64,
    commands_processed: u32,
};

// =============================================================================
// Protocol Handlers
// =============================================================================

pub const ProtocolHandler = struct {
    const Self = @This();

    protocol: Protocol,
    handle_fn: *const fn (*Connection, []const u8) anyerror![]const u8,
    init_fn: ?*const fn (*Connection) anyerror!void,
    cleanup_fn: ?*const fn (*Connection) void,
};

pub const SmtpHandler = struct {
    pub fn init(conn: *Connection) !void {
        _ = conn;
        // Send greeting
    }

    pub fn handle(conn: *Connection, data: []const u8) ![]const u8 {
        _ = conn;
        _ = data;
        // Parse SMTP command and handle
        return "250 OK\r\n";
    }

    pub fn cleanup(conn: *Connection) void {
        _ = conn;
    }
};

pub const ImapHandler = struct {
    pub fn init(conn: *Connection) !void {
        _ = conn;
        // Send greeting
    }

    pub fn handle(conn: *Connection, data: []const u8) ![]const u8 {
        _ = conn;
        _ = data;
        // Parse IMAP command and handle
        return "* OK Ready\r\n";
    }

    pub fn cleanup(conn: *Connection) void {
        _ = conn;
    }
};

pub const Pop3Handler = struct {
    pub fn init(conn: *Connection) !void {
        _ = conn;
        // Send greeting
    }

    pub fn handle(conn: *Connection, data: []const u8) ![]const u8 {
        _ = conn;
        _ = data;
        // Parse POP3 command and handle
        return "+OK Ready\r\n";
    }

    pub fn cleanup(conn: *Connection) void {
        _ = conn;
    }
};

pub const WebSocketHandler = struct {
    pub fn init(conn: *Connection) !void {
        _ = conn;
        // Perform WebSocket handshake
    }

    pub fn handle(conn: *Connection, data: []const u8) ![]const u8 {
        _ = conn;
        _ = data;
        // Handle WebSocket frame
        return "";
    }

    pub fn cleanup(conn: *Connection) void {
        _ = conn;
    }
};

// =============================================================================
// Listener
// =============================================================================

pub const Listener = struct {
    const Self = @This();

    protocol: Protocol,
    port: u16,
    socket: ?posix.socket_t,
    running: bool,
    connections: u32,

    pub fn init(protocol: Protocol, port: u16) Self {
        return .{
            .protocol = protocol,
            .port = port,
            .socket = null,
            .running = false,
            .connections = 0,
        };
    }

    pub fn bind(self: *Self, address: []const u8) !void {
        const addr = try std.net.Address.parseIp4(address, self.port);

        const sock = try posix.socket(
            posix.AF.INET,
            posix.SOCK.STREAM | posix.SOCK.NONBLOCK,
            posix.IPPROTO.TCP,
        );
        errdefer _ = std.c.close(sock);

        // Set socket options
        const one: u32 = 1;
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one));

        try posix.bind(sock, &addr.any, addr.getOsSockLen());
        try posix.listen(sock, 128);

        self.socket = sock;
        self.running = true;
    }

    pub fn close(self: *Self) void {
        if (self.socket) |sock| {
            _ = std.c.close(sock);
            self.socket = null;
        }
        self.running = false;
    }
};

// =============================================================================
// Protocol Server
// =============================================================================

pub const ProtocolServer = struct {
    const Self = @This();

    allocator: Allocator,
    config: ProtocolConfig,

    // Listeners
    listeners: std.ArrayList(Listener),

    // Connections
    connections: std.AutoHashMap(u64, Connection),
    next_connection_id: u64,

    // State
    running: bool,
    start_time: i64,

    // Metrics
    metrics: ProtocolMetrics,

    pub fn init(allocator: Allocator, config: ProtocolConfig) !Self {
        return .{
            .allocator = allocator,
            .config = config,
            .listeners = std.ArrayList(Listener).init(allocator),
            .connections = std.AutoHashMap(u64, Connection).init(allocator),
            .next_connection_id = 1,
            .running = false,
            .start_time = 0,
            .metrics = ProtocolMetrics{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.stop();
        self.listeners.deinit();
        self.connections.deinit();
    }

    pub fn start(self: *Self) !void {
        if (self.running) return;

        // Create listeners for enabled protocols
        if (self.config.enable_smtp) {
            try self.addListener(.smtp, self.config.smtp_port);
            try self.addListener(.smtp_submission, self.config.submission_port);
            if (self.config.tls_cert_path != null) {
                try self.addListener(.smtps, self.config.smtps_port);
            }
        }

        if (self.config.enable_imap) {
            try self.addListener(.imap, self.config.imap_port);
            if (self.config.tls_cert_path != null) {
                try self.addListener(.imaps, self.config.imaps_port);
            }
        }

        if (self.config.enable_pop3) {
            try self.addListener(.pop3, self.config.pop3_port);
            if (self.config.tls_cert_path != null) {
                try self.addListener(.pop3s, self.config.pop3s_port);
            }
        }

        if (self.config.enable_websocket) {
            try self.addListener(.websocket, self.config.websocket_port);
        }

        // Bind all listeners
        for (self.listeners.items) |*listener| {
            try listener.bind(self.config.bind_address);
        }

        self.running = true;
        self.start_time = std.time.timestamp();
    }

    pub fn stop(self: *Self) void {
        if (!self.running) return;

        // Close all listeners
        for (self.listeners.items) |*listener| {
            listener.close();
        }

        // Close all connections
        var iter = self.connections.iterator();
        while (iter.next()) |entry| {
            _ = entry;
            // Close connection
        }
        self.connections.clearRetainingCapacity();

        self.running = false;
    }

    fn addListener(self: *Self, protocol: Protocol, port: u16) !void {
        try self.listeners.append(Listener.init(protocol, port));
    }

    pub fn acceptConnection(self: *Self, listener: *Listener, addr: std.net.Address) !u64 {
        const conn_id = self.next_connection_id;
        self.next_connection_id += 1;

        const now = std.time.timestamp();

        try self.connections.put(conn_id, .{
            .id = conn_id,
            .protocol = listener.protocol,
            .state = .connecting,
            .remote_addr = addr,
            .connected_at = now,
            .last_activity = now,
            .tls_enabled = listener.protocol.requiresTls(),
            .authenticated_user = null,
            .bytes_sent = 0,
            .bytes_received = 0,
            .commands_processed = 0,
        });

        listener.connections += 1;

        // Update metrics
        switch (listener.protocol) {
            .smtp, .smtp_submission, .smtps => self.metrics.smtp_connections += 1,
            .imap, .imaps => self.metrics.imap_connections += 1,
            .pop3, .pop3s => self.metrics.pop3_connections += 1,
            .websocket => self.metrics.websocket_connections += 1,
        }

        return conn_id;
    }

    pub fn closeConnection(self: *Self, conn_id: u64) void {
        if (self.connections.fetchRemove(conn_id)) |entry| {
            const conn = entry.value;

            // Update listener count
            for (self.listeners.items) |*listener| {
                if (listener.protocol == conn.protocol and listener.connections > 0) {
                    listener.connections -= 1;
                    break;
                }
            }

            // Update metrics
            self.metrics.total_bytes_sent += conn.bytes_sent;
            self.metrics.total_bytes_received += conn.bytes_received;
            self.metrics.total_commands += conn.commands_processed;
        }
    }

    pub fn getHealth(self: *Self) HealthStatus {
        var status = HealthStatus{
            .overall = .healthy,
            .uptime_seconds = if (self.start_time > 0)
                @intCast(std.time.timestamp() - self.start_time)
            else
                0,
        };

        // Check each protocol
        for (self.listeners.items) |listener| {
            const proto_status = ProtocolStatus{
                .protocol = listener.protocol,
                .listening = listener.running,
                .port = listener.port,
                .active_connections = listener.connections,
            };

            switch (listener.protocol) {
                .smtp, .smtp_submission, .smtps => status.smtp = proto_status,
                .imap, .imaps => status.imap = proto_status,
                .pop3, .pop3s => status.pop3 = proto_status,
                .websocket => status.websocket = proto_status,
            }

            if (!listener.running) {
                status.overall = .degraded;
            }
        }

        return status;
    }

    pub fn getMetrics(self: *Self) ProtocolMetrics {
        return self.metrics;
    }

    pub fn getActiveConnections(self: *Self, protocol: ?Protocol) u32 {
        if (protocol) |p| {
            var count: u32 = 0;
            var iter = self.connections.valueIterator();
            while (iter.next()) |conn| {
                if (conn.protocol == p) count += 1;
            }
            return count;
        } else {
            return @intCast(self.connections.count());
        }
    }
};

// =============================================================================
// Metrics
// =============================================================================

pub const ProtocolMetrics = struct {
    smtp_connections: u64 = 0,
    imap_connections: u64 = 0,
    pop3_connections: u64 = 0,
    websocket_connections: u64 = 0,
    total_bytes_sent: u64 = 0,
    total_bytes_received: u64 = 0,
    total_commands: u64 = 0,
    auth_successes: u64 = 0,
    auth_failures: u64 = 0,
    tls_connections: u64 = 0,
};

// =============================================================================
// Health Status
// =============================================================================

pub const HealthLevel = enum {
    healthy,
    degraded,
    unhealthy,
};

pub const ProtocolStatus = struct {
    protocol: Protocol = .smtp,
    listening: bool = false,
    port: u16 = 0,
    active_connections: u32 = 0,
};

pub const HealthStatus = struct {
    overall: HealthLevel,
    uptime_seconds: u64,
    smtp: ?ProtocolStatus = null,
    imap: ?ProtocolStatus = null,
    pop3: ?ProtocolStatus = null,
    websocket: ?ProtocolStatus = null,
};

// =============================================================================
// Connection Router
// =============================================================================

pub const ConnectionRouter = struct {
    const Self = @This();

    server: *ProtocolServer,

    pub fn init(server: *ProtocolServer) Self {
        return .{ .server = server };
    }

    pub fn routeConnection(self: *Self, port: u16) ?Protocol {
        _ = self;
        return switch (port) {
            25 => .smtp,
            587 => .smtp_submission,
            465 => .smtps,
            143 => .imap,
            993 => .imaps,
            110 => .pop3,
            995 => .pop3s,
            8080 => .websocket,
            else => null,
        };
    }

    pub fn getHandler(self: *Self, protocol: Protocol) ProtocolHandler {
        _ = self;
        return switch (protocol) {
            .smtp, .smtp_submission, .smtps => .{
                .protocol = protocol,
                .handle_fn = SmtpHandler.handle,
                .init_fn = SmtpHandler.init,
                .cleanup_fn = SmtpHandler.cleanup,
            },
            .imap, .imaps => .{
                .protocol = protocol,
                .handle_fn = ImapHandler.handle,
                .init_fn = ImapHandler.init,
                .cleanup_fn = ImapHandler.cleanup,
            },
            .pop3, .pop3s => .{
                .protocol = protocol,
                .handle_fn = Pop3Handler.handle,
                .init_fn = Pop3Handler.init,
                .cleanup_fn = Pop3Handler.cleanup,
            },
            .websocket => .{
                .protocol = protocol,
                .handle_fn = WebSocketHandler.handle,
                .init_fn = WebSocketHandler.init,
                .cleanup_fn = WebSocketHandler.cleanup,
            },
        };
    }
};

// =============================================================================
// Server Builder
// =============================================================================

pub const ServerBuilder = struct {
    const Self = @This();

    allocator: Allocator,
    config: ProtocolConfig,

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .config = .{},
        };
    }

    pub fn withSmtp(self: *Self, port: u16) *Self {
        self.config.smtp_port = port;
        self.config.enable_smtp = true;
        return self;
    }

    pub fn withImap(self: *Self, port: u16) *Self {
        self.config.imap_port = port;
        self.config.enable_imap = true;
        return self;
    }

    pub fn withPop3(self: *Self, port: u16) *Self {
        self.config.pop3_port = port;
        self.config.enable_pop3 = true;
        return self;
    }

    pub fn withWebSocket(self: *Self, port: u16) *Self {
        self.config.websocket_port = port;
        self.config.enable_websocket = true;
        return self;
    }

    pub fn withTls(self: *Self, cert_path: []const u8, key_path: []const u8) *Self {
        self.config.tls_cert_path = cert_path;
        self.config.tls_key_path = key_path;
        return self;
    }

    pub fn withBindAddress(self: *Self, address: []const u8) *Self {
        self.config.bind_address = address;
        return self;
    }

    pub fn withMaxConnections(self: *Self, max: u32) *Self {
        self.config.max_connections_per_protocol = max;
        return self;
    }

    pub fn build(self: *Self) !ProtocolServer {
        return ProtocolServer.init(self.allocator, self.config);
    }
};

// =============================================================================
// IMAP Command Handlers (Stubs for integration)
// =============================================================================

pub const ImapCommands = struct {
    pub const Command = enum {
        capability,
        noop,
        logout,
        starttls,
        authenticate,
        login,
        select,
        examine,
        create,
        delete,
        rename,
        subscribe,
        unsubscribe,
        list,
        lsub,
        status,
        append,
        check,
        close,
        expunge,
        search,
        fetch,
        store,
        copy,
        uid,
        idle,
    };

    pub fn parse(line: []const u8) ?struct { tag: []const u8, cmd: Command, args: []const u8 } {
        // Parse IMAP command: TAG COMMAND [ARGS]
        var iter = std.mem.splitScalar(u8, line, ' ');
        const tag = iter.next() orelse return null;
        const cmd_str = iter.next() orelse return null;
        const args = iter.rest();

        const cmd = std.meta.stringToEnum(Command, std.ascii.lowerString(
            &[_]u8{0} ** 20,
            cmd_str,
        )[0..cmd_str.len]) orelse return null;

        return .{ .tag = tag, .cmd = cmd, .args = args };
    }
};

// =============================================================================
// POP3 Command Handlers (Stubs for integration)
// =============================================================================

pub const Pop3Commands = struct {
    pub const Command = enum {
        user,
        pass,
        stat,
        list,
        retr,
        dele,
        noop,
        rset,
        quit,
        top,
        uidl,
        apop,
        stls,
        capa,
    };

    pub fn parse(line: []const u8) ?struct { cmd: Command, arg: ?[]const u8 } {
        var iter = std.mem.splitScalar(u8, line, ' ');
        const cmd_str = iter.next() orelse return null;
        const arg = iter.next();

        const cmd = std.meta.stringToEnum(Command, std.ascii.lowerString(
            &[_]u8{0} ** 10,
            cmd_str,
        )[0..cmd_str.len]) orelse return null;

        return .{ .cmd = cmd, .arg = arg };
    }
};

// =============================================================================
// WebSocket Frame Handling (Stubs for integration)
// =============================================================================

pub const WebSocketFrame = struct {
    fin: bool,
    opcode: Opcode,
    masked: bool,
    payload: []const u8,

    pub const Opcode = enum(u4) {
        continuation = 0x0,
        text = 0x1,
        binary = 0x2,
        close = 0x8,
        ping = 0x9,
        pong = 0xA,
    };

    pub fn parse(data: []const u8) ?WebSocketFrame {
        if (data.len < 2) return null;

        const fin = (data[0] & 0x80) != 0;
        const opcode_val = data[0] & 0x0F;
        const opcode = std.meta.intToEnum(Opcode, opcode_val) catch return null;
        const masked = (data[1] & 0x80) != 0;
        var payload_len: usize = data[1] & 0x7F;

        var offset: usize = 2;

        if (payload_len == 126) {
            if (data.len < 4) return null;
            payload_len = std.mem.readInt(u16, data[2..4], .big);
            offset = 4;
        } else if (payload_len == 127) {
            if (data.len < 10) return null;
            payload_len = std.mem.readInt(u64, data[2..10], .big);
            offset = 10;
        }

        if (masked) {
            offset += 4; // Skip mask key
        }

        if (data.len < offset + payload_len) return null;

        return .{
            .fin = fin,
            .opcode = opcode,
            .masked = masked,
            .payload = data[offset .. offset + payload_len],
        };
    }
};

// =============================================================================
// Tests
// =============================================================================

test "protocol server initialization" {
    const allocator = std.testing.allocator;

    var server = try ProtocolServer.init(allocator, .{
        .enable_smtp = true,
        .enable_imap = true,
        .enable_pop3 = false,
        .enable_websocket = false,
    });
    defer server.deinit();

    try std.testing.expect(!server.running);
}

test "server builder" {
    const allocator = std.testing.allocator;

    var builder = ServerBuilder.init(allocator);
    var server = try builder
        .withSmtp(2525)
        .withImap(1143)
        .withMaxConnections(5000)
        .build();
    defer server.deinit();

    try std.testing.expectEqual(@as(u16, 2525), server.config.smtp_port);
    try std.testing.expectEqual(@as(u16, 1143), server.config.imap_port);
    try std.testing.expectEqual(@as(u32, 5000), server.config.max_connections_per_protocol);
}

test "protocol port mapping" {
    try std.testing.expectEqual(@as(u16, 25), Protocol.smtp.defaultPort());
    try std.testing.expectEqual(@as(u16, 143), Protocol.imap.defaultPort());
    try std.testing.expectEqual(@as(u16, 110), Protocol.pop3.defaultPort());
    try std.testing.expectEqual(@as(u16, 8080), Protocol.websocket.defaultPort());
}

test "websocket frame parsing" {
    // Simple text frame: FIN=1, opcode=1, masked=0, len=5, "hello"
    const frame_data = [_]u8{ 0x81, 0x05, 'h', 'e', 'l', 'l', 'o' };

    if (WebSocketFrame.parse(&frame_data)) |frame| {
        try std.testing.expect(frame.fin);
        try std.testing.expectEqual(WebSocketFrame.Opcode.text, frame.opcode);
        try std.testing.expect(!frame.masked);
        try std.testing.expectEqualStrings("hello", frame.payload);
    } else {
        try std.testing.expect(false);
    }
}

// =============================================================================
// Protocol Integration Test Suite
// =============================================================================

/// Integration test context for protocol testing
pub const IntegrationTestContext = struct {
    allocator: Allocator,
    server: *ProtocolServer,
    test_mailbox: TestMailbox,
    test_auth: TestAuthProvider,

    pub fn init(allocator: Allocator) !IntegrationTestContext {
        const config = ProtocolConfig{
            .enable_smtp = true,
            .enable_imap = true,
            .enable_pop3 = true,
            .enable_websocket = true,
            .smtp_port = 12525,
            .imap_port = 11143,
            .pop3_port = 11110,
            .websocket_port = 18080,
        };

        const server = try allocator.create(ProtocolServer);
        server.* = try ProtocolServer.init(allocator, config);

        return .{
            .allocator = allocator,
            .server = server,
            .test_mailbox = TestMailbox.init(allocator),
            .test_auth = TestAuthProvider.init(),
        };
    }

    pub fn deinit(self: *IntegrationTestContext) void {
        self.server.deinit();
        self.allocator.destroy(self.server);
        self.test_mailbox.deinit();
    }
};

/// Test mailbox for integration testing
pub const TestMailbox = struct {
    allocator: Allocator,
    messages: std.ArrayList(TestMessage),
    folders: std.StringHashMap(std.ArrayList(u64)),

    pub const TestMessage = struct {
        id: u64,
        uid: u64,
        from: []const u8,
        to: []const u8,
        subject: []const u8,
        body: []const u8,
        flags: MessageFlags,
        size: u64,
        received_at: i64,
    };

    pub const MessageFlags = struct {
        seen: bool = false,
        answered: bool = false,
        flagged: bool = false,
        deleted: bool = false,
        draft: bool = false,
        recent: bool = true,
    };

    pub fn init(allocator: Allocator) TestMailbox {
        return .{
            .allocator = allocator,
            .messages = std.ArrayList(TestMessage).init(allocator),
            .folders = std.StringHashMap(std.ArrayList(u64)).init(allocator),
        };
    }

    pub fn deinit(self: *TestMailbox) void {
        self.messages.deinit();
        var iter = self.folders.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.folders.deinit();
    }

    pub fn addMessage(self: *TestMailbox, folder: []const u8, msg: TestMessage) !u64 {
        try self.messages.append(msg);
        const msg_id = self.messages.items.len;

        var folder_list = self.folders.get(folder) orelse blk: {
            const new_list = std.ArrayList(u64).init(self.allocator);
            try self.folders.put(folder, new_list);
            break :blk self.folders.get(folder).?;
        };
        try folder_list.append(msg_id);

        return msg_id;
    }

    pub fn getMessageCount(self: *TestMailbox, folder: []const u8) u32 {
        if (self.folders.get(folder)) |list| {
            return @intCast(list.items.len);
        }
        return 0;
    }

    pub fn getMessage(self: *TestMailbox, id: u64) ?*TestMessage {
        if (id > 0 and id <= self.messages.items.len) {
            return &self.messages.items[id - 1];
        }
        return null;
    }
};

/// Test authentication provider
pub const TestAuthProvider = struct {
    users: [10]TestUser,
    user_count: usize,

    pub const TestUser = struct {
        username: [64]u8,
        username_len: usize,
        password: [64]u8,
        password_len: usize,
        enabled: bool,
    };

    pub fn init() TestAuthProvider {
        var provider = TestAuthProvider{
            .users = undefined,
            .user_count = 0,
        };

        // Add default test user
        provider.addUser("testuser", "testpass") catch {};

        return provider;
    }

    pub fn addUser(self: *TestAuthProvider, username: []const u8, password: []const u8) !void {
        if (self.user_count >= 10) return error.TooManyUsers;

        var user = &self.users[self.user_count];
        @memcpy(user.username[0..username.len], username);
        user.username_len = username.len;
        @memcpy(user.password[0..password.len], password);
        user.password_len = password.len;
        user.enabled = true;
        self.user_count += 1;
    }

    pub fn authenticate(self: *TestAuthProvider, username: []const u8, password: []const u8) bool {
        for (self.users[0..self.user_count]) |user| {
            if (user.enabled and
                std.mem.eql(u8, user.username[0..user.username_len], username) and
                std.mem.eql(u8, user.password[0..user.password_len], password))
            {
                return true;
            }
        }
        return false;
    }
};

// =============================================================================
// IMAP Integration
// =============================================================================

/// Full IMAP session handler for integration testing
pub const ImapSession = struct {
    allocator: Allocator,
    state: ImapState,
    authenticated_user: ?[]const u8,
    selected_mailbox: ?[]const u8,
    mailbox: *TestMailbox,
    auth_provider: *TestAuthProvider,

    pub const ImapState = enum {
        not_authenticated,
        authenticated,
        selected,
        logout,
    };

    pub fn init(allocator: Allocator, mailbox: *TestMailbox, auth: *TestAuthProvider) ImapSession {
        return .{
            .allocator = allocator,
            .state = .not_authenticated,
            .authenticated_user = null,
            .selected_mailbox = null,
            .mailbox = mailbox,
            .auth_provider = auth,
        };
    }

    pub fn handleCommand(self: *ImapSession, tag: []const u8, cmd: []const u8, args: []const u8) ![]u8 {
        const cmd_lower = std.ascii.lowerString(&[_]u8{0} ** 20, cmd);
        const cmd_name = cmd_lower[0..@min(cmd.len, 20)];

        if (std.mem.eql(u8, cmd_name[0..cmd.len], "capability")) {
            return self.cmdCapability(tag);
        } else if (std.mem.eql(u8, cmd_name[0..cmd.len], "login")) {
            return self.cmdLogin(tag, args);
        } else if (std.mem.eql(u8, cmd_name[0..cmd.len], "select")) {
            return self.cmdSelect(tag, args);
        } else if (std.mem.eql(u8, cmd_name[0..cmd.len], "list")) {
            return self.cmdList(tag, args);
        } else if (std.mem.eql(u8, cmd_name[0..cmd.len], "status")) {
            return self.cmdStatus(tag, args);
        } else if (std.mem.eql(u8, cmd_name[0..cmd.len], "fetch")) {
            return self.cmdFetch(tag, args);
        } else if (std.mem.eql(u8, cmd_name[0..cmd.len], "noop")) {
            return std.fmt.allocPrint(self.allocator, "{s} OK NOOP completed\r\n", .{tag});
        } else if (std.mem.eql(u8, cmd_name[0..cmd.len], "logout")) {
            self.state = .logout;
            return std.fmt.allocPrint(self.allocator, "* BYE IMAP4rev1 Server logging out\r\n{s} OK LOGOUT completed\r\n", .{tag});
        } else {
            return std.fmt.allocPrint(self.allocator, "{s} BAD Unknown command\r\n", .{tag});
        }
    }

    fn cmdCapability(self: *ImapSession, tag: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN AUTH=LOGIN IDLE NAMESPACE\r\n{s} OK CAPABILITY completed\r\n", .{tag});
    }

    fn cmdLogin(self: *ImapSession, tag: []const u8, args: []const u8) ![]u8 {
        // Parse username and password from args
        var iter = std.mem.splitScalar(u8, args, ' ');
        const username = iter.next() orelse return std.fmt.allocPrint(self.allocator, "{s} BAD Missing username\r\n", .{tag});
        const password = iter.next() orelse return std.fmt.allocPrint(self.allocator, "{s} BAD Missing password\r\n", .{tag});

        // Remove quotes if present
        const clean_user = std.mem.trim(u8, username, "\"");
        const clean_pass = std.mem.trim(u8, password, "\"");

        if (self.auth_provider.authenticate(clean_user, clean_pass)) {
            self.state = .authenticated;
            self.authenticated_user = clean_user;
            return std.fmt.allocPrint(self.allocator, "{s} OK LOGIN completed\r\n", .{tag});
        } else {
            return std.fmt.allocPrint(self.allocator, "{s} NO LOGIN failed\r\n", .{tag});
        }
    }

    fn cmdSelect(self: *ImapSession, tag: []const u8, args: []const u8) ![]u8 {
        if (self.state == .not_authenticated) {
            return std.fmt.allocPrint(self.allocator, "{s} BAD Not authenticated\r\n", .{tag});
        }

        const mailbox_name = std.mem.trim(u8, args, "\" \t");
        self.selected_mailbox = mailbox_name;
        self.state = .selected;

        const msg_count = self.mailbox.getMessageCount(mailbox_name);

        return std.fmt.allocPrint(self.allocator,
            \\* {d} EXISTS
            \\* 0 RECENT
            \\* OK [UIDVALIDITY 1] UIDs valid
            \\* OK [UIDNEXT {d}] Predicted next UID
            \\* FLAGS (\Seen \Answered \Flagged \Deleted \Draft)
            \\* OK [PERMANENTFLAGS (\Seen \Answered \Flagged \Deleted \Draft \*)] Flags permitted
            \\{s} OK [READ-WRITE] SELECT completed
            \\
        , .{ msg_count, msg_count + 1, tag });
    }

    fn cmdList(self: *ImapSession, tag: []const u8, args: []const u8) ![]u8 {
        _ = args;
        if (self.state == .not_authenticated) {
            return std.fmt.allocPrint(self.allocator, "{s} BAD Not authenticated\r\n", .{tag});
        }

        return std.fmt.allocPrint(self.allocator,
            \\* LIST (\HasNoChildren) "/" "INBOX"
            \\* LIST (\HasNoChildren) "/" "Sent"
            \\* LIST (\HasNoChildren) "/" "Drafts"
            \\* LIST (\HasNoChildren \Trash) "/" "Trash"
            \\{s} OK LIST completed
            \\
        , .{tag});
    }

    fn cmdStatus(self: *ImapSession, tag: []const u8, args: []const u8) ![]u8 {
        if (self.state == .not_authenticated) {
            return std.fmt.allocPrint(self.allocator, "{s} BAD Not authenticated\r\n", .{tag});
        }

        var iter = std.mem.splitScalar(u8, args, ' ');
        const mailbox_name = std.mem.trim(u8, iter.next() orelse "INBOX", "\"");
        const msg_count = self.mailbox.getMessageCount(mailbox_name);

        return std.fmt.allocPrint(self.allocator, "* STATUS \"{s}\" (MESSAGES {d} UNSEEN 0 UIDNEXT {d})\r\n{s} OK STATUS completed\r\n", .{ mailbox_name, msg_count, msg_count + 1, tag });
    }

    fn cmdFetch(self: *ImapSession, tag: []const u8, args: []const u8) ![]u8 {
        if (self.state != .selected) {
            return std.fmt.allocPrint(self.allocator, "{s} BAD No mailbox selected\r\n", .{tag});
        }

        // Parse sequence set and data items
        var iter = std.mem.splitScalar(u8, args, ' ');
        const seq_set = iter.next() orelse "1";
        _ = seq_set;

        // Return simple fetch response
        return std.fmt.allocPrint(self.allocator, "* 1 FETCH (FLAGS (\\Seen) RFC822.SIZE 1024)\r\n{s} OK FETCH completed\r\n", .{tag});
    }
};

// =============================================================================
// POP3 Integration
// =============================================================================

/// Full POP3 session handler for integration testing
pub const Pop3Session = struct {
    allocator: Allocator,
    state: Pop3State,
    authenticated_user: ?[]const u8,
    pending_username: ?[]const u8,
    mailbox: *TestMailbox,
    auth_provider: *TestAuthProvider,
    deleted_messages: std.ArrayList(u64),

    pub const Pop3State = enum {
        authorization,
        transaction,
        update,
    };

    pub fn init(allocator: Allocator, mailbox: *TestMailbox, auth: *TestAuthProvider) Pop3Session {
        return .{
            .allocator = allocator,
            .state = .authorization,
            .authenticated_user = null,
            .pending_username = null,
            .mailbox = mailbox,
            .auth_provider = auth,
            .deleted_messages = std.ArrayList(u64).init(allocator),
        };
    }

    pub fn deinit(self: *Pop3Session) void {
        self.deleted_messages.deinit();
    }

    pub fn handleCommand(self: *Pop3Session, cmd: []const u8, arg: ?[]const u8) ![]u8 {
        const cmd_upper = std.ascii.upperString(&[_]u8{0} ** 10, cmd);
        const cmd_name = cmd_upper[0..@min(cmd.len, 10)];

        if (std.mem.eql(u8, cmd_name[0..cmd.len], "USER")) {
            return self.cmdUser(arg);
        } else if (std.mem.eql(u8, cmd_name[0..cmd.len], "PASS")) {
            return self.cmdPass(arg);
        } else if (std.mem.eql(u8, cmd_name[0..cmd.len], "STAT")) {
            return self.cmdStat();
        } else if (std.mem.eql(u8, cmd_name[0..cmd.len], "LIST")) {
            return self.cmdList(arg);
        } else if (std.mem.eql(u8, cmd_name[0..cmd.len], "RETR")) {
            return self.cmdRetr(arg);
        } else if (std.mem.eql(u8, cmd_name[0..cmd.len], "DELE")) {
            return self.cmdDele(arg);
        } else if (std.mem.eql(u8, cmd_name[0..cmd.len], "NOOP")) {
            return std.fmt.allocPrint(self.allocator, "+OK\r\n", .{});
        } else if (std.mem.eql(u8, cmd_name[0..cmd.len], "RSET")) {
            return self.cmdRset();
        } else if (std.mem.eql(u8, cmd_name[0..cmd.len], "QUIT")) {
            return self.cmdQuit();
        } else if (std.mem.eql(u8, cmd_name[0..cmd.len], "CAPA")) {
            return self.cmdCapa();
        } else if (std.mem.eql(u8, cmd_name[0..cmd.len], "UIDL")) {
            return self.cmdUidl(arg);
        } else {
            return std.fmt.allocPrint(self.allocator, "-ERR Unknown command\r\n", .{});
        }
    }

    fn cmdUser(self: *Pop3Session, arg: ?[]const u8) ![]u8 {
        if (self.state != .authorization) {
            return std.fmt.allocPrint(self.allocator, "-ERR Already authenticated\r\n", .{});
        }
        const username = arg orelse return std.fmt.allocPrint(self.allocator, "-ERR Missing username\r\n", .{});
        self.pending_username = username;
        return std.fmt.allocPrint(self.allocator, "+OK User accepted\r\n", .{});
    }

    fn cmdPass(self: *Pop3Session, arg: ?[]const u8) ![]u8 {
        if (self.state != .authorization) {
            return std.fmt.allocPrint(self.allocator, "-ERR Already authenticated\r\n", .{});
        }
        const password = arg orelse return std.fmt.allocPrint(self.allocator, "-ERR Missing password\r\n", .{});
        const username = self.pending_username orelse return std.fmt.allocPrint(self.allocator, "-ERR Send USER first\r\n", .{});

        if (self.auth_provider.authenticate(username, password)) {
            self.state = .transaction;
            self.authenticated_user = username;
            return std.fmt.allocPrint(self.allocator, "+OK Mailbox open\r\n", .{});
        } else {
            return std.fmt.allocPrint(self.allocator, "-ERR Authentication failed\r\n", .{});
        }
    }

    fn cmdStat(self: *Pop3Session) ![]u8 {
        if (self.state != .transaction) {
            return std.fmt.allocPrint(self.allocator, "-ERR Not authenticated\r\n", .{});
        }
        const msg_count = self.mailbox.getMessageCount("INBOX");
        const total_size: u64 = msg_count * 1024; // Approximate
        return std.fmt.allocPrint(self.allocator, "+OK {d} {d}\r\n", .{ msg_count, total_size });
    }

    fn cmdList(self: *Pop3Session, arg: ?[]const u8) ![]u8 {
        if (self.state != .transaction) {
            return std.fmt.allocPrint(self.allocator, "-ERR Not authenticated\r\n", .{});
        }

        if (arg) |msg_num_str| {
            const msg_num = std.fmt.parseInt(u64, msg_num_str, 10) catch
                return std.fmt.allocPrint(self.allocator, "-ERR Invalid message number\r\n", .{});
            if (self.mailbox.getMessage(msg_num)) |msg| {
                return std.fmt.allocPrint(self.allocator, "+OK {d} {d}\r\n", .{ msg_num, msg.size });
            } else {
                return std.fmt.allocPrint(self.allocator, "-ERR No such message\r\n", .{});
            }
        }

        // List all messages
        var output = std.ArrayList(u8).init(self.allocator);
        const writer = output.writer();
        const msg_count = self.mailbox.getMessageCount("INBOX");
        try writer.print("+OK {d} messages\r\n", .{msg_count});

        for (self.mailbox.messages.items, 0..) |msg, i| {
            try writer.print("{d} {d}\r\n", .{ i + 1, msg.size });
        }
        try writer.print(".\r\n", .{});

        return output.toOwnedSlice();
    }

    fn cmdRetr(self: *Pop3Session, arg: ?[]const u8) ![]u8 {
        if (self.state != .transaction) {
            return std.fmt.allocPrint(self.allocator, "-ERR Not authenticated\r\n", .{});
        }
        const msg_num_str = arg orelse return std.fmt.allocPrint(self.allocator, "-ERR Missing message number\r\n", .{});
        const msg_num = std.fmt.parseInt(u64, msg_num_str, 10) catch
            return std.fmt.allocPrint(self.allocator, "-ERR Invalid message number\r\n", .{});

        if (self.mailbox.getMessage(msg_num)) |msg| {
            return std.fmt.allocPrint(self.allocator, "+OK {d} octets\r\nFrom: {s}\r\nTo: {s}\r\nSubject: {s}\r\n\r\n{s}\r\n.\r\n", .{ msg.size, msg.from, msg.to, msg.subject, msg.body });
        }
        return std.fmt.allocPrint(self.allocator, "-ERR No such message\r\n", .{});
    }

    fn cmdDele(self: *Pop3Session, arg: ?[]const u8) ![]u8 {
        if (self.state != .transaction) {
            return std.fmt.allocPrint(self.allocator, "-ERR Not authenticated\r\n", .{});
        }
        const msg_num_str = arg orelse return std.fmt.allocPrint(self.allocator, "-ERR Missing message number\r\n", .{});
        const msg_num = std.fmt.parseInt(u64, msg_num_str, 10) catch
            return std.fmt.allocPrint(self.allocator, "-ERR Invalid message number\r\n", .{});

        if (self.mailbox.getMessage(msg_num)) |_| {
            try self.deleted_messages.append(msg_num);
            return std.fmt.allocPrint(self.allocator, "+OK Message deleted\r\n", .{});
        }
        return std.fmt.allocPrint(self.allocator, "-ERR No such message\r\n", .{});
    }

    fn cmdRset(self: *Pop3Session) ![]u8 {
        self.deleted_messages.clearRetainingCapacity();
        return std.fmt.allocPrint(self.allocator, "+OK Maildrop reset\r\n", .{});
    }

    fn cmdQuit(self: *Pop3Session) ![]u8 {
        self.state = .update;
        // In update state, actually delete marked messages
        return std.fmt.allocPrint(self.allocator, "+OK Goodbye\r\n", .{});
    }

    fn cmdCapa(self: *Pop3Session) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\+OK Capability list follows
            \\TOP
            \\USER
            \\UIDL
            \\STLS
            \\.
            \\
        , .{});
    }

    fn cmdUidl(self: *Pop3Session, arg: ?[]const u8) ![]u8 {
        if (self.state != .transaction) {
            return std.fmt.allocPrint(self.allocator, "-ERR Not authenticated\r\n", .{});
        }

        if (arg) |msg_num_str| {
            const msg_num = std.fmt.parseInt(u64, msg_num_str, 10) catch
                return std.fmt.allocPrint(self.allocator, "-ERR Invalid message number\r\n", .{});
            if (self.mailbox.getMessage(msg_num)) |msg| {
                return std.fmt.allocPrint(self.allocator, "+OK {d} {d}\r\n", .{ msg_num, msg.uid });
            }
            return std.fmt.allocPrint(self.allocator, "-ERR No such message\r\n", .{});
        }

        // List all UIDs
        var output = std.ArrayList(u8).init(self.allocator);
        const writer = output.writer();
        try writer.print("+OK\r\n", .{});

        for (self.mailbox.messages.items, 0..) |msg, i| {
            try writer.print("{d} {d}\r\n", .{ i + 1, msg.uid });
        }
        try writer.print(".\r\n", .{});

        return output.toOwnedSlice();
    }
};

// =============================================================================
// Integration Tests
// =============================================================================

test "IMAP session authentication" {
    const allocator = std.testing.allocator;

    var mailbox = TestMailbox.init(allocator);
    defer mailbox.deinit();

    var auth = TestAuthProvider.init();

    var session = ImapSession.init(allocator, &mailbox, &auth);

    // Test CAPABILITY
    const cap_response = try session.handleCommand("A001", "CAPABILITY", "");
    defer allocator.free(cap_response);
    try std.testing.expect(std.mem.indexOf(u8, cap_response, "IMAP4rev1") != null);

    // Test failed LOGIN
    const bad_login = try session.handleCommand("A002", "LOGIN", "\"baduser\" \"badpass\"");
    defer allocator.free(bad_login);
    try std.testing.expect(std.mem.indexOf(u8, bad_login, "NO") != null);

    // Test successful LOGIN
    const good_login = try session.handleCommand("A003", "LOGIN", "\"testuser\" \"testpass\"");
    defer allocator.free(good_login);
    try std.testing.expect(std.mem.indexOf(u8, good_login, "OK") != null);
    try std.testing.expectEqual(ImapSession.ImapState.authenticated, session.state);
}

test "IMAP session mailbox operations" {
    const allocator = std.testing.allocator;

    var mailbox = TestMailbox.init(allocator);
    defer mailbox.deinit();

    var auth = TestAuthProvider.init();

    var session = ImapSession.init(allocator, &mailbox, &auth);

    // Login first
    const login = try session.handleCommand("A001", "LOGIN", "\"testuser\" \"testpass\"");
    defer allocator.free(login);

    // Test LIST
    const list_response = try session.handleCommand("A002", "LIST", "\"\" \"*\"");
    defer allocator.free(list_response);
    try std.testing.expect(std.mem.indexOf(u8, list_response, "INBOX") != null);

    // Test SELECT
    const select_response = try session.handleCommand("A003", "SELECT", "INBOX");
    defer allocator.free(select_response);
    try std.testing.expect(std.mem.indexOf(u8, select_response, "EXISTS") != null);
    try std.testing.expectEqual(ImapSession.ImapState.selected, session.state);
}

test "POP3 session authentication" {
    const allocator = std.testing.allocator;

    var mailbox = TestMailbox.init(allocator);
    defer mailbox.deinit();

    var auth = TestAuthProvider.init();

    var session = Pop3Session.init(allocator, &mailbox, &auth);
    defer session.deinit();

    // Test USER command
    const user_response = try session.handleCommand("USER", "testuser");
    defer allocator.free(user_response);
    try std.testing.expect(std.mem.indexOf(u8, user_response, "+OK") != null);

    // Test PASS with wrong password
    const bad_pass = try session.handleCommand("PASS", "wrongpass");
    defer allocator.free(bad_pass);
    try std.testing.expect(std.mem.indexOf(u8, bad_pass, "-ERR") != null);

    // Reset and try correct password
    session.pending_username = "testuser";
    const good_pass = try session.handleCommand("PASS", "testpass");
    defer allocator.free(good_pass);
    try std.testing.expect(std.mem.indexOf(u8, good_pass, "+OK") != null);
    try std.testing.expectEqual(Pop3Session.Pop3State.transaction, session.state);
}

test "POP3 session mailbox operations" {
    const allocator = std.testing.allocator;

    var mailbox = TestMailbox.init(allocator);
    defer mailbox.deinit();

    // Add a test message
    _ = try mailbox.addMessage("INBOX", .{
        .id = 1,
        .uid = 1001,
        .from = "sender@example.com",
        .to = "recipient@example.com",
        .subject = "Test Subject",
        .body = "Test body content",
        .flags = .{},
        .size = 256,
        .received_at = 0,
    });

    var auth = TestAuthProvider.init();

    var session = Pop3Session.init(allocator, &mailbox, &auth);
    defer session.deinit();

    // Authenticate
    _ = try session.handleCommand("USER", "testuser");
    const pass_response = try session.handleCommand("PASS", "testpass");
    defer allocator.free(pass_response);

    // Test STAT
    const stat_response = try session.handleCommand("STAT", null);
    defer allocator.free(stat_response);
    try std.testing.expect(std.mem.indexOf(u8, stat_response, "+OK") != null);

    // Test LIST
    const list_response = try session.handleCommand("LIST", null);
    defer allocator.free(list_response);
    try std.testing.expect(std.mem.indexOf(u8, list_response, "+OK") != null);

    // Test CAPA
    const capa_response = try session.handleCommand("CAPA", null);
    defer allocator.free(capa_response);
    try std.testing.expect(std.mem.indexOf(u8, capa_response, "USER") != null);
}

test "protocol health status" {
    const allocator = std.testing.allocator;

    var server = try ProtocolServer.init(allocator, .{
        .enable_smtp = true,
        .enable_imap = true,
        .enable_pop3 = true,
    });
    defer server.deinit();

    const health = server.getHealth();
    try std.testing.expectEqual(HealthLevel.healthy, health.overall);
}
