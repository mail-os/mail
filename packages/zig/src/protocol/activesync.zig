const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const net = std.net;
const Allocator = std.mem.Allocator;
const auth = @import("../auth/auth.zig");
const logger = @import("../core/logger.zig");

/// Microsoft Exchange ActiveSync Implementation
/// MS-ASHTTP and MS-ASCMD protocols
///
/// Provides mobile device synchronization for email, calendar, contacts, and tasks

// ============================================================================
// Configuration
// ============================================================================

pub const ActiveSyncConfig = struct {
    port: u16 = 443, // ActiveSync typically runs over HTTPS
    enable_ssl: bool = true,
    max_connections: usize = 200,
    connection_timeout_seconds: u64 = 900, // 15 minutes
    max_sync_size: usize = 50 * 1024 * 1024, // 50 MB
    heartbeat_interval: u64 = 540, // 9 minutes
    policy_key: []const u8 = "default",
    enable_ping: bool = true,
    enable_search: bool = true,
    enable_itemoperations: bool = true,
};

// ============================================================================
// Protocol Versions
// ============================================================================

pub const ProtocolVersion = enum {
    v2_5,
    v12_0,
    v12_1,
    v14_0,
    v14_1,
    v16_0,
    v16_1,

    pub fn toString(self: ProtocolVersion) []const u8 {
        return switch (self) {
            .v2_5 => "2.5",
            .v12_0 => "12.0",
            .v12_1 => "12.1",
            .v14_0 => "14.0",
            .v14_1 => "14.1",
            .v16_0 => "16.0",
            .v16_1 => "16.1",
        };
    }

    pub fn fromString(version: []const u8) ?ProtocolVersion {
        if (std.mem.eql(u8, version, "2.5")) return .v2_5;
        if (std.mem.eql(u8, version, "12.0")) return .v12_0;
        if (std.mem.eql(u8, version, "12.1")) return .v12_1;
        if (std.mem.eql(u8, version, "14.0")) return .v14_0;
        if (std.mem.eql(u8, version, "14.1")) return .v14_1;
        if (std.mem.eql(u8, version, "16.0")) return .v16_0;
        if (std.mem.eql(u8, version, "16.1")) return .v16_1;
        return null;
    }
};

// ============================================================================
// ActiveSync Commands
// ============================================================================

pub const ActiveSyncCommand = enum {
    sync,
    send_mail,
    smart_forward,
    smart_reply,
    get_attachment,
    get_hierarchy,
    create_collection,
    delete_collection,
    move_collection,
    folder_sync,
    folder_create,
    folder_delete,
    folder_update,
    move_items,
    get_item_estimate,
    meeting_response,
    search,
    settings,
    ping,
    item_operations,
    provision,
    resolve_recipients,
    validate_cert,

    pub fn fromString(cmd: []const u8) ?ActiveSyncCommand {
        const upper = std.ascii.allocUpperString(std.heap.page_allocator, cmd) catch return null;
        defer std.heap.page_allocator.free(upper);

        const commands = std.StaticStringMap(ActiveSyncCommand).initComptime(.{
            .{ "SYNC", .sync },
            .{ "SENDMAIL", .send_mail },
            .{ "SMARTFORWARD", .smart_forward },
            .{ "SMARTREPLY", .smart_reply },
            .{ "GETATTACHMENT", .get_attachment },
            .{ "GETHIERARCHY", .get_hierarchy },
            .{ "CREATECOLLECTION", .create_collection },
            .{ "DELETECOLLECTION", .delete_collection },
            .{ "MOVECOLLECTION", .move_collection },
            .{ "FOLDERSYNC", .folder_sync },
            .{ "FOLDERCREATE", .folder_create },
            .{ "FOLDERDELETE", .folder_delete },
            .{ "FOLDERUPDATE", .folder_update },
            .{ "MOVEITEMS", .move_items },
            .{ "GETITEMESTIMATE", .get_item_estimate },
            .{ "MEETINGRESPONSE", .meeting_response },
            .{ "SEARCH", .search },
            .{ "SETTINGS", .settings },
            .{ "PING", .ping },
            .{ "ITEMOPERATIONS", .item_operations },
            .{ "PROVISION", .provision },
            .{ "RESOLVERECIPIENTS", .resolve_recipients },
            .{ "VALIDATECERT", .validate_cert },
        });
        return commands.get(upper);
    }
};

// ============================================================================
// Folder Types
// ============================================================================

pub const FolderType = enum(u8) {
    generic = 1,
    default_inbox = 2,
    default_drafts = 3,
    default_deleted_items = 4,
    default_sent_items = 5,
    default_outbox = 6,
    default_tasks = 7,
    default_calendar = 8,
    default_contacts = 9,
    default_notes = 10,
    default_journal = 11,
    user_created_mail = 12,
    user_created_calendar = 13,
    user_created_contacts = 14,
    user_created_tasks = 15,
    user_created_journal = 16,
    user_created_notes = 17,
};

pub const Folder = struct {
    server_id: []const u8,
    parent_id: ?[]const u8,
    display_name: []const u8,
    folder_type: FolderType,
};

// ============================================================================
// Sync State
// ============================================================================

pub const SyncState = struct {
    sync_key: []const u8,
    collection_id: []const u8,
    filter_type: u8 = 0, // 0 = All items
    last_sync_time: i64,
};

// ============================================================================
// Email Message
// ============================================================================

pub const EmailMessage = struct {
    server_id: []const u8,
    from: []const u8,
    to: []const u8,
    subject: []const u8,
    date_received: i64,
    importance: u8 = 1, // 0=Low, 1=Normal, 2=High
    read: bool = false,
    body: []const u8,
    body_truncated: bool = false,
};

// ============================================================================
// ActiveSync Session
// ============================================================================

pub const ActiveSyncSession = struct {
    allocator: Allocator,
    stream: net.Stream,
    username: ?[]const u8 = null,
    device_id: ?[]const u8 = null,
    device_type: ?[]const u8 = null,
    protocol_version: ProtocolVersion = .v14_1,
    policy_key: ?[]const u8 = null,
    authenticated: bool = false,
    request_buffer: std.ArrayList(u8),
    auth_backend: *auth.AuthBackend,

    pub fn init(allocator: Allocator, stream: net.Stream, auth_backend: *auth.AuthBackend) !ActiveSyncSession {
        return ActiveSyncSession{
            .allocator = allocator,
            .stream = stream,
            .request_buffer = std.ArrayList(u8){},
            .auth_backend = auth_backend,
        };
    }

    pub fn deinit(self: *ActiveSyncSession) void {
        self.request_buffer.deinit(self.allocator);
        if (self.username) |username| {
            self.allocator.free(username);
        }
        if (self.device_id) |device_id| {
            self.allocator.free(device_id);
        }
        if (self.device_type) |device_type| {
            self.allocator.free(device_type);
        }
    }

    /// Handle incoming HTTP request
    pub fn handleRequest(self: *ActiveSyncSession, config: *const ActiveSyncConfig) !bool {
        var buffer: [8192]u8 = undefined;
        const bytes_read = try self.stream.read(&buffer);

        if (bytes_read == 0) {
            return false; // Connection closed
        }

        const request = buffer[0..bytes_read];

        // Parse HTTP request line
        var lines = std.mem.splitScalar(u8, request, '\n');
        const request_line = lines.next() orelse return false;

        var parts = std.mem.splitScalar(u8, request_line, ' ');
        const method_str = parts.next() orelse return false;
        const path = parts.next() orelse return false;
        const http_version = parts.next() orelse return false;
        _ = http_version;

        // ActiveSync uses POST for commands and OPTIONS for capability discovery
        if (!std.mem.eql(u8, method_str, "POST") and !std.mem.eql(u8, method_str, "OPTIONS")) {
            try self.sendError(405, "Method Not Allowed");
            return true;
        }

        // Parse headers
        var cmd: ?ActiveSyncCommand = null;
        var content_type: ?[]const u8 = null;

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
            if (trimmed.len == 0) break;

            if (std.mem.startsWith(u8, trimmed, "Authorization:")) {
                // Parse and validate Basic Auth
                const auth_value = std.mem.trim(u8, trimmed[14..], &std.ascii.whitespace);

                const validated_username = self.auth_backend.verifyBasicAuth(auth_value) catch |err| {
                    std.log.err("ActiveSync authentication error: {}", .{err});
                    try self.sendAuthRequired();
                    return true;
                };

                if (validated_username) |username| {
                    self.authenticated = true;
                    self.username = username;
                    std.log.info("Successful ActiveSync authentication for user: {s}", .{username});
                } else {
                    std.log.warn("Failed ActiveSync authentication attempt");
                    try self.sendAuthRequired();
                    return true;
                }
            } else if (std.mem.startsWith(u8, trimmed, "Content-Type:")) {
                content_type = std.mem.trim(u8, trimmed[13..], &std.ascii.whitespace);
            } else if (std.mem.startsWith(u8, trimmed, "User-Agent:")) {
                const ua = std.mem.trim(u8, trimmed[11..], &std.ascii.whitespace);
                // TODO: Store user agent for device info
                _ = ua;
            }
        }

        // Parse command from query string
        if (std.mem.indexOf(u8, path, "?Cmd=")) |idx| {
            const query_start = idx + 5;
            const query_end = std.mem.indexOfScalar(u8, path[query_start..], '&') orelse path.len - query_start;
            const cmd_str = path[query_start .. query_start + query_end];
            cmd = ActiveSyncCommand.fromString(cmd_str);
        }

        if (std.mem.eql(u8, method_str, "OPTIONS")) {
            try self.handleOptions();
            return true;
        }

        if (!self.authenticated) {
            try self.sendAuthRequired();
            return true;
        }

        // Parse device info from query string
        if (std.mem.indexOf(u8, path, "DeviceId=")) |idx| {
            const device_start = idx + 9;
            const device_end = std.mem.indexOfScalar(u8, path[device_start..], '&') orelse path.len - device_start;
            const device_id = path[device_start .. device_start + device_end];
            if (self.device_id == null) {
                self.device_id = try self.allocator.dupe(u8, device_id);
            }
        }

        // Route command
        const command = cmd orelse {
            try self.sendError(400, "Bad Request - Missing Cmd parameter");
            return true;
        };

        // Get request body
        const body_start = std.mem.indexOf(u8, request, "\r\n\r\n") orelse request.len;
        const body = if (body_start + 4 < request.len) request[body_start + 4 ..] else "";

        try self.routeCommand(command, body, content_type, config);

        return true;
    }

    /// Handle OPTIONS request (capability discovery)
    fn handleOptions(self: *ActiveSyncSession) !void {
        const response =
            \\HTTP/1.1 200 OK
            \\MS-ASProtocolVersions: 2.5,12.0,12.1,14.0,14.1,16.0,16.1
            \\MS-ASProtocolCommands: Sync,SendMail,SmartForward,SmartReply,GetAttachment,FolderSync,FolderCreate,FolderDelete,FolderUpdate,MoveItems,GetItemEstimate,MeetingResponse,Search,Settings,Ping,ItemOperations,Provision,ResolveRecipients,ValidateCert
            \\Public: OPTIONS,POST
            \\Allow: OPTIONS,POST
            \\Content-Length: 0
            \\
            \\
        ;

        _ = try self.stream.write(response);
    }

    /// Route command to handler
    fn routeCommand(
        self: *ActiveSyncSession,
        command: ActiveSyncCommand,
        body: []const u8,
        content_type: ?[]const u8,
        config: *const ActiveSyncConfig,
    ) !void {
        _ = content_type;

        switch (command) {
            .sync => try self.handleSync(body, config),
            .folder_sync => try self.handleFolderSync(body),
            .ping => try self.handlePing(body, config),
            .send_mail => try self.handleSendMail(body),
            .search => try self.handleSearch(body),
            .provision => try self.handleProvision(body),
            .get_item_estimate => try self.handleGetItemEstimate(body),
            else => try self.sendError(501, "Not Implemented"),
        }
    }

    /// Handle Sync command (email/calendar/contacts synchronization)
    fn handleSync(self: *ActiveSyncSession, body: []const u8, config: *const ActiveSyncConfig) !void {
        _ = body;
        _ = config;

        // Build WBXML response
        // For simplicity, we'll send an XML response (production would use WBXML)
        const response_body =
            \\<?xml version="1.0" encoding="utf-8"?>
            \\<Sync xmlns="AirSync:">
            \\  <Collections>
            \\    <Collection>
            \\      <SyncKey>1</SyncKey>
            \\      <CollectionId>5</CollectionId>
            \\      <Status>1</Status>
            \\      <Responses>
            \\        <Add>
            \\          <ServerId>5:1</ServerId>
            \\          <Status>1</Status>
            \\        </Add>
            \\      </Responses>
            \\    </Collection>
            \\  </Collections>
            \\</Sync>
        ;

        try self.sendXmlResponse(response_body);
    }

    /// Handle FolderSync command
    fn handleFolderSync(self: *ActiveSyncSession, body: []const u8) !void {
        _ = body;

        const response_body =
            \\<?xml version="1.0" encoding="utf-8"?>
            \\<FolderSync xmlns="FolderHierarchy:">
            \\  <Status>1</Status>
            \\  <SyncKey>1</SyncKey>
            \\  <Changes>
            \\    <Count>5</Count>
            \\    <Add>
            \\      <ServerId>1</ServerId>
            \\      <ParentId>0</ParentId>
            \\      <DisplayName>Inbox</DisplayName>
            \\      <Type>2</Type>
            \\    </Add>
            \\    <Add>
            \\      <ServerId>2</ServerId>
            \\      <ParentId>0</ParentId>
            \\      <DisplayName>Drafts</DisplayName>
            \\      <Type>3</Type>
            \\    </Add>
            \\    <Add>
            \\      <ServerId>3</ServerId>
            \\      <ParentId>0</ParentId>
            \\      <DisplayName>Sent Items</DisplayName>
            \\      <Type>5</Type>
            \\    </Add>
            \\    <Add>
            \\      <ServerId>4</ServerId>
            \\      <ParentId>0</ParentId>
            \\      <DisplayName>Deleted Items</DisplayName>
            \\      <Type>4</Type>
            \\    </Add>
            \\    <Add>
            \\      <ServerId>5</ServerId>
            \\      <ParentId>0</ParentId>
            \\      <DisplayName>Calendar</DisplayName>
            \\      <Type>8</Type>
            \\    </Add>
            \\  </Changes>
            \\</FolderSync>
        ;

        try self.sendXmlResponse(response_body);
    }

    /// Handle Ping command (push notifications)
    fn handlePing(self: *ActiveSyncSession, body: []const u8, config: *const ActiveSyncConfig) !void {
        _ = body;

        // Ping response - notify client of changes
        const response_body = try std.fmt.allocPrint(
            self.allocator,
            \\<?xml version="1.0" encoding="utf-8"?>
            \\<Ping xmlns="Ping:">
            \\  <Status>2</Status>
            \\  <HeartbeatInterval>{d}</HeartbeatInterval>
            \\  <Folders>
            \\    <Folder>1</Folder>
            \\  </Folders>
            \\</Ping>
        ,
            .{config.heartbeat_interval},
        );
        defer self.allocator.free(response_body);

        try self.sendXmlResponse(response_body);
    }

    /// Handle SendMail command
    fn handleSendMail(self: *ActiveSyncSession, body: []const u8) !void {
        _ = body;

        // Return success
        const response =
            \\HTTP/1.1 200 OK
            \\Content-Length: 0
            \\
            \\
        ;

        _ = try self.stream.write(response);
    }

    /// Handle Search command
    fn handleSearch(self: *ActiveSyncSession, body: []const u8) !void {
        _ = body;

        const response_body =
            \\<?xml version="1.0" encoding="utf-8"?>
            \\<Search xmlns="Search:">
            \\  <Status>1</Status>
            \\  <Response>
            \\    <Store>
            \\      <Status>1</Status>
            \\      <Result>
            \\        <Properties>
            \\          <Subject>Test Email</Subject>
            \\          <From>sender@example.com</From>
            \\        </Properties>
            \\      </Result>
            \\      <Range>0-0</Range>
            \\      <Total>1</Total>
            \\    </Store>
            \\  </Response>
            \\</Search>
        ;

        try self.sendXmlResponse(response_body);
    }

    /// Handle Provision command (policy provisioning)
    fn handleProvision(self: *ActiveSyncSession, body: []const u8) !void {
        _ = body;

        const response_body =
            \\<?xml version="1.0" encoding="utf-8"?>
            \\<Provision xmlns="Provision:">
            \\  <Status>1</Status>
            \\  <Policies>
            \\    <Policy>
            \\      <PolicyType>MS-EAS-Provisioning-WBXML</PolicyType>
            \\      <Status>1</Status>
            \\      <PolicyKey>123456789</PolicyKey>
            \\      <Data>
            \\        <EASProvisionDoc>
            \\          <DevicePasswordEnabled>0</DevicePasswordEnabled>
            \\          <AlphanumericDevicePasswordRequired>0</AlphanumericDevicePasswordRequired>
            \\          <PasswordRecoveryEnabled>0</PasswordRecoveryEnabled>
            \\          <MaxInactivityTimeDeviceLock>900</MaxInactivityTimeDeviceLock>
            \\          <MaxDevicePasswordFailedAttempts>8</MaxDevicePasswordFailedAttempts>
            \\          <AllowSimpleDevicePassword>1</AllowSimpleDevicePassword>
            \\        </EASProvisionDoc>
            \\      </Data>
            \\    </Policy>
            \\  </Policies>
            \\</Provision>
        ;

        try self.sendXmlResponse(response_body);
    }

    /// Handle GetItemEstimate command
    fn handleGetItemEstimate(self: *ActiveSyncSession, body: []const u8) !void {
        _ = body;

        const response_body =
            \\<?xml version="1.0" encoding="utf-8"?>
            \\<GetItemEstimate xmlns="GetItemEstimate:">
            \\  <Response>
            \\    <Status>1</Status>
            \\    <Collection>
            \\      <CollectionId>5</CollectionId>
            \\      <Estimate>10</Estimate>
            \\    </Collection>
            \\  </Response>
            \\</GetItemEstimate>
        ;

        try self.sendXmlResponse(response_body);
    }

    /// Send XML response
    fn sendXmlResponse(self: *ActiveSyncSession, body: []const u8) !void {
        const response_header = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.ms-sync.wbxml\r\nContent-Length: {d}\r\n\r\n",
            .{body.len},
        );
        defer self.allocator.free(response_header);

        _ = try self.stream.write(response_header);
        _ = try self.stream.write(body);
    }

    /// Send authentication required response
    fn sendAuthRequired(self: *ActiveSyncSession) !void {
        const response =
            \\HTTP/1.1 401 Unauthorized
            \\WWW-Authenticate: Basic realm="ActiveSync"
            \\Content-Length: 0
            \\
            \\
        ;
        _ = try self.stream.write(response);
    }

    /// Send error response
    fn sendError(self: *ActiveSyncSession, code: u16, message: []const u8) !void {
        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 {d} {s}\r\nContent-Length: 0\r\n\r\n",
            .{ code, message },
        );
        defer self.allocator.free(response);

        _ = try self.stream.write(response);
    }
};

// ============================================================================
// ActiveSync Server
// ============================================================================

pub const ActiveSyncServer = struct {
    allocator: Allocator,
    config: ActiveSyncConfig,
    server: ?net.Server = null,
    running: std.atomic.Value(bool),
    sessions: std.ArrayList(*ActiveSyncSession),
    sessions_mutex: mutex_compat.Mutex,
    auth_backend: *auth.AuthBackend,

    pub fn init(allocator: Allocator, config: ActiveSyncConfig, auth_backend: *auth.AuthBackend) ActiveSyncServer {
        return ActiveSyncServer{
            .allocator = allocator,
            .config = config,
            .running = std.atomic.Value(bool).init(false),
            .sessions = std.ArrayList(*ActiveSyncSession){},
            .sessions_mutex = mutex_compat.Mutex{},
            .auth_backend = auth_backend,
        };
    }

    pub fn deinit(self: *ActiveSyncServer) void {
        self.stop();

        // Clean up sessions
        self.sessions_mutex.lock();
        defer self.sessions_mutex.unlock();

        for (self.sessions.items) |session| {
            session.deinit();
            self.allocator.destroy(session);
        }
        self.sessions.deinit(self.allocator);
    }

    /// Start the ActiveSync server
    pub fn start(self: *ActiveSyncServer) !void {
        const address = try net.Address.parseIp("0.0.0.0", self.config.port);

        self.server = try address.listen(.{
            .reuse_address = true,
            .reuse_port = true,
        });

        self.running.store(true, .seq_cst);

        logger.info("ActiveSync server started on port {d}", .{self.config.port});

        while (self.running.load(.seq_cst)) {
            const connection = self.server.?.accept() catch |err| {
                logger.err("ActiveSync accept error: {}", .{err});
                continue;
            };

            // Handle connection in new thread
            const thread = try std.Thread.spawn(.{}, handleConnection, .{ self, connection.stream });
            thread.detach();
        }
    }

    /// Stop the server
    pub fn stop(self: *ActiveSyncServer) void {
        self.running.store(false, .seq_cst);
        if (self.server) |*server| {
            server.deinit();
            self.server = null;
        }
    }

    /// Handle client connection
    fn handleConnection(self: *ActiveSyncServer, stream: net.Stream) void {
        defer stream.close();

        var session = ActiveSyncSession.init(self.allocator, stream, self.auth_backend) catch |err| {
            logger.err("ActiveSync session init error: {}", .{err});
            return;
        };
        defer session.deinit();

        // Add to sessions list
        self.sessions_mutex.lock();
        const session_ptr = self.allocator.create(ActiveSyncSession) catch return;
        session_ptr.* = session;
        self.sessions.append(session_ptr) catch {
            self.allocator.destroy(session_ptr);
            self.sessions_mutex.unlock();
            return;
        };
        self.sessions_mutex.unlock();

        // Handle requests
        while (session.handleRequest(&self.config) catch false) {
            // Continue handling requests
        }

        logger.debug("ActiveSync session ended for device: {s}", .{session.device_id orelse "unknown"});
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ActiveSync server initialization" {
    const testing = std.testing;

    const config = ActiveSyncConfig{};
    var server = ActiveSyncServer.init(testing.allocator, config);
    defer server.deinit();

    try testing.expect(!server.running.load(.seq_cst));
}

test "ActiveSync command parsing" {
    const testing = std.testing;

    try testing.expectEqual(ActiveSyncCommand.sync, ActiveSyncCommand.fromString("Sync").?);
    try testing.expectEqual(ActiveSyncCommand.folder_sync, ActiveSyncCommand.fromString("FolderSync").?);
    try testing.expectEqual(ActiveSyncCommand.ping, ActiveSyncCommand.fromString("Ping").?);
    try testing.expect(ActiveSyncCommand.fromString("Invalid") == null);
}

test "Protocol version parsing" {
    const testing = std.testing;

    try testing.expectEqual(ProtocolVersion.v14_1, ProtocolVersion.fromString("14.1").?);
    try testing.expectEqual(ProtocolVersion.v16_0, ProtocolVersion.fromString("16.0").?);
    try testing.expect(ProtocolVersion.fromString("99.0") == null);

    try testing.expectEqualStrings("14.1", ProtocolVersion.v14_1.toString());
}

test "Folder types" {
    const testing = std.testing;

    try testing.expectEqual(@as(u8, 2), @intFromEnum(FolderType.default_inbox));
    try testing.expectEqual(@as(u8, 8), @intFromEnum(FolderType.default_calendar));
    try testing.expectEqual(@as(u8, 9), @intFromEnum(FolderType.default_contacts));
}
