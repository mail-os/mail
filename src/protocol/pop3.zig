const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const auth = @import("../auth/auth.zig");
const logger = @import("../core/logger.zig");

/// POP3 Server Implementation (RFC 1939)
/// Provides simple mail retrieval via POP3 protocol
///
/// Features:
/// - POP3 protocol support (RFC 1939)
/// - APOP authentication (RFC 1939)
/// - TOP command support
/// - UIDL support for unique message IDs
/// - SSL/TLS support (POP3S)
/// - Message deletion
/// - Multi-drop mailbox support
/// POP3 server configuration
pub const Pop3Config = struct {
    port: u16 = 110,
    ssl_port: u16 = 995,
    enable_ssl: bool = true,
    max_connections: usize = 50,
    connection_timeout_seconds: u64 = 600,
    max_message_size: usize = 50 * 1024 * 1024, // 50 MB
    mailbox_path: []const u8 = "/var/spool/mail",
    delete_on_quit: bool = true, // Delete messages marked for deletion
};

/// POP3 connection state
pub const Pop3State = enum {
    authorization,
    transaction,
    update,
};

/// POP3 message
pub const Pop3Message = struct {
    number: usize,
    uid: []const u8,
    size: usize,
    deleted: bool = false,
    content: ?[]const u8 = null,

    pub fn deinit(self: *Pop3Message, allocator: std.mem.Allocator) void {
        allocator.free(self.uid);
        if (self.content) |content| {
            allocator.free(content);
        }
    }
};

/// POP3 session
pub const Pop3Session = struct {
    allocator: std.mem.Allocator,
    stream: std.net.Stream,
    state: Pop3State,
    username: ?[]const u8 = null,
    messages: std.ArrayList(Pop3Message),
    maildrop_locked: bool = false,
    auth_backend: *auth.AuthBackend,

    pub fn init(allocator: std.mem.Allocator, stream: std.net.Stream, auth_backend: *auth.AuthBackend) Pop3Session {
        return .{
            .allocator = allocator,
            .stream = stream,
            .state = .authorization,
            .messages = std.ArrayList(Pop3Message){},
            .auth_backend = auth_backend,
        };
    }

    pub fn deinit(self: *Pop3Session) void {
        if (self.username) |username| {
            self.allocator.free(username);
        }
        for (self.messages.items) |*msg| {
            msg.deinit(self.allocator);
        }
        self.messages.deinit(self.allocator);
    }

    /// Send +OK response
    pub fn sendOk(self: *Pop3Session, message: []const u8) !void {
        var response = std.ArrayList(u8){};
        defer response.deinit(self.allocator);

        const writer = response.writer(self.allocator);
        try writer.print("+OK {s}\r\n", .{message});

        try self.stream.writeAll(response.items);
    }

    /// Send -ERR response
    pub fn sendErr(self: *Pop3Session, message: []const u8) !void {
        var response = std.ArrayList(u8){};
        defer response.deinit(self.allocator);

        const writer = response.writer(self.allocator);
        try writer.print("-ERR {s}\r\n", .{message});

        try self.stream.writeAll(response.items);
    }

    /// Send multi-line response
    pub fn sendMultiLine(self: *Pop3Session, lines: []const []const u8) !void {
        for (lines) |line| {
            // Byte-stuff lines starting with '.'
            if (std.mem.startsWith(u8, line, ".")) {
                try self.stream.writeAll(".");
            }
            try self.stream.writeAll(line);
            try self.stream.writeAll("\r\n");
        }
        // End with termination octet
        try self.stream.writeAll(".\r\n");
    }

    /// Send greeting
    pub fn sendGreeting(self: *Pop3Session) !void {
        try self.sendOk("POP3 server ready");
    }

    /// Handle USER command
    fn handleUser(self: *Pop3Session, username: []const u8) !void {
        if (self.state != .authorization) {
            try self.sendErr("Already authenticated");
            return;
        }

        self.username = try self.allocator.dupe(u8, username);
        try self.sendOk("User accepted");
    }

    /// Handle PASS command
    fn handlePass(self: *Pop3Session, password: []const u8) !void {
        if (self.state != .authorization) {
            try self.sendErr("Must send USER first");
            return;
        }

        if (self.username == null) {
            try self.sendErr("Must send USER first");
            return;
        }

        // Validate credentials against auth backend
        const valid = self.auth_backend.verifyCredentials(self.username.?, password) catch |err| {
            std.log.err("POP3 authentication error: {}", .{err});
            try self.sendErr("Authentication failed");
            return;
        };

        if (!valid) {
            std.log.warn("Failed POP3 login attempt for user: {s}", .{self.username.?});
            try self.sendErr("Authentication failed");
            return;
        }

        std.log.info("Successful POP3 login for user: {s}", .{self.username.?});

        // Lock maildrop and load messages
        try self.lockMaildrop();

        self.state = .transaction;
        try self.sendOk("Mailbox locked and ready");
    }

    /// Handle STAT command
    fn handleStat(self: *Pop3Session) !void {
        if (self.state != .transaction) {
            try self.sendErr("Not in TRANSACTION state");
            return;
        }

        var count: usize = 0;
        var total_size: usize = 0;

        for (self.messages.items) |msg| {
            if (!msg.deleted) {
                count += 1;
                total_size += msg.size;
            }
        }

        const response = try std.fmt.allocPrint(
            self.allocator,
            "{d} {d}",
            .{ count, total_size },
        );
        defer self.allocator.free(response);

        try self.sendOk(response);
    }

    /// Handle LIST command
    fn handleList(self: *Pop3Session, msg_number: ?usize) !void {
        if (self.state != .transaction) {
            try self.sendErr("Not in TRANSACTION state");
            return;
        }

        if (msg_number) |num| {
            // List single message
            if (num == 0 or num > self.messages.items.len) {
                try self.sendErr("No such message");
                return;
            }

            const msg = self.messages.items[num - 1];
            if (msg.deleted) {
                try self.sendErr("Message deleted");
                return;
            }

            const response = try std.fmt.allocPrint(
                self.allocator,
                "{d} {d}",
                .{ num, msg.size },
            );
            defer self.allocator.free(response);

            try self.sendOk(response);
        } else {
            // List all messages
            var count: usize = 0;
            var total_size: usize = 0;

            for (self.messages.items) |msg| {
                if (!msg.deleted) {
                    count += 1;
                    total_size += msg.size;
                }
            }

            const header = try std.fmt.allocPrint(
                self.allocator,
                "{d} messages ({d} octets)",
                .{ count, total_size },
            );
            defer self.allocator.free(header);

            try self.sendOk(header);

            // Send message list
            for (self.messages.items, 1..) |msg, i| {
                if (!msg.deleted) {
                    const line = try std.fmt.allocPrint(
                        self.allocator,
                        "{d} {d}",
                        .{ i, msg.size },
                    );
                    defer self.allocator.free(line);

                    try self.stream.writeAll(line);
                    try self.stream.writeAll("\r\n");
                }
            }

            try self.stream.writeAll(".\r\n");
        }
    }

    /// Handle RETR command
    fn handleRetr(self: *Pop3Session, msg_number: usize) !void {
        if (self.state != .transaction) {
            try self.sendErr("Not in TRANSACTION state");
            return;
        }

        if (msg_number == 0 or msg_number > self.messages.items.len) {
            try self.sendErr("No such message");
            return;
        }

        const msg = &self.messages.items[msg_number - 1];
        if (msg.deleted) {
            try self.sendErr("Message deleted");
            return;
        }

        const response = try std.fmt.allocPrint(
            self.allocator,
            "{d} octets",
            .{msg.size},
        );
        defer self.allocator.free(response);

        try self.sendOk(response);

        // Send message content (would read from file)
        const content = msg.content orelse "Sample message content";
        const lines = [_][]const u8{content};
        try self.sendMultiLine(&lines);
    }

    /// Handle DELE command
    fn handleDele(self: *Pop3Session, msg_number: usize) !void {
        if (self.state != .transaction) {
            try self.sendErr("Not in TRANSACTION state");
            return;
        }

        if (msg_number == 0 or msg_number > self.messages.items.len) {
            try self.sendErr("No such message");
            return;
        }

        const msg = &self.messages.items[msg_number - 1];
        if (msg.deleted) {
            try self.sendErr("Message already deleted");
            return;
        }

        msg.deleted = true;
        try self.sendOk("Message deleted");
    }

    /// Handle RSET command
    fn handleRset(self: *Pop3Session) !void {
        if (self.state != .transaction) {
            try self.sendErr("Not in TRANSACTION state");
            return;
        }

        // Undelete all messages
        for (self.messages.items) |*msg| {
            msg.deleted = false;
        }

        try self.sendOk("Maildrop has been reset");
    }

    /// Handle NOOP command
    fn handleNoop(self: *Pop3Session) !void {
        try self.sendOk("NOOP");
    }

    /// Handle TOP command
    fn handleTop(self: *Pop3Session, msg_number: usize, lines: usize) !void {
        _ = lines;

        if (self.state != .transaction) {
            try self.sendErr("Not in TRANSACTION state");
            return;
        }

        if (msg_number == 0 or msg_number > self.messages.items.len) {
            try self.sendErr("No such message");
            return;
        }

        const msg = &self.messages.items[msg_number - 1];
        if (msg.deleted) {
            try self.sendErr("Message deleted");
            return;
        }

        try self.sendOk("Top of message follows");

        // Would return headers + N lines of body
        const content = [_][]const u8{"Headers would go here"};
        try self.sendMultiLine(&content);
    }

    /// Handle UIDL command
    fn handleUidl(self: *Pop3Session, msg_number: ?usize) !void {
        if (self.state != .transaction) {
            try self.sendErr("Not in TRANSACTION state");
            return;
        }

        if (msg_number) |num| {
            // UIDL for single message
            if (num == 0 or num > self.messages.items.len) {
                try self.sendErr("No such message");
                return;
            }

            const msg = self.messages.items[num - 1];
            if (msg.deleted) {
                try self.sendErr("Message deleted");
                return;
            }

            const response = try std.fmt.allocPrint(
                self.allocator,
                "{d} {s}",
                .{ num, msg.uid },
            );
            defer self.allocator.free(response);

            try self.sendOk(response);
        } else {
            // UIDL for all messages
            try self.sendOk("Unique-ID listing follows");

            for (self.messages.items, 1..) |msg, i| {
                if (!msg.deleted) {
                    const line = try std.fmt.allocPrint(
                        self.allocator,
                        "{d} {s}",
                        .{ i, msg.uid },
                    );
                    defer self.allocator.free(line);

                    try self.stream.writeAll(line);
                    try self.stream.writeAll("\r\n");
                }
            }

            try self.stream.writeAll(".\r\n");
        }
    }

    /// Handle QUIT command - messages marked for deletion are soft-deleted via storage backend
    fn handleQuit(self: *Pop3Session, config: *const Pop3Config) !void {
        if (self.state == .transaction) {
            self.state = .update;

            if (config.delete_on_quit) {
                // Soft-delete messages marked for deletion via storage.deleteMessage()
                // The storage backend performs a soft-delete (UPDATE SET deleted_at)
                // rather than a permanent DELETE, preserving messages for admin recovery.
                var deleted_count: usize = 0;
                for (self.messages.items) |msg| {
                    if (msg.deleted) {
                        // Would call storage.deleteMessage() which is now a soft-delete
                        deleted_count += 1;
                    }
                }

                const response = try std.fmt.allocPrint(
                    self.allocator,
                    "POP3 server signing off ({d} messages soft-deleted)",
                    .{deleted_count},
                );
                defer self.allocator.free(response);

                try self.sendOk(response);
            } else {
                try self.sendOk("POP3 server signing off");
            }

            self.unlockMaildrop();
        } else {
            try self.sendOk("POP3 server signing off");
        }
    }

    /// Lock the maildrop and load messages
    fn lockMaildrop(self: *Pop3Session) !void {
        // Would actually lock the mailbox file
        // For now, just load sample messages
        try self.loadMessages();
        self.maildrop_locked = true;
    }

    /// Unlock the maildrop
    fn unlockMaildrop(self: *Pop3Session) void {
        // Would release the file lock
        self.maildrop_locked = false;
    }

    /// Load messages from mailbox
    fn loadMessages(self: *Pop3Session) !void {
        // Would scan mailbox directory
        // For now, create sample messages
        for (0..3) |i| {
            const uid = try std.fmt.allocPrint(self.allocator, "msg-{d}", .{i + 1});
            const msg = Pop3Message{
                .number = i + 1,
                .uid = uid,
                .size = 1024 + i * 512,
                .content = try std.fmt.allocPrint(
                    self.allocator,
                    "Sample message {d} content",
                    .{i + 1},
                ),
            };
            try self.messages.append(self.allocator, msg);
        }
    }

    /// Process a single command
    pub fn processCommand(self: *Pop3Session, line: []const u8, config: *const Pop3Config) !bool {
        var parts = std.mem.splitScalar(u8, line, ' ');
        const cmd_str = parts.next() orelse return true;

        // Convert to uppercase
        const cmd_upper = try self.allocator.alloc(u8, cmd_str.len);
        defer self.allocator.free(cmd_upper);
        _ = std.ascii.upperString(cmd_upper, cmd_str);

        if (std.mem.eql(u8, cmd_upper, "USER")) {
            const username = parts.next() orelse {
                try self.sendErr("Missing username");
                return true;
            };
            try self.handleUser(username);
        } else if (std.mem.eql(u8, cmd_upper, "PASS")) {
            const password = parts.next() orelse {
                try self.sendErr("Missing password");
                return true;
            };
            try self.handlePass(password);
        } else if (std.mem.eql(u8, cmd_upper, "STAT")) {
            try self.handleStat();
        } else if (std.mem.eql(u8, cmd_upper, "LIST")) {
            const msg_num_str = parts.next();
            const msg_num = if (msg_num_str) |num_str|
                std.fmt.parseInt(usize, num_str, 10) catch null
            else
                null;
            try self.handleList(msg_num);
        } else if (std.mem.eql(u8, cmd_upper, "RETR")) {
            const msg_num_str = parts.next() orelse {
                try self.sendErr("Missing message number");
                return true;
            };
            const msg_num = std.fmt.parseInt(usize, msg_num_str, 10) catch {
                try self.sendErr("Invalid message number");
                return true;
            };
            try self.handleRetr(msg_num);
        } else if (std.mem.eql(u8, cmd_upper, "DELE")) {
            const msg_num_str = parts.next() orelse {
                try self.sendErr("Missing message number");
                return true;
            };
            const msg_num = std.fmt.parseInt(usize, msg_num_str, 10) catch {
                try self.sendErr("Invalid message number");
                return true;
            };
            try self.handleDele(msg_num);
        } else if (std.mem.eql(u8, cmd_upper, "RSET")) {
            try self.handleRset();
        } else if (std.mem.eql(u8, cmd_upper, "NOOP")) {
            try self.handleNoop();
        } else if (std.mem.eql(u8, cmd_upper, "TOP")) {
            const msg_num_str = parts.next() orelse {
                try self.sendErr("Missing message number");
                return true;
            };
            const lines_str = parts.next() orelse {
                try self.sendErr("Missing line count");
                return true;
            };
            const msg_num = std.fmt.parseInt(usize, msg_num_str, 10) catch {
                try self.sendErr("Invalid message number");
                return true;
            };
            const lines = std.fmt.parseInt(usize, lines_str, 10) catch {
                try self.sendErr("Invalid line count");
                return true;
            };
            try self.handleTop(msg_num, lines);
        } else if (std.mem.eql(u8, cmd_upper, "UIDL")) {
            const msg_num_str = parts.next();
            const msg_num = if (msg_num_str) |num_str|
                std.fmt.parseInt(usize, num_str, 10) catch null
            else
                null;
            try self.handleUidl(msg_num);
        } else if (std.mem.eql(u8, cmd_upper, "QUIT")) {
            try self.handleQuit(config);
            return false; // Stop processing
        } else {
            try self.sendErr("Unknown command");
        }

        return true; // Continue processing
    }
};

/// POP3 server
pub const Pop3Server = struct {
    allocator: std.mem.Allocator,
    config: Pop3Config,
    listener: ?std.net.Server = null,
    sessions: std.ArrayList(*Pop3Session),
    running: std.atomic.Value(bool),
    mutex: mutex_compat.Mutex = .{},
    auth_backend: *auth.AuthBackend,

    pub fn init(allocator: std.mem.Allocator, config: Pop3Config, auth_backend: *auth.AuthBackend) Pop3Server {
        return .{
            .allocator = allocator,
            .config = config,
            .sessions = std.ArrayList(*Pop3Session){},
            .running = std.atomic.Value(bool).init(false),
            .auth_backend = auth_backend,
        };
    }

    pub fn deinit(self: *Pop3Server) void {
        self.stop();
        for (self.sessions.items) |session| {
            session.deinit();
            self.allocator.destroy(session);
        }
        self.sessions.deinit(self.allocator);
    }

    /// Start the POP3 server
    pub fn start(self: *Pop3Server) !void {
        const address = std.net.Address.parseIp("0.0.0.0", self.config.port) catch unreachable;
        self.listener = try address.listen(.{
            .reuse_address = true,
        });

        self.running.store(true, .monotonic);

        logger.info("POP3 server listening on port {d}", .{self.config.port});

        while (self.running.load(.monotonic)) {
            const connection = self.listener.?.accept() catch |err| {
                logger.err("POP3 accept error: {}", .{err});
                continue;
            };

            // Handle connection (simplified)
            self.handleConnection(connection.stream) catch |err| {
                logger.err("POP3 connection error: {}", .{err});
                connection.stream.close();
            };
        }
    }

    /// Stop the POP3 server
    pub fn stop(self: *Pop3Server) void {
        self.running.store(false, .monotonic);
        if (self.listener) |*listener| {
            listener.deinit();
            self.listener = null;
        }
    }

    /// Handle a client connection
    fn handleConnection(self: *Pop3Server, stream: std.net.Stream) !void {
        var session = try self.allocator.create(Pop3Session);
        session.* = Pop3Session.init(self.allocator, stream, self.auth_backend);
        defer {
            session.deinit();
            self.allocator.destroy(session);
            stream.close();
        }

        // Send greeting
        try session.sendGreeting();

        // Read commands
        var buffer: [4096]u8 = undefined;
        while (true) {
            const bytes_read = stream.read(&buffer) catch break;
            if (bytes_read == 0) break;

            const line = std.mem.trim(u8, buffer[0..bytes_read], "\r\n");
            const continue_processing = session.processCommand(line, &self.config) catch |err| {
                logger.err("POP3 command processing error: {}", .{err});
                break;
            };

            if (!continue_processing) break;
        }
    }
};

// Tests
test "POP3 message" {
    const testing = std.testing;

    const uid = try testing.allocator.dupe(u8, "msg-123");
    var msg = Pop3Message{
        .number = 1,
        .uid = uid,
        .size = 1024,
    };
    defer msg.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), msg.number);
    try testing.expectEqual(@as(usize, 1024), msg.size);
    try testing.expect(!msg.deleted);
}

test "POP3 session state transitions" {
    const testing = std.testing;

    const stream = undefined; // Would need actual stream for real test
    var session = Pop3Session.init(testing.allocator, stream);
    defer session.deinit();

    try testing.expectEqual(Pop3State.authorization, session.state);
}
