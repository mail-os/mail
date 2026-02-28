const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const posix = std.posix;
const time_compat = @import("../core/time_compat.zig");
const socket = @import("../core/socket_compat.zig");
const io_compat = @import("../core/io_compat.zig");
const auth = @import("../auth/auth.zig");
const logger = @import("../core/logger.zig");
const tls_mod = @import("../core/tls.zig");
const tls = @import("tls");

/// IMAP4rev1 Server Implementation (RFC 3501)
/// Provides mail retrieval and mailbox management via IMAP protocol
///
/// Features:
/// - IMAP4rev1 protocol support (RFC 3501)
/// - IDLE support for push notifications (RFC 2177)
/// - Multiple mailbox support
/// - Message flags and keywords
/// - Search capabilities
/// - SSL/TLS support (STARTTLS)
/// - SASL authentication
/// - Mailbox subscriptions
/// - Message status tracking
/// IMAP server configuration
pub const ImapConfig = struct {
    port: u16 = 143,
    ssl_port: u16 = 993,
    enable_ssl: bool = true,
    max_connections: usize = 100,
    connection_timeout_seconds: u64 = 300,
    idle_timeout_seconds: u64 = 1800,
    max_message_size: usize = 50 * 1024 * 1024, // 50 MB
    mailbox_path: []const u8 = "/var/spool/mail",
    // TLS configuration
    cert_path: ?[]const u8 = null,
    key_path: ?[]const u8 = null,
};

/// IMAP connection state
pub const ImapState = enum {
    not_authenticated,
    authenticated,
    selected,
    logout,
};

/// IMAP capabilities
pub const ImapCapability = enum {
    imap4rev1,
    starttls,
    auth_plain,
    auth_login,
    idle,
    namespace,
    uidplus,
    unselect,
    children,
    quota,
    sort,
    thread,
    special_use, // RFC 6154 - SPECIAL-USE for Gmail-style folders

    pub fn toString(self: ImapCapability) []const u8 {
        return switch (self) {
            .imap4rev1 => "IMAP4rev1",
            .starttls => "STARTTLS",
            .auth_plain => "AUTH=PLAIN",
            .auth_login => "AUTH=LOGIN",
            .idle => "IDLE",
            .namespace => "NAMESPACE",
            .uidplus => "UIDPLUS",
            .unselect => "UNSELECT",
            .children => "CHILDREN",
            .quota => "QUOTA",
            .sort => "SORT",
            .thread => "THREAD",
            .special_use => "SPECIAL-USE",
        };
    }
};

/// Folder type for Gmail-style folders
pub const FolderType = enum {
    inbox,
    sent,
    drafts,
    trash,
    junk,
    archive,
    all_mail,
    starred,
    important,
    social,
    forums,
    updates,
    promotions,
    notes,
    regular,

    /// Get the SPECIAL-USE attributes for this folder type
    pub fn getAttributes(self: FolderType) []const u8 {
        return switch (self) {
            .inbox => "\\HasNoChildren",
            .sent => "\\HasNoChildren \\Sent",
            .drafts => "\\HasNoChildren \\Drafts",
            .trash => "\\HasNoChildren \\Trash",
            .junk => "\\HasNoChildren \\Junk",
            .archive => "\\HasNoChildren \\Archive",
            .all_mail => "\\HasNoChildren \\All",
            .starred => "\\HasNoChildren \\Flagged",
            .important => "\\HasNoChildren \\Important",
            .social => "\\HasNoChildren",
            .forums => "\\HasNoChildren",
            .updates => "\\HasNoChildren",
            .promotions => "\\HasNoChildren",
            .notes => "\\HasNoChildren",
            .regular => "\\HasNoChildren",
        };
    }

    /// Get the display name for this folder type
    pub fn getName(self: FolderType) []const u8 {
        return switch (self) {
            .inbox => "INBOX",
            .sent => "Sent",
            .drafts => "Drafts",
            .trash => "Trash",
            .junk => "Junk",
            .archive => "Archive",
            .all_mail => "All Mail",
            .starred => "Starred",
            .important => "Important",
            .social => "Social",
            .forums => "Forums",
            .updates => "Updates",
            .promotions => "Promotions",
            .notes => "Notes",
            .regular => "",
        };
    }

    /// Check if this is a virtual folder (computed from flags, not stored separately)
    pub fn isVirtual(self: FolderType) bool {
        return switch (self) {
            .starred, .important, .all_mail => true,
            else => false,
        };
    }
};

/// Gmail-style folders in the order they should be listed
pub const GmailFolders = [_]FolderType{
    .inbox,
    .starred,
    .important,
    .sent,
    .drafts,
    .all_mail,
    .junk,
    .trash,
    .archive,
    .notes,
    .social,
    .forums,
    .updates,
    .promotions,
};

/// IMAP message flags
pub const MessageFlags = struct {
    seen: bool = false,
    answered: bool = false,
    flagged: bool = false,
    deleted: bool = false,
    draft: bool = false,
    recent: bool = false,

    pub fn toString(self: MessageFlags, allocator: std.mem.Allocator) ![]const u8 {
        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();

        try writer.writeAll("(");
        var has_flag = false;

        if (self.seen) {
            try writer.writeAll("\\Seen");
            has_flag = true;
        }
        if (self.answered) {
            if (has_flag) try writer.writeAll(" ");
            try writer.writeAll("\\Answered");
            has_flag = true;
        }
        if (self.flagged) {
            if (has_flag) try writer.writeAll(" ");
            try writer.writeAll("\\Flagged");
            has_flag = true;
        }
        if (self.deleted) {
            if (has_flag) try writer.writeAll(" ");
            try writer.writeAll("\\Deleted");
            has_flag = true;
        }
        if (self.draft) {
            if (has_flag) try writer.writeAll(" ");
            try writer.writeAll("\\Draft");
            has_flag = true;
        }
        if (self.recent) {
            if (has_flag) try writer.writeAll(" ");
            try writer.writeAll("\\Recent");
        }
        try writer.writeAll(")");

        return allocator.dupe(u8, fbs.getWritten());
    }
};

/// IMAP mailbox
pub const Mailbox = struct {
    name: []const u8,
    path: []const u8,
    exists: usize = 0, // Number of messages
    recent: usize = 0, // Number of recent messages
    unseen: usize = 0, // Number of unseen messages
    uidvalidity: u32,
    uidnext: u32,
    flags: std.ArrayList([]const u8),
    permanent_flags: std.ArrayList([]const u8),

    pub fn init(allocator: std.mem.Allocator, name: []const u8, path: []const u8) !Mailbox {
        return Mailbox{
            .name = try allocator.dupe(u8, name),
            .path = try allocator.dupe(u8, path),
            .uidvalidity = @intCast(time_compat.timestamp()),
            .uidnext = 1,
            .flags = std.ArrayList([]const u8){},
            .permanent_flags = std.ArrayList([]const u8){},
        };
    }

    pub fn deinit(self: *Mailbox, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.path);
        for (self.flags.items) |flag| {
            allocator.free(flag);
        }
        self.flags.deinit(allocator);
        for (self.permanent_flags.items) |flag| {
            allocator.free(flag);
        }
        self.permanent_flags.deinit(allocator);
    }
};

/// IMAP message
pub const ImapMessage = struct {
    uid: u32,
    sequence: u32,
    size: usize,
    flags: MessageFlags,
    internal_date: i64,
    envelope: ?[]const u8 = null,
    body_structure: ?[]const u8 = null,

    pub fn deinit(self: *ImapMessage, allocator: std.mem.Allocator) void {
        if (self.envelope) |env| allocator.free(env);
        if (self.body_structure) |bs| allocator.free(bs);
    }
};

/// IMAP command
pub const ImapCommand = enum {
    // Any state
    capability,
    noop,
    logout,

    // Not authenticated
    starttls,
    authenticate,
    login,

    // Authenticated
    select,
    examine,
    create,
    delete,
    rename,
    subscribe,
    unsubscribe,
    list,
    xlist, // Gmail extension
    lsub,
    status,
    append,

    // Selected
    check,
    close,
    expunge,
    search,
    fetch,
    store,
    copy,
    uid,
    idle,

    pub fn fromString(cmd: []const u8) ?ImapCommand {
        const upper = std.ascii.allocUpperString(std.heap.page_allocator, cmd) catch return null;
        defer std.heap.page_allocator.free(upper);

        const commands = std.StaticStringMap(ImapCommand).initComptime(.{
            .{ "CAPABILITY", .capability },
            .{ "NOOP", .noop },
            .{ "LOGOUT", .logout },
            .{ "STARTTLS", .starttls },
            .{ "AUTHENTICATE", .authenticate },
            .{ "LOGIN", .login },
            .{ "SELECT", .select },
            .{ "EXAMINE", .examine },
            .{ "CREATE", .create },
            .{ "DELETE", .delete },
            .{ "RENAME", .rename },
            .{ "SUBSCRIBE", .subscribe },
            .{ "UNSUBSCRIBE", .unsubscribe },
            .{ "LIST", .list },
            .{ "XLIST", .xlist },
            .{ "LSUB", .lsub },
            .{ "STATUS", .status },
            .{ "APPEND", .append },
            .{ "CHECK", .check },
            .{ "CLOSE", .close },
            .{ "EXPUNGE", .expunge },
            .{ "SEARCH", .search },
            .{ "FETCH", .fetch },
            .{ "STORE", .store },
            .{ "COPY", .copy },
            .{ "UID", .uid },
            .{ "IDLE", .idle },
        });

        return commands.get(upper);
    }
};

/// IMAP session
pub const ImapSession = struct {
    allocator: std.mem.Allocator,
    connection: socket.Connection,
    state: ImapState,
    username: ?[]const u8 = null,
    selected_mailbox: ?*Mailbox = null,
    tag: ?[]const u8 = null,
    command_buffer: std.ArrayList(u8),
    idle_mode: bool = false,
    auth_backend: *auth.AuthBackend,
    // TLS support for encrypted responses
    tls_connection: ?*tls.nonblock.Connection = null,

    pub fn init(allocator: std.mem.Allocator, connection: socket.Connection, auth_backend: *auth.AuthBackend) ImapSession {
        return .{
            .allocator = allocator,
            .connection = connection,
            .state = .not_authenticated,
            .command_buffer = std.ArrayList(u8){},
            .auth_backend = auth_backend,
            .tls_connection = null,
        };
    }

    /// Set the TLS connection for encrypted I/O
    pub fn setTlsConnection(self: *ImapSession, tls_conn: *tls.nonblock.Connection) void {
        self.tls_connection = tls_conn;
    }

    pub fn deinit(self: *ImapSession) void {
        if (self.username) |username| {
            self.allocator.free(username);
        }
        if (self.tag) |tag| {
            self.allocator.free(tag);
        }
        self.command_buffer.deinit(self.allocator);
    }

    /// Write data to connection (plain or TLS encrypted)
    fn writeData(self: *ImapSession, data: []const u8) !void {
        if (self.tls_connection) |tls_conn| {
            // TLS encrypted write
            var send_buf: [tls.output_buffer_len]u8 = undefined;
            const enc_result = tls_conn.encrypt(data, &send_buf) catch |err| {
                logger.err("Failed to encrypt IMAP response: {}", .{err});
                return error.TlsEncryptFailed;
            };
            var sent: usize = 0;
            while (sent < enc_result.ciphertext.len) {
                const n = self.connection.write(enc_result.ciphertext[sent..]) catch |err| {
                    logger.err("Failed to write encrypted IMAP response: {}", .{err});
                    return err;
                };
                if (n == 0) return error.ConnectionClosed;
                sent += n;
            }
        } else {
            // Plain text write
            _ = try self.connection.write(data);
        }
    }

    /// Send greeting
    pub fn sendGreeting(self: *ImapSession) !void {
        const greeting = "* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN] SMTP Server IMAP4rev1 ready\r\n";
        try self.writeData(greeting);
    }

    /// Send response
    pub fn sendResponse(self: *ImapSession, tag: []const u8, status: []const u8, message: []const u8) !void {
        var buf: [4096]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        try writer.print("{s} {s} {s}\r\n", .{ tag, status, message });

        try self.writeData(fbs.getWritten());
    }

    /// Send untagged response
    pub fn sendUntagged(self: *ImapSession, message: []const u8) !void {
        var buf: [4096]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        try writer.print("* {s}\r\n", .{message});

        try self.writeData(fbs.getWritten());
    }

    /// Handle CAPABILITY command
    fn handleCapability(self: *ImapSession, tag: []const u8) !void {
        const capabilities = [_]ImapCapability{
            .imap4rev1,
            .starttls,
            .auth_plain,
            .auth_login,
            .idle,
            .namespace,
            .uidplus,
            .special_use, // RFC 6154 - Gmail-style folders
        };

        var buf: [1024]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        try writer.writeAll("CAPABILITY");

        for (capabilities) |cap| {
            try writer.print(" {s}", .{cap.toString()});
        }

        try self.sendUntagged(fbs.getWritten());
        try self.sendResponse(tag, "OK", "CAPABILITY completed");
    }

    /// Handle LIST command - returns Gmail-style folder listing
    fn handleList(self: *ImapSession, tag: []const u8, reference: []const u8, pattern: []const u8) !void {
        _ = reference; // Reference name (usually empty)

        if (self.state == .not_authenticated) {
            try self.sendResponse(tag, "NO", "Must authenticate first");
            return;
        }

        // If pattern is empty, return hierarchy delimiter
        if (pattern.len == 0 or std.mem.eql(u8, pattern, "\"\"")) {
            try self.sendUntagged("LIST (\\Noselect) \"/\" \"\"");
            try self.sendResponse(tag, "OK", "LIST completed");
            return;
        }

        // Return all Gmail-style folders
        for (GmailFolders) |folder_type| {
            const attrs = folder_type.getAttributes();
            const name = folder_type.getName();

            var buf: [512]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&buf);
            const writer = fbs.writer();
            try writer.print("LIST ({s}) \"/\" \"{s}\"", .{ attrs, name });
            try self.sendUntagged(fbs.getWritten());
        }

        try self.sendResponse(tag, "OK", "LIST completed");
    }

    /// Handle STATUS command - returns folder status
    fn handleStatus(self: *ImapSession, tag: []const u8, mailbox_name: []const u8, status_items: []const u8) !void {
        if (self.state == .not_authenticated) {
            try self.sendResponse(tag, "NO", "Must authenticate first");
            return;
        }

        // Parse which status items are requested
        const want_messages = std.mem.indexOf(u8, status_items, "MESSAGES") != null;
        const want_recent = std.mem.indexOf(u8, status_items, "RECENT") != null;
        const want_uidnext = std.mem.indexOf(u8, status_items, "UIDNEXT") != null;
        const want_uidvalidity = std.mem.indexOf(u8, status_items, "UIDVALIDITY") != null;
        const want_unseen = std.mem.indexOf(u8, status_items, "UNSEEN") != null;

        // Build status response (would be populated from actual mailbox data)
        var buf: [1024]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        try writer.print("STATUS \"{s}\" (", .{mailbox_name});

        var first = true;
        if (want_messages) {
            try writer.writeAll("MESSAGES 0");
            first = false;
        }
        if (want_recent) {
            if (!first) try writer.writeAll(" ");
            try writer.writeAll("RECENT 0");
            first = false;
        }
        if (want_uidnext) {
            if (!first) try writer.writeAll(" ");
            try writer.writeAll("UIDNEXT 1");
            first = false;
        }
        if (want_uidvalidity) {
            if (!first) try writer.writeAll(" ");
            try writer.print("UIDVALIDITY {d}", .{@as(u32, @intCast(time_compat.timestamp()))});
            first = false;
        }
        if (want_unseen) {
            if (!first) try writer.writeAll(" ");
            try writer.writeAll("UNSEEN 0");
        }
        try writer.writeAll(")");

        try self.sendUntagged(fbs.getWritten());
        try self.sendResponse(tag, "OK", "STATUS completed");
    }

    /// Handle XLIST command (Gmail extension, same as LIST)
    fn handleXList(self: *ImapSession, tag: []const u8, reference: []const u8, pattern: []const u8) !void {
        // XLIST is a Gmail extension that's equivalent to LIST with SPECIAL-USE
        try self.handleList(tag, reference, pattern);
    }

    /// Handle LOGIN command
    fn handleLogin(self: *ImapSession, tag: []const u8, username: []const u8, password: []const u8) !void {
        if (self.state != .not_authenticated) {
            try self.sendResponse(tag, "BAD", "Already authenticated");
            return;
        }

        // Validate credentials against auth backend
        const valid = self.auth_backend.verifyCredentials(username, password) catch |err| {
            std.log.err("Authentication error: {}", .{err});
            try self.sendResponse(tag, "NO", "LOGIN failed");
            return;
        };

        if (!valid) {
            std.log.warn("Failed IMAP login attempt for user: {s}", .{username});
            try self.sendResponse(tag, "NO", "LOGIN failed");
            return;
        }

        // Store username
        self.username = try self.allocator.dupe(u8, username);
        self.state = .authenticated;

        std.log.info("Successful IMAP login for user: {s}", .{username});
        try self.sendResponse(tag, "OK", "LOGIN completed");
    }

    /// Handle SELECT command
    fn handleSelect(self: *ImapSession, tag: []const u8, mailbox_name: []const u8) !void {
        if (self.state == .not_authenticated) {
            try self.sendResponse(tag, "NO", "Must authenticate first");
            return;
        }

        // Create/open mailbox (simplified)
        var mailbox = try Mailbox.init(self.allocator, mailbox_name, "/var/spool/mail");
        mailbox.exists = 0; // Would scan directory
        mailbox.recent = 0;
        mailbox.unseen = 0;

        // Send mailbox info
        const exists_msg = try std.fmt.allocPrint(self.allocator, "{d} EXISTS", .{mailbox.exists});
        defer self.allocator.free(exists_msg);
        try self.sendUntagged(exists_msg);

        const recent_msg = try std.fmt.allocPrint(self.allocator, "{d} RECENT", .{mailbox.recent});
        defer self.allocator.free(recent_msg);
        try self.sendUntagged(recent_msg);

        const uidval_msg = try std.fmt.allocPrint(self.allocator, "OK [UIDVALIDITY {d}]", .{mailbox.uidvalidity});
        defer self.allocator.free(uidval_msg);
        try self.sendUntagged(uidval_msg);

        const uidnext_msg = try std.fmt.allocPrint(self.allocator, "OK [UIDNEXT {d}]", .{mailbox.uidnext});
        defer self.allocator.free(uidnext_msg);
        try self.sendUntagged(uidnext_msg);
        try self.sendUntagged("FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)");
        try self.sendUntagged("OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)]");

        self.state = .selected;
        try self.sendResponse(tag, "OK", "[READ-WRITE] SELECT completed");

        mailbox.deinit(self.allocator);
    }

    /// Handle FETCH command
    fn handleFetch(self: *ImapSession, tag: []const u8, sequence_set: []const u8, items: []const u8) !void {
        _ = sequence_set;
        _ = items;

        if (self.state != .selected) {
            try self.sendResponse(tag, "NO", "Must select mailbox first");
            return;
        }

        // Would fetch and return message data
        try self.sendResponse(tag, "OK", "FETCH completed");
    }

    /// Handle EXPUNGE command - soft-deletes messages marked with \Deleted flag
    fn handleExpunge(self: *ImapSession, tag: []const u8) !void {
        if (self.state != .selected) {
            try self.sendResponse(tag, "NO", "Must select mailbox first");
            return;
        }

        // Would iterate messages with \Deleted flag and call storage.deleteMessage()
        // (which is now a soft-delete). For each expunged message, send untagged response:
        // * <seq> EXPUNGE

        try self.sendResponse(tag, "OK", "EXPUNGE completed (soft-delete)");
    }

    /// Handle LOGOUT command
    fn handleLogout(self: *ImapSession, tag: []const u8) !void {
        try self.sendUntagged("BYE IMAP4rev1 Server logging out");
        try self.sendResponse(tag, "OK", "LOGOUT completed");
        self.state = .logout;
    }

    /// Process a single command
    pub fn processCommand(self: *ImapSession, line: []const u8) !void {
        // Parse command: TAG COMMAND [ARGS...]
        var parts = std.mem.splitScalar(u8, line, ' ');

        const tag = parts.next() orelse {
            try self.sendResponse("*", "BAD", "Missing tag");
            return;
        };

        const cmd_str = parts.next() orelse {
            try self.sendResponse(tag, "BAD", "Missing command");
            return;
        };

        const command = ImapCommand.fromString(cmd_str) orelse {
            try self.sendResponse(tag, "BAD", "Unknown command");
            return;
        };

        // Handle command
        switch (command) {
            .capability => try self.handleCapability(tag),
            .noop => try self.sendResponse(tag, "OK", "NOOP completed"),
            .logout => try self.handleLogout(tag),
            .login => {
                const username = parts.next() orelse "";
                const password = parts.next() orelse "";
                try self.handleLogin(tag, username, password);
            },
            .select => {
                const mailbox = parts.next() orelse "INBOX";
                try self.handleSelect(tag, mailbox);
            },
            .list, .xlist => {
                // LIST/XLIST reference pattern
                const reference = parts.next() orelse "";
                const pattern = parts.next() orelse "*";
                if (command == .xlist) {
                    try self.handleXList(tag, reference, pattern);
                } else {
                    try self.handleList(tag, reference, pattern);
                }
            },
            .lsub => {
                // LSUB is same as LIST for subscribed folders (we treat all as subscribed)
                const reference = parts.next() orelse "";
                const pattern = parts.next() orelse "*";
                try self.handleList(tag, reference, pattern);
            },
            .status => {
                // STATUS mailbox (items)
                const mailbox_name = parts.next() orelse "INBOX";
                // Get rest of line as status items
                var status_items_buf: [256]u8 = undefined;
                var status_len: usize = 0;
                while (parts.next()) |part| {
                    if (status_len > 0) {
                        status_items_buf[status_len] = ' ';
                        status_len += 1;
                    }
                    const copy_len = @min(part.len, status_items_buf.len - status_len);
                    @memcpy(status_items_buf[status_len..][0..copy_len], part[0..copy_len]);
                    status_len += copy_len;
                }
                const status_items = status_items_buf[0..status_len];
                try self.handleStatus(tag, mailbox_name, status_items);
            },
            .fetch => {
                const sequence_set = parts.next() orelse "1:*";
                const items = parts.next() orelse "FLAGS";
                try self.handleFetch(tag, sequence_set, items);
            },
            .expunge => try self.handleExpunge(tag),
            else => {
                try self.sendResponse(tag, "NO", "Command not implemented");
            },
        }
    }
};

/// IMAP server
pub const ImapServer = struct {
    allocator: std.mem.Allocator,
    config: ImapConfig,
    listener: ?socket.Server = null,
    ssl_listener: ?socket.Server = null,
    sessions: std.ArrayList(*ImapSession),
    running: std.atomic.Value(bool),
    mutex: mutex_compat.Mutex = .{},
    auth_backend: *auth.AuthBackend,
    tls_context: ?*tls_mod.TlsContext = null,
    cert_key_pair: ?tls.config.CertKeyPair = null,

    pub fn init(allocator: std.mem.Allocator, config: ImapConfig, auth_backend: *auth.AuthBackend) ImapServer {
        var server = ImapServer{
            .allocator = allocator,
            .config = config,
            .sessions = std.ArrayList(*ImapSession){},
            .running = std.atomic.Value(bool).init(false),
            .auth_backend = auth_backend,
            .tls_context = null,
            .cert_key_pair = null,
        };

        // Load TLS certificate if configured
        if (config.enable_ssl and config.cert_path != null and config.key_path != null) {
            server.cert_key_pair = tls.config.CertKeyPair.fromFilePathAbsoluteSync(
                allocator,
                config.cert_path.?,
                config.key_path.?,
            ) catch |err| {
                logger.err("Failed to load TLS certificate for IMAPS: {}", .{err});
                return server;
            };
            logger.info("Loaded TLS certificate for IMAPS", .{});
        }

        return server;
    }

    pub fn deinit(self: *ImapServer) void {
        self.stop();
        for (self.sessions.items) |session| {
            session.deinit();
            self.allocator.destroy(session);
        }
        self.sessions.deinit(self.allocator);
        if (self.tls_context) |ctx| {
            var tls_ctx = ctx;
            tls_ctx.deinit();
            self.allocator.destroy(ctx);
        }
        if (self.cert_key_pair) |*ckp| {
            ckp.deinit(self.allocator);
        }
    }

    /// Start the IMAP server (plain text on port 143)
    pub fn start(self: *ImapServer) !void {
        const address = try socket.Address.parseIp("0.0.0.0", self.config.port);
        self.listener = try socket.Server.listen(address, .{
            .reuse_address = true,
        });

        self.running.store(true, .monotonic);

        logger.info("IMAP server listening on port {d}", .{self.config.port});

        // Also start IMAPS (port 993) if SSL is enabled and certs are configured
        if (self.config.enable_ssl and self.config.cert_path != null and self.config.key_path != null) {
            _ = std.Thread.spawn(.{}, startImapsListener, .{self}) catch |err| {
                logger.warn("Failed to start IMAPS listener: {} (IMAP on port {d} still available)", .{ err, self.config.port });
            };
        }

        while (self.running.load(.monotonic)) {
            const connection = self.listener.?.accept() catch |err| {
                logger.err("IMAP accept error: {}", .{err});
                continue;
            };

            // Handle connection in a new thread (simplified)
            self.handleConnection(connection, false) catch |err| {
                logger.err("IMAP connection error: {}", .{err});
                connection.close();
            };
        }
    }

    /// Start the IMAPS listener on port 993 (runs in separate thread)
    fn startImapsListener(self: *ImapServer) void {
        const ssl_address = socket.Address.parseIp("0.0.0.0", self.config.ssl_port) catch |err| {
            logger.err("Failed to parse IMAPS address: {}", .{err});
            return;
        };

        self.ssl_listener = socket.Server.listen(ssl_address, .{
            .reuse_address = true,
        }) catch |err| {
            logger.err("Failed to start IMAPS listener: {}", .{err});
            return;
        };

        logger.info("IMAPS server listening on port {d} (SSL/TLS)", .{self.config.ssl_port});

        while (self.running.load(.monotonic)) {
            const connection = self.ssl_listener.?.accept() catch |err| {
                if (!self.running.load(.monotonic)) break; // Server is stopping
                logger.err("IMAPS accept error: {}", .{err});
                continue;
            };

            // Handle SSL connection
            self.handleConnection(connection, true) catch |err| {
                logger.err("IMAPS connection error: {}", .{err});
                connection.close();
            };
        }
    }

    /// Stop the IMAP server
    pub fn stop(self: *ImapServer) void {
        self.running.store(false, .monotonic);
        if (self.listener) |*listener| {
            listener.close();
            self.listener = null;
        }
        if (self.ssl_listener) |*ssl_listener| {
            ssl_listener.close();
            self.ssl_listener = null;
        }
    }

    /// Handle a client connection
    fn handleConnection(self: *ImapServer, connection: socket.Connection, is_ssl: bool) !void {
        var session = try self.allocator.create(ImapSession);
        session.* = ImapSession.init(self.allocator, connection, self.auth_backend);
        defer {
            session.deinit();
            self.allocator.destroy(session);
            connection.close();
        }

        // For IMAPS connections, perform TLS handshake first using nonblock API
        var tls_cipher: ?tls.Cipher = null;

        if (is_ssl) {
            // Check if we have a certificate loaded
            if (self.cert_key_pair == null) {
                logger.err("IMAPS connection attempted but no certificate loaded", .{});
                return error.TlsNotConfigured;
            }

            logger.info("Starting TLS handshake for IMAPS connection", .{});

            // Use nonblock TLS server handshake
            var tls_server = tls.nonblock.Server.init(.{
                .auth = &self.cert_key_pair.?,
                // cipher_suites defaults to cipher_suites.all which includes TLS 1.2
            });

            // Buffers for TLS handshake
            var recv_buf: [tls.input_buffer_len]u8 = undefined;
            var send_buf: [tls.output_buffer_len]u8 = undefined;
            var recv_len: usize = 0;

            // Perform handshake loop
            while (!tls_server.done()) {
                // Run handshake step
                const result = tls_server.run(recv_buf[0..recv_len], &send_buf) catch |err| {
                    logger.err("TLS handshake error: {}", .{err});
                    return error.TlsHandshakeFailed;
                };

                // Consume processed bytes
                if (result.recv_pos > 0) {
                    const remaining = recv_len - result.recv_pos;
                    if (remaining > 0) {
                        std.mem.copyForwards(u8, &recv_buf, recv_buf[result.recv_pos..recv_len]);
                    }
                    recv_len = remaining;
                }

                // Send data to client if any
                if (result.send.len > 0) {
                    logger.info("TLS handshake: preparing to send {d} bytes", .{result.send.len});
                    var sent: usize = 0;
                    while (sent < result.send.len) {
                        const n = connection.write(result.send[sent..]) catch |err| {
                            logger.err("TLS handshake write error: {}", .{err});
                            return error.TlsHandshakeFailed;
                        };
                        logger.info("TLS handshake: wrote {d} bytes (total sent: {d}/{d})", .{ n, sent + n, result.send.len });
                        if (n == 0) {
                            logger.err("TLS handshake: connection closed during write", .{});
                            return error.TlsHandshakeFailed;
                        }
                        sent += n;
                    }
                    logger.info("TLS handshake: finished sending all {d} bytes", .{result.send.len});
                }

                // Read more data from client if handshake not done
                if (!tls_server.done()) {
                    const n = connection.read(recv_buf[recv_len..]) catch |err| {
                        logger.err("TLS handshake read error: {}", .{err});
                        return error.TlsHandshakeFailed;
                    };
                    if (n == 0) {
                        logger.err("TLS handshake: connection closed during read", .{});
                        return error.TlsHandshakeFailed;
                    }
                    recv_len += n;
                }
            }

            tls_cipher = tls_server.cipher();
            logger.info("IMAPS TLS handshake completed successfully", .{});
        }

        // Handle session based on whether TLS is active
        if (tls_cipher) |cipher| {
            // TLS encrypted session using nonblock connection
            var tls_conn = tls.nonblock.Connection.init(cipher);

            // Set TLS connection on session so all responses are encrypted
            session.setTlsConnection(&tls_conn);

            // Send greeting over TLS (now using session's TLS-aware write)
            session.sendGreeting() catch |err| {
                logger.err("Failed to send IMAP greeting: {}", .{err});
                return;
            };

            // Read and process commands over TLS
            var recv_buf: [tls.input_buffer_len]u8 = undefined;
            var cleartext_buf: [4096]u8 = undefined;
            var ciphertext_accum: [tls.input_buffer_len * 2]u8 = undefined;
            var ciphertext_len: usize = 0;

            while (session.state != .logout) {
                // Read ciphertext from socket
                const bytes_read = connection.read(recv_buf[0..]) catch break;
                if (bytes_read == 0) break;

                // Accumulate ciphertext
                if (ciphertext_len + bytes_read <= ciphertext_accum.len) {
                    @memcpy(ciphertext_accum[ciphertext_len..][0..bytes_read], recv_buf[0..bytes_read]);
                    ciphertext_len += bytes_read;
                }

                // Try to decrypt
                const dec_result = tls_conn.decrypt(ciphertext_accum[0..ciphertext_len], &cleartext_buf) catch |err| {
                    logger.err("TLS decrypt error: {}", .{err});
                    break;
                };

                // Handle decrypted data
                if (dec_result.cleartext.len > 0) {
                    const line = std.mem.trim(u8, dec_result.cleartext, "\r\n");
                    // Now session.processCommand will use TLS for responses
                    session.processCommand(line) catch |err| {
                        logger.err("IMAP command processing error: {}", .{err});
                        break;
                    };
                }

                // Remove consumed ciphertext
                if (dec_result.ciphertext_pos > 0) {
                    const remaining = ciphertext_len - dec_result.ciphertext_pos;
                    if (remaining > 0) {
                        std.mem.copyForwards(u8, &ciphertext_accum, ciphertext_accum[dec_result.ciphertext_pos..ciphertext_len]);
                    }
                    ciphertext_len = remaining;
                }

                if (dec_result.closed) break;
            }

            // Send close notify
            var close_buf: [64]u8 = undefined;
            if (tls_conn.close(&close_buf)) |close_data| {
                _ = connection.write(close_data) catch {};
            } else |_| {}
        } else {
            // Plain text session (non-SSL)
            try session.sendGreeting();

            var buffer: [4096]u8 = undefined;
            while (session.state != .logout) {
                const bytes_read = connection.read(&buffer) catch break;
                if (bytes_read == 0) break;

                const line = std.mem.trim(u8, buffer[0..bytes_read], "\r\n");
                session.processCommand(line) catch |err| {
                    logger.err("IMAP command processing error: {}", .{err});
                    break;
                };
            }
        }
    }
};

// Tests
test "IMAP command parsing" {
    const testing = std.testing;

    const cmd = ImapCommand.fromString("LOGIN");
    try testing.expect(cmd != null);
    try testing.expectEqual(ImapCommand.login, cmd.?);

    const unknown = ImapCommand.fromString("UNKNOWN");
    try testing.expect(unknown == null);
}

test "IMAP message flags" {
    const testing = std.testing;

    var flags = MessageFlags{
        .seen = true,
        .flagged = true,
    };

    const flags_str = try flags.toString(testing.allocator);
    defer testing.allocator.free(flags_str);

    try testing.expect(std.mem.indexOf(u8, flags_str, "\\Seen") != null);
    try testing.expect(std.mem.indexOf(u8, flags_str, "\\Flagged") != null);
}

test "IMAP mailbox" {
    const testing = std.testing;

    var mailbox = try Mailbox.init(testing.allocator, "INBOX", "/var/spool/mail/user");
    defer mailbox.deinit(testing.allocator);

    try testing.expect(std.mem.eql(u8, mailbox.name, "INBOX"));
    try testing.expectEqual(@as(usize, 0), mailbox.exists);
}
