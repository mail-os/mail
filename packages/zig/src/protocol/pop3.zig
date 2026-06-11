const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const auth = @import("../auth/auth.zig");
const logger = @import("../core/logger.zig");
const fs_compat = @import("../core/fs_compat.zig");

/// POP3 Server Implementation (RFC 1939)
/// Provides simple mail retrieval via POP3 protocol
///
/// Features:
/// - POP3 protocol support (RFC 1939)
/// - TOP command support
/// - UIDL support for unique message IDs
/// - SSL/TLS support (POP3S on the dedicated SSL port)
/// - Message deletion (DELE + QUIT removes the underlying maildir files)
/// - Operates on the user's real maildir (mail/{local}/new + cur)
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

/// In-process registry of locked maildrops (RFC 1939 §3: the maildrop must
/// be held exclusively from PASS to QUIT). The maildir is only served by
/// this one process, so an in-process set is sufficient. Usernames are
/// copied into the set with the libc allocator and freed on release.
var maildrop_locks_mutex: mutex_compat.Mutex = .{};
var maildrop_locks: ?std.StringHashMap(void) = null;

fn acquireMaildropLock(username: []const u8) bool {
    maildrop_locks_mutex.lock();
    defer maildrop_locks_mutex.unlock();
    if (maildrop_locks == null) maildrop_locks = std.StringHashMap(void).init(std.heap.c_allocator);
    var locks = &maildrop_locks.?;
    if (locks.contains(username)) return false;
    const key = std.heap.c_allocator.dupe(u8, username) catch return false;
    locks.put(key, {}) catch {
        std.heap.c_allocator.free(key);
        return false;
    };
    return true;
}

fn releaseMaildropLock(username: []const u8) void {
    maildrop_locks_mutex.lock();
    defer maildrop_locks_mutex.unlock();
    if (maildrop_locks == null) return;
    if (maildrop_locks.?.fetchRemove(username)) |removed| {
        std.heap.c_allocator.free(removed.key);
    }
}

/// POP3 connection state
pub const Pop3State = enum {
    authorization,
    transaction,
    update,
};

/// POP3 message backed by a real maildir file.
pub const Pop3Message = struct {
    number: usize,
    /// Unique-ID for UIDL — the maildir filename, which is stable per message.
    uid: []const u8,
    /// Full path to the message file on disk (e.g. "mail/chris/new/1772486685658.eml").
    path: []const u8,
    size: usize,
    deleted: bool = false,

    pub fn deinit(self: *Pop3Message, allocator: std.mem.Allocator) void {
        allocator.free(self.uid);
        allocator.free(self.path);
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
            .messages = .empty,
            .auth_backend = auth_backend,
        };
    }

    pub fn deinit(self: *Pop3Session) void {
        // Release the maildrop lock even when the session dies without a
        // clean QUIT (dropped connection) — a leaked lock would block the
        // user's POP3 access until restart.
        self.unlockMaildrop();
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
        var response: std.ArrayList(u8) = .empty;
        defer response.deinit(self.allocator);

        const writer = response.writer(self.allocator);
        try writer.print("+OK {s}\r\n", .{message});

        try self.stream.writeAll(response.items);
    }

    /// Send -ERR response
    pub fn sendErr(self: *Pop3Session, message: []const u8) !void {
        var response: std.ArrayList(u8) = .empty;
        defer response.deinit(self.allocator);

        const writer = response.writer(self.allocator);
        try writer.print("-ERR {s}\r\n", .{message});

        try self.stream.writeAll(response.items);
    }

    /// Send a raw message body as a multi-line response, applying byte-stuffing
    /// per RFC 1939 (lines beginning with '.' get an extra leading '.') and
    /// terminating with the "." octet line. `body` is the raw message bytes;
    /// it is split on CRLF/LF boundaries.
    fn sendMultiLineBody(self: *Pop3Session, body: []const u8) !void {
        var it = std.mem.splitScalar(u8, body, '\n');
        while (it.next()) |raw_line| {
            // Strip a trailing CR so we can re-emit canonical CRLF endings.
            const line = if (raw_line.len > 0 and raw_line[raw_line.len - 1] == '\r')
                raw_line[0 .. raw_line.len - 1]
            else
                raw_line;

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

    /// Clear any pending USER/PASS state (used on auth failure).
    fn clearCredentials(self: *Pop3Session) void {
        if (self.username) |username| {
            self.allocator.free(username);
            self.username = null;
        }
    }

    /// Handle USER command
    fn handleUser(self: *Pop3Session, username: []const u8) !void {
        if (self.state != .authorization) {
            try self.sendErr("Already authenticated");
            return;
        }

        // Replace any previously-supplied username.
        self.clearCredentials();
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
            // Clear USER/PASS so the client must re-send both per RFC 1939.
            self.clearCredentials();
            try self.sendErr("Authentication failed");
            return;
        };

        if (!valid) {
            std.log.warn("Failed POP3 login attempt for user: {s}", .{self.username.?});
            // Clear USER/PASS so the client must re-send both per RFC 1939.
            self.clearCredentials();
            try self.sendErr("Authentication failed");
            return;
        }

        std.log.info("Successful POP3 login for user: {s}", .{self.username.?});

        // Lock maildrop and load messages
        self.lockMaildrop() catch |err| {
            if (err == error.MaildropLocked) {
                // RFC 1939 §3: the maildrop must be locked by exactly one
                // session; tell the second client it's busy.
                try self.sendErr("[IN-USE] maildrop already locked by another session");
                return;
            }
            std.log.err("POP3 failed to open maildrop: {}", .{err});
            try self.sendErr("Unable to open maildrop");
            return;
        };

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

        const content = fs_compat.readFileAlloc(self.allocator, msg.path) catch |err| {
            std.log.warn("POP3 failed to read message {s}: {}", .{ msg.path, err });
            try self.sendErr("Unable to retrieve message");
            return;
        };
        defer self.allocator.free(content);

        const response = try std.fmt.allocPrint(
            self.allocator,
            "{d} octets",
            .{content.len},
        );
        defer self.allocator.free(response);

        try self.sendOk(response);
        try self.sendMultiLineBody(content);
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

        // Mark for deletion; the file is only unlinked on QUIT (UPDATE state),
        // and RSET can undo this within the session, per RFC 1939.
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

    /// Handle TOP command — return the full header block plus the first
    /// `lines` lines of the body (RFC 1939).
    fn handleTop(self: *Pop3Session, msg_number: usize, lines: usize) !void {
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

        const content = fs_compat.readFileAlloc(self.allocator, msg.path) catch |err| {
            std.log.warn("POP3 failed to read message {s}: {}", .{ msg.path, err });
            try self.sendErr("Unable to retrieve message");
            return;
        };
        defer self.allocator.free(content);

        // Locate the header/body boundary (header_end marks the end of the
        // header text; body_start is the first byte of the body).
        var header_end: usize = content.len;
        var body_start: usize = content.len;
        if (std.mem.indexOf(u8, content, "\r\n\r\n")) |pos| {
            header_end = pos + 2;
            body_start = pos + 4;
        } else if (std.mem.indexOf(u8, content, "\n\n")) |pos| {
            header_end = pos + 1;
            body_start = pos + 2;
        }

        // Collect the first `lines` body lines.
        var body_end = body_start;
        var line_count: usize = 0;
        while (line_count < lines and body_end < content.len) {
            if (std.mem.indexOfScalarPos(u8, content, body_end, '\n')) |pos| {
                body_end = pos + 1;
            } else {
                body_end = content.len;
            }
            line_count += 1;
        }

        // Headers (always) plus the selected body lines. When no body lines
        // were requested/available, send just the header block.
        const partial = if (body_end > body_start) content[0..body_end] else content[0..header_end];

        try self.sendOk("Top of message follows");
        try self.sendMultiLineBody(partial);
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

    /// Handle QUIT command — in the UPDATE state, messages marked for deletion
    /// have their underlying maildir files removed from disk.
    fn handleQuit(self: *Pop3Session, config: *const Pop3Config) !void {
        if (self.state == .transaction) {
            self.state = .update;

            if (config.delete_on_quit) {
                var deleted_count: usize = 0;
                for (self.messages.items) |msg| {
                    if (msg.deleted) {
                        fs_compat.cwd().deleteFile(msg.path) catch |err| {
                            std.log.warn("POP3 failed to delete message {s}: {}", .{ msg.path, err });
                            continue;
                        };
                        deleted_count += 1;
                    }
                }

                const response = try std.fmt.allocPrint(
                    self.allocator,
                    "POP3 server signing off ({d} messages deleted)",
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

    /// Lock the maildrop and load messages. Fails with error.MaildropLocked
    /// if another session holds the lock — without it, two concurrent
    /// sessions for the same user could RETR/DELE files the other already
    /// unlinked at QUIT.
    fn lockMaildrop(self: *Pop3Session) !void {
        const username = self.username orelse return error.NotAuthenticated;
        if (!acquireMaildropLock(username)) return error.MaildropLocked;
        errdefer releaseMaildropLock(username);
        try self.loadMessages();
        self.maildrop_locked = true;
    }

    /// Unlock the maildrop
    fn unlockMaildrop(self: *Pop3Session) void {
        if (!self.maildrop_locked) return;
        if (self.username) |username| releaseMaildropLock(username);
        self.maildrop_locked = false;
    }

    /// Load messages from the authenticated user's real maildir.
    /// Scans both `mail/{local}/new` and `mail/{local}/cur` (Maildir layout),
    /// recording each message's full path, on-disk size, and a stable UID
    /// (the maildir filename).
    fn loadMessages(self: *Pop3Session) !void {
        const username = self.username orelse return;

        // Extract local part from the email address (chris@stacksjs.com -> chris).
        const local_part = if (std.mem.indexOfScalar(u8, username, '@')) |at_pos|
            username[0..at_pos]
        else
            username;

        try self.loadMessagesFromDir(local_part, "new");
        try self.loadMessagesFromDir(local_part, "cur");

        // Fallback to the legacy global mail/new if the user has no per-user dir.
        if (self.messages.items.len == 0) {
            try self.loadMessagesFromAbsoluteDir("mail/new");
        }
    }

    fn loadMessagesFromDir(self: *Pop3Session, local_part: []const u8, sub: []const u8) !void {
        const dir_path = try std.fmt.allocPrint(self.allocator, "mail/{s}/{s}", .{ local_part, sub });
        defer self.allocator.free(dir_path);
        try self.loadMessagesFromAbsoluteDir(dir_path);
    }

    fn loadMessagesFromAbsoluteDir(self: *Pop3Session, dir_path: []const u8) !void {
        const files = fs_compat.listEmlFiles(self.allocator, dir_path) catch return;
        defer {
            for (files) |f| self.allocator.free(f);
            self.allocator.free(files);
        }

        for (files) |filename| {
            const path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ dir_path, filename });
            errdefer self.allocator.free(path);

            const size = fs_compat.getFileSize(path) catch 0;

            const uid = try self.allocator.dupe(u8, filename);
            errdefer self.allocator.free(uid);

            try self.messages.append(self.allocator, .{
                .number = self.messages.items.len + 1,
                .uid = uid,
                .path = path,
                .size = @intCast(size),
            });
        }
    }

    /// Process a single command
    pub fn processCommand(self: *Pop3Session, line: []const u8, config: *const Pop3Config) !bool {
        // Split into command verb and the remaining argument string. Splitting
        // only on the first space keeps argument values (notably PASS, which may
        // contain spaces) intact.
        const trimmed = std.mem.trim(u8, line, " \t");
        if (trimmed.len == 0) return true;

        const sp = std.mem.indexOfScalar(u8, trimmed, ' ');
        const cmd_str = if (sp) |i| trimmed[0..i] else trimmed;
        const args = if (sp) |i| std.mem.trimLeft(u8, trimmed[i + 1 ..], " ") else "";

        // Convert command verb to uppercase
        const cmd_upper = try self.allocator.alloc(u8, cmd_str.len);
        defer self.allocator.free(cmd_upper);
        _ = std.ascii.upperString(cmd_upper, cmd_str);

        if (std.mem.eql(u8, cmd_upper, "USER")) {
            if (args.len == 0) {
                try self.sendErr("Missing username");
                return true;
            }
            try self.handleUser(args);
        } else if (std.mem.eql(u8, cmd_upper, "PASS")) {
            // PASS argument is the rest of the line verbatim (passwords may
            // legitimately contain spaces).
            if (args.len == 0) {
                try self.sendErr("Missing password");
                return true;
            }
            try self.handlePass(args);
        } else if (std.mem.eql(u8, cmd_upper, "STAT")) {
            try self.handleStat();
        } else if (std.mem.eql(u8, cmd_upper, "LIST")) {
            const msg_num = if (args.len > 0)
                (std.fmt.parseInt(usize, args, 10) catch null)
            else
                null;
            try self.handleList(msg_num);
        } else if (std.mem.eql(u8, cmd_upper, "RETR")) {
            const msg_num = std.fmt.parseInt(usize, args, 10) catch {
                try self.sendErr("Invalid message number");
                return true;
            };
            try self.handleRetr(msg_num);
        } else if (std.mem.eql(u8, cmd_upper, "DELE")) {
            const msg_num = std.fmt.parseInt(usize, args, 10) catch {
                try self.sendErr("Invalid message number");
                return true;
            };
            try self.handleDele(msg_num);
        } else if (std.mem.eql(u8, cmd_upper, "RSET")) {
            try self.handleRset();
        } else if (std.mem.eql(u8, cmd_upper, "NOOP")) {
            try self.handleNoop();
        } else if (std.mem.eql(u8, cmd_upper, "TOP")) {
            // TOP <msg> <lines>
            var top_parts = std.mem.splitScalar(u8, args, ' ');
            const msg_num_str = top_parts.next() orelse "";
            const lines_str = top_parts.next() orelse "";
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
            const msg_num = if (args.len > 0)
                (std.fmt.parseInt(usize, args, 10) catch null)
            else
                null;
            try self.handleUidl(msg_num);
        } else if (std.mem.eql(u8, cmd_upper, "CAPA")) {
            try self.handleCapa();
        } else if (std.mem.eql(u8, cmd_upper, "QUIT")) {
            try self.handleQuit(config);
            return false; // Stop processing
        } else {
            try self.sendErr("Unknown command");
        }

        return true; // Continue processing
    }

    /// Handle CAPA command — only advertise capabilities that are implemented.
    /// Notably we do NOT advertise SASL/APOP/STLS since they are not supported.
    fn handleCapa(self: *Pop3Session) !void {
        try self.sendOk("Capability list follows");
        const caps = [_][]const u8{
            "TOP",
            "USER",
            "UIDL",
        };
        for (caps) |cap| {
            try self.stream.writeAll(cap);
            try self.stream.writeAll("\r\n");
        }
        try self.stream.writeAll(".\r\n");
    }
};

/// POP3 server
pub const Pop3Server = struct {
    allocator: std.mem.Allocator,
    config: Pop3Config,
    listener: ?std.net.Server = null,
    running: std.atomic.Value(bool),
    mutex: mutex_compat.Mutex = .{},
    auth_backend: *auth.AuthBackend,

    pub fn init(allocator: std.mem.Allocator, config: Pop3Config, auth_backend: *auth.AuthBackend) Pop3Server {
        return .{
            .allocator = allocator,
            .config = config,
            .running = std.atomic.Value(bool).init(false),
            .auth_backend = auth_backend,
        };
    }

    pub fn deinit(self: *Pop3Server) void {
        self.stop();
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
                logger.warn("POP3 accept error: {}", .{err});
                continue;
            };

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

        // Line-buffered command processing. POP3 commands are CRLF-terminated;
        // we accumulate bytes until a full line is available so commands are
        // never split or merged across TCP reads.
        var line_buf: std.ArrayList(u8) = .empty;
        defer line_buf.deinit(self.allocator);

        var read_buf: [4096]u8 = undefined;
        outer: while (true) {
            const bytes_read = stream.read(&read_buf) catch break;
            if (bytes_read == 0) break;

            try line_buf.appendSlice(self.allocator, read_buf[0..bytes_read]);

            // Extract and process every complete line currently buffered.
            while (std.mem.indexOfScalar(u8, line_buf.items, '\n')) |nl| {
                const raw_line = line_buf.items[0..nl];
                const line = std.mem.trimRight(u8, raw_line, "\r");

                const continue_processing = session.processCommand(line, &self.config) catch |err| {
                    logger.err("POP3 command processing error: {}", .{err});
                    break :outer;
                };

                // Drop the consumed line (including the '\n') from the buffer.
                const remaining = line_buf.items.len - (nl + 1);
                std.mem.copyForwards(u8, line_buf.items[0..remaining], line_buf.items[nl + 1 ..]);
                line_buf.shrinkRetainingCapacity(remaining);

                if (!continue_processing) break :outer;
            }

            // Guard against unbounded buffering of a never-terminated line.
            if (line_buf.items.len > self.config.max_message_size) break;
        }
    }
};

// TODO(STLS): RFC 2595 STLS (in-band TLS upgrade) is not implemented. The
// session currently operates over a raw std.net.Stream, whereas the TLS stack
// (src/core/tls.zig + the zig-tls dependency) is integrated through the IMAP
// connection wrapper. Implementing STLS would require routing POP3 I/O through
// that same abstraction so the plaintext socket can be upgraded mid-session.
// Until then, encrypted access is only offered via implicit POP3S on the
// dedicated SSL port, and STLS is intentionally NOT advertised in CAPA.

// Tests
test "POP3 message" {
    const testing = std.testing;

    const uid = try testing.allocator.dupe(u8, "msg-123");
    const path = try testing.allocator.dupe(u8, "mail/test/new/msg-123.eml");
    var msg = Pop3Message{
        .number = 1,
        .uid = uid,
        .path = path,
        .size = 1024,
    };
    defer msg.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), msg.number);
    try testing.expectEqual(@as(usize, 1024), msg.size);
    try testing.expect(!msg.deleted);
}
