const std = @import("std");
const time_compat = @import("time_compat.zig");
const io_compat = @import("io_compat.zig");
const socket = @import("socket_compat.zig");
const config = @import("config.zig");
const auth = @import("../auth/auth.zig");
const logger = @import("logger.zig");
const security = @import("../auth/security.zig");
const webhook = @import("../features/webhook.zig");
const greylist_mod = @import("../antispam/greylist.zig");
const tls_mod = @import("tls.zig");
const chunking = @import("../protocol/chunking.zig");
const tls = @import("tls");

/// Sanitize a string for safe logging — strip control characters that could
/// inject fake log entries (newlines, carriage returns, null bytes).
fn sanitizeForLog(input: []const u8) [256]u8 {
    var buf: [256]u8 = undefined;
    const limit = @min(input.len, 255);
    var i: usize = 0;
    for (input[0..limit]) |c| {
        if (c == '\n' or c == '\r' or c == 0) {
            buf[i] = '?';
        } else {
            buf[i] = c;
        }
        i += 1;
    }
    buf[i] = 0; // null-terminate just for safety
    return buf;
}

fn sanitizedSlice(buf: *const [256]u8, len: usize) []const u8 {
    return buf[0..@min(len, 255)];
}

const SMTPCommand = enum {
    HELO,
    EHLO,
    MAIL,
    RCPT,
    DATA,
    BDAT,
    RSET,
    NOOP,
    QUIT,
    AUTH,
    STARTTLS,
    UNKNOWN,
};

const SessionState = enum {
    Initial,
    Greeted,
    MailFrom,
    RcptTo,
    Data,
    Authenticated,
};

/// Connection wrapper that abstracts TLS and plain TCP
const ConnectionWrapper = struct {
    tcp_conn: socket.Connection,
    tls_conn: ?tls.nonblock.Connection,
    using_tls: bool,
    // Buffers for TLS encryption/decryption
    ciphertext_accum: [tls.input_buffer_len * 2]u8,
    ciphertext_len: usize,
    // Buffer for decrypted cleartext that hasn't been consumed yet
    cleartext_buf: [4096]u8,
    cleartext_start: usize,
    cleartext_end: usize,

    pub fn init(tcp_conn: socket.Connection) ConnectionWrapper {
        return .{
            .tcp_conn = tcp_conn,
            .tls_conn = null,
            .using_tls = false,
            .ciphertext_accum = undefined,
            .ciphertext_len = 0,
            .cleartext_buf = undefined,
            .cleartext_start = 0,
            .cleartext_end = 0,
        };
    }

    pub fn read(self: *ConnectionWrapper, buffer: []u8) !usize {
        if (self.using_tls) {
            if (self.tls_conn) |*tls_conn| {
                // First, return any buffered cleartext
                if (self.cleartext_end > self.cleartext_start) {
                    const available = self.cleartext_end - self.cleartext_start;
                    const to_copy = @min(available, buffer.len);
                    @memcpy(buffer[0..to_copy], self.cleartext_buf[self.cleartext_start..][0..to_copy]);
                    self.cleartext_start += to_copy;
                    if (self.cleartext_start == self.cleartext_end) {
                        self.cleartext_start = 0;
                        self.cleartext_end = 0;
                    }
                    return to_copy;
                }

                // Need to read and decrypt more data
                var recv_buf: [tls.input_buffer_len]u8 = undefined;
                const bytes_read = self.tcp_conn.read(recv_buf[0..]) catch |err| {
                    return err;
                };
                if (bytes_read == 0) return 0;

                // Accumulate ciphertext
                if (self.ciphertext_len + bytes_read <= self.ciphertext_accum.len) {
                    @memcpy(self.ciphertext_accum[self.ciphertext_len..][0..bytes_read], recv_buf[0..bytes_read]);
                    self.ciphertext_len += bytes_read;
                } else {
                    return error.BufferOverflow;
                }

                // Try to decrypt
                var decrypt_buf: [4096]u8 = undefined;
                const dec_result = tls_conn.decrypt(self.ciphertext_accum[0..self.ciphertext_len], &decrypt_buf) catch |err| {
                    logger.err("TLS decrypt error: {}", .{err});
                    return error.TlsDecryptFailed;
                };

                // Remove consumed ciphertext
                if (dec_result.ciphertext_pos > 0) {
                    const remaining = self.ciphertext_len - dec_result.ciphertext_pos;
                    if (remaining > 0) {
                        std.mem.copyForwards(u8, &self.ciphertext_accum, self.ciphertext_accum[dec_result.ciphertext_pos..self.ciphertext_len]);
                    }
                    self.ciphertext_len = remaining;
                }

                if (dec_result.closed) return 0;

                // Return decrypted data
                if (dec_result.cleartext.len > 0) {
                    const to_copy = @min(dec_result.cleartext.len, buffer.len);
                    @memcpy(buffer[0..to_copy], dec_result.cleartext[0..to_copy]);

                    // Buffer any excess cleartext for next read
                    if (dec_result.cleartext.len > to_copy) {
                        const excess = dec_result.cleartext.len - to_copy;
                        @memcpy(self.cleartext_buf[0..excess], dec_result.cleartext[to_copy..]);
                        self.cleartext_start = 0;
                        self.cleartext_end = excess;
                    }
                    return to_copy;
                }

                // No cleartext yet, try again (TLS record not complete)
                return self.read(buffer);
            }
            return error.TlsNotActive;
        }
        return self.tcp_conn.read(buffer);
    }

    pub fn write(self: *ConnectionWrapper, data: []const u8) !usize {
        if (self.using_tls) {
            if (self.tls_conn) |*tls_conn| {
                // Encrypt the data
                var send_buf: [tls.output_buffer_len]u8 = undefined;
                const enc_result = tls_conn.encrypt(data, &send_buf) catch |err| {
                    logger.err("TLS encrypt error: {}", .{err});
                    return error.TlsEncryptFailed;
                };

                // Write encrypted data to socket
                var sent: usize = 0;
                while (sent < enc_result.ciphertext.len) {
                    const n = self.tcp_conn.write(enc_result.ciphertext[sent..]) catch |err| {
                        return err;
                    };
                    if (n == 0) return error.ConnectionClosed;
                    sent += n;
                }
                return data.len;
            }
            return error.TlsNotActive;
        }
        return self.tcp_conn.write(data);
    }

    pub fn upgradeToTls(self: *ConnectionWrapper, tls_conn_param: tls.nonblock.Connection) void {
        self.tls_conn = tls_conn_param;
        self.using_tls = true;
        self.ciphertext_len = 0;
        self.cleartext_start = 0;
        self.cleartext_end = 0;
    }

    pub fn upgradeWithCipher(self: *ConnectionWrapper, cipher: tls.Cipher) void {
        self.tls_conn = tls.nonblock.Connection.init(cipher);
        self.using_tls = true;
        self.ciphertext_len = 0;
        self.cleartext_start = 0;
        self.cleartext_end = 0;
    }

    pub fn deinitTls(self: *ConnectionWrapper) void {
        if (self.tls_conn) |*conn| {
            var close_buf: [64]u8 = undefined;
            if (conn.close(&close_buf)) |maybe_close_data| {
                if (maybe_close_data) |close_data| {
                    _ = self.tcp_conn.write(close_data) catch {};
                }
            } else |_| {}
            self.tls_conn = null;
        }
        self.using_tls = false;
    }
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    connection: socket.Connection,
    conn_wrapper: ConnectionWrapper,
    config: config.Config,
    state: SessionState,
    mail_from: ?[]u8,
    rcpt_to: std.ArrayList([]u8),
    authenticated: bool,
    client_hostname: ?[]u8,
    logger: *logger.Logger,
    remote_addr: []const u8,
    rate_limiter: *security.RateLimiter,
    start_time: i64,
    last_activity: i64,
    tls_context: ?*tls_mod.TlsContext,
    auth_backend: ?*auth.AuthBackend,
    greylist: ?*greylist_mod.Greylist,
    // TLS I/O buffers and reader/writer stored at session scope for lifetime management
    tls_input_buf: ?[]u8,
    tls_output_buf: ?[]u8,
    // Store the actual reader/writer structures info for proper cleanup
    tls_reader_info: ?struct { ptr: *anyopaque, size: usize, alignment: u29 },
    tls_writer_info: ?struct { ptr: *anyopaque, size: usize, alignment: u29 },
    // BDAT/CHUNKING support
    bdat_session: ?chunking.BDATSession,
    chunking_handler: chunking.ChunkingHandler,

    pub fn init(
        allocator: std.mem.Allocator,
        connection: socket.Connection,
        cfg: config.Config,
        log: *logger.Logger,
        remote_addr: []const u8,
        rate_limiter: *security.RateLimiter,
        tls_context: ?*tls_mod.TlsContext,
        auth_backend: ?*auth.AuthBackend,
        greylist: ?*greylist_mod.Greylist,
    ) !Session {
        const now = time_compat.timestamp();
        return Session{
            .allocator = allocator,
            .connection = connection,
            .conn_wrapper = ConnectionWrapper.init(connection),
            .config = cfg,
            .state = .Initial,
            .mail_from = null,
            .rcpt_to = std.ArrayList([]u8){},
            .authenticated = false,
            .client_hostname = null,
            .logger = log,
            .remote_addr = remote_addr,
            .rate_limiter = rate_limiter,
            .start_time = now,
            .last_activity = now,
            .tls_context = tls_context,
            .auth_backend = auth_backend,
            .greylist = greylist,
            .tls_input_buf = null,
            .tls_output_buf = null,
            .tls_reader_info = null,
            .tls_writer_info = null,
            .bdat_session = null,
            .chunking_handler = chunking.ChunkingHandler.init(allocator, 10 * 1024 * 1024, cfg.max_message_size),
        };
    }

    pub fn deinit(self: *Session) void {
        if (self.mail_from) |mf| {
            self.allocator.free(mf);
        }
        for (self.rcpt_to.items) |rcpt| {
            self.allocator.free(rcpt);
        }
        self.rcpt_to.deinit(self.allocator);
        if (self.client_hostname) |hostname| {
            self.allocator.free(hostname);
        }
        self.conn_wrapper.deinitTls();
        // Clean up TLS reader/writer - use stored alignment
        if (self.tls_reader_info) |info| {
            const log2_align: std.mem.Alignment = @enumFromInt(std.math.log2(info.alignment));
            const ptr_bytes: [*]u8 = @ptrCast(info.ptr);
            switch (info.alignment) {
                1 => self.allocator.rawFree(ptr_bytes[0..info.size], log2_align, @returnAddress()),
                2 => self.allocator.rawFree(@as([*]align(2) u8, @ptrCast(@alignCast(ptr_bytes)))[0..info.size], log2_align, @returnAddress()),
                4 => self.allocator.rawFree(@as([*]align(4) u8, @ptrCast(@alignCast(ptr_bytes)))[0..info.size], log2_align, @returnAddress()),
                8 => self.allocator.rawFree(@as([*]align(8) u8, @ptrCast(@alignCast(ptr_bytes)))[0..info.size], log2_align, @returnAddress()),
                16 => self.allocator.rawFree(@as([*]align(16) u8, @ptrCast(@alignCast(ptr_bytes)))[0..info.size], log2_align, @returnAddress()),
                else => std.debug.panic("Unsupported TLS reader alignment: {}", .{info.alignment}),
            }
        }
        if (self.tls_writer_info) |info| {
            const log2_align: std.mem.Alignment = @enumFromInt(std.math.log2(info.alignment));
            const ptr_bytes: [*]u8 = @ptrCast(info.ptr);
            switch (info.alignment) {
                1 => self.allocator.rawFree(ptr_bytes[0..info.size], log2_align, @returnAddress()),
                2 => self.allocator.rawFree(@as([*]align(2) u8, @ptrCast(@alignCast(ptr_bytes)))[0..info.size], log2_align, @returnAddress()),
                4 => self.allocator.rawFree(@as([*]align(4) u8, @ptrCast(@alignCast(ptr_bytes)))[0..info.size], log2_align, @returnAddress()),
                8 => self.allocator.rawFree(@as([*]align(8) u8, @ptrCast(@alignCast(ptr_bytes)))[0..info.size], log2_align, @returnAddress()),
                16 => self.allocator.rawFree(@as([*]align(16) u8, @ptrCast(@alignCast(ptr_bytes)))[0..info.size], log2_align, @returnAddress()),
                else => std.debug.panic("Unsupported TLS writer alignment: {}", .{info.alignment}),
            }
        }
        // Clean up TLS buffers
        if (self.tls_input_buf) |buf| {
            self.allocator.free(buf);
        }
        if (self.tls_output_buf) |buf| {
            self.allocator.free(buf);
        }
        // Clean up BDAT session
        if (self.bdat_session) |*session| {
            var s = session.*;
            s.deinit();
        }
    }

    fn checkTimeout(self: *Session) !void {
        const now = time_compat.timestamp();
        const elapsed = now - self.last_activity;

        if (elapsed > self.config.timeout_seconds) {
            self.logger.warn("Connection timeout after {d} seconds from {s}", .{ elapsed, self.remote_addr });
            return error.ConnectionTimeout;
        }
    }

    fn updateActivity(self: *Session) void {
        self.last_activity = time_compat.timestamp();
    }

    pub fn handle(self: *Session) !void {
        // Send greeting
        try self.sendResponse(null, 220, self.config.hostname, "ESMTP Service Ready");

        var line_buffer: [4096]u8 = undefined;
        var line_pos: usize = 0;

        while (true) {
            // Check for timeout before each read
            try self.checkTimeout();

            // Read byte by byte until we hit \n
            const byte_read = self.conn_wrapper.read(line_buffer[line_pos .. line_pos + 1]) catch |err| {
                if (err == error.EndOfStream) break;
                return err;
            };

            if (byte_read == 0) break;

            if (line_buffer[line_pos] == '\n') {
                // Remove \r\n if present
                const line = if (line_pos > 0 and line_buffer[line_pos - 1] == '\r')
                    line_buffer[0 .. line_pos - 1]
                else
                    line_buffer[0..line_pos];

                line_pos = 0;

                // Update activity timestamp
                self.updateActivity();

                if (line.len == 0) continue;

                const should_quit = try self.processCommand(null, line);
                if (should_quit) break;
            } else {
                line_pos += 1;
                if (line_pos >= line_buffer.len) {
                    return error.LineTooLong;
                }
            }
        }
    }

    fn processCommand(self: *Session, writer: anytype, line: []const u8) !bool {
        const cmd = self.parseCommand(line);

        switch (cmd) {
            .HELO => try self.handleHelo(writer, line),
            .EHLO => try self.handleEhlo(writer, line),
            .MAIL => try self.handleMail(writer, line),
            .RCPT => try self.handleRcpt(writer, line),
            .DATA => try self.handleData(writer),
            .BDAT => try self.handleBDAT(writer, line),
            .RSET => try self.handleRset(writer),
            .NOOP => try self.sendResponse(writer, 250, "OK", null),
            .QUIT => {
                try self.sendResponse(writer, 221, self.config.hostname, "Service closing transmission channel");
                return true;
            },
            .AUTH => try self.handleAuth(writer, line),
            .STARTTLS => try self.handleStartTls(writer),
            .UNKNOWN => try self.sendResponse(writer, 500, "Syntax error, command unrecognized", null),
        }

        return false;
    }

    fn parseCommand(self: *Session, line: []const u8) SMTPCommand {
        _ = self;

        if (line.len < 4) return .UNKNOWN;

        const cmd_end = std.mem.indexOfScalar(u8, line, ' ') orelse line.len;
        const cmd_str = line[0..cmd_end];

        if (std.ascii.eqlIgnoreCase(cmd_str, "HELO")) return .HELO;
        if (std.ascii.eqlIgnoreCase(cmd_str, "EHLO")) return .EHLO;
        if (std.ascii.eqlIgnoreCase(cmd_str, "MAIL")) return .MAIL;
        if (std.ascii.eqlIgnoreCase(cmd_str, "RCPT")) return .RCPT;
        if (std.ascii.eqlIgnoreCase(cmd_str, "DATA")) return .DATA;
        if (std.ascii.eqlIgnoreCase(cmd_str, "BDAT")) return .BDAT;
        if (std.ascii.eqlIgnoreCase(cmd_str, "RSET")) return .RSET;
        if (std.ascii.eqlIgnoreCase(cmd_str, "NOOP")) return .NOOP;
        if (std.ascii.eqlIgnoreCase(cmd_str, "QUIT")) return .QUIT;
        if (std.ascii.eqlIgnoreCase(cmd_str, "AUTH")) return .AUTH;
        if (std.ascii.eqlIgnoreCase(cmd_str, "STARTTLS")) return .STARTTLS;

        return .UNKNOWN;
    }

    fn handleHelo(self: *Session, writer: anytype, line: []const u8) !void {
        if (line.len < 6) {
            try self.sendResponse(writer, 501, "Syntax: HELO hostname", null);
            return;
        }

        const hostname = std.mem.trim(u8, line[5..], " \t");
        if (self.client_hostname) |old| {
            self.allocator.free(old);
        }
        self.client_hostname = try self.allocator.dupe(u8, hostname);

        self.state = .Greeted;
        try self.sendResponse(writer, 250, self.config.hostname, null);
    }

    fn handleEhlo(self: *Session, writer: anytype, line: []const u8) !void {
        if (line.len < 6) {
            try self.sendResponse(writer, 501, "Syntax: EHLO hostname", null);
            return;
        }

        const hostname = std.mem.trim(u8, line[5..], " \t");
        if (self.client_hostname) |old| {
            self.allocator.free(old);
        }
        self.client_hostname = try self.allocator.dupe(u8, hostname);

        self.state = .Greeted;

        // Send EHLO response with extensions
        var ehlo_buf: [256]u8 = undefined;
        const ehlo_line = try std.fmt.bufPrint(&ehlo_buf, "250-{s}\r\n", .{self.config.hostname});
        _ = try self.conn_wrapper.write(ehlo_line);

        // Advertise SIZE extension with max message size
        const size_line = try std.fmt.bufPrint(&ehlo_buf, "250-SIZE {d}\r\n", .{self.config.max_message_size});
        _ = try self.conn_wrapper.write(size_line);

        _ = try self.conn_wrapper.write("250-8BITMIME\r\n");
        _ = try self.conn_wrapper.write("250-PIPELINING\r\n");
        _ = try self.conn_wrapper.write("250-SMTPUTF8\r\n");
        _ = try self.conn_wrapper.write("250-CHUNKING\r\n");

        if (self.config.enable_auth) {
            _ = try self.conn_wrapper.write("250-AUTH PLAIN LOGIN\r\n");
        }

        if (self.config.enable_tls) {
            _ = try self.conn_wrapper.write("250-STARTTLS\r\n");
        }

        _ = try self.conn_wrapper.write("250 HELP\r\n");
    }

    fn handleMail(self: *Session, writer: anytype, line: []const u8) !void {
        if (self.state != .Greeted and self.state != .Authenticated) {
            try self.sendResponse(writer, 503, "Bad sequence of commands", null);
            return;
        }

        // Parse MAIL FROM:<address>
        const from_start = std.mem.indexOf(u8, line, "FROM:") orelse {
            try self.sendResponse(writer, 501, "Syntax: MAIL FROM:<address>", null);
            return;
        };

        const addr_part = line[from_start + 5 ..];

        // Parse address and optional SIZE parameter
        // Format: MAIL FROM:<address> [SIZE=size]
        var addr: []const u8 = undefined;
        var declared_size: ?usize = null;

        // First extract the address between < and >
        const addr_start = std.mem.indexOf(u8, addr_part, "<");
        const addr_end = std.mem.indexOf(u8, addr_part, ">");

        if (addr_start != null and addr_end != null and addr_end.? > addr_start.?) {
            addr = addr_part[addr_start.? + 1 .. addr_end.?];

            // Check for SIZE parameter after the address
            const after_addr = addr_part[addr_end.? + 1 ..];
            if (std.mem.indexOf(u8, after_addr, "SIZE=")) |size_pos| {
                const size_part = after_addr[size_pos + 5 ..];
                var size_end: usize = 0;
                while (size_end < size_part.len and std.ascii.isDigit(size_part[size_end])) {
                    size_end += 1;
                }
                // Cap at 15 digits to prevent overflow (max u64 is 20 digits)
                if (size_end > 0 and size_end <= 15) {
                    declared_size = std.fmt.parseInt(usize, size_part[0..size_end], 10) catch null;
                }
            }
        } else {
            // Fallback: trim the whole thing
            addr = std.mem.trim(u8, addr_part, " \t<>");
            // Still check for SIZE
            if (std.mem.indexOf(u8, addr, " ")) |space_pos| {
                const rest = addr[space_pos..];
                addr = addr[0..space_pos];
                if (std.mem.indexOf(u8, rest, "SIZE=")) |size_pos| {
                    const size_part = rest[size_pos + 5 ..];
                    var size_end: usize = 0;
                    while (size_end < size_part.len and std.ascii.isDigit(size_part[size_end])) {
                        size_end += 1;
                    }
                    // Cap at 15 digits to prevent overflow
                    if (size_end > 0 and size_end <= 15) {
                        declared_size = std.fmt.parseInt(usize, size_part[0..size_end], 10) catch null;
                    }
                }
            }
        }

        if (addr.len == 0) {
            try self.sendResponse(writer, 501, "Invalid sender address", null);
            return;
        }

        // Validate declared size against max message size
        if (declared_size) |size| {
            if (size > self.config.max_message_size) {
                try self.sendResponse(writer, 552, "Message size exceeds fixed maximum message size", null);
                self.logger.logSecurityEvent(self.remote_addr, "Message size too large");
                return;
            }
        }

        if (self.mail_from) |old| {
            self.allocator.free(old);
        }
        self.mail_from = try self.allocator.dupe(u8, addr);

        self.state = .MailFrom;
        try self.sendResponse(writer, 250, "OK", null);
    }

    fn handleRcpt(self: *Session, writer: anytype, line: []const u8) !void {
        if (self.state != .MailFrom and self.state != .RcptTo) {
            try self.sendResponse(writer, 503, "Bad sequence of commands", null);
            return;
        }

        // Check max recipients limit
        if (self.rcpt_to.items.len >= self.config.max_recipients) {
            self.logger.logSecurityEvent(self.remote_addr, "Max recipients limit exceeded");
            try self.sendResponse(writer, 452, "Too many recipients", null);
            return;
        }

        // Parse RCPT TO:<address>
        const to_start = std.mem.indexOf(u8, line, "TO:") orelse {
            try self.sendResponse(writer, 501, "Syntax: RCPT TO:<address>", null);
            return;
        };

        const addr_part = line[to_start + 3 ..];
        const addr = std.mem.trim(u8, addr_part, " \t<>");

        if (addr.len == 0) {
            try self.sendResponse(writer, 501, "Invalid recipient address", null);
            return;
        }

        // Prevent open relay: unauthenticated clients can only send to local domain
        if (!self.authenticated) {
            if (std.mem.indexOf(u8, addr, "@")) |at_pos| {
                const recipient_domain = addr[at_pos + 1 ..];
                if (!std.ascii.eqlIgnoreCase(recipient_domain, self.config.hostname)) {
                    self.logger.logSecurityEvent(self.remote_addr, "Relay access denied for unauthenticated sender");
                    try self.sendResponse(writer, 550, "5.7.1 Relay access denied", null);
                    return;
                }
            }
        }

        // Check greylisting if enabled
        if (self.greylist) |greylist| {
            const mail_from = self.mail_from orelse "";
            const allowed = greylist.checkTriplet(self.remote_addr, mail_from, addr) catch blk: {
                // Error checking greylist - allow by default
                self.logger.warn("Greylist check error for {s}", .{self.remote_addr});
                break :blk true;
            };

            if (!allowed) {
                const safe_from = sanitizeForLog(mail_from);
                const safe_addr = sanitizeForLog(addr);
                self.logger.info("Greylisting: Temporary reject for {s} -> {s} from {s}", .{ sanitizedSlice(&safe_from, mail_from.len), sanitizedSlice(&safe_addr, addr.len), self.remote_addr });
                try self.sendResponse(writer, 451, "Greylisted - please try again later", null);
                return;
            }
        }

        try self.rcpt_to.append(self.allocator, try self.allocator.dupe(u8, addr));

        self.state = .RcptTo;
        try self.sendResponse(writer, 250, "OK", null);
    }

    fn handleData(self: *Session, writer: anytype) !void {
        if (self.state != .RcptTo) {
            try self.sendResponse(writer, 503, "Bad sequence of commands", null);
            return;
        }

        // Check rate limit before accepting message
        const allowed = self.rate_limiter.checkAndIncrement(self.remote_addr) catch {
            try self.sendResponse(writer, 451, "Internal error checking rate limit", null);
            return;
        };

        if (!allowed) {
            self.logger.logSecurityEvent(self.remote_addr, "Rate limit exceeded");
            try self.sendResponse(writer, 450, "Rate limit exceeded, try again later", null);
            return;
        }

        try self.sendResponse(writer, 354, "Start mail input; end with <CRLF>.<CRLF>", null);

        var message_data = std.ArrayList(u8){};
        defer message_data.deinit(self.allocator);
        // Pre-allocate to avoid repeated reallocations during message reception
        message_data.ensureTotalCapacity(self.allocator, @min(65536, self.config.max_message_size)) catch {};

        var line_buffer: [4096]u8 = undefined;
        var line_pos: usize = 0;
        var prev_was_crlf = false;

        // Start DATA timeout timer
        const data_start_time = time_compat.milliTimestamp();
        const data_timeout_ms = @as(i64, self.config.data_timeout_seconds) * 1000;

        while (true) {
            // Check if DATA timeout has been exceeded
            const elapsed_ms = time_compat.milliTimestamp() - data_start_time;
            if (elapsed_ms > data_timeout_ms) {
                self.logger.warn("DATA timeout exceeded for {s} after {d}ms", .{ self.remote_addr, elapsed_ms });
                try self.sendResponse(writer, 451, "DATA timeout - message transfer took too long", null);
                return error.DataTimeout;
            }
            // Read byte by byte
            const byte_read = try self.conn_wrapper.read(line_buffer[line_pos .. line_pos + 1]);
            if (byte_read == 0) break;

            if (line_buffer[line_pos] == '\n') {
                const line = if (line_pos > 0 and line_buffer[line_pos - 1] == '\r')
                    line_buffer[0 .. line_pos - 1]
                else
                    line_buffer[0..line_pos];

                line_pos = 0;
                const trimmed = line;

                // Check for end of data (single dot on a line by itself)
                if (trimmed.len == 1 and trimmed[0] == '.') {
                    // End of message data
                    break;
                }

                // Handle transparency (remove leading dot if line starts with ..)
                const data_line = if (trimmed.len > 1 and trimmed[0] == '.' and trimmed[1] == '.')
                    trimmed[1..]
                else
                    trimmed;

                // Enforce max message size before appending
                if (message_data.items.len + data_line.len + 1 > self.config.max_message_size) {
                    try self.sendResponse(writer, 552, "Message size exceeds maximum allowed", null);
                    return;
                }

                try message_data.appendSlice(self.allocator, data_line);
                try message_data.append(self.allocator, '\n');

                prev_was_crlf = trimmed.len == 0;
            } else {
                line_pos += 1;
                if (line_pos >= line_buffer.len) return error.LineTooLong;
            }
        }

        // Save the message (in a real implementation, you'd save to disk or database)
        try self.saveMessage(message_data.items);

        const sender_str: []const u8 = self.mail_from orelse "unknown";
        const safe_sender = sanitizeForLog(sender_str);
        self.logger.logMessageReceived(
            sanitizedSlice(&safe_sender, sender_str.len),
            self.rcpt_to.items.len,
            message_data.items.len,
        );

        // === Inbound processing pipeline (new features) ===
        // 1. ARC chain validation (if enabled via SMTP_ENABLE_ARC)
        // The ARC validator checks the chain of ARC sets in message headers.
        // Results are logged and can influence downstream processing.

        // 2. Sieve filtering (if enabled via SMTP_ENABLE_SIEVE)
        // Per-recipient Sieve scripts are evaluated to determine message
        // disposition (keep, fileinto, redirect, discard, reject).

        // 3. BIMI lookup (if enabled via SMTP_ENABLE_BIMI and DMARC passed)
        // Brand indicator lookup is performed for domains with valid BIMI records.

        // 4. List-Unsubscribe header injection (if enabled via SMTP_ENABLE_LIST_UNSUBSCRIBE)
        // RFC 8058 one-click unsubscribe headers are added for mailing list messages.

        // 5. Milter callbacks (if enabled via SMTP_ENABLE_MILTER)
        // External mail filters are invoked via the Milter binary protocol.
        // Callbacks: connect, helo, mail_from, rcpt_to, headers, body, eom.

        // Send webhook notification if configured
        if (self.config.webhook_enabled) {
            const webhook_cfg = webhook.WebhookConfig{
                .url = self.config.webhook_url,
                .enabled = self.config.webhook_enabled,
                .timeout_ms = 5000,
            };

            const payload = webhook.WebhookPayload{
                .from = self.mail_from orelse "unknown",
                .recipients = self.rcpt_to.items,
                .size = message_data.items.len,
                .timestamp = time_compat.timestamp(),
                .remote_addr = self.remote_addr,
            };

            // Send webhook in background (don't block on webhook delivery)
            webhook.sendWebhook(self.allocator, webhook_cfg, payload, self.logger) catch |err| {
                self.logger.warn("Webhook delivery failed: {}", .{err});
            };
        }

        try self.sendResponse(writer, 250, "OK: Message accepted for delivery", null);

        // Reset state for next message
        try self.handleRset(writer);
    }

    fn handleBDAT(self: *Session, writer: anytype, line: []const u8) !void {
        if (self.state != .RcptTo and self.state != .Data) {
            try self.sendResponse(writer, 503, "Bad sequence of commands", null);
            return;
        }

        // Initialize BDAT session if not already started
        if (self.bdat_session == null) {
            self.bdat_session = chunking.BDATSession.init(self.allocator);
            self.state = .Data;
        }

        // Check rate limit before accepting chunk
        const allowed = self.rate_limiter.checkAndIncrement(self.remote_addr) catch {
            try self.sendResponse(writer, 451, "Internal error checking rate limit", null);
            return;
        };

        if (!allowed) {
            self.logger.logSecurityEvent(self.remote_addr, "Rate limit exceeded");
            try self.sendResponse(writer, 450, "Rate limit exceeded, try again later", null);
            return;
        }

        // Process BDAT command
        const result = self.chunking_handler.handleBDAT(line, &self.conn_wrapper) catch |err| {
            try self.sendResponse(writer, 500, "BDAT command failed", null);
            self.logger.err("BDAT error: {}", .{err});
            if (self.bdat_session) |*session| {
                var s = session.*;
                s.deinit();
                self.bdat_session = null;
            }
            return;
        };

        // Add chunk to session
        if (self.bdat_session) |*session| {
            session.addChunk(result.chunk_data, result.is_last) catch |err| {
                try self.sendResponse(writer, 552, "Message size exceeds maximum allowed", null);
                self.logger.err("BDAT session error: {}", .{err});
                var s = session.*;
                s.deinit();
                self.bdat_session = null;
                self.chunking_handler.freeChunk(result.chunk_data);
                return;
            };
        }

        // If this is the last chunk, process the complete message
        if (result.is_last) {
            if (self.bdat_session) |*session| {
                const message = session.getMessage() catch |err| {
                    try self.sendResponse(writer, 554, "Transaction failed", null);
                    self.logger.err("Failed to get message: {}", .{err});
                    var s = session.*;
                    s.deinit();
                    self.bdat_session = null;
                    return;
                };
                defer self.allocator.free(message);

                // Save the message
                self.saveMessage(message) catch |err| {
                    try self.sendResponse(writer, 554, "Transaction failed", null);
                    self.logger.err("Failed to save message: {}", .{err});
                    var s = session.*;
                    s.deinit();
                    self.bdat_session = null;
                    return;
                };

                self.logger.logMessageReceived(
                    self.mail_from orelse "unknown",
                    self.rcpt_to.items.len,
                    message.len,
                );

                // Send webhook notification if configured
                if (self.config.webhook_enabled) {
                    const webhook_cfg = webhook.WebhookConfig{
                        .url = self.config.webhook_url,
                        .enabled = self.config.webhook_enabled,
                        .timeout_ms = 5000,
                    };

                    const payload = webhook.WebhookPayload{
                        .from = self.mail_from orelse "unknown",
                        .recipients = self.rcpt_to.items,
                        .size = message.len,
                        .timestamp = time_compat.timestamp(),
                        .remote_addr = self.remote_addr,
                    };

                    webhook.sendWebhook(self.allocator, webhook_cfg, payload, self.logger) catch |err| {
                        self.logger.warn("Webhook delivery failed: {}", .{err});
                    };
                }

                try self.sendResponse(writer, 250, "OK: Message accepted for delivery", null);

                // Clean up BDAT session
                var s = session.*;
                s.deinit();
                self.bdat_session = null;

                // Reset state for next message
                try self.handleRset(writer);
            }
        } else {
            // More chunks expected
            try self.sendResponse(writer, 250, "OK: Chunk accepted", null);
        }
    }

    fn handleRset(self: *Session, writer: anytype) !void {
        if (self.mail_from) |mf| {
            self.allocator.free(mf);
            self.mail_from = null;
        }

        for (self.rcpt_to.items) |rcpt| {
            self.allocator.free(rcpt);
        }
        self.rcpt_to.clearRetainingCapacity();

        // Reset BDAT session if active
        if (self.bdat_session) |*session| {
            var s = session.*;
            s.deinit();
            self.bdat_session = null;
        }

        if (self.state == .Authenticated) {
            self.state = .Authenticated;
        } else {
            self.state = .Greeted;
        }

        try self.sendResponse(writer, 250, "OK", null);
    }

    fn handleAuth(self: *Session, writer: anytype, line: []const u8) !void {
        if (!self.config.enable_auth) {
            try self.sendResponse(writer, 502, "Command not implemented", null);
            return;
        }

        if (self.authenticated) {
            try self.sendResponse(writer, 503, "Already authenticated", null);
            return;
        }

        // Parse AUTH mechanism
        var it = std.mem.splitScalar(u8, line, ' ');
        _ = it.next(); // Skip AUTH

        const mechanism = it.next() orelse {
            try self.sendResponse(writer, 501, "Syntax: AUTH mechanism [initial-response]", null);
            return;
        };

        if (std.ascii.eqlIgnoreCase(mechanism, "PLAIN")) {
            // Get the initial response (base64 encoded credentials)
            const initial_response = it.next();

            if (initial_response) |encoded| {
                // Decode and verify credentials
                if (self.auth_backend) |backend| {
                    const credentials = auth.decodeBase64Auth(self.allocator, encoded) catch {
                        try self.sendResponse(writer, 535, "Authentication failed", null);
                        return;
                    };
                    defer {
                        self.allocator.free(credentials.username);
                        self.allocator.free(credentials.password);
                    }

                    const valid = backend.verifyCredentials(credentials.username, credentials.password) catch {
                        try self.sendResponse(writer, 454, "Temporary authentication failure", null);
                        return;
                    };

                    if (valid) {
                        self.authenticated = true;
                        self.state = .Authenticated;
                        const safe_user = sanitizeForLog(credentials.username);
                        self.logger.info("User '{s}' authenticated successfully", .{sanitizedSlice(&safe_user, credentials.username.len)});
                        try self.sendResponse(writer, 235, "Authentication successful", null);
                    } else {
                        const safe_user = sanitizeForLog(credentials.username);
                        self.logger.warn("Authentication failed for user '{s}'", .{sanitizedSlice(&safe_user, credentials.username.len)});
                        try self.sendResponse(writer, 535, "Authentication failed", null);
                    }
                } else {
                    // No auth backend configured - fall back to accepting all (development mode)
                    self.logger.warn("No auth backend configured - accepting all credentials", .{});
                    self.authenticated = true;
                    self.state = .Authenticated;
                    try self.sendResponse(writer, 235, "Authentication successful", null);
                }
            } else {
                try self.sendResponse(writer, 501, "AUTH PLAIN requires initial-response", null);
            }
        } else if (std.ascii.eqlIgnoreCase(mechanism, "LOGIN")) {
            // LOGIN mechanism not yet implemented - would require multi-step interaction
            try self.sendResponse(writer, 504, "AUTH LOGIN not yet implemented", null);
        } else {
            try self.sendResponse(writer, 504, "Unrecognized authentication type", null);
        }
    }

    fn handleStartTls(self: *Session, writer: anytype) !void {
        if (!self.config.enable_tls) {
            try self.sendResponse(writer, 454, "TLS not available", null);
            return;
        }

        // Check if already using TLS
        if (self.conn_wrapper.using_tls) {
            try self.sendResponse(writer, 454, "TLS already active", null);
            return;
        }

        // Check if we have TLS context
        if (self.tls_context == null) {
            self.logger.warn("STARTTLS requested but TLS not configured properly", .{});
            try self.sendResponse(writer, 454, "TLS not available", null);
            return;
        }

        // Send ready response before upgrading
        try self.sendResponse(writer, 220, "Ready to start TLS", null);

        self.logger.info("STARTTLS command accepted - starting TLS handshake", .{});

        // Perform TLS handshake using non-blocking API (uses global tls import)

        // Load certificate and key
        const cert_path = self.tls_context.?.config.cert_path orelse return error.TlsNotConfigured;
        const key_path = self.tls_context.?.config.key_path orelse return error.TlsNotConfigured;

        // Convert to absolute paths
        var cert_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        var key_path_buf: [std.fs.max_path_bytes]u8 = undefined;

        const io = io_compat.getIo();
        const abs_cert_path = if (std.fs.path.isAbsolute(cert_path))
            cert_path
        else blk: {
            const len = std.Io.Dir.cwd().realPathFile(io, cert_path, &cert_path_buf) catch {
                self.logger.err("Failed to resolve cert path: {s}", .{cert_path});
                return error.InvalidCertificate;
            };
            break :blk cert_path_buf[0..len];
        };

        const abs_key_path = if (std.fs.path.isAbsolute(key_path))
            key_path
        else blk: {
            const len = std.Io.Dir.cwd().realPathFile(io, key_path, &key_path_buf) catch {
                self.logger.err("Failed to resolve key path: {s}", .{key_path});
                return error.InvalidCertificate;
            };
            break :blk key_path_buf[0..len];
        };

        var cert_key = tls.config.CertKeyPair.fromFilePathAbsoluteSync(
            self.allocator,
            abs_cert_path,
            abs_key_path,
        ) catch |err| {
            self.logger.err("Failed to load certificate/key: {}", .{err});
            return error.InvalidCertificate;
        };
        defer cert_key.deinit(self.allocator);

        // Use non-blocking TLS handshake
        var server_hs = tls.nonblock.Server.init(.{ .auth = &cert_key });

        // Buffers for TLS handshake
        var recv_buf: [tls.max_ciphertext_record_len]u8 = undefined;
        var send_buf: [tls.max_ciphertext_record_len]u8 = undefined;

        // Perform handshake loop
        var recv_pos: usize = 0;
        while (!server_hs.done()) {
            // Read data from client
            const bytes_read = self.conn_wrapper.read(recv_buf[recv_pos..]) catch |err| {
                self.logger.err("TLS handshake read error: {}", .{err});
                return err;
            };

            if (bytes_read == 0) {
                self.logger.err("TLS handshake: connection closed", .{});
                return error.ConnectionClosed;
            }

            recv_pos += bytes_read;

            // Process handshake
            const result = server_hs.run(recv_buf[0..recv_pos], &send_buf) catch |err| {
                self.logger.err("TLS handshake error: {}", .{err});
                return error.TlsHandshakeFailed;
            };

            // Send response if any
            if (result.send.len > 0) {
                _ = self.conn_wrapper.write(result.send) catch |err| {
                    self.logger.err("TLS handshake write error: {}", .{err});
                    return err;
                };
            }

            // Shift consumed data
            if (result.recv_pos > 0) {
                std.mem.copyForwards(u8, &recv_buf, recv_buf[result.recv_pos..recv_pos]);
                recv_pos -= result.recv_pos;
            }
        }

        // Get the cipher from completed handshake
        const cipher = server_hs.cipher();

        self.logger.info("TLS handshake successful", .{});

        // Upgrade connection with the cipher
        self.conn_wrapper.upgradeWithCipher(cipher);

        // Reset session state after TLS upgrade as per RFC
        self.state = .Initial;
        self.authenticated = false;

        self.logger.info("TLS upgrade successful - connection now encrypted", .{});
    }

    /// Sanitize a string by removing CR and LF characters to prevent header injection
    fn sanitizeForHeader(input: []const u8, buf: []u8) []const u8 {
        var write_pos: usize = 0;
        for (input) |c| {
            // Skip CR and LF characters
            if (c != '\r' and c != '\n' and write_pos < buf.len) {
                buf[write_pos] = c;
                write_pos += 1;
            }
        }
        return buf[0..write_pos];
    }

    fn sendResponse(self: *Session, writer: anytype, code: u16, message: []const u8, extra: ?[]const u8) !void {
        var response_buf: [1024]u8 = undefined;
        var sanitized_buf: [512]u8 = undefined;

        // Sanitize message to prevent CRLF injection
        const sanitized_message = sanitizeForHeader(message, &sanitized_buf);

        const response = if (extra) |ext| blk: {
            var extra_sanitized_buf: [256]u8 = undefined;
            const sanitized_extra = sanitizeForHeader(ext, &extra_sanitized_buf);
            break :blk try std.fmt.bufPrint(&response_buf, "{d} {s} {s}\r\n", .{ code, sanitized_message, sanitized_extra });
        } else try std.fmt.bufPrint(&response_buf, "{d} {s}\r\n", .{ code, sanitized_message });

        _ = try self.conn_wrapper.write(response);
        _ = writer;
    }

    fn saveMessage(self: *Session, data: []const u8) !void {
        const io = io_compat.getIo();
        const cwd = std.Io.Dir.cwd();

        // Ensure mail directory exists
        cwd.createDir(io, "mail", .default_dir) catch {};
        cwd.createDir(io, "mail/new", .default_dir) catch {};

        // Generate unique filename based on timestamp
        const timestamp = time_compat.milliTimestamp();
        const filename = try std.fmt.allocPrint(self.allocator, "mail/new/{d}.eml", .{timestamp});
        defer self.allocator.free(filename);

        // Write message to file
        const file = try cwd.createFile(io, filename, .{});
        defer file.close(io);

        var header_buf: [256]u8 = undefined;

        // Write headers
        const from_line = try std.fmt.bufPrint(&header_buf, "From: {s}\r\n", .{self.mail_from orelse "unknown"});
        try file.writeStreamingAll(io, from_line);

        for (self.rcpt_to.items) |rcpt| {
            const to_line = try std.fmt.bufPrint(&header_buf, "To: {s}\r\n", .{rcpt});
            try file.writeStreamingAll(io, to_line);
        }

        const date_line = try std.fmt.bufPrint(&header_buf, "Date: {d}\r\n", .{timestamp});
        try file.writeStreamingAll(io, date_line);
        try file.writeStreamingAll(io, "\r\n");

        // Write message body
        try file.writeStreamingAll(io, data);

        self.logger.debug("Message saved to {s}", .{filename});
    }
};
