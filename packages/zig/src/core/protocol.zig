const std = @import("std");
const time_compat = @import("time_compat.zig");
const io_compat = @import("io_compat.zig");
const fs_compat = @import("fs_compat.zig");
const socket = @import("socket_compat.zig");
const config = @import("config.zig");
const auth = @import("../auth/auth.zig");
const logger = @import("logger.zig");
const security = @import("../auth/security.zig");
const webhook = @import("../features/webhook.zig");
const greylist_mod = @import("../antispam/greylist.zig");
const spf_mod = @import("../antispam/spf.zig");
const dkim_mod = @import("../antispam/dkim.zig");
const dmarc_mod = @import("../antispam/dmarc.zig");
const arc_mod = @import("../antispam/arc.zig");
const tls_mod = @import("tls.zig");
const chunking = @import("../protocol/chunking.zig");
const tls = @import("tls");
const outbound = @import("../delivery/outbound.zig");

/// Maximum number of in-flight detached outbound/forward delivery worker
/// threads across the whole process. Without a cap, a flood of recipients
/// could spawn unbounded threads and exhaust resources.
const max_outbound_workers: usize = 64;

/// Current number of in-flight outbound/forward worker threads. Incremented
/// before spawning a worker and decremented when the worker exits.
var outbound_worker_count: std.atomic.Value(usize) = std.atomic.Value(usize).init(0);

/// Try to reserve a slot for a new outbound worker. Returns true if a slot was
/// reserved (caller must ensure the worker decrements the counter on exit),
/// false if the in-flight limit has been reached.
fn tryReserveOutboundSlot() bool {
    while (true) {
        const cur = outbound_worker_count.load(.monotonic);
        if (cur >= max_outbound_workers) return false;
        if (outbound_worker_count.cmpxchgWeak(cur, cur + 1, .monotonic, .monotonic) == null) {
            return true;
        }
    }
}

fn releaseOutboundSlot() void {
    _ = outbound_worker_count.fetchSub(1, .monotonic);
}

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

/// Domain part of an address like `<user@example.com>` or `user@example.com`.
fn domainOf(addr: []const u8) []const u8 {
    const at = std.mem.lastIndexOfScalar(u8, addr, '@') orelse return "";
    var d = addr[at + 1 ..];
    while (d.len > 0 and (d[d.len - 1] == '>' or d[d.len - 1] == ' ' or d[d.len - 1] == '\t' or d[d.len - 1] == '\r')) {
        d = d[0 .. d.len - 1];
    }
    return d;
}

/// Extract the domain from the first `From:` header line, if present.
fn extractFromDomain(headers: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, headers, '\n');
    while (it.next()) |line| {
        if (line.len >= 5 and std.ascii.eqlIgnoreCase(line[0..5], "From:")) {
            const at = std.mem.lastIndexOfScalar(u8, line, '@') orelse return null;
            const d = line[at + 1 ..];
            var end: usize = 0;
            while (end < d.len and d[end] != '>' and d[end] != ' ' and d[end] != '\t' and d[end] != '\r' and d[end] != ';') {
                end += 1;
            }
            return d[0..end];
        }
    }
    return null;
}

pub const SMTPCommand = enum {
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

/// Process-wide counter for synthesized Message-IDs.
var msgid_seq: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

/// If the message has no Message-ID header, prepend a synthesized one. The
/// stored message uses LF line endings (the DATA loop strips CR), so the
/// inserted header matches.
fn ensureMessageId(allocator: std.mem.Allocator, message_data: *std.ArrayList(u8), hostname: []const u8) !void {
    const items = message_data.items;
    const hdr_end = std.mem.indexOf(u8, items, "\n\n") orelse
        std.mem.indexOf(u8, items, "\r\n\r\n") orelse items.len;
    if (headerPresent(items[0..hdr_end], "message-id")) return;
    const seq = msgid_seq.fetchAdd(1, .monotonic);
    const line = try std.fmt.allocPrint(allocator, "Message-ID: <{d}.{d}@{s}>\n", .{ time_compat.timestamp(), seq, hostname });
    defer allocator.free(line);
    try message_data.insertSlice(allocator, 0, line);
}

/// True if a header line `<name>:` (case-insensitive) exists in the block.
fn headerPresent(headers: []const u8, name_lower: []const u8) bool {
    var it = std.mem.splitScalar(u8, headers, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len > name_lower.len and line[name_lower.len] == ':' and
            std.ascii.eqlIgnoreCase(line[0..name_lower.len], name_lower)) return true;
    }
    return false;
}

pub const SessionState = enum {
    Initial,
    Greeted,
    MailFrom,
    RcptTo,
    Data,
    Authenticated,
};

/// Connection wrapper that abstracts TLS and plain TCP
pub const ConnectionWrapper = struct {
    tcp_conn: socket.Connection,
    tls_conn: ?tls.nonblock.Connection,
    using_tls: bool,
    // Buffers for TLS encryption/decryption
    ciphertext_accum: [tls.input_buffer_len * 4]u8,
    ciphertext_len: usize,
    // Buffer for decrypted cleartext that hasn't been consumed yet
    cleartext_buf: [16384]u8,
    cleartext_start: usize,
    cleartext_end: usize,
    // Read-ahead buffer for line-oriented parsing (one syscall per chunk
    // instead of one per byte). Raw read() bypasses this; before a TLS
    // upgrade any unconsumed bytes must be drained via drainBuffered().
    read_buf: [4096]u8,
    read_buf_start: usize,
    read_buf_end: usize,

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
            .read_buf = undefined,
            .read_buf_start = 0,
            .read_buf_end = 0,
        };
    }

    /// Buffered read: serves from the read-ahead buffer, refilling it with
    /// one large read() when empty.
    pub fn readBuffered(self: *ConnectionWrapper, buffer: []u8) !usize {
        if (self.read_buf_start == self.read_buf_end) {
            const n = try self.rawRead(self.read_buf[0..]);
            if (n == 0) return 0;
            self.read_buf_start = 0;
            self.read_buf_end = n;
        }
        const available = self.read_buf_end - self.read_buf_start;
        const to_copy = @min(available, buffer.len);
        @memcpy(buffer[0..to_copy], self.read_buf[self.read_buf_start..][0..to_copy]);
        self.read_buf_start += to_copy;
        return to_copy;
    }

    /// Hand back any read-ahead bytes without touching the socket. Called
    /// before a TLS upgrade so pipelined handshake bytes aren't lost.
    pub fn drainBuffered(self: *ConnectionWrapper, buffer: []u8) usize {
        const available = self.read_buf_end - self.read_buf_start;
        const to_copy = @min(available, buffer.len);
        @memcpy(buffer[0..to_copy], self.read_buf[self.read_buf_start..][0..to_copy]);
        self.read_buf_start += to_copy;
        if (self.read_buf_start == self.read_buf_end) {
            self.read_buf_start = 0;
            self.read_buf_end = 0;
        }
        return to_copy;
    }

    pub fn read(self: *ConnectionWrapper, buffer: []u8) !usize {
        // Serve read-ahead bytes first so raw and buffered reads never
        // observe the stream out of order.
        if (self.read_buf_end > self.read_buf_start) {
            return self.drainBuffered(buffer);
        }
        return self.rawRead(buffer);
    }

    fn rawRead(self: *ConnectionWrapper, buffer: []u8) !usize {
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

                // Try to decrypt pre-existing ciphertext first (e.g. leftover from STARTTLS handshake)
                if (self.ciphertext_len > 0) {
                    var decrypt_buf: [16384]u8 = undefined;
                    const dec_result = tls_conn.decrypt(self.ciphertext_accum[0..self.ciphertext_len], &decrypt_buf) catch |err| {
                        logger.err("TLS decrypt error (pre-existing): {}", .{err});
                        return error.TlsDecryptFailed;
                    };

                    if (dec_result.ciphertext_pos > 0) {
                        const remaining = self.ciphertext_len - dec_result.ciphertext_pos;
                        if (remaining > 0) {
                            std.mem.copyForwards(u8, &self.ciphertext_accum, self.ciphertext_accum[dec_result.ciphertext_pos..self.ciphertext_len]);
                        }
                        self.ciphertext_len = remaining;
                    }

                    if (dec_result.closed) return 0;

                    if (dec_result.cleartext.len > 0) {
                        const to_copy = @min(dec_result.cleartext.len, buffer.len);
                        @memcpy(buffer[0..to_copy], dec_result.cleartext[0..to_copy]);
                        if (dec_result.cleartext.len > to_copy) {
                            const excess = dec_result.cleartext.len - to_copy;
                            @memcpy(self.cleartext_buf[0..excess], dec_result.cleartext[to_copy..]);
                            self.cleartext_start = 0;
                            self.cleartext_end = excess;
                        }
                        return to_copy;
                    }
                    // Pre-existing data wasn't a complete TLS record, fall through to read more
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
                var decrypt_buf: [16384]u8 = undefined;
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
                return self.rawRead(buffer);
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
            if (conn.close(&close_buf)) |close_data| {
                _ = self.tcp_conn.write(close_data) catch {};
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
    // Per-command rate limiting
    command_count: u32,
    command_window_start: i64,

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
            .rcpt_to = .empty,
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
            .command_count = 0,
            .command_window_start = now,
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
        self.logger.info("SMTP: Sending 220 greeting (tls={s})", .{if (self.conn_wrapper.using_tls) "yes" else "no"});
        try self.sendResponse(null, 220, self.config.hostname, "ESMTP Service Ready");
        self.logger.info("SMTP: Greeting sent, waiting for client command", .{});

        var line_buffer: [4096]u8 = undefined;
        var line_pos: usize = 0;

        while (true) {
            // Check for timeout before each read
            try self.checkTimeout();

            // Read until we hit \n (buffered: bulk syscalls, per-byte consume)
            const byte_read = self.conn_wrapper.readBuffered(line_buffer[line_pos .. line_pos + 1]) catch |err| {
                self.logger.err("SMTP: Read error after {d} bytes: {}", .{ line_pos, err });
                if (err == error.EndOfStream) break;
                return err;
            };

            if (byte_read == 0) {
                self.logger.info("SMTP: Client disconnected (0 bytes read, line_pos={d})", .{line_pos});
                break;
            }

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

                // Log the command
                const san = sanitizeForLog(line);
                self.logger.info("SMTP CMD: {s}", .{sanitizedSlice(&san, line.len)});

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
        // Per-connection command rate limiting (max 50 commands per 10 seconds)
        const now = time_compat.timestamp();
        if (now - self.command_window_start >= 10) {
            self.command_count = 0;
            self.command_window_start = now;
        }
        self.command_count += 1;
        if (self.command_count > 50) {
            try self.sendResponse(writer, 421, "Too many commands, slow down", null);
            return true;
        }

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
        return parseCommandStatic(line);
    }

    pub fn parseCommandStatic(line: []const u8) SMTPCommand {
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

        // Only advertise AUTH over an encrypted channel when TLS is required for
        // auth, so credentials are never solicited in cleartext.
        if (self.config.enable_auth and (self.conn_wrapper.using_tls or !self.config.require_tls_for_auth)) {
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

        // Parse MAIL FROM:<address> (case-insensitive for FROM:)
        var upper_buf: [512]u8 = undefined;
        const upper_len = @min(line.len, upper_buf.len);
        for (line[0..upper_len], 0..) |c, i| {
            upper_buf[i] = std.ascii.toUpper(c);
        }
        const from_start = std.mem.indexOf(u8, upper_buf[0..upper_len], "FROM:") orelse {
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

        // Parse RCPT TO:<address> (case-insensitive for TO:)
        var rcpt_upper_buf: [512]u8 = undefined;
        const rcpt_upper_len = @min(line.len, rcpt_upper_buf.len);
        for (line[0..rcpt_upper_len], 0..) |c, i| {
            rcpt_upper_buf[i] = std.ascii.toUpper(c);
        }
        const to_start = std.mem.indexOf(u8, rcpt_upper_buf[0..rcpt_upper_len], "TO:") orelse {
            try self.sendResponse(writer, 501, "Syntax: RCPT TO:<address>", null);
            return;
        };

        const addr_part = line[to_start + 3 ..];
        const addr = std.mem.trim(u8, addr_part, " \t<>");

        if (addr.len == 0) {
            try self.sendResponse(writer, 501, "Invalid recipient address", null);
            return;
        }

        // Prevent open relay: unauthenticated clients can only send to local domain.
        // A recipient with no '@' (or an empty domain) is NOT a local recipient and
        // must be rejected — otherwise it would bypass the local-domain check.
        if (!self.authenticated) {
            const is_local = if (std.mem.indexOf(u8, addr, "@")) |at_pos| blk: {
                const recipient_domain = addr[at_pos + 1 ..];
                if (recipient_domain.len == 0) break :blk false;
                // Check if recipient domain matches hostname or is the parent domain
                // e.g. hostname "mail.stacksjs.com" should accept mail for "stacksjs.com"
                if (std.ascii.eqlIgnoreCase(recipient_domain, self.config.hostname)) break :blk true;
                if (std.mem.indexOf(u8, self.config.hostname, ".")) |dot_pos| {
                    break :blk std.ascii.eqlIgnoreCase(recipient_domain, self.config.hostname[dot_pos + 1 ..]);
                }
                break :blk false;
            } else false;

            if (!is_local) {
                self.logger.logSecurityEvent(self.remote_addr, "Relay access denied for unauthenticated sender");
                try self.sendResponse(writer, 550, "5.7.1 Relay access denied", null);
                return;
            }
        }

        // Check greylisting if enabled (skip for authenticated users)
        if (self.greylist != null and !self.authenticated) {
            const greylist = self.greylist.?;
            const mail_from = self.mail_from orelse "";
            const allowed = greylist.checkTriplet(self.remote_addr, mail_from, addr) catch |err| blk: {
                // Error checking greylist - allow by default (fail open)
                self.logger.warn("Greylist check error for {s}: {} - allowing", .{ self.remote_addr, err });
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

        var message_data: std.ArrayList(u8) = .empty;
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
            const byte_read = try self.conn_wrapper.readBuffered(line_buffer[line_pos .. line_pos + 1]);
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

        // Message-ID safety net: a submission without a Message-ID is rejected
        // by Gmail and others ("missing a valid Message-ID header"). If an
        // authenticated client omitted one, synthesize it before processing so
        // the message is well-formed (and DKIM can cover it).
        if (self.authenticated) {
            ensureMessageId(self.allocator, &message_data, self.config.hostname) catch {};
        }

        // === Inbound authentication: SPF/DKIM/DMARC/ARC ===
        // Only for unauthenticated (inbound) mail — submission clients are
        // already trusted via AUTH. Records an Authentication-Results header
        // and is advisory unless SMTP_ANTISPAM_ENFORCE is set.
        if (self.config.antispam_check and !self.authenticated) {
            if (self.runInboundAntispam(&message_data)) {
                try self.sendResponse(writer, 550, "5.7.1 Message rejected by mail authentication policy", null);
                try self.handleRset(writer);
                return;
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

    /// Run inbound SPF/DKIM/DMARC/ARC on a received message. Inserts an
    /// Authentication-Results header into `message_data` and logs the verdicts.
    /// Returns true only when the message should be rejected (enforce + DMARC
    /// fail); otherwise checks are advisory and never block delivery.
    fn runInboundAntispam(self: *Session, message_data: *std.ArrayList(u8)) bool {
        const data = message_data.items;
        const split = std.mem.indexOf(u8, data, "\n\n");
        const headers = if (split) |i| data[0..i] else data;
        const body = if (split) |i| (if (i + 2 <= data.len) data[i + 2 ..] else "") else "";

        const mail_from = self.mail_from orelse "";
        const helo = self.client_hostname orelse "";
        const spf_domain = domainOf(mail_from);
        const from_domain = extractFromDomain(headers) orelse spf_domain;

        var spf_v = spf_mod.SPFValidator.init(self.allocator);
        const spf_res = spf_v.validate(self.remote_addr, mail_from, helo) catch spf_mod.SPFResult.temperror;

        var dkim_v = dkim_mod.DKIMValidator.init(self.allocator);
        const dkim_res = dkim_v.validate(headers, body) catch dkim_mod.DKIMResult.temperror;

        var arc_v = arc_mod.ARCValidator.init(self.allocator);
        const arc_res = arc_v.validateChain(headers) catch arc_mod.ARCResult.temperror;

        var dmarc_v = dmarc_mod.DMARCValidator.init(self.allocator);
        const dmarc_res = dmarc_v.validate(from_domain, spf_res, spf_domain, dkim_res, from_domain) catch dmarc_mod.DMARCResult.temperror;

        self.logger.info("inbound auth ip={s} mailfrom_domain={s} header_from={s}: spf={s} dkim={s} dmarc={s} arc={s}", .{ self.remote_addr, spf_domain, from_domain, spf_res.toString(), dkim_res.toString(), dmarc_res.toString(), arc_res.toString() });

        var ar_buf: [600]u8 = undefined;
        const ar = std.fmt.bufPrint(&ar_buf, "Authentication-Results: {s}; spf={s} smtp.mailfrom={s}; dkim={s}; dmarc={s} header.from={s}; arc={s}\n", .{ self.config.hostname, spf_res.toString(), spf_domain, dkim_res.toString(), dmarc_res.toString(), from_domain, arc_res.toString() }) catch return false;
        // Prepend the header by rebuilding the buffer (only append/deinit, which
        // are the unmanaged-ArrayList APIs used throughout this codebase).
        var combined: std.ArrayList(u8) = .empty;
        combined.appendSlice(self.allocator, ar) catch {
            combined.deinit(self.allocator);
            return false;
        };
        combined.appendSlice(self.allocator, message_data.items) catch {
            combined.deinit(self.allocator);
            return false;
        };
        message_data.deinit(self.allocator);
        message_data.* = combined;

        return self.config.antispam_enforce and dmarc_res == .fail;
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

        // Refuse cleartext AUTH when TLS is required (RFC 3207): credentials
        // must not be sent before STARTTLS / on a non-TLS connection.
        if (self.config.require_tls_for_auth and !self.conn_wrapper.using_tls) {
            try self.sendResponse(writer, 538, "Encryption required for requested authentication mechanism", null);
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
            // AUTH LOGIN: multi-step challenge-response
            // Step 1: Send "Username:" challenge (base64 encoded)
            try self.sendResponse(writer, 334, "VXNlcm5hbWU6", null); // "Username:"

            // Step 2: Read base64-encoded username
            var username_line: [1024]u8 = undefined;
            var username_pos: usize = 0;
            while (true) {
                const n = self.conn_wrapper.readBuffered(username_line[username_pos .. username_pos + 1]) catch {
                    try self.sendResponse(writer, 535, "Authentication failed", null);
                    return;
                };
                if (n == 0) {
                    try self.sendResponse(writer, 535, "Authentication failed", null);
                    return;
                }
                if (username_line[username_pos] == '\n') break;
                username_pos += 1;
                if (username_pos >= username_line.len - 1) break;
            }
            const username_b64 = std.mem.trim(u8, username_line[0..username_pos], " \t\r\n");

            // Decode username from base64
            var username_buf: [256]u8 = undefined;
            const username_dec_len = std.base64.standard.Decoder.calcSizeForSlice(username_b64) catch {
                try self.sendResponse(writer, 535, "Authentication failed", null);
                return;
            };
            if (username_dec_len > username_buf.len) {
                try self.sendResponse(writer, 535, "Authentication failed", null);
                return;
            }
            std.base64.standard.Decoder.decode(username_buf[0..username_dec_len], username_b64) catch {
                try self.sendResponse(writer, 535, "Authentication failed", null);
                return;
            };
            const username = username_buf[0..username_dec_len];

            // Step 3: Send "Password:" challenge (base64 encoded)
            try self.sendResponse(writer, 334, "UGFzc3dvcmQ6", null); // "Password:"

            // Step 4: Read base64-encoded password
            var password_line: [1024]u8 = undefined;
            var password_pos: usize = 0;
            while (true) {
                const n = self.conn_wrapper.readBuffered(password_line[password_pos .. password_pos + 1]) catch {
                    try self.sendResponse(writer, 535, "Authentication failed", null);
                    return;
                };
                if (n == 0) {
                    try self.sendResponse(writer, 535, "Authentication failed", null);
                    return;
                }
                if (password_line[password_pos] == '\n') break;
                password_pos += 1;
                if (password_pos >= password_line.len - 1) break;
            }
            const password_b64 = std.mem.trim(u8, password_line[0..password_pos], " \t\r\n");

            // Decode password from base64
            var password_buf: [256]u8 = undefined;
            const password_dec_len = std.base64.standard.Decoder.calcSizeForSlice(password_b64) catch {
                try self.sendResponse(writer, 535, "Authentication failed", null);
                return;
            };
            if (password_dec_len > password_buf.len) {
                try self.sendResponse(writer, 535, "Authentication failed", null);
                return;
            }
            std.base64.standard.Decoder.decode(password_buf[0..password_dec_len], password_b64) catch {
                try self.sendResponse(writer, 535, "Authentication failed", null);
                return;
            };
            const password = password_buf[0..password_dec_len];

            // Verify credentials
            if (self.auth_backend) |backend| {
                const valid = backend.verifyCredentials(username, password) catch {
                    try self.sendResponse(writer, 454, "Temporary authentication failure", null);
                    return;
                };

                if (valid) {
                    self.authenticated = true;
                    self.state = .Authenticated;
                    const safe_user = sanitizeForLog(username);
                    self.logger.info("User '{s}' authenticated via LOGIN", .{sanitizedSlice(&safe_user, username.len)});
                    try self.sendResponse(writer, 235, "Authentication successful", null);
                } else {
                    const safe_user = sanitizeForLog(username);
                    self.logger.warn("AUTH LOGIN failed for user '{s}'", .{sanitizedSlice(&safe_user, username.len)});
                    try self.sendResponse(writer, 535, "Authentication failed", null);
                }
            } else {
                self.authenticated = true;
                self.state = .Authenticated;
                try self.sendResponse(writer, 235, "Authentication successful", null);
            }
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

        try self.doTlsHandshake();

        // Reset session state after TLS upgrade as per RFC
        self.state = .Initial;
        self.authenticated = false;

        self.logger.info("TLS upgrade successful - connection now encrypted", .{});
    }

    /// Perform TLS handshake (shared by STARTTLS and SMTPS implicit TLS)
    fn doTlsHandshake(self: *Session) !void {
        // Reuse the CertKeyPair the TlsContext parsed at startup instead of
        // re-reading cert/key files from disk on every handshake.
        const ctx = self.tls_context.?;
        if (ctx.cert_key_pair == null) {
            self.logger.err("TLS certificate not loaded in context", .{});
            return error.TlsNotConfigured;
        }
        const cert_key = &ctx.cert_key_pair.?;

        // Use non-blocking TLS handshake (matches proven IMAP pattern)
        var server_hs = tls.nonblock.Server.init(.{ .auth = cert_key });

        // Buffers for TLS handshake
        var recv_buf: [tls.input_buffer_len]u8 = undefined;
        var send_buf: [tls.output_buffer_len]u8 = undefined;
        // Seed with any read-ahead bytes (a pipelining client may have sent
        // its ClientHello right behind the STARTTLS command).
        var recv_len: usize = self.conn_wrapper.drainBuffered(recv_buf[0..]);

        // Perform handshake loop: run first, then read if needed (IMAP pattern)
        while (!server_hs.done()) {
            // Run handshake step with whatever data we have
            const result = server_hs.run(recv_buf[0..recv_len], &send_buf) catch |err| {
                self.logger.err("TLS handshake error: {}", .{err});
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

            // Send data to client if any — use a write loop to ensure ALL bytes are sent
            if (result.send.len > 0) {
                var sent: usize = 0;
                while (sent < result.send.len) {
                    const n = self.connection.write(result.send[sent..]) catch |err| {
                        self.logger.debug("TLS handshake write error: {}", .{err});
                        return error.TlsHandshakeFailed;
                    };
                    if (n == 0) {
                        self.logger.debug("TLS handshake: connection closed during write", .{});
                        return error.TlsHandshakeFailed;
                    }
                    sent += n;
                }
            }

            // Read more data from client if handshake not done
            if (!server_hs.done()) {
                const n = self.connection.read(recv_buf[recv_len..]) catch |err| {
                    self.logger.debug("TLS handshake read error: {}", .{err});
                    return error.TlsHandshakeFailed;
                };
                if (n == 0) {
                    self.logger.debug("TLS handshake: connection closed during read", .{});
                    return error.ConnectionClosed;
                }
                recv_len += n;
            }
        }

        const cipher = server_hs.cipher() orelse return error.TlsHandshakeFailed;

        self.logger.info("TLS handshake successful", .{});
        self.conn_wrapper.upgradeWithCipher(cipher);

        // Seed any leftover bytes from the handshake into conn_wrapper's ciphertext buffer
        if (recv_len > 0) {
            if (recv_len <= self.conn_wrapper.ciphertext_accum.len) {
                @memcpy(self.conn_wrapper.ciphertext_accum[0..recv_len], recv_buf[0..recv_len]);
                self.conn_wrapper.ciphertext_len = recv_len;
            }
        }
    }

    /// Perform implicit TLS handshake for SMTPS (port 465).
    /// Called before sending the SMTP banner.
    pub fn performImplicitTls(self: *Session) !void {
        if (self.tls_context == null) {
            self.logger.err("SMTPS: TLS not configured", .{});
            return error.TlsNotConfigured;
        }
        self.logger.info("SMTPS: Starting implicit TLS handshake", .{});
        try self.doTlsHandshake();
        self.logger.info("SMTPS: TLS handshake completed", .{});
    }

    /// Sanitize a string by removing CR and LF characters to prevent header injection
    pub fn sanitizeForHeader(input: []const u8, buf: []u8) []const u8 {
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
        const cwd = fs_compat.cwd();
        const timestamp = time_compat.milliTimestamp();
        const sender = self.mail_from orelse "unknown";

        for (self.rcpt_to.items) |rcpt| {
            // Determine if recipient is local or external
            // Compare against hostname and its parent domain (mail.stacksjs.com -> stacksjs.com)
            const is_local = if (std.mem.indexOf(u8, rcpt, "@")) |at_pos| blk: {
                const rcpt_domain = rcpt[at_pos + 1 ..];
                if (std.mem.eql(u8, rcpt_domain, self.config.hostname)) break :blk true;
                // Also check parent domain: if hostname is "mail.X", accept "X" as local
                if (std.mem.indexOf(u8, self.config.hostname, ".")) |dot_pos| {
                    const parent_domain = self.config.hostname[dot_pos + 1 ..];
                    if (std.mem.eql(u8, rcpt_domain, parent_domain)) break :blk true;
                }
                break :blk false;
            } else true;

            if (is_local) {
                // Local delivery: save to Maildir
                const username = if (std.mem.indexOf(u8, rcpt, "@")) |at_pos|
                    rcpt[0..at_pos]
                else
                    rcpt;

                const new_dir = try std.fmt.allocPrint(self.allocator, "mail/{s}/new", .{username});
                defer self.allocator.free(new_dir);
                cwd.makePath(new_dir) catch {};

                const filename = try std.fmt.allocPrint(self.allocator, "mail/{s}/new/{d}.eml", .{ username, timestamp });
                defer self.allocator.free(filename);

                const file = cwd.createFile(filename, .{}) catch |err| {
                    self.logger.err("Failed to create message file {s}: {}", .{ filename, err });
                    continue;
                };
                defer file.close();

                // Write the raw message data as-is (it already contains headers from the client)
                file.writeAll(data) catch |err| {
                    self.logger.err("Failed to write message data to {s}: {}", .{ filename, err });
                    continue;
                };

                self.logger.debug("Message saved to {s}", .{filename});

                // Check for auto-forwarding rules
                self.checkAndForward(username, sender, data) catch |err| {
                    self.logger.err("Forward check failed for {s}: {}", .{ username, err });
                };
            } else {
                // External delivery: relay via SES in a background thread
                // so we don't block the SMTP session (Apple Mail times out otherwise).
                // Bound the number of in-flight worker threads to avoid resource
                // exhaustion from a flood of recipients.
                if (!tryReserveOutboundSlot()) {
                    self.logger.warn("Outbound worker limit reached; dropping background delivery to {s}", .{rcpt});
                    continue;
                }
                self.logger.info("Queueing outbound delivery to: {s}", .{rcpt});
                const bg = self.allocator.create(OutboundContext) catch {
                    releaseOutboundSlot();
                    continue;
                };
                bg.* = .{
                    .allocator = self.allocator,
                    .from = self.allocator.dupe(u8, sender) catch {
                        self.allocator.destroy(bg);
                        releaseOutboundSlot();
                        continue;
                    },
                    .to = self.allocator.dupe(u8, rcpt) catch {
                        self.allocator.free(bg.from);
                        self.allocator.destroy(bg);
                        releaseOutboundSlot();
                        continue;
                    },
                    .data = self.allocator.dupe(u8, data) catch {
                        self.allocator.free(bg.from);
                        self.allocator.free(bg.to);
                        self.allocator.destroy(bg);
                        releaseOutboundSlot();
                        continue;
                    },
                    .hostname = self.config.hostname,
                    .delivery_method = self.config.delivery_method,
                    .ses_region = self.config.ses_region,
                };
                const thread = std.Thread.spawn(.{}, outboundWorker, .{bg}) catch |err| {
                    self.logger.err("Failed to spawn outbound thread for {s}: {}", .{ rcpt, err });
                    self.allocator.free(bg.data);
                    self.allocator.free(bg.to);
                    self.allocator.free(bg.from);
                    self.allocator.destroy(bg);
                    releaseOutboundSlot();
                    continue;
                };
                thread.detach();
            }
        }
    }

    const OutboundContext = struct {
        allocator: std.mem.Allocator,
        from: []u8,
        to: []u8,
        data: []u8,
        hostname: []const u8,
        delivery_method: config.DeliveryMethod,
        ses_region: []const u8,
    };

    fn outboundWorker(ctx: *OutboundContext) void {
        defer {
            ctx.allocator.free(ctx.data);
            ctx.allocator.free(ctx.to);
            ctx.allocator.free(ctx.from);
            ctx.allocator.destroy(ctx);
            // Release the in-flight worker slot reserved before spawning.
            releaseOutboundSlot();
        }
        outbound.deliverToRemote(
            ctx.allocator,
            ctx.from,
            ctx.to,
            ctx.data,
            ctx.hostname,
            ctx.delivery_method,
            ctx.ses_region,
        ) catch |err| {
            std.log.err("Outbound delivery to {s} failed: {}", .{ ctx.to, err });
        };
    }

    /// Check forwards.json for auto-forwarding rules and relay if matched.
    /// Format: {"hi": ["chris@stacksjs.com"], "info": ["a@x.com","b@x.com"]}
    fn checkAndForward(self: *Session, username: []const u8, sender: []const u8, data: []const u8) !void {
        const contents = fs_compat.readFileAlloc(self.allocator, "forwards.json") catch return;
        defer self.allocator.free(contents);
        if (contents.len == 0) return;

        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, contents, .{}) catch return;
        defer parsed.deinit();

        const obj = switch (parsed.value) {
            .object => |o| o,
            else => return,
        };

        const targets = obj.get(username) orelse return;
        const arr = switch (targets) {
            .array => |a| a,
            else => return,
        };

        for (arr.items) |item| {
            const forward_to = switch (item) {
                .string => |s| s,
                else => continue,
            };

            self.logger.info("Auto-forwarding from {s} to {s}", .{ username, forward_to });

            // Check if forward target is a local address
            const is_local_forward = if (std.mem.indexOf(u8, forward_to, "@")) |at_pos| blk: {
                const fwd_domain = forward_to[at_pos + 1 ..];
                if (std.mem.eql(u8, fwd_domain, self.config.hostname)) break :blk true;
                if (std.mem.indexOf(u8, self.config.hostname, ".")) |dot_pos| {
                    const parent_domain = self.config.hostname[dot_pos + 1 ..];
                    if (std.mem.eql(u8, fwd_domain, parent_domain)) break :blk true;
                }
                break :blk false;
            } else true;

            if (is_local_forward) {
                // Local forward: save directly to recipient's mailbox
                const fwd_username = if (std.mem.indexOf(u8, forward_to, "@")) |at_pos|
                    forward_to[0..at_pos]
                else
                    forward_to;

                const cwd = fs_compat.cwd();
                const ts = time_compat.milliTimestamp();
                const fwd_dir = std.fmt.allocPrint(self.allocator, "mail/{s}/new", .{fwd_username}) catch continue;
                defer self.allocator.free(fwd_dir);
                cwd.makePath(fwd_dir) catch {};

                const fwd_filename = std.fmt.allocPrint(self.allocator, "mail/{s}/new/{d}.eml", .{ fwd_username, ts }) catch continue;
                defer self.allocator.free(fwd_filename);

                const file = cwd.createFile(fwd_filename, .{}) catch |err| {
                    self.logger.err("Failed to create forward file {s}: {}", .{ fwd_filename, err });
                    continue;
                };
                defer file.close();
                file.writeAll(data) catch |err| {
                    self.logger.err("Failed to write forward data to {s}: {}", .{ fwd_filename, err });
                    continue;
                };
                self.logger.info("Local forward from {s} to {s} saved to {s}", .{ username, fwd_username, fwd_filename });
            } else {
                // External forward: relay via SES. Bound the number of in-flight
                // worker threads to avoid resource exhaustion.
                if (!tryReserveOutboundSlot()) {
                    self.logger.warn("Outbound worker limit reached; dropping forward to {s}", .{forward_to});
                    continue;
                }
                const bg = self.allocator.create(OutboundContext) catch {
                    releaseOutboundSlot();
                    continue;
                };
                bg.* = .{
                    .allocator = self.allocator,
                    .from = self.allocator.dupe(u8, sender) catch {
                        self.allocator.destroy(bg);
                        releaseOutboundSlot();
                        continue;
                    },
                    .to = self.allocator.dupe(u8, forward_to) catch {
                        self.allocator.free(bg.from);
                        self.allocator.destroy(bg);
                        releaseOutboundSlot();
                        continue;
                    },
                    .data = self.allocator.dupe(u8, data) catch {
                        self.allocator.free(bg.from);
                        self.allocator.free(bg.to);
                        self.allocator.destroy(bg);
                        releaseOutboundSlot();
                        continue;
                    },
                    .hostname = self.config.hostname,
                    .delivery_method = self.config.delivery_method,
                    .ses_region = self.config.ses_region,
                };
                const thread = std.Thread.spawn(.{}, outboundWorker, .{bg}) catch |err| {
                    self.logger.err("Failed to spawn forward thread to {s}: {}", .{ forward_to, err });
                    self.allocator.free(bg.data);
                    self.allocator.free(bg.to);
                    self.allocator.free(bg.from);
                    self.allocator.destroy(bg);
                    releaseOutboundSlot();
                    continue;
                };
                thread.detach();
            }
        }
    }
};
