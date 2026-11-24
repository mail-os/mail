//! Webmail HTTP server.
//!
//! A small plain-HTTP/1.1 listener (thread-per-connection, mirroring the IMAP
//! server's accept loop) that serves the webmail JSON API consumed by the stx
//! frontend in packages/webmail. It is the only HTTP surface on the mail server.
//!
//! Routes (all JSON; see WEBMAIL.md "API Contract"):
//!   POST /webmail/auth/login    {username,password} -> sets session cookie
//!   POST /webmail/auth/logout   -> clears cookie
//!   GET  /webmail/auth/me       -> {user}
//!   POST /webmail/auth/forgot   {address} -> always {ok:true}; mails a reset
//!                                link to the mailbox's recovery address
//!   POST /webmail/auth/reset/verify {token} -> {account} | 400 invalid_token
//!   POST /webmail/auth/reset    {token,password} -> sets the new password
//!   GET  /webmail/auth/recovery -> {recovery,setBy}
//!   PUT  /webmail/auth/recovery {currentPassword,recovery} -> changes it
//!   GET  /webmail/api/folders   -> [{name,total,unread}]
//!   GET  /webmail/api/messages?folder=&page=&per_page=  -> {items,total,page}
//!   GET  /webmail/api/messages/:uid?folder=            -> {message}
//!
//! Auth: login verifies via AuthBackend (Argon2id) and mints a DB-backed
//! session (webmail_session.zig). Subsequent requests carry an HttpOnly cookie.
//! Mutating requests (currently just login/logout) are same-origin; CSRF
//! enforcement for state-changing mailbox actions arrives with Phase 5.
//!
//! TLS: this listener is plain HTTP, intended to sit behind the existing TLS
//! termination story (or localhost during dev). Production serving model is the
//! Phase 9 decision in WEBMAIL.md.

const std = @import("std");
const clamav = @import("../antispam/clamav.zig");
const socket = @import("../core/socket_compat.zig");
const time_compat = @import("../core/time_compat.zig");
const logger = @import("../core/logger.zig");
const database = @import("../storage/database.zig");
const client_passwords = @import("../storage/client_passwords.zig");
const mailbox_operator = @import("../storage/mailbox_operator.zig");
const teams = @import("../storage/team_store.zig");
const shared_inbox = @import("../storage/shared_inbox.zig");
const auth_mod = @import("../auth/auth.zig");
const session_mod = @import("webmail_session.zig");
const account_links = @import("../storage/webmail_account_links.zig");
const maildir = @import("webmail_maildir.zig");
const search_index = @import("webmail_index.zig");
const personal = @import("webmail_private.zig");
const security = @import("../auth/security.zig");
const core_config = @import("../core/config.zig");
const compose = @import("webmail_compose.zig");
const compose_library = @import("webmail_compose_library.zig");
const message_submission = @import("../message/submission.zig");
const webmail_tls = @import("webmail_tls.zig");
const io_compat = @import("../core/io_compat.zig");
const tls = @import("tls");
const service_mod = @import("webmail_service.zig");
const sender_review = @import("webmail_sender_review.zig");
const retention = @import("webmail_retention.zig");
const store = @import("webmail_store.zig");
const threads = @import("webmail_threads.zig");
const categories = @import("../message/categories.zig");
const local_routing = @import("../delivery/local_routing.zig");
const attention = @import("webmail_attention.zig");
const thread_ids = @import("../message/thread_ids.zig");
const message_refs = @import("../storage/message_refs.zig");
const ascii_compat = @import("ascii-compat");
const caldav_store = @import("../storage/caldav_store.zig");
const hosted_sign_in = @import("../storage/hosted_sign_in.zig");
const calendar_day_labels = @import("../storage/calendar_day_labels.zig");
const calendar_tasks = @import("../storage/calendar_tasks.zig");
const calendar_tools = @import("../storage/calendar_tools.zig");
const snapshots = @import("webmail_snapshots.zig");
const assistant = @import("webmail_assistant.zig");
const team_threads = @import("webmail_team_threads.zig");
const thread_shares_path = "/webmail/api/thread-shares";
const reply_batches = @import("webmail_batch_replies.zig");
const file_links = @import("webmail_file_links.zig");
const link_tokens = @import("webmail_link_tokens.zig");
const caldav = @import("../protocol/caldav.zig");
const calendar_import = @import("webmail_calendar_import.zig");
const calendar_invite = @import("webmail_calendar_invite.zig");
const calendar_events = @import("webmail_calendar_events.zig");
const invitation_events = @import("webmail_invitation_events.zig");
const calendar_clock = @import("../protocol/icalendar_time.zig");
const recovery = @import("webmail_recovery.zig");
const health = @import("webmail_health.zig");
const password_hasher = @import("../auth/password.zig");
const mailbox_domains = @import("../core/mailbox_domains.zig");
const hosted_retirement = @import("../storage/hosted_domain_retirement.zig");

pub const ProvisioningConfig = struct {
    token: []const u8,
    domain: []const u8,
    additional_domains: ?[]const u8 = null,

    fn servesDomain(self: ProvisioningConfig, domain: []const u8) bool {
        return std.mem.eql(u8, domain, self.domain) or
            (validProvisioningDomain(domain) and mailbox_domains.contains(self.additional_domains, domain));
    }
};

pub fn validHostedSignInOrigin(origin: []const u8) bool {
    const prefix = "https://";
    if (!std.mem.startsWith(u8, origin, prefix)) return false;
    var authority = std.mem.splitScalar(u8, origin[prefix.len..], ':');
    if (!validProvisioningDomain(authority.first())) return false;
    if (authority.next()) |port_text| {
        const port = std.fmt.parseInt(u16, port_text, 10) catch return false;
        if (port == 0 or port == 443 or port_text[0] == '0') return false;
        for (port_text) |byte| if (!std.ascii.isDigit(byte)) return false;
    }
    return authority.next() == null;
}

// SPA static assets, rendered by packages/webmail/build.ts into webmail_dist/
// (gitignored, regenerated by `zig build`) and baked into the binary so the whole
// webmail UI ships as one executable — same single-binary model as admin.html.
const index_html = @embedFile("webmail_dist/index.html");
const client_password_path = "/webmail/api/client-passwords";
const login_html = @embedFile("webmail_dist/login.html");
const calendar_html = @embedFile("webmail_dist/calendar.html");
const shared_html = @embedFile("webmail_dist/shared.html");
const combined_html = @embedFile("webmail_dist/combined.html");
const recover_html = @embedFile("webmail_dist/recover.html");
const snapshot_html = @embedFile("webmail_dist/snapshot.html");
const file_link_html = @embedFile("webmail_dist/file-link.html");
const status_html = @embedFile("webmail_dist/status.html");
const mailbox_admin_html = @embedFile("webmail_dist/mailboxes.html");
const mailbox_admin_path = "/webmail/api/operator/mailboxes";
const styles_css = @embedFile("webmail_dist/styles.css");
const notifications_worker = @embedFile("webmail_dist/mail-notifications.js");

pub const WebmailHttpConfig = struct {
    port: u16 = 8080,
    bind_host: []const u8 = "127.0.0.1",
    /// Add the Secure attribute to cookies (set false for local plain-HTTP dev).
    secure_cookies: bool = true,
    messages_per_page: usize = 50,
    /// Max failed or pending logins per IP within login_rate_window_seconds.
    login_rate_max: u32 = 10,
    login_rate_window_seconds: u64 = 300,
    /// Outbound send settings — must mirror the server's so webmail mail is
    /// delivered + DKIM-signed identically to SMTP submission.
    hostname: []const u8 = "localhost",
    mail_config: ?*const core_config.Config = null,
    delivery_method: core_config.DeliveryMethod = .ses,
    ses_region: []const u8 = "us-east-1",
    /// TLS: when enabled the server terminates HTTPS itself (like IMAPS/CalDAV),
    /// loading the cert below. Off => plain HTTP (dev / behind a proxy).
    enable_tls: bool = false,
    tls_cert_path: ?[]const u8 = null,
    tls_key_path: ?[]const u8 = null,
    max_attachment_file_bytes: usize = 20 * 1024 * 1024,
    max_attachment_total_bytes: usize = 20 * 1024 * 1024,
    max_attachment_count: usize = 20,
    scanner: ?*clamav.ClamAVScanner = null,
    undo_send_seconds: u32 = 10,
    provisioning: ?ProvisioningConfig = null,
    operator_id: ?i64 = null,
    hosted_sign_in_origin: ?[]const u8 = null,
    hosted_team_domains: ?[]const u8 = null,
    primary_provisioning_domain: ?[]const u8 = null,
};

pub const WebmailHttpServer = struct {
    allocator: std.mem.Allocator,
    config: WebmailHttpConfig,
    db: *database.Database,
    auth: *auth_mod.AuthBackend,
    service: service_mod.Service,
    dav_store: ?*caldav_store.CalDavStore = null,
    sessions: session_mod.SessionManager,
    /// Webmail-specific login and authenticated account-change budgets.
    /// Its own internal mutex makes it safe to share across connection threads.
    login_limiter: security.RateLimiter,
    /// Throttles the unauthenticated password reset endpoints per IP: asking
    /// for links (by IP) and presenting tokens (by "token:<ip>"). The per
    /// mailbox cap on links sent lives in the database (webmail_recovery.zig).
    reset_limiter: security.RateLimiter,
    /// Loaded once at init when TLS is enabled (shared read-only across threads).
    cert_key_pair: ?tls.config.CertKeyPair = null,
    listener: ?socket.Server = null,
    running: std.atomic.Value(bool),
    active_connections: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    file_transfers: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    assistant_mutations: @import("../core/mutex_compat.zig").Mutex = .{},

    fn claimFileTransfer(self: *WebmailHttpServer) bool {
        if (self.file_transfers.fetchAdd(1, .acq_rel) < 4) return true;
        self.releaseFileTransfer();
        return false;
    }

    fn releaseFileTransfer(self: *WebmailHttpServer) void {
        _ = self.file_transfers.fetchSub(1, .release);
    }

    pub fn init(
        allocator: std.mem.Allocator,
        config: WebmailHttpConfig,
        db: *database.Database,
        auth: *auth_mod.AuthBackend,
    ) !WebmailHttpServer {
        if (config.provisioning) |provision| {
            if (!std.mem.eql(u8, config.bind_host, "127.0.0.1") or config.enable_tls or provision.token.len != 64 or
                config.mail_config == null or !validProvisioningDomain(provision.domain)) return error.InvalidProvisioningConfiguration;
            for (provision.token) |byte| if (!std.ascii.isHex(byte)) return error.InvalidProvisioningConfiguration;
            if (provision.additional_domains) |list| {
                const mail = config.mail_config.?;
                var domains = std.mem.splitScalar(u8, list, ',');
                while (domains.next()) |entry| {
                    const domain = std.mem.trim(u8, entry, " \t");
                    if (!validProvisioningDomain(domain) or !mail.isLocalDomain(domain) or
                        !mailbox_domains.contains(mail.exact_mailbox_domains, domain)) return error.InvalidProvisioningConfiguration;
                }
            }
        }
        if (config.max_attachment_total_bytes > 100 * 1024 * 1024 or config.max_attachment_file_bytes > 100 * 1024 * 1024 or config.max_attachment_count > 100 or config.undo_send_seconds > 30) return error.InvalidWebmailConfiguration;
        var sessions = session_mod.SessionManager.init(allocator, db, auth);
        sessions.secure_cookies = config.secure_cookies;
        var server: WebmailHttpServer = .{
            .allocator = allocator,
            .config = config,
            .db = db,
            .auth = auth,
            .service = try service_mod.Service.init(db, auth, .{
                .hostname = config.hostname,
                .delivery_method = config.delivery_method,
                .ses_region = config.ses_region,
                .mail_config = config.mail_config,
                .max_file_bytes = config.max_attachment_file_bytes,
                .max_total_bytes = config.max_attachment_total_bytes,
                .max_count = config.max_attachment_count,
                .max_message_bytes = if (config.mail_config) |cfg| cfg.max_message_size else 25 * 1024 * 1024,
                .undo_send_seconds = config.undo_send_seconds,
            }),
            .sessions = sessions,
            .login_limiter = security.RateLimiter.init(
                allocator,
                config.login_rate_window_seconds,
                config.login_rate_max,
                config.login_rate_max,
                config.login_rate_window_seconds,
            ),
            .reset_limiter = security.RateLimiter.init(allocator, 15 * 60, 10, 30, 15 * 60),
            .running = std.atomic.Value(bool).init(false),
        };
        server.login_limiter.max_auth_attempts = config.login_rate_max;
        server.login_limiter.auth_window_seconds = @intCast(@min(config.login_rate_window_seconds, std.math.maxInt(i64)));
        if (config.enable_tls and config.tls_cert_path != null and config.tls_key_path != null) {
            server.cert_key_pair = tls.config.CertKeyPair.fromFilePathAbsolute(
                allocator,
                io_compat.getIo(),
                config.tls_cert_path.?,
                config.tls_key_path.?,
            ) catch |err| {
                logger.err("Failed to load TLS certificate for webmail: {}", .{err});
                return server;
            };
            logger.info("Loaded TLS certificate for webmail", .{});
        }
        return server;
    }

    pub fn deinit(self: *WebmailHttpServer) void {
        self.stop();
        self.login_limiter.deinit();
        self.reset_limiter.deinit();
    }

    pub fn bind(self: *WebmailHttpServer) !void {
        const address = try socket.Address.parseIp(self.config.bind_host, self.config.port);
        self.listener = try socket.Server.listen(address, .{ .reuse_address = true });
        errdefer self.stop();
        try self.listener.?.setNonBlocking(true);
        self.running.store(true, .monotonic);
    }

    pub fn start(self: *WebmailHttpServer) !void {
        if (self.listener == null) try self.bind();
        const is_private = self.config.provisioning != null;
        logger.info("{s} HTTP server listening on {s}:{d}", .{ if (is_private) "Provisioning" else "Webmail", self.config.bind_host, self.config.port });

        const worker = if (!is_private) blk: {
            self.sessions.sweep();
            try self.service.recoverInterrupted(time_compat.timestamp());
            self.service.sweep(time_compat.timestamp()) catch |err| logger.warn("Webmail state cleanup failed: {}", .{err});
            snapshots.sweep(self.db, time_compat.timestamp()) catch |err| logger.warn("Snapshot link cleanup failed: {}", .{err});
            assistant.sweep(self.db, time_compat.timestamp()) catch |err| logger.warn("Assistant grant cleanup failed: {}", .{err});
            file_links.sweep(self.db, time_compat.timestamp()) catch |err| logger.warn("File link cleanup failed: {}", .{err});
            break :blk try std.Thread.spawn(.{}, deliveryWorker, .{self});
        } else null;
        defer {
            self.running.store(false, .monotonic);
            if (worker) |thread| thread.join();
            // Main joins this listener before freeing the shared database,
            // session manager and CardDAV contact store. Detached handlers
            // must finish before those owners can be destroyed.
            while (self.active_connections.load(.acquire) != 0) time_compat.sleepMs(10);
        }
        var last_sweep = time_compat.timestamp();
        const sweep_interval_seconds: i64 = 600;

        while (self.running.load(.monotonic)) {
            const now = time_compat.timestamp();
            if (!is_private and now - last_sweep >= sweep_interval_seconds) {
                last_sweep = now;
                self.sessions.sweep();
                self.service.sweep(now) catch |err| logger.warn("Webmail state cleanup failed: {}", .{err});
                snapshots.sweep(self.db, now) catch |err| logger.warn("Snapshot link cleanup failed: {}", .{err});
                assistant.sweep(self.db, now) catch |err| logger.warn("Assistant grant cleanup failed: {}", .{err});
                file_links.sweep(self.db, now) catch |err| logger.warn("File link cleanup failed: {}", .{err});
            }

            const connection = self.listener.?.accept() catch |err| {
                if (!self.running.load(.monotonic)) break;
                if (err == error.OperationCancelled or err == error.WouldBlock) {
                    self.listener.?.waitReadable(1000);
                    continue;
                }
                logger.warn("Webmail accept error: {}", .{err});
                time_compat.sleepMs(500);
                continue;
            };

            if (is_private and self.active_connections.load(.monotonic) >= 4) {
                connection.close();
                continue;
            }
            const ctx = ConnCtx{ .server = self, .connection = connection };
            _ = self.active_connections.fetchAdd(1, .monotonic);
            const thread = std.Thread.spawn(.{}, handleConnectionThread, .{ctx}) catch |err| {
                _ = self.active_connections.fetchSub(1, .release);
                logger.err("Failed to spawn webmail handler: {}", .{err});
                connection.close();
                continue;
            };
            thread.detach();
        }
    }

    pub fn stop(self: *WebmailHttpServer) void {
        self.requestStop();
        if (self.listener) |*listener| {
            listener.close();
            self.listener = null;
        }
    }

    pub fn requestStop(self: *WebmailHttpServer) void {
        self.running.store(false, .monotonic);
    }
};

const ConnCtx = struct {
    server: *WebmailHttpServer,
    connection: socket.Connection,
};

fn deliveryWorker(server: *WebmailHttpServer) void {
    var next_retention_check: i64 = 0;
    while (server.running.load(.monotonic)) {
        var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        const now = time_compat.timestamp();
        const delivered = server.service.dispatchDue(scratch.allocator(), now) catch |err| blk: {
            logger.err("Webmail outbox dispatch failed: {}", .{err});
            break :blk false;
        };
        const reviewed = sender_review.drain(server.allocator, server.db, null, server.service.config.hostname, server.service.config.mail_config, 20) catch |err| blk: {
            logger.err("Sender Review recovery failed: {}", .{err});
            break :blk false;
        };
        _ = maildir.indexCalendarHistory(server.db, null) catch |err| blk: {
            logger.err("Calendar history recovery failed: {}", .{err});
            break :blk false;
        };
        if (now >= next_retention_check) {
            next_retention_check = now + 5;
            retention.runDue(scratch.allocator(), server.db, now) catch |err|
                logger.err("Mailbox retention check failed: {}", .{err});
        }
        scratch.deinit();
        if (!delivered and !reviewed) time_compat.sleepMs(200);
    }
}

fn handleConnectionThread(ctx: ConnCtx) void {
    defer _ = ctx.server.active_connections.fetchSub(1, .release);
    defer ctx.connection.close();
    // Per-request arena: every allocation during this request (parsing, JSON,
    // Maildir reads) lives here and is freed wholesale at the end.
    var arena = std.heap.ArenaAllocator.init(ctx.server.allocator);
    defer arena.deinit();

    // The listener is non-blocking; the accepted connection can inherit that on
    // some platforms, which would make reads return WouldBlock. Force blocking,
    // then bound read time with RCVTIMEO so a stuck client still frees the thread.
    ctx.connection.setBlocking();
    const rcv_tv: std.posix.timeval = .{ .sec = if (ctx.server.config.provisioning != null) 5 else 120, .usec = 0 };
    std.posix.setsockopt(ctx.connection.fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&rcv_tv)) catch {};

    var stream: webmail_tls.Stream = blk: {
        if (ctx.server.cert_key_pair) |*cert| {
            break :blk webmail_tls.handshake(ctx.connection, cert) catch |err| {
                logger.debug("Webmail TLS handshake failed: {}", .{err});
                return;
            };
        }
        break :blk webmail_tls.Stream.plain(ctx.connection);
    };
    defer stream.closeTls();

    handleConnection(ctx.server, &stream, arena.allocator()) catch |err| {
        logger.warn("Webmail request error: {}", .{err});
    };
}

// ── HTTP request parsing ─────────────────────────────────────────────────────

const max_request_bytes = 1024 * 1024; // 1 MiB cap on a single request

const Request = struct {
    method: []const u8,
    path: []const u8,
    query: []const u8,
    headers: []const u8, // raw header block (after request line, before body)
    body: []const u8,
    /// Only a plaintext listener bound to loopback may trust gateway headers.
    trust_forwarded_headers: bool = false,
    holds_file_transfer: bool = false,

    fn header(self: Request, name: []const u8) ?[]const u8 {
        var line_start: usize = 0;
        while (line_start < self.headers.len) {
            const nl = std.mem.indexOfScalarPos(u8, self.headers, line_start, '\n') orelse self.headers.len;
            const line = std.mem.trim(u8, self.headers[line_start..nl], "\r ");
            if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
                const key = std.mem.trim(u8, line[0..colon], " \t");
                if (std.ascii.eqlIgnoreCase(key, name)) {
                    return std.mem.trim(u8, line[colon + 1 ..], " \t");
                }
            }
            line_start = nl + 1;
        }
        return null;
    }

    fn queryParam(self: Request, allocator: std.mem.Allocator, name: []const u8) ?[]const u8 {
        var it = std.mem.splitScalar(u8, self.query, '&');
        while (it.next()) |pair| {
            if (std.mem.indexOfScalar(u8, pair, '=')) |eq| {
                if (std.mem.eql(u8, pair[0..eq], name)) {
                    return urlDecode(allocator, pair[eq + 1 ..]) catch pair[eq + 1 ..];
                }
            } else if (std.mem.eql(u8, pair, name)) {
                return "";
            }
        }
        return null;
    }
};

/// Read and parse a full HTTP request (request line + headers + body, honoring
/// Content-Length). Returns null if the connection closed cleanly with no data.
fn readRequest(server: *WebmailHttpServer, conn: *webmail_tls.Stream, allocator: std.mem.Allocator) !?Request {
    var buf: std.ArrayList(u8) = .empty;
    var chunk: [8192]u8 = undefined;

    // Read until we have the full header block.
    var header_len: usize = 0;
    while (true) {
        const n = conn.read(&chunk) catch |err| {
            if (buf.items.len == 0) return null;
            return err;
        };
        if (n == 0) {
            if (buf.items.len == 0) return null;
            break;
        }
        try buf.appendSlice(allocator, chunk[0..n]);
        if (buf.items.len > max_request_bytes) return error.RequestTooLarge;
        if (std.mem.indexOf(u8, buf.items, "\r\n\r\n")) |idx| {
            header_len = idx + 4;
            break;
        }
        // Guard against header-only floods.
        if (buf.items.len > 64 * 1024) return error.HeadersTooLarge;
    }
    if (header_len == 0) {
        // No header terminator seen; treat as malformed unless empty.
        return error.MalformedRequest;
    }

    const head = buf.items[0..header_len];

    // Request line.
    const line_end = std.mem.indexOf(u8, head, "\r\n") orelse return error.MalformedRequest;
    const request_line = head[0..line_end];
    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method = try allocator.dupe(u8, parts.next() orelse return error.MalformedRequest);
    const target = try allocator.dupe(u8, parts.next() orelse return error.MalformedRequest);

    // Split path?query.
    var path = target;
    var query: []const u8 = "";
    if (std.mem.indexOfScalar(u8, target, '?')) |q| {
        path = target[0..q];
        query = target[q + 1 ..];
    }

    const headers_block = try allocator.dupe(u8, head[line_end + 2 .. header_len]);
    const loopback_bind = std.mem.eql(u8, server.config.bind_host, "127.0.0.1") or std.mem.eql(u8, server.config.bind_host, "::1");
    const peer = conn.peerIp();
    const loopback_peer = std.mem.eql(u8, peer, "127.0.0.1") or std.mem.eql(u8, peer, "::1");
    const trusted = !server.config.enable_tls and loopback_bind and loopback_peer;
    var request = Request{ .method = method, .path = path, .query = query, .headers = headers_block, .body = "", .trust_forwarded_headers = trusted };
    if (request.header("Transfer-Encoding") != null) return error.MalformedRequest;
    var body_limit: usize = if (server.config.provisioning != null) 4096 else max_request_bytes;
    if (std.mem.eql(u8, path, "/webmail/api/combined/accounts")) body_limit = @min(body_limit, 8192);
    if (std.mem.eql(u8, path, "/webmail/api/combined/actions")) body_limit = @min(body_limit, 32 * 1024);
    if (std.mem.startsWith(u8, path, "/webmail/assistant/")) body_limit = @min(body_limit, 512 * 1024);
    if (std.mem.startsWith(u8, path, "/webmail/api/assistant-grants")) body_limit = @min(body_limit, 4096);
    if (std.mem.eql(u8, path, client_password_path)) body_limit = @min(body_limit, 8192);
    if (std.mem.eql(u8, path, mailbox_admin_path)) body_limit = @min(body_limit, 8192);
    if (std.mem.eql(u8, path, "/webmail/auth/hosted")) body_limit = session_mod.token_hex_len + "proof=".len;
    const file_upload = std.mem.eql(u8, path, file_links.path);
    errdefer if (request.holds_file_transfer) server.releaseFileTransfer();
    if (server.config.provisioning == null and std.mem.eql(u8, method, "POST") and
        (file_upload or std.mem.eql(u8, path, "/webmail/api/uploads")))
    {
        if (!isSameOrigin(request)) return error.CrossOrigin;
        var session = try resolveRequestSession(server, allocator, request);
        defer session.deinit(server.allocator);
        if (file_upload) {
            if (!try expectedAccountMatches(allocator, request, session.username)) return error.AccountChanged;
            body_limit = try file_links.uploadLimit(server.db, session.username);
            if (body_limit == 0) return error.Unauthorized;
            if (!server.claimFileTransfer()) return error.FileTransfersBusy;
            request.holds_file_transfer = true;
        } else body_limit = (try server.service.limits(session.username)).maxFileBytes;
    }

    // Body, per Content-Length.
    var body: []const u8 = "";
    if (findContentLength(headers_block)) |clen| {
        if (clen > body_limit) return error.RequestTooLarge;
        const have = buf.items.len - header_len;
        while (buf.items.len - header_len < clen) {
            const remaining = header_len + clen - buf.items.len;
            const n = try conn.read(chunk[0..@min(chunk.len, remaining)]);
            if (n == 0) break;
            try buf.appendSlice(allocator, chunk[0..n]);
            if (buf.items.len > header_len + body_limit) return error.RequestTooLarge;
        }
        _ = have;
        if (buf.items.len < header_len + clen) return error.MalformedRequest;
        const end = header_len + clen;
        body = buf.items[header_len..end];
    }

    request.body = body;
    return request;
}

fn findContentLength(headers_block: []const u8) ?usize {
    var line_start: usize = 0;
    while (line_start < headers_block.len) {
        const nl = std.mem.indexOfScalarPos(u8, headers_block, line_start, '\n') orelse headers_block.len;
        const line = std.mem.trim(u8, headers_block[line_start..nl], "\r ");
        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            const key = std.mem.trim(u8, line[0..colon], " \t");
            if (std.ascii.eqlIgnoreCase(key, "Content-Length")) {
                const val = std.mem.trim(u8, line[colon + 1 ..], " \t");
                return std.fmt.parseInt(usize, val, 10) catch null;
            }
        }
        line_start = nl + 1;
    }
    return null;
}

// ── Routing ──────────────────────────────────────────────────────────────────

fn handleConnection(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator) !void {
    var req = (readRequest(server, conn, arena) catch |err| {
        return switch (err) {
            error.RequestTooLarge => sendError(conn, arena, 413, "too_large", "This request exceeds the configured limit"),
            error.Unauthorized => sendError(conn, arena, 401, "unauthorized", "Please sign in"),
            error.HostedReadOnly => sendError(conn, arena, 403, "mailbox_read_only", "This mailbox is available for reading and export."),
            error.AccountChanged => sendError(conn, arena, 409, "account_changed", "The signed-in account changed. Reload this tab before continuing."),
            error.LinkedAccountUnavailable => sendError(conn, arena, 403, "linked_account_unavailable", "This linked mailbox is no longer available."),
            error.FileTransfersBusy => sendError(conn, arena, 503, "file_transfers_busy", "File transfers are busy. Try again shortly."),
            error.CrossOrigin => sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected"),
            error.MalformedRequest, error.HeadersTooLarge => sendError(conn, arena, 400, "bad_request", "Malformed request"),
            else => err,
        };
    }) orelse return;
    defer if (req.holds_file_transfer) server.releaseFileTransfer();
    const loopback_bind = std.mem.eql(u8, server.config.bind_host, "127.0.0.1") or std.mem.eql(u8, server.config.bind_host, "::1");
    const peer = conn.peerIp();
    const loopback_peer = std.mem.eql(u8, peer, "127.0.0.1") or std.mem.eql(u8, peer, "::1");
    req.trust_forwarded_headers = !server.config.enable_tls and loopback_bind and loopback_peer;
    if (server.config.provisioning) |provision| {
        return handleProvisioning(server, conn, arena, req, provision);
    }

    // CORS preflight (the dev proxy is same-origin, but be tolerant).
    if (std.mem.eql(u8, req.method, "OPTIONS")) {
        try sendStatus(conn, arena, 204, "No Content", null);
        return;
    }

    const p = req.path;
    if (std.mem.eql(u8, p, "/webmail/auth/hosted") and std.mem.eql(u8, req.method, "POST"))
        return handleHostedSignIn(server, conn, arena, req);
    if (req.queryParam(arena, "linked") != null and !linkedRequestAllowed(req) and
        !(std.mem.eql(u8, p, "/") and std.mem.eql(u8, req.method, "GET")))
        return sendError(conn, arena, 403, "linked_route_unavailable", "This action is unavailable in a linked mailbox.");

    if (std.mem.eql(u8, p, "/health/report") and std.mem.eql(u8, req.method, "GET")) {
        if (!health.authorized(req.header("oh-dear-health-check-secret")))
            return sendError(conn, arena, 401, "unauthorized", "Monitoring credential required");
        const report = try health.response(arena, time_compat.timestamp());
        return sendJson(conn, arena, if (health.isHealthy(arena, report)) 200 else 503, report, null);
    }
    if (std.mem.eql(u8, p, "/healthz") and std.mem.eql(u8, req.method, "GET")) {
        const ok = health.isHealthy(arena, try health.response(arena, time_compat.timestamp()));
        return sendJson(conn, arena, if (ok) 200 else 503, if (ok) "{\"status\":\"healthy\"}" else "{\"status\":\"unavailable\"}", null);
    }
    if (std.mem.eql(u8, p, "/webmail/api/health") and std.mem.eql(u8, req.method, "GET")) return handleHealth(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/config") and std.mem.eql(u8, req.method, "GET")) return handleClientConfig(server, conn, arena, req);
    const combined_accounts = "/webmail/api/combined/accounts";
    if (std.mem.eql(u8, p, combined_accounts)) return handleCombinedAccounts(server, conn, arena, req, null);
    if (std.mem.startsWith(u8, p, combined_accounts ++ "/") and std.mem.eql(u8, req.method, "DELETE"))
        return handleCombinedAccounts(server, conn, arena, req, p[combined_accounts.len + 1 ..]);
    if (std.mem.eql(u8, p, "/webmail/api/combined/messages") and std.mem.eql(u8, req.method, "GET"))
        return handleCombinedMessages(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/combined/actions") and std.mem.eql(u8, req.method, "POST"))
        return handleCombinedAction(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/sender-identities") and std.mem.eql(u8, req.method, "GET")) return handleSenderIdentities(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/external-sender-review") and std.mem.eql(u8, req.method, "POST")) return handleExternalSenderReview(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/external-sender-verification")) return handleExternalSenderVerification(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/preferences") and std.mem.eql(u8, req.method, "PUT")) return handlePreferences(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/compose-library") and
        (std.mem.eql(u8, req.method, "GET") or std.mem.eql(u8, req.method, "PUT"))) return handleComposeLibrary(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/team-invitations")) return handleTeamInvitations(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/teams") or std.mem.startsWith(u8, p, "/webmail/api/teams/"))
        return handleTeams(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/shared-inboxes") or std.mem.startsWith(u8, p, "/webmail/api/shared-inboxes/"))
        return handleSharedInboxes(server, conn, arena, req);
    if (std.mem.eql(u8, p, thread_shares_path) or std.mem.startsWith(u8, p, thread_shares_path ++ "/"))
        return handleThreadShares(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/sender-review/status") and std.mem.eql(u8, req.method, "GET")) return handleSenderReviewStatus(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/sender-review") and std.mem.eql(u8, req.method, "GET")) return handleSenderReviewList(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/sender-review") and std.mem.eql(u8, req.method, "PUT")) return handleSenderReviewSettings(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/sender-review/decision") and std.mem.eql(u8, req.method, "POST")) return handleSenderReviewDecision(server, conn, arena, req);
    const invitations = "/webmail/api/sender-review/invitations";
    if (std.mem.eql(u8, p, invitations) and std.mem.eql(u8, req.method, "POST"))
        return handleSenderInvitation(server, conn, arena, req, null);
    if (std.mem.eql(u8, req.method, "DELETE")) {
        if (pathId(p, invitations ++ "/")) |id| return handleSenderInvitation(server, conn, arena, req, id);
    }
    if (std.mem.eql(u8, p, "/webmail/api/category-settings") and
        (std.mem.eql(u8, req.method, "GET") or std.mem.eql(u8, req.method, "PUT"))) return handleCategorySettings(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/category-rule") and std.mem.eql(u8, req.method, "PUT")) return handleCategoryRule(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/attention")) {
        if (std.mem.eql(u8, req.method, "GET")) return handleAttentionStatus(server, conn, arena, req);
        if (std.mem.eql(u8, req.method, "PUT")) return handleAttentionChange(server, conn, arena, req);
    }
    if (std.mem.eql(u8, p, "/webmail/api/notifications") and
        (std.mem.eql(u8, req.method, "GET") or std.mem.eql(u8, req.method, "PUT")))
        return handleBrowserNotifications(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/notifications/claim") and std.mem.eql(u8, req.method, "POST"))
        return handleBrowserNotificationClaim(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/notifications/rule") and std.mem.eql(u8, req.method, "PUT"))
        return handleBrowserNotificationRule(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/private/message")) {
        if (std.mem.eql(u8, req.method, "GET") or std.mem.eql(u8, req.method, "POST"))
            return handlePrivateMessage(server, conn, arena, req);
    }
    if (std.mem.eql(u8, p, "/webmail/api/private/collections")) {
        if (std.mem.eql(u8, req.method, "GET") or std.mem.eql(u8, req.method, "POST"))
            return handlePrivateCollections(server, conn, arena, req);
    }
    if (std.mem.eql(u8, p, "/webmail/api/private/group") and std.mem.eql(u8, req.method, "POST"))
        return handlePrivateGroup(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/private/undo-group") and std.mem.eql(u8, req.method, "POST"))
        return handlePrivateGroupUndo(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/uploads") and std.mem.eql(u8, req.method, "POST")) return handleUpload(server, conn, arena, req);
    const snapshot_path = "/webmail/api/snapshot-links";
    const assistant_path = "/webmail/api/assistant-grants";
    if (std.mem.eql(u8, p, client_password_path)) {
        if (std.mem.eql(u8, req.method, "GET")) return handleClientPasswords(server, conn, arena, req, .list, "");
        if (std.mem.eql(u8, req.method, "POST")) return handleClientPasswords(server, conn, arena, req, .create, "");
    }
    if (std.mem.startsWith(u8, p, client_password_path ++ "/") and std.mem.eql(u8, req.method, "DELETE"))
        return handleClientPasswords(server, conn, arena, req, .revoke, p[client_password_path.len + 1 ..]);
    if (std.mem.eql(u8, p, assistant_path)) {
        if (std.mem.eql(u8, req.method, "GET")) return handleAssistantOwner(server, conn, arena, req, .list, "");
        if (std.mem.eql(u8, req.method, "POST")) return handleAssistantOwner(server, conn, arena, req, .issue, "");
    }
    if (std.mem.eql(u8, p, assistant_path ++ "/preview") and std.mem.eql(u8, req.method, "POST"))
        return handleAssistantOwner(server, conn, arena, req, .preview, "");
    if (std.mem.startsWith(u8, p, assistant_path ++ "/") and std.mem.eql(u8, req.method, "DELETE"))
        return handleAssistantOwner(server, conn, arena, req, .revoke, p[assistant_path.len + 1 ..]);
    if (std.mem.eql(u8, req.method, "POST")) {
        if (std.mem.eql(u8, p, "/webmail/assistant/read")) return handleAssistantUse(server, conn, arena, req, .read);
        if (std.mem.eql(u8, p, "/webmail/assistant/drafts")) return handleAssistantUse(server, conn, arena, req, .draft);
    }
    if (std.mem.eql(u8, p, snapshot_path) and std.mem.eql(u8, req.method, "GET")) return handleSnapshotList(server, conn, arena, req);
    if (std.mem.eql(u8, p, snapshot_path) and std.mem.eql(u8, req.method, "POST")) return handleSnapshotCreate(server, conn, arena, req, false);
    if (std.mem.eql(u8, p, snapshot_path ++ "/preview") and std.mem.eql(u8, req.method, "POST")) return handleSnapshotCreate(server, conn, arena, req, true);
    if (std.mem.startsWith(u8, p, snapshot_path ++ "/") and std.mem.eql(u8, req.method, "DELETE"))
        return handleSnapshotRevoke(server, conn, arena, req, p[(snapshot_path.len + 1)..]);
    if (std.mem.eql(u8, p, "/webmail/public/snapshot") and std.mem.eql(u8, req.method, "POST")) return handleSnapshotView(server, conn, arena, req);
    if (std.mem.eql(u8, p, file_links.path)) {
        if (std.mem.eql(u8, req.method, "POST")) return handleFileLinkUpload(server, conn, arena, req);
        if (std.mem.eql(u8, req.method, "GET")) return handleFileLinkList(server, conn, arena, req);
    }
    if (std.mem.startsWith(u8, p, file_links.path ++ "/") and std.mem.eql(u8, req.method, "DELETE"))
        return handleFileLinkRevoke(server, conn, arena, req, p[(file_links.path.len + 1)..]);
    if (std.mem.eql(u8, req.method, "POST")) {
        if (std.mem.eql(u8, p, "/webmail/public/file-link")) return handleFileLinkPublic(server, conn, arena, req, false);
        if (std.mem.eql(u8, p, "/webmail/public/file-link/download")) return handleFileLinkPublic(server, conn, arena, req, true);
    }
    if (std.mem.startsWith(u8, p, "/webmail/api/uploads/") and std.mem.eql(u8, req.method, "DELETE")) return handleUploadDelete(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/bulk") and std.mem.eql(u8, req.method, "POST")) return handleBulk(server, conn, arena, req);
    const replies_path = "/webmail/api/reply-batches";
    if (std.mem.eql(u8, p, replies_path ++ "/preview") and std.mem.eql(u8, req.method, "POST")) return handleReplyBatchPreview(server, conn, arena, req);
    if (std.mem.eql(u8, p, replies_path) and std.mem.eql(u8, req.method, "POST")) return handleReplyBatchQueue(server, conn, arena, req);
    if (std.mem.startsWith(u8, p, replies_path ++ "/") and std.mem.eql(u8, req.method, "GET"))
        return handleReplyBatchStatus(server, conn, arena, req, p[(replies_path.len + 1)..]);
    if (std.mem.startsWith(u8, p, "/webmail/api/undo/") and std.mem.eql(u8, req.method, "POST")) return handleUndo(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/outbox") and std.mem.eql(u8, req.method, "GET")) return handleOutboxList(server, conn, arena, req);
    if (std.mem.startsWith(u8, p, "/webmail/api/outbox/")) return handleOutboxItem(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/drafts") and std.mem.eql(u8, req.method, "GET")) return handleDraftGet(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/address-book"))
        return handleAddressBook(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/contacts") and std.mem.eql(u8, req.method, "GET")) return handleContacts(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/calendars") and std.mem.eql(u8, req.method, "GET")) return handleCalendars(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/calendars") and std.mem.eql(u8, req.method, "POST")) return handleCalendarCreate(server, conn, arena, req);
    if (std.mem.startsWith(u8, p, "/webmail/api/calendars/") and std.mem.eql(u8, req.method, "PATCH")) return handleCalendarColor(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/calendar-shares") and std.mem.eql(u8, req.method, "GET")) return handleCalendarShares(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/calendar-day-labels") and std.mem.eql(u8, req.method, "GET")) return handleCalendarDayLabels(server, conn, arena, req, null);
    const day_label_path = "/webmail/api/calendar-day-labels/";
    if (std.mem.startsWith(u8, p, day_label_path) and std.mem.eql(u8, req.method, "PUT")) return handleCalendarDayLabels(server, conn, arena, req, p[day_label_path.len..]);
    const task_path = "/webmail/api/calendar-tasks";
    if (std.mem.eql(u8, p, task_path) and (std.mem.eql(u8, req.method, "GET") or std.mem.eql(u8, req.method, "POST")))
        return handleCalendarTasks(server, conn, arena, req, null);
    if (std.mem.startsWith(u8, p, task_path ++ "/") and (std.mem.eql(u8, req.method, "PUT") or std.mem.eql(u8, req.method, "DELETE")))
        return handleCalendarTasks(server, conn, arena, req, p[(task_path.len + 1)..]);
    if (std.mem.eql(u8, p, "/webmail/api/calendar-tools") and (std.mem.eql(u8, req.method, "GET") or std.mem.eql(u8, req.method, "PUT")))
        return handleCalendarTools(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/calendar-timezone") and std.mem.eql(u8, req.method, "GET")) return handleCalendarTimezone(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/calendar-free-busy") and std.mem.eql(u8, req.method, "GET")) return handleCalendarFreeBusy(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/calendar-reminders") and std.mem.eql(u8, req.method, "GET")) return handleCalendarReminders(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/calendar-reminders/dismiss") and std.mem.eql(u8, req.method, "POST")) return handleReminderDismiss(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/calendar-events") and std.mem.eql(u8, req.method, "GET")) return handleCalendarEvents(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/calendar-event-source") and std.mem.eql(u8, req.method, "GET")) return handleCalendarEventSource(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/calendar-rsvp") and std.mem.eql(u8, req.method, "POST")) return handleCalendarRsvp(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/calendar-invitation-event") and std.mem.eql(u8, req.method, "POST")) return handleInvitationEvent(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/calendar-events") and std.mem.eql(u8, req.method, "POST")) return handleCalendarEventCreate(server, conn, arena, req);
    if (std.mem.startsWith(u8, p, "/webmail/api/calendar-events/")) return handleCalendarEventItem(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/calendar-export") and std.mem.eql(u8, req.method, "GET")) return handleCalendarExport(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/calendar-import") and std.mem.eql(u8, req.method, "POST")) return handleCalendarImport(server, conn, arena, req);

    if (std.mem.eql(u8, p, "/webmail/auth/login") and std.mem.eql(u8, req.method, "POST")) {
        return handleLogin(server, conn, arena, req);
    }
    if (std.mem.eql(u8, p, "/webmail/auth/logout") and std.mem.eql(u8, req.method, "POST")) {
        return handleLogout(server, conn, arena, req);
    }
    if (std.mem.eql(u8, p, "/webmail/auth/password") and std.mem.eql(u8, req.method, "POST")) {
        return handlePasswordChange(server, conn, arena, req);
    }
    if (std.mem.eql(u8, p, "/webmail/auth/me") and std.mem.eql(u8, req.method, "GET")) {
        return handleMe(server, conn, arena, req);
    }
    if (std.mem.eql(u8, p, "/webmail/auth/forgot") and std.mem.eql(u8, req.method, "POST")) {
        return handleForgot(server, conn, arena, req);
    }
    if (std.mem.eql(u8, p, "/webmail/auth/reset/verify") and std.mem.eql(u8, req.method, "POST")) {
        return handleResetVerify(server, conn, arena, req);
    }
    if (std.mem.eql(u8, p, "/webmail/auth/reset") and std.mem.eql(u8, req.method, "POST")) {
        return handleResetComplete(server, conn, arena, req);
    }
    if (std.mem.eql(u8, p, "/webmail/auth/recovery") and std.mem.eql(u8, req.method, "GET")) {
        return handleRecoveryGet(server, conn, arena, req);
    }
    if (std.mem.eql(u8, p, "/webmail/auth/recovery") and std.mem.eql(u8, req.method, "PUT")) {
        return handleRecoveryUpdate(server, conn, arena, req);
    }
    if (std.mem.eql(u8, p, "/webmail/api/forwarding")) return handleForwarding(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/retention")) return handleRetention(server, conn, arena, req, .rule);
    if (std.mem.eql(u8, p, "/webmail/api/retention/preview")) return handleRetention(server, conn, arena, req, .preview);
    if (std.mem.eql(u8, p, "/webmail/api/retention/restore")) return handleRetention(server, conn, arena, req, .restore);
    if (std.mem.eql(u8, p, "/webmail/api/vacation")) return handleVacation(server, conn, arena, req);
    if (std.mem.eql(u8, p, "/webmail/api/compose") and std.mem.eql(u8, req.method, "POST")) {
        return handleCompose(server, conn, arena, req);
    }
    if (std.mem.eql(u8, p, "/webmail/api/drafts") and std.mem.eql(u8, req.method, "POST")) {
        return handleDraftSave(server, conn, arena, req);
    }
    if (std.mem.eql(u8, p, "/webmail/api/attachment") and std.mem.eql(u8, req.method, "GET")) {
        return handleAttachment(server, conn, arena, req);
    }
    if (std.mem.eql(u8, p, "/webmail/api/attachments") and std.mem.eql(u8, req.method, "GET")) {
        return handleAttachmentLibrary(server, conn, arena, req);
    }
    if (std.mem.eql(u8, p, "/webmail/api/folders") and std.mem.eql(u8, req.method, "GET")) {
        return handleFolders(server, conn, arena, req);
    }
    if (std.mem.startsWith(u8, p, "/webmail/api/messages/") and std.mem.eql(u8, req.method, "GET")) {
        return handleMessageDetail(server, conn, arena, req);
    }
    if (std.mem.startsWith(u8, p, "/webmail/api/messages/") and std.mem.eql(u8, req.method, "PUT")) {
        return handleMessageUpdate(server, conn, arena, req);
    }
    if (std.mem.startsWith(u8, p, "/webmail/api/messages/") and std.mem.eql(u8, req.method, "DELETE")) {
        return handleMessageDelete(server, conn, arena, req);
    }
    if (std.mem.eql(u8, p, "/webmail/api/messages") and std.mem.eql(u8, req.method, "GET")) {
        return handleMessageList(server, conn, arena, req);
    }
    if (std.mem.eql(u8, p, "/webmail/api/search") and std.mem.eql(u8, req.method, "GET")) {
        return handleSearch(server, conn, arena, req);
    }
    if (std.mem.eql(u8, p, mailbox_admin_path) and
        (std.mem.eql(u8, req.method, "GET") or std.mem.eql(u8, req.method, "POST")))
        return handleOperatorMailboxes(server, conn, arena, req);

    // ── SPA static assets (embedded) ─────────────────────────────────────────
    // The pages call /webmail/* on the same origin (no proxy in prod). The page
    // JS gates on /webmail/auth/me itself, so "/" can serve the inbox shell
    // unconditionally — an unauthenticated visitor is redirected client-side to
    // /login (and the shell starts hidden, so nothing leaks).
    if (std.mem.eql(u8, req.method, "GET")) {
        if (std.mem.eql(u8, p, "/")) {
            return serveAsset(conn, arena, index_html, "text/html; charset=utf-8");
        }
        if (std.mem.eql(u8, p, "/status")) {
            return serveAsset(conn, arena, status_html, "text/html; charset=utf-8");
        }
        if (std.mem.eql(u8, p, "/mailboxes") and server.config.operator_id != null) {
            if (!isSecureBrowserRequest(server, req))
                return sendError(conn, arena, 403, "https_required", "Use HTTPS to manage server mailboxes");
            return serveAsset(conn, arena, mailbox_admin_html, "text/html; charset=utf-8");
        }
        if (std.mem.eql(u8, p, "/calendar")) {
            return serveAsset(conn, arena, calendar_html, "text/html; charset=utf-8");
        }
        if (std.mem.eql(u8, p, "/shared")) {
            return serveAsset(conn, arena, shared_html, "text/html; charset=utf-8");
        }
        if (std.mem.eql(u8, p, "/combined")) {
            return serveAsset(conn, arena, combined_html, "text/html; charset=utf-8");
        }
        if (std.mem.eql(u8, p, "/snapshot")) {
            return serveAsset(conn, arena, snapshot_html, "text/html; charset=utf-8");
        }
        if (std.mem.eql(u8, p, "/file-link")) {
            return serveAsset(conn, arena, file_link_html, "text/html; charset=utf-8");
        }
        if (std.mem.eql(u8, p, "/login")) {
            return serveAsset(conn, arena, login_html, "text/html; charset=utf-8");
        }
        // One page asks for a link (/forgot) and spends it (/reset#token=...).
        if (std.mem.eql(u8, p, "/forgot") or std.mem.eql(u8, p, "/reset")) {
            return serveAsset(conn, arena, recover_html, "text/html; charset=utf-8");
        }
        if (std.mem.eql(u8, p, "/styles.css")) {
            return serveAsset(conn, arena, styles_css, "text/css; charset=utf-8");
        }
        if (std.mem.eql(u8, p, "/mail.webmanifest")) {
            return serveAsset(conn, arena, @embedFile("webmail_dist/mail.webmanifest"), "application/manifest+json; charset=utf-8");
        }
        inline for (.{ "mail-icon-192.png", "mail-icon-512.png", "mail-icon-maskable.png" }) |icon| {
            if (std.mem.eql(u8, p, "/" ++ icon))
                return serveAsset(conn, arena, @embedFile("webmail_dist/" ++ icon), "image/png");
        }
        if (std.mem.eql(u8, p, "/mail-notifications.js")) {
            return serveAsset(conn, arena, notifications_worker, "application/javascript; charset=utf-8");
        }
    }

    try sendError(conn, arena, 404, "not_found", "No such endpoint");
}

/// Serve an embedded static asset with sensible caching + security headers.
/// HTML is not cached (so a deploy is picked up immediately); CSS caches briefly.
fn serveAsset(conn: *webmail_tls.Stream, arena: std.mem.Allocator, body: []const u8, content_type: []const u8) !void {
    var resp: std.ArrayList(u8) = .empty;
    const w = jw(&resp, arena);
    try w.writeAll("HTTP/1.1 200 OK\r\n");
    try w.print("Content-Type: {s}\r\n", .{content_type});
    try w.print("Content-Length: {d}\r\n", .{body.len});
    try w.writeAll("X-Content-Type-Options: nosniff\r\n");
    try w.writeAll("X-Frame-Options: DENY\r\n");
    if (std.mem.indexOf(u8, content_type, "text/html") != null) {
        try w.writeAll("Cache-Control: no-cache\r\n");
        // A reset page carries its token in the URL fragment; no link on any
        // page should hand the URL to another site.
        try w.writeAll("Referrer-Policy: no-referrer\r\n");
    } else {
        try w.writeAll("Cache-Control: public, max-age=3600\r\n");
    }
    try w.writeAll("Connection: close\r\n\r\n");
    try w.writeAll(body);
    try writeAll(conn, resp.items);
}

/// Parse the :uid from a /webmail/api/messages/:uid path (ignores any query,
/// already stripped). Returns null on malformed input.
fn uidFromPath(path: []const u8) ?i64 {
    const prefix = "/webmail/api/messages/";
    if (!std.mem.startsWith(u8, path, prefix)) return null;
    const rest = path[prefix.len..];
    return std.fmt.parseInt(i64, rest, 10) catch null;
}

/// Resolve the authenticated session for a request, or send 401 and return null.
fn requireSession(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !?session_mod.Session {
    return resolveRequestSession(server, arena, req) catch |err| {
        switch (err) {
            error.AccountChanged => try sendError(conn, arena, 409, "account_changed", "The signed-in account changed. Reload this tab before continuing."),
            error.LinkedAccountUnavailable => try sendError(conn, arena, 403, "linked_account_unavailable", "This linked mailbox is no longer available."),
            error.Unauthorized => try sendError(conn, arena, 401, "unauthorized", "Invalid or expired session"),
            error.HostedReadOnly => try sendError(conn, arena, 403, "mailbox_read_only", "This mailbox is available for reading and export."),
            else => return err,
        }
        return null;
    };
}

fn resolveRequestSession(server: *WebmailHttpServer, a: std.mem.Allocator, req: Request) !session_mod.Session {
    const token = session_mod.parseSessionCookie(req.header("Cookie") orelse "") orelse return error.Unauthorized;
    var root = server.sessions.validate(token) catch return error.Unauthorized;
    errdefer root.deinit(server.allocator);
    const linked = req.queryParam(a, "linked") orelse {
        if (!try expectedAccountMatches(a, req, root.username)) return error.AccountChanged;
        try checkSessionWrite(server.db, req, root.username);
        return root;
    };
    if (!linkedRequestAllowed(req) or !message_refs.valid(linked)) return error.LinkedAccountUnavailable;
    const source = try account_links.resolve(a, server.db, root.session_id, linked, time_compat.timestamp());
    var session = server.sessions.validate(source.private_session) catch return error.LinkedAccountUnavailable;
    errdefer session.deinit(server.allocator);
    if (!std.mem.eql(u8, session.username, source.account.username)) return error.LinkedAccountUnavailable;
    if (!try expectedAccountMatches(a, req, session.username)) return error.AccountChanged;
    try checkSessionWrite(server.db, req, session.username);
    session.linked_id = try server.allocator.dupe(u8, linked);
    root.deinit(server.allocator);
    return session;
}

fn checkSessionWrite(db: *database.Database, req: Request, user: []const u8) !void {
    if (std.mem.eql(u8, req.method, "GET") or std.mem.eql(u8, req.method, "HEAD")) return;
    const access = try db.mailboxAccess(user);
    if (!access.readable()) return error.Unauthorized;
    const revoking_client_password = std.mem.eql(u8, req.method, "DELETE") and std.mem.startsWith(u8, req.path, client_password_path ++ "/");
    if (access == .read_only and !revoking_client_password) return error.HostedReadOnly;
}

// A linked account permits mail operations. Credential, team, calendar, link,
// and account-management routes continue to require their own browser login.
fn linkedRequestAllowed(req: Request) bool {
    const p = req.path;
    const get = std.mem.eql(u8, req.method, "GET");
    if (get) for ([_][]const u8{
        "/webmail/auth/me",         "/webmail/api/config",   "/webmail/api/folders",
        "/webmail/api/messages",    "/webmail/api/search",   "/webmail/api/attachment",
        "/webmail/api/attachments", "/webmail/api/contacts", "/webmail/api/compose-library",
        "/webmail/api/drafts",      "/webmail/api/outbox",   "/webmail/api/sender-identities",
    }) |allowed| {
        if (std.mem.eql(u8, p, allowed)) return true;
    };
    if (std.mem.eql(u8, req.method, "POST")) for ([_][]const u8{
        "/webmail/api/compose",                "/webmail/api/drafts", "/webmail/api/uploads", "/webmail/api/bulk",
        "/webmail/api/external-sender-review",
    }) |allowed| {
        if (std.mem.eql(u8, p, allowed)) return true;
    };
    if (std.mem.startsWith(u8, p, message_ref_prefix))
        return message_refs.valid(p[message_ref_prefix.len..]);
    if (uidFromPath(p) != null) return true;
    for ([_][]const u8{ "/webmail/api/outbox/", "/webmail/api/undo/", "/webmail/api/uploads/" }) |prefix| {
        if (std.mem.startsWith(u8, p, prefix)) return store.validId(p[prefix.len..]);
    }
    return false;
}

fn expectedAccountMatches(arena: std.mem.Allocator, req: Request, username: []const u8) !bool {
    const expected_header = if (req.header("X-Webmail-Account")) |encoded| try urlDecode(arena, encoded) else null;
    for ([_]?[]const u8{ expected_header, req.queryParam(arena, "account") }) |expected_account| {
        if (expected_account) |expected| if (!std.mem.eql(u8, expected, username)) return false;
    }
    return true;
}

fn combinedError(conn: *webmail_tls.Stream, a: std.mem.Allocator, err: anyerror) !void {
    return switch (err) {
        error.LinkedAccountUnavailable => sendError(conn, a, 403, "linked_account_unavailable", "This linked mailbox is no longer available."),
        error.AccountAlreadyLinked => sendError(conn, a, 409, "account_already_linked", "This mailbox is already in the combined inbox."),
        error.LinkedAccountLimit => sendError(conn, a, 409, "linked_account_limit", "This browser can link up to four other mailboxes."),
        else => mapServiceError(conn, a, err),
    };
}

fn handleCombinedAccounts(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request, id: ?[]const u8) !void {
    const get = std.mem.eql(u8, req.method, "GET");
    if (!get and !isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var root = (try requireSession(server, conn, a, req)) orelse return;
    defer root.deinit(server.allocator);
    if (id) |link| {
        if (!message_refs.valid(link)) return combinedError(conn, a, error.LinkedAccountUnavailable);
        account_links.remove(server.db, root.session_id, link) catch |err| return combinedError(conn, a, err);
    } else if (std.mem.eql(u8, req.method, "POST")) {
        const Credentials = struct { username: []const u8, password: []const u8 };
        if (req.body.len > 8192) return combinedError(conn, a, service_mod.ServiceError.InvalidPayload);
        const credentials = std.json.parseFromSliceLeaky(Credentials, a, req.body, .{}) catch
            return combinedError(conn, a, service_mod.ServiceError.InvalidPayload);
        if (credentials.username.len == 0 or credentials.username.len > 320 or credentials.password.len == 0 or credentials.password.len > 1024)
            return combinedError(conn, a, service_mod.ServiceError.InvalidPayload);
        const link = try store.newId(a);
        const ip = if (req.trust_forwarded_headers) req.header("X-Real-IP") orelse conn.peerIp() else conn.peerIp();
        const attempt = (server.login_limiter.beginAuthAttempt(ip) catch null) orelse
            return sendError(conn, a, 429, "rate_limited", "Too many sign-in attempts. Try again later.");
        var source = server.sessions.login(credentials.username, credentials.password, ip, req.header("User-Agent")) catch |err| switch (err) {
            error.AuthenticationRateLimited => return sendError(conn, a, 429, "rate_limited", "Too many sign-in attempts. Try again later."),
            session_mod.SessionError.InvalidCredentials => return sendError(conn, a, 403, "invalid_credentials", "The linked mailbox username or password is incorrect."),
            else => return err,
        };
        defer source.deinit(server.allocator);
        server.login_limiter.finishAuthSuccess(ip, attempt);
        if (std.mem.eql(u8, root.username, source.username)) {
            server.sessions.logout(source.session_id);
            return combinedError(conn, a, error.AccountAlreadyLinked);
        }
        account_links.create(server.db, root.session_id, source.session_id, link, time_compat.timestamp()) catch |err| {
            server.sessions.logout(source.session_id);
            return combinedError(conn, a, err);
        };
    } else if (!get) return sendError(conn, a, 405, "method_not_allowed", "Use GET or POST.");
    const accounts = try account_links.list(a, server.db, root.session_id, time_compat.timestamp());
    return sendJson(conn, a, 200, try service_mod.json(a, .{
        .owner = account_links.Account{ .id = "", .username = root.username, .address = root.email },
        .accounts = accounts,
    }), null);
}

const CombinedRow = struct {
    source: account_links.Account,
    message: maildir.MessageSummary,

    fn before(_: void, left: CombinedRow, right: CombinedRow) bool {
        if (left.message.timestamp == right.message.timestamp) {
            const order = std.mem.order(u8, left.source.username, right.source.username);
            if (order != .eq) return order == .lt;
        }
        return maildir.messagePosition(left.message).before(maildir.messagePosition(right.message));
    }
};

fn handleCombinedMessages(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    var root = (try requireSession(server, conn, a, req)) orelse return;
    defer root.deinit(server.allocator);
    const linked = try account_links.list(a, server.db, root.session_id, time_compat.timestamp());
    const owner: account_links.Account = .{ .id = "", .username = root.username, .address = root.email };
    const sources = try std.mem.concat(a, account_links.Account, &.{ &.{owner}, linked });
    const location = req.queryParam(a, "scope") orelse "inbox";
    const folder = if (std.mem.eql(u8, location, "mail")) "*" else if (std.mem.eql(u8, location, "inbox")) "INBOX" else return sendError(conn, a, 400, "bad_request", "Choose Inbox or All folders.");
    var options = searchFilters(req, a, folder) catch |err| return searchFilterError(conn, a, err);
    var rows: std.ArrayList(CombinedRow) = .empty;
    var progress: search_index.Progress = .{};
    options.include_versions = true;
    for (sources) |source| {
        const workflow = if (attention.isInboxView(folder)) try attention.load(a, server.db, source.username) else null;
        var current = options;
        var source_progress: search_index.Progress = .{};
        current.index_progress = &source_progress;
        current.attention_snapshot = if (workflow != null and workflow.?.hasHidden()) workflow else null;
        const messages = try maildir.queryMessages(a, server.db, source.username, current);
        for (messages) |message| {
            if (message.flags.deleted or (!maildir.isPersonalFolder(message.folder) and !std.ascii.eqlIgnoreCase(message.folder, "Drafts"))) continue;
            try rows.append(a, .{ .source = source, .message = message });
        }
        progress.indexed += source_progress.indexed;
        progress.total += source_progress.total;
    }
    std.mem.sort(CombinedRow, rows.items, {}, CombinedRow.before);
    const per_page = std.math.clamp(parseUintParam(req, a, "per_page", server.config.messages_per_page), 1, 100);
    const page = std.math.clamp(parseUintParam(req, a, "page", 1), 1, @max((rows.items.len + per_page - 1) / per_page, 1));
    const start = (page - 1) * per_page;
    const end = @min(start + per_page, rows.items.len);
    var body: std.ArrayList(u8) = .empty;
    const w = jw(&body, a);
    try w.print("{{\"page\":{d},\"total\":{d},\"more\":{},\"index\":", .{ page, rows.items.len, end < rows.items.len });
    try writeSearchIndex(w, progress);
    try w.writeAll(",\"items\":[");
    for (rows.items[start..end], 0..) |row, index| {
        if (index != 0) try w.writeAll(",");
        try w.writeAll("{\"source\":");
        try w.writeAll(try service_mod.json(a, row.source));
        try w.writeAll(",\"message\":");
        try writeMessageSummary(w, row.message, try maildir.summaryVersion(a, server.db, row.source.username, row.message));
        try w.writeAll("}");
    }
    try w.writeAll("]}");
    // A read made while an account was removed cannot publish its old results.
    for (linked) |source| {
        _ = account_links.resolve(a, server.db, root.session_id, source.id, time_compat.timestamp()) catch |err|
            return combinedError(conn, a, err);
    }
    return sendJson(conn, a, 200, body.items, null);
}

fn handleCombinedAction(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var root = (try requireSession(server, conn, a, req)) orelse return;
    defer root.deinit(server.allocator);
    const Selection = struct { account: []const u8, reference: []const u8, revision: []const u8 };
    const Change = struct { action: enum { read, unread, archive, trash, flag, unflag }, messages: []const Selection };
    if (req.body.len > 32 * 1024) return combinedError(conn, a, service_mod.ServiceError.InvalidPayload);
    const change = std.json.parseFromSliceLeaky(Change, a, req.body, .{}) catch
        return combinedError(conn, a, service_mod.ServiceError.InvalidPayload);
    if (change.messages.len == 0 or change.messages.len > 100) return combinedError(conn, a, service_mod.ServiceError.InvalidPayload);
    const Group = struct { username: []const u8, batch: std.ArrayList(service_mod.MessageRef) = .empty };
    var groups: std.StringArrayHashMapUnmanaged(Group) = .empty;
    const now = time_compat.timestamp();
    for (change.messages) |message| {
        if (!message_refs.valid(message.reference) or message.revision.len != 66)
            return combinedError(conn, a, service_mod.ServiceError.InvalidPayload);
        const entry = try groups.getOrPut(a, message.account);
        if (!entry.found_existing) {
            const username = if (message.account.len == 0) root.username else blk: {
                if (!message_refs.valid(message.account)) return combinedError(conn, a, error.LinkedAccountUnavailable);
                const source = account_links.resolve(a, server.db, root.session_id, message.account, now) catch |err|
                    return combinedError(conn, a, err);
                break :blk source.account.username;
            };
            entry.value_ptr.* = .{ .username = username };
        }
        for (entry.value_ptr.batch.items) |previous| {
            if (std.mem.eql(u8, previous.reference.?, message.reference)) return combinedError(conn, a, service_mod.ServiceError.InvalidPayload);
        }
        try entry.value_ptr.batch.append(a, .{ .uid = 0, .folder = "", .reference = message.reference, .revision = message.revision });
    }
    const action: service_mod.BulkAction = switch (change.action) {
        .read => .read,
        .unread => .unread,
        .archive => .move,
        .trash => .trash,
        .flag => .flag,
        .unflag => .unflag,
    };
    const Report = struct { account: []const u8, affected: usize, error_code: ?[]const u8 = null };
    var reports: std.ArrayList(Report) = .empty;
    for (groups.keys(), groups.values()) |account, group| {
        if (account.len > 0) {
            _ = account_links.resolve(a, server.db, root.session_id, account, time_compat.timestamp()) catch {
                try reports.append(a, .{ .account = account, .affected = 0, .error_code = "linked_account_unavailable" });
                continue;
            };
        }
        const result = server.service.bulk(a, group.username, .{ .action = action, .messages = group.batch.items }, now) catch |err| {
            try reports.append(a, .{ .account = account, .affected = 0, .error_code = @errorName(err) });
            continue;
        };
        var affected: usize = 0;
        for (result.results) |item| affected += @intFromBool(item.ok);
        try reports.append(a, .{ .account = account, .affected = affected, .error_code = if (result.ok) null else "message_changed" });
    }
    return sendJson(conn, a, 200, try service_mod.json(a, .{ .items = reports.items }), null);
}

// ── Handlers ─────────────────────────────────────────────────────────────────

fn handleHostedSignIn(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    const origin = server.config.hosted_sign_in_origin orelse
        return sendError(conn, arena, 404, "not_found", "Hosted sign-in is unavailable");
    if (!std.mem.eql(u8, origin, req.header("Origin") orelse ""))
        return sendError(conn, arena, 403, "forbidden", "Start from the Mail website");
    if (!std.mem.eql(u8, req.header("Content-Type") orelse "", "application/x-www-form-urlencoded") or
        req.query.len != 0 or !std.mem.startsWith(u8, req.body, "proof="))
        return sendError(conn, arena, 400, "bad_request", "Invalid sign-in form");
    const proof = req.body["proof=".len..];
    if (proof.len != session_mod.token_hex_len)
        return sendError(conn, arena, 400, "bad_request", "Invalid sign-in form");
    for (proof) |byte| if (!std.ascii.isHex(byte))
        return sendError(conn, arena, 400, "bad_request", "Invalid sign-in form");

    const session = try session_mod.generateToken(arena);
    const csrf = try session_mod.generateToken(arena);
    const previous = if (req.header("Cookie")) |cookie| session_mod.parseSessionCookie(cookie) else null;
    const now = time_compat.timestamp();
    const cookie = try server.sessions.buildSetCookie(session);
    defer server.allocator.free(cookie);
    const redirect = try std.fmt.allocPrint(arena, "HTTP/1.1 303 See Other\r\nLocation: /\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nSet-Cookie: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", .{cookie});
    const ip = if (req.trust_forwarded_headers) req.header("X-Real-IP") orelse conn.peerIp() else conn.peerIp();
    const attempt = (server.login_limiter.beginAuthAttempt(ip) catch null) orelse
        return sendError(conn, arena, 429, "rate_limited", "Too many login attempts; try again later");
    hosted_sign_in.exchange(server.db, proof, session, csrf, previous, now, now + server.sessions.idle_ttl_seconds) catch |err| {
        if (err == error.InvalidProof) return sendError(conn, arena, 401, "invalid_proof", "This sign-in has expired or was already used. Start again from the Mail website.");
        logger.err("Hosted webmail sign-in failed: {}", .{err});
        return sendError(conn, arena, 503, "sign_in_unavailable", "Sign-in is temporarily unavailable");
    };
    server.login_limiter.finishAuthSuccess(ip, attempt);
    try writeAll(conn, redirect);
}

fn handleLogin(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    const ip = if (req.trust_forwarded_headers) req.header("X-Real-IP") orelse conn.peerIp() else conn.peerIp();

    const username = (try jsonStringFieldAlloc(arena, req.body, "username")) orelse {
        return sendError(conn, arena, 400, "bad_request", "Missing username");
    };
    const password = (try jsonStringFieldAlloc(arena, req.body, "password")) orelse {
        return sendError(conn, arena, 400, "bad_request", "Missing password");
    };

    // Retain the configured webmail cap as well as the shared backend cap.
    // Both reserve before verification and refund a successful login.
    const attempt = (server.login_limiter.beginAuthAttempt(ip) catch null) orelse
        return sendError(conn, arena, 429, "rate_limited", "Too many login attempts; try again later");
    const ua = req.header("User-Agent");

    var sess = server.sessions.login(username, password, if (ip.len > 0) ip else null, ua) catch |err| {
        if (err == error.AuthenticationRateLimited)
            return sendError(conn, arena, 429, "rate_limited", "Too many login attempts; try again later");
        if (err == session_mod.SessionError.InvalidCredentials) {
            logger.warn("Webmail login failed for {s} from {s}", .{ username, ip });
            return sendError(conn, arena, 401, "invalid_credentials", "Invalid username or password");
        }
        return sendError(conn, arena, 500, "server_error", "Login failed");
    };
    defer sess.deinit(server.allocator);
    server.login_limiter.finishAuthSuccess(ip, attempt);

    logger.info("Webmail login: {s} from {s}", .{ sess.username, ip });

    const cookie = try server.sessions.buildSetCookie(sess.session_id);
    defer server.allocator.free(cookie);

    var body: std.ArrayList(u8) = .empty;
    const w = jw(&body, arena);
    try w.writeAll("{\"user\":{\"username\":");
    try writeJsonString(w, sess.username);
    try w.writeAll(",\"email\":");
    try writeJsonString(w, sess.email);
    try w.writeAll("},\"csrf_token\":");
    try writeJsonString(w, sess.csrf_secret);
    try w.writeAll("}");

    try sendJson(conn, arena, 200, body.items, cookie);
}

fn handleLogout(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    // CSRF guard: logout is state-changing. SameSite=Lax allows top-level
    // cross-origin POSTs, so reject when an Origin/Referer is present and does
    // not match the Host. (Full per-action CSRF tokens land in Phase 5.)
    if (!isSameOrigin(req)) {
        return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    }
    if (req.header("Cookie")) |cookie| {
        if (session_mod.parseSessionCookie(cookie)) |token| {
            if (req.header("X-Webmail-Account") != null or req.queryParam(arena, "account") != null) {
                if (server.sessions.validate(token) catch null) |active| {
                    var session = active;
                    defer session.deinit(server.allocator);
                    if (!try expectedAccountMatches(arena, req, session.username))
                        return sendError(conn, arena, 409, "account_changed", "The signed-in account changed. Reload this tab before continuing.");
                }
            }
            server.sessions.logout(token);
        }
    }
    const clear = try server.sessions.buildClearCookie();
    try sendJson(conn, arena, 200, "{\"ok\":true}", clear);
}

/// Same-origin check for state-changing requests. If neither Origin nor Referer
/// is present (e.g. a non-browser client), allow. If present, the authority must
/// match the Host header. Conservative: an Origin/Referer we can't parse fails.
fn isSameOrigin(req: Request) bool {
    // A gateway rewrites Host to its upstream. Compare the original authority
    // only when the listener and connection are both trusted loopback peers.
    const host = (if (req.trust_forwarded_headers) req.header("X-Forwarded-Host") orelse req.header("Host") else req.header("Host")) orelse return false;
    if (req.header("Origin")) |origin| {
        return std.mem.eql(u8, authorityOf(origin), host);
    }
    if (req.header("Referer")) |referer| {
        return std.mem.eql(u8, authorityOf(referer), host);
    }
    return true; // neither header present
}

/// Strip scheme and path from a URL, leaving host[:port]. "http://a:8/x" -> "a:8".
fn authorityOf(url: []const u8) []const u8 {
    var rest = url;
    if (std.mem.indexOf(u8, rest, "://")) |i| rest = rest[i + 3 ..];
    if (std.mem.indexOfScalar(u8, rest, '/')) |i| rest = rest[0..i];
    return rest;
}

/// Change the shared IMAP/SMTP/webmail password, then revoke browser sessions.
fn handlePasswordChange(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const current = (try jsonStringFieldAlloc(arena, req.body, "currentPassword")) orelse return sendError(conn, arena, 400, "bad_request", "Missing current password");
    const next = (try jsonStringFieldAlloc(arena, req.body, "newPassword")) orelse return sendError(conn, arena, 400, "bad_request", "Missing new password");
    if (next.len < 12 or next.len > 1024) return sendError(conn, arena, 400, "bad_request", "Use a password between 12 and 1024 characters");
    const key = try std.fmt.allocPrint(arena, "password:{s}", .{sess.username});
    if (!try server.login_limiter.checkAndIncrementUser(key)) return sendError(conn, arena, 429, "rate_limited", "Too many attempts. Please wait five minutes");
    if (!try server.auth.verifyCredentials(sess.username, current)) return sendError(conn, arena, 400, "invalid_credentials", "Current password is incorrect");
    try server.auth.changePassword(sess.username, next);
    const ip = if (req.trust_forwarded_headers) req.header("X-Real-IP") orelse conn.peerIp() else conn.peerIp();
    logger.info("Webmail password changed for {s} from {s}", .{ sess.username, ip });
    const clear = try server.sessions.buildClearCookie();
    try sendJson(conn, arena, 200, "{\"ok\":true}", clear);
}

fn handleHealth(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    return sendJson(conn, arena, 200, try health.response(arena, time_compat.timestamp()), null);
}

fn handleMe(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);

    var body: std.ArrayList(u8) = .empty;
    const w = jw(&body, arena);
    try w.writeAll("{\"user\":{\"username\":");
    try writeJsonString(w, sess.username);
    try w.writeAll(",\"email\":");
    try writeJsonString(w, sess.email);
    if (operatorSession(server, req, sess)) |operator| {
        if (mailbox_operator.canManage(server.db, operator) catch false)
            try w.writeAll(",\"can_manage_mailboxes\":true");
    }
    try w.writeAll("}}");
    try sendJson(conn, arena, 200, body.items, null);
}

// ── Password reset and recovery address ─────────────────────────────────────

fn clientIp(req: Request, conn: *webmail_tls.Stream) []const u8 {
    return if (req.trust_forwarded_headers) req.header("X-Real-IP") orelse conn.peerIp() else conn.peerIp();
}

/// The authority the browser used, as isSameOrigin reads it.
fn requestHost(req: Request) ?[]const u8 {
    return if (req.trust_forwarded_headers) req.header("X-Forwarded-Host") orelse req.header("Host") else req.header("Host");
}

/// Links point at https whenever the browser is on https: direct TLS here, or
/// a TLS gateway in front of a listener that sets Secure cookies.
fn publicHttps(server: *const WebmailHttpServer) bool {
    return server.config.enable_tls or server.config.secure_cookies;
}

const SystemMail = struct {
    server: *WebmailHttpServer,
    arena: std.heap.ArenaAllocator,
    message: compose.Message,
    what: []const u8,
    about: []const u8,
};

/// Deliver a server-written message off the request thread, so a reset
/// request is answered in the same time whether or not anything is sent, and
/// a slow remote MX cannot hold a connection open. Counted as an active
/// connection so shutdown waits for it. Takes ownership of `job_arena`, which
/// must hold every byte `message` points at.
fn dispatchSystemMail(server: *WebmailHttpServer, job_arena: std.heap.ArenaAllocator, message: compose.Message, what: []const u8, about: []const u8) void {
    var owned = job_arena;
    const job = std.heap.page_allocator.create(SystemMail) catch {
        owned.deinit();
        logger.err("Webmail {s} for {s} not sent: out of memory", .{ what, about });
        return;
    };
    job.* = .{ .server = server, .arena = owned, .message = message, .what = what, .about = about };
    _ = server.active_connections.fetchAdd(1, .monotonic);
    const thread = std.Thread.spawn(.{}, systemMailThread, .{job}) catch |err| {
        _ = server.active_connections.fetchSub(1, .release);
        logger.err("Webmail {s} for {s} not sent: {}", .{ what, about, err });
        job.arena.deinit();
        std.heap.page_allocator.destroy(job);
        return;
    };
    thread.detach();
}

fn systemMailThread(job: *SystemMail) void {
    const server = job.server;
    defer {
        job.arena.deinit();
        std.heap.page_allocator.destroy(job);
        _ = server.active_connections.fetchSub(1, .release);
    }
    const cfg = compose.SendConfig{
        .hostname = server.config.hostname,
        .delivery_method = server.config.delivery_method,
        .ses_region = server.config.ses_region,
        .sender_user = "",
        .mail_config = server.config.mail_config,
        .auth = server.auth,
    };
    compose.deliverSystem(job.arena.allocator(), job.message, cfg) catch |err| {
        logger.warn("Webmail {s} for {s} could not be delivered: {}", .{ job.what, job.about, err });
        return;
    };
    logger.info("Webmail {s} for {s} delivered", .{ job.what, job.about });
}

const reset_accepted = "{\"ok\":true}";

/// A server-written message plus the mailbox it is about, both in a job arena.
const Built = struct { message: compose.Message, about: []const u8 };

/// POST /webmail/auth/forgot {address}
///
/// Always answers {ok:true}, whether or not the mailbox exists, has a recovery
/// address, or was sent anything: the answer must not tell anyone which
/// mailboxes exist. The link goes to the recovery address, never to the
/// requester, and is sent from another thread so timing tells nothing either.
fn handleForgot(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    const ip = clientIp(req, conn);
    if (ip.len > 0 and !(server.reset_limiter.checkAndIncrement(ip) catch true)) {
        logger.warn("Webmail password reset requests rate-limited for {s}", .{ip});
        return sendError(conn, arena, 429, "rate_limited", "Too many requests. Please wait a few minutes.");
    }
    const raw = (try jsonStringFieldAlloc(arena, req.body, "address")) orelse return sendError(conn, arena, 400, "bad_request", "Enter your mailbox address");
    const address = std.mem.trim(u8, raw, " \t\r\n");
    if (address.len == 0 or address.len > 320) return sendError(conn, arena, 400, "bad_request", "Enter your mailbox address");
    for (address) |c| if (c <= 0x20 or c == 0x7f) return sendError(conn, arena, 400, "bad_request", "Enter your mailbox address");

    const username = try server.auth.canonicalUsername(address, arena);
    const result = recovery.issue(arena, server.db, username, if (ip.len > 0) ip else null, time_compat.timestamp()) catch |err| {
        logger.err("Webmail password reset for {s} failed: {}", .{ username, err });
        return sendJson(conn, arena, 200, reset_accepted, null);
    };
    switch (result) {
        .issued => |issued| {
            var job = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            const ja = job.allocator();
            const message: ?Built = blk: {
                const about = ja.dupe(u8, username) catch break :blk null;
                const base = recovery.linkBase(ja, requestHost(req), about, server.config.hostname, publicHttps(server)) catch break :blk null;
                const link = recovery.resetLink(ja, base, &issued.token) catch break :blk null;
                const built = recovery.resetMessage(ja, .{
                    .username = about,
                    .recovery = ja.dupe(u8, issued.recovery) catch break :blk null,
                    .link = link,
                    .ip = if (ip.len > 0) (ja.dupe(u8, ip) catch null) else null,
                    .hostname = server.config.hostname,
                }) catch break :blk null;
                break :blk .{ .message = built, .about = about };
            };
            if (message) |m| {
                logger.info("Webmail password reset link requested for {s} from {s}", .{ username, ip });
                dispatchSystemMail(server, job, m.message, "password reset link", m.about);
            } else {
                job.deinit();
                logger.err("Webmail password reset link for {s} could not be built", .{username});
            }
        },
        else => logger.info("Webmail password reset requested for {s} from {s}: nothing sent ({s})", .{ username, ip, @tagName(result) }),
    }
    return sendJson(conn, arena, 200, reset_accepted, null);
}

fn resetTokenAllowed(server: *WebmailHttpServer, arena: std.mem.Allocator, req: Request, conn: *webmail_tls.Stream) !bool {
    const ip = clientIp(req, conn);
    if (ip.len == 0) return true;
    const key = try std.fmt.allocPrint(arena, "token:{s}", .{ip});
    return server.reset_limiter.checkAndIncrementUser(key) catch true;
}

const invalid_token_message = "This reset link is invalid, already used or expired. Ask for a new one.";

/// POST /webmail/auth/reset/verify {token} -> {ok, account}
/// Lets the reset page say which mailbox it is for before asking for a
/// password. Does not spend the token.
fn handleResetVerify(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    if (!try resetTokenAllowed(server, arena, req, conn)) return sendError(conn, arena, 429, "rate_limited", "Too many attempts. Please wait a few minutes.");
    const token = (try jsonStringFieldAlloc(arena, req.body, "token")) orelse return sendError(conn, arena, 400, "invalid_token", invalid_token_message);
    const account = (recovery.lookup(arena, server.db, token, time_compat.timestamp()) catch {
        return sendError(conn, arena, 500, "server_error", "Could not check this link");
    }) orelse return sendError(conn, arena, 400, "invalid_token", invalid_token_message);
    var body: std.ArrayList(u8) = .empty;
    const w = jw(&body, arena);
    try w.writeAll("{\"ok\":true,\"account\":");
    try writeJsonString(w, account);
    try w.writeAll("}");
    try sendJson(conn, arena, 200, body.items, null);
}

/// POST /webmail/auth/reset {token, password}
/// Spends the token, sets the password (webmail, IMAP and SMTP share it),
/// signs out every session of that mailbox, and tells the recovery address.
fn handleResetComplete(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    if (!try resetTokenAllowed(server, arena, req, conn)) return sendError(conn, arena, 429, "rate_limited", "Too many attempts. Please wait a few minutes.");
    const token = (try jsonStringFieldAlloc(arena, req.body, "token")) orelse return sendError(conn, arena, 400, "invalid_token", invalid_token_message);
    const password = (try jsonStringFieldAlloc(arena, req.body, "password")) orelse return sendError(conn, arena, 400, "bad_request", "Missing new password");
    if (password.len < recovery.min_password_len or password.len > recovery.max_password_len)
        return sendError(conn, arena, 400, "bad_request", "Use a password between 12 and 1024 characters");
    const done = (recovery.complete(arena, server.db, server.auth, token, password, time_compat.timestamp()) catch |err| {
        logger.err("Webmail password reset could not be completed: {}", .{err});
        return sendError(conn, arena, 500, "server_error", "The password could not be changed. Please try again.");
    }) orelse return sendError(conn, arena, 400, "invalid_token", invalid_token_message);

    logger.info("Webmail password reset completed for {s} from {s}", .{ done.username, clientIp(req, conn) });

    var job = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const ja = job.allocator();
    const notice: ?Built = blk: {
        const about = ja.dupe(u8, done.username) catch break :blk null;
        const to = ja.dupe(u8, done.recovery) catch break :blk null;
        const built = recovery.passwordResetNotice(ja, about, to, server.config.hostname) catch break :blk null;
        break :blk .{ .message = built, .about = about };
    };
    if (notice) |n| dispatchSystemMail(server, job, n.message, "password reset notice", n.about) else job.deinit();

    var body: std.ArrayList(u8) = .empty;
    const w = jw(&body, arena);
    try w.writeAll("{\"ok\":true,\"account\":");
    try writeJsonString(w, done.username);
    try w.writeAll("}");
    try sendJson(conn, arena, 200, body.items, try server.sessions.buildClearCookie());
}

fn writeRecovery(w: anytype, current: ?recovery.Recovery) !void {
    try w.writeAll("{\"recovery\":");
    if (current) |r| {
        if (r.address) |address| try writeJsonString(w, address) else try w.writeAll("null");
        try w.writeAll(",\"setBy\":");
        if (r.address != null and r.source != null) try writeJsonString(w, @tagName(r.source.?)) else try w.writeAll("null");
    } else try w.writeAll("null,\"setBy\":null");
    try w.writeAll("}");
}

/// GET /webmail/auth/recovery -> {recovery, setBy}
fn handleRecoveryGet(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const current = recovery.get(arena, server.db, sess.username) catch return sendError(conn, arena, 500, "server_error", "Could not read the recovery address");
    var body: std.ArrayList(u8) = .empty;
    try writeRecovery(jw(&body, arena), current);
    try sendJson(conn, arena, 200, body.items, null);
}

/// PUT /webmail/auth/recovery {currentPassword, recovery}
/// Re-authenticates with the mailbox password: a borrowed session must not be
/// enough to redirect the account's reset links. An empty `recovery` removes
/// it. The previous address, if any, is told about the change.
fn handleRecoveryUpdate(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const current_password = (try jsonStringFieldAlloc(arena, req.body, "currentPassword")) orelse return sendError(conn, arena, 400, "bad_request", "Enter your current password");
    const wanted_raw = (try jsonStringFieldAlloc(arena, req.body, "recovery")) orelse return sendError(conn, arena, 400, "bad_request", "Missing recovery address");
    const key = try std.fmt.allocPrint(arena, "recovery:{s}", .{sess.username});
    if (!try server.login_limiter.checkAndIncrementUser(key)) return sendError(conn, arena, 429, "rate_limited", "Too many attempts. Please wait five minutes");
    if (!try server.auth.verifyCredentials(sess.username, current_password)) return sendError(conn, arena, 400, "invalid_credentials", "Current password is incorrect");

    const trimmed = std.mem.trim(u8, wanted_raw, " \t\r\n");
    const wanted: ?[]const u8 = if (trimmed.len == 0) null else recovery.validateAddress(sess.username, trimmed) catch |err| return switch (err) {
        recovery.RecoveryError.SameAsMailbox => sendError(conn, arena, 400, "bad_request", "Use an address outside this mailbox: a reset link sent here could not be read without the password"),
        else => sendError(conn, arena, 400, "bad_request", "Enter a valid email address"),
    };

    const previous = recovery.get(arena, server.db, sess.username) catch return sendError(conn, arena, 500, "server_error", "Could not read the recovery address");
    recovery.set(server.db, sess.username, wanted, .user, time_compat.timestamp()) catch |err| {
        logger.err("Webmail recovery address update for {s} failed: {}", .{ sess.username, err });
        return sendError(conn, arena, 500, "server_error", "Could not save the recovery address");
    };
    logger.info("Webmail recovery address {s} for {s} from {s}", .{ if (wanted == null) "removed" else "changed", sess.username, clientIp(req, conn) });

    const old: ?[]const u8 = if (previous) |p| p.address else null;
    if (old) |old_address| {
        const same = if (wanted) |w| std.ascii.eqlIgnoreCase(w, old_address) else false;
        if (!same) {
            var job = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            const ja = job.allocator();
            const notice: ?Built = blk: {
                const about = ja.dupe(u8, sess.username) catch break :blk null;
                const to = ja.dupe(u8, old_address) catch break :blk null;
                const built = recovery.recoveryChangedNotice(ja, about, to, server.config.hostname) catch break :blk null;
                break :blk .{ .message = built, .about = about };
            };
            if (notice) |n| dispatchSystemMail(server, job, n.message, "recovery address change notice", n.about) else job.deinit();
        }
    }

    const now_value = recovery.get(arena, server.db, sess.username) catch null;
    var body: std.ArrayList(u8) = .empty;
    try writeRecovery(jw(&body, arena), now_value);
    try sendJson(conn, arena, 200, body.items, null);
}

const ForwardingChange = struct {
    action: enum { request, confirm, cancel, disable, scope },
    revision: i64,
    address: ?[]const u8 = null,
    currentPassword: ?[]const u8 = null,
    code: ?[]const u8 = null,
    scope: ?database.Database.ForwardScope = null,
};

fn forwardScopeAddress(opt: ?[]const u8) !?[]const u8 {
    const address = std.mem.trim(u8, opt orelse return null, " \t");
    if (address.len > 254 or !std.unicode.utf8ValidateSlice(address) or !message_submission.validMailbox(address))
        return error.InvalidForwardScope;
    return address;
}

fn forwardingScope(change: ForwardingChange) !?database.Database.ForwardScope {
    const scope = change.scope orelse return if (change.action == .scope) error.InvalidForwardScope else null;
    if (change.action != .scope and change.action != .confirm) return error.InvalidForwardScope;
    return .{
        .sender = try forwardScopeAddress(scope.sender),
        .recipient = try forwardScopeAddress(scope.recipient),
    };
}

fn handleForwarding(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    const get = std.mem.eql(u8, req.method, "GET");
    if (!get and !std.mem.eql(u8, req.method, "POST")) return sendError(conn, a, 405, "method_not_allowed", "Use GET or POST");
    if (!get and !isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var session = (try requireSession(server, conn, a, req)) orelse return;
    defer session.deinit(server.allocator);
    if (!get) {
        const change = std.json.parseFromSliceLeaky(ForwardingChange, a, req.body, .{}) catch
            return sendError(conn, a, 400, "bad_request", "Invalid forwarding settings");
        if (change.revision < 0) return sendError(conn, a, 400, "bad_request", "Invalid forwarding revision");
        const scope = forwardingScope(change) catch |err| return forwardingError(conn, a, err);
        if (change.action == .request or change.action == .disable or change.action == .scope) {
            const password = change.currentPassword orelse "";
            if (password.len == 0 or password.len > recovery.max_password_len)
                return sendError(conn, a, 400, "invalid_credentials", "Enter your current password");
            const limit_key = try std.fmt.allocPrint(a, "forwarding:{s}", .{session.username});
            if (!try server.login_limiter.checkAndIncrementUser(limit_key)) return forwardingError(conn, a, error.ForwardRateLimited);
            if (!try server.auth.verifyCredentials(session.username, password))
                return sendError(conn, a, 400, "invalid_credentials", "Current password is incorrect");
        }
        switch (change.action) {
            .request => {
                const address = recovery.validateAddress(session.username, change.address orelse "") catch
                    return sendError(conn, a, 400, "invalid_address", "Enter a different mailbox address");
                const destination = resolveForwardDestination(server, a, session.username, address) catch |err|
                    return forwardingError(conn, a, err);
                requestForwardCode(server, session.username, destination, change.revision) catch |err|
                    return forwardingError(conn, a, err);
            },
            .confirm => {
                const code = std.mem.trim(u8, change.code orelse "", " \r\n\t");
                if (code.len != 32) return forwardingError(conn, a, error.InvalidForwardCode);
                for (code) |byte| if (!std.ascii.isHex(byte)) return forwardingError(conn, a, error.InvalidForwardCode);
                const normalized = try std.ascii.allocLowerString(a, code);
                const confirmed = server.db.confirmForwardRequest(a, session.username, change.revision, hashForwardCode(normalized), time_compat.timestamp(), scope) catch |err|
                    return forwardingError(conn, a, err);
                if (!confirmed) return forwardingError(conn, a, error.InvalidForwardCode);
            },
            .cancel, .disable => server.db.clearForwarding(session.username, change.revision, change.action == .cancel) catch |err|
                return forwardingError(conn, a, err),
            .scope => server.db.setForwardingScope(session.username, change.revision, scope.?) catch |err|
                return forwardingError(conn, a, err),
        }
    }
    const settings = try server.db.forwardingSettings(a, session.username);
    return sendJson(conn, a, 200, try service_mod.json(a, settings), null);
}

fn resolveForwardDestination(server: *WebmailHttpServer, a: std.mem.Allocator, user: []const u8, address: []const u8) !database.Database.ForwardDestination {
    const cfg = server.config;
    if (!local_routing.isLocal(address, cfg.hostname, cfg.mail_config)) return .{ .address = address, .mailbox_id = null };
    const mailbox = local_routing.resolveMailbox(a, server.db, cfg.mail_config, address) catch |err| switch (err) {
        error.UnknownLocalMailbox => return error.InvalidForwardDestination,
        else => return err,
    };
    if (std.mem.eql(u8, mailbox, user)) return error.InvalidForwardDestination;
    const id = (try server.db.enabledMailboxId(mailbox)) orelse return error.InvalidForwardDestination;
    return .{ .address = address, .mailbox_id = id };
}

fn hashForwardCode(code: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(code, &digest, .{});
    return digest;
}

fn requestForwardCode(server: *WebmailHttpServer, user: []const u8, destination: database.Database.ForwardDestination, revision: i64) !void {
    var job = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    errdefer job.deinit();
    const a = job.allocator();
    var entropy: [16]u8 = undefined;
    io_compat.randomBytes(&entropy);
    const code = std.fmt.bytesToHex(entropy, .lower);
    const owner = try a.dupe(u8, user);
    const to = try a.alloc([]const u8, 1);
    to[0] = try a.dupe(u8, destination.address);
    const message: compose.Message = .{
        .from = try recovery.senderFor(a, user, server.config.hostname),
        .to = to,
        .subject = "Confirm mail forwarding",
        .text_body = try std.fmt.allocPrint(a,
            \\Someone requested to forward mail from {s} to this address.
            \\
            \\To confirm, enter this code in the source mailbox's Account settings within 30 minutes:
            \\
            \\{s}
            \\
            \\If you did not request this, you can ignore this message.
        , .{ user, code }),
        .auto_submitted = true,
        .notice_recipient_id = destination.mailbox_id,
    };
    const now = time_compat.timestamp();
    try server.db.startForwardRequest(user, revision, .{ .destination = destination, .hash = hashForwardCode(&code), .now = now, .expires = now + 30 * 60 });
    dispatchSystemMail(server, job, message, "forwarding verification code", owner);
}

fn forwardingError(conn: *webmail_tls.Stream, a: std.mem.Allocator, err: anyerror) !void {
    return switch (err) {
        error.InvalidForwardCode => sendError(conn, a, 400, "invalid_code", "This code is incorrect, expired, or already used. Request another code if needed."),
        error.InvalidForwardDestination => sendError(conn, a, 400, "invalid_address", "Choose a different active mailbox"),
        error.InvalidForwardScope => sendError(conn, a, 400, "invalid_scope", "Enter one email address per forwarding field"),
        error.NoVerifiedForward => sendError(conn, a, 409, "no_verified_destination", "Verify a forwarding destination first"),
        error.ForwardAlreadyActive => sendError(conn, a, 409, "already_forwarding", "This address is already verified"),
        error.PreconditionFailed => sendError(conn, a, 412, "revision_mismatch", "Forwarding changed in another window. Reopen Account settings before continuing."),
        error.ForwardRateLimited => sendError(conn, a, 429, "rate_limited", "Too many forwarding requests. Please wait before trying again."),
        else => err,
    };
}

const RetentionEndpoint = enum { rule, preview, restore };
const RetentionPreviewRequest = struct { folder: retention.Folder, days: i64, revision: i64 };
const RetentionChange = struct {
    action: enum { enable, disable },
    revision: i64,
    preview: ?[]const u8 = null,
    currentPassword: ?[]const u8 = null,
};

fn handleRetention(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request, endpoint: RetentionEndpoint) !void {
    const get = endpoint == .rule and std.mem.eql(u8, req.method, "GET");
    if (!get and !std.mem.eql(u8, req.method, if (endpoint == .rule) "PUT" else "POST"))
        return sendError(conn, a, 405, "method_not_allowed", if (endpoint == .rule) "Use GET or PUT" else "Use POST");
    if (!get and !isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var session = (try requireSession(server, conn, a, req)) orelse return;
    defer session.deinit(server.allocator);
    if (get) {
        const page = std.fmt.parseInt(usize, req.queryParam(a, "page") orelse "1", 10) catch 0;
        if (page == 0) return sendError(conn, a, 400, "invalid_page", "Invalid recovery page");
        const settings = retention.status(a, server.db, session.username, page) catch |err| return retentionError(conn, a, err);
        return sendJson(conn, a, 200, try service_mod.json(a, settings), null);
    }
    const now = time_compat.timestamp();
    switch (endpoint) {
        .preview => {
            const payload = std.json.parseFromSliceLeaky(RetentionPreviewRequest, a, req.body, .{}) catch
                return sendError(conn, a, 400, "bad_request", "Choose a folder and age for cleanup");
            const preview = retention.preview(a, server.db, session.username, .{ .folder = payload.folder, .days = payload.days }, payload.revision, now) catch |err|
                return retentionError(conn, a, err);
            return sendJson(conn, a, 200, try service_mod.json(a, preview), null);
        },
        .restore => {
            const payload = std.json.parseFromSliceLeaky(struct { reference: []const u8 }, a, req.body, .{}) catch
                return sendError(conn, a, 400, "bad_request", "Choose a message to restore");
            const restored = retention.restore(a, server.db, session.username, payload.reference) catch |err| return retentionError(conn, a, err);
            return sendJson(conn, a, 200, try service_mod.json(a, .{ .restored = restored }), null);
        },
        .rule => {
            const change = std.json.parseFromSliceLeaky(RetentionChange, a, req.body, .{}) catch
                return sendError(conn, a, 400, "bad_request", "Invalid cleanup settings");
            const rule = switch (change.action) {
                .disable => retention.disable(server.db, session.username, change.revision, now) catch |err| return retentionError(conn, a, err),
                .enable => blk: {
                    const token = change.preview orelse "";
                    if (!message_refs.valid(token)) return retentionError(conn, a, error.RetentionPreviewRequired);
                    const password = change.currentPassword orelse "";
                    if (password.len == 0 or password.len > recovery.max_password_len)
                        return sendError(conn, a, 400, "invalid_credentials", "Enter your current password");
                    const limit_key = try std.fmt.allocPrint(a, "retention:{s}", .{session.username});
                    if (!try server.login_limiter.checkAndIncrementUser(limit_key))
                        return sendError(conn, a, 429, "rate_limited", "Too many attempts. Try again later.");
                    if (!try server.auth.verifyCredentials(session.username, password))
                        return sendError(conn, a, 400, "invalid_credentials", "Current password is incorrect");
                    break :blk retention.enable(a, server.db, session.username, token, change.revision, time_compat.timestamp()) catch |err|
                        return retentionError(conn, a, err);
                },
            };
            return sendJson(conn, a, 200, try service_mod.json(a, rule), null);
        },
    }
}

fn retentionError(conn: *webmail_tls.Stream, a: std.mem.Allocator, err: anyerror) !void {
    return switch (err) {
        error.RetentionChanged => sendError(conn, a, 412, "revision_mismatch", "Cleanup settings changed. Reopen Account settings and try again."),
        error.RetentionPreviewRequired => sendError(conn, a, 409, "preview_required", "Preview the rule again before enabling cleanup"),
        error.InvalidRetentionPolicy => sendError(conn, a, 400, "invalid_policy", "Invalid cleanup folder, age, or page"),
        error.NotFound, error.FileNotFound => sendError(conn, a, 404, "not_found", "Message or mailbox not found"),
        else => mapMaildirError(conn, a, err),
    };
}

fn handleVacation(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    const get = std.mem.eql(u8, req.method, "GET");
    if (!get and !std.mem.eql(u8, req.method, "PUT")) return sendError(conn, a, 405, "method_not_allowed", "Use GET or PUT");
    if (!get and !isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var session = (try requireSession(server, conn, a, req)) orelse return;
    defer session.deinit(server.allocator);
    var settings = if (get)
        try server.db.vacationSettings(a, session.username)
    else
        std.json.parseFromSliceLeaky(database.Database.VacationSettings, a, req.body, .{}) catch
            return sendError(conn, a, 400, "bad_request", "Invalid vacation reply settings");
    if (!get) {
        if (settings.revision < 0) return sendError(conn, a, 400, "bad_request", "Invalid vacation reply revision");
        settings.subject = privateText(settings.subject, 256, false, false) catch
            return sendError(conn, a, 400, "invalid_subject", "Enter a subject up to 256 bytes without line breaks");
        if (settings.body.len > 8192) return sendError(conn, a, 400, "invalid_message", "Use a message up to 8192 bytes");
        settings.body = privateText(settings.body, 8192, !settings.enabled, true) catch
            return sendError(conn, a, 400, "invalid_message", "Enter a plain-text vacation reply");
        const last_date: i64 = 253402300799; // End of year 9999.
        const start = settings.startsAt orelse 0;
        const end = settings.endsAt orelse last_date;
        if (start < 0 or end <= start or end > last_date)
            return sendError(conn, a, 400, "invalid_schedule", "Choose an end time after the start time");
        settings.revision = server.db.setVacationSettings(session.username, settings) catch |err| switch (err) {
            error.PreconditionFailed => return sendError(conn, a, 412, "revision_mismatch", "Vacation replies changed in another window. Reopen Account settings before saving."),
            else => return err,
        };
    }
    return sendJson(conn, a, 200, try service_mod.json(a, settings), null);
}

const ComposePayload = service_mod.Payload;

fn handleDraftSave(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const parsed = std.json.parseFromSlice(ComposePayload, arena, req.body, .{ .ignore_unknown_fields = true }) catch return sendError(conn, arena, 400, "bad_request", "Invalid draft JSON");
    defer parsed.deinit();
    server.service.scanInlineAttachments(server.config.scanner, arena, sess.username, parsed.value) catch |err| return mapServiceError(conn, arena, err);
    const result = server.service.saveDraft(arena, sess.username, sess.email, parsed.value) catch |err| return mapServiceError(conn, arena, err);
    return sendJson(conn, arena, 200, try service_mod.json(arena, result), null);
}

fn attachmentDisposition(arena: std.mem.Allocator, filename: []const u8) ![]const u8 {
    var encoded: std.ArrayList(u8) = .empty;
    const hex = "0123456789ABCDEF";
    for (filename) |c| try encoded.appendSlice(arena, &.{ '%', hex[c >> 4], hex[c & 15] });
    return std.fmt.allocPrint(arena, "attachment; filename=\"download\"; filename*=UTF-8''{s}", .{encoded.items});
}

fn handleAttachment(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const index = std.fmt.parseInt(usize, req.queryParam(arena, "index") orelse "", 10) catch return sendError(conn, arena, 400, "bad_request", "Invalid attachment index");
    const message = if (req.queryParam(arena, "reference")) |reference| blk: {
        const revision = req.queryParam(arena, "revision");
        const content_revision = req.queryParam(arena, "content_revision");
        if (revision != null and content_revision != null) return sendError(conn, arena, 400, "invalid_revision", "Use one attachment revision");
        const expected = content_revision orelse revision orelse return sendError(conn, arena, 428, "revision_required", "Use a current attachment link");
        const current = maildir.getByReference(arena, server.db, sess.username, reference) catch |err| return mapMaildirError(conn, arena, err);
        // Maildir renames for flags leave the MIME bytes unchanged.
        const actual = if (content_revision != null) &current.version.?.content_revision else current.version.?.revision;
        if (!std.mem.eql(u8, actual, expected)) return mapMaildirError(conn, arena, error.RevisionMismatch);
        break :blk current;
    } else blk: {
        const folder = req.queryParam(arena, "folder") orelse "INBOX";
        const uid = std.fmt.parseInt(i64, req.queryParam(arena, "uid") orelse "", 10) catch return sendError(conn, arena, 400, "bad_request", "Invalid message UID");
        break :blk maildir.getVersionedMessage(arena, server.db, sess.username, folder, uid) catch |err| return mapMaildirError(conn, arena, err);
    };
    if (index >= message.attachments.len) return sendError(conn, arena, 404, "not_found", "No such attachment");
    return sendAttachment(conn, arena, message.attachments[index]);
}

fn sendAttachment(conn: *webmail_tls.Stream, arena: std.mem.Allocator, att: maildir.AttachmentInfo) !void {
    const header = try std.fmt.allocPrint(arena, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Disposition: {s}\r\nContent-Length: {d}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: sandbox\r\nConnection: close\r\n\r\n", .{ try attachmentDisposition(arena, att.filename), att.data.len });
    try writeAll(conn, header);
    try writeAll(conn, att.data);
}

/// POST /webmail/api/compose
/// { to:[...], cc:[...], bcc:[...], subject, text, html, inReplyTo?, references? }
/// Sends through the shared delivery path (DKIM-signed) and saves to Sent.
/// An optional senderId selects a mailbox that granted this account send access.
fn handleCompose(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);

    const parsed = std.json.parseFromSlice(ComposePayload, arena, req.body, .{ .ignore_unknown_fields = true }) catch return sendError(conn, arena, 400, "bad_request", "Invalid compose JSON");
    defer parsed.deinit();
    if (parsed.value.scheduleAt != null and parsed.value.sendId == null)
        return sendError(conn, arena, 400, "invalid_send_schedule", "A scheduled message requires a send ID.");
    server.service.scanInlineAttachments(server.config.scanner, arena, sess.username, parsed.value) catch |err| return mapServiceError(conn, arena, err);
    if (parsed.value.sendId != null) {
        const row = server.service.queueFromAccount(arena, sess.username, sess.email, parsed.value, time_compat.timestamp(), sess.linked_id) catch |err| return mapServiceError(conn, arena, err);
        return sendJson(conn, arena, 200, try outboxJson(arena, row), null);
    }
    if (sess.linked_id != null) return sendError(conn, arena, 400, "linked_send_requires_outbox", "A linked mailbox sends through Outbox.");
    server.service.requireOrdinaryDirectSend(arena, sess.username, parsed.value) catch |err| return mapServiceError(conn, arena, err);
    const delegated_id = parsed.value.delegatedSender() catch |err| return mapServiceError(conn, arena, err);
    const from = server.service.sendAddress(arena, sess.username, sess.email, delegated_id) catch |err| return mapServiceError(conn, arena, err);
    const msg = server.service.payloadMessage(arena, parsed.value, sess.username, from, false) catch |err| return mapServiceError(conn, arena, err);
    if (msg.to.len + msg.cc.len + msg.bcc.len > 100) return sendError(conn, arena, 400, "bad_request", "Use at most 100 recipients");

    const cfg = compose.SendConfig{
        .hostname = server.config.hostname,
        .delivery_method = server.config.delivery_method,
        .ses_region = server.config.ses_region,
        .sender_user = sess.username,
        .delegated_sender_id = delegated_id,
        .mail_config = server.config.mail_config,
        .auth = server.auth,
        .team_reply_source = server.service.followedSentSource(arena, sess.username, parsed.value),
    };

    const result = compose.send(arena, msg, cfg) catch |err| {
        if (err == compose.ComposeError.InvalidAddress) return sendError(conn, arena, 400, "bad_request", "Invalid recipient address");
        if (err == compose.ComposeError.InvalidHeader) return sendError(conn, arena, 400, "bad_request", "Invalid header content");
        if (err == compose.ComposeError.NoRecipients) return sendError(conn, arena, 400, "bad_request", "No recipients");
        return mapServiceError(conn, arena, err);
    };

    var body: std.ArrayList(u8) = .empty;
    const w = jw(&body, arena);
    // ok=true only if every recipient was delivered; otherwise report which failed.
    const all_ok = result.failed.len == 0;
    try w.print("{{\"ok\":{},\"message_id\":", .{all_ok});
    try writeJsonString(w, result.message_id);
    try w.print(",\"delivered\":{d},\"sent_saved\":{},\"failed\":[", .{ result.delivered, result.sent_saved });
    for (result.failed, 0..) |f, i| {
        if (i > 0) try w.writeAll(",");
        try writeJsonString(w, f);
    }
    try w.writeAll("]");
    if (result.limit_notice) |notice| {
        try w.writeAll(",\"notice\":");
        try writeJsonString(w, notice);
    }
    try w.writeAll("}");
    // 207-ish semantics over 200: still 200 so the client parses the body, which
    // carries ok=false + the failed list when delivery was partial.
    try sendJson(conn, arena, 200, body.items, null);
}

fn handleFolders(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);

    const folders = maildir.listFolders(arena, server.db, sess.username, server.service.junkFolder()) catch {
        return sendError(conn, arena, 500, "server_error", "Failed to read folders");
    };
    const workflow = try attention.load(arena, server.db, sess.username);
    if (workflow.hasHidden()) {
        for (folders) |*folder| {
            if (!attention.isInboxView(folder.name)) continue;
            const visible = try maildir.queryMessages(arena, server.db, sess.username, .{
                .folder = folder.name,
                .attention_snapshot = workflow,
                .headers_only = true,
            });
            folder.total = visible.len;
            folder.unread = 0;
            for (visible) |message| {
                if (!message.flags.seen and !message.flags.deleted) folder.unread += 1;
            }
        }
    }

    var body: std.ArrayList(u8) = .empty;
    const w = jw(&body, arena);
    try w.writeAll("[");
    for (folders, 0..) |f, i| {
        if (i > 0) try w.writeAll(",");
        try w.writeAll("{\"name\":");
        try writeJsonString(w, f.name);
        try w.print(",\"total\":{d},\"unread\":{d}}}", .{ f.total, f.unread });
    }
    try w.writeAll("]");
    try sendJson(conn, arena, 200, body.items, null);
}

fn mapServiceError(conn: *webmail_tls.Stream, arena: std.mem.Allocator, err: anyerror) !void {
    return switch (err) {
        service_mod.ServiceError.Conflict => sendError(conn, arena, 409, "conflict", "This item changed in another window or its undo window expired. Refresh before retrying."),
        error.InvalidSendSchedule => sendError(conn, arena, 400, "invalid_send_schedule", "Choose a future send time within 365 days. Use either a schedule or an Undo Send delay."),
        service_mod.ServiceError.AttachmentLimit => sendError(conn, arena, 413, "attachment_limit", "The message exceeds your configured size limit"),
        error.MalwareDetected => sendError(conn, arena, 422, "malware_detected", "Attachment rejected by malware scanner"),
        error.MalwareScanTooLarge => sendError(conn, arena, 413, "scan_limit", "Attachment exceeds scanner size limit"),
        error.MalwareScanUnavailable => sendError(conn, arena, 503, "scanner_unavailable", "Malware scanner unavailable. Try again later."),
        store.StoreError.StorageLimit => sendError(conn, arena, 413, "staging_limit", "Pending attachment storage is full. Remove unused draft attachments before retrying."),
        store.StoreError.DraftStorageLimit => sendError(conn, arena, 413, "draft_storage_limit", "Draft storage is full. Permanently delete drafts you no longer need or reduce this draft's size."),
        store.StoreError.OutboxStorageLimit => sendError(conn, arena, 413, "outbox_storage_limit", "Outbox storage is full. Review interrupted sends and try again after older entries expire."),
        service_mod.ServiceError.InvalidPayload, service_mod.ServiceError.InvalidAction, service_mod.ServiceError.InvalidAttachment, compose.ComposeError.InvalidAddress, compose.ComposeError.InvalidHeader, compose.ComposeError.NoRecipients => sendError(conn, arena, 400, "bad_request", "Check the recipients, headers and attachment limits"),
        error.HostedSendingLimit => sendError(conn, arena, 429, "sending_limit", "Daily recipient allowance exhausted. Try again after midnight UTC."),
        error.HostedSenderDisabled => sendError(conn, arena, 403, "mailbox_disabled", "This mailbox is disabled."),
        error.SenderIdentityUnavailable => sendError(conn, arena, 403, "sender_identity_unavailable", "This From address is no longer available. Choose another address before sending."),
        error.ExternalSenderUnavailable => sendError(conn, arena, 403, "external_sender_unavailable", "This external From address is unavailable."),
        error.ExternalReviewRequired => sendError(conn, arena, 409, "external_review_required", "Review the external From address and every recipient before sending."),
        error.ExternalSenderAlreadyVerified => sendError(conn, arena, 409, "external_sender_verified", "This external From address is already verified."),
        error.LinkedAccountUnavailable => sendError(conn, arena, 403, "linked_account_unavailable", "This linked mailbox is no longer available."),
        error.ExternalSenderRateLimited => sendError(conn, arena, 429, "rate_limited", "Wait one minute before requesting another code."),
        error.InvalidExternalSenderCode => sendError(conn, arena, 400, "invalid_external_sender_code", "This code is incorrect, expired, or already used."),
        error.SharedReplyUnavailable => sendError(conn, arena, 409, "shared_reply_unavailable", "This shared reply is unavailable. Check the original message, assignment, and send access."),
        error.SharedReplyConflict => sendError(conn, arena, 409, "shared_reply_conflict", "A reply is already queued, sent, or awaiting delivery review for this message."),
        error.SharedReplyQueueRequired => sendError(conn, arena, 400, "shared_reply_queue_required", "A shared reply requires an Outbox send ID."),
        error.HostedStorageFull => sendError(conn, arena, 507, "mailbox_full", "Mailbox storage is full. Free space before retrying."),
        error.HostedReadOnly => sendError(conn, arena, 403, "mailbox_read_only", "This mailbox is available for reading and export."),
        error.HostedRecipientDisabled => sendError(conn, arena, 409, "recipient_disabled", "A recipient mailbox is disabled."),
        error.HostedRecipientReadOnly => sendError(conn, arena, 503, "recipient_read_only", "A recipient mailbox is temporarily read-only."),
        error.HostedRecipientExpired => sendError(conn, arena, 409, "recipient_expired", "A recipient mailbox's service ended."),
        store.StoreError.NotFound => sendError(conn, arena, 404, "not_found", "No such item in this account"),
        else => mapMaildirError(conn, arena, err),
    };
}

fn pathId(path: []const u8, prefix: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, path, prefix)) return null;
    const id = path[prefix.len..];
    return if (store.validId(id)) id else null;
}

fn handleSenderReviewStatus(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    return sendJson(conn, arena, 200, try service_mod.json(arena, try server.db.senderReviewStatus(sess.username)), null);
}

fn handleSenderReviewList(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const view = std.meta.stringToEnum(sender_review.View, req.queryParam(arena, "view") orelse "pending") orelse
        return sendError(conn, arena, 400, "bad_request", "Unknown Sender Review view");
    const page = @max(1, parseUintParam(req, arena, "page", 1));
    const result = sender_review.list(arena, server.db, sess.username, view, page) catch |err|
        return mapSenderReviewError(conn, arena, err);
    return sendJson(conn, arena, 200, try service_mod.json(arena, result), null);
}

fn handleSenderReviewSettings(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const payload = std.json.parseFromSlice(struct { setting: database.Database.ScreeningSetting }, arena, req.body, .{}) catch
        return sendError(conn, arena, 400, "bad_request", "Invalid Sender Review setting");
    defer payload.deinit();
    {
        server.db.lockMailboxes();
        defer server.db.unlockMailboxes();
        try server.db.setSenderScreening(sess.username, payload.value.setting);
    }
    return sendJson(conn, arena, 200, try service_mod.json(arena, try server.db.senderReviewStatus(sess.username)), null);
}

fn handleSenderReviewDecision(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const payload = std.json.parseFromSlice(sender_review.Request, arena, req.body, .{}) catch
        return sendError(conn, arena, 400, "bad_request", "Invalid Sender Review decision");
    defer payload.deinit();
    const expected = req.header("If-Match");
    if (payload.value.reference != null) {
        const revision = expected orelse return sendError(conn, arena, 428, "revision_required", "Reload the message before choosing a decision");
        if (!isSingleStrongRevision(revision)) return sendError(conn, arena, 400, "invalid_revision", "Send one strong message ETag in If-Match");
    }
    sender_review.schedule(arena, server.db, sess.username, payload.value, expected) catch |err|
        return mapSenderReviewError(conn, arena, err);
    // Fast path for an interactive decision. The durable queue keeps any
    // remainder for the native worker, including after a restart.
    _ = sender_review.drain(server.allocator, server.db, sess.username, server.service.config.hostname, server.service.config.mail_config, 30) catch |err| blk: {
        logger.warn("Sender Review work is queued: {}", .{err});
        break :blk false;
    };
    return sendJson(conn, arena, 200, try service_mod.json(arena, try server.db.senderReviewStatus(sess.username)), null);
}

fn handleSenderInvitation(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request, id: ?[]const u8) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    if (id) |ref| {
        sender_review.revokeInvitation(server.db, sess.username, ref) catch |err|
            return mapSenderReviewError(conn, arena, err);
        return sendJson(conn, arena, 200, "{\"revoked\":true}", null);
    }
    const payload = std.json.parseFromSlice(sender_review.InvitationRequest, arena, req.body, .{}) catch
        return sendError(conn, arena, 400, "bad_request", "Invalid sender invitation");
    defer payload.deinit();
    const result = sender_review.invite(arena, server.db, sess.username, payload.value) catch |err|
        return mapSenderReviewError(conn, arena, err);
    return sendJson(conn, arena, 201, try service_mod.json(arena, result), null);
}

fn mapSenderReviewError(conn: *webmail_tls.Stream, arena: std.mem.Allocator, err: anyerror) !void {
    return switch (err) {
        error.InvalidReviewDecision => sendError(conn, arena, 400, "bad_request", "Invalid Sender Review decision"),
        error.UnverifiedSender => sendError(conn, arena, 400, "unverified_sender", "Choose a decision for this message only"),
        error.ReviewChanged, maildir.MaildirError.RevisionMismatch => sendError(conn, arena, 412, "revision_mismatch", "Sender Review changed. Refresh before trying again."),
        error.ReviewInProgress => sendError(conn, arena, 409, "review_in_progress", "A decision is still being applied for this sender"),
        error.NotFound => sendError(conn, arena, 404, "not_found", "No such item in this mailbox"),
        error.InvalidSenderInvitation => sendError(conn, arena, 400, "invalid_invitation", "Enter one email address and a supported duration"),
        error.InvitationRequiresReview => sendError(conn, arena, 409, "review_disabled", "Turn on Sender Review before inviting a sender"),
        error.InvitationHasDecision => sendError(conn, arena, 409, "saved_decision", "This sender has a saved decision"),
        error.InvitationUnavailable => sendError(conn, arena, 409, "invitation_unavailable", "This sender already has an invitation or you have reached 50 active invitations"),
        else => mapMaildirError(conn, arena, err),
    };
}

fn handleClientConfig(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    var limits = try server.service.limits(sess.username);
    limits.calendarAvailable = server.dav_store != null;
    limits.sharedInboxesAvailable = try shared_inbox.available(server.db, sess.username);
    limits.teamThreadsAvailable = try team_threads.available(server.db, sess.username);
    limits.maxFileLinkBytes = try file_links.uploadLimit(server.db, sess.username);
    if (store.get(arena, server.db, sess.username, "preferences", "settings")) |row| {
        const parsed = try std.json.parseFromSlice(struct { undoSendSeconds: u32 }, arena, row.payload, .{});
        defer parsed.deinit();
        limits.undoSendSeconds = @min(parsed.value.undoSendSeconds, 30);
    } else |err| if (err != store.StoreError.NotFound) return err;
    return sendJson(conn, arena, 200, try service_mod.json(arena, limits), null);
}

fn handlePreferences(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const parsed = std.json.parseFromSlice(struct { undoSendSeconds: u32 }, arena, req.body, .{}) catch return sendError(conn, arena, 400, "bad_request", "Invalid preferences");
    defer parsed.deinit();
    if (parsed.value.undoSendSeconds > 30) return sendError(conn, arena, 400, "bad_request", "Use a send delay between 0 and 30 seconds");
    server.service.mutations.lock();
    defer server.service.mutations.unlock();
    const previous: ?store.Record = store.get(arena, server.db, sess.username, "preferences", "settings") catch |err| blk: {
        if (err != store.StoreError.NotFound) return err;
        break :blk null;
    };
    _ = try store.put(server.db, .{ .username = sess.username, .kind = "preferences", .id = "settings", .payload = try service_mod.json(arena, parsed.value), .state = "saved", .revision = 0, .due_at = 0, .expires_at = 0 }, if (previous) |row| row.revision else 0);
    return sendJson(conn, arena, 200, "{\"ok\":true}", null);
}

fn handleComposeLibrary(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    const editing = std.mem.eql(u8, req.method, "PUT");
    if (editing and !isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    if (!editing) {
        const library = compose_library.load(arena, server.db, sess.username) catch |err| return mapServiceError(conn, arena, err);
        return sendJson(conn, arena, 200, try service_mod.json(arena, library), null);
    }
    if (req.body.len > compose_library.max_bytes)
        return sendError(conn, arena, 400, "invalid_compose_library", "Writing tools can use up to 128 KiB.");
    const requested = std.json.parseFromSliceLeaky(compose_library.Library, arena, req.body, .{}) catch
        return sendError(conn, arena, 400, "invalid_compose_library", "Check the writing tools data.");
    const library = compose_library.save(arena, server.db, sess.username, requested) catch |err| switch (err) {
        error.InvalidComposeLibrary => return sendError(conn, arena, 400, "invalid_compose_library", "Check your snippet and signature names, text, and default signature."),
        store.StoreError.Conflict => return sendError(conn, arena, 409, "compose_library_changed", "Writing tools changed in another window. Reload before saving."),
        else => return mapServiceError(conn, arena, err),
    };
    return sendJson(conn, arena, 200, try service_mod.json(arena, library), null);
}

fn handleSenderIdentities(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    var session = (try requireSession(server, conn, a, req)) orelse return;
    defer session.deinit(server.allocator);
    const identities = teams.senderIdentities(server.db, a, session.username) catch |err| return mapServiceError(conn, a, err);
    var available: std.ArrayList(teams.SenderIdentity) = .empty;
    for (identities) |identity| {
        if (compose.isSafeAddress(identity.address)) try available.append(a, identity);
    }
    @import("webmail_external_senders.zig").choices(a, server.db, server.service.externalSendersFile(), session.username, &available) catch |err| {
        if (err != error.ExternalSenderUnavailable) return mapServiceError(conn, a, err);
    };
    return sendJson(conn, a, 200, try service_mod.json(a, available.items), null);
}

fn handleExternalSenderReview(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var session = (try requireSession(server, conn, a, req)) orelse return;
    defer session.deinit(server.allocator);
    if (req.body.len > 64 * 1024) return mapServiceError(conn, a, service_mod.ServiceError.InvalidPayload);
    const request = std.json.parseFromSliceLeaky(service_mod.ExternalReviewRequest, a, req.body, .{}) catch
        return mapServiceError(conn, a, service_mod.ServiceError.InvalidPayload);
    const review = server.service.reviewExternalSend(a, session.username, request) catch |err| return mapServiceError(conn, a, err);
    return sendJson(conn, a, 200, try service_mod.json(a, review), null);
}

fn handleExternalSenderVerification(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    const external = @import("webmail_external_senders.zig");
    const get = std.mem.eql(u8, req.method, "GET");
    if (!get and !std.mem.eql(u8, req.method, "POST")) return sendError(conn, a, 405, "method_not_allowed", "Use GET or POST.");
    if (!get and !isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var session = (try requireSession(server, conn, a, req)) orelse return;
    defer session.deinit(server.allocator);
    const path = server.service.externalSendersFile();
    const now = time_compat.timestamp();
    if (!get) {
        const Change = struct { id: []const u8, action: enum { request, confirm, revoke }, code: []const u8 = "" };
        if (req.body.len > 1024) return mapServiceError(conn, a, service_mod.ServiceError.InvalidPayload);
        const change = std.json.parseFromSliceLeaky(Change, a, req.body, .{}) catch
            return mapServiceError(conn, a, service_mod.ServiceError.InvalidPayload);
        const grant = external.find(a, path, session.username, change.id) catch |err| return mapServiceError(conn, a, err);
        switch (change.action) {
            .request => sendExternalSenderCode(server, grant, now) catch |err| return mapServiceError(conn, a, err),
            .confirm => external.confirmProof(a, server.db, grant, change.code, now) catch |err| return mapServiceError(conn, a, err),
            .revoke => external.revokeProof(a, server.db, grant, now) catch |err| return mapServiceError(conn, a, err),
        }
    }
    const states = external.statuses(a, server.db, path, session.username, now) catch |err| return mapServiceError(conn, a, err);
    return sendJson(conn, a, 200, try service_mod.json(a, states), null);
}

fn sendExternalSenderCode(server: *WebmailHttpServer, grant: @import("webmail_external_senders.zig").Grant, now: i64) !void {
    var job = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    errdefer job.deinit();
    const a = job.allocator();
    const owner = try a.dupe(u8, grant.mailbox);
    const destination = resolveForwardDestination(server, a, owner, grant.address) catch return error.ExternalSenderUnavailable;
    const to = try a.dupe([]const u8, &.{try a.dupe(u8, destination.address)});
    const from = try recovery.senderFor(a, owner, server.config.hostname);
    const code = try @import("webmail_external_senders.zig").requestProof(a, server.db, grant, now);
    const message: compose.Message = .{
        .from = from,
        .to = to,
        .subject = "Verify an external From address",
        .text_body = try std.fmt.allocPrint(a,
            \\Mail account {s} requested to send from this address.
            \\
            \\Enter this code in that account's External From addresses settings within 30 minutes:
            \\
            \\{s}
            \\
            \\If you did not request this, ignore this message.
        , .{ owner, code }),
        .auto_submitted = true,
        .notice_recipient_id = destination.mailbox_id,
    };
    dispatchSystemMail(server, job, message, "external From verification code", owner);
}

fn handleTeams(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    const editing = std.mem.eql(u8, req.method, "PUT");
    const reading = std.mem.eql(u8, req.method, "GET");
    if (editing and !isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const path = "/webmail/api/teams";
    if (std.mem.eql(u8, req.path, path) and reading) {
        const rows = teams.list(server.db, arena, sess.username) catch |err| return teamError(conn, arena, err);
        return sendJson(conn, arena, 200, try service_mod.json(arena, rows), null);
    }
    if (req.path.len <= path.len) return teamError(conn, arena, error.TeamNotFound);
    var parts = std.mem.splitScalar(u8, req.path[path.len + 1 ..], '/');
    const team = parts.next().?;
    const action = parts.next();
    if (!teams.validTeamId(team) or parts.next() != null) return teamError(conn, arena, error.TeamNotFound);
    const actor: teams.Actor = .{ .mailbox = sess.username };
    if (reading and action == null) {
        const detail = teams.details(server.db, arena, actor, team) catch |err| return teamError(conn, arena, err);
        return sendJson(conn, arena, 200, try service_mod.json(arena, detail), null);
    }
    if (!editing or action == null) return teamError(conn, arena, error.TeamNotFound);
    if (req.body.len > 8192) return teamError(conn, arena, error.InvalidTeamData);
    if (std.mem.eql(u8, action.?, "members")) {
        const body = std.json.parseFromSliceLeaky(struct { mailbox: []const u8, role: ?teams.Role }, arena, req.body, .{}) catch
            return teamError(conn, arena, error.InvalidTeamData);
        teams.setMember(server.db, arena, actor, team, body.mailbox, body.role) catch |err| return teamError(conn, arena, err);
    } else if (std.mem.eql(u8, action.?, "grants")) {
        const Body = struct { source: []const u8, grantee: []const u8, scope: teams.Scope, resource: []const u8 = "", allowed: bool };
        const body = std.json.parseFromSliceLeaky(Body, arena, req.body, .{}) catch return teamError(conn, arena, error.InvalidTeamData);
        teams.setGrant(server.db, arena, actor, team, .{ .source = body.source, .grantee = body.grantee, .scope = body.scope, .resource = body.resource }, body.allowed) catch |err|
            return teamError(conn, arena, err);
    } else if (std.mem.eql(u8, action.?, "calendar-shares")) {
        const dav = server.dav_store orelse return sendError(conn, arena, 503, "calendar_unavailable", "Calendar is unavailable on this server");
        const Body = struct { calendarId: u64, grantee: []const u8, access: ?teams.CalendarAccess };
        const body = std.json.parseFromSliceLeaky(Body, arena, req.body, .{}) catch return teamError(conn, arena, error.InvalidTeamData);
        const share_id = dav.mailboxCalendarShareId(sess.username, body.calendarId, body.access != null) catch |err|
            return calendarWriteError(conn, arena, err);
        teams.setCalendarShare(server.db, arena, sess.username, team, body.grantee, share_id, body.access) catch |err|
            return teamError(conn, arena, err);
    } else return teamError(conn, arena, error.TeamNotFound);
    return sendJson(conn, arena, 200, "{\"ok\":true}", null);
}

fn teamError(conn: *webmail_tls.Stream, arena: std.mem.Allocator, err: anyerror) !void {
    return switch (err) {
        error.TeamNotFound => sendError(conn, arena, 404, "team_not_found", "Team not found."),
        error.TeamMemberNotFound => sendError(conn, arena, 404, "team_member_not_found", "Mailbox or team member not found."),
        error.TeamForbidden => sendError(conn, arena, 403, "team_forbidden", "You do not have permission to change this team or grant."),
        error.LastTeamOwner => sendError(conn, arena, 409, "last_team_owner", "Assign another owner before changing this membership."),
        error.DisabledTeamAccount => sendError(conn, arena, 409, "team_account_disabled", "Activate the mailbox before granting team access."),
        error.TeamInviteeUnavailable => sendError(conn, arena, 404, "team_invitee_unavailable", "Choose an active paid mailbox on your hosted domain."),
        error.TeamInvitationNotFound => sendError(conn, arena, 404, "team_invitation_not_found", "This invitation is no longer available."),
        error.TeamAlreadyJoined => sendError(conn, arena, 409, "team_already_joined", "This mailbox is already on the team."),
        error.InvalidTeamData => sendError(conn, arena, 400, "invalid_team_data", "Check the team, mailbox, role, or resource."),
        else => mapServiceError(conn, arena, err),
    };
}

fn hostedTeamMailbox(cfg: WebmailHttpConfig, mailbox: []const u8) bool {
    const mail = cfg.mail_config orelse return false;
    const domain = mailbox_domains.addressDomain(mailbox) orelse return false;
    const primary = cfg.primary_provisioning_domain orelse return false;
    return !std.ascii.eqlIgnoreCase(domain, primary) and mail.requiresFullMailbox(mailbox) and mailbox_domains.contains(cfg.hosted_team_domains, domain);
}

fn handleTeamInvitations(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    const reading = std.mem.eql(u8, req.method, "GET");
    if (!reading and !std.mem.eql(u8, req.method, "POST")) return sendError(conn, a, 405, "method_not_allowed", "Method not allowed.");
    if (!reading and !isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    const enabled = hostedTeamMailbox(server.config, sess.username);
    if (reading) {
        const panel = if (enabled) teams.invitations(server.db, a, sess.username) catch |err| return teamError(conn, a, err) else teams.InvitationPanel{};
        return sendJson(conn, a, 200, try service_mod.json(a, panel), null);
    }
    if (!enabled) return sendError(conn, a, 409, "team_invites_unavailable", "Team invitations are unavailable for this mailbox.");
    if (req.body.len > 2048) return teamError(conn, a, error.InvalidTeamData);
    const Body = struct { action: enum { invite, accept, decline, revoke }, team: ?[]const u8 = null, recipient: ?[]const u8 = null, id: ?[]const u8 = null };
    const body = std.json.parseFromSliceLeaky(Body, a, req.body, .{}) catch return teamError(conn, a, error.InvalidTeamData);
    if (body.action == .invite) {
        const team = body.team orelse return teamError(conn, a, error.InvalidTeamData);
        const recipient = body.recipient orelse return teamError(conn, a, error.InvalidTeamData);
        const canonical = try std.ascii.allocLowerString(a, std.mem.trim(u8, recipient, " \t"));
        teams.invite(server.db, a, sess.username, team, canonical) catch |err| return teamError(conn, a, err);
    } else {
        const id = body.id orelse return teamError(conn, a, error.InvalidTeamData);
        const decision: teams.InvitationDecision = switch (body.action) {
            .invite => unreachable,
            .accept => .accept,
            .decline => .decline,
            .revoke => .revoke,
        };
        teams.decideInvitation(server.db, a, sess.username, id, decision) catch |err| return teamError(conn, a, err);
    }
    return sendJson(conn, a, 200, "{\"ok\":true}", null);
}

const ThreadShareInput = struct {
    references: []const []const u8 = &.{},
    collectionId: ?[]const u8 = null,
    downloads: bool = false,
    followReplies: bool = false,
    followSentReplies: bool = false,
    team: ?[]const u8 = null,
    grantee: ?[]const u8 = null,
    digest: ?[]const u8 = null,
};

fn handleThreadShares(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    const reading = std.mem.eql(u8, req.method, "GET");
    const posting = std.mem.eql(u8, req.method, "POST");
    const deleting = std.mem.eql(u8, req.method, "DELETE");
    if ((posting or deleting) and !isSameOrigin(req))
        return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    const actor = sess.username;
    const junk = server.service.junkFolder();
    const preview = std.mem.eql(u8, req.path, thread_shares_path ++ "/preview");
    if (std.mem.eql(u8, req.path, thread_shares_path) or preview) {
        if (reading and !preview) {
            const grants = try team_threads.list(a, server.db, actor);
            return sendJson(conn, a, 200, try service_mod.json(a, .{ .grants = grants }), null);
        }
        if (!posting or req.body.len > 4096) return threadShareError(conn, a, error.InvalidThreadShare);
        const input = std.json.parseFromSliceLeaky(ThreadShareInput, a, req.body, .{}) catch
            return threadShareError(conn, a, error.InvalidThreadShare);
        if (input.collectionId) |collection| {
            if (input.references.len != 0 or input.followReplies or input.followSentReplies) return threadShareError(conn, a, error.InvalidThreadShare);
            if (preview) {
                const prepared = team_threads.previewCollection(a, server.db, actor, collection, input.downloads, junk) catch |err|
                    return threadShareError(conn, a, err);
                return sendJson(conn, a, 200, try service_mod.json(a, .{
                    .collection = prepared.collection,
                    .messages = prepared.page.messages,
                    .next = prepared.page.next,
                    .digest = @as([]const u8, &prepared.digest),
                    .followingAuthors = &[_][]const u8{},
                }), null);
            }
            const team = input.team orelse return threadShareError(conn, a, error.InvalidThreadShare);
            const grantee = input.grantee orelse return threadShareError(conn, a, error.InvalidThreadShare);
            const grant = team_threads.createCollection(a, server.db, actor, team, grantee, collection, input.downloads, input.digest orelse "") catch |err|
                return threadShareError(conn, a, err);
            return sendJson(conn, a, 201, try service_mod.json(a, grant), null);
        }
        const prepared = team_threads.prepare(a, server.db, actor, input.references, input.downloads, input.followReplies, input.followSentReplies, junk) catch |err|
            return threadShareError(conn, a, err);
        if (preview)
            return sendJson(conn, a, 200, try service_mod.json(a, .{
                .messages = prepared.messages,
                .digest = @as([]const u8, &prepared.digest),
                .followingAuthors = prepared.authors,
                .followingSentReplies = prepared.follow_sent,
            }), null);
        const team = input.team orelse return threadShareError(conn, a, error.InvalidThreadShare);
        const grantee = input.grantee orelse return threadShareError(conn, a, error.InvalidThreadShare);
        if (!std.mem.eql(u8, input.digest orelse "", &prepared.digest))
            return sendError(conn, a, 409, "thread_share_changed", "Review the current conversation preview before sharing.");
        const grant = team_threads.create(a, server.db, actor, team, grantee, prepared, time_compat.milliTimestamp()) catch |err|
            return threadShareError(conn, a, err);
        return sendJson(conn, a, 201, try service_mod.json(a, grant), null);
    }
    var parts = std.mem.splitScalar(u8, req.path[thread_shares_path.len + 1 ..], '/');
    const id = parts.next().?;
    if (!store.validId(id)) return threadShareError(conn, a, error.ThreadShareUnavailable);
    if (parts.next()) |section| {
        if (posting and std.mem.eql(u8, section, "comments") and parts.next() == null) {
            if (req.body.len > 8192) return threadShareError(conn, a, error.InvalidThreadShare);
            const body = std.json.parseFromSliceLeaky(struct { text: []const u8 }, a, req.body, .{}) catch
                return threadShareError(conn, a, error.InvalidThreadShare);
            team_threads.addComment(a, server.db, actor, id, body.text, time_compat.timestamp()) catch |err|
                return threadShareError(conn, a, err);
            return sendJson(conn, a, 201, "{\"ok\":true}", null);
        }
        if (reading and std.mem.eql(u8, section, "attachments")) {
            const ref = parts.next() orelse "";
            const index = std.fmt.parseInt(usize, parts.next() orelse "", 10) catch
                return threadShareError(conn, a, error.ThreadShareUnavailable);
            if (parts.next() != null or !message_refs.valid(ref)) return threadShareError(conn, a, error.ThreadShareUnavailable);
            const part = team_threads.attachment(a, server.db, actor, id, ref, index, junk) catch |err|
                return threadShareError(conn, a, err);
            return sendAttachment(conn, a, part);
        }
        return threadShareError(conn, a, error.ThreadShareUnavailable);
    }
    if (reading) {
        const before = if (req.queryParam(a, "before")) |cursor| std.fmt.parseInt(i64, cursor, 10) catch
            return threadShareError(conn, a, error.InvalidThreadShare) else null;
        const result = team_threads.detail(a, server.db, actor, id, req.queryParam(a, "q") orelse "", before, junk) catch |err|
            return threadShareError(conn, a, err);
        return sendJson(conn, a, 200, try service_mod.json(a, result), null);
    }
    if (deleting) {
        team_threads.revoke(server.db, actor, id) catch |err| return threadShareError(conn, a, err);
        return sendJson(conn, a, 200, "{\"ok\":true}", null);
    }
    return threadShareError(conn, a, error.ThreadShareUnavailable);
}

fn threadShareError(conn: *webmail_tls.Stream, a: std.mem.Allocator, err: anyerror) !void {
    switch (err) {
        error.ThreadShareUnavailable, maildir.MaildirError.MessageNotFound, error.FileNotFound => return sendError(conn, a, 404, "thread_share_unavailable", "This share or message is unavailable."),
        error.ThreadShareTooLarge => return sendError(conn, a, 413, "thread_share_too_large", "Share fewer or smaller messages."),
        error.InvalidThreadShare => return sendError(conn, a, 400, "invalid_thread_share", "Check the share, teammate, or comment."),
        error.ThreadShareChanged => return sendError(conn, a, 409, "thread_share_changed", "Review the current collection preview before sharing."),
        error.CollectionAlreadyShared => return sendError(conn, a, 409, "collection_already_shared", "This teammate already has access in this team."),
        error.ThreadFollowUnavailable => return sendError(conn, a, 409, "thread_follow_unavailable", "To follow replies, select a conversation with a verified inbound sender and a message ID."),
        error.ThreadShareGrantUnavailable => return sendError(conn, a, 409, "thread_share_grant_unavailable", "Choose an active teammate or revoke a share before creating another."),
        error.ThreadShareCommentLimit => return sendError(conn, a, 409, "thread_share_comment_limit", "This conversation reached its comment limit."),
        else => return mapServiceError(conn, a, err),
    }
}

fn handleSharedInboxes(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    const writing = std.mem.eql(u8, req.method, "PUT");
    const posting = std.mem.eql(u8, req.method, "POST");
    const reading = std.mem.eql(u8, req.method, "GET");
    if ((writing or posting) and !isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var session = (try requireSession(server, conn, a, req)) orelse return;
    defer session.deinit(server.allocator);
    const path = "/webmail/api/shared-inboxes";
    if (std.mem.eql(u8, req.path, path)) {
        if (!reading) return sharedInboxError(conn, a, error.SharedInboxNotFound);
        const inboxes = shared_inbox.list(a, server.db, session.username) catch |err| return sharedInboxError(conn, a, err);
        return sendJson(conn, a, 200, try service_mod.json(a, inboxes), null);
    }
    var parts = std.mem.splitScalar(u8, req.path[path.len + 1 ..], '/');
    const team = parts.next().?;
    const source_id = parts.next() orelse "";
    const id = shared_inbox.positiveId(source_id) orelse return sharedInboxError(conn, a, error.SharedInboxNotFound);
    if (!teams.validTeamId(team)) return sharedInboxError(conn, a, error.SharedInboxNotFound);
    const source = shared_inbox.source(a, server.db, session.username, team, id) catch |err| return sharedInboxError(conn, a, err);
    const section = parts.next() orelse {
        if (!reading) return sharedInboxError(conn, a, error.SharedInboxNotFound);
        return sharedInboxPage(server, conn, a, req, session.username, team, id, source.username);
    };
    if (std.mem.eql(u8, section, "stages") and parts.next() == null) {
        if (writing) {
            if (req.body.len > 8192) return sharedInboxError(conn, a, error.InvalidSharedChange);
            const patch = std.json.parseFromSliceLeaky(shared_inbox.StageChange, a, req.body, .{}) catch return sharedInboxError(conn, a, error.InvalidSharedChange);
            shared_inbox.changeStage(a, server.db, session.username, team, id, patch) catch |err| return sharedInboxError(conn, a, err);
        } else if (!reading) return sharedInboxError(conn, a, error.SharedInboxNotFound);
        const current = shared_inbox.source(a, server.db, session.username, team, id) catch |err| return sharedInboxError(conn, a, err);
        const rows = try shared_inbox.stages(a, server.db, team, id, current.can_manage);
        const checked = shared_inbox.source(a, server.db, session.username, team, id) catch |err| return sharedInboxError(conn, a, err);
        const can_manage = current.can_manage and checked.can_manage;
        if (!can_manage) for (rows) |*row| {
            row.sender = null;
        };
        return sendJson(conn, a, 200, try service_mod.json(a, .{ .canManage = can_manage, .items = rows }), null);
    }
    const reference = parts.next() orelse "";
    if (!std.mem.eql(u8, section, "messages") or !message_refs.valid(reference))
        return sharedInboxError(conn, a, error.SharedInboxNotFound);
    const action = parts.next();
    if (posting and action != null and std.mem.eql(u8, action.?, "reply") and parts.next() == null) {
        return stageSharedReply(server, conn, a, req, session, source, .{ .team = team, .sourceId = source_id, .reference = reference, .messageRevision = "" });
    }
    if (writing and action != null and std.mem.eql(u8, action.?, "workflow") and parts.next() == null) {
        if (req.body.len > 8192) return sharedInboxError(conn, a, error.InvalidSharedChange);
        const patch = std.json.parseFromSliceLeaky(shared_inbox.Change, a, req.body, .{}) catch return sharedInboxError(conn, a, error.InvalidSharedChange);
        const changed = changeSharedWorkflow(a, server.db, session.username, team, id, source.username, reference, patch) catch |err|
            return sharedInboxError(conn, a, err);
        return sendJson(conn, a, 200, try service_mod.json(a, changed), null);
    }
    if (!reading) return sharedInboxError(conn, a, error.SharedInboxNotFound);
    if (action) |part| {
        const index = std.fmt.parseInt(usize, parts.next() orelse "", 10) catch return sharedInboxError(conn, a, error.SharedInboxNotFound);
        if (!std.mem.eql(u8, part, "attachments") or parts.next() != null)
            return sharedInboxError(conn, a, error.SharedInboxNotFound);
        if (!try shared_inbox.canDownload(server.db, session.username, team, id, reference))
            return sharedInboxError(conn, a, error.SharedAttachmentForbidden);
        const msg = maildir.getSharedInboxMessage(a, server.db, source.username, reference) catch |err| return sharedInboxError(conn, a, err);
        const revision = req.queryParam(a, "revision") orelse return sendError(conn, a, 428, "revision_required", "Use a current attachment link.");
        if (!std.mem.eql(u8, msg.version.?.revision, revision)) return sharedInboxError(conn, a, error.RevisionMismatch);
        if (index >= msg.attachments.len) return sharedInboxError(conn, a, error.SharedInboxNotFound);
        if (!try shared_inbox.canDownload(server.db, session.username, team, id, reference))
            return sharedInboxError(conn, a, error.SharedAttachmentForbidden);
        return sendAttachment(conn, a, msg.attachments[index]);
    }
    const msg = maildir.getSharedInboxMessage(a, server.db, source.username, reference) catch |err| return sharedInboxError(conn, a, err);
    const workflow = try shared_inbox.workflow(a, server.db, team, id, reference);
    const assignable = try shared_inbox.targets(a, server.db, team, id);
    const attachments = try shared_inbox.canDownload(server.db, session.username, team, id, reference);
    var body: std.ArrayList(u8) = .empty;
    const w = jw(&body, a);
    const reply = try shared_inbox.replyStatus(a, server.db, team, id, reference);
    const allowed = reply == null and try shared_inbox.canReply(server.db, session.username, .{
        .team = team,
        .sourceId = source_id,
        .reference = reference,
        .messageRevision = msg.version.?.revision,
    });
    try writeSharedMessage(w, a, msg, workflow, assignable, attachments, reply, allowed);
    _ = shared_inbox.source(a, server.db, session.username, team, id) catch |err| return sharedInboxError(conn, a, err);
    return sendJson(conn, a, 200, body.items, null);
}

fn sharedInboxPage(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request, actor: []const u8, team: []const u8, id: i64, source: []const u8) !void {
    const per_page = 25;
    const requested = @max(parseUintParam(req, a, "page", 1), 1);
    var page = maildir.listSharedInboxPage(a, server.db, source, requested, per_page) catch |err| return sharedInboxError(conn, a, err);
    const last = @max(1, page.total / per_page + @intFromBool(page.total % per_page != 0));
    const current = @min(last, requested);
    if (requested > current) page = try maildir.listSharedInboxPage(a, server.db, source, current, per_page);
    var body: std.ArrayList(u8) = .empty;
    const w = jw(&body, a);
    try w.print("{{\"page\":{d},\"total\":{d},\"more\":{},\"items\":[", .{ current, page.total, current < last });
    var first = true;
    for (page.items) |item| {
        const version = (try maildir.summaryVersion(a, server.db, source, item)) orelse continue;
        if (!first) try w.writeByte(',');
        first = false;
        try w.writeAll("{\"message\":");
        try writeMessageSummary(w, item, version);
        try w.writeAll(",\"workflow\":");
        try w.writeAll(try service_mod.json(a, try shared_inbox.workflow(a, server.db, team, id, version.reference)));
        try w.writeByte('}');
    }
    try w.writeAll("]}");
    _ = shared_inbox.source(a, server.db, actor, team, id) catch |err| return sharedInboxError(conn, a, err);
    return sendJson(conn, a, 200, body.items, null);
}

fn changeSharedWorkflow(a: std.mem.Allocator, db: *database.Database, actor: []const u8, team: []const u8, id: i64, source: []const u8, reference: []const u8, patch: shared_inbox.Change) !shared_inbox.Workflow {
    db.lockMailboxes();
    defer db.unlockMailboxes();
    try maildir.checkSharedInboxRevision(a, db, source, reference, patch.messageRevision);
    return shared_inbox.change(a, db, actor, team, id, reference, patch);
}

fn stageSharedReply(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request, session: session_mod.Session, source: shared_inbox.Source, target: shared_inbox.ReplyContext) !void {
    const Patch = struct { draftId: []const u8, messageRevision: []const u8 };
    if (req.body.len > 8192) return sharedInboxError(conn, a, error.InvalidSharedChange);
    const patch = std.json.parseFromSliceLeaky(Patch, a, req.body, .{}) catch return sharedInboxError(conn, a, error.InvalidSharedChange);
    if (!store.validId(patch.draftId)) return sharedInboxError(conn, a, error.InvalidSharedChange);
    var context = target;
    context.messageRevision = patch.messageRevision;
    if (!try shared_inbox.canReply(server.db, session.username, context)) return sharedInboxError(conn, a, error.SharedReplyUnavailable);
    if (try shared_inbox.replyStatus(a, server.db, context.team, shared_inbox.positiveId(context.sourceId).?, context.reference) != null)
        return sharedInboxError(conn, a, error.SharedReplyConflict);
    const msg = maildir.getSharedInboxMessage(a, server.db, source.username, context.reference) catch |err| return sharedInboxError(conn, a, err);
    if (!std.mem.eql(u8, msg.version.?.revision, context.messageRevision))
        return sharedInboxError(conn, a, error.RevisionMismatch);
    var recipients: std.ArrayList([]const u8) = .empty;
    message_submission.appendMailboxes(a, if (msg.reply_to.len > 0) msg.reply_to else msg.from, &recipients) catch |err| switch (err) {
        error.InvalidAddress => return sharedInboxError(conn, a, err),
        else => return err,
    };
    const subject = if (std.ascii.startsWithIgnoreCase(msg.subject, "re:")) msg.subject else try std.fmt.allocPrint(a, "Re: {s}", .{msg.subject});
    var text: std.ArrayList(u8) = .empty;
    const w = jw(&text, a);
    const library = try compose_library.load(a, server.db, session.username);
    if (library.defaultSignatureId) |default| for (library.signatures) |signature| {
        if (std.mem.eql(u8, signature.id, default)) {
            try w.print("\n\n-- \n{s}", .{signature.text});
            break;
        }
    };
    try w.print("\n\nOn {s}, {s} wrote:\n", .{ msg.date, msg.from });
    var lines = std.mem.splitScalar(u8, msg.text_body, '\n');
    while (lines.next()) |line| {
        if (line.len + text.items.len > 64 * 1024) break;
        try w.print("> {s}\n", .{line});
    }
    const ack = server.service.saveDraft(a, session.username, session.email, .{
        .draftId = patch.draftId,
        .saveToken = patch.draftId,
        .to = recipients.items,
        .subject = subject,
        .text = text.items,
        .inReplyTo = msg.message_id,
        .references = std.mem.trim(u8, try std.fmt.allocPrint(a, "{s} {s}", .{ msg.references, msg.message_id }), " "),
        .senderId = if (std.mem.eql(u8, source.username, session.username)) null else context.sourceId,
        .sharedReply = context,
    }) catch |err| return sharedInboxError(conn, a, err);
    return sendJson(conn, a, 200, try service_mod.json(a, ack), null);
}

fn writeSharedMessage(w: anytype, a: std.mem.Allocator, msg: maildir.MessageDetail, state: shared_inbox.Workflow, targets: []const shared_inbox.Target, downloads: bool, reply: ?shared_inbox.ReplyStatus, allowed: bool) !void {
    try w.writeAll("{\"from\":");
    try writeJsonString(w, msg.from);
    try w.writeAll(",\"subject\":");
    try writeJsonString(w, msg.subject);
    try w.writeAll(",\"date\":");
    try writeJsonString(w, msg.date);
    try w.writeAll(",\"to\":");
    try writeJsonString(w, msg.to);
    try w.writeAll(",\"text\":");
    try writeJsonString(w, msg.text_body);
    try w.writeAll(",\"html\":");
    try writeJsonString(w, msg.html_body);
    try writeVersion(w, msg.version, false);
    try w.print(",\"hasAttachments\":{},\"attachments\":[", .{msg.attachments.len > 0});
    if (downloads) for (msg.attachments, 0..) |att, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"filename\":");
        try writeJsonString(w, att.filename);
        try w.print(",\"size\":{d}}}", .{att.size});
    };
    try w.writeAll("],\"embedded_images\":[");
    if (downloads and msg.html_body.len > 0) try writeEmbeddedImages(w, a, msg.attachments);
    try w.writeAll("],\"workflow\":");
    try w.writeAll(try service_mod.json(a, state));
    try w.writeAll(",\"assignable\":");
    try w.writeAll(try service_mod.json(a, targets));
    try w.print(",\"canReply\":{},\"reply\":", .{allowed});
    try w.writeAll(try service_mod.json(a, reply));
    try w.writeByte('}');
}

fn sharedInboxError(conn: *webmail_tls.Stream, a: std.mem.Allocator, err: anyerror) !void {
    return switch (err) {
        error.SharedInboxNotFound, maildir.MaildirError.MessageNotFound => sendError(conn, a, 404, "shared_inbox_not_found", "This shared inbox or message is unavailable."),
        error.SharedInboxConflict => sendError(conn, a, 409, "shared_inbox_conflict", "A teammate changed this message. Review the latest assignment and status."),
        error.AssigneeUnavailable => sendError(conn, a, 409, "assignee_unavailable", "That teammate no longer has access to this inbox."),
        error.StageUnavailable => sendError(conn, a, 409, "stage_unavailable", "That stage is no longer available in this inbox."),
        error.StageConfigConflict => sendError(conn, a, 409, "stage_changed", "A teammate changed this stage. Review the latest settings."),
        error.StageNameOrSenderConflict => sendError(conn, a, 409, "stage_duplicate", "That stage name or routing address is already in use."),
        error.StageAdminRequired => sendError(conn, a, 403, "stage_admin_required", "Only an inbox team owner or admin can configure stages."),
        error.SharedAttachmentForbidden => sendError(conn, a, 403, "shared_attachment_forbidden", "You do not have access to this message’s attachments."),
        error.InvalidSharedChange => sendError(conn, a, 400, "invalid_shared_change", "Check the requested assignment, status, or stage."),
        else => mapServiceError(conn, a, err),
    };
}

fn handleFileLinkUpload(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    const filename = req.queryParam(a, "filename") orelse "";
    const id = req.queryParam(a, "uploadId") orelse "";
    const lifetime = std.fmt.parseInt(i64, req.queryParam(a, "lifetime") orelse "", 10) catch 0;
    if (!file_links.validId(id) or !service_mod.validFilename(filename) or
        !link_tokens.validLifetime(lifetime) or req.body.len == 0)
        return sendError(conn, a, 400, "invalid_file_link", "Choose a nonempty file and a supported link expiry.");
    clamav.requireAllowed(server.config.scanner, req.body) catch |err| return mapServiceError(conn, a, err);
    const issued = file_links.create(server.db, sess.username, id, filename, req.body, lifetime, time_compat.timestamp()) catch |err| switch (err) {
        error.InvalidLinkedFile => return sendError(conn, a, 413, "file_link_too_large", "The file exceeds the file-link upload limit."),
        error.FileLinkStorageLimit => return sendError(conn, a, 507, "file_link_storage_full", "File-link storage is full. Revoke an active file link before uploading another."),
        error.FileLinkAlreadyCreated => return sendError(conn, a, 409, "file_link_already_created", "Mail already saved this upload. Manage the link from Account settings."),
        error.FileLinkOwnerUnavailable, error.HostedRecipientDisabled => return sendError(conn, a, 401, "unauthorized", "This mailbox is unavailable."),
        else => return mapServiceError(conn, a, err),
    };
    return sendJson(conn, a, 201, try service_mod.json(a, .{ .file = issued.file, .token = @as([]const u8, &issued.token) }), null);
}

fn handleFileLinkList(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    const links = try file_links.list(a, server.db, sess.username, time_compat.timestamp());
    return sendJson(conn, a, 200, try service_mod.json(a, .{ .links = links }), null);
}

fn handleFileLinkRevoke(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request, id: []const u8) !void {
    if (!isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    if (!file_links.validId(id) or !try file_links.revoke(server.db, sess.username, id))
        return sendError(conn, a, 404, "file_link_unavailable", "This file link is unavailable.");
    return sendJson(conn, a, 200, "{\"revoked\":true}", null);
}

fn handleFileLinkPublic(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request, download: bool) !void {
    // Browsers can send an opaque Origin for the no-referrer download form.
    // The download is read-only and still requires the file's bearer token.
    const opaque_download = download and std.mem.eql(u8, req.header("Origin") orelse "", "null");
    if (!opaque_download and !isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    const unavailable = "This file link is unavailable.";
    if (req.body.len > 256) return sendError(conn, a, 404, "file_link_unavailable", unavailable);
    const token = if (download) blk: {
        // The native form sends exactly one URL-safe hexadecimal field.
        const prefix = "token=";
        if (!std.mem.startsWith(u8, req.body, prefix)) return sendError(conn, a, 404, "file_link_unavailable", unavailable);
        break :blk req.body[prefix.len..];
    } else blk: {
        const body = std.json.parseFromSliceLeaky(struct { token: []const u8 }, a, req.body, .{}) catch
            return sendError(conn, a, 404, "file_link_unavailable", unavailable);
        break :blk body.token;
    };
    if (download and !server.claimFileTransfer())
        return sendError(conn, a, 503, "file_transfers_busy", "File transfers are busy. Try again shortly.");
    defer if (download) server.releaseFileTransfer();
    const result = (try file_links.read(a, server.db, token, time_compat.timestamp(), download)) orelse
        return sendError(conn, a, 404, "file_link_unavailable", unavailable);
    if (!download) return sendJson(conn, a, 200, try service_mod.json(a, result.file), null);
    return sendAttachment(conn, a, .{ .filename = result.file.filename, .content_type = "application/octet-stream", .size = result.data.len, .data = result.data });
}

fn handleUpload(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const name = req.queryParam(arena, "filename") orelse return sendError(conn, arena, 400, "bad_request", "Missing filename");
    const content_type = req.queryParam(arena, "contentType") orelse "application/octet-stream";
    if (!service_mod.validFilename(name) or !service_mod.validContentType(content_type)) return sendError(conn, arena, 400, "bad_request", "Invalid attachment metadata");
    const allowed = try server.service.limits(sess.username);
    if (req.body.len > allowed.maxFileBytes or req.body.len > allowed.maxTotalBytes) return sendError(conn, arena, 413, "attachment_limit", "Attachment exceeds the configured size limit");
    const id = req.queryParam(arena, "uploadId") orelse try store.newId(arena);
    if (!store.validId(id)) return sendError(conn, arena, 400, "bad_request", "Invalid upload id");
    const upload = store.Upload{ .id = id, .filename = name, .content_type = content_type, .data = req.body };
    const response = try service_mod.json(arena, .{ .uploadId = id, .filename = name, .contentType = content_type, .size = req.body.len });
    if (server.config.scanner) |scanner| {
        if (try respondToExistingUpload(server.db, conn, arena, sess.username, upload, response)) return;
        clamav.requireAllowed(scanner, req.body) catch |err| return mapServiceError(conn, arena, err);
    }
    server.service.mutations.lock();
    defer server.service.mutations.unlock();
    if (try respondToExistingUpload(server.db, conn, arena, sess.username, upload, response)) return;
    server.service.stageUpload(sess.username, upload, allowed, time_compat.timestamp()) catch |err| return mapServiceError(conn, arena, err);
    return sendJson(conn, arena, 200, response, null);
}

fn respondToExistingUpload(db: *database.Database, conn: *webmail_tls.Stream, arena: std.mem.Allocator, user: []const u8, upload: store.Upload, response: []const u8) !bool {
    const known = store.getUpload(arena, db, user, upload.id) catch |err| switch (err) {
        store.StoreError.NotFound => return false,
        else => return err,
    };
    if (!std.mem.eql(u8, known.filename, upload.filename) or
        !std.mem.eql(u8, known.content_type, upload.content_type) or
        !std.mem.eql(u8, known.data, upload.data))
    {
        try sendError(conn, arena, 409, "upload_changed", "This upload identifier already belongs to different attachment data");
    } else {
        try sendJson(conn, arena, 200, response, null);
    }
    return true;
}

fn handleUploadDelete(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const id = pathId(req.path, "/webmail/api/uploads/") orelse return sendError(conn, arena, 400, "bad_request", "Invalid attachment id");
    server.service.mutations.lock();
    defer server.service.mutations.unlock();
    try store.removeUpload(server.db, sess.username, id);
    return sendJson(conn, arena, 200, "{\"ok\":true}", null);
}

fn handleDraftGet(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const uid = @as(i64, @intCast(parseUintParam(req, arena, "uid", 0)));
    const row = server.service.loadDraft(arena, sess.username, req.queryParam(arena, "folder") orelse "Drafts", uid) catch |err| return mapServiceError(conn, arena, err);
    const parsed = try std.json.parseFromSlice(service_mod.Draft, arena, row.payload, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    return sendJson(conn, arena, 200, try service_mod.json(arena, .{ .draftId = row.id, .revision = row.revision, .state = row.state, .uid = parsed.value.uid, .message = parsed.value.message }), null);
}

fn handleBulk(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const parsed = std.json.parseFromSlice(service_mod.BulkPayload, arena, req.body, .{}) catch return sendError(conn, arena, 400, "bad_request", "Invalid message selection");
    defer parsed.deinit();
    const result = server.service.bulk(arena, sess.username, parsed.value, time_compat.timestamp()) catch |err| return mapServiceError(conn, arena, err);
    return sendJson(conn, arena, 200, try service_mod.json(arena, result), null);
}

fn handleReplyBatchPreview(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    if (req.body.len > 2048) return mapReplyBatchError(conn, a, error.InvalidReplyBatchSelection);
    const input = std.json.parseFromSliceLeaky(struct { references: []const []const u8 }, a, req.body, .{}) catch
        return mapReplyBatchError(conn, a, error.InvalidReplyBatchSelection);
    const review = reply_batches.preview(a, &server.service, sess.username, sess.email, input.references) catch |err|
        return mapReplyBatchError(conn, a, err);
    return sendJson(conn, a, 200, try service_mod.json(a, review), null);
}

fn handleReplyBatchQueue(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    const input = std.json.parseFromSliceLeaky(reply_batches.Request, a, req.body, .{}) catch
        return mapReplyBatchError(conn, a, error.InvalidReplyBatch);
    const result = reply_batches.queue(a, &server.service, sess.username, sess.email, input, time_compat.timestamp()) catch |err|
        return mapReplyBatchError(conn, a, err);
    return sendJson(conn, a, 200, try service_mod.json(a, result), null);
}

fn handleReplyBatchStatus(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request, id: []const u8) !void {
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    const result = reply_batches.status(a, server.db, sess.username, id) catch |err| return mapReplyBatchError(conn, a, err);
    return sendJson(conn, a, 200, try service_mod.json(a, result), null);
}

fn mapReplyBatchError(conn: *webmail_tls.Stream, a: std.mem.Allocator, err: anyerror) !void {
    return switch (err) {
        error.InvalidReplyBatchSelection => sendError(conn, a, 400, "invalid_reply_selection", "Choose one to twenty received messages."),
        error.DuplicateReplyBatchSource => sendError(conn, a, 400, "duplicate_reply_source", "Choose one copy of each message."),
        error.InvalidReplyBatch => sendError(conn, a, 400, "invalid_reply_batch", "Review the recipients and enter a reply of up to 256 KiB."),
        error.ReplyBatchSourceUnavailable => sendError(conn, a, 422, "reply_source_unavailable", "A selected message cannot be included. Open it to reply individually."),
        error.ReplyBatchRecipientUnavailable => sendError(conn, a, 422, "reply_recipient_unavailable", "A selected message lacks a single reply address. Open it to reply individually."),
        error.ReplyBatchPreviewChanged => sendError(conn, a, 409, "reply_preview_changed", "A selected message or sending address changed. Review the replies again."),
        error.ReplyBatchAccountChanged => sendError(conn, a, 409, "account_changed", "The signed-in account changed. Reload this tab before continuing."),
        error.ReplyBatchConflict, store.StoreError.Conflict => sendError(conn, a, 409, "reply_batch_conflict", "This batch identifier already belongs to a different request. Check Outbox before starting a new batch."),
        else => mapServiceError(conn, a, err),
    };
}

fn handleUndo(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const id = pathId(req.path, "/webmail/api/undo/") orelse return sendError(conn, arena, 400, "bad_request", "Invalid undo id");
    const result = server.service.undo(arena, sess.username, id, time_compat.timestamp()) catch |err| return mapServiceError(conn, arena, err);
    return sendJson(conn, arena, 200, try service_mod.json(arena, result), null);
}

fn outboxJson(arena: std.mem.Allocator, row: store.Record) ![]const u8 {
    const parsed = try std.json.parseFromSlice(service_mod.Outbox, arena, row.payload, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    return service_mod.json(arena, .{ .id = row.id, .state = row.state, .dueAt = row.due_at, .serverTime = time_compat.timestamp(), .scheduled = parsed.value.scheduled or parsed.value.message.scheduleAt != null, .calendarRsvp = parsed.value.calendarReply != null, .message = parsed.value.message, .result = parsed.value.result, .@"error" = parsed.value.error_message });
}

fn handleCalendars(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const dav = server.dav_store orelse return sendError(conn, arena, 503, "calendar_unavailable", "Calendar is unavailable on this server");
    const calendars = try dav.snapshotCalendars(arena, sess.username);
    return sendJson(conn, arena, 200, try service_mod.json(arena, .{ .calendars = calendars }), null);
}

fn handleCalendarShares(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const dav = server.dav_store orelse return sendError(conn, arena, 503, "calendar_unavailable", "Calendar is unavailable on this server");
    const shares = try teams.calendarShares(server.db, arena, sess.username);
    const CalendarShare = struct {
        team: []const u8,
        source: []const u8,
        grantee: []const u8,
        calendarId: u64,
        calendarName: []const u8,
        displayName: ?[]const u8,
        access: teams.CalendarAccess,
    };
    var rows: std.ArrayList(CalendarShare) = .empty;
    for (shares) |share| {
        const calendar = (try dav.snapshotSharedCalendar(arena, share.source_id, share.calendar_share_id)) orelse continue;
        try rows.append(arena, .{
            .team = share.team,
            .source = share.source,
            .grantee = share.grantee,
            .calendarId = calendar.id,
            .calendarName = calendar.name,
            .displayName = calendar.display_name,
            .access = share.access,
        });
    }
    return sendJson(conn, arena, 200, try service_mod.json(arena, .{ .shares = rows.items }), null);
}

fn handleCalendarDayLabels(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request, day: ?[]const u8) !void {
    if (day != null and !isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    if (server.dav_store == null) return sendError(conn, arena, 503, "calendar_unavailable", "Calendar is unavailable on this server");
    if (day) |date| {
        // Bound the JSON document, including escaped UTF-8 and the revision.
        if (req.body.len > 2048) return sendError(conn, arena, 400, "invalid_day_label", "Enter a day label of up to 80 characters.");
        const edit = std.json.parseFromSliceLeaky(calendar_day_labels.Edit, arena, req.body, .{}) catch
            return sendError(conn, arena, 400, "invalid_day_label", "Check the label and revision.");
        const label = calendar_day_labels.save(server.db, sess.username, date, edit) catch |err| switch (err) {
            error.InvalidDayLabel => return sendError(conn, arena, 400, "invalid_day_label", "Enter a valid date and a one-line day label of up to 80 characters."),
            error.DayLabelChanged => return sendError(conn, arena, 409, "day_label_changed", "This day label changed in another window. Load the latest label before editing again."),
            error.InvalidDayLabelOwner => return sendError(conn, arena, 401, "unauthorized", "This mailbox is unavailable."),
            else => return err,
        };
        return sendJson(conn, arena, 200, try service_mod.json(arena, label), null);
    }
    const start = req.queryParam(arena, "start") orelse "";
    const end = req.queryParam(arena, "end") orelse "";
    const labels = calendar_day_labels.list(arena, server.db, sess.username, start, end) catch |err| switch (err) {
        error.InvalidDayLabelRange => return sendError(conn, arena, 400, "invalid_day_label_range", "Choose a range of up to 366 calendar dates."),
        else => return err,
    };
    return sendJson(conn, arena, 200, try service_mod.json(arena, .{ .labels = labels }), null);
}

fn handleCalendarTasks(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request, id_param: ?[]const u8) !void {
    const reading = std.mem.eql(u8, req.method, "GET");
    if (!reading and !isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    if (server.dav_store == null) return sendError(conn, arena, 503, "calendar_unavailable", "Calendar is unavailable on this server");
    if (reading) {
        const tasks = try calendar_tasks.list(arena, server.db, sess.username);
        return sendJson(conn, arena, 200, try service_mod.json(arena, .{ .tasks = tasks }), null);
    }
    const id = if (id_param) |value| blk: {
        const parsed = std.fmt.parseInt(i64, value, 10) catch 0;
        if (parsed <= 0) return sendError(conn, arena, 400, "invalid_calendar_task", "Enter a valid task ID.");
        break :blk parsed;
    } else null;
    writeCalendarTask(server.db, conn, arena, req, sess.username, id) catch |err| switch (err) {
        error.InvalidCalendarTask => return sendError(conn, arena, 400, "invalid_calendar_task", "Enter a one-line title of up to 120 characters and a valid date or no date."),
        error.CalendarTaskChanged => return sendError(conn, arena, 409, "calendar_task_changed", "This task changed or was removed. Load the latest tasks before trying again."),
        error.CalendarTaskLimit => return sendError(conn, arena, 409, "calendar_task_limit", "The task list is full. Delete a task before adding another."),
        error.InvalidCalendarTaskOwner => return sendError(conn, arena, 401, "unauthorized", "This mailbox is unavailable."),
        else => return err,
    };
}

fn writeCalendarTask(db: *database.Database, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request, mailbox: []const u8, id: ?i64) !void {
    if (req.body.len > 2048) return error.InvalidCalendarTask;
    if (std.mem.eql(u8, req.method, "DELETE")) {
        const removal = std.json.parseFromSliceLeaky(struct { revision: i64 }, arena, req.body, .{}) catch return error.InvalidCalendarTask;
        try calendar_tasks.remove(db, mailbox, id orelse return error.InvalidCalendarTask, removal.revision);
        return sendJson(conn, arena, 200, "{\"removed\":true}", null);
    }
    const edit = std.json.parseFromSliceLeaky(calendar_tasks.Edit, arena, req.body, .{}) catch return error.InvalidCalendarTask;
    const task = try calendar_tasks.save(db, mailbox, id, edit);
    return sendJson(conn, arena, if (id == null) 201 else 200, try service_mod.json(arena, task), null);
}

fn handleCalendarTools(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    const reading = std.mem.eql(u8, req.method, "GET");
    if (!reading and !isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    if (server.dav_store == null) return sendError(conn, arena, 503, "calendar_unavailable", "Calendar is unavailable on this server");
    if (reading) {
        if (std.mem.eql(u8, req.queryParam(arena, "display") orelse "", "1")) {
            const compact = try calendar_tools.isCompact(server.db, sess.username);
            return sendJson(conn, arena, 200, try service_mod.json(arena, .{ .compact = compact }), null);
        }
        return sendJson(conn, arena, 200, try service_mod.json(arena, try calendar_tools.load(arena, server.db, sess.username)), null);
    }
    if (req.body.len > calendar_tools.max_bytes + 128)
        return sendError(conn, arena, 413, "personal_tools_too_large", "Personal tools can store up to 512 KiB.");
    const change = std.json.parseFromSliceLeaky(calendar_tools.Snapshot, arena, req.body, .{}) catch
        return sendError(conn, arena, 400, "invalid_personal_tools", "Check the personal tools file or entry.");
    const saved = calendar_tools.save(arena, server.db, sess.username, change) catch |err| switch (err) {
        error.InvalidPersonalTools => return sendError(conn, arena, 400, "invalid_personal_tools", "Check the personal tools entries, dates and limits."),
        error.PersonalToolsChanged => return sendError(conn, arena, 409, "personal_tools_changed", "Personal tools changed in another window. Load the latest data before saving."),
        error.PersonalToolsTooLarge => return sendError(conn, arena, 413, "personal_tools_too_large", "Personal tools can store up to 512 KiB."),
        error.PersonalToolsUnavailable => return sendError(conn, arena, 401, "unauthorized", "This mailbox is unavailable."),
        else => return err,
    };
    return sendJson(conn, arena, 200, try service_mod.json(arena, saved), null);
}

const reminder_history = 86_400;

fn handleCalendarReminders(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const dav = server.dav_store orelse return sendError(conn, arena, 503, "calendar_unavailable", "Calendar is unavailable on this server");
    const now = time_compat.timestamp();
    const start = now - reminder_history;
    const end = now + 60;
    const snapshot = dav.snapshotReminderSources(arena, sess.username, .{ .start = start, .end = end }) catch |err| switch (err) {
        error.TooManySeriesBytes => return sendError(conn, arena, 413, "too_many_reminders", "Too many calendar resources to check for reminders"),
        else => return err,
    };
    return sendJson(conn, arena, 200, try service_mod.json(arena, .{
        .now = now,
        .start = start,
        .end = end,
        .events = snapshot.events,
        .dismissed = snapshot.dismissed,
    }), null);
}

fn handleReminderDismiss(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const dav = server.dav_store orelse return sendError(conn, arena, 503, "calendar_unavailable", "Calendar is unavailable on this server");
    const body = std.json.parseFromSliceLeaky(struct { eventId: u64, key: []const u8, due: i64 }, arena, req.body, .{}) catch
        return sendError(conn, arena, 400, "bad_request", "Enter a valid reminder");
    const now = time_compat.timestamp();
    const cutoff = now - reminder_history;
    if (body.due < cutoff or body.due > now or body.key.len == 0 or body.key.len > 128)
        return sendError(conn, arena, 400, "bad_request", "Enter a current reminder");
    for (body.key) |byte| if (!std.ascii.isAlphanumeric(byte) and std.mem.indexOfScalar(u8, ":_-", byte) == null)
        return sendError(conn, arena, 400, "bad_request", "Enter a valid reminder");
    const prefix = try std.fmt.allocPrint(arena, "{d}:{d}:", .{ body.eventId, body.due });
    if (!std.mem.startsWith(u8, body.key, prefix))
        return sendError(conn, arena, 400, "bad_request", "Enter a valid reminder");
    dav.dismissReminder(sess.username, body.eventId, body.key, body.due, cutoff) catch |err| switch (err) {
        error.ReminderStorageUnavailable => return sendError(conn, arena, 503, "calendar_unavailable", "Reminder storage is unavailable"),
        error.TooManyDismissals => return sendError(conn, arena, 429, "too_many_reminders", "Too many reminders were dismissed today"),
        else => return calendarWriteError(conn, arena, err),
    };
    return sendStatus(conn, arena, 204, "No Content", null);
}

fn handleCalendarTimezone(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const zone = req.queryParam(arena, "zone") orelse "";
    if (zone.len == 0 or zone.len > 100) return sendError(conn, arena, 400, "bad_request", "Enter an IANA time zone");
    for (zone) |byte| if (!std.ascii.isAlphanumeric(byte) and std.mem.indexOfScalar(u8, "_+./-", byte) == null)
        return sendError(conn, arena, 400, "bad_request", "Enter an IANA time zone");
    const source = calendar_clock.bundledTimezone(zone) orelse
        return sendError(conn, arena, 404, "timezone_not_found", "The server has no definition for this time zone");
    return sendJson(conn, arena, 200, try service_mod.json(arena, .{ .icalendar = source }), null);
}

fn handleCalendarFreeBusy(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const dav = server.dav_store orelse return sendError(conn, arena, 503, "calendar_unavailable", "Calendar is unavailable on this server");
    const calendar_id: ?u64 = if (req.queryParam(arena, "calendarId")) |id|
        std.fmt.parseInt(u64, id, 10) catch return sendError(conn, arena, 400, "bad_request", "Invalid calendar ID")
    else
        null;
    const include_owned = std.mem.eql(u8, req.queryParam(arena, "includeOwned") orelse "", "1");
    const start = std.fmt.parseInt(i64, req.queryParam(arena, "start") orelse "", 10) catch
        return sendError(conn, arena, 400, "bad_request", "Invalid start timestamp");
    const end = std.fmt.parseInt(i64, req.queryParam(arena, "end") orelse "", 10) catch
        return sendError(conn, arena, 400, "bad_request", "Invalid end timestamp");
    const result = dav.webCalendarBusyPeriods(arena, sess.username, .{ .id = calendar_id, .include_owned = include_owned }, .{ .start = start, .end = end }) catch |err| switch (err) {
        error.InvalidRange => return sendError(conn, arena, 400, "bad_request", "Specify a positive calendar window of at most 366 days"),
        error.CalendarNotFound, error.DavMailboxNotFound => return sendError(conn, arena, 404, "not_found", "Calendar not found"),
        error.AvailabilityLimit => return sendError(conn, arena, 413, "availability_limit", "The calendar exceeds the availability calculation limit"),
        error.AvailabilityUnsupported, error.UnsupportedTimezone, error.InvalidCalendar => return sendError(conn, arena, 422, "availability_incomplete", "Some busy times could not be calculated"),
        else => return err,
    };
    return sendJson(conn, arena, 200, try service_mod.json(arena, .{ .busy = result }), null);
}

fn handleCalendarCreate(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const dav = server.dav_store orelse return sendError(conn, arena, 503, "calendar_unavailable", "Calendar is unavailable on this server");
    const payload = std.json.parseFromSlice(struct { name: []const u8 }, arena, req.body, .{}) catch
        return sendError(conn, arena, 400, "bad_request", "Enter a calendar name");
    defer payload.deinit();
    const name = calendar_import.calendarName(arena, payload.value.name) catch |err| return calendarWriteError(conn, arena, err);
    const id = dav.createMailboxCalendar(sess.username, name) catch |err| return calendarWriteError(conn, arena, err);
    return sendJson(conn, arena, 201, try service_mod.json(arena, .{ .id = id, .name = name }), null);
}

fn handleCalendarColor(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const dav = server.dav_store orelse return sendError(conn, arena, 503, "calendar_unavailable", "Calendar is unavailable on this server");
    const calendar_id = std.fmt.parseInt(u64, req.path["/webmail/api/calendars/".len..], 10) catch
        return sendError(conn, arena, 400, "bad_request", "Invalid calendar ID");
    const payload = std.json.parseFromSlice(struct { color: ?[]const u8 }, arena, req.body, .{}) catch
        return sendError(conn, arena, 400, "bad_request", "Enter a six-digit hex color or null");
    defer payload.deinit();
    if (payload.value.color) |color| {
        if (color.len != 7 or color[0] != '#') return sendError(conn, arena, 400, "bad_request", "Enter a six-digit hex color");
        for (color[1..]) |byte| if (!std.ascii.isHex(byte))
            return sendError(conn, arena, 400, "bad_request", "Enter a six-digit hex color");
    }
    dav.setMailboxCalendarColor(sess.username, calendar_id, payload.value.color) catch |err| return calendarWriteError(conn, arena, err);
    return sendStatus(conn, arena, 204, "No Content", null);
}

fn handleCalendarEvents(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const dav = server.dav_store orelse return sendError(conn, arena, 503, "calendar_unavailable", "Calendar is unavailable on this server");
    const calendar_id: ?u64 = if (req.queryParam(arena, "calendarId")) |id|
        std.fmt.parseInt(u64, id, 10) catch return sendError(conn, arena, 400, "bad_request", "Invalid calendar ID")
    else
        null;
    const query = std.mem.trim(u8, req.queryParam(arena, "q") orelse "", " \t\r\n");
    if (query.len > 256 or !std.unicode.utf8ValidateSlice(query))
        return sendError(conn, arena, 400, "bad_request", "Enter a search of at most 256 bytes");
    const start = req.queryParam(arena, "start");
    const end = req.queryParam(arena, "end");
    const window: ?caldav_store.CalDavStore.CalendarWindow = if (start != null or end != null or query.len == 0) .{
        .start = std.fmt.parseInt(i64, start orelse "", 10) catch return sendError(conn, arena, 400, "bad_request", "Invalid start timestamp"),
        .end = std.fmt.parseInt(i64, end orelse "", 10) catch return sendError(conn, arena, 400, "bad_request", "Invalid end timestamp"),
    } else null;
    const include_series = std.mem.eql(u8, req.queryParam(arena, "instances") orelse "", "1");
    const events = dav.queryWebCalendarEvents(arena, sess.username, calendar_id, window, query, include_series) catch |err| switch (err) {
        error.InvalidRange => return sendError(conn, arena, 400, "bad_request", "Specify a positive calendar window of at most 366 days"),
        error.CalendarNotFound, error.DavMailboxNotFound => return sendError(conn, arena, 404, "not_found", "Calendar not found"),
        error.TooManyEvents => return sendError(conn, arena, 400, "too_many_events", "More than 500 events match. Narrow your search or select a calendar or shorter view."),
        error.TooManySeriesBytes => return sendError(conn, arena, 413, "calendar_series_too_large", "Recurring event data exceeds this view's limit. Select one calendar."),
        else => return err,
    };
    return sendJson(conn, arena, 200, try service_mod.json(arena, .{ .events = events }), null);
}

fn handleCalendarEventSource(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    if (server.dav_store == null) return sendError(conn, arena, 503, "calendar_unavailable", "Calendar is unavailable on this server");
    const reference = req.queryParam(arena, "reference") orelse return mapMaildirError(conn, arena, error.MessageNotFound);
    const subject = maildir.calendarSourceSubject(arena, server.db, sess.username, reference) catch |err| return mapMaildirError(conn, arena, err);
    return sendJson(conn, arena, 200, try service_mod.json(arena, .{ .subject = subject }), null);
}

fn handleCalendarEventCreate(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const dav = server.dav_store orelse return sendError(conn, arena, 503, "calendar_unavailable", "Calendar is unavailable on this server");
    const calendar_id, var data = if (isICalendar(req)) resource: {
        const id = std.fmt.parseInt(u64, req.queryParam(arena, "calendarId") orelse "", 10) catch
            return sendError(conn, arena, 400, "bad_request", "Invalid calendar ID");
        if (req.body.len > dav.config.max_event_size) return calendarWriteError(conn, arena, error.EventTooLarge);
        const prepared = calendar_events.prepareDocument(arena, req.body, null) catch |err| return calendarWriteError(conn, arena, err);
        break :resource .{ id, prepared };
    } else json: {
        const payload = std.json.parseFromSliceLeaky(calendar_events.Create, arena, req.body, .{}) catch
            return sendError(conn, arena, 400, "bad_request", "Enter a calendar, title and start time");
        const prepared = calendar_events.prepareCreate(arena, payload) catch |err| return calendarWriteError(conn, arena, err);
        break :json .{ payload.calendarId, prepared };
    };
    if (req.header("X-Webmail-Source-Message")) |reference| {
        _ = maildir.calendarSourceSubject(arena, server.db, sess.username, reference) catch |err| return mapMaildirError(conn, arena, err);
        data.source_message = reference[0..@sizeOf(caldav_store.MessageReference)].*;
    }
    checkCalendarEventBody(server, arena, dav, data.ics_data.?) catch |err| return calendarWriteError(conn, arena, err);
    const created = dav.createWebCalendarEvent(sess.username, calendar_id, data) catch |err| return calendarWriteError(conn, arena, err);
    return sendRevisionJson(conn, arena, 201, try service_mod.json(arena, .{
        .id = created.id,
        .calendarId = calendar_id,
        .uid = data.uid.?,
        .etag = created.revision.etag(),
    }), null, created.revision.etag());
}

fn handleCalendarEventItem(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    const get = std.mem.eql(u8, req.method, "GET");
    const patch = std.mem.eql(u8, req.method, "PATCH");
    const put = std.mem.eql(u8, req.method, "PUT");
    const delete = std.mem.eql(u8, req.method, "DELETE");
    if (!get and !patch and !put and !delete) return sendError(conn, arena, 405, "method_not_allowed", "Use GET, PATCH, PUT or DELETE for a calendar event");
    if (!get and !isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const dav = server.dav_store orelse return sendError(conn, arena, 503, "calendar_unavailable", "Calendar is unavailable on this server");
    const event_id = std.fmt.parseInt(u64, req.path["/webmail/api/calendar-events/".len..], 10) catch
        return sendError(conn, arena, 400, "bad_request", "Invalid event ID");
    if (get) {
        const detail = dav.snapshotWebCalendarEvent(arena, sess.username, event_id, .read) catch |err| return calendarWriteError(conn, arena, err);
        const include_source = std.mem.eql(u8, req.queryParam(arena, "source") orelse "", "1");
        const source_message: ?[]const u8 = if (detail.source_message) |*reference| source: {
            _ = maildir.calendarSourceSubject(arena, server.db, sess.username, reference) catch |err| switch (err) {
                error.MessageNotFound, error.FileNotFound => break :source null,
                else => return err,
            };
            break :source reference;
        } else null;
        return sendRevisionJson(conn, arena, 200, try service_mod.json(arena, .{
            .event = detail.event,
            .calendarId = detail.calendar_id,
            .description = detail.description,
            .organizer = detail.organizer,
            .icalendar = if (include_source) @as(?[]const u8, detail.ics_data) else null,
            .source_message = source_message,
        }), null, detail.event.etag);
    }

    const expected = req.header("If-Match") orelse
        return sendError(conn, arena, 428, "revision_required", "Read the event and send its ETag in If-Match");
    if (!isSingleStrongRevision(expected)) return sendError(conn, arena, 400, "invalid_revision", "Send one strong event ETag in If-Match");
    if (delete) {
        dav.deleteWebCalendarEvent(sess.username, event_id, expected) catch |err| return calendarWriteError(conn, arena, err);
        return sendStatus(conn, arena, 204, "No Content", null);
    }

    const stored = dav.snapshotWebCalendarEvent(arena, sess.username, event_id, .edit) catch |err| return calendarWriteError(conn, arena, err);
    if (!std.mem.eql(u8, stored.event.etag, expected)) return calendarWriteError(conn, arena, error.PreconditionFailed);
    const data = if (put) data: {
        if (!isICalendar(req))
            return sendError(conn, arena, 415, "unsupported_media_type", "Send an iCalendar resource");
        if (req.body.len > dav.config.max_event_size) return calendarWriteError(conn, arena, error.EventTooLarge);
        break :data calendar_events.prepareReplacement(arena, stored, req.body) catch |err| return calendarWriteError(conn, arena, err);
    } else data: {
        const payload = std.json.parseFromSliceLeaky(calendar_events.Edit, arena, req.body, .{}) catch
            return sendError(conn, arena, 400, "bad_request", "Invalid event changes");
        break :data calendar_events.prepareEdit(arena, stored, payload) catch |err| return calendarWriteError(conn, arena, err);
    };
    checkCalendarEventBody(server, arena, dav, data.ics_data.?) catch |err| return calendarWriteError(conn, arena, err);
    const revision = dav.updateWebCalendarEvent(sess.username, event_id, expected, data) catch |err| return calendarWriteError(conn, arena, err);
    return sendRevisionJson(conn, arena, 200, try service_mod.json(arena, .{ .id = event_id, .etag = revision.etag() }), null, revision.etag());
}

fn isICalendar(req: Request) bool {
    const media = req.header("Content-Type") orelse return false;
    const essence = media[0 .. std.mem.indexOfScalar(u8, media, ';') orelse media.len];
    return std.ascii.eqlIgnoreCase(std.mem.trim(u8, essence, " \t"), "text/calendar");
}

fn isSingleStrongRevision(value: []const u8) bool {
    if (value.len < 3 or value[0] != '"' or value[value.len - 1] != '"') return false;
    for (value[1 .. value.len - 1]) |byte| if (byte <= 32 or byte == '"' or byte == 127) return false;
    return true;
}

fn checkCalendarEventBody(server: *WebmailHttpServer, arena: std.mem.Allocator, dav: *caldav_store.CalDavStore, body: []const u8) !void {
    if (body.len > dav.config.max_event_size) return error.EventTooLarge;
    try caldav.scanDavResource(arena, server.config.scanner, body);
}

fn calendarWriteError(conn: *webmail_tls.Stream, arena: std.mem.Allocator, err: anyerror) !void {
    return switch (err) {
        error.CalendarNotFound, error.EventNotFound, error.DavMailboxNotFound => sendError(conn, arena, 404, "not_found", "Calendar or event not found"),
        error.CalendarNameConflict => sendError(conn, arena, 409, "calendar_name_conflict", "This name is already in use"),
        error.EventAlreadyExists => sendError(conn, arena, 409, "event_exists", "An event with this UID already exists"),
        error.InvalidCalendarName => sendError(conn, arena, 400, "invalid_calendar_name", "Enter a calendar name of at most 100 bytes without slashes or consecutive dots"),
        error.InvalidEventTitle => sendError(conn, arena, 400, "invalid_title", "Enter an event title"),
        error.InvalidEventText => sendError(conn, arena, 400, "invalid_event_text", "An event field is too long or contains invalid text"),
        error.InvalidEventTime => sendError(conn, arena, 400, "invalid_event_time", "Enter valid times. An end must follow the start and all-day dates must be at UTC midnight"),
        error.EmptyEventEdit => sendError(conn, arena, 400, "empty_event_edit", "Provide at least one event change"),
        error.PreconditionFailed => sendError(conn, arena, 412, "event_changed", "The event changed. Reload it before saving"),
        error.CalendarInvitationStale => sendError(conn, arena, 409, "invitation_stale", "A newer organizer revision is available."),
        error.CalendarInvitationCancelled => sendError(conn, arena, 409, "invitation_cancelled", "The organizer cancelled this invitation."),
        error.CalendarHistoryPending => sendError(conn, arena, 503, "calendar_history_pending", "Mail is checking earlier invitations. Refresh this message and try again."),
        error.InvitationEventRequired => sendError(conn, arena, 409, "invitation_event_required", "Add the original invitation to Calendar first."),
        error.InvitationScopeConflict => sendError(conn, arena, 409, "invitation_scope_conflict", "This occurrence already anchors a change to future events."),
        error.AvailabilityUnsupported => sendError(conn, arena, 422, "invitation_recurrence_unsupported", "Mail could not resolve this recurrence."),
        error.AvailabilityLimit => sendError(conn, arena, 422, "invitation_recurrence_limit", "Mail could not expand this recurrence within its limits."),
        error.UnsupportedTimezone, error.ConflictingTimezone => sendError(conn, arena, 422, "invitation_timezone", "This event's time zone could not be verified."),
        error.InvalidCalendar, error.NoPrimaryEvent => sendError(conn, arena, 422, "invalid_calendar_event", "This stored calendar resource has no single editable primary event"),
        error.SharedEventMustBePublic => sendError(conn, arena, 422, "shared_event_must_be_public", "Shared calendar edits must use public events"),
        error.RecurringTimeEdit => sendError(conn, arena, 422, "recurring_event_time", "Edit recurring event times through a CalDAV client"),
        error.EventTooLarge, error.CalendarExportTooLarge, error.MalwareScanTooLarge => sendError(conn, arena, 413, "event_too_large", "The event exceeds the allowed size"),
        error.MalwareDetected, error.InvalidDavBinary => sendError(conn, arena, 422, "event_rejected", "The calendar resource did not pass attachment scanning"),
        error.MalwareScanUnavailable => sendError(conn, arena, 503, "scanner_unavailable", "The malware scanner is unavailable. Try again later"),
        error.PrepareFailed, error.ExecuteFailed, error.BindFailed, error.StepFailed => sendError(conn, arena, 500, "calendar_storage_error", "Calendar storage request failed. Try again."),
        else => err,
    };
}

fn handleCalendarExport(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const dav = server.dav_store orelse return sendError(conn, arena, 503, "calendar_unavailable", "Calendar is unavailable on this server");
    const calendar_id = std.fmt.parseInt(u64, req.queryParam(arena, "calendarId") orelse "", 10) catch return sendError(conn, arena, 400, "bad_request", "Invalid calendar ID");
    const data = dav.exportCalendar(arena, sess.username, calendar_id) catch |err| switch (err) {
        error.CalendarNotFound => return sendError(conn, arena, 404, "not_found", "Calendar not found"),
        error.CalendarExportTooLarge => return sendError(conn, arena, 422, "calendar_export_too_large", "This calendar exceeds the 16 MiB download limit"),
        error.ConflictingTimezone => return sendError(conn, arena, 422, "conflicting_timezone", "This calendar contains conflicting definitions for the same time zone"),
        error.InvalidCalendar => return sendError(conn, arena, 422, "invalid_calendar", "A stored event could not be exported as iCalendar"),
        else => return err,
    };
    var header: [256]u8 = undefined;
    try writeAll(conn, try std.fmt.bufPrint(&header, "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: text/calendar; charset=utf-8\r\nContent-Disposition: attachment; filename=\"calendar.ics\"\r\n" ++
        "Content-Length: {d}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n", .{data.len}));
    try writeAll(conn, data);
}

fn handleCalendarImport(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const dav = server.dav_store orelse return sendError(conn, arena, 503, "calendar_unavailable", "Calendar is unavailable on this server");
    const mode = req.queryParam(arena, "mode") orelse "preview";
    const preview = std.mem.eql(u8, mode, "preview");
    if (!preview and !std.mem.eql(u8, mode, "import")) return sendError(conn, arena, 400, "bad_request", "Choose preview or import");
    const id = req.queryParam(arena, "calendarId");
    const name = req.queryParam(arena, "calendarName");
    const destination: caldav_store.CalDavStore.ImportDestination = if (id != null and name == null)
        .{ .existing = std.fmt.parseInt(u64, id.?, 10) catch return sendError(conn, arena, 400, "bad_request", "Invalid calendar ID") }
    else if (name != null and id == null)
        .{ .name = calendar_import.calendarName(arena, name.?) catch |err| switch (err) {
            error.InvalidCalendarName => return sendError(conn, arena, 400, "invalid_calendar_name", "Enter a calendar name of at most 100 bytes without slashes or consecutive dots"),
            else => return err,
        } }
    else
        return sendError(conn, arena, 400, "bad_request", "Choose an existing calendar or enter a new calendar name");

    const entries = calendar_import.prepare(arena, req.body) catch |err| switch (err) {
        error.InvalidCalendar => return sendError(conn, arena, 422, "invalid_calendar", "Choose a valid iCalendar (.ics) file"),
        error.NoEvents => return sendError(conn, arena, 422, "no_events", "The calendar file has no events"),
        error.TooManyEvents => return sendError(conn, arena, 422, "too_many_events", "Import a file with at most 1,000 events or occurrences"),
        else => return err,
    };
    const proposed = try arena.alloc(?caldav_store.CalDavStore.ImportEvent, entries.len);
    for (entries, proposed) |*entry, *item| {
        item.* = null;
        const event = entry.event orelse continue;
        caldav.scanDavResource(arena, server.config.scanner, event.ics_data.?) catch |err| {
            entry.issue = switch (err) {
                error.MalwareDetected => "The malware scanner rejected this event.",
                error.InvalidDavBinary => "The event includes invalid binary data.",
                error.MalwareScanTooLarge => "The event exceeds the scanner size limit.",
                error.MalwareScanUnavailable => "The malware scanner is unavailable. Try again later.",
                else => return err,
            };
            continue;
        };
        item.* = .{ .uid = entry.uid.?, .data = event };
    }
    const result = dav.importEvents(arena, sess.username, destination, proposed, preview) catch |err| switch (err) {
        error.CalendarNotFound => return sendError(conn, arena, 404, "not_found", "Calendar not found"),
        error.CalendarNameConflict => return sendError(conn, arena, 409, "calendar_name_conflict", "An address book already has this name. Choose a different calendar name"),
        else => return err,
    };
    const Row = struct {
        number: usize,
        summary: []const u8,
        start: ?i64,
        allDay: bool,
        status: []const u8,
        message: ?[]const u8,
    };
    const rows = try arena.alloc(Row, entries.len);
    for (entries, result.statuses, rows) |entry, status, *row| {
        row.* = .{
            .number = entry.number,
            .summary = entry.summary,
            .start = if (entry.event) |event| event.dtstart else null,
            .allDay = if (entry.event) |event| event.all_day else false,
            .status = if (status == .failed) "error" else @tagName(status),
            .message = entry.issue orelse switch (status) {
                .skipped => "This event is already in the destination calendar.",
                .failed => "This event could not be stored.",
                else => null,
            },
        };
    }
    return sendJson(conn, arena, 200, try service_mod.json(arena, .{ .calendarId = result.calendar_id, .events = rows }), null);
}

fn validContactComponent(value: []const u8, max: usize) bool {
    if (value.len == 0 or value.len > max or !std.unicode.utf8ValidateSlice(value)) return false;
    for (value) |byte| {
        if (byte < 0x20 or byte == 0x7f or byte == '/' or byte == '\\') return false;
    }
    return !std.mem.eql(u8, value, ".") and !std.mem.eql(u8, value, "..");
}

fn addressBookError(conn: *webmail_tls.Stream, a: std.mem.Allocator, err: anyerror) !void {
    return switch (err) {
        error.ContactNotFound, error.AddressBookNotFound => sendError(conn, a, 404, "not_found", "Contact or address book not found"),
        error.PreconditionFailed => sendError(conn, a, 412, "revision_mismatch", "The card has changed. Reload it before saving."),
        error.InvalidGroupMember => sendError(conn, a, 400, "invalid_member", "Choose contacts with addresses or vCard IDs from this address book"),
        error.InvalidContact => sendError(conn, a, 400, "bad_request", "Enter a valid name, note and contact information"),
        else => err,
    };
}

fn validateContactEdit(edit: caldav_store.ContactEdit) !caldav_store.ContactEdit {
    var result = edit;
    result.name = privateText(edit.name, 256, false, false) catch return error.InvalidContact;
    if (edit.note.len > 8192) return error.InvalidContact;
    _ = privateText(edit.note, 8192, true, true) catch return error.InvalidContact;
    if (edit.emails.len > 64 or edit.members.len > 256) return error.InvalidContact;
    if (edit.kind == .contact and edit.members.len != 0) return error.InvalidContact;
    if (edit.kind == .group and edit.emails.len != 0) return error.InvalidContact;
    for (edit.emails, 0..) |email, i| {
        if (!compose.isSafeAddress(email)) return error.InvalidContact;
        for (edit.emails[0..i]) |previous| if (std.ascii.eqlIgnoreCase(previous, email)) return error.InvalidContact;
    }
    for (edit.members) |member| if (!validContactComponent(member, 256)) return error.InvalidGroupMember;
    return result;
}

fn handleAddressBook(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    const read = std.mem.eql(u8, req.method, "GET");
    const create = std.mem.eql(u8, req.method, "POST");
    const update = std.mem.eql(u8, req.method, "PUT");
    const remove = std.mem.eql(u8, req.method, "DELETE");
    if (!read and !create and !update and !remove) return sendError(conn, a, 405, "method_not_allowed", "Use GET, POST, PUT or DELETE");
    if (!read and !isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    const dav = server.dav_store orelse return sendError(conn, a, 503, "contacts_unavailable", "Contacts are unavailable on this server");
    const collection = req.queryParam(a, "book");
    if (collection) |book| if (!validContactComponent(book, 128)) return addressBookError(conn, a, error.AddressBookNotFound);
    if (read) {
        const snapshot = dav.snapshotContactBook(a, sess.username, collection) catch |err| return addressBookError(conn, a, err);
        return sendJson(conn, a, 200, try service_mod.json(a, snapshot), null);
    }
    const book = collection orelse caldav_store.CalDavStore.default_address_book;
    const uid, const expected = if (create) .{ @as(?[]const u8, null), @as(?[]const u8, null) } else mutate: {
        const uid = req.queryParam(a, "uid") orelse return addressBookError(conn, a, error.ContactNotFound);
        if (!validContactComponent(uid, 256)) return addressBookError(conn, a, error.ContactNotFound);
        const etag = req.header("If-Match") orelse return sendError(conn, a, 428, "revision_required", "Send the contact's revision in If-Match");
        if (!isSingleStrongRevision(etag)) return sendError(conn, a, 400, "invalid_revision", "Send one strong contact ETag in If-Match");
        break :mutate .{ @as(?[]const u8, uid), @as(?[]const u8, etag) };
    };
    if (remove) {
        dav.removeOwnedContact(sess.username, book, uid.?, expected.?) catch |err| return addressBookError(conn, a, err);
        return sendStatus(conn, a, 204, "No Content", null);
    }
    const input = std.json.parseFromSliceLeaky(caldav_store.ContactEdit, a, req.body, .{}) catch return addressBookError(conn, a, error.InvalidContact);
    const edit = validateContactEdit(input) catch |err| return addressBookError(conn, a, err);
    const result = dav.editOwnedContact(a, sess.username, book, uid, .{ .if_match = expected, .if_none_match = if (create) "*" else null }, edit) catch |err|
        return addressBookError(conn, a, err);
    return sendRevisionJson(conn, a, if (result.created) 201 else 200, try service_mod.json(a, .{ .etag = result.etag() }), null, result.etag());
}

fn handleContacts(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const query = req.queryParam(arena, "q") orelse "";
    if (query.len > 256) return sendError(conn, arena, 400, "bad_request", "Contact search is too long");
    var contacts: std.ArrayList(Contact) = .empty;
    var known = std.StringHashMap(void).init(arena);
    defer known.deinit();
    if (server.dav_store) |addressbook| {
        const saved = try addressbook.suggestContacts(arena, sess.username, query, 10);
        for (saved) |contact| {
            if (!compose.isSafeAddress(contact.address)) continue;
            try known.put(try std.ascii.allocLowerString(arena, contact.address), {});
            try contacts.append(arena, .{ .address = contact.address, .name = contact.name });
        }
    }
    for ([_][]const u8{ "Sent", "INBOX" }) |folder| {
        const rows = try maildir.listMessages(arena, server.db, sess.username, folder, 1, 200);
        for (rows) |row| {
            try collectContacts(arena, &contacts, &known, if (std.mem.eql(u8, folder, "Sent")) row.to else row.from, query);
            if (contacts.items.len >= 10) break;
        }
        if (contacts.items.len >= 10) break;
    }
    var body: std.ArrayList(u8) = .empty;
    const w = jw(&body, arena);
    try w.writeAll("[");
    for (contacts.items, 0..) |contact, index| {
        if (index > 0) try w.writeAll(",");
        try w.writeAll("{\"address\":");
        try writeJsonString(w, contact.address);
        try w.writeAll(",\"name\":");
        try writeJsonString(w, contact.name);
        try w.writeAll("}");
    }
    try w.writeAll("]");
    return sendJson(conn, arena, 200, body.items, null);
}

const Contact = struct { address: []const u8, name: []const u8 };
fn collectContacts(a: std.mem.Allocator, result: *std.ArrayList(Contact), known: *std.StringHashMap(void), header: []const u8, query: []const u8) !void {
    var start: usize = 0;
    var quoted = false;
    var angle = false;
    var index: usize = 0;
    while (index <= header.len and result.items.len < 10) : (index += 1) {
        if (index < header.len) {
            const byte = header[index];
            if (byte == '\\' and quoted and index + 1 < header.len) {
                index += 1;
                continue;
            }
            if (byte == '"') quoted = !quoted;
            if (byte == '<' and !quoted) angle = true;
            if (byte == '>' and !quoted) angle = false;
            if (byte != ',' or quoted or angle) continue;
        }
        const value = std.mem.trim(u8, header[start..index], " \t\r\n");
        start = index + 1;
        var address = value;
        var name: []const u8 = "";
        if (std.mem.lastIndexOfScalar(u8, value, '<')) |open| {
            if (std.mem.lastIndexOfScalar(u8, value, '>')) |close| {
                if (close > open) {
                    address = std.mem.trim(u8, value[open + 1 .. close], " ");
                    name = std.mem.trim(u8, value[0..open], " \"");
                }
            }
        }
        if (!compose.isSafeAddress(address)) continue;
        if (query.len > 0 and ascii_compat.indexOfIgnoreCase(address, query) == null and ascii_compat.indexOfIgnoreCase(name, query) == null) continue;
        const key = try std.ascii.allocLowerString(a, address);
        if (known.contains(key)) continue;
        try known.put(key, {});
        try result.append(a, .{ .address = try a.dupe(u8, address), .name = try a.dupe(u8, name) });
    }
}

fn handleOutboxList(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    if (req.queryParam(arena, "view")) |value| {
        const view = std.meta.stringToEnum(store.OutboxView, value) orelse
            return sendError(conn, arena, 400, "invalid_outbox_view", "Choose a valid Outbox view.");
        const after = req.queryParam(arena, "after");
        const track = req.queryParam(arena, "track");
        if (after) |id| {
            if (view == .overview or !store.validId(id)) return sendError(conn, arena, 400, "invalid_outbox_cursor", "Choose a valid Outbox cursor.");
        }
        if (track) |id| {
            if (!store.validId(id)) return sendError(conn, arena, 400, "invalid_outbox_id", "Choose a valid Outbox message.");
        }
        const page = store.outboxPage(arena, server.db, sess.username, view, after, track) catch |err| {
            if (err == store.StoreError.NotFound)
                return sendError(conn, arena, 404, "outbox_cursor_expired", "This Outbox page has changed. Open the first page.");
            return mapServiceError(conn, arena, err);
        };
        return sendJson(conn, arena, 200, try service_mod.json(arena, .{
            .items = page.items,
            .counts = page.counts,
            .nextCursor = page.nextCursor,
            .tracked = page.tracked,
            .serverTime = time_compat.timestamp(),
        }), null);
    }
    const rows = try store.list(arena, server.db, sess.username, "outbox", 100);
    var body: std.ArrayList(u8) = .empty;
    const w = jw(&body, arena);
    try w.writeAll("[");
    for (rows, 0..) |row, index| {
        if (index > 0) try w.writeAll(",");
        try w.writeAll(try outboxJson(arena, row));
    }
    try w.writeAll("]");
    return sendJson(conn, arena, 200, body.items, null);
}

fn handleOutboxItem(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    const cancelling = std.mem.eql(u8, req.method, "DELETE");
    const resolving = std.mem.eql(u8, req.method, "PATCH");
    if (!cancelling and !resolving and !std.mem.eql(u8, req.method, "GET")) return sendError(conn, arena, 405, "method_not_allowed", "Use GET, DELETE or PATCH");
    if ((cancelling or resolving) and !isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const id = pathId(req.path, "/webmail/api/outbox/") orelse return sendError(conn, arena, 400, "bad_request", "Invalid send id");
    if (resolving) {
        const reviewed = std.json.parseFromSlice(struct { reviewed: bool }, arena, req.body, .{}) catch return sendError(conn, arena, 400, "bad_request", "Confirm that the delivery result was reviewed");
        defer reviewed.deinit();
        if (!reviewed.value.reviewed) return sendError(conn, arena, 400, "bad_request", "Confirm that the delivery result was reviewed");
    }
    const row = (if (cancelling) server.service.cancel(arena, sess.username, id, time_compat.timestamp()) else if (resolving) server.service.resolveUnknown(arena, sess.username, id, time_compat.timestamp()) else store.get(arena, server.db, sess.username, "outbox", id)) catch |err| return mapServiceError(conn, arena, err);
    return sendJson(conn, arena, 200, try outboxJson(arena, row), null);
}

fn handleCategorySettings(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    const write = std.mem.eql(u8, req.method, "PUT");
    if (write and !isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const Settings = struct { automatic: bool };
    if (write) {
        const payload = std.json.parseFromSlice(Settings, arena, req.body, .{}) catch
            return sendError(conn, arena, 400, "bad_request", "Invalid mail sorting setting");
        defer payload.deinit();
        {
            server.db.lockMailboxes();
            defer server.db.unlockMailboxes();
            try server.db.setCategorySettings(sess.username, payload.value.automatic);
        }
    }
    const policy = try server.db.categoryPolicy(sess.username, "");
    return sendJson(conn, arena, 200, try service_mod.json(arena, Settings{ .automatic = policy.automatic }), null);
}

fn handleCategoryRule(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const expected = req.header("If-Match") orelse return sendError(conn, arena, 428, "revision_required", "Read the message and send its ETag in If-Match");
    if (!isSingleStrongRevision(expected)) return sendError(conn, arena, 400, "invalid_revision", "Send one strong message ETag in If-Match");
    const payload = std.json.parseFromSlice(struct { reference: []const u8, destination: []const u8 }, arena, req.body, .{}) catch
        return sendError(conn, arena, 400, "bad_request", "Invalid sender rule");
    defer payload.deinit();
    const value = payload.value;
    const destination: ?categories.Destination = if (std.mem.eql(u8, value.destination, "automatic")) null else std.meta.stringToEnum(categories.Destination, value.destination) orelse
        return sendError(conn, arena, 400, "bad_request", "Unknown sorting destination");
    updateCategoryRule(arena, server.db, sess.username, value.reference, expected, destination) catch |err| switch (err) {
        error.UnverifiedSender => return sendError(conn, arena, 409, "sender_unverified", "A sender rule needs a message from a verified sender"),
        else => return mapMaildirError(conn, arena, err),
    };
    return sendJson(conn, arena, 200, try service_mod.json(arena, .{ .destination = value.destination }), null);
}

fn updateCategoryRule(a: std.mem.Allocator, db: *database.Database, user: []const u8, reference: []const u8, expected: []const u8, destination: ?categories.Destination) !void {
    db.lockMailboxes();
    defer db.unlockMailboxes();
    _ = try maildir.checkRevision(a, db, user, reference, expected);
    const placement = (try message_refs.placement(a, db, user, reference)) orelse return error.UnverifiedSender;
    if (placement.verified_author.len == 0) return error.UnverifiedSender;
    try db.setCategoryRule(user, placement.verified_author, destination);
}

fn handleAttentionStatus(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    const snapshot = try attention.load(a, server.db, sess.username);
    const status: ?attention.Status = if (req.queryParam(a, "reference")) |reference| blk: {
        const msg = maildir.getByReference(a, server.db, sess.username, reference) catch |err| return mapMaildirError(conn, a, err);
        const ids = try thread_ids.fromFields(a, msg.message_id, msg.in_reply_to, msg.references);
        break :blk snapshot.status(reference, "", "", "", ids);
    } else null;
    return sendJson(conn, a, 200, try service_mod.json(a, .{ .due_reminders = snapshot.dueCount(time_compat.timestamp()), .attention = status }), null);
}

const AttentionChange = struct {
    reference: []const u8,
    kind: attention.Kind,
    enabled: bool,
    deadline: i64 = 0,
};

fn handleBrowserNotifications(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    const write = std.mem.eql(u8, req.method, "PUT");
    if (write and !isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    const Setting = struct { enabled: bool };
    if (write) {
        const doc = std.json.parseFromSlice(Setting, a, req.body, .{}) catch
            return sendError(conn, a, 400, "bad_request", "Invalid notification setting");
        defer doc.deinit();
        server.db.lockMailboxes();
        defer server.db.unlockMailboxes();
        try server.db.setBrowserNotifications(sess.username, doc.value.enabled);
    }
    const value: Setting = .{ .enabled = try server.db.browserNotificationsEnabled(sess.username) };
    return sendJson(conn, a, 200, try service_mod.json(a, value), null);
}

fn handleBrowserNotificationClaim(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    const ids = try server.db.claimBrowserNotifications(a, sess.username);
    const replies = team_threads.claimReplyNotices(a, server.db, sess.username, server.service.junkFolder()) catch |err| blk: {
        logger.warn("Shared reply notification claim failed: {}", .{err});
        break :blk 0;
    };
    if (replies == 0) return sendJson(conn, a, 200, try service_mod.json(a, .{ .ids = ids }), null);
    return sendJson(conn, a, 200, try service_mod.json(a, .{ .ids = ids, .teamReplies = replies }), null);
}

const BrowserNotificationChange = struct {
    reference: []const u8,
    scope: database.Database.NotificationScope,
    rule: database.Database.NotificationRule,
};

fn handleBrowserNotificationRule(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    const expected = req.header("If-Match") orelse return sendError(conn, a, 428, "revision_required", "Read the message and send its ETag in If-Match");
    if (!isSingleStrongRevision(expected)) return sendError(conn, a, 400, "invalid_revision", "Send one strong message ETag in If-Match");
    const doc = std.json.parseFromSlice(BrowserNotificationChange, a, req.body, .{}) catch
        return sendError(conn, a, 400, "bad_request", "Invalid notification rule");
    defer doc.deinit();
    const result = updateBrowserNotificationRule(a, server.db, sess.username, doc.value, expected) catch |err| switch (err) {
        error.UnverifiedSender => return sendError(conn, a, 409, "sender_unverified", "A sender rule needs a message from a verified sender"),
        else => return mapMaildirError(conn, a, err),
    };
    return sendJson(conn, a, 200, try service_mod.json(a, result), null);
}

fn updateBrowserNotificationRule(a: std.mem.Allocator, db: *database.Database, user: []const u8, change: BrowserNotificationChange, expected: []const u8) !database.Database.NotificationRules {
    db.lockMailboxes();
    defer db.unlockMailboxes();
    const file = try maildir.resolveVersioned(a, db, user, change.reference);
    if (!std.mem.eql(u8, file.version.revision, expected)) return error.RevisionMismatch;
    const placement = try message_refs.placement(a, db, user, change.reference);
    const author = if (placement) |value| value.verified_author else "";
    const ids = try thread_ids.parse(a, file.raw);
    const keys = try service_mod.json(a, try ids.keys(a));
    try db.setBrowserNotificationRule(user, change.reference, keys, author, change.scope, change.rule);
    return db.browserNotificationRules(user, change.reference, keys, author);
}

fn handleAttentionChange(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    const expected = req.header("If-Match") orelse return sendError(conn, a, 428, "revision_required", "Read the message and send its ETag in If-Match");
    if (!isSingleStrongRevision(expected)) return sendError(conn, a, 400, "invalid_revision", "Send one strong message ETag in If-Match");
    const payload = std.json.parseFromSlice(AttentionChange, a, req.body, .{}) catch
        return sendError(conn, a, 400, "bad_request", "Invalid message action");
    defer payload.deinit();
    const change = payload.value;
    const now = time_compat.timestamp();
    if (change.enabled and (change.kind == .snoozed or change.kind == .reminders) and
        (change.deadline <= now or change.deadline > now + 366 * 86400)) return sendError(conn, a, 400, "invalid_deadline", "Choose a future time within one year");
    const status = updateAttention(a, server.db, sess.username, change, expected) catch |err| switch (err) {
        error.InvalidSentMessage => return sendError(conn, a, 400, "invalid_sent_message", "Set a no-reply reminder from a sent message with a Message-ID"),
        error.AlreadyReplied => return sendError(conn, a, 409, "already_replied", "A reply has already arrived for this message"),
        else => return mapMaildirError(conn, a, err),
    };
    return sendJson(conn, a, 200, try service_mod.json(a, status), null);
}

fn updateAttention(a: std.mem.Allocator, db: *database.Database, user: []const u8, change: AttentionChange, expected: []const u8) !attention.Status {
    db.lockMailboxes();
    defer db.unlockMailboxes();
    const file = try maildir.resolveVersioned(a, db, user, change.reference);
    if (!std.mem.eql(u8, file.version.revision, expected)) return error.RevisionMismatch;
    const ids = try thread_ids.parse(a, file.raw);
    if (change.enabled and change.kind == .reminders and
        (!std.mem.eql(u8, file.locator.folder, "Sent") or ids.own == null)) return error.InvalidSentMessage;
    const keys = try std.json.Stringify.valueAlloc(a, try ids.keys(a), .{});
    const waiting_id = if (change.kind == .reminders) ids.own orelse "" else "";
    try db.changeAttention(user, change.reference, change.kind, change.enabled, change.deadline, time_compat.milliTimestamp(), keys, waiting_id);
    const snapshot = try attention.load(a, db, user);
    return snapshot.status(change.reference, "", "", "", ids);
}

const PrivateChange = struct {
    reference: []const u8,
    action: enum { note, clip, edit, remove, label, collection },
    body: ?[]const u8 = null,
    entry: ?[]const u8 = null,
    revision: ?i64 = null,
    label_revision: ?[]const u8 = null,
    collection: ?[]const u8 = null,
    included: ?bool = null,
    shareCollectionMessage: bool = false,
};

fn privateError(conn: *webmail_tls.Stream, a: std.mem.Allocator, err: anyerror) !void {
    return switch (err) {
        error.InvalidPrivateChange => sendError(conn, a, 400, "bad_request", "Invalid private conversation change"),
        error.InvalidClip => sendError(conn, a, 400, "bad_request", "Choose an excerpt from the message text"),
        error.CollectionChanged => sendError(conn, a, 409, "conflict", "Collection changed or name already exists"),
        error.CollectionShareConfirmationRequired => sendError(conn, a, 409, "shared_collection_confirmation", "Reopen Private tools to confirm adding this message to the shared collection."),
        error.NotFound => sendError(conn, a, 404, "not_found", "Private item not found"),
        else => mapMaildirError(conn, a, err),
    };
}

fn privateText(value: ?[]const u8, limit: usize, allow_empty: bool, multiline: bool) ![]const u8 {
    const text = std.mem.trim(u8, value orelse return error.InvalidPrivateChange, " \t\r\n");
    if ((!allow_empty and text.len == 0) or text.len > limit or !std.unicode.utf8ValidateSlice(text)) return error.InvalidPrivateChange;
    for (text) |c| {
        if (c >= 0x20 and c != 0x7f) continue;
        if (multiline and (c == '\t' or c == '\n' or c == '\r')) continue;
        return error.InvalidPrivateChange;
    }
    return text;
}

fn privateID(value: ?[]const u8) ![]const u8 {
    const id = value orelse return error.InvalidPrivateChange;
    if (!message_refs.valid(id)) return error.InvalidPrivateChange;
    return id;
}

fn applyPrivateChange(a: std.mem.Allocator, db: *database.Database, user: []const u8, file: maildir.VersionedFile, change: PrivateChange, current: personal.Context, clip_source: []const u8) !void {
    switch (change.action) {
        .note, .clip => {
            const is_clip = change.action == .clip;
            const body = try privateText(change.body, if (is_clip) 2048 else 8192, false, true);
            if (is_clip and std.mem.indexOf(u8, clip_source, body) == null) return error.InvalidClip;
            const subject = if (is_clip) (try maildir.reviewHeaders(a, file.raw)).subject else "";
            try personal.remember(a, db, user, change.reference, current.natural_wire);
            try personal.addEntry(db, user, change.reference, if (is_clip) .clip else .note, body, if (std.unicode.utf8ValidateSlice(subject)) subject else "");
        },
        .edit, .remove => {
            const id = try privateID(change.entry);
            const revision = change.revision orelse return error.InvalidPrivateChange;
            const body = if (change.action == .edit) try privateText(change.body, 8192, false, true) else null;
            try personal.changeEntry(db, user, current, id, revision, body);
        },
        .label => {
            const label = try privateText(change.body, 120, true, false);
            const revision = change.label_revision orelse return error.InvalidPrivateChange;
            if (label.len > 0) try personal.remember(a, db, user, change.reference, current.natural_wire);
            try personal.setLabel(db, user, change.reference, current, label, revision);
        },
        .collection => {
            const id = try privateID(change.collection);
            const included = change.included orelse return error.InvalidPrivateChange;
            if (included) try personal.remember(a, db, user, change.reference, current.natural_wire);
            try personal.setMember(db, user, change.reference, id, included, change.shareCollectionMessage, current);
        },
    }
}

fn privateMessage(a: std.mem.Allocator, db: *database.Database, user: []const u8, reference: []const u8, expected: ?[]const u8, change: ?PrivateChange) !personal.MessageTools {
    const live_links = if (change != null or try personal.hasAnchors(db, user)) try maildir.conversationLinks(a, db, user) else &.{};
    db.lockMailboxes();
    defer db.unlockMailboxes();
    const file = try personal.resolve(a, db, user, reference, expected);
    const wire = try personal.wireKeys(a, file);
    const source = try maildir.clipText(a, file.raw);
    var current = try personal.context(a, db, user, reference, wire, live_links);
    if (change) |value| {
        try applyPrivateChange(a, db, user, file, value, current, source);
        current = try personal.context(a, db, user, reference, wire, live_links);
    }
    var length = @min(source.len, 12_288);
    while (length < source.len and source[length] & 0xc0 == 0x80) length -= 1;
    return personal.tools(a, db, user, reference, current, source[0..length]);
}

fn handlePrivateMessage(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    const write = std.mem.eql(u8, req.method, "POST");
    if (write and !isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    const result = if (write) blk: {
        const expected = req.header("If-Match") orelse return sendError(conn, a, 428, "revision_required", "Read the message and send its ETag in If-Match");
        if (!isSingleStrongRevision(expected)) return sendError(conn, a, 400, "invalid_revision", "Send one strong message ETag in If-Match");
        const doc = std.json.parseFromSlice(PrivateChange, a, req.body, .{}) catch return privateError(conn, a, error.InvalidPrivateChange);
        defer doc.deinit();
        break :blk privateMessage(a, server.db, sess.username, doc.value.reference, expected, doc.value);
    } else privateMessage(a, server.db, sess.username, req.queryParam(a, "reference") orelse "", null, null);
    return sendJson(conn, a, 200, try service_mod.json(a, result catch |err| return privateError(conn, a, err)), null);
}

const PrivateCollectionChange = struct {
    action: personal.CollectionAction,
    id: ?[]const u8 = null,
    revision: ?i64 = null,
    name: ?[]const u8 = null,
};

fn changePrivateCollection(db: *database.Database, user: []const u8, change: PrivateCollectionChange) !void {
    const name = if (change.action != .delete) try privateText(change.name, 80, false, false) else null;
    const id = if (change.action != .create) try privateID(change.id) else null;
    if (id != null and change.revision == null) return error.InvalidPrivateChange;
    db.lockMailboxes();
    defer db.unlockMailboxes();
    try personal.changeCollection(db, user, change.action, id, change.revision, name);
}

fn handlePrivateCollections(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    const write = std.mem.eql(u8, req.method, "POST");
    if (write and !isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    if (write) {
        const doc = std.json.parseFromSlice(PrivateCollectionChange, a, req.body, .{}) catch return privateError(conn, a, error.InvalidPrivateChange);
        defer doc.deinit();
        changePrivateCollection(server.db, sess.username, doc.value) catch |err| return privateError(conn, a, err);
    }
    const items = try personal.listCollections(a, server.db, sess.username, "[]", null);
    return sendJson(conn, a, 200, try service_mod.json(a, .{ .items = items }), null);
}

fn createPrivateGroup(a: std.mem.Allocator, db: *database.Database, user: []const u8, targets: []const personal.Target) !personal.GroupReceipt {
    if (targets.len < 2 or targets.len > 200) return error.InvalidPrivateChange;
    const live_links = try maildir.conversationLinks(a, db, user);
    db.lockMailboxes();
    defer db.unlockMailboxes();
    var unique = std.StringHashMap(void).init(a);
    const refs = try a.alloc([]const u8, targets.len);
    const wires = try a.alloc([]const []const u8, targets.len);
    for (targets, refs, wires) |target, *reference, *wire| {
        const slot = try unique.getOrPut(target.reference);
        if (slot.found_existing or !isSingleStrongRevision(target.revision)) return error.InvalidPrivateChange;
        const file = try personal.resolve(a, db, user, target.reference, target.revision);
        reference.* = target.reference;
        wire.* = try personal.wireKeys(a, file);
    }
    return personal.createGroup(a, db, user, refs, wires, live_links);
}

fn handlePrivateGroup(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    const Payload = struct { messages: []const personal.Target };
    const doc = std.json.parseFromSlice(Payload, a, req.body, .{}) catch return privateError(conn, a, error.InvalidPrivateChange);
    defer doc.deinit();
    const receipt = createPrivateGroup(a, server.db, sess.username, doc.value.messages) catch |err| return privateError(conn, a, err);
    return sendJson(conn, a, 200, try service_mod.json(a, receipt), null);
}

fn handlePrivateGroupUndo(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    const id = privateID(try jsonStringFieldAlloc(a, req.body, "id")) catch |err| return privateError(conn, a, err);
    {
        server.db.lockMailboxes();
        defer server.db.unlockMailboxes();
        personal.undoGroup(server.db, sess.username, id) catch |err| return privateError(conn, a, err);
    }
    return sendJson(conn, a, 200, "{\"ok\":true}", null);
}

fn searchFilters(req: Request, a: std.mem.Allocator, folder: []const u8) !maildir.QueryOptions {
    const query = req.queryParam(a, "q") orelse "";
    const sender = req.queryParam(a, "from") orelse "";
    const recipient = req.queryParam(a, "to") orelse "";
    const filename = req.queryParam(a, "filename") orelse "";
    for ([_][]const u8{ query, sender, recipient, filename }) |term| {
        if (term.len > 256 or std.mem.indexOfScalar(u8, term, 0) != null) return error.InvalidSearch;
    }
    const after: ?i64 = if (req.queryParam(a, "after")) |value| std.fmt.parseInt(i64, value, 10) catch return error.InvalidDate else null;
    const before: ?i64 = if (req.queryParam(a, "before")) |value| std.fmt.parseInt(i64, value, 10) catch return error.InvalidDate else null;
    if (after != null and before != null and before.? < after.?) return error.InvalidDateRange;
    const MessageStatus = enum { any, read, unread, answered };
    const status = std.meta.stringToEnum(MessageStatus, req.queryParam(a, "status") orelse "any") orelse return error.InvalidStatus;
    return .{
        .folder = folder,
        .query = query,
        .sender = sender,
        .recipient = recipient,
        .filename = filename,
        .after = after,
        .before = before,
        .attachments = std.mem.eql(u8, req.queryParam(a, "attachments") orelse "", "true"),
        .unread = status == .unread or std.mem.eql(u8, req.queryParam(a, "unread") orelse "", "true"),
        .read = status == .read,
        .answered = status == .answered,
        .flagged = std.mem.eql(u8, req.queryParam(a, "flagged") orelse "", "true"),
        .index_budget = if (req.queryParam(a, "index_budget") != null)
            std.math.clamp(parseUintParam(req, a, "index_budget", 256), 1, 512)
        else
            std.math.maxInt(usize),
    };
}

fn searchFilterError(conn: *webmail_tls.Stream, a: std.mem.Allocator, err: anyerror) !void {
    return sendError(conn, a, 400, "bad_request", switch (err) {
        error.InvalidSearch => "Search terms must fit within 256 bytes",
        error.InvalidDate => "Invalid date filter",
        error.InvalidDateRange => "End date precedes start date",
        error.InvalidStatus => "Invalid message status",
        else => "Invalid search",
    });
}

fn writeSearchIndex(w: anytype, progress: search_index.Progress) !void {
    try w.print("{{\"indexed\":{d},\"total\":{d},\"pending\":{}}}", .{ progress.indexed, progress.total, !progress.complete() });
}

fn handleMessageList(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    const io = io_compat.getIo();
    const started = std.Io.Clock.awake.now(io);
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);

    const collection = req.queryParam(arena, "collection");
    if (collection) |id| {
        if (!message_refs.valid(id) or !try personal.hasCollection(server.db, sess.username, id))
            return privateError(conn, arena, error.NotFound);
    }
    const folder = if (collection != null) "*" else req.queryParam(arena, "folder") orelse "INBOX";
    const view: ?attention.Kind = if (req.queryParam(arena, "attention")) |name|
        std.meta.stringToEnum(attention.Kind, name) orelse return sendError(conn, arena, 400, "bad_request", "Unknown mail workflow")
    else
        null;
    if (view != null and collection != null) return privateError(conn, arena, error.InvalidPrivateChange);
    const workflow: ?attention.Snapshot = if (view != null or attention.isInboxView(folder)) try attention.load(arena, server.db, sess.username) else null;
    const unread_queue = std.mem.eql(u8, req.queryParam(arena, "queue") orelse "", "unread");
    if (unread_queue and view != null) return sendError(conn, arena, 400, "bad_request", "Next unread works in mail folders");
    const queue_cursor = if (unread_queue) unreadQueueCursor(req, arena) catch return sendError(conn, arena, 400, "bad_request", "Invalid unread position") else null;
    const requested_page = @max(parseUintParam(req, arena, "page", 1), 1);
    const per_page = @max(@min(parseUintParam(req, arena, "per_page", server.config.messages_per_page), 200), 1);
    var options = searchFilters(req, arena, if (view != null) "*" else folder) catch |err| return searchFilterError(conn, arena, err);
    const bundled = !unread_queue and view == null and categories.isCategory(folder) and std.mem.eql(u8, req.queryParam(arena, "bundles") orelse "", "true");
    const conversations = !unread_queue and view == null and !bundled and std.mem.eql(u8, req.queryParam(arena, "conversations") orelse "", "true");
    const grouped = bundled or conversations;
    var progress: search_index.Progress = .{};
    options.unread = unread_queue or options.unread;
    options.include_context = conversations;
    options.include_versions = true;
    options.attention_view = view;
    options.attention_snapshot = if (view != null or (workflow != null and workflow.?.hasHidden())) workflow else null;
    options.unread_queue = unread_queue;
    options.headers_only = unread_queue and options.query.len == 0 and !options.attachments;
    if (unread_queue) options.index_budget = std.math.maxInt(usize);
    options.index_progress = &progress;
    var rows = maildir.queryMessages(arena, server.db, sess.username, options) catch |err| {
        if (err == maildir.MaildirError.InvalidFolderName) return sendError(conn, arena, 400, "bad_request", "Invalid folder");
        return sendError(conn, arena, 500, "server_error", "Failed to read messages");
    };
    if (collection != null or std.mem.eql(u8, req.queryParam(arena, "personal") orelse "", "true"))
        rows = personal.decorate(arena, server.db, sess.username, rows, collection) catch |err| return privateError(conn, arena, err);
    const grouped_rows: []const threads.Thread = if (bundled)
        try threads.bundleSenders(arena, rows)
    else if (conversations)
        try threads.group(arena, rows)
    else
        &.{};
    const total = if (grouped) grouped_rows.len else rows.len;
    const last_page = @max(total / per_page + @intFromBool(total % per_page > 0), 1);
    const page = if (unread_queue) 1 else @min(requested_page, last_page);
    const start = if (unread_queue) nextUnreadIndex(rows, queue_cursor) else (page - 1) * per_page;
    const unread_batch = unread_queue and std.mem.eql(u8, req.queryParam(arena, "batch") orelse "", "true");
    const count = if (unread_batch) @min(per_page, 12) else if (unread_queue) 1 else per_page;
    const end = @min(start + count, total);
    var matching: usize = 0;
    for (rows) |row| if (row.matches_filters) {
        matching += 1;
    };

    var body: std.ArrayList(u8) = .empty;
    const w = jw(&body, arena);
    try w.writeAll("{\"folder\":");
    try writeJsonString(w, folder);
    try w.print(",\"page\":{d},\"total\":{d},\"message_total\":{d},\"conversations\":{},\"sender_bundles\":{},\"index\":", .{ page, total, matching, conversations, bundled });
    try writeSearchIndex(w, progress);
    try w.writeAll(",\"items\":[");
    const msgs = if (grouped) &[_]maildir.MessageSummary{} else rows[start..end];
    for (msgs, 0..) |m, i| {
        if (i > 0) try w.writeAll(",");
        try writeMessageSummary(w, m, try maildir.summaryVersion(arena, server.db, sess.username, m));
    }
    try w.writeAll("],\"threads\":[");
    if (grouped) for (grouped_rows[start..end], 0..) |thread, index| {
        if (index > 0) try w.writeAll(",");
        try w.writeAll("{\"id\":");
        try writeJsonString(w, thread.id);
        try w.print(",\"count\":{d},\"unread\":{d},\"matching\":{d},\"latest\":", .{ thread.members.len, thread.unread, thread.matching });
        const latest_version = try maildir.summaryVersion(arena, server.db, sess.username, thread.latest);
        try writeMessageSummary(w, thread.latest, latest_version);
        try w.writeAll(",\"members\":[");
        for (thread.members, 0..) |member, member_index| {
            if (member_index > 0) try w.writeAll(",");
            const version = if (member.uid == thread.latest.uid and std.mem.eql(u8, member.folder, thread.latest.folder)) latest_version else try maildir.summaryVersion(arena, server.db, sess.username, member);
            try writeMessageSummary(w, member, version);
        }
        try w.writeAll("]}");
    };
    try w.writeAll("]}");
    const elapsed = std.Io.Clock.awake.now(io).nanoseconds - started.nanoseconds;
    const elapsed_ms = @as(f64, @floatFromInt(elapsed)) / std.time.ns_per_ms;
    try sendJsonWithHeaders(conn, arena, 200, body.items, .{ .list_duration_ms = elapsed_ms });
}

fn handleAttachmentLibrary(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const folder = req.queryParam(arena, "folder") orelse "*";
    var options = searchFilters(req, arena, folder) catch |err| return searchFilterError(conn, arena, err);
    var progress: search_index.Progress = .{};
    options.list_attachments = true;
    options.include_versions = true;
    options.index_progress = &progress;
    if (attention.isInboxView(folder)) {
        const snapshot = try attention.load(arena, server.db, sess.username);
        if (snapshot.hasHidden()) options.attention_snapshot = snapshot;
    }
    const rows = maildir.queryMessages(arena, server.db, sess.username, options) catch |err| {
        if (err == maildir.MaildirError.InvalidFolderName) return sendError(conn, arena, 400, "bad_request", "Invalid folder");
        return err;
    };
    var total: usize = 0;
    for (rows) |row| total += row.indexed_attachments.len;
    const per_page = std.math.clamp(parseUintParam(req, arena, "per_page", server.config.messages_per_page), 1, 200);
    const page = std.math.clamp(parseUintParam(req, arena, "page", 1), 1, @max(total / per_page + @intFromBool(total % per_page > 0), 1));
    const start = (page - 1) * per_page;
    const end = @min(total, start + per_page);
    var body: std.ArrayList(u8) = .empty;
    const w = jw(&body, arena);
    try w.print("{{\"page\":{d},\"total\":{d},\"index\":", .{ page, total });
    try writeSearchIndex(w, progress);
    try w.writeAll(",\"items\":[");
    var position: usize = 0;
    var written: usize = 0;
    for (rows) |row| {
        const row_start = position;
        position += row.indexed_attachments.len;
        if (position <= start) continue;
        if (row_start >= end) break;
        const version = (try maildir.summaryVersion(arena, server.db, sess.username, row)) orelse continue;
        for (row.indexed_attachments[(start -| row_start)..@min(row.indexed_attachments.len, end - row_start)]) |file| {
            if (written > 0) try w.writeAll(",");
            written += 1;
            try w.print("{{\"index\":{d},\"size\":{d},\"filename\":", .{ file.index, file.size });
            try writeJsonString(w, file.filename);
            try w.writeAll(",\"content_type\":");
            try writeJsonString(w, file.content_type);
            try w.writeAll(",\"message\":");
            try writeMessageSummary(w, row, version);
            try w.writeAll("}");
        }
    }
    try w.writeAll("]}");
    try sendJson(conn, arena, 200, body.items, null);
}

fn unreadQueueCursor(req: Request, a: std.mem.Allocator) !?maildir.MessagePosition {
    const timestamp = req.queryParam(a, "cursor_time");
    const folder = req.queryParam(a, "cursor_folder");
    const uid = req.queryParam(a, "cursor_uid");
    if (timestamp == null and folder == null and uid == null) return null;
    const name = folder orelse return error.InvalidCursor;
    if (!maildir.isValidFolderName(name)) return error.InvalidCursor;
    const number = try std.fmt.parseInt(i64, uid orelse return error.InvalidCursor, 10);
    if (number < 1) return error.InvalidCursor;
    return .{
        .timestamp = try std.fmt.parseInt(i64, timestamp orelse return error.InvalidCursor, 10),
        .folder = name,
        .uid = number,
    };
}

fn nextUnreadIndex(rows: []const maildir.MessageSummary, cursor: ?maildir.MessagePosition) usize {
    if (cursor) |previous| {
        for (rows, 0..) |row, index| {
            if (previous.before(maildir.messagePosition(row))) return index;
        }
    }
    return 0;
}

/// The direct search API keeps the existing query and hit fields while using
/// the same account scope, filters, and live index as the message list.
fn handleSearch(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const folder = req.queryParam(arena, "folder") orelse "*";
    var options = searchFilters(req, arena, folder) catch |err| return searchFilterError(conn, arena, err);
    if (options.query.len == 0) return sendError(conn, arena, 400, "bad_request", "Missing query parameter 'q'");
    var progress: search_index.Progress = .{};
    options.index_progress = &progress;
    options.include_versions = true;
    if (attention.isInboxView(folder)) {
        const snapshot = try attention.load(arena, server.db, sess.username);
        if (snapshot.hasHidden()) options.attention_snapshot = snapshot;
    }
    const hits = maildir.queryMessages(arena, server.db, sess.username, options) catch |err| {
        if (err == maildir.MaildirError.InvalidFolderName) return sendError(conn, arena, 400, "bad_request", "Invalid folder");
        return err;
    };
    const per_page = std.math.clamp(parseUintParam(req, arena, "per_page", server.config.messages_per_page), 1, 200);
    const page = std.math.clamp(parseUintParam(req, arena, "page", 1), 1, @max(hits.len / per_page + @intFromBool(hits.len % per_page > 0), 1));
    const start = (page - 1) * per_page;

    var body: std.ArrayList(u8) = .empty;
    const w = jw(&body, arena);
    try w.writeAll("{\"query\":");
    try writeJsonString(w, options.query);
    try w.print(",\"page\":{d},\"total\":{d},\"index\":", .{ page, hits.len });
    try writeSearchIndex(w, progress);
    try w.writeAll(",\"items\":[");
    var written: usize = 0;
    for (hits[start..@min(hits.len, start + per_page)]) |hit| {
        const version = (try maildir.summaryVersion(arena, server.db, sess.username, hit)) orelse continue;
        if (written > 0) try w.writeAll(",");
        written += 1;
        try w.print("{{\"uid\":{d},\"folder\":", .{hit.uid});
        try writeJsonString(w, hit.folder);
        try w.writeAll(",\"subject\":");
        try writeJsonString(w, hit.subject);
        try w.writeAll(",\"from\":");
        try writeJsonString(w, hit.from);
        try w.writeAll(",\"to\":");
        try writeJsonString(w, hit.to);
        try w.writeAll(",\"reference\":");
        try writeJsonString(w, version.reference);
        try w.writeAll(",\"revision\":");
        try writeJsonString(w, version.revision);
        try w.print(",\"date\":{d}}}", .{hit.timestamp});
    }
    try w.writeAll("]}");
    try sendJson(conn, arena, 200, body.items, null);
}

const message_ref_prefix = "/webmail/api/messages/ref/";

fn messageReference(path: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, path, message_ref_prefix)) return null;
    return path[message_ref_prefix.len..];
}

fn canRsvpToMessage(server: *WebmailHttpServer, msg: maildir.MessageDetail) bool {
    return maildir.isPersonalFolder(msg.folder) and !msg.flags.deleted and
        !std.ascii.eqlIgnoreCase(msg.folder, server.service.junkFolder()) and !std.ascii.eqlIgnoreCase(msg.folder, "Trash");
}

const InvitationAction = struct {
    status: ?service_mod.RsvpStatus,
    availability: database.Database.InvitationDisposition,
};

const CalendarInvitationAction = caldav_store.CalDavStore.InvitationAction;

fn checkCalendarHistory(db: *database.Database, user: []const u8, organizer: []const u8) !void {
    if (!try maildir.indexCalendarHistory(db, .{ .user = user, .author = organizer })) return error.CalendarHistoryPending;
}

fn handleInvitationEvent(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    const dav = server.dav_store orelse return sendError(conn, a, 503, "calendar_unavailable", "Calendar is unavailable on this server");
    const expected = req.header("If-Match") orelse return sendError(conn, a, 428, "revision_required", "Open the invitation before saving it.");
    if (!isSingleStrongRevision(expected)) return sendError(conn, a, 400, "invalid_revision", "Send one strong message ETag in If-Match");
    const request = std.json.parseFromSliceLeaky(struct {
        reference: []const u8,
        index: usize,
        calendarId: ?u64 = null,
        eventRevision: ?[]const u8 = null,
    }, a, req.body, .{}) catch return sendError(conn, a, 400, "bad_request", "Invalid calendar invitation");
    if (!message_refs.valid(request.reference) or request.index >= calendar_invite.max_previews)
        return sendError(conn, a, 400, "bad_request", "Invalid invitation reference");
    const msg = maildir.getByReference(a, server.db, sess.username, request.reference) catch |err| return mapMaildirError(conn, a, err);
    if (!std.mem.eql(u8, msg.version.?.revision, expected)) return mapMaildirError(conn, a, error.RevisionMismatch);
    if (!canRsvpToMessage(server, msg)) return sendError(conn, a, 403, "invitation_unavailable", "Open the invitation in a personal mailbox.");
    const placement = try message_refs.placement(a, server.db, sess.username, request.reference);
    const invitations = try calendar_invite.invitations(a, msg.calendar_parts, sess.email, if (placement) |source| source.verified_author else "");
    if (request.index >= invitations.len) return sendError(conn, a, 404, "invitation_not_found", "No such calendar invitation in this message.");
    const invite = invitations[request.index];
    if (!invite.canTrack(sess.email)) return sendError(conn, a, 403, "invitation_unavailable", "Saving this invitation requires a verified organizer and an invitation addressed to this account.");
    checkCalendarHistory(server.db, sess.username, invite.preview.organizer) catch |err| return calendarWriteError(conn, a, err);
    const revision = try invite.revision(a);
    database.Database.requireCurrentCalendarInvitation(server.db, sess.username, revision) catch |err| return calendarWriteError(conn, a, err);
    const before = dav.snapshotInvitationEvent(a, sess.username, revision.series) catch |err| return calendarWriteError(conn, a, err);
    const reference = request.reference[0..@sizeOf(caldav_store.MessageReference)].*;
    const data = invitation_events.prepare(a, invite, sess.email, revision, reference, before) catch |err| return calendarWriteError(conn, a, err);
    const event = if (before) |saved| event: {
        if (data != null and (request.eventRevision == null or !std.mem.eql(u8, request.eventRevision.?, saved.detail.event.etag)))
            return calendarWriteError(conn, a, error.PreconditionFailed);
        break :event caldav_store.CalDavStore.InvitationTarget{
            .id = saved.detail.event.id,
            .calendarId = saved.detail.calendar_id,
            .etag = saved.detail.event.etag,
        };
    } else null;
    if (data) |change| {
        const projections_size = if (change.invitation_projections) |bytes| bytes.len else 0;
        if (change.invitation_revisions.?.len + projections_size > dav.config.max_event_size)
            return calendarWriteError(conn, a, error.EventTooLarge);
        checkCalendarEventBody(server, a, dav, change.ics_data.?) catch |err| return calendarWriteError(conn, a, err);
    }
    const saved = dav.saveInvitationEvent(sess.username, revision, invite.preview.uid, request.calendarId, event, data) catch |err| return calendarWriteError(conn, a, err);
    return sendRevisionJson(conn, a, if (before == null) 201 else 200, try service_mod.json(a, .{
        .id = saved.id,
        .calendarId = if (event) |target| target.calendarId else request.calendarId.?,
        .etag = saved.revision.etag(),
        .changed = data != null,
    }), null, saved.revision.etag());
}

fn handleCalendarRsvp(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    const expected = req.header("If-Match") orelse return sendError(conn, a, 428, "revision_required", "Open the invitation before sending a response.");
    if (!isSingleStrongRevision(expected)) return sendError(conn, a, 400, "invalid_revision", "Send one strong message ETag in If-Match");
    const request = std.json.parseFromSliceLeaky(struct {
        reference: []const u8,
        index: usize,
        response: calendar_invite.Response,
        previousSendId: ?[]const u8 = null,
    }, a, req.body, .{}) catch return sendError(conn, a, 400, "bad_request", "Invalid RSVP");
    if (!message_refs.valid(request.reference) or request.index >= calendar_invite.max_previews)
        return sendError(conn, a, 400, "bad_request", "Invalid invitation reference");
    if (request.previousSendId) |id| if (!store.validId(id))
        return sendError(conn, a, 400, "bad_request", "Invalid RSVP receipt");
    const msg = maildir.getByReference(a, server.db, sess.username, request.reference) catch |err| return mapMaildirError(conn, a, err);
    if (!std.mem.eql(u8, msg.version.?.revision, expected)) return mapMaildirError(conn, a, error.RevisionMismatch);
    if (!canRsvpToMessage(server, msg)) return sendError(conn, a, 403, "rsvp_unavailable", "Open the invitation in a personal mailbox to respond.");
    const placement = try message_refs.placement(a, server.db, sess.username, request.reference);
    const invitations = try calendar_invite.invitations(a, msg.calendar_parts, sess.email, if (placement) |source| source.verified_author else "");
    if (request.index >= invitations.len) return sendError(conn, a, 404, "invitation_not_found", "No such calendar invitation in this message.");
    const invite = invitations[request.index];
    if (invite.canReply(sess.email)) checkCalendarHistory(server.db, sess.username, invite.preview.organizer) catch |err| return calendarWriteError(conn, a, err);
    const status = server.service.queueRsvp(a, sess.username, sess.email, invite, request.response, request.previousSendId, server.config.scanner, time_compat.timestamp()) catch |err| switch (err) {
        error.CalendarReplyUnavailable => return sendError(conn, a, 403, "rsvp_unavailable", "RSVP requires a verified organizer and an invitation addressed to this account."),
        error.CalendarInvitationStale => return sendError(conn, a, 409, "invitation_stale", "The organizer sent a newer version of this invitation."),
        error.CalendarInvitationCancelled => return sendError(conn, a, 409, "invitation_cancelled", "The organizer cancelled this invitation."),
        error.CalendarReplyInProgress => return sendError(conn, a, 409, "rsvp_in_progress", "Check the previous response's delivery in Outbox before sending another."),
        error.CalendarReplyTimezone => return sendError(conn, a, 422, "invitation_timezone", "This occurrence's time zone could not be verified."),
        else => return mapServiceError(conn, a, err),
    };
    return sendJson(conn, a, 200, try service_mod.json(a, status), null);
}

fn handleSnapshotList(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    const links = try snapshots.list(a, server.db, sess.username, time_compat.timestamp());
    return sendJson(conn, a, 200, try service_mod.json(a, .{ .links = links }), null);
}

fn handleClientPasswords(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request, action: enum { list, create, revoke }, id_text: []const u8) !void {
    if (action != .list) {
        if ((req.header("Origin") == null and req.header("Referer") == null) or !isSameOrigin(req))
            return sendError(conn, a, 403, "forbidden", "Change app passwords from your webmail account");
        if (!isSecureBrowserRequest(server, req))
            return sendError(conn, a, 403, "https_required", "Use HTTPS to manage app passwords");
    }
    var session = (try requireSession(server, conn, a, req)) orelse return;
    defer session.deinit(server.allocator);
    switch (action) {
        .list => return sendJson(conn, a, 200, try service_mod.json(a, .{
            .passwords = try client_passwords.list(server.db, a, session.username),
            .can_create = isSecureBrowserRequest(server, req) and (try server.db.mailboxAccess(session.username)) == .full,
        }), null),
        .revoke => {
            const id = std.fmt.parseInt(i64, id_text, 10) catch 0;
            if (id <= 0 or !try client_passwords.revoke(server.db, session.username, id))
                return sendError(conn, a, 404, "credential_not_found", "App password not found");
            return sendJson(conn, a, 200, "{\"revoked\":true}", null);
        },
        .create => {
            const Form = struct { label: []const u8, scope: client_passwords.Scope, current_password: []const u8 };
            const input = std.json.parseFromSliceLeaky(Form, a, req.body, .{}) catch
                return sendError(conn, a, 400, "bad_request", "Enter a label, client type and mailbox password");
            if (input.current_password.len == 0 or input.current_password.len > 1024)
                return sendError(conn, a, 400, "bad_request", "Enter your mailbox password");
            var user = try server.db.getUserByUsername(session.username);
            defer user.deinit(server.db.allocator);
            const peer = if (req.trust_forwarded_headers) req.header("X-Real-IP") orelse conn.peerIp() else conn.peerIp();
            const valid = server.auth.verifyCredentialsForPeer(peer, session.username, input.current_password) catch |err| {
                if (err == error.AuthenticationRateLimited)
                    return sendError(conn, a, 429, "rate_limited", "Too many attempts. Try again in five minutes");
                return err;
            };
            if (!valid) return sendError(conn, a, 403, "invalid_credentials", "Your mailbox password is incorrect");
            var issued = client_passwords.create(server.db, session.username, session.session_id, user.password_hash, input.label, input.scope, time_compat.timestamp()) catch |err| switch (err) {
                error.InvalidCredentialLabel => return sendError(conn, a, 400, "invalid_label", "Enter an app name of up to 80 bytes"),
                error.CredentialUnavailable => return sendError(conn, a, 409, "credential_unavailable", "Remove an old app password or sign in again"),
                else => {
                    logger.err("Could not create client password: {}", .{err});
                    return sendError(conn, a, 500, "credential_unavailable", "Could not create the app password");
                },
            };
            defer std.crypto.secureZero(u8, &issued.password);
            return sendJson(conn, a, 201, try service_mod.json(a, .{
                .entry = issued.entry,
                .password = @as([]const u8, &issued.password),
            }), null);
        },
    }
}

const AssistantOwnerAction = enum { list, preview, issue, revoke };

fn isSecureBrowserRequest(server: *WebmailHttpServer, req: Request) bool {
    return server.cert_key_pair != null or
        (req.trust_forwarded_headers and std.ascii.eqlIgnoreCase(req.header("X-Forwarded-Proto") orelse "", "https"));
}

fn operatorSession(server: *WebmailHttpServer, req: Request, session: session_mod.Session) ?mailbox_operator.Operator {
    const id = server.config.operator_id orelse return null;
    if (session.linked_id != null or !isSecureBrowserRequest(server, req)) return null;
    return .{ .id = id, .username = session.username, .session = session.session_id };
}

fn operatorError(conn: *webmail_tls.Stream, a: std.mem.Allocator, err: anyerror) !void {
    return switch (err) {
        error.OperatorUnavailable, error.NotFound => sendError(conn, a, 403, "operator_required", "This account cannot manage server mailboxes"),
        error.MailboxExists => sendError(conn, a, 409, "mailbox_exists", "That mailbox address is already in use"),
        else => blk: {
            logger.err("Mailbox operator request failed: {}", .{err});
            break :blk sendError(conn, a, 500, "server_error", "Could not complete the mailbox request. Try again.");
        },
    };
}

fn validOperatorAddress(mail: core_config.Config, address: []const u8) bool {
    const domain = mailbox_domains.addressDomain(address) orelse return false;
    if (address.len > 254 or !validProvisioningDomain(domain) or !mail.isLocalDomain(domain)) return false;
    const name = address[0 .. address.len - domain.len - 1];
    if (name.len == 0 or name.len > 64 or !std.ascii.isAlphanumeric(name[0]) or !std.ascii.isAlphanumeric(name[name.len - 1]) or
        std.mem.indexOf(u8, name, "..") != null) return false;
    for (name) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_' and byte != '.') return false;
    return true;
}

fn handleOperatorMailboxes(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    const mail = server.config.mail_config orelse return sendError(conn, a, 404, "not_found", "No such endpoint");
    if (server.config.operator_id == null) return sendError(conn, a, 404, "not_found", "No such endpoint");
    var session = (try requireSession(server, conn, a, req)) orelse return;
    defer session.deinit(server.allocator);
    const operator = operatorSession(server, req, session) orelse return operatorError(conn, a, error.OperatorUnavailable);
    if (std.mem.eql(u8, req.method, "GET")) {
        const after = if (req.queryParam(a, "after")) |value| std.fmt.parseInt(i64, value, 10) catch -1 else 0;
        if (after < 0) return sendError(conn, a, 400, "bad_request", "Invalid mailbox page");
        const page = mailbox_operator.list(a, server.db, operator, after) catch |err| return operatorError(conn, a, err);
        return sendJson(conn, a, 200, try service_mod.json(a, page), null);
    }
    const origin = req.header("Origin") orelse return sendError(conn, a, 403, "forbidden", "Create mailboxes from this webmail site");
    if (!std.mem.startsWith(u8, origin, "https://") or !isSameOrigin(req))
        return sendError(conn, a, 403, "forbidden", "Create mailboxes from this webmail site");
    if (!(mailbox_operator.canManage(server.db, operator) catch |err| return operatorError(conn, a, err)))
        return operatorError(conn, a, error.OperatorUnavailable);
    const Form = struct { address: []const u8, password: []const u8, current_password: []const u8 };
    const input = std.json.parseFromSliceLeaky(Form, a, req.body, .{}) catch
        return sendError(conn, a, 400, "bad_request", "Enter a mailbox address and both passwords");
    const address = try std.ascii.allocLowerString(a, std.mem.trim(u8, input.address, " \t"));
    if (!validOperatorAddress(mail.*, address))
        return sendError(conn, a, 400, "invalid_address", "Use a mailbox address on a domain served by this Mail server");
    if (input.password.len < 12 or input.password.len > 1024 or std.mem.indexOfScalar(u8, input.password, 0) != null)
        return sendError(conn, a, 400, "invalid_password", "Use a mailbox password between 12 and 1024 bytes");
    if (input.current_password.len == 0 or input.current_password.len > 1024)
        return sendError(conn, a, 400, "bad_request", "Enter your operator mailbox password");
    var user = server.db.getUserByUsername(session.username) catch |err| return operatorError(conn, a, err);
    defer user.deinit(server.db.allocator);
    const valid = server.auth.verifyCredentialsForPeer(clientIp(req, conn), session.username, input.current_password) catch |err| {
        if (err == error.AuthenticationRateLimited)
            return sendError(conn, a, 429, "rate_limited", "Too many attempts. Try again in five minutes");
        return operatorError(conn, a, err);
    };
    if (!valid) return sendError(conn, a, 403, "invalid_credentials", "Your operator mailbox password is incorrect");
    var hasher = password_hasher.PasswordHasher.init(a);
    const hash = hasher.hashPassword(input.password) catch |err| return operatorError(conn, a, err);
    const id = mailbox_operator.create(server.db, operator, user.password_hash, address, hash) catch |err|
        return operatorError(conn, a, err);
    return sendJson(conn, a, 201, try service_mod.json(a, .{ .id = id, .address = address }), null);
}

fn handleAssistantOwner(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request, action: AssistantOwnerAction, id_text: []const u8) !void {
    if (action != .list and !isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    if (action == .issue and !isSecureBrowserRequest(server, req))
        return sendError(conn, a, 403, "https_required", "Use HTTPS to issue an assistant credential.");
    var session = (try requireSession(server, conn, a, req)) orelse return;
    defer session.deinit(server.allocator);
    if (action == .list) return sendJson(conn, a, 200, try service_mod.json(a, try assistant.status(a, server.db, session.username, time_compat.timestamp())), null);
    if (action == .revoke) {
        const id = std.fmt.parseInt(i64, id_text, 10) catch return assistantError(conn, a, error.AssistantUnavailable);
        server.assistant_mutations.lock();
        const revoked = assistant.revoke(server.db, session.username, id, time_compat.timestamp());
        server.assistant_mutations.unlock();
        revoked catch |err| return assistantError(conn, a, err);
        return sendJson(conn, a, 200, "{\"revoked\":true}", null);
    }
    const input = std.json.parseFromSliceLeaky(assistant.Input, a, req.body, .{}) catch
        return assistantError(conn, a, error.InvalidAssistantGrant);
    const prepared = assistant.prepare(a, server.db, session.username, input, server.service.junkFolder()) catch |err|
        return assistantError(conn, a, err);
    if (action == .preview) {
        const shown = prepared.preview;
        return sendJson(conn, a, 200, try service_mod.json(a, .{
            .integration = shown.integration,
            .read = shown.read,
            .draft = shown.draft,
            .lifetime = shown.lifetime,
            .messages = shown.messages,
            .digest = @as([]const u8, &shown.digest),
        }), null);
    }
    if (!std.mem.eql(u8, &prepared.preview.digest, input.digest orelse ""))
        return sendError(conn, a, 409, "assistant_preview_changed", "Review the current grant preview before approving it.");
    const issued = assistant.issue(server.db, session.username, prepared, time_compat.timestamp()) catch |err| return assistantError(conn, a, err);
    return sendJson(conn, a, 201, try service_mod.json(a, .{ .grant = issued.grant, .token = @as([]const u8, &issued.token) }), null);
}

fn handleAssistantUse(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request, action: assistant.Action) !void {
    if (!isSecureBrowserRequest(server, req)) return sendError(conn, a, 403, "https_required", "Use HTTPS for assistant requests.");
    const prefix = "Bearer ";
    const header = req.header("Authorization") orelse "";
    if (!std.mem.startsWith(u8, header, prefix)) return assistantError(conn, a, error.AssistantUnavailable);
    const body = assistantUseResult(server, a, header[prefix.len..], req.body, action) catch |err| return assistantError(conn, a, err);
    return sendJson(conn, a, 200, body, null);
}

fn assistantUseResult(server: *WebmailHttpServer, a: std.mem.Allocator, token: []const u8, json_body: []const u8, action: assistant.Action) ![]const u8 {
    server.assistant_mutations.lock();
    defer server.assistant_mutations.unlock();
    const now = time_compat.timestamp();
    const access = try assistant.authenticate(a, server.db, token, action, now);
    const body = switch (action) {
        .read => blk: {
            const input = std.json.parseFromSliceLeaky(struct { reference: []const u8 }, a, json_body, .{}) catch {
                try assistant.audit(server.db, access, action, .denied, now);
                return error.InvalidAssistantGrant;
            };
            const item = assistant.read(a, server.db, access, input.reference, server.service.junkFolder()) catch |err| {
                try assistant.audit(server.db, access, action, if (err == error.AssistantUnavailable or err == error.MessageNotFound) .denied else .failed, now);
                return err;
            };
            break :blk try service_mod.json(a, item);
        },
        .draft => blk: {
            const input = std.json.parseFromSliceLeaky(assistant.DraftInput, a, json_body, .{}) catch {
                try assistant.audit(server.db, access, action, .denied, now);
                return error.InvalidAssistantDraft;
            };
            const draft = assistant.prepareDraft(a, &server.service, access, input) catch |err| {
                try assistant.audit(server.db, access, action, .failed, now);
                return err;
            };
            break :blk try service_mod.json(a, draft);
        },
        else => unreachable,
    };
    try assistant.audit(server.db, access, action, .ok, now);
    return body;
}

fn assistantError(conn: *webmail_tls.Stream, a: std.mem.Allocator, err: anyerror) !void {
    return switch (err) {
        error.AssistantUnavailable, error.MessageNotFound => sendError(conn, a, 404, "assistant_unavailable", "The requested assistant grant or message is unavailable."),
        error.InvalidAssistantGrant => sendError(conn, a, 400, "invalid_assistant_grant", "Choose an integration, permissions, and a supported expiry."),
        error.InvalidAssistantDraft => sendError(conn, a, 400, "invalid_assistant_draft", "Enter a request ID and plain-text draft within the size limits."),
        error.InvalidAssistantText => sendError(conn, a, 422, "assistant_text_unavailable", "This message has text that could not be shared."),
        error.AssistantPreviewTooLarge => sendError(conn, a, 413, "assistant_preview_too_large", "Choose fewer or smaller messages."),
        error.AssistantGrantLimit => sendError(conn, a, 409, "assistant_grant_limit", "Revoke an active grant before adding another."),
        error.AssistantDraftLimit => sendError(conn, a, 409, "assistant_draft_limit", "This grant reached its draft limit."),
        error.AssistantDraftConflict => sendError(conn, a, 409, "assistant_draft_conflict", "Check Drafts before submitting a different request ID."),
        else => mapServiceError(conn, a, err),
    };
}

fn handleSnapshotCreate(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request, preview: bool) !void {
    if (!isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    const RequestBody = struct { references: []const []const u8, digest: ?[]const u8 = null, lifetime: ?i64 = null };
    if (req.body.len > 2048) return sendError(conn, a, 400, "invalid_snapshot", "Choose up to ten messages.");
    const input = std.json.parseFromSliceLeaky(RequestBody, a, req.body, .{}) catch
        return sendError(conn, a, 400, "invalid_snapshot", "Choose up to ten messages.");
    if (!preview and (!link_tokens.valid(input.digest orelse "") or !link_tokens.validLifetime(input.lifetime orelse 0)))
        return sendError(conn, a, 400, "invalid_snapshot", "Review the snapshot and choose an expiry before creating the link.");
    const prepared = snapshots.prepare(a, server.db, sess.username, input.references, server.service.junkFolder()) catch |err| switch (err) {
        error.InvalidSnapshotSelection => return sendError(conn, a, 400, "invalid_snapshot", "Choose one to ten distinct messages."),
        error.SnapshotTooLarge => return sendError(conn, a, 413, "snapshot_too_large", "This snapshot is larger than 128 KiB. Choose fewer or smaller messages."),
        error.SnapshotTextUnavailable => return sendError(conn, a, 422, "snapshot_text_unavailable", "A message has text that could not be shared."),
        else => return mapMaildirError(conn, a, err),
    };
    if (preview) return sendJson(conn, a, 200, try service_mod.json(a, .{
        .messages = prepared.messages,
        .digest = @as([]const u8, &prepared.digest),
    }), null);
    if (!std.mem.eql(u8, &prepared.digest, input.digest.?))
        return sendError(conn, a, 409, "snapshot_changed", "The messages changed. Open a new preview before sharing.");
    const issued = snapshots.create(server.db, sess.username, prepared, input.lifetime.?, time_compat.timestamp()) catch |err| switch (err) {
        error.SnapshotOwnerUnavailable => return sendError(conn, a, 401, "unauthorized", "This mailbox is unavailable."),
        error.TooManySnapshotLinks => return sendError(conn, a, 409, "snapshot_limit", "You can have up to 20 active snapshot links. Revoke one before sharing again."),
        else => return err,
    };
    return sendJson(conn, a, 201, try service_mod.json(a, .{ .link = issued.link, .token = @as([]const u8, &issued.token) }), null);
}

fn handleSnapshotRevoke(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request, id_param: []const u8) !void {
    if (!isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, a, req)) orelse return;
    defer sess.deinit(server.allocator);
    const id = std.fmt.parseInt(i64, id_param, 10) catch 0;
    if (id <= 0 or !try snapshots.revoke(server.db, sess.username, id))
        return sendError(conn, a, 404, "snapshot_unavailable", "This snapshot link is unavailable.");
    return sendJson(conn, a, 200, "{\"revoked\":true}", null);
}

fn handleSnapshotView(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, a, 403, "forbidden", "Cross-origin request rejected");
    const unavailable = "This snapshot link is unavailable.";
    if (req.body.len > 256) return sendError(conn, a, 404, "snapshot_unavailable", unavailable);
    const input = std.json.parseFromSliceLeaky(struct { token: []const u8 }, a, req.body, .{}) catch
        return sendError(conn, a, 404, "snapshot_unavailable", unavailable);
    const view = (try snapshots.read(a, server.db, input.token, time_compat.timestamp())) orelse
        return sendError(conn, a, 404, "snapshot_unavailable", unavailable);
    const body = try std.fmt.allocPrint(a, "{{\"expires_at\":{d},\"messages\":{s}}}", .{ view.expires_at, view.payload });
    return sendJson(conn, a, 200, body, null);
}

fn handleMessageDetail(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);

    const msg = (if (messageReference(req.path)) |id|
        maildir.getByReference(arena, server.db, sess.username, id)
    else blk: {
        const uid = uidFromPath(req.path) orelse return sendError(conn, arena, 400, "bad_request", "Invalid message id");
        const folder = req.queryParam(arena, "folder") orelse "INBOX";
        break :blk maildir.getVersionedMessage(arena, server.db, sess.username, folder, uid);
    }) catch |err| return mapMaildirError(conn, arena, err);
    if (req.header("If-Match")) |expected| {
        if (!std.mem.eql(u8, msg.version.?.revision, expected)) return mapMaildirError(conn, arena, error.RevisionMismatch);
    }

    var body: std.ArrayList(u8) = .empty;
    const w = jw(&body, arena);
    const placement = try message_refs.placement(arena, server.db, sess.username, msg.version.?.reference);
    const rule = if (placement) |source| if (source.verified_author.len > 0) (try server.db.categoryPolicy(sess.username, source.verified_author)).destination else null else null;
    const workflow = try attention.load(arena, server.db, sess.username);
    const ids = try thread_ids.fromFields(arena, msg.message_id, msg.in_reply_to, msg.references);
    const author = if (placement) |value| value.verified_author else "";
    const keys = try service_mod.json(arena, try ids.keys(arena));
    const notifications = try server.db.browserNotificationRules(sess.username, msg.version.?.reference, keys, author);
    const invitations = try calendar_invite.invitations(arena, msg.calendar_parts, sess.email, author);
    const previews = try arena.alloc(calendar_invite.Preview, invitations.len);
    const actions = try arena.alloc(?InvitationAction, invitations.len);
    const calendar_actions = try arena.alloc(?CalendarInvitationAction, invitations.len);
    const eligible_folder = canRsvpToMessage(server, msg);
    const history_pending = pending: {
        if (!eligible_folder) break :pending false;
        for (invitations) |invite| {
            if (invite.canTrack(sess.email))
                break :pending !try maildir.indexCalendarHistory(server.db, .{ .user = sess.username, .author = invite.preview.organizer });
        }
        break :pending false;
    };
    for (invitations, previews, actions, calendar_actions) |invite, *preview, *action, *calendar_action| {
        preview.* = invite.preview;
        action.* = null;
        calendar_action.* = null;
        if (!eligible_folder or history_pending or !invite.canTrack(sess.email)) continue;
        const revision = try invite.revision(arena);
        const availability = try database.Database.calendarInvitationDisposition(server.db, sess.username, revision);
        if (invite.canReply(sess.email)) {
            action.* = .{
                .status = try server.service.rsvpStatus(arena, sess.username, invite),
                .availability = availability,
            };
        }
        if (server.dav_store) |dav| {
            if (availability != .current) continue;
            calendar_action.* = try dav.snapshotInvitationAction(arena, sess.username, revision);
        }
    }
    try writeMessageDetail(w, msg, placement, rule, workflow.status(msg.version.?.reference, "", "", "", ids), notifications, previews, actions, calendar_actions, history_pending, arena);
    try sendRevisionJson(conn, arena, 200, body.items, null, msg.version.?.revision);
}

/// PUT /webmail/api/messages/:uid  { flags?: {...}, folder?: "dest" }
/// Sets flags (rename suffix) and/or moves the message to another folder.
fn handleMessageUpdate(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    // State-changing: require same-origin (CSRF guard) and a session.
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);
    const target = try messageMutationTarget(conn, arena, req) orelse return;
    const result = updateMessage(server, arena, sess.username, target, req.body) catch |err| return mapMaildirError(conn, arena, err);
    try sendRevisionJson(conn, arena, 200, try service_mod.json(arena, result), null, result.revision);
}

fn messageMutationTarget(conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !?service_mod.MessageRef {
    if (messageReference(req.path)) |id| {
        const expected = req.header("If-Match") orelse {
            try sendError(conn, arena, 428, "revision_required", "Read the message and send its ETag in If-Match");
            return null;
        };
        if (!isSingleStrongRevision(expected)) {
            try sendError(conn, arena, 400, "invalid_revision", "Send one strong message ETag in If-Match");
            return null;
        }
        return .{ .uid = 0, .folder = "", .reference = id, .revision = expected };
    }
    const uid = uidFromPath(req.path) orelse {
        try sendError(conn, arena, 400, "bad_request", "Invalid message id");
        return null;
    };
    return .{ .uid = uid, .folder = req.queryParam(arena, "folder") orelse "INBOX" };
}

const MessageUpdate = struct { ok: bool = true, uid: i64, folder: []const u8, reference: []const u8, revision: []const u8 };

fn updateMessage(server: *WebmailHttpServer, arena: std.mem.Allocator, user: []const u8, target: service_mod.MessageRef, body: []const u8) !MessageUpdate {
    server.service.mutations.lock();
    defer server.service.mutations.unlock();
    server.db.lockMailboxes();
    defer server.db.unlockMailboxes();
    const current: maildir.MessageLocator = if (target.reference) |id|
        try maildir.checkRevision(arena, server.db, user, id, target.revision.?)
    else
        .{ .uid = target.uid, .folder = target.folder };
    var current_uid = current.uid;
    var current_folder = current.folder;

    // Move first if a destination folder is given, so a subsequent flag change
    // applies to the message in its new home.
    if (jsonStringField(body, "folder")) |dest| {
        current_uid = try maildir.moveMessageLocked(arena, server.db, user, current.folder, current.uid, dest);
        current_folder = dest;
        try server.service.updateDraftLocation(arena, user, .{ .uid = current.uid, .folder = current.folder }, .{ .uid = current_uid, .folder = dest });
    }

    // Apply flags if present.
    if (std.mem.indexOf(u8, body, "\"flags\"") != null) {
        const flags = maildir.Flags{
            .seen = jsonBoolField(body, "seen") orelse false,
            .answered = jsonBoolField(body, "answered") orelse false,
            .flagged = jsonBoolField(body, "flagged") orelse false,
            .draft = jsonBoolField(body, "draft") orelse false,
            .deleted = jsonBoolField(body, "deleted") orelse false,
        };
        _ = try maildir.setFlagsLocked(arena, server.db, user, current_folder, current_uid, flags);
    }

    const version = try maildir.versionAt(arena, server.db, user, current_folder, current_uid);
    return .{ .uid = current_uid, .folder = current_folder, .reference = version.reference, .revision = version.revision };
}

/// DELETE /webmail/api/messages/:uid?folder=  → move to Trash (or purge in Trash)
fn handleMessageDelete(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request) !void {
    if (!isSameOrigin(req)) return sendError(conn, arena, 403, "forbidden", "Cross-origin request rejected");
    var sess = (try requireSession(server, conn, arena, req)) orelse return;
    defer sess.deinit(server.allocator);

    const target = try messageMutationTarget(conn, arena, req) orelse return;
    const result = server.service.bulk(arena, sess.username, .{ .action = .delete, .messages = &.{target} }, time_compat.timestamp()) catch |err| return mapServiceError(conn, arena, err);
    try sendJson(conn, arena, 200, try service_mod.json(arena, result), null);
}

fn mapMaildirError(conn: *webmail_tls.Stream, arena: std.mem.Allocator, err: anyerror) !void {
    return switch (err) {
        maildir.MaildirError.MessageNotFound => sendError(conn, arena, 404, "not_found", "Message not found"),
        maildir.MaildirError.InvalidFolderName => sendError(conn, arena, 400, "bad_request", "Invalid folder"),
        maildir.MaildirError.Conflict => sendError(conn, arena, 409, "conflict", "Message changed concurrently; retry"),
        error.KeywordLimit => sendError(conn, arena, 409, "keyword_limit", "The destination folder has no room for these message keywords"),
        maildir.MaildirError.RevisionMismatch => sendError(conn, arena, 412, "revision_mismatch", "Message changed; reload it before retrying"),
        else => sendError(conn, arena, 500, "server_error", "Operation failed"),
    };
}

// ── JSON writers ─────────────────────────────────────────────────────────────

/// Minimal writer over an unmanaged ArrayList(u8) + arena. The unmanaged
/// ArrayList in this Zig has no `.writer()` that takes an allocator, so we wrap
/// one. All the JSON emitters below take `anytype`, so this drops in cleanly.
const JsonWriter = struct {
    list: *std.ArrayList(u8),
    arena: std.mem.Allocator,

    pub fn writeAll(self: JsonWriter, bytes: []const u8) !void {
        try self.list.appendSlice(self.arena, bytes);
    }
    pub fn writeByte(self: JsonWriter, b: u8) !void {
        try self.list.append(self.arena, b);
    }
    pub fn print(self: JsonWriter, comptime fmt: []const u8, args: anytype) !void {
        const s = try std.fmt.allocPrint(self.arena, fmt, args);
        try self.list.appendSlice(self.arena, s);
    }
};

fn jw(list: *std.ArrayList(u8), arena: std.mem.Allocator) JsonWriter {
    return .{ .list = list, .arena = arena };
}

fn writeFlags(w: anytype, flags: maildir.Flags) !void {
    try w.print(
        "{{\"seen\":{},\"answered\":{},\"flagged\":{},\"draft\":{},\"deleted\":{}}}",
        .{ flags.seen, flags.answered, flags.flagged, flags.draft, flags.deleted },
    );
}

fn writeVersion(w: anytype, version: ?maildir.MessageVersion, include_content_revision: bool) !void {
    try w.writeAll(",\"reference\":");
    if (version) |value| try writeJsonString(w, value.reference) else try w.writeAll("null");
    try w.writeAll(",\"revision\":");
    if (version) |value| {
        try writeJsonString(w, value.revision);
        if (include_content_revision) {
            try w.writeAll(",\"content_revision\":");
            try writeJsonString(w, &value.content_revision);
        }
    } else try w.writeAll("null");
}

fn writeMessageSummary(w: anytype, m: maildir.MessageSummary, version: ?maildir.MessageVersion) !void {
    try w.print("{{\"uid\":{d},\"from\":", .{m.uid});
    try writeJsonString(w, m.from);
    try w.writeAll(",\"to\":");
    try writeJsonString(w, m.to);
    try w.writeAll(",\"subject\":");
    try writeJsonString(w, m.subject);
    if (m.personal_subject) |label| {
        try w.writeAll(",\"personal_subject\":");
        try writeJsonString(w, label);
    }
    try w.writeAll(",\"date\":");
    try writeJsonString(w, m.date);
    try w.writeAll(",\"folder\":");
    try writeJsonString(w, m.folder);
    try writeVersion(w, version, m.has_attachments);
    try w.writeAll(",\"message_id\":");
    try writeJsonString(w, m.message_id);
    try w.writeAll(",\"in_reply_to\":");
    try writeJsonString(w, m.in_reply_to);
    try w.writeAll(",\"references\":");
    try writeJsonString(w, m.references);
    try w.print(",\"timestamp\":{d},\"matches_filters\":{}", .{ m.timestamp, m.matches_filters });
    try w.writeAll(",\"snippet\":");
    try writeJsonString(w, m.snippet);
    try w.print(",\"has_attachments\":{},\"size\":{d},\"flags\":", .{ m.has_attachments, m.size });
    try writeFlags(w, m.flags);
    if (m.attention_deadline > 0) try w.print(",\"attention_deadline\":{d}", .{m.attention_deadline});
    try w.writeAll("}");
}

fn writeMessageDetail(w: anytype, m: maildir.MessageDetail, placement: ?message_refs.Placement, rule: ?categories.Destination, workflow: attention.Status, notifications: database.Database.NotificationRules, invitations: []const calendar_invite.Preview, rsvps: []const ?InvitationAction, calendar_actions: []const ?CalendarInvitationAction, history_pending: bool, a: std.mem.Allocator) !void {
    try w.print("{{\"uid\":{d},\"from\":", .{m.uid});
    try writeJsonString(w, m.from);
    try w.writeAll(",\"folder\":");
    try writeJsonString(w, m.folder);
    try w.print(",\"timestamp\":{d}", .{m.timestamp});
    try writeVersion(w, m.version, m.attachments.len != 0);
    try w.writeAll(",\"to\":");
    try writeJsonString(w, m.to);
    try w.writeAll(",\"cc\":");
    try writeJsonString(w, m.cc);
    try w.writeAll(",\"bcc\":");
    try writeJsonString(w, m.bcc);
    try w.writeAll(",\"reply_to\":");
    try writeJsonString(w, m.reply_to);
    try w.writeAll(",\"in_reply_to\":");
    try writeJsonString(w, m.in_reply_to);
    try w.writeAll(",\"references\":");
    try writeJsonString(w, m.references);
    try w.writeAll(",\"subject\":");
    try writeJsonString(w, m.subject);
    try w.writeAll(",\"date\":");
    try writeJsonString(w, m.date);
    try w.writeAll(",\"message_id\":");
    try writeJsonString(w, m.message_id);
    try w.writeAll(",\"text\":");
    try writeJsonString(w, m.text_body);
    try w.writeAll(",\"html\":");
    try writeJsonString(w, m.html_body);
    try w.print(",\"size\":{d},\"attachments\":[", .{m.size});
    for (m.attachments, 0..) |att, i| {
        if (i > 0) try w.writeAll(",");
        try w.writeAll("{\"filename\":");
        try writeJsonString(w, att.filename);
        try w.writeAll(",\"content_type\":");
        try writeJsonString(w, att.content_type);
        try w.print(",\"size\":{d}}}", .{att.size});
    }
    try w.writeAll("],\"embedded_images\":[");
    if (m.html_body.len > 0) try writeEmbeddedImages(w, a, m.attachments);
    try w.writeAll("],\"flags\":");
    try writeFlags(w, m.flags);
    try w.writeAll(",\"attention\":");
    try w.writeAll(try service_mod.json(a, workflow));
    try w.writeAll(",\"notifications\":");
    try w.writeAll(try service_mod.json(a, notifications));
    if (invitations.len != 0) {
        try w.writeAll(",\"calendar_invites\":");
        try w.writeAll(try service_mod.json(a, invitations));
        try w.writeAll(",\"calendar_rsvps\":");
        try w.writeAll(try service_mod.json(a, rsvps));
        try w.writeAll(",\"calendar_invitation_events\":");
        try w.writeAll(try service_mod.json(a, calendar_actions));
        if (history_pending) try w.writeAll(",\"calendar_history_pending\":true");
        if (m.calendar_only) try w.writeAll(",\"calendar_only\":true");
    }
    if (placement) |source| {
        try w.writeAll(",\"placement\":{\"original_folder\":");
        try writeJsonString(w, source.original_folder);
        try w.writeAll(",\"reason\":");
        try writeJsonString(w, source.reason);
        try w.writeAll(",\"verified_author\":");
        try writeJsonString(w, source.verified_author);
        try w.writeAll(",\"rule\":");
        try writeJsonString(w, if (rule) |destination| @tagName(destination) else "automatic");
        try w.writeAll("}");
    }
    try w.writeAll("}");
}

fn writeEmbeddedImages(w: anytype, a: std.mem.Allocator, attachments: []const maildir.AttachmentInfo) !void {
    var available: usize = 4 * 1024 * 1024;
    var written: usize = 0;
    const encoder = std.base64.standard.Encoder;
    for (attachments) |attachment| {
        const mime = maildir.embeddedImageType(attachment) orelse continue;
        if (attachment.data.len > available) continue;
        if (written == 16) break;
        available -= attachment.data.len;
        const encoded = try a.alloc(u8, encoder.calcSize(attachment.data.len));
        if (written > 0) try w.writeAll(",");
        try w.writeAll("{\"id\":");
        try writeJsonString(w, attachment.content_id);
        try w.print(",\"source\":\"data:{s};base64,{s}\"}}", .{ mime, encoder.encode(encoded, attachment.data) });
        written += 1;
    }
}

/// Write a JSON-escaped string (including surrounding quotes).
fn writeJsonString(w: anytype, s: []const u8) !void {
    // The output is declared charset=utf-8, so it must BE valid UTF-8. Email
    // content (From/Subject/body) is attacker-controlled and may contain raw
    // Latin-1 or otherwise-invalid bytes (e.g. from a charset we don't convert),
    // which would make JSON.parse() throw on the frontend. We iterate by UTF-8
    // sequence: pass valid sequences through verbatim, and replace any invalid
    // byte with U+FFFD (the Unicode replacement character).
    const replacement = "\u{FFFD}";
    try w.writeByte('"');
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        if (c < 0x80) {
            switch (c) {
                '"' => try w.writeAll("\\\""),
                '\\' => try w.writeAll("\\\\"),
                '\n' => try w.writeAll("\\n"),
                '\r' => try w.writeAll("\\r"),
                '\t' => try w.writeAll("\\t"),
                0x08 => try w.writeAll("\\b"),
                0x0C => try w.writeAll("\\f"),
                else => {
                    if (c < 0x20) {
                        try w.print("\\u{x:0>4}", .{c});
                    } else {
                        try w.writeByte(c);
                    }
                },
            }
            i += 1;
            continue;
        }
        // Multi-byte: validate the full sequence before emitting it.
        const seq_len = std.unicode.utf8ByteSequenceLength(c) catch {
            try w.writeAll(replacement);
            i += 1;
            continue;
        };
        if (i + seq_len > s.len or !std.unicode.utf8ValidateSlice(s[i .. i + seq_len])) {
            try w.writeAll(replacement);
            i += 1;
            continue;
        }
        try w.writeAll(s[i .. i + seq_len]);
        i += seq_len;
    }
    try w.writeByte('"');
}

// ── Response helpers ─────────────────────────────────────────────────────────

fn validProvisioningDomain(domain: []const u8) bool {
    if (domain.len > 253 or std.mem.indexOfScalar(u8, domain, '.') == null) return false;
    var labels = std.mem.splitScalar(u8, domain, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63 or label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |byte| if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and byte != '-') return false;
    }
    return true;
}

fn validProvisioningId(id: []const u8) bool {
    if (id.len < 16 or id.len > 64) return false;
    for (id) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return false;
    return true;
}

fn validProvisioningMailbox(mailbox: []const u8, config: ProvisioningConfig) bool {
    const at = std.mem.indexOfScalar(u8, mailbox, '@') orelse return false;
    if (!config.servesDomain(mailbox[at + 1 ..])) return false;
    const name = mailbox[0..at];
    if (name.len < 2 or name.len > 32 or !std.ascii.isAlphanumeric(name[0]) or !std.ascii.isAlphanumeric(name[name.len - 1]) or
        std.mem.indexOf(u8, name, "..") != null) return false;
    for (name) |byte| if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and byte != '-' and byte != '_' and byte != '.') return false;
    for ([_][]const u8{ "abuse", "admin", "hostmaster", "mailer-daemon", "postmaster", "root", "security", "support" }) |reserved| {
        if (std.mem.eql(u8, name, reserved)) return false;
    }
    return true;
}

const ProvisioningRequest = struct {
    mailbox: []const u8,
    actor: []const u8,
    operation_id: []const u8,
    revision: i64,
    quota_bytes: i64,
    send_recipients_per_day: i64 = 0,
    enabled: bool,
    access_window: ?database.Database.AccessWindow = null,
    initial_recovery: ?[]const u8 = null,
    initial_password: ?[]const u8 = null,
    team_invitation: ?teams.HostedMailboxInvitation = null,
};

fn provisioningError(conn: *webmail_tls.Stream, arena: std.mem.Allocator, err: anyerror) !void {
    return switch (err) {
        error.MailboxNotFound => sendError(conn, arena, 404, "mailbox_not_found", "Managed mailbox not found"),
        error.MailboxUnavailable => sendError(conn, arena, 409, "mailbox_unavailable", "Mailbox is unavailable"),
        error.OperationConflict => sendError(conn, arena, 409, "operation_conflict", "Operation ID already has a different request"),
        error.StaleRevision => sendError(conn, arena, 409, "stale_revision", "Mailbox revision does not match"),
        error.IncompleteCreate => sendError(conn, arena, 400, "invalid_request", "Initial password and recovery address are required"),
        error.InvalidAccessWindow => sendError(conn, arena, 400, "invalid_request", "Set a positive service deadline and an export deadline at or after it"),
        error.InvalidTeamData => sendError(conn, arena, 400, "invalid_request", "Enter a team name of 1 to 100 bytes"),
        error.TeamInvitationNotFound => sendError(conn, arena, 409, "team_invitation_unavailable", "The team invitation is no longer available."),
        else => blk: {
            logger.warn("Provisioning operation failed: {}", .{err});
            break :blk sendError(conn, arena, 503, "provisioning_unavailable", "Provisioning is temporarily unavailable");
        },
    };
}

fn sendProvisioningState(conn: *webmail_tls.Stream, arena: std.mem.Allocator, state: database.Database.ProvisioningState) !void {
    return sendJson(conn, arena, 200, try std.json.Stringify.valueAlloc(arena, state, .{ .emit_null_optional_fields = false }), null);
}

fn handleProvisioning(server: *WebmailHttpServer, conn: *webmail_tls.Stream, arena: std.mem.Allocator, req: Request, cfg: ProvisioningConfig) !void {
    const auth = req.header("Authorization") orelse "";
    if (!req.trust_forwarded_headers or req.header("Origin") != null or req.header("Cookie") != null or
        auth.len != 71 or !std.mem.startsWith(u8, auth, "Bearer ") or
        !std.crypto.timing_safe.eql([64]u8, auth[7..71].*, cfg.token[0..64].*))
        return sendError(conn, arena, 401, "unauthorized", "Provisioning credential required");

    const get = std.mem.eql(u8, req.method, "GET");
    if (get and std.mem.eql(u8, req.path, "/provisioning/v1/status")) {
        return sendJson(conn, arena, 200, try service_mod.json(arena, .{ .version = @as(u8, 1), .domain = cfg.domain }), null);
    }
    if (std.mem.eql(u8, req.method, "POST") and std.mem.eql(u8, req.path, "/provisioning/v1/webmail/sign-in")) {
        if (server.config.hosted_sign_in_origin == null)
            return sendError(conn, arena, 404, "sign_in_unavailable", "Hosted sign-in is unavailable");
        const input = std.json.parseFromSliceLeaky(hosted_sign_in.IssueRequest, arena, req.body, .{}) catch
            return sendError(conn, arena, 400, "invalid_request", "Invalid sign-in request");
        if (!validProvisioningMailbox(input.mailbox, cfg) or !validProvisioningId(input.actor))
            return sendError(conn, arena, 400, "invalid_request", "Invalid sign-in request");
        const proof = try session_mod.generateToken(arena);
        const expires_at = hosted_sign_in.issue(server.db, arena, proof, input) catch |err| {
            if (err == error.InvalidActivationPassword)
                return sendError(conn, arena, 401, "invalid_credentials", "Use the mailbox password");
            return provisioningError(conn, arena, err);
        };
        return sendJson(conn, arena, 201, try service_mod.json(arena, .{
            .proof = proof,
            .expires_at = expires_at,
            .password_verified = input.password != null,
        }), null);
    }
    if (get and std.mem.eql(u8, req.path, "/provisioning/v1/domain")) {
        const name = req.queryParam(arena, "name") orelse "";
        if (!cfg.servesDomain(name)) return sendError(conn, arena, 404, "domain_not_found", "Provisioning domain is not configured");
        return sendJson(conn, arena, 200, try service_mod.json(arena, .{ .name = name, .configured = true }), null);
    }
    if (get and std.mem.eql(u8, req.path, "/provisioning/v1/retirement")) {
        const id = req.queryParam(arena, "id") orelse "";
        if (!validProvisioningId(id)) return sendError(conn, arena, 400, "invalid_request", "Invalid retirement operation ID");
        const result = (hosted_retirement.receipt(arena, server.db, id) catch |err| return provisioningError(conn, arena, err)) orelse
            return sendError(conn, arena, 404, "retirement_not_found", "Hosted domain retirement not found");
        return sendJson(conn, arena, 200, try service_mod.json(arena, result), null);
    }
    if (std.mem.eql(u8, req.path, "/provisioning/v1/team"))
        return handleProvisioningTeam(server, conn, arena, req, cfg);
    if (get and std.mem.eql(u8, req.path, "/provisioning/v1/mailbox/activity")) {
        const mailbox = req.queryParam(arena, "mailbox") orelse "";
        const actor = req.queryParam(arena, "actor") orelse "";
        if (!validProvisioningMailbox(mailbox, cfg) or !validProvisioningId(actor))
            return sendError(conn, arena, 400, "invalid_request", "Invalid mailbox or actor");
        const activity = server.db.hostedMailboxActivity(mailbox, actor) catch |err| return provisioningError(conn, arena, err);
        return sendJson(conn, arena, 200, try service_mod.json(arena, activity), null);
    }
    if (get and std.mem.eql(u8, req.path, "/provisioning/v1/mailbox")) {
        const mailbox = req.queryParam(arena, "mailbox") orelse "";
        const actor = req.queryParam(arena, "actor") orelse "";
        if (!validProvisioningMailbox(mailbox, cfg) or !validProvisioningId(actor))
            return sendError(conn, arena, 400, "invalid_request", "Invalid mailbox or actor");
        const state = server.db.provisioningState(mailbox, actor) catch |err| return provisioningError(conn, arena, err);
        return sendProvisioningState(conn, arena, state);
    }
    if (std.mem.eql(u8, req.method, "POST") and std.mem.eql(u8, req.path, "/provisioning/v1/mailbox/access")) {
        const body = std.json.parseFromSlice(database.Database.ProvisioningAccessChange, arena, req.body, .{}) catch
            return sendError(conn, arena, 400, "invalid_request", "Invalid access window request");
        const change = body.value;
        if (!validProvisioningMailbox(change.mailbox, cfg) or !validProvisioningId(change.actor) or
            !validProvisioningId(change.operation_id) or change.revision < 1)
            return sendError(conn, arena, 400, "invalid_request", "Invalid mailbox, actor, operation or revision");
        const state = server.db.applyProvisioningAccess(change) catch |err| return provisioningError(conn, arena, err);
        return sendProvisioningState(conn, arena, state);
    }
    if (!std.mem.eql(u8, req.method, "POST") or !std.mem.eql(u8, req.path, "/provisioning/v1/mailbox"))
        return sendError(conn, arena, 404, "not_found", "No such provisioning endpoint");

    const body = std.json.parseFromSlice(ProvisioningRequest, arena, req.body, .{}) catch
        return sendError(conn, arena, 400, "invalid_request", "Invalid provisioning request");
    const change = body.value;
    if (change.access_window) |window| if (!window.valid())
        return provisioningError(conn, arena, error.InvalidAccessWindow);
    if (!validProvisioningMailbox(change.mailbox, cfg) or !validProvisioningId(change.actor) or
        !validProvisioningId(change.operation_id) or change.revision < 1 or change.quota_bytes < 1 or change.quota_bytes > 1 << 40 or
        change.send_recipients_per_day < 0 or change.send_recipients_per_day > 1_000_000)
        return sendError(conn, arena, 400, "invalid_request", "Invalid mailbox, actor, operation, revision, storage quota, or sending allowance");
    if (change.team_invitation) |invitation| {
        const domain = mailbox_domains.addressDomain(change.mailbox).?;
        if (change.revision != 1 or std.mem.eql(u8, domain, cfg.domain) or !teams.validTeamId(invitation.team) or
            !validProvisioningMailbox(invitation.owner, cfg) or !validProvisioningId(invitation.owner_actor))
            return sendError(conn, arena, 400, "invalid_request", "Invalid team invitation");
    }
    var password_hash: ?[]const u8 = null;
    var initial_recovery: ?[]const u8 = null;
    if (change.revision == 1) {
        const password = change.initial_password orelse return provisioningError(conn, arena, error.IncompleteCreate);
        const address = change.initial_recovery orelse return provisioningError(conn, arena, error.IncompleteCreate);
        initial_recovery = recovery.validateAddress(change.mailbox, address) catch
            return sendError(conn, arena, 400, "invalid_request", "Invalid recovery address");
        const recovery_domain = initial_recovery.?[std.mem.lastIndexOfScalar(u8, initial_recovery.?, '@').? + 1 ..];
        if (std.ascii.eqlIgnoreCase(recovery_domain, cfg.domain) or (server.config.mail_config orelse unreachable).isLocalDomain(recovery_domain))
            return sendError(conn, arena, 400, "invalid_request", "Recovery requires an external address");
        if (password.len < 12 or password.len > 1024)
            return sendError(conn, arena, 400, "invalid_request", "Use a password between 12 and 1024 bytes");
        var hasher = password_hasher.PasswordHasher.init(arena);
        password_hash = hasher.hashPassword(password) catch |err| return provisioningError(conn, arena, err);
    } else if (change.initial_password != null or change.initial_recovery != null) {
        return sendError(conn, arena, 400, "invalid_request", "Credentials are accepted only for mailbox creation");
    }
    const state = server.db.applyProvisioning(.{
        .mailbox = change.mailbox,
        .actor = change.actor,
        .operation_id = change.operation_id,
        .revision = change.revision,
        .quota_bytes = change.quota_bytes,
        .send_recipients_per_day = change.send_recipients_per_day,
        .enabled = change.enabled,
        .access_window = change.access_window,
        .initial_recovery = initial_recovery,
        .initial_password_hash = password_hash,
        .team_invitation = change.team_invitation,
    }) catch |err| return provisioningError(conn, arena, err);
    return sendProvisioningState(conn, arena, state);
}

fn handleProvisioningTeam(server: *WebmailHttpServer, conn: *webmail_tls.Stream, a: std.mem.Allocator, req: Request, cfg: ProvisioningConfig) !void {
    const Body = struct { mailbox: []const u8, actor: []const u8, name: ?[]const u8 = null };
    const input: Body = if (std.mem.eql(u8, req.method, "GET")) .{
        .mailbox = req.queryParam(a, "mailbox") orelse "",
        .actor = req.queryParam(a, "actor") orelse "",
    } else if (std.mem.eql(u8, req.method, "POST")) blk: {
        if (req.body.len > 2048) return sendError(conn, a, 400, "invalid_request", "Invalid team setup request");
        const parsed = std.json.parseFromSliceLeaky(Body, a, req.body, .{}) catch
            return sendError(conn, a, 400, "invalid_request", "Invalid team setup request");
        if (parsed.name == null) return sendError(conn, a, 400, "invalid_request", "Enter a team name");
        break :blk parsed;
    } else return sendError(conn, a, 405, "method_not_allowed", "Method not allowed");
    if (!validProvisioningMailbox(input.mailbox, cfg) or !validProvisioningId(input.actor))
        return sendError(conn, a, 400, "invalid_request", "Invalid mailbox or actor");
    const domain = mailbox_domains.addressDomain(input.mailbox).?;
    if (std.mem.eql(u8, domain, cfg.domain)) return sendError(conn, a, 409, "team_domain_unavailable", "Team setup requires an additional hosted domain");
    const result = teams.hostedTeam(server.db, a, input.mailbox, input.actor, input.name) catch |err|
        return provisioningError(conn, a, err);
    return sendJson(conn, a, if (result.created) 201 else 200, try service_mod.json(a, result), null);
}

fn sendJson(conn: *webmail_tls.Stream, arena: std.mem.Allocator, status: u16, json_body: []const u8, set_cookie: ?[]const u8) !void {
    return sendRevisionJson(conn, arena, status, json_body, set_cookie, null);
}

fn sendRevisionJson(conn: *webmail_tls.Stream, arena: std.mem.Allocator, status: u16, json_body: []const u8, set_cookie: ?[]const u8, etag: ?[]const u8) !void {
    return sendJsonWithHeaders(conn, arena, status, json_body, .{ .set_cookie = set_cookie, .etag = etag });
}

const JsonHeaders = struct {
    set_cookie: ?[]const u8 = null,
    etag: ?[]const u8 = null,
    list_duration_ms: ?f64 = null,
};

fn sendJsonWithHeaders(conn: *webmail_tls.Stream, arena: std.mem.Allocator, status: u16, json_body: []const u8, headers: JsonHeaders) !void {
    var resp: std.ArrayList(u8) = .empty;
    const w = jw(&resp, arena);
    try w.print("HTTP/1.1 {d} {s}\r\n", .{ status, statusText(status) });
    try w.writeAll("Content-Type: application/json; charset=utf-8\r\n");
    try w.print("Content-Length: {d}\r\n", .{json_body.len});
    try w.writeAll("Cache-Control: no-store\r\n");
    try w.writeAll("X-Content-Type-Options: nosniff\r\n");
    if (headers.etag) |tag| try w.print("ETag: {s}\r\n", .{tag});
    if (headers.list_duration_ms) |ms| try w.print("Server-Timing: mail-list;dur={d:.2}\r\n", .{ms});
    if (headers.set_cookie) |c| {
        try w.print("Set-Cookie: {s}\r\n", .{c});
    }
    try w.writeAll("Connection: close\r\n\r\n");
    try w.writeAll(json_body);
    try writeAll(conn, resp.items);
}

fn sendError(conn: *webmail_tls.Stream, arena: std.mem.Allocator, status: u16, code: []const u8, message: []const u8) !void {
    var body: std.ArrayList(u8) = .empty;
    const w = jw(&body, arena);
    try w.writeAll("{\"error\":");
    try writeJsonString(w, code);
    try w.writeAll(",\"message\":");
    try writeJsonString(w, message);
    try w.writeAll("}");
    try sendJson(conn, arena, status, body.items, null);
}

fn sendStatus(conn: *webmail_tls.Stream, arena: std.mem.Allocator, status: u16, text: []const u8, set_cookie: ?[]const u8) !void {
    var resp: std.ArrayList(u8) = .empty;
    const w = jw(&resp, arena);
    try w.print("HTTP/1.1 {d} {s}\r\n", .{ status, text });
    if (status != 204) try w.writeAll("Content-Length: 0\r\n");
    if (set_cookie) |c| try w.print("Set-Cookie: {s}\r\n", .{c});
    try w.writeAll("Connection: close\r\n\r\n");
    try writeAll(conn, resp.items);
}

fn writeAll(conn: *webmail_tls.Stream, data: []const u8) !void {
    // Stream.writeAll handles the write loop (and TLS record chunking).
    try conn.writeAll(data);
}

fn statusText(status: u16) []const u8 {
    return switch (status) {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        412 => "Precondition Failed",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        422 => "Unprocessable Content",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        507 => "Insufficient Storage",
        else => "OK",
    };
}

// ── Small parsing helpers ────────────────────────────────────────────────────

fn parseUintParam(req: Request, arena: std.mem.Allocator, name: []const u8, default: usize) usize {
    const v = req.queryParam(arena, name) orelse return default;
    return std.fmt.parseInt(usize, v, 10) catch default;
}

/// Extract a top-level string field from a small JSON object. Deliberately
/// minimal (no nesting, no escapes beyond \" and \\) — login bodies are tiny
/// and trusted in shape. Returns null if absent.
fn jsonStringField(body: []const u8, field: []const u8) ?[]const u8 {
    // Find "field"
    var needle_buf: [128]u8 = undefined;
    if (field.len + 2 > needle_buf.len) return null;
    needle_buf[0] = '"';
    @memcpy(needle_buf[1 .. 1 + field.len], field);
    needle_buf[1 + field.len] = '"';
    const needle = needle_buf[0 .. field.len + 2];

    const key_at = std.mem.indexOf(u8, body, needle) orelse return null;
    var i = key_at + needle.len;
    // Skip whitespace and ':'
    while (i < body.len and (body[i] == ' ' or body[i] == '\t' or body[i] == ':' or body[i] == '\r' or body[i] == '\n')) : (i += 1) {}
    if (i >= body.len or body[i] != '"') return null;
    i += 1;
    const start = i;
    while (i < body.len) : (i += 1) {
        if (body[i] == '\\') {
            i += 1; // skip escaped char (best-effort; not unescaped here)
            continue;
        }
        if (body[i] == '"') break;
    }
    // Reject unterminated strings: the loop only exits early on a closing quote;
    // reaching the end (i >= body.len) means there was none — or a trailing
    // backslash skipped past the end. Either way the input is malformed.
    if (i >= body.len or body[i] != '"') return null;
    return body[start..i];
}

/// Like jsonStringField but returns a JSON-UNESCAPED, arena-allocated copy
/// (resolves \n \t \r \" \\ \/ \b \f \uXXXX). Use for free-text fields (subject,
/// body) where the browser's JSON.stringify emits escapes that must be decoded
/// before the value goes into a mail header/body. Returns null if absent.
fn jsonStringFieldAlloc(arena: std.mem.Allocator, body: []const u8, field: []const u8) !?[]const u8 {
    const raw = jsonStringField(body, field) orelse return null;
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < raw.len) : (i += 1) {
        const c = raw[i];
        if (c != '\\') {
            try out.append(arena, c);
            continue;
        }
        i += 1;
        if (i >= raw.len) break;
        switch (raw[i]) {
            'n' => try out.append(arena, '\n'),
            't' => try out.append(arena, '\t'),
            'r' => try out.append(arena, '\r'),
            'b' => try out.append(arena, 0x08),
            'f' => try out.append(arena, 0x0C),
            '"' => try out.append(arena, '"'),
            '\\' => try out.append(arena, '\\'),
            '/' => try out.append(arena, '/'),
            'u' => {
                // \uXXXX -> UTF-8. Best-effort; on malformed input emit U+FFFD.
                if (i + 4 < raw.len) {
                    const hex = raw[i + 1 .. i + 5];
                    const cp = std.fmt.parseInt(u21, hex, 16) catch {
                        try out.appendSlice(arena, "\u{FFFD}");
                        i += 4;
                        continue;
                    };
                    var buf: [4]u8 = undefined;
                    const n = std.unicode.utf8Encode(cp, &buf) catch {
                        try out.appendSlice(arena, "\u{FFFD}");
                        i += 4;
                        continue;
                    };
                    try out.appendSlice(arena, buf[0..n]);
                    i += 4;
                } else {
                    try out.appendSlice(arena, "\u{FFFD}");
                }
            },
            else => |x| try out.append(arena, x), // unknown escape: keep the char
        }
    }
    return try out.toOwnedSlice(arena);
}

/// Extract a top-level string ARRAY field (`"name": ["a","b"]`) from a small
/// JSON object. Returns an arena-allocated slice of the string elements (empty
/// if the field is absent or `[]`). Minimal parser matching jsonStringField's
/// scope: handles quoted strings with backslash escapes skipped (not unescaped).
fn jsonStringArray(arena: std.mem.Allocator, body: []const u8, field: []const u8) ![]const []const u8 {
    var needle_buf: [128]u8 = undefined;
    if (field.len + 2 > needle_buf.len) return &.{};
    needle_buf[0] = '"';
    @memcpy(needle_buf[1 .. 1 + field.len], field);
    needle_buf[1 + field.len] = '"';
    const needle = needle_buf[0 .. field.len + 2];

    const key_at = std.mem.indexOf(u8, body, needle) orelse return &.{};
    var i = key_at + needle.len;
    while (i < body.len and (body[i] == ' ' or body[i] == '\t' or body[i] == ':' or body[i] == '\r' or body[i] == '\n')) : (i += 1) {}
    if (i >= body.len or body[i] != '[') return &.{};
    i += 1;

    var out: std.ArrayList([]const u8) = .empty;
    while (i < body.len) {
        // skip whitespace and commas
        while (i < body.len and (body[i] == ' ' or body[i] == '\t' or body[i] == ',' or body[i] == '\r' or body[i] == '\n')) : (i += 1) {}
        if (i >= body.len or body[i] == ']') break;
        if (body[i] != '"') break; // malformed element
        i += 1;
        const start = i;
        while (i < body.len) : (i += 1) {
            if (body[i] == '\\') {
                i += 1;
                continue;
            }
            if (body[i] == '"') break;
        }
        if (i >= body.len) break; // unterminated
        try out.append(arena, body[start..i]);
        i += 1; // past closing quote
    }
    return out.toOwnedSlice(arena);
}

/// Extract a top-level boolean field (`"name": true/false`) from a small JSON
/// object. Returns null if absent. Minimal — matches jsonStringField's scope.
fn jsonBoolField(body: []const u8, field: []const u8) ?bool {
    var needle_buf: [128]u8 = undefined;
    if (field.len + 2 > needle_buf.len) return null;
    needle_buf[0] = '"';
    @memcpy(needle_buf[1 .. 1 + field.len], field);
    needle_buf[1 + field.len] = '"';
    const needle = needle_buf[0 .. field.len + 2];

    const key_at = std.mem.indexOf(u8, body, needle) orelse return null;
    var i = key_at + needle.len;
    while (i < body.len and (body[i] == ' ' or body[i] == '\t' or body[i] == ':' or body[i] == '\r' or body[i] == '\n')) : (i += 1) {}
    const rest = body[i..];
    // Require a JSON terminator after the literal so "trueX"/"falsey" are rejected.
    if (jsonLiteralAt(rest, "true")) return true;
    if (jsonLiteralAt(rest, "false")) return false;
    return null;
}

/// True if `s` begins with `lit` followed by a JSON value terminator (so we
/// match the literal `true`, not the prefix of `trueX`).
fn jsonLiteralAt(s: []const u8, lit: []const u8) bool {
    if (!std.mem.startsWith(u8, s, lit)) return false;
    if (s.len == lit.len) return true;
    const c = s[lit.len];
    return c == ',' or c == '}' or c == ']' or c == ' ' or c == '\t' or c == '\r' or c == '\n';
}

/// URL-decode a query component (%XX and '+'). Arena-allocated.
fn urlDecode(allocator: std.mem.Allocator, s: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c == '+') {
            try out.append(allocator, ' ');
        } else if (c == '%' and i + 2 < s.len) {
            const hi = hexDigit(s[i + 1]);
            const lo = hexDigit(s[i + 2]);
            if (hi != null and lo != null) {
                try out.append(allocator, hi.? * 16 + lo.?);
                i += 2;
            } else {
                try out.append(allocator, c);
            }
        } else {
            try out.append(allocator, c);
        }
    }
    return out.toOwnedSlice(allocator);
}

fn hexDigit(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "jsonStringField extracts simple fields" {
    const t = std.testing;
    const body = "{\"username\": \"chris\", \"password\":\"secret\"}";
    try t.expectEqualStrings("chris", jsonStringField(body, "username").?);
    try t.expectEqualStrings("secret", jsonStringField(body, "password").?);
    try t.expect(jsonStringField(body, "missing") == null);
}

test "jsonStringFieldAlloc unescapes JSON escapes" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const body = "{\"text\":\"Line A\\nLine B\\tTabbed \\\"q\\\" end\"}";
    const v = (try jsonStringFieldAlloc(a, body, "text")).?;
    try t.expectEqualStrings("Line A\nLine B\tTabbed \"q\" end", v);
    // unicode escape
    const u = (try jsonStringFieldAlloc(a, "{\"text\":\"Caf\\u00e9\"}", "text")).?;
    try t.expectEqualStrings("Caf\u{00E9}", u);
}

test "jsonStringArray parses recipient lists" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const body = "{\"to\":[\"a@x.com\", \"b@y.com\"],\"cc\":[],\"subject\":\"hi\"}";
    const to = try jsonStringArray(a, body, "to");
    try t.expectEqual(@as(usize, 2), to.len);
    try t.expectEqualStrings("a@x.com", to[0]);
    try t.expectEqualStrings("b@y.com", to[1]);
    const cc = try jsonStringArray(a, body, "cc");
    try t.expectEqual(@as(usize, 0), cc.len);
    const missing = try jsonStringArray(a, body, "bcc");
    try t.expectEqual(@as(usize, 0), missing.len);
}

test "jsonBoolField parses booleans" {
    const t = std.testing;
    const body = "{\"flags\":{\"seen\":true,\"flagged\":false}}";
    try t.expectEqual(@as(?bool, true), jsonBoolField(body, "seen"));
    try t.expectEqual(@as(?bool, false), jsonBoolField(body, "flagged"));
    try t.expectEqual(@as(?bool, null), jsonBoolField(body, "draft"));
}

test "jsonBoolField rejects non-terminated literals" {
    const t = std.testing;
    // "trueX"/"falsey" must NOT be accepted as true/false.
    try t.expectEqual(@as(?bool, null), jsonBoolField("{\"seen\":trueX}", "seen"));
    try t.expectEqual(@as(?bool, null), jsonBoolField("{\"seen\":falsey}", "seen"));
    // Proper terminators are accepted.
    try t.expectEqual(@as(?bool, true), jsonBoolField("{\"seen\":true}", "seen"));
    try t.expectEqual(@as(?bool, true), jsonBoolField("{\"seen\":true,\"x\":1}", "seen"));
}

test "uidFromPath parses the uid" {
    const t = std.testing;
    try t.expectEqual(@as(?i64, 42), uidFromPath("/webmail/api/messages/42"));
    try t.expectEqual(@as(?i64, null), uidFromPath("/webmail/api/messages/abc"));
    try t.expectEqual(@as(?i64, null), uidFromPath("/other"));
}

test "jsonStringField rejects unterminated and trailing-backslash strings" {
    const t = std.testing;
    // Unterminated value must return null, not the rest of the buffer.
    try t.expect(jsonStringField("{\"password\":\"unclosed", "password") == null);
    // Trailing backslash that escapes past the end must not swallow the buffer.
    try t.expect(jsonStringField("{\"password\":\"abc\\", "password") == null);
    // Properly terminated still works.
    try t.expectEqualStrings("ok", jsonStringField("{\"password\":\"ok\"}", "password").?);
}

test "writeJsonString keeps valid UTF-8 and replaces invalid bytes" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    // Valid UTF-8 (é = C3 A9) passes through verbatim.
    {
        var buf: std.ArrayList(u8) = .empty;
        try writeJsonString(jw(&buf, arena.allocator()), "Caf\u{00E9}");
        try t.expectEqualStrings("\"Caf\u{00E9}\"", buf.items);
    }
    // A lone 0xE9 (Latin-1 'é', invalid UTF-8) becomes U+FFFD, not a raw byte.
    {
        var buf: std.ArrayList(u8) = .empty;
        try writeJsonString(jw(&buf, arena.allocator()), "Caf\xe9");
        try t.expectEqualStrings("\"Caf\u{FFFD}\"", buf.items);
        // And the result is itself valid UTF-8.
        try t.expect(std.unicode.utf8ValidateSlice(buf.items));
    }
}

test "isSameOrigin and authorityOf" {
    const t = std.testing;
    try t.expectEqualStrings("a:8", authorityOf("http://a:8/x"));
    try t.expectEqualStrings("host", authorityOf("https://host"));
    const ok = Request{ .method = "POST", .path = "/x", .query = "", .headers = "Host: h\r\nOrigin: http://h\r\n", .body = "" };
    try t.expect(isSameOrigin(ok));
    const bad = Request{ .method = "POST", .path = "/x", .query = "", .headers = "Host: h\r\nOrigin: http://evil\r\n", .body = "" };
    try t.expect(!isSameOrigin(bad));
    const none = Request{ .method = "POST", .path = "/x", .query = "", .headers = "Host: h\r\n", .body = "" };
    try t.expect(isSameOrigin(none)); // no Origin/Referer -> allowed
}

test "CSRF uses gateway authority only on trusted loopback requests" {
    const t = std.testing;
    var req = Request{ .method = "POST", .path = "/webmail/api/compose", .query = "", .headers = "Host: localhost:8099\r\nX-Forwarded-Host: mail.stacksjs.com\r\nOrigin: https://mail.stacksjs.com\r\n", .body = "" };
    try t.expect(!isSameOrigin(req));
    req.trust_forwarded_headers = true;
    try t.expect(isSameOrigin(req));
    req.headers = "Host: localhost:8099\r\nX-Forwarded-Host: mail.stacksjs.com\r\nOrigin: https://example.invalid\r\n";
    try t.expect(!isSameOrigin(req));
}

test "writeJsonString escapes control chars and quotes" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    var buf: std.ArrayList(u8) = .empty;
    try writeJsonString(jw(&buf, arena.allocator()), "a\"b\\c\nd");
    try t.expectEqualStrings("\"a\\\"b\\\\c\\nd\"", buf.items);
}

test "urlDecode handles percent and plus" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const d = try urlDecode(arena.allocator(), "All%20Mail+x");
    try t.expectEqualStrings("All Mail x", d);
}

test "Request.header and queryParam" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const req = Request{
        .method = "GET",
        .path = "/webmail/api/messages",
        .query = "folder=Sent&page=2",
        .headers = "Host: x\r\nCookie: webmail_session=abc\r\n",
        .body = "",
    };
    try t.expectEqualStrings("webmail_session=abc", req.header("Cookie").?);
    try t.expectEqualStrings("Sent", req.queryParam(arena.allocator(), "folder").?);
    try t.expectEqualStrings("2", req.queryParam(arena.allocator(), "page").?);
    try t.expect(req.queryParam(arena.allocator(), "missing") == null);
}

test "compose JSON is typed and attachment fields cannot shadow the message" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const parsed = try std.json.parseFromSlice(ComposePayload, a, "{\"subject\":\"real subject\",\"text\":\"Line 1\\nCafé\",\"attachments\":[{\"filename\":\"subject\",\"data\":\"AAEC/w==\"}]}", .{});
    defer parsed.deinit();
    var db = try database.Database.init(t.allocator, ":memory:");
    defer db.deinit();
    _ = try db.createUser("user@example.com", "test-hash", "user@example.com");
    var auth = auth_mod.AuthBackend.init(t.allocator, &db);
    defer auth.deinit();
    var service = try service_mod.Service.init(&db, &auth, .{});
    const msg = try service.payloadMessage(a, parsed.value, "user@example.com", "user@example.com", false);
    try t.expectEqualStrings("real subject", msg.subject);
    try t.expectEqualStrings("Line 1\nCafé", msg.text_body);
    try t.expectEqualSlices(u8, &.{ 0, 1, 2, 255 }, msg.attachments[0].data);
    try t.expectError(service_mod.ServiceError.InvalidAttachment, service.payloadMessage(a, .{ .attachments = &.{.{ .filename = "a", .data = "!!!!" }} }, "user@example.com", "user@example.com", false));
}

test "attachment download headers percent-encode untrusted filenames" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const header = try attachmentDisposition(arena.allocator(), "café\"\r\n.txt");
    try t.expect(std.mem.indexOf(u8, header, "\r") == null);
    try t.expect(std.mem.indexOf(u8, header, "\n") == null);
    try t.expect(std.mem.indexOf(u8, header, "%C3%A9%22%0D%0A") != null);
}

test "security: HTTP logins refund successes and retain configured failure limits" {
    const a = std.testing.allocator;
    var db = try database.Database.init(a, ":memory:");
    defer db.deinit();
    var backend = auth_mod.AuthBackend.init(a, &db);
    defer backend.deinit();
    var hash: [32]u8 = undefined;
    try std.crypto.pwhash.argon2.kdf(a, &hash, "test-password", "0123456789abcdef", .{ .m = 8, .t = 1, .p = 1 }, .argon2id, io_compat.getIo());
    var encoded: [43]u8 = undefined;
    const stored = try std.fmt.allocPrint(a, "$argon2id$v=19$m=8,t=1,p=1$MDEyMzQ1Njc4OWFiY2RlZg${s}", .{std.base64.standard_no_pad.Encoder.encode(&encoded, &hash)});
    defer a.free(stored);
    _ = try db.createUser("user@test.local", stored, "user@test.local");
    var server = try WebmailHttpServer.init(a, .{ .login_rate_max = 2 }, &db, &backend);
    defer server.deinit();
    var fds: [2]c_int = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, @intCast(@as(u32, std.posix.SOCK.STREAM)), 0, &fds) != 0) return error.SocketPairFailed;
    defer _ = std.c.close(fds[0]);
    defer _ = std.c.close(fds[1]);
    var connection = socket.Connection{ .fd = fds[0] };
    const peer = "192.0.2.1";
    @memcpy(connection.peer_ip_buf[0..peer.len], peer);
    connection.peer_ip_len = peer.len;
    var stream = webmail_tls.Stream.plain(connection);
    for (0..15) |index| {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        try handleLogin(&server, &stream, arena.allocator(), .{
            .method = "POST",
            .path = "/webmail/auth/login",
            .query = "",
            .headers = "Host: test.local\r\nOrigin: http://test.local\r\n",
            .body = if (index == 12 or index == 13)
                "{\"username\":\"user@test.local\",\"password\":\"wrong-password\"}"
            else
                "{\"username\":\"user@test.local\",\"password\":\"test-password\"}",
        });
        var reply: [8192]u8 = undefined;
        const n = std.c.read(fds[1], &reply, reply.len);
        try std.testing.expect(n > 0);
        const expected = if (index < 12) "HTTP/1.1 200" else if (index < 14) "HTTP/1.1 401" else "HTTP/1.1 429";
        try std.testing.expect(std.mem.startsWith(u8, reply[0..@intCast(n)], expected));
    }
}
