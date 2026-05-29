const std = @import("std");
const socket = @import("socket_compat.zig");
const time_compat = @import("time_compat.zig");
const config = @import("config.zig");
const auth = @import("../auth/auth.zig");
const database = @import("../storage/database.zig");
const protocol = @import("protocol.zig");
const logger = @import("logger.zig");
const security = @import("../auth/security.zig");
const tls_mod = @import("tls.zig");
const dnsbl = @import("../antispam/dnsbl.zig");
const greylist_mod = @import("../antispam/greylist.zig");

pub const Server = struct {
    allocator: std.mem.Allocator,
    config: config.Config,
    listener: ?socket.Server,
    running: bool,
    logger: *logger.Logger,
    active_connections: std.atomic.Value(u32),
    rate_limiter: security.RateLimiter,
    tls_context: ?tls_mod.TlsContext,
    db: ?*database.Database,
    auth_backend: ?*auth.AuthBackend,
    dnsbl_checker: ?dnsbl.DnsblChecker,
    greylist: ?*greylist_mod.Greylist,

    pub fn init(
        allocator: std.mem.Allocator,
        cfg: config.Config,
        log: *logger.Logger,
        db: ?*database.Database,
        auth_backend: ?*auth.AuthBackend,
        greylist: ?*greylist_mod.Greylist,
    ) !Server {
        // Rate limiter: max messages per hour per IP and per user
        const rate_limiter = security.RateLimiter.init(
            allocator,
            3600, // 1 hour window
            cfg.rate_limit_per_ip,
            cfg.rate_limit_per_user,
            cfg.rate_limit_cleanup_interval,
        );

        // Initialize TLS context if enabled
        var tls_ctx: ?tls_mod.TlsContext = null;
        if (cfg.enable_tls) {
            const tls_config = tls_mod.TlsConfig{
                .enabled = true,
                .cert_path = cfg.tls_cert_path,
                .key_path = cfg.tls_key_path,
            };
            tls_ctx = try tls_mod.TlsContext.init(allocator, tls_config, log);
        }

        // Initialize DNSBL checker if enabled
        var dnsbl_checker_opt: ?dnsbl.DnsblChecker = null;
        if (cfg.enable_dnsbl) {
            dnsbl_checker_opt = dnsbl.DnsblChecker.init(allocator, null);
            log.info("DNSBL spam checking enabled with {} blacklists", .{dnsbl.DnsblChecker.DEFAULT_BLACKLISTS.len});
        }

        return Server{
            .allocator = allocator,
            .config = cfg,
            .listener = null,
            .running = false,
            .logger = log,
            .active_connections = std.atomic.Value(u32).init(0),
            .rate_limiter = rate_limiter,
            .tls_context = tls_ctx,
            .db = db,
            .auth_backend = auth_backend,
            .dnsbl_checker = dnsbl_checker_opt,
            .greylist = greylist,
        };
    }

    pub fn deinit(self: *Server) void {
        self.running = false;
        if (self.listener) |*listener| {
            listener.close();
        }
        self.rate_limiter.deinit();
        if (self.tls_context) |*ctx| {
            var tls_ctx = ctx.*;
            tls_ctx.deinit();
        }
        self.logger.info("Server cleanup complete", .{});
    }

    pub fn start(self: *Server, shutdown_flag: *std.atomic.Value(bool)) !void {
        return self.startWithReload(shutdown_flag, null, null);
    }

    /// Start server with optional hot reload support
    pub fn startWithReload(
        self: *Server,
        shutdown_flag: *std.atomic.Value(bool),
        reload_flag: ?*std.atomic.Value(bool),
        reload_callback: ?*const fn () void,
    ) !void {
        const address = try socket.Address.parseIp(self.config.host, self.config.port);

        self.listener = try socket.Server.listen(address, .{
            .reuse_address = true,
        });
        try self.listener.?.setNonBlocking(true);

        self.running = true;

        self.logger.info("SMTP Server listening on {s}:{d}", .{ self.config.host, self.config.port });

        while (self.running and !shutdown_flag.load(.acquire)) {
            // Check for configuration reload
            if (reload_flag) |flag| {
                if (flag.load(.acquire)) {
                    flag.store(false, .release);
                    self.logger.info("Configuration reload signal received", .{});
                    if (reload_callback) |callback| {
                        callback();
                    }
                }
            }

            // Accept with timeout to allow checking shutdown flag
            const connection = self.listener.?.accept() catch |err| {
                if (err == error.OperationCancelled or err == error.WouldBlock) {
                    time_compat.sleepMs(100);
                    continue;
                }
                self.logger.warn("Error accepting connection: {}", .{err});
                // Backoff on system errors to avoid CPU-burning tight loops
                time_compat.sleepMs(500);
                continue;
            };

            // Check connection limits
            const current_connections = self.active_connections.load(.monotonic);
            if (current_connections >= self.config.max_connections) {
                self.logger.warn("Max connections ({d}) reached, rejecting new connection", .{self.config.max_connections});
                _ = connection.write("421 Too many connections, try again later\r\n") catch {};
                connection.close();
                continue;
            }

            _ = self.active_connections.fetchAdd(1, .monotonic);

            // Real peer IP (empty if unknown). Used for logging + DNSBL here
            // while `connection` is still in scope; the session's remote_addr is
            // re-derived from the thread's own connection copy in
            // handleConnection to avoid a dangling slice across the spawn.
            const addr_str = if (connection.peerIp().len > 0) connection.peerIp() else "client";

            self.logger.logConnection(addr_str, "connected");

            // Check DNSBL if enabled
            if (self.dnsbl_checker) |*checker| {
                const is_blacklisted = checker.isBlacklisted(addr_str) catch false;
                if (is_blacklisted) {
                    self.logger.warn("Connection from {s} rejected - IP blacklisted in DNSBL", .{addr_str});
                    _ = self.active_connections.fetchSub(1, .monotonic);
                    connection.close();
                    continue;
                }
            }

            // Handle connection in a new thread for concurrent processing
            const ctx = ConnectionContext{
                .server = self,
                .connection = connection,
                // Static fallback; the real IP is read from ctx.connection
                // (the thread's own copy) inside handleConnection.
                .remote_addr = "client",
            };

            const thread = std.Thread.spawn(.{}, handleConnection, .{ctx}) catch |err| {
                self.logger.err("Failed to spawn connection handler: {}", .{err});
                _ = self.active_connections.fetchSub(1, .monotonic);
                connection.close();
                continue;
            };
            thread.detach();
        }

        self.logger.info("Server shutting down gracefully...", .{});

        // Wait for active connections to finish (60s timeout)
        var wait_count: u32 = 0;
        while (self.active_connections.load(.monotonic) > 0 and wait_count < 600) : (wait_count += 1) {
            time_compat.sleepMs(100);
        }

        const remaining = self.active_connections.load(.monotonic);
        if (remaining > 0) {
            self.logger.warn("Shutdown timeout: {d} connections still active", .{remaining});
        } else {
            self.logger.info("All connections closed gracefully", .{});
        }
    }

    const ConnectionContext = struct {
        server: *Server,
        connection: socket.Connection,
        remote_addr: []const u8,
        implicit_tls: bool = false,
    };

    fn handleConnection(ctx: ConnectionContext) void {
        defer ctx.connection.close();
        defer _ = ctx.server.active_connections.fetchSub(1, .monotonic);

        // The peer IP lives in this thread's own copy of the connection, so a
        // slice into it is valid for the whole session.
        const remote_addr = if (ctx.connection.peerIp().len > 0) ctx.connection.peerIp() else ctx.remote_addr;

        // Get pointer to TLS context if it exists
        var tls_ctx_ptr: ?*tls_mod.TlsContext = null;
        if (ctx.server.tls_context) |*tls_ctx| {
            tls_ctx_ptr = tls_ctx;
        }

        var session = protocol.Session.init(
            ctx.server.allocator,
            ctx.connection,
            ctx.server.config,
            ctx.server.logger,
            remote_addr,
            &ctx.server.rate_limiter,
            tls_ctx_ptr,
            ctx.server.auth_backend,
            ctx.server.greylist,
        ) catch |err| {
            ctx.server.logger.err("Failed to initialize session from {s}: {}", .{ remote_addr, err });
            return;
        };
        defer session.deinit();

        // For SMTPS (port 465), perform TLS handshake before SMTP banner
        if (ctx.implicit_tls) {
            session.performImplicitTls() catch |err| {
                ctx.server.logger.warn("SMTPS TLS handshake failed from {s}: {}", .{ remote_addr, err });
                return;
            };
        }

        session.handle() catch |err| {
            ctx.server.logger.err("Session error from {s}: {}", .{ remote_addr, err });
        };

        ctx.server.logger.logConnection(remote_addr, "disconnected");
    }

    /// Start SMTPS listener on port 465 (implicit TLS).
    /// Runs in a separate thread alongside the main SMTP server.
    pub fn startSmtps(self: *Server, smtps_port: u16, shutdown_flag: *std.atomic.Value(bool)) void {
        const address = socket.Address.parseIp(self.config.host, smtps_port) catch |err| {
            self.logger.err("SMTPS: Failed to parse address: {}", .{err});
            return;
        };

        var smtps_listener = socket.Server.listen(address, .{
            .reuse_address = true,
        }) catch |err| {
            self.logger.err("SMTPS: Failed to listen on port {d}: {}", .{ smtps_port, err });
            return;
        };
        smtps_listener.setNonBlocking(true) catch |err| {
            self.logger.err("SMTPS: Failed to set nonblocking listener: {}", .{err});
            smtps_listener.close();
            return;
        };

        self.logger.info("SMTPS Server listening on {s}:{d} (implicit TLS)", .{ self.config.host, smtps_port });

        while (!shutdown_flag.load(.acquire)) {
            const connection = smtps_listener.accept() catch |err| {
                if (err == error.OperationCancelled or err == error.WouldBlock) {
                    time_compat.sleepMs(100);
                    continue;
                }
                self.logger.warn("SMTPS: Error accepting connection: {}", .{err});
                time_compat.sleepMs(500);
                continue;
            };

            _ = self.active_connections.fetchAdd(1, .monotonic);

            self.logger.logConnection("client", "SMTPS connected");

            const ctx = ConnectionContext{
                .server = self,
                .connection = connection,
                .remote_addr = "client",
                .implicit_tls = true,
            };

            const thread = std.Thread.spawn(.{}, handleConnection, .{ctx}) catch |err| {
                self.logger.err("SMTPS: Failed to spawn handler: {}", .{err});
                _ = self.active_connections.fetchSub(1, .monotonic);
                connection.close();
                continue;
            };
            thread.detach();
        }

        smtps_listener.close();
    }

    /// Start Submission listener on port 587 (STARTTLS).
    /// Runs in a separate thread alongside the main SMTP server.
    /// This is the standard port for mail clients to send outgoing mail.
    pub fn startSubmission(self: *Server, submission_port: u16, shutdown_flag: *std.atomic.Value(bool)) void {
        const address = socket.Address.parseIp(self.config.host, submission_port) catch |err| {
            self.logger.err("Submission: Failed to parse address: {}", .{err});
            return;
        };

        var submission_listener = socket.Server.listen(address, .{
            .reuse_address = true,
        }) catch |err| {
            self.logger.err("Submission: Failed to listen on port {d}: {}", .{ submission_port, err });
            return;
        };
        submission_listener.setNonBlocking(true) catch |err| {
            self.logger.err("Submission: Failed to set nonblocking listener: {}", .{err});
            submission_listener.close();
            return;
        };

        self.logger.info("Submission Server listening on {s}:{d} (STARTTLS)", .{ self.config.host, submission_port });

        while (!shutdown_flag.load(.acquire)) {
            const connection = submission_listener.accept() catch |err| {
                if (err == error.OperationCancelled or err == error.WouldBlock) {
                    time_compat.sleepMs(100);
                    continue;
                }
                self.logger.warn("Submission: Error accepting connection: {}", .{err});
                time_compat.sleepMs(500);
                continue;
            };

            _ = self.active_connections.fetchAdd(1, .monotonic);

            self.logger.logConnection("client", "Submission connected");

            const ctx = ConnectionContext{
                .server = self,
                .connection = connection,
                .remote_addr = "client",
                .implicit_tls = false, // STARTTLS, not implicit
            };

            const thread = std.Thread.spawn(.{}, handleConnection, .{ctx}) catch |err| {
                self.logger.err("Submission: Failed to spawn handler: {}", .{err});
                _ = self.active_connections.fetchSub(1, .monotonic);
                connection.close();
                continue;
            };
            thread.detach();
        }

        submission_listener.close();
    }
};
