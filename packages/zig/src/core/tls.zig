const std = @import("std");
const mutex_compat = @import("mutex_compat.zig");
const time_compat = @import("time_compat.zig");
const io_compat = @import("io_compat.zig");
const net = std.Io.net;
const logger = @import("logger.zig");
const tls = @import("tls");
const cert_validator = @import("cert_validator.zig");

/// Supported TLS versions
pub const TlsVersion = enum {
    tls_1_2,
    tls_1_3,

    pub fn toString(self: TlsVersion) []const u8 {
        return switch (self) {
            .tls_1_2 => "TLS 1.2",
            .tls_1_3 => "TLS 1.3",
        };
    }
};

/// TLS cipher suites supported by the server
/// RFC 8446 (TLS 1.3) and RFC 5246 (TLS 1.2) cipher suites
pub const CipherSuite = enum(u16) {
    // TLS 1.3 cipher suites (mandatory)
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,

    // TLS 1.2 cipher suites (for legacy compatibility)
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9,

    pub fn isSecure(self: CipherSuite) bool {
        // All listed ciphers are considered secure
        return switch (self) {
            .TLS_AES_128_GCM_SHA256,
            .TLS_AES_256_GCM_SHA384,
            .TLS_CHACHA20_POLY1305_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            .TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            => true,
        };
    }

    pub fn isTls13(self: CipherSuite) bool {
        return switch (self) {
            .TLS_AES_128_GCM_SHA256,
            .TLS_AES_256_GCM_SHA384,
            .TLS_CHACHA20_POLY1305_SHA256,
            => true,
            else => false,
        };
    }

    pub fn toString(self: CipherSuite) []const u8 {
        return switch (self) {
            .TLS_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
            .TLS_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
            .TLS_CHACHA20_POLY1305_SHA256 => "TLS_CHACHA20_POLY1305_SHA256",
            .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            .TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        };
    }
};

/// TLS session ticket for session resumption (RFC 5077)
pub const SessionTicket = struct {
    ticket_lifetime: u32, // Lifetime in seconds
    ticket_age_add: u32, // Random value for obfuscating ticket age
    nonce: [12]u8, // Unique nonce for this ticket
    ticket: []const u8, // Encrypted session state
    creation_time: i64, // When ticket was created

    pub fn isExpired(self: SessionTicket) bool {
        const now = time_compat.timestamp();
        return (now - self.creation_time) > self.ticket_lifetime;
    }
};

/// OCSP response for stapling
pub const OcspResponse = struct {
    status: OcspStatus,
    this_update: i64,
    next_update: i64,
    response_data: []const u8,

    pub const OcspStatus = enum {
        good,
        revoked,
        unknown,
    };

    pub fn isValid(self: OcspResponse) bool {
        const now = time_compat.timestamp();
        return now >= self.this_update and now <= self.next_update and self.status == .good;
    }
};

/// TLS configuration for the SMTP server
pub const TlsConfig = struct {
    enabled: bool,
    cert_path: ?[]const u8,
    key_path: ?[]const u8,
    validate_certificates: bool = true,
    allow_self_signed: bool = false,

    /// Minimum TLS version (default: TLS 1.2)
    min_version: TlsVersion = .tls_1_2,

    /// Preferred TLS version (default: TLS 1.3)
    preferred_version: TlsVersion = .tls_1_3,

    /// Enable TLS 1.2 fallback for legacy clients
    allow_tls_1_2_fallback: bool = true,

    /// Enabled cipher suites (null = use defaults)
    cipher_suites: ?[]const CipherSuite = null,

    /// Enable session tickets for session resumption
    enable_session_tickets: bool = true,

    /// Session ticket lifetime in seconds (default: 24 hours)
    session_ticket_lifetime: u32 = 86400,

    /// Enable OCSP stapling
    enable_ocsp_stapling: bool = false,

    /// OCSP responder URL (optional, can be extracted from certificate)
    ocsp_responder_url: ?[]const u8 = null,

    /// Certificate chain path (for intermediate certificates)
    cert_chain_path: ?[]const u8 = null,

    /// Get default cipher suites based on configuration
    pub fn getEnabledCipherSuites(self: TlsConfig) []const CipherSuite {
        if (self.cipher_suites) |suites| {
            return suites;
        }

        // Default cipher suites in preference order
        if (self.allow_tls_1_2_fallback) {
            return &[_]CipherSuite{
                // TLS 1.3 (preferred)
                .TLS_AES_256_GCM_SHA384,
                .TLS_CHACHA20_POLY1305_SHA256,
                .TLS_AES_128_GCM_SHA256,
                // TLS 1.2 (fallback)
                .TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            };
        } else {
            // TLS 1.3 only
            return &[_]CipherSuite{
                .TLS_AES_256_GCM_SHA384,
                .TLS_CHACHA20_POLY1305_SHA256,
                .TLS_AES_128_GCM_SHA256,
            };
        }
    }
};

/// Session cache for TLS session resumption
pub const SessionCache = struct {
    allocator: std.mem.Allocator,
    sessions: std.StringHashMap(SessionTicket),
    max_sessions: usize,
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator, max_sessions: usize) SessionCache {
        return .{
            .allocator = allocator,
            .sessions = std.StringHashMap(SessionTicket).init(allocator),
            .max_sessions = max_sessions,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *SessionCache) void {
        var iter = self.sessions.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.ticket);
        }
        self.sessions.deinit();
    }

    /// Store a session ticket
    pub fn put(self: *SessionCache, session_id: []const u8, ticket: SessionTicket) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Evict expired sessions if at capacity
        if (self.sessions.count() >= self.max_sessions) {
            self.evictExpired();
        }

        // SECURITY: If still at capacity after evicting expired, evict oldest (LRU)
        if (self.sessions.count() >= self.max_sessions) {
            self.evictOldest();
        }

        const id_copy = try self.allocator.dupe(u8, session_id);
        const ticket_copy = SessionTicket{
            .ticket_lifetime = ticket.ticket_lifetime,
            .ticket_age_add = ticket.ticket_age_add,
            .nonce = ticket.nonce,
            .ticket = try self.allocator.dupe(u8, ticket.ticket),
            .creation_time = ticket.creation_time,
        };

        try self.sessions.put(id_copy, ticket_copy);
    }

    /// Retrieve a session ticket
    pub fn get(self: *SessionCache, session_id: []const u8) ?SessionTicket {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.sessions.get(session_id)) |ticket| {
            if (!ticket.isExpired()) {
                return ticket;
            }
            // Remove expired ticket
            _ = self.sessions.remove(session_id);
        }
        return null;
    }

    /// Remove expired sessions
    fn evictExpired(self: *SessionCache) void {
        var to_remove: std.ArrayList([]const u8) = .empty;
        defer to_remove.deinit(self.allocator);

        var iter = self.sessions.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.isExpired()) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            if (self.sessions.fetchRemove(key)) |removed| {
                self.allocator.free(removed.key);
                self.allocator.free(removed.value.ticket);
            }
        }
    }

    /// Evict the oldest session (LRU eviction when cache is full and no expired entries)
    fn evictOldest(self: *SessionCache) void {
        var oldest_key: ?[]const u8 = null;
        var oldest_time: i64 = std.math.maxInt(i64);

        var iter = self.sessions.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.creation_time < oldest_time) {
                oldest_time = entry.value_ptr.creation_time;
                oldest_key = entry.key_ptr.*;
            }
        }

        if (oldest_key) |key| {
            if (self.sessions.fetchRemove(key)) |removed| {
                self.allocator.free(removed.key);
                self.allocator.free(removed.value.ticket);
            }
        }
    }
};

/// TLS context for managing certificates and keys
pub const TlsContext = struct {
    allocator: std.mem.Allocator,
    config: TlsConfig,
    cert_data: ?[]u8,
    key_data: ?[]u8,
    cert_chain_data: ?[]u8,
    // Store the parsed CertKeyPair to reuse across handshakes
    cert_key_pair: ?tls.config.CertKeyPair,
    logger: *logger.Logger,
    // Session cache for session resumption
    session_cache: ?*SessionCache,
    // Cached OCSP response for stapling
    ocsp_response: ?OcspResponse,
    ocsp_response_data: ?[]u8,

    pub fn init(allocator: std.mem.Allocator, cfg: TlsConfig, log: *logger.Logger) !TlsContext {
        var ctx = TlsContext{
            .allocator = allocator,
            .config = cfg,
            .cert_data = null,
            .key_data = null,
            .cert_chain_data = null,
            .cert_key_pair = null,
            .logger = log,
            .session_cache = null,
            .ocsp_response = null,
            .ocsp_response_data = null,
        };

        if (cfg.enabled) {
            try ctx.loadCertificates();
            try ctx.loadCertKeyPair();

            // Initialize session cache if session tickets enabled
            if (cfg.enable_session_tickets) {
                const cache = try allocator.create(SessionCache);
                cache.* = SessionCache.init(allocator, 10000); // Max 10k sessions
                ctx.session_cache = cache;
                log.info("TLS session resumption enabled (max 10000 sessions)", .{});
            }

            // Log TLS configuration
            log.info("TLS configuration: min={s}, preferred={s}, fallback={}", .{
                cfg.min_version.toString(),
                cfg.preferred_version.toString(),
                cfg.allow_tls_1_2_fallback,
            });

            // Log enabled cipher suites
            const suites = cfg.getEnabledCipherSuites();
            log.info("Enabled cipher suites ({d}):", .{suites.len});
            for (suites) |suite| {
                log.info("  - {s}", .{suite.toString()});
            }
        }

        return ctx;
    }

    pub fn deinit(self: *TlsContext) void {
        if (self.cert_key_pair) |*ckp| {
            var mut_ckp = ckp.*;
            mut_ckp.deinit(self.allocator);
        }
        if (self.cert_data) |data| {
            self.allocator.free(data);
        }
        if (self.key_data) |data| {
            self.allocator.free(data);
        }
        if (self.cert_chain_data) |data| {
            self.allocator.free(data);
        }
        if (self.session_cache) |cache| {
            cache.deinit();
            self.allocator.destroy(cache);
        }
        if (self.ocsp_response_data) |data| {
            self.allocator.free(data);
        }
    }

    fn loadCertificates(self: *TlsContext) !void {
        if (self.config.cert_path) |cert_path| {
            self.logger.info("Loading TLS certificate from: {s}", .{cert_path});

            const io = io_compat.getIo();
            const cert_file = std.Io.Dir.cwd().openFile(io, cert_path, .{}) catch |err| {
                self.logger.err("Failed to open certificate file: {s} - {}", .{ cert_path, err });
                return error.CertificateLoadFailed;
            };
            defer cert_file.close(io);

            const cert_data = try time_compat.readFileToEnd(self.allocator, cert_file, 1024 * 1024); // Max 1MB
            self.cert_data = cert_data;

            self.logger.info("Certificate loaded successfully ({d} bytes)", .{cert_data.len});
        }

        if (self.config.key_path) |key_path| {
            self.logger.info("Loading TLS private key from: {s}", .{key_path});

            const io = io_compat.getIo();
            const key_file = std.Io.Dir.cwd().openFile(io, key_path, .{}) catch |err| {
                self.logger.err("Failed to open key file: {s} - {}", .{ key_path, err });
                return error.KeyLoadFailed;
            };
            defer key_file.close(io);

            const key_data = try time_compat.readFileToEnd(self.allocator, key_file, 1024 * 1024); // Max 1MB
            self.key_data = key_data;

            self.logger.info("Private key loaded successfully ({d} bytes)", .{key_data.len});
        }

        if (self.cert_data == null or self.key_data == null) {
            self.logger.err("TLS enabled but certificate or key not provided", .{});
            return error.IncompleteTlsConfiguration;
        }
    }

    /// Validate certificates using the certificate validator
    pub fn validateCertificates(self: *TlsContext) !void {
        if (!self.config.validate_certificates) {
            self.logger.warn("Certificate validation disabled", .{});
            return;
        }

        if (self.cert_data) |cert| {
            // Basic PEM format check
            if (!std.mem.startsWith(u8, cert, "-----BEGIN CERTIFICATE-----")) {
                self.logger.err("Certificate does not appear to be in PEM format", .{});
                return error.InvalidCertificateFormat;
            }

            // Comprehensive validation using CertificateValidator
            var validator = cert_validator.CertificateValidator.init(self.allocator);
            validator.allow_self_signed = self.config.allow_self_signed;

            var result = validator.validateCertificate(cert) catch |err| {
                self.logger.err("Certificate validation failed: {}", .{err});
                return err;
            };
            defer result.deinit(self.allocator);

            // Log validation results
            if (!result.valid) {
                self.logger.err("Certificate validation failed:", .{});
                for (result.errors.items) |error_msg| {
                    self.logger.err("  - {s}", .{error_msg});
                }
                return error.InvalidCertificate;
            }

            // Log warnings
            if (result.warnings.items.len > 0) {
                self.logger.warn("Certificate validation warnings:", .{});
                for (result.warnings.items) |warning| {
                    self.logger.warn("  - {s}", .{warning});
                }
            }

            // Log certificate info
            if (result.subject_cn) |cn| {
                self.logger.info("Certificate subject: {s}", .{cn});
            }
            if (result.issuer_cn) |issuer| {
                self.logger.info("Certificate issuer: {s}", .{issuer});
            }
            if (result.self_signed) {
                self.logger.warn("Certificate is self-signed", .{});
            }
            if (result.expired) {
                self.logger.err("Certificate is expired", .{});
                return error.CertificateExpired;
            }
            if (result.not_yet_valid) {
                self.logger.err("Certificate is not yet valid", .{});
                return error.CertificateNotYetValid;
            }
            if (result.days_until_expiry) |days| {
                self.logger.info("Certificate expires in {d} days", .{days});
            }
        }

        if (self.key_data) |key| {
            if (!std.mem.startsWith(u8, key, "-----BEGIN") or
                !std.mem.containsAtLeast(u8, key, 1, "PRIVATE KEY-----"))
            {
                self.logger.err("Private key does not appear to be in PEM format", .{});
                return error.InvalidKeyFormat;
            }
        }

        self.logger.info("TLS certificates validated successfully", .{});
    }

    /// Load and parse the CertKeyPair for reuse across handshakes
    fn loadCertKeyPair(self: *TlsContext) !void {
        if (!self.config.enabled) return;

        const cert_path = self.config.cert_path orelse return error.TlsNotConfigured;
        const key_path = self.config.key_path orelse return error.TlsNotConfigured;

        self.logger.info("Loading TLS CertKeyPair...", .{});

        // Convert to absolute paths if needed
        var cert_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        var key_path_buf: [std.fs.max_path_bytes]u8 = undefined;

        const io = io_compat.getIo();
        const abs_cert_path = if (std.fs.path.isAbsolute(cert_path))
            cert_path
        else blk: {
            const len = try std.Io.Dir.cwd().realPathFile(io, cert_path, &cert_path_buf);
            break :blk cert_path_buf[0..len];
        };

        const abs_key_path = if (std.fs.path.isAbsolute(key_path))
            key_path
        else blk: {
            const len = try std.Io.Dir.cwd().realPathFile(io, key_path, &key_path_buf);
            break :blk key_path_buf[0..len];
        };

        const cert_key = tls.config.CertKeyPair.fromFilePathAbsolute(
            self.allocator,
            io,
            abs_cert_path,
            abs_key_path,
        ) catch |err| {
            self.logger.err("Failed to load CertKeyPair: {}", .{err});
            return error.CertKeyPairLoadFailed;
        };

        self.cert_key_pair = cert_key;
        self.logger.info("CertKeyPair loaded successfully", .{});
    }
};

/// TLS connection wrapper
/// Note: Buffers are owned by caller (Session), not by TlsConnection
pub const TlsConnection = struct {
    conn: ?tls.Connection,
    cipher: ?tls.Cipher,

    pub fn initWithConnection(conn: tls.Connection) TlsConnection {
        return .{
            .conn = conn,
            .cipher = null,
        };
    }

    pub fn initWithCipher(cipher: tls.Cipher) TlsConnection {
        return .{
            .conn = null,
            .cipher = cipher,
        };
    }

    pub fn deinit(self: *TlsConnection) void {
        if (self.conn) |*c| {
            c.close() catch {};
        }
        self.conn = null;
        self.cipher = null;
    }

    pub fn read(self: *TlsConnection, buffer: []u8) !usize {
        if (self.conn) |*c| {
            return c.read(buffer);
        }
        // Cipher-only mode not yet fully implemented
        return error.TlsNotActive;
    }

    pub fn write(self: *TlsConnection, data: []const u8) !usize {
        if (self.conn) |*c| {
            return c.write(data);
        }
        // Cipher-only mode not yet fully implemented
        return error.TlsNotActive;
    }
};

/// Upgrade a plain TCP connection to TLS using tls.zig library
/// Caller must provide pre-allocated buffers that will persist for the connection's lifetime
pub fn upgradeToTls(
    allocator: std.mem.Allocator,
    stream: net.Stream,
    ctx: *TlsContext,
    log: *logger.Logger,
    input_buf: []u8,
    output_buf: []u8,
) !TlsConnection {
    if (!ctx.config.enabled) {
        return error.TlsNotEnabled;
    }

    const cert_path = ctx.config.cert_path orelse return error.TlsNotConfigured;
    const key_path = ctx.config.key_path orelse return error.TlsNotConfigured;

    log.info("Starting TLS handshake...", .{});

    // Load certificate and key
    const io = io_compat.getIo();
    var auth = tls.config.CertKeyPair.fromFilePathAbsolute(
        allocator,
        io,
        cert_path,
        key_path,
    ) catch |err| {
        log.err("Failed to load certificate/key: {}", .{err});
        return error.InvalidCertificate;
    };
    defer auth.deinit(allocator);

    // Use caller-provided buffers that persist at session scope
    // These buffers MUST remain valid for the lifetime of the TLS connection

    // Create buffered reader/writer with the provided buffers
    var stream_reader = stream.reader(input_buf);
    var stream_writer = stream.writer(output_buf);

    // Get interface pointers (these point into stack-local reader/writer structs)
    const reader_iface = if (@hasField(@TypeOf(stream_reader), "interface"))
        &stream_reader.interface
    else
        stream_reader.interface();
    const writer_iface = &stream_writer.interface;

    // Perform TLS handshake
    // The handshake happens synchronously here, reading/writing through the interfaces
    const tls_conn = tls.server(reader_iface, writer_iface, .{
        .auth = &auth,
    }) catch |err| {
        log.err("TLS handshake failed: {}", .{err});
        return error.TlsHandshakeFailed;
    };

    log.info("TLS handshake successful", .{});

    return TlsConnection{
        .conn = tls_conn,
    };
}

/// Generate a self-signed certificate for testing (helper function)
/// This is for development only - use proper CA-signed certificates in production
pub fn generateSelfSignedCert(allocator: std.mem.Allocator, hostname: []const u8) !void {
    _ = allocator;
    _ = hostname;

    // This would require OpenSSL or similar
    // For development, users should generate certificates manually:
    // openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365

    return error.NotImplemented;
}

/// OCSP (Online Certificate Status Protocol) helper functions
pub const OcspHelper = struct {
    allocator: std.mem.Allocator,
    responder_url: ?[]const u8,

    pub fn init(allocator: std.mem.Allocator, responder_url: ?[]const u8) OcspHelper {
        return .{
            .allocator = allocator,
            .responder_url = responder_url,
        };
    }

    /// Fetch OCSP response for certificate stapling
    /// Note: This is a placeholder - actual OCSP request requires HTTP client
    /// and proper ASN.1 encoding/decoding
    pub fn fetchOcspResponse(self: *OcspHelper, cert_data: []const u8) !OcspResponse {
        _ = self;
        _ = cert_data;

        // In a full implementation, this would:
        // 1. Parse the certificate to extract OCSP responder URL
        // 2. Build OCSP request with certificate serial number and issuer
        // 3. Send HTTP POST to OCSP responder
        // 4. Parse OCSP response and verify signature
        // 5. Cache response until nextUpdate

        return error.NotImplemented;
    }

    /// Check if OCSP response needs refresh
    pub fn needsRefresh(response: *const OcspResponse) bool {
        const now = time_compat.timestamp();
        // Refresh if within 10% of expiry
        const remaining = response.next_update - now;
        const total_validity = response.next_update - response.this_update;
        return remaining < @divFloor(total_validity, 10);
    }
};

/// TLS handshake error categories for better diagnostics
pub const TlsHandshakeError = enum {
    certificate_expired,
    certificate_revoked,
    certificate_unknown,
    certificate_chain_incomplete,
    cipher_mismatch,
    version_mismatch,
    client_hello_failed,
    server_hello_failed,
    key_exchange_failed,
    finished_verification_failed,
    unknown,

    pub fn fromError(err: anyerror) TlsHandshakeError {
        return switch (err) {
            error.TlsHandshakeFailed => .unknown,
            error.InvalidCertificate => .certificate_unknown,
            error.CertificateExpired => .certificate_expired,
            else => .unknown,
        };
    }

    pub fn toString(self: TlsHandshakeError) []const u8 {
        return switch (self) {
            .certificate_expired => "Certificate has expired",
            .certificate_revoked => "Certificate has been revoked",
            .certificate_unknown => "Certificate validation failed",
            .certificate_chain_incomplete => "Certificate chain is incomplete",
            .cipher_mismatch => "No common cipher suite found",
            .version_mismatch => "No common TLS version supported",
            .client_hello_failed => "Failed to parse ClientHello",
            .server_hello_failed => "Failed to send ServerHello",
            .key_exchange_failed => "Key exchange failed",
            .finished_verification_failed => "Finished message verification failed",
            .unknown => "Unknown handshake error",
        };
    }
};

/// TLS statistics for monitoring
pub const TlsStats = struct {
    handshakes_total: u64 = 0,
    handshakes_failed: u64 = 0,
    session_resumptions: u64 = 0,
    active_sessions: u32 = 0,
    bytes_encrypted: u64 = 0,
    bytes_decrypted: u64 = 0,

    pub fn recordHandshake(self: *TlsStats, success: bool) void {
        self.handshakes_total += 1;
        if (!success) {
            self.handshakes_failed += 1;
        }
    }

    pub fn recordSessionResumption(self: *TlsStats) void {
        self.session_resumptions += 1;
    }

    pub fn getHandshakeSuccessRate(self: *const TlsStats) f64 {
        if (self.handshakes_total == 0) return 1.0;
        const successful = self.handshakes_total - self.handshakes_failed;
        return @as(f64, @floatFromInt(successful)) / @as(f64, @floatFromInt(self.handshakes_total));
    }
};

// Tests
test "cipher suite properties" {
    const testing = std.testing;

    // TLS 1.3 cipher suites
    try testing.expect(CipherSuite.TLS_AES_256_GCM_SHA384.isTls13());
    try testing.expect(CipherSuite.TLS_AES_256_GCM_SHA384.isSecure());

    // TLS 1.2 cipher suites
    try testing.expect(!CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.isTls13());
    try testing.expect(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.isSecure());
}

test "TLS version string conversion" {
    const testing = std.testing;

    try testing.expectEqualStrings("TLS 1.2", TlsVersion.tls_1_2.toString());
    try testing.expectEqualStrings("TLS 1.3", TlsVersion.tls_1_3.toString());
}

test "session ticket expiry" {
    const testing = std.testing;

    const ticket = SessionTicket{
        .ticket_lifetime = 3600, // 1 hour
        .ticket_age_add = 12345,
        .nonce = [_]u8{0} ** 12,
        .ticket = "",
        .creation_time = time_compat.timestamp() - 3601, // Created over 1 hour ago
    };

    try testing.expect(ticket.isExpired());

    const fresh_ticket = SessionTicket{
        .ticket_lifetime = 3600,
        .ticket_age_add = 12345,
        .nonce = [_]u8{0} ** 12,
        .ticket = "",
        .creation_time = time_compat.timestamp(),
    };

    try testing.expect(!fresh_ticket.isExpired());
}

test "OCSP response validity" {
    const testing = std.testing;

    const now = time_compat.timestamp();

    const valid_response = OcspResponse{
        .status = .good,
        .this_update = now - 3600, // 1 hour ago
        .next_update = now + 3600, // 1 hour from now
        .response_data = "",
    };

    try testing.expect(valid_response.isValid());

    const expired_response = OcspResponse{
        .status = .good,
        .this_update = now - 7200,
        .next_update = now - 3600, // Expired 1 hour ago
        .response_data = "",
    };

    try testing.expect(!expired_response.isValid());

    const revoked_response = OcspResponse{
        .status = .revoked,
        .this_update = now - 3600,
        .next_update = now + 3600,
        .response_data = "",
    };

    try testing.expect(!revoked_response.isValid());
}

test "TLS config cipher suite defaults" {
    const testing = std.testing;

    // Config with TLS 1.2 fallback enabled
    const config_with_fallback = TlsConfig{
        .enabled = true,
        .cert_path = null,
        .key_path = null,
        .allow_tls_1_2_fallback = true,
    };

    const suites_with_fallback = config_with_fallback.getEnabledCipherSuites();
    try testing.expect(suites_with_fallback.len == 9); // 3 TLS 1.3 + 6 TLS 1.2

    // Config without TLS 1.2 fallback
    const config_no_fallback = TlsConfig{
        .enabled = true,
        .cert_path = null,
        .key_path = null,
        .allow_tls_1_2_fallback = false,
    };

    const suites_no_fallback = config_no_fallback.getEnabledCipherSuites();
    try testing.expect(suites_no_fallback.len == 3); // Only TLS 1.3
}

test "TLS stats tracking" {
    const testing = std.testing;

    var stats = TlsStats{};

    stats.recordHandshake(true);
    stats.recordHandshake(true);
    stats.recordHandshake(false);

    try testing.expectEqual(@as(u64, 3), stats.handshakes_total);
    try testing.expectEqual(@as(u64, 1), stats.handshakes_failed);

    const rate = stats.getHandshakeSuccessRate();
    try testing.expectApproxEqAbs(@as(f64, 0.666), rate, 0.01);
}

test "session cache" {
    const testing = std.testing;

    var cache = SessionCache.init(testing.allocator, 100);
    defer cache.deinit();

    var nonce: [12]u8 = undefined;
    io_compat.randomBytes(&nonce);

    const ticket_data = "test-ticket-data";
    const ticket = SessionTicket{
        .ticket_lifetime = 3600,
        .ticket_age_add = 12345,
        .nonce = nonce,
        .ticket = ticket_data,
        .creation_time = time_compat.timestamp(),
    };

    try cache.put("session-1", ticket);

    const retrieved = cache.get("session-1");
    try testing.expect(retrieved != null);
    try testing.expectEqual(@as(u32, 3600), retrieved.?.ticket_lifetime);

    // Non-existent session
    try testing.expect(cache.get("session-nonexistent") == null);
}

// =============================================================================
// TLS Cipher Suite Negotiation
// =============================================================================

/// Named groups (curves) for key exchange - RFC 8446
pub const NamedGroup = enum(u16) {
    // Elliptic Curve Groups (ECDHE)
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,
    x25519 = 0x001D,
    x448 = 0x001E,

    // Finite Field Groups (DHE)
    ffdhe2048 = 0x0100,
    ffdhe3072 = 0x0101,
    ffdhe4096 = 0x0102,
    ffdhe6144 = 0x0103,
    ffdhe8192 = 0x0104,

    pub fn toString(self: NamedGroup) []const u8 {
        return switch (self) {
            .secp256r1 => "secp256r1",
            .secp384r1 => "secp384r1",
            .secp521r1 => "secp521r1",
            .x25519 => "x25519",
            .x448 => "x448",
            .ffdhe2048 => "ffdhe2048",
            .ffdhe3072 => "ffdhe3072",
            .ffdhe4096 => "ffdhe4096",
            .ffdhe6144 => "ffdhe6144",
            .ffdhe8192 => "ffdhe8192",
        };
    }

    pub fn getKeySize(self: NamedGroup) u16 {
        return switch (self) {
            .secp256r1, .x25519 => 256,
            .secp384r1 => 384,
            .secp521r1, .x448 => 521,
            .ffdhe2048 => 2048,
            .ffdhe3072 => 3072,
            .ffdhe4096 => 4096,
            .ffdhe6144 => 6144,
            .ffdhe8192 => 8192,
        };
    }

    pub fn isEllipticCurve(self: NamedGroup) bool {
        return switch (self) {
            .secp256r1, .secp384r1, .secp521r1, .x25519, .x448 => true,
            else => false,
        };
    }
};

/// Signature algorithms for certificate verification - RFC 8446
pub const SignatureScheme = enum(u16) {
    // RSA PKCS#1 v1.5
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,

    // ECDSA
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,

    // RSA-PSS with public key OID rsaEncryption
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,

    // EdDSA
    ed25519 = 0x0807,
    ed448 = 0x0808,

    // RSA-PSS with public key OID RSASSA-PSS
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,

    pub fn toString(self: SignatureScheme) []const u8 {
        return switch (self) {
            .rsa_pkcs1_sha256 => "rsa_pkcs1_sha256",
            .rsa_pkcs1_sha384 => "rsa_pkcs1_sha384",
            .rsa_pkcs1_sha512 => "rsa_pkcs1_sha512",
            .ecdsa_secp256r1_sha256 => "ecdsa_secp256r1_sha256",
            .ecdsa_secp384r1_sha384 => "ecdsa_secp384r1_sha384",
            .ecdsa_secp521r1_sha512 => "ecdsa_secp521r1_sha512",
            .rsa_pss_rsae_sha256 => "rsa_pss_rsae_sha256",
            .rsa_pss_rsae_sha384 => "rsa_pss_rsae_sha384",
            .rsa_pss_rsae_sha512 => "rsa_pss_rsae_sha512",
            .ed25519 => "ed25519",
            .ed448 => "ed448",
            .rsa_pss_pss_sha256 => "rsa_pss_pss_sha256",
            .rsa_pss_pss_sha384 => "rsa_pss_pss_sha384",
            .rsa_pss_pss_sha512 => "rsa_pss_pss_sha512",
        };
    }

    pub fn isTls13Only(self: SignatureScheme) bool {
        return switch (self) {
            .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            .ed25519,
            .ed448,
            .rsa_pss_pss_sha256,
            .rsa_pss_pss_sha384,
            .rsa_pss_pss_sha512,
            => true,
            else => false,
        };
    }
};

/// TLS extension types - RFC 8446
pub const ExtensionType = enum(u16) {
    server_name = 0,
    max_fragment_length = 1,
    status_request = 5,
    supported_groups = 10,
    signature_algorithms = 13,
    use_srtp = 14,
    heartbeat = 15,
    application_layer_protocol_negotiation = 16,
    signed_certificate_timestamp = 18,
    client_certificate_type = 19,
    server_certificate_type = 20,
    padding = 21,
    pre_shared_key = 41,
    early_data = 42,
    supported_versions = 43,
    cookie = 44,
    psk_key_exchange_modes = 45,
    certificate_authorities = 47,
    oid_filters = 48,
    post_handshake_auth = 49,
    signature_algorithms_cert = 50,
    key_share = 51,

    pub fn toString(self: ExtensionType) []const u8 {
        return switch (self) {
            .server_name => "server_name",
            .max_fragment_length => "max_fragment_length",
            .status_request => "status_request",
            .supported_groups => "supported_groups",
            .signature_algorithms => "signature_algorithms",
            .use_srtp => "use_srtp",
            .heartbeat => "heartbeat",
            .application_layer_protocol_negotiation => "alpn",
            .signed_certificate_timestamp => "sct",
            .client_certificate_type => "client_certificate_type",
            .server_certificate_type => "server_certificate_type",
            .padding => "padding",
            .pre_shared_key => "pre_shared_key",
            .early_data => "early_data",
            .supported_versions => "supported_versions",
            .cookie => "cookie",
            .psk_key_exchange_modes => "psk_key_exchange_modes",
            .certificate_authorities => "certificate_authorities",
            .oid_filters => "oid_filters",
            .post_handshake_auth => "post_handshake_auth",
            .signature_algorithms_cert => "signature_algorithms_cert",
            .key_share => "key_share",
        };
    }
};

/// Cipher suite negotiator for selecting best cipher suite
pub const CipherNegotiator = struct {
    allocator: std.mem.Allocator,
    server_config: NegotiationConfig,

    pub const NegotiationConfig = struct {
        // Server's preferred cipher suites (in order of preference)
        cipher_suites: []const CipherSuite = &[_]CipherSuite{
            .TLS_AES_256_GCM_SHA384,
            .TLS_CHACHA20_POLY1305_SHA256,
            .TLS_AES_128_GCM_SHA256,
            .TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        },

        // Server's preferred named groups
        named_groups: []const NamedGroup = &[_]NamedGroup{
            .x25519,
            .secp256r1,
            .secp384r1,
            .x448,
        },

        // Server's preferred signature algorithms
        signature_algorithms: []const SignatureScheme = &[_]SignatureScheme{
            .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pkcs1_sha256,
            .rsa_pkcs1_sha384,
            .ed25519,
        },

        // TLS version constraints
        min_version: TlsVersion = .tls_1_2,
        max_version: TlsVersion = .tls_1_3,

        // Prefer server cipher order
        server_preference: bool = true,

        // Require perfect forward secrecy
        require_pfs: bool = true,
    };

    pub fn init(allocator: std.mem.Allocator, config: NegotiationConfig) CipherNegotiator {
        return .{
            .allocator = allocator,
            .server_config = config,
        };
    }

    /// Negotiate cipher suite from client hello
    pub fn negotiateCipherSuite(
        self: *CipherNegotiator,
        client_suites: []const u16,
    ) ?CipherSuite {
        if (self.server_config.server_preference) {
            // Server preference: iterate server's list first
            for (self.server_config.cipher_suites) |server_suite| {
                for (client_suites) |client_suite| {
                    if (@intFromEnum(server_suite) == client_suite) {
                        return server_suite;
                    }
                }
            }
        } else {
            // Client preference: iterate client's list first
            for (client_suites) |client_suite| {
                for (self.server_config.cipher_suites) |server_suite| {
                    if (@intFromEnum(server_suite) == client_suite) {
                        return server_suite;
                    }
                }
            }
        }
        return null;
    }

    /// Negotiate named group for key exchange
    pub fn negotiateNamedGroup(
        self: *CipherNegotiator,
        client_groups: []const u16,
    ) ?NamedGroup {
        for (self.server_config.named_groups) |server_group| {
            for (client_groups) |client_group| {
                if (@intFromEnum(server_group) == client_group) {
                    return server_group;
                }
            }
        }
        return null;
    }

    /// Negotiate signature algorithm
    pub fn negotiateSignatureAlgorithm(
        self: *CipherNegotiator,
        client_schemes: []const u16,
        tls_version: TlsVersion,
    ) ?SignatureScheme {
        for (self.server_config.signature_algorithms) |server_scheme| {
            // Skip TLS 1.3-only schemes for TLS 1.2
            if (tls_version == .tls_1_2 and server_scheme.isTls13Only()) {
                continue;
            }

            for (client_schemes) |client_scheme| {
                if (@intFromEnum(server_scheme) == client_scheme) {
                    return server_scheme;
                }
            }
        }
        return null;
    }

    /// Negotiate TLS version
    pub fn negotiateVersion(
        self: *CipherNegotiator,
        client_versions: []const u16,
    ) ?TlsVersion {
        // TLS 1.3 = 0x0304, TLS 1.2 = 0x0303
        const tls_1_3: u16 = 0x0304;
        const tls_1_2: u16 = 0x0303;

        // Check if client supports TLS 1.3 and we allow it
        if (self.server_config.max_version == .tls_1_3) {
            for (client_versions) |ver| {
                if (ver == tls_1_3) return .tls_1_3;
            }
        }

        // Check if client supports TLS 1.2 and we allow it
        if (self.server_config.min_version == .tls_1_2 or
            self.server_config.max_version == .tls_1_2)
        {
            for (client_versions) |ver| {
                if (ver == tls_1_2) return .tls_1_2;
            }
        }

        return null;
    }

    /// Full negotiation result
    pub fn negotiate(
        self: *CipherNegotiator,
        client_hello: *const ClientHelloParams,
    ) NegotiationResult {
        const version = self.negotiateVersion(client_hello.supported_versions) orelse {
            return .{ .success = false, .error_reason = .version_mismatch };
        };

        const cipher_suite = self.negotiateCipherSuite(client_hello.cipher_suites) orelse {
            return .{ .success = false, .error_reason = .cipher_mismatch };
        };

        const named_group = self.negotiateNamedGroup(client_hello.named_groups) orelse {
            return .{ .success = false, .error_reason = .no_common_group };
        };

        const signature_scheme = self.negotiateSignatureAlgorithm(
            client_hello.signature_algorithms,
            version,
        ) orelse {
            return .{ .success = false, .error_reason = .no_common_signature };
        };

        return .{
            .success = true,
            .error_reason = null,
            .version = version,
            .cipher_suite = cipher_suite,
            .named_group = named_group,
            .signature_scheme = signature_scheme,
            .server_name = client_hello.server_name,
            .alpn_protocol = self.negotiateAlpn(client_hello.alpn_protocols),
        };
    }

    fn negotiateAlpn(self: *CipherNegotiator, client_protocols: []const []const u8) ?[]const u8 {
        _ = self;
        // For SMTP, we typically use "smtp" or don't use ALPN
        for (client_protocols) |proto| {
            if (std.mem.eql(u8, proto, "smtp") or
                std.mem.eql(u8, proto, "submission"))
            {
                return proto;
            }
        }
        return null;
    }

    pub const NegotiationResult = struct {
        success: bool,
        error_reason: ?NegotiationError = null,
        version: ?TlsVersion = null,
        cipher_suite: ?CipherSuite = null,
        named_group: ?NamedGroup = null,
        signature_scheme: ?SignatureScheme = null,
        server_name: ?[]const u8 = null,
        alpn_protocol: ?[]const u8 = null,

        pub fn toJson(self: *const NegotiationResult, allocator: std.mem.Allocator) ![]u8 {
            if (!self.success) {
                return std.fmt.allocPrint(allocator,
                    \\{{"success": false, "error": "{s}"}}
                , .{if (self.error_reason) |e| e.toString() else "unknown"});
            }

            return std.fmt.allocPrint(allocator,
                \\{{
                \\  "success": true,
                \\  "version": "{s}",
                \\  "cipher_suite": "{s}",
                \\  "named_group": "{s}",
                \\  "signature_scheme": "{s}"
                \\}}
            , .{
                if (self.version) |v| v.toString() else "none",
                if (self.cipher_suite) |c| c.toString() else "none",
                if (self.named_group) |g| g.toString() else "none",
                if (self.signature_scheme) |s| s.toString() else "none",
            });
        }
    };

    pub const NegotiationError = enum {
        version_mismatch,
        cipher_mismatch,
        no_common_group,
        no_common_signature,
        invalid_extension,
        missing_extension,

        pub fn toString(self: NegotiationError) []const u8 {
            return switch (self) {
                .version_mismatch => "no_common_tls_version",
                .cipher_mismatch => "no_common_cipher_suite",
                .no_common_group => "no_common_named_group",
                .no_common_signature => "no_common_signature_algorithm",
                .invalid_extension => "invalid_tls_extension",
                .missing_extension => "missing_required_extension",
            };
        }
    };
};

/// Parsed ClientHello parameters for negotiation
pub const ClientHelloParams = struct {
    // Legacy version field (usually 0x0303 for TLS 1.2 compatibility)
    legacy_version: u16 = 0x0303,

    // Random bytes (32 bytes)
    random: [32]u8 = [_]u8{0} ** 32,

    // Session ID (for resumption)
    session_id: []const u8 = &[_]u8{},

    // Offered cipher suites
    cipher_suites: []const u16 = &[_]u16{},

    // Compression methods (should be [0] for TLS 1.3)
    compression_methods: []const u8 = &[_]u8{0},

    // Extensions
    supported_versions: []const u16 = &[_]u16{},
    named_groups: []const u16 = &[_]u16{},
    signature_algorithms: []const u16 = &[_]u16{},
    server_name: ?[]const u8 = null,
    alpn_protocols: []const []const u8 = &[_][]const u8{},
    key_shares: []const KeyShare = &[_]KeyShare{},

    pub const KeyShare = struct {
        group: u16,
        key_exchange: []const u8,
    };
};

/// ServerHello builder
pub const ServerHelloBuilder = struct {
    allocator: std.mem.Allocator,
    version: TlsVersion,
    cipher_suite: CipherSuite,
    session_id: []const u8,
    extensions: std.ArrayList(Extension) = .empty,

    pub const Extension = struct {
        ext_type: ExtensionType,
        data: []const u8,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        version: TlsVersion,
        cipher_suite: CipherSuite,
        session_id: []const u8,
    ) ServerHelloBuilder {
        return .{
            .allocator = allocator,
            .version = version,
            .cipher_suite = cipher_suite,
            .session_id = session_id,
        };
    }

    pub fn deinit(self: *ServerHelloBuilder) void {
        self.extensions.deinit(self.allocator);
    }

    pub fn addExtension(self: *ServerHelloBuilder, ext_type: ExtensionType, data: []const u8) !void {
        try self.extensions.append(self.allocator, .{
            .ext_type = ext_type,
            .data = data,
        });
    }

    pub fn addSupportedVersions(self: *ServerHelloBuilder) !void {
        // TLS 1.3 = 0x0304
        var data: [2]u8 = undefined;
        std.mem.writeInt(u16, &data, 0x0304, .big);
        try self.addExtension(.supported_versions, &data);
    }

    pub fn addKeyShare(self: *ServerHelloBuilder, group: NamedGroup, key_exchange: []const u8) !void {
        var data: std.ArrayList(u8) = .empty;
        defer data.deinit(self.allocator);

        // Named group (2 bytes)
        var group_bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &group_bytes, @intFromEnum(group), .big);
        try data.appendSlice(self.allocator, &group_bytes);

        // Key exchange length (2 bytes)
        var len_bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_bytes, @intCast(key_exchange.len), .big);
        try data.appendSlice(self.allocator, &len_bytes);

        // Key exchange data
        try data.appendSlice(self.allocator, key_exchange);

        try self.addExtension(.key_share, try data.toOwnedSlice(self.allocator));
    }

    /// Build the ServerHello message
    pub fn build(self: *ServerHelloBuilder) ![]u8 {
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(self.allocator);

        // Legacy version (TLS 1.2 = 0x0303)
        var version_bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &version_bytes, 0x0303, .big);
        try output.appendSlice(self.allocator, &version_bytes);

        // Server random (32 bytes)
        var random: [32]u8 = undefined;
        io_compat.randomBytes(&random);
        try output.appendSlice(self.allocator, &random);

        // Session ID length and data
        try output.append(self.allocator, @intCast(self.session_id.len));
        try output.appendSlice(self.allocator, self.session_id);

        // Cipher suite (2 bytes)
        var cipher_bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &cipher_bytes, @intFromEnum(self.cipher_suite), .big);
        try output.appendSlice(self.allocator, &cipher_bytes);

        // Compression method (0 = null)
        try output.append(self.allocator, 0);

        // Extensions length (2 bytes) - placeholder
        const ext_len_pos = output.items.len;
        try output.appendSlice(self.allocator, &[_]u8{ 0, 0 });

        // Extensions
        const ext_start = output.items.len;
        for (self.extensions.items) |ext| {
            // Extension type (2 bytes)
            var ext_type_bytes: [2]u8 = undefined;
            std.mem.writeInt(u16, &ext_type_bytes, @intFromEnum(ext.ext_type), .big);
            try output.appendSlice(self.allocator, &ext_type_bytes);

            // Extension data length (2 bytes)
            var ext_len_bytes: [2]u8 = undefined;
            std.mem.writeInt(u16, &ext_len_bytes, @intCast(ext.data.len), .big);
            try output.appendSlice(self.allocator, &ext_len_bytes);

            // Extension data
            try output.appendSlice(self.allocator, ext.data);
        }

        // Update extensions length
        const ext_len = output.items.len - ext_start;
        std.mem.writeInt(u16, output.items[ext_len_pos..][0..2], @intCast(ext_len), .big);

        return output.toOwnedSlice(self.allocator);
    }
};

// =============================================================================
// TLS Alert Codes (RFC 5246, RFC 8446)
// =============================================================================

/// TLS Alert Level
pub const AlertLevel = enum(u8) {
    warning = 1,
    fatal = 2,
};

/// TLS Alert Description (for proper error signaling)
pub const AlertDescription = enum(u8) {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    decryption_failed = 21,
    record_overflow = 22,
    decompression_failure = 30,
    handshake_failure = 40,
    no_certificate = 41,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    export_restriction = 60,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    inappropriate_fallback = 86,
    user_canceled = 90,
    no_renegotiation = 100,
    missing_extension = 109,
    unsupported_extension = 110,
    certificate_unobtainable = 111,
    unrecognized_name = 112,
    bad_certificate_status_response = 113,
    bad_certificate_hash_value = 114,
    unknown_psk_identity = 115,
    certificate_required = 116,
    no_application_protocol = 120,

    pub fn toString(self: AlertDescription) []const u8 {
        return switch (self) {
            .close_notify => "close_notify",
            .unexpected_message => "unexpected_message",
            .bad_record_mac => "bad_record_mac",
            .handshake_failure => "handshake_failure",
            .bad_certificate => "bad_certificate",
            .certificate_expired => "certificate_expired",
            .certificate_unknown => "certificate_unknown",
            .illegal_parameter => "illegal_parameter",
            .unknown_ca => "unknown_ca",
            .decode_error => "decode_error",
            .protocol_version => "protocol_version",
            .insufficient_security => "insufficient_security",
            .internal_error => "internal_error",
            .inappropriate_fallback => "inappropriate_fallback",
            .missing_extension => "missing_extension",
            .unsupported_extension => "unsupported_extension",
            .no_application_protocol => "no_application_protocol",
            else => "unknown_alert",
        };
    }

    pub fn isFatal(self: AlertDescription) bool {
        return switch (self) {
            .close_notify, .user_canceled, .no_renegotiation => false,
            else => true,
        };
    }
};

/// TLS Alert message
pub const TlsAlert = struct {
    level: AlertLevel,
    description: AlertDescription,

    /// Build alert message bytes
    pub fn build(self: TlsAlert) [7]u8 {
        return .{
            21, // Alert content type
            0x03, 0x03, // Version (TLS 1.2 for compatibility)
            0x00,                     0x02, // Length
            @intFromEnum(self.level), @intFromEnum(self.description),
        };
    }

    /// Create fatal alert
    pub fn fatal(description: AlertDescription) TlsAlert {
        return .{ .level = .fatal, .description = description };
    }

    /// Create warning alert
    pub fn warning(description: AlertDescription) TlsAlert {
        return .{ .level = .warning, .description = description };
    }
};

/// Map negotiation error to TLS alert
pub fn negotiationErrorToAlert(err: CipherNegotiator.NegotiationError) TlsAlert {
    return switch (err) {
        .version_mismatch => TlsAlert.fatal(.protocol_version),
        .cipher_mismatch => TlsAlert.fatal(.handshake_failure),
        .no_common_group => TlsAlert.fatal(.handshake_failure),
        .no_common_signature => TlsAlert.fatal(.handshake_failure),
        .invalid_extension => TlsAlert.fatal(.illegal_parameter),
        .missing_extension => TlsAlert.fatal(.missing_extension),
    };
}

// =============================================================================
// ClientHello Parser (from raw bytes)
// =============================================================================

/// Parse ClientHello from raw TLS record
pub const ClientHelloParser = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) ClientHelloParser {
        return .{ .allocator = allocator };
    }

    pub const ParseError = error{
        TooShort,
        InvalidRecordType,
        InvalidHandshakeType,
        InvalidLength,
        UnsupportedVersion,
        OutOfMemory,
    };

    /// Parse ClientHello from raw bytes
    pub fn parse(self: *ClientHelloParser, data: []const u8) ParseError!ClientHelloParams {
        if (data.len < 5) return error.TooShort;

        // Check record type (should be 22 = Handshake)
        if (data[0] != 22) return error.InvalidRecordType;

        // Skip record header (5 bytes)
        const record_payload = data[5..];
        if (record_payload.len < 4) return error.TooShort;

        // Check handshake type (should be 1 = ClientHello)
        if (record_payload[0] != 1) return error.InvalidHandshakeType;

        // Parse handshake length (3 bytes)
        const handshake_len = (@as(u32, record_payload[1]) << 16) |
            (@as(u32, record_payload[2]) << 8) |
            @as(u32, record_payload[3]);
        _ = handshake_len;

        var pos: usize = 4;
        var result = ClientHelloParams{};

        // Legacy version (2 bytes)
        if (pos + 2 > record_payload.len) return error.TooShort;
        result.legacy_version = std.mem.readInt(u16, record_payload[pos..][0..2], .big);
        pos += 2;

        // Random (32 bytes)
        if (pos + 32 > record_payload.len) return error.TooShort;
        @memcpy(&result.random, record_payload[pos..][0..32]);
        pos += 32;

        // Session ID length (1 byte) and data
        if (pos + 1 > record_payload.len) return error.TooShort;
        const session_id_len = record_payload[pos];
        pos += 1;
        if (pos + session_id_len > record_payload.len) return error.TooShort;
        result.session_id = record_payload[pos..][0..session_id_len];
        pos += session_id_len;

        // Cipher suites length (2 bytes)
        if (pos + 2 > record_payload.len) return error.TooShort;
        const cipher_suites_len = std.mem.readInt(u16, record_payload[pos..][0..2], .big);
        pos += 2;

        // Parse cipher suites
        if (pos + cipher_suites_len > record_payload.len) return error.TooShort;
        const num_suites = cipher_suites_len / 2;
        const suites = try self.allocator.alloc(u16, num_suites);
        for (0..num_suites) |i| {
            suites[i] = std.mem.readInt(u16, record_payload[pos + i * 2 ..][0..2], .big);
        }
        result.cipher_suites = suites;
        pos += cipher_suites_len;

        // Compression methods (skip for now)
        if (pos + 1 > record_payload.len) return error.TooShort;
        const compression_len = record_payload[pos];
        pos += 1 + compression_len;

        // Extensions
        if (pos + 2 <= record_payload.len) {
            const extensions_len = std.mem.readInt(u16, record_payload[pos..][0..2], .big);
            pos += 2;

            const extensions_end = pos + extensions_len;
            while (pos + 4 <= extensions_end and pos + 4 <= record_payload.len) {
                const ext_type = std.mem.readInt(u16, record_payload[pos..][0..2], .big);
                const ext_len = std.mem.readInt(u16, record_payload[pos + 2 ..][0..2], .big);
                pos += 4;

                if (pos + ext_len > record_payload.len) break;

                // Parse specific extensions
                switch (ext_type) {
                    0x0000 => { // server_name
                        if (ext_len >= 5) {
                            const name_len = std.mem.readInt(u16, record_payload[pos + 3 ..][0..2], .big);
                            if (pos + 5 + name_len <= record_payload.len) {
                                result.server_name = record_payload[pos + 5 ..][0..name_len];
                            }
                        }
                    },
                    0x002b => { // supported_versions
                        if (ext_len >= 1) {
                            const versions_len = record_payload[pos];
                            const num_versions = versions_len / 2;
                            const versions = try self.allocator.alloc(u16, num_versions);
                            for (0..num_versions) |i| {
                                versions[i] = std.mem.readInt(u16, record_payload[pos + 1 + i * 2 ..][0..2], .big);
                            }
                            result.supported_versions = versions;
                        }
                    },
                    0x000a => { // supported_groups
                        if (ext_len >= 2) {
                            const groups_len = std.mem.readInt(u16, record_payload[pos..][0..2], .big);
                            const num_groups = groups_len / 2;
                            const groups = try self.allocator.alloc(u16, num_groups);
                            for (0..num_groups) |i| {
                                groups[i] = std.mem.readInt(u16, record_payload[pos + 2 + i * 2 ..][0..2], .big);
                            }
                            result.named_groups = groups;
                        }
                    },
                    0x000d => { // signature_algorithms
                        if (ext_len >= 2) {
                            const sig_len = std.mem.readInt(u16, record_payload[pos..][0..2], .big);
                            const num_sigs = sig_len / 2;
                            const sigs = try self.allocator.alloc(u16, num_sigs);
                            for (0..num_sigs) |i| {
                                sigs[i] = std.mem.readInt(u16, record_payload[pos + 2 + i * 2 ..][0..2], .big);
                            }
                            result.signature_algorithms = sigs;
                        }
                    },
                    else => {},
                }

                pos += ext_len;
            }
        }

        return result;
    }
};

/// Detect TLS version downgrade attack
pub fn detectVersionDowngrade(server_random: [32]u8, negotiated_version: TlsVersion) bool {
    // RFC 8446 Section 4.1.3: Downgrade protection
    // Last 8 bytes of ServerHello.random contain special values if downgrade
    const downgrade_tls12: [8]u8 = .{ 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01 };
    const downgrade_tls11: [8]u8 = .{ 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00 };

    const last8 = server_random[24..32];

    return switch (negotiated_version) {
        .tls_1_2 => std.mem.eql(u8, last8, &downgrade_tls12),
        else => std.mem.eql(u8, last8, &downgrade_tls11),
    };
}

/// Check if a cipher suite provides perfect forward secrecy
pub fn hasPerfectForwardSecrecy(cipher: CipherSuite) bool {
    return switch (cipher) {
        // All ECDHE ciphers provide PFS
        .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        .TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        // TLS 1.3 ciphers always use ephemeral key exchange
        .TLS_AES_128_GCM_SHA256,
        .TLS_AES_256_GCM_SHA384,
        .TLS_CHACHA20_POLY1305_SHA256,
        => true,
    };
}

/// Get cipher suite security level (bits)
pub fn getCipherSecurityLevel(cipher: CipherSuite) u16 {
    return switch (cipher) {
        .TLS_AES_256_GCM_SHA384,
        .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        .TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        => 256,
        .TLS_CHACHA20_POLY1305_SHA256,
        .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        => 256,
        .TLS_AES_128_GCM_SHA256,
        .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        => 128,
    };
}

// =============================================================================
// Additional TLS Tests
// =============================================================================

test "tls alert construction" {
    const alert = TlsAlert.fatal(.handshake_failure);
    const bytes = alert.build();
    try std.testing.expectEqual(@as(u8, 21), bytes[0]); // Alert type
    try std.testing.expectEqual(@as(u8, 2), bytes[5]); // Fatal level
    try std.testing.expectEqual(@as(u8, 40), bytes[6]); // Handshake failure
}

test "cipher suite security properties" {
    try std.testing.expect(hasPerfectForwardSecrecy(.TLS_AES_256_GCM_SHA384));
    try std.testing.expect(hasPerfectForwardSecrecy(.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256));
    try std.testing.expectEqual(@as(u16, 256), getCipherSecurityLevel(.TLS_AES_256_GCM_SHA384));
    try std.testing.expectEqual(@as(u16, 128), getCipherSecurityLevel(.TLS_AES_128_GCM_SHA256));
}

test "cipher negotiation server preference" {
    const testing = std.testing;

    var negotiator = CipherNegotiator.init(testing.allocator, .{});

    // Client offers TLS 1.2 ciphers first, then TLS 1.3
    const client_suites = [_]u16{
        @intFromEnum(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
        @intFromEnum(CipherSuite.TLS_AES_128_GCM_SHA256),
        @intFromEnum(CipherSuite.TLS_AES_256_GCM_SHA384),
    };

    // Server prefers TLS_AES_256_GCM_SHA384 (first in server list)
    const result = negotiator.negotiateCipherSuite(&client_suites);
    try testing.expect(result != null);
    try testing.expectEqual(CipherSuite.TLS_AES_256_GCM_SHA384, result.?);
}

test "version negotiation" {
    const testing = std.testing;

    var negotiator = CipherNegotiator.init(testing.allocator, .{
        .min_version = .tls_1_2,
        .max_version = .tls_1_3,
    });

    // Client supports both versions
    const client_versions = [_]u16{ 0x0304, 0x0303 }; // TLS 1.3, TLS 1.2
    const result = negotiator.negotiateVersion(&client_versions);
    try testing.expect(result != null);
    try testing.expectEqual(TlsVersion.tls_1_3, result.?);

    // Client only supports TLS 1.2
    const client_1_2_only = [_]u16{0x0303};
    const result_1_2 = negotiator.negotiateVersion(&client_1_2_only);
    try testing.expect(result_1_2 != null);
    try testing.expectEqual(TlsVersion.tls_1_2, result_1_2.?);
}

test "named group negotiation" {
    const testing = std.testing;

    var negotiator = CipherNegotiator.init(testing.allocator, .{});

    const client_groups = [_]u16{
        @intFromEnum(NamedGroup.secp256r1),
        @intFromEnum(NamedGroup.x25519),
    };

    // Server prefers x25519
    const result = negotiator.negotiateNamedGroup(&client_groups);
    try testing.expect(result != null);
    try testing.expectEqual(NamedGroup.x25519, result.?);
}

test "full negotiation" {
    const testing = std.testing;

    var negotiator = CipherNegotiator.init(testing.allocator, .{});

    const client_hello = ClientHelloParams{
        .cipher_suites = &[_]u16{
            @intFromEnum(CipherSuite.TLS_AES_128_GCM_SHA256),
            @intFromEnum(CipherSuite.TLS_AES_256_GCM_SHA384),
        },
        .supported_versions = &[_]u16{ 0x0304, 0x0303 },
        .named_groups = &[_]u16{
            @intFromEnum(NamedGroup.x25519),
            @intFromEnum(NamedGroup.secp256r1),
        },
        .signature_algorithms = &[_]u16{
            @intFromEnum(SignatureScheme.ecdsa_secp256r1_sha256),
            @intFromEnum(SignatureScheme.rsa_pss_rsae_sha256),
        },
        .server_name = "mail.example.com",
    };

    const result = negotiator.negotiate(&client_hello);
    try testing.expect(result.success);
    try testing.expectEqual(TlsVersion.tls_1_3, result.version.?);
    try testing.expectEqual(NamedGroup.x25519, result.named_group.?);
}

test "negotiation result json" {
    const testing = std.testing;

    const result = CipherNegotiator.NegotiationResult{
        .success = true,
        .version = .tls_1_3,
        .cipher_suite = .TLS_AES_256_GCM_SHA384,
        .named_group = .x25519,
        .signature_scheme = .ecdsa_secp256r1_sha256,
    };

    const json = try result.toJson(testing.allocator);
    defer testing.allocator.free(json);

    try testing.expect(std.mem.indexOf(u8, json, "TLS 1.3") != null);
    try testing.expect(std.mem.indexOf(u8, json, "x25519") != null);
}
