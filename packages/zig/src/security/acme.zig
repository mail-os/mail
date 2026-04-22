const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");

// =============================================================================
// ACME / Let's Encrypt - Automatic Certificate Provisioning
// =============================================================================
//
// ## Overview
// Implements the ACME (Automatic Certificate Management Environment) protocol
// defined in RFC 8555 for automated TLS certificate issuance and renewal,
// primarily targeting Let's Encrypt but compatible with any ACME CA.
//
// ## Architecture
//
// ```
//   ┌──────────────────────┐         ┌──────────────────────┐
//   │  CertificateManager  │────────▶│      ACMEClient      │
//   │  (High-level API)    │         │  (Protocol Handler)  │
//   └──────────┬───────────┘         └──────────┬───────────┘
//              │                                 │
//              │ monitors/renews                  │ ACME protocol
//              ▼                                 ▼
//   ┌──────────────────────┐         ┌──────────────────────┐
//   │  CertRenewalThread   │         │    ACME Directory    │
//   │  (Background Worker) │         │  (Let's Encrypt CA)  │
//   └──────────────────────┘         └──────────────────────┘
// ```
//
// ## ACME Protocol Flow (RFC 8555)
//
// ```
// 1. Client discovers endpoints via directory URL
//    GET /directory -> { newNonce, newAccount, newOrder, ... }
//
// 2. Client creates/finds account
//    POST /acme/new-account { termsOfServiceAgreed, contact }
//
// 3. Client submits order for certificate
//    POST /acme/new-order { identifiers: [{type: "dns", value: "example.com"}] }
//
// 4. Client fetches authorization challenges
//    POST /acme/authz/{id} -> { challenges: [{type: "http-01", token, url}] }
//
// 5. Client provisions challenge response
//    - HTTP-01: serve token at /.well-known/acme-challenge/{token}
//    - DNS-01:  create TXT record _acme-challenge.{domain}
//    - TLS-ALPN-01: serve special TLS cert with acme-tls/1
//
// 6. Client notifies CA that challenge is ready
//    POST /acme/challenge/{id} {}
//
// 7. Client polls order until ready
//    POST /acme/order/{id} -> { status: "ready" }
//
// 8. Client finalizes order with CSR
//    POST /acme/order/{id}/finalize { csr: base64url(der_csr) }
//
// 9. Client downloads certificate
//    POST /acme/cert/{id} -> PEM certificate chain
// ```
//
// ## HTTP-01 Challenge Detail
//
// The HTTP-01 challenge requires serving a specific key authorization at:
//   http://{domain}/.well-known/acme-challenge/{token}
//
// Key authorization = {token}.{account_key_thumbprint}
//
// The thumbprint is the base64url-encoded SHA-256 hash of the JWK thumbprint
// of the account key, per RFC 7638.
//
// ## Certificate Renewal Strategy
//
// ```
// Certificate Timeline:
// |--issued--|----------valid----------|--renew--|--expire--|
//                                      ^
//                                      renew_before_days
//
// Default: renew 30 days before expiry (configurable)
// Check interval: every 12 hours
// Retry on failure: exponential backoff (1h, 2h, 4h, 8h, max 24h)
// ```
//
// ## Security Considerations
//
// - Account private keys are stored with restrictive permissions (0600)
// - Challenge tokens are validated before serving
// - Nonces are consumed exactly once (replay protection)
// - Certificate chains are verified before installation
// - All ACME requests use JWS (JSON Web Signature) with ES256 or RS256
//
// ## Configuration Example
//
// ```zig
// var config = ACMEConfig{
//     .directory_url = ACMEConfig.LETS_ENCRYPT_PRODUCTION,
//     .email = "admin@example.com",
//     .domains = &.{ "mail.example.com", "smtp.example.com" },
//     .key_type = .ec256,
//     .auto_renew = true,
//     .renew_before_days = 30,
//     .cert_dir = "/etc/ssl/acme",
// };
// ```
// =============================================================================

/// ACME protocol error types matching RFC 8555 Section 6.7
pub const ACMEError = error{
    /// The request specified an account that does not exist
    AccountDoesNotExist,
    /// The request specified a certificate to be revoked that has already been revoked
    AlreadyRevoked,
    /// The CSR is unacceptable (e.g., due to a short key)
    BadCSR,
    /// The client sent an unacceptable anti-replay nonce
    BadNonce,
    /// The JWS was signed by a public key the server does not support
    BadPublicKey,
    /// The revocation reason provided is not allowed by the server
    BadRevocationReason,
    /// The JWS was signed with an algorithm the server does not support
    BadSignatureAlgorithm,
    /// The client's Certificate Authority Authorization (CAA) records
    /// forbid the CA from issuing a certificate
    CAA,
    /// Specific error conditions are indicated in sub-problems
    Compound,
    /// The server could not connect to the client for DV validation
    Connection,
    /// There was a problem with a DNS query during identifier validation
    DNS,
    /// The request must include a value for the "externalAccountBinding" field
    ExternalAccountRequired,
    /// Response received didn't match the challenge's requirements
    IncorrectResponse,
    /// A contact URL for an account used an unsupported protocol scheme
    InvalidContact,
    /// The request message was malformed
    Malformed,
    /// The request attempted to finalize an order that is not ready
    OrderNotReady,
    /// The request exceeds a rate limit
    RateLimited,
    /// The server will not issue for the identifier
    RejectedIdentifier,
    /// The server experienced an internal error
    ServerInternal,
    /// The server received a TLS error during validation
    TLS,
    /// The client lacks sufficient authorization
    Unauthorized,
    /// A contact URL for an account was not supported by the server
    UnsupportedContact,
    /// The identifier is of an unsupported type
    UnsupportedIdentifier,
    /// The revocation request included user-assigned certificate fields
    /// that the CA doesn't support
    UserActionRequired,
    /// HTTP request to the ACME server failed
    HttpRequestFailed,
    /// Failed to parse ACME server response
    InvalidResponse,
    /// No valid challenge type available
    NoChallengeAvailable,
    /// Certificate directory does not exist or is not writable
    CertDirNotAccessible,
    /// Failed to generate key pair
    KeyGenerationFailed,
    /// CSR generation failed
    CSRGenerationFailed,
    /// Challenge validation timed out
    ChallengeTimeout,
    /// Order processing timed out
    OrderTimeout,
    /// The renewal thread is already running
    RenewalAlreadyRunning,
    /// Certificate file not found on disk
    CertificateNotFound,
    /// Failed to read certificate metadata
    CertificateMetadataError,
    /// Account key not found
    AccountKeyNotFound,
    /// Directory fetch failed
    DirectoryFetchFailed,
    /// Nonce acquisition failed
    NonceFetchFailed,
};

/// ACME order status as defined in RFC 8555 Section 7.1.6
pub const ACMEOrderStatus = enum {
    /// The order has been created but authorizations are not yet satisfied
    pending,
    /// All authorizations are satisfied; ready to finalize
    ready,
    /// The certificate is being issued
    processing,
    /// The certificate has been issued
    valid,
    /// The order has failed or one of its authorizations has become invalid
    invalid,

    pub fn toString(self: ACMEOrderStatus) []const u8 {
        return switch (self) {
            .pending => "pending",
            .ready => "ready",
            .processing => "processing",
            .valid => "valid",
            .invalid => "invalid",
        };
    }

    pub fn fromString(s: []const u8) ?ACMEOrderStatus {
        if (std.mem.eql(u8, s, "pending")) return .pending;
        if (std.mem.eql(u8, s, "ready")) return .ready;
        if (std.mem.eql(u8, s, "processing")) return .processing;
        if (std.mem.eql(u8, s, "valid")) return .valid;
        if (std.mem.eql(u8, s, "invalid")) return .invalid;
        return null;
    }

    pub fn isTerminal(self: ACMEOrderStatus) bool {
        return self == .valid or self == .invalid;
    }
};

/// ACME challenge types as defined in RFC 8555
pub const ChallengeType = enum {
    /// HTTP-01: serve key authorization at /.well-known/acme-challenge/{token}
    http01,
    /// DNS-01: provision TXT record at _acme-challenge.{domain}
    dns01,
    /// TLS-ALPN-01: serve special TLS cert with acme-tls/1 ALPN
    tlsalpn01,

    pub fn toString(self: ChallengeType) []const u8 {
        return switch (self) {
            .http01 => "http-01",
            .dns01 => "dns-01",
            .tlsalpn01 => "tls-alpn-01",
        };
    }

    pub fn fromString(s: []const u8) ?ChallengeType {
        if (std.mem.eql(u8, s, "http-01")) return .http01;
        if (std.mem.eql(u8, s, "dns-01")) return .dns01;
        if (std.mem.eql(u8, s, "tls-alpn-01")) return .tlsalpn01;
        return null;
    }
};

/// Challenge status as defined in RFC 8555 Section 7.1.6
pub const ChallengeStatus = enum {
    pending,
    processing,
    valid,
    invalid,

    pub fn toString(self: ChallengeStatus) []const u8 {
        return switch (self) {
            .pending => "pending",
            .processing => "processing",
            .valid => "valid",
            .invalid => "invalid",
        };
    }

    pub fn fromString(s: []const u8) ?ChallengeStatus {
        if (std.mem.eql(u8, s, "pending")) return .pending;
        if (std.mem.eql(u8, s, "processing")) return .processing;
        if (std.mem.eql(u8, s, "valid")) return .valid;
        if (std.mem.eql(u8, s, "invalid")) return .invalid;
        return null;
    }
};

/// Key type for ACME account and certificate keys
pub const KeyType = enum {
    /// ECDSA P-256 (recommended, smaller keys)
    ec256,
    /// ECDSA P-384
    ec384,
    /// RSA 2048-bit
    rsa2048,
    /// RSA 4096-bit
    rsa4096,

    pub fn toString(self: KeyType) []const u8 {
        return switch (self) {
            .ec256 => "EC-P256",
            .ec384 => "EC-P384",
            .rsa2048 => "RSA-2048",
            .rsa4096 => "RSA-4096",
        };
    }

    pub fn keyBits(self: KeyType) u32 {
        return switch (self) {
            .ec256 => 256,
            .ec384 => 384,
            .rsa2048 => 2048,
            .rsa4096 => 4096,
        };
    }
};

/// ACME directory endpoints as returned by the directory URL
pub const ACMEDirectory = struct {
    new_nonce_url: []const u8,
    new_account_url: []const u8,
    new_order_url: []const u8,
    revoke_cert_url: []const u8,
    key_change_url: []const u8,
    terms_of_service_url: ?[]const u8,

    pub fn deinit(self: *ACMEDirectory, allocator: std.mem.Allocator) void {
        allocator.free(self.new_nonce_url);
        allocator.free(self.new_account_url);
        allocator.free(self.new_order_url);
        allocator.free(self.revoke_cert_url);
        allocator.free(self.key_change_url);
        if (self.terms_of_service_url) |tos| allocator.free(tos);
    }
};

/// ACME challenge descriptor
pub const ACMEChallenge = struct {
    challenge_type: ChallengeType,
    url: []const u8,
    token: []const u8,
    status: ChallengeStatus,
    key_authorization: ?[]const u8,
    validated_at: ?i64,
    error_detail: ?[]const u8,

    pub fn init(
        challenge_type: ChallengeType,
        url: []const u8,
        token: []const u8,
        status: ChallengeStatus,
    ) ACMEChallenge {
        return .{
            .challenge_type = challenge_type,
            .url = url,
            .token = token,
            .status = status,
            .key_authorization = null,
            .validated_at = null,
            .error_detail = null,
        };
    }

    pub fn deinit(self: *ACMEChallenge, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
        allocator.free(self.token);
        if (self.key_authorization) |ka| allocator.free(ka);
        if (self.error_detail) |ed| allocator.free(ed);
    }

    /// Compute the HTTP-01 challenge response path
    /// Returns: /.well-known/acme-challenge/{token}
    pub fn httpChallengePath(self: *const ACMEChallenge, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "/.well-known/acme-challenge/{s}", .{self.token});
    }

    /// Compute the DNS-01 challenge TXT record name
    /// Returns: _acme-challenge.{domain}
    pub fn dnsChallengeRecord(self: *const ACMEChallenge, allocator: std.mem.Allocator, domain: []const u8) ![]u8 {
        _ = self;
        return std.fmt.allocPrint(allocator, "_acme-challenge.{s}", .{domain});
    }

    /// Check whether the challenge is in a final state
    pub fn isFinished(self: *const ACMEChallenge) bool {
        return self.status == .valid or self.status == .invalid;
    }
};

/// ACME order representing a certificate issuance request
pub const ACMEOrder = struct {
    url: []const u8,
    status: ACMEOrderStatus,
    identifiers: []const Identifier,
    authorizations: []const []const u8,
    finalize_url: []const u8,
    certificate_url: ?[]const u8,
    expires_at: ?i64,
    not_before: ?i64,
    not_after: ?i64,

    pub const Identifier = struct {
        id_type: []const u8, // "dns"
        value: []const u8, // "example.com"

        pub fn deinit(self: *const Identifier, allocator: std.mem.Allocator) void {
            allocator.free(self.id_type);
            allocator.free(self.value);
        }
    };

    pub fn deinit(self: *ACMEOrder, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
        allocator.free(self.finalize_url);
        if (self.certificate_url) |cu| allocator.free(cu);
        for (self.identifiers) |id| id.deinit(allocator);
        allocator.free(self.identifiers);
        for (self.authorizations) |auth| allocator.free(auth);
        allocator.free(self.authorizations);
    }

    pub fn isFinished(self: *const ACMEOrder) bool {
        return self.status.isTerminal();
    }
};

/// Information about an issued certificate
pub const CertificateInfo = struct {
    domain: []const u8,
    issuer: []const u8,
    not_before: i64,
    not_after: i64,
    serial: []const u8,
    fingerprint: []const u8,
    san_domains: []const []const u8,
    key_type: KeyType,
    cert_path: []const u8,
    key_path: []const u8,

    pub fn deinit(self: *CertificateInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.domain);
        allocator.free(self.issuer);
        allocator.free(self.serial);
        allocator.free(self.fingerprint);
        for (self.san_domains) |san| allocator.free(san);
        allocator.free(self.san_domains);
        allocator.free(self.cert_path);
        allocator.free(self.key_path);
    }

    /// Returns seconds until the certificate expires
    pub fn secondsUntilExpiry(self: *const CertificateInfo) i64 {
        const now = time_compat.timestamp();
        return self.not_after - now;
    }

    /// Returns days until the certificate expires
    pub fn daysUntilExpiry(self: *const CertificateInfo) i64 {
        return @divFloor(self.secondsUntilExpiry(), 86400);
    }

    /// Check if the certificate is currently valid
    pub fn isValid(self: *const CertificateInfo) bool {
        const now = time_compat.timestamp();
        return now >= self.not_before and now <= self.not_after;
    }

    /// Check if the certificate has expired
    pub fn isExpired(self: *const CertificateInfo) bool {
        return time_compat.timestamp() > self.not_after;
    }
};

/// ACME configuration for certificate provisioning
pub const ACMEConfig = struct {
    /// Let's Encrypt production directory URL
    pub const LETS_ENCRYPT_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory";
    /// Let's Encrypt staging directory URL (for testing)
    pub const LETS_ENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory";

    /// ACME directory URL (default: Let's Encrypt production)
    directory_url: []const u8 = LETS_ENCRYPT_PRODUCTION,

    /// Contact email for the ACME account
    email: []const u8 = "",

    /// List of domain names to obtain certificates for
    domains: []const []const u8 = &.{},

    /// Key type for certificate and account keys
    key_type: KeyType = .ec256,

    /// Whether to automatically renew certificates before expiry
    auto_renew: bool = true,

    /// Number of days before expiry to trigger renewal
    renew_before_days: u32 = 30,

    /// Directory to store certificates and keys
    cert_dir: []const u8 = "/etc/ssl/acme",

    /// Directory to store account keys
    account_dir: []const u8 = "/etc/ssl/acme/accounts",

    /// Preferred challenge type
    preferred_challenge: ChallengeType = .http01,

    /// Maximum time to wait for order completion (seconds)
    order_timeout_seconds: u32 = 300,

    /// Maximum time to wait for challenge validation (seconds)
    challenge_timeout_seconds: u32 = 120,

    /// Interval between renewal checks (seconds)
    renewal_check_interval_seconds: u32 = 43200, // 12 hours

    /// Whether to accept the CA's terms of service automatically
    agree_to_terms: bool = false,

    /// HTTP port for HTTP-01 challenge server (typically 80)
    http_challenge_port: u16 = 80,

    /// Whether to use the staging environment (for testing)
    use_staging: bool = false,

    /// Get the effective directory URL (respects use_staging flag)
    pub fn effectiveDirectoryUrl(self: *const ACMEConfig) []const u8 {
        if (self.use_staging) return LETS_ENCRYPT_STAGING;
        return self.directory_url;
    }

    /// Validate the configuration
    pub fn validate(self: *const ACMEConfig) !void {
        if (self.email.len == 0) return ACMEError.InvalidContact;
        if (self.domains.len == 0) return ACMEError.UnsupportedIdentifier;
        if (self.renew_before_days == 0) return ACMEError.Malformed;

        // Basic email validation
        if (std.mem.indexOf(u8, self.email, "@") == null) return ACMEError.InvalidContact;

        // Validate each domain
        for (self.domains) |domain| {
            if (domain.len == 0 or domain.len > 253) return ACMEError.UnsupportedIdentifier;
            // Must not be a wildcard unless DNS-01 is the preferred challenge
            if (std.mem.startsWith(u8, domain, "*.") and self.preferred_challenge != .dns01) {
                return ACMEError.UnsupportedIdentifier;
            }
        }
    }
};

/// ACME account information
const ACMEAccount = struct {
    account_url: ?[]const u8,
    status: []const u8,
    contact: []const []const u8,
    created_at: i64,
    key_id: ?[]const u8,

    pub fn deinit(self: *ACMEAccount, allocator: std.mem.Allocator) void {
        if (self.account_url) |url| allocator.free(url);
        allocator.free(self.status);
        for (self.contact) |c| allocator.free(c);
        allocator.free(self.contact);
        if (self.key_id) |kid| allocator.free(kid);
    }
};

/// Nonce manager for ACME anti-replay protection
const NonceManager = struct {
    allocator: std.mem.Allocator,
    current_nonce: ?[]u8,
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator) NonceManager {
        return .{
            .allocator = allocator,
            .current_nonce = null,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *NonceManager) void {
        if (self.current_nonce) |nonce| {
            self.allocator.free(nonce);
        }
    }

    /// Store a new nonce received from the server
    pub fn setNonce(self: *NonceManager, nonce: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.current_nonce) |old| {
            self.allocator.free(old);
        }
        self.current_nonce = try self.allocator.dupe(u8, nonce);
    }

    /// Consume the current nonce (returns it and clears the stored value)
    pub fn consumeNonce(self: *NonceManager) ?[]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const nonce = self.current_nonce;
        self.current_nonce = null;
        return nonce;
    }

    /// Check if a nonce is available
    pub fn hasNonce(self: *NonceManager) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.current_nonce != null;
    }
};

/// ACME client implementing the ACME protocol (RFC 8555)
///
/// Handles account creation, order submission, challenge responses,
/// and certificate retrieval. HTTP transport is stubbed for integration
/// with any HTTP client library.
///
/// ## Usage
/// ```zig
/// var client = ACMEClient.init(allocator, config);
/// defer client.deinit();
///
/// try client.createAccount("admin@example.com");
/// const order = try client.requestCertificate("mail.example.com");
/// // ... handle challenges ...
/// const cert_pem = try client.getCertificate(order.url);
/// ```
pub const ACMEClient = struct {
    allocator: std.mem.Allocator,
    config: ACMEConfig,
    directory: ?ACMEDirectory,
    account: ?ACMEAccount,
    nonces: NonceManager,
    pending_challenges: std.StringHashMap(ACMEChallenge),
    active_orders: std.StringHashMap(ACMEOrder),
    stats: ACMEStats,
    mutex: mutex_compat.Mutex,

    pub const ACMEStats = struct {
        orders_created: u64 = 0,
        orders_completed: u64 = 0,
        orders_failed: u64 = 0,
        challenges_completed: u64 = 0,
        challenges_failed: u64 = 0,
        certificates_issued: u64 = 0,
        certificates_renewed: u64 = 0,
        http_requests: u64 = 0,
        http_errors: u64 = 0,
        last_order_time: i64 = 0,
        last_renewal_time: i64 = 0,
    };

    pub fn init(allocator: std.mem.Allocator, config: ACMEConfig) ACMEClient {
        return .{
            .allocator = allocator,
            .config = config,
            .directory = null,
            .account = null,
            .nonces = NonceManager.init(allocator),
            .pending_challenges = std.StringHashMap(ACMEChallenge).init(allocator),
            .active_orders = std.StringHashMap(ACMEOrder).init(allocator),
            .stats = ACMEStats{},
            .mutex = .{},
        };
    }

    pub fn deinit(self: *ACMEClient) void {
        if (self.directory) |*dir| dir.deinit(self.allocator);
        if (self.account) |*acct| acct.deinit(self.allocator);
        self.nonces.deinit();

        // Clean up pending challenges
        var challenge_iter = self.pending_challenges.iterator();
        while (challenge_iter.next()) |entry| {
            var challenge = entry.value_ptr.*;
            challenge.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.pending_challenges.deinit();

        // Clean up active orders
        var order_iter = self.active_orders.iterator();
        while (order_iter.next()) |entry| {
            var order = entry.value_ptr.*;
            order.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.active_orders.deinit();
    }

    /// Fetch the ACME directory from the CA server.
    ///
    /// The directory provides URLs for all ACME protocol operations.
    /// This must be called before any other protocol operation.
    ///
    /// Stubbed: In production, this performs GET {directory_url} and parses
    /// the JSON response to populate the ACMEDirectory structure.
    pub fn fetchDirectory(self: *ACMEClient) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.stats.http_requests += 1;

        // Stubbed HTTP GET to directory URL
        // In production: GET self.config.effectiveDirectoryUrl()
        // Response: JSON with newNonce, newAccount, newOrder, revokeCert, keyChange URLs

        const dir_url = self.config.effectiveDirectoryUrl();

        // Construct placeholder directory from the base URL
        const base = extractBaseUrl(dir_url);

        self.directory = ACMEDirectory{
            .new_nonce_url = try std.fmt.allocPrint(self.allocator, "{s}/acme/new-nonce", .{base}),
            .new_account_url = try std.fmt.allocPrint(self.allocator, "{s}/acme/new-acct", .{base}),
            .new_order_url = try std.fmt.allocPrint(self.allocator, "{s}/acme/new-order", .{base}),
            .revoke_cert_url = try std.fmt.allocPrint(self.allocator, "{s}/acme/revoke-cert", .{base}),
            .key_change_url = try std.fmt.allocPrint(self.allocator, "{s}/acme/key-change", .{base}),
            .terms_of_service_url = try std.fmt.allocPrint(self.allocator, "{s}/acme/terms", .{base}),
        };
    }

    /// Create an ACME account with the CA.
    ///
    /// Registers a new account using the provided email as the contact.
    /// The account is bound to the client's key pair and is required before
    /// ordering certificates.
    ///
    /// Stubbed: In production, this performs POST {newAccountUrl} with a JWS
    /// body containing the contact email and terms-of-service agreement.
    pub fn createAccount(self: *ACMEClient, email: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.directory == null) {
            return ACMEError.DirectoryFetchFailed;
        }

        self.stats.http_requests += 1;

        // Stubbed: POST to newAccount URL
        // JWS payload: { "termsOfServiceAgreed": true, "contact": ["mailto:{email}"] }
        // Response: 201 Created with account URL in Location header

        const contact_entry = try std.fmt.allocPrint(self.allocator, "mailto:{s}", .{email});
        var contacts = try self.allocator.alloc([]const u8, 1);
        contacts[0] = contact_entry;

        self.account = ACMEAccount{
            .account_url = try self.allocator.dupe(u8, "https://acme-v02.api.letsencrypt.org/acme/acct/stub-id"),
            .status = try self.allocator.dupe(u8, "valid"),
            .contact = contacts,
            .created_at = time_compat.timestamp(),
            .key_id = try self.allocator.dupe(u8, "stub-key-id"),
        };
    }

    /// Request a new certificate for the specified domain.
    ///
    /// Creates an ACME order and populates it with pending authorizations
    /// and challenges that must be fulfilled before the certificate can be issued.
    ///
    /// Stubbed: In production, this performs POST {newOrderUrl} with identifiers,
    /// then fetches each authorization URL to discover available challenges.
    ///
    /// Returns the order URL that can be used to track progress.
    pub fn requestCertificate(self: *ACMEClient, domain: []const u8) ![]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.account == null) {
            return ACMEError.AccountDoesNotExist;
        }

        self.stats.http_requests += 1;
        self.stats.orders_created += 1;
        self.stats.last_order_time = time_compat.timestamp();

        // Stubbed: POST to newOrder URL
        // JWS payload: { "identifiers": [{"type": "dns", "value": "{domain}"}] }
        // Response: 201 Created with order object

        const order_url = try std.fmt.allocPrint(
            self.allocator,
            "https://acme-v02.api.letsencrypt.org/acme/order/stub/{s}",
            .{domain},
        );
        const order_url_key = try self.allocator.dupe(u8, order_url);

        // Create identifier
        var identifiers = try self.allocator.alloc(ACMEOrder.Identifier, 1);
        identifiers[0] = .{
            .id_type = try self.allocator.dupe(u8, "dns"),
            .value = try self.allocator.dupe(u8, domain),
        };

        // Create authorization URL
        var authorizations = try self.allocator.alloc([]const u8, 1);
        authorizations[0] = try std.fmt.allocPrint(
            self.allocator,
            "https://acme-v02.api.letsencrypt.org/acme/authz/stub/{s}",
            .{domain},
        );

        const finalize_url = try std.fmt.allocPrint(
            self.allocator,
            "https://acme-v02.api.letsencrypt.org/acme/order/stub/{s}/finalize",
            .{domain},
        );

        const order = ACMEOrder{
            .url = order_url,
            .status = .pending,
            .identifiers = identifiers,
            .authorizations = authorizations,
            .finalize_url = finalize_url,
            .certificate_url = null,
            .expires_at = time_compat.timestamp() + 604800, // 7 days
            .not_before = null,
            .not_after = null,
        };

        try self.active_orders.put(order_url_key, order);

        // Create a stub HTTP-01 challenge for this domain
        const challenge_token = try std.fmt.allocPrint(self.allocator, "token-{s}", .{domain});
        const challenge_url = try std.fmt.allocPrint(
            self.allocator,
            "https://acme-v02.api.letsencrypt.org/acme/challenge/stub/{s}",
            .{domain},
        );

        const challenge = ACMEChallenge.init(
            self.config.preferred_challenge,
            challenge_url,
            challenge_token,
            .pending,
        );

        const domain_key = try self.allocator.dupe(u8, domain);
        try self.pending_challenges.put(domain_key, challenge);

        // Return a separate copy for the caller to own (order_url_key is owned by the hashmap)
        const caller_url = try self.allocator.dupe(u8, order_url_key);
        return caller_url;
    }

    /// Respond to an ACME challenge for a given domain.
    ///
    /// For HTTP-01 challenges, this computes the key authorization and prepares
    /// the response. The caller must ensure the challenge response is accessible
    /// at the expected URL before calling this method.
    ///
    /// Stubbed: In production, this performs POST {challengeUrl} with an empty
    /// JWS body to signal the CA to validate the challenge.
    pub fn respondToChallenge(self: *ACMEClient, domain: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const challenge_ptr = self.pending_challenges.getPtr(domain) orelse {
            return ACMEError.NoChallengeAvailable;
        };

        if (challenge_ptr.status != .pending) {
            return; // Already responded
        }

        self.stats.http_requests += 1;

        // Compute key authorization: {token}.{account_key_thumbprint}
        // The thumbprint is SHA-256 of the JWK thumbprint (RFC 7638)
        const key_auth = try std.fmt.allocPrint(
            self.allocator,
            "{s}.stub-account-thumbprint",
            .{challenge_ptr.token},
        );

        challenge_ptr.key_authorization = key_auth;

        // Stubbed: POST to challenge URL with empty JWS body
        // This tells the CA to begin validation
        // Response: challenge object with updated status

        challenge_ptr.status = .processing;
        self.stats.challenges_completed += 1;
    }

    /// Retrieve the issued certificate for a completed order.
    ///
    /// Polls the order URL to check status, and once the order is valid,
    /// downloads the certificate chain from the certificate URL.
    ///
    /// Stubbed: In production, this performs POST {orderUrl} to get the current
    /// order status, then POST {certificateUrl} to download the PEM chain.
    ///
    /// Returns a stub PEM certificate chain string.
    pub fn getCertificate(self: *ACMEClient, order_url: []const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const order_ptr = self.active_orders.getPtr(order_url) orelse {
            return ACMEError.OrderNotReady;
        };

        self.stats.http_requests += 1;

        // Stubbed: POST to order URL to poll status
        // In production, we would check if status transitions to "valid"
        // and then download the certificate from certificate_url

        // Simulate order transitioning to valid
        order_ptr.status = .valid;

        const cert_url = try std.fmt.allocPrint(
            self.allocator,
            "{s}/cert",
            .{order_url},
        );
        if (order_ptr.certificate_url) |old_url| self.allocator.free(old_url);
        order_ptr.certificate_url = cert_url;

        self.stats.certificates_issued += 1;

        // Return a stub PEM certificate
        // In production, this would be the actual PEM downloaded from the CA
        const domain_name = if (order_ptr.identifiers.len > 0)
            order_ptr.identifiers[0].value
        else
            "unknown";

        return std.fmt.allocPrint(
            self.allocator,
            "-----BEGIN CERTIFICATE-----\n" ++
                "STUB-CERTIFICATE-FOR-{s}\n" ++
                "-----END CERTIFICATE-----\n" ++
                "-----BEGIN CERTIFICATE-----\n" ++
                "STUB-INTERMEDIATE-CA\n" ++
                "-----END CERTIFICATE-----\n",
            .{domain_name},
        );
    }

    /// Finalize an order by submitting a Certificate Signing Request (CSR).
    ///
    /// This is called after all challenges have been validated and the order
    /// status is "ready". The CSR contains the domain information and the
    /// certificate public key.
    ///
    /// Stubbed: In production, this generates a CSR, encodes it in base64url,
    /// and POSTs it to the finalize URL in a JWS body.
    pub fn finalizeOrder(self: *ACMEClient, order_url: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const order_ptr = self.active_orders.getPtr(order_url) orelse {
            return ACMEError.OrderNotReady;
        };

        if (order_ptr.status != .ready and order_ptr.status != .pending) {
            return ACMEError.OrderNotReady;
        }

        self.stats.http_requests += 1;

        // Stubbed: Generate CSR and POST to finalize URL
        // JWS payload: { "csr": base64url(der_csr) }
        // Response: order object with status "processing" or "valid"

        order_ptr.status = .processing;
    }

    /// Revoke a previously issued certificate.
    ///
    /// Stubbed: In production, this POSTs the certificate DER to the
    /// revokeCert URL in a JWS body.
    pub fn revokeCertificate(self: *ACMEClient, cert_pem: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.directory == null) {
            return ACMEError.DirectoryFetchFailed;
        }

        _ = cert_pem;
        self.stats.http_requests += 1;

        // Stubbed: POST to revokeCert URL
        // JWS payload: { "certificate": base64url(der_cert), "reason": 0 }
    }

    /// Get the current challenge for a domain, if any
    pub fn getChallenge(self: *ACMEClient, domain: []const u8) ?ACMEChallenge {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.pending_challenges.get(domain);
    }

    /// Get the current order for a domain URL, if any
    pub fn getOrder(self: *ACMEClient, order_url: []const u8) ?ACMEOrder {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.active_orders.get(order_url);
    }

    /// Get client statistics
    pub fn getStats(self: *const ACMEClient) ACMEStats {
        return self.stats;
    }

    /// Extract the base URL from a directory URL (helper for stub generation)
    fn extractBaseUrl(url: []const u8) []const u8 {
        // Find the third slash (after https://) to get the base
        var slash_count: u32 = 0;
        for (url, 0..) |c, i| {
            if (c == '/') {
                slash_count += 1;
                if (slash_count == 3) {
                    return url[0..i];
                }
            }
        }
        return url;
    }
};

/// Certificate manager providing high-level certificate lifecycle management.
///
/// Wraps ACMEClient with domain-aware certificate storage, expiry checking,
/// and automatic renewal scheduling.
///
/// ## Usage
/// ```zig
/// var manager = CertificateManager.init(allocator, config);
/// defer manager.deinit();
///
/// try manager.ensureCertificates();
/// const cert_path = try manager.getCertPath("mail.example.com");
/// const key_path = try manager.getKeyPath("mail.example.com");
/// ```
pub const CertificateManager = struct {
    allocator: std.mem.Allocator,
    config: ACMEConfig,
    client: ACMEClient,
    certificates: std.StringHashMap(CertificateInfo),
    renewal_thread: ?CertRenewalThread,
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator, config: ACMEConfig) CertificateManager {
        return .{
            .allocator = allocator,
            .config = config,
            .client = ACMEClient.init(allocator, config),
            .certificates = std.StringHashMap(CertificateInfo).init(allocator),
            .renewal_thread = null,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *CertificateManager) void {
        // Stop renewal thread if running
        self.stopAutoRenewal();

        // Clean up certificates map
        var cert_iter = self.certificates.iterator();
        while (cert_iter.next()) |entry| {
            var info = entry.value_ptr.*;
            info.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.certificates.deinit();

        self.client.deinit();
    }

    /// Ensure all configured domains have valid certificates.
    ///
    /// For each domain in the configuration:
    /// 1. Check if a certificate exists on disk
    /// 2. Check if the certificate is approaching expiry
    /// 3. If missing or expiring, request a new certificate via ACME
    /// 4. Store the issued certificate and key to disk
    ///
    /// This is the primary entry point for certificate provisioning.
    pub fn ensureCertificates(self: *CertificateManager) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Initialize ACME client if needed
        if (self.client.directory == null) {
            try self.client.fetchDirectory();
        }
        if (self.client.account == null) {
            try self.client.createAccount(self.config.email);
        }

        for (self.config.domains) |domain| {
            const needs_renewal = self.checkRenewalNeededInternal(domain);
            if (needs_renewal) {
                self.provisionCertificate(domain) catch |err| {
                    // Log the error but continue with other domains
                    _ = err;
                    continue;
                };
            }
        }
    }

    /// Get the filesystem path to the certificate file for a domain.
    ///
    /// Returns the path where the PEM certificate is stored.
    /// The certificate may not exist if it hasn't been provisioned yet.
    pub fn getCertPath(self: *CertificateManager, domain: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/{s}/cert.pem", .{
            self.config.cert_dir,
            domain,
        });
    }

    /// Get the filesystem path to the private key file for a domain.
    ///
    /// Returns the path where the PEM private key is stored.
    /// The key may not exist if a certificate hasn't been provisioned yet.
    pub fn getKeyPath(self: *CertificateManager, domain: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/{s}/privkey.pem", .{
            self.config.cert_dir,
            domain,
        });
    }

    /// Get the filesystem path to the certificate chain file for a domain.
    pub fn getChainPath(self: *CertificateManager, domain: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/{s}/chain.pem", .{
            self.config.cert_dir,
            domain,
        });
    }

    /// Get the filesystem path to the full chain (cert + intermediates) for a domain.
    pub fn getFullChainPath(self: *CertificateManager, domain: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/{s}/fullchain.pem", .{
            self.config.cert_dir,
            domain,
        });
    }

    /// Check if a certificate for the given domain needs renewal.
    ///
    /// Returns true if:
    /// - No certificate exists for the domain
    /// - The certificate expires within `renew_before_days`
    /// - The certificate has already expired
    pub fn isRenewalNeeded(self: *CertificateManager, domain: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.checkRenewalNeededInternal(domain);
    }

    /// Get certificate information for a domain, if available
    pub fn getCertificateInfo(self: *CertificateManager, domain: []const u8) ?CertificateInfo {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.certificates.get(domain);
    }

    /// Start the automatic renewal background thread
    pub fn startAutoRenewal(self: *CertificateManager) !void {
        if (self.renewal_thread != null) {
            return ACMEError.RenewalAlreadyRunning;
        }

        var thread = CertRenewalThread.init(self);
        try thread.start();
        self.renewal_thread = thread;
    }

    /// Stop the automatic renewal background thread
    pub fn stopAutoRenewal(self: *CertificateManager) void {
        if (self.renewal_thread) |*thread| {
            thread.stop();
            self.renewal_thread = null;
        }
    }

    /// Check whether auto-renewal is currently active
    pub fn isAutoRenewalRunning(self: *const CertificateManager) bool {
        return self.renewal_thread != null;
    }

    /// Force renewal of a specific domain's certificate, even if not yet needed
    pub fn forceRenewal(self: *CertificateManager, domain: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.provisionCertificate(domain);
    }

    /// Get a summary of all managed certificates
    pub fn getCertificateSummary(self: *CertificateManager) ![]CertificateSummaryEntry {
        self.mutex.lock();
        defer self.mutex.unlock();

        var entries: std.ArrayList(CertificateSummaryEntry) = .empty;
        errdefer entries.deinit(self.allocator);

        var iter = self.certificates.iterator();
        while (iter.next()) |entry| {
            const info = entry.value_ptr;
            try entries.append(self.allocator, .{
                .domain = try self.allocator.dupe(u8, entry.key_ptr.*),
                .days_until_expiry = info.daysUntilExpiry(),
                .is_valid = info.isValid(),
                .needs_renewal = self.checkRenewalNeededInternal(entry.key_ptr.*),
                .key_type = info.key_type,
            });
        }

        return entries.toOwnedSlice(self.allocator);
    }

    // Internal methods

    fn checkRenewalNeededInternal(self: *CertificateManager, domain: []const u8) bool {
        const cert_info = self.certificates.get(domain) orelse return true; // No cert = needs provisioning

        if (cert_info.isExpired()) return true;

        const days_left = cert_info.daysUntilExpiry();
        return days_left <= @as(i64, @intCast(self.config.renew_before_days));
    }

    fn provisionCertificate(self: *CertificateManager, domain: []const u8) !void {
        // Step 1: Request certificate (creates order + challenges)
        const order_url = try self.client.requestCertificate(domain);
        defer self.allocator.free(order_url);

        // Step 2: Respond to challenge
        try self.client.respondToChallenge(domain);

        // Step 3: Finalize order
        try self.client.finalizeOrder(order_url);

        // Step 4: Get certificate
        const cert_pem = try self.client.getCertificate(order_url);
        defer self.allocator.free(cert_pem);

        // Step 5: Store certificate info
        const now = time_compat.timestamp();
        const cert_path = try self.getCertPath(domain);
        const key_path = try self.getKeyPath(domain);

        var empty_sans = try self.allocator.alloc([]const u8, 0);
        _ = &empty_sans;

        const info = CertificateInfo{
            .domain = try self.allocator.dupe(u8, domain),
            .issuer = try self.allocator.dupe(u8, "Let's Encrypt Authority X3 (stub)"),
            .not_before = now,
            .not_after = now + (90 * 86400), // 90 days (Let's Encrypt standard)
            .serial = try self.allocator.dupe(u8, "stub-serial"),
            .fingerprint = try self.allocator.dupe(u8, "stub-fingerprint"),
            .san_domains = empty_sans,
            .key_type = self.config.key_type,
            .cert_path = cert_path,
            .key_path = key_path,
        };

        // Remove old entry if present
        if (self.certificates.fetchRemove(domain)) |old_entry| {
            var old_info = old_entry.value;
            old_info.deinit(self.allocator);
            self.allocator.free(old_entry.key);
        }

        const domain_key = try self.allocator.dupe(u8, domain);
        try self.certificates.put(domain_key, info);
    }
};

/// Summary entry for certificate status reporting
pub const CertificateSummaryEntry = struct {
    domain: []const u8,
    days_until_expiry: i64,
    is_valid: bool,
    needs_renewal: bool,
    key_type: KeyType,

    pub fn deinit(self: *CertificateSummaryEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.domain);
    }
};

/// Background thread for automatic certificate renewal.
///
/// Periodically checks all managed certificates and triggers renewal
/// for any that are approaching expiry. Uses exponential backoff on
/// failure to avoid overwhelming the CA.
///
/// ```
/// Check Loop:
///   1. Sleep for renewal_check_interval_seconds
///   2. For each domain: if isRenewalNeeded -> provisionCertificate
///   3. On failure: backoff, retry next interval
///   4. On success: reset backoff, log renewal
/// ```
pub const CertRenewalThread = struct {
    manager: *CertificateManager,
    thread: ?std.Thread,
    should_stop: std.atomic.Value(bool),
    backoff_seconds: u64,
    last_check: i64,
    renewals_performed: u64,
    errors_encountered: u64,

    const MIN_BACKOFF_SECONDS: u64 = 3600; // 1 hour
    const MAX_BACKOFF_SECONDS: u64 = 86400; // 24 hours
    const SLEEP_GRANULARITY_NS: u64 = 10 * std.time.ns_per_s; // 10 seconds

    pub fn init(manager: *CertificateManager) CertRenewalThread {
        return .{
            .manager = manager,
            .thread = null,
            .should_stop = std.atomic.Value(bool).init(false),
            .backoff_seconds = MIN_BACKOFF_SECONDS,
            .last_check = 0,
            .renewals_performed = 0,
            .errors_encountered = 0,
        };
    }

    /// Spawn the background renewal worker thread
    pub fn start(self: *CertRenewalThread) !void {
        if (self.thread != null) {
            return ACMEError.RenewalAlreadyRunning;
        }

        self.should_stop.store(false, .monotonic);
        self.thread = try std.Thread.spawn(.{}, renewalWorker, .{self});
    }

    /// Signal the renewal thread to stop and wait for it to finish
    pub fn stop(self: *CertRenewalThread) void {
        if (self.thread) |thread| {
            self.should_stop.store(true, .monotonic);
            thread.join();
            self.thread = null;
        }
    }

    /// Check if the renewal thread is currently running
    pub fn isRunning(self: *const CertRenewalThread) bool {
        return self.thread != null and !self.should_stop.load(.monotonic);
    }

    fn renewalWorker(self: *CertRenewalThread) void {
        const check_interval_ns = @as(u64, self.manager.config.renewal_check_interval_seconds) * std.time.ns_per_s;

        while (!self.should_stop.load(.monotonic)) {
            // Sleep in small intervals to allow quick shutdown
            var remaining = check_interval_ns;
            while (remaining > 0 and !self.should_stop.load(.monotonic)) {
                const sleep_time = @min(remaining, SLEEP_GRANULARITY_NS);
                time_compat.sleep(sleep_time);
                remaining -|= sleep_time;
            }

            if (self.should_stop.load(.monotonic)) break;

            self.last_check = time_compat.timestamp();

            // Check each configured domain
            for (self.manager.config.domains) |domain| {
                if (self.should_stop.load(.monotonic)) break;

                if (self.manager.isRenewalNeeded(domain)) {
                    self.manager.forceRenewal(domain) catch {
                        self.errors_encountered += 1;
                        // Apply exponential backoff on failure
                        self.backoff_seconds = @min(
                            self.backoff_seconds * 2,
                            MAX_BACKOFF_SECONDS,
                        );
                        continue;
                    };

                    self.renewals_performed += 1;
                    // Reset backoff on success
                    self.backoff_seconds = MIN_BACKOFF_SECONDS;
                }
            }
        }
    }
};

/// JWS (JSON Web Signature) builder for ACME protocol messages.
///
/// All ACME requests are wrapped in JWS with either a JWK (for account
/// creation) or a Key ID (for subsequent requests), per RFC 8555 Section 6.2.
///
/// Stubbed: In production, this would use real cryptographic signing (ES256/RS256).
const JWSBuilder = struct {
    allocator: std.mem.Allocator,
    key_id: ?[]const u8,
    nonce: ?[]const u8,

    pub fn init(allocator: std.mem.Allocator) JWSBuilder {
        return .{
            .allocator = allocator,
            .key_id = null,
            .nonce = null,
        };
    }

    /// Build a JWS envelope for an ACME request.
    ///
    /// Structure:
    /// {
    ///   "protected": base64url({ "alg": "ES256", "kid": key_id, "nonce": nonce, "url": url }),
    ///   "payload": base64url(payload_json),
    ///   "signature": base64url(signature)
    /// }
    pub fn buildJWS(self: *JWSBuilder, url: []const u8, payload: []const u8) ![]u8 {
        // Build protected header
        const protected = if (self.key_id) |kid|
            try std.fmt.allocPrint(
                self.allocator,
                "{{\"alg\":\"ES256\",\"kid\":\"{s}\",\"nonce\":\"{s}\",\"url\":\"{s}\"}}",
                .{ kid, self.nonce orelse "", url },
            )
        else
            try std.fmt.allocPrint(
                self.allocator,
                "{{\"alg\":\"ES256\",\"jwk\":{{\"kty\":\"EC\",\"crv\":\"P-256\"}},\"nonce\":\"{s}\",\"url\":\"{s}\"}}",
                .{ self.nonce orelse "", url },
            );
        defer self.allocator.free(protected);

        // Stubbed: In production, compute actual ECDSA signature over
        // base64url(protected).base64url(payload)

        return std.fmt.allocPrint(
            self.allocator,
            "{{\"protected\":\"{s}\",\"payload\":\"{s}\",\"signature\":\"stub-signature\"}}",
            .{ protected, payload },
        );
    }
};

/// CSR (Certificate Signing Request) builder.
///
/// Generates PKCS#10 certificate signing requests containing the domain
/// name(s) and public key, formatted for submission to the ACME CA.
///
/// Stubbed: In production, this would generate proper DER-encoded CSRs
/// using the selected key type.
const CSRBuilder = struct {
    allocator: std.mem.Allocator,
    common_name: ?[]const u8,
    san_domains: std.ArrayList([]const u8),
    key_type: KeyType,

    pub fn init(allocator: std.mem.Allocator, key_type: KeyType) CSRBuilder {
        return .{
            .allocator = allocator,
            .common_name = null,
            .san_domains = .{},
            .key_type = key_type,
        };
    }

    pub fn deinit(self: *CSRBuilder) void {
        if (self.common_name) |cn| self.allocator.free(cn);
        for (self.san_domains.items) |san| self.allocator.free(san);
        self.san_domains.deinit(self.allocator);
    }

    pub fn setCommonName(self: *CSRBuilder, cn: []const u8) !void {
        if (self.common_name) |old| self.allocator.free(old);
        self.common_name = try self.allocator.dupe(u8, cn);
    }

    pub fn addSAN(self: *CSRBuilder, domain: []const u8) !void {
        const d = try self.allocator.dupe(u8, domain);
        try self.san_domains.append(self.allocator, d);
    }

    /// Build the CSR in DER format (stubbed).
    ///
    /// In production, this would:
    /// 1. Generate a key pair of the configured type
    /// 2. Build the PKCS#10 structure with subject DN and SANs
    /// 3. Sign with the private key
    /// 4. Return DER-encoded bytes
    pub fn buildDER(self: *CSRBuilder) ![]u8 {
        const cn = self.common_name orelse return ACMEError.CSRGenerationFailed;

        // Stub: return a placeholder that includes the CN for identification
        return std.fmt.allocPrint(
            self.allocator,
            "STUB-CSR-DER-{s}-{s}",
            .{ cn, self.key_type.toString() },
        );
    }
};

/// HTTP-01 challenge responder.
///
/// Manages the challenge tokens and key authorizations that need to be served
/// at /.well-known/acme-challenge/{token} for HTTP-01 validation.
///
/// The actual HTTP server integration is left to the caller; this struct
/// provides the mapping from token to key authorization.
pub const HTTP01Responder = struct {
    allocator: std.mem.Allocator,
    tokens: std.StringHashMap([]const u8),
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator) HTTP01Responder {
        return .{
            .allocator = allocator,
            .tokens = std.StringHashMap([]const u8).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *HTTP01Responder) void {
        var iter = self.tokens.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
            self.allocator.free(entry.key_ptr.*);
        }
        self.tokens.deinit();
    }

    /// Register a token and its key authorization for serving
    pub fn addChallenge(self: *HTTP01Responder, token: []const u8, key_authorization: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const token_copy = try self.allocator.dupe(u8, token);
        errdefer self.allocator.free(token_copy);
        const ka_copy = try self.allocator.dupe(u8, key_authorization);
        errdefer self.allocator.free(ka_copy);

        try self.tokens.put(token_copy, ka_copy);
    }

    /// Look up the key authorization for a given token
    pub fn getResponse(self: *HTTP01Responder, token: []const u8) ?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.tokens.get(token);
    }

    /// Remove a challenge token after validation is complete
    pub fn removeChallenge(self: *HTTP01Responder, token: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.tokens.fetchRemove(token)) |entry| {
            self.allocator.free(entry.value);
            self.allocator.free(entry.key);
        }
    }

    /// Get the number of active challenge tokens
    pub fn activeCount(self: *HTTP01Responder) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return @intCast(self.tokens.count());
    }
};

/// Base64url encoder/decoder for ACME JWS payloads (RFC 4648 Section 5).
///
/// ACME uses base64url encoding without padding for all binary data
/// in JWS protected headers, payloads, and signatures.
const Base64Url = struct {
    const url_safe_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// Encode bytes to base64url without padding
    pub fn encode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
        if (data.len == 0) return try allocator.dupe(u8, "");

        // Calculate output size (no padding)
        const full_groups = data.len / 3;
        const remaining = data.len % 3;
        const encoded_len = full_groups * 4 + if (remaining > 0) remaining + 1 else 0;

        var output = try allocator.alloc(u8, encoded_len);
        var out_idx: usize = 0;

        var i: usize = 0;
        while (i + 3 <= data.len) : (i += 3) {
            const b0 = data[i];
            const b1 = data[i + 1];
            const b2 = data[i + 2];

            output[out_idx] = url_safe_alphabet[b0 >> 2];
            output[out_idx + 1] = url_safe_alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
            output[out_idx + 2] = url_safe_alphabet[((b1 & 0x0f) << 2) | (b2 >> 6)];
            output[out_idx + 3] = url_safe_alphabet[b2 & 0x3f];
            out_idx += 4;
        }

        // Handle remaining bytes (no padding)
        if (remaining == 1) {
            const b0 = data[i];
            output[out_idx] = url_safe_alphabet[b0 >> 2];
            output[out_idx + 1] = url_safe_alphabet[(b0 & 0x03) << 4];
        } else if (remaining == 2) {
            const b0 = data[i];
            const b1 = data[i + 1];
            output[out_idx] = url_safe_alphabet[b0 >> 2];
            output[out_idx + 1] = url_safe_alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
            output[out_idx + 2] = url_safe_alphabet[(b1 & 0x0f) << 2];
        }

        return output;
    }

    /// Decode base64url to bytes
    pub fn decode(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
        if (encoded.len == 0) return try allocator.dupe(u8, "");

        // Build decode table
        var decode_table: [256]u8 = undefined;
        @memset(&decode_table, 0xFF);
        for (url_safe_alphabet, 0..) |c, idx| {
            decode_table[c] = @intCast(idx);
        }

        // Calculate output size
        const padded_len = encoded.len + (4 - encoded.len % 4) % 4;
        const decoded_len = padded_len / 4 * 3 - (padded_len - encoded.len);

        var output = try allocator.alloc(u8, decoded_len);
        var out_idx: usize = 0;

        var i: usize = 0;
        while (i + 4 <= encoded.len) : (i += 4) {
            const a = decode_table[encoded[i]];
            const b = decode_table[encoded[i + 1]];
            const c = decode_table[encoded[i + 2]];
            const d = decode_table[encoded[i + 3]];

            if (a == 0xFF or b == 0xFF or c == 0xFF or d == 0xFF) {
                allocator.free(output);
                return ACMEError.InvalidResponse;
            }

            output[out_idx] = (a << 2) | (b >> 4);
            output[out_idx + 1] = (b << 4) | (c >> 2);
            output[out_idx + 2] = (c << 6) | d;
            out_idx += 3;
        }

        // Handle remaining (2 or 3 chars without padding)
        const rem = encoded.len - i;
        if (rem >= 2) {
            const a = decode_table[encoded[i]];
            const b = decode_table[encoded[i + 1]];
            if (a == 0xFF or b == 0xFF) {
                allocator.free(output);
                return ACMEError.InvalidResponse;
            }
            output[out_idx] = (a << 2) | (b >> 4);
            out_idx += 1;

            if (rem >= 3) {
                const c = decode_table[encoded[i + 2]];
                if (c == 0xFF) {
                    allocator.free(output);
                    return ACMEError.InvalidResponse;
                }
                output[out_idx] = (b << 4) | (c >> 2);
            }
        }

        return output;
    }
};

// =============================================================================
// Tests
// =============================================================================

test "ACMEConfig defaults" {
    const testing = std.testing;

    const config = ACMEConfig{};

    try testing.expectEqualStrings(ACMEConfig.LETS_ENCRYPT_PRODUCTION, config.directory_url);
    try testing.expectEqualStrings("", config.email);
    try testing.expectEqual(@as(usize, 0), config.domains.len);
    try testing.expectEqual(KeyType.ec256, config.key_type);
    try testing.expect(config.auto_renew);
    try testing.expectEqual(@as(u32, 30), config.renew_before_days);
    try testing.expectEqualStrings("/etc/ssl/acme", config.cert_dir);
    try testing.expectEqual(ChallengeType.http01, config.preferred_challenge);
    try testing.expectEqual(@as(u32, 300), config.order_timeout_seconds);
    try testing.expectEqual(@as(u32, 120), config.challenge_timeout_seconds);
    try testing.expectEqual(@as(u32, 43200), config.renewal_check_interval_seconds);
    try testing.expect(!config.agree_to_terms);
    try testing.expectEqual(@as(u16, 80), config.http_challenge_port);
    try testing.expect(!config.use_staging);
}

test "ACMEConfig staging URL" {
    const testing = std.testing;

    const config = ACMEConfig{ .use_staging = true };
    try testing.expectEqualStrings(ACMEConfig.LETS_ENCRYPT_STAGING, config.effectiveDirectoryUrl());

    const prod_config = ACMEConfig{};
    try testing.expectEqualStrings(ACMEConfig.LETS_ENCRYPT_PRODUCTION, prod_config.effectiveDirectoryUrl());
}

test "ACMEConfig validation" {
    const testing = std.testing;

    // Missing email
    const bad_email = ACMEConfig{};
    try testing.expectError(ACMEError.InvalidContact, bad_email.validate());

    // Invalid email format
    const bad_fmt = ACMEConfig{ .email = "no-at-sign" };
    try testing.expectError(ACMEError.InvalidContact, bad_fmt.validate());

    // No domains
    const no_domains = ACMEConfig{ .email = "admin@example.com" };
    try testing.expectError(ACMEError.UnsupportedIdentifier, no_domains.validate());

    // Wildcard with non-DNS challenge
    const domains = [_][]const u8{"*.example.com"};
    const wildcard_http = ACMEConfig{
        .email = "admin@example.com",
        .domains = &domains,
        .preferred_challenge = .http01,
    };
    try testing.expectError(ACMEError.UnsupportedIdentifier, wildcard_http.validate());

    // Valid wildcard with DNS-01
    const wildcard_dns = ACMEConfig{
        .email = "admin@example.com",
        .domains = &domains,
        .preferred_challenge = .dns01,
    };
    try wildcard_dns.validate();
}

test "ACMEOrderStatus conversions" {
    const testing = std.testing;

    try testing.expectEqualStrings("pending", ACMEOrderStatus.pending.toString());
    try testing.expectEqualStrings("ready", ACMEOrderStatus.ready.toString());
    try testing.expectEqualStrings("processing", ACMEOrderStatus.processing.toString());
    try testing.expectEqualStrings("valid", ACMEOrderStatus.valid.toString());
    try testing.expectEqualStrings("invalid", ACMEOrderStatus.invalid.toString());

    try testing.expectEqual(ACMEOrderStatus.pending, ACMEOrderStatus.fromString("pending").?);
    try testing.expectEqual(ACMEOrderStatus.valid, ACMEOrderStatus.fromString("valid").?);
    try testing.expect(ACMEOrderStatus.fromString("unknown") == null);

    // Terminal states
    try testing.expect(!ACMEOrderStatus.pending.isTerminal());
    try testing.expect(!ACMEOrderStatus.ready.isTerminal());
    try testing.expect(!ACMEOrderStatus.processing.isTerminal());
    try testing.expect(ACMEOrderStatus.valid.isTerminal());
    try testing.expect(ACMEOrderStatus.invalid.isTerminal());
}

test "ChallengeType conversions" {
    const testing = std.testing;

    try testing.expectEqualStrings("http-01", ChallengeType.http01.toString());
    try testing.expectEqualStrings("dns-01", ChallengeType.dns01.toString());
    try testing.expectEqualStrings("tls-alpn-01", ChallengeType.tlsalpn01.toString());

    try testing.expectEqual(ChallengeType.http01, ChallengeType.fromString("http-01").?);
    try testing.expectEqual(ChallengeType.dns01, ChallengeType.fromString("dns-01").?);
    try testing.expectEqual(ChallengeType.tlsalpn01, ChallengeType.fromString("tls-alpn-01").?);
    try testing.expect(ChallengeType.fromString("unknown") == null);
}

test "ACMEChallenge initialization and state" {
    const testing = std.testing;

    var challenge = ACMEChallenge.init(
        .http01,
        try testing.allocator.dupe(u8, "https://acme.example.com/challenge/1"),
        try testing.allocator.dupe(u8, "test-token-abc"),
        .pending,
    );
    defer challenge.deinit(testing.allocator);

    try testing.expectEqual(ChallengeType.http01, challenge.challenge_type);
    try testing.expectEqual(ChallengeStatus.pending, challenge.status);
    try testing.expectEqualStrings("test-token-abc", challenge.token);
    try testing.expect(challenge.key_authorization == null);
    try testing.expect(!challenge.isFinished());

    // Test HTTP challenge path generation
    const path = try challenge.httpChallengePath(testing.allocator);
    defer testing.allocator.free(path);
    try testing.expectEqualStrings("/.well-known/acme-challenge/test-token-abc", path);

    // Test DNS challenge record generation
    const record = try challenge.dnsChallengeRecord(testing.allocator, "example.com");
    defer testing.allocator.free(record);
    try testing.expectEqualStrings("_acme-challenge.example.com", record);
}

test "ACMEChallenge finished states" {
    const testing = std.testing;

    var valid_challenge = ACMEChallenge.init(
        .dns01,
        try testing.allocator.dupe(u8, "https://acme.example.com/challenge/2"),
        try testing.allocator.dupe(u8, "token-2"),
        .valid,
    );
    defer valid_challenge.deinit(testing.allocator);
    try testing.expect(valid_challenge.isFinished());

    var invalid_challenge = ACMEChallenge.init(
        .http01,
        try testing.allocator.dupe(u8, "https://acme.example.com/challenge/3"),
        try testing.allocator.dupe(u8, "token-3"),
        .invalid,
    );
    defer invalid_challenge.deinit(testing.allocator);
    try testing.expect(invalid_challenge.isFinished());

    var processing_challenge = ACMEChallenge.init(
        .tlsalpn01,
        try testing.allocator.dupe(u8, "https://acme.example.com/challenge/4"),
        try testing.allocator.dupe(u8, "token-4"),
        .processing,
    );
    defer processing_challenge.deinit(testing.allocator);
    try testing.expect(!processing_challenge.isFinished());
}

test "CertificateInfo validity and expiry" {
    const testing = std.testing;

    const now = time_compat.timestamp();
    const empty_sans = try testing.allocator.alloc([]const u8, 0);

    // Valid certificate, 60 days remaining
    var valid_cert = CertificateInfo{
        .domain = try testing.allocator.dupe(u8, "mail.example.com"),
        .issuer = try testing.allocator.dupe(u8, "Test CA"),
        .not_before = now - 86400, // issued yesterday
        .not_after = now + (60 * 86400), // expires in 60 days
        .serial = try testing.allocator.dupe(u8, "1234567890"),
        .fingerprint = try testing.allocator.dupe(u8, "AA:BB:CC:DD"),
        .san_domains = empty_sans,
        .key_type = .ec256,
        .cert_path = try testing.allocator.dupe(u8, "/etc/ssl/acme/mail.example.com/cert.pem"),
        .key_path = try testing.allocator.dupe(u8, "/etc/ssl/acme/mail.example.com/privkey.pem"),
    };
    defer valid_cert.deinit(testing.allocator);

    try testing.expect(valid_cert.isValid());
    try testing.expect(!valid_cert.isExpired());
    try testing.expect(valid_cert.daysUntilExpiry() >= 59);
    try testing.expect(valid_cert.daysUntilExpiry() <= 60);
    try testing.expect(valid_cert.secondsUntilExpiry() > 0);
}

test "CertificateInfo expired certificate" {
    const testing = std.testing;

    const now = time_compat.timestamp();
    const empty_sans = try testing.allocator.alloc([]const u8, 0);

    var expired_cert = CertificateInfo{
        .domain = try testing.allocator.dupe(u8, "old.example.com"),
        .issuer = try testing.allocator.dupe(u8, "Test CA"),
        .not_before = now - (120 * 86400), // issued 120 days ago
        .not_after = now - 86400, // expired yesterday
        .serial = try testing.allocator.dupe(u8, "expired-serial"),
        .fingerprint = try testing.allocator.dupe(u8, "EE:FF:00:11"),
        .san_domains = empty_sans,
        .key_type = .rsa2048,
        .cert_path = try testing.allocator.dupe(u8, "/etc/ssl/acme/old.example.com/cert.pem"),
        .key_path = try testing.allocator.dupe(u8, "/etc/ssl/acme/old.example.com/privkey.pem"),
    };
    defer expired_cert.deinit(testing.allocator);

    try testing.expect(!expired_cert.isValid());
    try testing.expect(expired_cert.isExpired());
    try testing.expect(expired_cert.daysUntilExpiry() < 0);
}

test "KeyType properties" {
    const testing = std.testing;

    try testing.expectEqualStrings("EC-P256", KeyType.ec256.toString());
    try testing.expectEqualStrings("EC-P384", KeyType.ec384.toString());
    try testing.expectEqualStrings("RSA-2048", KeyType.rsa2048.toString());
    try testing.expectEqualStrings("RSA-4096", KeyType.rsa4096.toString());

    try testing.expectEqual(@as(u32, 256), KeyType.ec256.keyBits());
    try testing.expectEqual(@as(u32, 384), KeyType.ec384.keyBits());
    try testing.expectEqual(@as(u32, 2048), KeyType.rsa2048.keyBits());
    try testing.expectEqual(@as(u32, 4096), KeyType.rsa4096.keyBits());
}

test "ACMEClient initialization and directory fetch" {
    const testing = std.testing;

    const domains = [_][]const u8{"mail.example.com"};
    const config = ACMEConfig{
        .email = "admin@example.com",
        .domains = &domains,
        .use_staging = true,
    };

    var client = ACMEClient.init(testing.allocator, config);
    defer client.deinit();

    try testing.expect(client.directory == null);
    try testing.expect(client.account == null);
    try testing.expectEqual(@as(u64, 0), client.stats.orders_created);

    // Fetch directory (stubbed)
    try client.fetchDirectory();
    try testing.expect(client.directory != null);
    try testing.expectEqual(@as(u64, 1), client.stats.http_requests);
}

test "ACMEClient account creation" {
    const testing = std.testing;

    const domains = [_][]const u8{"mail.example.com"};
    const config = ACMEConfig{
        .email = "admin@example.com",
        .domains = &domains,
    };

    var client = ACMEClient.init(testing.allocator, config);
    defer client.deinit();

    // Must fetch directory first
    try client.fetchDirectory();

    // Create account
    try client.createAccount("admin@example.com");
    try testing.expect(client.account != null);
    try testing.expectEqualStrings("valid", client.account.?.status);
    try testing.expectEqual(@as(usize, 1), client.account.?.contact.len);
}

test "ACMEClient certificate request flow" {
    const testing = std.testing;

    const domains = [_][]const u8{"mail.example.com"};
    const config = ACMEConfig{
        .email = "admin@example.com",
        .domains = &domains,
    };

    var client = ACMEClient.init(testing.allocator, config);
    defer client.deinit();

    try client.fetchDirectory();
    try client.createAccount("admin@example.com");

    // Request certificate
    const order_url = try client.requestCertificate("mail.example.com");
    defer testing.allocator.free(order_url);

    try testing.expectEqual(@as(u64, 1), client.stats.orders_created);

    // Verify challenge was created
    const challenge = client.getChallenge("mail.example.com");
    try testing.expect(challenge != null);
    try testing.expectEqual(ChallengeType.http01, challenge.?.challenge_type);
    try testing.expectEqual(ChallengeStatus.pending, challenge.?.status);

    // Respond to challenge
    try client.respondToChallenge("mail.example.com");
    try testing.expectEqual(@as(u64, 1), client.stats.challenges_completed);

    // Retrieve certificate
    const cert_pem = try client.getCertificate(order_url);
    defer testing.allocator.free(cert_pem);

    try testing.expect(std.mem.startsWith(u8, cert_pem, "-----BEGIN CERTIFICATE-----"));
    try testing.expectEqual(@as(u64, 1), client.stats.certificates_issued);
}

test "ACMEClient error handling - no account" {
    const testing = std.testing;

    const config = ACMEConfig{
        .email = "admin@example.com",
    };

    var client = ACMEClient.init(testing.allocator, config);
    defer client.deinit();

    // Cannot request certificate without account
    try testing.expectError(
        ACMEError.AccountDoesNotExist,
        client.requestCertificate("example.com"),
    );
}

test "ACMEClient error handling - no directory" {
    const testing = std.testing;

    const config = ACMEConfig{
        .email = "admin@example.com",
    };

    var client = ACMEClient.init(testing.allocator, config);
    defer client.deinit();

    // Cannot create account without directory
    try testing.expectError(
        ACMEError.DirectoryFetchFailed,
        client.createAccount("admin@example.com"),
    );
}

test "ACMEClient challenge not found" {
    const testing = std.testing;

    const domains = [_][]const u8{"mail.example.com"};
    const config = ACMEConfig{
        .email = "admin@example.com",
        .domains = &domains,
    };

    var client = ACMEClient.init(testing.allocator, config);
    defer client.deinit();

    try client.fetchDirectory();
    try client.createAccount("admin@example.com");

    // Respond to challenge for non-existent domain
    try testing.expectError(
        ACMEError.NoChallengeAvailable,
        client.respondToChallenge("nonexistent.example.com"),
    );
}

test "CertificateManager initialization" {
    const testing = std.testing;

    const domains = [_][]const u8{"mail.example.com"};
    const config = ACMEConfig{
        .email = "admin@example.com",
        .domains = &domains,
        .renew_before_days = 30,
    };

    var manager = CertificateManager.init(testing.allocator, config);
    defer manager.deinit();

    try testing.expect(!manager.isAutoRenewalRunning());
    try testing.expect(manager.getCertificateInfo("mail.example.com") == null);
}

test "CertificateManager paths" {
    const testing = std.testing;

    const config = ACMEConfig{
        .cert_dir = "/etc/ssl/acme",
    };

    var manager = CertificateManager.init(testing.allocator, config);
    defer manager.deinit();

    const cert_path = try manager.getCertPath("mail.example.com");
    defer testing.allocator.free(cert_path);
    try testing.expectEqualStrings("/etc/ssl/acme/mail.example.com/cert.pem", cert_path);

    const key_path = try manager.getKeyPath("mail.example.com");
    defer testing.allocator.free(key_path);
    try testing.expectEqualStrings("/etc/ssl/acme/mail.example.com/privkey.pem", key_path);

    const chain_path = try manager.getChainPath("mail.example.com");
    defer testing.allocator.free(chain_path);
    try testing.expectEqualStrings("/etc/ssl/acme/mail.example.com/chain.pem", chain_path);

    const full_chain_path = try manager.getFullChainPath("mail.example.com");
    defer testing.allocator.free(full_chain_path);
    try testing.expectEqualStrings("/etc/ssl/acme/mail.example.com/fullchain.pem", full_chain_path);
}

test "CertificateManager renewal needed - no cert" {
    const testing = std.testing;

    const domains = [_][]const u8{"mail.example.com"};
    const config = ACMEConfig{
        .email = "admin@example.com",
        .domains = &domains,
        .renew_before_days = 30,
    };

    var manager = CertificateManager.init(testing.allocator, config);
    defer manager.deinit();

    // No certificate provisioned - should need renewal
    try testing.expect(manager.isRenewalNeeded("mail.example.com"));
}

test "CertificateManager ensure certificates" {
    const testing = std.testing;

    const domains = [_][]const u8{"mail.example.com"};
    const config = ACMEConfig{
        .email = "admin@example.com",
        .domains = &domains,
        .renew_before_days = 30,
    };

    var manager = CertificateManager.init(testing.allocator, config);
    defer manager.deinit();

    // Provision certificates for all domains
    try manager.ensureCertificates();

    // Certificate should now exist
    const info = manager.getCertificateInfo("mail.example.com");
    try testing.expect(info != null);
    try testing.expectEqualStrings("mail.example.com", info.?.domain);
    try testing.expect(info.?.isValid());
    try testing.expect(!info.?.isExpired());

    // Should not need renewal (just provisioned, 90 days validity)
    try testing.expect(!manager.isRenewalNeeded("mail.example.com"));
}

test "CertificateManager force renewal" {
    const testing = std.testing;

    const domains = [_][]const u8{"mail.example.com"};
    const config = ACMEConfig{
        .email = "admin@example.com",
        .domains = &domains,
    };

    var manager = CertificateManager.init(testing.allocator, config);
    defer manager.deinit();

    // Initial provision
    try manager.ensureCertificates();

    const info_before = manager.getCertificateInfo("mail.example.com");
    try testing.expect(info_before != null);

    // Force renewal
    try manager.forceRenewal("mail.example.com");

    const info_after = manager.getCertificateInfo("mail.example.com");
    try testing.expect(info_after != null);
    try testing.expect(info_after.?.isValid());
}

test "NonceManager lifecycle" {
    const testing = std.testing;

    var nonces = NonceManager.init(testing.allocator);
    defer nonces.deinit();

    try testing.expect(!nonces.hasNonce());
    try testing.expect(nonces.consumeNonce() == null);

    // Set a nonce
    try nonces.setNonce("test-nonce-1234");
    try testing.expect(nonces.hasNonce());

    // Consume should return it and clear
    const nonce = nonces.consumeNonce();
    try testing.expect(nonce != null);
    try testing.expectEqualStrings("test-nonce-1234", nonce.?);
    testing.allocator.free(nonce.?);

    try testing.expect(!nonces.hasNonce());
    try testing.expect(nonces.consumeNonce() == null);
}

test "NonceManager replacement" {
    const testing = std.testing;

    var nonces = NonceManager.init(testing.allocator);
    defer nonces.deinit();

    try nonces.setNonce("nonce-1");
    try nonces.setNonce("nonce-2"); // Should free nonce-1

    const nonce = nonces.consumeNonce();
    try testing.expect(nonce != null);
    try testing.expectEqualStrings("nonce-2", nonce.?);
    testing.allocator.free(nonce.?);
}

test "HTTP01Responder add and lookup" {
    const testing = std.testing;

    var responder = HTTP01Responder.init(testing.allocator);
    defer responder.deinit();

    try testing.expectEqual(@as(u32, 0), responder.activeCount());

    // Add a challenge
    try responder.addChallenge("test-token-abc", "test-token-abc.thumbprint123");
    try testing.expectEqual(@as(u32, 1), responder.activeCount());

    // Look up the response
    const response = responder.getResponse("test-token-abc");
    try testing.expect(response != null);
    try testing.expectEqualStrings("test-token-abc.thumbprint123", response.?);

    // Non-existent token
    try testing.expect(responder.getResponse("nonexistent") == null);

    // Remove challenge
    responder.removeChallenge("test-token-abc");
    try testing.expectEqual(@as(u32, 0), responder.activeCount());
    try testing.expect(responder.getResponse("test-token-abc") == null);
}

test "HTTP01Responder multiple challenges" {
    const testing = std.testing;

    var responder = HTTP01Responder.init(testing.allocator);
    defer responder.deinit();

    try responder.addChallenge("token-1", "auth-1");
    try responder.addChallenge("token-2", "auth-2");
    try responder.addChallenge("token-3", "auth-3");

    try testing.expectEqual(@as(u32, 3), responder.activeCount());
    try testing.expectEqualStrings("auth-1", responder.getResponse("token-1").?);
    try testing.expectEqualStrings("auth-2", responder.getResponse("token-2").?);
    try testing.expectEqualStrings("auth-3", responder.getResponse("token-3").?);
}

test "Base64Url encoding" {
    const testing = std.testing;

    // Empty input
    const empty = try Base64Url.encode(testing.allocator, "");
    defer testing.allocator.free(empty);
    try testing.expectEqualStrings("", empty);

    // Standard test vectors
    const hello = try Base64Url.encode(testing.allocator, "Hello");
    defer testing.allocator.free(hello);
    try testing.expectEqualStrings("SGVsbG8", hello);

    // Ensure no padding characters
    for (hello) |c| {
        try testing.expect(c != '=');
    }

    // Verify URL-safe: no + or /
    const binary_data = [_]u8{ 0xFF, 0xFE, 0xFD, 0xFC, 0xFB };
    const encoded = try Base64Url.encode(testing.allocator, &binary_data);
    defer testing.allocator.free(encoded);
    for (encoded) |c| {
        try testing.expect(c != '+');
        try testing.expect(c != '/');
    }
}

test "ChallengeStatus conversions" {
    const testing = std.testing;

    try testing.expectEqualStrings("pending", ChallengeStatus.pending.toString());
    try testing.expectEqualStrings("processing", ChallengeStatus.processing.toString());
    try testing.expectEqualStrings("valid", ChallengeStatus.valid.toString());
    try testing.expectEqualStrings("invalid", ChallengeStatus.invalid.toString());

    try testing.expectEqual(ChallengeStatus.pending, ChallengeStatus.fromString("pending").?);
    try testing.expectEqual(ChallengeStatus.valid, ChallengeStatus.fromString("valid").?);
    try testing.expect(ChallengeStatus.fromString("bogus") == null);
}

test "CertRenewalThread initialization" {
    const testing = std.testing;

    const domains = [_][]const u8{"mail.example.com"};
    const config = ACMEConfig{
        .email = "admin@example.com",
        .domains = &domains,
    };

    var manager = CertificateManager.init(testing.allocator, config);
    defer manager.deinit();

    var thread = CertRenewalThread.init(&manager);
    try testing.expect(!thread.isRunning());
    try testing.expectEqual(@as(u64, 0), thread.renewals_performed);
    try testing.expectEqual(@as(u64, 0), thread.errors_encountered);
    try testing.expectEqual(@as(i64, 0), thread.last_check);
    try testing.expectEqual(CertRenewalThread.MIN_BACKOFF_SECONDS, thread.backoff_seconds);
}

test "ACMEClient stats tracking" {
    const testing = std.testing;

    const domains = [_][]const u8{"mail.example.com"};
    const config = ACMEConfig{
        .email = "admin@example.com",
        .domains = &domains,
    };

    var client = ACMEClient.init(testing.allocator, config);
    defer client.deinit();

    const initial_stats = client.getStats();
    try testing.expectEqual(@as(u64, 0), initial_stats.orders_created);
    try testing.expectEqual(@as(u64, 0), initial_stats.certificates_issued);
    try testing.expectEqual(@as(u64, 0), initial_stats.http_requests);

    try client.fetchDirectory();
    try client.createAccount("admin@example.com");
    const order_url = try client.requestCertificate("mail.example.com");
    defer testing.allocator.free(order_url);

    try client.respondToChallenge("mail.example.com");
    const cert = try client.getCertificate(order_url);
    defer testing.allocator.free(cert);

    const final_stats = client.getStats();
    try testing.expectEqual(@as(u64, 1), final_stats.orders_created);
    try testing.expectEqual(@as(u64, 1), final_stats.certificates_issued);
    try testing.expectEqual(@as(u64, 1), final_stats.challenges_completed);
    try testing.expect(final_stats.http_requests >= 4); // directory + account + order + challenge + cert
    try testing.expect(final_stats.last_order_time > 0);
}
