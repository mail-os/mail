//! SMTP Server Root Module
//! Provides centralized imports and re-exports for all modules
//!
//! Usage:
//! ```zig
//! const smtp = @import("root.zig");
//!
//! // Access modules
//! var logger = smtp.log.Logger.init(.{});
//! const map = try smtp.presized_maps.MapFactory.createHeaderMap(allocator);
//! ```

const std = @import("std");

// =============================================================================
// Core Modules
// =============================================================================

/// Configuration management with profiles and validation
pub const config = @import("core/config.zig");

/// Configuration profiles (dev/test/staging/prod)
pub const config_profiles = @import("core/config_profiles.zig");

/// Command-line argument parsing
pub const args = @import("core/args.zig");

/// Centralized structured logging (replaces std.debug.print)
pub const log = @import("core/log.zig");

/// Existing logger for compatibility
pub const logger = @import("core/logger.zig");

/// Error handling utilities with categories and metrics
pub const error_handler = @import("core/error_handler.zig");

/// Memory management (RAII patterns, pools, arenas)
pub const memory = @import("core/memory.zig");

/// Pre-sized hash maps for headers, recipients, sessions
pub const presized_maps = @import("core/presized_maps.zig");

/// Zero-copy optimizations for hot paths
pub const zero_copy = @import("core/zero_copy.zig");

/// Buffer and protocol constants
pub const constants = @import("core/constants.zig");

/// Email address validation
pub const email_validator = @import("core/email_validator.zig");

/// TOML configuration parser
pub const toml = @import("core/toml.zig");

/// Hot reload support (SIGHUP)
pub const hot_reload = @import("core/hot_reload.zig");

/// Plugin system
pub const plugin = @import("core/plugin.zig");

/// TLS implementation
pub const tls = @import("core/tls.zig");

/// Time compatibility utilities
pub const time_compat = @import("core/time_compat.zig");

// =============================================================================
// Protocol Modules
// =============================================================================

/// SMTP protocol implementation (RFC 5321)
pub const smtp = @import("protocol/smtp.zig");

/// IMAP protocol implementation (RFC 3501)
pub const imap = @import("protocol/imap.zig");

/// POP3 protocol implementation (RFC 1939)
pub const pop3 = @import("protocol/pop3.zig");

/// WebSocket protocol (RFC 6455)
pub const websocket = @import("protocol/websocket.zig");

/// CalDAV/CardDAV protocol (RFC 4791/6352)
pub const caldav = @import("protocol/caldav.zig");

/// ActiveSync protocol (MS-ASHTTP)
pub const activesync = @import("protocol/activesync.zig");

/// ActiveSync sync engine
pub const activesync_sync = @import("protocol/activesync_sync.zig");

/// Protocol integration and unified server
pub const protocol_integration = @import("protocol/integration.zig");

// =============================================================================
// Authentication Modules
// =============================================================================

/// Authentication system
pub const auth = @import("auth/auth.zig");

/// Security utilities (rate limiting, connection limiting)
pub const security = @import("auth/security.zig");

/// SASL authentication mechanisms
pub const sasl = @import("auth/sasl.zig");

// =============================================================================
// Message Handling Modules
// =============================================================================

/// Email message parsing and manipulation
pub const message = @import("message/message.zig");

/// MIME parsing and generation
pub const mime = @import("message/mime.zig");

/// Email header parsing
pub const headers = @import("message/headers.zig");

// =============================================================================
// Validation Modules
// =============================================================================

/// SPF validation (RFC 7208)
pub const spf = @import("validation/spf.zig");

/// DKIM validation (RFC 6376)
pub const dkim = @import("validation/dkim.zig");

/// DMARC validation (RFC 7489)
pub const dmarc = @import("validation/dmarc.zig");

/// Machine Learning spam detection
pub const ml_spam = @import("validation/ml_spam.zig");

// =============================================================================
// Storage Modules
// =============================================================================

/// Database operations
pub const database = @import("storage/database.zig");

/// Maildir storage format
pub const maildir = @import("storage/maildir.zig");

/// Backup and restore utilities
pub const backup = @import("storage/backup.zig");

/// CalDAV/CardDAV storage
pub const caldav_store = @import("storage/caldav_store.zig");

// =============================================================================
// Queue Modules
// =============================================================================

/// Message queue management
pub const queue = @import("queue/manager.zig");

// =============================================================================
// Infrastructure Modules
// =============================================================================

/// DNS resolution
pub const dns = @import("infrastructure/dns_resolver.zig");

/// Connection pooling
pub const connection_pool = @import("infrastructure/connection_pool.zig");

/// Cluster management
pub const cluster = @import("infrastructure/cluster.zig");

/// Raft consensus for distributed coordination
pub const raft = @import("infrastructure/raft.zig");

/// Multi-region support
pub const multi_region = @import("infrastructure/multi_region.zig");

/// Service dependency graph
pub const dependency_graph = @import("infrastructure/dependency_graph.zig");

/// io_uring integration (Linux)
pub const io_uring = @import("infrastructure/io_uring.zig");

/// Vectored I/O
pub const vectored_io = @import("infrastructure/vectored_io.zig");

// =============================================================================
// Observability Modules
// =============================================================================

/// Distributed tracing (Jaeger, DataDog, Zipkin, OTLP)
pub const tracing = @import("observability/trace_exporters.zig");

/// Alerting (Slack, PagerDuty, OpsGenie, etc.)
pub const alerting = @import("observability/alerting.zig");

/// SLO/SLI tracking
pub const slo = @import("observability/slo.zig");

/// Prometheus metrics
pub const metrics = @import("observability/metrics.zig");

// =============================================================================
// Security Modules
// =============================================================================

/// Secret management (Vault, K8s, AWS, Azure)
pub const secrets = @import("security/secrets.zig");

// =============================================================================
// API Modules
// =============================================================================

/// Health check and metrics endpoints
pub const health = @import("api/health.zig");

// =============================================================================
// Tools
// =============================================================================

/// Test coverage measurement
pub const coverage = @import("tools/coverage.zig");

/// Server migration tools
pub const server_migration = @import("tools/server_migration.zig");

// =============================================================================
// Features Modules
// =============================================================================

/// Multi-tenancy support
pub const multitenancy = @import("features/multitenancy.zig");

/// Tenant integration for connections
pub const tenant_integration = @import("features/tenant_integration.zig");

/// Email archiving and compliance
pub const email_archiving = @import("features/email_archiving.zig");

/// Quota management
pub const quota = @import("features/quota.zig");

/// Audit logging
pub const audit = @import("features/audit.zig");

/// GDPR compliance
pub const gdpr = @import("features/gdpr.zig");

/// Autoresponder
pub const autoresponder = @import("features/autoresponder.zig");

/// Mailing list support
pub const mailinglist = @import("features/mailinglist.zig");

/// Webhook notifications
pub const webhook = @import("features/webhook.zig");

// =============================================================================
// Common Type Aliases
// =============================================================================

/// Standard allocator type
pub const Allocator = std.mem.Allocator;

/// Common error set for SMTP operations
pub const SmtpError = error{
    ConnectionClosed,
    ProtocolError,
    AuthenticationFailed,
    MessageTooLarge,
    TooManyRecipients,
    InvalidAddress,
    RelayDenied,
    RateLimited,
    ServerBusy,
    InternalError,
    TlsError,
    DnsError,
    QueueFull,
    StorageError,
};

// =============================================================================
// Convenience Functions
// =============================================================================

/// Initialize the logging system with default configuration
pub fn initLogging(level: log.Level) void {
    log.initGlobal(.{
        .level = level,
        .format = .text,
        .colors = true,
    });
}

/// Initialize logging for production (JSON format)
pub fn initProductionLogging() void {
    log.initGlobal(.{
        .level = .info,
        .format = .json,
        .colors = false,
        .timestamps = true,
    });
}

/// Create a scoped logger for a component
pub fn scopedLog(comptime component: []const u8) type {
    return log.scoped(component);
}

/// Create a pre-sized header map
pub fn createHeaderMap(allocator: Allocator) !presized_maps.HeaderMap {
    return presized_maps.HeaderMap.init(allocator);
}

/// Create a pre-sized recipient set
pub fn createRecipientSet(allocator: Allocator) !presized_maps.RecipientSet {
    return presized_maps.RecipientSet.init(allocator);
}

/// Create a scoped allocator (arena)
pub fn createScopedAllocator(backing: Allocator) memory.ScopedAllocator {
    return memory.ScopedAllocator.init(backing);
}

/// Create an error handler
pub fn createErrorHandler(allocator: Allocator) !error_handler.ErrorHandler {
    return error_handler.ErrorHandler.init(allocator, .{});
}

/// Parse a buffer without allocation using zero-copy
pub fn parseSmtpCommand(input: []const u8) zero_copy.Parser.SmtpCommand {
    return zero_copy.Parser.parseSmtpCommand(input);
}

/// Parse email address without allocation
pub fn parseEmailAddress(input: []const u8) zero_copy.Parser.EmailAddress {
    return zero_copy.Parser.parseEmailAddress(input);
}

// =============================================================================
// Version Information
// =============================================================================

pub const version = struct {
    pub const major: u32 = 0;
    pub const minor: u32 = 29;
    pub const patch: u32 = 0;
    pub const string = "0.29.0";
    pub const full = "SMTP Server v0.29.0";

    pub fn greaterThan(other_major: u32, other_minor: u32, other_patch: u32) bool {
        if (major != other_major) return major > other_major;
        if (minor != other_minor) return minor > other_minor;
        return patch > other_patch;
    }
};

// =============================================================================
// Build Information
// =============================================================================

pub const build = struct {
    pub const zig_version = @import("builtin").zig_version_string;
    pub const target = @import("builtin").target;
    pub const mode = @import("builtin").mode;

    pub fn isDebug() bool {
        return mode == .Debug;
    }

    pub fn isRelease() bool {
        return mode == .ReleaseFast or mode == .ReleaseSafe or mode == .ReleaseSmall;
    }

    pub fn targetString() []const u8 {
        return @tagName(target.cpu.arch) ++ "-" ++ @tagName(target.os.tag);
    }
};

// =============================================================================
// Tests
// =============================================================================

test "version info" {
    try std.testing.expectEqual(@as(u32, 0), version.major);
    try std.testing.expectEqual(@as(u32, 29), version.minor);
    try std.testing.expectEqualStrings("0.29.0", version.string);
    try std.testing.expect(!version.greaterThan(1, 0, 0));
    try std.testing.expect(version.greaterThan(0, 28, 0));
}

test "build info" {
    _ = build.zig_version;
    _ = build.target;
    _ = build.isDebug();
    _ = build.isRelease();
    _ = build.targetString();
}

test "zero-copy parsing" {
    const cmd = parseSmtpCommand("MAIL FROM:<test@example.com>\r\n");
    try std.testing.expect(cmd.isVerb("MAIL"));

    const addr = parseEmailAddress("<user@example.com>");
    try std.testing.expectEqualStrings("user", addr.local.bytes());
    try std.testing.expectEqualStrings("example.com", addr.domain.bytes());
}
