const std = @import("std");

/// Configuration profiles for different environments (dev/test/prod)
/// Provides sane defaults and environment-specific tuning
pub const Profile = enum {
    development,
    testing,
    staging,
    production,

    pub fn fromString(s: []const u8) ?Profile {
        if (std.ascii.eqlIgnoreCase(s, "development") or std.ascii.eqlIgnoreCase(s, "dev")) {
            return .development;
        } else if (std.ascii.eqlIgnoreCase(s, "testing") or std.ascii.eqlIgnoreCase(s, "test")) {
            return .testing;
        } else if (std.ascii.eqlIgnoreCase(s, "staging") or std.ascii.eqlIgnoreCase(s, "stage")) {
            return .staging;
        } else if (std.ascii.eqlIgnoreCase(s, "production") or std.ascii.eqlIgnoreCase(s, "prod")) {
            return .production;
        }
        return null;
    }

    pub fn toString(self: Profile) []const u8 {
        return switch (self) {
            .development => "development",
            .testing => "testing",
            .staging => "staging",
            .production => "production",
        };
    }
};

/// Configuration values for a specific profile
pub const ProfileConfig = struct {
    // Server settings
    smtp_port: u16,
    api_port: u16,
    max_connections: u32,
    connection_timeout_seconds: u32,
    command_timeout_seconds: u32,

    // Rate limiting
    rate_limit_window_seconds: u32,
    rate_limit_max_requests: u32,
    rate_limit_max_per_user: u32,

    // Message limits
    max_message_size: usize,
    max_recipients: u32,

    // Storage
    queue_batch_size: usize,
    queue_flush_interval_ms: u64,
    database_pool_size: u32,

    // Logging
    log_level: LogLevel,
    enable_json_logging: bool,
    log_file_path: ?[]const u8,

    // Security
    require_tls: bool,
    require_auth: bool,
    tls_min_version: []const u8,

    // Performance
    buffer_pool_size: u32,
    enable_io_uring: bool,
    worker_threads: u32,

    // Features
    enable_spam_filter: bool,
    enable_virus_scan: bool,
    enable_greylist: bool,
    enable_webhooks: bool,
    enable_metrics: bool,
    enable_tracing: bool,

    // Resilience
    circuit_breaker_threshold: u32,
    circuit_breaker_timeout_seconds: u32,
    max_retry_attempts: u32,
    retry_delay_seconds: u32,
};

pub const LogLevel = enum {
    debug,
    info,
    warn,
    err,

    pub fn fromString(s: []const u8) ?LogLevel {
        if (std.ascii.eqlIgnoreCase(s, "debug")) {
            return .debug;
        } else if (std.ascii.eqlIgnoreCase(s, "info")) {
            return .info;
        } else if (std.ascii.eqlIgnoreCase(s, "warn") or std.ascii.eqlIgnoreCase(s, "warning")) {
            return .warn;
        } else if (std.ascii.eqlIgnoreCase(s, "err") or std.ascii.eqlIgnoreCase(s, "error")) {
            return .err;
        }
        return null;
    }
};

/// Get default configuration for a profile
pub fn getProfileConfig(profile: Profile) ProfileConfig {
    return switch (profile) {
        .development => .{
            // Server settings - permissive for development
            .smtp_port = 2525,
            .api_port = 8081,
            .max_connections = 100,
            .connection_timeout_seconds = 300,
            .command_timeout_seconds = 60,

            // Rate limiting - relaxed for testing
            .rate_limit_window_seconds = 60,
            .rate_limit_max_requests = 1000,
            .rate_limit_max_per_user = 500,

            // Message limits - moderate
            .max_message_size = 10 * 1024 * 1024, // 10MB
            .max_recipients = 100,

            // Storage - small batches for quick feedback
            .queue_batch_size = 10,
            .queue_flush_interval_ms = 1000,
            .database_pool_size = 5,

            // Logging - verbose for debugging
            .log_level = .debug,
            .enable_json_logging = false,
            .log_file_path = null,

            // Security - relaxed for development
            .require_tls = false,
            .require_auth = false,
            .tls_min_version = "1.2",

            // Performance - minimal for debugging
            .buffer_pool_size = 50,
            .enable_io_uring = false,
            .worker_threads = 2,

            // Features - all enabled for testing
            .enable_spam_filter = true,
            .enable_virus_scan = false, // Often slow in dev
            .enable_greylist = false, // Annoying in dev
            .enable_webhooks = true,
            .enable_metrics = true,
            .enable_tracing = true,

            // Resilience - fast failures for quick iteration
            .circuit_breaker_threshold = 10,
            .circuit_breaker_timeout_seconds = 10,
            .max_retry_attempts = 2,
            .retry_delay_seconds = 1,
        },

        .testing => .{
            // Server settings - minimal for tests
            .smtp_port = 0, // Random port
            .api_port = 0, // Random port
            .max_connections = 10,
            .connection_timeout_seconds = 5,
            .command_timeout_seconds = 2,

            // Rate limiting - disabled for deterministic tests
            .rate_limit_window_seconds = 60,
            .rate_limit_max_requests = 10000,
            .rate_limit_max_per_user = 10000,

            // Message limits - small for fast tests
            .max_message_size = 1 * 1024 * 1024, // 1MB
            .max_recipients = 10,

            // Storage - minimal for speed
            .queue_batch_size = 5,
            .queue_flush_interval_ms = 100,
            .database_pool_size = 2,

            // Logging - minimal noise in tests
            .log_level = .warn,
            .enable_json_logging = false,
            .log_file_path = null,

            // Security - disabled for deterministic tests
            .require_tls = false,
            .require_auth = false,
            .tls_min_version = "1.2",

            // Performance - minimal for tests
            .buffer_pool_size = 10,
            .enable_io_uring = false,
            .worker_threads = 1,

            // Features - minimal for fast tests
            .enable_spam_filter = false,
            .enable_virus_scan = false,
            .enable_greylist = false,
            .enable_webhooks = false,
            .enable_metrics = false,
            .enable_tracing = false,

            // Resilience - fast failures for tests
            .circuit_breaker_threshold = 3,
            .circuit_breaker_timeout_seconds = 1,
            .max_retry_attempts = 1,
            .retry_delay_seconds = 0,
        },

        .staging => .{
            // Server settings - production-like
            .smtp_port = 25,
            .api_port = 8080,
            .max_connections = 500,
            .connection_timeout_seconds = 300,
            .command_timeout_seconds = 60,

            // Rate limiting - moderate
            .rate_limit_window_seconds = 60,
            .rate_limit_max_requests = 500,
            .rate_limit_max_per_user = 200,

            // Message limits - production-like
            .max_message_size = 25 * 1024 * 1024, // 25MB
            .max_recipients = 100,

            // Storage - balanced
            .queue_batch_size = 50,
            .queue_flush_interval_ms = 2000,
            .database_pool_size = 10,

            // Logging - structured for aggregation
            .log_level = .info,
            .enable_json_logging = true,
            .log_file_path = "/var/log/smtp/server.log",

            // Security - enforced
            .require_tls = true,
            .require_auth = true,
            .tls_min_version = "1.2",

            // Performance - moderate
            .buffer_pool_size = 200,
            .enable_io_uring = false, // Test first in staging
            .worker_threads = 4,

            // Features - all enabled for pre-prod testing
            .enable_spam_filter = true,
            .enable_virus_scan = true,
            .enable_greylist = true,
            .enable_webhooks = true,
            .enable_metrics = true,
            .enable_tracing = true,

            // Resilience - production-like
            .circuit_breaker_threshold = 5,
            .circuit_breaker_timeout_seconds = 30,
            .max_retry_attempts = 3,
            .retry_delay_seconds = 5,
        },

        .production => .{
            // Server settings - production tuned
            .smtp_port = 25,
            .api_port = 8080,
            .max_connections = 2000,
            .connection_timeout_seconds = 300,
            .command_timeout_seconds = 60,

            // Rate limiting - strict
            .rate_limit_window_seconds = 60,
            .rate_limit_max_requests = 200,
            .rate_limit_max_per_user = 100,

            // Message limits - standard SMTP
            .max_message_size = 25 * 1024 * 1024, // 25MB
            .max_recipients = 100,

            // Storage - optimized for throughput
            .queue_batch_size = 100,
            .queue_flush_interval_ms = 5000,
            .database_pool_size = 20,

            // Logging - structured, errors and above
            .log_level = .info,
            .enable_json_logging = true,
            .log_file_path = "/var/log/smtp/server.log",

            // Security - maximum security
            .require_tls = true,
            .require_auth = true,
            .tls_min_version = "1.3",

            // Performance - maximum throughput
            .buffer_pool_size = 500,
            .enable_io_uring = true, // Linux only
            .worker_threads = 8,

            // Features - production security
            .enable_spam_filter = true,
            .enable_virus_scan = true,
            .enable_greylist = true,
            .enable_webhooks = true,
            .enable_metrics = true,
            .enable_tracing = true,

            // Resilience - production tuned
            .circuit_breaker_threshold = 10,
            .circuit_breaker_timeout_seconds = 60,
            .max_retry_attempts = 5,
            .retry_delay_seconds = 10,
        },
    };
}

/// Validate profile configuration
pub fn validateConfig(config: *const ProfileConfig) !void {
    // Ports are u16 so automatically valid range (0-65535)
    // But we can check for reserved ports if needed
    _ = config.smtp_port;
    _ = config.api_port;

    // Validate timeouts
    if (config.connection_timeout_seconds == 0) {
        return error.InvalidTimeout;
    }
    if (config.command_timeout_seconds == 0) {
        return error.InvalidTimeout;
    }

    // Validate rate limits
    if (config.rate_limit_window_seconds == 0) {
        return error.InvalidRateLimit;
    }

    // Validate message limits
    if (config.max_message_size == 0) {
        return error.InvalidMessageSize;
    }
    if (config.max_recipients == 0) {
        return error.InvalidRecipientLimit;
    }

    // Validate storage
    if (config.database_pool_size == 0) {
        return error.InvalidPoolSize;
    }

    // Validate performance
    if (config.worker_threads == 0) {
        return error.InvalidWorkerThreads;
    }
}

/// Print configuration summary
pub fn printSummary(config: *const ProfileConfig, profile: Profile, writer: anytype) !void {
    try writer.print("Configuration Profile: {s}\n", .{profile.toString()});
    try writer.print("=================================\n", .{});
    try writer.print("Server:\n", .{});
    try writer.print("  SMTP Port: {d}\n", .{config.smtp_port});
    try writer.print("  API Port: {d}\n", .{config.api_port});
    try writer.print("  Max Connections: {d}\n", .{config.max_connections});
    try writer.print("\n", .{});
    try writer.print("Security:\n", .{});
    try writer.print("  Require TLS: {}\n", .{config.require_tls});
    try writer.print("  Require Auth: {}\n", .{config.require_auth});
    try writer.print("  TLS Min Version: {s}\n", .{config.tls_min_version});
    try writer.print("\n", .{});
    try writer.print("Performance:\n", .{});
    try writer.print("  Worker Threads: {d}\n", .{config.worker_threads});
    try writer.print("  Buffer Pool Size: {d}\n", .{config.buffer_pool_size});
    try writer.print("  Enable io_uring: {}\n", .{config.enable_io_uring});
    try writer.print("\n", .{});
    try writer.print("Features:\n", .{});
    try writer.print("  Spam Filter: {}\n", .{config.enable_spam_filter});
    try writer.print("  Virus Scan: {}\n", .{config.enable_virus_scan});
    try writer.print("  Greylist: {}\n", .{config.enable_greylist});
    try writer.print("  Metrics: {}\n", .{config.enable_metrics});
    try writer.print("  Tracing: {}\n", .{config.enable_tracing});
}

// Tests
test "profile from string" {
    const testing = std.testing;

    try testing.expectEqual(Profile.development, Profile.fromString("development").?);
    try testing.expectEqual(Profile.development, Profile.fromString("dev").?);
    try testing.expectEqual(Profile.testing, Profile.fromString("test").?);
    try testing.expectEqual(Profile.production, Profile.fromString("prod").?);
    try testing.expectEqual(Profile.staging, Profile.fromString("staging").?);
    try testing.expect(Profile.fromString("invalid") == null);
}

test "get profile config" {
    const testing = std.testing;

    const dev_config = getProfileConfig(.development);
    try testing.expectEqual(@as(u16, 2525), dev_config.smtp_port);
    try testing.expectEqual(LogLevel.debug, dev_config.log_level);
    try testing.expect(!dev_config.require_tls);

    const prod_config = getProfileConfig(.production);
    try testing.expectEqual(@as(u16, 25), prod_config.smtp_port);
    try testing.expectEqual(LogLevel.info, prod_config.log_level);
    try testing.expect(prod_config.require_tls);
}

test "validate config" {
    const testing = std.testing;

    var config = getProfileConfig(.production);
    try validateConfig(&config);

    // Reset config for next test
    config = getProfileConfig(.production);

    // Test invalid timeout
    config.connection_timeout_seconds = 0;
    try testing.expectError(error.InvalidTimeout, validateConfig(&config));
}

test "profile differences" {
    const testing = std.testing;

    const dev = getProfileConfig(.development);
    const prod = getProfileConfig(.production);

    // Development should be more permissive
    try testing.expect(dev.max_connections < prod.max_connections);
    try testing.expect(dev.rate_limit_max_requests > prod.rate_limit_max_requests);
    try testing.expect(dev.log_level != prod.log_level);
}
