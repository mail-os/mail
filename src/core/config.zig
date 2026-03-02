const std = @import("std");
const args = @import("args.zig");
const config_profiles = @import("config_profiles.zig");
const toml = @import("toml.zig");
const env = @import("env.zig");
const io_compat = @import("io_compat.zig");

pub const ValidationError = error{
    InvalidPort,
    InvalidHost,
    InvalidHostname,
    InvalidMaxConnections,
    InvalidMaxMessageSize,
    InvalidMaxRecipients,
    InvalidTimeout,
    InvalidRateLimit,
    InvalidTLSConfiguration,
    InvalidWebhookConfiguration,
    TLSCertificateNotFound,
    TLSKeyNotFound,
    InvalidHostnameFormat,
};

pub const DeliveryMethod = enum {
    ses, // Relay through AWS SES (works when port 25 is blocked)
    direct, // Direct MX delivery (requires outbound port 25)
};

pub const Config = struct {
    host: []const u8,
    port: u16,
    max_connections: usize,
    enable_tls: bool,
    tls_cert_path: ?[]const u8,
    tls_key_path: ?[]const u8,
    enable_auth: bool,
    max_message_size: usize,

    // Timeout configuration with granularity
    timeout_seconds: u32, // General connection timeout
    data_timeout_seconds: u32, // Specific timeout for DATA command
    command_timeout_seconds: u32, // Timeout between commands
    greeting_timeout_seconds: u32, // Timeout for initial greeting

    rate_limit_per_ip: u32,
    rate_limit_per_user: u32,
    rate_limit_cleanup_interval: u64,
    max_recipients: usize,
    hostname: []const u8,
    webhook_url: ?[]const u8,
    webhook_enabled: bool,
    enable_dnsbl: bool,
    enable_greylist: bool,
    enable_tracing: bool,
    tracing_service_name: []const u8,
    enable_json_logging: bool,

    // Feature flags for new modules
    enable_dkim_rotation: bool = false,
    dkim_rotation_interval_days: u32 = 90,
    enable_sieve: bool = false,
    enable_dane: bool = false,
    enable_mta_sts: bool = false,
    enable_acme: bool = false,
    acme_email: ?[]const u8 = null,
    enable_tls_rpt: bool = false,
    enable_arc: bool = false,
    enable_bimi: bool = false,
    enable_list_unsubscribe: bool = false,
    list_unsubscribe_url: ?[]const u8 = null,
    enable_autoconfig: bool = false,
    enable_managesieve: bool = false,
    managesieve_port: u16 = 4190,
    enable_milter: bool = false,

    // Outbound delivery method: "ses" (AWS SES relay), "direct" (direct MX delivery)
    delivery_method: DeliveryMethod = .ses,
    ses_region: []const u8 = "us-east-1",

    pub fn deinit(self: Config, allocator: std.mem.Allocator) void {
        allocator.free(self.tracing_service_name);
        allocator.free(self.host);
        allocator.free(self.hostname);
        if (self.tls_cert_path) |path| allocator.free(path);
        if (self.tls_key_path) |path| allocator.free(path);
        if (self.webhook_url) |url| allocator.free(url);
        if (self.acme_email) |email| allocator.free(email);
        if (self.list_unsubscribe_url) |url| allocator.free(url);
    }

    /// Validates the configuration and returns detailed error messages
    pub fn validate(self: Config) ValidationError!void {
        // Validate port range (0 for random port in testing, 1-65535 otherwise)
        // Port 0 is allowed and means the OS will assign a random available port
        _ = self.port; // Port 0 is valid for testing scenarios

        // Validate host is not empty
        if (self.host.len == 0) {
            std.debug.print("Configuration Error: Host cannot be empty\n", .{});
            return ValidationError.InvalidHost;
        }

        // Validate hostname is not empty and has valid format
        if (self.hostname.len == 0) {
            std.debug.print("Configuration Error: Hostname cannot be empty\n", .{});
            return ValidationError.InvalidHostname;
        }

        // Basic hostname format validation (no spaces, basic characters)
        for (self.hostname) |c| {
            if (c == ' ' or c == '\t' or c == '\r' or c == '\n') {
                std.debug.print("Configuration Error: Hostname contains invalid whitespace characters\n", .{});
                return ValidationError.InvalidHostnameFormat;
            }
        }

        // Validate max_connections is reasonable (1-100000)
        if (self.max_connections == 0 or self.max_connections > 100000) {
            std.debug.print("Configuration Error: max_connections must be between 1 and 100000, got {d}\n", .{self.max_connections});
            return ValidationError.InvalidMaxConnections;
        }

        // Validate max_message_size is reasonable (1KB - 100MB)
        const min_message_size = 1024; // 1KB
        const max_message_size = 100 * 1024 * 1024; // 100MB
        if (self.max_message_size < min_message_size or self.max_message_size > max_message_size) {
            std.debug.print("Configuration Error: max_message_size must be between {d} and {d}, got {d}\n", .{ min_message_size, max_message_size, self.max_message_size });
            return ValidationError.InvalidMaxMessageSize;
        }

        // Validate max_recipients is reasonable (1-10000)
        if (self.max_recipients == 0 or self.max_recipients > 10000) {
            std.debug.print("Configuration Error: max_recipients must be between 1 and 10000, got {d}\n", .{self.max_recipients});
            return ValidationError.InvalidMaxRecipients;
        }

        // Validate timeout values (1 second - 1 hour)
        const min_timeout: u32 = 1;
        const max_timeout: u32 = 3600;

        if (self.timeout_seconds < min_timeout or self.timeout_seconds > max_timeout) {
            std.debug.print("Configuration Error: timeout_seconds must be between {d} and {d}, got {d}\n", .{ min_timeout, max_timeout, self.timeout_seconds });
            return ValidationError.InvalidTimeout;
        }

        if (self.data_timeout_seconds < min_timeout or self.data_timeout_seconds > max_timeout) {
            std.debug.print("Configuration Error: data_timeout_seconds must be between {d} and {d}, got {d}\n", .{ min_timeout, max_timeout, self.data_timeout_seconds });
            return ValidationError.InvalidTimeout;
        }

        if (self.command_timeout_seconds < min_timeout or self.command_timeout_seconds > max_timeout) {
            std.debug.print("Configuration Error: command_timeout_seconds must be between {d} and {d}, got {d}\n", .{ min_timeout, max_timeout, self.command_timeout_seconds });
            return ValidationError.InvalidTimeout;
        }

        if (self.greeting_timeout_seconds < min_timeout or self.greeting_timeout_seconds > max_timeout) {
            std.debug.print("Configuration Error: greeting_timeout_seconds must be between {d} and {d}, got {d}\n", .{ min_timeout, max_timeout, self.greeting_timeout_seconds });
            return ValidationError.InvalidTimeout;
        }

        // Validate rate limits (1-1000000 per hour)
        if (self.rate_limit_per_ip == 0 or self.rate_limit_per_ip > 1000000) {
            std.debug.print("Configuration Error: rate_limit_per_ip must be between 1 and 1000000, got {d}\n", .{self.rate_limit_per_ip});
            return ValidationError.InvalidRateLimit;
        }

        if (self.rate_limit_per_user == 0 or self.rate_limit_per_user > 1000000) {
            std.debug.print("Configuration Error: rate_limit_per_user must be between 1 and 1000000, got {d}\n", .{self.rate_limit_per_user});
            return ValidationError.InvalidRateLimit;
        }

        // Validate rate limit cleanup interval (60 seconds - 24 hours)
        const min_cleanup_interval: u64 = 60;
        const max_cleanup_interval: u64 = 86400;
        if (self.rate_limit_cleanup_interval < min_cleanup_interval or self.rate_limit_cleanup_interval > max_cleanup_interval) {
            std.debug.print("Configuration Error: rate_limit_cleanup_interval must be between {d} and {d}, got {d}\n", .{ min_cleanup_interval, max_cleanup_interval, self.rate_limit_cleanup_interval });
            return ValidationError.InvalidRateLimit;
        }

        // Validate TLS configuration
        if (self.enable_tls) {
            if (self.tls_cert_path == null) {
                std.debug.print("Configuration Error: TLS is enabled but tls_cert_path is not set\n", .{});
                return ValidationError.InvalidTLSConfiguration;
            }
            if (self.tls_key_path == null) {
                std.debug.print("Configuration Error: TLS is enabled but tls_key_path is not set\n", .{});
                return ValidationError.InvalidTLSConfiguration;
            }

            // Check if TLS certificate file exists
            if (self.tls_cert_path) |cert_path| {
                std.Io.Dir.cwd().access(io_compat.getIo(), cert_path, .{}) catch {
                    std.debug.print("Configuration Error: TLS certificate file not found: {s}\n", .{cert_path});
                    return ValidationError.TLSCertificateNotFound;
                };
            }

            // Check if TLS key file exists
            if (self.tls_key_path) |key_path| {
                std.Io.Dir.cwd().access(io_compat.getIo(), key_path, .{}) catch {
                    std.debug.print("Configuration Error: TLS key file not found: {s}\n", .{key_path});
                    return ValidationError.TLSKeyNotFound;
                };
            }
        }

        // Validate webhook configuration
        if (self.webhook_enabled) {
            if (self.webhook_url == null or self.webhook_url.?.len == 0) {
                std.debug.print("Configuration Error: Webhooks are enabled but webhook_url is not set\n", .{});
                return ValidationError.InvalidWebhookConfiguration;
            }

            // Basic URL validation (must start with http:// or https://)
            if (self.webhook_url) |url| {
                if (!std.mem.startsWith(u8, url, "http://") and !std.mem.startsWith(u8, url, "https://")) {
                    std.debug.print("Configuration Error: webhook_url must start with http:// or https://, got: {s}\n", .{url});
                    return ValidationError.InvalidWebhookConfiguration;
                }
            }
        }
    }
};

/// Standard configuration file locations (in order of priority)
const CONFIG_FILE_PATHS = [_][]const u8{
    "./config.toml",
    "./smtp-server.toml",
    "/etc/smtp-server/config.toml",
};

pub fn loadConfig(allocator: std.mem.Allocator, cli_args: args.Args) !Config {
    // Determine which profile to use (from env var or default to development)
    const profile = determineProfile();

    var cfg = try loadDefaultsFromProfile(allocator, profile);

    // Try to load from config file (CLI arg takes priority, then standard paths)
    if (cli_args.config_file) |config_path| {
        try applyConfigFile(allocator, &cfg, config_path);
    } else if (env.get("SMTP_CONFIG_FILE")) |config_path| {
        try applyConfigFile(allocator, &cfg, config_path);
    } else {
        // Try standard config file locations
        for (CONFIG_FILE_PATHS) |path| {
            if (applyConfigFile(allocator, &cfg, path)) {
                break;
            } else |_| {
                // File not found, try next location
                continue;
            }
        }
    }

    // Override with environment variables
    try applyEnvironmentVariables(allocator, &cfg);

    // Override with command-line arguments (highest priority)
    try applyCommandLineArgs(allocator, &cfg, cli_args);

    // Validate the final configuration
    try cfg.validate();

    return cfg;
}

/// Determine which configuration profile to use
fn determineProfile() config_profiles.Profile {
    if (env.get("SMTP_PROFILE")) |profile_str| {
        if (config_profiles.Profile.fromString(profile_str)) |profile| {
            return profile;
        }
        // If invalid profile specified, log warning and use development
        std.debug.print("Warning: Invalid SMTP_PROFILE '{s}', using 'development'\n", .{profile_str});
    }
    // Default to development profile
    return .development;
}

/// Load configuration defaults from a profile
/// This is the single source of truth for all default values
fn loadDefaultsFromProfile(allocator: std.mem.Allocator, profile: config_profiles.Profile) !Config {
    const profile_config = config_profiles.getProfileConfig(profile);

    // Log which profile is being used
    std.debug.print("Using configuration profile: {s}\n", .{profile.toString()});

    return Config{
        .host = try allocator.dupe(u8, "0.0.0.0"),
        .port = profile_config.smtp_port,
        .max_connections = @intCast(profile_config.max_connections),
        .enable_tls = profile_config.require_tls,
        .tls_cert_path = null,
        .tls_key_path = null,
        .enable_auth = profile_config.require_auth,
        .max_message_size = profile_config.max_message_size,
        .timeout_seconds = profile_config.connection_timeout_seconds,
        .data_timeout_seconds = profile_config.connection_timeout_seconds * 2, // DATA needs longer timeout
        .command_timeout_seconds = profile_config.command_timeout_seconds,
        .greeting_timeout_seconds = 30, // Fixed at 30 seconds for all profiles
        .rate_limit_per_ip = profile_config.rate_limit_max_requests,
        .rate_limit_per_user = profile_config.rate_limit_max_per_user,
        .rate_limit_cleanup_interval = @as(u64, profile_config.rate_limit_window_seconds) * 60, // Convert to seconds
        .max_recipients = @intCast(profile_config.max_recipients),
        .hostname = try allocator.dupe(u8, "localhost"),
        .webhook_url = null,
        .webhook_enabled = false, // Only enable when URL is provided via env var
        .enable_dnsbl = false, // Not in profile config yet
        .enable_greylist = profile_config.enable_greylist,
        .enable_tracing = profile_config.enable_tracing,
        .tracing_service_name = try allocator.dupe(u8, "smtp-server"),
        .enable_json_logging = profile_config.enable_json_logging,
        .enable_dkim_rotation = false,
        .dkim_rotation_interval_days = 90,
        .enable_sieve = false,
        .enable_dane = false,
        .enable_mta_sts = false,
        .enable_acme = false,
        .acme_email = null,
        .enable_tls_rpt = false,
        .enable_arc = false,
        .enable_bimi = false,
        .enable_list_unsubscribe = false,
        .list_unsubscribe_url = null,
        .enable_autoconfig = false,
        .enable_managesieve = false,
        .managesieve_port = 4190,
        .enable_milter = false,
    };
}

fn applyEnvironmentVariables(allocator: std.mem.Allocator, cfg: *Config) !void {
    // SMTP_HOST
    if (env.get("SMTP_HOST")) |value| {
        allocator.free(cfg.host);
        cfg.host = try allocator.dupe(u8, value);
    }

    // SMTP_PORT
    if (env.get("SMTP_PORT")) |value| {
        cfg.port = std.fmt.parseInt(u16, value, 10) catch cfg.port;
    }

    // SMTP_HOSTNAME
    if (env.get("SMTP_HOSTNAME")) |value| {
        allocator.free(cfg.hostname);
        cfg.hostname = try allocator.dupe(u8, value);
    }

    // SMTP_MAX_CONNECTIONS
    if (env.get("SMTP_MAX_CONNECTIONS")) |value| {
        cfg.max_connections = std.fmt.parseInt(usize, value, 10) catch cfg.max_connections;
    }

    // SMTP_MAX_MESSAGE_SIZE
    if (env.get("SMTP_MAX_MESSAGE_SIZE")) |value| {
        cfg.max_message_size = std.fmt.parseInt(usize, value, 10) catch cfg.max_message_size;
    }

    // SMTP_MAX_RECIPIENTS
    if (env.get("SMTP_MAX_RECIPIENTS")) |value| {
        cfg.max_recipients = std.fmt.parseInt(usize, value, 10) catch cfg.max_recipients;
    }

    // SMTP_TIMEOUT_SECONDS (connection timeout)
    if (env.get("SMTP_TIMEOUT_SECONDS")) |value| {
        cfg.timeout_seconds = std.fmt.parseInt(u32, value, 10) catch cfg.timeout_seconds;
    }

    // SMTP_DATA_TIMEOUT_SECONDS (DATA command timeout)
    if (env.get("SMTP_DATA_TIMEOUT_SECONDS")) |value| {
        cfg.data_timeout_seconds = std.fmt.parseInt(u32, value, 10) catch cfg.data_timeout_seconds;
    }

    // SMTP_COMMAND_TIMEOUT_SECONDS (timeout between commands)
    if (env.get("SMTP_COMMAND_TIMEOUT_SECONDS")) |value| {
        cfg.command_timeout_seconds = std.fmt.parseInt(u32, value, 10) catch cfg.command_timeout_seconds;
    }

    // SMTP_GREETING_TIMEOUT_SECONDS (timeout for initial greeting)
    if (env.get("SMTP_GREETING_TIMEOUT_SECONDS")) |value| {
        cfg.greeting_timeout_seconds = std.fmt.parseInt(u32, value, 10) catch cfg.greeting_timeout_seconds;
    }

    // SMTP_ENABLE_TLS
    if (env.get("SMTP_ENABLE_TLS")) |value| {
        cfg.enable_tls = std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "1");
    }

    // SMTP_ENABLE_AUTH
    if (env.get("SMTP_ENABLE_AUTH")) |value| {
        cfg.enable_auth = std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "1");
    }

    // SMTP_ENABLE_DNSBL
    if (env.get("SMTP_ENABLE_DNSBL")) |value| {
        cfg.enable_dnsbl = std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "1");
    }

    // SMTP_ENABLE_GREYLIST
    if (env.get("SMTP_ENABLE_GREYLIST")) |value| {
        cfg.enable_greylist = std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "1");
    }

    // SMTP_TLS_CERT
    if (env.get("SMTP_TLS_CERT")) |value| {
        if (cfg.tls_cert_path) |old| allocator.free(old);
        cfg.tls_cert_path = try allocator.dupe(u8, value);
    }

    // SMTP_TLS_KEY
    if (env.get("SMTP_TLS_KEY")) |value| {
        if (cfg.tls_key_path) |old| allocator.free(old);
        cfg.tls_key_path = try allocator.dupe(u8, value);
    }

    // SMTP_WEBHOOK_URL
    if (env.get("SMTP_WEBHOOK_URL")) |value| {
        if (cfg.webhook_url) |old| allocator.free(old);
        cfg.webhook_url = try allocator.dupe(u8, value);
        cfg.webhook_enabled = true;
    }

    // SMTP_WEBHOOK_ENABLED
    if (env.get("SMTP_WEBHOOK_ENABLED")) |value| {
        cfg.webhook_enabled = std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "1");
    }

    // SMTP_RATE_LIMIT_PER_IP
    if (env.get("SMTP_RATE_LIMIT_PER_IP")) |value| {
        cfg.rate_limit_per_ip = std.fmt.parseInt(u32, value, 10) catch cfg.rate_limit_per_ip;
    }

    // SMTP_RATE_LIMIT_PER_USER
    if (env.get("SMTP_RATE_LIMIT_PER_USER")) |value| {
        cfg.rate_limit_per_user = std.fmt.parseInt(u32, value, 10) catch cfg.rate_limit_per_user;
    }

    // SMTP_RATE_LIMIT_CLEANUP_INTERVAL
    if (env.get("SMTP_RATE_LIMIT_CLEANUP_INTERVAL")) |value| {
        cfg.rate_limit_cleanup_interval = std.fmt.parseInt(u64, value, 10) catch cfg.rate_limit_cleanup_interval;
    }

    // SMTP_ENABLE_TRACING
    if (env.get("SMTP_ENABLE_TRACING")) |value| {
        cfg.enable_tracing = std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "1");
    }

    // SMTP_TRACING_SERVICE_NAME
    if (env.get("SMTP_TRACING_SERVICE_NAME")) |value| {
        allocator.free(cfg.tracing_service_name);
        cfg.tracing_service_name = try allocator.dupe(u8, value);
    }

    // SMTP_ENABLE_JSON_LOGGING
    if (env.get("SMTP_ENABLE_JSON_LOGGING")) |value| {
        cfg.enable_json_logging = std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "1");
    }

    // Feature flags for new modules
    if (env.get("SMTP_ENABLE_DKIM_ROTATION")) |value| {
        cfg.enable_dkim_rotation = std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "1");
    }
    if (env.get("SMTP_DKIM_ROTATION_INTERVAL_DAYS")) |value| {
        cfg.dkim_rotation_interval_days = std.fmt.parseInt(u32, value, 10) catch cfg.dkim_rotation_interval_days;
    }
    if (env.get("SMTP_ENABLE_SIEVE")) |value| {
        cfg.enable_sieve = std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "1");
    }
    if (env.get("SMTP_ENABLE_DANE")) |value| {
        cfg.enable_dane = std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "1");
    }
    if (env.get("SMTP_ENABLE_MTA_STS")) |value| {
        cfg.enable_mta_sts = std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "1");
    }
    if (env.get("SMTP_ENABLE_ACME")) |value| {
        cfg.enable_acme = std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "1");
    }
    if (env.get("SMTP_ACME_EMAIL")) |value| {
        if (cfg.acme_email) |old| allocator.free(old);
        cfg.acme_email = try allocator.dupe(u8, value);
    }
    if (env.get("SMTP_ENABLE_TLS_RPT")) |value| {
        cfg.enable_tls_rpt = std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "1");
    }
    if (env.get("SMTP_ENABLE_ARC")) |value| {
        cfg.enable_arc = std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "1");
    }
    if (env.get("SMTP_ENABLE_BIMI")) |value| {
        cfg.enable_bimi = std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "1");
    }
    if (env.get("SMTP_ENABLE_LIST_UNSUBSCRIBE")) |value| {
        cfg.enable_list_unsubscribe = std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "1");
    }
    if (env.get("SMTP_LIST_UNSUBSCRIBE_URL")) |value| {
        if (cfg.list_unsubscribe_url) |old| allocator.free(old);
        cfg.list_unsubscribe_url = try allocator.dupe(u8, value);
    }
    if (env.get("SMTP_ENABLE_AUTOCONFIG")) |value| {
        cfg.enable_autoconfig = std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "1");
    }
    if (env.get("SMTP_ENABLE_MANAGESIEVE")) |value| {
        cfg.enable_managesieve = std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "1");
    }
    if (env.get("SMTP_MANAGESIEVE_PORT")) |value| {
        cfg.managesieve_port = std.fmt.parseInt(u16, value, 10) catch cfg.managesieve_port;
    }
    if (env.get("SMTP_ENABLE_MILTER")) |value| {
        cfg.enable_milter = std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "1");
    }

    // SMTP_DELIVERY_METHOD (ses or direct)
    if (env.get("SMTP_DELIVERY_METHOD")) |value| {
        if (std.ascii.eqlIgnoreCase(value, "direct")) {
            cfg.delivery_method = .direct;
        } else {
            cfg.delivery_method = .ses;
        }
    }

    // SMTP_SES_REGION
    if (env.get("SMTP_SES_REGION")) |value| {
        cfg.ses_region = try allocator.dupe(u8, value);
    }
}

fn applyCommandLineArgs(allocator: std.mem.Allocator, cfg: *Config, cli_args: args.Args) !void {
    if (cli_args.host) |value| {
        allocator.free(cfg.host);
        cfg.host = try allocator.dupe(u8, value);
    }

    if (cli_args.port) |value| {
        cfg.port = value;
    }

    if (cli_args.max_connections) |value| {
        cfg.max_connections = value;
    }

    if (cli_args.enable_tls) |value| {
        cfg.enable_tls = value;
    }

    if (cli_args.enable_auth) |value| {
        cfg.enable_auth = value;
    }
}

/// Apply configuration from a TOML file
fn applyConfigFile(allocator: std.mem.Allocator, cfg: *Config, path: []const u8) !void {
    var parser = toml.TomlParser.init(allocator);
    var doc = try parser.parseFile(path);
    defer doc.deinit();

    std.debug.print("Loaded configuration from: {s}\n", .{path});

    // Apply [server] section
    if (doc.getSection("server")) |server| {
        if (server.getString("host")) |value| {
            allocator.free(cfg.host);
            cfg.host = try allocator.dupe(u8, value);
        }
        if (server.getInt("port")) |value| {
            cfg.port = @intCast(value);
        }
        if (server.getString("hostname")) |value| {
            allocator.free(cfg.hostname);
            cfg.hostname = try allocator.dupe(u8, value);
        }
        if (server.getInt("max_connections")) |value| {
            cfg.max_connections = @intCast(value);
        }
        if (server.getInt("max_message_size")) |value| {
            cfg.max_message_size = @intCast(value);
        }
        if (server.getInt("max_recipients")) |value| {
            cfg.max_recipients = @intCast(value);
        }
    }

    // Apply [timeouts] section
    if (doc.getSection("timeouts")) |timeouts| {
        if (timeouts.getInt("connection")) |value| {
            cfg.timeout_seconds = @intCast(value);
        }
        if (timeouts.getInt("data")) |value| {
            cfg.data_timeout_seconds = @intCast(value);
        }
        if (timeouts.getInt("command")) |value| {
            cfg.command_timeout_seconds = @intCast(value);
        }
        if (timeouts.getInt("greeting")) |value| {
            cfg.greeting_timeout_seconds = @intCast(value);
        }
    }

    // Apply [tls] section
    if (doc.getSection("tls")) |tls| {
        if (tls.getBool("enabled")) |value| {
            cfg.enable_tls = value;
        }
        if (tls.getString("cert_path")) |value| {
            if (cfg.tls_cert_path) |old| allocator.free(old);
            cfg.tls_cert_path = try allocator.dupe(u8, value);
        }
        if (tls.getString("key_path")) |value| {
            if (cfg.tls_key_path) |old| allocator.free(old);
            cfg.tls_key_path = try allocator.dupe(u8, value);
        }
    }

    // Apply [auth] section
    if (doc.getSection("auth")) |auth_section| {
        if (auth_section.getBool("enabled")) |value| {
            cfg.enable_auth = value;
        }
    }

    // Apply [rate_limit] section
    if (doc.getSection("rate_limit")) |rate_limit| {
        if (rate_limit.getInt("per_ip")) |value| {
            cfg.rate_limit_per_ip = @intCast(value);
        }
        if (rate_limit.getInt("per_user")) |value| {
            cfg.rate_limit_per_user = @intCast(value);
        }
        if (rate_limit.getInt("cleanup_interval")) |value| {
            cfg.rate_limit_cleanup_interval = @intCast(value);
        }
    }

    // Apply [webhook] section
    if (doc.getSection("webhook")) |webhook| {
        if (webhook.getBool("enabled")) |value| {
            cfg.webhook_enabled = value;
        }
        if (webhook.getString("url")) |value| {
            if (cfg.webhook_url) |old| allocator.free(old);
            cfg.webhook_url = try allocator.dupe(u8, value);
        }
    }

    // Apply [antispam] section
    if (doc.getSection("antispam")) |antispam| {
        if (antispam.getBool("dnsbl")) |value| {
            cfg.enable_dnsbl = value;
        }
        if (antispam.getBool("greylist")) |value| {
            cfg.enable_greylist = value;
        }
    }

    // Apply [observability] section
    if (doc.getSection("observability")) |obs| {
        if (obs.getBool("tracing")) |value| {
            cfg.enable_tracing = value;
        }
        if (obs.getString("service_name")) |value| {
            allocator.free(cfg.tracing_service_name);
            cfg.tracing_service_name = try allocator.dupe(u8, value);
        }
        if (obs.getBool("json_logging")) |value| {
            cfg.enable_json_logging = value;
        }
    }

    // Apply [dkim] section
    if (doc.getSection("dkim")) |section| {
        if (section.getBool("rotation_enabled")) |value| {
            cfg.enable_dkim_rotation = value;
        }
        if (section.getInt("rotation_interval_days")) |value| {
            cfg.dkim_rotation_interval_days = @intCast(value);
        }
    }

    // Apply [sieve] section
    if (doc.getSection("sieve")) |section| {
        if (section.getBool("enabled")) |value| {
            cfg.enable_sieve = value;
        }
    }

    // Apply [dane] section
    if (doc.getSection("dane")) |section| {
        if (section.getBool("enabled")) |value| {
            cfg.enable_dane = value;
        }
    }

    // Apply [mta_sts] section
    if (doc.getSection("mta_sts")) |section| {
        if (section.getBool("enabled")) |value| {
            cfg.enable_mta_sts = value;
        }
    }

    // Apply [acme] section
    if (doc.getSection("acme")) |section| {
        if (section.getBool("enabled")) |value| {
            cfg.enable_acme = value;
        }
        if (section.getString("email")) |value| {
            if (cfg.acme_email) |old| allocator.free(old);
            cfg.acme_email = try allocator.dupe(u8, value);
        }
    }

    // Apply [tls_rpt] section
    if (doc.getSection("tls_rpt")) |section| {
        if (section.getBool("enabled")) |value| {
            cfg.enable_tls_rpt = value;
        }
    }

    // Apply [arc] section
    if (doc.getSection("arc")) |section| {
        if (section.getBool("enabled")) |value| {
            cfg.enable_arc = value;
        }
    }

    // Apply [bimi] section
    if (doc.getSection("bimi")) |section| {
        if (section.getBool("enabled")) |value| {
            cfg.enable_bimi = value;
        }
    }

    // Apply [list_unsubscribe] section
    if (doc.getSection("list_unsubscribe")) |section| {
        if (section.getBool("enabled")) |value| {
            cfg.enable_list_unsubscribe = value;
        }
        if (section.getString("url_base")) |value| {
            if (cfg.list_unsubscribe_url) |old| allocator.free(old);
            cfg.list_unsubscribe_url = try allocator.dupe(u8, value);
        }
    }

    // Apply [autoconfig] section
    if (doc.getSection("autoconfig")) |section| {
        if (section.getBool("enabled")) |value| {
            cfg.enable_autoconfig = value;
        }
    }

    // Apply [managesieve] section
    if (doc.getSection("managesieve")) |section| {
        if (section.getBool("enabled")) |value| {
            cfg.enable_managesieve = value;
        }
        if (section.getInt("port")) |value| {
            cfg.managesieve_port = @intCast(value);
        }
    }

    // Apply [milter] section
    if (doc.getSection("milter")) |section| {
        if (section.getBool("enabled")) |value| {
            cfg.enable_milter = value;
        }
    }
}
