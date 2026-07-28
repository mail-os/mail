const std = @import("std");
const mutex_compat = @import("mutex_compat.zig");
const time_compat = @import("time_compat.zig");
const config = @import("config.zig");
const args = @import("args.zig");
const logger = @import("logger.zig");

/// Callback function type for configuration change notifications
pub const ConfigChangeCallback = *const fn (*config.Config) void;

/// Hot reload manager for configuration changes
/// Handles SIGHUP-triggered configuration reloads without server restart
pub const HotReloadManager = struct {
    allocator: std.mem.Allocator,
    current_config: *config.Config,
    config_file_path: ?[]const u8,
    last_reload_time: i64,
    reload_count: u32,
    mutex: mutex_compat.Mutex,
    callbacks: std.ArrayList(ConfigChangeCallback),

    pub fn init(allocator: std.mem.Allocator, cfg: *config.Config, config_file_path: ?[]const u8) HotReloadManager {
        return .{
            .allocator = allocator,
            .current_config = cfg,
            .config_file_path = config_file_path,
            .last_reload_time = time_compat.timestamp(),
            .reload_count = 0,
            .mutex = .{},
            .callbacks = .{ .items = &.{}, .capacity = 0 },
        };
    }

    pub fn deinit(self: *HotReloadManager) void {
        self.callbacks.deinit(self.allocator);
    }

    /// Register a callback to be notified when configuration changes
    pub fn registerCallback(self: *HotReloadManager, callback: ConfigChangeCallback) !void {
        try self.callbacks.append(self.allocator, callback);
    }

    /// Check if reload is requested and perform the reload
    /// Returns true if configuration was reloaded
    pub fn checkAndReload(self: *HotReloadManager, reload_flag: *std.atomic.Value(bool)) bool {
        if (!reload_flag.load(.acquire)) {
            return false;
        }

        // Clear the flag
        reload_flag.store(false, .release);

        // Perform reload
        self.reload() catch |err| {
            logger.err("Configuration reload failed: {}", .{err});
            return false;
        };

        return true;
    }

    /// Reload configuration from file/environment
    pub fn reload(self: *HotReloadManager) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        logger.info("=== Configuration Hot Reload Started ===", .{});

        // Create empty args for reload (CLI args don't change)
        var reload_args = args.Args{};

        // If we have a config file path, use it
        if (self.config_file_path) |path| {
            reload_args.config_file = path;
        }

        // Load new configuration
        const new_config = config.loadConfig(self.allocator, reload_args) catch |err| {
            logger.err("Failed to load new configuration: {}", .{err});
            return err;
        };
        errdefer new_config.deinit(self.allocator);

        // Log changes
        self.logConfigChanges(&new_config);

        // Apply new configuration (swap)
        const old_config = self.current_config.*;
        self.current_config.* = new_config;

        // Release every owned string from the replaced configuration. Keeping
        // a second partial cleanup list here leaked newly added optional fields.
        old_config.deinit(self.allocator);

        // Update reload statistics
        self.last_reload_time = time_compat.timestamp();
        self.reload_count += 1;

        // Notify callbacks
        for (self.callbacks.items) |callback| {
            callback(self.current_config);
        }

        logger.info("=== Configuration Hot Reload Complete (#{d}) ===", .{self.reload_count});
    }

    /// Log configuration changes between old and new config
    fn logConfigChanges(self: *HotReloadManager, new_config: *const config.Config) void {
        const old = self.current_config;

        if (old.port != new_config.port) {
            logger.info("Config change: port {d} -> {d} (requires restart)", .{ old.port, new_config.port });
        }
        if (old.max_connections != new_config.max_connections) {
            logger.info("Config change: max_connections {d} -> {d}", .{ old.max_connections, new_config.max_connections });
        }
        if (old.max_message_size != new_config.max_message_size) {
            logger.info("Config change: max_message_size {d} -> {d}", .{ old.max_message_size, new_config.max_message_size });
        }
        if (old.timeout_seconds != new_config.timeout_seconds) {
            logger.info("Config change: timeout_seconds {d} -> {d}", .{ old.timeout_seconds, new_config.timeout_seconds });
        }
        if (old.rate_limit_per_ip != new_config.rate_limit_per_ip) {
            logger.info("Config change: rate_limit_per_ip {d} -> {d}", .{ old.rate_limit_per_ip, new_config.rate_limit_per_ip });
        }
        if (old.rate_limit_per_user != new_config.rate_limit_per_user) {
            logger.info("Config change: rate_limit_per_user {d} -> {d}", .{ old.rate_limit_per_user, new_config.rate_limit_per_user });
        }
        if (old.enable_tls != new_config.enable_tls) {
            logger.info("Config change: enable_tls {} -> {} (requires restart)", .{ old.enable_tls, new_config.enable_tls });
        }
        if (old.enable_auth != new_config.enable_auth) {
            logger.info("Config change: enable_auth {} -> {} (requires restart)", .{ old.enable_auth, new_config.enable_auth });
        }
        if (old.enable_dnsbl != new_config.enable_dnsbl) {
            logger.info("Config change: enable_dnsbl {} -> {}", .{ old.enable_dnsbl, new_config.enable_dnsbl });
        }
        if (old.enable_greylist != new_config.enable_greylist) {
            logger.info("Config change: enable_greylist {} -> {}", .{ old.enable_greylist, new_config.enable_greylist });
        }
        if (old.enable_tracing != new_config.enable_tracing) {
            logger.info("Config change: enable_tracing {} -> {}", .{ old.enable_tracing, new_config.enable_tracing });
        }
        if (old.enable_json_logging != new_config.enable_json_logging) {
            logger.info("Config change: enable_json_logging {} -> {}", .{ old.enable_json_logging, new_config.enable_json_logging });
        }
    }

    /// Get reload statistics
    pub fn getStats(self: *HotReloadManager) ReloadStats {
        return .{
            .reload_count = self.reload_count,
            .last_reload_time = self.last_reload_time,
        };
    }
};

pub const ReloadStats = struct {
    reload_count: u32,
    last_reload_time: i64,
};

/// Configuration changes that require server restart
pub const RestartRequiredChanges = struct {
    port_changed: bool,
    tls_changed: bool,
    auth_changed: bool,
    host_changed: bool,

    pub fn requiresRestart(self: RestartRequiredChanges) bool {
        return self.port_changed or self.tls_changed or self.auth_changed or self.host_changed;
    }
};

/// Compare two configs and determine what requires restart
pub fn checkRestartRequired(old: *const config.Config, new: *const config.Config) RestartRequiredChanges {
    return .{
        .port_changed = old.port != new.port,
        .tls_changed = old.enable_tls != new.enable_tls,
        .auth_changed = old.enable_auth != new.enable_auth,
        .host_changed = !std.mem.eql(u8, old.host, new.host),
    };
}

// Tests
test "hot reload manager initialization" {
    const testing = std.testing;

    var cfg = config.Config{
        .host = try testing.allocator.dupe(u8, "localhost"),
        .port = 25,
        .max_connections = 100,
        .enable_tls = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .enable_auth = false,
        .max_message_size = 1024 * 1024,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .command_timeout_seconds = 60,
        .greeting_timeout_seconds = 30,
        .rate_limit_per_ip = 100,
        .rate_limit_per_user = 500,
        .rate_limit_cleanup_interval = 3600,
        .max_recipients = 100,
        .hostname = try testing.allocator.dupe(u8, "localhost"),
        .webhook_url = null,
        .webhook_enabled = false,
        .enable_dnsbl = false,
        .enable_greylist = false,
        .enable_tracing = false,
        .tracing_service_name = try testing.allocator.dupe(u8, "test"),
        .enable_json_logging = false,
    };
    defer cfg.deinit(testing.allocator);

    var manager = HotReloadManager.init(testing.allocator, &cfg, null);
    defer manager.deinit();

    try testing.expectEqual(@as(u32, 0), manager.reload_count);
}
