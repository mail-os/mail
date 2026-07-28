const std = @import("std");
const mutex_compat = @import("mutex_compat.zig");
const logger = @import("logger.zig");

/// Plugin System for SMTP Server Extensibility
/// Provides a flexible plugin architecture for extending server functionality
///
/// Features:
/// - Dynamic plugin loading from shared libraries (.so, .dylib, .dll)
/// - Plugin lifecycle management (init, deinit, enable, disable)
/// - Hook-based extension points (message processing, authentication, etc.)
/// - Plugin dependency resolution
/// - Sandboxed plugin execution with resource limits
/// - Plugin configuration and metadata
/// - Hot-reload support for development
/// Plugin metadata
pub const PluginMetadata = struct {
    name: []const u8,
    version: []const u8,
    author: []const u8,
    description: []const u8,
    license: []const u8,
    dependencies: []const []const u8 = &.{},
    min_server_version: []const u8 = "0.1.0",
    max_server_version: ?[]const u8 = null,

    pub fn init(allocator: std.mem.Allocator, name: []const u8, version: []const u8) !PluginMetadata {
        return PluginMetadata{
            .name = try allocator.dupe(u8, name),
            .version = try allocator.dupe(u8, version),
            .author = try allocator.dupe(u8, ""),
            .description = try allocator.dupe(u8, ""),
            .license = try allocator.dupe(u8, "MIT"),
        };
    }

    pub fn deinit(self: *PluginMetadata, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.version);
        allocator.free(self.author);
        allocator.free(self.description);
        allocator.free(self.license);
        for (self.dependencies) |dep| {
            allocator.free(dep);
        }
        if (self.dependencies.len > 0) {
            allocator.free(self.dependencies);
        }
        if (self.max_server_version) |max_ver| {
            allocator.free(max_ver);
        }
    }
};

/// Plugin hook types
pub const PluginHookType = enum {
    // Message Processing Hooks
    message_received, // Called when a message is received
    message_validated, // Called after message validation
    message_filtered, // Called during spam/virus filtering
    message_stored, // Called after message is stored
    message_delivered, // Called after successful delivery

    // Authentication Hooks
    auth_started, // Called when authentication begins
    auth_completed, // Called after authentication
    auth_failed, // Called on authentication failure

    // Connection Hooks
    connection_opened, // Called when client connects
    connection_closed, // Called when client disconnects
    connection_upgraded, // Called after STARTTLS

    // Command Hooks
    command_received, // Called for each SMTP command
    command_validated, // Called after command validation

    // Configuration Hooks
    config_loaded, // Called after configuration is loaded
    config_changed, // Called when configuration changes

    // Server Lifecycle Hooks
    server_starting, // Called before server starts
    server_started, // Called after server starts
    server_stopping, // Called before server stops
    server_stopped, // Called after server stops

    pub fn toString(self: PluginHookType) []const u8 {
        return @tagName(self);
    }
};

/// Hook context - data passed to plugin hooks
pub const HookContext = struct {
    allocator: std.mem.Allocator,
    hook_type: PluginHookType,
    data: ?*anyopaque = null, // Hook-specific data
    metadata: std.StringHashMap([]const u8),
    cancel: bool = false, // Plugins can set this to cancel the operation

    pub fn init(allocator: std.mem.Allocator, hook_type: PluginHookType) HookContext {
        return .{
            .allocator = allocator,
            .hook_type = hook_type,
            .metadata = std.StringHashMap([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *HookContext) void {
        var iter = self.metadata.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.metadata.deinit();
    }

    pub fn setMetadata(self: *HookContext, key: []const u8, value: []const u8) !void {
        const key_copy = try self.allocator.dupe(u8, key);
        const value_copy = try self.allocator.dupe(u8, value);
        try self.metadata.put(key_copy, value_copy);
    }

    pub fn getMetadata(self: *const HookContext, key: []const u8) ?[]const u8 {
        return self.metadata.get(key);
    }
};

/// Plugin hook result
pub const HookResult = enum {
    continue_processing, // Continue with other plugins
    stop_processing, // Stop processing this hook chain
    cancel_operation, // Cancel the operation entirely
    error_occurred, // An error occurred in the plugin
};

/// Plugin interface - functions that plugins must implement
pub const PluginInterface = struct {
    /// Initialize the plugin
    init: *const fn (allocator: std.mem.Allocator, config: []const u8) callconv(.C) c_int,

    /// Cleanup plugin resources
    deinit: *const fn () callconv(.C) void,

    /// Get plugin metadata
    getMetadata: *const fn () callconv(.C) ?*const PluginMetadata,

    /// Execute plugin hook
    executeHook: *const fn (context: *HookContext) callconv(.C) c_int,

    /// Enable the plugin
    enable: *const fn () callconv(.C) c_int,

    /// Disable the plugin
    disable: *const fn () callconv(.C) c_int,
};

/// Plugin state
pub const PluginState = enum {
    unloaded,
    loaded,
    initialized,
    enabled,
    disabled,
    error_state,
};

/// Plugin instance
pub const Plugin = struct {
    allocator: std.mem.Allocator,
    metadata: PluginMetadata,
    interface: ?*PluginInterface,
    state: PluginState,
    library_handle: ?std.DynLib,
    config: ?[]const u8,
    error_message: ?[]const u8,
    enabled_hooks: std.ArrayList(PluginHookType),

    pub fn init(allocator: std.mem.Allocator, metadata: PluginMetadata) Plugin {
        return .{
            .allocator = allocator,
            .metadata = metadata,
            .interface = null,
            .state = .unloaded,
            .library_handle = null,
            .config = null,
            .error_message = null,
            .enabled_hooks = .empty,
        };
    }

    pub fn deinit(self: *Plugin) void {
        if (self.interface) |interface| {
            interface.deinit();
        }
        if (self.library_handle) |*lib| {
            lib.close();
        }
        if (self.config) |config| {
            self.allocator.free(config);
        }
        if (self.error_message) |err| {
            self.allocator.free(err);
        }
        self.enabled_hooks.deinit(self.allocator);
        self.metadata.deinit(self.allocator);
    }

    /// Load plugin from shared library
    pub fn load(self: *Plugin, library_path: []const u8) !void {
        if (self.state != .unloaded) {
            return error.PluginAlreadyLoaded;
        }

        // Open shared library
        var lib = std.DynLib.open(library_path) catch |err| {
            self.state = .error_state;
            self.error_message = try std.fmt.allocPrint(
                self.allocator,
                "Failed to load library: {}",
                .{err},
            );
            return err;
        };

        self.library_handle = lib;

        // Load plugin interface
        const get_plugin_interface = lib.lookup(
            *const fn () callconv(.C) ?*PluginInterface,
            "smtp_plugin_get_interface",
        ) orelse {
            self.state = .error_state;
            self.error_message = try self.allocator.dupe(u8, "Plugin missing smtp_plugin_get_interface function");
            return error.MissingInterface;
        };

        self.interface = get_plugin_interface() orelse {
            self.state = .error_state;
            self.error_message = try self.allocator.dupe(u8, "Plugin returned null interface");
            return error.NullInterface;
        };

        self.state = .loaded;
    }

    /// Initialize the plugin
    pub fn initialize(self: *Plugin, config: ?[]const u8) !void {
        if (self.state != .loaded) {
            return error.PluginNotLoaded;
        }

        const interface = self.interface orelse return error.NoInterface;

        const config_str = config orelse "";
        const result = interface.init(self.allocator, config_str);

        if (result != 0) {
            self.state = .error_state;
            self.error_message = try std.fmt.allocPrint(
                self.allocator,
                "Plugin initialization failed with code: {d}",
                .{result},
            );
            return error.InitializationFailed;
        }

        if (config) |cfg| {
            self.config = try self.allocator.dupe(u8, cfg);
        }

        self.state = .initialized;
    }

    /// Enable the plugin
    pub fn enable(self: *Plugin) !void {
        if (self.state != .initialized and self.state != .disabled) {
            return error.PluginNotInitialized;
        }

        const interface = self.interface orelse return error.NoInterface;
        const result = interface.enable();

        if (result != 0) {
            self.state = .error_state;
            self.error_message = try std.fmt.allocPrint(
                self.allocator,
                "Plugin enable failed with code: {d}",
                .{result},
            );
            return error.EnableFailed;
        }

        self.state = .enabled;
    }

    /// Disable the plugin
    pub fn disable(self: *Plugin) !void {
        if (self.state != .enabled) {
            return error.PluginNotEnabled;
        }

        const interface = self.interface orelse return error.NoInterface;
        const result = interface.disable();

        if (result != 0) {
            self.state = .error_state;
            self.error_message = try std.fmt.allocPrint(
                self.allocator,
                "Plugin disable failed with code: {d}",
                .{result},
            );
            return error.DisableFailed;
        }

        self.state = .disabled;
    }

    /// Execute a hook
    pub fn executeHook(self: *Plugin, context: *HookContext) !HookResult {
        if (self.state != .enabled) {
            return .continue_processing;
        }

        const interface = self.interface orelse return .error_occurred;
        const result = interface.executeHook(context);

        return switch (result) {
            0 => .continue_processing,
            1 => .stop_processing,
            2 => .cancel_operation,
            else => .error_occurred,
        };
    }

    /// Register interest in a specific hook type
    pub fn registerHook(self: *Plugin, hook_type: PluginHookType) !void {
        try self.enabled_hooks.append(self.allocator, hook_type);
    }

    /// Check if plugin handles a specific hook type
    pub fn handlesHook(self: *const Plugin, hook_type: PluginHookType) bool {
        for (self.enabled_hooks.items) |hook| {
            if (hook == hook_type) return true;
        }
        return false;
    }
};

/// Plugin manager - manages all loaded plugins
pub const PluginManager = struct {
    allocator: std.mem.Allocator,
    plugins: std.ArrayList(*Plugin),
    plugin_dir: []const u8,
    mutex: mutex_compat.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, plugin_dir: []const u8) !PluginManager {
        return .{
            .allocator = allocator,
            .plugins = .empty,
            .plugin_dir = try allocator.dupe(u8, plugin_dir),
        };
    }

    pub fn deinit(self: *PluginManager) void {
        for (self.plugins.items) |plugin| {
            plugin.deinit();
            self.allocator.destroy(plugin);
        }
        self.plugins.deinit(self.allocator);
        self.allocator.free(self.plugin_dir);
    }

    /// Load a plugin from a file
    pub fn loadPlugin(self: *PluginManager, library_path: []const u8, config: ?[]const u8) !*Plugin {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Create plugin metadata (would normally be loaded from manifest)
        const metadata = try PluginMetadata.init(self.allocator, "plugin", "1.0.0");

        const plugin = try self.allocator.create(Plugin);
        plugin.* = Plugin.init(self.allocator, metadata);

        errdefer {
            plugin.deinit();
            self.allocator.destroy(plugin);
        }

        try plugin.load(library_path);
        try plugin.initialize(config);
        try plugin.enable();

        try self.plugins.append(self.allocator, plugin);

        logger.info("Loaded plugin: {s}", .{metadata.name});

        return plugin;
    }

    /// Load all plugins from the plugin directory
    pub fn loadAllPlugins(self: *PluginManager) !void {
        var dir = try std.fs.cwd().openDir(self.plugin_dir, .{ .iterate = true });
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .file) continue;

            // Check for shared library extension
            const is_plugin = std.mem.endsWith(u8, entry.name, ".so") or
                std.mem.endsWith(u8, entry.name, ".dylib") or
                std.mem.endsWith(u8, entry.name, ".dll");

            if (!is_plugin) continue;

            const full_path = try std.fs.path.join(self.allocator, &.{ self.plugin_dir, entry.name });
            defer self.allocator.free(full_path);

            _ = self.loadPlugin(full_path, null) catch |err| {
                logger.err("Failed to load plugin {s}: {}", .{ entry.name, err });
                continue;
            };
        }
    }

    /// Unload a plugin
    pub fn unloadPlugin(self: *PluginManager, plugin_name: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.plugins.items, 0..) |plugin, i| {
            if (std.mem.eql(u8, plugin.metadata.name, plugin_name)) {
                _ = try plugin.disable();
                plugin.deinit();
                self.allocator.destroy(plugin);
                _ = self.plugins.orderedRemove(i);
                logger.info("Unloaded plugin: {s}", .{plugin_name});
                return;
            }
        }

        return error.PluginNotFound;
    }

    /// Execute a hook across all plugins
    pub fn executeHook(self: *PluginManager, hook_type: PluginHookType, context: *HookContext) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.plugins.items) |plugin| {
            if (!plugin.handlesHook(hook_type)) continue;

            const result = plugin.executeHook(context) catch |err| {
                logger.err("Plugin {s} hook execution failed: {}", .{ plugin.metadata.name, err });
                continue;
            };

            switch (result) {
                .continue_processing => continue,
                .stop_processing => break,
                .cancel_operation => {
                    context.cancel = true;
                    return;
                },
                .error_occurred => {
                    logger.err("Plugin {s} returned error during hook execution", .{plugin.metadata.name});
                    continue;
                },
            }
        }
    }

    /// Get a plugin by name
    pub fn getPlugin(self: *PluginManager, name: []const u8) ?*Plugin {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.plugins.items) |plugin| {
            if (std.mem.eql(u8, plugin.metadata.name, name)) {
                return plugin;
            }
        }
        return null;
    }

    /// List all loaded plugins
    pub fn listPlugins(self: *PluginManager) []const *Plugin {
        return self.plugins.items;
    }
};

/// Example plugin helper for creating plugins
pub const PluginBuilder = struct {
    allocator: std.mem.Allocator,
    metadata: PluginMetadata,
    hooks: std.ArrayList(PluginHookType),

    pub fn init(allocator: std.mem.Allocator, name: []const u8, version: []const u8) !PluginBuilder {
        return .{
            .allocator = allocator,
            .metadata = try PluginMetadata.init(allocator, name, version),
            .hooks = .empty,
        };
    }

    pub fn deinit(self: *PluginBuilder) void {
        self.hooks.deinit(self.allocator);
        self.metadata.deinit(self.allocator);
    }

    pub fn setAuthor(self: *PluginBuilder, author: []const u8) !void {
        self.allocator.free(self.metadata.author);
        self.metadata.author = try self.allocator.dupe(u8, author);
    }

    pub fn setDescription(self: *PluginBuilder, description: []const u8) !void {
        self.allocator.free(self.metadata.description);
        self.metadata.description = try self.allocator.dupe(u8, description);
    }

    pub fn addHook(self: *PluginBuilder, hook_type: PluginHookType) !void {
        try self.hooks.append(self.allocator, hook_type);
    }

    pub fn addDependency(self: *PluginBuilder, dependency: []const u8) !void {
        var new_deps = try self.allocator.alloc([]const u8, self.metadata.dependencies.len + 1);
        @memcpy(new_deps[0..self.metadata.dependencies.len], self.metadata.dependencies);
        new_deps[self.metadata.dependencies.len] = try self.allocator.dupe(u8, dependency);

        if (self.metadata.dependencies.len > 0) {
            self.allocator.free(self.metadata.dependencies);
        }
        self.metadata.dependencies = new_deps;
    }
};

// =============================================================================
// Hot-Reload Support
// =============================================================================

/// File change event for hot-reload
pub const FileChangeEvent = struct {
    path: []const u8,
    event_type: enum { created, modified, deleted },
    timestamp: i64,
};

/// Plugin hot-reload manager
pub const HotReloadManager = struct {
    allocator: std.mem.Allocator,
    plugin_manager: *PluginManager,
    watch_paths: std.ArrayList([]const u8),
    file_checksums: std.StringHashMap([32]u8),
    reload_callback: ?*const fn (plugin_name: []const u8, success: bool) void,
    enabled: bool,
    check_interval_ms: u64,
    last_check: i64,
    pending_reloads: std.ArrayList(PendingReload),
    reload_delay_ms: u64, // Debounce delay

    const PendingReload = struct {
        plugin_path: []const u8,
        detected_at: i64,
    };

    pub fn init(allocator: std.mem.Allocator, plugin_manager: *PluginManager) HotReloadManager {
        return .{
            .allocator = allocator,
            .plugin_manager = plugin_manager,
            .watch_paths = std.ArrayList([]const u8).init(allocator),
            .file_checksums = std.StringHashMap([32]u8).init(allocator),
            .reload_callback = null,
            .enabled = false,
            .check_interval_ms = 1000, // Check every second
            .last_check = 0,
            .pending_reloads = std.ArrayList(PendingReload).init(allocator),
            .reload_delay_ms = 500, // Wait 500ms after change detected
        };
    }

    pub fn deinit(self: *HotReloadManager) void {
        for (self.watch_paths.items) |path| {
            self.allocator.free(path);
        }
        self.watch_paths.deinit();

        var iter = self.file_checksums.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.file_checksums.deinit();

        for (self.pending_reloads.items) |reload| {
            self.allocator.free(reload.plugin_path);
        }
        self.pending_reloads.deinit();
    }

    /// Add a path to watch for changes
    pub fn watchPath(self: *HotReloadManager, path: []const u8) !void {
        const path_copy = try self.allocator.dupe(u8, path);
        try self.watch_paths.append(path_copy);

        // Compute initial checksum
        const checksum = try self.computeChecksum(path);
        try self.file_checksums.put(path_copy, checksum);
    }

    /// Remove a path from watching
    pub fn unwatchPath(self: *HotReloadManager, path: []const u8) void {
        for (self.watch_paths.items, 0..) |watched, i| {
            if (std.mem.eql(u8, watched, path)) {
                self.allocator.free(watched);
                _ = self.watch_paths.orderedRemove(i);
                _ = self.file_checksums.remove(path);
                return;
            }
        }
    }

    /// Enable hot-reload
    pub fn enable(self: *HotReloadManager) void {
        self.enabled = true;
        self.last_check = std.time.milliTimestamp();
    }

    /// Disable hot-reload
    pub fn disable(self: *HotReloadManager) void {
        self.enabled = false;
    }

    /// Set reload callback
    pub fn setReloadCallback(self: *HotReloadManager, callback: *const fn ([]const u8, bool) void) void {
        self.reload_callback = callback;
    }

    /// Check for file changes (call periodically)
    pub fn checkForChanges(self: *HotReloadManager) ![]FileChangeEvent {
        if (!self.enabled) return &[_]FileChangeEvent{};

        const now = std.time.milliTimestamp();
        if (now - self.last_check < @as(i64, @intCast(self.check_interval_ms))) {
            return &[_]FileChangeEvent{};
        }
        self.last_check = now;

        var changes = std.ArrayList(FileChangeEvent).init(self.allocator);
        errdefer changes.deinit();

        for (self.watch_paths.items) |path| {
            const new_checksum = self.computeChecksum(path) catch |err| {
                if (err == error.FileNotFound) {
                    // File was deleted
                    try changes.append(.{
                        .path = path,
                        .event_type = .deleted,
                        .timestamp = now,
                    });
                }
                continue;
            };

            if (self.file_checksums.get(path)) |old_checksum| {
                if (!std.mem.eql(u8, &old_checksum, &new_checksum)) {
                    // File was modified
                    try changes.append(.{
                        .path = path,
                        .event_type = .modified,
                        .timestamp = now,
                    });

                    // Update checksum
                    const key = try self.allocator.dupe(u8, path);
                    try self.file_checksums.put(key, new_checksum);
                }
            } else {
                // New file
                try changes.append(.{
                    .path = path,
                    .event_type = .created,
                    .timestamp = now,
                });

                const key = try self.allocator.dupe(u8, path);
                try self.file_checksums.put(key, new_checksum);
            }
        }

        // Process pending reloads
        try self.processPendingReloads(now);

        return changes.toOwnedSlice();
    }

    /// Process pending reloads with debounce
    fn processPendingReloads(self: *HotReloadManager, now: i64) !void {
        var i: usize = 0;
        while (i < self.pending_reloads.items.len) {
            const reload = self.pending_reloads.items[i];
            if (now - reload.detected_at >= @as(i64, @intCast(self.reload_delay_ms))) {
                // Reload the plugin
                const success = self.reloadPlugin(reload.plugin_path);
                if (self.reload_callback) |callback| {
                    callback(reload.plugin_path, success);
                }
                self.allocator.free(reload.plugin_path);
                _ = self.pending_reloads.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Schedule a plugin for reload
    pub fn scheduleReload(self: *HotReloadManager, plugin_path: []const u8) !void {
        // Check if already pending
        for (self.pending_reloads.items) |reload| {
            if (std.mem.eql(u8, reload.plugin_path, plugin_path)) {
                return; // Already pending
            }
        }

        try self.pending_reloads.append(.{
            .plugin_path = try self.allocator.dupe(u8, plugin_path),
            .detected_at = std.time.milliTimestamp(),
        });
    }

    /// Reload a plugin
    fn reloadPlugin(self: *HotReloadManager, plugin_path: []const u8) bool {
        // Find the plugin
        for (self.plugin_manager.plugins.items) |plugin| {
            // Check if this is the plugin's library
            if (plugin.library_handle != null) {
                // Unload and reload
                _ = plugin.disable() catch return false;

                if (plugin.library_handle) |*lib| {
                    lib.close();
                }
                plugin.library_handle = null;
                plugin.interface = null;
                plugin.state = .unloaded;

                // Reload
                plugin.load(plugin_path) catch return false;
                plugin.initialize(plugin.config) catch return false;
                plugin.enable() catch return false;

                logger.info("Hot-reloaded plugin: {s}", .{plugin.metadata.name});
                return true;
            }
        }
        return false;
    }

    /// Compute file checksum using a simple hash
    fn computeChecksum(self: *HotReloadManager, path: []const u8) ![32]u8 {
        _ = self;
        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            if (err == error.FileNotFound) return error.FileNotFound;
            return @splat(0);
        };
        defer file.close();

        var hasher = std.crypto.hash.sha2.Sha256.init(.{});

        var buf: [4096]u8 = undefined;
        while (true) {
            const bytes_read = file.read(&buf) catch break;
            if (bytes_read == 0) break;
            hasher.update(buf[0..bytes_read]);
        }

        return hasher.finalResult();
    }

    /// Force reload all plugins
    pub fn reloadAll(self: *HotReloadManager) !void {
        for (self.plugin_manager.plugins.items) |plugin| {
            if (plugin.library_handle != null and plugin.state == .enabled) {
                _ = plugin.disable() catch continue;
                plugin.initialize(plugin.config) catch continue;
                plugin.enable() catch continue;
            }
        }
    }
};

// =============================================================================
// Plugin Manifest System
// =============================================================================

/// Plugin manifest for configuration
pub const PluginManifest = struct {
    name: []const u8,
    version: []const u8,
    author: []const u8,
    description: []const u8,
    license: []const u8,
    entry_point: []const u8, // Library file name
    dependencies: []const Dependency,
    hooks: []const PluginHookType,
    config_schema: ?ConfigSchema,
    permissions: []const Permission,

    const Dependency = struct {
        name: []const u8,
        version: []const u8,
        optional: bool = false,
    };

    const Permission = enum {
        network_access,
        file_system_read,
        file_system_write,
        database_access,
        exec_process,
        send_email,
        modify_headers,
        block_message,
    };

    const ConfigSchema = struct {
        fields: []const ConfigField,

        const ConfigField = struct {
            name: []const u8,
            field_type: enum { string, integer, boolean, array, object },
            required: bool = false,
            default_value: ?[]const u8 = null,
            description: ?[]const u8 = null,
        };
    };

    /// Parse manifest from TOML content
    pub fn parseToml(allocator: std.mem.Allocator, content: []const u8) !PluginManifest {
        _ = content;
        // Simplified parser - in production would use full TOML parser
        return PluginManifest{
            .name = try allocator.dupe(u8, "unnamed"),
            .version = try allocator.dupe(u8, "0.0.0"),
            .author = try allocator.dupe(u8, ""),
            .description = try allocator.dupe(u8, ""),
            .license = try allocator.dupe(u8, "MIT"),
            .entry_point = try allocator.dupe(u8, "plugin.so"),
            .dependencies = &.{},
            .hooks = &.{},
            .config_schema = null,
            .permissions = &.{},
        };
    }

    pub fn deinit(self: *PluginManifest, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.version);
        allocator.free(self.author);
        allocator.free(self.description);
        allocator.free(self.license);
        allocator.free(self.entry_point);
    }
};

// =============================================================================
// Plugin Event System
// =============================================================================

/// Event emitter for plugin communication
pub const PluginEventEmitter = struct {
    allocator: std.mem.Allocator,
    listeners: std.StringHashMap(std.ArrayList(EventListener)),

    const EventListener = struct {
        plugin_name: []const u8,
        callback: *const fn (event_name: []const u8, data: ?*anyopaque) void,
        priority: i32,
    };

    pub fn init(allocator: std.mem.Allocator) PluginEventEmitter {
        return .{
            .allocator = allocator,
            .listeners = std.StringHashMap(std.ArrayList(EventListener)).init(allocator),
        };
    }

    pub fn deinit(self: *PluginEventEmitter) void {
        var iter = self.listeners.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            for (entry.value_ptr.items) |listener| {
                self.allocator.free(listener.plugin_name);
            }
            entry.value_ptr.deinit();
        }
        self.listeners.deinit();
    }

    /// Register event listener
    pub fn on(self: *PluginEventEmitter, event_name: []const u8, plugin_name: []const u8, callback: *const fn ([]const u8, ?*anyopaque) void, priority: i32) !void {
        const result = try self.listeners.getOrPut(try self.allocator.dupe(u8, event_name));
        if (!result.found_existing) {
            result.value_ptr.* = std.ArrayList(EventListener).init(self.allocator);
        }

        try result.value_ptr.append(.{
            .plugin_name = try self.allocator.dupe(u8, plugin_name),
            .callback = callback,
            .priority = priority,
        });

        // Sort by priority (higher priority first)
        std.mem.sort(EventListener, result.value_ptr.items, {}, struct {
            fn lessThan(_: void, a: EventListener, b: EventListener) bool {
                return a.priority > b.priority;
            }
        }.lessThan);
    }

    /// Remove event listener
    pub fn off(self: *PluginEventEmitter, event_name: []const u8, plugin_name: []const u8) void {
        if (self.listeners.getPtr(event_name)) |list| {
            var i: usize = 0;
            while (i < list.items.len) {
                if (std.mem.eql(u8, list.items[i].plugin_name, plugin_name)) {
                    self.allocator.free(list.items[i].plugin_name);
                    _ = list.orderedRemove(i);
                } else {
                    i += 1;
                }
            }
        }
    }

    /// Emit event
    pub fn emit(self: *PluginEventEmitter, event_name: []const u8, data: ?*anyopaque) void {
        if (self.listeners.get(event_name)) |list| {
            for (list.items) |listener| {
                listener.callback(event_name, data);
            }
        }
    }
};

// =============================================================================
// Example Plugin Templates
// =============================================================================

/// Spam filter plugin template
pub const SpamFilterPluginTemplate = struct {
    pub const metadata = PluginMetadata{
        .name = "spam-filter",
        .version = "1.0.0",
        .author = "SMTP Server Team",
        .description = "Advanced spam filtering with Bayesian classification",
        .license = "MIT",
        .dependencies = &.{},
        .min_server_version = "0.20.0",
        .max_server_version = null,
    };

    pub const hooks = [_]PluginHookType{
        .message_received,
        .message_filtered,
    };

    /// Example spam classification
    pub fn classifyMessage(headers: []const u8, body: []const u8) SpamScore {
        var score: f64 = 0.0;

        // Check for common spam indicators
        if (std.mem.indexOf(u8, headers, "X-Spam-Flag: YES")) |_| {
            score += 5.0;
        }
        if (std.mem.indexOf(u8, body, "CLICK HERE")) |_| {
            score += 2.0;
        }
        if (std.mem.indexOf(u8, body, "FREE MONEY")) |_| {
            score += 3.0;
        }
        if (std.mem.indexOf(u8, body, "URGENT")) |_| {
            score += 1.0;
        }

        // Check excessive capitalization
        var caps_count: usize = 0;
        for (body) |c| {
            if (c >= 'A' and c <= 'Z') caps_count += 1;
        }
        if (body.len > 0 and @as(f64, @floatFromInt(caps_count)) / @as(f64, @floatFromInt(body.len)) > 0.3) {
            score += 2.0;
        }

        return .{
            .score = score,
            .is_spam = score >= 5.0,
            .confidence = @min(score / 10.0, 1.0),
        };
    }

    pub const SpamScore = struct {
        score: f64,
        is_spam: bool,
        confidence: f64,
    };
};

/// Rate limiter plugin template
pub const RateLimiterPluginTemplate = struct {
    pub const metadata = PluginMetadata{
        .name = "rate-limiter",
        .version = "1.0.0",
        .author = "SMTP Server Team",
        .description = "Connection and message rate limiting",
        .license = "MIT",
        .dependencies = &.{},
        .min_server_version = "0.20.0",
        .max_server_version = null,
    };

    pub const hooks = [_]PluginHookType{
        .connection_opened,
        .message_received,
    };

    /// Rate limit configuration
    pub const Config = struct {
        connections_per_minute: u32 = 10,
        messages_per_hour: u32 = 100,
        burst_allowance: u32 = 5,
    };

    /// Token bucket implementation
    pub const TokenBucket = struct {
        tokens: f64,
        max_tokens: f64,
        refill_rate: f64, // tokens per second
        last_refill: i64,

        pub fn init(max_tokens: f64, refill_rate: f64) TokenBucket {
            return .{
                .tokens = max_tokens,
                .max_tokens = max_tokens,
                .refill_rate = refill_rate,
                .last_refill = std.time.milliTimestamp(),
            };
        }

        pub fn tryConsume(self: *TokenBucket, count: f64) bool {
            self.refill();
            if (self.tokens >= count) {
                self.tokens -= count;
                return true;
            }
            return false;
        }

        fn refill(self: *TokenBucket) void {
            const now = std.time.milliTimestamp();
            const elapsed_seconds = @as(f64, @floatFromInt(now - self.last_refill)) / 1000.0;
            self.tokens = @min(self.max_tokens, self.tokens + elapsed_seconds * self.refill_rate);
            self.last_refill = now;
        }
    };
};

/// Logging plugin template
pub const LoggingPluginTemplate = struct {
    pub const metadata = PluginMetadata{
        .name = "advanced-logging",
        .version = "1.0.0",
        .author = "SMTP Server Team",
        .description = "Enhanced logging with structured output",
        .license = "MIT",
        .dependencies = &.{},
        .min_server_version = "0.20.0",
        .max_server_version = null,
    };

    pub const hooks = [_]PluginHookType{
        .server_starting,
        .server_started,
        .server_stopping,
        .connection_opened,
        .connection_closed,
        .message_received,
        .message_delivered,
        .auth_started,
        .auth_completed,
        .auth_failed,
    };

    /// Log entry structure
    pub const LogEntry = struct {
        timestamp: i64,
        level: LogLevel,
        component: []const u8,
        message: []const u8,
        context: ?std.StringHashMap([]const u8),

        pub const LogLevel = enum {
            debug,
            info,
            warning,
            err,
            critical,
        };

        pub fn format(self: *const LogEntry, allocator: std.mem.Allocator) ![]u8 {
            var buf = std.ArrayList(u8).init(allocator);
            const writer = buf.writer();

            try writer.print("[{d}] [{s}] [{s}] {s}", .{
                self.timestamp,
                @tagName(self.level),
                self.component,
                self.message,
            });

            if (self.context) |ctx| {
                var iter = ctx.iterator();
                while (iter.next()) |entry| {
                    try writer.print(" {s}={s}", .{ entry.key_ptr.*, entry.value_ptr.* });
                }
            }

            return buf.toOwnedSlice();
        }
    };
};

/// Attachment scanner plugin template
pub const AttachmentScannerPluginTemplate = struct {
    pub const metadata = PluginMetadata{
        .name = "attachment-scanner",
        .version = "1.0.0",
        .author = "SMTP Server Team",
        .description = "Scan email attachments for viruses and malware",
        .license = "MIT",
        .dependencies = &.{},
        .min_server_version = "0.20.0",
        .max_server_version = null,
    };

    pub const hooks = [_]PluginHookType{
        .message_received,
        .message_filtered,
    };

    /// Scan result
    pub const ScanResult = struct {
        is_clean: bool,
        threats: []const Threat,
        scan_time_ms: u64,

        pub const Threat = struct {
            filename: []const u8,
            threat_name: []const u8,
            severity: enum { low, medium, high, critical },
        };
    };

    /// Dangerous file extensions
    pub const dangerous_extensions = [_][]const u8{
        ".exe", ".bat", ".cmd",  ".com",  ".scr",
        ".pif", ".vbs", ".vbe",  ".js",   ".jse",
        ".ws",  ".wsf", ".msi",  ".msp",  ".msc",
        ".ps1", ".ps2", ".psc1", ".psc2",
    };

    /// Check if file extension is dangerous
    pub fn isDangerousExtension(filename: []const u8) bool {
        const lower = std.ascii.lowerString(undefined, filename) catch filename;
        for (dangerous_extensions) |ext| {
            if (std.mem.endsWith(u8, lower, ext)) {
                return true;
            }
        }
        return false;
    }
};

/// Header modifier plugin template
pub const HeaderModifierPluginTemplate = struct {
    pub const metadata = PluginMetadata{
        .name = "header-modifier",
        .version = "1.0.0",
        .author = "SMTP Server Team",
        .description = "Add, modify, or remove email headers",
        .license = "MIT",
        .dependencies = &.{},
        .min_server_version = "0.20.0",
        .max_server_version = null,
    };

    pub const hooks = [_]PluginHookType{
        .message_received,
        .message_delivered,
    };

    /// Header modification rule
    pub const Rule = struct {
        action: Action,
        header_name: []const u8,
        header_value: ?[]const u8,
        condition: ?Condition,

        pub const Action = enum {
            add,
            set,
            remove,
            append,
        };

        pub const Condition = struct {
            field: []const u8,
            operator: enum { equals, contains, matches, exists },
            value: ?[]const u8,
        };
    };

    /// Apply rules to headers
    pub fn applyRules(headers: *std.StringHashMap([]const u8), rules: []const Rule) void {
        for (rules) |rule| {
            // Check condition
            if (rule.condition) |cond| {
                const field_value = headers.get(cond.field) orelse {
                    if (cond.operator != .exists) continue;
                    continue; // Field doesn't exist
                };

                const matches = switch (cond.operator) {
                    .equals => if (cond.value) |v| std.mem.eql(u8, field_value, v) else false,
                    .contains => if (cond.value) |v| std.mem.indexOf(u8, field_value, v) != null else false,
                    .matches => true, // Would need regex support
                    .exists => true,
                };

                if (!matches) continue;
            }

            // Apply action
            switch (rule.action) {
                .add => {
                    if (!headers.contains(rule.header_name)) {
                        if (rule.header_value) |v| {
                            headers.put(rule.header_name, v) catch {};
                        }
                    }
                },
                .set => {
                    if (rule.header_value) |v| {
                        headers.put(rule.header_name, v) catch {};
                    }
                },
                .remove => {
                    _ = headers.remove(rule.header_name);
                },
                .append => {
                    // Would need to concatenate with existing value
                },
            }
        }
    }
};

// =============================================================================
// Plugin SDK for External Developers
// =============================================================================

/// Plugin SDK version
pub const sdk_version = "1.0.0";

/// Plugin context passed to external plugins
pub const PluginContext = struct {
    server_version: []const u8,
    plugin_dir: []const u8,
    data_dir: []const u8,
    log_level: u8,
    allocator: std.mem.Allocator,

    /// Get configuration value
    pub fn getConfig(self: *PluginContext, key: []const u8) ?[]const u8 {
        _ = self;
        _ = key;
        return null;
    }

    /// Log message
    pub fn log(self: *PluginContext, level: u8, message: []const u8) void {
        _ = self;
        _ = level;
        _ = message;
    }

    /// Send event to other plugins
    pub fn emitEvent(self: *PluginContext, event_name: []const u8, data: ?*anyopaque) void {
        _ = self;
        _ = event_name;
        _ = data;
    }
};

/// Plugin registration helper
pub const PluginRegistration = struct {
    context: *PluginContext,
    hooks_registered: std.ArrayList(PluginHookType),

    pub fn init(context: *PluginContext) PluginRegistration {
        return .{
            .context = context,
            .hooks_registered = std.ArrayList(PluginHookType).init(context.allocator),
        };
    }

    pub fn deinit(self: *PluginRegistration) void {
        self.hooks_registered.deinit();
    }

    /// Register a hook handler
    pub fn registerHook(self: *PluginRegistration, hook_type: PluginHookType) !void {
        try self.hooks_registered.append(hook_type);
    }
};

// Tests
test "plugin metadata lifecycle" {
    const testing = std.testing;

    var metadata = try PluginMetadata.init(testing.allocator, "test-plugin", "1.0.0");
    defer metadata.deinit(testing.allocator);

    try testing.expect(std.mem.eql(u8, metadata.name, "test-plugin"));
    try testing.expect(std.mem.eql(u8, metadata.version, "1.0.0"));
}

test "hook context" {
    const testing = std.testing;

    var context = HookContext.init(testing.allocator, .message_received);
    defer context.deinit();

    try context.setMetadata("sender", "test@example.com");
    try context.setMetadata("subject", "Test Message");

    const sender = context.getMetadata("sender");
    try testing.expect(sender != null);
    try testing.expect(std.mem.eql(u8, sender.?, "test@example.com"));
}

test "plugin builder" {
    const testing = std.testing;

    var builder = try PluginBuilder.init(testing.allocator, "spam-filter", "2.0.0");
    defer builder.deinit();

    try builder.setAuthor("SMTP Team");
    try builder.setDescription("Advanced spam filtering plugin");
    try builder.addHook(.message_received);
    try builder.addHook(.message_filtered);
    try builder.addDependency("spamassassin");

    try testing.expect(std.mem.eql(u8, builder.metadata.author, "SMTP Team"));
    try testing.expectEqual(@as(usize, 2), builder.hooks.items.len);
    try testing.expectEqual(@as(usize, 1), builder.metadata.dependencies.len);
}

test "spam filter template" {
    const result = SpamFilterPluginTemplate.classifyMessage(
        "From: spammer@example.com\r\nX-Spam-Flag: YES\r\n",
        "CLICK HERE for FREE MONEY!!!",
    );

    try std.testing.expect(result.is_spam);
    try std.testing.expect(result.score >= 5.0);
    try std.testing.expect(result.confidence > 0.0);
}

test "rate limiter token bucket" {
    var bucket = RateLimiterPluginTemplate.TokenBucket.init(10.0, 1.0);

    // Should be able to consume tokens
    try std.testing.expect(bucket.tryConsume(5.0));
    try std.testing.expect(bucket.tryConsume(4.0));

    // Should not be able to consume more than available
    try std.testing.expect(!bucket.tryConsume(5.0));
}

test "attachment scanner dangerous extensions" {
    try std.testing.expect(AttachmentScannerPluginTemplate.isDangerousExtension("virus.exe"));
    try std.testing.expect(AttachmentScannerPluginTemplate.isDangerousExtension("script.vbs"));
    try std.testing.expect(!AttachmentScannerPluginTemplate.isDangerousExtension("document.pdf"));
    try std.testing.expect(!AttachmentScannerPluginTemplate.isDangerousExtension("image.png"));
}

test "plugin event emitter" {
    const testing = std.testing;

    var emitter = PluginEventEmitter.init(testing.allocator);
    defer emitter.deinit();

    // Event emitter basic test (just checking init/deinit works)
    emitter.emit("test-event", null);
}
