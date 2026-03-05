const std = @import("std");

/// Hello World Plugin Example
/// Demonstrates the basic plugin interface
///
/// Build:
///   zig build-lib examples/plugins/hello_world.zig -dynamic --name hello_world
///
/// Load:
///   ./mail --plugin-dir ./zig-out/lib

// Plugin state
var allocator: std.mem.Allocator = undefined;
var message_count: usize = 0;

// Plugin metadata
const PluginMetadata = struct {
    name: []const u8,
    version: []const u8,
    author: []const u8,
    description: []const u8,
    license: []const u8,
};

const metadata = PluginMetadata{
    .name = "hello-world",
    .version = "1.0.0",
    .author = "SMTP Team",
    .description = "Hello World example plugin",
    .license = "MIT",
};

/// Initialize plugin
export fn smtp_plugin_init(alloc: std.mem.Allocator, config: [*:0]const u8) callconv(.C) c_int {
    allocator = alloc;
    const config_str = std.mem.span(config);

    std.debug.print("[hello-world] Initializing plugin\n", .{});
    if (config_str.len > 0) {
        std.debug.print("[hello-world] Config: {s}\n", .{config_str});
    }

    return 0; // Success
}

/// Cleanup plugin resources
export fn smtp_plugin_deinit() callconv(.C) void {
    std.debug.print("[hello-world] Total messages processed: {d}\n", .{message_count});
    std.debug.print("[hello-world] Cleanup complete\n", .{});
}

/// Get plugin metadata
export fn smtp_plugin_get_metadata() callconv(.C) ?*const PluginMetadata {
    return &metadata;
}

/// Execute hook
export fn smtp_plugin_execute_hook(context: *anyopaque) callconv(.C) c_int {
    _ = context;
    // In a real plugin, you would cast context to HookContext and process it
    message_count += 1;

    std.debug.print("[hello-world] Hook executed! Message count: {d}\n", .{message_count});

    return 0; // Continue processing
}

/// Enable plugin
export fn smtp_plugin_enable() callconv(.C) c_int {
    std.debug.print("[hello-world] Plugin enabled\n", .{});
    return 0;
}

/// Disable plugin
export fn smtp_plugin_disable() callconv(.C) c_int {
    std.debug.print("[hello-world] Plugin disabled\n", .{});
    return 0;
}

/// Get plugin interface (required entry point)
export fn smtp_plugin_get_interface() callconv(.C) ?*const anyopaque {
    const Interface = struct {
        init: *const fn (std.mem.Allocator, [*:0]const u8) callconv(.C) c_int,
        deinit: *const fn () callconv(.C) void,
        getMetadata: *const fn () callconv(.C) ?*const PluginMetadata,
        executeHook: *const fn (*anyopaque) callconv(.C) c_int,
        enable: *const fn () callconv(.C) c_int,
        disable: *const fn () callconv(.C) c_int,
    };

    const interface = Interface{
        .init = smtp_plugin_init,
        .deinit = smtp_plugin_deinit,
        .getMetadata = smtp_plugin_get_metadata,
        .executeHook = smtp_plugin_execute_hook,
        .enable = smtp_plugin_enable,
        .disable = smtp_plugin_disable,
    };

    return @ptrCast(&interface);
}
