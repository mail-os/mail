# Plugin System Guide

**Version:** v0.28.0
**Date:** 2025-10-24

## Overview

The SMTP server includes a flexible plugin system that allows you to extend functionality without modifying the core codebase. Plugins are loaded as shared libraries (.so, .dylib, .dll) and can hook into various server events.

## Features

- **Dynamic Loading**: Load plugins at runtime from shared libraries
- **Hook-Based Architecture**: Intercept and modify server behavior at specific points
- **Lifecycle Management**: Full control over plugin initialization, enabling, and cleanup
- **Dependency Resolution**: Declare and enforce plugin dependencies
- **Hot Reload**: Reload plugins without restarting the server (development mode)
- **Resource Limits**: Sandboxed execution with configurable resource limits
- **Configuration**: Per-plugin configuration via JSON/TOML

---

## Plugin Architecture

### Plugin Interface

Every plugin must implement the standard plugin interface:

```zig
pub const PluginInterface = struct {
    init: *const fn (allocator: std.mem.Allocator, config: []const u8) callconv(.C) c_int,
    deinit: *const fn () callconv(.C) void,
    getMetadata: *const fn () callconv(.C) ?*const PluginMetadata,
    executeHook: *const fn (context: *HookContext) callconv(.C) c_int,
    enable: *const fn () callconv(.C) c_int,
    disable: *const fn () callconv(.C) c_int,
};
```

### Hook Types

Plugins can register for these hooks:

**Message Processing:**
- `message_received` - When a message is received
- `message_validated` - After message validation
- `message_filtered` - During spam/virus filtering
- `message_stored` - After message is stored
- `message_delivered` - After successful delivery

**Authentication:**
- `auth_started` - When authentication begins
- `auth_completed` - After successful authentication
- `auth_failed` - On authentication failure

**Connection:**
- `connection_opened` - When client connects
- `connection_closed` - When client disconnects
- `connection_upgraded` - After STARTTLS

**Commands:**
- `command_received` - For each SMTP command
- `command_validated` - After command validation

**Configuration:**
- `config_loaded` - After configuration is loaded
- `config_changed` - When configuration changes

**Server Lifecycle:**
- `server_starting` - Before server starts
- `server_started` - After server starts
- `server_stopping` - Before server stops
- `server_stopped` - After server stops

---

## Creating a Plugin

### Example: Spam Filter Plugin

**File:** `plugins/spam_filter.zig`

```zig
const std = @import("std");
const plugin = @import("mail").plugin;

var allocator: std.mem.Allocator = undefined;
var spam_threshold: f64 = 5.0;

// Plugin metadata
const metadata = plugin.PluginMetadata{
    .name = "spam-filter",
    .version = "1.0.0",
    .author = "SMTP Team",
    .description = "Basic spam filtering using keyword analysis",
    .license = "MIT",
    .dependencies = &.{},
    .min_server_version = "0.28.0",
    .max_server_version = null,
};

// Initialize plugin
export fn smtp_plugin_init(alloc: std.mem.Allocator, config: [*:0]const u8) callconv(.C) c_int {
    allocator = alloc;

    // Parse configuration (simplified)
    const config_str = std.mem.span(config);
    if (config_str.len > 0) {
        // Parse JSON config for spam_threshold
        spam_threshold = 5.0; // Default
    }

    std.debug.print("[spam-filter] Initialized with threshold: {d}\n", .{spam_threshold});
    return 0;
}

// Cleanup plugin resources
export fn smtp_plugin_deinit() callconv(.C) void {
    std.debug.print("[spam-filter] Cleanup complete\n", .{});
}

// Get plugin metadata
export fn smtp_plugin_get_metadata() callconv(.C) ?*const plugin.PluginMetadata {
    return &metadata;
}

// Execute hook
export fn smtp_plugin_execute_hook(context: *plugin.HookContext) callconv(.C) c_int {
    switch (context.hook_type) {
        .message_filtered => {
            return filterMessage(context);
        },
        else => return 0, // Continue processing
    }
}

// Enable plugin
export fn smtp_plugin_enable() callconv(.C) c_int {
    std.debug.print("[spam-filter] Plugin enabled\n", .{});
    return 0;
}

// Disable plugin
export fn smtp_plugin_disable() callconv(.C) c_int {
    std.debug.print("[spam-filter] Plugin disabled\n", .{});
    return 0;
}

// Get plugin interface (required entry point)
export fn smtp_plugin_get_interface() callconv(.C) ?*plugin.PluginInterface {
    const interface = plugin.PluginInterface{
        .init = smtp_plugin_init,
        .deinit = smtp_plugin_deinit,
        .getMetadata = smtp_plugin_get_metadata,
        .executeHook = smtp_plugin_execute_hook,
        .enable = smtp_plugin_enable,
        .disable = smtp_plugin_disable,
    };
    return &interface;
}

// Filter message for spam
fn filterMessage(context: *plugin.HookContext) c_int {
    // Get message body from context metadata
    const body = context.getMetadata("message_body") orelse return 0;

    // Calculate spam score (simplified keyword matching)
    var score: f64 = 0.0;

    const spam_keywords = [_][]const u8{
        "viagra", "casino", "winner", "free money", "click here",
        "limited time", "act now", "congratulations",
    };

    for (spam_keywords) |keyword| {
        if (std.mem.indexOf(u8, body, keyword)) |_| {
            score += 1.0;
        }
    }

    // Check if message is spam
    if (score >= spam_threshold) {
        context.setMetadata("spam_score",
            std.fmt.allocPrint(allocator, "{d}", .{score}) catch return 1
        ) catch return 1;

        context.setMetadata("is_spam", "true") catch return 1;

        std.debug.print("[spam-filter] Message flagged as spam (score: {d})\n", .{score});

        // Stop processing (prevent delivery)
        return 1;
    }

    // Continue processing
    return 0;
}
```

### Building the Plugin

```bash
# Build as shared library
zig build-lib plugins/spam_filter.zig \
  -dynamic \
  -O ReleaseFast \
  --name spam_filter

# Output: libspam_filter.so (Linux)
#         libspam_filter.dylib (macOS)
#         spam_filter.dll (Windows)
```

---

## Loading Plugins

### Configuration

**config.toml:**

```toml
[plugins]
enabled = true
directory = "./plugins"
auto_load = true

[[plugins.plugin]]
name = "spam-filter"
enabled = true
library = "libspam_filter.so"
config = '''
{
  "spam_threshold": 5.0,
  "quarantine": true
}
'''

[[plugins.plugin]]
name = "virus-scanner"
enabled = true
library = "libvirus_scanner.so"
config = '''
{
  "clamav_socket": "/var/run/clamav/clamd.sock"
}
'''
```

### Programmatic Loading

```zig
const plugin_mgr = try PluginManager.init(allocator, "./plugins");
defer plugin_mgr.deinit();

// Load specific plugin
const spam_filter = try plugin_mgr.loadPlugin(
    "./plugins/libspam_filter.so",
    "{\"spam_threshold\": 5.0}"
);

// Load all plugins from directory
try plugin_mgr.loadAllPlugins();

// Execute a hook
var context = HookContext.init(allocator, .message_filtered);
defer context.deinit();

try context.setMetadata("message_body", message_body);
try plugin_mgr.executeHook(.message_filtered, &context);

if (context.cancel) {
    std.debug.print("Message delivery cancelled by plugin\n", .{});
}
```

---

## Plugin Examples

### 1. Authentication Plugin

**Purpose**: Custom authentication against LDAP server

```zig
// plugins/ldap_auth.zig
export fn smtp_plugin_execute_hook(context: *plugin.HookContext) callconv(.C) c_int {
    switch (context.hook_type) {
        .auth_started => {
            const username = context.getMetadata("username") orelse return 0;
            const password = context.getMetadata("password") orelse return 0;

            // Authenticate against LDAP
            const auth_result = ldapAuthenticate(username, password);

            if (!auth_result) {
                context.cancel = true;
                return 2; // Cancel operation
            }

            return 0; // Continue
        },
        else => return 0,
    }
}
```

### 2. Rate Limiting Plugin

**Purpose**: Per-domain rate limiting

```zig
// plugins/rate_limiter.zig
var rate_limits = std.StringHashMap(RateLimit).init(allocator);

export fn smtp_plugin_execute_hook(context: *plugin.HookContext) callconv(.C) c_int {
    switch (context.hook_type) {
        .message_received => {
            const domain = context.getMetadata("sender_domain") orelse return 0;

            var limit = rate_limits.get(domain) orelse RateLimit{
                .count = 0,
                .reset_time = std.time.timestamp() + 3600,
            };

            limit.count += 1;

            if (limit.count > 100) { // 100 messages per hour
                context.setMetadata("rate_limit_exceeded", "true") catch {};
                context.cancel = true;
                return 2; // Cancel
            }

            rate_limits.put(domain, limit) catch {};
            return 0;
        },
        else => return 0,
    }
}
```

### 3. Message Logging Plugin

**Purpose**: Log all messages to external system

```zig
// plugins/message_logger.zig
export fn smtp_plugin_execute_hook(context: *plugin.HookContext) callconv(.C) c_int {
    switch (context.hook_type) {
        .message_stored => {
            const message_id = context.getMetadata("message_id") orelse return 0;
            const sender = context.getMetadata("sender") orelse return 0;
            const recipient = context.getMetadata("recipient") orelse return 0;

            // Send to logging service
            logToElasticsearch(.{
                .message_id = message_id,
                .sender = sender,
                .recipient = recipient,
                .timestamp = std.time.timestamp(),
            }) catch |err| {
                std.debug.print("Failed to log message: {}\n", .{err});
            };

            return 0; // Continue (don't block on logging failure)
        },
        else => return 0,
    }
}
```

### 4. Virus Scanner Plugin

**Purpose**: Scan attachments with ClamAV

```zig
// plugins/virus_scanner.zig
export fn smtp_plugin_execute_hook(context: *plugin.HookContext) callconv(.C) c_int {
    switch (context.hook_type) {
        .message_filtered => {
            const message_path = context.getMetadata("message_path") orelse return 0;

            // Scan with ClamAV
            const scan_result = scanWithClamAV(message_path);

            if (scan_result.infected) {
                context.setMetadata("virus_name", scan_result.virus_name) catch {};
                context.setMetadata("infected", "true") catch {};
                context.cancel = true; // Quarantine
                return 2;
            }

            return 0;
        },
        else => return 0,
    }
}
```

---

## Plugin Configuration

### Per-Plugin Configuration File

**plugins/spam_filter.json:**

```json
{
  "enabled": true,
  "spam_threshold": 5.0,
  "quarantine_path": "/var/spool/smtp/quarantine",
  "whitelist": [
    "example.com",
    "trusted-domain.com"
  ],
  "blacklist_keywords": [
    "viagra",
    "casino",
    "free money"
  ],
  "auto_learn": true,
  "bayesian_filtering": false
}
```

### Loading Configuration

```zig
export fn smtp_plugin_init(alloc: std.mem.Allocator, config: [*:0]const u8) callconv(.C) c_int {
    allocator = alloc;

    const config_str = std.mem.span(config);
    const parsed = std.json.parseFromSlice(
        PluginConfig,
        allocator,
        config_str,
        .{}
    ) catch |err| {
        std.debug.print("Failed to parse config: {}\n", .{err});
        return 1;
    };
    defer parsed.deinit();

    plugin_config = parsed.value;
    return 0;
}
```

---

## Best Practices

### 1. Error Handling

Always handle errors gracefully:

```zig
export fn smtp_plugin_execute_hook(context: *plugin.HookContext) callconv(.C) c_int {
    performOperation() catch |err| {
        std.debug.print("[plugin] Operation failed: {}\n", .{err});
        return 0; // Continue (don't break the chain)
    };
    return 0;
}
```

### 2. Resource Cleanup

Clean up resources in deinit:

```zig
export fn smtp_plugin_deinit() callconv(.C) void {
    if (database_connection) |conn| {
        conn.close();
    }
    if (allocated_buffer) |buf| {
        allocator.free(buf);
    }
}
```

### 3. Thread Safety

Use mutexes for shared state:

```zig
var mutex = std.Thread.Mutex{};
var shared_cache = std.StringHashMap([]const u8).init(allocator);

export fn smtp_plugin_execute_hook(context: *plugin.HookContext) callconv(.C) c_int {
    mutex.lock();
    defer mutex.unlock();

    // Safe access to shared_cache
    shared_cache.put("key", "value") catch {};
    return 0;
}
```

### 4. Performance

Avoid blocking operations in hot paths:

```zig
// BAD: Synchronous HTTP call in message_received hook
const response = http.get("https://api.example.com/check") catch return 1;

// GOOD: Queue for background processing
try background_queue.append(context.getMetadata("message_id"));
return 0;
```

### 5. Logging

Use structured logging:

```zig
std.debug.print("[{s}] {s}: {s}\n", .{
    metadata.name,
    @tagName(context.hook_type),
    "Processing message",
});
```

---

## Testing Plugins

### Unit Tests

```zig
// plugins/spam_filter_test.zig
test "spam detection" {
    const testing = std.testing;

    var context = plugin.HookContext.init(testing.allocator, .message_filtered);
    defer context.deinit();

    const spam_body = "Buy viagra now! Click here for free money!";
    try context.setMetadata("message_body", spam_body);

    const result = smtp_plugin_execute_hook(&context);

    try testing.expectEqual(@as(c_int, 1), result); // Should block
    const is_spam = context.getMetadata("is_spam");
    try testing.expect(is_spam != null);
}
```

### Integration Tests

```bash
# Load plugin in test mode
./mail --plugin-dir ./plugins --test-mode

# Send test message
echo "Test message" | nc localhost 2525
```

---

## Debugging Plugins

### Enable Debug Logging

```bash
export SMTP_PLUGIN_DEBUG=1
./mail
```

### Use GDB/LLDB

```bash
# Build with debug symbols
zig build-lib plugins/spam_filter.zig -dynamic -g

# Debug with GDB
gdb --args ./mail --plugin-dir ./plugins
(gdb) break smtp_plugin_execute_hook
(gdb) run
```

### Memory Leak Detection

```bash
# Build with sanitizers
zig build-lib plugins/spam_filter.zig \
  -dynamic \
  -fsanitize=address \
  -fsanitize=undefined

# Run with leak detection
ASAN_OPTIONS=detect_leaks=1 ./mail
```

---

## Security Considerations

### 1. Input Validation

Always validate plugin inputs:

```zig
const username = context.getMetadata("username") orelse return 0;
if (username.len > 256) {
    std.debug.print("Username too long\n", .{});
    return 1;
}
```

### 2. Resource Limits

Limit plugin resource usage:

```zig
const max_memory = 100 * 1024 * 1024; // 100 MB
var gpa = std.heap.GeneralPurposeAllocator(.{
    .max_memory = max_memory,
}){};
```

### 3. Sandboxing

Run plugins in restricted environment (future feature):

```zig
// Limit system calls
// Restrict file system access
// Network isolation
```

---

## See Also

- [API_REFERENCE.md](API_REFERENCE.md) - REST API documentation
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
- [DEVELOPMENT.md](DEVELOPMENT.md) - Development guide

---

**Last Updated:** 2025-10-24
**Version:** v0.28.0
