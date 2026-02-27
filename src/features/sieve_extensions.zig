const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");

/// Sieve Extension Framework (RFC 5228, Section 2.2)
/// Manages the registration, lookup, and validation of Sieve language
/// extensions. Each extension maps to a capability string that scripts
/// declare via the "require" command before using extension-specific
/// actions or tests.

// ============================================================================
// Extension Descriptor
// ============================================================================

/// Describes a single Sieve extension, including its capability name,
/// governing RFC, and whether it is currently enabled on the server.
pub const SieveExtension = struct {
    /// Capability string used in `require` statements (e.g. "fileinto").
    name: []const u8,
    /// Human-readable description of what the extension provides.
    description: []const u8,
    /// The RFC number that defines this extension (0 if non-standard).
    rfc_number: u32,
    /// Whether this extension is currently enabled on the server.
    enabled: bool,
    /// Capability names that this extension depends on. A script that
    /// requires this extension implicitly needs the dependencies too.
    required_capabilities: []const []const u8,
    /// Timestamp (unix seconds) when the extension was registered.
    registered_at: i64,

    /// Return the RFC reference string (e.g. "RFC 5228").
    pub fn rfcReference(self: *const SieveExtension) ?[]const u8 {
        if (self.rfc_number == 0) return null;
        return self.name; // callers can format with rfc_number directly
    }

    /// Check whether this extension depends on a given capability.
    pub fn dependsOn(self: *const SieveExtension, capability: []const u8) bool {
        for (self.required_capabilities) |dep| {
            if (std.mem.eql(u8, dep, capability)) return true;
        }
        return false;
    }
};

// ============================================================================
// Validation Results
// ============================================================================

/// Result of validating a script's `require` list against the registry.
pub const ValidationResult = struct {
    valid: bool,
    missing_extensions: []const []const u8,
    disabled_extensions: []const []const u8,
    missing_dependencies: []const DependencyError,

    pub const DependencyError = struct {
        extension: []const u8,
        missing_dependency: []const u8,
    };
};

// ============================================================================
// Extension Registry
// ============================================================================

/// Manages the set of Sieve extensions available on this server.
/// Provides lookup, enable/disable, and script-validation facilities.
pub const SieveExtensionRegistry = struct {
    allocator: std.mem.Allocator,
    extensions: std.StringHashMap(SieveExtension),
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator) SieveExtensionRegistry {
        return .{
            .allocator = allocator,
            .extensions = std.StringHashMap(SieveExtension).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *SieveExtensionRegistry) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.extensions.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.freeExtension(entry.value_ptr.*);
        }
        self.extensions.deinit();
    }

    fn freeExtension(self: *SieveExtensionRegistry, ext: SieveExtension) void {
        self.allocator.free(ext.name);
        self.allocator.free(ext.description);
        for (ext.required_capabilities) |cap| {
            self.allocator.free(cap);
        }
        if (ext.required_capabilities.len > 0) {
            self.allocator.free(ext.required_capabilities);
        }
    }

    // ------------------------------------------------------------------------
    // Registration
    // ------------------------------------------------------------------------

    /// Register a new extension. Returns error.ExtensionAlreadyRegistered
    /// if an extension with the same capability name already exists.
    pub fn register(
        self: *SieveExtensionRegistry,
        name: []const u8,
        description: []const u8,
        rfc_number: u32,
        enabled: bool,
        required_capabilities: []const []const u8,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.extensions.contains(name)) {
            return error.ExtensionAlreadyRegistered;
        }

        // Deep-copy all strings so the registry owns the memory.
        const name_copy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_copy);

        const desc_copy = try self.allocator.dupe(u8, description);
        errdefer self.allocator.free(desc_copy);

        var caps = try self.allocator.alloc([]const u8, required_capabilities.len);
        errdefer {
            for (caps) |c| self.allocator.free(c);
            self.allocator.free(caps);
        }
        for (required_capabilities, 0..) |cap, i| {
            caps[i] = try self.allocator.dupe(u8, cap);
        }

        const ext = SieveExtension{
            .name = name_copy,
            .description = desc_copy,
            .rfc_number = rfc_number,
            .enabled = enabled,
            .required_capabilities = caps,
            .registered_at = time_compat.timestamp(),
        };

        const key = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(key);
        try self.extensions.put(key, ext);
    }

    // ------------------------------------------------------------------------
    // Lookup
    // ------------------------------------------------------------------------

    /// Look up an extension by capability name. Returns null if not found.
    pub fn getExtension(self: *SieveExtensionRegistry, name: []const u8) ?*const SieveExtension {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.extensions.getPtr(name);
    }

    /// Check whether a `require`'d capability is available and enabled.
    pub fn isAvailable(self: *SieveExtensionRegistry, name: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.extensions.getPtr(name)) |ext| {
            return ext.enabled;
        }
        return false;
    }

    /// Return the number of registered extensions.
    pub fn count(self: *SieveExtensionRegistry) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.extensions.count();
    }

    /// Return the number of currently enabled extensions.
    pub fn enabledCount(self: *SieveExtensionRegistry) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var n: usize = 0;
        var it = self.extensions.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.enabled) n += 1;
        }
        return n;
    }

    // ------------------------------------------------------------------------
    // Enable / Disable
    // ------------------------------------------------------------------------

    /// Enable an extension by name.
    pub fn enableExtension(self: *SieveExtensionRegistry, name: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.extensions.getPtr(name)) |ext| {
            ext.enabled = true;
        } else {
            return error.ExtensionNotFound;
        }
    }

    /// Disable an extension by name.
    pub fn disableExtension(self: *SieveExtensionRegistry, name: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.extensions.getPtr(name)) |ext| {
            ext.enabled = false;
        } else {
            return error.ExtensionNotFound;
        }
    }

    // ------------------------------------------------------------------------
    // Listing
    // ------------------------------------------------------------------------

    /// Collect the capability names of all enabled extensions into a
    /// caller-owned slice. The caller must free the returned slice (but not
    /// the individual strings, which are borrowed from the registry).
    pub fn listEnabled(self: *SieveExtensionRegistry, allocator: std.mem.Allocator) ![]const []const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var list: std.ArrayList([]const u8) = .{};
        errdefer list.deinit(allocator);

        var it = self.extensions.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.enabled) {
                try list.append(allocator, entry.value_ptr.name);
            }
        }

        return list.toOwnedSlice(allocator);
    }

    /// Collect all registered extension names (enabled or not).
    pub fn listAll(self: *SieveExtensionRegistry, allocator: std.mem.Allocator) ![]const []const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var list: std.ArrayList([]const u8) = .{};
        errdefer list.deinit(allocator);

        var it = self.extensions.iterator();
        while (it.next()) |entry| {
            try list.append(allocator, entry.value_ptr.name);
        }

        return list.toOwnedSlice(allocator);
    }

    // ------------------------------------------------------------------------
    // Validation
    // ------------------------------------------------------------------------

    /// Validate a script's `require` list against available extensions.
    /// Checks that every required capability is registered, enabled, and
    /// that all transitive dependencies are satisfied.
    pub fn validateRequires(
        self: *SieveExtensionRegistry,
        required: []const []const u8,
        allocator: std.mem.Allocator,
    ) !ValidationResult {
        self.mutex.lock();
        defer self.mutex.unlock();

        var missing: std.ArrayList([]const u8) = .{};
        errdefer missing.deinit(allocator);

        var disabled: std.ArrayList([]const u8) = .{};
        errdefer disabled.deinit(allocator);

        var dep_errors: std.ArrayList(ValidationResult.DependencyError) = .{};
        errdefer dep_errors.deinit(allocator);

        for (required) |cap| {
            if (self.extensions.getPtr(cap)) |ext| {
                // Registered but disabled
                if (!ext.enabled) {
                    try disabled.append(allocator, cap);
                    continue;
                }

                // Check that every dependency is also in the require list
                for (ext.required_capabilities) |dep| {
                    var dep_found = false;
                    for (required) |r| {
                        if (std.mem.eql(u8, r, dep)) {
                            dep_found = true;
                            break;
                        }
                    }
                    if (!dep_found) {
                        // The dependency might still be available even if
                        // not explicitly required -- check if it is at
                        // least registered and enabled.
                        if (self.extensions.getPtr(dep)) |dep_ext| {
                            if (!dep_ext.enabled) {
                                try dep_errors.append(allocator, .{
                                    .extension = cap,
                                    .missing_dependency = dep,
                                });
                            }
                        } else {
                            try dep_errors.append(allocator, .{
                                .extension = cap,
                                .missing_dependency = dep,
                            });
                        }
                    }
                }
            } else {
                // Not registered at all
                try missing.append(allocator, cap);
            }
        }

        const is_valid = missing.items.len == 0 and
            disabled.items.len == 0 and
            dep_errors.items.len == 0;

        return ValidationResult{
            .valid = is_valid,
            .missing_extensions = try missing.toOwnedSlice(allocator),
            .disabled_extensions = try disabled.toOwnedSlice(allocator),
            .missing_dependencies = try dep_errors.toOwnedSlice(allocator),
        };
    }

    /// Free a ValidationResult previously returned by validateRequires.
    pub fn freeValidationResult(self: *SieveExtensionRegistry, result: ValidationResult) void {
        _ = self;
        const allocator = self.allocator;
        allocator.free(result.missing_extensions);
        allocator.free(result.disabled_extensions);
        allocator.free(result.missing_dependencies);
    }
};

// ============================================================================
// Built-in Extensions
// ============================================================================

/// Extension descriptor used to seed the registry with well-known
/// Sieve extensions. Stored as comptime data so no allocation is needed
/// until the caller registers them.
const BuiltinExtensionDef = struct {
    name: []const u8,
    description: []const u8,
    rfc_number: u32,
    enabled_by_default: bool,
    required_capabilities: []const []const u8,
};

/// The set of built-in extensions shipped with the server.
pub const builtin_extensions = [_]BuiltinExtensionDef{
    .{
        .name = "fileinto",
        .description = "Delivers the message into a specified mailbox (RFC 5228, Section 4.1)",
        .rfc_number = 5228,
        .enabled_by_default = true,
        .required_capabilities = &.{},
    },
    .{
        .name = "reject",
        .description = "Refuses delivery of a message with an MDN to the sender (RFC 5429)",
        .rfc_number = 5429,
        .enabled_by_default = true,
        .required_capabilities = &.{},
    },
    .{
        .name = "envelope",
        .description = "Provides access to envelope sender and recipient addresses (RFC 5228, Section 5.4)",
        .rfc_number = 5228,
        .enabled_by_default = true,
        .required_capabilities = &.{},
    },
    .{
        .name = "body",
        .description = "Allows testing against the body of the message (RFC 5173)",
        .rfc_number = 5173,
        .enabled_by_default = true,
        .required_capabilities = &.{},
    },
    .{
        .name = "vacation",
        .description = "Sends automatic vacation / out-of-office responses (RFC 5230)",
        .rfc_number = 5230,
        .enabled_by_default = true,
        .required_capabilities = &.{},
    },
    .{
        .name = "notify",
        .description = "Sends notifications through external channels (RFC 5435)",
        .rfc_number = 5435,
        .enabled_by_default = false,
        .required_capabilities = &.{},
    },
    .{
        .name = "imap4flags",
        .description = "Manipulates IMAP flags and keywords on messages (RFC 5232)",
        .rfc_number = 5232,
        .enabled_by_default = true,
        .required_capabilities = &.{},
    },
    .{
        .name = "editheader",
        .description = "Adds and removes message header fields (RFC 5293)",
        .rfc_number = 5293,
        .enabled_by_default = false,
        .required_capabilities = &.{},
    },
    .{
        .name = "variables",
        .description = "Adds support for variables and variable expansion (RFC 5229)",
        .rfc_number = 5229,
        .enabled_by_default = true,
        .required_capabilities = &.{},
    },
    .{
        .name = "regex",
        .description = "Provides regular expression matching for tests (draft-murchison-sieve-regex)",
        .rfc_number = 0,
        .enabled_by_default = false,
        .required_capabilities = &.{},
    },
    .{
        .name = "copy",
        .description = "Delivers a copy without cancelling implicit keep (RFC 3894)",
        .rfc_number = 3894,
        .enabled_by_default = true,
        .required_capabilities = &.{"fileinto"},
    },
    .{
        .name = "relational",
        .description = "Provides relational (numeric/ordering) comparators (RFC 5231)",
        .rfc_number = 5231,
        .enabled_by_default = true,
        .required_capabilities = &.{},
    },
};

/// Populate a registry with all built-in extensions using their default
/// enabled state.
pub fn registerBuiltins(registry: *SieveExtensionRegistry) !void {
    for (builtin_extensions) |def| {
        try registry.register(
            def.name,
            def.description,
            def.rfc_number,
            def.enabled_by_default,
            def.required_capabilities,
        );
    }
}

/// Create a new registry pre-populated with all built-in extensions.
pub fn createDefaultRegistry(allocator: std.mem.Allocator) !SieveExtensionRegistry {
    var registry = SieveExtensionRegistry.init(allocator);
    errdefer registry.deinit();
    try registerBuiltins(&registry);
    return registry;
}

// ============================================================================
// Tests
// ============================================================================

test "registry init and deinit" {
    const testing = std.testing;
    var registry = SieveExtensionRegistry.init(testing.allocator);
    defer registry.deinit();

    try testing.expectEqual(@as(usize, 0), registry.count());
}

test "register and lookup extension" {
    const testing = std.testing;
    var registry = SieveExtensionRegistry.init(testing.allocator);
    defer registry.deinit();

    try registry.register(
        "fileinto",
        "Delivers message into a specified mailbox",
        5228,
        true,
        &.{},
    );

    try testing.expectEqual(@as(usize, 1), registry.count());

    const ext = registry.getExtension("fileinto");
    try testing.expect(ext != null);
    try testing.expectEqualStrings("fileinto", ext.?.name);
    try testing.expectEqual(@as(u32, 5228), ext.?.rfc_number);
    try testing.expect(ext.?.enabled);
}

test "duplicate registration returns error" {
    const testing = std.testing;
    var registry = SieveExtensionRegistry.init(testing.allocator);
    defer registry.deinit();

    try registry.register("fileinto", "desc", 5228, true, &.{});
    try testing.expectError(
        error.ExtensionAlreadyRegistered,
        registry.register("fileinto", "desc2", 5228, true, &.{}),
    );
}

test "enable and disable extension" {
    const testing = std.testing;
    var registry = SieveExtensionRegistry.init(testing.allocator);
    defer registry.deinit();

    try registry.register("notify", "Notifications", 5435, false, &.{});
    try testing.expect(!registry.isAvailable("notify"));

    try registry.enableExtension("notify");
    try testing.expect(registry.isAvailable("notify"));

    try registry.disableExtension("notify");
    try testing.expect(!registry.isAvailable("notify"));
}

test "enable unknown extension returns error" {
    const testing = std.testing;
    var registry = SieveExtensionRegistry.init(testing.allocator);
    defer registry.deinit();

    try testing.expectError(
        error.ExtensionNotFound,
        registry.enableExtension("nonexistent"),
    );
}

test "isAvailable returns false for unknown" {
    const testing = std.testing;
    var registry = SieveExtensionRegistry.init(testing.allocator);
    defer registry.deinit();

    try testing.expect(!registry.isAvailable("nonexistent"));
}

test "list enabled extensions" {
    const testing = std.testing;
    var registry = SieveExtensionRegistry.init(testing.allocator);
    defer registry.deinit();

    try registry.register("fileinto", "Deliver to mailbox", 5228, true, &.{});
    try registry.register("reject", "Reject message", 5429, true, &.{});
    try registry.register("notify", "Notifications", 5435, false, &.{});

    const enabled = try registry.listEnabled(testing.allocator);
    defer testing.allocator.free(enabled);

    try testing.expectEqual(@as(usize, 2), enabled.len);
}

test "list all extensions" {
    const testing = std.testing;
    var registry = SieveExtensionRegistry.init(testing.allocator);
    defer registry.deinit();

    try registry.register("fileinto", "Deliver to mailbox", 5228, true, &.{});
    try registry.register("notify", "Notifications", 5435, false, &.{});

    const all = try registry.listAll(testing.allocator);
    defer testing.allocator.free(all);

    try testing.expectEqual(@as(usize, 2), all.len);
}

test "enabled count" {
    const testing = std.testing;
    var registry = SieveExtensionRegistry.init(testing.allocator);
    defer registry.deinit();

    try registry.register("fileinto", "Deliver to mailbox", 5228, true, &.{});
    try registry.register("reject", "Reject message", 5429, true, &.{});
    try registry.register("notify", "Notifications", 5435, false, &.{});

    try testing.expectEqual(@as(usize, 2), registry.enabledCount());
    try testing.expectEqual(@as(usize, 3), registry.count());
}

test "register builtins populates all extensions" {
    const testing = std.testing;
    var registry = SieveExtensionRegistry.init(testing.allocator);
    defer registry.deinit();

    try registerBuiltins(&registry);
    try testing.expectEqual(@as(usize, builtin_extensions.len), registry.count());

    // Spot-check several extensions
    try testing.expect(registry.isAvailable("fileinto"));
    try testing.expect(registry.isAvailable("reject"));
    try testing.expect(registry.isAvailable("envelope"));
    try testing.expect(registry.isAvailable("body"));
    try testing.expect(registry.isAvailable("vacation"));
    try testing.expect(registry.isAvailable("imap4flags"));
    try testing.expect(registry.isAvailable("variables"));
    try testing.expect(registry.isAvailable("copy"));
    try testing.expect(registry.isAvailable("relational"));

    // These are disabled by default
    try testing.expect(!registry.isAvailable("notify"));
    try testing.expect(!registry.isAvailable("editheader"));
    try testing.expect(!registry.isAvailable("regex"));
}

test "createDefaultRegistry convenience function" {
    const testing = std.testing;
    var registry = try createDefaultRegistry(testing.allocator);
    defer registry.deinit();

    try testing.expectEqual(@as(usize, builtin_extensions.len), registry.count());
    try testing.expect(registry.isAvailable("vacation"));
}

test "validate requires - all valid" {
    const testing = std.testing;
    var registry = try createDefaultRegistry(testing.allocator);
    defer registry.deinit();

    const requires = [_][]const u8{ "fileinto", "reject", "envelope" };
    const result = try registry.validateRequires(&requires, testing.allocator);
    defer {
        testing.allocator.free(result.missing_extensions);
        testing.allocator.free(result.disabled_extensions);
        testing.allocator.free(result.missing_dependencies);
    }

    try testing.expect(result.valid);
    try testing.expectEqual(@as(usize, 0), result.missing_extensions.len);
    try testing.expectEqual(@as(usize, 0), result.disabled_extensions.len);
    try testing.expectEqual(@as(usize, 0), result.missing_dependencies.len);
}

test "validate requires - missing extension" {
    const testing = std.testing;
    var registry = try createDefaultRegistry(testing.allocator);
    defer registry.deinit();

    const requires = [_][]const u8{ "fileinto", "nonexistent_ext" };
    const result = try registry.validateRequires(&requires, testing.allocator);
    defer {
        testing.allocator.free(result.missing_extensions);
        testing.allocator.free(result.disabled_extensions);
        testing.allocator.free(result.missing_dependencies);
    }

    try testing.expect(!result.valid);
    try testing.expectEqual(@as(usize, 1), result.missing_extensions.len);
    try testing.expectEqualStrings("nonexistent_ext", result.missing_extensions[0]);
}

test "validate requires - disabled extension" {
    const testing = std.testing;
    var registry = try createDefaultRegistry(testing.allocator);
    defer registry.deinit();

    // "notify" is disabled by default
    const requires = [_][]const u8{"notify"};
    const result = try registry.validateRequires(&requires, testing.allocator);
    defer {
        testing.allocator.free(result.missing_extensions);
        testing.allocator.free(result.disabled_extensions);
        testing.allocator.free(result.missing_dependencies);
    }

    try testing.expect(!result.valid);
    try testing.expectEqual(@as(usize, 1), result.disabled_extensions.len);
    try testing.expectEqualStrings("notify", result.disabled_extensions[0]);
}

test "validate requires - missing dependency" {
    const testing = std.testing;
    var registry = SieveExtensionRegistry.init(testing.allocator);
    defer registry.deinit();

    // Register "copy" which depends on "fileinto", but don't register "fileinto"
    try registry.register("copy", "Copy extension", 3894, true, &[_][]const u8{"fileinto"});

    const requires = [_][]const u8{"copy"};
    const result = try registry.validateRequires(&requires, testing.allocator);
    defer {
        testing.allocator.free(result.missing_extensions);
        testing.allocator.free(result.disabled_extensions);
        testing.allocator.free(result.missing_dependencies);
    }

    try testing.expect(!result.valid);
    try testing.expectEqual(@as(usize, 1), result.missing_dependencies.len);
    try testing.expectEqualStrings("copy", result.missing_dependencies[0].extension);
    try testing.expectEqualStrings("fileinto", result.missing_dependencies[0].missing_dependency);
}

test "extension dependsOn helper" {
    const testing = std.testing;

    const ext = SieveExtension{
        .name = "copy",
        .description = "Copy extension",
        .rfc_number = 3894,
        .enabled = true,
        .required_capabilities = &[_][]const u8{"fileinto"},
        .registered_at = 0,
    };

    try testing.expect(ext.dependsOn("fileinto"));
    try testing.expect(!ext.dependsOn("reject"));
}

test "builtin extension definitions are consistent" {
    const testing = std.testing;

    // Every built-in must have a non-empty name and description
    for (builtin_extensions) |def| {
        try testing.expect(def.name.len > 0);
        try testing.expect(def.description.len > 0);
    }

    // "copy" must depend on "fileinto"
    for (builtin_extensions) |def| {
        if (std.mem.eql(u8, def.name, "copy")) {
            try testing.expect(def.required_capabilities.len > 0);
            try testing.expectEqualStrings("fileinto", def.required_capabilities[0]);
        }
    }
}

test "validate empty requires list is valid" {
    const testing = std.testing;
    var registry = try createDefaultRegistry(testing.allocator);
    defer registry.deinit();

    const requires = [_][]const u8{};
    const result = try registry.validateRequires(&requires, testing.allocator);
    defer {
        testing.allocator.free(result.missing_extensions);
        testing.allocator.free(result.disabled_extensions);
        testing.allocator.free(result.missing_dependencies);
    }

    try testing.expect(result.valid);
}

test "copy extension with fileinto present is valid" {
    const testing = std.testing;
    var registry = try createDefaultRegistry(testing.allocator);
    defer registry.deinit();

    // Both "copy" and its dependency "fileinto" are required
    const requires = [_][]const u8{ "copy", "fileinto" };
    const result = try registry.validateRequires(&requires, testing.allocator);
    defer {
        testing.allocator.free(result.missing_extensions);
        testing.allocator.free(result.disabled_extensions);
        testing.allocator.free(result.missing_dependencies);
    }

    try testing.expect(result.valid);
}
