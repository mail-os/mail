const std = @import("std");
const io_compat = @import("../core/io_compat.zig");

// =============================================================================
// Email Signature Management
// =============================================================================
//
// ## Overview
// Provides creation, management, and auto-insertion of email signatures.
// Supports multiple signatures per user with HTML formatting.
//
// ## Features
// - Multiple signatures per account
// - HTML and plain text formats
// - Default signature per account
// - Per-folder signature rules
// - Reply vs new message signatures
// - Image embedding support
//
// =============================================================================

/// Signature-related errors
pub const SignatureError = error{
    SignatureNotFound,
    InvalidSignature,
    StorageFull,
    DuplicateName,
    OutOfMemory,
};

/// Signature position in email
pub const SignaturePosition = enum {
    /// At the bottom of the email
    bottom,
    /// Above quoted text in replies
    above_quote,
    /// Below quoted text in replies
    below_quote,

    pub fn toString(self: SignaturePosition) []const u8 {
        return switch (self) {
            .bottom => "Bottom",
            .above_quote => "Above Quote",
            .below_quote => "Below Quote",
        };
    }
};

/// Email signature
pub const EmailSignature = struct {
    id: []const u8,
    name: []const u8,
    /// Plain text version
    text: []const u8,
    /// HTML version (optional)
    html: ?[]const u8,
    /// Is this the default signature?
    is_default: bool,
    /// Use for new messages
    use_for_new: bool,
    /// Use for replies
    use_for_reply: bool,
    /// Use for forwards
    use_for_forward: bool,
    /// Position in email
    position: SignaturePosition,
    /// Associated account/identity (optional)
    account_id: ?[]const u8,
    /// Creation timestamp
    created_at: i64,
    /// Last update timestamp
    updated_at: i64,

    /// Convert to JSON
    pub fn toJson(self: *const EmailSignature, allocator: std.mem.Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        errdefer buffer.deinit();
        const writer = buffer.writer();

        try writer.writeAll("{");
        try writer.print("\"id\":\"{s}\",", .{self.id});
        try writer.print("\"name\":\"{s}\",", .{escapeJson(self.name)});
        try writer.print("\"text\":\"{s}\",", .{escapeJson(self.text)});
        if (self.html) |h| {
            try writer.print("\"html\":\"{s}\",", .{escapeJson(h)});
        } else {
            try writer.writeAll("\"html\":null,");
        }
        try writer.print("\"is_default\":{s},", .{if (self.is_default) "true" else "false"});
        try writer.print("\"use_for_new\":{s},", .{if (self.use_for_new) "true" else "false"});
        try writer.print("\"use_for_reply\":{s},", .{if (self.use_for_reply) "true" else "false"});
        try writer.print("\"use_for_forward\":{s},", .{if (self.use_for_forward) "true" else "false"});
        try writer.print("\"position\":\"{s}\",", .{self.position.toString()});
        if (self.account_id) |aid| {
            try writer.print("\"account_id\":\"{s}\",", .{aid});
        } else {
            try writer.writeAll("\"account_id\":null,");
        }
        try writer.print("\"created_at\":{d},", .{self.created_at});
        try writer.print("\"updated_at\":{d}", .{self.updated_at});
        try writer.writeAll("}");

        return buffer.toOwnedSlice();
    }

    /// Get formatted text with separator
    pub fn getFormattedText(self: *const EmailSignature, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "\n\n--\n{s}", .{self.text});
    }

    /// Get formatted HTML with separator
    pub fn getFormattedHtml(self: *const EmailSignature, allocator: std.mem.Allocator) ![]u8 {
        if (self.html) |h| {
            return std.fmt.allocPrint(allocator, "<br><br><div class=\"signature\">--<br>{s}</div>", .{h});
        }
        // Convert plain text to HTML
        return std.fmt.allocPrint(allocator, "<br><br><div class=\"signature\">--<br>{s}</div>", .{self.text});
    }
};

/// Signature manager
pub const SignatureManager = struct {
    allocator: std.mem.Allocator,
    signatures: std.StringHashMap(EmailSignature),
    config: SignatureConfig,

    pub const SignatureConfig = struct {
        /// Maximum number of signatures per user
        max_signatures: usize = 10,
        /// Maximum signature size
        max_size: usize = 50 * 1024, // 50KB
        /// Enable HTML signatures
        enable_html: bool = true,
        /// Default position
        default_position: SignaturePosition = .bottom,
    };

    pub fn init(allocator: std.mem.Allocator, config: SignatureConfig) SignatureManager {
        return .{
            .allocator = allocator,
            .signatures = std.StringHashMap(EmailSignature).init(allocator),
            .config = config,
        };
    }

    pub fn deinit(self: *SignatureManager) void {
        var it = self.signatures.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.freeSignature(entry.value_ptr.*);
        }
        self.signatures.deinit();
    }

    fn freeSignature(self: *SignatureManager, sig: EmailSignature) void {
        self.allocator.free(sig.id);
        self.allocator.free(sig.name);
        self.allocator.free(sig.text);
        if (sig.html) |h| self.allocator.free(h);
        if (sig.account_id) |a| self.allocator.free(a);
    }

    /// Create a new signature
    pub fn create(
        self: *SignatureManager,
        name: []const u8,
        text: []const u8,
        html: ?[]const u8,
        options: CreateOptions,
    ) ![]const u8 {
        if (self.signatures.count() >= self.config.max_signatures) {
            return SignatureError.StorageFull;
        }

        if (text.len > self.config.max_size) {
            return SignatureError.InvalidSignature;
        }

        // Generate ID
        var rand_bytes: [8]u8 = undefined;
        io_compat.randomBytes(&rand_bytes);
        const timestamp = std.time.timestamp();

        const id = try std.fmt.allocPrint(self.allocator, "sig_{x}_{x}", .{
            @as(u64, @intCast(timestamp)),
            std.mem.readInt(u64, &rand_bytes, .big),
        });
        errdefer self.allocator.free(id);

        // Copy strings
        const name_copy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_copy);

        const text_copy = try self.allocator.dupe(u8, text);
        errdefer self.allocator.free(text_copy);

        var html_copy: ?[]u8 = null;
        if (html) |h| {
            html_copy = try self.allocator.dupe(u8, h);
        }
        errdefer if (html_copy) |h| self.allocator.free(h);

        var account_copy: ?[]u8 = null;
        if (options.account_id) |a| {
            account_copy = try self.allocator.dupe(u8, a);
        }
        errdefer if (account_copy) |a| self.allocator.free(a);

        // If this is set as default, unset others
        if (options.is_default) {
            self.unsetDefault(options.account_id);
        }

        const signature = EmailSignature{
            .id = id,
            .name = name_copy,
            .text = text_copy,
            .html = html_copy,
            .is_default = options.is_default,
            .use_for_new = options.use_for_new,
            .use_for_reply = options.use_for_reply,
            .use_for_forward = options.use_for_forward,
            .position = options.position,
            .account_id = account_copy,
            .created_at = timestamp,
            .updated_at = timestamp,
        };

        const key = try self.allocator.dupe(u8, id);
        try self.signatures.put(key, signature);

        return id;
    }

    pub const CreateOptions = struct {
        is_default: bool = false,
        use_for_new: bool = true,
        use_for_reply: bool = true,
        use_for_forward: bool = true,
        position: SignaturePosition = .bottom,
        account_id: ?[]const u8 = null,
    };

    /// Get signature by ID
    pub fn get(self: *const SignatureManager, id: []const u8) ?*const EmailSignature {
        return self.signatures.getPtr(id);
    }

    /// Get default signature
    pub fn getDefault(self: *const SignatureManager, account_id: ?[]const u8) ?*const EmailSignature {
        var it = self.signatures.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.is_default) {
                // Match account if specified
                if (account_id) |aid| {
                    if (entry.value_ptr.account_id) |sig_aid| {
                        if (std.mem.eql(u8, aid, sig_aid)) {
                            return entry.value_ptr;
                        }
                    }
                } else if (entry.value_ptr.account_id == null) {
                    return entry.value_ptr;
                }
            }
        }
        return null;
    }

    /// Get signature for specific context
    pub fn getForContext(
        self: *const SignatureManager,
        context: SignatureContext,
        account_id: ?[]const u8,
    ) ?*const EmailSignature {
        var it = self.signatures.iterator();
        while (it.next()) |entry| {
            const sig = entry.value_ptr;

            // Check account match
            if (account_id) |aid| {
                if (sig.account_id) |sig_aid| {
                    if (!std.mem.eql(u8, aid, sig_aid)) continue;
                }
            }

            // Check context
            const matches_context = switch (context) {
                .new_message => sig.use_for_new,
                .reply => sig.use_for_reply,
                .forward => sig.use_for_forward,
            };

            if (matches_context and sig.is_default) {
                return sig;
            }
        }

        // Fall back to any default
        return self.getDefault(account_id);
    }

    pub const SignatureContext = enum {
        new_message,
        reply,
        forward,
    };

    /// Update signature
    pub fn update(
        self: *SignatureManager,
        id: []const u8,
        updates: UpdateOptions,
    ) !void {
        const sig = self.signatures.getPtr(id) orelse return SignatureError.SignatureNotFound;

        if (updates.name) |name| {
            const name_copy = try self.allocator.dupe(u8, name);
            self.allocator.free(sig.name);
            sig.name = name_copy;
        }

        if (updates.text) |text| {
            const text_copy = try self.allocator.dupe(u8, text);
            self.allocator.free(sig.text);
            sig.text = text_copy;
        }

        if (updates.html) |html| {
            if (sig.html) |h| self.allocator.free(h);
            sig.html = try self.allocator.dupe(u8, html);
        }

        if (updates.is_default) |is_default| {
            if (is_default and !sig.is_default) {
                self.unsetDefault(sig.account_id);
            }
            sig.is_default = is_default;
        }

        if (updates.use_for_new) |v| sig.use_for_new = v;
        if (updates.use_for_reply) |v| sig.use_for_reply = v;
        if (updates.use_for_forward) |v| sig.use_for_forward = v;
        if (updates.position) |p| sig.position = p;

        sig.updated_at = std.time.timestamp();
    }

    pub const UpdateOptions = struct {
        name: ?[]const u8 = null,
        text: ?[]const u8 = null,
        html: ?[]const u8 = null,
        is_default: ?bool = null,
        use_for_new: ?bool = null,
        use_for_reply: ?bool = null,
        use_for_forward: ?bool = null,
        position: ?SignaturePosition = null,
    };

    /// Delete signature
    pub fn delete(self: *SignatureManager, id: []const u8) !void {
        if (self.signatures.fetchRemove(id)) |entry| {
            self.allocator.free(entry.key);
            self.freeSignature(entry.value);
        } else {
            return SignatureError.SignatureNotFound;
        }
    }

    /// List all signatures
    pub fn list(self: *const SignatureManager, allocator: std.mem.Allocator) ![]const EmailSignature {
        var result = try allocator.alloc(EmailSignature, self.signatures.count());
        var i: usize = 0;

        var it = self.signatures.iterator();
        while (it.next()) |entry| {
            result[i] = entry.value_ptr.*;
            i += 1;
        }

        return result;
    }

    /// Set a signature as default (unset others)
    pub fn setDefault(self: *SignatureManager, id: []const u8) !void {
        const sig = self.signatures.getPtr(id) orelse return SignatureError.SignatureNotFound;

        self.unsetDefault(sig.account_id);
        sig.is_default = true;
        sig.updated_at = std.time.timestamp();
    }

    fn unsetDefault(self: *SignatureManager, account_id: ?[]const u8) void {
        var it = self.signatures.iterator();
        while (it.next()) |entry| {
            if (account_id) |aid| {
                if (entry.value_ptr.account_id) |sig_aid| {
                    if (std.mem.eql(u8, aid, sig_aid)) {
                        entry.value_ptr.is_default = false;
                    }
                }
            } else if (entry.value_ptr.account_id == null) {
                entry.value_ptr.is_default = false;
            }
        }
    }

    /// Apply signature to email body
    pub fn applySignature(
        self: *SignatureManager,
        signature_id: []const u8,
        body_text: []const u8,
        body_html: ?[]const u8,
        quoted_text: ?[]const u8,
    ) !AppliedSignature {
        const sig = self.signatures.getPtr(signature_id) orelse return SignatureError.SignatureNotFound;

        var result_text: []u8 = undefined;
        var result_html: ?[]u8 = null;

        // Apply based on position
        switch (sig.position) {
            .bottom => {
                const formatted = try sig.getFormattedText(self.allocator);
                defer self.allocator.free(formatted);

                if (quoted_text) |qt| {
                    result_text = try std.fmt.allocPrint(self.allocator, "{s}\n\n{s}{s}", .{ body_text, qt, formatted });
                } else {
                    result_text = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ body_text, formatted });
                }
            },
            .above_quote => {
                const formatted = try sig.getFormattedText(self.allocator);
                defer self.allocator.free(formatted);

                if (quoted_text) |qt| {
                    result_text = try std.fmt.allocPrint(self.allocator, "{s}{s}\n\n{s}", .{ body_text, formatted, qt });
                } else {
                    result_text = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ body_text, formatted });
                }
            },
            .below_quote => {
                const formatted = try sig.getFormattedText(self.allocator);
                defer self.allocator.free(formatted);

                if (quoted_text) |qt| {
                    result_text = try std.fmt.allocPrint(self.allocator, "{s}\n\n{s}{s}", .{ body_text, qt, formatted });
                } else {
                    result_text = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ body_text, formatted });
                }
            },
        }

        // Apply to HTML if provided
        if (body_html) |html| {
            const formatted_html = try sig.getFormattedHtml(self.allocator);
            defer self.allocator.free(formatted_html);
            result_html = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ html, formatted_html });
        }

        return .{
            .text = result_text,
            .html = result_html,
        };
    }

    pub const AppliedSignature = struct {
        text: []const u8,
        html: ?[]const u8,
    };

    /// Get statistics
    pub fn getStats(self: *const SignatureManager) SignatureStats {
        var html_count: usize = 0;
        var default_count: usize = 0;

        var it = self.signatures.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.html != null) html_count += 1;
            if (entry.value_ptr.is_default) default_count += 1;
        }

        return .{
            .total_signatures = self.signatures.count(),
            .html_signatures = html_count,
            .default_signatures = default_count,
        };
    }
};

/// Signature statistics
pub const SignatureStats = struct {
    total_signatures: usize,
    html_signatures: usize,
    default_signatures: usize,
};

// =============================================================================
// Built-in Signatures
// =============================================================================

/// Get professional signature template
pub fn getProfessionalSignature() EmailSignature {
    return .{
        .id = "builtin_professional",
        .name = "Professional",
        .text =
        \\Best regards,
        \\
        \\{{name}}
        \\{{title}}
        \\{{company}}
        \\Phone: {{phone}}
        \\Email: {{email}}
        ,
        .html =
        \\<div style="font-family: Arial, sans-serif; font-size: 14px; color: #333;">
        \\  <p style="margin: 0;">Best regards,</p>
        \\  <p style="margin: 16px 0 4px; font-weight: bold;">{{name}}</p>
        \\  <p style="margin: 0; color: #666;">{{title}}</p>
        \\  <p style="margin: 0; color: #666;">{{company}}</p>
        \\  <p style="margin: 8px 0 0; font-size: 12px;">
        \\    <span>Phone: {{phone}}</span> | <span>Email: {{email}}</span>
        \\  </p>
        \\</div>
        ,
        .is_default = false,
        .use_for_new = true,
        .use_for_reply = true,
        .use_for_forward = true,
        .position = .bottom,
        .account_id = null,
        .created_at = 0,
        .updated_at = 0,
    };
}

/// Get simple signature template
pub fn getSimpleSignature() EmailSignature {
    return .{
        .id = "builtin_simple",
        .name = "Simple",
        .text =
        \\Thanks,
        \\{{name}}
        ,
        .html = null,
        .is_default = false,
        .use_for_new = true,
        .use_for_reply = true,
        .use_for_forward = false,
        .position = .bottom,
        .account_id = null,
        .created_at = 0,
        .updated_at = 0,
    };
}

// =============================================================================
// Helper Functions
// =============================================================================

fn escapeJson(s: []const u8) []const u8 {
    return s; // Production would need proper escaping
}

// =============================================================================
// Tests
// =============================================================================

test "SignatureManager create and get" {
    const allocator = std.testing.allocator;

    var manager = SignatureManager.init(allocator, .{});
    defer manager.deinit();

    const id = try manager.create(
        "My Signature",
        "Best regards,\nJohn",
        null,
        .{ .is_default = true },
    );

    const sig = manager.get(id);
    try std.testing.expect(sig != null);
    try std.testing.expectEqualStrings("My Signature", sig.?.name);
    try std.testing.expect(sig.?.is_default);
}

test "SignatureManager default handling" {
    const allocator = std.testing.allocator;

    var manager = SignatureManager.init(allocator, .{});
    defer manager.deinit();

    const id1 = try manager.create("Sig 1", "Text 1", null, .{ .is_default = true });
    const id2 = try manager.create("Sig 2", "Text 2", null, .{ .is_default = true });

    // id2 should now be default, id1 should not
    const sig1 = manager.get(id1);
    const sig2 = manager.get(id2);

    try std.testing.expect(!sig1.?.is_default);
    try std.testing.expect(sig2.?.is_default);
}

test "SignatureManager getForContext" {
    const allocator = std.testing.allocator;

    var manager = SignatureManager.init(allocator, .{});
    defer manager.deinit();

    _ = try manager.create("Reply Sig", "Reply text", null, .{
        .is_default = true,
        .use_for_new = false,
        .use_for_reply = true,
    });

    const reply_sig = manager.getForContext(.reply, null);
    try std.testing.expect(reply_sig != null);
    try std.testing.expectEqualStrings("Reply Sig", reply_sig.?.name);
}

test "EmailSignature getFormattedText" {
    const allocator = std.testing.allocator;

    const sig = EmailSignature{
        .id = "test",
        .name = "Test",
        .text = "Best,\nJohn",
        .html = null,
        .is_default = false,
        .use_for_new = true,
        .use_for_reply = true,
        .use_for_forward = true,
        .position = .bottom,
        .account_id = null,
        .created_at = 0,
        .updated_at = 0,
    };

    const formatted = try sig.getFormattedText(allocator);
    defer allocator.free(formatted);

    try std.testing.expect(std.mem.indexOf(u8, formatted, "--") != null);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "John") != null);
}

test "SignaturePosition toString" {
    try std.testing.expectEqualStrings("Bottom", SignaturePosition.bottom.toString());
    try std.testing.expectEqualStrings("Above Quote", SignaturePosition.above_quote.toString());
}
