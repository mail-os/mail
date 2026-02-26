const std = @import("std");

// =============================================================================
// Email Templates System
// =============================================================================
//
// ## Overview
// Provides pre-defined email templates with variable substitution for common
// messages like vacation replies, form letters, and quick responses.
//
// ## Variable Syntax
// Templates use {{variable_name}} syntax for substitution:
//   - {{recipient_name}} - Recipient's name
//   - {{sender_name}} - Sender's name
//   - {{date}} - Current date
//   - {{company}} - Company name
//   - {{custom:field}} - Custom user-defined field
//
// =============================================================================

/// Template-related errors
pub const TemplateError = error{
    TemplateNotFound,
    InvalidTemplate,
    VariableNotFound,
    CircularReference,
    OutOfMemory,
    StorageFull,
};

/// Template category
pub const TemplateCategory = enum {
    vacation,
    auto_reply,
    form_letter,
    quick_response,
    newsletter,
    notification,
    custom,

    pub fn toString(self: TemplateCategory) []const u8 {
        return switch (self) {
            .vacation => "Vacation",
            .auto_reply => "Auto Reply",
            .form_letter => "Form Letter",
            .quick_response => "Quick Response",
            .newsletter => "Newsletter",
            .notification => "Notification",
            .custom => "Custom",
        };
    }

    pub fn icon(self: TemplateCategory) []const u8 {
        return switch (self) {
            .vacation => "sun",
            .auto_reply => "repeat",
            .form_letter => "file-text",
            .quick_response => "zap",
            .newsletter => "mail",
            .notification => "bell",
            .custom => "edit",
        };
    }
};

/// Email template
pub const EmailTemplate = struct {
    id: []const u8,
    name: []const u8,
    description: ?[]const u8,
    category: TemplateCategory,
    subject: []const u8,
    body_text: []const u8,
    body_html: ?[]const u8,
    variables: []const TemplateVariable,
    is_active: bool,
    use_count: u32,
    created_at: i64,
    updated_at: i64,

    /// Variable definition in template
    pub const TemplateVariable = struct {
        name: []const u8,
        description: ?[]const u8,
        default_value: ?[]const u8,
        required: bool,
    };

    /// Convert to JSON
    pub fn toJson(self: *const EmailTemplate, allocator: std.mem.Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        errdefer buffer.deinit();
        const writer = buffer.writer();

        try writer.writeAll("{");
        try writer.print("\"id\":\"{s}\",", .{self.id});
        try writer.print("\"name\":\"{s}\",", .{escapeJson(self.name)});
        if (self.description) |desc| {
            try writer.print("\"description\":\"{s}\",", .{escapeJson(desc)});
        } else {
            try writer.writeAll("\"description\":null,");
        }
        try writer.print("\"category\":\"{s}\",", .{self.category.toString()});
        try writer.print("\"subject\":\"{s}\",", .{escapeJson(self.subject)});
        try writer.print("\"body_text\":\"{s}\",", .{escapeJson(self.body_text)});
        if (self.body_html) |html| {
            try writer.print("\"body_html\":\"{s}\",", .{escapeJson(html)});
        } else {
            try writer.writeAll("\"body_html\":null,");
        }
        try writer.print("\"is_active\":{s},", .{if (self.is_active) "true" else "false"});
        try writer.print("\"use_count\":{d},", .{self.use_count});
        try writer.print("\"created_at\":{d},", .{self.created_at});
        try writer.print("\"updated_at\":{d},", .{self.updated_at});

        // Variables
        try writer.writeAll("\"variables\":[");
        for (self.variables, 0..) |v, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.writeAll("{");
            try writer.print("\"name\":\"{s}\",", .{v.name});
            if (v.description) |desc| {
                try writer.print("\"description\":\"{s}\",", .{escapeJson(desc)});
            } else {
                try writer.writeAll("\"description\":null,");
            }
            if (v.default_value) |def| {
                try writer.print("\"default_value\":\"{s}\",", .{escapeJson(def)});
            } else {
                try writer.writeAll("\"default_value\":null,");
            }
            try writer.print("\"required\":{s}", .{if (v.required) "true" else "false"});
            try writer.writeAll("}");
        }
        try writer.writeAll("]}");

        return buffer.toOwnedSlice();
    }
};

/// Template manager
pub const TemplateManager = struct {
    allocator: std.mem.Allocator,
    templates: std.StringHashMap(EmailTemplate),
    config: TemplateConfig,

    pub const TemplateConfig = struct {
        /// Maximum number of templates
        max_templates: usize = 100,
        /// Maximum template body size
        max_body_size: usize = 100 * 1024, // 100KB
        /// Enable HTML templates
        enable_html: bool = true,
    };

    pub fn init(allocator: std.mem.Allocator, config: TemplateConfig) TemplateManager {
        return .{
            .allocator = allocator,
            .templates = std.StringHashMap(EmailTemplate).init(allocator),
            .config = config,
        };
    }

    pub fn deinit(self: *TemplateManager) void {
        var it = self.templates.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.freeTemplate(entry.value_ptr.*);
        }
        self.templates.deinit();
    }

    fn freeTemplate(self: *TemplateManager, template: EmailTemplate) void {
        self.allocator.free(template.id);
        self.allocator.free(template.name);
        if (template.description) |d| self.allocator.free(d);
        self.allocator.free(template.subject);
        self.allocator.free(template.body_text);
        if (template.body_html) |h| self.allocator.free(h);
        for (template.variables) |v| {
            self.allocator.free(v.name);
            if (v.description) |d| self.allocator.free(d);
            if (v.default_value) |d| self.allocator.free(d);
        }
        if (template.variables.len > 0) {
            self.allocator.free(template.variables);
        }
    }

    /// Create a new template
    pub fn create(
        self: *TemplateManager,
        name: []const u8,
        category: TemplateCategory,
        subject: []const u8,
        body_text: []const u8,
        body_html: ?[]const u8,
        description: ?[]const u8,
    ) ![]const u8 {
        if (self.templates.count() >= self.config.max_templates) {
            return TemplateError.StorageFull;
        }

        if (body_text.len > self.config.max_body_size) {
            return TemplateError.InvalidTemplate;
        }

        // Generate ID
        var rand_bytes: [8]u8 = undefined;
        std.c.arc4random_buf(&rand_bytes, rand_bytes.len);
        const timestamp = std.time.timestamp();

        const id = try std.fmt.allocPrint(self.allocator, "tmpl_{x}_{x}", .{
            @as(u64, @intCast(timestamp)),
            std.mem.readInt(u64, &rand_bytes, .big),
        });
        errdefer self.allocator.free(id);

        // Extract variables from body
        const variables = try self.extractVariables(body_text);

        // Copy strings
        const name_copy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_copy);

        const subject_copy = try self.allocator.dupe(u8, subject);
        errdefer self.allocator.free(subject_copy);

        const body_copy = try self.allocator.dupe(u8, body_text);
        errdefer self.allocator.free(body_copy);

        var html_copy: ?[]u8 = null;
        if (body_html) |h| {
            html_copy = try self.allocator.dupe(u8, h);
        }
        errdefer if (html_copy) |h| self.allocator.free(h);

        var desc_copy: ?[]u8 = null;
        if (description) |d| {
            desc_copy = try self.allocator.dupe(u8, d);
        }
        errdefer if (desc_copy) |d| self.allocator.free(d);

        const template = EmailTemplate{
            .id = id,
            .name = name_copy,
            .description = desc_copy,
            .category = category,
            .subject = subject_copy,
            .body_text = body_copy,
            .body_html = html_copy,
            .variables = variables,
            .is_active = true,
            .use_count = 0,
            .created_at = timestamp,
            .updated_at = timestamp,
        };

        const key = try self.allocator.dupe(u8, id);
        try self.templates.put(key, template);

        return id;
    }

    /// Get template by ID
    pub fn get(self: *const TemplateManager, id: []const u8) ?*const EmailTemplate {
        return self.templates.getPtr(id);
    }

    /// Delete template
    pub fn delete(self: *TemplateManager, id: []const u8) !void {
        if (self.templates.fetchRemove(id)) |entry| {
            self.allocator.free(entry.key);
            self.freeTemplate(entry.value);
        } else {
            return TemplateError.TemplateNotFound;
        }
    }

    /// List all templates
    pub fn list(self: *const TemplateManager, allocator: std.mem.Allocator) ![]const EmailTemplate {
        var result = try allocator.alloc(EmailTemplate, self.templates.count());
        var i: usize = 0;

        var it = self.templates.iterator();
        while (it.next()) |entry| {
            result[i] = entry.value_ptr.*;
            i += 1;
        }

        return result;
    }

    /// List templates by category
    pub fn listByCategory(self: *const TemplateManager, category: TemplateCategory, allocator: std.mem.Allocator) ![]const EmailTemplate {
        var count: usize = 0;
        var it = self.templates.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.category == category) {
                count += 1;
            }
        }

        var result = try allocator.alloc(EmailTemplate, count);
        var i: usize = 0;

        it = self.templates.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.category == category) {
                result[i] = entry.value_ptr.*;
                i += 1;
            }
        }

        return result;
    }

    /// Apply template with variables
    pub fn apply(
        self: *TemplateManager,
        id: []const u8,
        variables: []const VariableValue,
    ) !AppliedTemplate {
        const template = self.templates.getPtr(id) orelse return TemplateError.TemplateNotFound;

        // Increment use count
        template.use_count += 1;

        // Apply substitutions
        const subject = try self.substitute(template.subject, variables);
        errdefer self.allocator.free(subject);

        const body_text = try self.substitute(template.body_text, variables);
        errdefer self.allocator.free(body_text);

        var body_html: ?[]u8 = null;
        if (template.body_html) |html| {
            body_html = try self.substitute(html, variables);
        }

        return .{
            .subject = subject,
            .body_text = body_text,
            .body_html = body_html,
        };
    }

    /// Variable value for substitution
    pub const VariableValue = struct {
        name: []const u8,
        value: []const u8,
    };

    /// Result of applying a template
    pub const AppliedTemplate = struct {
        subject: []const u8,
        body_text: []const u8,
        body_html: ?[]const u8,
    };

    /// Substitute variables in text
    fn substitute(self: *TemplateManager, text: []const u8, variables: []const VariableValue) ![]u8 {
        var result = std.ArrayList(u8).init(self.allocator);
        errdefer result.deinit();

        var i: usize = 0;
        while (i < text.len) {
            // Look for {{
            if (i + 2 <= text.len and std.mem.eql(u8, text[i .. i + 2], "{{")) {
                // Find closing }}
                if (std.mem.indexOfPos(u8, text, i + 2, "}}")) |end| {
                    const var_name = std.mem.trim(u8, text[i + 2 .. end], " ");

                    // Look for variable value
                    var found = false;
                    for (variables) |v| {
                        if (std.mem.eql(u8, v.name, var_name)) {
                            try result.appendSlice(v.value);
                            found = true;
                            break;
                        }
                    }

                    // Use built-in variables if not provided
                    if (!found) {
                        if (std.mem.eql(u8, var_name, "date")) {
                            const date = try self.getCurrentDate();
                            defer self.allocator.free(date);
                            try result.appendSlice(date);
                            found = true;
                        }
                    }

                    // Keep original if not found
                    if (!found) {
                        try result.appendSlice(text[i .. end + 2]);
                    }

                    i = end + 2;
                    continue;
                }
            }

            try result.append(text[i]);
            i += 1;
        }

        return result.toOwnedSlice();
    }

    /// Extract variable names from template
    fn extractVariables(self: *TemplateManager, text: []const u8) ![]const EmailTemplate.TemplateVariable {
        var names = std.ArrayList([]const u8).init(self.allocator);
        defer {
            for (names.items) |n| self.allocator.free(n);
            names.deinit();
        }

        var i: usize = 0;
        while (i < text.len) {
            if (i + 2 <= text.len and std.mem.eql(u8, text[i .. i + 2], "{{")) {
                if (std.mem.indexOfPos(u8, text, i + 2, "}}")) |end| {
                    const var_name = std.mem.trim(u8, text[i + 2 .. end], " ");

                    // Skip built-in variables
                    const builtins = [_][]const u8{ "date", "time", "year", "month", "day" };
                    var is_builtin = false;
                    for (builtins) |b| {
                        if (std.mem.eql(u8, var_name, b)) {
                            is_builtin = true;
                            break;
                        }
                    }

                    if (!is_builtin) {
                        // Check if already added
                        var exists = false;
                        for (names.items) |n| {
                            if (std.mem.eql(u8, n, var_name)) {
                                exists = true;
                                break;
                            }
                        }

                        if (!exists) {
                            const name_copy = try self.allocator.dupe(u8, var_name);
                            try names.append(name_copy);
                        }
                    }

                    i = end + 2;
                    continue;
                }
            }
            i += 1;
        }

        // Convert to TemplateVariable array
        var result = try self.allocator.alloc(EmailTemplate.TemplateVariable, names.items.len);
        for (names.items, 0..) |name, idx| {
            result[idx] = .{
                .name = try self.allocator.dupe(u8, name),
                .description = null,
                .default_value = null,
                .required = true,
            };
        }

        return result;
    }

    fn getCurrentDate(self: *TemplateManager) ![]u8 {
        const timestamp = std.time.timestamp();
        const epoch_seconds = @as(u64, @intCast(timestamp));
        const days_since_epoch = epoch_seconds / 86400;

        // Simple date calculation
        var year: u32 = 1970;
        var remaining_days = days_since_epoch;

        while (true) {
            const days_in_year: u64 = if (isLeapYear(year)) 366 else 365;
            if (remaining_days < days_in_year) break;
            remaining_days -= days_in_year;
            year += 1;
        }

        const months = [_]u32{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
        var month: u32 = 1;
        for (months, 0..) |days, i| {
            var d = days;
            if (i == 1 and isLeapYear(year)) d = 29;
            if (remaining_days < d) break;
            remaining_days -= d;
            month += 1;
        }

        const day = @as(u32, @intCast(remaining_days)) + 1;

        return std.fmt.allocPrint(self.allocator, "{d}-{d:0>2}-{d:0>2}", .{ year, month, day });
    }

    /// Get statistics
    pub fn getStats(self: *const TemplateManager) TemplateStats {
        var total_uses: u32 = 0;
        var active_count: usize = 0;

        var it = self.templates.iterator();
        while (it.next()) |entry| {
            total_uses += entry.value_ptr.use_count;
            if (entry.value_ptr.is_active) {
                active_count += 1;
            }
        }

        return .{
            .total_templates = self.templates.count(),
            .active_templates = active_count,
            .total_uses = total_uses,
        };
    }
};

fn isLeapYear(year: u32) bool {
    return (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0);
}

/// Template statistics
pub const TemplateStats = struct {
    total_templates: usize,
    active_templates: usize,
    total_uses: u32,
};

// =============================================================================
// Built-in Templates
// =============================================================================

/// Get default vacation template
pub fn getVacationTemplate() EmailTemplate {
    return .{
        .id = "builtin_vacation",
        .name = "Out of Office",
        .description = "Standard vacation auto-reply",
        .category = .vacation,
        .subject = "Out of Office: {{original_subject}}",
        .body_text =
        \\Hello,
        \\
        \\Thank you for your email. I am currently out of the office from {{start_date}} to {{end_date}}.
        \\
        \\I will have limited access to email during this time. If your matter is urgent, please contact {{alternate_contact}}.
        \\
        \\I will respond to your email upon my return.
        \\
        \\Best regards,
        \\{{sender_name}}
        ,
        .body_html = null,
        .variables = &[_]EmailTemplate.TemplateVariable{
            .{ .name = "start_date", .description = "Vacation start date", .default_value = null, .required = true },
            .{ .name = "end_date", .description = "Vacation end date", .default_value = null, .required = true },
            .{ .name = "alternate_contact", .description = "Emergency contact", .default_value = null, .required = false },
            .{ .name = "sender_name", .description = "Your name", .default_value = null, .required = true },
        },
        .is_active = true,
        .use_count = 0,
        .created_at = 0,
        .updated_at = 0,
    };
}

/// Get default thank you template
pub fn getThankYouTemplate() EmailTemplate {
    return .{
        .id = "builtin_thankyou",
        .name = "Thank You",
        .description = "Quick thank you response",
        .category = .quick_response,
        .subject = "Re: {{original_subject}}",
        .body_text =
        \\Hi {{recipient_name}},
        \\
        \\Thank you for your message. I appreciate you taking the time to reach out.
        \\
        \\{{custom_message}}
        \\
        \\Best regards,
        \\{{sender_name}}
        ,
        .body_html = null,
        .variables = &[_]EmailTemplate.TemplateVariable{
            .{ .name = "recipient_name", .description = "Recipient's name", .default_value = null, .required = true },
            .{ .name = "custom_message", .description = "Additional message", .default_value = "", .required = false },
            .{ .name = "sender_name", .description = "Your name", .default_value = null, .required = true },
        },
        .is_active = true,
        .use_count = 0,
        .created_at = 0,
        .updated_at = 0,
    };
}

/// Get meeting request template
pub fn getMeetingTemplate() EmailTemplate {
    return .{
        .id = "builtin_meeting",
        .name = "Meeting Request",
        .description = "Request a meeting",
        .category = .form_letter,
        .subject = "Meeting Request: {{meeting_topic}}",
        .body_text =
        \\Hi {{recipient_name}},
        \\
        \\I would like to schedule a meeting to discuss {{meeting_topic}}.
        \\
        \\Proposed time: {{proposed_time}}
        \\Duration: {{duration}}
        \\Location: {{location}}
        \\
        \\Please let me know if this works for you, or suggest an alternative time.
        \\
        \\Best regards,
        \\{{sender_name}}
        ,
        .body_html = null,
        .variables = &[_]EmailTemplate.TemplateVariable{
            .{ .name = "recipient_name", .description = "Recipient's name", .default_value = null, .required = true },
            .{ .name = "meeting_topic", .description = "Topic of meeting", .default_value = null, .required = true },
            .{ .name = "proposed_time", .description = "Suggested date/time", .default_value = null, .required = true },
            .{ .name = "duration", .description = "Meeting duration", .default_value = "30 minutes", .required = false },
            .{ .name = "location", .description = "Meeting location", .default_value = "TBD", .required = false },
            .{ .name = "sender_name", .description = "Your name", .default_value = null, .required = true },
        },
        .is_active = true,
        .use_count = 0,
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

test "TemplateManager create and get" {
    const allocator = std.testing.allocator;

    var manager = TemplateManager.init(allocator, .{});
    defer manager.deinit();

    const id = try manager.create(
        "Test Template",
        .quick_response,
        "Hello {{name}}",
        "Dear {{name}},\n\nThank you for your message.\n\nBest,\n{{sender}}",
        null,
        "A test template",
    );

    const template = manager.get(id);
    try std.testing.expect(template != null);
    try std.testing.expectEqualStrings("Test Template", template.?.name);
}

test "TemplateManager apply with variables" {
    const allocator = std.testing.allocator;

    var manager = TemplateManager.init(allocator, .{});
    defer manager.deinit();

    const id = try manager.create(
        "Greeting",
        .quick_response,
        "Hello {{name}}!",
        "Dear {{name}}, welcome to {{company}}!",
        null,
        null,
    );

    const variables = [_]TemplateManager.VariableValue{
        .{ .name = "name", .value = "John" },
        .{ .name = "company", .value = "Acme Corp" },
    };

    const result = try manager.apply(id, &variables);
    defer {
        allocator.free(result.subject);
        allocator.free(result.body_text);
    }

    try std.testing.expectEqualStrings("Hello John!", result.subject);
    try std.testing.expectEqualStrings("Dear John, welcome to Acme Corp!", result.body_text);
}

test "TemplateCategory toString" {
    try std.testing.expectEqualStrings("Vacation", TemplateCategory.vacation.toString());
    try std.testing.expectEqualStrings("Quick Response", TemplateCategory.quick_response.toString());
}

test "Variable extraction" {
    const allocator = std.testing.allocator;

    var manager = TemplateManager.init(allocator, .{});
    defer manager.deinit();

    const id = try manager.create(
        "Multi-var",
        .form_letter,
        "Subject",
        "Hello {{name}}, from {{sender}}. Today is {{date}}.",
        null,
        null,
    );

    const template = manager.get(id);
    try std.testing.expect(template != null);
    // Should have 2 variables (name, sender) - date is built-in
    try std.testing.expectEqual(@as(usize, 2), template.?.variables.len);
}
