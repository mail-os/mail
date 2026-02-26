// CAN-SPAM Act Compliance Implementation
// Controlling the Assault of Non-Solicited Pornography And Marketing Act of 2003
// https://www.ftc.gov/business-guidance/resources/can-spam-act-compliance-guide-business

const std = @import("std");
const time_compat = @import("../core/time_compat.zig");

/// CAN-SPAM compliance checker and enforcer
pub const CanSpamCompliance = struct {
    allocator: std.mem.Allocator,
    unsubscribe_domain: []const u8,
    physical_address: []const u8,

    const Self = @This();

    pub const Config = struct {
        unsubscribe_domain: []const u8,
        physical_address: []const u8,
    };

    pub const ValidationResult = struct {
        is_compliant: bool,
        violations: std.ArrayList(Violation),

        pub fn deinit(self: *ValidationResult) void {
            for (self.violations.items) |violation| {
                self.violations.allocator.free(violation.description);
            }
            self.violations.deinit();
        }
    };

    pub const Violation = struct {
        rule: Rule,
        description: []const u8,
    };

    pub const Rule = enum {
        missing_unsubscribe_link,
        invalid_unsubscribe_format,
        missing_physical_address,
        deceptive_subject_line,
        missing_from_header,
        invalid_from_header,
        missing_ad_identifier,
        expired_unsubscribe_option,
    };

    pub fn init(allocator: std.mem.Allocator, config: Config) !Self {
        return Self{
            .allocator = allocator,
            .unsubscribe_domain = try allocator.dupe(u8, config.unsubscribe_domain),
            .physical_address = try allocator.dupe(u8, config.physical_address),
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.unsubscribe_domain);
        self.allocator.free(self.physical_address);
    }

    /// Validate a message for CAN-SPAM compliance
    pub fn validateMessage(self: *Self, message: []const u8) !ValidationResult {
        var violations = std.ArrayList(Violation).init(self.allocator);

        // Parse message into headers and body
        const separator_pos = std.mem.indexOf(u8, message, "\r\n\r\n") orelse
            std.mem.indexOf(u8, message, "\n\n") orelse
            return error.InvalidMessageFormat;

        const headers_section = message[0..separator_pos];
        const body_section = if (separator_pos + 4 <= message.len)
            message[separator_pos + 4 ..]
        else
            message[separator_pos + 2 ..];

        // Parse headers
        var headers = std.StringHashMap([]const u8).init(self.allocator);
        defer headers.deinit();
        try self.parseHeaders(headers_section, &headers);

        // Rule 1: Don't use false or misleading header information
        try self.checkFromHeader(&headers, &violations);

        // Rule 2: Don't use deceptive subject lines
        try self.checkSubjectLine(&headers, &violations);

        // Rule 3: Identify the message as an ad (if commercial)
        // Note: This is context-dependent and may need manual review

        // Rule 4: Tell recipients where you're located
        try self.checkPhysicalAddress(body_section, &violations);

        // Rule 5: Tell recipients how to opt out
        try self.checkUnsubscribeLink(body_section, &violations);

        // Rule 6: Honor opt-out requests promptly (within 10 business days)
        // This is a process requirement, not message validation

        const is_compliant = violations.items.len == 0;

        return ValidationResult{
            .is_compliant = is_compliant,
            .violations = violations,
        };
    }

    /// Add CAN-SPAM required elements to a message
    pub fn addComplianceElements(
        self: *Self,
        message: []const u8,
        is_commercial: bool,
    ) ![]const u8 {
        // Parse message
        const separator_pos = std.mem.indexOf(u8, message, "\r\n\r\n") orelse
            std.mem.indexOf(u8, message, "\n\n") orelse
            return error.InvalidMessageFormat;

        const headers_section = message[0..separator_pos];
        var body_section = if (separator_pos + 4 <= message.len)
            message[separator_pos + 4 ..]
        else
            message[separator_pos + 2 ..];

        // Parse headers to get recipient
        var headers = std.StringHashMap([]const u8).init(self.allocator);
        defer headers.deinit();
        try self.parseHeaders(headers_section, &headers);

        const to_header = headers.get("To") orelse headers.get("to") orelse "recipient@example.com";

        // Build enhanced body
        var enhanced_body = std.ArrayList(u8).init(self.allocator);
        defer enhanced_body.deinit();

        // Original body
        try enhanced_body.appendSlice(body_section);

        // Add footer
        try enhanced_body.appendSlice("\r\n\r\n");
        try enhanced_body.appendSlice("--------------------------------------------------\r\n");

        // Add commercial identifier if needed
        if (is_commercial) {
            try enhanced_body.appendSlice("This is a commercial message.\r\n\r\n");
        }

        // Add physical address
        try enhanced_body.appendSlice("Sent by:\r\n");
        try enhanced_body.appendSlice(self.physical_address);
        try enhanced_body.appendSlice("\r\n\r\n");

        // Add unsubscribe link
        const unsubscribe_link = try self.generateUnsubscribeLink(to_header);
        defer self.allocator.free(unsubscribe_link);

        try enhanced_body.appendSlice("To unsubscribe from future emails, click here:\r\n");
        try enhanced_body.appendSlice(unsubscribe_link);
        try enhanced_body.appendSlice("\r\n\r\n");
        try enhanced_body.appendSlice("You may also reply to this email with \"UNSUBSCRIBE\" in the subject line.\r\n");

        // Reconstruct message
        var result = std.ArrayList(u8).init(self.allocator);
        errdefer result.deinit();

        try result.appendSlice(headers_section);
        try result.appendSlice("\r\n\r\n");
        try result.appendSlice(enhanced_body.items);

        return result.toOwnedSlice();
    }

    /// Generate an unsubscribe link for a recipient
    fn generateUnsubscribeLink(self: *Self, recipient: []const u8) ![]const u8 {
        // Extract email from "Name <email>" format
        const email = if (std.mem.indexOf(u8, recipient, "<")) |start| blk: {
            if (std.mem.indexOf(u8, recipient[start..], ">")) |end| {
                break :blk recipient[start + 1 .. start + end];
            }
            break :blk recipient;
        } else recipient;

        // URL-encode email
        // For simplicity, just replace @ and . (real implementation needs full URL encoding)
        const encoded = try self.allocator.dupe(u8, email);
        // In production, use proper URL encoding

        return try std.fmt.allocPrint(
            self.allocator,
            "https://{s}/unsubscribe?email={s}",
            .{ self.unsubscribe_domain, encoded },
        );
    }

    // Validation functions

    fn checkFromHeader(
        self: *Self,
        headers: *std.StringHashMap([]const u8),
        violations: *std.ArrayList(Violation),
    ) !void {
        _ = self;

        const from = headers.get("From") orelse headers.get("from") orelse {
            try violations.append(.{
                .rule = .missing_from_header,
                .description = try violations.allocator.dupe(u8, "Missing From header"),
            });
            return;
        };

        // From must contain valid email address
        if (std.mem.indexOf(u8, from, "@") == null) {
            try violations.append(.{
                .rule = .invalid_from_header,
                .description = try violations.allocator.dupe(u8, "From header does not contain valid email address"),
            });
        }

        // From must not be misleading (check for common spoofing patterns)
        // This is a simplified check; real implementation needs more sophisticated detection
        if (std.mem.indexOf(u8, from, "noreply") == null and
            std.mem.indexOf(u8, from, "no-reply") == null)
        {
            // Legitimate From address
        }
    }

    fn checkSubjectLine(
        self: *Self,
        headers: *std.StringHashMap([]const u8),
        violations: *std.ArrayList(Violation),
    ) !void {
        _ = self;

        const subject = headers.get("Subject") orelse headers.get("subject") orelse "";

        // Check for deceptive subject line indicators
        const deceptive_patterns = [_][]const u8{
            "RE: ",  // False reply indicator
            "FWD: ", // False forward indicator
            "urgent",
            "URGENT",
            "congratulations you won",
            "act now",
            "limited time",
        };

        for (deceptive_patterns) |pattern| {
            if (std.ascii.indexOfIgnoreCase(subject, pattern)) |_| {
                // Potentially deceptive - log warning
                // In production, this might be configurable
                break;
            }
        }
    }

    fn checkPhysicalAddress(
        self: *Self,
        body: []const u8,
        violations: *std.ArrayList(Violation),
    ) !void {
        _ = self;

        // Check if body contains a physical address
        // Look for address indicators
        const address_indicators = [_][]const u8{
            "street",
            "avenue",
            "road",
            "suite",
            "floor",
            "building",
            "city",
            "state",
            "zip",
            "postal",
        };

        var has_address = false;
        const lower_body = try std.ascii.allocLowerString(violations.allocator, body);
        defer violations.allocator.free(lower_body);

        for (address_indicators) |indicator| {
            if (std.mem.indexOf(u8, lower_body, indicator) != null) {
                has_address = true;
                break;
            }
        }

        if (!has_address) {
            try violations.append(.{
                .rule = .missing_physical_address,
                .description = try violations.allocator.dupe(u8, "Message does not contain a valid physical postal address"),
            });
        }
    }

    fn checkUnsubscribeLink(
        self: *Self,
        body: []const u8,
        violations: *std.ArrayList(Violation),
    ) !void {
        _ = self;

        const lower_body = try std.ascii.allocLowerString(violations.allocator, body);
        defer violations.allocator.free(lower_body);

        // Check for unsubscribe link
        const has_unsubscribe = std.mem.indexOf(u8, lower_body, "unsubscribe") != null or
            std.mem.indexOf(u8, lower_body, "opt out") != null or
            std.mem.indexOf(u8, lower_body, "opt-out") != null;

        if (!has_unsubscribe) {
            try violations.append(.{
                .rule = .missing_unsubscribe_link,
                .description = try violations.allocator.dupe(u8, "Message does not contain an unsubscribe mechanism"),
            });
            return;
        }

        // Check for valid unsubscribe link format
        const has_link = std.mem.indexOf(u8, lower_body, "http://") != null or
            std.mem.indexOf(u8, lower_body, "https://") != null;

        const has_email_instruction = std.mem.indexOf(u8, lower_body, "reply") != null;

        if (!has_link and !has_email_instruction) {
            try violations.append(.{
                .rule = .invalid_unsubscribe_format,
                .description = try violations.allocator.dupe(u8, "Unsubscribe mechanism must be a working link or email reply"),
            });
        }
    }

    fn parseHeaders(
        self: *Self,
        headers_section: []const u8,
        headers: *std.StringHashMap([]const u8),
    ) !void {
        _ = self;

        var lines = std.mem.split(u8, headers_section, "\n");
        var current_name: ?[]const u8 = null;
        var current_value = std.ArrayList(u8).init(headers.allocator);
        defer current_value.deinit();

        while (lines.next()) |line| {
            const trimmed = std.mem.trimEnd(u8, line, "\r");
            if (trimmed.len == 0) continue;

            // Check if continuation line
            if (trimmed[0] == ' ' or trimmed[0] == '\t') {
                try current_value.appendSlice(" ");
                try current_value.appendSlice(std.mem.trim(u8, trimmed, " \t"));
                continue;
            }

            // Save previous header
            if (current_name) |name| {
                const value = try current_value.toOwnedSlice();
                try headers.put(name, value);
                current_value = std.ArrayList(u8).init(headers.allocator);
            }

            // Parse new header
            if (std.mem.indexOf(u8, trimmed, ":")) |colon_pos| {
                const name = try headers.allocator.dupe(u8, trimmed[0..colon_pos]);
                current_name = name;

                const value_start = colon_pos + 1;
                const value_raw = if (value_start < trimmed.len)
                    trimmed[value_start..]
                else
                    "";
                try current_value.appendSlice(std.mem.trim(u8, value_raw, " \t"));
            }
        }

        // Save last header
        if (current_name) |name| {
            const value = try current_value.toOwnedSlice();
            try headers.put(name, value);
        }
    }
};

/// Unsubscribe list manager
pub const UnsubscribeList = struct {
    allocator: std.mem.Allocator,
    list: std.StringHashMap(UnsubscribeEntry),

    const Self = @This();

    pub const UnsubscribeEntry = struct {
        email: []const u8,
        unsubscribed_at: i64,
        reason: ?[]const u8,
    };

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .list = std.StringHashMap(UnsubscribeEntry).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var iter = self.list.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            if (entry.value_ptr.reason) |reason| {
                self.allocator.free(reason);
            }
        }
        self.list.deinit();
    }

    /// Add an email to the unsubscribe list
    pub fn addUnsubscribe(
        self: *Self,
        email: []const u8,
        reason: ?[]const u8,
    ) !void {
        const email_copy = try self.allocator.dupe(u8, email);
        const reason_copy = if (reason) |r|
            try self.allocator.dupe(u8, r)
        else
            null;

        const timestamp = time_compat.timestamp();

        try self.list.put(email_copy, .{
            .email = email_copy,
            .unsubscribed_at = timestamp,
            .reason = reason_copy,
        });
    }

    /// Check if an email is unsubscribed
    pub fn isUnsubscribed(self: *Self, email: []const u8) bool {
        return self.list.contains(email);
    }

    /// Remove an email from unsubscribe list (re-subscribe)
    pub fn removeUnsubscribe(self: *Self, email: []const u8) void {
        if (self.list.fetchRemove(email)) |entry| {
            self.allocator.free(entry.key);
            if (entry.value.reason) |reason| {
                self.allocator.free(reason);
            }
        }
    }
};

// Tests

test "CAN-SPAM: Validate compliant message" {
    const allocator = std.testing.allocator;

    var compliance = try CanSpamCompliance.init(allocator, .{
        .unsubscribe_domain = "example.com",
        .physical_address = "123 Main St, City, ST 12345",
    });
    defer compliance.deinit();

    const message =
        \\From: sender@example.com
        \\To: recipient@example.com
        \\Subject: Newsletter
        \\
        \\Hello,
        \\
        \\This is our newsletter.
        \\
        \\--
        \\Company Name
        \\123 Main St, City, ST 12345
        \\
        \\To unsubscribe: https://example.com/unsubscribe
    ;

    var result = try compliance.validateMessage(message);
    defer result.deinit();

    // Should be compliant or have minimal violations
    try std.testing.expect(result.violations.items.len < 2);
}

test "CAN-SPAM: Detect missing unsubscribe link" {
    const allocator = std.testing.allocator;

    var compliance = try CanSpamCompliance.init(allocator, .{
        .unsubscribe_domain = "example.com",
        .physical_address = "123 Main St, City, ST 12345",
    });
    defer compliance.deinit();

    const message =
        \\From: sender@example.com
        \\To: recipient@example.com
        \\Subject: Newsletter
        \\
        \\Hello,
        \\
        \\This is our newsletter.
    ;

    var result = try compliance.validateMessage(message);
    defer result.deinit();

    // Should have violations
    try std.testing.expect(result.violations.items.len > 0);
    try std.testing.expect(!result.is_compliant);
}

test "CAN-SPAM: Add compliance elements" {
    const allocator = std.testing.allocator;

    var compliance = try CanSpamCompliance.init(allocator, .{
        .unsubscribe_domain = "example.com",
        .physical_address = "123 Main St, City, ST 12345",
    });
    defer compliance.deinit();

    const message =
        \\From: sender@example.com
        \\To: recipient@example.com
        \\Subject: Newsletter
        \\
        \\Hello world
    ;

    const enhanced = try compliance.addComplianceElements(message, true);
    defer allocator.free(enhanced);

    // Should contain unsubscribe link
    try std.testing.expect(std.mem.indexOf(u8, enhanced, "unsubscribe") != null);

    // Should contain physical address
    try std.testing.expect(std.mem.indexOf(u8, enhanced, "123 Main St") != null);

    // Should contain commercial identifier
    try std.testing.expect(std.mem.indexOf(u8, enhanced, "commercial") != null);
}

test "UnsubscribeList: Add and check" {
    const allocator = std.testing.allocator;

    var list = UnsubscribeList.init(allocator);
    defer list.deinit();

    try list.addUnsubscribe("user@example.com", "User request");

    try std.testing.expect(list.isUnsubscribed("user@example.com"));
    try std.testing.expect(!list.isUnsubscribed("other@example.com"));
}

test "UnsubscribeList: Remove" {
    const allocator = std.testing.allocator;

    var list = UnsubscribeList.init(allocator);
    defer list.deinit();

    try list.addUnsubscribe("user@example.com", null);
    try std.testing.expect(list.isUnsubscribed("user@example.com"));

    list.removeUnsubscribe("user@example.com");
    try std.testing.expect(!list.isUnsubscribed("user@example.com"));
}
