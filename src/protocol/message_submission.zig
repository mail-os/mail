// RFC 6409 - Message Submission Agent (MSA) Implementation
// Handles message submission from Mail User Agents (MUAs)

const std = @import("std");
const io_compat = @import("../core/io_compat.zig");
const time_compat = @import("../core/time_compat.zig");

/// Message Submission Agent - RFC 6409 compliant
pub const MessageSubmissionAgent = struct {
    allocator: std.mem.Allocator,
    hostname: []const u8,
    dkim_enabled: bool,
    fix_headers: bool,

    const Self = @This();

    pub const Config = struct {
        hostname: []const u8,
        dkim_enabled: bool = false,
        fix_headers: bool = true,
        add_message_id: bool = true,
        add_date: bool = true,
        add_sender: bool = true,
    };

    pub fn init(allocator: std.mem.Allocator, config: Config) !Self {
        const hostname_copy = try allocator.dupe(u8, config.hostname);

        return Self{
            .allocator = allocator,
            .hostname = hostname_copy,
            .dkim_enabled = config.dkim_enabled,
            .fix_headers = config.fix_headers,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.hostname);
    }

    /// Process a submitted message according to RFC 6409
    pub fn processSubmission(
        self: *Self,
        message_data: []const u8,
        auth_user: []const u8,
        client_ip: []const u8,
    ) ![]u8 {
        // Parse message into headers and body
        const separator_pos = std.mem.indexOf(u8, message_data, "\r\n\r\n") orelse
            std.mem.indexOf(u8, message_data, "\n\n") orelse
            return error.InvalidMessageFormat;

        const headers_section = message_data[0..separator_pos];
        const body_section = if (separator_pos + 4 <= message_data.len)
            message_data[separator_pos + 4 ..]
        else
            message_data[separator_pos + 2 ..];

        // Parse headers
        var headers = std.ArrayList(Header).init(self.allocator);
        defer {
            for (headers.items) |header| {
                self.allocator.free(header.name);
                self.allocator.free(header.value);
            }
            headers.deinit();
        }

        try self.parseHeaders(headers_section, &headers);

        // Apply RFC 6409 modifications
        try self.addRequiredHeaders(&headers, auth_user);
        try self.addReceivedHeader(&headers, auth_user, client_ip);

        // Validate From matches authentication
        try self.validateFrom(&headers, auth_user);

        // Reconstruct message
        return try self.reconstructMessage(&headers, body_section);
    }

    /// Add required headers if missing (RFC 6409 Section 5)
    fn addRequiredHeaders(
        self: *Self,
        headers: *std.ArrayList(Header),
        auth_user: []const u8,
    ) !void {
        // Add Date if missing
        if (!self.hasHeader(headers, "Date")) {
            const date = try self.generateRFC5322Date();
            try self.addHeader(headers, "Date", date);
        }

        // Add Message-ID if missing
        if (!self.hasHeader(headers, "Message-ID")) {
            const msg_id = try self.generateMessageID();
            try self.addHeader(headers, "Message-ID", msg_id);
        }

        // Add From if missing (from authenticated user)
        if (!self.hasHeader(headers, "From")) {
            try self.addHeader(headers, "From", auth_user);
        }
    }

    /// Add Received header for trace (RFC 6409 Section 5)
    fn addReceivedHeader(
        self: *Self,
        headers: *std.ArrayList(Header),
        auth_user: []const u8,
        client_ip: []const u8,
    ) !void {
        const timestamp = time_compat.timestamp();
        const date = try self.formatTimestamp(timestamp);
        defer self.allocator.free(date);

        const received = try std.fmt.allocPrint(
            self.allocator,
            "from authenticated-user {s} ([{s}]) by {s} (SMTP Server) with ESMTPSA id {s}; {s}",
            .{ auth_user, client_ip, self.hostname, try self.generateID(), date },
        );

        // Received headers should be prepended
        try self.prependHeader(headers, "Received", received);
    }

    /// Validate From header matches authentication
    fn validateFrom(
        self: *Self,
        headers: *std.ArrayList(Header),
        auth_user: []const u8,
    ) !void {
        const from_header = self.getHeader(headers, "From") orelse return;

        // Extract email address from From header
        const from_addr = try self.extractEmailAddress(from_header);
        defer self.allocator.free(from_addr);

        // If From doesn't match auth_user, add Sender header
        if (!std.mem.eql(u8, from_addr, auth_user)) {
            if (!self.hasHeader(headers, "Sender")) {
                try self.addHeader(headers, "Sender", auth_user);
            }
        }
    }

    /// Generate Message-ID header
    fn generateMessageID(self: *Self) ![]const u8 {
        var random_bytes: [16]u8 = undefined;
        io_compat.randomBytes(&random_bytes);

        const timestamp = time_compat.timestamp();

        return try std.fmt.allocPrint(
            self.allocator,
            "<{d}.{x}@{s}>",
            .{ timestamp, std.fmt.fmtSliceHexLower(&random_bytes), self.hostname },
        );
    }

    /// Generate RFC 5322 compliant Date header
    fn generateRFC5322Date(self: *Self) ![]const u8 {
        const timestamp = time_compat.timestamp();
        return try self.formatTimestamp(timestamp);
    }

    /// Format Unix timestamp to RFC 5322 date
    fn formatTimestamp(self: *Self, timestamp: i64) ![]const u8 {
        const epoch_seconds = @as(u64, @intCast(timestamp));

        // Convert to broken-down time
        const days_since_epoch = epoch_seconds / 86400;
        const seconds_today = epoch_seconds % 86400;

        const hours = seconds_today / 3600;
        const minutes = (seconds_today % 3600) / 60;
        const seconds = seconds_today % 60;

        // Calculate year, month, day (simplified)
        const year = 1970 + (days_since_epoch / 365);
        const day_of_year = days_since_epoch % 365;
        const month = (day_of_year / 30) + 1;
        const day = (day_of_year % 30) + 1;

        const day_names = [_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
        const month_names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

        const day_of_week = (days_since_epoch + 4) % 7; // Jan 1, 1970 was Thursday
        const day_name = day_names[day_of_week];
        const month_name = month_names[@min(month - 1, 11)];

        // Format: Mon, 24 Oct 2025 10:00:00 +0000
        return try std.fmt.allocPrint(
            self.allocator,
            "{s}, {d} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} +0000",
            .{ day_name, day, month_name, year, hours, minutes, seconds },
        );
    }

    /// Generate unique ID for Received header
    fn generateID(self: *Self) ![]const u8 {
        var random_bytes: [8]u8 = undefined;
        io_compat.randomBytes(&random_bytes);

        return try std.fmt.allocPrint(
            self.allocator,
            "{X}",
            .{std.fmt.fmtSliceHexUpper(&random_bytes)},
        );
    }

    /// Extract email address from header value (handles "Name <email>" format)
    fn extractEmailAddress(self: *Self, header_value: []const u8) ![]const u8 {
        // Look for angle brackets
        if (std.mem.indexOf(u8, header_value, "<")) |start| {
            if (std.mem.indexOf(u8, header_value[start..], ">")) |end| {
                const email = header_value[start + 1 .. start + end];
                return try self.allocator.dupe(u8, email);
            }
        }

        // No angle brackets, entire value is email (trim whitespace)
        const trimmed = std.mem.trim(u8, header_value, " \t\r\n");
        return try self.allocator.dupe(u8, trimmed);
    }

    // Header management functions

    fn hasHeader(self: *Self, headers: *std.ArrayList(Header), name: []const u8) bool {
        _ = self;
        for (headers.items) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) {
                return true;
            }
        }
        return false;
    }

    fn getHeader(self: *Self, headers: *std.ArrayList(Header), name: []const u8) ?[]const u8 {
        _ = self;
        for (headers.items) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) {
                return header.value;
            }
        }
        return null;
    }

    fn addHeader(self: *Self, headers: *std.ArrayList(Header), name: []const u8, value: []const u8) !void {
        const name_copy = try self.allocator.dupe(u8, name);
        const value_copy = try self.allocator.dupe(u8, value);

        try headers.append(.{
            .name = name_copy,
            .value = value_copy,
        });
    }

    fn prependHeader(self: *Self, headers: *std.ArrayList(Header), name: []const u8, value: []const u8) !void {
        const name_copy = try self.allocator.dupe(u8, name);
        const value_copy = try self.allocator.dupe(u8, value);

        try headers.insert(0, .{
            .name = name_copy,
            .value = value_copy,
        });
    }

    fn parseHeaders(self: *Self, headers_section: []const u8, headers: *std.ArrayList(Header)) !void {
        var lines = std.mem.split(u8, headers_section, "\n");
        var current_header: ?Header = null;

        while (lines.next()) |line| {
            const trimmed = std.mem.trimEnd(u8, line, "\r");

            if (trimmed.len == 0) continue;

            // Check if continuation line (starts with whitespace)
            if (trimmed[0] == ' ' or trimmed[0] == '\t') {
                if (current_header) |*header| {
                    // Append to current header value
                    const new_value = try std.fmt.allocPrint(
                        self.allocator,
                        "{s} {s}",
                        .{ header.value, std.mem.trim(u8, trimmed, " \t") },
                    );
                    self.allocator.free(header.value);
                    header.value = new_value;
                }
                continue;
            }

            // Save previous header
            if (current_header) |header| {
                try headers.append(header);
            }

            // Parse new header
            if (std.mem.indexOf(u8, trimmed, ":")) |colon_pos| {
                const name = try self.allocator.dupe(u8, trimmed[0..colon_pos]);
                const value_start = colon_pos + 1;
                const value_raw = if (value_start < trimmed.len)
                    trimmed[value_start..]
                else
                    "";
                const value = try self.allocator.dupe(u8, std.mem.trim(u8, value_raw, " \t"));

                current_header = Header{
                    .name = name,
                    .value = value,
                };
            }
        }

        // Save last header
        if (current_header) |header| {
            try headers.append(header);
        }
    }

    fn reconstructMessage(
        self: *Self,
        headers: *std.ArrayList(Header),
        body: []const u8,
    ) ![]const u8 {
        var result = std.ArrayList(u8).init(self.allocator);
        errdefer result.deinit();

        // Write headers
        for (headers.items) |header| {
            try result.appendSlice(header.name);
            try result.appendSlice(": ");
            try result.appendSlice(header.value);
            try result.appendSlice("\r\n");
        }

        // Blank line separator
        try result.appendSlice("\r\n");

        // Write body
        try result.appendSlice(body);

        return result.toOwnedSlice();
    }
};

const Header = struct {
    name: []const u8,
    value: []const u8,
};

// Tests

test "MessageSubmissionAgent: Add missing Message-ID" {
    const allocator = std.testing.allocator;

    var msa = try MessageSubmissionAgent.init(allocator, .{
        .hostname = "mail.example.com",
    });
    defer msa.deinit();

    const message =
        \\From: user@example.com
        \\To: recipient@example.com
        \\Subject: Test
        \\Date: Mon, 24 Oct 2025 10:00:00 +0000
        \\
        \\Body
    ;

    const result = try msa.processSubmission(message, "user@example.com", "192.168.1.1");
    defer allocator.free(result);

    // Should contain Message-ID
    try std.testing.expect(std.mem.indexOf(u8, result, "Message-ID:") != null);
}

test "MessageSubmissionAgent: Add Received header" {
    const allocator = std.testing.allocator;

    var msa = try MessageSubmissionAgent.init(allocator, .{
        .hostname = "mail.example.com",
    });
    defer msa.deinit();

    const message =
        \\From: user@example.com
        \\To: recipient@example.com
        \\Date: Mon, 24 Oct 2025 10:00:00 +0000
        \\
        \\Body
    ;

    const result = try msa.processSubmission(message, "user@example.com", "192.168.1.1");
    defer allocator.free(result);

    // Should contain Received header
    try std.testing.expect(std.mem.indexOf(u8, result, "Received:") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "192.168.1.1") != null);
}

test "MessageSubmissionAgent: Add Sender when From differs" {
    const allocator = std.testing.allocator;

    var msa = try MessageSubmissionAgent.init(allocator, .{
        .hostname = "mail.example.com",
    });
    defer msa.deinit();

    const message =
        \\From: different@example.com
        \\To: recipient@example.com
        \\Date: Mon, 24 Oct 2025 10:00:00 +0000
        \\
        \\Body
    ;

    const result = try msa.processSubmission(message, "user@example.com", "192.168.1.1");
    defer allocator.free(result);

    // Should contain Sender header
    try std.testing.expect(std.mem.indexOf(u8, result, "Sender:") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "user@example.com") != null);
}

test "MessageSubmissionAgent: Extract email from angle brackets" {
    const allocator = std.testing.allocator;

    var msa = try MessageSubmissionAgent.init(allocator, .{
        .hostname = "mail.example.com",
    });
    defer msa.deinit();

    const addr1 = try msa.extractEmailAddress("<user@example.com>");
    defer allocator.free(addr1);
    try std.testing.expectEqualStrings("user@example.com", addr1);

    const addr2 = try msa.extractEmailAddress("John Doe <john@example.com>");
    defer allocator.free(addr2);
    try std.testing.expectEqualStrings("john@example.com", addr2);

    const addr3 = try msa.extractEmailAddress("user@example.com");
    defer allocator.free(addr3);
    try std.testing.expectEqualStrings("user@example.com", addr3);
}

test "MessageSubmissionAgent: Generate Message-ID" {
    const allocator = std.testing.allocator;

    var msa = try MessageSubmissionAgent.init(allocator, .{
        .hostname = "mail.example.com",
    });
    defer msa.deinit();

    const msg_id = try msa.generateMessageID();
    defer allocator.free(msg_id);

    // Should have format <id@hostname>
    try std.testing.expect(std.mem.startsWith(u8, msg_id, "<"));
    try std.testing.expect(std.mem.endsWith(u8, msg_id, ">"));
    try std.testing.expect(std.mem.indexOf(u8, msg_id, "@mail.example.com") != null);
}

test "MessageSubmissionAgent: Generate RFC 5322 date" {
    const allocator = std.testing.allocator;

    var msa = try MessageSubmissionAgent.init(allocator, .{
        .hostname = "mail.example.com",
    });
    defer msa.deinit();

    const date = try msa.generateRFC5322Date();
    defer allocator.free(date);

    // Should contain date components
    try std.testing.expect(date.len > 20);
    try std.testing.expect(std.mem.indexOf(u8, date, ":") != null); // Has time
}
