const std = @import("std");

/// Email header parser and validator
pub const HeaderParser = struct {
    allocator: std.mem.Allocator,

    /// RFC 5322 line length limits
    pub const MAX_LINE_LENGTH = 998; // Hard limit
    pub const RECOMMENDED_LINE_LENGTH = 78; // Recommended limit

    pub fn init(allocator: std.mem.Allocator) HeaderParser {
        return .{ .allocator = allocator };
    }

    /// Typical number of headers in an email message for pre-sizing
    const EXPECTED_HEADER_COUNT = 16;

    /// Parse email headers from raw data
    /// Returns a hash map of header name -> value
    pub fn parseHeaders(self: *HeaderParser, data: []const u8) !std.StringHashMap([]const u8) {
        var headers = std.StringHashMap([]const u8).init(self.allocator);
        // Pre-size for typical email header count to reduce reallocations
        try headers.ensureTotalCapacity(EXPECTED_HEADER_COUNT);
        errdefer {
            var it = headers.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*);
            }
            headers.deinit();
        }

        var lines = std.mem.splitSequence(u8, data, "\r\n");
        var current_header: ?[]const u8 = null;
        var current_value = std.ArrayList(u8).init(self.allocator);
        defer current_value.deinit();

        while (lines.next()) |line| {
            // Empty line marks end of headers
            if (line.len == 0) break;

            // Validate line length per RFC 5322
            if (line.len > MAX_LINE_LENGTH) {
                std.log.err("Header line exceeds maximum length: {d} bytes (max: {d})", .{ line.len, MAX_LINE_LENGTH });
                return error.HeaderLineTooLong;
            }

            // Warn if exceeding recommended length
            if (line.len > RECOMMENDED_LINE_LENGTH) {
                std.log.warn("Header line exceeds recommended length: {d} bytes (recommended: {d})", .{ line.len, RECOMMENDED_LINE_LENGTH });
            }

            // Check if this is a continuation line (starts with whitespace)
            if (line.len > 0 and (line[0] == ' ' or line[0] == '\t')) {
                if (current_header) |_| {
                    // Append to current value
                    try current_value.appendSlice(" ");
                    try current_value.appendSlice(std.mem.trim(u8, line, " \t"));
                }
                continue;
            }

            // Save previous header if exists
            if (current_header) |header_name| {
                const value = try self.allocator.dupe(u8, current_value.items);
                try headers.put(header_name, value);
                current_value.clearRetainingCapacity();
            }

            // Parse new header: "Header-Name: value"
            if (std.mem.indexOf(u8, line, ":")) |colon_pos| {
                const header_name = std.mem.trim(u8, line[0..colon_pos], " \t");
                const header_value = std.mem.trim(u8, line[colon_pos + 1 ..], " \t");

                current_header = try self.allocator.dupe(u8, header_name);
                try current_value.appendSlice(header_value);
            }
        }

        // Save last header if exists
        if (current_header) |header_name| {
            const value = try self.allocator.dupe(u8, current_value.items);
            try headers.put(header_name, value);
        }

        return headers;
    }

    /// Validate required email headers according to RFC 5322
    pub fn validateHeaders(self: *HeaderParser, headers: *const std.StringHashMap([]const u8)) !void {
        _ = self;

        // Required headers according to RFC 5322
        const required_headers = [_][]const u8{
            "From",
            "Date",
        };

        for (required_headers) |header| {
            if (!headers.contains(header)) {
                return error.MissingRequiredHeader;
            }
        }
    }

    /// Get a header value (case-insensitive)
    pub fn getHeader(self: *HeaderParser, headers: *const std.StringHashMap([]const u8), name: []const u8) ?[]const u8 {
        _ = self;

        // Try exact match first
        if (headers.get(name)) |value| {
            return value;
        }

        // Try case-insensitive match
        var it = headers.iterator();
        while (it.next()) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, name)) {
                return entry.value_ptr.*;
            }
        }

        return null;
    }

    /// Extract email addresses from a header value
    /// Handles formats like: "Name <email@example.com>" or "email@example.com"
    pub fn extractEmailAddresses(self: *HeaderParser, value: []const u8) ![][]const u8 {
        var addresses = std.ArrayList([]const u8).init(self.allocator);
        errdefer {
            for (addresses.items) |addr| {
                self.allocator.free(addr);
            }
            addresses.deinit();
        }

        var parts = std.mem.splitSequence(u8, value, ",");
        while (parts.next()) |part| {
            const trimmed = std.mem.trim(u8, part, " \t");

            // Look for <email@example.com>
            if (std.mem.indexOf(u8, trimmed, "<")) |start| {
                if (std.mem.indexOf(u8, trimmed[start..], ">")) |end_rel| {
                    const email = trimmed[start + 1 .. start + end_rel];
                    try addresses.append(try self.allocator.dupe(u8, email));
                    continue;
                }
            }

            // Otherwise use the whole part
            if (trimmed.len > 0) {
                try addresses.append(try self.allocator.dupe(u8, trimmed));
            }
        }

        return try addresses.toOwnedSlice();
    }

    /// Free headers hash map
    pub fn freeHeaders(self: *HeaderParser, headers: *std.StringHashMap([]const u8)) void {
        var it = headers.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        headers.deinit();
    }
};

test "parse basic headers" {
    const testing = std.testing;
    var parser = HeaderParser.init(testing.allocator);

    const data =
        \\From: sender@example.com
        \\To: recipient@example.com
        \\Subject: Test
        \\Date: Mon, 1 Jan 2024 00:00:00 +0000
        \\
        \\Body here
    ;

    var headers = try parser.parseHeaders(data);
    defer parser.freeHeaders(&headers);

    try testing.expect(headers.contains("From"));
    try testing.expect(headers.contains("To"));
    try testing.expect(headers.contains("Subject"));
    try testing.expect(headers.contains("Date"));

    const from = headers.get("From").?;
    try testing.expectEqualStrings("sender@example.com", from);
}

test "parse headers with continuation" {
    const testing = std.testing;
    var parser = HeaderParser.init(testing.allocator);

    const data =
        \\From: sender@example.com
        \\Subject: This is a long
        \\  subject line
        \\Date: Mon, 1 Jan 2024 00:00:00 +0000
        \\
        \\Body
    ;

    var headers = try parser.parseHeaders(data);
    defer parser.freeHeaders(&headers);

    const subject = headers.get("Subject").?;
    try testing.expectEqualStrings("This is a long subject line", subject);
}

test "extract email addresses" {
    const testing = std.testing;
    var parser = HeaderParser.init(testing.allocator);

    const value = "John Doe <john@example.com>, Jane <jane@example.com>";
    const addresses = try parser.extractEmailAddresses(value);
    defer {
        for (addresses) |addr| {
            testing.allocator.free(addr);
        }
        testing.allocator.free(addresses);
    }

    try testing.expectEqual(@as(usize, 2), addresses.len);
    try testing.expectEqualStrings("john@example.com", addresses[0]);
    try testing.expectEqualStrings("jane@example.com", addresses[1]);
}

test "validate required headers" {
    const testing = std.testing;
    var parser = HeaderParser.init(testing.allocator);

    var headers = std.StringHashMap([]const u8).init(testing.allocator);
    defer headers.deinit();

    // Missing required headers - should fail
    try testing.expectError(error.MissingRequiredHeader, parser.validateHeaders(&headers));

    // Add From header
    try headers.put("From", "test@example.com");
    try testing.expectError(error.MissingRequiredHeader, parser.validateHeaders(&headers));

    // Add Date header
    try headers.put("Date", "Mon, 1 Jan 2024 00:00:00 +0000");
    try parser.validateHeaders(&headers);
}

test "reject header lines exceeding 998 characters" {
    const testing = std.testing;
    var parser = HeaderParser.init(testing.allocator);

    // Create a header line that's 999 characters (too long)
    var long_header = try testing.allocator.alloc(u8, 999);
    defer testing.allocator.free(long_header);

    // Fill with valid header format: "X-Long: " + 991 'a' characters
    const header_name = "X-Long: ";
    @memcpy(long_header[0..header_name.len], header_name);
    @memset(long_header[header_name.len..], 'a');

    // Append newlines
    var data = try std.fmt.allocPrint(testing.allocator, "{s}\r\n\r\n", .{long_header});
    defer testing.allocator.free(data);

    const result = parser.parseHeaders(data);
    try testing.expectError(error.HeaderLineTooLong, result);
}

test "accept header lines at 998 character limit" {
    const testing = std.testing;
    var parser = HeaderParser.init(testing.allocator);

    // Create a header line that's exactly 998 characters (at limit)
    var long_header = try testing.allocator.alloc(u8, 998);
    defer testing.allocator.free(long_header);

    // Fill with valid header format
    const header_name = "X-Long: ";
    @memcpy(long_header[0..header_name.len], header_name);
    @memset(long_header[header_name.len..], 'a');

    // Append newlines and From/Date for validation
    var data = try std.fmt.allocPrint(testing.allocator, "{s}\r\nFrom: test@example.com\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\n\r\n", .{long_header});
    defer testing.allocator.free(data);

    var headers = try parser.parseHeaders(data);
    defer parser.freeHeaders(&headers);

    // Should succeed
    try testing.expect(headers.count() > 0);
}
