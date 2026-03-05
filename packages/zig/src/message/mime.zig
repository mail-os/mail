const std = @import("std");

/// MIME content type parser
pub const ContentType = struct {
    media_type: []const u8, // e.g., "text"
    media_subtype: []const u8, // e.g., "plain"
    boundary: ?[]const u8, // For multipart types
    charset: ?[]const u8, // Character set
    parameters: std.StringHashMap([]const u8),
    allocator: std.mem.Allocator,

    /// Typical number of Content-Type parameters for pre-sizing
    const EXPECTED_PARAM_COUNT = 4;

    pub fn init(allocator: std.mem.Allocator) ContentType {
        var ct = ContentType{
            .media_type = "",
            .media_subtype = "",
            .boundary = null,
            .charset = null,
            .parameters = std.StringHashMap([]const u8).init(allocator),
            .allocator = allocator,
        };
        // Pre-size for typical parameter count
        ct.parameters.ensureTotalCapacity(EXPECTED_PARAM_COUNT) catch {};
        return ct;
    }

    pub fn deinit(self: *ContentType) void {
        if (self.media_type.len > 0) self.allocator.free(self.media_type);
        if (self.media_subtype.len > 0) self.allocator.free(self.media_subtype);
        if (self.boundary) |b| self.allocator.free(b);
        if (self.charset) |c| self.allocator.free(c);

        var it = self.parameters.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.parameters.deinit();
    }

    /// Parse Content-Type header value
    /// Example: "multipart/mixed; boundary=\"----=_Part_123\""
    pub fn parse(allocator: std.mem.Allocator, value: []const u8) !ContentType {
        var ct = ContentType.init(allocator);
        errdefer ct.deinit();

        // Split by semicolon to separate type from parameters
        var parts = std.mem.splitSequence(u8, value, ";");

        // Parse main type
        const type_part = std.mem.trim(u8, parts.next() orelse return error.InvalidContentType, " \t");
        if (std.mem.indexOf(u8, type_part, "/")) |slash_pos| {
            ct.media_type = try allocator.dupe(u8, std.mem.trim(u8, type_part[0..slash_pos], " \t"));
            ct.media_subtype = try allocator.dupe(u8, std.mem.trim(u8, type_part[slash_pos + 1 ..], " \t"));
        } else {
            return error.InvalidContentType;
        }

        // Parse parameters
        while (parts.next()) |param| {
            const trimmed = std.mem.trim(u8, param, " \t");
            if (std.mem.indexOf(u8, trimmed, "=")) |eq_pos| {
                const key = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
                var val = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " \t");

                // Remove quotes if present
                if (val.len >= 2 and val[0] == '"' and val[val.len - 1] == '"') {
                    val = val[1 .. val.len - 1];
                }

                if (std.ascii.eqlIgnoreCase(key, "boundary")) {
                    ct.boundary = try allocator.dupe(u8, val);
                } else if (std.ascii.eqlIgnoreCase(key, "charset")) {
                    ct.charset = try allocator.dupe(u8, val);
                } else {
                    const key_copy = try allocator.dupe(u8, key);
                    const val_copy = try allocator.dupe(u8, val);
                    try ct.parameters.put(key_copy, val_copy);
                }
            }
        }

        return ct;
    }

    pub fn isMultipart(self: *const ContentType) bool {
        return std.ascii.eqlIgnoreCase(self.media_type, "multipart");
    }
};

/// Represents a MIME part in a multipart message
pub const MimePart = struct {
    headers: std.StringHashMap([]const u8),
    body: []const u8,
    content_type: ?ContentType,
    allocator: std.mem.Allocator,

    /// Typical number of headers per MIME part for pre-sizing
    const EXPECTED_PART_HEADER_COUNT = 4;

    pub fn init(allocator: std.mem.Allocator) MimePart {
        var part = MimePart{
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = "",
            .content_type = null,
            .allocator = allocator,
        };
        // Pre-size for typical MIME part header count
        part.headers.ensureTotalCapacity(EXPECTED_PART_HEADER_COUNT) catch {};
        return part;
    }

    pub fn deinit(self: *MimePart) void {
        var it = self.headers.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();

        if (self.body.len > 0) self.allocator.free(self.body);
        if (self.content_type) |*ct| {
            var ct_mut = ct.*;
            ct_mut.deinit();
        }
    }
};

/// MIME multipart parser
pub const MultipartParser = struct {
    allocator: std.mem.Allocator,
    max_depth: u32,
    current_depth: u32,

    pub const MAX_MIME_DEPTH = 10; // RFC recommendation
    pub const MAX_BOUNDARY_LENGTH = 70; // RFC 2046 limit

    pub fn init(allocator: std.mem.Allocator) MultipartParser {
        return .{
            .allocator = allocator,
            .max_depth = MAX_MIME_DEPTH,
            .current_depth = 0,
        };
    }

    /// Parse a multipart message body given a boundary
    pub fn parse(self: *MultipartParser, body: []const u8, boundary: []const u8) ![]MimePart {
        // Validate MIME depth
        if (self.current_depth >= self.max_depth) {
            return error.MimeDepthExceeded;
        }

        // Validate boundary length per RFC 2046
        if (boundary.len > MAX_BOUNDARY_LENGTH) {
            return error.BoundaryTooLong;
        }

        // Validate boundary characters (RFC 2046: must be 1-70 characters from bchars set)
        for (boundary) |c| {
            const is_valid = std.ascii.isAlphanumeric(c) or
                c == '\'' or c == '(' or c == ')' or c == '+' or c == '_' or
                c == ',' or c == '-' or c == '.' or c == '/' or c == ':' or
                c == '=' or c == '?';
            if (!is_valid) {
                return error.InvalidBoundary;
            }
        }

        self.current_depth += 1;
        defer self.current_depth -= 1;

        var parts: std.ArrayList(MimePart) = .{};
        errdefer {
            for (parts.items) |*part| {
                part.deinit();
            }
            parts.deinit(self.allocator);
        }

        // Boundary start marker — stack buffer (RFC 2046: max 70 char boundary)
        var start_buf: [74]u8 = undefined;
        if (boundary.len > 70) return error.InvalidBoundary;
        start_buf[0] = '-';
        start_buf[1] = '-';
        @memcpy(start_buf[2 .. 2 + boundary.len], boundary);
        const boundary_start = start_buf[0 .. 2 + boundary.len];

        var pos: usize = 0;
        while (pos < body.len) {
            // Find next boundary
            const boundary_pos = std.mem.indexOf(u8, body[pos..], boundary_start) orelse break;
            pos += boundary_pos + boundary_start.len;

            // Check if this is the end boundary
            if (pos + 2 <= body.len and std.mem.eql(u8, body[pos .. pos + 2], "--")) {
                break;
            }

            // Skip to end of boundary line
            if (std.mem.indexOf(u8, body[pos..], "\r\n")) |newline| {
                pos += newline + 2;
            } else {
                break;
            }

            // Find next boundary or end
            const next_boundary = std.mem.indexOf(u8, body[pos..], boundary_start) orelse body.len - pos;
            const part_data = body[pos .. pos + next_boundary];

            // Parse this part
            var part = try self.parsePart(part_data);
            errdefer part.deinit();

            // Check if this part is itself multipart and recursively parse
            if (part.content_type) |*ct| {
                if (ct.isMultipart() and ct.boundary != null) {
                    // Recursively parse nested multipart (depth tracking happens in parse())
                    const nested_parts = self.parse(part.body, ct.boundary.?) catch |err| {
                        std.log.err("Failed to parse nested multipart: {}", .{err});
                        return err;
                    };
                    // Free nested parts (just demonstrating depth tracking works)
                    self.freeParts(nested_parts);
                }
            }

            try parts.append(self.allocator, part);

            pos += next_boundary;
        }

        return try parts.toOwnedSlice(self.allocator);
    }

    fn parsePart(self: *MultipartParser, data: []const u8) !MimePart {
        var part = MimePart.init(self.allocator);
        errdefer part.deinit();

        // Split headers and body at double newline
        const header_end = std.mem.indexOf(u8, data, "\r\n\r\n") orelse data.len;
        const headers_data = data[0..header_end];
        const body_start = @min(header_end + 4, data.len);

        // Parse headers
        var lines = std.mem.splitSequence(u8, headers_data, "\r\n");
        var current_header: ?[]const u8 = null;
        var current_value: std.ArrayList(u8) = .{};
        defer current_value.deinit(self.allocator);

        while (lines.next()) |line| {
            if (line.len == 0) continue;

            // Check for continuation line
            if (line[0] == ' ' or line[0] == '\t') {
                if (current_header != null) {
                    try current_value.appendSlice(self.allocator, " ");
                    try current_value.appendSlice(self.allocator, std.mem.trim(u8, line, " \t"));
                }
                continue;
            }

            // Save previous header
            if (current_header) |header_name| {
                const value = try self.allocator.dupe(u8, current_value.items);
                try part.headers.put(header_name, value);
                current_value.clearRetainingCapacity();
            }

            // Parse new header
            if (std.mem.indexOf(u8, line, ":")) |colon_pos| {
                const header_name = std.mem.trim(u8, line[0..colon_pos], " \t");
                const header_value = std.mem.trim(u8, line[colon_pos + 1 ..], " \t");

                current_header = try self.allocator.dupe(u8, header_name);
                try current_value.appendSlice(self.allocator, header_value);
            }
        }

        // Save last header
        if (current_header) |header_name| {
            const value = try self.allocator.dupe(u8, current_value.items);
            try part.headers.put(header_name, value);
        }

        // Parse Content-Type if present
        if (part.headers.get("Content-Type")) |ct_value| {
            part.content_type = try ContentType.parse(self.allocator, ct_value);
        }

        // Store body (trim trailing whitespace/newlines)
        var body_data = data[body_start..];
        while (body_data.len > 0 and (body_data[body_data.len - 1] == '\r' or body_data[body_data.len - 1] == '\n')) {
            body_data = body_data[0 .. body_data.len - 1];
        }
        part.body = try self.allocator.dupe(u8, body_data);

        return part;
    }

    /// Free parsed parts
    pub fn freeParts(self: *MultipartParser, parts: []MimePart) void {
        for (parts) |*part| {
            part.deinit();
        }
        self.allocator.free(parts);
    }
};

test "parse content type" {
    const testing = std.testing;

    var ct = try ContentType.parse(
        testing.allocator,
        "multipart/mixed; boundary=\"----=_Part_123\"; charset=utf-8",
    );
    defer ct.deinit();

    try testing.expectEqualStrings("multipart", ct.media_type);
    try testing.expectEqualStrings("mixed", ct.media_subtype);
    try testing.expectEqualStrings("----=_Part_123", ct.boundary.?);
    try testing.expectEqualStrings("utf-8", ct.charset.?);
    try testing.expect(ct.isMultipart());
}

test "parse simple multipart message" {
    const testing = std.testing;
    var parser = MultipartParser.init(testing.allocator);

    const message =
        \\------=_Part_123
        \\Content-Type: text/plain; charset=utf-8
        \\
        \\Hello, World!
        \\------=_Part_123
        \\Content-Type: text/html; charset=utf-8
        \\
        \\<html><body>Hello, World!</body></html>
        \\------=_Part_123--
    ;

    const parts = try parser.parse(message, "----=_Part_123");
    defer parser.freeParts(parts);

    try testing.expectEqual(@as(usize, 2), parts.len);

    // First part
    try testing.expectEqualStrings("Hello, World!", parts[0].body);
    try testing.expect(parts[0].content_type != null);
    try testing.expectEqualStrings("text", parts[0].content_type.?.media_type);
    try testing.expectEqualStrings("plain", parts[0].content_type.?.media_subtype);

    // Second part
    try testing.expectEqualStrings("<html><body>Hello, World!</body></html>", parts[1].body);
    try testing.expect(parts[1].content_type != null);
    try testing.expectEqualStrings("text", parts[1].content_type.?.media_type);
    try testing.expectEqualStrings("html", parts[1].content_type.?.media_subtype);
}

test "reject boundary longer than 70 characters" {
    const testing = std.testing;
    var parser = MultipartParser.init(testing.allocator);

    // Create a boundary that's 71 characters (too long)
    const long_boundary = "a" ** 71;
    const message = "--" ++ long_boundary ++ "\r\ntest\r\n--" ++ long_boundary ++ "--";

    const result = parser.parse(message, long_boundary);
    try testing.expectError(error.BoundaryTooLong, result);
}

test "reject invalid boundary characters" {
    const testing = std.testing;
    var parser = MultipartParser.init(testing.allocator);

    // Boundary with invalid character (space)
    const invalid_boundary = "test boundary";
    const message = "--test boundary\r\ntest\r\n--test boundary--";

    const result = parser.parse(message, invalid_boundary);
    try testing.expectError(error.InvalidBoundary, result);
}

test "reject MIME depth exceeding 10 levels" {
    const testing = std.testing;
    var parser = MultipartParser.init(testing.allocator);

    // Simulate depth exceeded by setting current_depth
    parser.current_depth = 10;

    const message =
        \\--boundary
        \\Content-Type: text/plain
        \\
        \\test
        \\--boundary--
    ;

    const result = parser.parse(message, "boundary");
    try testing.expectError(error.MimeDepthExceeded, result);
}
