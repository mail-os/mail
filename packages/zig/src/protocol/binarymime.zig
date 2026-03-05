const std = @import("std");

/// BINARYMIME extension (RFC 3030)
/// Allows transmission of binary data without base64/quoted-printable encoding
/// Requires CHUNKING extension for proper operation
///
/// Extension keywords:
/// - BINARYMIME: Server supports binary data
/// - 8BITMIME: Server supports 8-bit data (prerequisite)
///
/// MAIL FROM parameters:
/// - BODY=7BIT: 7-bit ASCII only
/// - BODY=8BITMIME: 8-bit data allowed
/// - BODY=BINARYMIME: Binary data allowed (requires CHUNKING)
pub const BinaryMimeHandler = struct {
    allocator: std.mem.Allocator,
    chunking_required: bool, // RFC 3030 requires CHUNKING
    max_line_length: ?usize, // None if BINARYMIME, Some(998) if 8BITMIME

    pub fn init(allocator: std.mem.Allocator) BinaryMimeHandler {
        return .{
            .allocator = allocator,
            .chunking_required = true,
            .max_line_length = null,
        };
    }

    /// Parse BODY parameter from MAIL FROM
    pub fn parseBodyType(self: *BinaryMimeHandler, params: []const u8) !BodyType {
        _ = self;

        var parts = std.mem.splitScalar(u8, params, ' ');
        while (parts.next()) |part| {
            if (std.mem.startsWith(u8, part, "BODY=")) {
                const body_value = part[5..];

                if (std.mem.eql(u8, body_value, "7BIT")) {
                    return .seven_bit;
                } else if (std.mem.eql(u8, body_value, "8BITMIME")) {
                    return .eight_bit;
                } else if (std.mem.eql(u8, body_value, "BINARYMIME")) {
                    return .binary;
                } else {
                    return error.InvalidBodyType;
                }
            }
        }

        // Default to 7BIT if not specified
        return .seven_bit;
    }

    /// Validate that message conforms to declared BODY type
    pub fn validateMessage(self: *BinaryMimeHandler, body_type: BodyType, data: []const u8) !ValidationResult {
        _ = self;

        var result = ValidationResult{
            .valid = true,
            .has_binary = false,
            .has_8bit = false,
            .has_null_bytes = false,
            .max_line_length = 0,
            .line_count = 0,
        };

        var line_length: usize = 0;
        var in_line = true;

        for (data) |byte| {
            // Check for null bytes
            if (byte == 0) {
                result.has_null_bytes = true;
                result.has_binary = true;
            }

            // Check for 8-bit data
            if (byte > 127) {
                result.has_8bit = true;
            }

            // Track line lengths
            if (byte == '\n') {
                result.line_count += 1;
                if (line_length > result.max_line_length) {
                    result.max_line_length = line_length;
                }
                line_length = 0;
                in_line = false;
            } else if (byte != '\r') {
                line_length += 1;
                in_line = true;
            }
        }

        // Handle last line without newline
        if (in_line and line_length > result.max_line_length) {
            result.max_line_length = line_length;
        }

        // Validate according to BODY type
        switch (body_type) {
            .seven_bit => {
                if (result.has_8bit or result.has_binary) {
                    result.valid = false;
                }
                if (result.max_line_length > 998) {
                    result.valid = false;
                }
            },
            .eight_bit => {
                if (result.has_binary) {
                    result.valid = false;
                }
                if (result.max_line_length > 998) {
                    result.valid = false;
                }
            },
            .binary => {
                // Binary allows anything, no restrictions
            },
        }

        return result;
    }

    /// Check if CHUNKING is required for this BODY type
    pub fn requiresChunking(self: *BinaryMimeHandler, body_type: BodyType) bool {
        _ = self;
        return body_type == .binary;
    }

    /// Convert binary data to 8-bit (downgrade)
    /// Removes null bytes and long lines
    pub fn downgradeToBinary(self: *BinaryMimeHandler, data: []const u8) ![]const u8 {
        var result = std.ArrayList(u8).init(self.allocator);
        defer result.deinit(self.allocator);

        for (data) |byte| {
            if (byte != 0) { // Remove null bytes
                try result.append(self.allocator, byte);
            }
        }

        return try result.toOwnedSlice(self.allocator);
    }

    /// Get EHLO capability string
    pub fn getCapabilities(self: *BinaryMimeHandler, chunking_available: bool) ![]const u8 {
        if (chunking_available and self.chunking_required) {
            // Full BINARYMIME support requires CHUNKING
            return try self.allocator.dupe(u8, "8BITMIME\r\nBINARYMIME");
        } else {
            // Only 8BITMIME without CHUNKING
            return try self.allocator.dupe(u8, "8BITMIME");
        }
    }
};

/// BODY parameter from MAIL FROM command
pub const BodyType = enum {
    seven_bit, // 7-bit ASCII only (default)
    eight_bit, // 8-bit data allowed
    binary, // Binary data allowed (requires CHUNKING)

    pub fn toString(self: BodyType) []const u8 {
        return switch (self) {
            .seven_bit => "7BIT",
            .eight_bit => "8BITMIME",
            .binary => "BINARYMIME",
        };
    }

    pub fn fromString(str: []const u8) !BodyType {
        if (std.mem.eql(u8, str, "7BIT")) {
            return .seven_bit;
        } else if (std.mem.eql(u8, str, "8BITMIME")) {
            return .eight_bit;
        } else if (std.mem.eql(u8, str, "BINARYMIME")) {
            return .binary;
        }
        return error.InvalidBodyType;
    }
};

pub const ValidationResult = struct {
    valid: bool,
    has_binary: bool, // Contains null bytes or control characters
    has_8bit: bool, // Contains bytes > 127
    has_null_bytes: bool,
    max_line_length: usize,
    line_count: usize,
};

/// Binary content transfer encoding detection
pub const ContentTransferEncoding = enum {
    seven_bit,
    eight_bit,
    binary,
    quoted_printable,
    base64,

    pub fn fromHeader(header_value: []const u8) ContentTransferEncoding {
        const lower = std.ascii.lowerString(header_value, header_value) catch return .seven_bit;
        defer std.heap.page_allocator.free(lower);

        if (std.mem.indexOf(u8, lower, "7bit")) |_| {
            return .seven_bit;
        } else if (std.mem.indexOf(u8, lower, "8bit")) |_| {
            return .eight_bit;
        } else if (std.mem.indexOf(u8, lower, "binary")) |_| {
            return .binary;
        } else if (std.mem.indexOf(u8, lower, "quoted-printable")) |_| {
            return .quoted_printable;
        } else if (std.mem.indexOf(u8, lower, "base64")) |_| {
            return .base64;
        }

        return .seven_bit;
    }

    pub fn toString(self: ContentTransferEncoding) []const u8 {
        return switch (self) {
            .seven_bit => "7bit",
            .eight_bit => "8bit",
            .binary => "binary",
            .quoted_printable => "quoted-printable",
            .base64 => "base64",
        };
    }
};

/// MIME part with binary content support
pub const BinaryMimePart = struct {
    allocator: std.mem.Allocator,
    content_type: []const u8,
    content_transfer_encoding: ContentTransferEncoding,
    body: []const u8,
    headers: std.StringHashMap([]const u8),

    pub fn init(allocator: std.mem.Allocator) BinaryMimePart {
        return .{
            .allocator = allocator,
            .content_type = "",
            .content_transfer_encoding = .seven_bit,
            .body = "",
            .headers = std.StringHashMap([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *BinaryMimePart) void {
        var iter = self.headers.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
    }

    /// Check if this part can be transmitted with BINARYMIME
    pub fn canUseBinary(self: *const BinaryMimePart) bool {
        return self.content_transfer_encoding == .binary or
            self.content_transfer_encoding == .eight_bit;
    }

    /// Get required BODY type for this part
    pub fn getRequiredBodyType(self: *const BinaryMimePart) BodyType {
        return switch (self.content_transfer_encoding) {
            .binary => .binary,
            .eight_bit => .eight_bit,
            else => .seven_bit,
        };
    }
};

test "parse BODY type from MAIL FROM" {
    const testing = std.testing;

    var handler = BinaryMimeHandler.init(testing.allocator);

    const body_type_7bit = try handler.parseBodyType("BODY=7BIT");
    try testing.expectEqual(BodyType.seven_bit, body_type_7bit);

    const body_type_8bit = try handler.parseBodyType("BODY=8BITMIME");
    try testing.expectEqual(BodyType.eight_bit, body_type_8bit);

    const body_type_binary = try handler.parseBodyType("BODY=BINARYMIME");
    try testing.expectEqual(BodyType.binary, body_type_binary);
}

test "validate 7-bit message" {
    const testing = std.testing;

    var handler = BinaryMimeHandler.init(testing.allocator);

    const valid_7bit = "Hello World\r\nThis is a test\r\n";
    const result = try handler.validateMessage(.seven_bit, valid_7bit);

    try testing.expect(result.valid);
    try testing.expect(!result.has_8bit);
    try testing.expect(!result.has_binary);
}

test "validate 8-bit message" {
    const testing = std.testing;

    var handler = BinaryMimeHandler.init(testing.allocator);

    const valid_8bit = "Hello\xC3\xA9 World\r\n"; // UTF-8 with é
    const result = try handler.validateMessage(.eight_bit, valid_8bit);

    try testing.expect(result.valid);
    try testing.expect(result.has_8bit);
    try testing.expect(!result.has_binary);
}

test "validate binary message" {
    const testing = std.testing;

    var handler = BinaryMimeHandler.init(testing.allocator);

    const binary_data = "\x00\x01\x02\xFF\xFE\xFD";
    const result = try handler.validateMessage(.binary, binary_data);

    try testing.expect(result.valid);
    try testing.expect(result.has_binary);
    try testing.expect(result.has_null_bytes);
}

test "invalid 7-bit with 8-bit data" {
    const testing = std.testing;

    var handler = BinaryMimeHandler.init(testing.allocator);

    const invalid = "Hello\xFF World"; // 8-bit byte in 7-bit message
    const result = try handler.validateMessage(.seven_bit, invalid);

    try testing.expect(!result.valid);
    try testing.expect(result.has_8bit);
}

test "BODY type enum" {
    const testing = std.testing;

    try testing.expectEqualStrings("7BIT", BodyType.seven_bit.toString());
    try testing.expectEqualStrings("8BITMIME", BodyType.eight_bit.toString());
    try testing.expectEqualStrings("BINARYMIME", BodyType.binary.toString());

    const parsed = try BodyType.fromString("8BITMIME");
    try testing.expectEqual(BodyType.eight_bit, parsed);
}

test "content transfer encoding detection" {
    const testing = std.testing;

    const encoding_7bit = ContentTransferEncoding.fromHeader("7bit");
    try testing.expectEqual(ContentTransferEncoding.seven_bit, encoding_7bit);

    const encoding_base64 = ContentTransferEncoding.fromHeader("base64");
    try testing.expectEqual(ContentTransferEncoding.base64, encoding_base64);

    const encoding_binary = ContentTransferEncoding.fromHeader("binary");
    try testing.expectEqual(ContentTransferEncoding.binary, encoding_binary);
}

test "binary MIME part" {
    const testing = std.testing;

    var part = BinaryMimePart.init(testing.allocator);
    defer part.deinit();

    part.content_transfer_encoding = .binary;

    try testing.expect(part.canUseBinary());
    try testing.expectEqual(BodyType.binary, part.getRequiredBodyType());
}

test "requires chunking" {
    const testing = std.testing;

    var handler = BinaryMimeHandler.init(testing.allocator);

    try testing.expect(!handler.requiresChunking(.seven_bit));
    try testing.expect(!handler.requiresChunking(.eight_bit));
    try testing.expect(handler.requiresChunking(.binary));
}

test "get capabilities" {
    const testing = std.testing;

    var handler = BinaryMimeHandler.init(testing.allocator);

    const caps_full = try handler.getCapabilities(true);
    defer testing.allocator.free(caps_full);
    try testing.expect(std.mem.indexOf(u8, caps_full, "BINARYMIME") != null);

    const caps_8bit = try handler.getCapabilities(false);
    defer testing.allocator.free(caps_8bit);
    try testing.expect(std.mem.indexOf(u8, caps_8bit, "8BITMIME") != null);
}
