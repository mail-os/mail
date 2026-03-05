const std = @import("std");
const mime = @import("mime.zig");
const path_sanitizer = @import("../core/path_sanitizer.zig");

/// Email attachment
pub const Attachment = struct {
    filename: []const u8,
    content_type: []const u8,
    encoding: []const u8, // e.g., "base64", "quoted-printable", "7bit"
    data: []const u8, // Raw encoded data
    decoded_data: ?[]const u8, // Decoded data (null until decoded)
    size: usize,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Attachment) void {
        self.allocator.free(self.filename);
        self.allocator.free(self.content_type);
        self.allocator.free(self.encoding);
        self.allocator.free(self.data);
        if (self.decoded_data) |decoded| {
            self.allocator.free(decoded);
        }
    }

    /// Decode attachment data based on encoding
    pub fn decode(self: *Attachment) !void {
        if (self.decoded_data != null) {
            return; // Already decoded
        }

        if (std.ascii.eqlIgnoreCase(self.encoding, "base64")) {
            self.decoded_data = try decodeBase64(self.allocator, self.data);
        } else if (std.ascii.eqlIgnoreCase(self.encoding, "quoted-printable")) {
            self.decoded_data = try decodeQuotedPrintable(self.allocator, self.data);
        } else {
            // 7bit, 8bit, binary - no decoding needed
            self.decoded_data = try self.allocator.dupe(u8, self.data);
        }
    }

    /// Save attachment to file with path sanitization
    /// The path should be a directory path where the attachment will be saved
    /// The filename will be sanitized and appended to the directory
    pub fn saveToFile(self: *Attachment, directory_path: []const u8) !void {
        if (self.decoded_data == null) {
            try self.decode();
        }

        // Sanitize the filename to prevent directory traversal
        const safe_filename = try path_sanitizer.PathSanitizer.sanitizeFilename(self.allocator, self.filename);
        defer self.allocator.free(safe_filename);

        // Sanitize the full path
        const safe_path = if (std.fs.path.isAbsolute(directory_path))
            try std.fs.path.join(self.allocator, &[_][]const u8{ directory_path, safe_filename })
        else blk: {
            const cwd = try std.fs.cwd().realpathAlloc(self.allocator, ".");
            defer self.allocator.free(cwd);

            const sanitized = try path_sanitizer.PathSanitizer.sanitizePath(self.allocator, cwd, directory_path);
            defer self.allocator.free(sanitized);

            break :blk try std.fs.path.join(self.allocator, &[_][]const u8{ sanitized, safe_filename });
        };
        defer self.allocator.free(safe_path);

        std.log.info("Saving attachment to: {s}", .{safe_path});

        const file = try std.fs.cwd().createFile(safe_path, .{});
        defer file.close();

        try file.writeAll(self.decoded_data.?);
    }
};

/// Extract attachments from MIME parts
pub const AttachmentExtractor = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) AttachmentExtractor {
        return .{ .allocator = allocator };
    }

    /// Extract all attachments from MIME parts
    pub fn extractFromParts(self: *AttachmentExtractor, parts: []mime.MimePart) ![]Attachment {
        var attachments = std.ArrayList(Attachment).init(self.allocator);
        errdefer {
            for (attachments.items) |*att| {
                att.deinit();
            }
            attachments.deinit();
        }

        for (parts) |*part| {
            if (try self.isAttachment(part)) {
                const att = try self.extractAttachment(part);
                try attachments.append(att);
            }
        }

        return try attachments.toOwnedSlice();
    }

    fn isAttachment(self: *AttachmentExtractor, part: *const mime.MimePart) !bool {
        _ = self;

        // Check Content-Disposition header
        if (part.headers.get("Content-Disposition")) |disposition| {
            if (std.mem.indexOf(u8, disposition, "attachment") != null) {
                return true;
            }
        }

        // Check if it has a filename parameter
        if (part.content_type) |*ct| {
            if (ct.parameters.contains("name")) {
                return true;
            }
        }

        return false;
    }

    fn extractAttachment(self: *AttachmentExtractor, part: *const mime.MimePart) !Attachment {
        var filename: []const u8 = "attachment.bin";
        var content_type: []const u8 = "application/octet-stream";
        var encoding: []const u8 = "7bit";

        // Extract filename
        if (part.headers.get("Content-Disposition")) |disposition| {
            if (self.extractParameter(disposition, "filename")) |fn_value| {
                filename = fn_value;
            }
        }

        // Extract content type
        if (part.content_type) |*ct| {
            const ct_str = try std.fmt.allocPrint(
                self.allocator,
                "{s}/{s}",
                .{ ct.media_type, ct.media_subtype },
            );
            content_type = ct_str;

            if (ct.parameters.get("name")) |name| {
                filename = name;
            }
        }

        // Extract encoding
        if (part.headers.get("Content-Transfer-Encoding")) |enc| {
            encoding = std.mem.trim(u8, enc, " \t\r\n");
        }

        return Attachment{
            .filename = try self.allocator.dupe(u8, filename),
            .content_type = try self.allocator.dupe(u8, content_type),
            .encoding = try self.allocator.dupe(u8, encoding),
            .data = try self.allocator.dupe(u8, part.body),
            .decoded_data = null,
            .size = part.body.len,
            .allocator = self.allocator,
        };
    }

    fn extractParameter(self: *AttachmentExtractor, header_value: []const u8, param_name: []const u8) ?[]const u8 {
        _ = self;

        const param_start = std.mem.indexOf(u8, header_value, param_name) orelse return null;
        const eq_pos = std.mem.indexOf(u8, header_value[param_start..], "=") orelse return null;
        const value_start = param_start + eq_pos + 1;

        var value_end = value_start;
        while (value_end < header_value.len and header_value[value_end] != ';' and header_value[value_end] != '\r') {
            value_end += 1;
        }

        var value = std.mem.trim(u8, header_value[value_start..value_end], " \t\"");
        return value;
    }

    pub fn freeAttachments(self: *AttachmentExtractor, attachments: []Attachment) void {
        for (attachments) |*att| {
            att.deinit();
        }
        self.allocator.free(attachments);
    }
};

/// Decode base64 data
fn decodeBase64(allocator: std.mem.Allocator, encoded: []const u8) ![]const u8 {
    // Remove whitespace and newlines
    var clean_data = std.ArrayList(u8).init(allocator);
    defer clean_data.deinit();

    for (encoded) |c| {
        if (!std.ascii.isWhitespace(c)) {
            try clean_data.append(c);
        }
    }

    const decoder = std.base64.standard.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(clean_data.items);
    const decoded = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(decoded);

    try decoder.decode(decoded, clean_data.items);
    return decoded;
}

/// Decode quoted-printable data
fn decodeQuotedPrintable(allocator: std.mem.Allocator, encoded: []const u8) ![]const u8 {
    var decoded = std.ArrayList(u8).init(allocator);
    defer decoded.deinit();

    var i: usize = 0;
    while (i < encoded.len) {
        if (encoded[i] == '=') {
            if (i + 2 < encoded.len) {
                // Check for soft line break (=\r\n or =\n)
                if (encoded[i + 1] == '\r' and i + 2 < encoded.len and encoded[i + 2] == '\n') {
                    i += 3; // Skip soft line break
                    continue;
                } else if (encoded[i + 1] == '\n') {
                    i += 2; // Skip soft line break
                    continue;
                }

                // Decode hex characters
                const hex = encoded[i + 1 .. i + 3];
                const byte = std.fmt.parseInt(u8, hex, 16) catch {
                    // Invalid hex, keep as-is
                    try decoded.append(encoded[i]);
                    i += 1;
                    continue;
                };
                try decoded.append(byte);
                i += 3;
            } else {
                try decoded.append(encoded[i]);
                i += 1;
            }
        } else {
            try decoded.append(encoded[i]);
            i += 1;
        }
    }

    return try decoded.toOwnedSlice();
}

test "base64 decoding" {
    const testing = std.testing;

    const encoded = "SGVsbG8sIFdvcmxkIQ==";
    const decoded = try decodeBase64(testing.allocator, encoded);
    defer testing.allocator.free(decoded);

    try testing.expectEqualStrings("Hello, World!", decoded);
}

test "base64 decoding with whitespace" {
    const testing = std.testing;

    const encoded = "SGVs\r\nbG8s\r\nIFdv\r\ncmxk\r\nIQ==";
    const decoded = try decodeBase64(testing.allocator, encoded);
    defer testing.allocator.free(decoded);

    try testing.expectEqualStrings("Hello, World!", decoded);
}

test "quoted-printable decoding" {
    const testing = std.testing;

    const encoded = "Hello=2C World=21";
    const decoded = try decodeQuotedPrintable(testing.allocator, encoded);
    defer testing.allocator.free(decoded);

    try testing.expectEqualStrings("Hello, World!", decoded);
}

test "quoted-printable soft line break" {
    const testing = std.testing;

    const encoded = "This is a long=\r\n line";
    const decoded = try decodeQuotedPrintable(testing.allocator, encoded);
    defer testing.allocator.free(decoded);

    try testing.expectEqualStrings("This is a long line", decoded);
}

test "attachment creation" {
    const testing = std.testing;

    var att = Attachment{
        .filename = try testing.allocator.dupe(u8, "test.txt"),
        .content_type = try testing.allocator.dupe(u8, "text/plain"),
        .encoding = try testing.allocator.dupe(u8, "base64"),
        .data = try testing.allocator.dupe(u8, "SGVsbG8h"),
        .decoded_data = null,
        .size = 8,
        .allocator = testing.allocator,
    };
    defer att.deinit();

    try att.decode();
    try testing.expectEqualStrings("Hello!", att.decoded_data.?);
}
