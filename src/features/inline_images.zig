const std = @import("std");
const io_compat = @import("../core/io_compat.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

// =============================================================================
// Inline Image Support for Email
// =============================================================================
//
// ## Overview
// Handles inline images embedded in emails using Content-ID (CID) references.
// Supports parsing, storage, and resolution of inline attachments.
//
// ## How Inline Images Work
// 1. Email contains multipart MIME with inline attachments
// 2. Attachments have Content-ID header: <image001@domain.com>
// 3. HTML body references via: <img src="cid:image001@domain.com">
// 4. We resolve CID URLs to data URIs or blob URLs for display
//
// =============================================================================

/// Inline image related errors
pub const InlineImageError = error{
    InvalidContentId,
    ImageNotFound,
    InvalidMimeType,
    DataTooLarge,
    EncodingError,
    OutOfMemory,
};

/// Inline attachment with Content-ID
pub const InlineAttachment = struct {
    /// Content-ID without angle brackets (e.g., "image001@domain.com")
    content_id: []const u8,
    /// Original filename
    filename: []const u8,
    /// MIME type (e.g., "image/png")
    mime_type: []const u8,
    /// Raw binary data
    data: []const u8,
    /// Data as base64 (for data URI)
    data_base64: ?[]const u8,
    /// SHA-256 hash of data
    hash: [32]u8,
    /// Size in bytes
    size: usize,

    /// Create data URI for this attachment
    pub fn toDataUri(self: *const InlineAttachment, allocator: std.mem.Allocator) ![]u8 {
        if (self.data_base64) |b64| {
            return std.fmt.allocPrint(allocator, "data:{s};base64,{s}", .{ self.mime_type, b64 });
        }

        // Encode to base64 on demand
        const b64_len = std.base64.standard.Encoder.calcSize(self.data.len);
        const b64_buf = try allocator.alloc(u8, b64_len);
        defer allocator.free(b64_buf);

        const encoded = std.base64.standard.Encoder.encode(b64_buf, self.data);
        return std.fmt.allocPrint(allocator, "data:{s};base64,{s}", .{ self.mime_type, encoded });
    }

    /// Check if this is an image type
    pub fn isImage(self: *const InlineAttachment) bool {
        return std.mem.startsWith(u8, self.mime_type, "image/");
    }
};

/// Inline image storage and resolver
pub const InlineImageStore = struct {
    allocator: std.mem.Allocator,
    /// Map from Content-ID to attachment
    attachments: std.StringHashMap(InlineAttachment),
    /// Map from message ID to list of Content-IDs
    message_attachments: std.StringHashMap(std.ArrayList([]const u8)),
    /// Configuration
    config: InlineImageConfig,

    pub const InlineImageConfig = struct {
        /// Maximum size for inline images (default 10MB)
        max_image_size: usize = 10 * 1024 * 1024,
        /// Whether to pre-encode base64
        pre_encode_base64: bool = true,
        /// Allowed MIME types for inline images
        allowed_types: []const []const u8 = &[_][]const u8{
            "image/jpeg",
            "image/png",
            "image/gif",
            "image/webp",
            "image/svg+xml",
            "image/bmp",
            "image/x-icon",
        },
    };

    pub fn init(allocator: std.mem.Allocator, config: InlineImageConfig) InlineImageStore {
        return .{
            .allocator = allocator,
            .attachments = std.StringHashMap(InlineAttachment).init(allocator),
            .message_attachments = std.StringHashMap(std.ArrayList([]const u8)).init(allocator),
            .config = config,
        };
    }

    pub fn deinit(self: *InlineImageStore) void {
        // Free attachment data
        var att_it = self.attachments.iterator();
        while (att_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.content_id);
            self.allocator.free(entry.value_ptr.filename);
            self.allocator.free(entry.value_ptr.data);
            if (entry.value_ptr.data_base64) |b64| {
                self.allocator.free(b64);
            }
        }
        self.attachments.deinit();

        // Free message attachment lists
        var msg_it = self.message_attachments.iterator();
        while (msg_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            for (entry.value_ptr.items) |cid| {
                self.allocator.free(cid);
            }
            entry.value_ptr.deinit();
        }
        self.message_attachments.deinit();
    }

    /// Store an inline attachment
    pub fn store(
        self: *InlineImageStore,
        content_id: []const u8,
        filename: []const u8,
        mime_type: []const u8,
        data: []const u8,
        message_id: ?[]const u8,
    ) !void {
        // Validate size
        if (data.len > self.config.max_image_size) {
            return InlineImageError.DataTooLarge;
        }

        // Validate MIME type
        var allowed = false;
        for (self.config.allowed_types) |t| {
            if (std.mem.eql(u8, mime_type, t)) {
                allowed = true;
                break;
            }
        }
        if (!allowed) {
            return InlineImageError.InvalidMimeType;
        }

        // Parse Content-ID (remove angle brackets if present)
        const cid = parseContentId(content_id);

        // Calculate hash
        var hash: [32]u8 = undefined;
        Sha256.hash(data, &hash, .{});

        // Copy data
        const cid_copy = try self.allocator.dupe(u8, cid);
        errdefer self.allocator.free(cid_copy);

        const filename_copy = try self.allocator.dupe(u8, filename);
        errdefer self.allocator.free(filename_copy);

        const data_copy = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(data_copy);

        // Optionally pre-encode base64
        var base64_data: ?[]u8 = null;
        if (self.config.pre_encode_base64) {
            const b64_len = std.base64.standard.Encoder.calcSize(data.len);
            base64_data = try self.allocator.alloc(u8, b64_len);
            _ = std.base64.standard.Encoder.encode(base64_data.?, data);
        }
        errdefer if (base64_data) |b| self.allocator.free(b);

        const attachment = InlineAttachment{
            .content_id = cid_copy,
            .filename = filename_copy,
            .mime_type = mime_type,
            .data = data_copy,
            .data_base64 = base64_data,
            .hash = hash,
            .size = data.len,
        };

        // Store by Content-ID
        const key = try self.allocator.dupe(u8, cid);
        try self.attachments.put(key, attachment);

        // Track by message ID
        if (message_id) |mid| {
            const gop = try self.message_attachments.getOrPut(try self.allocator.dupe(u8, mid));
            if (!gop.found_existing) {
                gop.value_ptr.* = std.ArrayList([]const u8).init(self.allocator);
            }
            try gop.value_ptr.append(try self.allocator.dupe(u8, cid));
        }
    }

    /// Get inline attachment by Content-ID
    pub fn get(self: *const InlineImageStore, content_id: []const u8) ?*const InlineAttachment {
        const cid = parseContentId(content_id);
        return self.attachments.getPtr(cid);
    }

    /// Get data URI for Content-ID
    pub fn getDataUri(self: *InlineImageStore, content_id: []const u8) !?[]u8 {
        const cid = parseContentId(content_id);
        if (self.attachments.getPtr(cid)) |att| {
            return try att.toDataUri(self.allocator);
        }
        return null;
    }

    /// Resolve all CID references in HTML body
    pub fn resolveHtml(self: *InlineImageStore, html: []const u8) ![]u8 {
        var result = std.ArrayList(u8).init(self.allocator);
        errdefer result.deinit();

        var i: usize = 0;
        while (i < html.len) {
            // Look for cid: references
            if (i + 4 <= html.len and std.mem.eql(u8, html[i .. i + 4], "cid:")) {
                // Find the end of the CID (quote, space, or >)
                var end = i + 4;
                while (end < html.len) {
                    const c = html[end];
                    if (c == '"' or c == '\'' or c == ' ' or c == '>' or c == ')') {
                        break;
                    }
                    end += 1;
                }

                const cid = html[i + 4 .. end];
                if (self.getDataUri(cid) catch null) |data_uri| {
                    defer self.allocator.free(data_uri);
                    try result.appendSlice(data_uri);
                } else {
                    // Keep original if not found
                    try result.appendSlice(html[i..end]);
                }
                i = end;
            } else {
                try result.append(html[i]);
                i += 1;
            }
        }

        return result.toOwnedSlice();
    }

    /// Get all inline attachments for a message
    pub fn getForMessage(self: *const InlineImageStore, message_id: []const u8) ?[]const []const u8 {
        if (self.message_attachments.get(message_id)) |list| {
            return list.items;
        }
        return null;
    }

    /// Delete all inline attachments for a message
    pub fn deleteForMessage(self: *InlineImageStore, message_id: []const u8) void {
        if (self.message_attachments.fetchRemove(message_id)) |entry| {
            self.allocator.free(entry.key);
            for (entry.value.items) |cid| {
                // Remove from attachments map
                if (self.attachments.fetchRemove(cid)) |att_entry| {
                    self.allocator.free(att_entry.key);
                    self.allocator.free(att_entry.value.content_id);
                    self.allocator.free(att_entry.value.filename);
                    self.allocator.free(att_entry.value.data);
                    if (att_entry.value.data_base64) |b64| {
                        self.allocator.free(b64);
                    }
                }
                self.allocator.free(cid);
            }
            entry.value.deinit();
        }
    }

    /// Get statistics
    pub fn getStats(self: *const InlineImageStore) InlineImageStats {
        var total_size: usize = 0;
        var image_count: usize = 0;

        var it = self.attachments.iterator();
        while (it.next()) |entry| {
            total_size += entry.value_ptr.size;
            if (entry.value_ptr.isImage()) {
                image_count += 1;
            }
        }

        return .{
            .total_attachments = self.attachments.count(),
            .total_images = image_count,
            .total_size = total_size,
            .message_count = self.message_attachments.count(),
        };
    }
};

/// Statistics for inline images
pub const InlineImageStats = struct {
    total_attachments: usize,
    total_images: usize,
    total_size: usize,
    message_count: usize,
};

/// Parse MIME multipart to extract inline attachments
pub const MimeInlineParser = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) MimeInlineParser {
        return .{ .allocator = allocator };
    }

    /// Parse inline attachments from MIME content
    pub fn parseInlineAttachments(
        self: *MimeInlineParser,
        mime_content: []const u8,
        store: *InlineImageStore,
        message_id: ?[]const u8,
    ) !usize {
        var count: usize = 0;

        // Find boundary
        const boundary = findBoundary(mime_content) orelse return 0;

        // Split by boundary
        var parts = std.mem.splitSequence(u8, mime_content, boundary);
        while (parts.next()) |part| {
            if (part.len < 10) continue;

            // Check for Content-Disposition: inline or Content-ID
            const has_inline = std.mem.indexOf(u8, part, "Content-Disposition: inline") != null or
                std.mem.indexOf(u8, part, "Content-Disposition:inline") != null;
            const cid_start = std.mem.indexOf(u8, part, "Content-ID:");

            if (has_inline or cid_start != null) {
                // Extract Content-ID
                var content_id: ?[]const u8 = null;
                if (cid_start) |start| {
                    var end = start + 11;
                    // Skip whitespace
                    while (end < part.len and (part[end] == ' ' or part[end] == '\t')) {
                        end += 1;
                    }
                    const cid_end = std.mem.indexOfAnyPos(u8, part, end, "\r\n") orelse part.len;
                    content_id = std.mem.trim(u8, part[end..cid_end], " \t<>");
                }

                if (content_id) |cid| {
                    // Extract Content-Type
                    var mime_type: []const u8 = "application/octet-stream";
                    if (std.mem.indexOf(u8, part, "Content-Type:")) |ct_start| {
                        var ct_end = ct_start + 13;
                        while (ct_end < part.len and (part[ct_end] == ' ' or part[ct_end] == '\t')) {
                            ct_end += 1;
                        }
                        const ct_line_end = std.mem.indexOfAnyPos(u8, part, ct_end, ";\r\n") orelse part.len;
                        mime_type = std.mem.trim(u8, part[ct_end..ct_line_end], " \t");
                    }

                    // Find filename
                    var filename: []const u8 = "inline_image";
                    if (std.mem.indexOf(u8, part, "filename=")) |fn_start| {
                        var fn_end = fn_start + 9;
                        if (fn_end < part.len and part[fn_end] == '"') {
                            fn_end += 1;
                            const fn_close = std.mem.indexOfPos(u8, part, fn_end, "\"") orelse part.len;
                            filename = part[fn_end..fn_close];
                        }
                    }

                    // Find body (after double CRLF)
                    if (std.mem.indexOf(u8, part, "\r\n\r\n")) |body_start| {
                        var body = part[body_start + 4 ..];
                        // Trim trailing boundary markers
                        if (std.mem.lastIndexOf(u8, body, "\r\n--")) |trim_end| {
                            body = body[0..trim_end];
                        }

                        // Check if base64 encoded
                        const is_base64 = std.mem.indexOf(u8, part[0..body_start], "base64") != null;

                        if (is_base64) {
                            // Decode base64
                            const clean_body = removeWhitespace(self.allocator, body) catch continue;
                            defer self.allocator.free(clean_body);

                            const decoded_size = std.base64.standard.Decoder.calcSizeForSlice(clean_body) catch continue;
                            const decoded = self.allocator.alloc(u8, decoded_size) catch continue;
                            defer self.allocator.free(decoded);

                            const actual_len = std.base64.standard.Decoder.decode(decoded, clean_body) catch continue;

                            store.store(cid, filename, mime_type, decoded[0..actual_len], message_id) catch continue;
                        } else {
                            // Store raw
                            store.store(cid, filename, mime_type, body, message_id) catch continue;
                        }

                        count += 1;
                    }
                }
            }
        }

        return count;
    }
};

// =============================================================================
// Helper Functions
// =============================================================================

/// Parse Content-ID, removing angle brackets
pub fn parseContentId(raw: []const u8) []const u8 {
    var result = raw;
    if (result.len > 0 and result[0] == '<') {
        result = result[1..];
    }
    if (result.len > 0 and result[result.len - 1] == '>') {
        result = result[0 .. result.len - 1];
    }
    return std.mem.trim(u8, result, " \t");
}

/// Find MIME boundary from Content-Type header
fn findBoundary(content: []const u8) ?[]const u8 {
    const boundary_start = std.mem.indexOf(u8, content, "boundary=") orelse return null;
    var start = boundary_start + 9;

    // Skip quotes if present
    if (start < content.len and content[start] == '"') {
        start += 1;
        const end = std.mem.indexOfPos(u8, content, start, "\"") orelse return null;
        return content[start..end];
    }

    // Find end (semicolon, space, or newline)
    const end = std.mem.indexOfAnyPos(u8, content, start, "; \r\n") orelse content.len;
    return content[start..end];
}

/// Remove whitespace from base64 content
fn removeWhitespace(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var result = try allocator.alloc(u8, input.len);
    var len: usize = 0;

    for (input) |c| {
        if (c != ' ' and c != '\t' and c != '\r' and c != '\n') {
            result[len] = c;
            len += 1;
        }
    }

    return allocator.realloc(result, len);
}

/// Generate a Content-ID for a new inline image
pub fn generateContentId(allocator: std.mem.Allocator, domain: []const u8) ![]u8 {
    var rand_bytes: [8]u8 = undefined;
    io_compat.randomBytes(&rand_bytes);

    const timestamp = std.time.timestamp();

    return std.fmt.allocPrint(allocator, "img{x}{x}@{s}", .{
        @as(u64, @intCast(timestamp)),
        std.mem.readInt(u64, &rand_bytes, .big),
        domain,
    });
}

/// Create HTML img tag with data URI
pub fn createInlineImgTag(
    allocator: std.mem.Allocator,
    data: []const u8,
    mime_type: []const u8,
    alt: ?[]const u8,
) ![]u8 {
    const b64_len = std.base64.standard.Encoder.calcSize(data.len);
    const b64_buf = try allocator.alloc(u8, b64_len);
    defer allocator.free(b64_buf);

    const encoded = std.base64.standard.Encoder.encode(b64_buf, data);

    return std.fmt.allocPrint(allocator, "<img src=\"data:{s};base64,{s}\" alt=\"{s}\">", .{
        mime_type,
        encoded,
        alt orelse "inline image",
    });
}

// =============================================================================
// Tests
// =============================================================================

test "parseContentId removes angle brackets" {
    try std.testing.expectEqualStrings("image001@example.com", parseContentId("<image001@example.com>"));
    try std.testing.expectEqualStrings("image001@example.com", parseContentId("image001@example.com"));
    try std.testing.expectEqualStrings("test", parseContentId("  <test>  "));
}

test "InlineImageStore basic operations" {
    const allocator = std.testing.allocator;

    var store = InlineImageStore.init(allocator, .{});
    defer store.deinit();

    // Store an inline image
    const test_data = "fake png data";
    try store.store(
        "<test123@example.com>",
        "test.png",
        "image/png",
        test_data,
        "msg001",
    );

    // Retrieve
    const att = store.get("test123@example.com");
    try std.testing.expect(att != null);
    try std.testing.expectEqualStrings("test.png", att.?.filename);
    try std.testing.expectEqualStrings(test_data, att.?.data);

    // Stats
    const stats = store.getStats();
    try std.testing.expectEqual(@as(usize, 1), stats.total_attachments);
    try std.testing.expectEqual(@as(usize, 1), stats.total_images);
}

test "InlineImageStore resolves CID in HTML" {
    const allocator = std.testing.allocator;

    var store = InlineImageStore.init(allocator, .{});
    defer store.deinit();

    // Store a test image
    try store.store("img1@test.com", "test.png", "image/png", "X", null);

    // Resolve HTML
    const html = "<img src=\"cid:img1@test.com\">";
    const resolved = try store.resolveHtml(html);
    defer allocator.free(resolved);

    // Should start with data URI
    try std.testing.expect(std.mem.startsWith(u8, resolved, "<img src=\"data:image/png;base64,"));
}

test "generateContentId creates valid CID" {
    const allocator = std.testing.allocator;

    const cid = try generateContentId(allocator, "example.com");
    defer allocator.free(cid);

    try std.testing.expect(std.mem.startsWith(u8, cid, "img"));
    try std.testing.expect(std.mem.endsWith(u8, cid, "@example.com"));
}

test "InlineAttachment toDataUri" {
    const allocator = std.testing.allocator;

    const att = InlineAttachment{
        .content_id = "test",
        .filename = "test.png",
        .mime_type = "image/png",
        .data = "test",
        .data_base64 = null,
        .hash = undefined,
        .size = 4,
    };

    const uri = try att.toDataUri(allocator);
    defer allocator.free(uri);

    try std.testing.expect(std.mem.startsWith(u8, uri, "data:image/png;base64,"));
}
