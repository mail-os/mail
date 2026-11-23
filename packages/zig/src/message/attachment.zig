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

    /// Decode attachment data based on encoding. Parts from
    /// `extractFromParts` arrive decoded already; this serves hand-built ones.
    pub fn decode(self: *Attachment) !void {
        if (self.decoded_data != null) {
            return; // Already decoded
        }
        self.decoded_data = try mime.decodeAlloc(self.allocator, mime.Encoding.parse(self.encoding), self.data);
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
    pub fn extractFromParts(self: *AttachmentExtractor, parts: []const mime.MimePart) ![]Attachment {
        var attachments: std.ArrayList(Attachment) = .empty;
        errdefer {
            for (attachments.items) |*att| {
                att.deinit();
            }
            attachments.deinit(self.allocator);
        }

        for (parts) |*part| {
            if (isAttachment(part)) {
                var att = try self.extractAttachment(part);
                errdefer att.deinit();
                try attachments.append(self.allocator, att);
            }
        }

        return try attachments.toOwnedSlice(self.allocator);
    }

    /// A part is an attachment when it says so or carries a file name. The
    /// walker parsed both parameters, so "inline; filename=attachment.png"
    /// no longer matches by substring.
    fn isAttachment(part: *const mime.MimePart) bool {
        return part.disposition == .attachment or part.filename != null or part.name != null;
    }

    fn extractAttachment(self: *AttachmentExtractor, part: *const mime.MimePart) !Attachment {
        const a = self.allocator;
        // Already RFC 2231 and RFC 2047 decoded by the walker.
        const filename = try a.dupe(u8, part.filename orelse part.name orelse "attachment.bin");
        errdefer a.free(filename);
        const content_type = if (part.content_type) |ct|
            try std.fmt.allocPrint(a, "{s}/{s}", .{ ct.media_type, ct.media_subtype })
        else
            try a.dupe(u8, "application/octet-stream");
        errdefer a.free(content_type);
        const encoding = try a.dupe(u8, encodingName(part));
        errdefer a.free(encoding);
        const data = try a.dupe(u8, part.body);
        errdefer a.free(data);
        const decoded = try a.dupe(u8, part.decoded);

        return Attachment{
            .filename = filename,
            .content_type = content_type,
            .encoding = encoding,
            .data = data,
            .decoded_data = decoded,
            .size = part.body.len,
            .allocator = a,
        };
    }

    /// The Content-Transfer-Encoding field the walker decoded with. With
    /// duplicate fields it prefers a later decoding one over an identity
    /// first, so the first field could contradict `decoded_data`.
    fn encodingName(part: *const mime.MimePart) []const u8 {
        var it = part.headers.iterator();
        while (it.next()) |f| {
            if (!std.ascii.eqlIgnoreCase(f.name, "content-transfer-encoding")) continue;
            if (mime.Encoding.parse(f.value) == part.encoding) return f.value;
        }
        return "7bit";
    }

    pub fn freeAttachments(self: *AttachmentExtractor, attachments: []Attachment) void {
        for (attachments) |*att| {
            att.deinit();
        }
        self.allocator.free(attachments);
    }
};

test "base64 decoding" {
    const testing = std.testing;

    const encoded = "SGVsbG8sIFdvcmxkIQ==";
    const decoded = try mime.decodeAlloc(testing.allocator, .base64, encoded);
    defer testing.allocator.free(decoded);

    try testing.expectEqualStrings("Hello, World!", decoded);
}

test "base64 decoding with whitespace" {
    const testing = std.testing;

    const encoded = "SGVs\r\nbG8s\r\nIFdv\r\ncmxk\r\nIQ==";
    const decoded = try mime.decodeAlloc(testing.allocator, .base64, encoded);
    defer testing.allocator.free(decoded);

    try testing.expectEqualStrings("Hello, World!", decoded);
}

test "quoted-printable decoding" {
    const testing = std.testing;

    const encoded = "Hello=2C World=21";
    const decoded = try mime.decodeAlloc(testing.allocator, .quoted_printable, encoded);
    defer testing.allocator.free(decoded);

    try testing.expectEqualStrings("Hello, World!", decoded);
}

test "quoted-printable soft line break" {
    const testing = std.testing;

    const encoded = "This is a long=\r\n line";
    const decoded = try mime.decodeAlloc(testing.allocator, .quoted_printable, encoded);
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

test "extractFromParts finds a bare-LF attachment" {
    const testing = std.testing;

    var parser = mime.MultipartParser.init(testing.allocator);
    const message = "--b\nContent-Type: text/plain\n\nhello\n--b\n" ++
        "Content-Type: application/octet-stream; name=\"payload.exe\"\n" ++
        "Content-Transfer-Encoding: base64\n" ++
        "Content-Disposition: attachment; filename=\"payload.exe\"\n\n" ++
        "TVqQAAMAAAAEAAAA\n--b--\n";
    const parts = try parser.parse(message, "b");
    defer parser.freeParts(parts);

    var extractor = AttachmentExtractor.init(testing.allocator);
    const attachments = try extractor.extractFromParts(parts);
    defer extractor.freeAttachments(attachments);

    try testing.expectEqual(@as(usize, 1), attachments.len);
    const att = attachments[0];
    try testing.expectEqualStrings("payload.exe", att.filename);
    try testing.expectEqualStrings("application/octet-stream", att.content_type);
    try testing.expectEqualStrings("base64", att.encoding);
    try testing.expect(std.mem.startsWith(u8, att.decoded_data.?, "MZ"));
}

test "the encoding names the field decoded_data was decoded with" {
    const testing = std.testing;

    var parser = mime.MultipartParser.init(testing.allocator);
    const message = "--b\r\nContent-Type: application/octet-stream; name=\"x.bin\"\r\n" ++
        "Content-Transfer-Encoding: 7bit\r\nContent-Transfer-Encoding: base64\r\n\r\n" ++
        "SGVsbG8=\r\n--b--\r\n";
    const parts = try parser.parse(message, "b");
    defer parser.freeParts(parts);

    var extractor = AttachmentExtractor.init(testing.allocator);
    const attachments = try extractor.extractFromParts(parts);
    defer extractor.freeAttachments(attachments);

    try testing.expectEqual(@as(usize, 1), attachments.len);
    const att = attachments[0];
    try testing.expectEqualStrings("base64", att.encoding);
    try testing.expectEqualStrings("SGVsbG8=", att.data);
    try testing.expectEqualStrings("Hello", att.decoded_data.?);
}

test "extractFromParts finds an attachment inside a base64-encoded multipart" {
    const testing = std.testing;

    const inner = "--i\r\nContent-Type: application/octet-stream\r\n" ++
        "Content-Disposition: attachment; filename=\"evil.exe\"\r\n" ++
        "Content-Transfer-Encoding: base64\r\n\r\nTVqQ\r\n--i--\r\n";
    const encoded = comptime blk: {
        var buf: [std.base64.standard.Encoder.calcSize(inner.len)]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&buf, inner);
        break :blk buf;
    };
    const message = "--o\r\nContent-Type: multipart/mixed; boundary=\"i\"\r\n" ++
        "Content-Transfer-Encoding: base64\r\n\r\n" ++ encoded ++ "\r\n--o--\r\n";

    var parser = mime.MultipartParser.init(testing.allocator);
    const parts = try parser.parse(message, "o");
    defer parser.freeParts(parts);

    var extractor = AttachmentExtractor.init(testing.allocator);
    const attachments = try extractor.extractFromParts(parts);
    defer extractor.freeAttachments(attachments);

    try testing.expectEqual(@as(usize, 1), attachments.len);
    try testing.expectEqualStrings("evil.exe", attachments[0].filename);
    try testing.expect(std.mem.startsWith(u8, attachments[0].decoded_data.?, "MZ"));
}
