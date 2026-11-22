//! Preserve the existing MIME body and headers while adding EWS file parts.
const std = @import("std");
const mime = @import("../../message/mime.zig");
const compose = @import("../../api/webmail_compose.zig");
const io = @import("../../core/io_compat.zig");

pub const File = struct {
    id: [32]u8,
    name: []const u8,
    content_type: []const u8,
    data: []const u8,
    content_id: ?[]const u8,
    inline_part: bool,
};

pub fn id() [32]u8 {
    var random: [16]u8 = undefined;
    io.randomBytes(&random);
    return std.fmt.bytesToHex(random, .lower);
}

pub fn decode(a: std.mem.Allocator, raw: []const u8, limit: usize) ![]const u8 {
    const space = " \t\r\n";
    var encoded = raw;
    if (std.mem.indexOfAny(u8, raw, space) != null) {
        var compact: std.ArrayList(u8) = .empty;
        for (raw) |byte| if (std.mem.indexOfScalar(u8, space, byte) == null) try compact.append(a, byte);
        encoded = compact.items;
    }
    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(encoded) catch return error.InvalidBase64;
    if (size > limit) return error.MessageTooLarge;
    const bytes = try a.alloc(u8, size);
    decoder.decode(bytes, encoded) catch return error.InvalidBase64;
    return bytes;
}

/// Find a closing delimiter at a MIME line boundary, leaving the epilogue intact.
fn closingDelimiter(body: []const u8, boundary: []const u8) ?usize {
    var offset: usize = 0;
    while (offset < body.len) {
        const end = std.mem.indexOfScalarPos(u8, body, offset, '\n') orelse body.len;
        const line = std.mem.trimEnd(u8, body[offset..end], " \t\r");
        if (line.len == boundary.len + 4 and std.mem.startsWith(u8, line, "--") and
            std.mem.endsWith(u8, line, "--") and std.mem.eql(u8, line[2 .. line.len - 2], boundary)) return offset;
        offset = end + 1;
    }
    return null;
}

fn appendFiles(a: std.mem.Allocator, output: *std.ArrayList(u8), boundary: []const u8, files: []const File, limit: usize) !void {
    for (files) |file| {
        try output.print(a, "--{s}\r\nContent-Type: {s}\r\nContent-Transfer-Encoding: base64\r\nX-Mail-Ews-Attachment-Id: {s}\r\n", .{ boundary, file.content_type, file.id });
        if (file.content_id) |content_id| try output.print(a, "Content-ID: <{s}>\r\n", .{content_id});
        try output.print(a, "Content-Disposition: {s}; filename=\"", .{if (file.inline_part) "inline" else "attachment"});
        for (file.name) |byte| {
            if (byte == '"') try output.append(a, '\\');
            try output.append(a, byte);
        }
        try output.appendSlice(a, "\"\r\n\r\n");
        try output.appendSlice(a, try compose.base64Wrapped(a, file.data));
        if (output.items.len > limit) return error.MessageTooLarge;
    }
}

pub fn add(a: std.mem.Allocator, raw: []const u8, header_end: usize, body_start: usize, content_type: ?[]const u8, files: []const File, limit: usize) ![]const u8 {
    if (files.len == 0) return raw;
    if (body_start <= header_end) return error.InvalidMime;
    var output: std.ArrayList(u8) = .empty;
    if (content_type) |value| {
        var parsed = try mime.ContentType.parse(a, value);
        defer parsed.deinit();
        if (parsed.isMultipart() and std.ascii.eqlIgnoreCase(parsed.media_subtype, "mixed")) {
            const boundary = parsed.boundary orelse return error.InvalidMime;
            if (boundary.len == 0 or boundary.len > mime.MultipartParser.MAX_BOUNDARY_LENGTH) return error.InvalidMime;
            const before_close = body_start + (closingDelimiter(raw[body_start..], boundary) orelse return error.InvalidMime);
            try output.appendSlice(a, raw[0..before_close]);
            try appendFiles(a, &output, boundary, files, limit);
            try output.appendSlice(a, raw[before_close..]);
            if (output.items.len > limit) return error.MessageTooLarge;
            return output.items;
        }
    }

    const boundary = try std.fmt.allocPrint(a, "=_ews_{s}", .{id()});
    if (std.mem.indexOf(u8, raw, boundary) != null) return error.InvalidMime;
    var entity_headers: std.ArrayList(u8) = .empty;
    var lines = std.mem.splitScalar(u8, raw[0..header_end], '\n');
    var is_entity = false;
    var drop = false;
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (line.len == 0) continue;
        if (line[0] != ' ' and line[0] != '\t') {
            is_entity = std.ascii.startsWithIgnoreCase(line, "Content-");
            drop = std.ascii.startsWithIgnoreCase(line, "MIME-Version:");
        }
        if (drop) continue;
        const dest = if (is_entity) &entity_headers else &output;
        try dest.appendSlice(a, line);
        try dest.appendSlice(a, "\r\n");
    }
    try output.print(a, "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"{s}\"\r\n\r\n--{s}\r\n", .{ boundary, boundary });
    try output.appendSlice(a, entity_headers.items);
    try output.appendSlice(a, "\r\n");
    try output.appendSlice(a, raw[body_start..]);
    // The CRLF introducing a delimiter belongs to the multipart framing.
    try output.appendSlice(a, "\r\n");
    try appendFiles(a, &output, boundary, files, limit);
    try output.print(a, "--{s}--\r\n", .{boundary});
    if (output.items.len > limit) return error.MessageTooLarge;
    return output.items;
}
