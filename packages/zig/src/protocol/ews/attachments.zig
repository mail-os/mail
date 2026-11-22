//! Preserve the existing MIME body and headers while editing EWS file attachments.
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

const maildir = @import("../../api/webmail_maildir.zig");
const id_header = "X-Mail-Ews-Attachment-Id";

pub const Part = struct {
    id: [32]u8,
    /// This entity's original marker or digest collided with another part.
    id_disambiguated: bool,
    /// Offsets in the entire MIME message, including the preceding delimiter.
    start: usize,
    entity_start: usize,
    end: usize,
    only_child: bool,
    info: maildir.AttachmentInfo,
    inline_part: bool,

    pub fn readData(self: Part, a: std.mem.Allocator, raw: []const u8) ![]const u8 {
        const info = (try maildir.inspectAttachment(a, self.entity(raw), true)) orelse return error.InvalidAttachmentId;
        return info.data;
    }

    fn entity(self: Part, raw: []const u8) []const u8 {
        return entityBytes(raw, self.entity_start, self.end, self.start != self.entity_start);
    }
};

pub fn list(a: std.mem.Allocator, raw: []const u8) ![]const Part {
    var result: std.ArrayList(Part) = .empty;
    var seen = std.AutoHashMapUnmanaged([32]u8, void){};
    try collect(a, raw, 0, 0, raw.len, false, 0, &result, &seen);
    return result.items;
}

fn entityBytes(raw: []const u8, start: usize, end: usize, nested: bool) []const u8 {
    const entity = raw[start..end];
    if (!nested) return entity;
    // The CRLF immediately before a delimiter is part of the framing.
    if (std.mem.endsWith(u8, entity, "\r\n")) return entity[0 .. entity.len - 2];
    if (std.mem.endsWith(u8, entity, "\n")) return entity[0 .. entity.len - 1];
    return entity;
}

const Delimiter = struct { start: usize, next: usize, closing: bool };

fn boundaryAt(body: []const u8, boundary: []const u8, from: usize) ?Delimiter {
    var offset = from;
    while (offset < body.len) {
        const end = std.mem.indexOfScalarPos(u8, body, offset, '\n') orelse body.len;
        const line = std.mem.trimEnd(u8, body[offset..end], " \t\r");
        if (std.mem.startsWith(u8, line, "--") and std.mem.startsWith(u8, line[2..], boundary)) {
            const suffix = line[2 + boundary.len ..];
            if (suffix.len == 0 or std.mem.eql(u8, suffix, "--"))
                return .{ .start = offset, .next = @min(end + 1, body.len), .closing = suffix.len != 0 };
        }
        offset = end + 1;
    }
    return null;
}

fn collect(a: std.mem.Allocator, raw: []const u8, start: usize, entity_start: usize, end: usize, only_child: bool, depth: usize, result: *std.ArrayList(Part), seen: *std.AutoHashMapUnmanaged([32]u8, void)) !void {
    if (depth >= mime.MultipartParser.MAX_MIME_DEPTH or entity_start >= end) return;
    const entity = entityBytes(raw, entity_start, end, depth > 0);
    if (try maildir.inspectAttachment(a, entity, false)) |info| {
        const marker = try maildir.mimeHeader(a, entity, id_header);
        const valid = isId(marker);
        const identity = if (valid and !seen.contains(marker[0..32].*))
            Identity{ .key = marker[0..32].*, .disambiguated = false }
        else
            try derivedId(a, entity, seen);
        try seen.put(a, identity.key, {});
        const disposition = try maildir.mimeHeader(a, entity, "Content-Disposition");
        const kind = std.mem.trim(u8, disposition[0 .. std.mem.indexOfScalar(u8, disposition, ';') orelse disposition.len], " \t");
        try result.append(a, .{
            .id = identity.key,
            .id_disambiguated = (valid and !std.mem.eql(u8, marker, &identity.key)) or identity.disambiguated,
            .start = start,
            .entity_start = entity_start,
            .end = end,
            .only_child = only_child,
            .info = info,
            .inline_part = std.ascii.eqlIgnoreCase(kind, "inline"),
        });
        return;
    }

    const ctype = try maildir.mimeHeader(a, entity, "Content-Type");
    if (!std.ascii.startsWithIgnoreCase(ctype, "multipart/")) return;
    var parsed = try mime.ContentType.parse(a, ctype);
    defer parsed.deinit();
    const boundary = parsed.boundary orelse return error.InvalidMime;
    if (boundary.len == 0 or boundary.len > mime.MultipartParser.MAX_BOUNDARY_LENGTH) return error.InvalidMime;
    const body_start = if (std.mem.indexOf(u8, entity, "\r\n\r\n")) |i| i + 4 else if (std.mem.indexOf(u8, entity, "\n\n")) |i| i + 2 else return error.InvalidMime;
    const body = entity[body_start..];
    const absolute = entity_start + body_start;
    var prior = boundaryAt(body, boundary, 0) orelse return error.InvalidMime;
    var first = true;
    while (!prior.closing) {
        const next = boundaryAt(body, boundary, prior.next) orelse return error.InvalidMime;
        try collect(a, raw, absolute + prior.start, absolute + prior.next, absolute + next.start, first and next.closing, depth + 1, result, seen);
        prior = next;
        first = false;
    }
}

pub fn isId(value: []const u8) bool {
    if (value.len != 32) return false;
    for (value) |c| if (!(std.ascii.isDigit(c) or (c >= 'a' and c <= 'f'))) return false;
    return true;
}

const Identity = struct { key: [32]u8, disambiguated: bool };

/// Existing MIME may have no EWS identifier. The digest is independent of
/// where the entity was in the message. Identical occurrences are disambiguated.
fn derivedId(a: std.mem.Allocator, entity: []const u8, seen: *std.AutoHashMapUnmanaged([32]u8, void)) !Identity {
    var base: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(entity, &base, .{});
    var key = std.fmt.bytesToHex(base[0..16].*, .lower);
    var count: usize = 1;
    while (seen.contains(key)) : (count += 1) {
        const label = try std.fmt.allocPrint(a, "{s}:{d}", .{ std.fmt.bytesToHex(base, .lower), count });
        var derived: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(label, &derived, .{});
        key = std.fmt.bytesToHex(derived[0..16].*, .lower);
    }
    return .{ .key = key, .disambiguated = count > 1 };
}

pub fn remove(a: std.mem.Allocator, raw: []const u8, parts: []const Part, index: usize) ![]const u8 {
    const target = parts[index];
    var result: std.ArrayList(u8) = .empty;
    if (target.entity_start == 0) {
        // A single-part attachment occupies the root body. Keep the message headers.
        var lines = std.mem.splitScalar(u8, raw, '\n');
        var skip = false;
        while (lines.next()) |raw_line| {
            const line = std.mem.trimEnd(u8, raw_line, "\r");
            if (line.len == 0) break;
            if (line[0] != ' ' and line[0] != '\t')
                skip = std.ascii.startsWithIgnoreCase(line, "Content-") or std.ascii.startsWithIgnoreCase(line, id_header ++ ":");
            if (!skip) try result.print(a, "{s}\r\n", .{line});
        }
        try result.appendSlice(a, "Content-Type: text/plain; charset=utf-8\r\n\r\n");
        return result.items;
    }

    var cursor: usize = 0;
    for (parts, 0..) |sibling, position| {
        if (position == index) {
            try result.appendSlice(a, raw[cursor..target.start]);
            if (target.only_child) {
                try result.appendSlice(a, raw[target.start..target.entity_start]);
                try result.appendSlice(a, "Content-Type: text/plain; charset=utf-8\r\n\r\n\r\n");
            }
            cursor = target.end;
        } else if (position > index and sibling.id_disambiguated) {
            // Save IDs already given to callers, including identical duplicate files.
            try result.appendSlice(a, raw[cursor..sibling.entity_start]);
            try result.print(a, id_header ++ ": {s}\r\n", .{sibling.id});
            cursor = sibling.entity_start;
        }
    }
    try result.appendSlice(a, raw[cursor..]);
    return result.items;
}
