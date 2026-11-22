//! Build the MIME entity for a server-assisted reply or forward.
const std = @import("std");
const io_compat = @import("../core/io_compat.zig");
const mime = @import("mime.zig");
const submission = @import("submission.zig");

pub const Mode = enum { reply, forward, attachment };

const Message = struct {
    headers: []const u8,
    body: []const u8,

    fn parse(raw: []const u8) !Message {
        var pos: usize = 0;
        while (std.mem.indexOfScalarPos(u8, raw, pos, '\n')) |end| {
            if (std.mem.trimEnd(u8, raw[pos..end], "\r").len == 0)
                return .{ .headers = raw[0..pos], .body = raw[end + 1 ..] };
            pos = end + 1;
        }
        return error.InvalidMime;
    }
};

const Field = struct { name: []const u8, raw: []const u8 };

const Fields = struct {
    rest: []const u8,

    fn next(self: *Fields) ?Field {
        if (self.rest.len == 0) return null;
        var end = afterLine(self.rest, 0);
        const first = self.rest[0..end];
        while (end < self.rest.len and (self.rest[end] == ' ' or self.rest[end] == '\t')) end = afterLine(self.rest, end);
        const field = Field{
            .name = if (std.mem.indexOfScalar(u8, first, ':')) |colon| first[0..colon] else "",
            .raw = self.rest[0..end],
        };
        self.rest = self.rest[end..];
        return field;
    }
};

fn afterLine(bytes: []const u8, offset: usize) usize {
    return if (std.mem.indexOfScalarPos(u8, bytes, offset, '\n')) |end| end + 1 else bytes.len;
}

fn isHeader(name: []const u8, expected: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, expected);
}

fn headerValue(a: std.mem.Allocator, headers: []const u8, name: []const u8) ![]const u8 {
    var fields = Fields{ .rest = headers };
    while (fields.next()) |field| {
        if (!isHeader(field.name, name)) continue;
        var value: std.ArrayList(u8) = .empty;
        var lines = std.mem.splitScalar(u8, field.raw[field.name.len + 1 ..], '\n');
        while (lines.next()) |line| {
            const part = std.mem.trim(u8, line, " \t\r");
            if (part.len == 0) continue;
            if (value.items.len > 0) try value.append(a, ' ');
            try value.appendSlice(a, part);
        }
        return value.toOwnedSlice(a);
    }
    return "";
}

fn writeField(a: std.mem.Allocator, out: *std.ArrayList(u8), raw: []const u8) !void {
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, raw, "\r\n"), '\n');
    while (lines.next()) |line| {
        const clean = std.mem.trimEnd(u8, line, "\r");
        for (clean) |byte| {
            if ((byte < 32 and byte != '\t') or byte == 127) return error.InvalidMime;
        }
        try out.print(a, "{s}\r\n", .{clean});
    }
}

fn writeEntity(a: std.mem.Allocator, out: *std.ArrayList(u8), entity: Message, include_disposition: bool) !void {
    var fields = Fields{ .rest = entity.headers };
    while (fields.next()) |field| {
        if (!std.ascii.startsWithIgnoreCase(field.name, "Content-")) continue;
        if (!include_disposition and isHeader(field.name, "Content-Disposition")) continue;
        try writeField(a, out, field.raw);
    }
    try out.print(a, "\r\n{s}\r\n", .{entity.body});
}

const Display = struct {
    kind: []const u8,
    encoding: []const u8,
    body: []const u8,
};

fn partHeader(part: mime.MimePart, name: []const u8) []const u8 {
    var it = part.headers.iterator();
    while (it.next()) |entry| {
        if (isHeader(entry.key_ptr.*, name)) return entry.value_ptr.*;
    }
    return "";
}

/// Replies quote a display body. Forwards retain the original MIME tree,
/// including attachments. Carry the display part's encoding and charset.
fn displayBody(a: std.mem.Allocator, body: []const u8, kind: []const u8, encoding: []const u8, disposition: []const u8, depth: usize) !?Display {
    if (depth >= mime.MultipartParser.MAX_MIME_DEPTH) return error.InvalidMime;
    if (std.ascii.startsWithIgnoreCase(disposition, "attachment")) return null;
    if (kind.len == 0) return .{ .kind = "text/plain", .encoding = encoding, .body = body };
    var content_type = try mime.ContentType.parse(a, kind);
    defer content_type.deinit();
    if (isHeader(content_type.media_type, "text") and
        (isHeader(content_type.media_subtype, "plain") or isHeader(content_type.media_subtype, "html")))
    {
        return .{ .kind = kind, .encoding = encoding, .body = body };
    }
    if (!content_type.isMultipart()) return null;
    const boundary = content_type.boundary orelse return error.InvalidMime;
    var parser = mime.MultipartParser.init(a);
    const parts = try parser.parse(body, boundary);
    var html: ?Display = null;
    for (parts) |part| {
        const shown = (try displayBody(a, part.body, partHeader(part, "Content-Type"), partHeader(part, "Content-Transfer-Encoding"), partHeader(part, "Content-Disposition"), depth + 1)) orelse continue;
        if (std.ascii.startsWithIgnoreCase(shown.kind, "text/plain")) return shown;
        if (html == null) html = shown;
    }
    return html;
}

/// Use a fresh boundary of fixed length and verify that neither message
/// already contains it. This also makes the stored size independent of retries.
fn newBoundary(client: []const u8, original: []const u8, buffer: *[42]u8) ![]const u8 {
    for (0..8) |_| {
        var random: [18]u8 = undefined;
        io_compat.randomBytes(&random);
        const hex = std.fmt.bytesToHex(random, .lower);
        const value = try std.fmt.bufPrint(buffer, "eas_{s}", .{&hex});
        if (std.mem.indexOf(u8, client, value) == null and std.mem.indexOf(u8, original, value) == null)
            return value;
    }
    return error.InvalidMime;
}

/// DATA stores LF line endings. The multipart decoder reads CRLF delimiters;
/// normalize the quote input only, preserving the forwarded MIME bytes.
fn replyBody(a: std.mem.Allocator, source: Message) !?Display {
    const kind = try headerValue(a, source.headers, "Content-Type");
    var body = source.body;
    if (std.ascii.startsWithIgnoreCase(kind, "multipart/") and std.mem.indexOfScalar(u8, body, '\n') != null) {
        var normalized: std.ArrayList(u8) = .empty;
        var pos: usize = 0;
        while (std.mem.indexOfScalarPos(u8, body, pos, '\n')) |end| {
            try normalized.appendSlice(a, std.mem.trimEnd(u8, body[pos..end], "\r"));
            try normalized.appendSlice(a, "\r\n");
            pos = end + 1;
        }
        try normalized.appendSlice(a, body[pos..]);
        body = try normalized.toOwnedSlice(a);
    }
    return displayBody(a, body, kind, try headerValue(a, source.headers, "Content-Transfer-Encoding"), try headerValue(a, source.headers, "Content-Disposition"), 0);
}

/// Add the source to the outgoing message without inheriting its envelope.
/// The caller uses an arena for the returned MIME and intermediate parts.
pub fn withOriginal(a: std.mem.Allocator, client: []const u8, original: []const u8, mode: Mode, max_bytes: usize) ![]const u8 {
    if (client.len > max_bytes or original.len > max_bytes) return error.MessageTooLarge;
    const outgoing = try Message.parse(client);
    const source = try Message.parse(original);
    const quote = if (mode == .reply) try replyBody(a, source) else null;
    if (mode == .reply and quote == null) return client;

    var boundary_buffer: [42]u8 = undefined;
    const boundary = try newBoundary(client, original, &boundary_buffer);
    var result: std.ArrayList(u8) = .empty;
    var fields = Fields{ .rest = outgoing.headers };
    while (fields.next()) |field| {
        if (isHeader(field.name, "MIME-Version") or std.ascii.startsWithIgnoreCase(field.name, "Content-")) continue;
        try writeField(a, &result, field.raw);
    }
    try result.print(a, "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"{s}\"\r\n\r\n--{s}\r\n", .{ boundary, boundary });
    try writeEntity(a, &result, outgoing, true);
    try result.print(a, "--{s}\r\n", .{boundary});
    switch (mode) {
        .reply => {
            const display = quote.?;
            try writeField(a, &result, try std.fmt.allocPrint(a, "Content-Type: {s}", .{display.kind}));
            if (display.encoding.len != 0)
                try writeField(a, &result, try std.fmt.allocPrint(a, "Content-Transfer-Encoding: {s}", .{display.encoding}));
            try result.print(a, "\r\n{s}\r\n", .{display.body});
        },
        .forward => try writeEntity(a, &result, source, false),
        .attachment => {
            const attached = try submission.withoutBcc(a, original);
            try result.print(a, "Content-Type: message/rfc822\r\nContent-Disposition: attachment; filename=\"forwarded.eml\"\r\n\r\n{s}\r\n", .{attached});
        },
    }
    try result.print(a, "--{s}--\r\n", .{boundary});
    if (result.items.len > max_bytes) return error.MessageTooLarge;
    return result.toOwnedSlice(a);
}
