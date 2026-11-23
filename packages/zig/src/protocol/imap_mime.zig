//! IMAP's view of a message, with offsets into its transfer-encoded source.
const std = @import("std");
const mime = @import("../message/mime.zig");
const source = @import("../message/mime_source.zig");

const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const max_depth = mime.MultipartParser.MAX_MIME_DEPTH;
const max_parts = 10_000;
const default_type = mime.ContentType.default;

const Part = struct {
    kind: mime.lib.Kind = .leaf,
    content_type: mime.ContentType = default_type,
    headers: mime.lib.Headers = .{},
    encoding: []const u8 = "7BIT",
    header_start: usize = 0,
    body_start: usize,
    body_end: usize = 0,
    first_child: ?usize = null,
    next_sibling: ?usize = null,
};

pub const Tree = struct {
    raw: []const u8,
    parts: []const Part,

    /// The allocator owns the tree and its copied header metadata. Source
    /// spans refer to raw and keep its original line endings and encoding.
    pub fn parse(a: Allocator, raw: []const u8, header_end: usize) Allocator.Error!Tree {
        var scratch_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer scratch_arena.deinit();
        const scratch_allocator = scratch_arena.allocator();
        const walker = try scratch_allocator.create(mime.lib.Walker);
        const scratch = try scratch_allocator.alloc(u8, @min(raw.len, 1024 * 1024) + 64 * 1024);
        var builder: Builder = .{ .a = a, .raw = raw };
        source.walk(walker, scratch, raw, null, &builder, .{
            .max_depth = max_depth,
            .max_parts = max_parts,
        }) catch {
            if (builder.out_of_memory) return error.OutOfMemory;
            const fallback = try a.create(Part);
            fallback.* = .{ .body_start = header_end, .body_end = raw.len };
            return .{ .raw = raw, .parts = @as(*[1]Part, @ptrCast(fallback)) };
        };
        return .{ .raw = raw, .parts = builder.parts.items };
    }

    pub fn writeStructure(self: Tree, a: Allocator, out: *Writer) !void {
        try self.writePart(a, out, 0);
    }

    pub const Section = struct {
        bytes: []const u8,
        /// A numbered HEADER.FIELDS or HEADER.FIELDS.NOT suffix to apply.
        header_filter: ?[]const u8 = null,
    };

    pub fn section(self: Tree, spec: []const u8) ?Section {
        var current: usize = 0;
        var rest = spec;
        var first = true;
        while (true) {
            const dot = std.mem.indexOfScalar(u8, rest, '.');
            const number = rest[0 .. dot orelse rest.len];
            if (number.len == 0 or number[0] == '0') return null;
            for (number) |byte| if (!std.ascii.isDigit(byte)) return null;
            const ordinal = std.fmt.parseInt(usize, number, 10) catch return null;

            if (!first and self.parts[current].kind == .message) {
                current = self.parts[current].first_child orelse return null;
                if (self.parts[current].kind == .multipart) {
                    current = self.childAt(current, ordinal) orelse return null;
                } else if (ordinal != 1) return null;
            } else if (self.parts[current].kind == .multipart) {
                current = self.childAt(current, ordinal) orelse return null;
            } else if (!first or ordinal != 1) {
                return null;
            }

            if (dot) |at| {
                rest = rest[at + 1 ..];
                if (rest.len == 0) return null;
                if (!std.ascii.isDigit(rest[0])) return self.suffix(current, rest);
                first = false;
            } else return .{ .bytes = self.body(self.parts[current]) };
        }
    }

    fn childAt(self: Tree, parent: usize, ordinal: usize) ?usize {
        var child = self.parts[parent].first_child;
        var remaining = ordinal - 1;
        while (remaining > 0) : (remaining -= 1) {
            const index = child orelse return null;
            child = self.parts[index].next_sibling;
        }
        return child;
    }

    fn suffix(self: Tree, index: usize, spec: []const u8) ?Section {
        const part = self.parts[index];
        if (std.ascii.eqlIgnoreCase(spec, "MIME"))
            return .{ .bytes = self.raw[part.header_start..part.body_start] };
        if (part.kind != .message) return null;
        const embedded = self.parts[part.first_child orelse return null];
        if (std.ascii.eqlIgnoreCase(spec, "TEXT")) return .{ .bytes = self.body(embedded) };
        const header = self.raw[embedded.header_start..embedded.body_start];
        if (std.ascii.eqlIgnoreCase(spec, "HEADER")) return .{ .bytes = header };
        if (std.ascii.startsWithIgnoreCase(spec, "HEADER.FIELDS"))
            return .{ .bytes = header, .header_filter = spec };
        return null;
    }

    fn body(self: Tree, part: Part) []const u8 {
        return self.raw[part.body_start..part.body_end];
    }

    fn writePart(self: Tree, a: Allocator, out: *Writer, index: usize) error{ OutOfMemory, WriteFailed }!void {
        const part = self.parts[index];
        try out.writeByte('(');
        if (part.kind == .multipart and part.first_child != null) {
            var child = part.first_child;
            while (child) |entry| : (child = self.parts[entry].next_sibling) {
                try self.writePart(a, out, entry);
            }
            try out.writeByte(' ');
            try writeString(out, part.content_type.media_subtype, true);
            try out.writeByte(' ');
            try writeParams(a, out, part.content_type.params, false);
            try writeExtensions(a, out, part.headers);
        } else {
            // An opaque or empty container has no nested structure to emit.
            // Preserve its raw bytes as a single attachment.
            const opaque_container = part.content_type.isMultipart() or
                (part.content_type.isEmbeddedMessage() and (part.kind != .message or part.first_child == null));
            const media_type = if (opaque_container) "application" else part.content_type.media_type;
            const subtype = if (opaque_container) "octet-stream" else part.content_type.media_subtype;
            try writeString(out, media_type, true);
            try out.writeByte(' ');
            try writeString(out, subtype, true);
            try out.writeByte(' ');
            const is_text = std.ascii.eqlIgnoreCase(media_type, "text");
            try writeParams(a, out, if (opaque_container) "" else part.content_type.params, is_text);
            try out.writeByte(' ');
            try writeOptional(out, part.headers.get("Content-ID"));
            try out.writeByte(' ');
            try writeOptional(out, part.headers.get("Content-Description"));
            try out.writeByte(' ');
            try writeString(out, part.encoding, true);
            const bytes = self.body(part);
            try out.print(" {d}", .{bytes.len});
            if (part.kind == .message and !opaque_container) {
                const embedded = part.first_child.?;
                try out.writeByte(' ');
                try writeEnvelope(out, self.parts[embedded].headers);
                try out.writeByte(' ');
                try self.writePart(a, out, embedded);
            }
            if (is_text or (part.kind == .message and !opaque_container))
                try out.print(" {d}", .{std.mem.count(u8, bytes, "\n")});
            try out.writeAll(" NIL"); // Content-MD5
            try writeExtensions(a, out, part.headers);
        }
        try out.writeByte(')');
    }
};

const Builder = struct {
    const Slot = struct {
        index: usize = 0,
        last_child: ?usize = null,
        boundaries: []const []const u8 = &.{},
    };

    a: Allocator,
    raw: []const u8,
    parts: std.ArrayList(Part) = .empty,
    stack: [max_depth + 1]Slot = @splat(.{}),
    out_of_memory: bool = false,

    pub fn onEvent(self: *Builder, event: mime.lib.Event, loc: source.Location) mime.lib.Sink.Error!void {
        switch (event) {
            .part_begin => |part| self.begin(part, loc) catch {
                self.out_of_memory = true;
                return error.Aborted;
            },
            .part_end => |end| {
                const node = &self.parts.items[self.stack[end.part.depth].index];
                // An empty part's header separator can be the newline the
                // walker consumes as framing for the following delimiter.
                node.body_end = @max(node.body_start, loc.bodyEnd(self.raw));
                node.header_start = @min(node.header_start, node.body_start);
                if (node.first_child == null) node.kind = .leaf;
            },
            .diagnostic => |diag| switch (diag.kind) {
                .depth_exceeded, .part_limit, .header_too_large, .scratch_exhausted => return error.Aborted,
                else => {},
            },
            .body => {},
        }
    }

    fn begin(self: *Builder, part: *const mime.lib.Part, loc: source.Location) Allocator.Error!void {
        const index = self.parts.items.len;
        var header_start: usize = 0;
        if (part.depth > 0) {
            const parent = &self.stack[part.depth - 1];
            const node = &self.parts.items[parent.index];
            header_start = if (node.kind == .message)
                node.body_start
            else
                childHeaderStart(self.raw, node.body_start, loc.start, parent.boundaries);
            if (parent.last_child) |previous| {
                self.parts.items[previous].next_sibling = index;
            } else node.first_child = index;
            parent.last_child = index;
        }
        self.stack[part.depth] = .{ .index = index, .boundaries = part.boundaries };
        const content_type = part.content_type;
        const headers: mime.lib.Headers = .{ .block = try self.a.dupe(u8, part.headers.block) };
        try self.parts.append(self.a, .{
            .kind = part.kind,
            .headers = headers,
            .content_type = .{
                .media_type = try self.a.dupe(u8, content_type.media_type),
                .media_subtype = try self.a.dupe(u8, content_type.media_subtype),
                .params = try self.a.dupe(u8, content_type.params),
            },
            .encoding = switch (part.encoding) {
                .none, .seven_bit => "7BIT",
                .eight_bit => "8BIT",
                .binary => "BINARY",
                .base64 => "BASE64",
                .quoted_printable => "QUOTED-PRINTABLE",
                .unknown => headers.get("Content-Transfer-Encoding") orelse "7BIT",
            },
            .header_start = header_start,
            .body_start = loc.bodyStart(),
        });
    }
};

/// The open multipart's delimiter precedes this part's first header line.
/// The walker already decided which boundaries belong to the parent; do not
/// infer one from the text of a raw Content-Type header.
fn childHeaderStart(raw: []const u8, floor: usize, current_line: usize, boundaries: []const []const u8) usize {
    var end = current_line;
    while (end > floor) {
        const previous = std.mem.lastIndexOfScalar(u8, raw[floor .. end - 1], '\n');
        const start = if (previous) |nl| floor + nl + 1 else floor;
        if (std.mem.startsWith(u8, raw[start..end], "--")) {
            for (boundaries) |boundary| {
                if (std.mem.startsWith(u8, raw[start + 2 .. end], boundary)) return end;
            }
        }
        end = start;
    }
    return current_line;
}

fn writeString(out: *Writer, value: []const u8, uppercase: bool) Writer.Error!void {
    var literal = false;
    for (value) |byte| {
        if (byte < ' ' or byte > '~') {
            literal = true;
            break;
        }
    }
    if (literal) {
        try out.print("{{{d}}}\r\n", .{value.len});
    } else try out.writeByte('"');
    for (value) |byte| {
        if (!literal and (byte == '"' or byte == '\\')) try out.writeByte('\\');
        try out.writeByte(if (byte == 0) '?' else if (uppercase) std.ascii.toUpper(byte) else byte);
    }
    if (!literal) try out.writeByte('"');
}

fn writeOptional(out: *Writer, value: ?[]const u8) Writer.Error!void {
    if (value) |text| try writeString(out, text, false) else try out.writeAll("NIL");
}

fn writeParams(a: Allocator, out: *Writer, params: []const u8, default_charset: bool) !void {
    // Collapse duplicate names and RFC 2231 fragments, preserving the order
    // of the first occurrence of each parameter.
    var names: std.StringArrayHashMapUnmanaged(mime.lib.headers.Param) = .empty;
    var it: mime.lib.headers.ParamIterator = .{ .rest = params };
    while (it.next()) |param| {
        const star = std.mem.indexOfScalar(u8, param.name, '*') orelse param.name.len;
        if (star == 0) continue;
        const name = try std.ascii.allocLowerString(a, param.name[0..star]);
        const entry = try names.getOrPut(a, name);
        if (!entry.found_existing or star != param.name.len) entry.value_ptr.* = param;
    }
    if (names.count() == 0 and !default_charset) return out.writeAll("NIL");

    var first = true;
    var decoded_buf: [4096]u8 = undefined;
    for (names.keys(), names.values()) |name, param| {
        const value = if (param.name.len != name.len)
            if (mime.lib.decodeParam(params, name, &decoded_buf)) |decoded| decoded.text else continue
        else if (param.quoted)
            mime.lib.headers.unquote(param.value[0..@min(param.value.len, decoded_buf.len)], &decoded_buf)
        else
            param.value;
        try out.writeByte(if (first) '(' else ' ');
        try writeString(out, name, true);
        try out.writeByte(' ');
        try writeString(out, value, false);
        first = false;
    }
    if (default_charset and !names.contains("charset")) {
        try out.writeByte(if (first) '(' else ' ');
        try out.writeAll("\"CHARSET\" \"US-ASCII\"");
        first = false;
    }
    // A malformed parameter list can contain only unusable continuations.
    if (first) return out.writeAll("NIL");
    try out.writeByte(')');
}

fn writeExtensions(a: Allocator, out: *Writer, headers: mime.lib.Headers) !void {
    const value = headers.get("Content-Disposition") orelse "";
    const disposition = mime.lib.Disposition.parse(value);
    const kind = std.mem.trim(u8, value[0 .. value.len - disposition.params.len], " \t");
    if (kind.len == 0) {
        try out.writeAll(" NIL");
    } else {
        try out.writeAll(" (");
        try writeString(out, kind, true);
        try out.writeByte(' ');
        try writeParams(a, out, disposition.params, false);
        try out.writeByte(')');
    }
    if (headers.get("Content-Language")) |language| {
        var languages = std.mem.tokenizeAny(u8, language, ", \t");
        if (languages.next()) |first| {
            if (languages.peek() != null) {
                try out.writeAll(" (");
                try writeString(out, first, false);
                while (languages.next()) |next| {
                    try out.writeByte(' ');
                    try writeString(out, next, false);
                }
                try out.writeByte(')');
            } else {
                try out.writeByte(' ');
                try writeString(out, first, false);
            }
        } else try out.writeAll(" NIL");
    } else try out.writeAll(" NIL");
    try out.writeByte(' ');
    try writeOptional(out, headers.get("Content-Location"));
}

fn writeEnvelope(out: *Writer, headers: mime.lib.Headers) Writer.Error!void {
    try out.writeByte('(');
    try writeOptional(out, headers.get("Date"));
    try out.writeByte(' ');
    try writeOptional(out, headers.get("Subject"));
    const from = headers.get("From") orelse "";
    for ([_][]const u8{
        from,
        headers.get("Sender") orelse from,
        headers.get("Reply-To") orelse from,
        headers.get("To") orelse "",
        headers.get("Cc") orelse "",
        headers.get("Bcc") orelse "",
    }) |value| {
        try out.writeByte(' ');
        try writeAddresses(out, value);
    }
    try out.writeByte(' ');
    try writeOptional(out, headers.get("In-Reply-To"));
    try out.writeByte(' ');
    try writeOptional(out, headers.get("Message-ID"));
    try out.writeByte(')');
}

fn writeAddresses(out: *Writer, value: []const u8) Writer.Error!void {
    var start: usize = 0;
    var quoted = false;
    var escaped = false;
    var comments: usize = 0;
    var angled = false;
    var domain_literal = false;
    var opened = false;
    var group = false;
    for (value, 0..) |byte, index| {
        if (escaped) {
            escaped = false;
            continue;
        }
        if (byte == '\\' and (quoted or comments != 0 or domain_literal)) {
            escaped = true;
            continue;
        }
        if (!quoted and !domain_literal and byte == '(') {
            comments += 1;
            continue;
        }
        if (comments != 0) {
            if (byte == ')') comments -= 1;
            continue;
        }
        if (!domain_literal and byte == '"') quoted = !quoted;
        if (quoted) continue;
        if (byte == '[') domain_literal = true;
        if (byte == ']') domain_literal = false;
        if (domain_literal) continue;
        if (byte == '<') angled = true;
        if (byte == '>') angled = false;
        if (angled) continue;
        switch (byte) {
            ':' => {
                const name = std.mem.trim(u8, value[start..index], " \t");
                if (!group and name.len != 0) {
                    try beginAddressList(out, &opened);
                    try writeAddress(out, null, null, name, null);
                    group = true;
                }
                start = index + 1;
            },
            ',', ';' => {
                try writeMailbox(out, &opened, value[start..index]);
                if (byte == ';' and group) {
                    try writeAddress(out, null, null, null, null);
                    group = false;
                }
                start = index + 1;
            },
            else => {},
        }
    }
    try writeMailbox(out, &opened, value[start..]);
    if (group) try writeAddress(out, null, null, null, null);
    try out.writeAll(if (opened) ")" else "NIL");
}

fn beginAddressList(out: *Writer, opened: *bool) Writer.Error!void {
    if (!opened.*) {
        try out.writeByte('(');
        opened.* = true;
    }
}

fn writeMailbox(out: *Writer, opened: *bool, value: []const u8) Writer.Error!void {
    const trimmed = std.mem.trim(u8, value, " \t");
    var address = trimmed;
    var name: ?[]const u8 = null;
    var route: ?[]const u8 = null;
    if (std.mem.lastIndexOfScalar(u8, trimmed, '<')) |left| {
        const right = std.mem.lastIndexOfScalar(u8, trimmed, '>') orelse return;
        if (right <= left) return;
        address = std.mem.trim(u8, trimmed[left + 1 .. right], " \t");
        const display = std.mem.trim(u8, trimmed[0..left], " \t");
        if (display.len != 0) name = display;
    }
    if (std.mem.startsWith(u8, address, "@")) {
        if (std.mem.indexOfScalar(u8, address, ':')) |colon| {
            route = address[0..colon];
            address = address[colon + 1 ..];
        }
    }
    const at = std.mem.lastIndexOfScalar(u8, address, '@') orelse return;
    if (at == 0 or at + 1 == address.len) return;
    const host = address[at + 1 ..];
    const comment = std.mem.indexOfScalar(u8, host, '(') orelse host.len;
    const domain = std.mem.trimEnd(u8, host[0..comment], " \t");
    if (domain.len == 0) return;
    try beginAddressList(out, opened);
    try writeAddress(out, name, route, address[0..at], domain);
}

fn writeAddress(out: *Writer, name: ?[]const u8, route: ?[]const u8, mailbox: ?[]const u8, domain: ?[]const u8) Writer.Error!void {
    try out.writeByte('(');
    for ([_]?[]const u8{ name, route, mailbox, domain }, 0..) |field, index| {
        if (index != 0) try out.writeByte(' ');
        if (field) |value| {
            if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
                var buf: [4096]u8 = undefined;
                const quoted = value[1 .. value.len - 1];
                try writeString(out, mime.lib.headers.unquote(quoted[0..@min(quoted.len, buf.len)], &buf), false);
                continue;
            }
        }
        try writeOptional(out, field);
    }
    try out.writeByte(')');
}
