//! Project the MIME walker into the body and file views used by webmail.
const std = @import("std");
const mime = @import("../message/mime.zig");
const calendar = @import("webmail_calendar_invite.zig");

const Allocator = std.mem.Allocator;
const Part = mime.lib.Part;
const max_depth = mime.MultipartParser.MAX_MIME_DEPTH;
const max_parts = 10_000;

pub const AttachmentInfo = struct {
    filename: []const u8,
    content_type: []const u8,
    size: usize,
    data: []const u8 = "",
    content_id: []const u8 = "",
};

pub const BodyParts = struct {
    text: []const u8 = "",
    html: []const u8 = "",
    has_attachments: bool = false,
    attachments: []const AttachmentInfo = &.{},
    calendar_parts: []const calendar.Part = &.{},
};

pub const Mode = enum { preview, metadata, full, calendar };

pub fn extract(a: Allocator, raw: []const u8, mode: Mode) !BodyParts {
    var output: Output = .{};
    try walk(a, &output, raw, null, mode, 0, false);
    return .{
        .text = output.text,
        .html = output.html,
        .has_attachments = output.has_attachments,
        .attachments = output.attachments.items,
        .calendar_parts = output.calendar_parts.items,
    };
}

/// EWS uses this for an already-framed attachment. An enclosing multipart
/// without an attachment name must not be mistaken for one of its children.
pub fn inspectAttachment(a: Allocator, raw: []const u8, include_data: bool) !?AttachmentInfo {
    var output: Output = .{};
    try walk(a, &output, raw, null, if (include_data) .full else .metadata, 0, true);
    return if (output.attachments.items.len == 0) null else output.attachments.items[0];
}

const Output = struct {
    text: []const u8 = "",
    html: []const u8 = "",
    has_attachments: bool = false,
    attachments: std.ArrayList(AttachmentInfo) = .empty,
    calendar_parts: std.ArrayList(calendar.Part) = .empty,
    seen: u32 = 0,
};

const Line = struct {
    start: usize = 0,
    end: usize = 0,
    blank: bool = false,
};

const Slot = struct {
    boundaries: []const []const u8 = &.{},
    body_start: usize = 0,
    attached_container: bool = false,
    skipped: bool = false,
    file: ?AttachmentInfo = null,
    method: ?calendar.Method = null,
    display: enum { none, text, html } = .none,
    encoded_multipart: bool = false,
    bytes: std.ArrayList(u8) = .empty,
};

fn walk(a: Allocator, output: *Output, raw: []const u8, headers: ?[]const u8, mode: Mode, depth: u8, root_only: bool) anyerror!void {
    if (depth > max_depth or output.seen >= max_parts) return;
    var workspace = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer workspace.deinit();
    const temporary = workspace.allocator();
    const scratch = try temporary.alloc(u8, @min(raw.len, 1024 * 1024) + 64 * 1024);
    const walker = try temporary.create(mime.lib.Walker);
    var collector: Collector = .{ .a = a, .output = output, .raw = raw, .mode = mode, .depth = depth, .root_only = root_only };
    walker.* = mime.lib.Walker.init(scratch, mime.lib.Sink.init(&collector), .{
        .max_depth = max_depth - depth,
        .max_parts = max_parts - output.seen,
    });
    collector.read(walker, headers) catch {
        if (collector.failure) |err| return err;
    };
}

const Collector = struct {
    a: Allocator,
    output: *Output,
    raw: []const u8,
    mode: Mode,
    depth: u8,
    root_only: bool,
    line: Line = .{},
    eof: bool = false,
    slots: [max_depth + 1]Slot = @splat(.{}),
    failure: ?anyerror = null,

    /// Feed physical lines from the original message. The walker decides
    /// which lines open and close parts. The line positions let us preserve
    /// opaque containers, whose bytes are not emitted as leaf body events.
    fn read(self: *Collector, walker: *mime.lib.Walker, headers: ?[]const u8) mime.lib.Sink.Error!void {
        if (headers) |block| try walker.beginWithHeaders(block);
        var pos: usize = 0;
        while (pos < self.raw.len) {
            const end = if (std.mem.indexOfScalarPos(u8, self.raw, pos, '\n')) |nl| nl + 1 else self.raw.len;
            const line = self.raw[pos..end];
            self.line = .{ .start = pos, .end = end, .blank = std.mem.eql(u8, line, "\n") or std.mem.eql(u8, line, "\r\n") };
            try walker.feed(line);
            // Resolve a delimiter at EOF even when it has no final newline.
            // Compare with the open boundaries, whose tolerant prefix match
            // is also used by the walker. Only a delimiter gets a synthetic
            // newline, so transfer decoders never see an altered body.
            if (end == self.raw.len and line[line.len - 1] != '\n' and self.terminalDelimiter(line)) try walker.feed("\n");
            pos = end;
        }
        self.eof = true;
        self.line = .{ .start = self.raw.len, .end = self.raw.len };
        try walker.finish();
    }

    pub fn onEvent(self: *Collector, event: mime.lib.Event) mime.lib.Sink.Error!void {
        switch (event) {
            .part_begin => |p| self.beginPart(p) catch |err| return self.abort(err),
            .body => |b| self.body(b) catch |err| return self.abort(err),
            .part_end => |e| self.finishPart(e) catch |err| return self.abort(err),
            .diagnostic => |d| switch (d.kind) {
                // Stop before incomplete headers can turn an attachment into
                // display text. Keep the earlier parts and mailbox usable.
                .header_too_large, .scratch_exhausted => return error.Aborted,
                else => {},
            },
        }
    }

    fn abort(self: *Collector, err: anyerror) mime.lib.Sink.Error {
        if (err != error.NoRootAttachment) self.failure = err;
        return error.Aborted;
    }

    fn beginPart(self: *Collector, p: *const Part) !void {
        self.output.seen += 1;
        const slot = &self.slots[p.depth];
        slot.* = .{ .boundaries = p.boundaries };
        if (p.depth != 0 and (self.root_only or self.slots[p.depth - 1].attached_container or self.slots[p.depth - 1].skipped)) {
            slot.skipped = true;
            return;
        }
        slot.body_start = if (self.line.blank) self.line.end else self.line.start;
        const filename = fileName(p);
        slot.attached_container = p.content_type.isEmbeddedMessage() or (p.content_type.isMultipart() and filename != null);
        if (self.root_only and filename == null) return error.NoRootAttachment;
        if (filename) |name| {
            if (self.mode != .calendar) self.output.has_attachments = true;
            if (self.mode == .full or self.mode == .metadata)
                slot.file = try attachment(self.a, p, name, self.root_only);
        }
        if (p.content_type.is("text", "calendar") and p.headers.count("content-type") == 1 and p.encoding != .unknown and
            (self.mode == .full or self.mode == .calendar) and self.output.calendar_parts.items.len < calendar.max_parts)
        {
            slot.method = calendar.mimeMethod(p.headers.get("content-type").?);
        }
        if (p.kind != .leaf or slot.attached_container or filename != null or self.root_only) return;
        if (p.content_type.isMultipart() and !p.encoding.isIdentity() and p.depth + self.depth < max_depth) {
            slot.encoded_multipart = true;
        } else if (self.mode != .calendar) {
            if (p.content_type.is("text", "html")) {
                if (self.output.html.len == 0) slot.display = .html;
            } else if (p.content_type.is("text", "plain") or (p.depth == 0 and self.depth == 0)) {
                if (self.output.text.len == 0) slot.display = .text;
            }
        }
    }

    fn body(self: *Collector, b: mime.lib.Body) !void {
        if (b.raw or b.region != .content) return;
        const slot = &self.slots[b.part.depth];
        if (slot.skipped or b.part.kind != .leaf) return;
        const has_file = slot.file != null and self.mode == .full;
        if (!has_file and slot.display == .none and slot.method == null and !slot.encoded_multipart) return;
        // Calendar delivery reads only bounded calendar payloads. The walker
        // can continue counting larger files without retaining their content.
        if (!has_file and slot.display == .none and !slot.encoded_multipart and
            slot.bytes.items.len + b.bytes.len > calendar.max_part_bytes)
        {
            slot.method = null;
            return;
        }
        try slot.bytes.appendSlice(self.a, b.bytes);
    }

    fn finishPart(self: *Collector, e: mime.lib.PartEnd) !void {
        const slot = &self.slots[e.part.depth];
        slot.boundaries = &.{};
        if (slot.skipped) return;
        if (slot.file) |*file| {
            if (slot.attached_container and e.part.kind != .leaf) {
                const end_pos = if (self.eof) self.raw.len else beforeDelimiter(self.raw, self.line.start);
                const bytes = self.raw[slot.body_start..@max(slot.body_start, end_pos)];
                file.size = bytes.len;
                if (self.mode == .full) file.data = bytes;
            } else {
                file.size = @intCast(e.decoded_bytes);
                if (self.mode == .full) file.data = slot.bytes.items;
            }
            try self.output.attachments.append(self.a, file.*);
        }
        if (slot.method) |method| {
            // Multipart invitation actions require a terminated part.
            if ((!self.eof or e.part.depth == 0) and !e.decode_flags.invalid_input and !e.decode_flags.padding_inside)
                try self.addCalendar(method, slot.bytes.items);
        }
        switch (slot.display) {
            .text => self.output.text = slot.bytes.items,
            .html => self.output.html = slot.bytes.items,
            .none => {},
        }
        if (slot.encoded_multipart and slot.bytes.items.len > 0) {
            var headers: std.ArrayList(u8) = .empty;
            var fields = e.part.headers.iterator();
            while (fields.next()) |field| {
                if (!std.ascii.eqlIgnoreCase(field.name, "content-type")) continue;
                try headers.print(self.a, "Content-Type: {s}\n", .{field.value});
            }
            try walk(self.a, self.output, slot.bytes.items, headers.items, self.mode, self.depth + e.part.depth + 1, false);
        }
    }

    fn addCalendar(self: *Collector, method: calendar.Method, decoded: []const u8) !void {
        const bytes = std.mem.trimEnd(u8, decoded, "\r\n");
        if (bytes.len == 0 or bytes.len > calendar.max_part_bytes or self.output.calendar_parts.items.len >= calendar.max_parts) return;
        for (self.output.calendar_parts.items) |part| {
            if (part.method == method and std.mem.eql(u8, part.body, bytes)) return;
        }
        try self.output.calendar_parts.append(self.a, .{ .method = method, .body = bytes });
    }

    fn terminalDelimiter(self: *const Collector, line: []const u8) bool {
        if (!std.mem.startsWith(u8, line, "--")) return false;
        for (self.slots) |slot| {
            for (slot.boundaries) |boundary| {
                if (std.mem.startsWith(u8, line[2..], boundary)) return true;
            }
        }
        return false;
    }
};

fn beforeDelimiter(raw: []const u8, offset: usize) usize {
    if (offset >= 2 and std.mem.eql(u8, raw[offset - 2 .. offset], "\r\n")) return offset - 2;
    if (offset >= 1 and raw[offset - 1] == '\n') return offset - 1;
    return offset;
}

fn fileName(p: *const Part) ?[]const u8 {
    if (p.filename) |name| if (name.len > 0) return name;
    if (!p.content_type.isMultipart()) {
        if (p.name) |name| if (name.len > 0) return name;
    }
    if (std.ascii.eqlIgnoreCase(p.content_type.media_type, "image") and contentId(p.headers.get("content-id") orelse "").len != 0)
        return "inline-image";
    if (p.disposition == .attachment) return "attachment";
    return null;
}

fn attachment(a: Allocator, p: *const Part, name: []const u8, root_only: bool) !AttachmentInfo {
    const ct = p.content_type;
    const cid = if (root_only or std.ascii.eqlIgnoreCase(ct.media_type, "image"))
        contentId(p.headers.get("content-id") orelse "")
    else
        "";
    return .{
        .filename = try a.dupe(u8, name),
        .content_type = if (p.headers.get("content-type") == null)
            "application/octet-stream"
        else
            try std.fmt.allocPrint(a, "{s}/{s}{s}", .{ ct.media_type, ct.media_subtype, ct.params }),
        .size = 0,
        .content_id = try a.dupe(u8, cid),
    };
}

fn contentId(s: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, s, " \t\r\n");
    const id = if (trimmed.len >= 2 and trimmed[0] == '<' and trimmed[trimmed.len - 1] == '>') trimmed[1 .. trimmed.len - 1] else trimmed;
    if (id.len > 320) return "";
    for (id) |byte| {
        if (!std.ascii.isPrint(byte) or byte == ' ' or byte == '<' or byte == '>') return "";
    }
    return id;
}

test "named multipart stays opaque at a closing delimiter without a final newline" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const raw = "Content-Type: multipart/mixed; boundary=outer\r\n\r\n" ++
        "--outer\r\nContent-Type: multipart/alternative; boundary=inner\r\n" ++
        "Content-Disposition: attachment; filename=source.mime\r\n\r\n";
    const attachment_body = "--inner\r\nContent-Type: text/plain\r\n\r\nHidden body\r\n--inner--\r\n";
    const message = raw ++ attachment_body ++ "\r\n--outer--";
    const full = try extract(arena.allocator(), message, .full);
    try std.testing.expectEqualStrings("", full.text);
    try std.testing.expectEqual(@as(usize, 1), full.attachments.len);
    try std.testing.expectEqualStrings("source.mime", full.attachments[0].filename);
    try std.testing.expectEqualStrings(attachment_body, full.attachments[0].data);
    const metadata = try extract(arena.allocator(), message, .metadata);
    try std.testing.expectEqual(attachment_body.len, metadata.attachments[0].size);
    try std.testing.expectEqualStrings("", metadata.attachments[0].data);
}
