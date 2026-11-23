//! MIME multipart parsing for the mail server, backed by zig-mime.
//!
//! zig-mime's `Walker` is the parser: the same streaming walker the scan
//! engine uses, so a message is split one way everywhere. It ends lines at LF
//! as well as CRLF, anchors delimiters to line starts and descends into nested
//! multiparts and embedded messages, which is what closes the bare-LF and
//! nesting evasions the old in-tree splitter had (mail-os/mail#23).
//!
//! The walker never allocates and its slices die at part_end (headers) or when
//! the event returns (bodies). `MultipartParser` is a thin adapter for callers
//! that want an owned array of parts instead. New code that scans messages
//! should implement a `lib.Sink` and stream the events rather than buffering
//! whole parts through this.

const std = @import("std");

/// zig-mime itself, for callers (and tests) that drive the walker directly.
pub const lib = @import("zig-mime");

/// A parsed Content-Type. Its slices point into the value it was parsed from
/// (for a `MimePart`, into that part's owned header block); it has no deinit.
pub const ContentType = lib.ContentType;
pub const Encoding = lib.Encoding;
pub const DiagnosticKind = lib.DiagnosticKind;
pub const validateBoundary = lib.validateBoundary;

/// One leaf part of a multipart message, with every slice owned by the part.
pub const MimePart = struct {
    allocator: std.mem.Allocator,
    /// The unfolded header block, one "name:value\n" line per field.
    header_block: []u8,
    /// Case-insensitive field lookup over `header_block`.
    headers: lib.Headers,
    /// Null when the part has no Content-Type field. An unparsable one gives
    /// the RFC 2045 default text/plain (and an `invalid_content_type`
    /// diagnostic) rather than failing the whole parse.
    content_type: ?ContentType,
    /// The body as it appears in the message, before transfer decoding.
    body: []u8,
    /// The transfer-decoded body; the same memory as `body` when the encoding
    /// is an identity one.
    decoded: []u8,
    encoding: Encoding,
    disposition: lib.Disposition.Kind,
    /// Content-Disposition filename, RFC 2231 and RFC 2047 decoded to UTF-8.
    filename: ?[]u8,
    /// Content-Type name parameter, decoded the same way.
    name: ?[]u8,
    /// Nesting depth: 1 for a direct child of the parsed multipart.
    depth: u8,
    /// The part belongs to the enclosing message's display body, outside
    /// attachment containers and attached messages.
    display_candidate: bool,
    /// What the transfer decoder tolerated.
    decode_flags: lib.decode.Flags,

    /// Zero-argument so a copied part (`var mp = p.*; mp.deinit()`) frees itself.
    pub fn deinit(self: *MimePart) void {
        const a = self.allocator;
        if (!self.encoding.isIdentity()) a.free(self.decoded);
        a.free(self.body);
        a.free(self.header_block);
        if (self.filename) |f| a.free(f);
        if (self.name) |n| a.free(n);
        self.* = undefined;
    }
};

pub const ParseError = error{
    BoundaryTooLong,
    InvalidBoundary,
    MimeDepthExceeded,
    TooManyParts,
    /// The header blocks and decoded parameters of the open parts outgrew the
    /// scratch buffer. Later parts would lose their headers (and with them
    /// their attachment status), so the parse fails instead.
    HeaderScratchExhausted,
    OutOfMemory,
};

/// Splits a multipart body into its leaf parts.
pub const MultipartParser = struct {
    allocator: std.mem.Allocator,
    /// Most nested multipart levels in one message, the parsed multipart
    /// included; more fails the parse. Each embedded message gets its own
    /// budget, as the old parser (which never opened them) effectively did,
    /// so a chain of forwarded mail is not refused. The walker's fixed
    /// nesting cap still bounds the total.
    max_depth: u8 = MAX_MIME_DEPTH,
    /// Most parts per message; more fails the parse.
    max_parts: u32 = 10_000,
    /// Malformations the last `parse` tolerated. They no longer fail the parse
    /// (except the depth, part and scratch limits), so a caller that must
    /// reject malformed mail checks this instead.
    diagnostics: std.EnumSet(DiagnosticKind) = .init(.{}),

    pub const MAX_MIME_DEPTH = 10;
    pub const MAX_BOUNDARY_LENGTH = lib.headers.max_rfc_boundary_len;

    pub fn init(allocator: std.mem.Allocator) MultipartParser {
        return .{ .allocator = allocator };
    }

    /// Parses `body` as the content of a multipart entity with `boundary`.
    /// Returns every leaf at every depth in document order; preamble,
    /// epilogue and container parts are not returned. A base64 or
    /// quoted-printable container (forbidden by RFC 2045, still shown by
    /// some clients) is returned as a leaf and its decoded content is walked
    /// too, so its parts follow it. Free with `freeParts`.
    pub fn parse(self: *MultipartParser, body: []const u8, boundary: []const u8) ParseError![]MimePart {
        // The old parser accepted an empty boundary and split on every "--".
        if (boundary.len == 0) return error.InvalidBoundary;
        try validateBoundary(boundary);
        self.diagnostics = .init(.{});

        // Always quoted: unquoted '(' and ')' are bchars but would start a comment.
        // 44 bytes of field around a boundary of at most 70.
        var header_buf: [44 + MAX_BOUNDARY_LENGTH]u8 = undefined;
        const header = std.fmt.bufPrint(&header_buf, "Content-Type: multipart/mixed; boundary=\"{s}\"\r\n", .{boundary}) catch unreachable;

        var shared: Shared = .{
            .allocator = self.allocator,
            .diagnostics = &self.diagnostics,
            .max_multipart_depth = self.max_depth,
            .max_parts = self.max_parts,
        };
        errdefer shared.deinit();
        try walkEntity(&shared, header, body, .{});
        return shared.parts.toOwnedSlice(self.allocator);
    }

    pub fn freeParts(self: *MultipartParser, parts: []MimePart) void {
        for (parts) |*part| part.deinit();
        self.allocator.free(parts);
    }
};

/// Upper bound on scratch for header blocks. Header bytes cannot exceed the
/// input, so small messages get a small buffer.
const max_scratch = 1024 * 1024;
/// Room for decoded parameters and the synthesized top-level header.
const scratch_slack = 64 * 1024;
const depth_slots = lib.walker.max_depth_cap + 1;

/// State one `parse` shares across the walks it makes (one per encoded container).
const Shared = struct {
    allocator: std.mem.Allocator,
    diagnostics: *std.EnumSet(DiagnosticKind),
    max_multipart_depth: u8,
    max_parts: u32,
    parts: std.ArrayList(MimePart) = .empty,
    /// Parts begun so far, counted the way the walker counts them.
    seen: u32 = 0,

    fn deinit(self: *Shared) void {
        for (self.parts.items) |*p| p.deinit();
        self.parts.deinit(self.allocator);
    }
};

/// Where a walk sits in the message: the absolute depth of its depth-0 part
/// and the nesting state of that part's parent.
const Origin = struct {
    depth: u8 = 0,
    multipart_levels: u8 = 0,
    in_message: bool = false,
    in_attachment: bool = false,
};

fn walkEntity(shared: *Shared, header: []const u8, input: []const u8, origin: Origin) ParseError!void {
    const a = shared.allocator;
    const scratch = try a.alloc(u8, @min(input.len, max_scratch) + scratch_slack + header.len);
    defer a.free(scratch);

    var collector: Collector = .{ .shared = shared, .origin = origin };
    defer collector.deinit();

    // On the heap: it is about 20 KiB and must not move once fed.
    const walker = try a.create(lib.Walker);
    defer a.destroy(walker);
    walker.* = lib.Walker.init(scratch, lib.Sink.init(&collector), .{
        // Multipart nesting is limited by the collector; the walker only keeps
        // the absolute depth inside its fixed stack.
        .max_depth = lib.walker.max_depth_cap - origin.depth,
        // A nested walk sees its container again as its first part.
        .max_parts = (shared.max_parts -| shared.seen) +| @intFromBool(origin.depth > 0),
        .raw_view = true,
    });

    walk(walker, header, input) catch return collector.err.?;
}

fn walk(walker: *lib.Walker, header: []const u8, input: []const u8) lib.Sink.Error!void {
    try walker.beginWithHeaders(header);
    try walker.feed(input);
    try walker.finish();
}

/// Collects walker events into owned `MimePart`s.
const Collector = struct {
    shared: *Shared,
    origin: Origin,
    current: ?Builder = null,
    err: ?ParseError = null,
    /// Per walk-relative depth, for the parts currently open.
    kinds: [depth_slots]lib.Kind = undefined,
    multipart_levels: [depth_slots]u8 = undefined,
    in_message: [depth_slots]bool = undefined,
    in_attachment: [depth_slots]bool = undefined,

    const Builder = struct {
        index: u32,
        rel_depth: u8,
        part: MimePart,
        /// The walker delivered a base64 or QP container as this leaf.
        encoded_container: bool = false,
        raw: std.ArrayList(u8) = .empty,
        decoded: std.ArrayList(u8) = .empty,

        fn deinit(self: *Builder, a: std.mem.Allocator) void {
            self.raw.deinit(a);
            self.decoded.deinit(a);
            a.free(self.part.header_block);
            if (self.part.filename) |f| a.free(f);
            if (self.part.name) |n| a.free(n);
        }
    };

    fn deinit(self: *Collector) void {
        if (self.current) |*c| c.deinit(self.shared.allocator);
    }

    pub fn onEvent(self: *Collector, event: lib.Event) lib.Sink.Error!void {
        self.handle(event) catch |e| {
            self.err = e;
            return error.Aborted;
        };
    }

    fn handle(self: *Collector, event: lib.Event) ParseError!void {
        switch (event) {
            .part_begin => |p| {
                if (!(self.origin.depth > 0 and p.depth == 0)) self.shared.seen += 1;
                try self.track(p);
                // Depth 0 is the multipart the caller named (or, in a nested
                // walk, the encoded container); only leaves are kept.
                if (p.kind == .leaf and p.depth >= 1) try self.begin(p);
            },
            .body => |b| if (self.current) |*c| {
                if (c.index != b.part.index or b.region != .content) return;
                // Identity parts get no raw events; their decoded bytes are the body.
                if (b.raw) try c.raw.appendSlice(self.shared.allocator, b.bytes) else try c.decoded.appendSlice(self.shared.allocator, b.bytes);
            },
            .part_end => |e| if (self.current) |*c| {
                if (c.index != e.part.index) return;
                c.part.decode_flags = e.decode_flags;
                try self.end(c);
            },
            .diagnostic => |d| {
                self.shared.diagnostics.insert(d.kind);
                switch (d.kind) {
                    // The adapter promises every part, which it cannot deliver
                    // past these limits, so they stay fail-closed.
                    .depth_exceeded => {
                        const p = d.part orelse return error.MimeDepthExceeded;
                        // Inside an embedded message (or for a message part
                        // itself) the old parser kept an opaque leaf too.
                        if (!self.in_message[p.depth] and !p.content_type.isEmbeddedMessage()) return error.MimeDepthExceeded;
                    },
                    .part_limit => return error.TooManyParts,
                    // How big the scratch buffer is says nothing about the
                    // message, so headers lost to it must not pass silently.
                    .scratch_exhausted => return error.HeaderScratchExhausted,
                    .encoded_container => if (self.current) |*c| {
                        if (d.part) |p| {
                            if (p.index == c.index) c.encoded_container = true;
                        }
                    },
                    else => {},
                }
            },
        }
    }

    /// Counts multipart levels the way the old parser did: each embedded
    /// message starts afresh, because the old parser never opened one.
    fn track(self: *Collector, p: *const lib.Part) ParseError!void {
        const d = p.depth;
        var levels: u8 = undefined;
        if (d == 0) {
            levels = self.origin.multipart_levels;
            self.in_message[0] = self.origin.in_message;
            self.in_attachment[0] = self.origin.in_attachment;
        } else {
            const parent_is_message = self.kinds[d - 1] == .message;
            levels = if (parent_is_message) 0 else self.multipart_levels[d - 1];
            self.in_message[d] = self.in_message[d - 1] or parent_is_message;
            self.in_attachment[d] = self.in_attachment[d - 1];
        }
        self.in_attachment[d] = self.in_attachment[d] or p.disposition == .attachment or p.filename != null or p.name != null;
        if (p.kind == .multipart) levels += 1;
        self.kinds[d] = p.kind;
        self.multipart_levels[d] = levels;
        if (levels > self.shared.max_multipart_depth) return error.MimeDepthExceeded;
    }

    fn begin(self: *Collector, p: *const lib.Part) ParseError!void {
        const a = self.shared.allocator;
        const block = try a.dupe(u8, p.headers.block);
        errdefer a.free(block);
        const filename = if (p.filename) |f| try a.dupe(u8, f) else null;
        errdefer if (filename) |f| a.free(f);
        const name = if (p.name) |n| try a.dupe(u8, n) else null;

        const headers: lib.Headers = .{ .block = block };
        self.current = .{
            .index = p.index,
            .rel_depth = p.depth,
            .part = .{
                .allocator = a,
                .header_block = block,
                .headers = headers,
                .content_type = if (headers.count("content-type") == 0) null else rebaseContentType(p.content_type, p.headers.block, block),
                .body = &.{},
                .decoded = &.{},
                .encoding = p.encoding,
                .disposition = p.disposition,
                .filename = filename,
                .name = name,
                .depth = self.origin.depth + p.depth,
                .display_candidate = !self.in_attachment[p.depth] and !self.in_message[p.depth] and !p.content_type.isEmbeddedMessage(),
                .decode_flags = .{},
            },
        };
    }

    fn end(self: *Collector, c: *Builder) ParseError!void {
        const a = self.shared.allocator;
        try self.shared.parts.ensureUnusedCapacity(a, 1);
        var part = c.part;
        if (part.encoding.isIdentity()) {
            part.body = try c.decoded.toOwnedSlice(a);
            part.decoded = part.body;
        } else {
            part.body = try c.raw.toOwnedSlice(a);
            part.decoded = c.decoded.toOwnedSlice(a) catch |e| {
                a.free(part.body);
                return e;
            };
        }
        c.raw.deinit(a);
        c.decoded.deinit(a);
        const encoded = c.encoded_container;
        const rel = c.rel_depth;
        self.current = null;
        self.shared.parts.appendAssumeCapacity(part);

        // Walk the decoded content so attachments inside an encoded container
        // are not hidden from callers. `part.decoded` is its own allocation, so
        // parts appended meanwhile cannot move it.
        if (encoded) try self.walkContainer(part, rel);
    }

    fn walkContainer(self: *Collector, part: MimePart, rel: u8) ParseError!void {
        const a = self.shared.allocator;
        // Only its Content-Type fields: the transfer encoding is already undone.
        var header: std.ArrayList(u8) = .empty;
        defer header.deinit(a);
        var it = part.headers.iterator();
        while (it.next()) |f| {
            if (!std.ascii.eqlIgnoreCase(f.name, "content-type")) continue;
            try header.print(a, "Content-Type: {s}\r\n", .{f.value});
        }
        try walkEntity(self.shared, header.items, part.decoded, .{
            .depth = part.depth,
            // The container counted as a leaf here; the nested walk adds its level.
            .multipart_levels = self.multipart_levels[rel],
            .in_message = self.in_message[rel],
            .in_attachment = self.in_attachment[rel],
        });
    }
};

/// Moves Content-Type slices that point into the walker's header block to the
/// same offsets in the owned copy. Static defaults (text/plain) stay as they are.
fn rebaseContentType(ct: ContentType, from: []const u8, to: []const u8) ContentType {
    return .{
        .media_type = rebase(ct.media_type, from, to),
        .media_subtype = rebase(ct.media_subtype, from, to),
        .params = rebase(ct.params, from, to),
        .boundary = if (ct.boundary) |b| rebase(b, from, to) else null,
        .charset = if (ct.charset) |s| rebase(s, from, to) else null,
    };
}

fn rebase(s: []const u8, from: []const u8, to: []const u8) []const u8 {
    const start = @intFromPtr(from.ptr);
    const at = @intFromPtr(s.ptr);
    if (at < start or at + s.len > start + from.len) return s;
    const off = at - start;
    return to[off..][0..s.len];
}

/// Transfer-decodes `raw` into a new buffer, as tolerantly as the walker does:
/// invalid input is skipped or kept, never an error.
pub fn decodeAlloc(allocator: std.mem.Allocator, encoding: Encoding, raw: []const u8) error{OutOfMemory}![]u8 {
    const Out = struct {
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        pub fn write(self: @This(), bytes: []const u8) error{OutOfMemory}!void {
            try self.list.appendSlice(self.allocator, bytes);
        }
    };
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    var decoder = lib.decode.Decoder.init(encoding);
    var buf: [4096]u8 = undefined;
    const out: Out = .{ .list = &list, .allocator = allocator };
    try decoder.feed(raw, &buf, out);
    try decoder.finish(&buf, out);
    return list.toOwnedSlice(allocator);
}

const testing = std.testing;

test "parse content type" {
    const ct = try ContentType.parse("multipart/mixed; boundary=\"----=_Part_123\"; charset=utf-8");

    try testing.expectEqualStrings("multipart", ct.media_type);
    try testing.expectEqualStrings("mixed", ct.media_subtype);
    try testing.expectEqualStrings("----=_Part_123", ct.boundary.?);
    try testing.expectEqualStrings("utf-8", ct.charset.?);
    try testing.expect(ct.isMultipart());
}

test "parse simple multipart message" {
    var parser = MultipartParser.init(testing.allocator);

    // The multiline literal ends its lines in bare LF, which the old CRLF-only
    // splitter parsed into zero parts.
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

    try testing.expectEqualStrings("Hello, World!", parts[0].body);
    try testing.expect(parts[0].content_type != null);
    try testing.expectEqualStrings("text", parts[0].content_type.?.media_type);
    try testing.expectEqualStrings("plain", parts[0].content_type.?.media_subtype);

    try testing.expectEqualStrings("<html><body>Hello, World!</body></html>", parts[1].body);
    try testing.expect(parts[1].content_type != null);
    try testing.expectEqualStrings("text", parts[1].content_type.?.media_type);
    try testing.expectEqualStrings("html", parts[1].content_type.?.media_subtype);
}

test "reject boundary longer than 70 characters" {
    var parser = MultipartParser.init(testing.allocator);

    const long_boundary = @as([71]u8, @splat('a'));
    const message = "--" ++ long_boundary ++ "\r\ntest\r\n--" ++ long_boundary ++ "--";

    try testing.expectError(error.BoundaryTooLong, parser.parse(message, &long_boundary));
}

test "reject invalid boundary characters" {
    var parser = MultipartParser.init(testing.allocator);

    const message = "--test boundary\r\ntest\r\n--test boundary--";
    try testing.expectError(error.InvalidBoundary, parser.parse(message, "test boundary"));
}

test "reject MIME depth exceeding 10 levels" {
    var parser = MultipartParser.init(testing.allocator);
    // No multipart level may open at all.
    parser.max_depth = 0;

    const message =
        \\--boundary
        \\Content-Type: text/plain
        \\
        \\test
        \\--boundary--
    ;

    try testing.expectError(error.MimeDepthExceeded, parser.parse(message, "boundary"));
}

const bare_lf_attachment = "--b\nContent-Type: text/plain\n\nhello\n--b\n" ++
    "Content-Type: application/octet-stream; name=\"payload.exe\"\n" ++
    "Content-Transfer-Encoding: base64\n" ++
    "Content-Disposition: attachment; filename=\"payload.exe\"\n\n" ++
    "TVqQAAMAAAAEAAAA\n--b--\n";

test "a bare-LF base64 attachment is decoded and named" {
    var parser = MultipartParser.init(testing.allocator);
    const parts = try parser.parse(bare_lf_attachment, "b");
    defer parser.freeParts(parts);

    try testing.expectEqual(@as(usize, 2), parts.len);
    const att = parts[1];
    try testing.expectEqualSlices(u8, &.{ 0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00 }, att.decoded);
    try testing.expectEqualStrings("TVqQAAMAAAAEAAAA", att.body);
    try testing.expectEqualStrings("payload.exe", att.filename.?);
    try testing.expectEqualStrings("payload.exe", att.name.?);
    try testing.expectEqual(Encoding.base64, att.encoding);
    try testing.expectEqual(lib.Disposition.Kind.attachment, att.disposition);
    try testing.expectEqual(@as(u8, 1), att.depth);
}

test "a missing close delimiter is tolerated and reported" {
    var parser = MultipartParser.init(testing.allocator);
    const parts = try parser.parse("--b\r\n\r\nx", "b");
    defer parser.freeParts(parts);

    try testing.expectEqual(@as(usize, 1), parts.len);
    try testing.expectEqualStrings("x", parts[0].body);
    try testing.expect(parser.diagnostics.contains(.missing_close_delimiter));
}

test "a nested boundary outside RFC 2046 still splits" {
    var parser = MultipartParser.init(testing.allocator);
    const message = "--o\r\nContent-Type: multipart/mixed; boundary=\"a b\"\r\n\r\n" ++
        "--a b\r\nContent-Type: text/plain\r\n\r\none\r\n" ++
        "--a b\r\nContent-Type: text/plain\r\n\r\ntwo\r\n--a b--\r\n--o--\r\n";
    const parts = try parser.parse(message, "o");
    defer parser.freeParts(parts);

    try testing.expectEqual(@as(usize, 2), parts.len);
    try testing.expectEqualStrings("one", parts[0].body);
    try testing.expectEqualStrings("two", parts[1].body);
    try testing.expectEqual(@as(u8, 2), parts[1].depth);
    try testing.expect(parser.diagnostics.contains(.boundary_invalid));
}

test "an RFC 2231 filename is decoded to UTF-8" {
    var parser = MultipartParser.init(testing.allocator);
    const message = "--b\r\nContent-Type: text/plain\r\n" ++
        "Content-Disposition: attachment; filename*=UTF-8''%E2%82%AC.txt\r\n\r\nx\r\n--b--\r\n";
    const parts = try parser.parse(message, "b");
    defer parser.freeParts(parts);

    try testing.expectEqualStrings("\xE2\x82\xAC.txt", parts[0].filename.?);
}

test "copied parts free themselves without leaks or double frees" {
    var parser = MultipartParser.init(testing.allocator);

    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(testing.allocator);
    for (0..200) |i| {
        if (i % 2 == 0) {
            try message.print(testing.allocator, "--b\r\nContent-Type: text/plain\r\n\r\ntext {d}\r\n", .{i});
        } else {
            try message.print(testing.allocator, "--b\r\nContent-Type: application/octet-stream; name=\"f{d}.bin\"\r\n" ++
                "Content-Transfer-Encoding: base64\r\n\r\nSGVsbG8=\r\n", .{i});
        }
    }
    try message.appendSlice(testing.allocator, "--b--\r\n");

    const parts = try parser.parse(message.items, "b");
    try testing.expectEqual(@as(usize, 200), parts.len);
    try testing.expect(parts[0].decoded.ptr == parts[0].body.ptr);
    try testing.expectEqualStrings("Hello", parts[1].decoded);
    // The cleanup shape tests/security_hardening_test.zig uses.
    for (parts) |*p| {
        var mp = p.*;
        mp.deinit();
    }
    testing.allocator.free(parts);
}

/// A chain of `forwards` messages, each multipart/mixed [text/plain,
/// message/rfc822] around the next; the innermost text says "leaf {forwards}".
fn forwardChain(a: std.mem.Allocator, forwards: usize) ![]u8 {
    var inner: std.ArrayList(u8) = .empty;
    errdefer inner.deinit(a);
    try inner.print(a, "--b{d}z\r\nContent-Type: text/plain\r\n\r\nleaf {d}\r\n--b{d}z--\r\n", .{ forwards, forwards, forwards });
    var level = forwards;
    while (level > 0) {
        level -= 1;
        var outer: std.ArrayList(u8) = .empty;
        errdefer outer.deinit(a);
        try outer.print(a, "--b{d}z\r\nContent-Type: text/plain\r\n\r\nnote\r\n--b{d}z\r\nContent-Type: message/rfc822\r\n\r\n" ++
            "Subject: fwd\r\nContent-Type: multipart/mixed; boundary=\"b{d}z\"\r\n\r\n{s}\r\n--b{d}z--\r\n", .{ level, level, level + 1, inner.items, level });
        inner.deinit(a);
        inner = outer;
    }
    return inner.toOwnedSlice(a);
}

test "a chain of forwarded messages does not count against the multipart limit" {
    const message = try forwardChain(testing.allocator, 12);
    defer testing.allocator.free(message);

    var parser = MultipartParser.init(testing.allocator);
    const parts = try parser.parse(message, "b0z");
    defer parser.freeParts(parts);

    // Twelve forwards nest 13 multiparts, past the limit of 10 had they
    // counted together; each message gets its own budget instead.
    try testing.expectEqualStrings("note", parts[0].body);
    try testing.expectEqualStrings("leaf 12", parts[parts.len - 1].body);
    try testing.expect(!parser.diagnostics.contains(.depth_exceeded));
}

test "a forward chain past the walker's nesting cap ends in an opaque leaf" {
    const message = try forwardChain(testing.allocator, 20);
    defer testing.allocator.free(message);

    var parser = MultipartParser.init(testing.allocator);
    const parts = try parser.parse(message, "b0z");
    defer parser.freeParts(parts);

    try testing.expect(parser.diagnostics.contains(.depth_exceeded));
    try testing.expectEqualStrings("note", parts[0].body);
    for (parts) |p| try testing.expect(!std.mem.eql(u8, p.body, "leaf 20"));
}

test "nested multiparts inside one embedded message still hit the limit" {
    // An embedded message holding 11 nested multiparts.
    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(testing.allocator);
    try message.appendSlice(testing.allocator, "--o\r\nContent-Type: message/rfc822\r\n\r\n");
    for (0..11) |i| try message.print(testing.allocator, "Content-Type: multipart/mixed; boundary=\"n{d}\"\r\n\r\n--n{d}\r\n", .{ i, i });
    try message.appendSlice(testing.allocator, "Content-Type: text/plain\r\n\r\ndeep\r\n--o--\r\n");

    var parser = MultipartParser.init(testing.allocator);
    try testing.expectError(error.MimeDepthExceeded, parser.parse(message.items, "o"));
}

test "headers lost to an exhausted scratch buffer fail the parse" {
    // A filename_alt of windows-1252 encoded words expands about 2.25 times
    // when decoded and is not held to the parameter cap, so a 50 KB message
    // can fill the scratch and leave the next part's headers unstored.
    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(testing.allocator);
    try message.appendSlice(testing.allocator, "--o\r\nContent-Type: multipart/mixed; boundary=\"i\"\r\n" ++
        "Content-Disposition: inline; filename=\"a\"; filename=\"");
    for (0..120) |_| {
        try message.appendSlice(testing.allocator, "=?windows-1252?B?");
        for (0..100) |_| try message.appendSlice(testing.allocator, "gICA");
        try message.appendSlice(testing.allocator, "?=");
    }
    try message.appendSlice(testing.allocator, "\"\r\n\r\n--i\r\n" ++
        "Content-Type: application/octet-stream; name=\"evil.exe\"\r\n" ++
        "Content-Transfer-Encoding: base64\r\n" ++
        "Content-Disposition: attachment; filename=\"evil.exe\"\r\n\r\nTVqQ\r\n--i--\r\n--o--\r\n");

    var parser = MultipartParser.init(testing.allocator);
    try testing.expectError(error.HeaderScratchExhausted, parser.parse(message.items, "o"));
    try testing.expect(parser.diagnostics.contains(.scratch_exhausted));
}

const evil_multipart = "--i\r\nContent-Type: application/octet-stream\r\n" ++
    "Content-Disposition: attachment; filename=\"evil.exe\"\r\n" ++
    "Content-Transfer-Encoding: base64\r\n\r\nTVqQ\r\n--i--\r\n";

fn base64Alloc(a: std.mem.Allocator, raw: []const u8) ![]u8 {
    const enc = std.base64.standard.Encoder;
    const out = try a.alloc(u8, enc.calcSize(raw.len));
    _ = enc.encode(out, raw);
    return out;
}

test "parts inside a base64-encoded multipart are walked" {
    const inner = try base64Alloc(testing.allocator, evil_multipart);
    defer testing.allocator.free(inner);
    const message = try std.mem.concat(testing.allocator, u8, &.{
        "--o\r\nContent-Type: multipart/mixed; boundary=\"i\"\r\nContent-Transfer-Encoding: base64\r\n\r\n",
        inner,
        "\r\n--o--\r\n",
    });
    defer testing.allocator.free(message);

    var parser = MultipartParser.init(testing.allocator);
    const parts = try parser.parse(message, "o");
    defer parser.freeParts(parts);

    try testing.expect(parser.diagnostics.contains(.encoded_container));
    // The container leaf first, then what it holds.
    try testing.expectEqual(@as(usize, 2), parts.len);
    try testing.expect(parts[0].content_type.?.isMultipart());
    const att = parts[1];
    try testing.expectEqualStrings("evil.exe", att.filename.?);
    try testing.expectEqual(lib.Disposition.Kind.attachment, att.disposition);
    try testing.expectEqual(@as(u8, 2), att.depth);
    try testing.expectEqualSlices(u8, &.{ 0x4d, 0x5a, 0x90 }, att.decoded);
}

test "parts inside a quoted-printable message/rfc822 are walked" {
    // "=3D" keeps the walker's view of the inner boundary parameter intact
    // only once decoded.
    const message = "--o\r\nContent-Type: message/rfc822\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" ++
        "Subject: inner\r\nContent-Type: multipart/mixed; boundary=3D\"i\"\r\n\r\n" ++ evil_multipart ++ "--o--\r\n";

    var parser = MultipartParser.init(testing.allocator);
    const parts = try parser.parse(message, "o");
    defer parser.freeParts(parts);

    try testing.expect(parser.diagnostics.contains(.encoded_container));
    var found = false;
    for (parts) |p| {
        if (p.filename) |f| if (std.mem.eql(u8, f, "evil.exe")) {
            found = true;
            try testing.expectEqual(@as(u8, 3), p.depth);
        };
    }
    try testing.expect(found);
}

test "encoded containers nested in each other are all walked" {
    const level2 = try base64Alloc(testing.allocator, evil_multipart);
    defer testing.allocator.free(level2);
    const level1_raw = try std.mem.concat(testing.allocator, u8, &.{
        "--m\r\nContent-Type: multipart/mixed; boundary=\"i\"\r\nContent-Transfer-Encoding: base64\r\n\r\n",
        level2,
        "\r\n--m--\r\n",
    });
    defer testing.allocator.free(level1_raw);
    const level1 = try base64Alloc(testing.allocator, level1_raw);
    defer testing.allocator.free(level1);
    const message = try std.mem.concat(testing.allocator, u8, &.{
        "--o\r\nContent-Type: multipart/mixed; boundary=\"m\"\r\nContent-Transfer-Encoding: base64\r\n\r\n",
        level1,
        "\r\n--o--\r\n",
    });
    defer testing.allocator.free(message);

    var parser = MultipartParser.init(testing.allocator);
    const parts = try parser.parse(message, "o");
    defer parser.freeParts(parts);

    try testing.expectEqual(@as(usize, 3), parts.len);
    try testing.expectEqualStrings("evil.exe", parts[2].filename.?);
    try testing.expectEqual(@as(u8, 3), parts[2].depth);
}

test "an encoded container still counts toward the multipart limit" {
    const inner = try base64Alloc(testing.allocator, evil_multipart);
    defer testing.allocator.free(inner);
    const message = try std.mem.concat(testing.allocator, u8, &.{
        "--o\r\nContent-Type: multipart/mixed; boundary=\"i\"\r\nContent-Transfer-Encoding: base64\r\n\r\n",
        inner,
        "\r\n--o--\r\n",
    });
    defer testing.allocator.free(message);

    var parser = MultipartParser.init(testing.allocator);
    parser.max_depth = 1;
    try testing.expectError(error.MimeDepthExceeded, parser.parse(message, "o"));
    parser.max_depth = 2;
    const parts = try parser.parse(message, "o");
    parser.freeParts(parts);
}

/// Records the header fields of the top-level entity and the first boundary seen.
const HeaderProbe = struct {
    from: ?[]const u8 = null,
    fields: usize = 0,
    boundary: ?[]const u8 = null,
    buf: [128]u8 = undefined,

    pub fn onEvent(self: *HeaderProbe, event: lib.Event) lib.Sink.Error!void {
        switch (event) {
            .part_begin => |p| if (p.depth == 0) {
                var it = p.headers.iterator();
                while (it.next()) |_| self.fields += 1;
                // Header slices die at part_end, so keep copies.
                if (p.headers.get("from")) |f| {
                    @memcpy(self.buf[0..f.len], f);
                    self.from = self.buf[0..f.len];
                }
                if (p.boundary) |b| {
                    @memcpy(self.buf[64..][0..b.len], b);
                    self.boundary = self.buf[64..][0..b.len];
                }
            },
            else => {},
        }
    }
};

/// Takes the probe by pointer: its slices point into its own buffer.
fn probe(result: *HeaderProbe, message: []const u8) !void {
    var scratch: [4096]u8 = undefined;
    var walker = lib.Walker.init(&scratch, lib.Sink.init(result), .{});
    try walker.feed(message);
    try walker.finish();
}

// Ported from the deleted streaming_parser.zig.
test "walker reads top-level headers" {
    const message =
        \\From: sender@example.com
        \\To: recipient@example.com
        \\Subject: Test
        \\
        \\Body content
    ;
    var result: HeaderProbe = .{};
    try probe(&result, message);
    try testing.expectEqualStrings("sender@example.com", result.from.?);
    try testing.expectEqual(@as(usize, 3), result.fields);
}

// Ported from the deleted streaming_parser.zig.
test "walker detects the multipart boundary" {
    const message =
        \\Content-Type: multipart/mixed; boundary="----Boundary123"
        \\
        \\------Boundary123
        \\Content-Type: text/plain
        \\
        \\Part 1
        \\------Boundary123--
    ;
    var result: HeaderProbe = .{};
    try probe(&result, message);
    try testing.expectEqualStrings("----Boundary123", result.boundary.?);
}

test "decodeAlloc decodes both transfer encodings" {
    const b64 = try decodeAlloc(testing.allocator, .base64, "SGVs\r\nbG8s\r\nIFdv\r\ncmxk\r\nIQ==");
    defer testing.allocator.free(b64);
    try testing.expectEqualStrings("Hello, World!", b64);

    const qp = try decodeAlloc(testing.allocator, .quoted_printable, "Hello=2C World=21");
    defer testing.allocator.free(qp);
    try testing.expectEqualStrings("Hello, World!", qp);

    const plain = try decodeAlloc(testing.allocator, .seven_bit, "as is");
    defer testing.allocator.free(plain);
    try testing.expectEqualStrings("as is", plain);
}
