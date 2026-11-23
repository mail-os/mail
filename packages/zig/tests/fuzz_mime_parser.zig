//! Randomized tests against the mail server's MIME parser: the
//! `mail.mime` adapter and the zig-mime walker behind it.
//!
//! This file used to be a libFuzzer harness that re-implemented its own
//! string scanning and never called a parser. Every test below does. Seeds
//! are fixed, so a failure reproduces. Long fuzzing runs live upstream in
//! zig-utils/zig-mime (`zig build fuzz -Dfuzz-iterations=...`).

const std = @import("std");
const testing = std.testing;
const mail = @import("mail");
const repeat = @import("test_util.zig").repeat;
const mime = mail.mime;
const lib = mail.mime.lib;

const iterations = 300;

/// The old harness's corpus, each message in a CRLF and a bare-LF form, plus
/// its test inputs.
const seeds = blk: {
    const examples = [_][]const u8{
        "Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 7bit\n\nHello, World!",
        "Content-Type: multipart/mixed; boundary=\"boundary123\"\n\n--boundary123\nContent-Type: text/plain\n\nPart 1\n" ++
            "--boundary123\nContent-Type: text/html\n\n<p>Part 2</p>\n--boundary123--",
        "Content-Transfer-Encoding: base64\n\nSGVsbG8sIFdvcmxkIQ==",
        "Content-Transfer-Encoding: quoted-printable\n\nHello=20World=21",
        "Content-Type: multipart/mixed; boundary=\"\"",
        "Content-Type: multipart/mixed; boundary=\"012345678901234567890123456789012345678901234567890123456789012345678901234567890\"",
        "Content-Transfer-Encoding: base64\n\nInvalid base64!!!",
        "Content-Type: multipart/mixed; boundary=\"outer\"\n\n--outer\nContent-Type: multipart/alternative; boundary=\"inner\"\n\n" ++
            "--inner\nContent-Type: text/plain\n\nText\n--inner--\n--outer--",
    };
    const extra = [_][]const u8{
        "Content-Type:",
        ":value",
        "\x00\xFF",
        "boundary=",
        "boundary=\"",
        "boundary=\"" ++ repeat("x", 100) ++ "\"",
        "!!!!",
        "SGVsbG8=",
        "--b\r\n\r\nx",
        "--b\nContent-Type: multipart/mixed; boundary=b\n\n--b\n--b--\n--b--",
        // Encoded containers, which the adapter walks a second time.
        "--b\nContent-Type: multipart/mixed; boundary=i\nContent-Transfer-Encoding: base64\n\n" ++
            "LS1pDQpDb250ZW50LVR5cGU6IHRleHQvcGxhaW4NCg0KaGkNCi0taS0tDQo=\n--b--\n",
        "--b\nContent-Type: message/rfc822\nContent-Transfer-Encoding: quoted-printable\n\n" ++
            "Content-Type: multipart/mixed; boundary=3Di\n\n--i\n\nx\n--i--\n--b--\n",
        "--b\nContent-Type: message/rfc822\n\nContent-Type: multipart/mixed; boundary=c\n\n" ++
            "--c\nContent-Type: message/rfc822\n\nSubject: x\n\nbody\n--c--\n--b--\n",
    };
    var out: [examples.len * 2 + extra.len][]const u8 = undefined;
    for (examples, 0..) |e, i| {
        out[2 * i] = e;
        out[2 * i + 1] = crlf(e);
    }
    for (extra, 0..) |e, i| out[examples.len * 2 + i] = e;
    const final = out;
    break :blk final;
};

fn crlf(comptime s: []const u8) []const u8 {
    comptime {
        @setEvalBranchQuota(100_000);
        var out: []const u8 = "";
        for (s) |c| out = out ++ (if (c == '\n') "\r\n" else &[_]u8{c});
        return out;
    }
}

/// Random bytes built mostly from MIME framing: line breaks, dashes, the
/// boundary "b" and header fragments, so delimiters and header ends collide.
fn framingNoise(allocator: std.mem.Allocator, random: std.Random, len: usize) ![]u8 {
    const pieces = [_][]const u8{
        "\r",   "\n",      "-",     "b",     ":",                                             ";",                              "=",                                     "\"",                                            "\t",                                                      " ",    "(",
        "\r\n", "--b\r\n", "--b\n", "--b--", "Content-Type: multipart/mixed; boundary=b\r\n", "Content-Type: message/rfc822\n", "Content-Transfer-Encoding: base64\r\n", "Content-Transfer-Encoding: quoted-printable\n", "Content-Disposition: attachment; filename=\"a.exe\"\r\n", "TVqQ", "=3D",
        "\x00", "\xff",
    };
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    while (out.items.len < len) {
        try out.appendSlice(allocator, pieces[random.uintLessThan(usize, pieces.len)]);
    }
    return out.toOwnedSlice(allocator);
}

/// `input` with a few random byte flips, inserts and deletes.
fn mutate(allocator: std.mem.Allocator, random: std.Random, input: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, input);
    for (0..random.intRangeAtMost(usize, 1, 8)) |_| {
        const at = random.uintAtMost(usize, out.items.len);
        switch (random.uintLessThan(u8, 3)) {
            0 => if (at < out.items.len) {
                out.items[at] = random.int(u8);
            },
            1 => try out.insert(allocator, at, "\r\n-b:"[random.uintLessThan(usize, 5)]),
            else => if (at < out.items.len) {
                _ = out.orderedRemove(at);
            },
        }
    }
    return out.toOwnedSlice(allocator);
}

fn parseAny(allocator: std.mem.Allocator, random: std.Random, data: []const u8) !void {
    var parser = mime.MultipartParser.init(allocator);
    parser.max_depth = random.uintAtMost(u8, 10);
    if (random.uintLessThan(u8, 4) == 0) parser.max_parts = random.intRangeAtMost(u32, 1, 20);
    const parts = parser.parse(data, "b") catch |err| switch (err) {
        error.MimeDepthExceeded, error.TooManyParts, error.HeaderScratchExhausted => return,
        else => return err,
    };
    defer parser.freeParts(parts);
    for (parts) |p| {
        // Touch every owned slice so a dangling one trips the safety checks.
        try testing.expect(p.depth >= 1);
        if (p.content_type) |ct| _ = ct.isMultipart();
        _ = std.mem.count(u8, p.body, "\n") + std.mem.count(u8, p.decoded, "\n");
        if (p.filename) |f| _ = f.len;
    }
}

test "Fuzz: MIME parse takes any bytes" {
    var prng = std.Random.DefaultPrng.init(0x313e_5eed);
    const random = prng.random();

    for (seeds) |s| try parseAny(testing.allocator, random, s);

    for (0..iterations) |_| {
        const data = if (random.boolean()) blk: {
            break :blk try framingNoise(testing.allocator, random, random.intRangeAtMost(usize, 1, 2048));
        } else try mutate(testing.allocator, random, seeds[random.uintLessThan(usize, seeds.len)]);
        defer testing.allocator.free(data);
        try parseAny(testing.allocator, random, data);
    }
}

test "Fuzz: MIME parse frees everything when allocation fails" {
    var prng = std.Random.DefaultPrng.init(0x00b_5eed);
    const random = prng.random();

    for (0..iterations) |_| {
        const data = try framingNoise(testing.allocator, random, random.intRangeAtMost(usize, 1, 1024));
        defer testing.allocator.free(data);
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = random.uintAtMost(usize, 40) });
        parseAny(failing.allocator(), random, data) catch |err| switch (err) {
            error.OutOfMemory => {},
            else => return err,
        };
    }
}

/// Generates well-formed nested messages, after zig-mime's differential tests.
const Gen = struct {
    r: std.Random,
    gpa: std.mem.Allocator,
    out: std.ArrayList(u8) = .empty,

    fn put(self: *Gen, s: []const u8) !void {
        try self.out.appendSlice(self.gpa, s);
    }

    fn boundary(self: *Gen, buf: []u8) []const u8 {
        const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'()+_,-./:=?";
        const n = self.r.intRangeAtMost(usize, 8, @min(buf.len, 70));
        for (buf[0..n]) |*c| c.* = chars[self.r.uintLessThan(usize, chars.len)];
        buf[0] = 'Z'; // a delimiter line never starts with a text word
        return buf[0..n];
    }

    fn multipart(self: *Gen, b: []const u8, depth: usize) !void {
        const r = self.r;
        if (r.boolean()) try self.put("This is a multi-part message in MIME format.\r\n");
        for (0..r.intRangeAtMost(usize, 1, 5)) |i| {
            try self.put("--");
            try self.put(b);
            try self.put("\r\n");
            switch (r.uintLessThan(u8, if (depth == 0) 4 else 3)) {
                0 => {
                    try self.put("Content-Type: text/plain; charset=utf-8\r\n\r\n");
                    try self.text();
                },
                1 => {
                    try self.put("Content-Type: text/html; charset=\"iso-8859-1\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n");
                    try self.text();
                },
                2 => {
                    try self.put("Content-Type: application/octet-stream; name=\"f.bin\"\r\nContent-Transfer-Encoding: base64\r\n");
                    try self.out.print(self.gpa, "Content-Disposition: attachment; filename=\"f{d}-{d}.bin\"\r\n\r\n", .{ depth, i });
                    var raw: [300]u8 = undefined;
                    const n = r.intRangeAtMost(usize, 1, raw.len);
                    r.bytes(raw[0..n]);
                    var enc: [400]u8 = undefined;
                    const e = std.base64.standard.Encoder.encode(&enc, raw[0..n]);
                    var at: usize = 0;
                    while (at < e.len) : (at += 76) {
                        if (at > 0) try self.put("\r\n");
                        try self.put(e[at..@min(at + 76, e.len)]);
                    }
                },
                else => {
                    var buf: [70]u8 = undefined;
                    const inner = self.boundary(&buf);
                    try self.put("Content-Type: multipart/alternative; boundary=\"");
                    try self.put(inner);
                    try self.put("\"\r\n\r\n");
                    try self.multipart(inner, depth + 1);
                },
            }
            try self.put("\r\n");
        }
        try self.put("--");
        try self.put(b);
        try self.put("--");
        if (r.boolean()) try self.put("\r\n");
    }

    fn text(self: *Gen) !void {
        const words = [_][]const u8{ "hello", "world", "caf=C3=A9", "-", "lorem", "ipsum", "=", "dolor" };
        for (0..self.r.intRangeAtMost(usize, 1, 6)) |l| {
            if (l > 0) try self.put("\r\n");
            for (0..self.r.intRangeAtMost(usize, 1, 9)) |w| {
                if (w > 0) try self.put(" ");
                try self.put(words[self.r.uintLessThan(usize, words.len)]);
            }
        }
    }
};

/// Walks `message` into a transcript, feeding it in pieces of `max_piece`
/// bytes or fewer (random lengths when `random` is given).
fn transcript(allocator: std.mem.Allocator, message: []const u8, max_piece: usize, random: ?std.Random) ![]u8 {
    var t = lib.Transcript.init(allocator);
    defer t.deinit();
    const scratch = try allocator.alloc(u8, 64 * 1024);
    defer allocator.free(scratch);
    // On the heap and never moved once fed: events point into the walker.
    const walker = try allocator.create(lib.Walker);
    defer allocator.destroy(walker);
    walker.* = lib.Walker.init(scratch, t.sink(), .{ .raw_view = true });

    var pos: usize = 0;
    while (pos < message.len) {
        const left = message.len - pos;
        const n = if (random) |r| r.intRangeAtMost(usize, 1, @min(left, max_piece)) else @min(left, max_piece);
        try walker.feed(message[pos..][0..n]);
        pos += n;
    }
    try walker.finish();
    try testing.expect(walker.scratch_peak <= scratch.len);
    return allocator.dupe(u8, t.text());
}

test "Fuzz: the MIME walk does not depend on how the stream is split" {
    var prng = std.Random.DefaultPrng.init(0x5917_5eed);
    const random = prng.random();

    for (0..iterations + seeds.len) |case| {
        var gen: Gen = .{ .r = random, .gpa = testing.allocator };
        defer gen.out.deinit(testing.allocator);
        if (case < seeds.len) {
            try gen.put(seeds[case]);
        } else {
            var buf: [70]u8 = undefined;
            const b = gen.boundary(&buf);
            try gen.put("From: a@example.com\r\nContent-Type: multipart/mixed; boundary=\"");
            try gen.put(b);
            try gen.put("\"\r\n\r\n");
            try gen.multipart(b, 0);
        }
        const message = if (random.boolean())
            try mutate(testing.allocator, random, gen.out.items)
        else
            try testing.allocator.dupe(u8, gen.out.items);
        defer testing.allocator.free(message);

        const whole = try transcript(testing.allocator, message, message.len, null);
        defer testing.allocator.free(whole);
        const chunked = try transcript(testing.allocator, message, 64, random);
        defer testing.allocator.free(chunked);
        const bytewise = try transcript(testing.allocator, message, 1, null);
        defer testing.allocator.free(bytewise);

        try testing.expectEqualStrings(whole, chunked);
        try testing.expectEqualStrings(whole, bytewise);
    }
}

fn toBareLf(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, s.len);
    var w: usize = 0;
    for (s, 0..) |c, i| {
        if (c == '\r' and i + 1 < s.len and s[i + 1] == '\n') continue;
        out[w] = c;
        w += 1;
    }
    return allocator.realloc(out, w);
}

// The property mail-os/mail#23 is about: a scanner must see the same
// attachments whichever line ending the sender chose.
test "Fuzz: bare LF and CRLF framing yield the same attachments" {
    var prng = std.Random.DefaultPrng.init(0x1f_c41f);
    const random = prng.random();

    for (0..iterations) |_| {
        var gen: Gen = .{ .r = random, .gpa = testing.allocator };
        defer gen.out.deinit(testing.allocator);
        var buf: [70]u8 = undefined;
        const b = gen.boundary(&buf);
        try gen.multipart(b, 0);
        const lf = try toBareLf(testing.allocator, gen.out.items);
        defer testing.allocator.free(lf);

        var parser = mime.MultipartParser.init(testing.allocator);
        const want = try parser.parse(gen.out.items, b);
        defer parser.freeParts(want);
        const got = try parser.parse(lf, b);
        defer parser.freeParts(got);

        try testing.expect(want.len > 0);
        try testing.expectEqual(want.len, got.len);
        for (want, got) |w, g| {
            try testing.expectEqualStrings(w.content_type.?.media_type, g.content_type.?.media_type);
            try testing.expectEqualStrings(w.content_type.?.media_subtype, g.content_type.?.media_subtype);
            try testing.expectEqual(w.encoding, g.encoding);
            try testing.expectEqual(w.disposition, g.disposition);
            try testing.expectEqual(w.depth, g.depth);
            try testing.expectEqual(w.filename == null, g.filename == null);
            if (w.filename) |f| try testing.expectEqualStrings(f, g.filename.?);
            // base64 ignores line breaks, so the decoded bytes must match.
            if (w.encoding == .base64) try testing.expectEqualSlices(u8, w.decoded, g.decoded);
        }
    }
}

fn decodeSplit(comptime D: type, input: []const u8, splits: []const usize, out: []u8) !struct { len: usize, flags: lib.decode.Flags } {
    var d: D = .{};
    var w: usize = 0;
    var pos: usize = 0;
    for (splits) |end| {
        w += d.decode(input[pos..end], out[w..]);
        pos = end;
    }
    w += d.decode(input[pos..], out[w..]);
    w += d.finish(out[w..]);
    return .{ .len = w, .flags = d.flags };
}

fn checkDecoder(comptime D: type, allocator: std.mem.Allocator, random: std.Random, input: []const u8) !void {
    // Each call may round its own output bound up; leave room for every split.
    const cap = D.maxOutput(input.len) + 512;
    const whole_out = try allocator.alloc(u8, cap);
    defer allocator.free(whole_out);
    const split_out = try allocator.alloc(u8, cap);
    defer allocator.free(split_out);

    var splits: [8]usize = undefined;
    const n = random.uintAtMost(usize, splits.len);
    for (splits[0..n]) |*s| s.* = random.uintAtMost(usize, input.len);
    std.mem.sort(usize, splits[0..n], {}, std.sort.asc(usize));

    const whole = try decodeSplit(D, input, &.{}, whole_out);
    const split = try decodeSplit(D, input, splits[0..n], split_out);
    try testing.expectEqualSlices(u8, whole_out[0..whole.len], split_out[0..split.len]);
    try testing.expectEqual(whole.flags, split.flags);
}

test "Fuzz: transfer decoders do not depend on chunking" {
    var prng = std.Random.DefaultPrng.init(0xdec0_5eed);
    const random = prng.random();
    const b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const junk = "=\r\n \t!*\x00\xff";

    for (0..iterations) |_| {
        var raw: [256]u8 = undefined;
        const len = random.uintAtMost(usize, raw.len);
        random.bytes(raw[0..len]);

        // base64: a valid encoding, sometimes sprinkled with junk and line breaks.
        var enc: [400]u8 = undefined;
        var input: std.ArrayList(u8) = .empty;
        defer input.deinit(testing.allocator);
        try input.appendSlice(testing.allocator, std.base64.standard.Encoder.encode(&enc, raw[0..len]));
        if (random.boolean()) {
            for (0..random.uintAtMost(usize, 12)) |_| {
                const at = random.uintAtMost(usize, input.items.len);
                const set = if (random.boolean()) junk else b64_alphabet;
                try input.insert(testing.allocator, at, set[random.uintLessThan(usize, set.len)]);
            }
        }
        try checkDecoder(lib.decode.base64.Decoder, testing.allocator, random, input.items);

        // quoted-printable: text with escapes, soft breaks and broken escapes.
        input.clearRetainingCapacity();
        const qp_pieces = [_][]const u8{ "a", "b", " ", "=3D", "=C3=A9", "=\r\n", "=\n", "= \r\n", "=G", "=", "\r\n", "\t", "=4" };
        for (0..random.uintAtMost(usize, 64)) |_| {
            try input.appendSlice(testing.allocator, qp_pieces[random.uintLessThan(usize, qp_pieces.len)]);
        }
        try checkDecoder(lib.decode.qp.Decoder, testing.allocator, random, input.items);
    }
}
