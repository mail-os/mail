//! Randomized tests against the SMTP server's own code.
//!
//! This file used to generate random data and assert that it was not empty,
//! with a note that "in a real implementation this would call the SMTP
//! parser". Nothing here called the server. Every test below does: the DATA
//! decoder, the command parser, and a whole Session over a socketpair.
//! Seeds are fixed, so a failure reproduces.

const std = @import("std");
const testing = std.testing;
const mail = @import("mail");
const DataDecoder = mail.smtp.DataDecoder;

const iterations = 300;

/// Decode `input` handing the decoder pieces of random length, the way a
/// socket delivers them.
fn decodeRandomlySplit(allocator: std.mem.Allocator, random: std.Random, input: []const u8, max_size: usize) !struct { out: std.ArrayList(u8), consumed: usize, done: bool, too_large: bool } {
    var decoder = DataDecoder.init(max_size);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var pos: usize = 0;
    while (pos < input.len and !decoder.done) {
        const piece = random.intRangeAtMost(usize, 1, @min(input.len - pos, 64));
        pos += try decoder.feed(allocator, &out, input[pos .. pos + piece]);
    }
    return .{ .out = out, .consumed = pos, .done = decoder.done, .too_large = decoder.too_large };
}

/// Random bytes drawn mostly from the characters that matter to DATA
/// framing, so dots, CRs and LFs land next to each other often.
fn framingNoise(allocator: std.mem.Allocator, random: std.Random, len: usize) ![]u8 {
    const alphabet = "\r\n.\r\n.ab\x00\xff";
    const data = try allocator.alloc(u8, len);
    for (data) |*b| b.* = alphabet[random.uintLessThan(usize, alphabet.len)];
    return data;
}

test "Fuzz: DATA decoding does not depend on how the stream is split" {
    var prng = std.Random.DefaultPrng.init(0x5eed_da7a);
    const random = prng.random();

    for (0..iterations) |_| {
        const input = try framingNoise(testing.allocator, random, random.intRangeAtMost(usize, 1, 400));
        defer testing.allocator.free(input);
        const max_size = random.intRangeAtMost(usize, 1, 500);

        var whole_decoder = DataDecoder.init(max_size);
        var whole: std.ArrayList(u8) = .empty;
        defer whole.deinit(testing.allocator);
        const whole_consumed = try whole_decoder.feed(testing.allocator, &whole, input);

        var split = try decodeRandomlySplit(testing.allocator, random, input, max_size);
        defer split.out.deinit(testing.allocator);

        try testing.expectEqual(whole_decoder.done, split.done);
        try testing.expectEqual(whole_decoder.too_large, split.too_large);
        try testing.expectEqual(whole_consumed, split.consumed);
        try testing.expectEqualStrings(whole.items, split.out.items);
        // Never more than the limit, whatever arrives.
        try testing.expect(split.out.items.len <= max_size);
    }
}

test "Fuzz: a dot-stuffed message round-trips through the DATA decoder" {
    var prng = std.Random.DefaultPrng.init(0xd07_5eed);
    const random = prng.random();

    for (0..iterations) |_| {
        // Build a message the way a sender holds it (LF line ends) and the
        // wire form a compliant client sends (CRLF, leading dots doubled,
        // then <CRLF>.<CRLF>), followed by a pipelined command.
        var original: std.ArrayList(u8) = .empty;
        defer original.deinit(testing.allocator);
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(testing.allocator);

        const lines = random.intRangeAtMost(usize, 0, 20);
        for (0..lines) |_| {
            const len = random.intRangeAtMost(usize, 0, if (random.boolean()) 8 else 6000);
            const line = try testing.allocator.alloc(u8, len);
            defer testing.allocator.free(line);
            for (line) |*b| b.* = ". x\t\r"[random.uintLessThan(usize, 5)];
            // A lone trailing CR would merge with the line's CRLF.
            if (line.len > 0 and line[line.len - 1] == '\r') line[line.len - 1] = 'x';

            try original.appendSlice(testing.allocator, line);
            try original.append(testing.allocator, '\n');
            if (line.len > 0 and line[0] == '.') try wire.append(testing.allocator, '.');
            try wire.appendSlice(testing.allocator, line);
            try wire.appendSlice(testing.allocator, "\r\n");
        }
        try wire.appendSlice(testing.allocator, ".\r\nQUIT\r\n");

        var r = try decodeRandomlySplit(testing.allocator, random, wire.items, 1 << 20);
        defer r.out.deinit(testing.allocator);
        try testing.expect(r.done);
        try testing.expect(!r.too_large);
        try testing.expectEqual(wire.items.len - "QUIT\r\n".len, r.consumed);
        try testing.expectEqualStrings(original.items, r.out.items);
    }
}

test "Fuzz: the command parser takes any bytes" {
    var prng = std.Random.DefaultPrng.init(0xc0de);
    const random = prng.random();
    var buf: [600]u8 = undefined;
    for (0..iterations * 10) |_| {
        const line = buf[0..random.uintAtMost(usize, buf.len)];
        random.bytes(line);
        _ = mail.smtp.Session.parseCommandStatic(line);
    }
}

/// Run one Session over a socketpair on `script`, returning what it replied.
fn converse(allocator: std.mem.Allocator, script: []const u8) ![]u8 {
    var fds: [2]c_int = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, @intCast(@as(u32, std.posix.SOCK.STREAM)), 0, &fds) != 0) return error.SocketPairFailed;
    defer _ = std.c.close(fds[1]);
    const bufsize: c_int = 1 << 20;
    _ = std.c.setsockopt(fds[1], std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&bufsize), @sizeOf(c_int));
    _ = std.c.setsockopt(fds[0], std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&bufsize), @sizeOf(c_int));

    var off: usize = 0;
    while (off < script.len) {
        const n = std.c.write(fds[1], script[off..].ptr, script.len - off);
        if (n <= 0) return error.WriteFailed;
        off += @intCast(n);
    }
    _ = std.c.shutdown(fds[1], std.c.SHUT.WR);

    var log = try mail.logger.Logger.init(allocator, .critical, null);
    defer log.deinit();
    var rate_limiter = mail.security.RateLimiter.init(allocator, 60, 1000, 1000, 3600);
    defer rate_limiter.deinit();
    const cfg = mail.config.Config{
        .host = "127.0.0.1",
        .port = 25,
        .max_connections = 10,
        .enable_tls = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .enable_auth = false,
        .max_message_size = 1 << 20,
        .timeout_seconds = 60,
        .data_timeout_seconds = 60,
        .command_timeout_seconds = 60,
        .greeting_timeout_seconds = 60,
        .rate_limit_per_ip = 1000,
        .rate_limit_per_user = 1000,
        .rate_limit_cleanup_interval = 3600,
        .max_recipients = 10,
        .hostname = "mail.example.com",
        .webhook_url = null,
        .webhook_enabled = false,
        .enable_dnsbl = false,
        .enable_greylist = false,
        .enable_tracing = false,
        .tracing_service_name = "test",
        .enable_json_logging = false,
        .antispam_check = false,
        .spam_filter_enabled = false,
    };
    {
        var session = try mail.smtp.Session.init(allocator, .{ .fd = fds[0] }, cfg, &log, "127.0.0.1", &rate_limiter, null, null, null);
        defer session.deinit();
        try session.handle();
    }
    _ = std.c.close(fds[0]);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var buf: [16384]u8 = undefined;
    while (true) {
        const n = std.c.read(fds[1], &buf, buf.len);
        if (n <= 0) break;
        try out.appendSlice(allocator, buf[0..@intCast(n)]);
    }
    return out.toOwnedSlice(allocator);
}

/// Final reply lines ("NNN text"), i.e. one per reply.
fn countReplies(replies: []const u8) usize {
    var n: usize = 0;
    var it = std.mem.splitSequence(u8, replies, "\r\n");
    while (it.next()) |line| {
        if (line.len >= 4 and line[3] == ' ') n += 1;
    }
    return n;
}

test "Fuzz: a session answers every random command line and survives to QUIT" {
    var prng = std.Random.DefaultPrng.init(0x5e55_1011);
    const random = prng.random();
    const verbs = [_][]const u8{
        "HELO", "EHLO",     "MAIL", "RCPT", "RSET",       "VRFY",     "EXPN", "HELP", "NOOP",
        "AUTH", "STARTTLS", "BDAT", "ETRN", "mail from:", "rcpt to:", "X",
    };

    for (0..40) |_| {
        var script: std.ArrayList(u8) = .empty;
        defer script.deinit(testing.allocator);

        // Under the 50-commands-per-10s limit, so every line is answered.
        const commands = random.intRangeAtMost(usize, 1, 30);
        for (0..commands) |_| {
            try script.appendSlice(testing.allocator, verbs[random.uintLessThan(usize, verbs.len)]);
            try script.append(testing.allocator, ' ');
            // Mostly short arguments, sometimes far past the 4096-byte
            // command buffer. Any byte but LF, and never ending in CR alone
            // being the whole line.
            const len = if (random.uintLessThan(u8, 8) == 0) random.intRangeAtMost(usize, 4000, 9000) else random.uintAtMost(usize, 80);
            for (0..len) |_| {
                var b = random.int(u8);
                if (b == '\n') b = 'n';
                try script.append(testing.allocator, b);
            }
            try script.appendSlice(testing.allocator, "\r\n");
        }
        try script.appendSlice(testing.allocator, "QUIT\r\n");

        const replies = try converse(testing.allocator, script.items);
        defer testing.allocator.free(replies);

        // The greeting, one reply per command, and the 221.
        try testing.expectEqual(commands + 2, countReplies(replies));
        try testing.expect(std.mem.endsWith(u8, replies, "\r\n") and std.mem.indexOf(u8, replies, "221 ") != null);
    }
}
