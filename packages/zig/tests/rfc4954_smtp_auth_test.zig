//! SMTP AUTH (RFC 4954) with the PLAIN (RFC 4616) and LOGIN mechanisms,
//! driven through a whole Session over a socketpair against a real auth
//! backend on an in-memory database.
//!
//! PLAIN once answered only the initial-response form ("AUTH PLAIN <b64>").
//! A client that sends bare "AUTH PLAIN" and waits for the 334, which is
//! what curl and many libraries do by default, got "501 AUTH PLAIN requires
//! initial-response" and reported a login failure, while AUTH LOGIN with the
//! same account worked.

const std = @import("std");
const testing = std.testing;
const mail = @import("mail");

const user = "user@example.com";
const password = "correct horse battery staple";

/// Run one Session over a socketpair on `script`, returning what it replied.
fn converse(allocator: std.mem.Allocator, backend: ?*mail.auth.AuthBackend, script: []const u8) ![]u8 {
    var fds: [2]c_int = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, @intCast(@as(u32, std.posix.SOCK.STREAM)), 0, &fds) != 0) return error.SocketPairFailed;
    defer _ = std.c.close(fds[1]);

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
        .port = 587,
        .max_connections = 10,
        .enable_tls = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .enable_auth = true,
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
        var session = try mail.smtp.Session.init(allocator, .{ .fd = fds[0] }, cfg, &log, "127.0.0.1", &rate_limiter, null, backend, null);
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

/// The final line of each reply ("NNN text"), so a multi-line EHLO counts once.
fn finalLines(allocator: std.mem.Allocator, replies: []const u8) ![]const []const u8 {
    var lines: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitSequence(u8, replies, "\r\n");
    while (it.next()) |line| {
        if (line.len >= 4 and line[3] == ' ') try lines.append(allocator, line);
    }
    return lines.toOwnedSlice(allocator);
}

/// Assert the reply codes, in order. `expected` is like "220 250 334 235 221".
fn expectCodes(replies: []const u8, expected: []const u8) !void {
    const lines = try finalLines(testing.allocator, replies);
    defer testing.allocator.free(lines);

    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(testing.allocator);
    for (lines, 0..) |line, i| {
        if (i > 0) try got.append(testing.allocator, ' ');
        try got.appendSlice(testing.allocator, line[0..3]);
    }
    testing.expectEqualStrings(expected, got.items) catch |err| {
        std.debug.print("full transcript:\n{s}\n", .{replies});
        return err;
    };
}

const Fixture = struct {
    db: mail.database.Database,
    backend: mail.auth.AuthBackend,

    fn init(self: *Fixture) !void {
        self.db = try mail.database.Database.init(testing.allocator, ":memory:");
        errdefer self.db.deinit();
        self.backend = mail.auth.AuthBackend.init(testing.allocator, &self.db);
        _ = try self.backend.createUser(user, password, user);
    }

    fn deinit(self: *Fixture) void {
        self.backend.deinit();
        self.db.deinit();
    }
};

/// base64 of `raw`, owned by the caller.
fn b64(raw: []const u8) ![]u8 {
    const enc = std.base64.standard.Encoder;
    const out = try testing.allocator.alloc(u8, enc.calcSize(raw.len));
    _ = enc.encode(out, raw);
    return out;
}

/// base64 of a PLAIN response: authzid NUL authcid NUL passwd.
fn plain(authzid: []const u8, authcid: []const u8, passwd: []const u8) ![]u8 {
    const raw = try std.fmt.allocPrint(testing.allocator, "{s}\x00{s}\x00{s}", .{ authzid, authcid, passwd });
    defer testing.allocator.free(raw);
    return b64(raw);
}

fn run(fx: ?*Fixture, comptime fmt: []const u8, args: anytype) ![]u8 {
    const script = try std.fmt.allocPrint(testing.allocator, fmt, args);
    defer testing.allocator.free(script);
    return converse(testing.allocator, if (fx) |f| &f.backend else null, script);
}

test "AUTH PLAIN with an initial response" {
    var fx: Fixture = undefined;
    try fx.init();
    defer fx.deinit();
    const ir = try plain("", user, password);
    defer testing.allocator.free(ir);

    const replies = try run(&fx, "EHLO c\r\nAUTH PLAIN {s}\r\nQUIT\r\n", .{ir});
    defer testing.allocator.free(replies);
    try expectCodes(replies, "220 250 235 221");
}

test "AUTH PLAIN without an initial response answers 334 and takes the credentials on the next line" {
    var fx: Fixture = undefined;
    try fx.init();
    defer fx.deinit();
    const resp = try plain("", user, password);
    defer testing.allocator.free(resp);

    const replies = try run(&fx, "EHLO c\r\nAUTH PLAIN\r\n{s}\r\nQUIT\r\n", .{resp});
    defer testing.allocator.free(replies);
    try expectCodes(replies, "220 250 334 235 221");
    // The challenge is empty: "334 " and nothing after it.
    try testing.expect(std.mem.indexOf(u8, replies, "\r\n334 \r\n") != null);
}

test "AUTH PLAIN is case-insensitive and tolerates a trailing space" {
    var fx: Fixture = undefined;
    try fx.init();
    defer fx.deinit();
    const resp = try plain("", user, password);
    defer testing.allocator.free(resp);

    const replies = try run(&fx, "EHLO c\r\nauth plain \r\n{s}\r\nQUIT\r\n", .{resp});
    defer testing.allocator.free(replies);
    try expectCodes(replies, "220 250 334 235 221");
}

test "AUTH PLAIN accepts an authzid naming the same account" {
    var fx: Fixture = undefined;
    try fx.init();
    defer fx.deinit();
    const ir = try plain("USER@example.com", user, password);
    defer testing.allocator.free(ir);

    const replies = try run(&fx, "EHLO c\r\nAUTH PLAIN {s}\r\nQUIT\r\n", .{ir});
    defer testing.allocator.free(replies);
    try expectCodes(replies, "220 250 235 221");
}

test "AUTH PLAIN refuses an authzid naming another account" {
    var fx: Fixture = undefined;
    try fx.init();
    defer fx.deinit();
    const ir = try plain("someone-else@example.com", user, password);
    defer testing.allocator.free(ir);

    const replies = try run(&fx, "EHLO c\r\nAUTH PLAIN {s}\r\nQUIT\r\n", .{ir});
    defer testing.allocator.free(replies);
    try expectCodes(replies, "220 250 535 221");
}

test "AUTH PLAIN rejects a wrong password in both forms" {
    var fx: Fixture = undefined;
    try fx.init();
    defer fx.deinit();
    const bad = try plain("", user, "wrong");
    defer testing.allocator.free(bad);

    const replies = try run(&fx, "EHLO c\r\nAUTH PLAIN {s}\r\nAUTH PLAIN\r\n{s}\r\nQUIT\r\n", .{ bad, bad });
    defer testing.allocator.free(replies);
    try expectCodes(replies, "220 250 535 334 535 221");
}

test "AUTH PLAIN: a cancelled exchange gets 501 and the session carries on" {
    var fx: Fixture = undefined;
    try fx.init();
    defer fx.deinit();
    const resp = try plain("", user, password);
    defer testing.allocator.free(resp);

    const replies = try run(&fx, "EHLO c\r\nAUTH PLAIN\r\n*\r\nNOOP\r\nAUTH PLAIN\r\n{s}\r\nQUIT\r\n", .{resp});
    defer testing.allocator.free(replies);
    try expectCodes(replies, "220 250 334 501 250 334 235 221");
}

test "AUTH PLAIN: undecodable, empty and malformed responses are refused" {
    var fx: Fixture = undefined;
    try fx.init();
    defer fx.deinit();
    // No NULs at all, and one NUL short.
    const no_nul = try b64("user@example.com");
    defer testing.allocator.free(no_nul);
    const one_nul = try b64("\x00user@example.com");
    defer testing.allocator.free(one_nul);

    const replies = try run(&fx, "EHLO c\r\nAUTH PLAIN !!!\r\nAUTH PLAIN =\r\nAUTH PLAIN {s}\r\nAUTH PLAIN\r\n{s}\r\nQUIT\r\n", .{ no_nul, one_nul });
    defer testing.allocator.free(replies);
    try expectCodes(replies, "220 250 501 535 535 334 535 221");
}

test "AUTH PLAIN: an over-long response is refused and the next command is still read" {
    var fx: Fixture = undefined;
    try fx.init();
    defer fx.deinit();
    const long = try testing.allocator.alloc(u8, 5000);
    defer testing.allocator.free(long);
    @memset(long, 'A');

    const replies = try run(&fx, "EHLO c\r\nAUTH PLAIN\r\n{s}\r\nNOOP\r\nQUIT\r\n", .{long});
    defer testing.allocator.free(replies);
    try expectCodes(replies, "220 250 334 500 250 221");
}

test "AUTH LOGIN with both challenges" {
    var fx: Fixture = undefined;
    try fx.init();
    defer fx.deinit();
    const u = try b64(user);
    defer testing.allocator.free(u);
    const p = try b64(password);
    defer testing.allocator.free(p);

    const replies = try run(&fx, "EHLO c\r\nAUTH LOGIN\r\n{s}\r\n{s}\r\nQUIT\r\n", .{ u, p });
    defer testing.allocator.free(replies);
    try expectCodes(replies, "220 250 334 334 235 221");
    try testing.expect(std.mem.indexOf(u8, replies, "334 VXNlcm5hbWU6\r\n334 UGFzc3dvcmQ6\r\n") != null);
}

test "AUTH LOGIN with the username as initial response skips the first challenge" {
    var fx: Fixture = undefined;
    try fx.init();
    defer fx.deinit();
    const u = try b64(user);
    defer testing.allocator.free(u);
    const p = try b64(password);
    defer testing.allocator.free(p);

    const replies = try run(&fx, "EHLO c\r\nAUTH LOGIN {s}\r\n{s}\r\nQUIT\r\n", .{ u, p });
    defer testing.allocator.free(replies);
    try expectCodes(replies, "220 250 334 235 221");
    try testing.expect(std.mem.indexOf(u8, replies, "334 UGFzc3dvcmQ6\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, replies, "VXNlcm5hbWU6") == null);
}

test "AUTH LOGIN rejects a wrong password, and a cancel" {
    var fx: Fixture = undefined;
    try fx.init();
    defer fx.deinit();
    const u = try b64(user);
    defer testing.allocator.free(u);
    const p = try b64("wrong");
    defer testing.allocator.free(p);

    const replies = try run(&fx, "EHLO c\r\nAUTH LOGIN\r\n{s}\r\n{s}\r\nAUTH LOGIN\r\n*\r\nQUIT\r\n", .{ u, p });
    defer testing.allocator.free(replies);
    try expectCodes(replies, "220 250 334 334 535 334 501 221");
}

test "a second AUTH after success is refused, and unknown mechanisms get 504" {
    var fx: Fixture = undefined;
    try fx.init();
    defer fx.deinit();
    const ir = try plain("", user, password);
    defer testing.allocator.free(ir);

    const replies = try run(&fx, "EHLO c\r\nAUTH CRAM-MD5\r\nAUTH PLAIN {s}\r\nAUTH PLAIN {s}\r\nQUIT\r\n", .{ ir, ir });
    defer testing.allocator.free(replies);
    try expectCodes(replies, "220 250 504 235 503 221");
}

test "AUTH fails closed with no auth backend" {
    const resp = try plain("", user, password);
    defer testing.allocator.free(resp);

    const replies = try run(null, "EHLO c\r\nAUTH PLAIN\r\n{s}\r\nQUIT\r\n", .{resp});
    defer testing.allocator.free(replies);
    try expectCodes(replies, "220 250 334 454 221");
}

test "decodeBase64Auth parses authzid NUL authcid NUL passwd" {
    const cases = [_]struct { raw: []const u8, user: ?[]const u8, pass: []const u8 = "" }{
        .{ .raw = "\x00alice\x00secret", .user = "alice", .pass = "secret" },
        .{ .raw = "alice\x00alice\x00secret", .user = "alice", .pass = "secret" },
        .{ .raw = "\x00alice\x00", .user = "alice", .pass = "" },
        .{ .raw = "\x00alice\x00pass word", .user = "alice", .pass = "pass word" },
        .{ .raw = "", .user = null },
        .{ .raw = "\x00alice", .user = null },
        .{ .raw = "\x00\x00secret", .user = null },
        .{ .raw = "\x00alice\x00sec\x00ret", .user = null },
        .{ .raw = "mallory\x00alice\x00secret", .user = null },
    };
    for (cases) |case| {
        const encoded = try b64(case.raw);
        defer testing.allocator.free(encoded);
        if (case.user) |expected_user| {
            const creds = try mail.auth.decodeBase64Auth(testing.allocator, encoded);
            defer {
                testing.allocator.free(creds.username);
                testing.allocator.free(creds.password);
            }
            try testing.expectEqualStrings(expected_user, creds.username);
            try testing.expectEqualStrings(case.pass, creds.password);
        } else {
            try testing.expect(std.meta.isError(mail.auth.decodeBase64Auth(testing.allocator, encoded)));
        }
    }
}
