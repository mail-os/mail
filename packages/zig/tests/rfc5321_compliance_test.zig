// RFC 5321 (SMTP Protocol) Compliance Test Suite
// Tests for compliance with RFC 5321 - Simple Mail Transfer Protocol
// https://datatracker.ietf.org/doc/html/rfc5321
//
// Each test talks to the server's own SMTP session (mail.smtp.Session) over a
// socketpair, in a scratch directory it can deliver into. This suite used to
// run against a stand-in responder written inside this file, which meant it
// tested that responder and not the server.

const std = @import("std");
const testing = std.testing;
const posix = std.posix;
const mail_pkg = @import("mail");

// Wrappers for raw I/O — posix.write/read were removed in Zig 0.16-dev
fn fdWrite(fd: posix.socket_t, data: []const u8) !usize {
    const rc = std.c.write(fd, data.ptr, data.len);
    if (rc < 0) return error.WriteFailed;
    return @intCast(rc);
}

fn fdRead(fd: posix.socket_t, buf: []u8) !usize {
    const rc = std.c.read(fd, buf.ptr, buf.len);
    if (rc < 0) return error.ReadFailed;
    return @intCast(rc);
}

// ============================================================================
// SMTP test client — talks to one end of a socketpair
// ============================================================================
const SmtpTestClient = struct {
    fd: posix.socket_t,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn initFromFd(allocator: std.mem.Allocator, fd: posix.socket_t) Self {
        return Self{ .fd = fd, .allocator = allocator };
    }

    pub fn deinit(self: *Self) void {
        _ = std.c.close(self.fd);
    }

    pub fn readResponse(self: *Self) ![]u8 {
        var buffer: std.ArrayList(u8) = .empty;
        errdefer buffer.deinit(self.allocator);

        var read_buffer: [4096]u8 = undefined;
        // Keep reading until we have a complete SMTP response.
        // Multi-line responses use "NNN-" continuation; final line uses "NNN ".
        while (true) {
            const bytes_read = fdRead(self.fd, &read_buffer) catch return error.ConnectionClosed;
            if (bytes_read == 0) return error.ConnectionClosed;

            try buffer.appendSlice(self.allocator, read_buffer[0..bytes_read]);

            // Check if response is complete: last line must end with \r\n
            // and have "NNN " (space after code, not hyphen)
            if (isResponseComplete(buffer.items)) break;
        }
        return buffer.toOwnedSlice(self.allocator);
    }

    fn isResponseComplete(data: []const u8) bool {
        // Must end with \r\n
        if (data.len < 5 or !std.mem.endsWith(u8, data, "\r\n")) return false;
        // Find the start of the last line
        const without_crlf = data[0 .. data.len - 2];
        const last_line_start = if (std.mem.lastIndexOf(u8, without_crlf, "\r\n")) |pos| pos + 2 else 0;
        const last_line = data[last_line_start..without_crlf.len];
        // Last line must be at least "NNN " (4 chars) and have space at pos 3
        return last_line.len >= 4 and last_line[3] == ' ';
    }

    /// Send one command line, CRLF appended when missing.
    pub fn sendCommand(self: *Self, command: []const u8) !void {
        var off: usize = 0;
        while (off < command.len) off += fdWrite(self.fd, command[off..]) catch return error.WriteFailed;
        if (!std.mem.endsWith(u8, command, "\r\n")) {
            _ = fdWrite(self.fd, "\r\n") catch return error.WriteFailed;
        }
    }

    pub fn sendAndRead(self: *Self, command: []const u8) ![]u8 {
        try self.sendCommand(command);
        return self.readResponse();
    }

    pub fn expectCode(response: []const u8, expected_code: []const u8) !void {
        if (response.len < 3 or !std.mem.startsWith(u8, response, expected_code)) {
            std.debug.print("Expected code {s}, got: {s}\n", .{ expected_code, response });
            return error.UnexpectedResponseCode;
        }
    }
};

// ============================================================================
// The server under test: a real mail.smtp.Session on a thread
// ============================================================================
const Server = struct {
    /// example.com is local to this hostname (its parent domain), so the
    /// tests' recipients are accepted rather than refused as relaying.
    const hostname = "mail.example.com";

    fn run(fd: posix.socket_t) void {
        defer _ = std.c.close(fd);
        const allocator = std.heap.c_allocator;
        var log = mail_pkg.logger.Logger.init(allocator, .critical, null) catch return;
        defer log.deinit();
        var rate_limiter = mail_pkg.security.RateLimiter.init(allocator, 60, 1000, 1000, 3600);
        defer rate_limiter.deinit();

        const cfg = mail_pkg.config.Config{
            .host = "127.0.0.1",
            .port = 25,
            .max_connections = 10,
            .enable_tls = false,
            .tls_cert_path = null,
            .tls_key_path = null,
            .enable_auth = false,
            .max_message_size = 10 * 1024 * 1024,
            .timeout_seconds = 60,
            .data_timeout_seconds = 60,
            .command_timeout_seconds = 60,
            .greeting_timeout_seconds = 60,
            .rate_limit_per_ip = 1000,
            .rate_limit_per_user = 1000,
            .rate_limit_cleanup_interval = 3600,
            .max_recipients = 100,
            .hostname = hostname,
            .webhook_url = null,
            .webhook_enabled = false,
            .enable_dnsbl = false,
            .enable_greylist = false,
            .enable_tracing = false,
            .tracing_service_name = "test",
            .enable_json_logging = false,
            // No DNS lookups from a test.
            .antispam_check = false,
            .spam_filter_enabled = false,
        };
        var session = mail_pkg.smtp.Session.init(allocator, .{ .fd = fd }, cfg, &log, "127.0.0.1", &rate_limiter, null, null, null) catch return;
        defer session.deinit();
        session.handle() catch {};
    }
};

// ============================================================================
// Helper: a client connected to a server thread, in a scratch directory
// ============================================================================
const TestPair = struct {
    client: SmtpTestClient,
    thread: std.Thread,
    root: [64]u8 = undefined,
    root_len: usize = 0,
    prev_cwd: [4096]u8 = undefined,

    fn create(allocator: std.mem.Allocator) !TestPair {
        var pair: TestPair = undefined;

        // The session delivers into mail/<user>/new relative to the working
        // directory, so give it one of its own.
        var rnd: [8]u8 = undefined;
        mail_pkg.io_compat.randomBytes(&rnd);
        const root = try std.fmt.bufPrintSentinel(&pair.root, "/tmp/mail-rfc5321-{x}", .{std.mem.readInt(u64, &rnd, .little)}, 0);
        pair.root_len = root.len;
        try mail_pkg.fs_compat.cwd().makePath(root);
        _ = std.c.getcwd(&pair.prev_cwd, pair.prev_cwd.len) orelse return error.GetCwdFailed;
        if (std.c.chdir(root.ptr) != 0) return error.ChdirFailed;

        var fds: [2]posix.socket_t = undefined;
        const rc = std.c.socketpair(posix.AF.UNIX, @intCast(@as(u32, posix.SOCK.STREAM)), 0, &fds);
        if (rc != 0) return error.SocketPairFailed;

        pair.thread = try std.Thread.spawn(.{}, Server.run, .{fds[1]});
        pair.client = SmtpTestClient.initFromFd(allocator, fds[0]);
        return pair;
    }

    fn deinit(self: *TestPair) void {
        self.client.deinit();
        self.thread.join();
        _ = std.c.chdir(@ptrCast(&self.prev_cwd));
        mail_pkg.fs_compat.cwd().deleteTree(self.root[0..self.root_len]) catch {};
    }

    /// The messages delivered to `user`'s inbox. Caller frees each and the slice.
    fn delivered(self: *TestPair, allocator: std.mem.Allocator, comptime user: []const u8) ![][]u8 {
        _ = self;
        const dir = "mail/" ++ user ++ "/new";
        const names = mail_pkg.fs_compat.listEmlFiles(allocator, dir) catch |err| switch (err) {
            error.FileNotFound => return allocator.alloc([]u8, 0),
            else => return err,
        };
        defer {
            for (names) |n| allocator.free(n);
            allocator.free(names);
        }
        const out = try allocator.alloc([]u8, names.len);
        for (names, 0..) |name, i| {
            const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir, name });
            defer allocator.free(path);
            out[i] = try mail_pkg.fs_compat.readFileAlloc(allocator, path);
        }
        return out;
    }
};

// ============================================================================
// RFC 5321 Compliance Tests
// ============================================================================

// RFC 5321 Section 3.1 - Session Initiation
test "RFC 5321 Section 3.1: Server greeting with 220 code" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);

    try SmtpTestClient.expectCode(greeting, "220");
    try testing.expect(greeting.len > 4);
}

// RFC 5321 Section 3.2 - Client Initiation (EHLO)
test "RFC 5321 Section 3.2: EHLO command returns 250" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);

    const response = try pair.client.sendAndRead("EHLO test.example.com");
    defer testing.allocator.free(response);

    try SmtpTestClient.expectCode(response, "250");
}

// RFC 5321 Section 3.3 - Mail Transactions
test "RFC 5321 Section 3.3: MAIL FROM command" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);
    const ehlo = try pair.client.sendAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo);

    const response = try pair.client.sendAndRead("MAIL FROM:<sender@example.com>");
    defer testing.allocator.free(response);

    try SmtpTestClient.expectCode(response, "250");
}

test "RFC 5321 Section 3.3: RCPT TO command" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);
    const ehlo = try pair.client.sendAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo);
    const mail = try pair.client.sendAndRead("MAIL FROM:<sender@example.com>");
    defer testing.allocator.free(mail);

    const response = try pair.client.sendAndRead("RCPT TO:<recipient@example.com>");
    defer testing.allocator.free(response);

    try SmtpTestClient.expectCode(response, "250");
}

test "RFC 5321 Section 3.3: DATA command" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);
    const ehlo = try pair.client.sendAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo);
    const mail = try pair.client.sendAndRead("MAIL FROM:<sender@example.com>");
    defer testing.allocator.free(mail);
    const rcpt = try pair.client.sendAndRead("RCPT TO:<recipient@example.com>");
    defer testing.allocator.free(rcpt);

    const response = try pair.client.sendAndRead("DATA");
    defer testing.allocator.free(response);

    try SmtpTestClient.expectCode(response, "354");
}

// RFC 5321 Section 4.1.1.1 - Command Syntax
test "RFC 5321 Section 4.1.1.1: Commands are case-insensitive" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);

    // Test lowercase
    const resp1 = try pair.client.sendAndRead("ehlo test.example.com");
    defer testing.allocator.free(resp1);
    try SmtpTestClient.expectCode(resp1, "250");

    // Test mixed case — MAIL FROM should still work
    const resp2 = try pair.client.sendAndRead("MaIl FrOm:<test@example.com>");
    defer testing.allocator.free(resp2);
    try SmtpTestClient.expectCode(resp2, "250");
}

test "RFC 5321 Section 4.1.1.1: CRLF line termination" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);

    // Send with explicit CRLF
    try pair.client.sendCommand("EHLO test.example.com\r\n");
    const response = try pair.client.readResponse();
    defer testing.allocator.free(response);

    try SmtpTestClient.expectCode(response, "250");
}

// RFC 5321 Section 4.1.2 - Command Argument Syntax
test "RFC 5321 Section 4.1.2: MAIL FROM with null sender" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);
    const ehlo = try pair.client.sendAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo);

    // Null sender for bounce messages
    const response = try pair.client.sendAndRead("MAIL FROM:<>");
    defer testing.allocator.free(response);

    try SmtpTestClient.expectCode(response, "250");
}

// RFC 5321 Section 4.1.3 - Address Literals
test "RFC 5321 Section 4.1.3: Address literals with square brackets" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);

    // EHLO with address literal
    const response = try pair.client.sendAndRead("EHLO [192.168.1.1]");
    defer testing.allocator.free(response);

    try SmtpTestClient.expectCode(response, "250");
}

// RFC 5321 Section 4.1.4 - Order of Commands
test "RFC 5321 Section 4.1.4: Commands must be in order" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);

    // Try MAIL before EHLO — should fail with 503
    const response = try pair.client.sendAndRead("MAIL FROM:<test@example.com>");
    defer testing.allocator.free(response);

    try SmtpTestClient.expectCode(response, "503");
}

// RFC 5321 Section 4.2.1 - Reply Codes
test "RFC 5321 Section 4.2.1: Reply codes are 3 digits" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);

    // Must start with 3 digits
    try testing.expect(greeting.len >= 3);
    try testing.expect(std.ascii.isDigit(greeting[0]));
    try testing.expect(std.ascii.isDigit(greeting[1]));
    try testing.expect(std.ascii.isDigit(greeting[2]));
}

// RFC 5321 Section 4.3.2 - EHLO/HELO
test "RFC 5321 Section 4.3.2: HELO command (backward compatibility)" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);

    // HELO for older clients
    const response = try pair.client.sendAndRead("HELO test.example.com");
    defer testing.allocator.free(response);

    try SmtpTestClient.expectCode(response, "250");
}

// RFC 5321 Section 4.5.1 - Minimum Implementation
test "RFC 5321 Section 4.5.1: Required commands are supported" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);

    // EHLO
    const ehlo_resp = try pair.client.sendAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo_resp);
    try SmtpTestClient.expectCode(ehlo_resp, "250");

    // MAIL
    const mail_resp = try pair.client.sendAndRead("MAIL FROM:<test@example.com>");
    defer testing.allocator.free(mail_resp);
    try SmtpTestClient.expectCode(mail_resp, "250");

    // RCPT
    const rcpt_resp = try pair.client.sendAndRead("RCPT TO:<recipient@example.com>");
    defer testing.allocator.free(rcpt_resp);
    try SmtpTestClient.expectCode(rcpt_resp, "250");

    // RSET
    const rset_resp = try pair.client.sendAndRead("RSET");
    defer testing.allocator.free(rset_resp);
    try SmtpTestClient.expectCode(rset_resp, "250");

    // VRFY (252 = cannot verify but will accept)
    const vrfy_resp = try pair.client.sendAndRead("VRFY postmaster");
    defer testing.allocator.free(vrfy_resp);
    try SmtpTestClient.expectCode(vrfy_resp, "252");

    // NOOP
    const noop_resp = try pair.client.sendAndRead("NOOP");
    defer testing.allocator.free(noop_resp);
    try SmtpTestClient.expectCode(noop_resp, "250");

    // QUIT
    const quit_resp = try pair.client.sendAndRead("QUIT");
    defer testing.allocator.free(quit_resp);
    try SmtpTestClient.expectCode(quit_resp, "221");
}

// RFC 5321 Section 4.5.3.1.8 - RSET Command
test "RFC 5321 Section 4.5.3.1.8: RSET clears transaction state" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);
    const ehlo = try pair.client.sendAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo);
    const mail1 = try pair.client.sendAndRead("MAIL FROM:<sender@example.com>");
    defer testing.allocator.free(mail1);

    // RSET should clear MAIL FROM
    const rset_resp = try pair.client.sendAndRead("RSET");
    defer testing.allocator.free(rset_resp);
    try SmtpTestClient.expectCode(rset_resp, "250");

    // Should be able to start new transaction
    const mail_resp = try pair.client.sendAndRead("MAIL FROM:<newsender@example.com>");
    defer testing.allocator.free(mail_resp);
    try SmtpTestClient.expectCode(mail_resp, "250");
}

// RFC 5321 Section 4.5.3.1.9 - NOOP Command
test "RFC 5321 Section 4.5.3.1.9: NOOP does nothing" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);
    const ehlo = try pair.client.sendAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo);

    // NOOP should not affect state
    const noop_resp = try pair.client.sendAndRead("NOOP");
    defer testing.allocator.free(noop_resp);
    try SmtpTestClient.expectCode(noop_resp, "250");

    // Should still be able to issue commands
    const mail_resp = try pair.client.sendAndRead("MAIL FROM:<test@example.com>");
    defer testing.allocator.free(mail_resp);
    try SmtpTestClient.expectCode(mail_resp, "250");
}

// RFC 5321 Section 4.5.3.1.10 - QUIT Command
test "RFC 5321 Section 4.5.3.1.10: QUIT closes connection gracefully" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);
    const ehlo = try pair.client.sendAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo);

    const quit_resp = try pair.client.sendAndRead("QUIT");
    defer testing.allocator.free(quit_resp);

    // Should return 221
    try SmtpTestClient.expectCode(quit_resp, "221");

    // Connection should close (read returns 0)
    var buffer: [10]u8 = undefined;
    const bytes = fdRead(pair.client.fd, &buffer) catch 0;
    try testing.expect(bytes == 0);
}

// RFC 5321 Section 4.5.4 - Trace Information
test "RFC 5321 Section 4.5.4: Server adds Received header" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);
    inline for (.{
        .{ "EHLO client.example.org", "250" },
        .{ "MAIL FROM:<sender@example.org>", "250" },
        .{ "RCPT TO:<recipient@example.com>", "250" },
        .{ "DATA", "354" },
        .{ "Subject: trace\r\n\r\nBody\r\n.", "250" },
    }) |step| {
        const resp = try pair.client.sendAndRead(step[0]);
        defer testing.allocator.free(resp);
        try SmtpTestClient.expectCode(resp, step[1]);
    }
    const quit = try pair.client.sendAndRead("QUIT");
    testing.allocator.free(quit);

    const messages = try pair.delivered(testing.allocator, "recipient");
    defer {
        for (messages) |m| testing.allocator.free(m);
        testing.allocator.free(messages);
    }
    try testing.expectEqual(@as(usize, 1), messages.len);
    // A Received line on top naming the client (from) and this server (by).
    try testing.expect(std.mem.startsWith(u8, messages[0], "Received: from client.example.org"));
    try testing.expect(std.mem.indexOf(u8, messages[0], "by " ++ Server.hostname) != null);
}

// RFC 5321 Section 6.1 - Reliability
test "RFC 5321 Section 6.1: Multiple recipients in one transaction" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);
    const ehlo = try pair.client.sendAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo);
    const mail = try pair.client.sendAndRead("MAIL FROM:<sender@example.com>");
    defer testing.allocator.free(mail);

    // Add multiple recipients
    const rcpt1 = try pair.client.sendAndRead("RCPT TO:<recipient1@example.com>");
    defer testing.allocator.free(rcpt1);
    try SmtpTestClient.expectCode(rcpt1, "250");

    const rcpt2 = try pair.client.sendAndRead("RCPT TO:<recipient2@example.com>");
    defer testing.allocator.free(rcpt2);
    try SmtpTestClient.expectCode(rcpt2, "250");

    const rcpt3 = try pair.client.sendAndRead("RCPT TO:<recipient3@example.com>");
    defer testing.allocator.free(rcpt3);
    try SmtpTestClient.expectCode(rcpt3, "250");
}

// RFC 5321 Section 7.1 - Timeouts
test "RFC 5321 Section 7.1: Connection remains open during valid session" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);
    const ehlo = try pair.client.sendAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo);

    // Brief pause
    const ts = std.c.timespec{ .sec = 0, .nsec = 50_000_000 };
    _ = std.c.nanosleep(&ts, null);

    // Connection should still work
    const noop_resp = try pair.client.sendAndRead("NOOP");
    defer testing.allocator.free(noop_resp);
    try SmtpTestClient.expectCode(noop_resp, "250");
}

// RFC 5321 Section 7.3 - Retry Strategies
test "RFC 5321 Section 7.3: Server handles multiple transactions in one connection" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);
    const ehlo = try pair.client.sendAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo);

    // First transaction
    const mail1 = try pair.client.sendAndRead("MAIL FROM:<sender1@example.com>");
    defer testing.allocator.free(mail1);
    try SmtpTestClient.expectCode(mail1, "250");
    const rset = try pair.client.sendAndRead("RSET");
    defer testing.allocator.free(rset);

    // Second transaction
    const mail_resp = try pair.client.sendAndRead("MAIL FROM:<sender2@example.com>");
    defer testing.allocator.free(mail_resp);
    try SmtpTestClient.expectCode(mail_resp, "250");
}

// RFC 5321 Section 8 - Security Considerations
test "RFC 5321 Section 8: Server rejects invalid commands" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);
    const ehlo = try pair.client.sendAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo);

    // Invalid command
    const response = try pair.client.sendAndRead("INVALID COMMAND");
    defer testing.allocator.free(response);

    try SmtpTestClient.expectCode(response, "500");
}

// RFC 5321 Section 9 - SIZE parameter
test "RFC 5321: SIZE parameter in MAIL FROM" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);
    const ehlo_resp = try pair.client.sendAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo_resp);

    // Check if SIZE is advertised
    try testing.expect(std.mem.indexOf(u8, ehlo_resp, "SIZE") != null);

    // SIZE is supported, test MAIL FROM with SIZE parameter
    const mail_resp = try pair.client.sendAndRead("MAIL FROM:<test@example.com> SIZE=1024");
    defer testing.allocator.free(mail_resp);

    try SmtpTestClient.expectCode(mail_resp, "250");
}

// Complete mail transaction test
test "RFC 5321: Complete mail transaction" {
    var pair = try TestPair.create(testing.allocator);
    defer pair.deinit();

    // Greeting
    const greeting = try pair.client.readResponse();
    defer testing.allocator.free(greeting);
    try SmtpTestClient.expectCode(greeting, "220");

    // EHLO
    const ehlo = try pair.client.sendAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo);
    try SmtpTestClient.expectCode(ehlo, "250");

    // MAIL FROM
    const mail = try pair.client.sendAndRead("MAIL FROM:<sender@example.com>");
    defer testing.allocator.free(mail);
    try SmtpTestClient.expectCode(mail, "250");

    // RCPT TO
    const rcpt = try pair.client.sendAndRead("RCPT TO:<recipient@example.com>");
    defer testing.allocator.free(rcpt);
    try SmtpTestClient.expectCode(rcpt, "250");

    // DATA
    const data = try pair.client.sendAndRead("DATA");
    defer testing.allocator.free(data);
    try SmtpTestClient.expectCode(data, "354");

    // Message body terminated by <CR><LF>.<CR><LF>
    const result = try pair.client.sendAndRead("From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nBody\r\n.");
    defer testing.allocator.free(result);
    try SmtpTestClient.expectCode(result, "250");

    // QUIT
    const quit = try pair.client.sendAndRead("QUIT");
    defer testing.allocator.free(quit);
    try SmtpTestClient.expectCode(quit, "221");
}
