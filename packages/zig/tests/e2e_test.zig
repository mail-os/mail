const std = @import("std");
const testing = std.testing;
const repeat = @import("test_util.zig").repeat;

// End-to-end tests for the SMTP server: a real `mail serve` process, spoken
// to over TCP.
//
// They need a running server and are skipped without one. Point them at it
// with MAIL_E2E_SMTP=<ipv4>:<port>; CI starts one in trap mode (every
// recipient accepted and filed into one mailbox) and runs `zig build
// test-e2e` against it. Once MAIL_E2E_SMTP is set, a server that cannot be
// reached is a failure, not a skip.

const SmtpClient = struct {
    fd: c_int,
    allocator: std.mem.Allocator,

    /// Connect to the server named by MAIL_E2E_SMTP, or skip the test.
    pub fn connect(allocator: std.mem.Allocator) !SmtpClient {
        const target_z = std.c.getenv("MAIL_E2E_SMTP") orelse return error.SkipZigTest;
        const target = std.mem.sliceTo(target_z, 0);
        const colon = std.mem.lastIndexOfScalar(u8, target, ':') orelse return error.InvalidE2ETarget;
        const port = try std.fmt.parseInt(u16, target[colon + 1 ..], 10);

        var ip: [4]u8 = undefined;
        var parts = std.mem.splitScalar(u8, target[0..colon], '.');
        for (&ip) |*octet| octet.* = try std.fmt.parseInt(u8, parts.next() orelse return error.InvalidE2ETarget, 10);

        const fd = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, 0);
        if (fd < 0) return error.SocketFailed;
        errdefer _ = std.c.close(fd);

        var addr = std.mem.zeroes(std.c.sockaddr.in);
        addr.family = std.c.AF.INET;
        addr.port = std.mem.nativeToBig(u16, port);
        addr.addr = @bitCast(ip);
        if (std.c.connect(fd, @ptrCast(&addr), @sizeOf(std.c.sockaddr.in)) != 0) return error.ConnectionRefused;

        return .{ .fd = fd, .allocator = allocator };
    }

    pub fn deinit(self: *SmtpClient) void {
        _ = std.c.close(self.fd);
    }

    /// Read one complete reply, multi-line replies included.
    pub fn readResponse(self: *SmtpClient) ![]u8 {
        return self.readReplies(1);
    }

    /// Read `count` complete replies (e.g. the answers to pipelined commands).
    pub fn readReplies(self: *SmtpClient, count: usize) ![]u8 {
        var buffer: std.ArrayList(u8) = .empty;
        errdefer buffer.deinit(self.allocator);

        var read_buffer: [4096]u8 = undefined;
        while (completeReplies(buffer.items) < count) {
            const n = std.c.read(self.fd, &read_buffer, read_buffer.len);
            if (n <= 0) return error.ConnectionClosed;
            try buffer.appendSlice(self.allocator, read_buffer[0..@intCast(n)]);
        }
        return buffer.toOwnedSlice(self.allocator);
    }

    /// Replies are complete at each CRLF-terminated "NNN " line.
    fn completeReplies(data: []const u8) usize {
        var n: usize = 0;
        var it = std.mem.splitSequence(u8, data, "\r\n");
        while (it.next()) |line| {
            if (it.index == null) break; // unterminated tail
            if (line.len >= 4 and line[3] == ' ') n += 1;
        }
        return n;
    }

    /// Send a command, or a message body. SMTP lines end in CRLF, so a bare
    /// LF (the multiline string literals below have those) is sent as CRLF,
    /// as any real client would.
    pub fn sendCommand(self: *SmtpClient, command: []const u8) !void {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.allocator);
        for (command, 0..) |c, i| {
            if (c == '\n' and (i == 0 or command[i - 1] != '\r')) try out.append(self.allocator, '\r');
            try out.append(self.allocator, c);
        }
        if (!std.mem.endsWith(u8, out.items, "\r\n")) try out.appendSlice(self.allocator, "\r\n");

        var off: usize = 0;
        while (off < out.items.len) {
            const n = std.c.write(self.fd, out.items[off..].ptr, out.items.len - off);
            if (n <= 0) return error.WriteFailed;
            off += @intCast(n);
        }
    }

    pub fn sendCommandAndRead(self: *SmtpClient, command: []const u8) ![]u8 {
        try self.sendCommand(command);
        return self.readResponse();
    }

    pub fn expectCode(_: *SmtpClient, response: []const u8, expected_code: []const u8) !void {
        if (!std.mem.startsWith(u8, response, expected_code)) {
            std.debug.print("Expected code {s}, got: {s}\n", .{ expected_code, response });
            return error.UnexpectedResponseCode;
        }
    }
};

test "E2E: Basic SMTP conversation" {
    var client = try SmtpClient.connect(testing.allocator);
    defer client.deinit();

    // Read greeting
    const greeting = try client.readResponse();
    defer testing.allocator.free(greeting);
    try client.expectCode(greeting, "220");

    // Send EHLO
    const ehlo_response = try client.sendCommandAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo_response);
    try client.expectCode(ehlo_response, "250");

    // Send QUIT
    const quit_response = try client.sendCommandAndRead("QUIT");
    defer testing.allocator.free(quit_response);
    try client.expectCode(quit_response, "221");
}

test "E2E: Send simple email without authentication" {
    var client = try SmtpClient.connect(testing.allocator);
    defer client.deinit();

    // Greeting
    const greeting = try client.readResponse();
    defer testing.allocator.free(greeting);
    try client.expectCode(greeting, "220");

    // EHLO
    const ehlo = try client.sendCommandAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo);
    try client.expectCode(ehlo, "250");

    // MAIL FROM
    const mail_from = try client.sendCommandAndRead("MAIL FROM:<sender@example.com>");
    defer testing.allocator.free(mail_from);
    try client.expectCode(mail_from, "250");

    // RCPT TO
    const rcpt_to = try client.sendCommandAndRead("RCPT TO:<recipient@example.com>");
    defer testing.allocator.free(rcpt_to);
    try client.expectCode(rcpt_to, "250");

    // DATA
    const data_cmd = try client.sendCommandAndRead("DATA");
    defer testing.allocator.free(data_cmd);
    try client.expectCode(data_cmd, "354");

    // Send message
    const message =
        \\From: sender@example.com
        \\To: recipient@example.com
        \\Subject: Test Email
        \\
        \\This is a test email.
        \\.
    ;
    const data_response = try client.sendCommandAndRead(message);
    defer testing.allocator.free(data_response);
    try client.expectCode(data_response, "250");

    // QUIT
    const quit = try client.sendCommandAndRead("QUIT");
    defer testing.allocator.free(quit);
    try client.expectCode(quit, "221");
}

test "E2E: Send email with authentication" {
    var client = try SmtpClient.connect(testing.allocator);
    defer client.deinit();

    // Greeting
    const greeting = try client.readResponse();
    defer testing.allocator.free(greeting);
    try client.expectCode(greeting, "220");

    // EHLO
    const ehlo = try client.sendCommandAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo);
    try client.expectCode(ehlo, "250");

    // AUTH PLAIN (base64 encoded: \0testuser\0testpass)
    const auth = try client.sendCommandAndRead("AUTH PLAIN AHRlc3R1c2VyAHRlc3RwYXNz");
    defer testing.allocator.free(auth);
    // Server might accept (235) or reject (535) depending on database state
    // Just check we get a valid response
    try testing.expect(std.mem.startsWith(u8, auth, "235") or std.mem.startsWith(u8, auth, "535"));

    // QUIT
    const quit = try client.sendCommandAndRead("QUIT");
    defer testing.allocator.free(quit);
    try client.expectCode(quit, "221");
}

test "E2E: PIPELINING support" {
    var client = try SmtpClient.connect(testing.allocator);
    defer client.deinit();

    // Greeting
    const greeting = try client.readResponse();
    defer testing.allocator.free(greeting);
    try client.expectCode(greeting, "220");

    // EHLO
    const ehlo = try client.sendCommandAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo);
    try client.expectCode(ehlo, "250");

    // Check if PIPELINING is advertised
    try testing.expect(std.mem.indexOf(u8, ehlo, "PIPELINING") != null);

    // Send pipelined commands
    try client.sendCommand("MAIL FROM:<sender@example.com>");
    try client.sendCommand("RCPT TO:<recipient@example.com>");
    try client.sendCommand("DATA");

    // Read all three responses
    const responses = try client.readReplies(3);
    defer testing.allocator.free(responses);

    // Should contain multiple 250 responses and one 354
    try testing.expect(std.mem.indexOf(u8, responses, "250") != null);
    try testing.expect(std.mem.indexOf(u8, responses, "354") != null);

    // Send message
    const message =
        \\From: sender@example.com
        \\To: recipient@example.com
        \\Subject: Pipelined Email
        \\
        \\This is a pipelined test email.
        \\.
    ;
    const data_response = try client.sendCommandAndRead(message);
    defer testing.allocator.free(data_response);
    try client.expectCode(data_response, "250");

    // QUIT
    const quit = try client.sendCommandAndRead("QUIT");
    defer testing.allocator.free(quit);
    try client.expectCode(quit, "221");
}

test "E2E: SIZE extension" {
    var client = try SmtpClient.connect(testing.allocator);
    defer client.deinit();

    // Greeting
    const greeting = try client.readResponse();
    defer testing.allocator.free(greeting);
    try client.expectCode(greeting, "220");

    // EHLO
    const ehlo = try client.sendCommandAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo);
    try client.expectCode(ehlo, "250");

    // Check if SIZE is advertised
    try testing.expect(std.mem.indexOf(u8, ehlo, "SIZE") != null);

    // MAIL FROM with SIZE parameter
    const mail_from = try client.sendCommandAndRead("MAIL FROM:<sender@example.com> SIZE=1000");
    defer testing.allocator.free(mail_from);
    try client.expectCode(mail_from, "250");

    // RCPT TO
    const rcpt_to = try client.sendCommandAndRead("RCPT TO:<recipient@example.com>");
    defer testing.allocator.free(rcpt_to);
    try client.expectCode(rcpt_to, "250");

    // RSET to reset
    const rset = try client.sendCommandAndRead("RSET");
    defer testing.allocator.free(rset);
    try client.expectCode(rset, "250");

    // QUIT
    const quit = try client.sendCommandAndRead("QUIT");
    defer testing.allocator.free(quit);
    try client.expectCode(quit, "221");
}

test "E2E: Error handling - invalid commands" {
    var client = try SmtpClient.connect(testing.allocator);
    defer client.deinit();

    // Greeting
    const greeting = try client.readResponse();
    defer testing.allocator.free(greeting);
    try client.expectCode(greeting, "220");

    // Send invalid command
    const invalid = try client.sendCommandAndRead("INVALID COMMAND");
    defer testing.allocator.free(invalid);
    try client.expectCode(invalid, "500"); // Command not recognized

    // Send DATA before MAIL FROM
    const premature_data = try client.sendCommandAndRead("DATA");
    defer testing.allocator.free(premature_data);
    try client.expectCode(premature_data, "503"); // Bad sequence

    // QUIT should still work
    const quit = try client.sendCommandAndRead("QUIT");
    defer testing.allocator.free(quit);
    try client.expectCode(quit, "221");
}

test "E2E: Multiple recipients" {
    var client = try SmtpClient.connect(testing.allocator);
    defer client.deinit();

    // Greeting
    const greeting = try client.readResponse();
    defer testing.allocator.free(greeting);
    try client.expectCode(greeting, "220");

    // EHLO
    const ehlo = try client.sendCommandAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo);
    try client.expectCode(ehlo, "250");

    // MAIL FROM
    const mail_from = try client.sendCommandAndRead("MAIL FROM:<sender@example.com>");
    defer testing.allocator.free(mail_from);
    try client.expectCode(mail_from, "250");

    // Multiple RCPT TO
    const rcpt1 = try client.sendCommandAndRead("RCPT TO:<recipient1@example.com>");
    defer testing.allocator.free(rcpt1);
    try client.expectCode(rcpt1, "250");

    const rcpt2 = try client.sendCommandAndRead("RCPT TO:<recipient2@example.com>");
    defer testing.allocator.free(rcpt2);
    try client.expectCode(rcpt2, "250");

    const rcpt3 = try client.sendCommandAndRead("RCPT TO:<recipient3@example.com>");
    defer testing.allocator.free(rcpt3);
    try client.expectCode(rcpt3, "250");

    // DATA
    const data_cmd = try client.sendCommandAndRead("DATA");
    defer testing.allocator.free(data_cmd);
    try client.expectCode(data_cmd, "354");

    // Send message
    const message =
        \\From: sender@example.com
        \\To: recipient1@example.com, recipient2@example.com, recipient3@example.com
        \\Subject: Multiple Recipients Test
        \\
        \\This email is sent to multiple recipients.
        \\.
    ;
    const data_response = try client.sendCommandAndRead(message);
    defer testing.allocator.free(data_response);
    try client.expectCode(data_response, "250");

    // QUIT
    const quit = try client.sendCommandAndRead("QUIT");
    defer testing.allocator.free(quit);
    try client.expectCode(quit, "221");
}

test "E2E: RSET command" {
    var client = try SmtpClient.connect(testing.allocator);
    defer client.deinit();

    // Greeting
    const greeting = try client.readResponse();
    defer testing.allocator.free(greeting);
    try client.expectCode(greeting, "220");

    // EHLO
    const ehlo = try client.sendCommandAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo);
    try client.expectCode(ehlo, "250");

    // Start transaction
    const mail_from = try client.sendCommandAndRead("MAIL FROM:<sender@example.com>");
    defer testing.allocator.free(mail_from);
    try client.expectCode(mail_from, "250");

    const rcpt_to = try client.sendCommandAndRead("RCPT TO:<recipient@example.com>");
    defer testing.allocator.free(rcpt_to);
    try client.expectCode(rcpt_to, "250");

    // Reset transaction
    const rset = try client.sendCommandAndRead("RSET");
    defer testing.allocator.free(rset);
    try client.expectCode(rset, "250");

    // Start new transaction
    const mail_from2 = try client.sendCommandAndRead("MAIL FROM:<newsender@example.com>");
    defer testing.allocator.free(mail_from2);
    try client.expectCode(mail_from2, "250");

    const rcpt_to2 = try client.sendCommandAndRead("RCPT TO:<newrecipient@example.com>");
    defer testing.allocator.free(rcpt_to2);
    try client.expectCode(rcpt_to2, "250");

    // QUIT
    const quit = try client.sendCommandAndRead("QUIT");
    defer testing.allocator.free(quit);
    try client.expectCode(quit, "221");
}

test "E2E: VRFY command" {
    var client = try SmtpClient.connect(testing.allocator);
    defer client.deinit();

    // Greeting
    const greeting = try client.readResponse();
    defer testing.allocator.free(greeting);
    try client.expectCode(greeting, "220");

    // EHLO
    const ehlo = try client.sendCommandAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo);
    try client.expectCode(ehlo, "250");

    // VRFY
    const vrfy = try client.sendCommandAndRead("VRFY user@example.com");
    defer testing.allocator.free(vrfy);
    // Server may return 250 (verified), 251 (will forward), or 252 (cannot verify)
    try testing.expect(
        std.mem.startsWith(u8, vrfy, "250") or
            std.mem.startsWith(u8, vrfy, "251") or
            std.mem.startsWith(u8, vrfy, "252") or
            std.mem.startsWith(u8, vrfy, "550"), // Not implemented
    );

    // QUIT
    const quit = try client.sendCommandAndRead("QUIT");
    defer testing.allocator.free(quit);
    try client.expectCode(quit, "221");
}

test "E2E: NOOP command" {
    var client = try SmtpClient.connect(testing.allocator);
    defer client.deinit();

    // Greeting
    const greeting = try client.readResponse();
    defer testing.allocator.free(greeting);
    try client.expectCode(greeting, "220");

    // EHLO
    const ehlo = try client.sendCommandAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo);
    try client.expectCode(ehlo, "250");

    // NOOP
    const noop = try client.sendCommandAndRead("NOOP");
    defer testing.allocator.free(noop);
    try client.expectCode(noop, "250");

    // QUIT
    const quit = try client.sendCommandAndRead("QUIT");
    defer testing.allocator.free(quit);
    try client.expectCode(quit, "221");
}

test "E2E: Case insensitivity of commands" {
    var client = try SmtpClient.connect(testing.allocator);
    defer client.deinit();

    // Greeting
    const greeting = try client.readResponse();
    defer testing.allocator.free(greeting);
    try client.expectCode(greeting, "220");

    // ehlo (lowercase)
    const ehlo = try client.sendCommandAndRead("ehlo test.example.com");
    defer testing.allocator.free(ehlo);
    try client.expectCode(ehlo, "250");

    // MaIl FrOm (mixed case)
    const mail_from = try client.sendCommandAndRead("MaIl FrOm:<sender@example.com>");
    defer testing.allocator.free(mail_from);
    try client.expectCode(mail_from, "250");

    // RcPt To (mixed case)
    const rcpt_to = try client.sendCommandAndRead("RcPt To:<recipient@example.com>");
    defer testing.allocator.free(rcpt_to);
    try client.expectCode(rcpt_to, "250");

    // rset (lowercase)
    const rset = try client.sendCommandAndRead("rset");
    defer testing.allocator.free(rset);
    try client.expectCode(rset, "250");

    // quit (lowercase)
    const quit = try client.sendCommandAndRead("quit");
    defer testing.allocator.free(quit);
    try client.expectCode(quit, "221");
}

test "E2E: a line far longer than 4096 bytes is accepted, and the session stays usable" {
    var client = try SmtpClient.connect(testing.allocator);
    defer client.deinit();

    const greeting = try client.readResponse();
    defer testing.allocator.free(greeting);
    try client.expectCode(greeting, "220");

    inline for (.{
        .{ "EHLO test.example.com", "250" },
        .{ "MAIL FROM:<sender@example.com>", "250" },
        .{ "RCPT TO:<recipient@example.com>", "250" },
        .{ "DATA", "354" },
        // One 20,000-character line: the server used to drop the connection
        // at 4096.
        .{ "Subject: long line\r\n\r\n" ++ repeat("x", 20_000) ++ "\r\n.", "250" },
        .{ "NOOP", "250" },
        .{ "QUIT", "221" },
    }) |step| {
        const reply = try client.sendCommandAndRead(step[0]);
        defer testing.allocator.free(reply);
        try client.expectCode(reply, step[1]);
    }
}
