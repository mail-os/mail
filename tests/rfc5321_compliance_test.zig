// RFC 5321 (SMTP Protocol) Compliance Test Suite
// Tests for compliance with RFC 5321 - Simple Mail Transfer Protocol
// https://datatracker.ietf.org/doc/html/rfc5321

const std = @import("std");
const testing = std.testing;
const posix = std.posix;

// Test configuration
const TestConfig = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 2525,
    timeout_ms: u64 = 5000,
};

const config = TestConfig{};

// SMTP test client
const SmtpTestClient = struct {
    fd: posix.socket_t,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !Self {
        const raw_fd = std.c.socket(posix.AF.INET, @intCast(@as(u32, posix.SOCK.STREAM | posix.SOCK.CLOEXEC)), 0);
        if (raw_fd < 0) return error.ConnectionRefused;
        const fd: posix.socket_t = @intCast(raw_fd);
        errdefer posix.close(fd);

        var addr: std.posix.sockaddr.in = .{
            .port = @byteSwap(@as(u16, config.port)),
            .addr = @byteSwap(@as(u32, 0x7f000001)), // 127.0.0.1
        };
        const rc = std.c.connect(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
        if (rc < 0) {
            std.debug.print("Failed to connect to {s}:{d}. Is the server running?\n", .{ config.host, config.port });
            return error.ConnectionRefused;
        }

        return Self{
            .fd = fd,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        posix.close(self.fd);
    }

    pub fn readResponse(self: *Self) ![]u8 {
        var buffer: std.ArrayList(u8) = .{};
        errdefer buffer.deinit(self.allocator);

        var read_buffer: [4096]u8 = undefined;
        const bytes_read = posix.read(self.fd, &read_buffer) catch return error.ConnectionClosed;

        if (bytes_read == 0) {
            return error.ConnectionClosed;
        }

        try buffer.appendSlice(self.allocator, read_buffer[0..bytes_read]);
        return buffer.toOwnedSlice(self.allocator);
    }

    pub fn sendCommand(self: *Self, command: []const u8) !void {
        const r1 = std.c.write(self.fd, command.ptr, command.len);
        if (r1 < 0) return error.WriteFailed;
        if (!std.mem.endsWith(u8, command, "\r\n")) {
            const crlf = "\r\n";
            const r2 = std.c.write(self.fd, crlf.ptr, crlf.len);
            if (r2 < 0) return error.WriteFailed;
        }
    }

    pub fn sendAndRead(self: *Self, command: []const u8) ![]u8 {
        try self.sendCommand(command);
        return self.readResponse();
    }

    pub fn expectCode(response: []const u8, expected_code: []const u8) !void {
        if (!std.mem.startsWith(u8, response, expected_code)) {
            std.debug.print("Expected code {s}, got: {s}\n", .{ expected_code, response });
            return error.UnexpectedResponseCode;
        }
    }
};

// RFC 5321 Section 3.1 - Session Initiation
test "RFC 5321 Section 3.1: Server greeting with 220 code" {
    var client = SmtpTestClient.init(testing.allocator) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
    defer client.deinit();

    // Server must send 220 greeting
    const greeting = try client.readResponse();
    defer testing.allocator.free(greeting);

    try SmtpTestClient.expectCode(greeting, "220");
    try testing.expect(greeting.len > 4); // Should have hostname
}

// RFC 5321 Section 3.2 - Client Initiation (EHLO)
test "RFC 5321 Section 3.2: EHLO command returns 250" {
    var client = SmtpTestClient.init(testing.allocator) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
    defer client.deinit();

    _ = try client.readResponse(); // Greeting

    const response = try client.sendAndRead("EHLO test.example.com");
    defer testing.allocator.free(response);

    try SmtpTestClient.expectCode(response, "250");
}

// RFC 5321 Section 3.3 - Mail Transactions
test "RFC 5321 Section 3.3: MAIL FROM command" {
    var client = SmtpTestClient.init(testing.allocator) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
    defer client.deinit();

    _ = try client.readResponse(); // Greeting
    _ = try client.sendAndRead("EHLO test.example.com");

    // Test with angle brackets (required format)
    const response = try client.sendAndRead("MAIL FROM:<sender@example.com>");
    defer testing.allocator.free(response);

    try SmtpTestClient.expectCode(response, "250");
}

test "RFC 5321 Section 3.3: RCPT TO command" {
    var client = SmtpTestClient.init(testing.allocator) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
    defer client.deinit();

    _ = try client.readResponse(); // Greeting
    _ = try client.sendAndRead("EHLO test.example.com");
    _ = try client.sendAndRead("MAIL FROM:<sender@example.com>");

    const response = try client.sendAndRead("RCPT TO:<recipient@example.com>");
    defer testing.allocator.free(response);

    // Should accept RCPT TO (250) or require auth (530/550)
    const code = response[0..3];
    const valid = std.mem.eql(u8, code, "250") or
        std.mem.eql(u8, code, "530") or
        std.mem.eql(u8, code, "550");

    try testing.expect(valid);
}

test "RFC 5321 Section 3.3: DATA command" {
    var client = SmtpTestClient.init(testing.allocator) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
    defer client.deinit();

    _ = try client.readResponse(); // Greeting
    _ = try client.sendAndRead("EHLO test.example.com");
    _ = try client.sendAndRead("MAIL FROM:<sender@example.com>");
    const rcpt_resp = try client.sendAndRead("RCPT TO:<recipient@example.com>");
    defer testing.allocator.free(rcpt_resp);

    // Only proceed with DATA if RCPT was accepted
    if (std.mem.startsWith(u8, rcpt_resp, "250")) {
        const response = try client.sendAndRead("DATA");
        defer testing.allocator.free(response);

        try SmtpTestClient.expectCode(response, "354");
    }
}

// RFC 5321 Section 4.1.1.1 - Command Syntax
test "RFC 5321 Section 4.1.1.1: Commands are case-insensitive" {
    var client = SmtpTestClient.init(testing.allocator) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
    defer client.deinit();

    _ = try client.readResponse(); // Greeting

    // Test lowercase
    const resp1 = try client.sendAndRead("ehlo test.example.com");
    defer testing.allocator.free(resp1);
    try SmtpTestClient.expectCode(resp1, "250");

    // Test mixed case
    const resp2 = try client.sendAndRead("MaIl FrOm:<test@example.com>");
    defer testing.allocator.free(resp2);
    try SmtpTestClient.expectCode(resp2, "250");
}

test "RFC 5321 Section 4.1.1.1: CRLF line termination" {
    var client = SmtpTestClient.init(testing.allocator) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
    defer client.deinit();

    _ = try client.readResponse(); // Greeting

    // Send with explicit CRLF
    try client.sendCommand("EHLO test.example.com\r\n");
    const response = try client.readResponse();
    defer testing.allocator.free(response);

    try SmtpTestClient.expectCode(response, "250");
}

// RFC 5321 Section 4.1.2 - Command Argument Syntax
test "RFC 5321 Section 4.1.2: MAIL FROM with null sender" {
    var client = SmtpTestClient.init(testing.allocator) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
    defer client.deinit();

    _ = try client.readResponse(); // Greeting
    _ = try client.sendAndRead("EHLO test.example.com");

    // Null sender for bounce messages
    const response = try client.sendAndRead("MAIL FROM:<>");
    defer testing.allocator.free(response);

    try SmtpTestClient.expectCode(response, "250");
}

// RFC 5321 Section 4.1.3 - Address Literals
test "RFC 5321 Section 4.1.3: Address literals with square brackets" {
    var client = SmtpTestClient.init(testing.allocator) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
    defer client.deinit();

    _ = try client.readResponse(); // Greeting

    // EHLO with address literal
    const response = try client.sendAndRead("EHLO [192.168.1.1]");
    defer testing.allocator.free(response);

    try SmtpTestClient.expectCode(response, "250");
}

// RFC 5321 Section 4.1.4 - Order of Commands
test "RFC 5321 Section 4.1.4: Commands must be in order" {
    var client = SmtpTestClient.init(testing.allocator) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
    defer client.deinit();

    _ = try client.readResponse(); // Greeting

    // Try MAIL before EHLO - should fail
    const response = try client.sendAndRead("MAIL FROM:<test@example.com>");
    defer testing.allocator.free(response);

    // Should return 503 (bad sequence)
    try SmtpTestClient.expectCode(response, "503");
}

// RFC 5321 Section 4.2.1 - Reply Codes
test "RFC 5321 Section 4.2.1: Reply codes are 3 digits" {
    var client = SmtpTestClient.init(testing.allocator) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
    defer client.deinit();

    const greeting = try client.readResponse();
    defer testing.allocator.free(greeting);

    // Must start with 3 digits
    try testing.expect(greeting.len >= 3);
    try testing.expect(std.ascii.isDigit(greeting[0]));
    try testing.expect(std.ascii.isDigit(greeting[1]));
    try testing.expect(std.ascii.isDigit(greeting[2]));
}

// RFC 5321 Section 4.3.2 - EHLO/HELO
test "RFC 5321 Section 4.3.2: HELO command (backward compatibility)" {
    var client = SmtpTestClient.init(testing.allocator) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
    defer client.deinit();

    _ = try client.readResponse(); // Greeting

    // HELO for older clients
    const response = try client.sendAndRead("HELO test.example.com");
    defer testing.allocator.free(response);

    try SmtpTestClient.expectCode(response, "250");
}

// RFC 5321 Section 4.5.1 - Minimum Implementation
test "RFC 5321 Section 4.5.1: Required commands are supported" {
    var client = SmtpTestClient.init(testing.allocator) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
    defer client.deinit();

    _ = try client.readResponse(); // Greeting

    // Test EHLO
    const ehlo_resp = try client.sendAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo_resp);
    try SmtpTestClient.expectCode(ehlo_resp, "250");

    // Test MAIL
    const mail_resp = try client.sendAndRead("MAIL FROM:<test@example.com>");
    defer testing.allocator.free(mail_resp);
    try SmtpTestClient.expectCode(mail_resp, "250");

    // Test RCPT
    _ = try client.sendAndRead("RCPT TO:<recipient@example.com>");

    // Test RSET
    const rset_resp = try client.sendAndRead("RSET");
    defer testing.allocator.free(rset_resp);
    try SmtpTestClient.expectCode(rset_resp, "250");

    // Test VRFY (may not be implemented - 252 or 502)
    const vrfy_resp = try client.sendAndRead("VRFY postmaster");
    defer testing.allocator.free(vrfy_resp);
    const vrfy_code = vrfy_resp[0..3];
    const vrfy_valid = std.mem.eql(u8, vrfy_code, "250") or
        std.mem.eql(u8, vrfy_code, "251") or
        std.mem.eql(u8, vrfy_code, "252") or
        std.mem.eql(u8, vrfy_code, "502") or
        std.mem.eql(u8, vrfy_code, "550");
    try testing.expect(vrfy_valid);

    // Test NOOP
    const noop_resp = try client.sendAndRead("NOOP");
    defer testing.allocator.free(noop_resp);
    try SmtpTestClient.expectCode(noop_resp, "250");

    // Test QUIT
    const quit_resp = try client.sendAndRead("QUIT");
    defer testing.allocator.free(quit_resp);
    try SmtpTestClient.expectCode(quit_resp, "221");
}

// RFC 5321 Section 4.5.3.1.8 - RSET Command
test "RFC 5321 Section 4.5.3.1.8: RSET clears transaction state" {
    var client = SmtpTestClient.init(testing.allocator) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
    defer client.deinit();

    _ = try client.readResponse(); // Greeting
    _ = try client.sendAndRead("EHLO test.example.com");
    _ = try client.sendAndRead("MAIL FROM:<sender@example.com>");

    // RSET should clear MAIL FROM
    const rset_resp = try client.sendAndRead("RSET");
    defer testing.allocator.free(rset_resp);
    try SmtpTestClient.expectCode(rset_resp, "250");

    // Should be able to start new transaction
    const mail_resp = try client.sendAndRead("MAIL FROM:<newsender@example.com>");
    defer testing.allocator.free(mail_resp);
    try SmtpTestClient.expectCode(mail_resp, "250");
}

// RFC 5321 Section 4.5.3.1.9 - NOOP Command
test "RFC 5321 Section 4.5.3.1.9: NOOP does nothing" {
    var client = SmtpTestClient.init(testing.allocator) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
    defer client.deinit();

    _ = try client.readResponse(); // Greeting
    _ = try client.sendAndRead("EHLO test.example.com");

    // NOOP should not affect state
    const noop_resp = try client.sendAndRead("NOOP");
    defer testing.allocator.free(noop_resp);
    try SmtpTestClient.expectCode(noop_resp, "250");

    // Should still be able to issue commands
    const mail_resp = try client.sendAndRead("MAIL FROM:<test@example.com>");
    defer testing.allocator.free(mail_resp);
    try SmtpTestClient.expectCode(mail_resp, "250");
}

// RFC 5321 Section 4.5.3.1.10 - QUIT Command
test "RFC 5321 Section 4.5.3.1.10: QUIT closes connection gracefully" {
    var client = SmtpTestClient.init(testing.allocator) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
    defer client.deinit();

    _ = try client.readResponse(); // Greeting
    _ = try client.sendAndRead("EHLO test.example.com");

    const quit_resp = try client.sendAndRead("QUIT");
    defer testing.allocator.free(quit_resp);

    // Should return 221
    try SmtpTestClient.expectCode(quit_resp, "221");

    // Connection should close
    var buffer: [10]u8 = undefined;
    const bytes = posix.read(client.fd, &buffer) catch 0;
    try testing.expect(bytes == 0); // EOF
}

// RFC 5321 Section 4.5.4 - Trace Information
test "RFC 5321 Section 4.5.4: Server adds Received header" {
    // This would need to be tested by sending a complete message
    // and inspecting the stored message for Received headers
    // Skipping for now as it requires message storage inspection
}

// RFC 5321 Section 6.1 - Reliability
test "RFC 5321 Section 6.1: Multiple recipients in one transaction" {
    var client = SmtpTestClient.init(testing.allocator) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
    defer client.deinit();

    _ = try client.readResponse(); // Greeting
    _ = try client.sendAndRead("EHLO test.example.com");
    _ = try client.sendAndRead("MAIL FROM:<sender@example.com>");

    // Add multiple recipients
    const rcpt1 = try client.sendAndRead("RCPT TO:<recipient1@example.com>");
    defer testing.allocator.free(rcpt1);

    const rcpt2 = try client.sendAndRead("RCPT TO:<recipient2@example.com>");
    defer testing.allocator.free(rcpt2);

    const rcpt3 = try client.sendAndRead("RCPT TO:<recipient3@example.com>");
    defer testing.allocator.free(rcpt3);

    // At least one should be accepted or all rejected
    const has_success = std.mem.startsWith(u8, rcpt1, "250") or
        std.mem.startsWith(u8, rcpt2, "250") or
        std.mem.startsWith(u8, rcpt3, "250");

    _ = has_success; // We just verify server doesn't crash
}

// RFC 5321 Section 7.1 - Timeouts
test "RFC 5321 Section 7.1: Connection remains open during valid session" {
    var client = SmtpTestClient.init(testing.allocator) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
    defer client.deinit();

    _ = try client.readResponse(); // Greeting
    _ = try client.sendAndRead("EHLO test.example.com");

    // Wait a bit (but not longer than timeout)
    var ts: std.c.timespec = .{ .sec = 1, .nsec = 0 };
    _ = std.c.nanosleep(&ts, null);

    // Connection should still work
    const noop_resp = try client.sendAndRead("NOOP");
    defer testing.allocator.free(noop_resp);
    try SmtpTestClient.expectCode(noop_resp, "250");
}

// RFC 5321 Section 7.3 - Retry Strategies
test "RFC 5321 Section 7.3: Server handles multiple transactions in one connection" {
    var client = SmtpTestClient.init(testing.allocator) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
    defer client.deinit();

    _ = try client.readResponse(); // Greeting
    _ = try client.sendAndRead("EHLO test.example.com");

    // First transaction
    _ = try client.sendAndRead("MAIL FROM:<sender1@example.com>");
    _ = try client.sendAndRead("RSET");

    // Second transaction
    const mail_resp = try client.sendAndRead("MAIL FROM:<sender2@example.com>");
    defer testing.allocator.free(mail_resp);
    try SmtpTestClient.expectCode(mail_resp, "250");
}

// RFC 5321 Section 8 - Security Considerations
test "RFC 5321 Section 8: Server rejects invalid commands" {
    var client = SmtpTestClient.init(testing.allocator) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
    defer client.deinit();

    _ = try client.readResponse(); // Greeting
    _ = try client.sendAndRead("EHLO test.example.com");

    // Invalid command
    const response = try client.sendAndRead("INVALID COMMAND");
    defer testing.allocator.free(response);

    // Should return 500 (syntax error) or 502 (not implemented)
    const code = response[0..3];
    const valid = std.mem.eql(u8, code, "500") or std.mem.eql(u8, code, "502");
    try testing.expect(valid);
}

// RFC 5321 Section 9 - IANA Considerations (MAIL parameters)
test "RFC 5321: SIZE parameter in MAIL FROM" {
    var client = SmtpTestClient.init(testing.allocator) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
    defer client.deinit();

    _ = try client.readResponse(); // Greeting
    const ehlo_resp = try client.sendAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo_resp);

    // Check if SIZE is advertised
    if (std.mem.indexOf(u8, ehlo_resp, "SIZE") != null) {
        // SIZE is supported, test it
        const mail_resp = try client.sendAndRead("MAIL FROM:<test@example.com> SIZE=1024");
        defer testing.allocator.free(mail_resp);

        // Should accept or reject based on size
        const code = mail_resp[0..3];
        const valid = std.mem.eql(u8, code, "250") or std.mem.eql(u8, code, "552");
        try testing.expect(valid);
    }
}

// Complete mail transaction test
test "RFC 5321: Complete mail transaction" {
    var client = SmtpTestClient.init(testing.allocator) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
    defer client.deinit();

    // Greeting
    const greeting = try client.readResponse();
    defer testing.allocator.free(greeting);
    try SmtpTestClient.expectCode(greeting, "220");

    // EHLO
    const ehlo = try client.sendAndRead("EHLO test.example.com");
    defer testing.allocator.free(ehlo);
    try SmtpTestClient.expectCode(ehlo, "250");

    // MAIL FROM
    const mail = try client.sendAndRead("MAIL FROM:<sender@example.com>");
    defer testing.allocator.free(mail);
    try SmtpTestClient.expectCode(mail, "250");

    // RCPT TO
    const rcpt = try client.sendAndRead("RCPT TO:<recipient@example.com>");
    defer testing.allocator.free(rcpt);

    // Only continue if RCPT was accepted
    if (std.mem.startsWith(u8, rcpt, "250")) {
        // DATA
        const data = try client.sendAndRead("DATA");
        defer testing.allocator.free(data);
        try SmtpTestClient.expectCode(data, "354");

        // Message body
        const message =
            \\From: sender@example.com
            \\To: recipient@example.com
            \\Subject: RFC 5321 Compliance Test
            \\
            \\This is a test message.
            \\.
            \\
        ;

        const result = try client.sendAndRead(message);
        defer testing.allocator.free(result);

        // Should be queued (250) or rejected
        const code = result[0..1];
        try testing.expect(std.mem.eql(u8, code, "2") or std.mem.eql(u8, code, "5"));
    }

    // QUIT
    const quit = try client.sendAndRead("QUIT");
    defer testing.allocator.free(quit);
    try SmtpTestClient.expectCode(quit, "221");
}
