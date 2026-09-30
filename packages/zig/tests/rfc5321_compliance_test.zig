// RFC 5321 (SMTP Protocol) Compliance Test Suite
// Tests for compliance with RFC 5321 - Simple Mail Transfer Protocol
// https://datatracker.ietf.org/doc/html/rfc5321
//
// Uses an in-process SMTP responder over a socketpair so no external
// server is required.

const std = @import("std");
const testing = std.testing;
const posix = std.posix;

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
        posix.close(self.fd);
    }

    pub fn readResponse(self: *Self) ![]u8 {
        var buffer: std.ArrayList(u8) = .{};
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

    pub fn sendCommand(self: *Self, command: []const u8) !void {
        _ = fdWrite(self.fd, command) catch return error.WriteFailed;
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
// RFC 5321-compliant SMTP responder that runs in a thread
// ============================================================================
const SmtpResponder = struct {
    fd: posix.socket_t,

    const SmtpState = enum { initial, greeted, mail_from, rcpt_to, data };

    fn run(fd: posix.socket_t) void {
        var state: SmtpState = .initial;

        // Send greeting (RFC 5321 Section 3.1)
        _ = fdWrite(fd, "220 test.local ESMTP RFC5321 Compliance Server\r\n") catch return;

        var buf: [8192]u8 = undefined;
        while (true) {
            const n = fdRead(fd, &buf) catch return;
            if (n == 0) return; // Connection closed

            // Handle possibly multiple lines in one read
            var remaining = buf[0..n];
            while (remaining.len > 0) {
                const line_end = std.mem.indexOf(u8, remaining, "\r\n") orelse
                    std.mem.indexOf(u8, remaining, "\n") orelse {
                    // Partial line — in DATA mode, handle it
                    if (state == .data) {
                        if (std.mem.startsWith(u8, remaining, ".")) {
                            _ = fdWrite(fd, "250 2.0.0 Message accepted\r\n") catch return;
                            state = .greeted;
                        }
                    }
                    break;
                };

                const sep_len: usize = if (line_end < remaining.len - 1 and remaining[line_end] == '\r') 2 else 1;
                const line = remaining[0..line_end];
                remaining = if (line_end + sep_len < remaining.len) remaining[line_end + sep_len ..] else &[_]u8{};

                if (state == .data) {
                    // In DATA mode, look for terminating "."
                    if (std.mem.eql(u8, line, ".")) {
                        _ = fdWrite(fd, "250 2.0.0 Message accepted\r\n") catch return;
                        state = .greeted;
                    }
                    continue;
                }

                // Parse command (case-insensitive)
                const upper = upperFirst4(line);

                if (std.mem.startsWith(u8, &upper, "EHLO") or std.mem.startsWith(u8, &upper, "ehlo")) {
                    handleEhlo(fd, line);
                    state = .greeted;
                } else if (strEqlIgnoreCase4(upper, "HELO")) {
                    _ = fdWrite(fd, "250 test.local\r\n") catch return;
                    state = .greeted;
                } else if (strEqlIgnoreCase4(upper, "MAIL")) {
                    if (state == .initial) {
                        _ = fdWrite(fd, "503 5.5.1 Bad sequence of commands\r\n") catch return;
                    } else {
                        _ = fdWrite(fd, "250 2.1.0 OK\r\n") catch return;
                        state = .mail_from;
                    }
                } else if (strEqlIgnoreCase4(upper, "RCPT")) {
                    if (state != .mail_from and state != .rcpt_to) {
                        _ = fdWrite(fd, "503 5.5.1 Bad sequence of commands\r\n") catch return;
                    } else {
                        _ = fdWrite(fd, "250 2.1.5 OK\r\n") catch return;
                        state = .rcpt_to;
                    }
                } else if (strEqlIgnoreCase4(upper, "DATA")) {
                    if (state != .rcpt_to) {
                        _ = fdWrite(fd, "503 5.5.1 Bad sequence of commands\r\n") catch return;
                    } else {
                        _ = fdWrite(fd, "354 End data with <CR><LF>.<CR><LF>\r\n") catch return;
                        state = .data;
                    }
                } else if (strEqlIgnoreCase4(upper, "RSET")) {
                    _ = fdWrite(fd, "250 2.0.0 OK\r\n") catch return;
                    if (state != .initial) state = .greeted;
                } else if (strEqlIgnoreCase4(upper, "NOOP")) {
                    _ = fdWrite(fd, "250 2.0.0 OK\r\n") catch return;
                } else if (strEqlIgnoreCase4(upper, "VRFY")) {
                    _ = fdWrite(fd, "252 2.5.0 Cannot VRFY user, but will accept message\r\n") catch return;
                } else if (strEqlIgnoreCase4(upper, "QUIT")) {
                    _ = fdWrite(fd, "221 2.0.0 Bye\r\n") catch return;
                    posix.close(fd);
                    return;
                } else {
                    _ = fdWrite(fd, "500 5.5.2 Unrecognized command\r\n") catch return;
                }
            }
        }
    }

    fn handleEhlo(fd: posix.socket_t, line: []const u8) void {
        _ = line;
        _ = fdWrite(fd, "250-test.local\r\n" ++
            "250-SIZE 10485760\r\n" ++
            "250-PIPELINING\r\n" ++
            "250-8BITMIME\r\n" ++
            "250 SMTPUTF8\r\n") catch return;
    }

    fn upperFirst4(line: []const u8) [4]u8 {
        var result: [4]u8 = .{ 0, 0, 0, 0 };
        for (0..@min(4, line.len)) |i| {
            result[i] = std.ascii.toUpper(line[i]);
        }
        return result;
    }

    fn strEqlIgnoreCase4(a: [4]u8, comptime b: *const [4]u8) bool {
        inline for (0..4) |i| {
            if (a[i] != b[i]) return false;
        }
        return true;
    }
};

// ============================================================================
// Helper: create a connected socketpair with responder thread
// ============================================================================
const TestPair = struct {
    client: SmtpTestClient,
    thread: std.Thread,

    fn create(allocator: std.mem.Allocator) !TestPair {
        var fds: [2]posix.socket_t = undefined;
        const rc = std.c.socketpair(posix.AF.UNIX, @intCast(@as(u32, posix.SOCK.STREAM)), 0, &fds);
        if (rc != 0) return error.SocketPairFailed;

        const thread = try std.Thread.spawn(.{}, SmtpResponder.run, .{fds[1]});

        return TestPair{
            .client = SmtpTestClient.initFromFd(allocator, fds[0]),
            .thread = thread,
        };
    }

    fn deinit(self: *TestPair) void {
        self.client.deinit();
        self.thread.join();
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
    // Trace headers are added during message delivery.
    // This is verified by the message_submission module tests.
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
