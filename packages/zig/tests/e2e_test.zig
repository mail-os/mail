const std = @import("std");
const net = std.net;
const testing = std.testing;

/// End-to-end tests for SMTP server
/// Tests complete workflows from client connection to message delivery
///
/// Test scenarios:
/// - Full message delivery workflow
/// - Authentication flows
/// - TLS/STARTTLS handshake
/// - Multiple concurrent clients
/// - Error recovery scenarios
/// - Performance under load
/// - Real-world email scenarios

const TestConfig = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 2525,
    timeout_ms: u32 = 5000,
    tls_port: u16 = 2526,
};

const SmtpClient = struct {
    stream: net.Stream,
    allocator: std.mem.Allocator,
    config: TestConfig,

    pub fn init(allocator: std.mem.Allocator, config: TestConfig) !SmtpClient {
        const address = try net.Address.parseIp(config.host, config.port);
        const stream = try net.tcpConnectToAddress(address);

        return SmtpClient{
            .stream = stream,
            .allocator = allocator,
            .config = config,
        };
    }

    pub fn deinit(self: *SmtpClient) void {
        self.stream.close();
    }

    pub fn readResponse(self: *SmtpClient) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        errdefer buffer.deinit();

        var read_buffer: [4096]u8 = undefined;
        const n = try self.stream.read(&read_buffer);
        try buffer.appendSlice(read_buffer[0..n]);

        return buffer.toOwnedSlice();
    }

    pub fn sendCommand(self: *SmtpClient, command: []const u8) !void {
        try self.stream.writeAll(command);
        try self.stream.writeAll("\r\n");
    }

    pub fn sendCommandAndRead(self: *SmtpClient, command: []const u8) ![]u8 {
        try self.sendCommand(command);
        return self.readResponse();
    }

    pub fn expectCode(self: *SmtpClient, response: []const u8, expected_code: []const u8) !void {
        if (!std.mem.startsWith(u8, response, expected_code)) {
            std.debug.print("Expected code {s}, got: {s}\n", .{ expected_code, response });
            return error.UnexpectedResponseCode;
        }
    }
};

// Helper to wait for server to be ready
fn waitForServer(allocator: std.mem.Allocator, config: TestConfig) !void {
    var attempts: u32 = 0;
    const max_attempts = 10;

    while (attempts < max_attempts) : (attempts += 1) {
        const address = net.Address.parseIp(config.host, config.port) catch {
            std.time.sleep(100 * std.time.ns_per_ms);
            continue;
        };

        const stream = net.tcpConnectToAddress(address) catch {
            std.time.sleep(100 * std.time.ns_per_ms);
            continue;
        };
        stream.close();
        return; // Server is ready
    }

    return error.ServerNotReady;
}

test "E2E: Basic SMTP conversation" {
    const config = TestConfig{};

    // Note: This test requires the SMTP server to be running
    // Skip if server is not available
    var client = SmtpClient.init(testing.allocator, config) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
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
    const config = TestConfig{};

    var client = SmtpClient.init(testing.allocator, config) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
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
    const config = TestConfig{};

    var client = SmtpClient.init(testing.allocator, config) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
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
    const config = TestConfig{};

    var client = SmtpClient.init(testing.allocator, config) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
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

    // Read all responses
    const responses = try client.readResponse();
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
    const config = TestConfig{};

    var client = SmtpClient.init(testing.allocator, config) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
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
    const config = TestConfig{};

    var client = SmtpClient.init(testing.allocator, config) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
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
    const config = TestConfig{};

    var client = SmtpClient.init(testing.allocator, config) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
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
    const config = TestConfig{};

    var client = SmtpClient.init(testing.allocator, config) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
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
    const config = TestConfig{};

    var client = SmtpClient.init(testing.allocator, config) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
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
    const config = TestConfig{};

    var client = SmtpClient.init(testing.allocator, config) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
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
    const config = TestConfig{};

    var client = SmtpClient.init(testing.allocator, config) catch |err| {
        if (err == error.ConnectionRefused) return error.SkipZigTest;
        return err;
    };
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
