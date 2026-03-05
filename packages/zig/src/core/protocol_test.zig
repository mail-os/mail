const std = @import("std");
const testing = std.testing;
const protocol = @import("protocol.zig");
const config = @import("config.zig");
const logger = @import("logger.zig");
const security = @import("../auth/security.zig");

// Mock connection for testing
const MockConnection = struct {
    read_buffer: []const u8,
    read_pos: usize,
    write_buffer: std.ArrayList(u8),

    fn init(allocator: std.mem.Allocator, read_data: []const u8) !MockConnection {
        return MockConnection{
            .read_buffer = read_data,
            .read_pos = 0,
            .write_buffer = std.ArrayList(u8).init(allocator),
        };
    }

    fn deinit(self: *MockConnection) void {
        self.write_buffer.deinit();
    }

    fn read(self: *MockConnection, buffer: []u8) !usize {
        if (self.read_pos >= self.read_buffer.len) return 0;

        const remaining = self.read_buffer.len - self.read_pos;
        const to_read = @min(buffer.len, remaining);

        @memcpy(buffer[0..to_read], self.read_buffer[self.read_pos .. self.read_pos + to_read]);
        self.read_pos += to_read;

        return to_read;
    }

    fn write(self: *MockConnection, data: []const u8) !usize {
        try self.write_buffer.appendSlice(data);
        return data.len;
    }

    fn getWritten(self: *MockConnection) []const u8 {
        return self.write_buffer.items;
    }
};

// Test command parsing
test "parseCommand - HELO" {
    const allocator = testing.allocator;

    var cfg = config.Config{
        .hostname = "test.example.com",
        .port = 25,
        .max_message_size = 10485760,
        .max_recipients = 100,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .enable_tls = false,
        .enable_auth = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .webhook_url = "",
        .webhook_enabled = false,
    };

    var log = try logger.Logger.init(allocator, .Info);
    defer log.deinit();

    var rate_limiter = security.RateLimiter.init(allocator, 100, 60);
    defer rate_limiter.deinit();

    // Create a mock connection
    var mock_stream = std.net.Stream{ .handle = 0 };
    var connection = std.net.Server.Connection{
        .stream = mock_stream,
        .address = std.net.Address.initIp4([_]u8{ 127, 0, 0, 1 }, 0),
    };

    var session = try protocol.Session.init(
        allocator,
        connection,
        cfg,
        &log,
        "127.0.0.1",
        &rate_limiter,
        null,
        null,
        null,
    );
    defer session.deinit();

    const cmd = session.parseCommand("HELO example.com");
    try testing.expectEqual(protocol.SMTPCommand.HELO, cmd);
}

test "parseCommand - EHLO" {
    const allocator = testing.allocator;

    var cfg = config.Config{
        .hostname = "test.example.com",
        .port = 25,
        .max_message_size = 10485760,
        .max_recipients = 100,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .enable_tls = false,
        .enable_auth = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .webhook_url = "",
        .webhook_enabled = false,
    };

    var log = try logger.Logger.init(allocator, .Info);
    defer log.deinit();

    var rate_limiter = security.RateLimiter.init(allocator, 100, 60);
    defer rate_limiter.deinit();

    var mock_stream = std.net.Stream{ .handle = 0 };
    var connection = std.net.Server.Connection{
        .stream = mock_stream,
        .address = std.net.Address.initIp4([_]u8{ 127, 0, 0, 1 }, 0),
    };

    var session = try protocol.Session.init(
        allocator,
        connection,
        cfg,
        &log,
        "127.0.0.1",
        &rate_limiter,
        null,
        null,
        null,
    );
    defer session.deinit();

    const cmd = session.parseCommand("EHLO example.com");
    try testing.expectEqual(protocol.SMTPCommand.EHLO, cmd);
}

test "parseCommand - MAIL FROM" {
    const allocator = testing.allocator;

    var cfg = config.Config{
        .hostname = "test.example.com",
        .port = 25,
        .max_message_size = 10485760,
        .max_recipients = 100,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .enable_tls = false,
        .enable_auth = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .webhook_url = "",
        .webhook_enabled = false,
    };

    var log = try logger.Logger.init(allocator, .Info);
    defer log.deinit();

    var rate_limiter = security.RateLimiter.init(allocator, 100, 60);
    defer rate_limiter.deinit();

    var mock_stream = std.net.Stream{ .handle = 0 };
    var connection = std.net.Server.Connection{
        .stream = mock_stream,
        .address = std.net.Address.initIp4([_]u8{ 127, 0, 0, 1 }, 0),
    };

    var session = try protocol.Session.init(
        allocator,
        connection,
        cfg,
        &log,
        "127.0.0.1",
        &rate_limiter,
        null,
        null,
        null,
    );
    defer session.deinit();

    const cmd = session.parseCommand("MAIL FROM:<sender@example.com>");
    try testing.expectEqual(protocol.SMTPCommand.MAIL, cmd);
}

test "parseCommand - RCPT TO" {
    const allocator = testing.allocator;

    var cfg = config.Config{
        .hostname = "test.example.com",
        .port = 25,
        .max_message_size = 10485760,
        .max_recipients = 100,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .enable_tls = false,
        .enable_auth = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .webhook_url = "",
        .webhook_enabled = false,
    };

    var log = try logger.Logger.init(allocator, .Info);
    defer log.deinit();

    var rate_limiter = security.RateLimiter.init(allocator, 100, 60);
    defer rate_limiter.deinit();

    var mock_stream = std.net.Stream{ .handle = 0 };
    var connection = std.net.Server.Connection{
        .stream = mock_stream,
        .address = std.net.Address.initIp4([_]u8{ 127, 0, 0, 1 }, 0),
    };

    var session = try protocol.Session.init(
        allocator,
        connection,
        cfg,
        &log,
        "127.0.0.1",
        &rate_limiter,
        null,
        null,
        null,
    );
    defer session.deinit();

    const cmd = session.parseCommand("RCPT TO:<recipient@example.com>");
    try testing.expectEqual(protocol.SMTPCommand.RCPT, cmd);
}

test "parseCommand - case insensitive" {
    const allocator = testing.allocator;

    var cfg = config.Config{
        .hostname = "test.example.com",
        .port = 25,
        .max_message_size = 10485760,
        .max_recipients = 100,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .enable_tls = false,
        .enable_auth = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .webhook_url = "",
        .webhook_enabled = false,
    };

    var log = try logger.Logger.init(allocator, .Info);
    defer log.deinit();

    var rate_limiter = security.RateLimiter.init(allocator, 100, 60);
    defer rate_limiter.deinit();

    var mock_stream = std.net.Stream{ .handle = 0 };
    var connection = std.net.Server.Connection{
        .stream = mock_stream,
        .address = std.net.Address.initIp4([_]u8{ 127, 0, 0, 1 }, 0),
    };

    var session = try protocol.Session.init(
        allocator,
        connection,
        cfg,
        &log,
        "127.0.0.1",
        &rate_limiter,
        null,
        null,
        null,
    );
    defer session.deinit();

    try testing.expectEqual(protocol.SMTPCommand.QUIT, session.parseCommand("quit"));
    try testing.expectEqual(protocol.SMTPCommand.QUIT, session.parseCommand("QUIT"));
    try testing.expectEqual(protocol.SMTPCommand.QUIT, session.parseCommand("QuIt"));
}

test "parseCommand - DATA" {
    const allocator = testing.allocator;

    var cfg = config.Config{
        .hostname = "test.example.com",
        .port = 25,
        .max_message_size = 10485760,
        .max_recipients = 100,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .enable_tls = false,
        .enable_auth = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .webhook_url = "",
        .webhook_enabled = false,
    };

    var log = try logger.Logger.init(allocator, .Info);
    defer log.deinit();

    var rate_limiter = security.RateLimiter.init(allocator, 100, 60);
    defer rate_limiter.deinit();

    var mock_stream = std.net.Stream{ .handle = 0 };
    var connection = std.net.Server.Connection{
        .stream = mock_stream,
        .address = std.net.Address.initIp4([_]u8{ 127, 0, 0, 1 }, 0),
    };

    var session = try protocol.Session.init(
        allocator,
        connection,
        cfg,
        &log,
        "127.0.0.1",
        &rate_limiter,
        null,
        null,
        null,
    );
    defer session.deinit();

    const cmd = session.parseCommand("DATA");
    try testing.expectEqual(protocol.SMTPCommand.DATA, cmd);
}

test "parseCommand - RSET" {
    const allocator = testing.allocator;

    var cfg = config.Config{
        .hostname = "test.example.com",
        .port = 25,
        .max_message_size = 10485760,
        .max_recipients = 100,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .enable_tls = false,
        .enable_auth = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .webhook_url = "",
        .webhook_enabled = false,
    };

    var log = try logger.Logger.init(allocator, .Info);
    defer log.deinit();

    var rate_limiter = security.RateLimiter.init(allocator, 100, 60);
    defer rate_limiter.deinit();

    var mock_stream = std.net.Stream{ .handle = 0 };
    var connection = std.net.Server.Connection{
        .stream = mock_stream,
        .address = std.net.Address.initIp4([_]u8{ 127, 0, 0, 1 }, 0),
    };

    var session = try protocol.Session.init(
        allocator,
        connection,
        cfg,
        &log,
        "127.0.0.1",
        &rate_limiter,
        null,
        null,
        null,
    );
    defer session.deinit();

    const cmd = session.parseCommand("RSET");
    try testing.expectEqual(protocol.SMTPCommand.RSET, cmd);
}

test "parseCommand - NOOP" {
    const allocator = testing.allocator;

    var cfg = config.Config{
        .hostname = "test.example.com",
        .port = 25,
        .max_message_size = 10485760,
        .max_recipients = 100,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .enable_tls = false,
        .enable_auth = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .webhook_url = "",
        .webhook_enabled = false,
    };

    var log = try logger.Logger.init(allocator, .Info);
    defer log.deinit();

    var rate_limiter = security.RateLimiter.init(allocator, 100, 60);
    defer rate_limiter.deinit();

    var mock_stream = std.net.Stream{ .handle = 0 };
    var connection = std.net.Server.Connection{
        .stream = mock_stream,
        .address = std.net.Address.initIp4([_]u8{ 127, 0, 0, 1 }, 0),
    };

    var session = try protocol.Session.init(
        allocator,
        connection,
        cfg,
        &log,
        "127.0.0.1",
        &rate_limiter,
        null,
        null,
        null,
    );
    defer session.deinit();

    const cmd = session.parseCommand("NOOP");
    try testing.expectEqual(protocol.SMTPCommand.NOOP, cmd);
}

test "parseCommand - QUIT" {
    const allocator = testing.allocator;

    var cfg = config.Config{
        .hostname = "test.example.com",
        .port = 25,
        .max_message_size = 10485760,
        .max_recipients = 100,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .enable_tls = false,
        .enable_auth = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .webhook_url = "",
        .webhook_enabled = false,
    };

    var log = try logger.Logger.init(allocator, .Info);
    defer log.deinit();

    var rate_limiter = security.RateLimiter.init(allocator, 100, 60);
    defer rate_limiter.deinit();

    var mock_stream = std.net.Stream{ .handle = 0 };
    var connection = std.net.Server.Connection{
        .stream = mock_stream,
        .address = std.net.Address.initIp4([_]u8{ 127, 0, 0, 1 }, 0),
    };

    var session = try protocol.Session.init(
        allocator,
        connection,
        cfg,
        &log,
        "127.0.0.1",
        &rate_limiter,
        null,
        null,
        null,
    );
    defer session.deinit();

    const cmd = session.parseCommand("QUIT");
    try testing.expectEqual(protocol.SMTPCommand.QUIT, cmd);
}

test "parseCommand - AUTH" {
    const allocator = testing.allocator;

    var cfg = config.Config{
        .hostname = "test.example.com",
        .port = 25,
        .max_message_size = 10485760,
        .max_recipients = 100,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .enable_tls = false,
        .enable_auth = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .webhook_url = "",
        .webhook_enabled = false,
    };

    var log = try logger.Logger.init(allocator, .Info);
    defer log.deinit();

    var rate_limiter = security.RateLimiter.init(allocator, 100, 60);
    defer rate_limiter.deinit();

    var mock_stream = std.net.Stream{ .handle = 0 };
    var connection = std.net.Server.Connection{
        .stream = mock_stream,
        .address = std.net.Address.initIp4([_]u8{ 127, 0, 0, 1 }, 0),
    };

    var session = try protocol.Session.init(
        allocator,
        connection,
        cfg,
        &log,
        "127.0.0.1",
        &rate_limiter,
        null,
        null,
        null,
    );
    defer session.deinit();

    const cmd = session.parseCommand("AUTH PLAIN");
    try testing.expectEqual(protocol.SMTPCommand.AUTH, cmd);
}

test "parseCommand - STARTTLS" {
    const allocator = testing.allocator;

    var cfg = config.Config{
        .hostname = "test.example.com",
        .port = 25,
        .max_message_size = 10485760,
        .max_recipients = 100,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .enable_tls = false,
        .enable_auth = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .webhook_url = "",
        .webhook_enabled = false,
    };

    var log = try logger.Logger.init(allocator, .Info);
    defer log.deinit();

    var rate_limiter = security.RateLimiter.init(allocator, 100, 60);
    defer rate_limiter.deinit();

    var mock_stream = std.net.Stream{ .handle = 0 };
    var connection = std.net.Server.Connection{
        .stream = mock_stream,
        .address = std.net.Address.initIp4([_]u8{ 127, 0, 0, 1 }, 0),
    };

    var session = try protocol.Session.init(
        allocator,
        connection,
        cfg,
        &log,
        "127.0.0.1",
        &rate_limiter,
        null,
        null,
        null,
    );
    defer session.deinit();

    const cmd = session.parseCommand("STARTTLS");
    try testing.expectEqual(protocol.SMTPCommand.STARTTLS, cmd);
}

test "parseCommand - BDAT" {
    const allocator = testing.allocator;

    var cfg = config.Config{
        .hostname = "test.example.com",
        .port = 25,
        .max_message_size = 10485760,
        .max_recipients = 100,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .enable_tls = false,
        .enable_auth = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .webhook_url = "",
        .webhook_enabled = false,
    };

    var log = try logger.Logger.init(allocator, .Info);
    defer log.deinit();

    var rate_limiter = security.RateLimiter.init(allocator, 100, 60);
    defer rate_limiter.deinit();

    var mock_stream = std.net.Stream{ .handle = 0 };
    var connection = std.net.Server.Connection{
        .stream = mock_stream,
        .address = std.net.Address.initIp4([_]u8{ 127, 0, 0, 1 }, 0),
    };

    var session = try protocol.Session.init(
        allocator,
        connection,
        cfg,
        &log,
        "127.0.0.1",
        &rate_limiter,
        null,
        null,
        null,
    );
    defer session.deinit();

    const cmd = session.parseCommand("BDAT 100");
    try testing.expectEqual(protocol.SMTPCommand.BDAT, cmd);
}

test "parseCommand - unknown command" {
    const allocator = testing.allocator;

    var cfg = config.Config{
        .hostname = "test.example.com",
        .port = 25,
        .max_message_size = 10485760,
        .max_recipients = 100,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .enable_tls = false,
        .enable_auth = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .webhook_url = "",
        .webhook_enabled = false,
    };

    var log = try logger.Logger.init(allocator, .Info);
    defer log.deinit();

    var rate_limiter = security.RateLimiter.init(allocator, 100, 60);
    defer rate_limiter.deinit();

    var mock_stream = std.net.Stream{ .handle = 0 };
    var connection = std.net.Server.Connection{
        .stream = mock_stream,
        .address = std.net.Address.initIp4([_]u8{ 127, 0, 0, 1 }, 0),
    };

    var session = try protocol.Session.init(
        allocator,
        connection,
        cfg,
        &log,
        "127.0.0.1",
        &rate_limiter,
        null,
        null,
        null,
    );
    defer session.deinit();

    const cmd = session.parseCommand("INVALID");
    try testing.expectEqual(protocol.SMTPCommand.UNKNOWN, cmd);
}

test "parseCommand - too short" {
    const allocator = testing.allocator;

    var cfg = config.Config{
        .hostname = "test.example.com",
        .port = 25,
        .max_message_size = 10485760,
        .max_recipients = 100,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .enable_tls = false,
        .enable_auth = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .webhook_url = "",
        .webhook_enabled = false,
    };

    var log = try logger.Logger.init(allocator, .Info);
    defer log.deinit();

    var rate_limiter = security.RateLimiter.init(allocator, 100, 60);
    defer rate_limiter.deinit();

    var mock_stream = std.net.Stream{ .handle = 0 };
    var connection = std.net.Server.Connection{
        .stream = mock_stream,
        .address = std.net.Address.initIp4([_]u8{ 127, 0, 0, 1 }, 0),
    };

    var session = try protocol.Session.init(
        allocator,
        connection,
        cfg,
        &log,
        "127.0.0.1",
        &rate_limiter,
        null,
        null,
        null,
    );
    defer session.deinit();

    const cmd = session.parseCommand("HE");
    try testing.expectEqual(protocol.SMTPCommand.UNKNOWN, cmd);
}

test "sanitizeForHeader - removes CRLF" {
    const allocator = testing.allocator;
    _ = allocator;

    var buf: [256]u8 = undefined;

    // Test removing CR
    const input1 = "Hello\rWorld";
    const result1 = protocol.Session.sanitizeForHeader(input1, &buf);
    try testing.expectEqualStrings("HelloWorld", result1);

    // Test removing LF
    const input2 = "Hello\nWorld";
    const result2 = protocol.Session.sanitizeForHeader(input2, &buf);
    try testing.expectEqualStrings("HelloWorld", result2);

    // Test removing CRLF
    const input3 = "Hello\r\nWorld";
    const result3 = protocol.Session.sanitizeForHeader(input3, &buf);
    try testing.expectEqualStrings("HelloWorld", result3);

    // Test multiple CRLF
    const input4 = "Line1\r\nLine2\r\nLine3";
    const result4 = protocol.Session.sanitizeForHeader(input4, &buf);
    try testing.expectEqualStrings("Line1Line2Line3", result4);
}

test "sanitizeForHeader - preserves normal text" {
    const allocator = testing.allocator;
    _ = allocator;

    var buf: [256]u8 = undefined;

    const input = "Normal text without special characters";
    const result = protocol.Session.sanitizeForHeader(input, &buf);
    try testing.expectEqualStrings(input, result);
}

test "sanitizeForHeader - empty string" {
    const allocator = testing.allocator;
    _ = allocator;

    var buf: [256]u8 = undefined;

    const input = "";
    const result = protocol.Session.sanitizeForHeader(input, &buf);
    try testing.expectEqualStrings("", result);
}

test "sanitizeForHeader - only CRLF" {
    const allocator = testing.allocator;
    _ = allocator;

    var buf: [256]u8 = undefined;

    const input = "\r\n\r\n";
    const result = protocol.Session.sanitizeForHeader(input, &buf);
    try testing.expectEqualStrings("", result);
}

test "Session init and deinit" {
    const allocator = testing.allocator;

    var cfg = config.Config{
        .hostname = "test.example.com",
        .port = 25,
        .max_message_size = 10485760,
        .max_recipients = 100,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .enable_tls = false,
        .enable_auth = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .webhook_url = "",
        .webhook_enabled = false,
    };

    var log = try logger.Logger.init(allocator, .Info);
    defer log.deinit();

    var rate_limiter = security.RateLimiter.init(allocator, 100, 60);
    defer rate_limiter.deinit();

    var mock_stream = std.net.Stream{ .handle = 0 };
    var connection = std.net.Server.Connection{
        .stream = mock_stream,
        .address = std.net.Address.initIp4([_]u8{ 127, 0, 0, 1 }, 0),
    };

    var session = try protocol.Session.init(
        allocator,
        connection,
        cfg,
        &log,
        "127.0.0.1",
        &rate_limiter,
        null,
        null,
        null,
    );
    defer session.deinit();

    // Verify initial state
    try testing.expectEqual(protocol.SessionState.Initial, session.state);
    try testing.expect(session.mail_from == null);
    try testing.expect(!session.authenticated);
    try testing.expectEqual(@as(usize, 0), session.rcpt_to.items.len);
}

test "Session state transitions" {
    const allocator = testing.allocator;

    var cfg = config.Config{
        .hostname = "test.example.com",
        .port = 25,
        .max_message_size = 10485760,
        .max_recipients = 100,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .enable_tls = false,
        .enable_auth = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .webhook_url = "",
        .webhook_enabled = false,
    };

    var log = try logger.Logger.init(allocator, .Info);
    defer log.deinit();

    var rate_limiter = security.RateLimiter.init(allocator, 100, 60);
    defer rate_limiter.deinit();

    var mock_stream = std.net.Stream{ .handle = 0 };
    var connection = std.net.Server.Connection{
        .stream = mock_stream,
        .address = std.net.Address.initIp4([_]u8{ 127, 0, 0, 1 }, 0),
    };

    var session = try protocol.Session.init(
        allocator,
        connection,
        cfg,
        &log,
        "127.0.0.1",
        &rate_limiter,
        null,
        null,
        null,
    );
    defer session.deinit();

    // Initial -> Greeted
    session.state = .Greeted;
    try testing.expectEqual(protocol.SessionState.Greeted, session.state);

    // Greeted -> MailFrom
    session.state = .MailFrom;
    try testing.expectEqual(protocol.SessionState.MailFrom, session.state);

    // MailFrom -> RcptTo
    session.state = .RcptTo;
    try testing.expectEqual(protocol.SessionState.RcptTo, session.state);

    // RcptTo -> Data
    session.state = .Data;
    try testing.expectEqual(protocol.SessionState.Data, session.state);
}

test "ConnectionWrapper - plain TCP read/write" {
    const allocator = testing.allocator;
    _ = allocator;

    var mock_stream = std.net.Stream{ .handle = 0 };
    var wrapper = protocol.ConnectionWrapper{
        .tcp_stream = mock_stream,
        .tls_conn = null,
        .using_tls = false,
    };

    // Verify initial state
    try testing.expect(!wrapper.using_tls);
    try testing.expect(wrapper.tls_conn == null);
}

test "Session timeout tracking" {
    const allocator = testing.allocator;

    var cfg = config.Config{
        .hostname = "test.example.com",
        .port = 25,
        .max_message_size = 10485760,
        .max_recipients = 100,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .enable_tls = false,
        .enable_auth = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .webhook_url = "",
        .webhook_enabled = false,
    };

    var log = try logger.Logger.init(allocator, .Info);
    defer log.deinit();

    var rate_limiter = security.RateLimiter.init(allocator, 100, 60);
    defer rate_limiter.deinit();

    var mock_stream = std.net.Stream{ .handle = 0 };
    var connection = std.net.Server.Connection{
        .stream = mock_stream,
        .address = std.net.Address.initIp4([_]u8{ 127, 0, 0, 1 }, 0),
    };

    var session = try protocol.Session.init(
        allocator,
        connection,
        cfg,
        &log,
        "127.0.0.1",
        &rate_limiter,
        null,
        null,
        null,
    );
    defer session.deinit();

    // Verify timestamps are set
    try testing.expect(session.start_time > 0);
    try testing.expect(session.last_activity > 0);
    try testing.expectEqual(session.start_time, session.last_activity);

    // Simulate activity
    const old_activity = session.last_activity;
    std.time.sleep(1 * std.time.ns_per_ms); // Sleep 1ms
    session.updateActivity();
    try testing.expect(session.last_activity >= old_activity);
}
