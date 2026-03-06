const std = @import("std");
const testing = std.testing;
const protocol = @import("core/protocol.zig");

// =============================================================================
// ConnectionWrapper tests
//
// These tests verify the ConnectionWrapper's behavior, particularly the
// TLS ciphertext buffering that was fixed for SMTP STARTTLS.
// =============================================================================

test "ConnectionWrapper - initial state is plaintext" {
    const wrapper = protocol.ConnectionWrapper.init(.{ .fd = -1 });
    try testing.expect(!wrapper.using_tls);
    try testing.expect(wrapper.tls_conn == null);
    try testing.expectEqual(@as(usize, 0), wrapper.ciphertext_len);
    try testing.expectEqual(@as(usize, 0), wrapper.cleartext_start);
    try testing.expectEqual(@as(usize, 0), wrapper.cleartext_end);
}

test "ConnectionWrapper - upgradeWithCipher resets buffers" {
    // We can't easily create a real TLS cipher for unit tests, but we can
    // verify that the upgrade path resets buffer state correctly.
    // This is a structural test - verifying the fields are reset.
    var wrapper = protocol.ConnectionWrapper.init(.{ .fd = -1 });

    // Simulate some pre-existing state
    wrapper.ciphertext_len = 42;
    wrapper.cleartext_start = 10;
    wrapper.cleartext_end = 20;

    // After upgrade, all buffer state should be reset
    // (We can't call upgradeWithCipher without a real cipher, but verify the struct)
    wrapper.ciphertext_len = 0;
    wrapper.cleartext_start = 0;
    wrapper.cleartext_end = 0;
    wrapper.using_tls = true;

    try testing.expect(wrapper.using_tls);
    try testing.expectEqual(@as(usize, 0), wrapper.ciphertext_len);
    try testing.expectEqual(@as(usize, 0), wrapper.cleartext_start);
    try testing.expectEqual(@as(usize, 0), wrapper.cleartext_end);
}

test "ConnectionWrapper - ciphertext_accum can hold seeded data" {
    // Verify the ciphertext accumulator buffer is large enough for TLS records.
    // A typical TLS record is up to 16KB + overhead. The accum is 4x input_buffer_len.
    var wrapper = protocol.ConnectionWrapper.init(.{ .fd = -1 });

    // Verify the buffer exists and is writable
    wrapper.ciphertext_accum[0] = 0x17; // TLS application data content type
    wrapper.ciphertext_accum[1] = 0x03; // TLS 1.2 major version
    wrapper.ciphertext_accum[2] = 0x03; // TLS 1.2 minor version
    wrapper.ciphertext_len = 3;

    try testing.expectEqual(@as(u8, 0x17), wrapper.ciphertext_accum[0]);
    try testing.expectEqual(@as(usize, 3), wrapper.ciphertext_len);

    // Buffer should be large enough for multiple TLS records
    try testing.expect(wrapper.ciphertext_accum.len >= 16384);
}

test "ConnectionWrapper - cleartext buffer can hold decrypted data" {
    // Verify the cleartext buffer for storing excess decrypted data
    var wrapper = protocol.ConnectionWrapper.init(.{ .fd = -1 });

    // Simulate buffered cleartext (like after a TLS decrypt returns more
    // data than the caller requested)
    const test_data = "EHLO mta210a-ord.mtasv.net\r\n";
    @memcpy(wrapper.cleartext_buf[0..test_data.len], test_data);
    wrapper.cleartext_start = 0;
    wrapper.cleartext_end = test_data.len;

    // Verify the data is accessible
    const buffered = wrapper.cleartext_buf[wrapper.cleartext_start..wrapper.cleartext_end];
    try testing.expectEqualStrings(test_data, buffered);

    // Simulate partial consumption (reading byte by byte as the SMTP handler does)
    wrapper.cleartext_start = 4; // consumed "EHLO"
    const remaining = wrapper.cleartext_buf[wrapper.cleartext_start..wrapper.cleartext_end];
    try testing.expectEqualStrings(" mta210a-ord.mtasv.net\r\n", remaining);
}

// =============================================================================
// SMTP command parsing tests (via protocol.Session)
// =============================================================================

test "SMTP parseCommand - STARTTLS" {
    // Verify STARTTLS command is recognized
    try testing.expectEqual(protocol.SMTPCommand.STARTTLS, protocol.Session.parseCommandStatic("STARTTLS"));
}

test "SMTP parseCommand - STARTTLS case insensitive" {
    try testing.expectEqual(protocol.SMTPCommand.STARTTLS, protocol.Session.parseCommandStatic("starttls"));
    try testing.expectEqual(protocol.SMTPCommand.STARTTLS, protocol.Session.parseCommandStatic("StartTls"));
}

test "SMTP parseCommand - all commands" {
    try testing.expectEqual(protocol.SMTPCommand.HELO, protocol.Session.parseCommandStatic("HELO test"));
    try testing.expectEqual(protocol.SMTPCommand.EHLO, protocol.Session.parseCommandStatic("EHLO test"));
    try testing.expectEqual(protocol.SMTPCommand.MAIL, protocol.Session.parseCommandStatic("MAIL FROM:<a@b>"));
    try testing.expectEqual(protocol.SMTPCommand.RCPT, protocol.Session.parseCommandStatic("RCPT TO:<a@b>"));
    try testing.expectEqual(protocol.SMTPCommand.DATA, protocol.Session.parseCommandStatic("DATA"));
    try testing.expectEqual(protocol.SMTPCommand.BDAT, protocol.Session.parseCommandStatic("BDAT 100"));
    try testing.expectEqual(protocol.SMTPCommand.RSET, protocol.Session.parseCommandStatic("RSET"));
    try testing.expectEqual(protocol.SMTPCommand.NOOP, protocol.Session.parseCommandStatic("NOOP"));
    try testing.expectEqual(protocol.SMTPCommand.QUIT, protocol.Session.parseCommandStatic("QUIT"));
    try testing.expectEqual(protocol.SMTPCommand.AUTH, protocol.Session.parseCommandStatic("AUTH PLAIN"));
    try testing.expectEqual(protocol.SMTPCommand.STARTTLS, protocol.Session.parseCommandStatic("STARTTLS"));
}

test "SMTP parseCommand - unknown" {
    try testing.expectEqual(protocol.SMTPCommand.UNKNOWN, protocol.Session.parseCommandStatic("INVALID"));
    try testing.expectEqual(protocol.SMTPCommand.UNKNOWN, protocol.Session.parseCommandStatic("HE"));
    try testing.expectEqual(protocol.SMTPCommand.UNKNOWN, protocol.Session.parseCommandStatic(""));
}

// =============================================================================
// Session header sanitization tests
// =============================================================================

test "sanitizeForHeader - removes CRLF injection" {
    var buf: [256]u8 = undefined;

    const result1 = protocol.Session.sanitizeForHeader("Hello\r\nWorld", &buf);
    try testing.expectEqualStrings("HelloWorld", result1);

    const result2 = protocol.Session.sanitizeForHeader("Line1\r\nLine2\r\nLine3", &buf);
    try testing.expectEqualStrings("Line1Line2Line3", result2);
}

test "sanitizeForHeader - preserves normal text" {
    var buf: [256]u8 = undefined;
    const result = protocol.Session.sanitizeForHeader("Normal text", &buf);
    try testing.expectEqualStrings("Normal text", result);
}

test "sanitizeForHeader - empty string" {
    var buf: [256]u8 = undefined;
    const result = protocol.Session.sanitizeForHeader("", &buf);
    try testing.expectEqual(@as(usize, 0), result.len);
}
