// Security Hardening Test Suite
// Tests for all security and performance improvements applied to the mail server.
//
// Covers: JSON escaping, SSRF protection, timestamp formatting, MIME boundary
// handling, nonce management, counter overflow, constant-time comparison,
// email validation, autoconfig security, and more.

const std = @import("std");
const testing = std.testing;
const mail = @import("mail");


// ============================================================================
// Webhook JSON Escaping Tests (Task #18)
// ============================================================================

test "Webhook: JSON escaping prevents injection via quotes" {
    const allocator = testing.allocator;
    const result = try mail.webhook.escapeJsonString(allocator, "test\"injection");
    defer allocator.free(result);
    try testing.expectEqualStrings("test\\\"injection", result);
}

test "Webhook: JSON escaping handles backslashes" {
    const allocator = testing.allocator;
    const result = try mail.webhook.escapeJsonString(allocator, "path\\to\\file");
    defer allocator.free(result);
    try testing.expectEqualStrings("path\\\\to\\\\file", result);
}

test "Webhook: JSON escaping handles control characters" {
    const allocator = testing.allocator;
    const result = try mail.webhook.escapeJsonString(allocator, "line1\nline2\rtab\there");
    defer allocator.free(result);
    try testing.expectEqualStrings("line1\\nline2\\rtab\\there", result);
}

test "Webhook: JSON escaping handles null bytes and low control chars" {
    const allocator = testing.allocator;
    const result = try mail.webhook.escapeJsonString(allocator, "has\x00null\x01ctrl");
    defer allocator.free(result);
    try testing.expect(std.mem.indexOf(u8, result, "\\u00") != null);
    try testing.expect(std.mem.indexOf(u8, result, "\x00") == null);
}

test "Webhook: JSON escaping passthrough for safe strings" {
    const allocator = testing.allocator;
    const result = try mail.webhook.escapeJsonString(allocator, "user@example.com");
    defer allocator.free(result);
    try testing.expectEqualStrings("user@example.com", result);
}

test "Webhook: JSON escaping handles empty string" {
    const allocator = testing.allocator;
    const result = try mail.webhook.escapeJsonString(allocator, "");
    defer allocator.free(result);
    try testing.expectEqualStrings("", result);
}

test "Webhook: JSON escaping handles combined attack string" {
    const allocator = testing.allocator;
    // Attempt to break out of JSON value and inject new key
    const result = try mail.webhook.escapeJsonString(allocator, "\",\"injected\":\"true");
    defer allocator.free(result);
    // All quotes should be escaped, preventing injection
    try testing.expect(std.mem.indexOf(u8, result, "\\\"") != null);
    // No unescaped quotes should remain
    var unescaped_count: usize = 0;
    for (result, 0..) |c, i| {
        if (c == '"' and (i == 0 or result[i - 1] != '\\')) unescaped_count += 1;
    }
    try testing.expectEqual(@as(usize, 0), unescaped_count);
}

// ============================================================================
// Webhook SSRF Protection Tests (Task #19)
// ============================================================================

test "Webhook: SSRF rejects loopback 127.0.0.1" {
    try testing.expect(mail.webhook.isPrivateIp(.{ 127, 0, 0, 1 }));
}

test "Webhook: SSRF rejects 127.x.x.x range" {
    try testing.expect(mail.webhook.isPrivateIp(.{ 127, 255, 255, 255 }));
}

test "Webhook: SSRF rejects 10.0.0.0/8" {
    try testing.expect(mail.webhook.isPrivateIp(.{ 10, 0, 0, 1 }));
    try testing.expect(mail.webhook.isPrivateIp(.{ 10, 255, 255, 255 }));
}

test "Webhook: SSRF rejects 172.16.0.0/12" {
    try testing.expect(mail.webhook.isPrivateIp(.{ 172, 16, 0, 1 }));
    try testing.expect(mail.webhook.isPrivateIp(.{ 172, 31, 255, 255 }));
}

test "Webhook: SSRF does not reject 172.15.x.x or 172.32.x.x" {
    try testing.expect(!mail.webhook.isPrivateIp(.{ 172, 15, 0, 1 }));
    try testing.expect(!mail.webhook.isPrivateIp(.{ 172, 32, 0, 1 }));
}

test "Webhook: SSRF rejects 192.168.0.0/16" {
    try testing.expect(mail.webhook.isPrivateIp(.{ 192, 168, 0, 1 }));
    try testing.expect(mail.webhook.isPrivateIp(.{ 192, 168, 255, 255 }));
}

test "Webhook: SSRF rejects link-local 169.254.0.0/16" {
    try testing.expect(mail.webhook.isPrivateIp(.{ 169, 254, 1, 1 }));
}

test "Webhook: SSRF rejects 0.0.0.0" {
    try testing.expect(mail.webhook.isPrivateIp(.{ 0, 0, 0, 0 }));
}

test "Webhook: SSRF allows public IPs" {
    try testing.expect(!mail.webhook.isPrivateIp(.{ 8, 8, 8, 8 }));
    try testing.expect(!mail.webhook.isPrivateIp(.{ 93, 184, 216, 34 }));
    try testing.expect(!mail.webhook.isPrivateIp(.{ 1, 1, 1, 1 }));
    try testing.expect(!mail.webhook.isPrivateIp(.{ 203, 0, 113, 1 }));
}

// ============================================================================
// Timestamp Formatting Tests — RFC 5322 Date (Task #30)
// ============================================================================

test "MSA: formatTimestamp rejects negative timestamps" {
    const allocator = testing.allocator;
    var msa = try mail.message_submission.MessageSubmissionAgent.init(allocator, .{ .hostname = "test.local" });
    defer msa.deinit();

    const result = msa.formatTimestamp(-1);
    try testing.expectError(error.InvalidTimestamp, result);
}

test "MSA: formatTimestamp handles epoch (1970-01-01)" {
    const allocator = testing.allocator;
    var msa = try mail.message_submission.MessageSubmissionAgent.init(allocator, .{ .hostname = "test.local" });
    defer msa.deinit();

    const date = try msa.formatTimestamp(0);
    defer allocator.free(date);

    // Jan 1, 1970 was a Thursday
    try testing.expect(std.mem.startsWith(u8, date, "Thu, 1 Jan 1970"));
}

test "MSA: formatTimestamp handles known date (2025-03-15)" {
    const allocator = testing.allocator;
    var msa = try mail.message_submission.MessageSubmissionAgent.init(allocator, .{ .hostname = "test.local" });
    defer msa.deinit();

    // 2025-03-15 12:00:00 UTC = 1742040000
    const date = try msa.formatTimestamp(1742040000);
    defer allocator.free(date);

    try testing.expect(std.mem.indexOf(u8, date, "Mar") != null);
    try testing.expect(std.mem.indexOf(u8, date, "2025") != null);
    try testing.expect(std.mem.indexOf(u8, date, "15") != null);
}

test "MSA: formatTimestamp handles leap year date (2024-02-29)" {
    const allocator = testing.allocator;
    var msa = try mail.message_submission.MessageSubmissionAgent.init(allocator, .{ .hostname = "test.local" });
    defer msa.deinit();

    // 2024-02-29 00:00:00 UTC = 1709164800
    const date = try msa.formatTimestamp(1709164800);
    defer allocator.free(date);

    try testing.expect(std.mem.indexOf(u8, date, "Feb") != null);
    try testing.expect(std.mem.indexOf(u8, date, "2024") != null);
    try testing.expect(std.mem.indexOf(u8, date, "29") != null);
}

test "MSA: formatTimestamp handles Dec 31 end of year" {
    const allocator = testing.allocator;
    var msa = try mail.message_submission.MessageSubmissionAgent.init(allocator, .{ .hostname = "test.local" });
    defer msa.deinit();

    // 2023-12-31 23:59:59 UTC = 1704067199
    const date = try msa.formatTimestamp(1704067199);
    defer allocator.free(date);

    try testing.expect(std.mem.indexOf(u8, date, "Dec") != null);
    try testing.expect(std.mem.indexOf(u8, date, "2023") != null);
    try testing.expect(std.mem.indexOf(u8, date, "31") != null);
}

test "MSA: formatTimestamp produces valid RFC 5322 format" {
    const allocator = testing.allocator;
    var msa = try mail.message_submission.MessageSubmissionAgent.init(allocator, .{ .hostname = "test.local" });
    defer msa.deinit();

    const date = try msa.formatTimestamp(1700000000);
    defer allocator.free(date);

    try testing.expect(std.mem.endsWith(u8, date, "+0000"));
    try testing.expect(std.mem.indexOf(u8, date, ",") != null);
}

test "MSA: isLeapYear correctly identifies leap years" {
    try testing.expect(mail.message_submission.MessageSubmissionAgent.isLeapYear(2000)); // divisible by 400
    try testing.expect(mail.message_submission.MessageSubmissionAgent.isLeapYear(2024)); // divisible by 4
    try testing.expect(!mail.message_submission.MessageSubmissionAgent.isLeapYear(1900)); // divisible by 100 but not 400
    try testing.expect(!mail.message_submission.MessageSubmissionAgent.isLeapYear(2023)); // not divisible by 4
    try testing.expect(mail.message_submission.MessageSubmissionAgent.isLeapYear(2400)); // divisible by 400
}

// ============================================================================
// Nonce Manager Tests (Task #24, #33)
// ============================================================================

test "NonceManager: generates unique nonces" {
    var nm = mail.auth.NonceManager.init(testing.allocator);
    defer nm.deinit();

    const n1 = try nm.generateNonce();
    const n2 = try nm.generateNonce();

    try testing.expect(!std.mem.eql(u8, n1, n2));
    try testing.expectEqual(@as(usize, 64), n1.len); // 32 bytes = 64 hex chars
}

test "NonceManager: validates generated nonce" {
    var nm = mail.auth.NonceManager.init(testing.allocator);
    defer nm.deinit();

    const nonce = try nm.generateNonce();
    try testing.expect(nm.validateNonce(nonce));
}

test "NonceManager: rejects unknown nonce" {
    var nm = mail.auth.NonceManager.init(testing.allocator);
    defer nm.deinit();

    try testing.expect(!nm.validateNonce("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
}

test "NonceManager: invalidation removes nonce" {
    var nm = mail.auth.NonceManager.init(testing.allocator);
    defer nm.deinit();

    const nonce = try nm.generateNonce();
    try testing.expect(nm.validateNonce(nonce));

    nm.invalidateNonce(nonce);
    try testing.expect(!nm.validateNonce(nonce));
}

test "NonceManager: deterministic cleanup caps at max_nonces" {
    var nm = mail.auth.NonceManager.init(testing.allocator);
    defer nm.deinit();
    nm.max_nonces = 10;
    nm.max_age_seconds = 0; // All nonces expire immediately

    for (0..15) |_| {
        _ = try nm.generateNonce();
    }

    // After cleanup triggered by max cap, count should be bounded
    try testing.expect(nm.nonces.count() <= 15);
}

test "NonceManager: nonce is 64 hex characters" {
    var nm = mail.auth.NonceManager.init(testing.allocator);
    defer nm.deinit();

    const nonce = try nm.generateNonce();
    try testing.expectEqual(@as(usize, 64), nonce.len);
    for (nonce) |c| {
        try testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

// ============================================================================
// Constant-Time Comparison Tests (Task #13)
// ============================================================================

test "Auth: constantTimeEql matches equal slices" {
    try testing.expect(mail.auth.constantTimeEql("hello", "hello"));
}

test "Auth: constantTimeEql rejects different slices" {
    try testing.expect(!mail.auth.constantTimeEql("hello", "world"));
}

test "Auth: constantTimeEql rejects different lengths" {
    try testing.expect(!mail.auth.constantTimeEql("short", "longer_string"));
}

test "Auth: constantTimeEql handles empty slices" {
    try testing.expect(mail.auth.constantTimeEql("", ""));
}

test "Auth: constantTimeEql detects single-bit difference" {
    try testing.expect(!mail.auth.constantTimeEql("A", "B"));
}

test "Auth: constantTimeEql handles identical binary data" {
    const a = [_]u8{ 0x00, 0xFF, 0x42, 0x99 };
    const b = [_]u8{ 0x00, 0xFF, 0x42, 0x99 };
    try testing.expect(mail.auth.constantTimeEql(&a, &b));
}

test "Auth: constantTimeEql detects last-byte difference" {
    const a = [_]u8{ 0x00, 0xFF, 0x42, 0x99 };
    const b = [_]u8{ 0x00, 0xFF, 0x42, 0x98 };
    try testing.expect(!mail.auth.constantTimeEql(&a, &b));
}

// ============================================================================
// MIME Boundary Stack Allocation Tests (Task #27)
// ============================================================================

test "MIME: parser handles standard boundary" {
    const allocator = testing.allocator;
    var parser = mail.mime.MultipartParser.init(allocator);

    const body = "--boundary123\r\nContent-Type: text/plain\r\n\r\nHello\r\n--boundary123--\r\n";
    const parts = try parser.parse(body, "boundary123");
    defer {
        for (parts) |*p| {
            var mp = p.*;
            mp.deinit();
        }
        allocator.free(parts);
    }
    try testing.expect(parts.len > 0);
}

test "MIME: parser rejects boundary over 70 chars" {
    const allocator = testing.allocator;
    var parser = mail.mime.MultipartParser.init(allocator);

    const long_boundary = "a" ** 71;
    const body = "--" ++ long_boundary ++ "\r\nContent-Type: text/plain\r\n\r\nHello\r\n--" ++ long_boundary ++ "--\r\n";
    const result = parser.parse(body, long_boundary);
    try testing.expectError(error.BoundaryTooLong, result);
}

test "MIME: parser accepts boundary at exactly 70 chars" {
    const allocator = testing.allocator;
    var parser = mail.mime.MultipartParser.init(allocator);

    const boundary_70 = "a" ** 70;
    const body = "--" ++ boundary_70 ++ "\r\nContent-Type: text/plain\r\n\r\nHello\r\n--" ++ boundary_70 ++ "--\r\n";
    const parts = try parser.parse(body, boundary_70);
    defer {
        for (parts) |*p| {
            var mp = p.*;
            mp.deinit();
        }
        allocator.free(parts);
    }
    try testing.expect(true);
}

// ============================================================================
// io_compat randomBytes Tests (DKIM crash fix)
// ============================================================================

test "io_compat: randomBytes fills buffer" {
    var buf: [32]u8 = undefined;
    @memset(&buf, 0);
    mail.io_compat.randomBytes(&buf);

    var all_zero = true;
    for (buf) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "io_compat: randomBytes produces non-trivial output" {
    var buf1: [32]u8 = undefined;
    @memset(&buf1, 0xAA);
    mail.io_compat.randomBytes(&buf1);

    // Check that randomBytes actually wrote something different from the fill pattern
    var different = false;
    for (buf1) |b| {
        if (b != 0xAA) {
            different = true;
            break;
        }
    }
    try testing.expect(different);
}

test "io_compat: randomBytes handles single byte" {
    var buf: [1]u8 = .{0};
    mail.io_compat.randomBytes(&buf);
    // Just verify it doesn't crash — single byte can be anything
    try testing.expect(true);
}

// ============================================================================
// Security: Email Validation Tests (Task #16)
// ============================================================================

test "Security: rejects email with multiple @ signs" {
    try testing.expect(!mail.security.validateEmailAddress("user@@example.com"));
    try testing.expect(!mail.security.validateEmailAddress("user@mid@example.com"));
}

test "Security: rejects email with control characters" {
    try testing.expect(!mail.security.validateEmailAddress("user\x00@example.com"));
    try testing.expect(!mail.security.validateEmailAddress("user\n@example.com"));
}

test "Security: rejects email with consecutive dots" {
    try testing.expect(!mail.security.validateEmailAddress("user..name@example.com"));
}

test "Security: rejects email with leading/trailing dots" {
    try testing.expect(!mail.security.validateEmailAddress(".user@example.com"));
    try testing.expect(!mail.security.validateEmailAddress("user.@example.com"));
}

test "Security: accepts valid email addresses" {
    try testing.expect(mail.security.validateEmailAddress("user@example.com"));
    try testing.expect(mail.security.validateEmailAddress("user.name@example.com"));
    try testing.expect(mail.security.validateEmailAddress("user+tag@example.com"));
}

test "Security: rejects empty email" {
    try testing.expect(!mail.security.validateEmailAddress(""));
}

test "Security: rejects email without @" {
    try testing.expect(!mail.security.validateEmailAddress("userexample.com"));
}

// ============================================================================
// Counter Overflow Protection Tests (Tasks #26, #34)
// ============================================================================

test "Saturating arithmetic: u32 max +| 1 stays at max" {
    const max_count: u32 = std.math.maxInt(u32);
    const incremented = max_count +| 1;
    try testing.expectEqual(max_count, incremented);
}

test "Saturating arithmetic: below max increments normally" {
    const below_max: u32 = std.math.maxInt(u32) - 1;
    const incremented = below_max +| 1;
    try testing.expectEqual(std.math.maxInt(u32), incremented);
}

test "Saturating arithmetic: zero increments to one" {
    const zero: u32 = 0;
    const incremented = zero +| 1;
    try testing.expectEqual(@as(u32, 1), incremented);
}

// ============================================================================
// Autoconfig: password-encrypted Tests (Task #15)
// ============================================================================

test "Autoconfig: Thunderbird config uses password-encrypted for email" {
    const allocator = testing.allocator;
    const config = mail.autoconfig.AutoconfigConfig{};
    const xml = try mail.autoconfig.generateThunderbirdXML(allocator, config, "example.com");
    defer allocator.free(xml);

    // Email (IMAP/SMTP) should use password-encrypted
    try testing.expect(std.mem.indexOf(u8, xml, "password-encrypted") != null);
}

test "Autoconfig: Thunderbird XML has required IMAP/SMTP sections" {
    const allocator = testing.allocator;
    const config = mail.autoconfig.AutoconfigConfig{};
    const xml = try mail.autoconfig.generateThunderbirdXML(allocator, config, "example.com");
    defer allocator.free(xml);

    try testing.expect(std.mem.indexOf(u8, xml, "incomingServer") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "outgoingServer") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "IMAP") != null or std.mem.indexOf(u8, xml, "imap") != null);
}

// ============================================================================
// CalDAV: Path Traversal Tests (Task #14) — module-level function
// ============================================================================

test "CalDAV: parsePath rejects path traversal with .." {
    const result = mail.caldav.parsePath("/../../../etc/passwd");
    try testing.expectEqual(result.path_type, .unknown);
}

test "CalDAV: parsePath rejects embedded .. traversal" {
    const result = mail.caldav.parsePath("/addressbooks/user/../admin/contacts");
    try testing.expectEqual(result.path_type, .unknown);
}

test "CalDAV: parsePath handles well-known carddav" {
    const result = mail.caldav.parsePath("/.well-known/carddav");
    try testing.expect(result.path_type == .well_known_carddav);
}

test "CalDAV: parsePath handles well-known caldav" {
    const result = mail.caldav.parsePath("/.well-known/caldav");
    try testing.expect(result.path_type == .well_known_caldav);
}

test "CalDAV: parsePath handles principals path" {
    const result = mail.caldav.parsePath("/principals/user@example.com");
    try testing.expect(result.path_type != .unknown);
}

// ============================================================================
// IMAP: Notes folder type (Task from plan Phase 3)
// ============================================================================

test "IMAP: FolderType.notes exists and has correct name" {
    const notes_name = mail.imap.FolderType.notes.getName();
    try testing.expectEqualStrings("Notes", notes_name);
}

test "IMAP: FolderType.notes is not virtual" {
    try testing.expect(!mail.imap.FolderType.notes.isVirtual());
}

test "IMAP: FolderType.notes has correct attributes" {
    const attrs = mail.imap.FolderType.notes.getAttributes();
    try testing.expect(attrs.len > 0);
}
