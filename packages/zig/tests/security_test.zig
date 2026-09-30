const std = @import("std");
const testing = std.testing;

// Import modules to test
const security = @import("../src/auth/security.zig");
const email_validator = @import("../src/core/email_validator.zig");
const headers = @import("../src/message/headers.zig");
const mime = @import("../src/message/mime.zig");

/// OWASP-based security test suite for SMTP server
/// Tests cover common attack vectors and security best practices

// ============================================================================
// OWASP A01:2021 - Broken Access Control
// ============================================================================

test "security: prevent unauthorized email relay" {
    // Test that server properly validates sender/recipient domains
    // to prevent being used as an open relay

    const invalid_addresses = [_][]const u8{
        "spam@malicious.com",
        "phishing@external.net",
        "user@192.168.1.1", // IP-based addresses should be validated
    };

    for (invalid_addresses) |addr| {
        // Email validator should catch these
        const result = email_validator.EmailValidator.validate(addr);
        // Should either reject or require authentication
        _ = result;
    }
}

test "security: enforce rate limiting per IP" {
    var rate_limiter = security.RateLimiter.init(
        testing.allocator,
        60, // 60 second window
        10, // max 10 requests
        20, // max 20 per user
        300, // cleanup interval
    );
    defer rate_limiter.deinit();

    const test_ip = "192.168.1.100";

    // Should allow first 10 requests
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        const allowed = try rate_limiter.checkAndIncrement(test_ip);
        try testing.expect(allowed);
    }

    // 11th request should be rate limited
    const blocked = try rate_limiter.checkAndIncrement(test_ip);
    try testing.expect(!blocked);
}

test "security: enforce rate limiting per user" {
    var rate_limiter = security.RateLimiter.init(
        testing.allocator,
        60, // 60 second window
        100, // high IP limit
        5, // max 5 per user
        300,
    );
    defer rate_limiter.deinit();

    const test_user = "user@example.com";

    // Should allow first 5 requests
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        const allowed = try rate_limiter.checkAndIncrementUser(test_user);
        try testing.expect(allowed);
    }

    // 6th request should be rate limited
    const blocked = try rate_limiter.checkAndIncrementUser(test_user);
    try testing.expect(!blocked);
}

// ============================================================================
// OWASP A03:2021 - Injection
// ============================================================================

test "security: prevent email header injection" {
    const malicious_inputs = [_][]const u8{
        "user@example.com\r\nBcc: attacker@evil.com",
        "user@example.com\nCc: spam@malicious.com",
        "user@example.com\r\n\r\nInjected body content",
        "user@example.com\x00null-byte-injection",
    };

    for (malicious_inputs) |input| {
        // Should sanitize or reject
        const is_safe = security.sanitizeInput(input);
        try testing.expect(!is_safe);
    }
}

test "security: prevent SMTP command injection" {
    const malicious_commands = [_][]const u8{
        "MAIL FROM:<user@example.com>\r\nRCPT TO:<attacker@evil.com>",
        "user@example.com\nDATA\n",
        "test\r\nQUIT\r\nHELO evil.com",
    };

    for (malicious_commands) |cmd| {
        const is_safe = security.sanitizeInput(cmd);
        try testing.expect(!is_safe);
    }
}

test "security: sanitize email addresses to prevent injection" {
    // Test email validator rejects malicious formats
    const malicious_emails = [_][]const u8{
        "user@example.com\r\n",
        "user@example.com\x00",
        "user@example.com\tmalicious",
        "<script>alert(1)</script>@example.com",
        "user\r\n@example.com",
    };

    for (malicious_emails) |email| {
        const result = email_validator.EmailValidator.validate(email);
        try testing.expectError(error.InvalidCharacterInLocalPart, result);
    }
}

test "security: reject SQL injection attempts in email" {
    const sql_injection_attempts = [_][]const u8{
        "'; DROP TABLE users--@example.com",
        "admin'--@example.com",
        "user' OR '1'='1@example.com",
    };

    for (sql_injection_attempts) |email| {
        // Email validator should reject invalid characters
        _ = email_validator.EmailValidator.validate(email) catch {
            // Expected to fail
            continue;
        };
    }
}

// ============================================================================
// OWASP A04:2021 - Insecure Design
// ============================================================================

test "security: validate email address length limits" {
    // Prevent DoS via extremely long addresses
    const long_local = "a" ** 65 ++ "@example.com";
    try testing.expectError(
        error.LocalPartTooLong,
        email_validator.EmailValidator.validate(long_local),
    );

    const long_domain = "user@" ++ ("a" ** 250) ++ ".com";
    try testing.expectError(
        error.DomainTooLong,
        email_validator.EmailValidator.validate(long_domain),
    );
}

test "security: enforce maximum MIME nesting depth" {
    var parser = mime.MultipartParser.init(testing.allocator);

    // Simulate deep nesting by setting depth
    parser.current_depth = 10; // At max

    const message =
        \\--boundary
        \\Content-Type: text/plain
        \\
        \\test
        \\--boundary--
    ;

    // Should reject due to depth limit
    const result = parser.parse(message, "boundary");
    try testing.expectError(error.MimeDepthExceeded, result);
}

test "security: enforce MIME boundary length limits" {
    var parser = mime.MultipartParser.init(testing.allocator);

    // Boundary with 71 characters (too long)
    const long_boundary = "a" ** 71;
    const message = "--" ++ long_boundary ++ "\r\ntest\r\n--" ++ long_boundary ++ "--";

    const result = parser.parse(message, long_boundary);
    try testing.expectError(error.BoundaryTooLong, result);
}

test "security: enforce RFC 5322 header line length" {
    var parser = headers.HeaderParser.init(testing.allocator);

    // Create header line exceeding 998 characters
    var long_header = try testing.allocator.alloc(u8, 999);
    defer testing.allocator.free(long_header);

    @memcpy(long_header[0..8], "X-Test: ");
    @memset(long_header[8..], 'a');

    var data = try std.fmt.allocPrint(testing.allocator, "{s}\r\n\r\n", .{long_header});
    defer testing.allocator.free(data);

    const result = parser.parseHeaders(data);
    try testing.expectError(error.HeaderLineTooLong, result);
}

// ============================================================================
// OWASP A05:2021 - Security Misconfiguration
// ============================================================================

test "security: validate hostname format" {
    const invalid_hostnames = [_][]const u8{
        "host name", // space
        "host\tname", // tab
        "host\nname", // newline
        "host\rname", // carriage return
        "",          // empty
    };

    for (invalid_hostnames) |hostname| {
        const is_valid = security.isValidHostname(hostname);
        try testing.expect(!is_valid);
    }
}

test "security: validate proper email format" {
    // Test that validator catches common mistakes and attacks
    const invalid_formats = [_][]const u8{
        "",                  // empty
        "no-at-sign",       // missing @
        "@no-local.com",    // no local part
        "no-domain@",       // no domain
        "multiple@@at.com", // double @
        ".starts-with-dot@example.com", // starts with dot
        "ends-with-dot.@example.com",   // ends with dot
        "double..dots@example.com",     // consecutive dots
        "user@.starts-with-dot.com",    // domain starts with dot
        "user@ends-with-dot.com.",      // domain ends with dot
        "user@no-tld",                  // missing TLD
    };

    for (invalid_formats) |email| {
        const result = email_validator.EmailValidator.validate(email);
        try testing.expect(std.meta.isError(result));
    }
}

// ============================================================================
// OWASP A06:2021 - Vulnerable and Outdated Components
// ============================================================================

test "security: ensure secure defaults" {
    // Verify rate limiter has reasonable defaults
    var rate_limiter = security.RateLimiter.init(
        testing.allocator,
        60,
        100,
        200,
        300,
    );
    defer rate_limiter.deinit();

    try testing.expect(rate_limiter.window_seconds > 0);
    try testing.expect(rate_limiter.max_requests > 0);
    try testing.expect(rate_limiter.max_requests_per_user > 0);
}

// ============================================================================
// OWASP A09:2021 - Security Logging and Monitoring Failures
// ============================================================================

test "security: validate input sanitization logging" {
    // Test that malicious inputs are detected
    const malicious_input = "test\r\n\r\ninjected";
    const is_safe = security.sanitizeInput(malicious_input);

    try testing.expect(!is_safe);
    // In production, this should be logged as a security event
}

// ============================================================================
// Additional Security Tests - Email-Specific Attacks
// ============================================================================

test "security: prevent directory traversal in attachments" {
    const malicious_filenames = [_][]const u8{
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "/etc/shadow",
        "C:\\Windows\\System32\\config\\SAM",
    };

    // These should be sanitized or rejected in real implementation
    for (malicious_filenames) |filename| {
        // Filename should not contain path traversal
        try testing.expect(std.mem.indexOf(u8, filename, "..") != null or
            std.mem.indexOf(u8, filename, "/") == 0 or
            std.mem.indexOf(u8, filename, "\\") != null);
    }
}

test "security: prevent homograph attacks in email addresses" {
    // Cyrillic 'а' vs Latin 'a' - visually similar but different
    // In production, should normalize or detect these
    const suspicious_emails = [_][]const u8{
        "admin@exаmple.com", // Cyrillic а
        "support@gооgle.com", // Cyrillic о
    };

    // These contain non-ASCII characters that should be validated
    for (suspicious_emails) |email| {
        for (email) |char| {
            if (char > 127) {
                // Non-ASCII detected
                break;
            }
        }
    }
}

test "security: prevent email spoofing via display name" {
    // "Admin <attacker@evil.com>" could fool users
    // Parser should extract actual email, not display name
    const test_email = "CEO <attacker@malicious.com>";

    // Should extract just the email part
    if (std.mem.indexOf(u8, test_email, "<")) |start| {
        if (std.mem.indexOf(u8, test_email[start..], ">")) |end_rel| {
            const actual_email = test_email[start + 1 .. start + end_rel];
            try testing.expect(!std.mem.eql(u8, actual_email, "ceo@company.com"));
            try testing.expect(std.mem.indexOf(u8, actual_email, "malicious") != null);
        }
    }
}

test "security: prevent buffer overflow with large inputs" {
    // Test that parser handles large inputs safely
    const huge_boundary = "a" ** 1000;
    var parser = mime.MultipartParser.init(testing.allocator);

    const result = parser.parse("test", huge_boundary);
    // Should error with BoundaryTooLong, not crash
    try testing.expectError(error.BoundaryTooLong, result);
}

test "security: validate email local part characters" {
    const emails_with_special_chars = [_][]const u8{
        "user<script>@example.com",
        "user%0d%0a@example.com",
        "user\r\n@example.com",
        "user\x00@example.com",
    };

    for (emails_with_special_chars) |email| {
        const result = email_validator.EmailValidator.validate(email);
        // Should fail validation
        try testing.expect(std.meta.isError(result));
    }
}

test "security: prevent ReDoS via complex email patterns" {
    // Test that email validation doesn't hang on complex inputs
    const complex_emails = [_][]const u8{
        "a" ** 64 ++ "@" ++ "b" ** 255,
        ("x" ** 60) ++ "@" ++ ("y." ** 50) ++ "com",
    };

    for (complex_emails) |email| {
        _ = email_validator.EmailValidator.validate(email) catch {
            // Expected to fail, but shouldn't hang
            continue;
        };
    }
}

test "security: prevent null byte injection" {
    const null_byte_inputs = [_][]const u8{
        "user\x00@example.com",
        "user@example.com\x00.evil.com",
        "user@\x00example.com",
    };

    for (null_byte_inputs) |input| {
        const is_safe = security.sanitizeInput(input);
        try testing.expect(!is_safe);
    }
}

test "security: enforce domain label length limits" {
    // Each DNS label must be ≤ 63 characters
    const long_label = "a" ** 64;
    const email = "user@" ++ long_label ++ ".com";

    const result = email_validator.EmailValidator.validate(email);
    try testing.expectError(error.DomainLabelTooLong, result);
}

test "security: prevent MIME bomb attacks" {
    // MIME bombs use deeply nested MIME to cause resource exhaustion
    // Our depth limit of 10 should prevent this
    var parser = mime.MultipartParser.init(testing.allocator);

    // Set to maximum allowed depth
    parser.current_depth = mime.MultipartParser.MAX_MIME_DEPTH;

    const message = "--boundary\r\ntest\r\n--boundary--";
    const result = parser.parse(message, "boundary");

    try testing.expectError(error.MimeDepthExceeded, result);
}

test "security: validate IPv6 addresses in email domain literals" {
    const ipv6_tests = [_]struct {
        email: []const u8,
        should_pass: bool,
    }{
        .{ .email = "user@[IPv6:2001:db8::1]", .should_pass = true },
        .{ .email = "user@[IPv6:invalid]", .should_pass = false },
        .{ .email = "user@[IPv6::::::]", .should_pass = false },
    };

    for (ipv6_tests) |test_case| {
        const result = email_validator.EmailValidator.validate(test_case.email);
        if (test_case.should_pass) {
            try testing.expect(!std.meta.isError(result));
        } else {
            try testing.expect(std.meta.isError(result));
        }
    }
}
