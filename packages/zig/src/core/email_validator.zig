const std = @import("std");

/// Comprehensive email address validator compliant with RFC 5321 and RFC 5322
pub const EmailValidator = struct {
    /// RFC 5321 limits
    pub const MAX_LOCAL_PART_LENGTH = 64;
    pub const MAX_DOMAIN_LENGTH = 255;
    pub const MAX_DOMAIN_LABEL_LENGTH = 63;
    pub const MAX_EMAIL_LENGTH = 320; // 64 (local) + 1 (@) + 255 (domain)

    /// Validate a complete email address
    pub fn validate(email: []const u8) !void {
        // Check overall length
        if (email.len == 0) return error.EmailEmpty;
        if (email.len > MAX_EMAIL_LENGTH) return error.EmailTooLong;

        // Find @ symbol
        const at_pos = std.mem.indexOf(u8, email, "@") orelse return error.MissingAtSymbol;

        // Can't have multiple @ symbols (simple check)
        if (std.mem.count(u8, email, "@") > 1) return error.MultipleAtSymbols;

        // Extract parts
        if (at_pos == 0) return error.EmptyLocalPart;
        if (at_pos == email.len - 1) return error.EmptyDomain;

        const local_part = email[0..at_pos];
        const domain = email[at_pos + 1 ..];

        // Validate parts
        try validateLocalPart(local_part);
        try validateDomain(domain);
    }

    /// Validate the local part (before @)
    fn validateLocalPart(local: []const u8) !void {
        if (local.len == 0) return error.EmptyLocalPart;
        if (local.len > MAX_LOCAL_PART_LENGTH) return error.LocalPartTooLong;

        // Check for quoted strings (RFC 5321 allows this)
        if (local[0] == '"') {
            return validateQuotedLocalPart(local);
        }

        // Validate dot-atom format
        return validateDotAtomLocalPart(local);
    }

    fn validateQuotedLocalPart(local: []const u8) !void {
        if (local.len < 2) return error.InvalidQuotedString;
        if (local[local.len - 1] != '"') return error.UnterminatedQuotedString;

        // Content between quotes can contain almost anything except unescaped quotes
        var i: usize = 1;
        var escaped = false;
        while (i < local.len - 1) : (i += 1) {
            const c = local[i];
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '"') return error.UnescapedQuoteInString;
            // Allow printable ASCII
            if (c < 32 or c > 126) return error.InvalidCharacterInQuotedString;
        }
    }

    fn validateDotAtomLocalPart(local: []const u8) !void {
        // Can't start or end with dot
        if (local[0] == '.') return error.LocalPartStartsWithDot;
        if (local[local.len - 1] == '.') return error.LocalPartEndsWithDot;

        // Can't have consecutive dots
        for (local[0 .. local.len - 1], 0..) |c, i| {
            if (c == '.' and local[i + 1] == '.') return error.ConsecutiveDotsInLocalPart;
        }

        // Validate characters
        for (local) |c| {
            const is_valid = std.ascii.isAlphanumeric(c) or
                c == '.' or c == '_' or c == '-' or c == '+' or
                c == '=' or c == '~' or c == '!' or c == '#' or
                c == '$' or c == '%' or c == '&' or c == '\'' or
                c == '*' or c == '/' or c == '?' or c == '^' or
                c == '`' or c == '{' or c == '|' or c == '}';

            if (!is_valid) return error.InvalidCharacterInLocalPart;
        }
    }

    /// Validate the domain part (after @)
    fn validateDomain(domain: []const u8) !void {
        if (domain.len == 0) return error.EmptyDomain;
        if (domain.len > MAX_DOMAIN_LENGTH) return error.DomainTooLong;

        // Check if it's an IP address literal (e.g., [192.168.1.1])
        if (domain[0] == '[') {
            return validateDomainLiteral(domain);
        }

        // Validate as hostname
        return validateHostname(domain);
    }

    fn validateDomainLiteral(domain: []const u8) !void {
        if (domain.len < 3) return error.InvalidDomainLiteral;
        if (domain[domain.len - 1] != ']') return error.UnterminatedDomainLiteral;

        const ip_part = domain[1 .. domain.len - 1];

        // Check for IPv6 prefix
        if (std.mem.startsWith(u8, ip_part, "IPv6:")) {
            // Basic IPv6 validation (simplified)
            const ipv6 = ip_part[5..];
            return validateIPv6(ipv6);
        }

        // Assume IPv4
        return validateIPv4(ip_part);
    }

    fn validateIPv4(ip: []const u8) !void {
        var parts = std.mem.splitSequence(u8, ip, ".");
        var count: u8 = 0;

        while (parts.next()) |part| {
            count += 1;
            if (count > 4) return error.InvalidIPv4;
            if (part.len == 0 or part.len > 3) return error.InvalidIPv4Octet;

            const num = std.fmt.parseInt(u8, part, 10) catch return error.InvalidIPv4Octet;
            _ = num; // Valid 0-255
        }

        if (count != 4) return error.InvalidIPv4;
    }

    fn validateIPv6(ip: []const u8) !void {
        // Simplified IPv6 validation (allows : and hex digits)
        if (ip.len == 0) return error.EmptyIPv6;

        var colon_count: u8 = 0;
        var double_colon = false;

        for (ip) |c| {
            if (c == ':') {
                colon_count += 1;
            } else if (c == '.') {
                // IPv4-mapped IPv6 address
                continue;
            } else if (!std.ascii.isHex(c)) {
                return error.InvalidIPv6Character;
            }
        }

        // Check for :: (can appear once)
        if (std.mem.indexOf(u8, ip, "::")) |_| {
            double_colon = true;
        }

        // Basic validation: should have 2-8 colons
        if (colon_count < 2 or colon_count > 7) {
            if (!double_colon) return error.InvalidIPv6;
        }
    }

    fn validateHostname(hostname: []const u8) !void {
        // Must contain at least one dot for a valid domain
        if (std.mem.indexOf(u8, hostname, ".") == null) return error.MissingDomainDot;

        // Can't start or end with dot or hyphen
        if (hostname[0] == '.' or hostname[0] == '-') return error.InvalidHostnameStart;
        if (hostname[hostname.len - 1] == '.' or hostname[hostname.len - 1] == '-') return error.InvalidHostnameEnd;

        // Split into labels
        var labels = std.mem.splitSequence(u8, hostname, ".");
        var label_count: u32 = 0;

        while (labels.next()) |label| {
            label_count += 1;
            try validateDomainLabel(label);
        }

        if (label_count < 2) return error.InsufficientDomainLabels;
    }

    fn validateDomainLabel(label: []const u8) !void {
        if (label.len == 0) return error.EmptyDomainLabel;
        if (label.len > MAX_DOMAIN_LABEL_LENGTH) return error.DomainLabelTooLong;

        // Can't start or end with hyphen
        if (label[0] == '-') return error.LabelStartsWithHyphen;
        if (label[label.len - 1] == '-') return error.LabelEndsWithHyphen;

        // Validate characters (letters, digits, hyphens only)
        for (label) |c| {
            const is_valid = std.ascii.isAlphanumeric(c) or c == '-';
            if (!is_valid) return error.InvalidCharacterInDomainLabel;
        }
    }

    /// Check if email is valid (returns bool instead of error)
    pub fn isValid(email: []const u8) bool {
        validate(email) catch return false;
        return true;
    }

    /// Extract local part from valid email
    pub fn getLocalPart(email: []const u8) ![]const u8 {
        const at_pos = std.mem.indexOf(u8, email, "@") orelse return error.MissingAtSymbol;
        return email[0..at_pos];
    }

    /// Extract domain from valid email
    pub fn getDomain(email: []const u8) ![]const u8 {
        const at_pos = std.mem.indexOf(u8, email, "@") orelse return error.MissingAtSymbol;
        return email[at_pos + 1 ..];
    }

    /// Normalize email address (lowercase domain, preserve local part case sensitivity)
    pub fn normalize(allocator: std.mem.Allocator, email: []const u8) ![]const u8 {
        const at_pos = std.mem.indexOf(u8, email, "@") orelse return error.MissingAtSymbol;

        const local = email[0..at_pos];
        const domain = email[at_pos + 1 ..];

        // Normalize domain to lowercase
        var normalized = try allocator.alloc(u8, email.len);
        @memcpy(normalized[0..local.len], local);
        normalized[local.len] = '@';

        for (domain, 0..) |c, i| {
            normalized[local.len + 1 + i] = std.ascii.toLower(c);
        }

        return normalized;
    }
};

// Tests
test "valid email addresses" {
    const testing = std.testing;

    const valid_emails = [_][]const u8{
        "user@example.com",
        "test.user@example.co.uk",
        "user+tag@example.com",
        "user_name@example.com",
        "user-name@example.com",
        "123@example.com",
        "a@example.co",
        "user@192.168.1.1", // Would fail without domain dot check, but this has the number format
    };

    for (valid_emails) |email| {
        try EmailValidator.validate(email);
    }
}

test "invalid email addresses" {
    const testing = std.testing;

    const invalid_emails = [_]struct { email: []const u8, expected_error: anyerror }{
        .{ .email = "", .expected_error = error.EmailEmpty },
        .{ .email = "user", .expected_error = error.MissingAtSymbol },
        .{ .email = "@example.com", .expected_error = error.EmptyLocalPart },
        .{ .email = "user@", .expected_error = error.EmptyDomain },
        .{ .email = "user@@example.com", .expected_error = error.MultipleAtSymbols },
        .{ .email = ".user@example.com", .expected_error = error.LocalPartStartsWithDot },
        .{ .email = "user.@example.com", .expected_error = error.LocalPartEndsWithDot },
        .{ .email = "user..name@example.com", .expected_error = error.ConsecutiveDotsInLocalPart },
        .{ .email = "user@.example.com", .expected_error = error.InvalidHostnameStart },
        .{ .email = "user@example.com.", .expected_error = error.InvalidHostnameEnd },
        .{ .email = "user@example", .expected_error = error.MissingDomainDot },
    };

    for (invalid_emails) |case| {
        try testing.expectError(case.expected_error, EmailValidator.validate(case.email));
    }
}

test "email address length limits" {
    const testing = std.testing;

    // Create a local part that's 65 characters (too long)
    const long_local = "a" ** 65 ++ "@example.com";
    try testing.expectError(error.LocalPartTooLong, EmailValidator.validate(long_local));

    // Create a domain that's 256 characters (too long)
    const long_domain = "user@" ++ ("a" ** 250) ++ ".com";
    try testing.expectError(error.DomainTooLong, EmailValidator.validate(long_domain));
}

test "domain label validation" {
    const testing = std.testing;

    const invalid_domains = [_][]const u8{
        "user@-example.com", // starts with hyphen
        "user@example-.com", // ends with hyphen
        "user@exam ple.com", // space in label
    };

    for (invalid_domains) |email| {
        const result = EmailValidator.validate(email);
        try testing.expect(std.meta.isError(result));
    }
}

test "normalize email" {
    const testing = std.testing;

    const normalized = try EmailValidator.normalize(testing.allocator, "User@EXAMPLE.COM");
    defer testing.allocator.free(normalized);

    try testing.expectEqualStrings("User@example.com", normalized);
}

test "extract parts" {
    const testing = std.testing;

    const email = "user@example.com";
    const local = try EmailValidator.getLocalPart(email);
    const domain = try EmailValidator.getDomain(email);

    try testing.expectEqualStrings("user", local);
    try testing.expectEqualStrings("example.com", domain);
}
