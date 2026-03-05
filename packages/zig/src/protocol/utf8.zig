const std = @import("std");

/// UTF-8 email address validator for SMTPUTF8 support (RFC 6531)
pub const UTF8EmailValidator = struct {
    /// Validate UTF-8 email address
    /// Supports international domain names and UTF-8 local parts
    pub fn isValidUTF8Email(email: []const u8) bool {
        // Must be valid UTF-8
        if (!std.unicode.utf8ValidateSlice(email)) {
            return false;
        }

        // Find @ symbol
        const at_pos = std.mem.indexOf(u8, email, "@") orelse return false;

        // Must have characters before and after @
        if (at_pos == 0 or at_pos == email.len - 1) {
            return false;
        }

        // Only one @ symbol
        if (std.mem.count(u8, email, "@") != 1) {
            return false;
        }

        const local_part = email[0..at_pos];
        const domain_part = email[at_pos + 1 ..];

        // Validate local part (before @)
        if (!isValidUTF8LocalPart(local_part)) {
            return false;
        }

        // Validate domain part (after @)
        if (!isValidUTF8Domain(domain_part)) {
            return false;
        }

        return true;
    }

    fn isValidUTF8LocalPart(local: []const u8) bool {
        if (local.len == 0 or local.len > 64) {
            return false;
        }

        // Cannot start or end with dot
        if (local[0] == '.' or local[local.len - 1] == '.') {
            return false;
        }

        // No consecutive dots
        if (std.mem.indexOf(u8, local, "..") != null) {
            return false;
        }

        // Check for valid characters (ASCII or valid UTF-8)
        var i: usize = 0;
        while (i < local.len) {
            const c = local[i];

            // ASCII printable characters (excluding special chars not allowed)
            if (c >= 0x21 and c <= 0x7E) {
                // Allow alphanumeric, dot, hyphen, underscore, plus
                if (std.ascii.isAlphanumeric(c) or c == '.' or c == '-' or c == '_' or c == '+') {
                    i += 1;
                    continue;
                }
                return false;
            }

            // UTF-8 multi-byte character
            if (c >= 0x80) {
                const char_len = std.unicode.utf8ByteSequenceLength(c) catch return false;
                if (i + char_len > local.len) {
                    return false;
                }
                i += char_len;
                continue;
            }

            return false;
        }

        return true;
    }

    fn isValidUTF8Domain(domain: []const u8) bool {
        if (domain.len == 0 or domain.len > 255) {
            return false;
        }

        // Cannot start or end with dot or hyphen
        if (domain[0] == '.' or domain[domain.len - 1] == '.' or domain[0] == '-' or domain[domain.len - 1] == '-') {
            return false;
        }

        // Must have at least one dot for TLD
        if (std.mem.indexOf(u8, domain, ".") == null) {
            return false;
        }

        // Check labels
        var labels = std.mem.splitScalar(u8, domain, '.');
        var label_count: usize = 0;

        while (labels.next()) |label| {
            if (!isValidDomainLabel(label)) {
                return false;
            }
            label_count += 1;
        }

        return label_count >= 2;
    }

    fn isValidDomainLabel(label: []const u8) bool {
        if (label.len == 0 or label.len > 63) {
            return false;
        }

        // Cannot start or end with hyphen
        if (label[0] == '-' or label[label.len - 1] == '-') {
            return false;
        }

        // Check characters
        for (label) |c| {
            // Allow alphanumeric, hyphen, and UTF-8 for internationalized domains
            if (std.ascii.isAlphanumeric(c) or c == '-' or c >= 0x80) {
                continue;
            }
            return false;
        }

        return true;
    }

    /// Check if an email address requires SMTPUTF8
    pub fn requiresSMTPUTF8(email: []const u8) bool {
        for (email) |c| {
            if (c >= 0x80) {
                return true;
            }
        }
        return false;
    }
};

test "valid UTF-8 email addresses" {
    const testing = std.testing;

    // Standard ASCII
    try testing.expect(UTF8EmailValidator.isValidUTF8Email("test@example.com"));
    try testing.expect(UTF8EmailValidator.isValidUTF8Email("user.name@example.com"));
    try testing.expect(UTF8EmailValidator.isValidUTF8Email("user+tag@example.com"));

    // UTF-8 local part
    try testing.expect(UTF8EmailValidator.isValidUTF8Email("用户@example.com"));
    try testing.expect(UTF8EmailValidator.isValidUTF8Email("José@example.com"));

    // UTF-8 domain (internationalized domain names)
    try testing.expect(UTF8EmailValidator.isValidUTF8Email("user@例え.jp"));
}

test "invalid UTF-8 email addresses" {
    const testing = std.testing;

    // No @
    try testing.expect(!UTF8EmailValidator.isValidUTF8Email("test.example.com"));

    // Multiple @
    try testing.expect(!UTF8EmailValidator.isValidUTF8Email("test@@example.com"));

    // Empty local part
    try testing.expect(!UTF8EmailValidator.isValidUTF8Email("@example.com"));

    // Empty domain
    try testing.expect(!UTF8EmailValidator.isValidUTF8Email("test@"));

    // Consecutive dots
    try testing.expect(!UTF8EmailValidator.isValidUTF8Email("test..name@example.com"));

    // Starts/ends with dot
    try testing.expect(!UTF8EmailValidator.isValidUTF8Email(".test@example.com"));
    try testing.expect(!UTF8EmailValidator.isValidUTF8Email("test.@example.com"));
}

test "requires SMTPUTF8" {
    const testing = std.testing;

    // ASCII only
    try testing.expect(!UTF8EmailValidator.requiresSMTPUTF8("test@example.com"));

    // UTF-8 characters
    try testing.expect(UTF8EmailValidator.requiresSMTPUTF8("用户@example.com"));
    try testing.expect(UTF8EmailValidator.requiresSMTPUTF8("user@例え.jp"));
}
