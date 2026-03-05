const std = @import("std");
const time_compat = @import("time_compat.zig");

/// Certificate validation errors
pub const CertValidationError = error{
    CertificateExpired,
    CertificateNotYetValid,
    InvalidCertificateFormat,
    SelfSignedCertificate,
    InvalidSubject,
    InvalidIssuer,
    CertificateRevoked,
    ChainValidationFailed,
};

/// Certificate validation result
pub const ValidationResult = struct {
    valid: bool,
    self_signed: bool,
    expired: bool,
    not_yet_valid: bool,
    days_until_expiry: ?i64,
    subject_cn: ?[]const u8,
    issuer_cn: ?[]const u8,
    serial_number: ?[]const u8,
    warnings: std.ArrayList([]const u8),
    errors: std.ArrayList([]const u8),

    pub fn deinit(self: *ValidationResult, allocator: std.mem.Allocator) void {
        for (self.warnings.items) |warning| {
            allocator.free(warning);
        }
        self.warnings.deinit();

        for (self.errors.items) |err| {
            allocator.free(err);
        }
        self.errors.deinit();

        if (self.subject_cn) |cn| allocator.free(cn);
        if (self.issuer_cn) |cn| allocator.free(cn);
        if (self.serial_number) |sn| allocator.free(sn);
    }
};

/// Certificate validator
pub const CertificateValidator = struct {
    allocator: std.mem.Allocator,
    allow_self_signed: bool,
    max_cert_age_days: u32,

    pub fn init(allocator: std.mem.Allocator) CertificateValidator {
        return .{
            .allocator = allocator,
            .allow_self_signed = false,
            .max_cert_age_days = 397, // Current CA/Browser Forum baseline
        };
    }

    /// Parse a PEM certificate and extract basic information
    pub fn validateCertificate(self: *CertificateValidator, cert_pem: []const u8) !ValidationResult {
        var result = ValidationResult{
            .valid = true,
            .self_signed = false,
            .expired = false,
            .not_yet_valid = false,
            .days_until_expiry = null,
            .subject_cn = null,
            .issuer_cn = null,
            .serial_number = null,
            .warnings = std.ArrayList([]const u8).init(self.allocator),
            .errors = std.ArrayList([]const u8).init(self.allocator),
        };

        // Basic format validation
        if (!std.mem.startsWith(u8, cert_pem, "-----BEGIN CERTIFICATE-----")) {
            try result.errors.append(try self.allocator.dupe(u8, "Invalid PEM format: missing BEGIN marker"));
            result.valid = false;
            return result;
        }

        if (!std.mem.endsWith(u8, cert_pem, "-----END CERTIFICATE-----\n") and
            !std.mem.endsWith(u8, cert_pem, "-----END CERTIFICATE-----"))
        {
            try result.errors.append(try self.allocator.dupe(u8, "Invalid PEM format: missing END marker"));
            result.valid = false;
            return result;
        }

        // Extract base64 content
        const begin_marker = "-----BEGIN CERTIFICATE-----";
        const end_marker = "-----END CERTIFICATE-----";

        const start = std.mem.indexOf(u8, cert_pem, begin_marker) orelse return error.InvalidCertificateFormat;
        const end = std.mem.indexOf(u8, cert_pem, end_marker) orelse return error.InvalidCertificateFormat;

        if (start >= end) {
            try result.errors.append(try self.allocator.dupe(u8, "Invalid certificate structure"));
            result.valid = false;
            return result;
        }

        const cert_b64 = cert_pem[start + begin_marker.len .. end];

        // Basic validation: check if base64 is valid
        const decoder = std.base64.standard.Decoder;
        const decoded_len = decoder.calcSizeForSlice(cert_b64) catch {
            try result.errors.append(try self.allocator.dupe(u8, "Invalid base64 encoding"));
            result.valid = false;
            return result;
        };

        // Validate minimum size (X.509 certificates are typically > 100 bytes)
        if (decoded_len < 100) {
            try result.errors.append(try self.allocator.dupe(u8, "Certificate data too small"));
            result.valid = false;
            return result;
        }

        // Decode to verify it's valid base64
        const decoded = try self.allocator.alloc(u8, decoded_len);
        defer self.allocator.free(decoded);

        decoder.decode(decoded, cert_b64) catch {
            try result.errors.append(try self.allocator.dupe(u8, "Failed to decode base64"));
            result.valid = false;
            return result;
        };

        // Check for DER encoding markers (X.509 certificate structure)
        // SEQUENCE tag = 0x30
        if (decoded.len < 2 or decoded[0] != 0x30) {
            try result.errors.append(try self.allocator.dupe(u8, "Invalid DER encoding: missing SEQUENCE tag"));
            result.valid = false;
            return result;
        }

        // Parse basic certificate information
        try self.parseCertificateInfo(decoded, &result);

        // Check self-signed
        if (result.subject_cn != null and result.issuer_cn != null) {
            if (std.mem.eql(u8, result.subject_cn.?, result.issuer_cn.?)) {
                result.self_signed = true;
                if (!self.allow_self_signed) {
                    try result.warnings.append(try self.allocator.dupe(u8, "Certificate is self-signed"));
                }
            }
        }

        return result;
    }

    /// Parse certificate information from DER-encoded data
    /// This is a simplified parser - for production, use a proper X.509 parser
    fn parseCertificateInfo(self: *CertificateValidator, der: []const u8, result: *ValidationResult) !void {
        _ = der;

        // NOTE: Full X.509 parsing is complex and requires a proper ASN.1 parser
        // This is a placeholder that demonstrates the validation structure
        // For production use, integrate with a library like OpenSSL or BoringSSL via C interop

        // For now, just add informational warnings
        try result.warnings.append(try self.allocator.dupe(
            u8,
            "Full X.509 certificate parsing not yet implemented - only basic validation performed",
        ));

        // In a full implementation, we would:
        // 1. Parse the TBSCertificate structure
        // 2. Extract validity period (notBefore, notAfter)
        // 3. Extract subject DN and issuer DN
        // 4. Extract serial number
        // 5. Verify signature algorithm
        // 6. Check extensions (Key Usage, Subject Alternative Names, etc.)
        // 7. Verify certificate chain if provided

        // Placeholder values
        result.subject_cn = try self.allocator.dupe(u8, "Unknown (parser not implemented)");
        result.issuer_cn = try self.allocator.dupe(u8, "Unknown (parser not implemented)");
    }

    /// Validate certificate expiration dates
    pub fn checkExpiration(self: *CertificateValidator, not_before: i64, not_after: i64) !ValidationResult {
        var result = ValidationResult{
            .valid = true,
            .self_signed = false,
            .expired = false,
            .not_yet_valid = false,
            .days_until_expiry = null,
            .subject_cn = null,
            .issuer_cn = null,
            .serial_number = null,
            .warnings = std.ArrayList([]const u8).init(self.allocator),
            .errors = std.ArrayList([]const u8).init(self.allocator),
        };

        const now = time_compat.timestamp();

        // Check if certificate is not yet valid
        if (now < not_before) {
            result.not_yet_valid = true;
            result.valid = false;
            try result.errors.append(try self.allocator.dupe(u8, "Certificate not yet valid"));
            return result;
        }

        // Check if certificate is expired
        if (now > not_after) {
            result.expired = true;
            result.valid = false;
            try result.errors.append(try self.allocator.dupe(u8, "Certificate expired"));
            return result;
        }

        // Calculate days until expiry
        const seconds_until_expiry = not_after - now;
        const days_until_expiry = @divFloor(seconds_until_expiry, 86400);
        result.days_until_expiry = days_until_expiry;

        // Warn if expiring soon (30 days)
        if (days_until_expiry < 30) {
            const warning = try std.fmt.allocPrint(
                self.allocator,
                "Certificate expires in {d} days",
                .{days_until_expiry},
            );
            try result.warnings.append(warning);
        }

        return result;
    }

    /// Validate certificate hostname match (SAN or CN)
    pub fn validateHostname(self: *CertificateValidator, cert_cn: []const u8, expected_hostname: []const u8) !bool {
        // Exact match
        if (std.mem.eql(u8, cert_cn, expected_hostname)) {
            return true;
        }

        // Wildcard match (e.g., *.example.com matches mail.example.com)
        if (std.mem.startsWith(u8, cert_cn, "*.")) {
            const cert_domain = cert_cn[2..];
            if (std.mem.indexOf(u8, expected_hostname, ".")) |dot_pos| {
                const hostname_domain = expected_hostname[dot_pos + 1 ..];
                if (std.mem.eql(u8, cert_domain, hostname_domain)) {
                    return true;
                }
            }
        }

        _ = self;
        return false;
    }
};

test "certificate format validation" {
    const testing = std.testing;
    var validator = CertificateValidator.init(testing.allocator);

    const invalid_cert = "not a certificate";
    var result = try validator.validateCertificate(invalid_cert);
    defer result.deinit(testing.allocator);

    try testing.expect(!result.valid);
    try testing.expect(result.errors.items.len > 0);
}

test "hostname validation" {
    const testing = std.testing;
    var validator = CertificateValidator.init(testing.allocator);

    // Exact match
    try testing.expect(try validator.validateHostname("mail.example.com", "mail.example.com"));

    // Wildcard match
    try testing.expect(try validator.validateHostname("*.example.com", "mail.example.com"));
    try testing.expect(try validator.validateHostname("*.example.com", "smtp.example.com"));

    // No match
    try testing.expect(!try validator.validateHostname("mail.example.com", "smtp.example.com"));
    try testing.expect(!try validator.validateHostname("*.example.com", "example.com"));
}

test "expiration check" {
    const testing = std.testing;
    var validator = CertificateValidator.init(testing.allocator);

    const now = time_compat.timestamp();
    const not_before = now - 86400; // 1 day ago
    const not_after = now + (30 * 86400); // 30 days from now

    var result = try validator.checkExpiration(not_before, not_after);
    defer result.deinit(testing.allocator);

    try testing.expect(result.valid);
    try testing.expect(result.warnings.items.len > 0); // Should warn about expiring soon
}
