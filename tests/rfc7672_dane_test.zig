// RFC 7672 DANE/TLSA Test Suite
// Tests for DNS-Based Authentication of Named Entities as applied to SMTP.
// https://datatracker.ietf.org/doc/html/rfc7672
// https://datatracker.ietf.org/doc/html/rfc6698

const std = @import("std");
const testing = std.testing;
const dane = @import("mail").dane;

// ============================================================================
// TLSA record parsing tests
// ============================================================================

test "RFC 7672 TLSA record parsing: DANE-EE SHA-256" {
    // Usage 3 (DANE-EE), Selector 1 (SPKI), Matching type 1 (SHA-256)
    const sha256_hex = "a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1";
    const record_text = "3 1 1 " ++ sha256_hex;

    var record = try dane.TLSARecord.parse(testing.allocator, record_text);
    defer record.deinit();

    try testing.expectEqual(dane.TLSAUsage.DOMAIN_ISSUED_CERT, record.usage);
    try testing.expectEqual(dane.TLSASelector.SUBJECT_PUBLIC_KEY_INFO, record.selector);
    try testing.expectEqual(dane.TLSAMatchingType.SHA256, record.matching_type);
    try testing.expectEqualStrings(sha256_hex, record.certificate_data);
    try testing.expectEqual(false, record.dnssec_validated);
}

test "RFC 7672 TLSA record parsing: PKIX-TA full cert SHA-512" {
    // Usage 0 (PKIX-TA), Selector 0 (Full cert), Matching type 2 (SHA-512)
    const sha512_hex = "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1" ++
        "c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3";
    const record_text = "0 0 2 " ++ sha512_hex;

    var record = try dane.TLSARecord.parse(testing.allocator, record_text);
    defer record.deinit();

    try testing.expectEqual(dane.TLSAUsage.CA_CONSTRAINT, record.usage);
    try testing.expectEqual(dane.TLSASelector.FULL_CERT, record.selector);
    try testing.expectEqual(dane.TLSAMatchingType.SHA512, record.matching_type);
    try testing.expectEqualStrings(sha512_hex, record.certificate_data);
}

test "RFC 7672 TLSA record parsing: PKIX-EE with SPKI" {
    const sha256_hex = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";
    const record_text = "1 1 1 " ++ sha256_hex;

    var record = try dane.TLSARecord.parse(testing.allocator, record_text);
    defer record.deinit();

    try testing.expectEqual(dane.TLSAUsage.SERVICE_CERT_CONSTRAINT, record.usage);
    try testing.expectEqual(dane.TLSASelector.SUBJECT_PUBLIC_KEY_INFO, record.selector);
}

test "RFC 7672 TLSA record parsing: DANE-TA trust anchor" {
    const sha256_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const record_text = "2 0 1 " ++ sha256_hex;

    var record = try dane.TLSARecord.parse(testing.allocator, record_text);
    defer record.deinit();

    try testing.expectEqual(dane.TLSAUsage.TRUST_ANCHOR_ASSERTION, record.usage);
    try testing.expectEqual(dane.TLSASelector.FULL_CERT, record.selector);
}

test "RFC 7672 TLSA record parsing: whitespace handling" {
    const sha256_hex = "a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1";
    const record_text = "  3 1 1 " ++ sha256_hex ++ "  ";

    var record = try dane.TLSARecord.parse(testing.allocator, record_text);
    defer record.deinit();

    try testing.expectEqual(dane.TLSAUsage.DOMAIN_ISSUED_CERT, record.usage);
}

// ============================================================================
// TLSA record parsing error cases
// ============================================================================

test "RFC 7672 TLSA record parsing: empty input" {
    try testing.expectError(error.InvalidTLSARecord, dane.TLSARecord.parse(testing.allocator, ""));
    try testing.expectError(error.InvalidTLSARecord, dane.TLSARecord.parse(testing.allocator, "   "));
}

test "RFC 7672 TLSA record parsing: invalid usage value" {
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "5 1 1 aabb"),
    );
}

test "RFC 7672 TLSA record parsing: missing fields" {
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "3"),
    );
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "3 1"),
    );
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "3 1 1"),
    );
}

test "RFC 7672 TLSA record parsing: non-hex certificate data" {
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "3 1 1 not-hex-data-here!!"),
    );
}

test "RFC 7672 TLSA record parsing: wrong SHA-256 data length" {
    // SHA-256 expects 64 hex chars (32 bytes), provide wrong length
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "3 1 1 aabb"),
    );
}

test "RFC 7672 TLSA record parsing: wrong SHA-512 data length" {
    // SHA-512 expects 128 hex chars (64 bytes), provide wrong length
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "3 1 2 aabb"),
    );
}

// ============================================================================
// TLSA record format tests
// ============================================================================

test "RFC 7672 TLSA record format roundtrip" {
    const sha256_hex = "a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1";
    var record = try dane.TLSARecord.parse(testing.allocator, "3 1 1 " ++ sha256_hex);
    defer record.deinit();

    const formatted = try record.format(testing.allocator);
    defer testing.allocator.free(formatted);

    try testing.expectEqualStrings("3 1 1 " ++ sha256_hex, formatted);
}

test "RFC 7672 TLSA record DNS name generation" {
    const dns_name = try dane.TLSARecord.dnsName(testing.allocator, "mail.example.com", 25);
    defer testing.allocator.free(dns_name);

    try testing.expectEqualStrings("_25._tcp.mail.example.com", dns_name);
}

test "RFC 7672 TLSA record DNS name for port 465" {
    const dns_name = try dane.TLSARecord.dnsName(testing.allocator, "smtp.example.com", 465);
    defer testing.allocator.free(dns_name);

    try testing.expectEqualStrings("_465._tcp.smtp.example.com", dns_name);
}

// ============================================================================
// TLSAUsage property tests
// ============================================================================

test "RFC 7672 TLSAUsage toString" {
    try testing.expect(std.mem.indexOf(u8, dane.TLSAUsage.CA_CONSTRAINT.toString(), "PKIX-TA") != null);
    try testing.expect(std.mem.indexOf(u8, dane.TLSAUsage.SERVICE_CERT_CONSTRAINT.toString(), "PKIX-EE") != null);
    try testing.expect(std.mem.indexOf(u8, dane.TLSAUsage.TRUST_ANCHOR_ASSERTION.toString(), "DANE-TA") != null);
    try testing.expect(std.mem.indexOf(u8, dane.TLSAUsage.DOMAIN_ISSUED_CERT.toString(), "DANE-EE") != null);
}

test "RFC 7672 TLSAUsage fromInt" {
    try testing.expectEqual(dane.TLSAUsage.CA_CONSTRAINT, dane.TLSAUsage.fromInt(0).?);
    try testing.expectEqual(dane.TLSAUsage.SERVICE_CERT_CONSTRAINT, dane.TLSAUsage.fromInt(1).?);
    try testing.expectEqual(dane.TLSAUsage.TRUST_ANCHOR_ASSERTION, dane.TLSAUsage.fromInt(2).?);
    try testing.expectEqual(dane.TLSAUsage.DOMAIN_ISSUED_CERT, dane.TLSAUsage.fromInt(3).?);
    try testing.expect(dane.TLSAUsage.fromInt(4) == null);
    try testing.expect(dane.TLSAUsage.fromInt(255) == null);
}

test "RFC 7672 TLSAUsage requiresPKIX" {
    try testing.expect(dane.TLSAUsage.CA_CONSTRAINT.requiresPKIX());
    try testing.expect(dane.TLSAUsage.SERVICE_CERT_CONSTRAINT.requiresPKIX());
    try testing.expect(!dane.TLSAUsage.TRUST_ANCHOR_ASSERTION.requiresPKIX());
    try testing.expect(!dane.TLSAUsage.DOMAIN_ISSUED_CERT.requiresPKIX());
}

test "RFC 7672 TLSAUsage isEndEntity" {
    try testing.expect(!dane.TLSAUsage.CA_CONSTRAINT.isEndEntity());
    try testing.expect(dane.TLSAUsage.SERVICE_CERT_CONSTRAINT.isEndEntity());
    try testing.expect(!dane.TLSAUsage.TRUST_ANCHOR_ASSERTION.isEndEntity());
    try testing.expect(dane.TLSAUsage.DOMAIN_ISSUED_CERT.isEndEntity());
}

// ============================================================================
// TLSASelector and TLSAMatchingType property tests
// ============================================================================

test "RFC 7672 TLSASelector toString" {
    try testing.expect(std.mem.indexOf(u8, dane.TLSASelector.FULL_CERT.toString(), "Certificate") != null);
    try testing.expect(std.mem.indexOf(u8, dane.TLSASelector.SUBJECT_PUBLIC_KEY_INFO.toString(), "Public") != null);
}

test "RFC 7672 TLSASelector fromInt" {
    try testing.expectEqual(dane.TLSASelector.FULL_CERT, dane.TLSASelector.fromInt(0).?);
    try testing.expectEqual(dane.TLSASelector.SUBJECT_PUBLIC_KEY_INFO, dane.TLSASelector.fromInt(1).?);
    try testing.expect(dane.TLSASelector.fromInt(2) == null);
}

test "RFC 7672 TLSAMatchingType toString and fromInt" {
    try testing.expect(std.mem.indexOf(u8, dane.TLSAMatchingType.EXACT.toString(), "Exact") != null);
    try testing.expect(std.mem.indexOf(u8, dane.TLSAMatchingType.SHA256.toString(), "256") != null);
    try testing.expect(std.mem.indexOf(u8, dane.TLSAMatchingType.SHA512.toString(), "512") != null);

    try testing.expectEqual(dane.TLSAMatchingType.EXACT, dane.TLSAMatchingType.fromInt(0).?);
    try testing.expectEqual(dane.TLSAMatchingType.SHA256, dane.TLSAMatchingType.fromInt(1).?);
    try testing.expectEqual(dane.TLSAMatchingType.SHA512, dane.TLSAMatchingType.fromInt(2).?);
    try testing.expect(dane.TLSAMatchingType.fromInt(3) == null);
}

test "RFC 7672 TLSAMatchingType hashLength" {
    try testing.expect(dane.TLSAMatchingType.EXACT.hashLength() == null);
    try testing.expectEqual(@as(usize, 32), dane.TLSAMatchingType.SHA256.hashLength().?);
    try testing.expectEqual(@as(usize, 64), dane.TLSAMatchingType.SHA512.hashLength().?);
}

// ============================================================================
// DANEResult property tests
// ============================================================================

test "RFC 7672 DANEResult toString" {
    try testing.expectEqualStrings("pass", dane.DANEResult.pass.toString());
    try testing.expectEqualStrings("fail", dane.DANEResult.fail.toString());
    try testing.expectEqualStrings("temperror", dane.DANEResult.temperror.toString());
    try testing.expectEqualStrings("permerror", dane.DANEResult.permerror.toString());
    try testing.expectEqualStrings("no_tlsa", dane.DANEResult.no_tlsa.toString());
}

test "RFC 7672 DANEResult shouldProceed" {
    // pass and no_tlsa should proceed
    try testing.expect(dane.DANEResult.pass.shouldProceed());
    try testing.expect(dane.DANEResult.no_tlsa.shouldProceed());
    // temperror should proceed (fail-open per RFC 7672)
    try testing.expect(dane.DANEResult.temperror.shouldProceed());
    // fail and permerror should NOT proceed
    try testing.expect(!dane.DANEResult.fail.shouldProceed());
    try testing.expect(!dane.DANEResult.permerror.shouldProceed());
}

test "RFC 7672 DANEResult requiresTLS" {
    // When DANE records exist, TLS is mandatory
    try testing.expect(dane.DANEResult.pass.requiresTLS());
    try testing.expect(dane.DANEResult.fail.requiresTLS());
    try testing.expect(dane.DANEResult.permerror.requiresTLS());
    // When no DANE records or temp error, TLS is not mandatory
    try testing.expect(!dane.DANEResult.no_tlsa.requiresTLS());
    try testing.expect(!dane.DANEResult.temperror.requiresTLS());
}

// ============================================================================
// DANE policy tests
// ============================================================================

test "RFC 7672 DANE policy init and deinit" {
    var policy = try dane.DANEPolicy.init(testing.allocator, "mail.example.com", 3600);
    defer policy.deinit();

    try testing.expectEqualStrings("mail.example.com", policy.domain);
    try testing.expectEqual(@as(u32, 3600), policy.cache_ttl);
    try testing.expectEqual(@as(usize, 0), policy.recordCount());
    try testing.expect(policy.last_checked > 0);
}

test "RFC 7672 DANE policy addRecord" {
    var policy = try dane.DANEPolicy.init(testing.allocator, "mail.example.com", 3600);
    defer policy.deinit();

    const sha256_hex = "a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1";
    const record = try dane.TLSARecord.parse(testing.allocator, "3 1 1 " ++ sha256_hex);

    try policy.addRecord(record);
    try testing.expectEqual(@as(usize, 1), policy.recordCount());
}

test "RFC 7672 DANE policy requiresPKIX" {
    // Policy with only DANE-EE records should not require PKIX
    var policy = try dane.DANEPolicy.init(testing.allocator, "mail.example.com", 3600);
    defer policy.deinit();

    const sha256_hex = "a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1";
    const record = try dane.TLSARecord.parse(testing.allocator, "3 1 1 " ++ sha256_hex);
    try policy.addRecord(record);

    try testing.expect(!policy.requiresPKIX());
}

test "RFC 7672 DANE policy requiresPKIX with PKIX-TA" {
    var policy = try dane.DANEPolicy.init(testing.allocator, "mail.example.com", 3600);
    defer policy.deinit();

    const sha256_hex = "a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1";
    // Usage 0 (CA_CONSTRAINT) requires PKIX
    const record = try dane.TLSARecord.parse(testing.allocator, "0 1 1 " ++ sha256_hex);
    try policy.addRecord(record);

    try testing.expect(policy.requiresPKIX());
}

// ============================================================================
// DANE policy cache tests
// ============================================================================

test "RFC 7672 DANE policy cache init and deinit" {
    var cache = dane.DANEPolicyCache.init(testing.allocator, 100);
    defer cache.deinit();

    try testing.expectEqual(@as(usize, 0), cache.count());
}

test "RFC 7672 DANE policy cache put and get" {
    var cache = dane.DANEPolicyCache.init(testing.allocator, 100);
    defer cache.deinit();

    const policy = try dane.DANEPolicy.init(testing.allocator, "mail.example.com", 3600);
    try cache.put(policy);

    const cached = cache.get("mail.example.com");
    try testing.expect(cached != null);
    try testing.expectEqualStrings("mail.example.com", cached.?.domain);
}

test "RFC 7672 DANE policy cache miss" {
    var cache = dane.DANEPolicyCache.init(testing.allocator, 100);
    defer cache.deinit();

    try testing.expect(cache.get("nonexistent.com") == null);
}

test "RFC 7672 DANE policy cache remove" {
    var cache = dane.DANEPolicyCache.init(testing.allocator, 100);
    defer cache.deinit();

    const policy = try dane.DANEPolicy.init(testing.allocator, "mail.example.com", 3600);
    try cache.put(policy);

    try testing.expect(cache.get("mail.example.com") != null);
    cache.remove("mail.example.com");
    try testing.expect(cache.get("mail.example.com") == null);
}

test "RFC 7672 DANE policy cache isExpired for missing domain" {
    var cache = dane.DANEPolicyCache.init(testing.allocator, 100);
    defer cache.deinit();

    try testing.expect(cache.isExpired("nonexistent.com"));
}

test "RFC 7672 DANE policy cache count" {
    var cache = dane.DANEPolicyCache.init(testing.allocator, 100);
    defer cache.deinit();

    const p1 = try dane.DANEPolicy.init(testing.allocator, "a.example.com", 3600);
    const p2 = try dane.DANEPolicy.init(testing.allocator, "b.example.com", 3600);

    try cache.put(p1);
    try cache.put(p2);

    try testing.expectEqual(@as(usize, 2), cache.count());
}

// ============================================================================
// DANE validator tests
// ============================================================================

test "RFC 7672 DANE validator init and deinit" {
    var validator = dane.DANEValidator.init(testing.allocator);
    defer validator.deinit();

    try testing.expectEqual(@as(u32, 5000), validator.dns_timeout_ms);
}

test "RFC 7672 DANE validator lookupTLSA returns null for unknown domain" {
    var validator = dane.DANEValidator.init(testing.allocator);
    defer validator.deinit();

    // Stubbed DNS returns null for unknown domains
    const result = try validator.lookupTLSA("unknown.example.com", 25);
    try testing.expect(result == null);
}

test "RFC 7672 DANE validator validateCertificate with no records returns no_tlsa" {
    var validator = dane.DANEValidator.init(testing.allocator);
    defer validator.deinit();

    const empty_records = &[_]dane.TLSARecord{};
    const result = validator.validateCertificate("cert-data", empty_records);
    try testing.expectEqual(dane.DANEResult.no_tlsa, result);
}

test "RFC 7672 DANE validator validateCertificate with empty cert returns permerror" {
    var validator = dane.DANEValidator.init(testing.allocator);
    defer validator.deinit();

    const sha256_hex = "a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1";
    var record = try dane.TLSARecord.parse(testing.allocator, "3 1 1 " ++ sha256_hex);
    defer record.deinit();

    const records = &[_]dane.TLSARecord{record};
    const result = validator.validateCertificate("", records);
    try testing.expectEqual(dane.DANEResult.permerror, result);
}

// ============================================================================
// Edge case tests: Invalid TLSA record data
// ============================================================================

test "RFC 7672 edge case: TLSA record with all-zero SHA-256 data" {
    // All-zero hash is technically valid hex; it should parse successfully.
    const all_zeros = "0000000000000000000000000000000000000000000000000000000000000000";
    var record = try dane.TLSARecord.parse(testing.allocator, "3 1 1 " ++ all_zeros);
    defer record.deinit();

    try testing.expectEqual(dane.TLSAUsage.DOMAIN_ISSUED_CERT, record.usage);
    try testing.expectEqualStrings(all_zeros, record.certificate_data);
}

test "RFC 7672 edge case: TLSA record with all-zero SHA-512 data" {
    const all_zeros = "0" ** 128;
    var record = try dane.TLSARecord.parse(testing.allocator, "3 1 2 " ++ all_zeros);
    defer record.deinit();

    try testing.expectEqual(dane.TLSAMatchingType.SHA512, record.matching_type);
    try testing.expectEqualStrings(all_zeros, record.certificate_data);
}

test "RFC 7672 edge case: TLSA record with all-ff data" {
    const all_ff = "f" ** 64;
    var record = try dane.TLSARecord.parse(testing.allocator, "3 0 1 " ++ all_ff);
    defer record.deinit();

    try testing.expectEqualStrings(all_ff, record.certificate_data);
}

test "RFC 7672 edge case: TLSA record with uppercase hex data" {
    const upper_hex = "A0B9C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1";
    var record = try dane.TLSARecord.parse(testing.allocator, "3 1 1 " ++ upper_hex);
    defer record.deinit();

    try testing.expectEqualStrings(upper_hex, record.certificate_data);
}

test "RFC 7672 edge case: TLSA record with mixed-case hex data" {
    const mixed_hex = "aAbBcCdDeEfF00112233445566778899AaBbCcDdEeFf00112233445566778899";
    var record = try dane.TLSARecord.parse(testing.allocator, "2 0 1 " ++ mixed_hex);
    defer record.deinit();

    try testing.expectEqualStrings(mixed_hex, record.certificate_data);
}

// ============================================================================
// Edge case tests: Certificate usage type boundaries
// ============================================================================

test "RFC 7672 edge case: usage value 4 is invalid" {
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "4 1 1 a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"),
    );
}

test "RFC 7672 edge case: usage value 255 is invalid" {
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "255 1 1 a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"),
    );
}

test "RFC 7672 edge case: usage value 256 overflows u8 parse" {
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "256 1 1 a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"),
    );
}

test "RFC 7672 edge case: all valid usage values 0 through 3" {
    const sha256_hex = "a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1";
    const expected_usages = [_]dane.TLSAUsage{
        .CA_CONSTRAINT,
        .SERVICE_CERT_CONSTRAINT,
        .TRUST_ANCHOR_ASSERTION,
        .DOMAIN_ISSUED_CERT,
    };

    for (expected_usages, 0..) |expected, i| {
        var buf: [80]u8 = undefined;
        const record_text = std.fmt.bufPrint(&buf, "{d} 1 1 " ++ sha256_hex, .{i}) catch unreachable;
        var record = try dane.TLSARecord.parse(testing.allocator, record_text);
        defer record.deinit();
        try testing.expectEqual(expected, record.usage);
    }
}

test "RFC 7672 edge case: negative usage value" {
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "-1 1 1 a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"),
    );
}

// ============================================================================
// Edge case tests: Selector type boundaries
// ============================================================================

test "RFC 7672 edge case: selector value 2 is invalid" {
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "3 2 1 a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"),
    );
}

test "RFC 7672 edge case: selector value 255 is invalid" {
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "3 255 1 a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"),
    );
}

test "RFC 7672 edge case: valid selector 0 full cert" {
    const sha256_hex = "a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1";
    var record = try dane.TLSARecord.parse(testing.allocator, "3 0 1 " ++ sha256_hex);
    defer record.deinit();
    try testing.expectEqual(dane.TLSASelector.FULL_CERT, record.selector);
}

test "RFC 7672 edge case: valid selector 1 SPKI" {
    const sha256_hex = "a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1";
    var record = try dane.TLSARecord.parse(testing.allocator, "3 1 1 " ++ sha256_hex);
    defer record.deinit();
    try testing.expectEqual(dane.TLSASelector.SUBJECT_PUBLIC_KEY_INFO, record.selector);
}

// ============================================================================
// Edge case tests: Matching type boundaries
// ============================================================================

test "RFC 7672 edge case: matching type 3 is invalid" {
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "3 1 3 a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"),
    );
}

test "RFC 7672 edge case: matching type 100 is invalid" {
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "3 1 100 a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"),
    );
}

test "RFC 7672 edge case: matching type 0 (exact) accepts any length data" {
    // Exact matching type has no fixed hash length, so short data is fine
    var record = try dane.TLSARecord.parse(testing.allocator, "3 1 0 aabb");
    defer record.deinit();
    try testing.expectEqual(dane.TLSAMatchingType.EXACT, record.matching_type);
    try testing.expectEqualStrings("aabb", record.certificate_data);
}

test "RFC 7672 edge case: matching type 0 (exact) accepts long data" {
    // Exact match with large data representing a full certificate
    const long_hex = "ab" ** 256;
    var record = try dane.TLSARecord.parse(testing.allocator, "3 0 0 " ++ long_hex);
    defer record.deinit();
    try testing.expectEqual(dane.TLSAMatchingType.EXACT, record.matching_type);
    try testing.expectEqual(@as(usize, 512), record.certificate_data.len);
}

// ============================================================================
// Edge case tests: SHA-256 hash with wrong length
// ============================================================================

test "RFC 7672 edge case: SHA-256 with 31 bytes (62 hex chars) rejected" {
    const short_hex = "a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0";
    try testing.expectEqual(@as(usize, 62), short_hex.len);
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "3 1 1 " ++ short_hex),
    );
}

test "RFC 7672 edge case: SHA-256 with 33 bytes (66 hex chars) rejected" {
    const long_hex = "a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1cc";
    try testing.expectEqual(@as(usize, 66), long_hex.len);
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "3 1 1 " ++ long_hex),
    );
}

test "RFC 7672 edge case: SHA-256 with 1 byte (2 hex chars) rejected" {
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "3 1 1 aa"),
    );
}

// ============================================================================
// Edge case tests: SHA-512 hash with wrong length
// ============================================================================

test "RFC 7672 edge case: SHA-512 with 63 bytes (126 hex chars) rejected" {
    const short_hex = "ab" ** 63;
    try testing.expectEqual(@as(usize, 126), short_hex.len);
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "3 1 2 " ++ short_hex),
    );
}

test "RFC 7672 edge case: SHA-512 with 65 bytes (130 hex chars) rejected" {
    const long_hex = "ab" ** 65;
    try testing.expectEqual(@as(usize, 130), long_hex.len);
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "3 1 2 " ++ long_hex),
    );
}

test "RFC 7672 edge case: SHA-512 with SHA-256 length (64 hex chars) rejected" {
    // 64 hex chars = 32 bytes = SHA-256 size, but we specified matching type 2 (SHA-512)
    const sha256_sized = "a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1";
    try testing.expectEqual(@as(usize, 64), sha256_sized.len);
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "3 1 2 " ++ sha256_sized),
    );
}

// ============================================================================
// Edge case tests: DNS name generation
// ============================================================================

test "RFC 7672 edge case: DNS name for port 0" {
    const dns_name = try dane.TLSARecord.dnsName(testing.allocator, "mail.example.com", 0);
    defer testing.allocator.free(dns_name);
    try testing.expectEqualStrings("_0._tcp.mail.example.com", dns_name);
}

test "RFC 7672 edge case: DNS name for port 65535" {
    const dns_name = try dane.TLSARecord.dnsName(testing.allocator, "mail.example.com", 65535);
    defer testing.allocator.free(dns_name);
    try testing.expectEqualStrings("_65535._tcp.mail.example.com", dns_name);
}

test "RFC 7672 edge case: DNS name for empty domain" {
    const dns_name = try dane.TLSARecord.dnsName(testing.allocator, "", 25);
    defer testing.allocator.free(dns_name);
    try testing.expectEqualStrings("_25._tcp.", dns_name);
}

test "RFC 7672 edge case: DNS name for domain with trailing dot" {
    const dns_name = try dane.TLSARecord.dnsName(testing.allocator, "mail.example.com.", 25);
    defer testing.allocator.free(dns_name);
    try testing.expectEqualStrings("_25._tcp.mail.example.com.", dns_name);
}

test "RFC 7672 edge case: DNS name for very long domain" {
    // Build a domain name near the 255-character DNS limit
    const long_label = "a" ** 63;
    const long_domain = long_label ++ "." ++ long_label ++ "." ++ long_label ++ ".example.com";
    const dns_name = try dane.TLSARecord.dnsName(testing.allocator, long_domain, 25);
    defer testing.allocator.free(dns_name);

    // Verify it starts with expected prefix
    try testing.expect(std.mem.startsWith(u8, dns_name, "_25._tcp."));
    try testing.expect(std.mem.endsWith(u8, dns_name, ".example.com"));
}

test "RFC 7672 edge case: DNS name for port 587 (submission)" {
    const dns_name = try dane.TLSARecord.dnsName(testing.allocator, "smtp.example.com", 587);
    defer testing.allocator.free(dns_name);
    try testing.expectEqualStrings("_587._tcp.smtp.example.com", dns_name);
}

// ============================================================================
// Edge case tests: TLSA record format with edge values
// ============================================================================

test "RFC 7672 edge case: format roundtrip for all usage types" {
    const sha256_hex = "a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1";
    const usages = [_]u8{ 0, 1, 2, 3 };

    for (usages) |u| {
        var buf: [80]u8 = undefined;
        const record_text = std.fmt.bufPrint(&buf, "{d} 1 1 " ++ sha256_hex, .{u}) catch unreachable;
        var record = try dane.TLSARecord.parse(testing.allocator, record_text);
        defer record.deinit();

        const formatted = try record.format(testing.allocator);
        defer testing.allocator.free(formatted);

        try testing.expectEqualStrings(record_text, formatted);
    }
}

test "RFC 7672 edge case: format roundtrip for exact matching type" {
    // Exact matching (type 0) can have arbitrary-length data
    const hex_data = "deadbeef";
    var record = try dane.TLSARecord.parse(testing.allocator, "3 0 0 " ++ hex_data);
    defer record.deinit();

    const formatted = try record.format(testing.allocator);
    defer testing.allocator.free(formatted);

    try testing.expectEqualStrings("3 0 0 " ++ hex_data, formatted);
}

// ============================================================================
// Edge case tests: TLSA record parsing error cases
// ============================================================================

test "RFC 7672 edge case: only whitespace and tabs" {
    try testing.expectError(error.InvalidTLSARecord, dane.TLSARecord.parse(testing.allocator, " \t \t "));
}

test "RFC 7672 edge case: only newlines" {
    try testing.expectError(error.InvalidTLSARecord, dane.TLSARecord.parse(testing.allocator, "\n\n\n"));
}

test "RFC 7672 edge case: non-numeric usage field" {
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "abc 1 1 a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"),
    );
}

test "RFC 7672 edge case: non-numeric selector field" {
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "3 x 1 a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"),
    );
}

test "RFC 7672 edge case: non-numeric matching type field" {
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "3 1 z a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"),
    );
}

test "RFC 7672 edge case: certificate data with non-hex chars (g-z)" {
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "3 1 1 g0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"),
    );
}

test "RFC 7672 edge case: certificate data with special characters" {
    try testing.expectError(
        error.InvalidTLSARecord,
        dane.TLSARecord.parse(testing.allocator, "3 1 0 dead!beef"),
    );
}

// ============================================================================
// Edge case tests: DANEPolicy with multiple records
// ============================================================================

test "RFC 7672 edge case: policy with mixed usage types" {
    var policy = try dane.DANEPolicy.init(testing.allocator, "mail.example.com", 3600);
    defer policy.deinit();

    const sha256_hex = "a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1";

    // DANE-EE record (no PKIX required)
    const r1 = try dane.TLSARecord.parse(testing.allocator, "3 1 1 " ++ sha256_hex);
    try policy.addRecord(r1);
    try testing.expect(!policy.requiresPKIX());

    // Add a PKIX-TA record (now PKIX IS required)
    const r2 = try dane.TLSARecord.parse(testing.allocator, "0 1 1 " ++ sha256_hex);
    try policy.addRecord(r2);
    try testing.expect(policy.requiresPKIX());
    try testing.expectEqual(@as(usize, 2), policy.recordCount());
}

test "RFC 7672 edge case: policy with no records does not require PKIX" {
    var policy = try dane.DANEPolicy.init(testing.allocator, "mail.example.com", 3600);
    defer policy.deinit();

    try testing.expectEqual(@as(usize, 0), policy.recordCount());
    try testing.expect(!policy.requiresPKIX());
}

// ============================================================================
// Edge case tests: DANEPolicyCache eviction and capacity
// ============================================================================

test "RFC 7672 edge case: cache with max_entries of 1 forces eviction" {
    var cache = dane.DANEPolicyCache.init(testing.allocator, 1);
    defer cache.deinit();

    const p1 = try dane.DANEPolicy.init(testing.allocator, "a.example.com", 3600);
    try cache.put(p1);
    try testing.expectEqual(@as(usize, 1), cache.count());

    const p2 = try dane.DANEPolicy.init(testing.allocator, "b.example.com", 3600);
    try cache.put(p2);
    // After eviction, only the newest entry should remain
    try testing.expectEqual(@as(usize, 1), cache.count());
    try testing.expect(cache.get("b.example.com") != null);
}

test "RFC 7672 edge case: cache remove nonexistent domain is safe" {
    var cache = dane.DANEPolicyCache.init(testing.allocator, 100);
    defer cache.deinit();

    // Removing a domain that does not exist should not panic
    cache.remove("nonexistent.com");
    try testing.expectEqual(@as(usize, 0), cache.count());
}

// ============================================================================
// Edge case tests: DANEValidator certificate validation
// ============================================================================

test "RFC 7672 edge case: validateCertificate with mismatched hash returns fail" {
    var validator = dane.DANEValidator.init(testing.allocator);
    defer validator.deinit();

    // Create a DANE-EE record with a known SHA-256 hash
    const sha256_hex = "a0b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1";
    var record = try dane.TLSARecord.parse(testing.allocator, "3 1 1 " ++ sha256_hex);
    defer record.deinit();

    // Validate with cert data that will NOT match the hash
    const records = &[_]dane.TLSARecord{record};
    const result = validator.validateCertificate("this-cert-wont-match", records);
    try testing.expectEqual(dane.DANEResult.fail, result);
}

test "RFC 7672 edge case: validateSMTP with unknown domain returns no_tlsa" {
    var validator = dane.DANEValidator.init(testing.allocator);
    defer validator.deinit();

    const result = try validator.validateSMTP("unknown.example.com", 25, "some-cert-data");
    try testing.expectEqual(dane.DANEResult.no_tlsa, result);
}

test "RFC 7672 edge case: computeSHA256Hash produces correct length" {
    var validator = dane.DANEValidator.init(testing.allocator);
    defer validator.deinit();

    const hash = validator.computeSHA256Hash("test data");
    try testing.expectEqual(@as(usize, 32), hash.len);
}

test "RFC 7672 edge case: computeSHA512Hash produces correct length" {
    var validator = dane.DANEValidator.init(testing.allocator);
    defer validator.deinit();

    const hash = validator.computeSHA512Hash("test data");
    try testing.expectEqual(@as(usize, 64), hash.len);
}

test "RFC 7672 edge case: computeSHA256Hash empty input" {
    var validator = dane.DANEValidator.init(testing.allocator);
    defer validator.deinit();

    // SHA-256 of empty string is a well-known value
    const hash = validator.computeSHA256Hash("");
    try testing.expectEqual(@as(usize, 32), hash.len);
    // The hash should be deterministic (same input = same output)
    const hash2 = validator.computeSHA256Hash("");
    try testing.expectEqualSlices(u8, &hash, &hash2);
}

test "RFC 7672 edge case: computeSHA512Hash empty input" {
    var validator = dane.DANEValidator.init(testing.allocator);
    defer validator.deinit();

    const hash = validator.computeSHA512Hash("");
    try testing.expectEqual(@as(usize, 64), hash.len);
    const hash2 = validator.computeSHA512Hash("");
    try testing.expectEqualSlices(u8, &hash, &hash2);
}

// ============================================================================
// Edge case tests: TLSAUsage fromInt boundary
// ============================================================================

test "RFC 7672 edge case: TLSAUsage fromInt exhaustive invalid range" {
    // Test several values in the invalid range
    const invalid_values = [_]u8{ 4, 5, 10, 50, 100, 127, 128, 200, 254, 255 };
    for (invalid_values) |v| {
        try testing.expect(dane.TLSAUsage.fromInt(v) == null);
    }
}

test "RFC 7672 edge case: TLSASelector fromInt exhaustive invalid range" {
    const invalid_values = [_]u8{ 2, 3, 10, 50, 100, 127, 128, 200, 254, 255 };
    for (invalid_values) |v| {
        try testing.expect(dane.TLSASelector.fromInt(v) == null);
    }
}

test "RFC 7672 edge case: TLSAMatchingType fromInt exhaustive invalid range" {
    const invalid_values = [_]u8{ 3, 4, 10, 50, 100, 127, 128, 200, 254, 255 };
    for (invalid_values) |v| {
        try testing.expect(dane.TLSAMatchingType.fromInt(v) == null);
    }
}

// ============================================================================
// Edge case tests: DANEResult combined logic
// ============================================================================

test "RFC 7672 edge case: DANEResult shouldProceed and requiresTLS are consistent" {
    // If requiresTLS is true and shouldProceed is false, delivery must abort.
    // pass: proceed=true, tls=true -> deliver with TLS
    try testing.expect(dane.DANEResult.pass.shouldProceed() and dane.DANEResult.pass.requiresTLS());

    // fail: proceed=false, tls=true -> abort (cert mismatch)
    try testing.expect(!dane.DANEResult.fail.shouldProceed() and dane.DANEResult.fail.requiresTLS());

    // no_tlsa: proceed=true, tls=false -> deliver, TLS optional
    try testing.expect(dane.DANEResult.no_tlsa.shouldProceed() and !dane.DANEResult.no_tlsa.requiresTLS());

    // temperror: proceed=true, tls=false -> deliver (fail-open)
    try testing.expect(dane.DANEResult.temperror.shouldProceed() and !dane.DANEResult.temperror.requiresTLS());

    // permerror: proceed=false, tls=true -> abort
    try testing.expect(!dane.DANEResult.permerror.shouldProceed() and dane.DANEResult.permerror.requiresTLS());
}

// ============================================================================
// Edge case tests: generateTLSARecord
// ============================================================================

test "RFC 7672 edge case: generateTLSARecord SHA-256 produces valid record" {
    var validator = dane.DANEValidator.init(testing.allocator);
    defer validator.deinit();

    var record = try validator.generateTLSARecord(
        "test-certificate-data",
        .DOMAIN_ISSUED_CERT,
        .SUBJECT_PUBLIC_KEY_INFO,
        .SHA256,
    );
    defer record.deinit();

    try testing.expectEqual(dane.TLSAUsage.DOMAIN_ISSUED_CERT, record.usage);
    try testing.expectEqual(dane.TLSASelector.SUBJECT_PUBLIC_KEY_INFO, record.selector);
    try testing.expectEqual(dane.TLSAMatchingType.SHA256, record.matching_type);
    // SHA-256 hex output should be 64 chars
    try testing.expectEqual(@as(usize, 64), record.certificate_data.len);
}

test "RFC 7672 edge case: generateTLSARecord SHA-512 produces valid record" {
    var validator = dane.DANEValidator.init(testing.allocator);
    defer validator.deinit();

    var record = try validator.generateTLSARecord(
        "test-certificate-data",
        .TRUST_ANCHOR_ASSERTION,
        .FULL_CERT,
        .SHA512,
    );
    defer record.deinit();

    try testing.expectEqual(dane.TLSAUsage.TRUST_ANCHOR_ASSERTION, record.usage);
    try testing.expectEqual(dane.TLSASelector.FULL_CERT, record.selector);
    try testing.expectEqual(dane.TLSAMatchingType.SHA512, record.matching_type);
    // SHA-512 hex output should be 128 chars
    try testing.expectEqual(@as(usize, 128), record.certificate_data.len);
}

test "RFC 7672 edge case: generateTLSARecord exact match" {
    var validator = dane.DANEValidator.init(testing.allocator);
    defer validator.deinit();

    var record = try validator.generateTLSARecord(
        "AB",
        .DOMAIN_ISSUED_CERT,
        .FULL_CERT,
        .EXACT,
    );
    defer record.deinit();

    try testing.expectEqual(dane.TLSAMatchingType.EXACT, record.matching_type);
    // "AB" = 0x41 0x42, hex = "4142"
    try testing.expectEqual(@as(usize, 4), record.certificate_data.len);
}
