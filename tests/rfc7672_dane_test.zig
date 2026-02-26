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
