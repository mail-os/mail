// RFC 8461 MTA-STS (Mail Transfer Agent Strict Transport Security) Test Suite
// Tests for MTA-STS policy parsing, MX pattern matching, cache behavior,
// and TLS enforcement decisions.
// https://datatracker.ietf.org/doc/html/rfc8461

const std = @import("std");
const testing = std.testing;
const mta_sts = @import("mail").mta_sts;

// ============================================================================
// MTASTSMode tests
// ============================================================================

test "RFC 8461 MTASTSMode toString" {
    try testing.expectEqualStrings("enforce", mta_sts.MTASTSMode.enforce.toString());
    try testing.expectEqualStrings("testing", mta_sts.MTASTSMode.testing.toString());
    try testing.expectEqualStrings("none", mta_sts.MTASTSMode.none.toString());
}

test "RFC 8461 MTASTSMode fromString" {
    try testing.expectEqual(mta_sts.MTASTSMode.enforce, mta_sts.MTASTSMode.fromString("enforce").?);
    try testing.expectEqual(mta_sts.MTASTSMode.testing, mta_sts.MTASTSMode.fromString("testing").?);
    try testing.expectEqual(mta_sts.MTASTSMode.none, mta_sts.MTASTSMode.fromString("none").?);
}

test "RFC 8461 MTASTSMode fromString case-insensitive" {
    try testing.expectEqual(mta_sts.MTASTSMode.enforce, mta_sts.MTASTSMode.fromString("ENFORCE").?);
    try testing.expectEqual(mta_sts.MTASTSMode.testing, mta_sts.MTASTSMode.fromString("Testing").?);
    try testing.expectEqual(mta_sts.MTASTSMode.none, mta_sts.MTASTSMode.fromString("NONE").?);
}

test "RFC 8461 MTASTSMode fromString invalid returns null" {
    try testing.expect(mta_sts.MTASTSMode.fromString("invalid") == null);
    try testing.expect(mta_sts.MTASTSMode.fromString("") == null);
    try testing.expect(mta_sts.MTASTSMode.fromString("report") == null);
}

// ============================================================================
// MTASTSResult tests
// ============================================================================

test "RFC 8461 MTASTSResult toString" {
    try testing.expectEqualStrings("pass", mta_sts.MTASTSResult.pass.toString());
    try testing.expectEqualStrings("fail", mta_sts.MTASTSResult.fail.toString());
    try testing.expectEqualStrings("no_policy", mta_sts.MTASTSResult.no_policy.toString());
    try testing.expectEqualStrings("policy_fetch_error", mta_sts.MTASTSResult.policy_fetch_error.toString());
    try testing.expectEqualStrings("temperror", mta_sts.MTASTSResult.temperror.toString());
}

test "RFC 8461 MTASTSResult shouldDeliver in enforce mode" {
    // In enforce mode, only fail should block delivery
    try testing.expect(mta_sts.MTASTSResult.pass.shouldDeliver(.enforce));
    try testing.expect(!mta_sts.MTASTSResult.fail.shouldDeliver(.enforce));
    try testing.expect(mta_sts.MTASTSResult.no_policy.shouldDeliver(.enforce));
    try testing.expect(mta_sts.MTASTSResult.policy_fetch_error.shouldDeliver(.enforce));
    try testing.expect(mta_sts.MTASTSResult.temperror.shouldDeliver(.enforce));
}

test "RFC 8461 MTASTSResult shouldDeliver in testing mode" {
    // In testing mode, even fail should allow delivery (report only)
    try testing.expect(mta_sts.MTASTSResult.pass.shouldDeliver(.testing));
    try testing.expect(mta_sts.MTASTSResult.fail.shouldDeliver(.testing));
    try testing.expect(mta_sts.MTASTSResult.no_policy.shouldDeliver(.testing));
    try testing.expect(mta_sts.MTASTSResult.temperror.shouldDeliver(.testing));
}

test "RFC 8461 MTASTSResult shouldDeliver in none mode" {
    // In none mode, everything should deliver
    try testing.expect(mta_sts.MTASTSResult.pass.shouldDeliver(.none));
    try testing.expect(mta_sts.MTASTSResult.fail.shouldDeliver(.none));
}

// ============================================================================
// MTASTSDnsRecord parsing tests
// ============================================================================

test "RFC 8461 DNS record parsing: valid record" {
    var rec = try mta_sts.MTASTSDnsRecord.parse(testing.allocator, "v=STSv1; id=20240101T000000");
    defer rec.deinit();

    try testing.expectEqualStrings("STSv1", rec.version);
    try testing.expectEqualStrings("20240101T000000", rec.id);
}

test "RFC 8461 DNS record parsing: with whitespace" {
    var rec = try mta_sts.MTASTSDnsRecord.parse(testing.allocator, "  v=STSv1 ;  id=abc123  ");
    defer rec.deinit();

    try testing.expectEqualStrings("STSv1", rec.version);
    try testing.expectEqualStrings("abc123", rec.id);
}

test "RFC 8461 DNS record parsing: invalid version" {
    try testing.expectError(
        error.InvalidMTASTSRecord,
        mta_sts.MTASTSDnsRecord.parse(testing.allocator, "v=STSv2; id=abc"),
    );
}

test "RFC 8461 DNS record parsing: missing id" {
    try testing.expectError(
        error.InvalidMTASTSRecord,
        mta_sts.MTASTSDnsRecord.parse(testing.allocator, "v=STSv1"),
    );
}

test "RFC 8461 DNS record parsing: missing version" {
    try testing.expectError(
        error.InvalidMTASTSRecord,
        mta_sts.MTASTSDnsRecord.parse(testing.allocator, "id=abc123"),
    );
}

test "RFC 8461 DNS record format roundtrip" {
    var rec = try mta_sts.MTASTSDnsRecord.parse(testing.allocator, "v=STSv1; id=20240101T000000");
    defer rec.deinit();

    const formatted = try rec.formatRecord(testing.allocator);
    defer testing.allocator.free(formatted);

    try testing.expectEqualStrings("v=STSv1; id=20240101T000000", formatted);
}

// ============================================================================
// MTA-STS policy parsing tests
// ============================================================================

test "RFC 8461 policy parsing: enforce mode" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.com\nmax_age: 86400\n");
    defer p.deinit();

    try testing.expectEqualStrings("STSv1", p.version);
    try testing.expectEqual(mta_sts.MTASTSMode.enforce, p.mode);
    try testing.expectEqual(@as(usize, 2), p.mx_patterns.items.len);
    try testing.expectEqualStrings("mail.example.com", p.mx_patterns.items[0]);
    try testing.expectEqualStrings("*.example.com", p.mx_patterns.items[1]);
    try testing.expectEqual(@as(u64, 86400), p.max_age);
}

test "RFC 8461 policy parsing: testing mode" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.parsePolicy("version: STSv1\nmode: testing\nmx: *.example.org\nmax_age: 604800\n");
    defer p.deinit();

    try testing.expectEqual(mta_sts.MTASTSMode.testing, p.mode);
}

test "RFC 8461 policy parsing: none mode without mx patterns" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.parsePolicy("version: STSv1\nmode: none\nmax_age: 86400\n");
    defer p.deinit();

    try testing.expectEqual(mta_sts.MTASTSMode.none, p.mode);
    try testing.expectEqual(@as(usize, 0), p.mx_patterns.items.len);
}

test "RFC 8461 policy parsing: CRLF line endings" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.parsePolicy("version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmax_age: 86400\r\n");
    defer p.deinit();

    try testing.expectEqualStrings("STSv1", p.version);
    try testing.expectEqual(mta_sts.MTASTSMode.enforce, p.mode);
}

test "RFC 8461 policy parsing: extra whitespace" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.parsePolicy("  version:  STSv1\n  mode:  enforce\n  mx:  mail.example.com\n  max_age:  3600\n");
    defer p.deinit();

    try testing.expectEqual(@as(u64, 3600), p.max_age);
}

test "RFC 8461 policy parsing: multiple mx patterns" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: m1.ex.com\nmx: m2.ex.com\nmx: *.bk.ex.com\nmx: *.ex.com\nmax_age: 86400\n");
    defer p.deinit();

    try testing.expectEqual(@as(usize, 4), p.mx_patterns.items.len);
}

// ============================================================================
// MTA-STS policy parsing error cases
// ============================================================================

test "RFC 8461 policy parsing: invalid version" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    try testing.expectError(
        error.InvalidPolicyVersion,
        v.parsePolicy("version: STSv2\nmode: enforce\nmx: m.ex.com\nmax_age: 86400\n"),
    );
}

test "RFC 8461 policy parsing: missing version" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    try testing.expectError(
        error.InvalidPolicyVersion,
        v.parsePolicy("mode: enforce\nmx: m.ex.com\nmax_age: 86400\n"),
    );
}

test "RFC 8461 policy parsing: invalid mode" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    try testing.expectError(
        error.InvalidPolicyMode,
        v.parsePolicy("version: STSv1\nmode: invalid\nmx: m.ex.com\nmax_age: 86400\n"),
    );
}

test "RFC 8461 policy parsing: missing mx in enforce mode" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    try testing.expectError(
        error.MissingMxPatterns,
        v.parsePolicy("version: STSv1\nmode: enforce\nmax_age: 86400\n"),
    );
}

test "RFC 8461 policy parsing: max_age too large" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    try testing.expectError(
        error.InvalidMaxAge,
        v.parsePolicy("version: STSv1\nmode: enforce\nmx: m.ex.com\nmax_age: 999999999\n"),
    );
}

test "RFC 8461 policy parsing: zero max_age in enforce mode" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    try testing.expectError(
        error.InvalidMaxAge,
        v.parsePolicy("version: STSv1\nmode: enforce\nmx: m.ex.com\nmax_age: 0\n"),
    );
}

// ============================================================================
// MX pattern matching tests
// ============================================================================

test "RFC 8461 MX pattern matching: exact match" {
    try testing.expect(mta_sts.matchesMxPattern("mail.example.com", "mail.example.com"));
}

test "RFC 8461 MX pattern matching: case-insensitive exact" {
    try testing.expect(mta_sts.matchesMxPattern("MAIL.EXAMPLE.COM", "mail.example.com"));
    try testing.expect(mta_sts.matchesMxPattern("mail.example.com", "MAIL.EXAMPLE.COM"));
}

test "RFC 8461 MX pattern matching: wildcard single label" {
    try testing.expect(mta_sts.matchesMxPattern("mail.example.com", "*.example.com"));
    try testing.expect(mta_sts.matchesMxPattern("mx1.example.com", "*.example.com"));
    try testing.expect(mta_sts.matchesMxPattern("MAIL.EXAMPLE.COM", "*.example.com"));
}

test "RFC 8461 MX pattern matching: wildcard does not match bare domain" {
    try testing.expect(!mta_sts.matchesMxPattern("example.com", "*.example.com"));
}

test "RFC 8461 MX pattern matching: wildcard does not match multi-level" {
    try testing.expect(!mta_sts.matchesMxPattern("sub.mail.example.com", "*.example.com"));
    try testing.expect(!mta_sts.matchesMxPattern("a.b.example.com", "*.example.com"));
}

test "RFC 8461 MX pattern matching: wildcard subdomain pattern" {
    try testing.expect(mta_sts.matchesMxPattern("mx1.mail.example.com", "*.mail.example.com"));
    try testing.expect(!mta_sts.matchesMxPattern("mail.example.com", "*.mail.example.com"));
}

test "RFC 8461 MX pattern matching: no match different domain" {
    try testing.expect(!mta_sts.matchesMxPattern("other.example.com", "mail.example.com"));
}

test "RFC 8461 MX pattern matching: empty strings" {
    try testing.expect(!mta_sts.matchesMxPattern("", "mail.example.com"));
    try testing.expect(!mta_sts.matchesMxPattern("mail.example.com", ""));
    try testing.expect(!mta_sts.matchesMxPattern("", ""));
}

// ============================================================================
// MTA-STS policy properties
// ============================================================================

test "RFC 8461 MTASTSPolicy init defaults" {
    var p = mta_sts.MTASTSPolicy.init(testing.allocator);
    defer p.deinit();

    try testing.expectEqualStrings("", p.version);
    try testing.expectEqual(mta_sts.MTASTSMode.none, p.mode);
    try testing.expectEqual(@as(u64, 0), p.max_age);
    try testing.expectEqual(@as(usize, 0), p.mx_patterns.items.len);
}

test "RFC 8461 MTASTSPolicy isExpired for default policy" {
    var p = mta_sts.MTASTSPolicy.init(testing.allocator);
    defer p.deinit();

    // Default policy (fetched_at=0, max_age=0) should be expired
    try testing.expect(p.isExpired());
    try testing.expectEqual(@as(u64, 0), p.remainingTTL());
}

test "RFC 8461 MTASTSPolicy isExpired for valid policy" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: m.ex.com\nmax_age: 86400\n");
    defer p.deinit();

    try testing.expect(!p.isExpired());
    try testing.expect(p.remainingTTL() > 0);
    try testing.expect(p.remainingTTL() <= 86400);
}

test "RFC 8461 MTASTSPolicy isExpiringSoon" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: m.ex.com\nmax_age: 60\n");
    defer p.deinit();

    try testing.expect(p.isExpiringSoon(3600)); // 60s TTL within 3600s threshold
    try testing.expect(!p.isExpiringSoon(30)); // 60s TTL NOT within 30s threshold
}

test "RFC 8461 MTASTSPolicy format" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.com\nmax_age: 86400\n");
    defer p.deinit();

    const formatted = try p.format(testing.allocator);
    defer testing.allocator.free(formatted);

    try testing.expect(std.mem.indexOf(u8, formatted, "version: STSv1") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "mode: enforce") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "mx: mail.example.com") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "mx: *.example.com") != null);
}

// ============================================================================
// MTA-STS policy cache tests
// ============================================================================

test "RFC 8461 policy cache: init and deinit" {
    var c = mta_sts.MTASTSPolicyCache.init(testing.allocator);
    defer c.deinit();

    try testing.expectEqual(@as(usize, 0), c.count());
}

test "RFC 8461 policy cache: put and get" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    const p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: m.ex.com\nmax_age: 86400\n");
    try v.cache.put("example.com", p, "id123");

    const cached = v.cache.get("example.com");
    try testing.expect(cached != null);
    try testing.expectEqual(mta_sts.MTASTSMode.enforce, cached.?.mode);
}

test "RFC 8461 policy cache: miss returns null" {
    var c = mta_sts.MTASTSPolicyCache.init(testing.allocator);
    defer c.deinit();

    try testing.expect(c.get("nonexistent.com") == null);
}

test "RFC 8461 policy cache: remove" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    const p = try v.parsePolicy("version: STSv1\nmode: testing\nmx: *.ex.org\nmax_age: 86400\n");
    try v.cache.put("ex.org", p, "id1");

    try testing.expect(v.cache.get("ex.org") != null);
    v.cache.remove("ex.org");
    try testing.expect(v.cache.get("ex.org") == null);
}

test "RFC 8461 policy cache: replace existing" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    const p1 = try v.parsePolicy("version: STSv1\nmode: testing\nmx: *.ex.com\nmax_age: 86400\n");
    const p2 = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: m.ex.com\nmax_age: 604800\n");

    try v.cache.put("ex.com", p1, "id1");
    try v.cache.put("ex.com", p2, "id2");

    const cached = v.cache.get("ex.com");
    try testing.expect(cached != null);
    try testing.expectEqual(mta_sts.MTASTSMode.enforce, cached.?.mode);
    try testing.expectEqual(@as(usize, 1), v.cache.count());
}

test "RFC 8461 policy cache: isPolicyUpdated" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    const p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: m.ex.com\nmax_age: 86400\n");
    try v.cache.put("ex.com", p, "id_v1");

    try testing.expect(!v.cache.isPolicyUpdated("ex.com", "id_v1"));
    try testing.expect(v.cache.isPolicyUpdated("ex.com", "id_v2"));
    try testing.expect(v.cache.isPolicyUpdated("unknown.com", "id_v1"));
}

test "RFC 8461 policy cache: getStats" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    const p1 = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: m.ex.com\nmax_age: 86400\n");
    const p2 = try v.parsePolicy("version: STSv1\nmode: testing\nmx: *.test.com\nmax_age: 86400\n");

    try v.cache.put("ex.com", p1, "id1");
    try v.cache.put("test.com", p2, "id2");

    const stats = v.cache.getStats();
    try testing.expectEqual(@as(usize, 2), stats.total_entries);
    try testing.expectEqual(@as(usize, 1), stats.enforce_entries);
    try testing.expectEqual(@as(usize, 1), stats.testing_entries);
    try testing.expectEqual(@as(usize, 0), stats.none_entries);
}

// ============================================================================
// TLS enforcement decision tests
// ============================================================================

test "RFC 8461 validate MX against policy" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.com\nmax_age: 86400\n");
    defer p.deinit();

    try testing.expect(v.validateMX("mail.example.com", &p));
    try testing.expect(v.validateMX("mx1.example.com", &p));
    try testing.expect(!v.validateMX("mail.evil.com", &p));
    try testing.expect(!v.validateMX("sub.mail.example.com", &p));
}

// ============================================================================
// extractPolicyDomain tests
// ============================================================================

test "RFC 8461 extractPolicyDomain" {
    try testing.expectEqualStrings("example.com", mta_sts.extractPolicyDomain("mail.example.com"));
    try testing.expectEqualStrings("example.com", mta_sts.extractPolicyDomain("mx1.mail.example.com"));
    try testing.expectEqualStrings("example.com", mta_sts.extractPolicyDomain("example.com"));
    try testing.expectEqualStrings("localhost", mta_sts.extractPolicyDomain("localhost"));
}

// ============================================================================
// End-to-end tests
// ============================================================================

test "RFC 8461 end-to-end: parse and validate" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.fetchPolicy("example.com");
    defer p.deinit();

    try testing.expect(v.validateMX("mail.example.com", &p));
    try testing.expect(v.validateMX("mx1.example.com", &p));
    try testing.expect(!v.validateMX("mail.evil.com", &p));
    try testing.expect(!v.validateMX("sub.mail.example.com", &p));
    try testing.expectEqual(mta_sts.MTASTSMode.enforce, p.mode);
}

test "RFC 8461 end-to-end: cache workflow" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    const p = try v.fetchPolicy("example.com");
    try v.cache.put("example.com", p, "20240101T000000");

    const cached = v.cache.get("example.com");
    try testing.expect(cached != null);
    try testing.expect(v.validateMX("mail.example.com", cached.?));
    try testing.expect(!v.validateMX("bad.evil.com", cached.?));

    try testing.expect(!v.cache.isPolicyUpdated("example.com", "20240101T000000"));
    try testing.expect(v.cache.isPolicyUpdated("example.com", "20240201T000000"));

    v.cache.remove("example.com");
    try testing.expect(v.cache.get("example.com") == null);
}

test "RFC 8461 fetchPolicy: mock domains" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p1 = try v.fetchPolicy("example.com");
    defer p1.deinit();
    try testing.expectEqual(mta_sts.MTASTSMode.enforce, p1.mode);

    var p2 = try v.fetchPolicy("testing.example.com");
    defer p2.deinit();
    try testing.expectEqual(mta_sts.MTASTSMode.testing, p2.mode);

    var p3 = try v.fetchPolicy("nomail.example.com");
    defer p3.deinit();
    try testing.expectEqual(mta_sts.MTASTSMode.none, p3.mode);

    try testing.expectError(error.PolicyFetchFailed, v.fetchPolicy("unknown.example.com"));
}

// ============================================================================
// isValidMxPattern helper tests
// ============================================================================

test "RFC 8461 isValidMxPattern" {
    try testing.expect(mta_sts.isValidMxPattern("mail.example.com"));
    try testing.expect(mta_sts.isValidMxPattern("*.example.com"));
    try testing.expect(mta_sts.isValidMxPattern("*.mail.example.com"));
    try testing.expect(!mta_sts.isValidMxPattern(""));
    try testing.expect(!mta_sts.isValidMxPattern("*."));
    try testing.expect(!mta_sts.isValidMxPattern("*.com"));
    try testing.expect(!mta_sts.isValidMxPattern(".example.com"));
}

// ============================================================================
// Edge case tests: Policy with no mx lines
// ============================================================================

test "RFC 8461 edge case: enforce mode requires at least one mx pattern" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    try testing.expectError(
        error.MissingMxPatterns,
        v.parsePolicy("version: STSv1\nmode: enforce\nmax_age: 86400\n"),
    );
}

test "RFC 8461 edge case: testing mode requires at least one mx pattern" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    try testing.expectError(
        error.MissingMxPatterns,
        v.parsePolicy("version: STSv1\nmode: testing\nmax_age: 86400\n"),
    );
}

test "RFC 8461 edge case: none mode allows zero mx patterns" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.parsePolicy("version: STSv1\nmode: none\nmax_age: 86400\n");
    defer p.deinit();

    try testing.expectEqual(@as(usize, 0), p.mx_patterns.items.len);
    try testing.expectEqual(mta_sts.MTASTSMode.none, p.mode);
}

// ============================================================================
// Edge case tests: Policy with wildcard mx patterns
// ============================================================================

test "RFC 8461 edge case: wildcard mx *.example.com in policy" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400\n");
    defer p.deinit();

    try testing.expectEqual(@as(usize, 1), p.mx_patterns.items.len);
    try testing.expectEqualStrings("*.example.com", p.mx_patterns.items[0]);

    // Wildcard should match single-label prefix
    try testing.expect(v.validateMX("mail.example.com", &p));
    try testing.expect(v.validateMX("mx1.example.com", &p));
    try testing.expect(v.validateMX("anything.example.com", &p));

    // Should NOT match bare domain or multi-level
    try testing.expect(!v.validateMX("example.com", &p));
    try testing.expect(!v.validateMX("sub.mail.example.com", &p));
}

test "RFC 8461 edge case: wildcard mx at deeper subdomain level" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: *.mail.example.com\nmax_age: 86400\n");
    defer p.deinit();

    try testing.expect(v.validateMX("mx1.mail.example.com", &p));
    try testing.expect(v.validateMX("mx2.mail.example.com", &p));
    try testing.expect(!v.validateMX("mail.example.com", &p));
    try testing.expect(!v.validateMX("deep.mx1.mail.example.com", &p));
}

// ============================================================================
// Edge case tests: Policy with max_age boundaries
// ============================================================================

test "RFC 8461 edge case: max_age at maximum allowed value (31557600 = 1 year)" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 31557600\n");
    defer p.deinit();

    try testing.expectEqual(@as(u64, 31557600), p.max_age);
}

test "RFC 8461 edge case: max_age one second above maximum is rejected" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    try testing.expectError(
        error.InvalidMaxAge,
        v.parsePolicy("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 31557601\n"),
    );
}

test "RFC 8461 edge case: max_age of 0 in enforce mode is rejected" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    try testing.expectError(
        error.InvalidMaxAge,
        v.parsePolicy("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 0\n"),
    );
}

test "RFC 8461 edge case: max_age of 0 in testing mode is rejected" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    try testing.expectError(
        error.InvalidMaxAge,
        v.parsePolicy("version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 0\n"),
    );
}

test "RFC 8461 edge case: max_age of 1 is the minimum valid value for enforce" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 1\n");
    defer p.deinit();

    try testing.expectEqual(@as(u64, 1), p.max_age);
}

test "RFC 8461 edge case: non-numeric max_age is rejected" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    try testing.expectError(
        error.InvalidMaxAge,
        v.parsePolicy("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: abc\n"),
    );
}

// ============================================================================
// Edge case tests: Mode boundary behavior
// ============================================================================

test "RFC 8461 edge case: mode none allows delivery for all results" {
    try testing.expect(mta_sts.MTASTSResult.pass.shouldDeliver(.none));
    try testing.expect(mta_sts.MTASTSResult.fail.shouldDeliver(.none));
    try testing.expect(mta_sts.MTASTSResult.no_policy.shouldDeliver(.none));
    try testing.expect(mta_sts.MTASTSResult.policy_fetch_error.shouldDeliver(.none));
    try testing.expect(mta_sts.MTASTSResult.temperror.shouldDeliver(.none));
}

test "RFC 8461 edge case: mode testing allows delivery for all results including fail" {
    try testing.expect(mta_sts.MTASTSResult.pass.shouldDeliver(.testing));
    try testing.expect(mta_sts.MTASTSResult.fail.shouldDeliver(.testing));
    try testing.expect(mta_sts.MTASTSResult.no_policy.shouldDeliver(.testing));
    try testing.expect(mta_sts.MTASTSResult.policy_fetch_error.shouldDeliver(.testing));
    try testing.expect(mta_sts.MTASTSResult.temperror.shouldDeliver(.testing));
}

test "RFC 8461 edge case: mode enforce blocks only fail" {
    try testing.expect(mta_sts.MTASTSResult.pass.shouldDeliver(.enforce));
    try testing.expect(!mta_sts.MTASTSResult.fail.shouldDeliver(.enforce));
    try testing.expect(mta_sts.MTASTSResult.no_policy.shouldDeliver(.enforce));
    try testing.expect(mta_sts.MTASTSResult.policy_fetch_error.shouldDeliver(.enforce));
    try testing.expect(mta_sts.MTASTSResult.temperror.shouldDeliver(.enforce));
}

// ============================================================================
// Edge case tests: Malformed policies
// ============================================================================

test "RFC 8461 edge case: missing version line" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    try testing.expectError(
        error.InvalidPolicyVersion,
        v.parsePolicy("mode: enforce\nmx: mail.example.com\nmax_age: 86400\n"),
    );
}

test "RFC 8461 edge case: wrong version number STSv2" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    try testing.expectError(
        error.InvalidPolicyVersion,
        v.parsePolicy("version: STSv2\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"),
    );
}

test "RFC 8461 edge case: version with extra text" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    try testing.expectError(
        error.InvalidPolicyVersion,
        v.parsePolicy("version: STSv1beta\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"),
    );
}

test "RFC 8461 edge case: missing mode line" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    // Without a mode line, the default mode is none. Since mode is none and
    // max_age is non-zero, there should be no error for missing mx patterns.
    // However the mode will be .none which does not require mx patterns.
    var p = try v.parsePolicy("version: STSv1\nmx: mail.example.com\nmax_age: 86400\n");
    defer p.deinit();
    try testing.expectEqual(mta_sts.MTASTSMode.none, p.mode);
}

test "RFC 8461 edge case: invalid mode string" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    try testing.expectError(
        error.InvalidPolicyMode,
        v.parsePolicy("version: STSv1\nmode: report\nmx: mail.example.com\nmax_age: 86400\n"),
    );
}

// ============================================================================
// Edge case tests: MX pattern matching edge cases
// ============================================================================

test "RFC 8461 edge case: matchesMxPattern hostname has trailing dot" {
    // DNS names can have a trailing dot; matching should still work for exact
    // Note: the current implementation does strict comparison, so trailing dots
    // cause a mismatch. This documents the current behavior.
    try testing.expect(!mta_sts.matchesMxPattern("mail.example.com.", "mail.example.com"));
}

test "RFC 8461 edge case: matchesMxPattern pattern has trailing dot" {
    try testing.expect(!mta_sts.matchesMxPattern("mail.example.com", "mail.example.com."));
}

test "RFC 8461 edge case: matchesMxPattern single character hostname" {
    try testing.expect(!mta_sts.matchesMxPattern("m", "*.example.com"));
    // Single character exact match works because matchesMxPattern does
    // case-insensitive string comparison before checking wildcard patterns.
    try testing.expect(mta_sts.matchesMxPattern("m", "m"));
}

test "RFC 8461 edge case: matchesMxPattern wildcard with single-char label" {
    try testing.expect(mta_sts.matchesMxPattern("x.example.com", "*.example.com"));
}

test "RFC 8461 edge case: matchesMxPattern hostname equals wildcard suffix" {
    // "example.com" should NOT match "*.example.com" (bare domain)
    try testing.expect(!mta_sts.matchesMxPattern("example.com", "*.example.com"));
}

test "RFC 8461 edge case: matchesMxPattern with very long hostname" {
    const long_label = "a" ** 63;
    const hostname = long_label ++ ".example.com";
    try testing.expect(mta_sts.matchesMxPattern(hostname, "*.example.com"));
}

test "RFC 8461 edge case: matchesMxPattern identical hostnames with different case" {
    try testing.expect(mta_sts.matchesMxPattern("MAIL.EXAMPLE.COM", "mail.example.com"));
    try testing.expect(mta_sts.matchesMxPattern("mail.example.com", "MAIL.EXAMPLE.COM"));
    try testing.expect(mta_sts.matchesMxPattern("MaIl.ExAmPlE.cOm", "mAiL.eXaMpLe.CoM"));
}

test "RFC 8461 edge case: matchesMxPattern wildcard case insensitive" {
    try testing.expect(mta_sts.matchesMxPattern("MAIL.EXAMPLE.COM", "*.EXAMPLE.COM"));
    try testing.expect(mta_sts.matchesMxPattern("mail.example.com", "*.EXAMPLE.COM"));
    try testing.expect(mta_sts.matchesMxPattern("MAIL.example.com", "*.EXAMPLE.COM"));
}

// ============================================================================
// Edge case tests: Policy with duplicate mx entries
// ============================================================================

test "RFC 8461 edge case: duplicate mx entries are accepted" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.parsePolicy(
        "version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: mail.example.com\nmax_age: 86400\n",
    );
    defer p.deinit();

    // Both duplicate entries should be stored
    try testing.expectEqual(@as(usize, 2), p.mx_patterns.items.len);
    try testing.expectEqualStrings("mail.example.com", p.mx_patterns.items[0]);
    try testing.expectEqualStrings("mail.example.com", p.mx_patterns.items[1]);
}

test "RFC 8461 edge case: duplicate wildcard and exact mx entries" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.parsePolicy(
        "version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.com\nmx: mail.example.com\nmax_age: 86400\n",
    );
    defer p.deinit();

    try testing.expectEqual(@as(usize, 3), p.mx_patterns.items.len);
}

// ============================================================================
// Edge case tests: Empty and whitespace-only policy strings
// ============================================================================

test "RFC 8461 edge case: empty policy string" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    // An empty policy has no version line, so it should fail version check
    try testing.expectError(
        error.InvalidPolicyVersion,
        v.parsePolicy(""),
    );
}

test "RFC 8461 edge case: policy with only whitespace" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    try testing.expectError(
        error.InvalidPolicyVersion,
        v.parsePolicy("   \t   \t   "),
    );
}

test "RFC 8461 edge case: policy with only newlines" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    try testing.expectError(
        error.InvalidPolicyVersion,
        v.parsePolicy("\n\n\n\n"),
    );
}

// ============================================================================
// Edge case tests: Policy with CR vs LF vs CRLF line endings
// ============================================================================

test "RFC 8461 edge case: policy with LF line endings" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n");
    defer p.deinit();

    try testing.expectEqual(mta_sts.MTASTSMode.enforce, p.mode);
    try testing.expectEqual(@as(usize, 1), p.mx_patterns.items.len);
}

test "RFC 8461 edge case: policy with CRLF line endings" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.parsePolicy("version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmax_age: 86400\r\n");
    defer p.deinit();

    try testing.expectEqual(mta_sts.MTASTSMode.enforce, p.mode);
    try testing.expectEqual(@as(usize, 1), p.mx_patterns.items.len);
}

test "RFC 8461 edge case: policy with mixed line endings" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    // Mix of LF and CRLF in a single policy
    var p = try v.parsePolicy("version: STSv1\nmode: enforce\r\nmx: mail.example.com\nmax_age: 86400\r\n");
    defer p.deinit();

    try testing.expectEqual(mta_sts.MTASTSMode.enforce, p.mode);
    try testing.expectEqual(@as(usize, 1), p.mx_patterns.items.len);
}

test "RFC 8461 edge case: policy without trailing newline" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400");
    defer p.deinit();

    try testing.expectEqual(mta_sts.MTASTSMode.enforce, p.mode);
    try testing.expectEqual(@as(u64, 86400), p.max_age);
}

// ============================================================================
// Edge case tests: isValidMxPattern edge cases
// ============================================================================

test "RFC 8461 edge case: isValidMxPattern empty string" {
    try testing.expect(!mta_sts.isValidMxPattern(""));
}

test "RFC 8461 edge case: isValidMxPattern just asterisk" {
    // "*" alone is not a valid pattern (no domain suffix)
    try testing.expect(!mta_sts.isValidMxPattern("*"));
}

test "RFC 8461 edge case: isValidMxPattern just a dot" {
    try testing.expect(!mta_sts.isValidMxPattern("."));
}

test "RFC 8461 edge case: isValidMxPattern consecutive dots" {
    // The current implementation allows consecutive dots since isValidHostnameChars
    // only checks individual character validity and leading/trailing constraints.
    // This documents the current behavior; stricter validation could reject these.
    try testing.expect(mta_sts.isValidMxPattern("mail..example.com"));
}

test "RFC 8461 edge case: isValidMxPattern leading dot" {
    try testing.expect(!mta_sts.isValidMxPattern(".example.com"));
}

test "RFC 8461 edge case: isValidMxPattern trailing dot" {
    try testing.expect(!mta_sts.isValidMxPattern("mail.example.com."));
}

test "RFC 8461 edge case: isValidMxPattern leading hyphen" {
    try testing.expect(!mta_sts.isValidMxPattern("-mail.example.com"));
}

test "RFC 8461 edge case: isValidMxPattern trailing hyphen" {
    try testing.expect(!mta_sts.isValidMxPattern("mail.example.com-"));
}

test "RFC 8461 edge case: isValidMxPattern wildcard with only TLD" {
    // "*.com" should be invalid (wildcard needs at least two labels after *)
    try testing.expect(!mta_sts.isValidMxPattern("*.com"));
}

test "RFC 8461 edge case: isValidMxPattern wildcard with proper domain" {
    try testing.expect(mta_sts.isValidMxPattern("*.example.com"));
    try testing.expect(mta_sts.isValidMxPattern("*.mail.example.com"));
}

test "RFC 8461 edge case: isValidMxPattern wildcard with trailing dot" {
    // "*.example.com." has a trailing dot which is invalid for hostname chars
    try testing.expect(!mta_sts.isValidMxPattern("*.example.com."));
}

test "RFC 8461 edge case: isValidMxPattern with underscores (invalid)" {
    try testing.expect(!mta_sts.isValidMxPattern("mail_server.example.com"));
}

test "RFC 8461 edge case: isValidMxPattern with valid hyphens" {
    try testing.expect(mta_sts.isValidMxPattern("mail-server.example.com"));
    try testing.expect(mta_sts.isValidMxPattern("mx-1.example.com"));
}

// ============================================================================
// Edge case tests: extractPolicyDomain edge cases
// ============================================================================

test "RFC 8461 edge case: extractPolicyDomain single label" {
    try testing.expectEqualStrings("localhost", mta_sts.extractPolicyDomain("localhost"));
}

test "RFC 8461 edge case: extractPolicyDomain two labels" {
    try testing.expectEqualStrings("example.com", mta_sts.extractPolicyDomain("example.com"));
}

test "RFC 8461 edge case: extractPolicyDomain deeply nested" {
    try testing.expectEqualStrings("example.com", mta_sts.extractPolicyDomain("a.b.c.d.example.com"));
}

test "RFC 8461 edge case: extractPolicyDomain empty string" {
    try testing.expectEqualStrings("", mta_sts.extractPolicyDomain(""));
}

// ============================================================================
// Edge case tests: Policy parsing with unusual field ordering
// ============================================================================

test "RFC 8461 edge case: policy fields in non-standard order" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    // max_age before mode, mx before version still works because parser processes line by line
    var p = try v.parsePolicy("max_age: 86400\nmx: mail.example.com\nmode: enforce\nversion: STSv1\n");
    defer p.deinit();

    try testing.expectEqualStrings("STSv1", p.version);
    try testing.expectEqual(mta_sts.MTASTSMode.enforce, p.mode);
    try testing.expectEqual(@as(u64, 86400), p.max_age);
    try testing.expectEqual(@as(usize, 1), p.mx_patterns.items.len);
}

test "RFC 8461 edge case: policy with blank lines interspersed" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.parsePolicy("version: STSv1\n\nmode: enforce\n\nmx: mail.example.com\n\nmax_age: 86400\n");
    defer p.deinit();

    try testing.expectEqual(mta_sts.MTASTSMode.enforce, p.mode);
}

test "RFC 8461 edge case: policy with unknown fields are ignored" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    // Unknown keys like "extra" should be silently ignored by the parser
    var p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\nextra: foobar\n");
    defer p.deinit();

    try testing.expectEqual(mta_sts.MTASTSMode.enforce, p.mode);
    try testing.expectEqual(@as(u64, 86400), p.max_age);
}

// ============================================================================
// Edge case tests: DNS record parsing edge cases
// ============================================================================

test "RFC 8461 edge case: DNS record with empty id" {
    try testing.expectError(
        error.InvalidMTASTSRecord,
        mta_sts.MTASTSDnsRecord.parse(testing.allocator, "v=STSv1; id="),
    );
}

test "RFC 8461 edge case: DNS record with no semicolon separator" {
    // "v=STSv1 id=abc" - no semicolon, so id won't be found
    try testing.expectError(
        error.InvalidMTASTSRecord,
        mta_sts.MTASTSDnsRecord.parse(testing.allocator, "v=STSv1 id=abc"),
    );
}

test "RFC 8461 edge case: DNS record with multiple semicolons" {
    var rec = try mta_sts.MTASTSDnsRecord.parse(testing.allocator, "v=STSv1; id=abc123; extra=ignored");
    defer rec.deinit();

    try testing.expectEqualStrings("STSv1", rec.version);
    try testing.expectEqualStrings("abc123", rec.id);
}

test "RFC 8461 edge case: DNS record empty string" {
    try testing.expectError(
        error.InvalidMTASTSRecord,
        mta_sts.MTASTSDnsRecord.parse(testing.allocator, ""),
    );
}

// ============================================================================
// Edge case tests: Cache behavior edge cases
// ============================================================================

test "RFC 8461 edge case: cache isPolicyUpdated for missing domain" {
    var c = mta_sts.MTASTSPolicyCache.init(testing.allocator);
    defer c.deinit();

    // Missing domain is always considered updated
    try testing.expect(c.isPolicyUpdated("missing.com", "any_id"));
}

test "RFC 8461 edge case: cache getEvenIfExpired for missing domain" {
    var c = mta_sts.MTASTSPolicyCache.init(testing.allocator);
    defer c.deinit();

    try testing.expect(c.getEvenIfExpired("missing.com") == null);
}

test "RFC 8461 edge case: cache cleanup on empty cache" {
    var c = mta_sts.MTASTSPolicyCache.init(testing.allocator);
    defer c.deinit();

    // Cleanup on empty cache should not panic
    try c.cleanup();
    try testing.expectEqual(@as(usize, 0), c.count());
}

test "RFC 8461 edge case: cache remove nonexistent domain is safe" {
    var c = mta_sts.MTASTSPolicyCache.init(testing.allocator);
    defer c.deinit();

    // Removing a domain that was never added should not panic
    c.remove("nonexistent.com");
    try testing.expectEqual(@as(usize, 0), c.count());
}

// ============================================================================
// Edge case tests: MTASTSPolicy properties
// ============================================================================

test "RFC 8461 edge case: default policy is expired and expiring soon" {
    var p = mta_sts.MTASTSPolicy.init(testing.allocator);
    defer p.deinit();

    try testing.expect(p.isExpired());
    try testing.expect(p.isExpiringSoon(0));
    try testing.expect(p.isExpiringSoon(999999));
    try testing.expectEqual(@as(u64, 0), p.remainingTTL());
}

test "RFC 8461 edge case: policy with max_age of 1 second" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    var p = try v.parsePolicy("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 1\n");
    defer p.deinit();

    // Immediately after parsing, a 1-second policy should not yet be expired
    try testing.expect(!p.isExpired());
    // But it is expiring soon (within any reasonable threshold)
    try testing.expect(p.isExpiringSoon(10));
}

// ============================================================================
// Edge case tests: MTASTSMode fromString edge cases
// ============================================================================

test "RFC 8461 edge case: MTASTSMode fromString with extra whitespace returns null" {
    try testing.expect(mta_sts.MTASTSMode.fromString(" enforce") == null);
    try testing.expect(mta_sts.MTASTSMode.fromString("enforce ") == null);
    try testing.expect(mta_sts.MTASTSMode.fromString(" enforce ") == null);
}

test "RFC 8461 edge case: MTASTSMode fromString partial matches return null" {
    try testing.expect(mta_sts.MTASTSMode.fromString("enfor") == null);
    try testing.expect(mta_sts.MTASTSMode.fromString("enforced") == null);
    try testing.expect(mta_sts.MTASTSMode.fromString("test") == null);
    try testing.expect(mta_sts.MTASTSMode.fromString("non") == null);
}

// ============================================================================
// Edge case tests: validateMX with policy containing no patterns
// ============================================================================

test "RFC 8461 edge case: validateMX with empty mx_patterns returns false" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    // Create a none-mode policy with no mx patterns
    var p = try v.parsePolicy("version: STSv1\nmode: none\nmax_age: 86400\n");
    defer p.deinit();

    try testing.expect(!v.validateMX("mail.example.com", &p));
    try testing.expect(!v.validateMX("anything.com", &p));
}

// ============================================================================
// Edge case tests: Policy with invalid mx patterns
// ============================================================================

test "RFC 8461 edge case: policy with invalid mx pattern leading dot" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    try testing.expectError(
        error.InvalidMxPattern,
        v.parsePolicy("version: STSv1\nmode: enforce\nmx: .example.com\nmax_age: 86400\n"),
    );
}

test "RFC 8461 edge case: policy with invalid mx pattern wildcard only TLD" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    try testing.expectError(
        error.InvalidMxPattern,
        v.parsePolicy("version: STSv1\nmode: enforce\nmx: *.com\nmax_age: 86400\n"),
    );
}

test "RFC 8461 edge case: policy with invalid mx pattern bare wildcard dot" {
    var v = mta_sts.MTASTSValidator.init(testing.allocator);
    defer v.deinit();

    try testing.expectError(
        error.InvalidMxPattern,
        v.parsePolicy("version: STSv1\nmode: enforce\nmx: *.\nmax_age: 86400\n"),
    );
}
