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
