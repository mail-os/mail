// BIMI (Brand Indicators for Message Identification) Test Suite
// Tests for BIMI record parsing, validation, and policy caching.

const std = @import("std");
const testing = std.testing;
const bimi = @import("mail").bimi;

// =============================================================================
// BIMI Record Parsing
// =============================================================================

test "BIMI record parsing - valid record with location and authority" {
    var validator = bimi.BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    const txt = "v=BIMI1; l=https://example.com/brand/logo.svg; a=https://example.com/certs/vmc.pem";
    var record = try validator.parseBIMIRecord(txt);
    defer record.deinit();

    try testing.expectEqualStrings("BIMI1", record.version);
    try testing.expectEqualStrings("https://example.com/brand/logo.svg", record.location.?);
    try testing.expectEqualStrings("https://example.com/certs/vmc.pem", record.authority.?);
    try testing.expectEqualStrings(txt, record.raw_record);
}

test "BIMI record parsing - valid record with location only" {
    var validator = bimi.BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    var record = try validator.parseBIMIRecord("v=BIMI1; l=https://brand.example.org/icon.svg");
    defer record.deinit();

    try testing.expectEqualStrings("BIMI1", record.version);
    try testing.expect(record.location != null);
    try testing.expect(record.authority == null);
}

test "BIMI record parsing - missing version tag" {
    var validator = bimi.BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    const result = validator.parseBIMIRecord("l=https://example.com/logo.svg");
    try testing.expectError(error.InvalidBIMIRecord, result);
}

test "BIMI record parsing - wrong version" {
    var validator = bimi.BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    try testing.expectError(error.InvalidBIMIRecord, validator.parseBIMIRecord("v=BIMI2; l=https://example.com/logo.svg"));
}

test "BIMI record parsing - empty location and authority" {
    var validator = bimi.BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    var record = try validator.parseBIMIRecord("v=BIMI1; l=; a=");
    defer record.deinit();

    try testing.expect(record.location == null);
    try testing.expect(record.authority == null);
}

test "BIMI record parsing - extra whitespace" {
    var validator = bimi.BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    var record = try validator.parseBIMIRecord("  v = BIMI1 ;  l = https://example.com/logo.svg ;  a = https://example.com/vmc.pem  ");
    defer record.deinit();

    try testing.expectEqualStrings("BIMI1", record.version);
    try testing.expectEqualStrings("https://example.com/logo.svg", record.location.?);
    try testing.expectEqualStrings("https://example.com/vmc.pem", record.authority.?);
}

// =============================================================================
// BIMI Validation with DMARC
// =============================================================================

test "BIMI validation - DMARC not passing returns fail" {
    var validator = bimi.BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    try testing.expect(try validator.validateBIMI("example.com", .fail, .reject) == .fail);
    try testing.expect(try validator.validateBIMI("example.com", .none, .reject) == .fail);
    try testing.expect(try validator.validateBIMI("example.com", .temperror, .reject) == .fail);
    try testing.expect(try validator.validateBIMI("example.com", .permerror, .reject) == .fail);
}

test "BIMI validation - DMARC policy none is ineligible" {
    var validator = bimi.BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    try testing.expect(try validator.validateBIMI("example.com", .pass, .none) == .fail);
}

test "BIMI validation - DMARC pass with quarantine returns none (no DNS record)" {
    var validator = bimi.BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    // The stub lookupBIMI returns null, so we expect .none (no record found)
    try testing.expect(try validator.validateBIMI("example.com", .pass, .quarantine) == .none);
}

test "BIMI validation - DMARC pass with reject returns none (no DNS record)" {
    var validator = bimi.BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    try testing.expect(try validator.validateBIMI("example.com", .pass, .reject) == .none);
}

// =============================================================================
// BIMI Result Properties
// =============================================================================

test "BIMIResult toString" {
    try testing.expectEqualStrings("pass", bimi.BIMIResult.pass.toString());
    try testing.expectEqualStrings("none", bimi.BIMIResult.none.toString());
    try testing.expectEqualStrings("fail", bimi.BIMIResult.fail.toString());
    try testing.expectEqualStrings("temperror", bimi.BIMIResult.temperror.toString());
    try testing.expectEqualStrings("declined", bimi.BIMIResult.declined.toString());
}

test "BIMIResult isSuccess and isError" {
    try testing.expect(bimi.BIMIResult.pass.isSuccess());
    try testing.expect(!bimi.BIMIResult.fail.isSuccess());
    try testing.expect(!bimi.BIMIResult.none.isSuccess());
    try testing.expect(!bimi.BIMIResult.temperror.isSuccess());
    try testing.expect(!bimi.BIMIResult.declined.isSuccess());

    try testing.expect(bimi.BIMIResult.fail.isError());
    try testing.expect(bimi.BIMIResult.temperror.isError());
    try testing.expect(!bimi.BIMIResult.pass.isError());
    try testing.expect(!bimi.BIMIResult.none.isError());
    try testing.expect(!bimi.BIMIResult.declined.isError());
}

test "DMARCPolicyLevel BIMI eligibility" {
    try testing.expect(!bimi.DMARCPolicyLevel.none.isBIMIEligible());
    try testing.expect(bimi.DMARCPolicyLevel.quarantine.isBIMIEligible());
    try testing.expect(bimi.DMARCPolicyLevel.reject.isBIMIEligible());
}

test "DMARCPolicyLevel fromString" {
    try testing.expect(bimi.DMARCPolicyLevel.fromString("reject") == .reject);
    try testing.expect(bimi.DMARCPolicyLevel.fromString("REJECT") == .reject);
    try testing.expect(bimi.DMARCPolicyLevel.fromString("quarantine") == .quarantine);
    try testing.expect(bimi.DMARCPolicyLevel.fromString("Quarantine") == .quarantine);
    try testing.expect(bimi.DMARCPolicyLevel.fromString("none") == .none);
    try testing.expect(bimi.DMARCPolicyLevel.fromString("unknown") == .none);
    try testing.expect(bimi.DMARCPolicyLevel.fromString("") == .none);
}

// =============================================================================
// SVG and VMC URL Validation
// =============================================================================

test "SVG URL validation" {
    // Valid
    try testing.expect(bimi.validateSvgUrl("https://example.com/logo.svg"));
    try testing.expect(bimi.validateSvgUrl("https://brand.example.org/assets/icon.svg"));
    try testing.expect(bimi.validateSvgUrl("https://cdn.example.com/path/to/image.SVG"));

    // Invalid
    try testing.expect(!bimi.validateSvgUrl("http://example.com/logo.svg")); // not HTTPS
    try testing.expect(!bimi.validateSvgUrl("https://example.com/logo")); // no extension
    try testing.expect(!bimi.validateSvgUrl("https://example.com/logo.png")); // wrong extension
    try testing.expect(!bimi.validateSvgUrl("https://")); // empty after scheme
    try testing.expect(!bimi.validateSvgUrl("https://localhost/logo.svg")); // no dot in hostname
    try testing.expect(!bimi.validateSvgUrl("")); // empty
}

test "VMC URL validation" {
    // Valid
    try testing.expect(bimi.validateVmcUrl("https://example.com/cert.pem"));
    try testing.expect(bimi.validateVmcUrl("https://certs.example.org/vmc/chain.pem"));
    try testing.expect(bimi.validateVmcUrl("https://ca.example.com/certificates/mark.PEM"));

    // Invalid
    try testing.expect(!bimi.validateVmcUrl("http://example.com/cert.pem")); // not HTTPS
    try testing.expect(!bimi.validateVmcUrl("https://example.com/cert.crt")); // wrong extension
    try testing.expect(!bimi.validateVmcUrl("https://example.com/cert")); // no extension
    try testing.expect(!bimi.validateVmcUrl("")); // empty
    try testing.expect(!bimi.validateVmcUrl("https://localhost/cert.pem")); // no dot
}

// =============================================================================
// BIMI Indicator
// =============================================================================

test "BIMIIndicator isDisplayable" {
    var indicator = bimi.BIMIIndicator{
        .domain = try testing.allocator.dupe(u8, "example.com"),
        .svg_url = try testing.allocator.dupe(u8, "https://example.com/logo.svg"),
        .vmc_url = try testing.allocator.dupe(u8, "https://example.com/vmc.pem"),
        .verified = true,
        .dmarc_aligned = true,
        .fetched_at = 1700000000,
        .allocator = testing.allocator,
    };
    defer indicator.deinit();

    try testing.expect(indicator.isDisplayable());

    indicator.verified = false;
    try testing.expect(!indicator.isDisplayable());

    indicator.verified = true;
    indicator.dmarc_aligned = false;
    try testing.expect(!indicator.isDisplayable());
}

// =============================================================================
// BIMI Policy Cache
// =============================================================================

test "BIMIPolicy init and DNS name" {
    const policy = try bimi.BIMIPolicy.init(testing.allocator, "example.com", "default", null, 3600);
    var policy_mut = policy;
    defer policy_mut.deinit();

    try testing.expectEqualStrings("example.com", policy.domain);
    try testing.expectEqualStrings("default", policy.selector);
    try testing.expect(policy.record == null);

    const dns_name = try policy.getDnsName(testing.allocator);
    defer testing.allocator.free(dns_name);
    try testing.expectEqualStrings("default._bimi.example.com", dns_name);
}

test "BIMIPolicy expiration" {
    // TTL of 0 means immediately expired
    const policy = try bimi.BIMIPolicy.init(testing.allocator, "example.com", "default", null, 0);
    var policy_mut = policy;
    defer policy_mut.deinit();

    try testing.expect(policy.isExpired());
}

test "BIMIPolicyCache put and get" {
    var cache = bimi.BIMIPolicyCache.init(testing.allocator);
    defer cache.deinit();

    const policy = try bimi.BIMIPolicy.init(testing.allocator, "example.com", "default", null, 3600);
    try cache.put(policy);

    try testing.expectEqual(@as(u32, 1), cache.count());
    const retrieved = cache.get("example.com");
    try testing.expect(retrieved != null);
    try testing.expectEqualStrings("example.com", retrieved.?.domain);
}

test "BIMIPolicyCache get nonexistent" {
    var cache = bimi.BIMIPolicyCache.init(testing.allocator);
    defer cache.deinit();

    try testing.expect(cache.get("nonexistent.com") == null);
}

test "BIMIPolicyCache isExpired with no entry" {
    var cache = bimi.BIMIPolicyCache.init(testing.allocator);
    defer cache.deinit();

    try testing.expect(cache.isExpired("nonexistent.com"));
}

test "BIMIPolicyCache remove" {
    var cache = bimi.BIMIPolicyCache.init(testing.allocator);
    defer cache.deinit();

    const policy = try bimi.BIMIPolicy.init(testing.allocator, "example.com", "default", null, 3600);
    try cache.put(policy);
    try testing.expectEqual(@as(u32, 1), cache.count());

    cache.remove("example.com");
    try testing.expectEqual(@as(u32, 0), cache.count());
    try testing.expect(cache.get("example.com") == null);
}

test "BIMIPolicyCache replace existing entry" {
    var cache = bimi.BIMIPolicyCache.init(testing.allocator);
    defer cache.deinit();

    const policy1 = try bimi.BIMIPolicy.init(testing.allocator, "example.com", "default", null, 3600);
    try cache.put(policy1);

    const policy2 = try bimi.BIMIPolicy.init(testing.allocator, "example.com", "brand2024", null, 7200);
    try cache.put(policy2);

    try testing.expectEqual(@as(u32, 1), cache.count());
    const retrieved = cache.get("example.com");
    try testing.expect(retrieved != null);
    try testing.expectEqualStrings("brand2024", retrieved.?.selector);
    try testing.expectEqual(@as(i64, 7200), retrieved.?.cache_ttl);
}

// =============================================================================
// BIMI Validator Stubs
// =============================================================================

test "BIMIValidator lookupBIMI returns null (stubbed)" {
    var validator = bimi.BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    const result = try validator.lookupBIMI("example.com");
    try testing.expect(result == null);
}

test "BIMIValidator fetchIndicator returns null (stubbed)" {
    var validator = bimi.BIMIValidator.init(testing.allocator);
    defer validator.deinit();

    const result = try validator.fetchIndicator("https://example.com/logo.svg");
    try testing.expect(result == null);
}
