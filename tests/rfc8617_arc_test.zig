// RFC 8617 (Authenticated Received Chain) Test Suite
// Tests for compliance with RFC 8617 - ARC Protocol
// https://datatracker.ietf.org/doc/html/rfc8617

const std = @import("std");
const testing = std.testing;
const arc = @import("mail").arc;

// =============================================================================
// RFC 8617 Section 4: ARC Result Types
// =============================================================================

test "RFC 8617: ARCResult toString produces correct strings" {
    try testing.expectEqualStrings("pass", arc.ARCResult.pass.toString());
    try testing.expectEqualStrings("fail", arc.ARCResult.fail.toString());
    try testing.expectEqualStrings("none", arc.ARCResult.none.toString());
    try testing.expectEqualStrings("temperror", arc.ARCResult.temperror.toString());
    try testing.expectEqualStrings("permerror", arc.ARCResult.permerror.toString());
}

test "RFC 8617: ARCResult fromString parses case-insensitively" {
    try testing.expect(arc.ARCResult.fromString("pass") == .pass);
    try testing.expect(arc.ARCResult.fromString("PASS") == .pass);
    try testing.expect(arc.ARCResult.fromString("Pass") == .pass);
    try testing.expect(arc.ARCResult.fromString("fail") == .fail);
    try testing.expect(arc.ARCResult.fromString("FAIL") == .fail);
    try testing.expect(arc.ARCResult.fromString("none") == .none);
    try testing.expect(arc.ARCResult.fromString("temperror") == .temperror);
    try testing.expect(arc.ARCResult.fromString("TEMPERROR") == .temperror);
    try testing.expect(arc.ARCResult.fromString("permerror") == .permerror);
}

test "RFC 8617: ARCResult fromString returns none for unknown values" {
    try testing.expect(arc.ARCResult.fromString("unknown") == .none);
    try testing.expect(arc.ARCResult.fromString("") == .none);
    try testing.expect(arc.ARCResult.fromString("invalid") == .none);
}

test "RFC 8617: ARCChainValidation toString" {
    try testing.expectEqualStrings("none", arc.ARCChainValidation.none.toString());
    try testing.expectEqualStrings("pass", arc.ARCChainValidation.pass.toString());
    try testing.expectEqualStrings("fail", arc.ARCChainValidation.fail.toString());
}

test "RFC 8617: ARCChainValidation fromString parses case-insensitively" {
    try testing.expect(arc.ARCChainValidation.fromString("pass") == .pass);
    try testing.expect(arc.ARCChainValidation.fromString("PASS") == .pass);
    try testing.expect(arc.ARCChainValidation.fromString("fail") == .fail);
    try testing.expect(arc.ARCChainValidation.fromString("FAIL") == .fail);
    try testing.expect(arc.ARCChainValidation.fromString("none") == .none);
    try testing.expect(arc.ARCChainValidation.fromString("unknown") == .none);
}

// =============================================================================
// RFC 8617 Section 5.1: ARC-Authentication-Results (AAR) Parsing
// =============================================================================

test "RFC 8617 Section 5.1: Parse valid AAR header" {
    const header = "i=1; mx.example.com; dkim=pass header.d=example.com; spf=pass";
    var aar = try arc.ARCAuthenticationResults.parse(testing.allocator, header);
    defer aar.deinit();

    try testing.expectEqual(@as(u32, 1), aar.instance);
    try testing.expectEqualStrings("mx.example.com; dkim=pass header.d=example.com; spf=pass", aar.results);
}

test "RFC 8617 Section 5.1: Parse AAR header with instance 5" {
    const header = "i=5; relay.example.org; dmarc=pass";
    var aar = try arc.ARCAuthenticationResults.parse(testing.allocator, header);
    defer aar.deinit();

    try testing.expectEqual(@as(u32, 5), aar.instance);
    try testing.expectEqualStrings("relay.example.org; dmarc=pass", aar.results);
}

test "RFC 8617 Section 5.1: AAR header missing i= tag fails" {
    const header = "mx.example.com; dkim=pass";
    const result = arc.ARCAuthenticationResults.parse(testing.allocator, header);
    try testing.expectError(error.InvalidAARHeader, result);
}

test "RFC 8617 Section 5.1: AAR header with invalid instance number fails" {
    const header = "i=abc; mx.example.com; dkim=pass";
    const result = arc.ARCAuthenticationResults.parse(testing.allocator, header);
    try testing.expectError(error.InvalidInstanceNumber, result);
}

test "RFC 8617 Section 5.1: AAR header with instance 0 fails" {
    const header = "i=0; mx.example.com; dkim=pass";
    const result = arc.ARCAuthenticationResults.parse(testing.allocator, header);
    try testing.expectError(error.InvalidInstanceNumber, result);
}

test "RFC 8617 Section 5.1: AAR header missing semicolon after i= fails" {
    const header = "i=1 no semicolon here";
    const result = arc.ARCAuthenticationResults.parse(testing.allocator, header);
    try testing.expectError(error.InvalidAARHeader, result);
}

test "RFC 8617 Section 5.1: AAR format generates correct header line" {
    var aar = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=2; mx.test.com; spf=pass");
    defer aar.deinit();

    const formatted = try aar.format(testing.allocator);
    defer testing.allocator.free(formatted);

    try testing.expect(std.mem.indexOf(u8, formatted, "ARC-Authentication-Results:") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "i=2") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "mx.test.com; spf=pass") != null);
}

// =============================================================================
// RFC 8617 Section 5.2: ARC-Message-Signature (AMS) Parsing
// =============================================================================

test "RFC 8617 Section 5.2: Parse valid AMS header" {
    const header = "i=1; a=rsa-sha256; d=example.com; s=selector1; h=from:to:subject; bh=BODYHASH==; b=SIGNATURE==";
    var ams = try arc.ARCMessageSignature.parse(testing.allocator, header);
    defer ams.deinit();

    try testing.expectEqual(@as(u32, 1), ams.instance);
    try testing.expectEqualStrings("rsa-sha256", ams.algorithm);
    try testing.expectEqualStrings("example.com", ams.domain);
    try testing.expectEqualStrings("selector1", ams.selector);
    try testing.expectEqualStrings("from:to:subject", ams.headers);
    try testing.expectEqualStrings("BODYHASH==", ams.body_hash);
    try testing.expectEqualStrings("SIGNATURE==", ams.signature);
}

test "RFC 8617 Section 5.2: AMS with explicit canonicalization" {
    const header = "i=1; a=rsa-sha256; c=simple/relaxed; d=example.com; s=sel; h=from; bh=bh==; b=sig==";
    var ams = try arc.ARCMessageSignature.parse(testing.allocator, header);
    defer ams.deinit();

    try testing.expectEqualStrings("simple/relaxed", ams.canonicalization);
}

test "RFC 8617 Section 5.2: AMS defaults to relaxed/relaxed canonicalization" {
    const header = "i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=bh==; b=sig==";
    var ams = try arc.ARCMessageSignature.parse(testing.allocator, header);
    defer ams.deinit();

    try testing.expectEqualStrings("relaxed/relaxed", ams.canonicalization);
}

test "RFC 8617 Section 5.2: AMS with timestamp" {
    const header = "i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=bh==; b=sig==; t=1700000000";
    var ams = try arc.ARCMessageSignature.parse(testing.allocator, header);
    defer ams.deinit();

    try testing.expect(ams.timestamp != null);
    try testing.expectEqual(@as(i64, 1700000000), ams.timestamp.?);
}

test "RFC 8617 Section 5.2: AMS missing required fields fails" {
    // Missing algorithm
    const header1 = "i=1; d=example.com; s=sel; h=from; bh=bh==; b=sig==";
    const result1 = arc.ARCMessageSignature.parse(testing.allocator, header1);
    try testing.expectError(error.InvalidAMSHeader, result1);

    // Missing domain
    const header2 = "i=1; a=rsa-sha256; s=sel; h=from; bh=bh==; b=sig==";
    const result2 = arc.ARCMessageSignature.parse(testing.allocator, header2);
    try testing.expectError(error.InvalidAMSHeader, result2);

    // Missing signature
    const header3 = "i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=bh==";
    const result3 = arc.ARCMessageSignature.parse(testing.allocator, header3);
    try testing.expectError(error.InvalidAMSHeader, result3);
}

test "RFC 8617 Section 5.2: AMS with instance 0 fails" {
    const header = "i=0; a=rsa-sha256; d=example.com; s=sel; h=from; bh=bh==; b=sig==";
    const result = arc.ARCMessageSignature.parse(testing.allocator, header);
    try testing.expectError(error.InvalidInstanceNumber, result);
}

test "RFC 8617 Section 5.2: AMS format produces valid header" {
    const header = "i=3; a=rsa-sha256; d=example.com; s=selector1; h=from:to; bh=bodyhash==; b=signature==";
    var ams = try arc.ARCMessageSignature.parse(testing.allocator, header);
    defer ams.deinit();

    const formatted = try ams.format(testing.allocator);
    defer testing.allocator.free(formatted);

    try testing.expect(std.mem.indexOf(u8, formatted, "ARC-Message-Signature:") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "i=3") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "rsa-sha256") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "example.com") != null);
}

// =============================================================================
// RFC 8617 Section 5.3: ARC-Seal (AS) Parsing
// =============================================================================

test "RFC 8617 Section 5.3: Parse valid ARC-Seal header" {
    const header = "i=1; a=rsa-sha256; d=example.com; s=selector; cv=none; b=SEALSIG==";
    var seal = try arc.ARCSeal.parse(testing.allocator, header);
    defer seal.deinit();

    try testing.expectEqual(@as(u32, 1), seal.instance);
    try testing.expectEqualStrings("rsa-sha256", seal.algorithm);
    try testing.expectEqualStrings("example.com", seal.domain);
    try testing.expectEqualStrings("selector", seal.selector);
    try testing.expectEqualStrings("SEALSIG==", seal.signature);
    try testing.expect(seal.chain_validation == .none);
}

test "RFC 8617 Section 5.3: ARC-Seal with cv=pass" {
    const header = "i=2; a=rsa-sha256; d=relay.example.com; s=s1; cv=pass; b=SEAL2==";
    var seal = try arc.ARCSeal.parse(testing.allocator, header);
    defer seal.deinit();

    try testing.expect(seal.chain_validation == .pass);
    try testing.expectEqual(@as(u32, 2), seal.instance);
}

test "RFC 8617 Section 5.3: ARC-Seal with cv=fail" {
    const header = "i=3; a=rsa-sha256; d=example.com; s=s1; cv=fail; b=SEAL3==";
    var seal = try arc.ARCSeal.parse(testing.allocator, header);
    defer seal.deinit();

    try testing.expect(seal.chain_validation == .fail);
}

test "RFC 8617 Section 5.3: ARC-Seal with timestamp" {
    const header = "i=1; a=rsa-sha256; d=example.com; s=s1; cv=none; b=SIG==; t=1700000000";
    var seal = try arc.ARCSeal.parse(testing.allocator, header);
    defer seal.deinit();

    try testing.expect(seal.timestamp != null);
    try testing.expectEqual(@as(i64, 1700000000), seal.timestamp.?);
}

test "RFC 8617 Section 5.3: ARC-Seal missing required fields fails" {
    // Missing algorithm
    const header = "i=1; d=example.com; s=sel; cv=none; b=sig==";
    const result = arc.ARCSeal.parse(testing.allocator, header);
    try testing.expectError(error.InvalidASSeal, result);
}

test "RFC 8617 Section 5.3: ARC-Seal format produces valid header" {
    const header = "i=1; a=rsa-sha256; d=example.com; s=selector; cv=none; b=SEAL==";
    var seal = try arc.ARCSeal.parse(testing.allocator, header);
    defer seal.deinit();

    const formatted = try seal.format(testing.allocator);
    defer testing.allocator.free(formatted);

    try testing.expect(std.mem.indexOf(u8, formatted, "ARC-Seal:") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "cv=none") != null);
}

// =============================================================================
// RFC 8617 Section 5.4: ARC Set Consistency
// =============================================================================

test "RFC 8617 Section 5.4: ARCSet validates instance consistency" {
    var aar = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=1; mx.example.com; spf=pass");
    errdefer aar.deinit();
    var ams = try arc.ARCMessageSignature.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=bh==; b=sig==");
    errdefer ams.deinit();
    var seal = try arc.ARCSeal.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; cv=none; b=sig==");
    errdefer seal.deinit();

    const set = arc.ARCSet{
        .instance = 1,
        .aar = aar,
        .ams = ams,
        .seal = seal,
    };

    try testing.expect(set.validateInstanceConsistency());

    // Clean up
    var mutable_set = set;
    mutable_set.deinit();
}

test "RFC 8617 Section 5.4: ARCSet detects instance mismatch" {
    var aar = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=1; mx.example.com; spf=pass");
    errdefer aar.deinit();
    var ams = try arc.ARCMessageSignature.parse(testing.allocator, "i=2; a=rsa-sha256; d=example.com; s=sel; h=from; bh=bh==; b=sig==");
    errdefer ams.deinit();
    var seal = try arc.ARCSeal.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; cv=none; b=sig==");
    errdefer seal.deinit();

    const set = arc.ARCSet{
        .instance = 1,
        .aar = aar,
        .ams = ams,
        .seal = seal,
    };

    // AMS has instance 2 but set has instance 1 -- mismatch
    try testing.expect(!set.validateInstanceConsistency());

    var mutable_set = set;
    mutable_set.deinit();
}

// =============================================================================
// RFC 8617 Section 5.5: ARC Chain Validation
// =============================================================================

test "RFC 8617 Section 5.5: Empty chain returns none" {
    var chain = arc.ARCChain.init(testing.allocator);
    defer chain.deinit();

    try testing.expect(chain.validateChainIntegrity() == .none);
    try testing.expectEqual(@as(usize, 0), chain.count());
}

test "RFC 8617 Section 5.5: Valid single-set chain (i=1, cv=none)" {
    var chain = arc.ARCChain.init(testing.allocator);
    defer chain.deinit();

    var aar = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=1; mx.example.com; dkim=pass");
    errdefer aar.deinit();
    var ams = try arc.ARCMessageSignature.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=bh==; b=sig==");
    errdefer ams.deinit();
    var seal = try arc.ARCSeal.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; cv=none; b=sig==");
    errdefer seal.deinit();

    try chain.addSet(.{ .instance = 1, .aar = aar, .ams = ams, .seal = seal });

    try testing.expectEqual(@as(usize, 1), chain.count());
    try testing.expect(chain.validateChainIntegrity() == .pass);
}

test "RFC 8617 Section 5.5: Valid two-set chain (i=1 cv=none, i=2 cv=pass)" {
    var chain = arc.ARCChain.init(testing.allocator);
    defer chain.deinit();

    // Set 1
    var aar1 = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=1; mx.example.com; dkim=pass");
    errdefer aar1.deinit();
    var ams1 = try arc.ARCMessageSignature.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=bh==; b=sig1==");
    errdefer ams1.deinit();
    var seal1 = try arc.ARCSeal.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; cv=none; b=seal1==");
    errdefer seal1.deinit();

    try chain.addSet(.{ .instance = 1, .aar = aar1, .ams = ams1, .seal = seal1 });

    // Set 2
    var aar2 = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=2; relay.example.org; dkim=pass");
    errdefer aar2.deinit();
    var ams2 = try arc.ARCMessageSignature.parse(testing.allocator, "i=2; a=rsa-sha256; d=relay.example.org; s=sel; h=from; bh=bh==; b=sig2==");
    errdefer ams2.deinit();
    var seal2 = try arc.ARCSeal.parse(testing.allocator, "i=2; a=rsa-sha256; d=relay.example.org; s=sel; cv=pass; b=seal2==");
    errdefer seal2.deinit();

    try chain.addSet(.{ .instance = 2, .aar = aar2, .ams = ams2, .seal = seal2 });

    try testing.expectEqual(@as(usize, 2), chain.count());
    try testing.expect(chain.validateChainIntegrity() == .pass);
}

test "RFC 8617 Section 5.5: Chain with cv=fail breaks validation" {
    var chain = arc.ARCChain.init(testing.allocator);
    defer chain.deinit();

    // Set 1 valid
    var aar1 = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=1; mx.example.com; spf=pass");
    errdefer aar1.deinit();
    var ams1 = try arc.ARCMessageSignature.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=bh==; b=sig1==");
    errdefer ams1.deinit();
    var seal1 = try arc.ARCSeal.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; cv=none; b=seal1==");
    errdefer seal1.deinit();

    try chain.addSet(.{ .instance = 1, .aar = aar1, .ams = ams1, .seal = seal1 });

    // Set 2 with cv=fail
    var aar2 = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=2; relay.example.org; dkim=fail");
    errdefer aar2.deinit();
    var ams2 = try arc.ARCMessageSignature.parse(testing.allocator, "i=2; a=rsa-sha256; d=relay.example.org; s=sel; h=from; bh=bh==; b=sig2==");
    errdefer ams2.deinit();
    var seal2 = try arc.ARCSeal.parse(testing.allocator, "i=2; a=rsa-sha256; d=relay.example.org; s=sel; cv=fail; b=seal2==");
    errdefer seal2.deinit();

    try chain.addSet(.{ .instance = 2, .aar = aar2, .ams = ams2, .seal = seal2 });

    try testing.expect(chain.validateChainIntegrity() == .fail);
}

test "RFC 8617 Section 5.5: First set must have cv=none" {
    var chain = arc.ARCChain.init(testing.allocator);
    defer chain.deinit();

    // Set 1 with cv=pass (invalid -- must be cv=none for i=1)
    var aar = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=1; mx.example.com; spf=pass");
    errdefer aar.deinit();
    var ams = try arc.ARCMessageSignature.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=bh==; b=sig==");
    errdefer ams.deinit();
    var seal = try arc.ARCSeal.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; cv=pass; b=seal==");
    errdefer seal.deinit();

    try chain.addSet(.{ .instance = 1, .aar = aar, .ams = ams, .seal = seal });

    try testing.expect(chain.validateChainIntegrity() == .fail);
}

test "RFC 8617 Section 5.5: Subsequent sets must not have cv=none" {
    var chain = arc.ARCChain.init(testing.allocator);
    defer chain.deinit();

    // Set 1 valid
    var aar1 = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=1; mx.example.com; spf=pass");
    errdefer aar1.deinit();
    var ams1 = try arc.ARCMessageSignature.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=bh==; b=sig==");
    errdefer ams1.deinit();
    var seal1 = try arc.ARCSeal.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; cv=none; b=seal==");
    errdefer seal1.deinit();

    try chain.addSet(.{ .instance = 1, .aar = aar1, .ams = ams1, .seal = seal1 });

    // Set 2 with cv=none (invalid for i>1)
    var aar2 = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=2; relay.example.org; spf=pass");
    errdefer aar2.deinit();
    var ams2 = try arc.ARCMessageSignature.parse(testing.allocator, "i=2; a=rsa-sha256; d=relay.example.org; s=sel; h=from; bh=bh==; b=sig2==");
    errdefer ams2.deinit();
    var seal2 = try arc.ARCSeal.parse(testing.allocator, "i=2; a=rsa-sha256; d=relay.example.org; s=sel; cv=none; b=seal2==");
    errdefer seal2.deinit();

    try chain.addSet(.{ .instance = 2, .aar = aar2, .ams = ams2, .seal = seal2 });

    try testing.expect(chain.validateChainIntegrity() == .fail);
}

// =============================================================================
// RFC 8617 Section 5.5: Chain Ordering
// =============================================================================

test "RFC 8617: Chain getSet retrieves by instance number" {
    var chain = arc.ARCChain.init(testing.allocator);
    defer chain.deinit();

    var aar = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=1; mx.example.com; spf=pass");
    errdefer aar.deinit();
    var ams = try arc.ARCMessageSignature.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=bh==; b=sig==");
    errdefer ams.deinit();
    var seal = try arc.ARCSeal.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; cv=none; b=seal==");
    errdefer seal.deinit();

    try chain.addSet(.{ .instance = 1, .aar = aar, .ams = ams, .seal = seal });

    // Can retrieve set 1
    const set = chain.getSet(1);
    try testing.expect(set != null);
    try testing.expectEqual(@as(u32, 1), set.?.instance);

    // Non-existent set returns null
    try testing.expect(chain.getSet(2) == null);
    try testing.expect(chain.getSet(0) == null);
}

test "RFC 8617: latestChainValidation returns status of highest instance" {
    var chain = arc.ARCChain.init(testing.allocator);
    defer chain.deinit();

    // Empty chain
    try testing.expect(chain.latestChainValidation() == .none);

    // Add set 1
    var aar1 = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=1; mx.example.com; spf=pass");
    errdefer aar1.deinit();
    var ams1 = try arc.ARCMessageSignature.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=bh==; b=sig==");
    errdefer ams1.deinit();
    var seal1 = try arc.ARCSeal.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; cv=none; b=seal==");
    errdefer seal1.deinit();

    try chain.addSet(.{ .instance = 1, .aar = aar1, .ams = ams1, .seal = seal1 });

    try testing.expect(chain.latestChainValidation() == .none);

    // Add set 2 with cv=pass
    var aar2 = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=2; relay.example.org; spf=pass");
    errdefer aar2.deinit();
    var ams2 = try arc.ARCMessageSignature.parse(testing.allocator, "i=2; a=rsa-sha256; d=relay.example.org; s=sel; h=from; bh=bh==; b=sig2==");
    errdefer ams2.deinit();
    var seal2 = try arc.ARCSeal.parse(testing.allocator, "i=2; a=rsa-sha256; d=relay.example.org; s=sel; cv=pass; b=seal2==");
    errdefer seal2.deinit();

    try chain.addSet(.{ .instance = 2, .aar = aar2, .ams = ams2, .seal = seal2 });

    try testing.expect(chain.latestChainValidation() == .pass);
}

// =============================================================================
// RFC 8617: ARCHeaderSet (Sealing Output)
// =============================================================================

test "RFC 8617: ARCHeaderSet deinit frees all headers" {
    const aar_h = try testing.allocator.dupe(u8, "ARC-Authentication-Results: i=1; mx.test.com; spf=pass");
    const ams_h = try testing.allocator.dupe(u8, "ARC-Message-Signature: i=1; a=rsa-sha256; d=test.com; s=sel; h=from; bh=bh==; b=sig==");
    const seal_h = try testing.allocator.dupe(u8, "ARC-Seal: i=1; a=rsa-sha256; d=test.com; s=sel; cv=none; b=seal==");

    var header_set = arc.ARCHeaderSet{
        .aar_header = aar_h,
        .ams_header = ams_h,
        .seal_header = seal_h,
        .allocator = testing.allocator,
    };
    defer header_set.deinit();

    // Produce full header block
    const block = try header_set.toHeaderBlock(testing.allocator);
    defer testing.allocator.free(block);

    try testing.expect(std.mem.indexOf(u8, block, "ARC-Authentication-Results:") != null);
    try testing.expect(std.mem.indexOf(u8, block, "ARC-Message-Signature:") != null);
    try testing.expect(std.mem.indexOf(u8, block, "ARC-Seal:") != null);
    // Headers separated by CRLF
    try testing.expect(std.mem.indexOf(u8, block, "\r\n") != null);
}

// =============================================================================
// RFC 8617: ARC Validator
// =============================================================================

test "RFC 8617: ARCValidator init and deinit" {
    var validator = arc.ARCValidator.init(testing.allocator);
    defer validator.deinit();
    // No crash = success
}

test "RFC 8617: Whitespace handling in tag=value parsing" {
    // Extra whitespace around tags should be handled gracefully
    const header = "  i=1 ;  a=rsa-sha256 ;  d=example.com ;  s=sel ;  h=from ;  bh=bh== ;  b=sig==  ";
    var ams = try arc.ARCMessageSignature.parse(testing.allocator, header);
    defer ams.deinit();

    try testing.expectEqual(@as(u32, 1), ams.instance);
    try testing.expectEqualStrings("rsa-sha256", ams.algorithm);
    try testing.expectEqualStrings("example.com", ams.domain);
}
