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

// =============================================================================
// Edge Case Tests
// =============================================================================

test "RFC 8617 Edge Case: ARC chain with instance number 0 is invalid" {
    // Instance numbers must start at 1 per RFC 8617.
    // AAR with i=0
    const aar_result = arc.ARCAuthenticationResults.parse(testing.allocator, "i=0; mx.example.com; dkim=pass");
    try testing.expectError(error.InvalidInstanceNumber, aar_result);

    // AMS with i=0
    const ams_result = arc.ARCMessageSignature.parse(testing.allocator, "i=0; a=rsa-sha256; d=example.com; s=sel; h=from; bh=bh==; b=sig==");
    try testing.expectError(error.InvalidInstanceNumber, ams_result);

    // ARC-Seal with i=0
    const seal_result = arc.ARCSeal.parse(testing.allocator, "i=0; a=rsa-sha256; d=example.com; s=sel; cv=none; b=sig==");
    try testing.expectError(error.InvalidInstanceNumber, seal_result);
}

test "RFC 8617 Edge Case: ARC chain with gap in instance numbers (1, 2, 4 - missing 3)" {
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

    // Set 4 (skipping instance 3)
    var aar4 = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=4; hop4.example.net; dkim=pass");
    errdefer aar4.deinit();
    var ams4 = try arc.ARCMessageSignature.parse(testing.allocator, "i=4; a=rsa-sha256; d=hop4.example.net; s=sel; h=from; bh=bh==; b=sig4==");
    errdefer ams4.deinit();
    var seal4 = try arc.ARCSeal.parse(testing.allocator, "i=4; a=rsa-sha256; d=hop4.example.net; s=sel; cv=pass; b=seal4==");
    errdefer seal4.deinit();
    try chain.addSet(.{ .instance = 4, .aar = aar4, .ams = ams4, .seal = seal4 });

    // Chain has 3 sets but instance numbers are 1,2,4 -- gap at 3.
    // validateChainIntegrity checks for sequential 1..n where n=count().
    // With n=3, it looks for instances 1,2,3. Instance 3 is missing, so it should fail.
    try testing.expect(chain.validateChainIntegrity() == .fail);
}

test "RFC 8617 Edge Case: ARC chain with duplicate instance numbers" {
    var chain = arc.ARCChain.init(testing.allocator);
    defer chain.deinit();

    // Two sets both claiming to be instance 1
    var aar1a = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=1; mx.example.com; dkim=pass");
    errdefer aar1a.deinit();
    var ams1a = try arc.ARCMessageSignature.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=bh==; b=sig1a==");
    errdefer ams1a.deinit();
    var seal1a = try arc.ARCSeal.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; cv=none; b=seal1a==");
    errdefer seal1a.deinit();
    try chain.addSet(.{ .instance = 1, .aar = aar1a, .ams = ams1a, .seal = seal1a });

    var aar1b = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=1; relay.example.org; spf=pass");
    errdefer aar1b.deinit();
    var ams1b = try arc.ARCMessageSignature.parse(testing.allocator, "i=1; a=rsa-sha256; d=relay.example.org; s=sel; h=from; bh=bh==; b=sig1b==");
    errdefer ams1b.deinit();
    var seal1b = try arc.ARCSeal.parse(testing.allocator, "i=1; a=rsa-sha256; d=relay.example.org; s=sel; cv=none; b=seal1b==");
    errdefer seal1b.deinit();
    try chain.addSet(.{ .instance = 1, .aar = aar1b, .ams = ams1b, .seal = seal1b });

    // Chain has 2 sets but both are instance 1.
    // validateChainIntegrity expects sequential 1..2, so it looks for instance 2 which does not exist.
    try testing.expect(chain.validateChainIntegrity() == .fail);
}

test "RFC 8617 Edge Case: ARC chain with instance number exceeding RFC limit of 50" {
    // RFC 8617 limits the chain to 50 ARC sets.
    // The ARCSealer enforces this: sealing at instance 51 should fail.
    var sealer = try arc.ARCSealer.init(testing.allocator, "example.com", "sel", "private-key-data");
    defer sealer.deinit();

    // Attempting to seal with existing_chain_length = 50 means new instance = 51
    const result = sealer.seal(
        "From: test@example.com\r\nTo: recv@example.com\r\n",
        "Hello, world!",
        "mx.example.com; dkim=pass",
        .pass,
        50,
    );
    try testing.expectError(error.ARCChainTooLong, result);
}

test "RFC 8617 Edge Case: ARC-Authentication-Results with empty results after semicolon" {
    // The AAR has i=1; followed by nothing meaningful -- just whitespace.
    // This should still parse since the format is valid (i=N; <results>).
    var aar = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=1;   ");
    defer aar.deinit();

    try testing.expectEqual(@as(u32, 1), aar.instance);
    try testing.expectEqualStrings("", aar.results);
}

test "RFC 8617 Edge Case: ARC-Message-Signature missing required d= field" {
    // Missing domain (d=) tag -- all other required fields present
    const header = "i=1; a=rsa-sha256; s=sel; h=from; bh=bh==; b=sig==";
    const result = arc.ARCMessageSignature.parse(testing.allocator, header);
    try testing.expectError(error.InvalidAMSHeader, result);
}

test "RFC 8617 Edge Case: ARC-Message-Signature missing required s= field" {
    // Missing selector (s=) tag
    const header = "i=1; a=rsa-sha256; d=example.com; h=from; bh=bh==; b=sig==";
    const result = arc.ARCMessageSignature.parse(testing.allocator, header);
    try testing.expectError(error.InvalidAMSHeader, result);
}

test "RFC 8617 Edge Case: ARC-Message-Signature missing required b= field" {
    // Missing signature (b=) tag
    const header = "i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=bh==";
    const result = arc.ARCMessageSignature.parse(testing.allocator, header);
    try testing.expectError(error.InvalidAMSHeader, result);
}

test "RFC 8617 Edge Case: ARC-Seal missing required d= field" {
    const header = "i=1; a=rsa-sha256; s=sel; cv=none; b=sig==";
    const result = arc.ARCSeal.parse(testing.allocator, header);
    try testing.expectError(error.InvalidASSeal, result);
}

test "RFC 8617 Edge Case: ARC-Seal missing required s= field" {
    const header = "i=1; a=rsa-sha256; d=example.com; cv=none; b=sig==";
    const result = arc.ARCSeal.parse(testing.allocator, header);
    try testing.expectError(error.InvalidASSeal, result);
}

test "RFC 8617 Edge Case: ARC-Seal missing required b= field" {
    const header = "i=1; a=rsa-sha256; d=example.com; s=sel; cv=none";
    const result = arc.ARCSeal.parse(testing.allocator, header);
    try testing.expectError(error.InvalidASSeal, result);
}

test "RFC 8617 Edge Case: ARC-Seal with cv=none on instance > 1 is invalid" {
    // Per RFC 8617, cv=none is only valid for i=1. For i>1, cv must be pass or fail.
    var chain = arc.ARCChain.init(testing.allocator);
    defer chain.deinit();

    // Valid set 1
    var aar1 = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=1; mx.example.com; spf=pass");
    errdefer aar1.deinit();
    var ams1 = try arc.ARCMessageSignature.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=bh==; b=sig1==");
    errdefer ams1.deinit();
    var seal1 = try arc.ARCSeal.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; cv=none; b=seal1==");
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

    // Also verify via the ARCValidator.validateSet path
    var validator = arc.ARCValidator.init(testing.allocator);
    defer validator.deinit();

    const set2 = chain.getSet(2).?;
    try testing.expect(!validator.validateSet(set2, 2));
}

test "RFC 8617 Edge Case: ARC-Seal with cv=pass on instance 1 is invalid" {
    // Per RFC 8617, the first ARC set (i=1) must have cv=none.
    var chain = arc.ARCChain.init(testing.allocator);
    defer chain.deinit();

    var aar = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=1; mx.example.com; spf=pass");
    errdefer aar.deinit();
    var ams = try arc.ARCMessageSignature.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=bh==; b=sig==");
    errdefer ams.deinit();
    var seal = try arc.ARCSeal.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; cv=pass; b=seal==");
    errdefer seal.deinit();
    try chain.addSet(.{ .instance = 1, .aar = aar, .ams = ams, .seal = seal });

    try testing.expect(chain.validateChainIntegrity() == .fail);

    // Also verify via validateSet
    var validator = arc.ARCValidator.init(testing.allocator);
    defer validator.deinit();

    const set1 = chain.getSet(1).?;
    try testing.expect(!validator.validateSet(set1, 1));
}

test "RFC 8617 Edge Case: Empty message headers for ARC validation returns none" {
    var validator = arc.ARCValidator.init(testing.allocator);
    defer validator.deinit();

    // An empty header string contains no ARC sets, so validateChain should return .none
    const result = try validator.validateChain("");
    try testing.expect(result == .none);
}

test "RFC 8617 Edge Case: Message with no ARC headers returns none" {
    var validator = arc.ARCValidator.init(testing.allocator);
    defer validator.deinit();

    const headers =
        "From: sender@example.com\r\n" ++
        "To: recipient@example.com\r\n" ++
        "Subject: Test Message\r\n" ++
        "Date: Thu, 01 Jan 2025 00:00:00 +0000\r\n" ++
        "\r\n";

    const result = try validator.validateChain(headers);
    try testing.expect(result == .none);
}

test "RFC 8617 Edge Case: Very long header value exceeding RFC 5322 line limit" {
    // RFC 5322 limits lines to 998 characters. ARC headers with very long
    // signatures may be folded. This test ensures parsing handles a single
    // very long value without crashing.
    const long_sig = "A" ** 1200;
    const header = try std.fmt.allocPrint(
        testing.allocator,
        "i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=bh==; b={s}",
        .{long_sig},
    );
    defer testing.allocator.free(header);

    var ams = try arc.ARCMessageSignature.parse(testing.allocator, header);
    defer ams.deinit();

    try testing.expectEqual(@as(u32, 1), ams.instance);
    try testing.expectEqualStrings(long_sig, ams.signature);
}

test "RFC 8617 Edge Case: ARCSealer determineChainValidation for instance 1 is always none" {
    var sealer = try arc.ARCSealer.init(testing.allocator, "example.com", "sel", "key");
    defer sealer.deinit();

    // Regardless of the chain_status argument, instance 1 must produce cv=none
    try testing.expect(sealer.determineChainValidation(1, .pass) == .none);
    try testing.expect(sealer.determineChainValidation(1, .fail) == .none);
    try testing.expect(sealer.determineChainValidation(1, .none) == .none);
}

test "RFC 8617 Edge Case: ARCSealer determineChainValidation for instance > 1 reflects chain status" {
    var sealer = try arc.ARCSealer.init(testing.allocator, "example.com", "sel", "key");
    defer sealer.deinit();

    try testing.expect(sealer.determineChainValidation(2, .pass) == .pass);
    try testing.expect(sealer.determineChainValidation(2, .fail) == .fail);
    try testing.expect(sealer.determineChainValidation(5, .pass) == .pass);
}

test "RFC 8617 Edge Case: ARC-Seal with cv=fail on instance 1 is invalid" {
    var chain = arc.ARCChain.init(testing.allocator);
    defer chain.deinit();

    var aar = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=1; mx.example.com; spf=fail");
    errdefer aar.deinit();
    var ams = try arc.ARCMessageSignature.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=bh==; b=sig==");
    errdefer ams.deinit();
    var seal = try arc.ARCSeal.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; cv=fail; b=seal==");
    errdefer seal.deinit();
    try chain.addSet(.{ .instance = 1, .aar = aar, .ams = ams, .seal = seal });

    // cv=fail on i=1 is invalid (must be cv=none)
    try testing.expect(chain.validateChainIntegrity() == .fail);
}

test "RFC 8617 Edge Case: AMS with unsupported algorithm fails validateSet" {
    var chain = arc.ARCChain.init(testing.allocator);
    defer chain.deinit();

    var aar = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=1; mx.example.com; spf=pass");
    errdefer aar.deinit();
    // Use an unsupported algorithm "rsa-md5"
    var ams = try arc.ARCMessageSignature.parse(testing.allocator, "i=1; a=rsa-md5; d=example.com; s=sel; h=from; bh=bh==; b=sig==");
    errdefer ams.deinit();
    var seal = try arc.ARCSeal.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; cv=none; b=seal==");
    errdefer seal.deinit();
    try chain.addSet(.{ .instance = 1, .aar = aar, .ams = ams, .seal = seal });

    var validator = arc.ARCValidator.init(testing.allocator);
    defer validator.deinit();

    const set1 = chain.getSet(1).?;
    try testing.expect(!validator.validateSet(set1, 1));
}

test "RFC 8617 Edge Case: ARC-Seal with unsupported algorithm fails validateSet" {
    var chain = arc.ARCChain.init(testing.allocator);
    defer chain.deinit();

    var aar = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=1; mx.example.com; spf=pass");
    errdefer aar.deinit();
    var ams = try arc.ARCMessageSignature.parse(testing.allocator, "i=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=bh==; b=sig==");
    errdefer ams.deinit();
    // Use unsupported algorithm in seal
    var seal = try arc.ARCSeal.parse(testing.allocator, "i=1; a=rsa-md5; d=example.com; s=sel; cv=none; b=seal==");
    errdefer seal.deinit();
    try chain.addSet(.{ .instance = 1, .aar = aar, .ams = ams, .seal = seal });

    var validator = arc.ARCValidator.init(testing.allocator);
    defer validator.deinit();

    const set1 = chain.getSet(1).?;
    try testing.expect(!validator.validateSet(set1, 1));
}

test "RFC 8617 Edge Case: Validator with more than 50 ARC sets returns permerror" {
    // Build raw headers with 51 ARC sets to exceed the RFC 8617 limit.
    var headers_buf: std.ArrayList(u8) = .{};
    defer headers_buf.deinit(testing.allocator);

    var i: u32 = 1;
    while (i <= 51) : (i += 1) {
        const cv = if (i == 1) "none" else "pass";
        const aar_line = try std.fmt.allocPrint(testing.allocator, "ARC-Authentication-Results: i={d}; mx.example.com; spf=pass\r\n", .{i});
        defer testing.allocator.free(aar_line);
        const ams_line = try std.fmt.allocPrint(testing.allocator, "ARC-Message-Signature: i={d}; a=rsa-sha256; d=example.com; s=sel; h=from; bh=bh==; b=sig{d}==\r\n", .{ i, i });
        defer testing.allocator.free(ams_line);
        const seal_line = try std.fmt.allocPrint(testing.allocator, "ARC-Seal: i={d}; a=rsa-sha256; d=example.com; s=sel; cv={s}; b=seal{d}==\r\n", .{ i, cv, i });
        defer testing.allocator.free(seal_line);

        try headers_buf.appendSlice(testing.allocator, aar_line);
        try headers_buf.appendSlice(testing.allocator, ams_line);
        try headers_buf.appendSlice(testing.allocator, seal_line);
    }
    try headers_buf.appendSlice(testing.allocator, "\r\n");

    var validator = arc.ARCValidator.init(testing.allocator);
    defer validator.deinit();

    const result = try validator.validateChain(headers_buf.items);
    try testing.expect(result == .permerror);
}

test "RFC 8617 Edge Case: AAR with negative instance number fails" {
    // A negative number is not valid for u32 parsing, so this should fail.
    const result = arc.ARCAuthenticationResults.parse(testing.allocator, "i=-1; mx.example.com; dkim=pass");
    try testing.expectError(error.InvalidInstanceNumber, result);
}

test "RFC 8617 Edge Case: AMS with empty tag values after equals sign" {
    // Tags with empty values: a=, d=, etc. should fail validation since required fields are empty.
    const header = "i=1; a=; d=; s=; h=; bh=; b=";
    const result = arc.ARCMessageSignature.parse(testing.allocator, header);
    try testing.expectError(error.InvalidAMSHeader, result);
}

test "RFC 8617 Edge Case: Valid three-set chain validates to pass" {
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
    var aar2 = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=2; relay1.example.org; dkim=pass");
    errdefer aar2.deinit();
    var ams2 = try arc.ARCMessageSignature.parse(testing.allocator, "i=2; a=rsa-sha256; d=relay1.example.org; s=sel; h=from; bh=bh==; b=sig2==");
    errdefer ams2.deinit();
    var seal2 = try arc.ARCSeal.parse(testing.allocator, "i=2; a=rsa-sha256; d=relay1.example.org; s=sel; cv=pass; b=seal2==");
    errdefer seal2.deinit();
    try chain.addSet(.{ .instance = 2, .aar = aar2, .ams = ams2, .seal = seal2 });

    // Set 3
    var aar3 = try arc.ARCAuthenticationResults.parse(testing.allocator, "i=3; relay2.example.net; dkim=pass");
    errdefer aar3.deinit();
    var ams3 = try arc.ARCMessageSignature.parse(testing.allocator, "i=3; a=rsa-sha256; d=relay2.example.net; s=sel; h=from; bh=bh==; b=sig3==");
    errdefer ams3.deinit();
    var seal3 = try arc.ARCSeal.parse(testing.allocator, "i=3; a=rsa-sha256; d=relay2.example.net; s=sel; cv=pass; b=seal3==");
    errdefer seal3.deinit();
    try chain.addSet(.{ .instance = 3, .aar = aar3, .ams = ams3, .seal = seal3 });

    try testing.expectEqual(@as(usize, 3), chain.count());
    try testing.expect(chain.validateChainIntegrity() == .pass);
}
