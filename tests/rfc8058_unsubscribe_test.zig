// RFC 8058 (One-Click List-Unsubscribe) Test Suite
// Tests for compliance with RFC 8058 - Signaling One-Click Functionality
// https://datatracker.ietf.org/doc/html/rfc8058

const std = @import("std");
const testing = std.testing;
const list_unsub = @import("mail").list_unsubscribe;

// =============================================================================
// Configuration Validation
// =============================================================================

test "RFC 8058: valid config passes validation" {
    const config = list_unsub.ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "supersecretkey1234567890abcdef",
    };
    try config.validate();
}

test "RFC 8058: empty url_base rejected" {
    const config = list_unsub.ListUnsubscribeConfig{
        .url_base = "",
        .hmac_secret = "supersecretkey1234567890abcdef",
    };
    try testing.expectError(error.EmptyUrlBase, config.validate());
}

test "RFC 8058: HTTP url rejected when require_https is true" {
    const config = list_unsub.ListUnsubscribeConfig{
        .url_base = "http://mail.example.com/unsubscribe",
        .hmac_secret = "supersecretkey1234567890abcdef",
        .require_https = true,
    };
    try testing.expectError(error.HttpsRequired, config.validate());
}

test "RFC 8058: HTTP url allowed when require_https is false" {
    const config = list_unsub.ListUnsubscribeConfig{
        .url_base = "http://localhost:8080/unsubscribe",
        .hmac_secret = "supersecretkey1234567890abcdef",
        .require_https = false,
    };
    try config.validate();
}

test "RFC 8058: secret too short rejected" {
    const config = list_unsub.ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "tooshort",
    };
    try testing.expectError(error.SecretTooShort, config.validate());
}

test "RFC 8058: zero TTL rejected" {
    const config = list_unsub.ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "supersecretkey1234567890abcdef",
        .token_ttl_seconds = 0,
    };
    try testing.expectError(error.InvalidTtl, config.validate());
}

test "RFC 8058: include_mailto without address rejected" {
    const config = list_unsub.ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "supersecretkey1234567890abcdef",
        .include_mailto = true,
        .mailto_address = null,
    };
    try testing.expectError(error.MissingMailtoAddress, config.validate());
}

// =============================================================================
// Token Generation and Validation
// =============================================================================

test "RFC 8058: token generation produces valid token" {
    const secret = "supersecretkey1234567890abcdef";
    var gen = list_unsub.UnsubscribeTokenGenerator.init(testing.allocator, secret);
    defer gen.deinit();

    const token = gen.generateToken("newsletter", "user@example.com", "<msg123@example.com>");

    try testing.expectEqualStrings("newsletter", token.list_id);
    try testing.expectEqualStrings("user@example.com", token.recipient);
    try testing.expectEqualStrings("<msg123@example.com>", token.message_id);
    try testing.expect(token.timestamp > 0);
}

test "RFC 8058: token with explicit timestamp" {
    const secret = "supersecretkey1234567890abcdef";
    var gen = list_unsub.UnsubscribeTokenGenerator.init(testing.allocator, secret);
    defer gen.deinit();

    const ts: i64 = 1700000000;
    const token = gen.generateTokenWithTimestamp("list1", "user@test.com", "<id@test.com>", ts);

    try testing.expectEqual(ts, token.timestamp);
}

test "RFC 8058: same inputs produce same HMAC" {
    const secret = "supersecretkey1234567890abcdef";
    var gen = list_unsub.UnsubscribeTokenGenerator.init(testing.allocator, secret);
    defer gen.deinit();

    const ts: i64 = 1700000000;
    const token1 = gen.generateTokenWithTimestamp("list", "user@test.com", "<id@test.com>", ts);
    const token2 = gen.generateTokenWithTimestamp("list", "user@test.com", "<id@test.com>", ts);

    try testing.expect(std.mem.eql(u8, &token1.hmac, &token2.hmac));
}

test "RFC 8058: different inputs produce different HMAC" {
    const secret = "supersecretkey1234567890abcdef";
    var gen = list_unsub.UnsubscribeTokenGenerator.init(testing.allocator, secret);
    defer gen.deinit();

    const ts: i64 = 1700000000;
    const token1 = gen.generateTokenWithTimestamp("list1", "user@test.com", "<id@test.com>", ts);
    const token2 = gen.generateTokenWithTimestamp("list2", "user@test.com", "<id@test.com>", ts);

    try testing.expect(!std.mem.eql(u8, &token1.hmac, &token2.hmac));
}

test "RFC 8058: token serialization roundtrip" {
    const secret = "supersecretkey1234567890abcdef";
    var gen = list_unsub.UnsubscribeTokenGenerator.init(testing.allocator, secret);
    defer gen.deinit();

    const ts: i64 = 1700000000;
    const original = gen.generateTokenWithTimestamp("newsletter", "user@example.com", "<msg@example.com>", ts);

    // Serialize
    const serialized = try original.serialize(testing.allocator);
    defer testing.allocator.free(serialized);

    // Deserialize
    var deserialized = try list_unsub.UnsubscribeToken.deserialize(testing.allocator, serialized);
    defer deserialized.deinit(testing.allocator);

    try testing.expectEqualStrings("newsletter", deserialized.list_id);
    try testing.expectEqualStrings("user@example.com", deserialized.recipient);
    try testing.expectEqualStrings("<msg@example.com>", deserialized.message_id);
    try testing.expectEqual(ts, deserialized.timestamp);
    try testing.expect(std.mem.eql(u8, &original.hmac, &deserialized.hmac));
}

test "RFC 8058: token validation accepts valid token" {
    const secret = "supersecretkey1234567890abcdef";
    var gen = list_unsub.UnsubscribeTokenGenerator.init(testing.allocator, secret);
    defer gen.deinit();

    const token = gen.generateToken("list", "user@test.com", "<id@test.com>");
    const result = gen.validateToken(&token);

    try testing.expect(result == .valid);
    try testing.expect(result.isValid());
}

test "RFC 8058: token validation rejects tampered HMAC" {
    const secret = "supersecretkey1234567890abcdef";
    var gen = list_unsub.UnsubscribeTokenGenerator.init(testing.allocator, secret);
    defer gen.deinit();

    var token = gen.generateToken("list", "user@test.com", "<id@test.com>");
    // Tamper with the HMAC
    token.hmac[0] ^= 0xFF;

    const result = gen.validateToken(&token);
    try testing.expect(result == .invalid_hmac);
    try testing.expect(!result.isValid());
}

test "RFC 8058: token validation rejects expired token" {
    const secret = "supersecretkey1234567890abcdef";
    // Create generator with 1-second TTL
    var gen = list_unsub.UnsubscribeTokenGenerator.initWithTtl(testing.allocator, secret, 1);
    defer gen.deinit();

    // Generate token far in the past
    const old_ts: i64 = 1000000000;
    const token = gen.generateTokenWithTimestamp("list", "user@test.com", "<id@test.com>", old_ts);

    const result = gen.validateToken(&token);
    try testing.expect(result == .expired);
}

test "RFC 8058: token validation rejects wrong secret" {
    const secret1 = "supersecretkey1234567890abcdef";
    const secret2 = "differentsecret1234567890abcde";

    var gen1 = list_unsub.UnsubscribeTokenGenerator.init(testing.allocator, secret1);
    defer gen1.deinit();
    var gen2 = list_unsub.UnsubscribeTokenGenerator.init(testing.allocator, secret2);
    defer gen2.deinit();

    const token = gen1.generateToken("list", "user@test.com", "<id@test.com>");
    const result = gen2.validateToken(&token);
    try testing.expect(result == .invalid_hmac);
}

// =============================================================================
// HMAC Validation
// =============================================================================

test "RFC 8058: validateTokenString with invalid base64" {
    const secret = "supersecretkey1234567890abcdef";
    var gen = list_unsub.UnsubscribeTokenGenerator.init(testing.allocator, secret);
    defer gen.deinit();

    const result = gen.validateTokenString("!!!not-valid-base64!!!");
    try testing.expect(result.result == .invalid_format);
    try testing.expect(result.token == null);
}

test "RFC 8058: validateTokenString with too-short data" {
    const secret = "supersecretkey1234567890abcdef";
    var gen = list_unsub.UnsubscribeTokenGenerator.init(testing.allocator, secret);
    defer gen.deinit();

    const result = gen.validateTokenString("AAAA");
    try testing.expect(result.result == .invalid_format);
    try testing.expect(result.token == null);
}

// =============================================================================
// TokenValidationResult Properties
// =============================================================================

test "RFC 8058: TokenValidationResult toString" {
    try testing.expectEqualStrings("Token is valid", list_unsub.TokenValidationResult.valid.toString());
    try testing.expectEqualStrings("Token HMAC verification failed", list_unsub.TokenValidationResult.invalid_hmac.toString());
    try testing.expectEqualStrings("Token has expired", list_unsub.TokenValidationResult.expired.toString());
    try testing.expectEqualStrings("Token format is invalid", list_unsub.TokenValidationResult.invalid_format.toString());
}

// =============================================================================
// One-Click Handler: POST-Only Enforcement
// =============================================================================

test "RFC 8058 Section 3: isValidRequest requires POST" {
    try testing.expect(list_unsub.OneClickHandler.isValidRequest("POST", "application/x-www-form-urlencoded"));
    try testing.expect(!list_unsub.OneClickHandler.isValidRequest("GET", "application/x-www-form-urlencoded"));
    try testing.expect(!list_unsub.OneClickHandler.isValidRequest("PUT", "application/x-www-form-urlencoded"));
    try testing.expect(!list_unsub.OneClickHandler.isValidRequest("DELETE", "application/x-www-form-urlencoded"));
}

test "RFC 8058 Section 3: isValidRequest requires correct content-type" {
    try testing.expect(list_unsub.OneClickHandler.isValidRequest("POST", "application/x-www-form-urlencoded"));
    try testing.expect(list_unsub.OneClickHandler.isValidRequest("POST", "application/x-www-form-urlencoded; charset=UTF-8"));
    try testing.expect(!list_unsub.OneClickHandler.isValidRequest("POST", "text/plain"));
    try testing.expect(!list_unsub.OneClickHandler.isValidRequest("POST", "application/json"));
}

test "RFC 8058 Section 3: handleUnsubscribeRequest rejects non-POST" {
    const config = list_unsub.ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "supersecretkey1234567890abcdef",
        .require_https = true,
    };
    var handler = list_unsub.OneClickHandler.init(testing.allocator, config);
    defer handler.deinit();

    const result = handler.handleUnsubscribeRequest("sometoken", "GET");
    try testing.expect(result == .invalid_method);
}

// =============================================================================
// UnsubscribeResult Properties
// =============================================================================

test "RFC 8058: UnsubscribeResult isSuccess" {
    try testing.expect(list_unsub.UnsubscribeResult.success.isSuccess());
    try testing.expect(!list_unsub.UnsubscribeResult.invalid_token.isSuccess());
    try testing.expect(!list_unsub.UnsubscribeResult.expired_token.isSuccess());
    try testing.expect(!list_unsub.UnsubscribeResult.invalid_method.isSuccess());
    try testing.expect(!list_unsub.UnsubscribeResult.already_unsubscribed.isSuccess());
    try testing.expect(!list_unsub.UnsubscribeResult.@"error".isSuccess());
}

test "RFC 8058: UnsubscribeResult toString" {
    try testing.expectEqualStrings("Successfully unsubscribed", list_unsub.UnsubscribeResult.success.toString());
    try testing.expectEqualStrings("Invalid unsubscribe token", list_unsub.UnsubscribeResult.invalid_token.toString());
    try testing.expectEqualStrings("Unsubscribe token has expired", list_unsub.UnsubscribeResult.expired_token.toString());
    try testing.expectEqualStrings("Invalid HTTP method (POST required)", list_unsub.UnsubscribeResult.invalid_method.toString());
    try testing.expectEqualStrings("Already unsubscribed", list_unsub.UnsubscribeResult.already_unsubscribed.toString());
}

// =============================================================================
// HttpMethod Parsing
// =============================================================================

test "RFC 8058: HttpMethod fromString" {
    try testing.expect(list_unsub.HttpMethod.fromString("GET") == .GET);
    try testing.expect(list_unsub.HttpMethod.fromString("POST") == .POST);
    try testing.expect(list_unsub.HttpMethod.fromString("post") == .POST);
    try testing.expect(list_unsub.HttpMethod.fromString("HEAD") == .HEAD);
    try testing.expect(list_unsub.HttpMethod.fromString("PUT") == .PUT);
    try testing.expect(list_unsub.HttpMethod.fromString("DELETE") == .DELETE);
    try testing.expect(list_unsub.HttpMethod.fromString("PATCH") == .PATCH);
    try testing.expect(list_unsub.HttpMethod.fromString("OPTIONS") == .OPTIONS);
    try testing.expect(list_unsub.HttpMethod.fromString("UNKNOWN") == .OTHER);
}

// =============================================================================
// URL Formatting
// =============================================================================

test "RFC 8058: formatUnsubscribeUrl with no existing query" {
    const url = try list_unsub.formatUnsubscribeUrl(testing.allocator, "https://mail.example.com/unsub", "TOKEN123");
    defer testing.allocator.free(url);

    try testing.expectEqualStrings("https://mail.example.com/unsub?token=TOKEN123", url);
}

test "RFC 8058: formatUnsubscribeUrl with existing query" {
    const url = try list_unsub.formatUnsubscribeUrl(testing.allocator, "https://mail.example.com/unsub?list=news", "TOKEN456");
    defer testing.allocator.free(url);

    try testing.expectEqualStrings("https://mail.example.com/unsub?list=news&token=TOKEN456", url);
}
