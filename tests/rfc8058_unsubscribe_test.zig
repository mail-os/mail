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

// =============================================================================
// Edge Case Tests
// =============================================================================

test "RFC 8058 edge case: generate headers with empty list ID" {
    const config = list_unsub.ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "supersecretkey1234567890abcdef",
        .require_https = true,
    };

    const header = list_unsub.ListUnsubscribeHeader.init(config);

    // Empty list_id should still produce valid headers -- the token encodes ""
    const pair = try header.generateHeaders(
        testing.allocator,
        "", // empty list ID
        "user@example.com",
        "<msg@example.com>",
    );
    defer pair.deinit(testing.allocator);

    // The List-Unsubscribe header should contain a URL with a token
    try testing.expect(pair.list_unsubscribe.len > 0);
    try testing.expect(std.mem.indexOf(u8, pair.list_unsubscribe, "token=") != null);
    try testing.expectEqualStrings("List-Unsubscribe=One-Click", pair.list_unsubscribe_post);
}

test "RFC 8058 edge case: generate headers with very long list ID" {
    const config = list_unsub.ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "supersecretkey1234567890abcdef",
        .require_https = true,
    };

    const header = list_unsub.ListUnsubscribeHeader.init(config);

    // Create a long list ID (200 chars)
    const long_list_id = "a]" ** 100;

    const pair = try header.generateHeaders(
        testing.allocator,
        long_list_id,
        "user@example.com",
        "<msg@example.com>",
    );
    defer pair.deinit(testing.allocator);

    // Should still produce valid output
    try testing.expect(pair.list_unsubscribe.len > 0);
    try testing.expectEqualStrings("List-Unsubscribe=One-Click", pair.list_unsubscribe_post);
}

test "RFC 8058 edge case: generate headers with special characters in list ID" {
    const config = list_unsub.ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "supersecretkey1234567890abcdef",
        .require_https = true,
    };

    const header = list_unsub.ListUnsubscribeHeader.init(config);

    // List ID with special characters that might break URL encoding
    const pair = try header.generateHeaders(
        testing.allocator,
        "list/with spaces&special=chars<>",
        "user@example.com",
        "<msg@example.com>",
    );
    defer pair.deinit(testing.allocator);

    try testing.expect(pair.list_unsubscribe.len > 0);

    // The token is base64-encoded, so the special chars in the list_id are
    // encoded within the token, not directly in the URL. Verify the URL
    // still starts with the base.
    try testing.expect(std.mem.indexOf(u8, pair.list_unsubscribe, "https://mail.example.com/unsubscribe") != null);
}

test "RFC 8058 edge case: one-click POST body parsing with empty body" {
    const config = list_unsub.ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "supersecretkey1234567890abcdef",
    };
    var handler = list_unsub.OneClickHandler.init(testing.allocator, config);
    defer handler.deinit();

    // handleFullRequest with empty body should fail (missing One-Click payload)
    const result = handler.handleFullRequest(
        "sometoken",
        "POST",
        "application/x-www-form-urlencoded",
        "", // empty body
    );
    try testing.expect(!result.isSuccess());
    try testing.expect(result == .@"error");
}

test "RFC 8058 edge case: one-click POST body missing List-Unsubscribe=One-Click" {
    const config = list_unsub.ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "supersecretkey1234567890abcdef",
    };
    var handler = list_unsub.OneClickHandler.init(testing.allocator, config);
    defer handler.deinit();

    // POST body that does not contain the required One-Click field
    const result = handler.handleFullRequest(
        "sometoken",
        "POST",
        "application/x-www-form-urlencoded",
        "action=unsubscribe&email=user@example.com",
    );
    try testing.expect(!result.isSuccess());
    try testing.expect(result == .@"error");
}

test "RFC 8058 edge case: one-click POST body with extra parameters around One-Click" {
    const secret = "supersecretkey1234567890abcdef";
    const config = list_unsub.ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = secret,
    };

    // Generate a valid token first
    var gen = list_unsub.UnsubscribeTokenGenerator.init(testing.allocator, secret);
    defer gen.deinit();
    const token = gen.generateToken("testlist", "user@test.com", "<id@test.com>");
    const token_str = try token.serialize(testing.allocator);
    defer testing.allocator.free(token_str);

    var handler = list_unsub.OneClickHandler.init(testing.allocator, config);
    defer handler.deinit();

    // Body with extra params but also containing the required One-Click field
    const result = handler.handleFullRequest(
        token_str,
        "POST",
        "application/x-www-form-urlencoded",
        "extra=param&List-Unsubscribe=One-Click&another=value",
    );

    // Should succeed because body contains "List-Unsubscribe=One-Click"
    try testing.expect(result.isSuccess());
}

test "RFC 8058 edge case: URL generation with special characters in domain" {
    // Domain with subdomain and hyphens
    const url1 = try list_unsub.formatUnsubscribeUrl(
        testing.allocator,
        "https://sub-domain.my-mail-server.example.com/unsubscribe",
        "TOKEN123",
    );
    defer testing.allocator.free(url1);
    try testing.expectEqualStrings(
        "https://sub-domain.my-mail-server.example.com/unsubscribe?token=TOKEN123",
        url1,
    );

    // URL with port number
    const url2 = try list_unsub.formatUnsubscribeUrl(
        testing.allocator,
        "https://mail.example.com:8443/unsubscribe",
        "TOKEN456",
    );
    defer testing.allocator.free(url2);
    try testing.expectEqualStrings(
        "https://mail.example.com:8443/unsubscribe?token=TOKEN456",
        url2,
    );

    // URL with path segments
    const url3 = try list_unsub.formatUnsubscribeUrl(
        testing.allocator,
        "https://example.com/api/v2/mail/unsubscribe",
        "TOKEN789",
    );
    defer testing.allocator.free(url3);
    try testing.expectEqualStrings(
        "https://example.com/api/v2/mail/unsubscribe?token=TOKEN789",
        url3,
    );
}

test "RFC 8058 edge case: header generation with mailto and https URLs" {
    const config = list_unsub.ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "supersecretkey1234567890abcdef",
        .require_https = true,
        .include_mailto = true,
        .mailto_address = "unsubscribe@example.com",
    };

    const header = list_unsub.ListUnsubscribeHeader.init(config);

    const pair = try header.generateHeaders(
        testing.allocator,
        "newsletter",
        "user@example.com",
        "<msg001@example.com>",
    );
    defer pair.deinit(testing.allocator);

    // Should contain both https and mailto URLs
    try testing.expect(std.mem.indexOf(u8, pair.list_unsubscribe, "https://") != null);
    try testing.expect(std.mem.indexOf(u8, pair.list_unsubscribe, "mailto:unsubscribe@example.com") != null);
    // RFC 8058 requires the post header
    try testing.expectEqualStrings("List-Unsubscribe=One-Click", pair.list_unsubscribe_post);

    // Also test generateHeaderLines for full header output
    const lines = try header.generateHeaderLines(
        testing.allocator,
        "newsletter",
        "user@example.com",
        "<msg001@example.com>",
    );
    defer testing.allocator.free(lines);

    try testing.expect(std.mem.indexOf(u8, lines, "List-Unsubscribe:") != null);
    try testing.expect(std.mem.indexOf(u8, lines, "List-Unsubscribe-Post:") != null);
    try testing.expect(std.mem.indexOf(u8, lines, "mailto:") != null);
}

test "RFC 8058 edge case: validate unsubscribe request with invalid token string" {
    const config = list_unsub.ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "supersecretkey1234567890abcdef",
    };
    var handler = list_unsub.OneClickHandler.init(testing.allocator, config);
    defer handler.deinit();

    // Completely invalid token (not base64, garbage)
    const result1 = handler.handleUnsubscribeRequest("!@#$%^&*()_+=", "POST");
    try testing.expect(result1 == .invalid_token);

    // Empty token string
    const result2 = handler.handleUnsubscribeRequest("", "POST");
    try testing.expect(result2 == .invalid_token);

    // Valid base64 but wrong structure (too short)
    const result3 = handler.handleUnsubscribeRequest("AAAA", "POST");
    try testing.expect(result3 == .invalid_token);

    // Long but random base64 data
    const result4 = handler.handleUnsubscribeRequest("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "POST");
    try testing.expect(result4 == .invalid_token);
}

test "RFC 8058 edge case: multiple unsubscribe operations and deduplication" {
    const secret = "supersecretkey1234567890abcdef";
    const config = list_unsub.ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = secret,
    };

    var gen = list_unsub.UnsubscribeTokenGenerator.init(testing.allocator, secret);
    defer gen.deinit();

    const token = gen.generateToken("list1", "user@example.com", "<msg1@example.com>");
    const token_str = try token.serialize(testing.allocator);
    defer testing.allocator.free(token_str);

    var handler = list_unsub.OneClickHandler.init(testing.allocator, config);
    defer handler.deinit();

    // First unsubscribe should succeed
    const result1 = handler.handleUnsubscribeRequest(token_str, "POST");
    try testing.expect(result1 == .success);

    // Second unsubscribe with same token should be flagged as already unsubscribed
    const result2 = handler.handleUnsubscribeRequest(token_str, "POST");
    try testing.expect(result2 == .already_unsubscribed);

    // Third attempt also remains already_unsubscribed
    const result3 = handler.handleUnsubscribeRequest(token_str, "POST");
    try testing.expect(result3 == .already_unsubscribed);

    // A different token for a different message should still succeed
    const token2 = gen.generateToken("list1", "user@example.com", "<msg2@example.com>");
    const token_str2 = try token2.serialize(testing.allocator);
    defer testing.allocator.free(token_str2);

    const result4 = handler.handleUnsubscribeRequest(token_str2, "POST");
    try testing.expect(result4 == .success);
}

test "RFC 8058 edge case: config validation rejects TTL exceeding 365 days" {
    const config = list_unsub.ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "supersecretkey1234567890abcdef",
        .token_ttl_seconds = 366 * 24 * 60 * 60, // 366 days > 365 max
    };
    try testing.expectError(error.InvalidTtl, config.validate());

    // Negative TTL should also be rejected
    const config2 = list_unsub.ListUnsubscribeConfig{
        .url_base = "https://mail.example.com/unsubscribe",
        .hmac_secret = "supersecretkey1234567890abcdef",
        .token_ttl_seconds = -1,
    };
    try testing.expectError(error.InvalidTtl, config2.validate());
}

test "RFC 8058 edge case: token serialization roundtrip with empty fields" {
    const secret = "supersecretkey1234567890abcdef";
    var gen = list_unsub.UnsubscribeTokenGenerator.init(testing.allocator, secret);
    defer gen.deinit();

    const ts: i64 = 1700000000;

    // Token with all empty string fields
    const token_empty = gen.generateTokenWithTimestamp("", "", "", ts);

    const serialized = try token_empty.serialize(testing.allocator);
    defer testing.allocator.free(serialized);

    var deserialized = try list_unsub.UnsubscribeToken.deserialize(testing.allocator, serialized);
    defer deserialized.deinit(testing.allocator);

    try testing.expectEqualStrings("", deserialized.list_id);
    try testing.expectEqualStrings("", deserialized.recipient);
    try testing.expectEqualStrings("", deserialized.message_id);
    try testing.expectEqual(ts, deserialized.timestamp);
    try testing.expect(std.mem.eql(u8, &token_empty.hmac, &deserialized.hmac));
}
