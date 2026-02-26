// ACME (RFC 8555) Certificate Management Test Suite
// Tests for ACME configuration, order status, challenge types,
// certificate info, and certificate manager lifecycle.
// https://datatracker.ietf.org/doc/html/rfc8555

const std = @import("std");
const testing = std.testing;
const acme = @import("mail").acme;

// ============================================================================
// ACMEConfig tests
// ============================================================================

test "ACME config defaults" {
    const config = acme.ACMEConfig{};

    try testing.expectEqualStrings(acme.ACMEConfig.LETS_ENCRYPT_PRODUCTION, config.directory_url);
    try testing.expectEqualStrings("", config.email);
    try testing.expectEqual(@as(usize, 0), config.domains.len);
    try testing.expectEqual(acme.KeyType.ec256, config.key_type);
    try testing.expect(config.auto_renew);
    try testing.expectEqual(@as(u32, 30), config.renew_before_days);
    try testing.expectEqualStrings("/etc/ssl/acme", config.cert_dir);
    try testing.expectEqualStrings("/etc/ssl/acme/accounts", config.account_dir);
    try testing.expectEqual(acme.ChallengeType.http01, config.preferred_challenge);
    try testing.expectEqual(@as(u32, 300), config.order_timeout_seconds);
    try testing.expectEqual(@as(u32, 120), config.challenge_timeout_seconds);
    try testing.expectEqual(@as(u32, 43200), config.renewal_check_interval_seconds);
    try testing.expect(!config.agree_to_terms);
    try testing.expectEqual(@as(u16, 80), config.http_challenge_port);
    try testing.expect(!config.use_staging);
}

test "ACME config effectiveDirectoryUrl returns staging when configured" {
    const config = acme.ACMEConfig{
        .use_staging = true,
    };

    try testing.expectEqualStrings(acme.ACMEConfig.LETS_ENCRYPT_STAGING, config.effectiveDirectoryUrl());
}

test "ACME config effectiveDirectoryUrl returns production by default" {
    const config = acme.ACMEConfig{};

    try testing.expectEqualStrings(acme.ACMEConfig.LETS_ENCRYPT_PRODUCTION, config.effectiveDirectoryUrl());
}

test "ACME config validate rejects empty email" {
    const config = acme.ACMEConfig{
        .email = "",
        .domains = &.{"example.com"},
    };
    try testing.expectError(acme.ACMEError.InvalidContact, config.validate());
}

test "ACME config validate rejects email without @" {
    const config = acme.ACMEConfig{
        .email = "notanemail",
        .domains = &.{"example.com"},
    };
    try testing.expectError(acme.ACMEError.InvalidContact, config.validate());
}

test "ACME config validate rejects empty domains" {
    const config = acme.ACMEConfig{
        .email = "admin@example.com",
        .domains = &.{},
    };
    try testing.expectError(acme.ACMEError.UnsupportedIdentifier, config.validate());
}

test "ACME config validate rejects zero renew_before_days" {
    const config = acme.ACMEConfig{
        .email = "admin@example.com",
        .domains = &.{"example.com"},
        .renew_before_days = 0,
    };
    try testing.expectError(acme.ACMEError.Malformed, config.validate());
}

test "ACME config validate rejects wildcard without dns01" {
    const config = acme.ACMEConfig{
        .email = "admin@example.com",
        .domains = &.{"*.example.com"},
        .preferred_challenge = .http01,
    };
    try testing.expectError(acme.ACMEError.UnsupportedIdentifier, config.validate());
}

test "ACME config validate accepts wildcard with dns01" {
    const config = acme.ACMEConfig{
        .email = "admin@example.com",
        .domains = &.{"*.example.com"},
        .preferred_challenge = .dns01,
    };
    // Should not error
    try config.validate();
}

// ============================================================================
// ACMEOrderStatus tests
// ============================================================================

test "ACME order status toString" {
    try testing.expectEqualStrings("pending", acme.ACMEOrderStatus.pending.toString());
    try testing.expectEqualStrings("ready", acme.ACMEOrderStatus.ready.toString());
    try testing.expectEqualStrings("processing", acme.ACMEOrderStatus.processing.toString());
    try testing.expectEqualStrings("valid", acme.ACMEOrderStatus.valid.toString());
    try testing.expectEqualStrings("invalid", acme.ACMEOrderStatus.invalid.toString());
}

test "ACME order status fromString" {
    try testing.expectEqual(acme.ACMEOrderStatus.pending, acme.ACMEOrderStatus.fromString("pending").?);
    try testing.expectEqual(acme.ACMEOrderStatus.ready, acme.ACMEOrderStatus.fromString("ready").?);
    try testing.expectEqual(acme.ACMEOrderStatus.processing, acme.ACMEOrderStatus.fromString("processing").?);
    try testing.expectEqual(acme.ACMEOrderStatus.valid, acme.ACMEOrderStatus.fromString("valid").?);
    try testing.expectEqual(acme.ACMEOrderStatus.invalid, acme.ACMEOrderStatus.fromString("invalid").?);
    try testing.expect(acme.ACMEOrderStatus.fromString("unknown") == null);
}

test "ACME order status transitions - isTerminal" {
    try testing.expect(!acme.ACMEOrderStatus.pending.isTerminal());
    try testing.expect(!acme.ACMEOrderStatus.ready.isTerminal());
    try testing.expect(!acme.ACMEOrderStatus.processing.isTerminal());
    try testing.expect(acme.ACMEOrderStatus.valid.isTerminal());
    try testing.expect(acme.ACMEOrderStatus.invalid.isTerminal());
}

// ============================================================================
// ChallengeType tests
// ============================================================================

test "ACME challenge type toString" {
    try testing.expectEqualStrings("http-01", acme.ChallengeType.http01.toString());
    try testing.expectEqualStrings("dns-01", acme.ChallengeType.dns01.toString());
    try testing.expectEqualStrings("tls-alpn-01", acme.ChallengeType.tlsalpn01.toString());
}

test "ACME challenge type fromString" {
    try testing.expectEqual(acme.ChallengeType.http01, acme.ChallengeType.fromString("http-01").?);
    try testing.expectEqual(acme.ChallengeType.dns01, acme.ChallengeType.fromString("dns-01").?);
    try testing.expectEqual(acme.ChallengeType.tlsalpn01, acme.ChallengeType.fromString("tls-alpn-01").?);
    try testing.expect(acme.ChallengeType.fromString("unknown") == null);
}

// ============================================================================
// ChallengeStatus tests
// ============================================================================

test "ACME challenge status toString and fromString" {
    try testing.expectEqualStrings("pending", acme.ChallengeStatus.pending.toString());
    try testing.expectEqualStrings("processing", acme.ChallengeStatus.processing.toString());
    try testing.expectEqualStrings("valid", acme.ChallengeStatus.valid.toString());
    try testing.expectEqualStrings("invalid", acme.ChallengeStatus.invalid.toString());

    try testing.expectEqual(acme.ChallengeStatus.pending, acme.ChallengeStatus.fromString("pending").?);
    try testing.expectEqual(acme.ChallengeStatus.valid, acme.ChallengeStatus.fromString("valid").?);
    try testing.expect(acme.ChallengeStatus.fromString("unknown") == null);
}

// ============================================================================
// KeyType tests
// ============================================================================

test "ACME key type toString" {
    try testing.expectEqualStrings("EC-P256", acme.KeyType.ec256.toString());
    try testing.expectEqualStrings("EC-P384", acme.KeyType.ec384.toString());
    try testing.expectEqualStrings("RSA-2048", acme.KeyType.rsa2048.toString());
    try testing.expectEqualStrings("RSA-4096", acme.KeyType.rsa4096.toString());
}

test "ACME key type keyBits" {
    try testing.expectEqual(@as(u32, 256), acme.KeyType.ec256.keyBits());
    try testing.expectEqual(@as(u32, 384), acme.KeyType.ec384.keyBits());
    try testing.expectEqual(@as(u32, 2048), acme.KeyType.rsa2048.keyBits());
    try testing.expectEqual(@as(u32, 4096), acme.KeyType.rsa4096.keyBits());
}

// ============================================================================
// ACMEChallenge tests
// ============================================================================

test "ACME challenge init" {
    const challenge = acme.ACMEChallenge.init(
        .http01,
        "https://acme.example.com/challenge/123",
        "token-abc",
        .pending,
    );

    try testing.expectEqual(acme.ChallengeType.http01, challenge.challenge_type);
    try testing.expectEqualStrings("https://acme.example.com/challenge/123", challenge.url);
    try testing.expectEqualStrings("token-abc", challenge.token);
    try testing.expectEqual(acme.ChallengeStatus.pending, challenge.status);
    try testing.expect(challenge.key_authorization == null);
    try testing.expect(challenge.validated_at == null);
    try testing.expect(challenge.error_detail == null);
}

test "ACME challenge isFinished" {
    var pending = acme.ACMEChallenge.init(.http01, "url", "token", .pending);
    try testing.expect(!pending.isFinished());

    var processing = acme.ACMEChallenge.init(.http01, "url", "token", .processing);
    try testing.expect(!processing.isFinished());

    var valid = acme.ACMEChallenge.init(.http01, "url", "token", .valid);
    try testing.expect(valid.isFinished());

    var invalid_challenge = acme.ACMEChallenge.init(.http01, "url", "token", .invalid);
    try testing.expect(invalid_challenge.isFinished());
}

test "ACME challenge httpChallengePath" {
    const challenge = acme.ACMEChallenge.init(.http01, "url", "my-test-token", .pending);

    const path = try challenge.httpChallengePath(testing.allocator);
    defer testing.allocator.free(path);

    try testing.expectEqualStrings("/.well-known/acme-challenge/my-test-token", path);
}

test "ACME challenge dnsChallengeRecord" {
    const challenge = acme.ACMEChallenge.init(.dns01, "url", "token", .pending);

    const record = try challenge.dnsChallengeRecord(testing.allocator, "example.com");
    defer testing.allocator.free(record);

    try testing.expectEqualStrings("_acme-challenge.example.com", record);
}

// ============================================================================
// ACMEClient tests
// ============================================================================

test "ACME client init and deinit" {
    var client = acme.ACMEClient.init(testing.allocator, .{});
    defer client.deinit();

    try testing.expect(client.directory == null);
    try testing.expect(client.account == null);

    const stats = client.getStats();
    try testing.expectEqual(@as(u64, 0), stats.orders_created);
    try testing.expectEqual(@as(u64, 0), stats.certificates_issued);
}

test "ACME client fetchDirectory" {
    var client = acme.ACMEClient.init(testing.allocator, .{});
    defer client.deinit();

    try client.fetchDirectory();
    try testing.expect(client.directory != null);
}

test "ACME client createAccount requires directory" {
    var client = acme.ACMEClient.init(testing.allocator, .{});
    defer client.deinit();

    try testing.expectError(
        acme.ACMEError.DirectoryFetchFailed,
        client.createAccount("admin@example.com"),
    );
}

test "ACME client createAccount after fetchDirectory" {
    var client = acme.ACMEClient.init(testing.allocator, .{});
    defer client.deinit();

    try client.fetchDirectory();
    try client.createAccount("admin@example.com");

    try testing.expect(client.account != null);
}

test "ACME client requestCertificate requires account" {
    var client = acme.ACMEClient.init(testing.allocator, .{});
    defer client.deinit();

    try testing.expectError(
        acme.ACMEError.AccountDoesNotExist,
        client.requestCertificate("example.com"),
    );
}

test "ACME client full certificate workflow" {
    var client = acme.ACMEClient.init(testing.allocator, .{});
    defer client.deinit();

    // Step 1: Fetch directory
    try client.fetchDirectory();

    // Step 2: Create account
    try client.createAccount("admin@example.com");

    // Step 3: Request certificate
    const order_url = try client.requestCertificate("mail.example.com");
    defer testing.allocator.free(order_url);

    // Verify order was created
    const order = client.getOrder(order_url);
    try testing.expect(order != null);
    try testing.expectEqual(acme.ACMEOrderStatus.pending, order.?.status);

    // Step 4: Respond to challenge
    try client.respondToChallenge("mail.example.com");

    // Step 5: Get certificate
    const cert_pem = try client.getCertificate(order_url);
    defer testing.allocator.free(cert_pem);

    try testing.expect(std.mem.indexOf(u8, cert_pem, "BEGIN CERTIFICATE") != null);
    try testing.expect(std.mem.indexOf(u8, cert_pem, "END CERTIFICATE") != null);
    try testing.expect(std.mem.indexOf(u8, cert_pem, "mail.example.com") != null);

    // Verify stats
    const stats = client.getStats();
    try testing.expectEqual(@as(u64, 1), stats.orders_created);
    try testing.expectEqual(@as(u64, 1), stats.certificates_issued);
    try testing.expect(stats.http_requests > 0);
}

// ============================================================================
// CertificateInfo tests
// ============================================================================

test "ACME certificate info secondsUntilExpiry" {
    const now = @import("mail").time_compat.timestamp();

    var empty_sans = try testing.allocator.alloc([]const u8, 0);
    _ = &empty_sans;

    var info = acme.CertificateInfo{
        .domain = try testing.allocator.dupe(u8, "example.com"),
        .issuer = try testing.allocator.dupe(u8, "Test CA"),
        .not_before = now - 86400, // issued 1 day ago
        .not_after = now + (89 * 86400), // expires in 89 days
        .serial = try testing.allocator.dupe(u8, "serial"),
        .fingerprint = try testing.allocator.dupe(u8, "fingerprint"),
        .san_domains = empty_sans,
        .key_type = .ec256,
        .cert_path = try testing.allocator.dupe(u8, "/tmp/cert.pem"),
        .key_path = try testing.allocator.dupe(u8, "/tmp/key.pem"),
    };
    defer info.deinit(testing.allocator);

    try testing.expect(info.secondsUntilExpiry() > 0);
    try testing.expect(info.daysUntilExpiry() > 80);
    try testing.expect(info.isValid());
    try testing.expect(!info.isExpired());
}

test "ACME certificate info expired certificate" {
    const now = @import("mail").time_compat.timestamp();

    var empty_sans = try testing.allocator.alloc([]const u8, 0);
    _ = &empty_sans;

    var info = acme.CertificateInfo{
        .domain = try testing.allocator.dupe(u8, "example.com"),
        .issuer = try testing.allocator.dupe(u8, "Test CA"),
        .not_before = now - (100 * 86400), // issued 100 days ago
        .not_after = now - 86400, // expired 1 day ago
        .serial = try testing.allocator.dupe(u8, "serial"),
        .fingerprint = try testing.allocator.dupe(u8, "fingerprint"),
        .san_domains = empty_sans,
        .key_type = .ec256,
        .cert_path = try testing.allocator.dupe(u8, "/tmp/cert.pem"),
        .key_path = try testing.allocator.dupe(u8, "/tmp/key.pem"),
    };
    defer info.deinit(testing.allocator);

    try testing.expect(info.secondsUntilExpiry() < 0);
    try testing.expect(info.isExpired());
    try testing.expect(!info.isValid());
}

// ============================================================================
// CertificateManager tests
// ============================================================================

test "ACME certificate manager init and deinit" {
    var manager = acme.CertificateManager.init(testing.allocator, .{});
    defer manager.deinit();

    try testing.expect(!manager.isAutoRenewalRunning());
}

test "ACME certificate manager getCertPath" {
    var manager = acme.CertificateManager.init(testing.allocator, .{
        .cert_dir = "/etc/ssl/acme",
    });
    defer manager.deinit();

    const path = try manager.getCertPath("mail.example.com");
    defer testing.allocator.free(path);

    try testing.expectEqualStrings("/etc/ssl/acme/mail.example.com/cert.pem", path);
}

test "ACME certificate manager getKeyPath" {
    var manager = acme.CertificateManager.init(testing.allocator, .{
        .cert_dir = "/etc/ssl/acme",
    });
    defer manager.deinit();

    const path = try manager.getKeyPath("mail.example.com");
    defer testing.allocator.free(path);

    try testing.expectEqualStrings("/etc/ssl/acme/mail.example.com/privkey.pem", path);
}

test "ACME certificate manager getChainPath" {
    var manager = acme.CertificateManager.init(testing.allocator, .{
        .cert_dir = "/etc/ssl/certs",
    });
    defer manager.deinit();

    const path = try manager.getChainPath("mail.example.com");
    defer testing.allocator.free(path);

    try testing.expectEqualStrings("/etc/ssl/certs/mail.example.com/chain.pem", path);
}

test "ACME certificate manager getFullChainPath" {
    var manager = acme.CertificateManager.init(testing.allocator, .{
        .cert_dir = "/etc/ssl/certs",
    });
    defer manager.deinit();

    const path = try manager.getFullChainPath("mail.example.com");
    defer testing.allocator.free(path);

    try testing.expectEqualStrings("/etc/ssl/certs/mail.example.com/fullchain.pem", path);
}

test "ACME certificate manager isRenewalNeeded for unknown domain" {
    var manager = acme.CertificateManager.init(testing.allocator, .{});
    defer manager.deinit();

    // No certificate provisioned means renewal is needed
    try testing.expect(manager.isRenewalNeeded("unknown.com"));
}

test "ACME certificate manager getCertificateInfo for unknown domain" {
    var manager = acme.CertificateManager.init(testing.allocator, .{});
    defer manager.deinit();

    try testing.expect(manager.getCertificateInfo("unknown.com") == null);
}

// ============================================================================
// Edge Case Tests
// ============================================================================

test "ACME edge case: certificate request for empty domain name" {
    // An empty domain should still proceed through the stub client
    // (the validation is in ACMEConfig.validate, not in requestCertificate itself).
    var client = acme.ACMEClient.init(testing.allocator, .{});
    defer client.deinit();

    try client.fetchDirectory();
    try client.createAccount("admin@example.com");

    const order_url = try client.requestCertificate("");
    defer testing.allocator.free(order_url);

    // The order URL should still be created (contains empty domain segment)
    try testing.expect(order_url.len > 0);

    const order = client.getOrder(order_url);
    try testing.expect(order != null);
    try testing.expectEqual(acme.ACMEOrderStatus.pending, order.?.status);
    try testing.expectEqual(@as(usize, 1), order.?.identifiers.len);
    try testing.expectEqualStrings("", order.?.identifiers[0].value);
}

test "ACME edge case: config validate rejects domain with invalid length (>253 chars)" {
    // RFC 1035 limits domain names to 253 characters.
    const long_domain = "a" ** 254;
    const config = acme.ACMEConfig{
        .email = "admin@example.com",
        .domains = &.{long_domain},
    };
    try testing.expectError(acme.ACMEError.UnsupportedIdentifier, config.validate());
}

test "ACME edge case: config validate accepts domain at exactly 253 chars" {
    const max_domain = "a" ** 253;
    const config = acme.ACMEConfig{
        .email = "admin@example.com",
        .domains = &.{max_domain},
    };
    // Should not error
    try config.validate();
}

test "ACME edge case: config validate rejects empty domain in domains list" {
    const config = acme.ACMEConfig{
        .email = "admin@example.com",
        .domains = &.{""},
    };
    try testing.expectError(acme.ACMEError.UnsupportedIdentifier, config.validate());
}

test "ACME edge case: JWS header generation with empty nonce via client workflow" {
    // The JWSBuilder uses an empty nonce when none is set. Test the client
    // workflow where nonce management is implicit.
    var client = acme.ACMEClient.init(testing.allocator, .{});
    defer client.deinit();

    // fetchDirectory works without a nonce (first request bootstraps it)
    try client.fetchDirectory();
    try testing.expect(client.directory != null);

    // Verify directory URLs are properly constructed
    const dir = client.directory.?;
    try testing.expect(dir.new_nonce_url.len > 0);
    try testing.expect(dir.new_account_url.len > 0);
    try testing.expect(dir.new_order_url.len > 0);
}

test "ACME edge case: certificate manager init and immediate deinit (no operations)" {
    // Ensure no leaks or crashes when the manager is created and immediately destroyed
    // without performing any ACME operations.
    var manager = acme.CertificateManager.init(testing.allocator, .{
        .email = "admin@example.com",
        .domains = &.{ "example.com", "mail.example.com" },
        .cert_dir = "/tmp/test-certs",
        .account_dir = "/tmp/test-accounts",
    });
    defer manager.deinit();

    // Verify initial state
    try testing.expect(!manager.isAutoRenewalRunning());
    try testing.expect(manager.getCertificateInfo("example.com") == null);
    try testing.expect(manager.getCertificateInfo("mail.example.com") == null);
    // All domains should need renewal since no certs exist
    try testing.expect(manager.isRenewalNeeded("example.com"));
    try testing.expect(manager.isRenewalNeeded("mail.example.com"));
}

test "ACME edge case: request certificates for multiple distinct domains" {
    var client = acme.ACMEClient.init(testing.allocator, .{});
    defer client.deinit();

    try client.fetchDirectory();
    try client.createAccount("admin@example.com");

    // Request certificates for two different domains
    const order_url_1 = try client.requestCertificate("first.example.com");
    defer testing.allocator.free(order_url_1);

    const order_url_2 = try client.requestCertificate("second.example.com");
    defer testing.allocator.free(order_url_2);

    // Both should succeed, and stats should reflect two orders
    const stats = client.getStats();
    try testing.expectEqual(@as(u64, 2), stats.orders_created);

    // Both order URLs should be valid and different
    try testing.expect(order_url_1.len > 0);
    try testing.expect(order_url_2.len > 0);
    try testing.expect(!std.mem.eql(u8, order_url_1, order_url_2));

    // Both orders should exist
    const order1 = client.getOrder(order_url_1);
    try testing.expect(order1 != null);
    try testing.expectEqualStrings("first.example.com", order1.?.identifiers[0].value);

    const order2 = client.getOrder(order_url_2);
    try testing.expect(order2 != null);
    try testing.expectEqualStrings("second.example.com", order2.?.identifiers[0].value);

    // Both challenges should exist independently
    const challenge1 = client.getChallenge("first.example.com");
    try testing.expect(challenge1 != null);
    const challenge2 = client.getChallenge("second.example.com");
    try testing.expect(challenge2 != null);
}

test "ACME edge case: CSR generation with very long domain name via requestCertificate" {
    // Use a domain that is long but within the 253-char limit
    const long_domain = "a" ** 200 ++ ".example.com";

    var client = acme.ACMEClient.init(testing.allocator, .{});
    defer client.deinit();

    try client.fetchDirectory();
    try client.createAccount("admin@example.com");

    const order_url = try client.requestCertificate(long_domain);
    defer testing.allocator.free(order_url);

    // Verify the order was created with the long domain
    const order = client.getOrder(order_url);
    try testing.expect(order != null);
    try testing.expectEqualStrings(long_domain, order.?.identifiers[0].value);

    // Complete the workflow: respond to challenge and get certificate
    try client.respondToChallenge(long_domain);

    const cert_pem = try client.getCertificate(order_url);
    defer testing.allocator.free(cert_pem);

    // The certificate should reference the long domain
    try testing.expect(std.mem.indexOf(u8, cert_pem, long_domain) != null);
    try testing.expect(std.mem.indexOf(u8, cert_pem, "BEGIN CERTIFICATE") != null);
}

test "ACME edge case: directory URL validation - staging vs production" {
    // Test that effectiveDirectoryUrl properly returns staging URL
    const staging_config = acme.ACMEConfig{
        .use_staging = true,
        .directory_url = "https://custom-acme.example.com/directory",
    };
    // When use_staging is true, it should return the LE staging URL regardless of custom URL
    try testing.expectEqualStrings(acme.ACMEConfig.LETS_ENCRYPT_STAGING, staging_config.effectiveDirectoryUrl());

    // When use_staging is false, it returns the configured directory_url
    const custom_config = acme.ACMEConfig{
        .use_staging = false,
        .directory_url = "https://custom-acme.example.com/directory",
    };
    try testing.expectEqualStrings("https://custom-acme.example.com/directory", custom_config.effectiveDirectoryUrl());
}

test "ACME edge case: challenge token with special characters in HTTP path" {
    // Tokens may contain URL-safe characters; verify httpChallengePath handles them
    const challenge = acme.ACMEChallenge.init(
        .http01,
        "https://acme.example.com/challenge/test",
        "abc-DEF_123.~token",
        .pending,
    );

    const path = try challenge.httpChallengePath(testing.allocator);
    defer testing.allocator.free(path);

    try testing.expectEqualStrings("/.well-known/acme-challenge/abc-DEF_123.~token", path);
}

test "ACME edge case: challenge token with empty string" {
    const challenge = acme.ACMEChallenge.init(
        .http01,
        "https://acme.example.com/challenge/test",
        "",
        .pending,
    );

    const path = try challenge.httpChallengePath(testing.allocator);
    defer testing.allocator.free(path);

    try testing.expectEqualStrings("/.well-known/acme-challenge/", path);
}

test "ACME edge case: certificate renewal check with expired timestamp" {
    const now = @import("mail").time_compat.timestamp();

    var empty_sans = try testing.allocator.alloc([]const u8, 0);
    _ = &empty_sans;

    // Create a certificate that expired far in the past
    var info = acme.CertificateInfo{
        .domain = try testing.allocator.dupe(u8, "expired.example.com"),
        .issuer = try testing.allocator.dupe(u8, "Test CA"),
        .not_before = now - (365 * 86400), // issued 1 year ago
        .not_after = now - (275 * 86400), // expired ~275 days ago
        .serial = try testing.allocator.dupe(u8, "expired-serial"),
        .fingerprint = try testing.allocator.dupe(u8, "expired-fp"),
        .san_domains = empty_sans,
        .key_type = .ec256,
        .cert_path = try testing.allocator.dupe(u8, "/tmp/expired-cert.pem"),
        .key_path = try testing.allocator.dupe(u8, "/tmp/expired-key.pem"),
    };
    defer info.deinit(testing.allocator);

    try testing.expect(info.isExpired());
    try testing.expect(!info.isValid());
    // secondsUntilExpiry should be very negative
    try testing.expect(info.secondsUntilExpiry() < -200 * 86400);
    // daysUntilExpiry should be very negative
    try testing.expect(info.daysUntilExpiry() < -200);
}

test "ACME edge case: certificate not yet valid (not_before in future)" {
    const now = @import("mail").time_compat.timestamp();

    var empty_sans = try testing.allocator.alloc([]const u8, 0);
    _ = &empty_sans;

    var info = acme.CertificateInfo{
        .domain = try testing.allocator.dupe(u8, "future.example.com"),
        .issuer = try testing.allocator.dupe(u8, "Test CA"),
        .not_before = now + 86400, // starts valid tomorrow
        .not_after = now + (91 * 86400), // expires in 91 days
        .serial = try testing.allocator.dupe(u8, "future-serial"),
        .fingerprint = try testing.allocator.dupe(u8, "future-fp"),
        .san_domains = empty_sans,
        .key_type = .rsa4096,
        .cert_path = try testing.allocator.dupe(u8, "/tmp/future-cert.pem"),
        .key_path = try testing.allocator.dupe(u8, "/tmp/future-key.pem"),
    };
    defer info.deinit(testing.allocator);

    // Certificate is not yet valid because now < not_before
    try testing.expect(!info.isValid());
    // But it's also not expired because now < not_after
    try testing.expect(!info.isExpired());
    // secondsUntilExpiry should be positive (expires in the future)
    try testing.expect(info.secondsUntilExpiry() > 0);
}

test "ACME edge case: HTTP01 responder add and remove challenge" {
    var responder = acme.HTTP01Responder.init(testing.allocator);
    defer responder.deinit();

    try testing.expectEqual(@as(u32, 0), responder.activeCount());

    // Add a challenge with special characters in token
    try responder.addChallenge("token-with-special_chars.123", "keyauth-value.thumbprint");
    try testing.expectEqual(@as(u32, 1), responder.activeCount());

    // Verify lookup
    const response = responder.getResponse("token-with-special_chars.123");
    try testing.expect(response != null);
    try testing.expectEqualStrings("keyauth-value.thumbprint", response.?);

    // Verify non-existent token returns null
    try testing.expect(responder.getResponse("nonexistent") == null);

    // Remove the challenge
    responder.removeChallenge("token-with-special_chars.123");
    try testing.expectEqual(@as(u32, 0), responder.activeCount());

    // Double remove should be safe
    responder.removeChallenge("token-with-special_chars.123");
    try testing.expectEqual(@as(u32, 0), responder.activeCount());
}

test "ACME edge case: HTTP01 responder multiple challenges" {
    var responder = acme.HTTP01Responder.init(testing.allocator);
    defer responder.deinit();

    // Add multiple challenges
    try responder.addChallenge("token-a", "keyauth-a");
    try responder.addChallenge("token-b", "keyauth-b");
    try responder.addChallenge("token-c", "keyauth-c");
    try testing.expectEqual(@as(u32, 3), responder.activeCount());

    // Verify each one
    try testing.expectEqualStrings("keyauth-a", responder.getResponse("token-a").?);
    try testing.expectEqualStrings("keyauth-b", responder.getResponse("token-b").?);
    try testing.expectEqualStrings("keyauth-c", responder.getResponse("token-c").?);

    // Remove one in the middle
    responder.removeChallenge("token-b");
    try testing.expectEqual(@as(u32, 2), responder.activeCount());
    try testing.expect(responder.getResponse("token-b") == null);
    // Others still present
    try testing.expect(responder.getResponse("token-a") != null);
    try testing.expect(responder.getResponse("token-c") != null);
}

test "ACME edge case: order status fromString with unknown values" {
    // Verify that unknown/garbage strings return null
    try testing.expect(acme.ACMEOrderStatus.fromString("") == null);
    try testing.expect(acme.ACMEOrderStatus.fromString("PENDING") == null);
    try testing.expect(acme.ACMEOrderStatus.fromString("Valid") == null);
    try testing.expect(acme.ACMEOrderStatus.fromString("pending ") == null);
    try testing.expect(acme.ACMEOrderStatus.fromString(" pending") == null);
    try testing.expect(acme.ACMEOrderStatus.fromString("expired") == null);
    try testing.expect(acme.ACMEOrderStatus.fromString("cancelled") == null);
}

test "ACME edge case: challenge type fromString with unknown values" {
    try testing.expect(acme.ChallengeType.fromString("") == null);
    try testing.expect(acme.ChallengeType.fromString("HTTP-01") == null);
    try testing.expect(acme.ChallengeType.fromString("http01") == null);
    try testing.expect(acme.ChallengeType.fromString("dns-02") == null);
    try testing.expect(acme.ChallengeType.fromString("tls-alpn-02") == null);
}

test "ACME edge case: challenge status fromString with unknown values" {
    try testing.expect(acme.ChallengeStatus.fromString("") == null);
    try testing.expect(acme.ChallengeStatus.fromString("VALID") == null);
    try testing.expect(acme.ChallengeStatus.fromString("expired") == null);
    try testing.expect(acme.ChallengeStatus.fromString("complete") == null);
}

test "ACME edge case: respondToChallenge for non-existent domain" {
    var client = acme.ACMEClient.init(testing.allocator, .{});
    defer client.deinit();

    try client.fetchDirectory();
    try client.createAccount("admin@example.com");

    // Try responding to a challenge for a domain with no pending challenge
    try testing.expectError(
        acme.ACMEError.NoChallengeAvailable,
        client.respondToChallenge("no-challenge-for-this.com"),
    );
}

test "ACME edge case: getCertificate for non-existent order" {
    var client = acme.ACMEClient.init(testing.allocator, .{});
    defer client.deinit();

    try client.fetchDirectory();
    try client.createAccount("admin@example.com");

    // Try getting a certificate for an order URL that doesn't exist
    try testing.expectError(
        acme.ACMEError.OrderNotReady,
        client.getCertificate("https://acme.example.com/order/nonexistent"),
    );
}

test "ACME edge case: finalizeOrder for non-existent order" {
    var client = acme.ACMEClient.init(testing.allocator, .{});
    defer client.deinit();

    try client.fetchDirectory();
    try client.createAccount("admin@example.com");

    try testing.expectError(
        acme.ACMEError.OrderNotReady,
        client.finalizeOrder("https://acme.example.com/order/nonexistent"),
    );
}

test "ACME edge case: revokeCertificate requires directory" {
    var client = acme.ACMEClient.init(testing.allocator, .{});
    defer client.deinit();

    // Without fetching directory first, revocation should fail
    try testing.expectError(
        acme.ACMEError.DirectoryFetchFailed,
        client.revokeCertificate("-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"),
    );
}

test "ACME edge case: dns challenge record for subdomain" {
    const challenge = acme.ACMEChallenge.init(.dns01, "url", "token", .pending);

    const record = try challenge.dnsChallengeRecord(testing.allocator, "sub.deep.example.com");
    defer testing.allocator.free(record);

    try testing.expectEqualStrings("_acme-challenge.sub.deep.example.com", record);
}

test "ACME edge case: certificate manager getCertPath and getKeyPath for domain with dots" {
    var manager = acme.CertificateManager.init(testing.allocator, .{
        .cert_dir = "/etc/ssl/acme",
    });
    defer manager.deinit();

    const cert_path = try manager.getCertPath("mail.sub.example.com");
    defer testing.allocator.free(cert_path);
    try testing.expectEqualStrings("/etc/ssl/acme/mail.sub.example.com/cert.pem", cert_path);

    const key_path = try manager.getKeyPath("mail.sub.example.com");
    defer testing.allocator.free(key_path);
    try testing.expectEqualStrings("/etc/ssl/acme/mail.sub.example.com/privkey.pem", key_path);

    const chain_path = try manager.getChainPath("mail.sub.example.com");
    defer testing.allocator.free(chain_path);
    try testing.expectEqualStrings("/etc/ssl/acme/mail.sub.example.com/chain.pem", chain_path);

    const fullchain_path = try manager.getFullChainPath("mail.sub.example.com");
    defer testing.allocator.free(fullchain_path);
    try testing.expectEqualStrings("/etc/ssl/acme/mail.sub.example.com/fullchain.pem", fullchain_path);
}

test "ACME edge case: config validate rejects renew_before_days of zero" {
    const config = acme.ACMEConfig{
        .email = "admin@example.com",
        .domains = &.{"example.com"},
        .renew_before_days = 0,
    };
    try testing.expectError(acme.ACMEError.Malformed, config.validate());
}

test "ACME edge case: client stats tracking across multiple operations" {
    var client = acme.ACMEClient.init(testing.allocator, .{});
    defer client.deinit();

    // Initially all stats should be zero
    var stats = client.getStats();
    try testing.expectEqual(@as(u64, 0), stats.orders_created);
    try testing.expectEqual(@as(u64, 0), stats.certificates_issued);
    try testing.expectEqual(@as(u64, 0), stats.http_requests);

    try client.fetchDirectory();
    stats = client.getStats();
    try testing.expectEqual(@as(u64, 1), stats.http_requests);

    try client.createAccount("admin@test.com");
    stats = client.getStats();
    try testing.expectEqual(@as(u64, 2), stats.http_requests);

    const url1 = try client.requestCertificate("a.com");
    defer testing.allocator.free(url1);
    stats = client.getStats();
    try testing.expectEqual(@as(u64, 1), stats.orders_created);
    try testing.expectEqual(@as(u64, 3), stats.http_requests);

    try client.respondToChallenge("a.com");
    stats = client.getStats();
    try testing.expectEqual(@as(u64, 1), stats.challenges_completed);
    try testing.expectEqual(@as(u64, 4), stats.http_requests);

    const cert = try client.getCertificate(url1);
    defer testing.allocator.free(cert);
    stats = client.getStats();
    try testing.expectEqual(@as(u64, 1), stats.certificates_issued);
    try testing.expectEqual(@as(u64, 5), stats.http_requests);
}
