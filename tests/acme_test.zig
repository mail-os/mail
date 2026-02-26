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
