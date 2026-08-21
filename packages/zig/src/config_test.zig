const std = @import("std");
const testing = std.testing;
const config = @import("core/config.zig");

test "configuration can be created with different values" {
    // Test that we can create configs with defaults
    const cfg = config.Config{
        .host = "0.0.0.0",
        .port = 2525,
        .max_connections = 100,
        .enable_tls = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .enable_auth = true,
        .max_message_size = 10 * 1024 * 1024,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .command_timeout_seconds = 300,
        .greeting_timeout_seconds = 30,
        .rate_limit_per_ip = 100,
        .rate_limit_per_user = 200,
        .rate_limit_cleanup_interval = 3600,
        .max_recipients = 100,
        .hostname = "localhost",
        .webhook_url = null,
        .webhook_enabled = false,
        .enable_dnsbl = false,
        .enable_greylist = false,
        .enable_tracing = false,
        .tracing_service_name = "mail",
        .enable_json_logging = false,
    };

    // Test that defaults are reasonable
    try testing.expect(cfg.port > 0);
    try testing.expect(cfg.max_connections > 0);
    try testing.expect(cfg.max_message_size > 0);
    try testing.expect(cfg.max_recipients > 0);
    try testing.expect(cfg.rate_limit_per_ip > 0);
    try testing.expect(cfg.timeout_seconds > 0);
}

test "port number types" {
    // Test that we can create configs with different port numbers
    const cfg = config.Config{
        .host = "127.0.0.1",
        .port = 25,
        .max_connections = 100,
        .enable_tls = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .enable_auth = true,
        .max_message_size = 10 * 1024 * 1024,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .command_timeout_seconds = 300,
        .greeting_timeout_seconds = 30,
        .rate_limit_per_ip = 100,
        .rate_limit_per_user = 200,
        .rate_limit_cleanup_interval = 3600,
        .max_recipients = 100,
        .hostname = "localhost",
        .webhook_url = null,
        .webhook_enabled = false,
        .enable_dnsbl = false,
        .enable_greylist = false,
        .enable_tracing = false,
        .tracing_service_name = "mail",
        .enable_json_logging = false,
    };

    // Standard SMTP ports
    try testing.expectEqual(@as(u16, 25), cfg.port);

    const cfg2 = config.Config{
        .host = "127.0.0.1",
        .port = 587,
        .max_connections = 100,
        .enable_tls = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .enable_auth = true,
        .max_message_size = 10 * 1024 * 1024,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .command_timeout_seconds = 300,
        .greeting_timeout_seconds = 30,
        .rate_limit_per_ip = 100,
        .rate_limit_per_user = 200,
        .rate_limit_cleanup_interval = 3600,
        .max_recipients = 100,
        .hostname = "localhost",
        .webhook_url = null,
        .webhook_enabled = false,
        .enable_dnsbl = false,
        .enable_greylist = false,
        .enable_tracing = false,
        .tracing_service_name = "mail",
        .enable_json_logging = false,
    };

    try testing.expectEqual(@as(u16, 587), cfg2.port);
}

test "configuration struct fields exist" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const cfg = config.Config{
        .host = "0.0.0.0",
        .port = 2525,
        .max_connections = 100,
        .enable_tls = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .enable_auth = true,
        .max_message_size = 10 * 1024 * 1024,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .command_timeout_seconds = 300,
        .greeting_timeout_seconds = 30,
        .rate_limit_per_ip = 100,
        .rate_limit_per_user = 200,
        .rate_limit_cleanup_interval = 3600,
        .max_recipients = 100,
        .hostname = "localhost",
        .webhook_url = null,
        .webhook_enabled = false,
        .enable_dnsbl = false,
        .enable_greylist = false,
        .enable_tracing = false,
        .tracing_service_name = "mail",
        .enable_json_logging = false,
    };
    _ = allocator;

    // Verify limits are non-zero and reasonable
    try testing.expect(cfg.max_connections > 0);
    try testing.expect(cfg.max_message_size > 0);
    try testing.expect(cfg.max_recipients > 0);
    try testing.expect(cfg.rate_limit_per_ip > 0);
    try testing.expect(cfg.timeout_seconds > 0);

    // Verify reasonable upper bounds
    try testing.expect(cfg.max_connections <= 10000);
    try testing.expect(cfg.max_message_size <= 100 * 1024 * 1024); // 100MB max
    try testing.expect(cfg.max_recipients <= 1000);
    try testing.expect(cfg.timeout_seconds <= 3600);
}

test "TLS configuration flags" {
    const cfg_tls_on = config.Config{
        .host = "0.0.0.0",
        .port = 2525,
        .max_connections = 100,
        .enable_tls = true,
        .tls_cert_path = null,
        .tls_key_path = null,
        .enable_auth = true,
        .max_message_size = 10 * 1024 * 1024,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .command_timeout_seconds = 300,
        .greeting_timeout_seconds = 30,
        .rate_limit_per_ip = 100,
        .rate_limit_per_user = 200,
        .rate_limit_cleanup_interval = 3600,
        .max_recipients = 100,
        .hostname = "localhost",
        .webhook_url = null,
        .webhook_enabled = false,
        .enable_dnsbl = false,
        .enable_greylist = false,
        .enable_tracing = false,
        .tracing_service_name = "mail",
        .enable_json_logging = false,
    };

    try testing.expectEqual(true, cfg_tls_on.enable_tls);

    const cfg_tls_off = config.Config{
        .host = "0.0.0.0",
        .port = 2525,
        .max_connections = 100,
        .enable_tls = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .enable_auth = true,
        .max_message_size = 10 * 1024 * 1024,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .command_timeout_seconds = 300,
        .greeting_timeout_seconds = 30,
        .rate_limit_per_ip = 100,
        .rate_limit_per_user = 200,
        .rate_limit_cleanup_interval = 3600,
        .max_recipients = 100,
        .hostname = "localhost",
        .webhook_url = null,
        .webhook_enabled = false,
        .enable_dnsbl = false,
        .enable_greylist = false,
        .enable_tracing = false,
        .tracing_service_name = "mail",
        .enable_json_logging = false,
    };

    try testing.expectEqual(false, cfg_tls_off.enable_tls);
}

test "authentication configuration flags" {
    const cfg_auth_on = config.Config{
        .host = "0.0.0.0",
        .port = 2525,
        .max_connections = 100,
        .enable_tls = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .enable_auth = true,
        .max_message_size = 10 * 1024 * 1024,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .command_timeout_seconds = 300,
        .greeting_timeout_seconds = 30,
        .rate_limit_per_ip = 100,
        .rate_limit_per_user = 200,
        .rate_limit_cleanup_interval = 3600,
        .max_recipients = 100,
        .hostname = "localhost",
        .webhook_url = null,
        .webhook_enabled = false,
        .enable_dnsbl = false,
        .enable_greylist = false,
        .enable_tracing = false,
        .tracing_service_name = "mail",
        .enable_json_logging = false,
    };

    try testing.expectEqual(true, cfg_auth_on.enable_auth);

    const cfg_auth_off = config.Config{
        .host = "0.0.0.0",
        .port = 2525,
        .max_connections = 100,
        .enable_tls = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .enable_auth = false,
        .max_message_size = 10 * 1024 * 1024,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .command_timeout_seconds = 300,
        .greeting_timeout_seconds = 30,
        .rate_limit_per_ip = 100,
        .rate_limit_per_user = 200,
        .rate_limit_cleanup_interval = 3600,
        .max_recipients = 100,
        .hostname = "localhost",
        .webhook_url = null,
        .webhook_enabled = false,
        .enable_dnsbl = false,
        .enable_greylist = false,
        .enable_tracing = false,
        .tracing_service_name = "mail",
        .enable_json_logging = false,
    };

    try testing.expectEqual(false, cfg_auth_off.enable_auth);
}

/// A config with everything required filled in, so a test can vary one field.
fn trapConfig(host: []const u8, catch_all: bool) config.Config {
    return config.Config{
        .host = host,
        .port = 1025,
        .max_connections = 100,
        .enable_tls = false,
        .tls_cert_path = null,
        .tls_key_path = null,
        .enable_auth = false,
        .max_message_size = 10 * 1024 * 1024,
        .timeout_seconds = 300,
        .data_timeout_seconds = 600,
        .command_timeout_seconds = 300,
        .greeting_timeout_seconds = 30,
        .rate_limit_per_ip = 100,
        .rate_limit_per_user = 200,
        .rate_limit_cleanup_interval = 3600,
        .max_recipients = 100,
        .hostname = "localhost",
        .webhook_url = null,
        .webhook_enabled = false,
        .enable_dnsbl = false,
        .enable_greylist = false,
        .enable_tracing = false,
        .tracing_service_name = "mail",
        .enable_json_logging = false,
        .catch_all = catch_all,
    };
}

test "catch_all makes every domain local, which is what a trap is" {
    // Without it, an application sending to whatever addresses its fixtures
    // contain is answered "550 relay access denied" for all of them - a trap
    // that catches nothing.
    const trap = trapConfig("127.0.0.1", true);

    try testing.expect(trap.isLocalDomain("anywhere.example"));
    try testing.expect(trap.isLocalDomain("totally-unrelated.test"));
    try testing.expect(trap.isLocalDomain("localhost"));
}

test "and an empty domain is still not local, trap or not" {
    // A recipient with no domain must never pass the local check: it is the
    // shape that bypasses it, not a local address.
    const trap = trapConfig("127.0.0.1", true);
    const normal = trapConfig("127.0.0.1", false);

    try testing.expect(!trap.isLocalDomain(""));
    try testing.expect(!normal.isLocalDomain(""));
}

test "without catch_all only the hostname and its parent are local" {
    const normal = trapConfig("127.0.0.1", false);

    try testing.expect(normal.isLocalDomain("localhost"));
    try testing.expect(!normal.isLocalDomain("anywhere.example"));
}

test "a trap refuses to start on a public interface" {
    // It accepts mail for every domain and files it locally, so one reachable
    // from the internet receives and stores the world's mail for anybody's
    // domain. Refused at startup, because it is invisible from the outside.
    try testing.expectError(
        config.ValidationError.CatchAllNotLoopback,
        trapConfig("0.0.0.0", true).validate(),
    );
    try testing.expectError(
        config.ValidationError.CatchAllNotLoopback,
        trapConfig("192.168.1.10", true).validate(),
    );
}

test "and starts on every loopback spelling" {
    try trapConfig("127.0.0.1", true).validate();
    try trapConfig("::1", true).validate();
    try trapConfig("localhost", true).validate();
    try trapConfig("127.0.0.53", true).validate();
}

test "a public bind is fine when it is not a trap" {
    try trapConfig("0.0.0.0", false).validate();
}
