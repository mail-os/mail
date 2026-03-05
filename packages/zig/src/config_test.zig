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
