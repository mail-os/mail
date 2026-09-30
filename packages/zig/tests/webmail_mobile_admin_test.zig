const std = @import("std");
const testing = std.testing;

// Import webmail and mobile admin modules
const webmail = @import("../src/api/webmail.zig");
const mobile_admin = @import("../src/api/mobile_admin.zig");

// =============================================================================
// Webmail Integration Tests
// =============================================================================

test "WebmailHandler initialization" {
    const allocator = testing.allocator;
    const config = webmail.WebmailConfig{};
    var handler = webmail.WebmailHandler.init(allocator, config);
    defer handler.deinit();

    try testing.expect(config.max_attachment_size == 25 * 1024 * 1024);
    try testing.expect(config.messages_per_page == 50);
    try testing.expect(config.session_timeout_seconds == 3600);
}

test "WebmailConfig default values" {
    const config = webmail.WebmailConfig{};

    try testing.expectEqual(@as(usize, 25 * 1024 * 1024), config.max_attachment_size);
    try testing.expectEqual(@as(u32, 50), config.messages_per_page);
    try testing.expectEqual(@as(u32, 3600), config.session_timeout_seconds);
    try testing.expect(config.enable_rich_text);
    try testing.expect(config.enable_drafts);
    try testing.expect(config.enable_contacts);
}

test "WebmailFolder types" {
    // Test all folder types are defined
    const inbox = webmail.FolderType.inbox;
    const sent = webmail.FolderType.sent;
    const drafts = webmail.FolderType.drafts;
    const trash = webmail.FolderType.trash;
    const spam = webmail.FolderType.spam;
    const archive = webmail.FolderType.archive;

    try testing.expectEqualStrings("inbox", inbox.toString());
    try testing.expectEqualStrings("sent", sent.toString());
    try testing.expectEqualStrings("drafts", drafts.toString());
    try testing.expectEqualStrings("trash", trash.toString());
    try testing.expectEqualStrings("spam", spam.toString());
    try testing.expectEqualStrings("archive", archive.toString());
}

test "WebmailFolder icons" {
    const inbox = webmail.FolderType.inbox;
    const sent = webmail.FolderType.sent;
    const drafts = webmail.FolderType.drafts;
    const trash = webmail.FolderType.trash;
    const spam = webmail.FolderType.spam;
    const archive = webmail.FolderType.archive;

    try testing.expectEqualStrings("inbox", inbox.icon());
    try testing.expectEqualStrings("send", sent.icon());
    try testing.expectEqualStrings("file-text", drafts.icon());
    try testing.expectEqualStrings("trash-2", trash.icon());
    try testing.expectEqualStrings("alert-octagon", spam.icon());
    try testing.expectEqualStrings("archive", archive.icon());
}

test "WebmailHandler request routing - main page" {
    const allocator = testing.allocator;
    var handler = webmail.WebmailHandler.init(allocator, .{});
    defer handler.deinit();

    // Test GET /webmail returns HTML
    const response = try handler.handleRequest("/webmail", "GET", null);
    defer allocator.free(response);

    try testing.expect(response.len > 0);
    try testing.expect(std.mem.indexOf(u8, response, "HTTP/1.1 200 OK") != null);
    try testing.expect(std.mem.indexOf(u8, response, "text/html") != null);
}

test "WebmailHandler request routing - folders API" {
    const allocator = testing.allocator;
    var handler = webmail.WebmailHandler.init(allocator, .{});
    defer handler.deinit();

    // Test GET /webmail/api/folders returns JSON
    const response = try handler.handleRequest("/webmail/api/folders", "GET", null);
    defer allocator.free(response);

    try testing.expect(response.len > 0);
    try testing.expect(std.mem.indexOf(u8, response, "folders") != null);
}

test "WebmailHandler request routing - messages API" {
    const allocator = testing.allocator;
    var handler = webmail.WebmailHandler.init(allocator, .{});
    defer handler.deinit();

    // Test GET /webmail/api/messages returns JSON
    const response = try handler.handleRequest("/webmail/api/messages", "GET", null);
    defer allocator.free(response);

    try testing.expect(response.len > 0);
    try testing.expect(std.mem.indexOf(u8, response, "messages") != null);
}

test "WebmailHandler request routing - user API" {
    const allocator = testing.allocator;
    var handler = webmail.WebmailHandler.init(allocator, .{});
    defer handler.deinit();

    // Test GET /webmail/api/user returns JSON
    const response = try handler.handleRequest("/webmail/api/user", "GET", null);
    defer allocator.free(response);

    try testing.expect(response.len > 0);
    try testing.expect(std.mem.indexOf(u8, response, "user") != null);
}

test "WebmailHandler request routing - 404 handling" {
    const allocator = testing.allocator;
    var handler = webmail.WebmailHandler.init(allocator, .{});
    defer handler.deinit();

    // Test unknown path returns 404
    const response = try handler.handleRequest("/webmail/nonexistent", "GET", null);
    defer allocator.free(response);

    try testing.expect(std.mem.indexOf(u8, response, "404") != null);
}

test "Webmail HTML contains essential elements" {
    const allocator = testing.allocator;
    var handler = webmail.WebmailHandler.init(allocator, .{});
    defer handler.deinit();

    const response = try handler.handleRequest("/webmail", "GET", null);
    defer allocator.free(response);

    // Check for essential HTML elements
    try testing.expect(std.mem.indexOf(u8, response, "<!DOCTYPE html>") != null);
    try testing.expect(std.mem.indexOf(u8, response, "<html") != null);
    try testing.expect(std.mem.indexOf(u8, response, "Webmail") != null);
    try testing.expect(std.mem.indexOf(u8, response, "Compose") != null);
    try testing.expect(std.mem.indexOf(u8, response, "Inbox") != null);
}

// =============================================================================
// Mobile Admin Integration Tests
// =============================================================================

test "MobileAdminConfig default values" {
    const config = mobile_admin.MobileAdminConfig{};

    try testing.expect(config.enable_push_notifications);
    try testing.expectEqual(@as(u32, 1800), config.session_timeout_seconds);
    try testing.expect(config.enable_biometric_auth);
    try testing.expectEqual(@as(u32, 30), config.refresh_interval);
    try testing.expectEqual(@as(usize, 50), config.max_recent_alerts);
    try testing.expect(config.enable_offline_mode);
}

test "MobileAdminHandler initialization" {
    const allocator = testing.allocator;
    const handler = mobile_admin.MobileAdminHandler.init(allocator, .{});

    try testing.expect(handler.config.enable_push_notifications);
    try testing.expectEqual(@as(u32, 1800), handler.config.session_timeout_seconds);
}

test "ServerStatus enum values" {
    // Test status toString
    try testing.expectEqualStrings("Healthy", mobile_admin.ServerStatus.Status.healthy.toString());
    try testing.expectEqualStrings("Degraded", mobile_admin.ServerStatus.Status.degraded.toString());
    try testing.expectEqualStrings("Critical", mobile_admin.ServerStatus.Status.critical.toString());
    try testing.expectEqualStrings("Offline", mobile_admin.ServerStatus.Status.offline.toString());

    // Test status colors
    try testing.expectEqualStrings("#10b981", mobile_admin.ServerStatus.Status.healthy.color());
    try testing.expectEqualStrings("#f59e0b", mobile_admin.ServerStatus.Status.degraded.color());
    try testing.expectEqualStrings("#ef4444", mobile_admin.ServerStatus.Status.critical.color());
    try testing.expectEqualStrings("#6b7280", mobile_admin.ServerStatus.Status.offline.color());
}

test "AdminAlert severity values" {
    // Test severity icons
    try testing.expectEqualStrings("info", mobile_admin.AdminAlert.Severity.info.icon());
    try testing.expectEqualStrings("alert-triangle", mobile_admin.AdminAlert.Severity.warning.icon());
    try testing.expectEqualStrings("alert-circle", mobile_admin.AdminAlert.Severity.critical.icon());

    // Test severity colors
    try testing.expectEqualStrings("#3b82f6", mobile_admin.AdminAlert.Severity.info.color());
    try testing.expectEqualStrings("#f59e0b", mobile_admin.AdminAlert.Severity.warning.color());
    try testing.expectEqualStrings("#ef4444", mobile_admin.AdminAlert.Severity.critical.color());
}

test "MobileAdminHandler request routing - main app" {
    const allocator = testing.allocator;
    var handler = mobile_admin.MobileAdminHandler.init(allocator, .{});

    // Test GET /admin/mobile returns HTML
    const response = try handler.handleRequest("/admin/mobile", "GET", null);
    defer allocator.free(response);

    try testing.expect(response.len > 0);
    try testing.expect(std.mem.indexOf(u8, response, "HTTP/1.1 200 OK") != null);
    try testing.expect(std.mem.indexOf(u8, response, "text/html") != null);
}

test "MobileAdminHandler request routing - PWA manifest" {
    const allocator = testing.allocator;
    var handler = mobile_admin.MobileAdminHandler.init(allocator, .{});

    // Test GET /admin/mobile/manifest.json returns manifest
    const response = try handler.handleRequest("/admin/mobile/manifest.json", "GET", null);
    defer allocator.free(response);

    try testing.expect(response.len > 0);
    try testing.expect(std.mem.indexOf(u8, response, "application/manifest+json") != null);
    try testing.expect(std.mem.indexOf(u8, response, "SMTP Admin") != null);
}

test "MobileAdminHandler request routing - service worker" {
    const allocator = testing.allocator;
    var handler = mobile_admin.MobileAdminHandler.init(allocator, .{});

    // Test GET /admin/mobile/sw.js returns JavaScript
    const response = try handler.handleRequest("/admin/mobile/sw.js", "GET", null);
    defer allocator.free(response);

    try testing.expect(response.len > 0);
    try testing.expect(std.mem.indexOf(u8, response, "application/javascript") != null);
    try testing.expect(std.mem.indexOf(u8, response, "CACHE_NAME") != null);
}

test "MobileAdminHandler request routing - status API" {
    const allocator = testing.allocator;
    var handler = mobile_admin.MobileAdminHandler.init(allocator, .{});

    // Test GET /admin/mobile/api/status returns JSON
    const response = try handler.handleRequest("/admin/mobile/api/status", "GET", null);
    defer allocator.free(response);

    try testing.expect(response.len > 0);
    try testing.expect(std.mem.indexOf(u8, response, "status") != null);
    try testing.expect(std.mem.indexOf(u8, response, "healthy") != null);
}

test "MobileAdminHandler request routing - alerts API" {
    const allocator = testing.allocator;
    var handler = mobile_admin.MobileAdminHandler.init(allocator, .{});

    // Test GET /admin/mobile/api/alerts returns JSON
    const response = try handler.handleRequest("/admin/mobile/api/alerts", "GET", null);
    defer allocator.free(response);

    try testing.expect(response.len > 0);
    try testing.expect(std.mem.indexOf(u8, response, "alerts") != null);
}

test "MobileAdminHandler request routing - users API" {
    const allocator = testing.allocator;
    var handler = mobile_admin.MobileAdminHandler.init(allocator, .{});

    // Test GET /admin/mobile/api/users returns JSON
    const response = try handler.handleRequest("/admin/mobile/api/users", "GET", null);
    defer allocator.free(response);

    try testing.expect(response.len > 0);
    try testing.expect(std.mem.indexOf(u8, response, "users") != null);
}

test "MobileAdminHandler request routing - queue API" {
    const allocator = testing.allocator;
    var handler = mobile_admin.MobileAdminHandler.init(allocator, .{});

    // Test GET /admin/mobile/api/queue returns JSON
    const response = try handler.handleRequest("/admin/mobile/api/queue", "GET", null);
    defer allocator.free(response);

    try testing.expect(response.len > 0);
    try testing.expect(std.mem.indexOf(u8, response, "queue") != null);
}

test "MobileAdminHandler request routing - stats API" {
    const allocator = testing.allocator;
    var handler = mobile_admin.MobileAdminHandler.init(allocator, .{});

    // Test GET /admin/mobile/api/stats returns JSON
    const response = try handler.handleRequest("/admin/mobile/api/stats", "GET", null);
    defer allocator.free(response);

    try testing.expect(response.len > 0);
    try testing.expect(std.mem.indexOf(u8, response, "messages_24h") != null);
}

test "MobileAdminHandler POST actions" {
    const allocator = testing.allocator;
    var handler = mobile_admin.MobileAdminHandler.init(allocator, .{});

    // Test POST /admin/mobile/api/action
    const response = try handler.handleRequest("/admin/mobile/api/action", "POST", null);
    defer allocator.free(response);

    try testing.expect(response.len > 0);
    try testing.expect(std.mem.indexOf(u8, response, "success") != null);
}

test "MobileAdminHandler POST acknowledge" {
    const allocator = testing.allocator;
    var handler = mobile_admin.MobileAdminHandler.init(allocator, .{});

    // Test POST /admin/mobile/api/acknowledge
    const response = try handler.handleRequest("/admin/mobile/api/acknowledge", "POST", null);
    defer allocator.free(response);

    try testing.expect(response.len > 0);
    try testing.expect(std.mem.indexOf(u8, response, "success") != null);
}

test "MobileAdminHandler 404 handling" {
    const allocator = testing.allocator;
    var handler = mobile_admin.MobileAdminHandler.init(allocator, .{});

    // Test unknown path returns 404
    const response = try handler.handleRequest("/admin/mobile/nonexistent", "GET", null);
    defer allocator.free(response);

    try testing.expect(std.mem.indexOf(u8, response, "404") != null);
}

test "Mobile Admin HTML contains PWA elements" {
    const allocator = testing.allocator;
    var handler = mobile_admin.MobileAdminHandler.init(allocator, .{});

    const response = try handler.handleRequest("/admin/mobile", "GET", null);
    defer allocator.free(response);

    // Check for PWA essentials
    try testing.expect(std.mem.indexOf(u8, response, "<!DOCTYPE html>") != null);
    try testing.expect(std.mem.indexOf(u8, response, "viewport") != null);
    try testing.expect(std.mem.indexOf(u8, response, "manifest") != null);
    try testing.expect(std.mem.indexOf(u8, response, "serviceWorker") != null);
    try testing.expect(std.mem.indexOf(u8, response, "SMTP Admin") != null);
}

test "Mobile Admin HTML contains touch-optimized elements" {
    const allocator = testing.allocator;
    var handler = mobile_admin.MobileAdminHandler.init(allocator, .{});

    const response = try handler.handleRequest("/admin/mobile", "GET", null);
    defer allocator.free(response);

    // Check for mobile-specific features
    try testing.expect(std.mem.indexOf(u8, response, "safe-area") != null);
    try testing.expect(std.mem.indexOf(u8, response, "bottom-nav") != null);
    try testing.expect(std.mem.indexOf(u8, response, "pull-indicator") != null);
}

// =============================================================================
// Cross-Feature Integration Tests
// =============================================================================

test "Webmail and Mobile Admin use consistent theming" {
    const allocator = testing.allocator;

    var webmail_handler = webmail.WebmailHandler.init(allocator, .{});
    defer webmail_handler.deinit();

    var mobile_handler = mobile_admin.MobileAdminHandler.init(allocator, .{});

    const webmail_response = try webmail_handler.handleRequest("/webmail", "GET", null);
    defer allocator.free(webmail_response);

    const mobile_response = try mobile_handler.handleRequest("/admin/mobile", "GET", null);
    defer allocator.free(mobile_response);

    // Both should have CSS variables for theming
    try testing.expect(std.mem.indexOf(u8, webmail_response, "--primary") != null);
    try testing.expect(std.mem.indexOf(u8, mobile_response, "--primary") != null);
}

test "ServerStatus struct initialization" {
    const status = mobile_admin.ServerStatus{
        .status = .healthy,
        .uptime_seconds = 86400,
        .version = "v0.30.0",
        .cpu_usage = 15.5,
        .memory_usage = 45.2,
        .disk_usage = 30.0,
        .active_connections = 100,
        .messages_today = 5000,
        .queue_size = 10,
    };

    try testing.expectEqual(mobile_admin.ServerStatus.Status.healthy, status.status);
    try testing.expectEqual(@as(u64, 86400), status.uptime_seconds);
    try testing.expectEqualStrings("v0.30.0", status.version);
    try testing.expectApproxEqAbs(@as(f32, 15.5), status.cpu_usage, 0.01);
}

test "QuickAction types" {
    const action = mobile_admin.QuickAction{
        .id = "flush_queue",
        .name = "Flush Queue",
        .icon = "refresh-cw",
        .action_type = .flush_queue,
        .requires_confirmation = true,
    };

    try testing.expectEqualStrings("flush_queue", action.id);
    try testing.expectEqualStrings("Flush Queue", action.name);
    try testing.expect(action.requires_confirmation);
}

test "UserSummary status enum" {
    const user = mobile_admin.UserSummary{
        .id = "user_1",
        .email = "test@example.com",
        .name = "Test User",
        .status = .active,
        .last_login = 1732700000,
        .storage_used = 1024 * 1024 * 100,
        .storage_quota = 1024 * 1024 * 1024,
    };

    try testing.expectEqual(mobile_admin.UserSummary.Status.active, user.status);
    try testing.expectEqualStrings("test@example.com", user.email);
}

test "QueueItem status enum" {
    const item = mobile_admin.QueueItem{
        .id = "queue_1",
        .from = "sender@example.com",
        .to = "recipient@example.com",
        .subject = "Test Subject",
        .size = 1024,
        .attempts = 2,
        .next_retry = 1732700000,
        .status = .deferred,
    };

    try testing.expectEqual(mobile_admin.QueueItem.Status.deferred, item.status);
    try testing.expectEqual(@as(u32, 2), item.attempts);
}
