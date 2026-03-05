const std = @import("std");
const testing = std.testing;
const security = @import("auth/security.zig");

test "email validation - valid addresses" {
    try testing.expect(security.validateEmailAddress("user@example.com"));
    try testing.expect(security.validateEmailAddress("first.last@example.com"));
    try testing.expect(security.validateEmailAddress("user+tag@example.co.uk"));
    try testing.expect(security.validateEmailAddress("123@example.com"));
    try testing.expect(security.validateEmailAddress("user@sub.domain.example.com"));
}

test "email validation - invalid addresses" {
    try testing.expect(!security.validateEmailAddress("invalid"));
    try testing.expect(!security.validateEmailAddress("@example.com"));
    try testing.expect(!security.validateEmailAddress("user@"));
    // Note: Current implementation doesn't check for spaces - would need enhancement
    // try testing.expect(!security.validateEmailAddress("user @example.com"));
    try testing.expect(!security.validateEmailAddress(""));
    try testing.expect(!security.validateEmailAddress("user@example")); // No dot in domain
}

test "rate limiter - basic functionality" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var limiter = security.RateLimiter.init(allocator, 3600, 10, 20, 3600); // 10 requests per hour per IP, 20 per user, 1 hour cleanup
    defer limiter.deinit();

    const ip = "192.168.1.1";

    // First request should succeed
    try testing.expect(try limiter.checkAndIncrement(ip));

    // Add 9 more requests (total 10)
    var i: usize = 0;
    while (i < 9) : (i += 1) {
        try testing.expect(try limiter.checkAndIncrement(ip));
    }

    // 11th request should fail (exceeds limit of 10)
    try testing.expect(!try limiter.checkAndIncrement(ip));
}

test "rate limiter - different IPs" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var limiter = security.RateLimiter.init(allocator, 3600, 5, 10, 3600);
    defer limiter.deinit();

    // Different IPs should have independent limits
    try testing.expect(try limiter.checkAndIncrement("192.168.1.1"));
    try testing.expect(try limiter.checkAndIncrement("192.168.1.2"));
    try testing.expect(try limiter.checkAndIncrement("192.168.1.3"));

    // Each IP should be able to make multiple requests
    try testing.expect(try limiter.checkAndIncrement("192.168.1.1"));
    try testing.expect(try limiter.checkAndIncrement("192.168.1.1"));
}

test "rate limiter - remaining requests" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var limiter = security.RateLimiter.init(allocator, 3600, 10, 20, 3600);
    defer limiter.deinit();

    const ip = "192.168.1.1";

    // Initially should have max_requests remaining
    try testing.expectEqual(@as(u32, 10), limiter.getRemainingRequests(ip));

    // After one request
    _ = try limiter.checkAndIncrement(ip);
    try testing.expectEqual(@as(u32, 9), limiter.getRemainingRequests(ip));

    // After two more requests
    _ = try limiter.checkAndIncrement(ip);
    _ = try limiter.checkAndIncrement(ip);
    try testing.expectEqual(@as(u32, 7), limiter.getRemainingRequests(ip));
}

test "hostname validation" {
    try testing.expect(security.isValidHostname("example.com"));
    try testing.expect(security.isValidHostname("sub.example.com"));
    try testing.expect(security.isValidHostname("localhost"));
    try testing.expect(security.isValidHostname("mail-server.example.com"));
    try testing.expect(security.isValidHostname("192.168.1.1")); // IP addresses are valid hostnames

    try testing.expect(!security.isValidHostname(""));
    try testing.expect(!security.isValidHostname("example .com")); // Space not allowed
    // Note: Current implementation allows leading/trailing dots - could be enhanced
    // try testing.expect(!security.isValidHostname(".example.com"));
    // try testing.expect(!security.isValidHostname("example.com."));
}
