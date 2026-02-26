// RFC 6376 DKIM Key Rotation Test Suite
// Tests for DKIM key rotation scheduling, domain registration, config
// management, and rotation lifecycle.
// https://datatracker.ietf.org/doc/html/rfc6376

const std = @import("std");
const testing = std.testing;
const dkim_rotation = @import("mail").dkim_rotation;
const dkim = @import("mail").dkim;

// ============================================================================
// Helper utilities
// ============================================================================

fn createKeyManager() !dkim.DKIMKeyManager {
    return try dkim.DKIMKeyManager.init(testing.allocator, null);
}

fn createScheduler(km: *dkim.DKIMKeyManager) dkim_rotation.DKIMRotationScheduler {
    return dkim_rotation.DKIMRotationScheduler.init(
        testing.allocator,
        km,
        .{},
    );
}

fn createSchedulerWithConfig(km: *dkim.DKIMKeyManager, config: dkim_rotation.DKIMRotationScheduler.RotationConfig) dkim_rotation.DKIMRotationScheduler {
    return dkim_rotation.DKIMRotationScheduler.init(
        testing.allocator,
        km,
        config,
    );
}

// ============================================================================
// Scheduler lifecycle tests
// ============================================================================

test "DKIM rotation scheduler init and deinit" {
    var km = try createKeyManager();
    defer km.deinit();

    var scheduler = createScheduler(&km);
    defer scheduler.deinit();

    try testing.expectEqual(false, scheduler.running);
    try testing.expectEqual(@as(u32, 90), scheduler.config.rotation_interval_days);
}

test "DKIM rotation scheduler init with custom config" {
    var km = try createKeyManager();
    defer km.deinit();

    var scheduler = createSchedulerWithConfig(&km, .{
        .rotation_interval_days = 30,
        .overlap_period_days = 3,
        .warning_threshold_days = 14,
        .auto_rotate = false,
        .max_keys_per_domain = 3,
    });
    defer scheduler.deinit();

    try testing.expectEqual(@as(u32, 30), scheduler.config.rotation_interval_days);
    try testing.expectEqual(@as(u32, 3), scheduler.config.overlap_period_days);
    try testing.expectEqual(@as(u32, 14), scheduler.config.warning_threshold_days);
    try testing.expectEqual(false, scheduler.config.auto_rotate);
    try testing.expectEqual(@as(u32, 3), scheduler.config.max_keys_per_domain);
}

// ============================================================================
// Domain registration tests
// ============================================================================

test "DKIM rotation register domain" {
    var km = try createKeyManager();
    defer km.deinit();

    var scheduler = createScheduler(&km);
    defer scheduler.deinit();

    try scheduler.registerDomain("example.com");
    const status = scheduler.getDomainStatus("example.com");
    try testing.expect(status != null);
    try testing.expectEqual(dkim_rotation.DKIMRotationScheduler.RotationStatus.idle, status.?.status);
    try testing.expectEqual(@as(u32, 0), status.?.rotation_count);
}

test "DKIM rotation register multiple domains" {
    var km = try createKeyManager();
    defer km.deinit();

    var scheduler = createScheduler(&km);
    defer scheduler.deinit();

    try scheduler.registerDomain("example.com");
    try scheduler.registerDomain("example.org");
    try scheduler.registerDomain("example.net");

    const domains = try scheduler.getRegisteredDomains();
    defer testing.allocator.free(domains);

    try testing.expectEqual(@as(usize, 3), domains.len);
}

test "DKIM rotation register duplicate domain is idempotent" {
    var km = try createKeyManager();
    defer km.deinit();

    var scheduler = createScheduler(&km);
    defer scheduler.deinit();

    try scheduler.registerDomain("example.com");
    try scheduler.registerDomain("example.com"); // No error

    const domains = try scheduler.getRegisteredDomains();
    defer testing.allocator.free(domains);

    try testing.expectEqual(@as(usize, 1), domains.len);
}

test "DKIM rotation unregister domain" {
    var km = try createKeyManager();
    defer km.deinit();

    var scheduler = createScheduler(&km);
    defer scheduler.deinit();

    try scheduler.registerDomain("example.com");
    try testing.expect(scheduler.getDomainStatus("example.com") != null);

    scheduler.unregisterDomain("example.com");
    try testing.expect(scheduler.getDomainStatus("example.com") == null);
}

test "DKIM rotation unregister nonexistent domain does not error" {
    var km = try createKeyManager();
    defer km.deinit();

    var scheduler = createScheduler(&km);
    defer scheduler.deinit();

    scheduler.unregisterDomain("doesnotexist.com"); // No error
}

// ============================================================================
// Config defaults tests
// ============================================================================

test "DKIM rotation config defaults" {
    const config = dkim_rotation.DKIMRotationScheduler.RotationConfig{};
    try testing.expectEqual(@as(u32, 90), config.rotation_interval_days);
    try testing.expectEqual(@as(u32, 7), config.overlap_period_days);
    try testing.expectEqual(@as(u32, 30), config.warning_threshold_days);
    try testing.expectEqual(dkim.KeyAlgorithm.rsa_2048, config.default_algorithm);
    try testing.expect(config.auto_rotate);
    try testing.expectEqual(@as(u32, 5), config.max_keys_per_domain);
}

// ============================================================================
// Config update tests
// ============================================================================

test "DKIM rotation update config recalculates next rotation" {
    var km = try createKeyManager();
    defer km.deinit();

    var scheduler = createScheduler(&km);
    defer scheduler.deinit();

    try scheduler.registerDomain("example.com");

    const initial_status = scheduler.getDomainStatus("example.com").?;
    const initial_next = initial_status.next_rotation;

    // Update config to shorter interval
    scheduler.updateConfig(.{
        .rotation_interval_days = 30,
    });

    const updated_status = scheduler.getDomainStatus("example.com").?;
    // Next rotation should be sooner with 30-day interval vs 90-day
    try testing.expect(updated_status.next_rotation < initial_next);
}

// ============================================================================
// Rotation status tests
// ============================================================================

test "DKIM rotation status toString" {
    const Stat = dkim_rotation.DKIMRotationScheduler.RotationStatus;
    try testing.expectEqualStrings("idle", Stat.idle.toString());
    try testing.expectEqualStrings("pending", Stat.pending.toString());
    try testing.expectEqualStrings("in_progress", Stat.in_progress.toString());
    try testing.expectEqualStrings("completed", Stat.completed.toString());
    try testing.expectEqualStrings("failed", Stat.failed.toString());
}

// ============================================================================
// Domain status query tests
// ============================================================================

test "DKIM rotation getDomainStatus for unregistered domain returns null" {
    var km = try createKeyManager();
    defer km.deinit();

    var scheduler = createScheduler(&km);
    defer scheduler.deinit();

    try testing.expect(scheduler.getDomainStatus("unknown.com") == null);
}

test "DKIM rotation domain state has correct initial timestamps" {
    var km = try createKeyManager();
    defer km.deinit();

    var scheduler = createScheduler(&km);
    defer scheduler.deinit();

    try scheduler.registerDomain("example.com");

    const status = scheduler.getDomainStatus("example.com").?;
    try testing.expect(status.last_rotation > 0);
    try testing.expect(status.next_rotation > status.last_rotation);

    // Next rotation should be roughly 90 days (in seconds) after last rotation
    const diff = status.next_rotation - status.last_rotation;
    const expected = @as(i64, 90) * 24 * 60 * 60;
    try testing.expectEqual(expected, diff);
}

// ============================================================================
// RotationSchedulerThread tests
// ============================================================================

test "DKIM RotationSchedulerThread init" {
    var km = try createKeyManager();
    defer km.deinit();

    var scheduler = createScheduler(&km);
    defer scheduler.deinit();

    var running = std.atomic.Value(bool).init(false);
    var thread = dkim_rotation.RotationSchedulerThread.init(&scheduler, 1000, &running);

    try testing.expectEqual(@as(u32, 1000), thread.check_interval_ms);
    try testing.expectEqual(false, thread.running.load(.monotonic));
}

// ============================================================================
// RotationEvent type tests
// ============================================================================

test "DKIM rotation event types are distinct" {
    const EventType = dkim_rotation.DKIMRotationScheduler.RotationEvent.EventType;

    const types = [_]EventType{
        .rotation_started,
        .rotation_completed,
        .rotation_failed,
        .key_expiring_soon,
        .key_expired,
        .overlap_started,
        .overlap_ended,
    };

    // Verify all types are distinct by comparing pairs
    for (types, 0..) |t1, i| {
        for (types[i + 1 ..]) |t2| {
            try testing.expect(t1 != t2);
        }
    }
}
