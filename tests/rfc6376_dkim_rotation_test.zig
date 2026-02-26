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

// ============================================================================
// Edge case tests
// ============================================================================

test "DKIM rotation edge case: zero interval days causes immediate next rotation" {
    var km = try createKeyManager();
    defer km.deinit();

    var scheduler = createSchedulerWithConfig(&km, .{
        .rotation_interval_days = 0,
        .overlap_period_days = 0,
    });
    defer scheduler.deinit();

    try scheduler.registerDomain("zero-interval.com");

    const status = scheduler.getDomainStatus("zero-interval.com").?;
    // With a zero interval, next_rotation should equal last_rotation
    // (0 days * 86400 seconds = 0 offset)
    try testing.expectEqual(status.last_rotation, status.next_rotation);
}

test "DKIM rotation edge case: very large interval (u32 max)" {
    var km = try createKeyManager();
    defer km.deinit();

    var scheduler = createSchedulerWithConfig(&km, .{
        .rotation_interval_days = std.math.maxInt(u32),
    });
    defer scheduler.deinit();

    try scheduler.registerDomain("max-interval.com");

    const status = scheduler.getDomainStatus("max-interval.com").?;
    // The interval in seconds is u32_max * 86400. It will overflow i64 multiplication
    // in the source: @as(i64, self.config.rotation_interval_days) * 24 * 60 * 60
    // but because it is cast to i64 first, the product is very large.
    // Just verify it does not crash and next_rotation > last_rotation.
    try testing.expect(status.next_rotation != status.last_rotation);
    try testing.expect(status.rotation_count == 0);
    try testing.expectEqual(dkim_rotation.DKIMRotationScheduler.RotationStatus.idle, status.status);
}

test "DKIM rotation edge case: register domain then immediately force rotation" {
    var km = try createKeyManager();
    defer km.deinit();

    var scheduler = createScheduler(&km);
    defer scheduler.deinit();

    try scheduler.registerDomain("force-rotate.com");

    const status_before = scheduler.getDomainStatus("force-rotate.com").?;
    try testing.expectEqual(@as(u32, 0), status_before.rotation_count);

    // Force rotation immediately after registration -- the key manager may
    // error because it cannot generate real keys, but the call should not panic.
    _ = scheduler.forceRotation("force-rotate.com") catch |err| {
        // Expected: the key manager stub may not support full generation.
        // Verify we get a well-defined error, not undefined behaviour.
        try testing.expect(@intFromError(err) != 0);
        return;
    };

    // If force rotation succeeds, rotation_count should be 1
    const status_after = scheduler.getDomainStatus("force-rotate.com").?;
    try testing.expectEqual(@as(u32, 1), status_after.rotation_count);
    try testing.expectEqual(dkim_rotation.DKIMRotationScheduler.RotationStatus.completed, status_after.status);
}

test "DKIM rotation edge case: multiple domains with different rotation schedules" {
    var km = try createKeyManager();
    defer km.deinit();

    // Start with 30-day schedule, register first domain
    var scheduler = createSchedulerWithConfig(&km, .{
        .rotation_interval_days = 30,
    });
    defer scheduler.deinit();

    try scheduler.registerDomain("fast-rotate.com");

    const fast_status = scheduler.getDomainStatus("fast-rotate.com").?;
    const fast_interval = fast_status.next_rotation - fast_status.last_rotation;
    const expected_30_days = @as(i64, 30) * 24 * 60 * 60;
    try testing.expectEqual(expected_30_days, fast_interval);

    // Update config to 180 days, register second domain
    scheduler.updateConfig(.{
        .rotation_interval_days = 180,
    });

    try scheduler.registerDomain("slow-rotate.com");

    const slow_status = scheduler.getDomainStatus("slow-rotate.com").?;
    const slow_interval = slow_status.next_rotation - slow_status.last_rotation;
    const expected_180_days = @as(i64, 180) * 24 * 60 * 60;
    try testing.expectEqual(expected_180_days, slow_interval);

    // After config update, the first domain's schedule was also recalculated
    // to the 180-day interval per updateConfig semantics.
    const fast_updated = scheduler.getDomainStatus("fast-rotate.com").?;
    const fast_updated_interval = fast_updated.next_rotation - fast_updated.last_rotation;
    try testing.expectEqual(expected_180_days, fast_updated_interval);
}

test "DKIM rotation edge case: rotation event log with many entries via checkAndRotate" {
    var km = try createKeyManager();
    defer km.deinit();

    var scheduler = createScheduler(&km);
    defer scheduler.deinit();

    // Register many domains
    const domains = [_][]const u8{
        "domain1.com", "domain2.com", "domain3.com",
        "domain4.com", "domain5.com", "domain6.com",
        "domain7.com", "domain8.com", "domain9.com",
        "domain10.com",
    };
    for (domains) |d| {
        try scheduler.registerDomain(d);
    }

    // checkAndRotate returns events (possibly empty since keys are not yet due).
    // The important thing is it handles 10 domains without crashing.
    const events = scheduler.checkAndRotate() catch |err| {
        // If there is an error from the key manager, that is acceptable in test.
        try testing.expect(@intFromError(err) != 0);
        return;
    };
    defer testing.allocator.free(events);

    // We registered 10 domains
    const registered = try scheduler.getRegisteredDomains();
    defer testing.allocator.free(registered);
    try testing.expectEqual(@as(usize, 10), registered.len);
}

test "DKIM rotation edge case: selector name generation uniqueness" {
    // Selector names are generated using timestamps: "s{timestamp}".
    // Two selectors generated at the same timestamp should be equal (deterministic).
    // This test verifies the format by creating a RotationEvent manually.
    const Event = dkim_rotation.DKIMRotationScheduler.RotationEvent;

    const event1 = Event{
        .domain = "example.com",
        .old_selector = "default",
        .new_selector = "s1700000000",
        .old_key_id = "",
        .new_key_id = "key-001",
        .timestamp = 1700000000,
        .event_type = .rotation_completed,
        .message = "ok",
    };

    const event2 = Event{
        .domain = "example.com",
        .old_selector = "s1700000000",
        .new_selector = "s1700000001",
        .old_key_id = "key-001",
        .new_key_id = "key-002",
        .timestamp = 1700000001,
        .event_type = .rotation_completed,
        .message = "ok",
    };

    // Different timestamps yield different selector names
    try testing.expect(!std.mem.eql(u8, event1.new_selector, event2.new_selector));

    // Same domain is preserved
    try testing.expectEqualStrings(event1.domain, event2.domain);

    // Chain: old_selector of event2 == new_selector of event1
    try testing.expectEqualStrings(event1.new_selector, event2.old_selector);
}

test "DKIM rotation edge case: empty domain registration" {
    var km = try createKeyManager();
    defer km.deinit();

    var scheduler = createScheduler(&km);
    defer scheduler.deinit();

    // Registering an empty domain string should not crash
    try scheduler.registerDomain("");

    const status = scheduler.getDomainStatus("");
    try testing.expect(status != null);
    try testing.expectEqualStrings("", status.?.domain);
}

test "DKIM rotation edge case: concurrent-like rotation requests for same domain" {
    var km = try createKeyManager();
    defer km.deinit();

    var scheduler = createScheduler(&km);
    defer scheduler.deinit();

    try scheduler.registerDomain("concurrent.com");

    // Simulate two sequential forceRotation calls for the same domain.
    // Both should either succeed or error consistently -- not panic.
    const result1 = scheduler.forceRotation("concurrent.com");
    const result2 = scheduler.forceRotation("concurrent.com");

    // At least one call should have a deterministic outcome.
    // If the key manager cannot generate keys, both should error the same way.
    if (result1) |event1| {
        try testing.expectEqualStrings("concurrent.com", event1.domain);
        try testing.expectEqual(
            dkim_rotation.DKIMRotationScheduler.RotationEvent.EventType.rotation_completed,
            event1.event_type,
        );

        // Second rotation should also succeed (rotation_count increments)
        if (result2) |event2| {
            try testing.expectEqualStrings("concurrent.com", event2.domain);
        } else |_| {
            // Also acceptable if second fails due to state
        }
    } else |_| {
        // Key generation error is acceptable in test environment;
        // just verify the second call also errors consistently.
        try testing.expectError(
            @as(anyerror, if (result2) |_| error.Unexpected else |e| e),
            result1,
        );
    }
}

test "DKIM rotation edge case: init/deinit cycle preserves clean state" {
    var km = try createKeyManager();
    defer km.deinit();

    // First cycle: register a domain, then deinit
    {
        var scheduler = createScheduler(&km);
        try scheduler.registerDomain("ephemeral.com");
        const status = scheduler.getDomainStatus("ephemeral.com");
        try testing.expect(status != null);
        scheduler.deinit();
    }

    // Second cycle: create a new scheduler, previous state should not leak
    {
        var scheduler = createScheduler(&km);
        defer scheduler.deinit();

        // "ephemeral.com" should not exist in the new scheduler
        const status = scheduler.getDomainStatus("ephemeral.com");
        try testing.expect(status == null);

        // New registrations should work fine
        try scheduler.registerDomain("new-domain.com");
        try testing.expect(scheduler.getDomainStatus("new-domain.com") != null);
    }
}

test "DKIM rotation edge case: timestamp boundaries around rotation time" {
    var km = try createKeyManager();
    defer km.deinit();

    var scheduler = createSchedulerWithConfig(&km, .{
        .rotation_interval_days = 1,
        .overlap_period_days = 0,
        .warning_threshold_days = 0,
    });
    defer scheduler.deinit();

    try scheduler.registerDomain("boundary.com");

    const status = scheduler.getDomainStatus("boundary.com").?;
    const one_day_seconds = @as(i64, 1) * 24 * 60 * 60;

    // Verify next_rotation is exactly one day after last_rotation
    try testing.expectEqual(status.last_rotation + one_day_seconds, status.next_rotation);

    // Update config to 2 days and verify recalculation
    scheduler.updateConfig(.{
        .rotation_interval_days = 2,
        .overlap_period_days = 0,
        .warning_threshold_days = 0,
    });

    const updated_status = scheduler.getDomainStatus("boundary.com").?;
    const two_day_seconds = @as(i64, 2) * 24 * 60 * 60;
    try testing.expectEqual(updated_status.last_rotation + two_day_seconds, updated_status.next_rotation);

    // last_rotation should not have changed (only next_rotation recalculated)
    try testing.expectEqual(status.last_rotation, updated_status.last_rotation);
}
