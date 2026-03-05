const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");
pub const dkim = @import("../antispam/dkim.zig");

/// DKIM Key Rotation Scheduler
/// Automates periodic DKIM key rotation with configurable intervals,
/// overlap periods, and notification callbacks.
pub const DKIMRotationScheduler = struct {
    allocator: std.mem.Allocator,
    key_manager: *dkim.DKIMKeyManager,
    config: RotationConfig,
    rotation_state: std.StringHashMap(DomainRotationState),
    mutex: mutex_compat.Mutex,
    running: bool,

    pub const RotationConfig = struct {
        /// Interval between rotations in days (default: 90)
        rotation_interval_days: u32 = 90,
        /// Overlap period where both old and new keys are valid (days)
        overlap_period_days: u32 = 7,
        /// Days before expiry to trigger warning
        warning_threshold_days: u32 = 30,
        /// Default algorithm for new keys
        default_algorithm: dkim.KeyAlgorithm = .rsa_2048,
        /// Auto-rotate when keys are expiring
        auto_rotate: bool = true,
        /// Maximum number of active keys per domain
        max_keys_per_domain: u32 = 5,
    };

    pub const DomainRotationState = struct {
        domain: []const u8,
        last_rotation: i64,
        next_rotation: i64,
        rotation_count: u32,
        status: RotationStatus,
    };

    pub const RotationStatus = enum {
        idle,
        pending,
        in_progress,
        completed,
        failed,

        pub fn toString(self: RotationStatus) []const u8 {
            return switch (self) {
                .idle => "idle",
                .pending => "pending",
                .in_progress => "in_progress",
                .completed => "completed",
                .failed => "failed",
            };
        }
    };

    pub const RotationEvent = struct {
        domain: []const u8,
        old_selector: []const u8,
        new_selector: []const u8,
        old_key_id: []const u8,
        new_key_id: []const u8,
        timestamp: i64,
        event_type: EventType,
        message: []const u8,

        pub const EventType = enum {
            rotation_started,
            rotation_completed,
            rotation_failed,
            key_expiring_soon,
            key_expired,
            overlap_started,
            overlap_ended,
        };
    };

    pub fn init(
        allocator: std.mem.Allocator,
        key_manager: *dkim.DKIMKeyManager,
        rotation_config: RotationConfig,
    ) DKIMRotationScheduler {
        return .{
            .allocator = allocator,
            .key_manager = key_manager,
            .config = rotation_config,
            .rotation_state = std.StringHashMap(DomainRotationState).init(allocator),
            .mutex = .{},
            .running = false,
        };
    }

    pub fn deinit(self: *DKIMRotationScheduler) void {
        var it = self.rotation_state.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.rotation_state.deinit();
    }

    /// Register a domain for automatic key rotation
    pub fn registerDomain(self: *DKIMRotationScheduler, domain: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.rotation_state.contains(domain)) return;

        const now = time_compat.timestamp();
        const interval_seconds = @as(i64, self.config.rotation_interval_days) * 24 * 60 * 60;

        const key = try self.allocator.dupe(u8, domain);
        errdefer self.allocator.free(key);

        try self.rotation_state.put(key, .{
            .domain = key,
            .last_rotation = now,
            .next_rotation = now + interval_seconds,
            .rotation_count = 0,
            .status = .idle,
        });
    }

    /// Unregister a domain from automatic rotation
    pub fn unregisterDomain(self: *DKIMRotationScheduler, domain: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.rotation_state.fetchRemove(domain)) |kv| {
            self.allocator.free(kv.key);
        }
    }

    /// Check all domains and rotate keys that are due
    pub fn checkAndRotate(self: *DKIMRotationScheduler) ![]RotationEvent {
        var events: std.ArrayList(RotationEvent) = .{};
        const now = time_compat.timestamp();

        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.rotation_state.iterator();
        while (it.next()) |entry| {
            const state = entry.value_ptr;

            // Check if rotation is due
            if (now >= state.next_rotation and state.status != .in_progress) {
                state.status = .in_progress;

                // Perform rotation
                const event = self.rotateKeyForDomain(state) catch |err| {
                    state.status = .failed;
                    try events.append(self.allocator, .{
                        .domain = state.domain,
                        .old_selector = "",
                        .new_selector = "",
                        .old_key_id = "",
                        .new_key_id = "",
                        .timestamp = now,
                        .event_type = .rotation_failed,
                        .message = @errorName(err),
                    });
                    continue;
                };

                try events.append(self.allocator, event);
            }

            // Check for expiring keys
            if (self.config.auto_rotate) {
                const active_key = self.key_manager.getActiveKey(state.domain);
                if (active_key) |key| {
                    if (key.isExpiringSoon(self.config.warning_threshold_days)) {
                        try events.append(self.allocator, .{
                            .domain = state.domain,
                            .old_selector = key.selector,
                            .new_selector = "",
                            .old_key_id = key.id,
                            .new_key_id = "",
                            .timestamp = now,
                            .event_type = .key_expiring_soon,
                            .message = "Key is expiring soon, rotation recommended",
                        });
                    }
                }
            }
        }

        return events.toOwnedSlice(self.allocator);
    }

    fn rotateKeyForDomain(self: *DKIMRotationScheduler, state: *DomainRotationState) !RotationEvent {
        const now = time_compat.timestamp();
        const interval_seconds = @as(i64, self.config.rotation_interval_days) * 24 * 60 * 60;

        // Get current active key
        const old_key = self.key_manager.getActiveKey(state.domain);
        const old_selector = if (old_key) |k| k.selector else "default";
        const old_key_id = if (old_key) |k| k.id else "";

        // Generate new selector with timestamp
        const new_selector = try std.fmt.allocPrint(self.allocator, "s{d}", .{now});
        defer self.allocator.free(new_selector);

        // Generate new key
        const new_key = try self.key_manager.generateKey(
            state.domain,
            new_selector,
            self.config.default_algorithm,
            self.config.rotation_interval_days + self.config.overlap_period_days,
        );

        // Schedule old key deactivation after overlap period
        if (old_key) |k| {
            const deactivation_time = now + @as(i64, self.config.overlap_period_days) * 24 * 60 * 60;
            k.expires_at = deactivation_time;
        }

        // Update state
        state.last_rotation = now;
        state.next_rotation = now + interval_seconds;
        state.rotation_count += 1;
        state.status = .completed;

        return .{
            .domain = state.domain,
            .old_selector = old_selector,
            .new_selector = new_key.selector,
            .old_key_id = old_key_id,
            .new_key_id = new_key.id,
            .timestamp = now,
            .event_type = .rotation_completed,
            .message = "Key rotation completed successfully",
        };
    }

    /// Get rotation status for a domain
    pub fn getDomainStatus(self: *DKIMRotationScheduler, domain: []const u8) ?DomainRotationState {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.rotation_state.get(domain);
    }

    /// Get all registered domains
    pub fn getRegisteredDomains(self: *DKIMRotationScheduler) ![][]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var domains: std.ArrayList([]const u8) = .{};
        var it = self.rotation_state.iterator();
        while (it.next()) |entry| {
            try domains.append(self.allocator, entry.key_ptr.*);
        }
        return domains.toOwnedSlice(self.allocator);
    }

    /// Force immediate rotation for a domain
    pub fn forceRotation(self: *DKIMRotationScheduler, domain: []const u8) !RotationEvent {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.rotation_state.getPtr(domain)) |state| {
            return self.rotateKeyForDomain(state);
        }
        return error.DomainNotRegistered;
    }

    /// Update rotation configuration
    pub fn updateConfig(self: *DKIMRotationScheduler, new_config: RotationConfig) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.config = new_config;

        // Recalculate next rotation times
        var it = self.rotation_state.iterator();
        const interval_seconds = @as(i64, new_config.rotation_interval_days) * 24 * 60 * 60;
        while (it.next()) |entry| {
            entry.value_ptr.next_rotation = entry.value_ptr.last_rotation + interval_seconds;
        }
    }

    /// Clean up expired and inactive keys beyond the retention limit
    pub fn cleanupExpiredKeys(self: *DKIMRotationScheduler) !u32 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var cleaned: u32 = 0;
        const now = time_compat.timestamp();

        var it = self.rotation_state.iterator();
        while (it.next()) |entry| {
            const domain = entry.key_ptr.*;
            const domain_keys = self.key_manager.listKeys(domain);
            var active_count: u32 = 0;

            for (domain_keys) |key| {
                if (key.is_active and key.isValidAt(now)) {
                    active_count += 1;
                }
            }

            // Remove inactive expired keys if we have too many
            if (active_count > self.config.max_keys_per_domain) {
                for (domain_keys) |key| {
                    if (!key.is_active) {
                        self.key_manager.deleteKey(key.id) catch continue;
                        cleaned += 1;
                    }
                }
            }
        }

        return cleaned;
    }
};

/// Rotation scheduler that runs in a background thread
pub const RotationSchedulerThread = struct {
    scheduler: *DKIMRotationScheduler,
    check_interval_ms: u32,
    running: *std.atomic.Value(bool),

    pub fn init(
        scheduler: *DKIMRotationScheduler,
        check_interval_ms: u32,
        running: *std.atomic.Value(bool),
    ) RotationSchedulerThread {
        return .{
            .scheduler = scheduler,
            .check_interval_ms = check_interval_ms,
            .running = running,
        };
    }

    pub fn run(self: *RotationSchedulerThread) void {
        while (self.running.load(.monotonic)) {
            _ = self.scheduler.checkAndRotate() catch {};
            time_compat.sleepMs(self.check_interval_ms);
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

test "rotation scheduler init and deinit" {
    var km = try dkim.DKIMKeyManager.init(std.testing.allocator, null);
    defer km.deinit();

    var scheduler = DKIMRotationScheduler.init(
        std.testing.allocator,
        &km,
        .{},
    );
    defer scheduler.deinit();

    try std.testing.expectEqual(@as(u32, 90), scheduler.config.rotation_interval_days);
}

test "register and unregister domain" {
    var km = try dkim.DKIMKeyManager.init(std.testing.allocator, null);
    defer km.deinit();

    var scheduler = DKIMRotationScheduler.init(
        std.testing.allocator,
        &km,
        .{},
    );
    defer scheduler.deinit();

    try scheduler.registerDomain("example.com");
    const status = scheduler.getDomainStatus("example.com");
    try std.testing.expect(status != null);
    try std.testing.expectEqual(DKIMRotationScheduler.RotationStatus.idle, status.?.status);

    scheduler.unregisterDomain("example.com");
    try std.testing.expect(scheduler.getDomainStatus("example.com") == null);
}

test "rotation config defaults" {
    const config = DKIMRotationScheduler.RotationConfig{};
    try std.testing.expectEqual(@as(u32, 90), config.rotation_interval_days);
    try std.testing.expectEqual(@as(u32, 7), config.overlap_period_days);
    try std.testing.expectEqual(@as(u32, 30), config.warning_threshold_days);
    try std.testing.expect(config.auto_rotate);
}

test "rotation status toString" {
    try std.testing.expectEqualStrings("idle", DKIMRotationScheduler.RotationStatus.idle.toString());
    try std.testing.expectEqualStrings("completed", DKIMRotationScheduler.RotationStatus.completed.toString());
    try std.testing.expectEqualStrings("failed", DKIMRotationScheduler.RotationStatus.failed.toString());
}
