const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");

/// Circuit breaker states
pub const CircuitState = enum {
    closed, // Normal operation
    open, // Failing, reject requests
    half_open, // Testing if service recovered

    pub fn toString(self: CircuitState) []const u8 {
        return switch (self) {
            .closed => "closed",
            .open => "open",
            .half_open => "half_open",
        };
    }
};

/// Circuit breaker configuration
pub const CircuitConfig = struct {
    failure_threshold: u32 = 5, // Failures before opening
    success_threshold: u32 = 2, // Successes in half-open before closing
    timeout_seconds: i64 = 60, // Time before trying half-open
    reset_timeout_seconds: i64 = 300, // Time before resetting counters
};

/// Circuit breaker error
pub const CircuitBreakerError = error{
    CircuitOpen,
    CircuitHalfOpen,
};

/// Circuit breaker for protecting against cascading failures
pub const CircuitBreaker = struct {
    allocator: std.mem.Allocator,
    name: []const u8,
    state: CircuitState,
    config: CircuitConfig,
    failure_count: u32,
    success_count: u32,
    last_failure_time: i64,
    last_success_time: i64,
    last_state_change: i64,
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator, name: []const u8, config: CircuitConfig) !CircuitBreaker {
        return CircuitBreaker{
            .allocator = allocator,
            .name = try allocator.dupe(u8, name),
            .state = .closed,
            .config = config,
            .failure_count = 0,
            .success_count = 0,
            .last_failure_time = 0,
            .last_success_time = 0,
            .last_state_change = time_compat.timestamp(),
            .mutex = mutex_compat.Mutex{},
        };
    }

    pub fn deinit(self: *CircuitBreaker) void {
        self.allocator.free(self.name);
    }

    /// Check if request is allowed
    pub fn allowRequest(self: *CircuitBreaker) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = time_compat.timestamp();

        switch (self.state) {
            .closed => return true,
            .open => {
                // Check if timeout has elapsed to try half-open
                const elapsed = now - self.last_state_change;
                if (elapsed >= self.config.timeout_seconds) {
                    self.state = .half_open;
                    self.success_count = 0;
                    self.last_state_change = now;
                    std.log.info("Circuit breaker '{s}' transitioning to half-open", .{self.name});
                    return true;
                }
                return error.CircuitOpen;
            },
            .half_open => {
                // Allow one request at a time in half-open
                return true;
            },
        }
    }

    /// Record successful execution
    pub fn recordSuccess(self: *CircuitBreaker) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = time_compat.timestamp();
        self.last_success_time = now;

        switch (self.state) {
            .closed => {
                // Reset failure count on success
                self.failure_count = 0;
            },
            .half_open => {
                self.success_count += 1;
                if (self.success_count >= self.config.success_threshold) {
                    self.state = .closed;
                    self.failure_count = 0;
                    self.success_count = 0;
                    self.last_state_change = now;
                    std.log.info("Circuit breaker '{s}' closed after successful recovery", .{self.name});
                }
            },
            .open => {
                // Should not happen, but handle gracefully
                std.log.warn("Circuit breaker '{s}' recorded success while open", .{self.name});
            },
        }
    }

    /// Record failed execution
    pub fn recordFailure(self: *CircuitBreaker) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = time_compat.timestamp();
        self.last_failure_time = now;
        self.failure_count += 1;

        switch (self.state) {
            .closed => {
                if (self.failure_count >= self.config.failure_threshold) {
                    self.state = .open;
                    self.last_state_change = now;
                    std.log.err("Circuit breaker '{s}' opened due to failures (count: {d})", .{ self.name, self.failure_count });
                }
            },
            .half_open => {
                // Single failure in half-open returns to open
                self.state = .open;
                self.success_count = 0;
                self.last_state_change = now;
                std.log.warn("Circuit breaker '{s}' returned to open after failure in half-open", .{self.name});
            },
            .open => {
                // Already open, just track
            },
        }
    }

    /// Reset circuit breaker to closed state
    pub fn reset(self: *CircuitBreaker) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = time_compat.timestamp();
        self.state = .closed;
        self.failure_count = 0;
        self.success_count = 0;
        self.last_state_change = now;
        std.log.info("Circuit breaker '{s}' manually reset", .{self.name});
    }

    /// Get current statistics
    pub fn getStats(self: *CircuitBreaker) CircuitStats {
        self.mutex.lock();
        defer self.mutex.unlock();

        return CircuitStats{
            .name = self.name,
            .state = self.state,
            .failure_count = self.failure_count,
            .success_count = self.success_count,
            .last_failure_time = self.last_failure_time,
            .last_success_time = self.last_success_time,
            .time_in_current_state = time_compat.timestamp() - self.last_state_change,
        };
    }

    /// Execute a function with circuit breaker protection
    pub fn execute(self: *CircuitBreaker, comptime T: type, func: fn () anyerror!T) !T {
        if (!try self.allowRequest()) {
            return error.CircuitOpen;
        }

        const result = func() catch |err| {
            self.recordFailure();
            return err;
        };

        self.recordSuccess();
        return result;
    }

    /// Execute a function with argument and circuit breaker protection
    pub fn executeWithArg(
        self: *CircuitBreaker,
        comptime T: type,
        comptime ArgT: type,
        func: fn (ArgT) anyerror!T,
        arg: ArgT,
    ) !T {
        if (!try self.allowRequest()) {
            return error.CircuitOpen;
        }

        const result = func(arg) catch |err| {
            self.recordFailure();
            return err;
        };

        self.recordSuccess();
        return result;
    }
};

pub const CircuitStats = struct {
    name: []const u8,
    state: CircuitState,
    failure_count: u32,
    success_count: u32,
    last_failure_time: i64,
    last_success_time: i64,
    time_in_current_state: i64,
};

/// Circuit breaker manager for multiple services
pub const CircuitBreakerManager = struct {
    allocator: std.mem.Allocator,
    breakers: std.StringHashMap(*CircuitBreaker),
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator) CircuitBreakerManager {
        return .{
            .allocator = allocator,
            .breakers = std.StringHashMap(*CircuitBreaker).init(allocator),
            .mutex = mutex_compat.Mutex{},
        };
    }

    pub fn deinit(self: *CircuitBreakerManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.breakers.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
            self.allocator.free(entry.key_ptr.*);
        }
        self.breakers.deinit();
    }

    /// Register a new circuit breaker
    pub fn register(self: *CircuitBreakerManager, name: []const u8, config: CircuitConfig) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.breakers.contains(name)) {
            return error.CircuitBreakerAlreadyExists;
        }

        const breaker = try self.allocator.create(CircuitBreaker);
        errdefer self.allocator.destroy(breaker);

        breaker.* = try CircuitBreaker.init(self.allocator, name, config);

        const name_copy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_copy);

        try self.breakers.put(name_copy, breaker);

        std.log.info("Circuit breaker '{s}' registered", .{name});
    }

    /// Get circuit breaker by name
    pub fn get(self: *CircuitBreakerManager, name: []const u8) ?*CircuitBreaker {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.breakers.get(name);
    }

    /// Get all circuit breaker statistics
    pub fn getAllStats(self: *CircuitBreakerManager, allocator: std.mem.Allocator) ![]CircuitStats {
        self.mutex.lock();
        defer self.mutex.unlock();

        var stats_list = std.ArrayList(CircuitStats).init(allocator);
        errdefer stats_list.deinit();

        var it = self.breakers.valueIterator();
        while (it.next()) |breaker| {
            try stats_list.append(breaker.*.getStats());
        }

        return stats_list.toOwnedSlice();
    }

    /// Reset all circuit breakers
    pub fn resetAll(self: *CircuitBreakerManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.breakers.valueIterator();
        while (it.next()) |breaker| {
            breaker.*.reset();
        }

        std.log.info("All circuit breakers reset", .{});
    }
};

test "circuit breaker basic operation" {
    const testing = std.testing;

    var breaker = try CircuitBreaker.init(testing.allocator, "test", .{
        .failure_threshold = 3,
        .success_threshold = 2,
        .timeout_seconds = 1,
        .reset_timeout_seconds = 10,
    });
    defer breaker.deinit();

    // Should allow request in closed state
    try testing.expect(try breaker.allowRequest());

    // Record failures
    breaker.recordFailure();
    breaker.recordFailure();
    try testing.expectEqual(CircuitState.closed, breaker.state);

    breaker.recordFailure();
    try testing.expectEqual(CircuitState.open, breaker.state);

    // Should not allow request when open
    try testing.expectError(error.CircuitOpen, breaker.allowRequest());
}

test "circuit breaker recovery" {
    const testing = std.testing;

    var breaker = try CircuitBreaker.init(testing.allocator, "test", .{
        .failure_threshold = 2,
        .success_threshold = 2,
        .timeout_seconds = 0, // Immediate transition for testing
        .reset_timeout_seconds = 10,
    });
    defer breaker.deinit();

    // Open circuit
    breaker.recordFailure();
    breaker.recordFailure();
    try testing.expectEqual(CircuitState.open, breaker.state);

    // Wait for transition to half-open
    std.time.sleep(std.time.ns_per_ms);

    // Should transition to half-open
    try testing.expect(try breaker.allowRequest());
    try testing.expectEqual(CircuitState.half_open, breaker.state);

    // Record successes
    breaker.recordSuccess();
    breaker.recordSuccess();
    try testing.expectEqual(CircuitState.closed, breaker.state);
}

test "circuit breaker manager" {
    const testing = std.testing;

    var manager = CircuitBreakerManager.init(testing.allocator);
    defer manager.deinit();

    try manager.register("database", .{});
    try manager.register("webhook", .{});

    const db_breaker = manager.get("database").?;
    try testing.expect(db_breaker != null);

    const webhook_breaker = manager.get("webhook").?;
    try testing.expect(webhook_breaker != null);

    const stats = try manager.getAllStats(testing.allocator);
    defer testing.allocator.free(stats);

    try testing.expectEqual(@as(usize, 2), stats.len);
}
