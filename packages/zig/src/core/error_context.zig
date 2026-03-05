const std = @import("std");
const mutex_compat = @import("mutex_compat.zig");
const time_compat = @import("time_compat.zig");

/// Error context for debugging and recovery
pub const ErrorContext = struct {
    allocator: std.mem.Allocator,
    operation: []const u8,
    component: []const u8,
    details: std.StringHashMap([]const u8),
    stack_trace: ?[]const u8,
    timestamp: i64,
    error_type: []const u8,

    pub fn init(allocator: std.mem.Allocator, component: []const u8, operation: []const u8) !ErrorContext {
        return ErrorContext{
            .allocator = allocator,
            .operation = try allocator.dupe(u8, operation),
            .component = try allocator.dupe(u8, component),
            .details = std.StringHashMap([]const u8).init(allocator),
            .stack_trace = null,
            .timestamp = time_compat.timestamp(),
            .error_type = try allocator.dupe(u8, "Unknown"),
        };
    }

    pub fn deinit(self: *ErrorContext) void {
        self.allocator.free(self.operation);
        self.allocator.free(self.component);
        self.allocator.free(self.error_type);

        var it = self.details.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.details.deinit();

        if (self.stack_trace) |trace| {
            self.allocator.free(trace);
        }
    }

    /// Add contextual detail
    pub fn addDetail(self: *ErrorContext, key: []const u8, value: []const u8) !void {
        const key_copy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(key_copy);

        const value_copy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_copy);

        try self.details.put(key_copy, value_copy);
    }

    /// Add formatted detail
    pub fn addDetailFmt(self: *ErrorContext, key: []const u8, comptime fmt: []const u8, args: anytype) !void {
        const value = try std.fmt.allocPrint(self.allocator, fmt, args);
        errdefer self.allocator.free(value);

        const key_copy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(key_copy);

        try self.details.put(key_copy, value);
    }

    /// Set error type
    pub fn setErrorType(self: *ErrorContext, error_type: []const u8) !void {
        self.allocator.free(self.error_type);
        self.error_type = try self.allocator.dupe(u8, error_type);
    }

    /// Set stack trace
    pub fn setStackTrace(self: *ErrorContext, trace: []const u8) !void {
        if (self.stack_trace) |old_trace| {
            self.allocator.free(old_trace);
        }
        self.stack_trace = try self.allocator.dupe(u8, trace);
    }

    /// Format error context as JSON
    pub fn toJSON(self: *ErrorContext) ![]const u8 {
        var json = std.ArrayList(u8).init(self.allocator);
        errdefer json.deinit();

        try json.appendSlice("{");

        // Basic fields
        try json.writer().print("\"timestamp\":{d},", .{self.timestamp});
        try json.writer().print("\"component\":\"{s}\",", .{self.component});
        try json.writer().print("\"operation\":\"{s}\",", .{self.operation});
        try json.writer().print("\"error_type\":\"{s}\"", .{self.error_type});

        // Details
        if (self.details.count() > 0) {
            try json.appendSlice(",\"details\":{");
            var first = true;
            var it = self.details.iterator();
            while (it.next()) |entry| {
                if (!first) try json.appendSlice(",");
                first = false;
                try json.writer().print("\"{s}\":\"{s}\"", .{ entry.key_ptr.*, entry.value_ptr.* });
            }
            try json.appendSlice("}");
        }

        // Stack trace
        if (self.stack_trace) |trace| {
            try json.appendSlice(",\"stack_trace\":\"");
            // Escape newlines in stack trace
            for (trace) |c| {
                if (c == '\n') {
                    try json.appendSlice("\\n");
                } else if (c == '"') {
                    try json.appendSlice("\\\"");
                } else if (c == '\\') {
                    try json.appendSlice("\\\\");
                } else {
                    try json.append(c);
                }
            }
            try json.appendSlice("\"");
        }

        try json.appendSlice("}");

        return json.toOwnedSlice();
    }

    /// Format error context as human-readable string
    pub fn toString(self: *ErrorContext) ![]const u8 {
        var output = std.ArrayList(u8).init(self.allocator);
        errdefer output.deinit();

        try output.writer().print("Error in {s}.{s}\n", .{ self.component, self.operation });
        try output.writer().print("Type: {s}\n", .{self.error_type});
        try output.writer().print("Timestamp: {d}\n", .{self.timestamp});

        if (self.details.count() > 0) {
            try output.appendSlice("Details:\n");
            var it = self.details.iterator();
            while (it.next()) |entry| {
                try output.writer().print("  {s}: {s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
            }
        }

        if (self.stack_trace) |trace| {
            try output.appendSlice("Stack trace:\n");
            try output.appendSlice(trace);
            try output.appendSlice("\n");
        }

        return output.toOwnedSlice();
    }
};

/// Error context manager for tracking errors across operations
pub const ErrorContextManager = struct {
    allocator: std.mem.Allocator,
    contexts: std.ArrayList(ErrorContext),
    max_contexts: usize,
    mutex: mutex_compat.Mutex,

    pub fn init(allocator: std.mem.Allocator, max_contexts: usize) ErrorContextManager {
        return .{
            .allocator = allocator,
            .contexts = std.ArrayList(ErrorContext).init(allocator),
            .max_contexts = max_contexts,
            .mutex = mutex_compat.Mutex{},
        };
    }

    pub fn deinit(self: *ErrorContextManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.contexts.items) |*ctx| {
            ctx.deinit();
        }
        self.contexts.deinit();
    }

    /// Record an error context
    pub fn record(self: *ErrorContextManager, ctx: ErrorContext) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // If at max capacity, remove oldest
        if (self.contexts.items.len >= self.max_contexts) {
            var oldest = self.contexts.orderedRemove(0);
            oldest.deinit();
        }

        try self.contexts.append(ctx);
    }

    /// Get recent error contexts
    pub fn getRecent(self: *ErrorContextManager, count: usize, allocator: std.mem.Allocator) ![]ErrorContext {
        self.mutex.lock();
        defer self.mutex.unlock();

        const actual_count = @min(count, self.contexts.items.len);
        var result = try allocator.alloc(ErrorContext, actual_count);

        const start_idx = self.contexts.items.len - actual_count;
        for (self.contexts.items[start_idx..], 0..) |ctx, i| {
            result[i] = ErrorContext{
                .allocator = ctx.allocator,
                .operation = try allocator.dupe(u8, ctx.operation),
                .component = try allocator.dupe(u8, ctx.component),
                .details = std.StringHashMap([]const u8).init(allocator),
                .stack_trace = if (ctx.stack_trace) |trace| try allocator.dupe(u8, trace) else null,
                .timestamp = ctx.timestamp,
                .error_type = try allocator.dupe(u8, ctx.error_type),
            };

            // Copy details
            var it = ctx.details.iterator();
            while (it.next()) |entry| {
                const key = try allocator.dupe(u8, entry.key_ptr.*);
                const value = try allocator.dupe(u8, entry.value_ptr.*);
                try result[i].details.put(key, value);
            }
        }

        return result;
    }

    /// Clear all error contexts
    pub fn clear(self: *ErrorContextManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.contexts.items) |*ctx| {
            ctx.deinit();
        }
        self.contexts.clearRetainingCapacity();
    }

    /// Get error statistics
    pub fn getStats(self: *ErrorContextManager) struct { total: usize, by_component: std.StringHashMap(usize) } {
        self.mutex.lock();
        defer self.mutex.unlock();

        var by_component = std.StringHashMap(usize).init(self.allocator);

        for (self.contexts.items) |ctx| {
            const entry = by_component.getOrPut(ctx.component) catch continue;
            if (!entry.found_existing) {
                entry.value_ptr.* = 0;
            }
            entry.value_ptr.* += 1;
        }

        return .{
            .total = self.contexts.items.len,
            .by_component = by_component,
        };
    }
};

test "error context basic usage" {
    const testing = std.testing;

    var ctx = try ErrorContext.init(testing.allocator, "Database", "connect");
    defer ctx.deinit();

    try ctx.addDetail("host", "localhost");
    try ctx.addDetail("port", "5432");
    try ctx.setErrorType("ConnectionRefused");

    const json = try ctx.toJSON();
    defer testing.allocator.free(json);

    try testing.expect(std.mem.indexOf(u8, json, "Database") != null);
    try testing.expect(std.mem.indexOf(u8, json, "connect") != null);
}

test "error context manager" {
    const testing = std.testing;

    var manager = ErrorContextManager.init(testing.allocator, 10);
    defer manager.deinit();

    var ctx1 = try ErrorContext.init(testing.allocator, "SMTP", "send");
    try ctx1.addDetail("recipient", "test@example.com");
    try manager.record(ctx1);

    var ctx2 = try ErrorContext.init(testing.allocator, "Database", "query");
    try ctx2.addDetail("table", "users");
    try manager.record(ctx2);

    const recent = try manager.getRecent(5, testing.allocator);
    defer {
        for (recent) |*ctx| {
            ctx.deinit();
        }
        testing.allocator.free(recent);
    }

    try testing.expectEqual(@as(usize, 2), recent.len);
}
