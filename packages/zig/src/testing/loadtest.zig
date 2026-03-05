const std = @import("std");

/// Load test configuration
pub const LoadTestConfig = struct {
    host: []const u8 = "localhost",
    port: u16 = 2525,
    num_connections: usize = 10,
    messages_per_connection: usize = 10,
    concurrent_connections: usize = 5,
    timeout_ms: u32 = 5000,
};

/// Load test result
pub const LoadTestResult = struct {
    total_messages: usize,
    successful_messages: usize,
    failed_messages: usize,
    total_duration_ms: u64,
    avg_message_time_ms: f64,
    messages_per_second: f64,
    errors: std.ArrayList([]const u8),

    pub fn print(self: *const LoadTestResult, writer: anytype) !void {
        try writer.print("\n=== Load Test Results ===\n", .{});
        try writer.print("Total messages: {d}\n", .{self.total_messages});
        try writer.print("Successful: {d}\n", .{self.successful_messages});
        try writer.print("Failed: {d}\n", .{self.failed_messages});
        try writer.print("Total duration: {d} ms ({d:.2} sec)\n", .{ self.total_duration_ms, @as(f64, @floatFromInt(self.total_duration_ms)) / 1000.0 });
        try writer.print("Avg message time: {d:.2} ms\n", .{self.avg_message_time_ms});
        try writer.print("Throughput: {d:.2} msg/sec\n", .{self.messages_per_second});

        if (self.errors.items.len > 0) {
            try writer.print("\nErrors ({d}):\n", .{self.errors.items.len});
            for (self.errors.items[0..@min(10, self.errors.items.len)]) |err| {
                try writer.print("  - {s}\n", .{err});
            }
            if (self.errors.items.len > 10) {
                try writer.print("  ... and {d} more\n", .{self.errors.items.len - 10});
            }
        }
    }

    pub fn deinit(self: *LoadTestResult, allocator: std.mem.Allocator) void {
        for (self.errors.items) |err| {
            allocator.free(err);
        }
        self.errors.deinit();
    }
};

/// SMTP load tester
pub const LoadTester = struct {
    allocator: std.mem.Allocator,
    config: LoadTestConfig,

    pub fn init(allocator: std.mem.Allocator, config: LoadTestConfig) LoadTester {
        return .{
            .allocator = allocator,
            .config = config,
        };
    }

    /// Run load test
    pub fn run(self: *LoadTester) !LoadTestResult {
        var result = LoadTestResult{
            .total_messages = self.config.num_connections * self.config.messages_per_connection,
            .successful_messages = 0,
            .failed_messages = 0,
            .total_duration_ms = 0,
            .avg_message_time_ms = 0,
            .messages_per_second = 0,
            .errors = std.ArrayList([]const u8).init(self.allocator),
        };

        const start_time = std.time.milliTimestamp();

        // Run connections in batches
        var completed: usize = 0;
        while (completed < self.config.num_connections) {
            const batch_size = @min(self.config.concurrent_connections, self.config.num_connections - completed);

            // For simplicity, run serially (true concurrent would need threads)
            var i: usize = 0;
            while (i < batch_size) : (i += 1) {
                self.runConnection(&result) catch |err| {
                    const err_msg = try std.fmt.allocPrint(
                        self.allocator,
                        "Connection {d} failed: {any}",
                        .{ completed + i, err },
                    );
                    try result.errors.append(err_msg);
                };
            }

            completed += batch_size;
        }

        const end_time = std.time.milliTimestamp();
        result.total_duration_ms = @as(u64, @intCast(end_time - start_time));

        if (result.successful_messages > 0) {
            result.avg_message_time_ms = @as(f64, @floatFromInt(result.total_duration_ms)) / @as(f64, @floatFromInt(result.successful_messages));
            result.messages_per_second = @as(f64, @floatFromInt(result.successful_messages)) / (@as(f64, @floatFromInt(result.total_duration_ms)) / 1000.0);
        }

        return result;
    }

    fn runConnection(self: *LoadTester, result: *LoadTestResult) !void {
        const address = try std.net.Address.parseIp(self.config.host, self.config.port);
        const stream = try std.net.tcpConnectToAddress(address);
        defer stream.close();

        // Read greeting
        var buf: [512]u8 = undefined;
        _ = try stream.read(&buf);

        var i: usize = 0;
        while (i < self.config.messages_per_connection) : (i += 1) {
            if (self.sendTestMessage(stream)) {
                result.successful_messages += 1;
            } else |err| {
                result.failed_messages += 1;
                const err_msg = try std.fmt.allocPrint(
                    self.allocator,
                    "Message send failed: {any}",
                    .{err},
                );
                try result.errors.append(err_msg);
            }
        }

        // QUIT
        _ = try stream.write("QUIT\r\n");
        _ = try stream.read(&buf);
    }

    fn sendTestMessage(self: *LoadTester, stream: std.net.Stream) !void {
        _ = self;
        var buf: [512]u8 = undefined;

        // EHLO
        _ = try stream.write("EHLO loadtest\r\n");
        _ = try stream.read(&buf);

        // MAIL FROM
        _ = try stream.write("MAIL FROM:<loadtest@example.com>\r\n");
        _ = try stream.read(&buf);

        // RCPT TO
        _ = try stream.write("RCPT TO:<recipient@example.com>\r\n");
        _ = try stream.read(&buf);

        // DATA
        _ = try stream.write("DATA\r\n");
        _ = try stream.read(&buf);

        // Message
        const message =
            \\From: loadtest@example.com
            \\To: recipient@example.com
            \\Subject: Load Test Message
            \\
            \\This is a load test message.
            \\.
            \\
        ;
        _ = try stream.write(message);
        _ = try stream.read(&buf);

        // RSET for next message
        _ = try stream.write("RSET\r\n");
        _ = try stream.read(&buf);
    }
};

/// Main load test program
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = LoadTestConfig{
        .host = "127.0.0.1",
        .port = 2525,
        .num_connections = 10,
        .messages_per_connection = 5,
        .concurrent_connections = 3,
    };

    const stdout = std.io.getStdOut().writer();
    try stdout.print("Starting SMTP load test...\n", .{});
    try stdout.print("Host: {s}:{d}\n", .{ config.host, config.port });
    try stdout.print("Connections: {d}\n", .{config.num_connections});
    try stdout.print("Messages per connection: {d}\n", .{config.messages_per_connection});
    try stdout.print("Concurrent connections: {d}\n", .{config.concurrent_connections});

    var tester = LoadTester.init(allocator, config);
    var result = try tester.run();
    defer result.deinit(allocator);

    try result.print(stdout);
}
