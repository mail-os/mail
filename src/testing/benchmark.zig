const std = @import("std");
const builtin = @import("builtin");
const time_compat = @import("../core/time_compat.zig");

// Simple stdout wrapper using libc write
const StdoutWriter = struct {
    const Self = @This();

    pub const Error = error{Unexpected};
    pub const Writer = std.io.GenericWriter(*Self, Error, write);

    pub fn write(_: *Self, bytes: []const u8) Error!usize {
        const result = std.c.write(1, bytes.ptr, bytes.len);
        if (result < 0) return error.Unexpected;
        return @intCast(result);
    }

    pub fn writeAll(self: *Self, data: []const u8) !void {
        var index: usize = 0;
        while (index < data.len) {
            index += try self.write(data[index..]);
        }
    }

    pub fn print(self: *Self, comptime fmt: []const u8, args: anytype) !void {
        var buf: [8192]u8 = undefined;
        const slice = std.fmt.bufPrint(&buf, fmt, args) catch return error.NoSpaceLeft;
        try self.writeAll(slice);
    }

    pub fn writer(self: *Self) Writer {
        return .{ .context = self };
    }
};

var stdout_instance = StdoutWriter{};

fn getStdoutWriter() *StdoutWriter {
    return &stdout_instance;
}

/// Benchmark categories for grouping
pub const BenchmarkCategory = enum {
    smtp_protocol,
    parsing,
    memory,
    crypto,
    io,
    connection,
    spam_filter,
    storage,

    pub fn toString(self: BenchmarkCategory) []const u8 {
        return switch (self) {
            .smtp_protocol => "SMTP Protocol",
            .parsing => "Parsing",
            .memory => "Memory",
            .crypto => "Cryptography",
            .io => "I/O",
            .connection => "Connection",
            .spam_filter => "Spam Filter",
            .storage => "Storage",
        };
    }
};

/// Benchmark result
pub const BenchmarkResult = struct {
    name: []const u8,
    category: BenchmarkCategory,
    iterations: usize,
    total_duration_ns: u64,
    min_duration_ns: u64,
    max_duration_ns: u64,
    avg_duration_ns: u64,
    median_duration_ns: u64,
    p95_duration_ns: u64,
    p99_duration_ns: u64,
    std_deviation_ns: f64,
    ops_per_second: f64,
    memory_used_bytes: usize,

    pub fn print(self: *const BenchmarkResult, writer: anytype) !void {
        try writer.print("Benchmark: {s} [{s}]\n", .{ self.name, self.category.toString() });
        try writer.print("  Iterations: {d}\n", .{self.iterations});
        try writer.print("  Total time: {d} ns ({d:.2} ms)\n", .{ self.total_duration_ns, @as(f64, @floatFromInt(self.total_duration_ns)) / 1_000_000.0 });
        try writer.print("  Average: {d} ns ({d:.2} μs)\n", .{ self.avg_duration_ns, @as(f64, @floatFromInt(self.avg_duration_ns)) / 1_000.0 });
        try writer.print("  Median: {d} ns ({d:.2} μs)\n", .{ self.median_duration_ns, @as(f64, @floatFromInt(self.median_duration_ns)) / 1_000.0 });
        try writer.print("  P95: {d} ns ({d:.2} μs)\n", .{ self.p95_duration_ns, @as(f64, @floatFromInt(self.p95_duration_ns)) / 1_000.0 });
        try writer.print("  P99: {d} ns ({d:.2} μs)\n", .{ self.p99_duration_ns, @as(f64, @floatFromInt(self.p99_duration_ns)) / 1_000.0 });
        try writer.print("  Min: {d} ns ({d:.2} μs)\n", .{ self.min_duration_ns, @as(f64, @floatFromInt(self.min_duration_ns)) / 1_000.0 });
        try writer.print("  Max: {d} ns ({d:.2} μs)\n", .{ self.max_duration_ns, @as(f64, @floatFromInt(self.max_duration_ns)) / 1_000.0 });
        try writer.print("  Std Dev: {d:.2} ns\n", .{self.std_deviation_ns});
        try writer.print("  Ops/sec: {d:.2}\n", .{self.ops_per_second});
        if (self.memory_used_bytes > 0) {
            try writer.print("  Memory: {d} bytes ({d:.2} KB)\n", .{ self.memory_used_bytes, @as(f64, @floatFromInt(self.memory_used_bytes)) / 1024.0 });
        }
    }

    /// Convert to JSON object
    pub fn toJson(self: *const BenchmarkResult, allocator: std.mem.Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        errdefer buffer.deinit();

        const writer = buffer.writer();
        try writer.print(
            \\{{
            \\  "name": "{s}",
            \\  "category": "{s}",
            \\  "iterations": {d},
            \\  "total_duration_ns": {d},
            \\  "avg_duration_ns": {d},
            \\  "median_duration_ns": {d},
            \\  "p95_duration_ns": {d},
            \\  "p99_duration_ns": {d},
            \\  "min_duration_ns": {d},
            \\  "max_duration_ns": {d},
            \\  "std_deviation_ns": {d:.2},
            \\  "ops_per_second": {d:.2},
            \\  "memory_used_bytes": {d}
            \\}}
        , .{
            self.name,
            self.category.toString(),
            self.iterations,
            self.total_duration_ns,
            self.avg_duration_ns,
            self.median_duration_ns,
            self.p95_duration_ns,
            self.p99_duration_ns,
            self.min_duration_ns,
            self.max_duration_ns,
            self.std_deviation_ns,
            self.ops_per_second,
            self.memory_used_bytes,
        });

        return buffer.toOwnedSlice();
    }
};

/// Benchmark runner with statistical analysis
pub const Benchmark = struct {
    allocator: std.mem.Allocator,
    warmup_iterations: usize = 100,
    iterations: usize = 10000,
    category: BenchmarkCategory = .smtp_protocol,

    pub fn init(allocator: std.mem.Allocator) Benchmark {
        return .{ .allocator = allocator };
    }

    pub fn withCategory(self: *Benchmark, category: BenchmarkCategory) *Benchmark {
        self.category = category;
        return self;
    }

    /// Calculate percentile from sorted durations
    fn calculatePercentile(durations: []u64, percentile: f64) u64 {
        if (durations.len == 0) return 0;
        const index = @as(usize, @intFromFloat(@as(f64, @floatFromInt(durations.len - 1)) * percentile));
        return durations[index];
    }

    /// Calculate standard deviation
    fn calculateStdDev(durations: []u64, mean: u64) f64 {
        if (durations.len == 0) return 0;
        var sum_sq_diff: f64 = 0;
        for (durations) |d| {
            const diff = @as(f64, @floatFromInt(d)) - @as(f64, @floatFromInt(mean));
            sum_sq_diff += diff * diff;
        }
        return @sqrt(sum_sq_diff / @as(f64, @floatFromInt(durations.len)));
    }

    /// Run a benchmark function
    pub fn run(
        self: *Benchmark,
        name: []const u8,
        comptime func: fn () anyerror!void,
    ) !BenchmarkResult {
        // Warmup
        var i: usize = 0;
        while (i < self.warmup_iterations) : (i += 1) {
            try func();
        }

        // Actual benchmark
        var durations = try self.allocator.alloc(u64, self.iterations);
        defer self.allocator.free(durations);

        var total_duration: u64 = 0;
        var min_duration: u64 = std.math.maxInt(u64);
        var max_duration: u64 = 0;

        i = 0;
        while (i < self.iterations) : (i += 1) {
            const start = std.time.nanoTimestamp();
            try func();
            const end = std.time.nanoTimestamp();

            const duration = @as(u64, @intCast(end - start));
            durations[i] = duration;
            total_duration += duration;
            min_duration = @min(min_duration, duration);
            max_duration = @max(max_duration, duration);
        }

        // Sort for percentile calculations
        std.mem.sort(u64, durations, {}, std.sort.asc(u64));

        const avg_duration = total_duration / self.iterations;
        const median = calculatePercentile(durations, 0.5);
        const p95 = calculatePercentile(durations, 0.95);
        const p99 = calculatePercentile(durations, 0.99);
        const std_dev = calculateStdDev(durations, avg_duration);
        const ops_per_second = if (avg_duration > 0)
            1_000_000_000.0 / @as(f64, @floatFromInt(avg_duration))
        else
            0.0;

        return BenchmarkResult{
            .name = name,
            .category = self.category,
            .iterations = self.iterations,
            .total_duration_ns = total_duration,
            .min_duration_ns = min_duration,
            .max_duration_ns = max_duration,
            .avg_duration_ns = avg_duration,
            .median_duration_ns = median,
            .p95_duration_ns = p95,
            .p99_duration_ns = p99,
            .std_deviation_ns = std_dev,
            .ops_per_second = ops_per_second,
            .memory_used_bytes = 0,
        };
    }

    /// Run a benchmark with context
    pub fn runWithContext(
        self: *Benchmark,
        name: []const u8,
        context: anytype,
        comptime func: fn (@TypeOf(context)) anyerror!void,
    ) !BenchmarkResult {
        // Warmup
        var i: usize = 0;
        while (i < self.warmup_iterations) : (i += 1) {
            try func(context);
        }

        // Actual benchmark
        var durations = try self.allocator.alloc(u64, self.iterations);
        defer self.allocator.free(durations);

        var total_duration: u64 = 0;
        var min_duration: u64 = std.math.maxInt(u64);
        var max_duration: u64 = 0;

        i = 0;
        while (i < self.iterations) : (i += 1) {
            const start = time_compat.nanoTimestamp();
            try func(context);
            const end = time_compat.nanoTimestamp();

            const duration = @as(u64, @intCast(end - start));
            durations[i] = duration;
            total_duration += duration;
            min_duration = @min(min_duration, duration);
            max_duration = @max(max_duration, duration);
        }

        // Sort for percentile calculations
        std.mem.sort(u64, durations, {}, std.sort.asc(u64));

        const avg_duration = total_duration / self.iterations;
        const median = calculatePercentile(durations, 0.5);
        const p95 = calculatePercentile(durations, 0.95);
        const p99 = calculatePercentile(durations, 0.99);
        const std_dev = calculateStdDev(durations, avg_duration);
        const ops_per_second = if (avg_duration > 0)
            1_000_000_000.0 / @as(f64, @floatFromInt(avg_duration))
        else
            0.0;

        return BenchmarkResult{
            .name = name,
            .category = self.category,
            .iterations = self.iterations,
            .total_duration_ns = total_duration,
            .min_duration_ns = min_duration,
            .max_duration_ns = max_duration,
            .avg_duration_ns = avg_duration,
            .median_duration_ns = median,
            .p95_duration_ns = p95,
            .p99_duration_ns = p99,
            .std_deviation_ns = std_dev,
            .ops_per_second = ops_per_second,
            .memory_used_bytes = 0,
        };
    }
};

/// Benchmark Suite for collecting and reporting results
pub const BenchmarkSuite = struct {
    allocator: std.mem.Allocator,
    results: std.ArrayList(BenchmarkResult),
    suite_name: []const u8,
    start_time: i64,
    end_time: i64,

    pub fn init(allocator: std.mem.Allocator, name: []const u8) BenchmarkSuite {
        return .{
            .allocator = allocator,
            .results = std.ArrayList(BenchmarkResult){},
            .suite_name = name,
            .start_time = time_compat.timestamp(),
            .end_time = 0,
        };
    }

    pub fn deinit(self: *BenchmarkSuite) void {
        self.results.deinit(self.allocator);
    }

    pub fn addResult(self: *BenchmarkSuite, result: BenchmarkResult) !void {
        try self.results.append(self.allocator, result);
    }

    pub fn finish(self: *BenchmarkSuite) void {
        self.end_time = time_compat.timestamp();
    }

    /// Generate JSON report for CI integration
    pub fn toJson(self: *const BenchmarkSuite) ![]u8 {
        // Calculate total ops for summary
        var total_ops: f64 = 0;
        for (self.results.items) |result| {
            total_ops += result.ops_per_second;
        }

        // Build JSON using fmt.allocPrint
        var json_parts = std.ArrayList(u8){};
        defer json_parts.deinit(self.allocator);

        // Header
        const header = try std.fmt.allocPrint(self.allocator,
            \\{{"suite":"{s}","timestamp":{d},"duration_seconds":{d},"total_benchmarks":{d},"benchmarks":[
        , .{
            self.suite_name,
            self.start_time,
            self.end_time - self.start_time,
            self.results.items.len,
        });
        defer self.allocator.free(header);
        try json_parts.appendSlice(self.allocator, header);

        // Benchmarks array
        for (self.results.items, 0..) |result, i| {
            if (i > 0) try json_parts.append(self.allocator, ',');
            const bench_json = try std.fmt.allocPrint(self.allocator,
                \\{{"name":"{s}","category":"{s}","iterations":{d},"avg_ns":{d},"median_ns":{d},"p95_ns":{d},"p99_ns":{d},"min_ns":{d},"max_ns":{d},"std_dev_ns":{d:.0},"ops_per_sec":{d:.0}}}
            , .{
                result.name,
                result.category.toString(),
                result.iterations,
                result.avg_duration_ns,
                result.median_duration_ns,
                result.p95_duration_ns,
                result.p99_duration_ns,
                result.min_duration_ns,
                result.max_duration_ns,
                result.std_deviation_ns,
                result.ops_per_second,
            });
            defer self.allocator.free(bench_json);
            try json_parts.appendSlice(self.allocator, bench_json);
        }

        // Footer with summary
        const footer = try std.fmt.allocPrint(self.allocator,
            \\],"summary":{{"total_benchmarks":{d},"total_ops_per_sec":{d:.0}}}}}
        , .{
            self.results.items.len,
            total_ops,
        });
        defer self.allocator.free(footer);
        try json_parts.appendSlice(self.allocator, footer);

        return try json_parts.toOwnedSlice(self.allocator);
    }

    /// Print human-readable report
    pub fn printReport(self: *const BenchmarkSuite, writer: anytype) !void {
        try writer.print("\n========== {s} Benchmark Suite ==========\n\n", .{self.suite_name});
        try writer.print("Total benchmarks: {d}\n", .{self.results.items.len});
        try writer.print("Duration: {d}s\n\n", .{self.end_time - self.start_time});

        // Group by category
        var current_category: ?BenchmarkCategory = null;
        for (self.results.items) |result| {
            if (current_category == null or current_category.? != result.category) {
                current_category = result.category;
                try writer.print("\n--- {s} ---\n\n", .{result.category.toString()});
            }
            try result.print(writer);
            try writer.writeAll("\n");
        }

        // Summary
        try writer.print("\n========== Summary ==========\n", .{});
        var total_ops: f64 = 0;
        for (self.results.items) |result| {
            total_ops += result.ops_per_second;
        }
        try writer.print("Combined throughput: {d:.2} ops/sec\n", .{total_ops});
    }
};

/// SMTP-specific benchmarks
pub const SMTPBenchmarks = struct {
    allocator: std.mem.Allocator,
    suite: ?*BenchmarkSuite,

    pub fn init(allocator: std.mem.Allocator) SMTPBenchmarks {
        return .{ .allocator = allocator, .suite = null };
    }

    pub fn withSuite(self: *SMTPBenchmarks, suite: *BenchmarkSuite) *SMTPBenchmarks {
        self.suite = suite;
        return self;
    }

    /// Benchmark email address validation
    pub fn benchmarkEmailValidation(self: *SMTPBenchmarks) !void {
        _ = self;
        // Simple email validation benchmark
        const email = "test@example.com";
        _ = std.mem.indexOf(u8, email, "@");
    }

    /// Benchmark complex email validation
    pub fn benchmarkComplexEmailValidation(self: *SMTPBenchmarks) !void {
        _ = self;
        // Complex email validation benchmark
        const email = "user.name+tag@subdomain.example.co.uk";
        _ = std.mem.indexOf(u8, email, "@");
    }

    /// Benchmark base64 decoding
    pub fn benchmarkBase64Decode(self: *SMTPBenchmarks) !void {
        const test_data = "dGVzdEB1c2VyOnBhc3N3b3Jk"; // "test@user:password"
        const decoder = std.base64.standard.Decoder;
        const decoded_len = try decoder.calcSizeForSlice(test_data);
        const decoded = try self.allocator.alloc(u8, decoded_len);
        defer self.allocator.free(decoded);
        try decoder.decode(decoded, test_data);
    }

    /// Benchmark large base64 decoding
    pub fn benchmarkLargeBase64Decode(self: *SMTPBenchmarks) !void {
        // Simulated 1KB base64 data
        const test_data = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=" ** 10;
        const decoder = std.base64.standard.Decoder;
        const decoded_len = try decoder.calcSizeForSlice(test_data);
        const decoded = try self.allocator.alloc(u8, decoded_len);
        defer self.allocator.free(decoded);
        try decoder.decode(decoded, test_data);
    }

    /// Benchmark string parsing
    pub fn benchmarkCommandParsing(self: *SMTPBenchmarks) !void {
        _ = self;
        const line = "MAIL FROM:<sender@example.com>";
        var it = std.mem.splitScalar(u8, line, ' ');
        _ = it.next(); // MAIL
        _ = it.next(); // FROM:<...>
    }

    /// Benchmark EHLO response parsing
    pub fn benchmarkEhloResponseParsing(self: *SMTPBenchmarks) !void {
        _ = self;
        const response =
            \\250-mail.example.com
            \\250-SIZE 52428800
            \\250-8BITMIME
            \\250-PIPELINING
            \\250-AUTH PLAIN LOGIN
            \\250 STARTTLS
        ;
        var it = std.mem.splitSequence(u8, response, "\r\n");
        while (it.next()) |_| {}
    }

    /// Benchmark header parsing
    pub fn benchmarkHeaderParsing(self: *SMTPBenchmarks) !void {
        _ = self;
        const header = "Content-Type: multipart/mixed; boundary=\"----=_Part_123\"";
        if (std.mem.indexOf(u8, header, ":")) |colon_pos| {
            _ = header[0..colon_pos]; // key
            _ = std.mem.trim(u8, header[colon_pos + 1 ..], " "); // value
        }
    }

    /// Benchmark memory allocation
    pub fn benchmarkAllocation(self: *SMTPBenchmarks) !void {
        const data = try self.allocator.alloc(u8, 1024);
        defer self.allocator.free(data);
    }

    /// Benchmark larger memory allocation (64KB - typical email size)
    pub fn benchmarkLargeAllocation(self: *SMTPBenchmarks) !void {
        const data = try self.allocator.alloc(u8, 65536);
        defer self.allocator.free(data);
    }

    /// Benchmark hash map operations (for connection tracking)
    pub fn benchmarkHashMapOps(self: *SMTPBenchmarks) !void {
        var map = std.StringHashMap(u64).init(self.allocator);
        defer map.deinit();

        try map.put("127.0.0.1", 1);
        _ = map.get("127.0.0.1");
        _ = map.remove("127.0.0.1");
    }

    /// Run all SMTP benchmarks
    pub fn runAll(self: *SMTPBenchmarks, output_json: bool) !void {
        var bench = Benchmark.init(self.allocator);
        bench.iterations = 10000;

        const stdout = getStdoutWriter();

        var suite = BenchmarkSuite.init(self.allocator, "SMTP Server");
        defer suite.deinit();

        // Protocol benchmarks
        bench.category = .smtp_protocol;

        const email_result = try bench.runWithContext(
            "Email Validation (Simple)",
            self,
            SMTPBenchmarks.benchmarkEmailValidation,
        );
        try suite.addResult(email_result);

        const complex_email_result = try bench.runWithContext(
            "Email Validation (Complex)",
            self,
            SMTPBenchmarks.benchmarkComplexEmailValidation,
        );
        try suite.addResult(complex_email_result);

        const cmd_result = try bench.runWithContext(
            "SMTP Command Parsing",
            self,
            SMTPBenchmarks.benchmarkCommandParsing,
        );
        try suite.addResult(cmd_result);

        const ehlo_result = try bench.runWithContext(
            "EHLO Response Parsing",
            self,
            SMTPBenchmarks.benchmarkEhloResponseParsing,
        );
        try suite.addResult(ehlo_result);

        // Parsing benchmarks
        bench.category = .parsing;

        const header_result = try bench.runWithContext(
            "Header Parsing",
            self,
            SMTPBenchmarks.benchmarkHeaderParsing,
        );
        try suite.addResult(header_result);

        // Crypto benchmarks
        bench.category = .crypto;

        const base64_result = try bench.runWithContext(
            "Base64 Decode (Small)",
            self,
            SMTPBenchmarks.benchmarkBase64Decode,
        );
        try suite.addResult(base64_result);

        const large_base64_result = try bench.runWithContext(
            "Base64 Decode (Large)",
            self,
            SMTPBenchmarks.benchmarkLargeBase64Decode,
        );
        try suite.addResult(large_base64_result);

        // Memory benchmarks
        bench.category = .memory;

        const alloc_result = try bench.runWithContext(
            "Memory Allocation (1KB)",
            self,
            SMTPBenchmarks.benchmarkAllocation,
        );
        try suite.addResult(alloc_result);

        const large_alloc_result = try bench.runWithContext(
            "Memory Allocation (64KB)",
            self,
            SMTPBenchmarks.benchmarkLargeAllocation,
        );
        try suite.addResult(large_alloc_result);

        // Connection benchmarks
        bench.category = .connection;

        const hashmap_result = try bench.runWithContext(
            "Connection HashMap Ops",
            self,
            SMTPBenchmarks.benchmarkHashMapOps,
        );
        try suite.addResult(hashmap_result);

        suite.finish();

        if (output_json) {
            const json = try suite.toJson();
            defer self.allocator.free(json);
            try stdout.writeAll(json);
            try stdout.writeAll("\n");
        } else {
            try suite.printReport(stdout);
        }
    }
};

/// Throughput benchmark for measuring messages per second
pub const ThroughputBenchmark = struct {
    allocator: std.mem.Allocator,
    target_duration_ms: u64 = 5000, // Run for 5 seconds

    pub fn init(allocator: std.mem.Allocator) ThroughputBenchmark {
        return .{ .allocator = allocator };
    }

    /// Measure throughput of an operation
    pub fn measure(
        self: *ThroughputBenchmark,
        name: []const u8,
        comptime func: fn () anyerror!void,
    ) !ThroughputResult {
        const start = std.time.milliTimestamp();
        var operations: u64 = 0;

        while (std.time.milliTimestamp() - start < @as(i64, @intCast(self.target_duration_ms))) {
            try func();
            operations += 1;
        }

        const actual_duration_ms = @as(u64, @intCast(std.time.milliTimestamp() - start));
        const ops_per_second = @as(f64, @floatFromInt(operations)) * 1000.0 / @as(f64, @floatFromInt(actual_duration_ms));

        return ThroughputResult{
            .name = name,
            .operations = operations,
            .duration_ms = actual_duration_ms,
            .ops_per_second = ops_per_second,
        };
    }
};

pub const ThroughputResult = struct {
    name: []const u8,
    operations: u64,
    duration_ms: u64,
    ops_per_second: f64,

    pub fn print(self: *const ThroughputResult, writer: anytype) !void {
        try writer.print("Throughput: {s}\n", .{self.name});
        try writer.print("  Operations: {d}\n", .{self.operations});
        try writer.print("  Duration: {d}ms\n", .{self.duration_ms});
        try writer.print("  Throughput: {d:.2} ops/sec\n", .{self.ops_per_second});
    }
};

/// Memory usage tracker
pub const MemoryTracker = struct {
    initial_bytes: usize,
    peak_bytes: usize,
    current_bytes: usize,
    allocations: usize,
    deallocations: usize,

    pub fn init() MemoryTracker {
        return .{
            .initial_bytes = 0,
            .peak_bytes = 0,
            .current_bytes = 0,
            .allocations = 0,
            .deallocations = 0,
        };
    }

    pub fn recordAllocation(self: *MemoryTracker, bytes: usize) void {
        self.current_bytes += bytes;
        self.allocations += 1;
        if (self.current_bytes > self.peak_bytes) {
            self.peak_bytes = self.current_bytes;
        }
    }

    pub fn recordDeallocation(self: *MemoryTracker, bytes: usize) void {
        self.current_bytes -= bytes;
        self.deallocations += 1;
    }

    pub fn report(self: *const MemoryTracker, writer: anytype) !void {
        try writer.print("Memory Usage:\n", .{});
        try writer.print("  Peak: {d} bytes ({d:.2} KB)\n", .{ self.peak_bytes, @as(f64, @floatFromInt(self.peak_bytes)) / 1024.0 });
        try writer.print("  Current: {d} bytes\n", .{self.current_bytes});
        try writer.print("  Allocations: {d}\n", .{self.allocations});
        try writer.print("  Deallocations: {d}\n", .{self.deallocations});
    }
};

/// Comparison report for regression detection
pub const ComparisonReport = struct {
    baseline_file: []const u8,
    current_results: *const BenchmarkSuite,
    regressions: std.ArrayList(Regression),
    improvements: std.ArrayList(Improvement),

    pub const Regression = struct {
        benchmark_name: []const u8,
        baseline_ops: f64,
        current_ops: f64,
        percentage_change: f64,
    };

    pub const Improvement = struct {
        benchmark_name: []const u8,
        baseline_ops: f64,
        current_ops: f64,
        percentage_change: f64,
    };

    pub fn init(allocator: std.mem.Allocator, baseline: []const u8, current: *const BenchmarkSuite) ComparisonReport {
        return .{
            .baseline_file = baseline,
            .current_results = current,
            .regressions = std.ArrayList(Regression).init(allocator),
            .improvements = std.ArrayList(Improvement).init(allocator),
        };
    }

    pub fn deinit(self: *ComparisonReport) void {
        self.regressions.deinit();
        self.improvements.deinit();
    }

    pub fn hasRegressions(self: *const ComparisonReport) bool {
        return self.regressions.items.len > 0;
    }

    pub fn printReport(self: *const ComparisonReport, writer: anytype) !void {
        try writer.print("\n=== Performance Comparison Report ===\n\n", .{});

        if (self.regressions.items.len > 0) {
            try writer.print("REGRESSIONS DETECTED:\n", .{});
            for (self.regressions.items) |reg| {
                try writer.print("  - {s}: {d:.2} -> {d:.2} ops/sec ({d:.1}%)\n", .{
                    reg.benchmark_name,
                    reg.baseline_ops,
                    reg.current_ops,
                    reg.percentage_change,
                });
            }
        } else {
            try writer.print("No regressions detected.\n", .{});
        }

        if (self.improvements.items.len > 0) {
            try writer.print("\nIMPROVEMENTS:\n", .{});
            for (self.improvements.items) |imp| {
                try writer.print("  + {s}: {d:.2} -> {d:.2} ops/sec (+{d:.1}%)\n", .{
                    imp.benchmark_name,
                    imp.baseline_ops,
                    imp.current_ops,
                    imp.percentage_change,
                });
            }
        }
    }
};

/// CLI for running benchmarks
pub const BenchmarkCli = struct {
    allocator: std.mem.Allocator,

    pub const Command = enum {
        run,
        compare,
        list,
        help,
    };

    pub fn init(allocator: std.mem.Allocator) BenchmarkCli {
        return .{ .allocator = allocator };
    }

    pub fn parseCommand(args: []const []const u8) Command {
        if (args.len < 1) return .help;

        if (std.mem.eql(u8, args[0], "run")) return .run;
        if (std.mem.eql(u8, args[0], "compare")) return .compare;
        if (std.mem.eql(u8, args[0], "list")) return .list;
        return .help;
    }

    pub fn execute(self: *BenchmarkCli, args: []const []const u8) !void {
        const stdout = getStdoutWriter();

        // Check for --json flag
        var output_json = false;
        for (args) |arg| {
            if (std.mem.eql(u8, arg, "--json")) {
                output_json = true;
                break;
            }
        }

        const cmd = parseCommand(args);

        switch (cmd) {
            .run => {
                var smtp_bench = SMTPBenchmarks.init(self.allocator);
                try smtp_bench.runAll(output_json);
            },
            .compare => {
                if (args.len < 2) {
                    try stdout.print("Usage: benchmark compare <baseline.json>\n", .{});
                    return;
                }
                try stdout.print("Comparison not yet implemented - would compare against: {s}\n", .{args[1]});
            },
            .list => {
                try stdout.print("Available benchmarks:\n", .{});
                try stdout.print("  - smtp: SMTP protocol benchmarks\n", .{});
                try stdout.print("  - parsing: Parsing benchmarks\n", .{});
                try stdout.print("  - memory: Memory allocation benchmarks\n", .{});
                try stdout.print("  - crypto: Cryptographic operation benchmarks\n", .{});
            },
            .help => {
                try stdout.print(
                    \\SMTP Server Benchmark Suite
                    \\
                    \\Usage: benchmark <command> [options]
                    \\
                    \\Commands:
                    \\  run      Run all benchmarks
                    \\  compare  Compare results against baseline
                    \\  list     List available benchmarks
                    \\  help     Show this help message
                    \\
                    \\Options:
                    \\  --json   Output results in JSON format (for CI integration)
                    \\
                    \\Examples:
                    \\  benchmark run
                    \\  benchmark run --json > results.json
                    \\  benchmark compare baseline.json
                    \\
                , .{});
            },
        }
    }
};

test "benchmark framework" {
    const testing = std.testing;
    var bench = Benchmark.init(testing.allocator);
    bench.iterations = 100;
    bench.warmup_iterations = 10;

    const TestContext = struct {
        fn testFunc(_: @This()) !void {
            var x: u64 = 0;
            var i: usize = 0;
            while (i < 100) : (i += 1) {
                x += i;
            }
        }
    };

    const result = try bench.runWithContext("test", TestContext{}, TestContext.testFunc);
    try testing.expect(result.iterations == 100);
    try testing.expect(result.avg_duration_ns > 0);
    try testing.expect(result.ops_per_second > 0);
    try testing.expect(result.median_duration_ns > 0);
    try testing.expect(result.p95_duration_ns >= result.median_duration_ns);
    try testing.expect(result.p99_duration_ns >= result.p95_duration_ns);
}

test "benchmark suite json output" {
    const testing = std.testing;

    var suite = BenchmarkSuite.init(testing.allocator, "Test Suite");
    defer suite.deinit();

    // Add a mock result
    try suite.addResult(.{
        .name = "Test Benchmark",
        .category = .smtp_protocol,
        .iterations = 1000,
        .total_duration_ns = 1000000,
        .min_duration_ns = 500,
        .max_duration_ns = 2000,
        .avg_duration_ns = 1000,
        .median_duration_ns = 950,
        .p95_duration_ns = 1800,
        .p99_duration_ns = 1950,
        .std_deviation_ns = 150.0,
        .ops_per_second = 1000000.0,
        .memory_used_bytes = 0,
    });

    suite.finish();

    const json = try suite.toJson();
    defer testing.allocator.free(json);

    try testing.expect(json.len > 0);
    try testing.expect(std.mem.indexOf(u8, json, "Test Benchmark") != null);
    try testing.expect(std.mem.indexOf(u8, json, "SMTP Protocol") != null);
}

test "memory tracker" {
    var tracker = MemoryTracker.init();

    tracker.recordAllocation(1024);
    try std.testing.expect(tracker.current_bytes == 1024);
    try std.testing.expect(tracker.peak_bytes == 1024);
    try std.testing.expect(tracker.allocations == 1);

    tracker.recordAllocation(2048);
    try std.testing.expect(tracker.current_bytes == 3072);
    try std.testing.expect(tracker.peak_bytes == 3072);

    tracker.recordDeallocation(1024);
    try std.testing.expect(tracker.current_bytes == 2048);
    try std.testing.expect(tracker.peak_bytes == 3072); // Peak unchanged
    try std.testing.expect(tracker.deallocations == 1);
}

test "benchmark category strings" {
    try std.testing.expectEqualStrings("SMTP Protocol", BenchmarkCategory.smtp_protocol.toString());
    try std.testing.expectEqualStrings("Memory", BenchmarkCategory.memory.toString());
    try std.testing.expectEqualStrings("Cryptography", BenchmarkCategory.crypto.toString());
    try std.testing.expectEqualStrings("I/O", BenchmarkCategory.io.toString());
}

test "cli command parsing" {
    const run_args = [_][]const u8{"run"};
    try std.testing.expect(BenchmarkCli.parseCommand(&run_args) == .run);

    const compare_args = [_][]const u8{"compare"};
    try std.testing.expect(BenchmarkCli.parseCommand(&compare_args) == .compare);

    const empty_args = [_][]const u8{};
    try std.testing.expect(BenchmarkCli.parseCommand(&empty_args) == .help);
}
