const std = @import("std");
const builtin = @import("builtin");
const benchmark = @import("testing/benchmark.zig");

// Re-export benchmark functionality
const Benchmark = benchmark.Benchmark;
const BenchmarkSuite = benchmark.BenchmarkSuite;
const BenchmarkResult = benchmark.BenchmarkResult;
const BenchmarkCategory = benchmark.BenchmarkCategory;
const SMTPBenchmarks = benchmark.SMTPBenchmarks;

// Simple output function using libc write
fn writeOutput(data: []const u8) void {
    _ = std.c.write(1, data.ptr, data.len);
}

fn printLine(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const slice = std.fmt.bufPrint(&buf, fmt, args) catch return;
    writeOutput(slice);
}

pub fn main(init: std.process.Init.Minimal) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Get command line arguments
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const args = try init.args.toSlice(arena.allocator());

    // Parse arguments
    var output_json = false;
    var show_help = false;

    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            output_json = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            show_help = true;
        }
    }

    if (show_help or args.len < 2) {
        writeOutput(
            \\SMTP Server Benchmark Suite
            \\
            \\Usage: benchmark <command> [options]
            \\
            \\Commands:
            \\  run      Run all benchmarks
            \\  list     List available benchmarks
            \\  help     Show this help message
            \\
            \\Options:
            \\  --json   Output results in JSON format (for CI integration)
            \\
            \\Examples:
            \\  benchmark run
            \\  benchmark run --json > results.json
            \\
        );
        return;
    }

    const cmd = args[1];

    if (std.mem.eql(u8, cmd, "run")) {
        var smtp_bench = SMTPBenchmarks.init(allocator);
        try smtp_bench.runAll(output_json);
    } else if (std.mem.eql(u8, cmd, "list")) {
        writeOutput(
            \\Available benchmarks:
            \\  - smtp_protocol: SMTP protocol benchmarks
            \\  - parsing: Parsing benchmarks
            \\  - memory: Memory allocation benchmarks
            \\  - crypto: Cryptographic operation benchmarks
            \\  - connection: Connection handling benchmarks
            \\
        );
    } else {
        printLine("Unknown command: {s}\n", .{cmd});
        writeOutput("Use 'benchmark help' for usage information.\n");
    }
}
