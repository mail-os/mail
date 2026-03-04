const std = @import("std");
const builtin = @import("builtin");
const benchmark = @import("testing/benchmark.zig");

const SMTPBenchmarks = benchmark.SMTPBenchmarks;

fn writeOutput(data: []const u8) void {
    _ = std.c.write(1, data.ptr, data.len);
}

pub fn runBenchmarks(allocator: std.mem.Allocator, output_json: bool) !void {
    var smtp_bench = SMTPBenchmarks.init(allocator);
    try smtp_bench.runAll(output_json);
}

pub fn listBenchmarks() void {
    writeOutput(
        \\Available benchmarks:
        \\  - smtp_protocol: SMTP protocol benchmarks
        \\  - parsing: Parsing benchmarks
        \\  - memory: Memory allocation benchmarks
        \\  - crypto: Cryptographic operation benchmarks
        \\  - connection: Connection handling benchmarks
        \\
    );
}
