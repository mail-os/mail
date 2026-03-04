const std = @import("std");
const cli = @import("zig-cli");
const benchmark_cli = @import("../benchmark_cli.zig");

fn runAction(ctx: *cli.BaseCommand.ParseContext) !void {
    const output_json = ctx.hasOption("json");
    try benchmark_cli.runBenchmarks(ctx.allocator, output_json);
}

fn listAction(_: *cli.BaseCommand.ParseContext) !void {
    benchmark_cli.listBenchmarks();
}

pub fn setup(allocator: std.mem.Allocator) !*cli.BaseCommand {
    const cmd = try cli.BaseCommand.init(allocator, "benchmark", "Performance benchmarking");

    const run_cmd = try cli.BaseCommand.init(allocator, "run", "Run all benchmarks");
    _ = try run_cmd.addOption(
        cli.Option.init("json", "json", "Output results in JSON format", .bool),
    );
    _ = run_cmd.setAction(runAction);
    _ = try cmd.addCommand(run_cmd);

    const list_cmd = try cli.BaseCommand.init(allocator, "list", "List available benchmarks");
    _ = list_cmd.setAction(listAction);
    _ = try cmd.addCommand(list_cmd);

    return cmd;
}
