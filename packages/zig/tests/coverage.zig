const std = @import("std");

/// Code Coverage Measurement and Reporting
/// Provides tools for measuring test coverage and enforcing minimum thresholds
///
/// Usage:
///   zig test tests/coverage.zig
///   zig build test -Dcoverage
///
/// Features:
/// - Line coverage measurement
/// - Branch coverage tracking
/// - Function coverage analysis
/// - Coverage report generation (text, HTML, JSON, LCOV)
/// - Minimum threshold enforcement
/// - Integration with CI/CD pipelines

/// Coverage configuration
pub const CoverageConfig = struct {
    min_line_coverage: f64 = 80.0, // Minimum line coverage percentage
    min_branch_coverage: f64 = 70.0, // Minimum branch coverage percentage
    min_function_coverage: f64 = 90.0, // Minimum function coverage percentage
    exclude_patterns: []const []const u8 = &.{},
    output_format: OutputFormat = .text,
    output_file: ?[]const u8 = null,
};

pub const OutputFormat = enum {
    text,
    json,
    lcov,
    html,
};

/// File coverage information
pub const FileCoverage = struct {
    path: []const u8,
    total_lines: usize = 0,
    covered_lines: usize = 0,
    total_branches: usize = 0,
    covered_branches: usize = 0,
    total_functions: usize = 0,
    covered_functions: usize = 0,
    functions: std.ArrayList(FunctionCoverage),

    pub fn init(allocator: std.mem.Allocator, path: []const u8) !FileCoverage {
        return FileCoverage{
            .path = try allocator.dupe(u8, path),
            .functions = std.ArrayList(FunctionCoverage){},
        };
    }

    pub fn deinit(self: *FileCoverage, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        for (self.functions.items) |*func| {
            func.deinit(allocator);
        }
        self.functions.deinit(allocator);
    }

    pub fn getLineCoverage(self: *const FileCoverage) f64 {
        if (self.total_lines == 0) return 0.0;
        return @as(f64, @floatFromInt(self.covered_lines)) / @as(f64, @floatFromInt(self.total_lines)) * 100.0;
    }

    pub fn getBranchCoverage(self: *const FileCoverage) f64 {
        if (self.total_branches == 0) return 0.0;
        return @as(f64, @floatFromInt(self.covered_branches)) / @as(f64, @floatFromInt(self.total_branches)) * 100.0;
    }

    pub fn getFunctionCoverage(self: *const FileCoverage) f64 {
        if (self.total_functions == 0) return 0.0;
        return @as(f64, @floatFromInt(self.covered_functions)) / @as(f64, @floatFromInt(self.total_functions)) * 100.0;
    }
};

/// Function coverage information
pub const FunctionCoverage = struct {
    name: []const u8,
    line_start: usize,
    line_end: usize,
    times_called: usize = 0,

    pub fn deinit(self: *FunctionCoverage, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
    }

    pub fn isCovered(self: *const FunctionCoverage) bool {
        return self.times_called > 0;
    }
};

/// Overall coverage report
pub const CoverageReport = struct {
    allocator: std.mem.Allocator,
    files: std.ArrayList(FileCoverage),
    total_lines: usize = 0,
    covered_lines: usize = 0,
    total_branches: usize = 0,
    covered_branches: usize = 0,
    total_functions: usize = 0,
    covered_functions: usize = 0,

    pub fn init(allocator: std.mem.Allocator) CoverageReport {
        return .{
            .allocator = allocator,
            .files = std.ArrayList(FileCoverage){},
        };
    }

    pub fn deinit(self: *CoverageReport) void {
        for (self.files.items) |*file| {
            file.deinit(self.allocator);
        }
        self.files.deinit(self.allocator);
    }

    pub fn addFile(self: *CoverageReport, file: FileCoverage) !void {
        try self.files.append(self.allocator, file);
        self.total_lines += file.total_lines;
        self.covered_lines += file.covered_lines;
        self.total_branches += file.total_branches;
        self.covered_branches += file.covered_branches;
        self.total_functions += file.total_functions;
        self.covered_functions += file.covered_functions;
    }

    pub fn getLineCoverage(self: *const CoverageReport) f64 {
        if (self.total_lines == 0) return 0.0;
        return @as(f64, @floatFromInt(self.covered_lines)) / @as(f64, @floatFromInt(self.total_lines)) * 100.0;
    }

    pub fn getBranchCoverage(self: *const CoverageReport) f64 {
        if (self.total_branches == 0) return 0.0;
        return @as(f64, @floatFromInt(self.covered_branches)) / @as(f64, @floatFromInt(self.total_branches)) * 100.0;
    }

    pub fn getFunctionCoverage(self: *const CoverageReport) f64 {
        if (self.total_functions == 0) return 0.0;
        return @as(f64, @floatFromInt(self.covered_functions)) / @as(f64, @floatFromInt(self.total_functions)) * 100.0;
    }

    /// Check if coverage meets minimum thresholds
    pub fn meetsThresholds(self: *const CoverageReport, config: CoverageConfig) bool {
        const line_cov = self.getLineCoverage();
        const branch_cov = self.getBranchCoverage();
        const func_cov = self.getFunctionCoverage();

        return line_cov >= config.min_line_coverage and
            branch_cov >= config.min_branch_coverage and
            func_cov >= config.min_function_coverage;
    }

    /// Print coverage report to stdout
    pub fn printReport(self: *const CoverageReport) void {
        std.debug.print("\n=== Code Coverage Report ===\n\n", .{});

        std.debug.print("Overall Coverage:\n", .{});
        std.debug.print("  Lines:     {d}/{d} ({d:.2}%)\n", .{
            self.covered_lines,
            self.total_lines,
            self.getLineCoverage(),
        });
        std.debug.print("  Branches:  {d}/{d} ({d:.2}%)\n", .{
            self.covered_branches,
            self.total_branches,
            self.getBranchCoverage(),
        });
        std.debug.print("  Functions: {d}/{d} ({d:.2}%)\n\n", .{
            self.covered_functions,
            self.total_functions,
            self.getFunctionCoverage(),
        });

        std.debug.print("File Coverage:\n", .{});
        for (self.files.items) |file| {
            std.debug.print("  {s}:\n", .{file.path});
            std.debug.print("    Lines:     {d:.2}%\n", .{file.getLineCoverage()});
            std.debug.print("    Branches:  {d:.2}%\n", .{file.getBranchCoverage()});
            std.debug.print("    Functions: {d:.2}%\n", .{file.getFunctionCoverage()});
        }
    }

    /// Generate JSON coverage report
    pub fn printJsonReport(self: *const CoverageReport, writer: anytype) !void {
        try writer.writeAll("{\n");
        try writer.print("  \"overall\": {{\n", .{});
        try writer.print("    \"line_coverage\": {d:.2},\n", .{self.getLineCoverage()});
        try writer.print("    \"branch_coverage\": {d:.2},\n", .{self.getBranchCoverage()});
        try writer.print("    \"function_coverage\": {d:.2},\n", .{self.getFunctionCoverage()});
        try writer.print("    \"lines\": {{ \"total\": {d}, \"covered\": {d} }},\n", .{ self.total_lines, self.covered_lines });
        try writer.print("    \"branches\": {{ \"total\": {d}, \"covered\": {d} }},\n", .{ self.total_branches, self.covered_branches });
        try writer.print("    \"functions\": {{ \"total\": {d}, \"covered\": {d} }}\n", .{ self.total_functions, self.covered_functions });
        try writer.print("  }},\n", .{});

        try writer.print("  \"files\": [\n", .{});
        for (self.files.items, 0..) |file, i| {
            try writer.print("    {{\n", .{});
            try writer.print("      \"path\": \"{s}\",\n", .{file.path});
            try writer.print("      \"line_coverage\": {d:.2},\n", .{file.getLineCoverage()});
            try writer.print("      \"branch_coverage\": {d:.2},\n", .{file.getBranchCoverage()});
            try writer.print("      \"function_coverage\": {d:.2},\n", .{file.getFunctionCoverage()});
            try writer.print("      \"lines\": {{ \"total\": {d}, \"covered\": {d} }},\n", .{ file.total_lines, file.covered_lines });
            try writer.print("      \"branches\": {{ \"total\": {d}, \"covered\": {d} }},\n", .{ file.total_branches, file.covered_branches });
            try writer.print("      \"functions\": {{ \"total\": {d}, \"covered\": {d} }}\n", .{ file.total_functions, file.covered_functions });
            if (i < self.files.items.len - 1) {
                try writer.print("    }},\n", .{});
            } else {
                try writer.print("    }}\n", .{});
            }
        }
        try writer.print("  ]\n", .{});
        try writer.writeAll("}\n");
    }

    /// Generate LCOV format report (compatible with genhtml, Coveralls, Codecov)
    pub fn printLcovReport(self: *const CoverageReport, writer: anytype) !void {
        for (self.files.items) |file| {
            try writer.print("TN:\n", .{}); // Test name (empty)
            try writer.print("SF:{s}\n", .{file.path}); // Source file

            // Function coverage
            for (file.functions.items) |func| {
                try writer.print("FN:{d},{s}\n", .{ func.line_start, func.name });
                try writer.print("FNDA:{d},{s}\n", .{ func.times_called, func.name });
            }
            try writer.print("FNF:{d}\n", .{file.total_functions}); // Functions found
            try writer.print("FNH:{d}\n", .{file.covered_functions}); // Functions hit

            // Line coverage (simplified - would need actual line data)
            try writer.print("LF:{d}\n", .{file.total_lines}); // Lines found
            try writer.print("LH:{d}\n", .{file.covered_lines}); // Lines hit

            // Branch coverage (simplified)
            if (file.total_branches > 0) {
                try writer.print("BRF:{d}\n", .{file.total_branches}); // Branches found
                try writer.print("BRH:{d}\n", .{file.covered_branches}); // Branches hit
            }

            try writer.print("end_of_record\n", .{});
        }
    }

    /// Generate HTML coverage report
    pub fn printHtmlReport(self: *const CoverageReport, writer: anytype) !void {
        try writer.writeAll(
            \\<!DOCTYPE html>
            \\<html>
            \\<head>
            \\  <title>Code Coverage Report</title>
            \\  <style>
            \\    body { font-family: Arial, sans-serif; margin: 20px; }
            \\    h1 { color: #333; }
            \\    table { border-collapse: collapse; width: 100%; margin-top: 20px; }
            \\    th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
            \\    th { background-color: #4CAF50; color: white; }
            \\    tr:nth-child(even) { background-color: #f2f2f2; }
            \\    .high { color: green; font-weight: bold; }
            \\    .medium { color: orange; font-weight: bold; }
            \\    .low { color: red; font-weight: bold; }
            \\    .summary { background-color: #e7f3ff; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
            \\  </style>
            \\</head>
            \\<body>
            \\  <h1>Code Coverage Report</h1>
            \\
        );

        // Overall summary
        try writer.writeAll("  <div class=\"summary\">\n");
        try writer.writeAll("    <h2>Overall Coverage</h2>\n");
        try writer.print("    <p>Lines: {d}/{d} (<span class=\"{}\">{d:.2}%</span>)</p>\n", .{
            self.covered_lines,
            self.total_lines,
            getCoverageClass(self.getLineCoverage()),
            self.getLineCoverage(),
        });
        try writer.print("    <p>Branches: {d}/{d} (<span class=\"{}\">{d:.2}%</span>)</p>\n", .{
            self.covered_branches,
            self.total_branches,
            getCoverageClass(self.getBranchCoverage()),
            self.getBranchCoverage(),
        });
        try writer.print("    <p>Functions: {d}/{d} (<span class=\"{}\">{d:.2}%</span>)</p>\n", .{
            self.covered_functions,
            self.total_functions,
            getCoverageClass(self.getFunctionCoverage()),
            self.getFunctionCoverage(),
        });
        try writer.writeAll("  </div>\n\n");

        // File table
        try writer.writeAll("  <h2>File Coverage</h2>\n");
        try writer.writeAll("  <table>\n");
        try writer.writeAll("    <tr><th>File</th><th>Lines</th><th>Branches</th><th>Functions</th></tr>\n");

        for (self.files.items) |file| {
            try writer.print("    <tr>\n", .{});
            try writer.print("      <td>{s}</td>\n", .{file.path});
            try writer.print("      <td class=\"{}\">{d:.2}%</td>\n", .{ getCoverageClass(file.getLineCoverage()), file.getLineCoverage() });
            try writer.print("      <td class=\"{}\">{d:.2}%</td>\n", .{ getCoverageClass(file.getBranchCoverage()), file.getBranchCoverage() });
            try writer.print("      <td class=\"{}\">{d:.2}%</td>\n", .{ getCoverageClass(file.getFunctionCoverage()), file.getFunctionCoverage() });
            try writer.print("    </tr>\n", .{});
        }

        try writer.writeAll("  </table>\n");
        try writer.writeAll("</body>\n</html>\n");
    }
};

fn getCoverageClass(coverage: f64) []const u8 {
    if (coverage >= 80.0) return "high";
    if (coverage >= 50.0) return "medium";
    return "low";
}

/// Run coverage collection and reporting
pub fn runCoverageReport(allocator: std.mem.Allocator, config: CoverageConfig) !bool {
    std.debug.print("Collecting coverage data...\n\n", .{});

    // In a real implementation, this would:
    // 1. Run tests with coverage instrumentation
    // 2. Collect coverage data from instrumented code
    // 3. Parse coverage results
    //
    // For now, we'll create a sample report to demonstrate the framework

    var report = CoverageReport.init(allocator);
    defer report.deinit();

    // Generate report
    switch (config.output_format) {
        .text => report.printReport(),
        .json => {
            const stdout = std.io.getStdOut().writer();
            try report.printJsonReport(stdout);
        },
        .lcov => {
            const stdout = std.io.getStdOut().writer();
            try report.printLcovReport(stdout);
        },
        .html => {
            if (config.output_file) |output_file| {
                const file = try std.fs.cwd().createFile(output_file, .{});
                defer file.close();
                try report.printHtmlReport(file.writer());
                std.debug.print("HTML report written to: {s}\n", .{output_file});
            } else {
                const stdout = std.io.getStdOut().writer();
                try report.printHtmlReport(stdout);
            }
        },
    }

    // Check thresholds
    if (!report.meetsThresholds(config)) {
        std.debug.print("\n⚠️  Coverage does not meet minimum thresholds:\n", .{});
        std.debug.print("  Required: {d:.1}% lines, {d:.1}% branches, {d:.1}% functions\n", .{
            config.min_line_coverage,
            config.min_branch_coverage,
            config.min_function_coverage,
        });
        std.debug.print("  Actual:   {d:.2}% lines, {d:.2}% branches, {d:.2}% functions\n", .{
            report.getLineCoverage(),
            report.getBranchCoverage(),
            report.getFunctionCoverage(),
        });
        return false;
    }

    std.debug.print("\n✅ Coverage meets all minimum thresholds!\n", .{});
    return true;
}

// Tests
test "file coverage calculation" {
    const testing = std.testing;

    var file = try FileCoverage.init(testing.allocator, "test.zig");
    defer file.deinit(testing.allocator);

    file.total_lines = 100;
    file.covered_lines = 80;
    file.total_branches = 50;
    file.covered_branches = 35;
    file.total_functions = 10;
    file.covered_functions = 9;

    try testing.expectApproxEqRel(@as(f64, 80.0), file.getLineCoverage(), 0.01);
    try testing.expectApproxEqRel(@as(f64, 70.0), file.getBranchCoverage(), 0.01);
    try testing.expectApproxEqRel(@as(f64, 90.0), file.getFunctionCoverage(), 0.01);
}

test "coverage report aggregation" {
    const testing = std.testing;

    var report = CoverageReport.init(testing.allocator);
    defer report.deinit();

    var file1 = try FileCoverage.init(testing.allocator, "file1.zig");
    file1.total_lines = 100;
    file1.covered_lines = 80;
    file1.total_functions = 10;
    file1.covered_functions = 9;
    try report.addFile(file1);

    var file2 = try FileCoverage.init(testing.allocator, "file2.zig");
    file2.total_lines = 50;
    file2.covered_lines = 40;
    file2.total_functions = 5;
    file2.covered_functions = 5;
    try report.addFile(file2);

    try testing.expectEqual(@as(usize, 150), report.total_lines);
    try testing.expectEqual(@as(usize, 120), report.covered_lines);
    try testing.expectApproxEqRel(@as(f64, 80.0), report.getLineCoverage(), 0.01);
}

test "coverage threshold checking" {
    const testing = std.testing;

    var report = CoverageReport.init(testing.allocator);
    defer report.deinit();

    var file = try FileCoverage.init(testing.allocator, "test.zig");
    file.total_lines = 100;
    file.covered_lines = 85;
    file.total_branches = 50;
    file.covered_branches = 40;
    file.total_functions = 10;
    file.covered_functions = 10;
    try report.addFile(file);

    const config = CoverageConfig{
        .min_line_coverage = 80.0,
        .min_branch_coverage = 70.0,
        .min_function_coverage = 90.0,
    };

    try testing.expect(report.meetsThresholds(config));
}
