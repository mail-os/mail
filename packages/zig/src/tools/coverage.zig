const std = @import("std");
const Allocator = std.mem.Allocator;

/// Test Coverage Measurement System
///
/// Provides test coverage tracking and enforcement for the SMTP server.
/// Integrates with Zig's built-in coverage support and provides:
/// - Line coverage tracking
/// - Branch coverage analysis
/// - Function coverage reporting
/// - Coverage thresholds enforcement
/// - HTML/JSON report generation
///
/// Usage:
/// ```
/// zig build test -Dcoverage=true
/// zig-out/bin/coverage-report --output coverage.html
/// ```

// ============================================================================
// Coverage Data Structures
// ============================================================================

/// Coverage counter types
pub const CoverageType = enum {
    line,
    branch,
    function,
};

/// Coverage region in source code
pub const CoverageRegion = struct {
    file: []const u8,
    start_line: u32,
    end_line: u32,
    start_col: u32,
    end_col: u32,
    execution_count: u64,
    region_type: RegionType,

    pub const RegionType = enum {
        code,
        branch,
        expansion,
        skipped,
    };
};

/// File coverage data
pub const FileCoverage = struct {
    path: []const u8,
    lines_total: u32,
    lines_covered: u32,
    branches_total: u32,
    branches_covered: u32,
    functions_total: u32,
    functions_covered: u32,
    regions: std.ArrayList(CoverageRegion),

    pub fn init(allocator: Allocator, path: []const u8) !FileCoverage {
        return .{
            .path = try allocator.dupe(u8, path),
            .lines_total = 0,
            .lines_covered = 0,
            .branches_total = 0,
            .branches_covered = 0,
            .functions_total = 0,
            .functions_covered = 0,
            .regions = std.ArrayList(CoverageRegion).init(allocator),
        };
    }

    pub fn deinit(self: *FileCoverage, allocator: Allocator) void {
        allocator.free(self.path);
        self.regions.deinit();
    }

    /// Calculate line coverage percentage
    pub fn lineCoveragePercent(self: *const FileCoverage) f64 {
        if (self.lines_total == 0) return 100.0;
        return @as(f64, @floatFromInt(self.lines_covered)) /
            @as(f64, @floatFromInt(self.lines_total)) * 100.0;
    }

    /// Calculate branch coverage percentage
    pub fn branchCoveragePercent(self: *const FileCoverage) f64 {
        if (self.branches_total == 0) return 100.0;
        return @as(f64, @floatFromInt(self.branches_covered)) /
            @as(f64, @floatFromInt(self.branches_total)) * 100.0;
    }

    /// Calculate function coverage percentage
    pub fn functionCoveragePercent(self: *const FileCoverage) f64 {
        if (self.functions_total == 0) return 100.0;
        return @as(f64, @floatFromInt(self.functions_covered)) /
            @as(f64, @floatFromInt(self.functions_total)) * 100.0;
    }
};

// ============================================================================
// Coverage Thresholds
// ============================================================================

/// Coverage threshold configuration
pub const CoverageThresholds = struct {
    line_minimum: f64 = 80.0,
    branch_minimum: f64 = 70.0,
    function_minimum: f64 = 90.0,
    per_file_line_minimum: f64 = 60.0,
    per_file_branch_minimum: f64 = 50.0,

    /// Default thresholds for production
    pub const production = CoverageThresholds{
        .line_minimum = 80.0,
        .branch_minimum = 70.0,
        .function_minimum = 90.0,
        .per_file_line_minimum = 60.0,
        .per_file_branch_minimum = 50.0,
    };

    /// Relaxed thresholds for development
    pub const development = CoverageThresholds{
        .line_minimum = 50.0,
        .branch_minimum = 40.0,
        .function_minimum = 60.0,
        .per_file_line_minimum = 30.0,
        .per_file_branch_minimum = 20.0,
    };

    /// Strict thresholds for critical paths
    pub const strict = CoverageThresholds{
        .line_minimum = 95.0,
        .branch_minimum = 90.0,
        .function_minimum = 100.0,
        .per_file_line_minimum = 80.0,
        .per_file_branch_minimum = 70.0,
    };
};

/// Threshold violation
pub const ThresholdViolation = struct {
    file: ?[]const u8,
    coverage_type: CoverageType,
    actual: f64,
    required: f64,
};

// ============================================================================
// Coverage Collector
// ============================================================================

/// Collects and aggregates coverage data
pub const CoverageCollector = struct {
    allocator: Allocator,
    files: std.StringHashMap(FileCoverage),
    thresholds: CoverageThresholds,
    excluded_paths: std.ArrayList([]const u8),

    pub fn init(allocator: Allocator) CoverageCollector {
        return .{
            .allocator = allocator,
            .files = std.StringHashMap(FileCoverage).init(allocator),
            .thresholds = CoverageThresholds.production,
            .excluded_paths = std.ArrayList([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *CoverageCollector) void {
        var iter = self.files.iterator();
        while (iter.next()) |entry| {
            var file = entry.value_ptr;
            file.deinit(self.allocator);
        }
        self.files.deinit();
        for (self.excluded_paths.items) |path| {
            self.allocator.free(path);
        }
        self.excluded_paths.deinit();
    }

    /// Add exclusion pattern
    pub fn addExclusion(self: *CoverageCollector, pattern: []const u8) !void {
        const copy = try self.allocator.dupe(u8, pattern);
        try self.excluded_paths.append(copy);
    }

    /// Check if path should be excluded
    pub fn isExcluded(self: *const CoverageCollector, path: []const u8) bool {
        for (self.excluded_paths.items) |pattern| {
            if (std.mem.indexOf(u8, path, pattern) != null) {
                return true;
            }
        }
        return false;
    }

    /// Add file coverage data
    pub fn addFile(self: *CoverageCollector, coverage: FileCoverage) !void {
        if (self.isExcluded(coverage.path)) return;
        try self.files.put(coverage.path, coverage);
    }

    /// Get total coverage summary
    pub fn getSummary(self: *const CoverageCollector) CoverageSummary {
        var summary = CoverageSummary{};

        var iter = self.files.iterator();
        while (iter.next()) |entry| {
            const file = entry.value_ptr;
            summary.lines_total += file.lines_total;
            summary.lines_covered += file.lines_covered;
            summary.branches_total += file.branches_total;
            summary.branches_covered += file.branches_covered;
            summary.functions_total += file.functions_total;
            summary.functions_covered += file.functions_covered;
            summary.files_total += 1;
        }

        return summary;
    }

    /// Check thresholds and return violations
    pub fn checkThresholds(self: *const CoverageCollector) ![]ThresholdViolation {
        var violations = std.ArrayList(ThresholdViolation).init(self.allocator);
        errdefer violations.deinit();

        const summary = self.getSummary();

        // Check global thresholds
        const line_pct = summary.lineCoveragePercent();
        if (line_pct < self.thresholds.line_minimum) {
            try violations.append(.{
                .file = null,
                .coverage_type = .line,
                .actual = line_pct,
                .required = self.thresholds.line_minimum,
            });
        }

        const branch_pct = summary.branchCoveragePercent();
        if (branch_pct < self.thresholds.branch_minimum) {
            try violations.append(.{
                .file = null,
                .coverage_type = .branch,
                .actual = branch_pct,
                .required = self.thresholds.branch_minimum,
            });
        }

        const func_pct = summary.functionCoveragePercent();
        if (func_pct < self.thresholds.function_minimum) {
            try violations.append(.{
                .file = null,
                .coverage_type = .function,
                .actual = func_pct,
                .required = self.thresholds.function_minimum,
            });
        }

        // Check per-file thresholds
        var iter = self.files.iterator();
        while (iter.next()) |entry| {
            const file = entry.value_ptr;

            const file_line_pct = file.lineCoveragePercent();
            if (file_line_pct < self.thresholds.per_file_line_minimum) {
                try violations.append(.{
                    .file = file.path,
                    .coverage_type = .line,
                    .actual = file_line_pct,
                    .required = self.thresholds.per_file_line_minimum,
                });
            }

            const file_branch_pct = file.branchCoveragePercent();
            if (file_branch_pct < self.thresholds.per_file_branch_minimum) {
                try violations.append(.{
                    .file = file.path,
                    .coverage_type = .branch,
                    .actual = file_branch_pct,
                    .required = self.thresholds.per_file_branch_minimum,
                });
            }
        }

        return violations.toOwnedSlice();
    }
};

/// Coverage summary
pub const CoverageSummary = struct {
    lines_total: u32 = 0,
    lines_covered: u32 = 0,
    branches_total: u32 = 0,
    branches_covered: u32 = 0,
    functions_total: u32 = 0,
    functions_covered: u32 = 0,
    files_total: u32 = 0,

    pub fn lineCoveragePercent(self: *const CoverageSummary) f64 {
        if (self.lines_total == 0) return 100.0;
        return @as(f64, @floatFromInt(self.lines_covered)) /
            @as(f64, @floatFromInt(self.lines_total)) * 100.0;
    }

    pub fn branchCoveragePercent(self: *const CoverageSummary) f64 {
        if (self.branches_total == 0) return 100.0;
        return @as(f64, @floatFromInt(self.branches_covered)) /
            @as(f64, @floatFromInt(self.branches_total)) * 100.0;
    }

    pub fn functionCoveragePercent(self: *const CoverageSummary) f64 {
        if (self.functions_total == 0) return 100.0;
        return @as(f64, @floatFromInt(self.functions_covered)) /
            @as(f64, @floatFromInt(self.functions_total)) * 100.0;
    }
};

// ============================================================================
// Report Generation
// ============================================================================

/// Coverage report format
pub const ReportFormat = enum {
    text,
    json,
    html,
    lcov,
    cobertura,
};

/// Coverage report generator
pub const ReportGenerator = struct {
    allocator: Allocator,
    collector: *const CoverageCollector,

    pub fn init(allocator: Allocator, collector: *const CoverageCollector) ReportGenerator {
        return .{
            .allocator = allocator,
            .collector = collector,
        };
    }

    /// Generate report in specified format
    pub fn generate(self: *ReportGenerator, format: ReportFormat) ![]u8 {
        return switch (format) {
            .text => self.generateText(),
            .json => self.generateJson(),
            .html => self.generateHtml(),
            .lcov => self.generateLcov(),
            .cobertura => self.generateCobertura(),
        };
    }

    /// Generate text report
    fn generateText(self: *ReportGenerator) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        const writer = buffer.writer();

        const summary = self.collector.getSummary();

        try writer.writeAll("=== Coverage Report ===\n\n");
        try std.fmt.format(writer, "Files:     {d}\n", .{summary.files_total});
        try std.fmt.format(writer, "Lines:     {d}/{d} ({d:.1}%)\n", .{
            summary.lines_covered,
            summary.lines_total,
            summary.lineCoveragePercent(),
        });
        try std.fmt.format(writer, "Branches:  {d}/{d} ({d:.1}%)\n", .{
            summary.branches_covered,
            summary.branches_total,
            summary.branchCoveragePercent(),
        });
        try std.fmt.format(writer, "Functions: {d}/{d} ({d:.1}%)\n", .{
            summary.functions_covered,
            summary.functions_total,
            summary.functionCoveragePercent(),
        });

        try writer.writeAll("\n--- Per-File Coverage ---\n\n");

        var iter = self.collector.files.iterator();
        while (iter.next()) |entry| {
            const file = entry.value_ptr;
            try std.fmt.format(writer, "{s}: {d:.1}% lines, {d:.1}% branches\n", .{
                file.path,
                file.lineCoveragePercent(),
                file.branchCoveragePercent(),
            });
        }

        return buffer.toOwnedSlice();
    }

    /// Generate JSON report
    fn generateJson(self: *ReportGenerator) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        const writer = buffer.writer();

        const summary = self.collector.getSummary();

        try writer.writeAll("{\"summary\":{");
        try std.fmt.format(writer,
            \\"files":{d},"lines_total":{d},"lines_covered":{d},"line_percent":{d:.2},
        , .{ summary.files_total, summary.lines_total, summary.lines_covered, summary.lineCoveragePercent() });
        try std.fmt.format(writer,
            \\"branches_total":{d},"branches_covered":{d},"branch_percent":{d:.2},
        , .{ summary.branches_total, summary.branches_covered, summary.branchCoveragePercent() });
        try std.fmt.format(writer,
            \\"functions_total":{d},"functions_covered":{d},"function_percent":{d:.2}
        , .{ summary.functions_total, summary.functions_covered, summary.functionCoveragePercent() });
        try writer.writeAll("},\"files\":[");

        var first = true;
        var iter = self.collector.files.iterator();
        while (iter.next()) |entry| {
            if (!first) try writer.writeAll(",");
            first = false;

            const file = entry.value_ptr;
            try std.fmt.format(writer,
                \\{{"path":"{s}","lines":{d:.2},"branches":{d:.2},"functions":{d:.2}}}
            , .{ file.path, file.lineCoveragePercent(), file.branchCoveragePercent(), file.functionCoveragePercent() });
        }

        try writer.writeAll("]}");
        return buffer.toOwnedSlice();
    }

    /// Generate HTML report
    fn generateHtml(self: *ReportGenerator) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        const writer = buffer.writer();

        const summary = self.collector.getSummary();

        try writer.writeAll(
            \\<!DOCTYPE html>
            \\<html>
            \\<head>
            \\<title>Coverage Report</title>
            \\<style>
            \\body { font-family: sans-serif; margin: 20px; }
            \\table { border-collapse: collapse; width: 100%; }
            \\th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            \\th { background-color: #4CAF50; color: white; }
            \\.good { background-color: #90EE90; }
            \\.warn { background-color: #FFE4B5; }
            \\.bad { background-color: #FFB6C1; }
            \\</style>
            \\</head>
            \\<body>
            \\<h1>Coverage Report</h1>
            \\<h2>Summary</h2>
            \\<table>
            \\<tr><th>Metric</th><th>Covered</th><th>Total</th><th>Percentage</th></tr>
            \\
        );

        try std.fmt.format(writer,
            \\<tr><td>Lines</td><td>{d}</td><td>{d}</td><td class="{s}">{d:.1}%</td></tr>
        , .{
            summary.lines_covered,
            summary.lines_total,
            coverageClass(summary.lineCoveragePercent()),
            summary.lineCoveragePercent(),
        });
        try std.fmt.format(writer,
            \\<tr><td>Branches</td><td>{d}</td><td>{d}</td><td class="{s}">{d:.1}%</td></tr>
        , .{
            summary.branches_covered,
            summary.branches_total,
            coverageClass(summary.branchCoveragePercent()),
            summary.branchCoveragePercent(),
        });
        try std.fmt.format(writer,
            \\<tr><td>Functions</td><td>{d}</td><td>{d}</td><td class="{s}">{d:.1}%</td></tr>
        , .{
            summary.functions_covered,
            summary.functions_total,
            coverageClass(summary.functionCoveragePercent()),
            summary.functionCoveragePercent(),
        });

        try writer.writeAll(
            \\</table>
            \\<h2>Files</h2>
            \\<table>
            \\<tr><th>File</th><th>Lines</th><th>Branches</th><th>Functions</th></tr>
            \\
        );

        var iter = self.collector.files.iterator();
        while (iter.next()) |entry| {
            const file = entry.value_ptr;
            try std.fmt.format(writer,
                \\<tr><td>{s}</td><td class="{s}">{d:.1}%</td><td class="{s}">{d:.1}%</td><td class="{s}">{d:.1}%</td></tr>
            , .{
                file.path,
                coverageClass(file.lineCoveragePercent()),
                file.lineCoveragePercent(),
                coverageClass(file.branchCoveragePercent()),
                file.branchCoveragePercent(),
                coverageClass(file.functionCoveragePercent()),
                file.functionCoveragePercent(),
            });
        }

        try writer.writeAll("</table></body></html>");
        return buffer.toOwnedSlice();
    }

    /// Generate LCOV format
    fn generateLcov(self: *ReportGenerator) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        const writer = buffer.writer();

        var iter = self.collector.files.iterator();
        while (iter.next()) |entry| {
            const file = entry.value_ptr;
            try std.fmt.format(writer, "SF:{s}\n", .{file.path});
            try std.fmt.format(writer, "LF:{d}\n", .{file.lines_total});
            try std.fmt.format(writer, "LH:{d}\n", .{file.lines_covered});
            try std.fmt.format(writer, "BRF:{d}\n", .{file.branches_total});
            try std.fmt.format(writer, "BRH:{d}\n", .{file.branches_covered});
            try std.fmt.format(writer, "FNF:{d}\n", .{file.functions_total});
            try std.fmt.format(writer, "FNH:{d}\n", .{file.functions_covered});
            try writer.writeAll("end_of_record\n");
        }

        return buffer.toOwnedSlice();
    }

    /// Generate Cobertura XML format
    fn generateCobertura(self: *ReportGenerator) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        const writer = buffer.writer();

        const summary = self.collector.getSummary();

        try writer.writeAll(
            \\<?xml version="1.0"?>
            \\<!DOCTYPE coverage SYSTEM "http://cobertura.sourceforge.net/xml/coverage-04.dtd">
            \\
        );
        try std.fmt.format(writer,
            \\<coverage line-rate="{d:.4}" branch-rate="{d:.4}" version="1.0">
        , .{ summary.lineCoveragePercent() / 100.0, summary.branchCoveragePercent() / 100.0 });

        try writer.writeAll("<packages><package name=\"smtp-server\"><classes>");

        var iter = self.collector.files.iterator();
        while (iter.next()) |entry| {
            const file = entry.value_ptr;
            try std.fmt.format(writer,
                \\<class name="{s}" filename="{s}" line-rate="{d:.4}" branch-rate="{d:.4}">
                \\<lines></lines></class>
            , .{
                file.path,
                file.path,
                file.lineCoveragePercent() / 100.0,
                file.branchCoveragePercent() / 100.0,
            });
        }

        try writer.writeAll("</classes></package></packages></coverage>");
        return buffer.toOwnedSlice();
    }

    fn coverageClass(percent: f64) []const u8 {
        if (percent >= 80.0) return "good";
        if (percent >= 60.0) return "warn";
        return "bad";
    }
};

// ============================================================================
// Coverage Enforcer
// ============================================================================

/// Enforces coverage thresholds in CI/CD pipelines
pub const CoverageEnforcer = struct {
    allocator: Allocator,
    collector: *CoverageCollector,
    fail_on_violation: bool,

    pub fn init(allocator: Allocator, collector: *CoverageCollector) CoverageEnforcer {
        return .{
            .allocator = allocator,
            .collector = collector,
            .fail_on_violation = true,
        };
    }

    /// Check coverage and return exit code
    pub fn enforce(self: *CoverageEnforcer) !u8 {
        const violations = try self.collector.checkThresholds();
        defer self.allocator.free(violations);

        if (violations.len == 0) {
            std.debug.print("✓ All coverage thresholds met\n", .{});
            return 0;
        }

        std.debug.print("✗ Coverage threshold violations:\n", .{});
        for (violations) |v| {
            if (v.file) |file| {
                std.debug.print("  {s}: {s} coverage {d:.1}% < {d:.1}% required\n", .{
                    file,
                    @tagName(v.coverage_type),
                    v.actual,
                    v.required,
                });
            } else {
                std.debug.print("  Global: {s} coverage {d:.1}% < {d:.1}% required\n", .{
                    @tagName(v.coverage_type),
                    v.actual,
                    v.required,
                });
            }
        }

        return if (self.fail_on_violation) 1 else 0;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "file coverage calculation" {
    const testing = std.testing;

    var file = try FileCoverage.init(testing.allocator, "src/main.zig");
    defer file.deinit(testing.allocator);

    file.lines_total = 100;
    file.lines_covered = 80;
    file.branches_total = 50;
    file.branches_covered = 35;

    try testing.expectApproxEqAbs(@as(f64, 80.0), file.lineCoveragePercent(), 0.01);
    try testing.expectApproxEqAbs(@as(f64, 70.0), file.branchCoveragePercent(), 0.01);
}

test "coverage summary" {
    const testing = std.testing;

    var summary = CoverageSummary{
        .lines_total = 1000,
        .lines_covered = 850,
        .branches_total = 200,
        .branches_covered = 150,
        .functions_total = 50,
        .functions_covered = 45,
    };

    try testing.expectApproxEqAbs(@as(f64, 85.0), summary.lineCoveragePercent(), 0.01);
    try testing.expectApproxEqAbs(@as(f64, 75.0), summary.branchCoveragePercent(), 0.01);
    try testing.expectApproxEqAbs(@as(f64, 90.0), summary.functionCoveragePercent(), 0.01);
}

test "threshold checking" {
    const testing = std.testing;

    var collector = CoverageCollector.init(testing.allocator);
    defer collector.deinit();

    collector.thresholds = CoverageThresholds{
        .line_minimum = 80.0,
        .branch_minimum = 70.0,
        .function_minimum = 90.0,
        .per_file_line_minimum = 60.0,
        .per_file_branch_minimum = 50.0,
    };

    // Add a file with low coverage
    var file = try FileCoverage.init(testing.allocator, "low_coverage.zig");
    file.lines_total = 100;
    file.lines_covered = 40; // 40% - below 60% threshold
    file.branches_total = 20;
    file.branches_covered = 8; // 40% - below 50% threshold
    try collector.addFile(file);

    const violations = try collector.checkThresholds();
    defer testing.allocator.free(violations);

    // Should have violations for per-file thresholds
    try testing.expect(violations.len > 0);
}

test "exclusion patterns" {
    const testing = std.testing;

    var collector = CoverageCollector.init(testing.allocator);
    defer collector.deinit();

    try collector.addExclusion("test");
    try collector.addExclusion("vendor");

    try testing.expect(collector.isExcluded("tests/unit_test.zig"));
    try testing.expect(collector.isExcluded("vendor/lib.zig"));
    try testing.expect(!collector.isExcluded("src/main.zig"));
}

test "report generation" {
    const testing = std.testing;

    var collector = CoverageCollector.init(testing.allocator);
    defer collector.deinit();

    var file = try FileCoverage.init(testing.allocator, "src/test.zig");
    file.lines_total = 100;
    file.lines_covered = 80;
    try collector.addFile(file);

    var generator = ReportGenerator.init(testing.allocator, &collector);

    const text_report = try generator.generate(.text);
    defer testing.allocator.free(text_report);
    try testing.expect(std.mem.indexOf(u8, text_report, "Coverage Report") != null);

    const json_report = try generator.generate(.json);
    defer testing.allocator.free(json_report);
    try testing.expect(std.mem.indexOf(u8, json_report, "summary") != null);
}
