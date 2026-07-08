const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Cross-compilation options
    const build_all_targets = b.option(bool, "all-targets", "Build for all supported platforms") orelse false;

    // Add zig-tls dependency
    const tls = b.dependency("tls", .{
        .target = target,
        .optimize = optimize,
    });
    const tls_module = tls.module("tls");

    // Add zig-cli dependency
    const zig_cli_dep = b.dependency("zig_cli", .{
        .target = target,
        .optimize = optimize,
    });
    const zig_cli_module = zig_cli_dep.module("zig_cli");

    // Add zig-search-engine dependency (Typesense-backed full-text search)
    const search_engine_dep = b.dependency("search_engine", .{
        .target = target,
        .optimize = optimize,
    });
    const search_engine_module = search_engine_dep.module("search-engine");

    // Translate sqlite3.h into a Zig module (replaces @cImport in source files)
    const sqlite_module = sqliteModule(b, target, optimize);

    if (build_all_targets) {
        // Build for all supported targets
        // The released/supported platforms. (windows/*bsd were dropped — they don't
        // cross-compile cleanly and aren't published.)
        const targets = [_]std.Build.ResolvedTarget{
            b.resolveTargetQuery(.{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu }),
            b.resolveTargetQuery(.{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .gnu }),
            b.resolveTargetQuery(.{ .cpu_arch = .x86_64, .os_tag = .macos }),
            b.resolveTargetQuery(.{ .cpu_arch = .aarch64, .os_tag = .macos }),
        };

        for (targets) |t| {
            buildForTarget(b, t, optimize, tls_module, zig_cli_module, search_engine_module);
        }
    }

    // Single unified binary: mail
    const mail_module = b.createModule(.{
        .root_source_file = b.path("src/mail_cli.zig"),
        .target = target,
        .optimize = optimize,
    });
    mail_module.addImport("tls", tls_module);
    mail_module.addImport("search-engine", search_engine_module);
    mail_module.addImport("zig-cli", zig_cli_module);
    mail_module.addImport("sqlite", sqlite_module);

    const mail_exe = b.addExecutable(.{
        .name = "mail",
        .root_module = mail_module,
    });

    // Build the webmail frontend (renders pages -> src/api/webmail_dist/*) before
    // compiling, so the @embedFile'd assets in webmail_http.zig are always fresh.
    // Best-effort, for real this time: when bun or the webmail package is
    // unavailable (the Docker context only ships packages/zig), skip the step
    // and embed an existing pre-rendered webmail_dist instead of failing the
    // whole build on an unspawnable command. webmail_dist is gitignored, so
    // whoever invokes such a build must pre-render it (the Docker CI job does).
    const have_bun = blk: {
        _ = b.findProgram(&.{"bun"}, &.{}) catch break :blk false;
        break :blk true;
    };
    const have_webmail_pkg = blk: {
        std.Io.Dir.accessAbsolute(b.graph.io, b.pathFromRoot("../webmail"), .{}) catch break :blk false;
        break :blk true;
    };
    if (have_bun and have_webmail_pkg) {
        const webmail_build = b.addSystemCommand(&.{ "bun", "run", "build" });
        webmail_build.setCwd(b.path("../webmail"));
        mail_exe.step.dependOn(&webmail_build.step);
    }

    linkPlatformLibraries(mail_exe, target);
    b.installArtifact(mail_exe);

    // Run step: mail serve
    const run_cmd = b.addRunArtifact(mail_exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the mail CLI");
    run_step.dependOn(&run_cmd.step);

    // Create test step
    const test_step = b.step("test", "Run unit tests");

    // Add tests for each module
    const test_files = [_][]const u8{
        "src/security_test.zig",
        "src/errors_test.zig",
        "src/config_test.zig",
        "src/fs_compat_test.zig",
        "src/imap_test.zig",
        "src/connection_wrapper_test.zig",
        "src/webmail_session_test.zig",
        "src/uid_consistency_test.zig",
        "src/antispam/spam_filter.zig",
        "src/dkim_verify_test.zig",
    };

    // RFC compliance tests
    const rfc_compliance_tests = [_][]const u8{
        "tests/rfc5321_compliance_test.zig",
        "tests/rfc5322_compliance_test.zig",
        "tests/rfc6376_dkim_rotation_test.zig",
        "tests/rfc5228_sieve_test.zig",
        "tests/rfc7672_dane_test.zig",
        "tests/rfc8461_mta_sts_test.zig",
        "tests/acme_test.zig",
        "tests/rfc8460_tls_rpt_test.zig",
        "tests/rfc8617_arc_test.zig",
        "tests/bimi_test.zig",
        "tests/rfc8058_unsubscribe_test.zig",
        "tests/autoconfig_test.zig",
        "tests/rfc5804_managesieve_test.zig",
        "tests/milter_test.zig",
        "tests/rfc6352_carddav_test.zig",
        "tests/imap_notes_test.zig",
        "tests/security_hardening_test.zig",
        "tests/imap_starttls_test.zig",
    };

    for (test_files) |test_file| {
        const test_module = b.createModule(.{
            .root_source_file = b.path(test_file),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_module.addImport("tls", tls_module);
        test_module.addImport("search-engine", search_engine_module);
        test_module.addImport("sqlite", sqlite_module);
        test_module.linkSystemLibrary("sqlite3", .{});

        const unit_tests = b.addTest(.{
            .root_module = test_module,
        });

        const run_unit_tests = b.addRunArtifact(unit_tests);
        test_step.dependOn(&run_unit_tests.step);
    }

    // RFC compliance tests
    const rfc_test_step = b.step("test-rfc", "Run RFC compliance tests");

    const mail_test_module = b.createModule(.{
        .root_source_file = b.path("src/test_exports.zig"),
        .target = target,
        .optimize = optimize,
    });
    mail_test_module.addImport("tls", tls_module);
    mail_test_module.addImport("search-engine", search_engine_module);
    mail_test_module.addImport("sqlite", sqlite_module);

    for (rfc_compliance_tests) |test_file| {
        const test_module = b.createModule(.{
            .root_source_file = b.path(test_file),
            .target = target,
            .optimize = optimize,
        });

        test_module.addImport("mail", mail_test_module);

        const compliance_tests = b.addTest(.{
            .root_module = test_module,
        });

        const run_compliance_tests = b.addRunArtifact(compliance_tests);
        rfc_test_step.dependOn(&run_compliance_tests.step);
    }

    // End-to-end tests
    const e2e_step = b.step("test-e2e", "Run end-to-end tests");
    const e2e_module = b.createModule(.{
        .root_source_file = b.path("tests/e2e_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    const e2e_tests = b.addTest(.{
        .root_module = e2e_module,
    });
    const run_e2e_tests = b.addRunArtifact(e2e_tests);
    e2e_step.dependOn(&run_e2e_tests.step);

    // Fuzzing tests
    const fuzz_step = b.step("test-fuzz", "Run fuzzing tests");
    const fuzz_module = b.createModule(.{
        .root_source_file = b.path("tests/fuzz_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    const fuzz_tests = b.addTest(.{
        .root_module = fuzz_module,
    });
    const run_fuzz_tests = b.addRunArtifact(fuzz_tests);
    fuzz_step.dependOn(&run_fuzz_tests.step);

    // All tests step
    const test_all_step = b.step("test-all", "Run all tests (unit + rfc + e2e + fuzz)");
    test_all_step.dependOn(test_step);
    test_all_step.dependOn(rfc_test_step);
    test_all_step.dependOn(e2e_step);
    test_all_step.dependOn(fuzz_step);

    // Cross-platform build step
    const cross_step = b.step("cross", "Build for all supported platforms");
    if (build_all_targets) {
        cross_step.dependOn(b.getInstallStep());
    }
}

/// Build executable for a specific target platform
fn buildForTarget(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    tls_module: *std.Build.Module,
    zig_cli_module: *std.Build.Module,
    search_engine_module: *std.Build.Module,
) void {
    const target_query = target.query;
    const triple = b.fmt("{s}-{s}", .{
        @tagName(target_query.cpu_arch orelse .x86_64),
        @tagName(target_query.os_tag orelse .linux),
    });

    const root_module = b.createModule(.{
        .root_source_file = b.path("src/mail_cli.zig"),
        .target = target,
        .optimize = optimize,
    });
    root_module.addImport("tls", tls_module);
    root_module.addImport("search-engine", search_engine_module);
    root_module.addImport("zig-cli", zig_cli_module);
    root_module.addImport("sqlite", sqliteModule(b, target, optimize));

    const exe = b.addExecutable(.{
        .name = b.fmt("mail-{s}", .{triple}),
        .root_module = root_module,
    });

    linkPlatformLibraries(exe, target);

    // Output under zig-out/cross/<triple>/ so the Pantry GitHub Action auto-discovers
    // and packages each platform for the release (it scans zig-out/cross/<target>/).
    const install = b.addInstallArtifact(exe, .{
        .dest_dir = .{
            .override = .{
                .custom = b.fmt("cross/{s}", .{triple}),
            },
        },
    });
    b.getInstallStep().dependOn(&install.step);
}

/// Build a Zig module from the vendored sqlite3.h via translate-c.
fn sqliteModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const translate = b.addTranslateC(.{
        .root_source_file = b.path("vendor/sqlite3.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    return translate.createModule();
}

/// Link platform-specific libraries
fn linkPlatformLibraries(exe: *std.Build.Step.Compile, target: std.Build.ResolvedTarget) void {
    const target_query = target.query;
    const os_tag = target_query.os_tag orelse .linux;
    const is_cross_compiling = target_query.os_tag != null or target_query.cpu_arch != null;

    exe.root_module.link_libc = true;

    if (is_cross_compiling) {
        exe.root_module.addCSourceFile(.{
            .file = .{ .cwd_relative = "vendor/sqlite3.c" },
            .flags = &.{
                "-DSQLITE_THREADSAFE=1",
                "-DSQLITE_ENABLE_FTS5",
                "-DSQLITE_ENABLE_JSON1",
                "-DSQLITE_ENABLE_RTREE",
                "-DSQLITE_DQS=0",
            },
        });
        exe.root_module.addIncludePath(.{ .cwd_relative = "vendor" });
    } else {
        switch (os_tag) {
            .windows => {
                exe.root_module.linkSystemLibrary("sqlite3", .{});
                exe.root_module.linkSystemLibrary("ws2_32", .{});
                exe.root_module.linkSystemLibrary("advapi32", .{});
            },
            else => {
                exe.root_module.linkSystemLibrary("sqlite3", .{});
            },
        }
    }
}
