const std = @import("std");
const testing = std.testing;
const fs_compat = @import("core/fs_compat.zig");

// =============================================================================
// Test helpers
// =============================================================================

/// Create a temporary directory, returning the null-terminated path.
/// Caller must call cleanupTestDir when done.
fn setupTestDir(comptime name: []const u8) [*:0]const u8 {
    const path: [*:0]const u8 = "/tmp/mail_test_" ++ name ++ "\x00";
    _ = std.c.mkdir(path, 0o755);
    return path;
}

/// Create an empty file inside a directory.
fn touchFile(dir: [*:0]const u8, filename: [*:0]const u8) void {
    var buf: [512]u8 = undefined;
    const d = std.mem.sliceTo(dir, 0);
    const f = std.mem.sliceTo(filename, 0);
    const written = std.fmt.bufPrint(&buf, "{s}/{s}", .{ d, f }) catch return;
    buf[written.len] = 0;
    const full: [*:0]const u8 = @ptrCast(&buf);
    const fd = std.c.open(full, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, @as(std.c.mode_t, 0o644));
    if (fd >= 0) _ = std.c.close(fd);
}

/// Write content to a file inside a directory.
fn writeTestFile(dir: [*:0]const u8, filename: [*:0]const u8, content: []const u8) void {
    var buf: [512]u8 = undefined;
    const d = std.mem.sliceTo(dir, 0);
    const f = std.mem.sliceTo(filename, 0);
    const written = std.fmt.bufPrint(&buf, "{s}/{s}", .{ d, f }) catch return;
    buf[written.len] = 0;
    const full: [*:0]const u8 = @ptrCast(&buf);
    const fd = std.c.open(full, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, @as(std.c.mode_t, 0o644));
    if (fd < 0) return;
    defer _ = std.c.close(fd);
    _ = std.c.write(fd, content.ptr, content.len);
}

/// Remove a file inside a directory.
fn removeFile(dir: [*:0]const u8, filename: [*:0]const u8) void {
    var buf: [512]u8 = undefined;
    const d = std.mem.sliceTo(dir, 0);
    const f = std.mem.sliceTo(filename, 0);
    const written = std.fmt.bufPrint(&buf, "{s}/{s}", .{ d, f }) catch return;
    buf[written.len] = 0;
    const full: [*:0]const u8 = @ptrCast(&buf);
    _ = std.c.unlink(full);
}

/// Clean up a test directory and its known files.
fn cleanupTestDir(dir: [*:0]const u8, files: []const [*:0]const u8) void {
    for (files) |f| removeFile(dir, f);
    _ = std.c.rmdir(dir);
}

/// Free the result of listEmlFiles.
fn freeEmlFiles(allocator: std.mem.Allocator, files: []const []const u8) void {
    for (files) |f| allocator.free(f);
    allocator.free(files);
}

/// Verify a directory exists using opendir.
fn dirExists(path_z: [*:0]const u8) bool {
    const d = std.c.opendir(path_z);
    if (d) |dir| {
        _ = std.c.closedir(dir);
        return true;
    }
    return false;
}

// =============================================================================
// listEmlFiles tests
// =============================================================================

test "listEmlFiles - non-existent directory returns FileNotFound" {
    const result = fs_compat.listEmlFiles(testing.allocator, "/tmp/mail_test_nonexistent_xyz_42");
    try testing.expectError(error.FileNotFound, result);
}

test "listEmlFiles - empty directory returns empty slice" {
    const dir = setupTestDir("empty");
    defer _ = std.c.rmdir(dir);

    const files = try fs_compat.listEmlFiles(testing.allocator, std.mem.sliceTo(dir, 0));
    defer freeEmlFiles(testing.allocator, files);

    try testing.expectEqual(@as(usize, 0), files.len);
}

test "listEmlFiles - only returns .eml files" {
    const dir = setupTestDir("filter");
    const eml_files = [_][*:0]const u8{ "msg.eml", "other.txt", "readme.md", "data.eml" };
    for (eml_files) |f| touchFile(dir, f);
    defer cleanupTestDir(dir, &eml_files);

    const files = try fs_compat.listEmlFiles(testing.allocator, std.mem.sliceTo(dir, 0));
    defer freeEmlFiles(testing.allocator, files);

    try testing.expectEqual(@as(usize, 2), files.len);
    // Both should end with .eml
    for (files) |f| {
        try testing.expect(std.mem.endsWith(u8, f, ".eml"));
    }
}

test "listEmlFiles - sorts by timestamp oldest first" {
    const dir = setupTestDir("sort_ts");
    const test_files = [_][*:0]const u8{ "300.eml", "100.eml", "200.eml" };
    for (test_files) |f| touchFile(dir, f);
    defer cleanupTestDir(dir, &test_files);

    const files = try fs_compat.listEmlFiles(testing.allocator, std.mem.sliceTo(dir, 0));
    defer freeEmlFiles(testing.allocator, files);

    try testing.expectEqual(@as(usize, 3), files.len);
    try testing.expectEqualStrings("100.eml", files[0]);
    try testing.expectEqualStrings("200.eml", files[1]);
    try testing.expectEqualStrings("300.eml", files[2]);
}

test "listEmlFiles - non-timestamp files sort before timestamp files" {
    const dir = setupTestDir("sort_mixed");
    const test_files = [_][*:0]const u8{ "500.eml", "abc-message-id.eml", "100.eml" };
    for (test_files) |f| touchFile(dir, f);
    defer cleanupTestDir(dir, &test_files);

    const files = try fs_compat.listEmlFiles(testing.allocator, std.mem.sliceTo(dir, 0));
    defer freeEmlFiles(testing.allocator, files);

    try testing.expectEqual(@as(usize, 3), files.len);
    // Non-timestamp (sort_key=0) should come first
    try testing.expectEqualStrings("abc-message-id.eml", files[0]);
    // Then timestamp files in order
    try testing.expectEqualStrings("100.eml", files[1]);
    try testing.expectEqualStrings("500.eml", files[2]);
}

test "listEmlFiles - alphabetical tiebreaker for same timestamp" {
    const dir = setupTestDir("sort_alpha");
    // sort_key=0 for all non-numeric names, so alphabetical order applies
    const test_files = [_][*:0]const u8{ "charlie.eml", "alpha.eml", "bravo.eml" };
    for (test_files) |f| touchFile(dir, f);
    defer cleanupTestDir(dir, &test_files);

    const files = try fs_compat.listEmlFiles(testing.allocator, std.mem.sliceTo(dir, 0));
    defer freeEmlFiles(testing.allocator, files);

    try testing.expectEqual(@as(usize, 3), files.len);
    try testing.expectEqualStrings("alpha.eml", files[0]);
    try testing.expectEqualStrings("bravo.eml", files[1]);
    try testing.expectEqualStrings("charlie.eml", files[2]);
}

test "listEmlFiles - regression: ArrayList cleanup does not crash" {
    // This is a regression test for the SEGV bug where `entries.items = &.{}`
    // was called before `entries.deinit(allocator)`, causing deinit to free
    // a comptime pointer with the wrong capacity. The crash manifested with
    // 11+ files (the exact count that triggered the bug on production).
    const dir = setupTestDir("regression");
    const test_files = [_][*:0]const u8{
        "1772486685001.eml",
        "1772486685002.eml",
        "1772486685003.eml",
        "1772486685004.eml",
        "1772486685005.eml",
        "1772486685006.eml",
        "1772486685007.eml",
        "1772486685008.eml",
        "1772486685009.eml",
        "1772486685010.eml",
        "1772486685011.eml",
        "ses-msgid-abcdef.eml",
        "ses-msgid-ghijkl.eml",
    };
    for (test_files) |f| touchFile(dir, f);
    defer cleanupTestDir(dir, &test_files);

    const files = try fs_compat.listEmlFiles(testing.allocator, std.mem.sliceTo(dir, 0));
    defer freeEmlFiles(testing.allocator, files);

    // 13 files total — the production crash happened with 11 .eml files
    try testing.expectEqual(@as(usize, 13), files.len);

    // Non-timestamp files (ses-msgid-*) should be first (sort_key=0)
    try testing.expect(std.mem.startsWith(u8, files[0], "ses-msgid-"));
    try testing.expect(std.mem.startsWith(u8, files[1], "ses-msgid-"));

    // Timestamp files should be in ascending order
    try testing.expectEqualStrings("1772486685001.eml", files[2]);
    try testing.expectEqualStrings("1772486685011.eml", files[12]);
}

test "listEmlFiles - no memory leaks with testing allocator" {
    const dir = setupTestDir("memleak");
    const test_files = [_][*:0]const u8{ "1.eml", "2.eml", "3.eml" };
    for (test_files) |f| touchFile(dir, f);
    defer cleanupTestDir(dir, &test_files);

    // testing.allocator will detect leaks automatically
    const files = try fs_compat.listEmlFiles(testing.allocator, std.mem.sliceTo(dir, 0));
    for (files) |f| testing.allocator.free(f);
    testing.allocator.free(files);
}

// =============================================================================
// ensureDir tests
// =============================================================================

test "ensureDir - creates nested directories" {
    const path = "/tmp/mail_test_ensuredir/a/b/c";
    defer {
        _ = std.c.rmdir("/tmp/mail_test_ensuredir/a/b/c\x00");
        _ = std.c.rmdir("/tmp/mail_test_ensuredir/a/b\x00");
        _ = std.c.rmdir("/tmp/mail_test_ensuredir/a\x00");
        _ = std.c.rmdir("/tmp/mail_test_ensuredir\x00");
    }

    try fs_compat.ensureDir(path);

    // Verify the deepest directory exists using opendir
    try testing.expect(dirExists("/tmp/mail_test_ensuredir/a/b/c\x00"));
}

test "ensureDir - idempotent on existing directory" {
    const path = "/tmp/mail_test_ensuredir_idem";
    defer _ = std.c.rmdir("/tmp/mail_test_ensuredir_idem\x00");

    // Call twice — should not error
    try fs_compat.ensureDir(path);
    try fs_compat.ensureDir(path);

    try testing.expect(dirExists("/tmp/mail_test_ensuredir_idem\x00"));
}

// =============================================================================
// readFileAlloc tests
// =============================================================================

test "readFileAlloc - reads file content correctly" {
    const dir = setupTestDir("readfile");
    defer {
        removeFile(dir, "test.txt");
        _ = std.c.rmdir(dir);
    }

    const expected = "Hello, mail server!\nLine 2\n";
    writeTestFile(dir, "test.txt", expected);

    const dir_s = std.mem.sliceTo(dir, 0);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/test.txt", .{dir_s});
    defer testing.allocator.free(path);

    const content = try fs_compat.readFileAlloc(testing.allocator, path);
    defer testing.allocator.free(content);

    try testing.expectEqualStrings(expected, content);
}

test "readFileAlloc - non-existent file returns FileNotFound" {
    const result = fs_compat.readFileAlloc(testing.allocator, "/tmp/mail_test_no_such_file_xyz_42.txt");
    try testing.expectError(error.FileNotFound, result);
}

test "readFileAlloc - empty file returns empty slice" {
    const dir = setupTestDir("readempty");
    defer {
        removeFile(dir, "empty.txt");
        _ = std.c.rmdir(dir);
    }

    touchFile(dir, "empty.txt");

    const dir_s = std.mem.sliceTo(dir, 0);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/empty.txt", .{dir_s});
    defer testing.allocator.free(path);

    const content = try fs_compat.readFileAlloc(testing.allocator, path);
    defer testing.allocator.free(content);

    try testing.expectEqual(@as(usize, 0), content.len);
}

// =============================================================================
// createFile + readFileAlloc roundtrip
// =============================================================================

test "createFile and readFileAlloc roundtrip" {
    const dir = setupTestDir("roundtrip");
    defer {
        removeFile(dir, "data.txt");
        _ = std.c.rmdir(dir);
    }

    const dir_s = std.mem.sliceTo(dir, 0);
    const file_path = try std.fmt.allocPrint(testing.allocator, "{s}/data.txt", .{dir_s});
    defer testing.allocator.free(file_path);

    // Create and write using Dir API
    {
        const f = try fs_compat.cwd().createFile(file_path, .{});
        defer f.close();
        try f.writeAll("roundtrip test data");
    }

    // Read back using readFileAlloc
    const content = try fs_compat.readFileAlloc(testing.allocator, file_path);
    defer testing.allocator.free(content);

    try testing.expectEqualStrings("roundtrip test data", content);
}
