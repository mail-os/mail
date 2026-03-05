const std = @import("std");
const Allocator = std.mem.Allocator;

/// Path Sanitizer - Prevents path traversal vulnerabilities
/// Ensures all file paths are safely contained within a base directory
pub const PathSanitizer = struct {
    /// Sanitize a user-provided path to prevent directory traversal attacks
    /// Returns an absolute path guaranteed to be within the base_path
    ///
    /// Security checks:
    /// 1. Rejects paths containing ".."
    /// 2. Rejects absolute paths
    /// 3. Resolves symlinks
    /// 4. Verifies final path is within base directory
    ///
    /// Arguments:
    /// - allocator: Memory allocator for the returned path
    /// - base_path: The base directory to contain the file (must be absolute)
    /// - user_path: The user-provided path (must be relative)
    ///
    /// Returns:
    /// - Sanitized absolute path (caller owns memory)
    ///
    /// Errors:
    /// - PathTraversalAttempt: Path contains ".." or escapes base directory
    /// - AbsolutePathNotAllowed: User provided an absolute path
    /// - InvalidBasePath: Base path is not absolute
    pub fn sanitizePath(allocator: Allocator, base_path: []const u8, user_path: []const u8) ![]const u8 {
        // Validate base_path is absolute
        if (!std.fs.path.isAbsolute(base_path)) {
            std.log.err("Base path must be absolute: {s}", .{base_path});
            return error.InvalidBasePath;
        }

        // Check for null bytes
        if (std.mem.indexOf(u8, user_path, "\x00") != null) {
            std.log.warn("Path contains null byte: {s}", .{user_path});
            return error.PathTraversalAttempt;
        }

        // Reject paths containing ".."
        if (std.mem.indexOf(u8, user_path, "..") != null) {
            std.log.warn("Path traversal attempt detected (..): {s}", .{user_path});
            return error.PathTraversalAttempt;
        }

        // Reject absolute paths
        if (std.fs.path.isAbsolute(user_path)) {
            std.log.warn("Absolute path not allowed: {s}", .{user_path});
            return error.AbsolutePathNotAllowed;
        }

        // Join paths
        const joined = try std.fs.path.join(allocator, &[_][]const u8{ base_path, user_path });
        defer allocator.free(joined);

        // Resolve to canonical absolute path (this also resolves symlinks)
        const resolved = std.fs.realpathAlloc(allocator, joined) catch |err| {
            // If the path doesn't exist, verify it's still within base_path
            // by checking the parent directory exists and is within base_path
            if (err == error.FileNotFound) {
                return try verifyNonExistentPath(allocator, base_path, joined);
            }
            return err;
        };
        errdefer allocator.free(resolved);

        // Get canonical base path
        const base_real = try std.fs.realpathAlloc(allocator, base_path);
        defer allocator.free(base_real);

        // Verify resolved path is within base directory
        if (!std.mem.startsWith(u8, resolved, base_real)) {
            std.log.warn("Path escapes base directory - resolved: {s}, base: {s}", .{ resolved, base_real });
            allocator.free(resolved);
            return error.PathTraversalAttempt;
        }

        // Additional check: ensure there's a path separator after base or they're equal
        if (resolved.len > base_real.len) {
            const next_char = resolved[base_real.len];
            if (next_char != '/' and next_char != '\\') {
                std.log.warn("Path escape attempt via similar prefix: {s}", .{resolved});
                allocator.free(resolved);
                return error.PathTraversalAttempt;
            }
        }

        return resolved;
    }

    /// Verify a non-existent path would be within the base directory
    fn verifyNonExistentPath(allocator: Allocator, base_path: []const u8, joined_path: []const u8) ![]const u8 {
        // Get the directory part of the path
        const dirname = std.fs.path.dirname(joined_path) orelse base_path;

        // Try to resolve the directory
        const dir_resolved = std.fs.realpathAlloc(allocator, dirname) catch {
            // If even the directory doesn't exist, we can't safely verify
            return error.FileNotFound;
        };
        defer allocator.free(dir_resolved);

        // Get canonical base path
        const base_real = try std.fs.realpathAlloc(allocator, base_path);
        defer allocator.free(base_real);

        // Verify directory is within base
        if (!std.mem.startsWith(u8, dir_resolved, base_real)) {
            return error.PathTraversalAttempt;
        }

        // Return the joined path as-is since it's safe
        return try allocator.dupe(u8, joined_path);
    }

    /// Sanitize a filename by removing dangerous characters
    /// This doesn't validate paths, only individual filenames
    ///
    /// Security checks:
    /// 1. Removes directory separators (/ and \)
    /// 2. Removes null bytes
    /// 3. Limits length to 255 characters
    /// 4. Removes control characters
    ///
    /// Arguments:
    /// - allocator: Memory allocator
    /// - filename: The filename to sanitize
    ///
    /// Returns:
    /// - Sanitized filename (caller owns memory)
    pub fn sanitizeFilename(allocator: Allocator, filename: []const u8) ![]const u8 {
        if (filename.len == 0) {
            return error.EmptyFilename;
        }

        // Limit filename length (255 is typical filesystem limit)
        const max_len = @min(filename.len, 255);
        const trimmed = filename[0..max_len];

        // Remove dangerous characters
        var sanitized = try std.ArrayList(u8).initCapacity(allocator, max_len);
        errdefer sanitized.deinit();

        for (trimmed) |c| {
            // Skip directory separators
            if (c == '/' or c == '\\') {
                continue;
            }
            // Skip null bytes
            if (c == 0) {
                continue;
            }
            // Skip control characters
            if (c < 32 or c == 127) {
                continue;
            }
            try sanitized.append(c);
        }

        if (sanitized.items.len == 0) {
            sanitized.deinit();
            return error.InvalidFilename;
        }

        return sanitized.toOwnedSlice();
    }
};

// ============================================================================
// Tests
// ============================================================================

test "sanitizePath - basic valid path" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create a temp directory for testing
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const base_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base_path);

    const sanitized = try PathSanitizer.sanitizePath(allocator, base_path, "test.txt");
    defer allocator.free(sanitized);

    try testing.expect(std.mem.startsWith(u8, sanitized, base_path));
    try testing.expect(std.mem.endsWith(u8, sanitized, "test.txt"));
}

test "sanitizePath - rejects path traversal with .." {
    const testing = std.testing;
    const allocator = testing.allocator;

    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const base_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base_path);

    const result = PathSanitizer.sanitizePath(allocator, base_path, "../etc/passwd");
    try testing.expectError(error.PathTraversalAttempt, result);
}

test "sanitizePath - rejects absolute paths" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const base_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base_path);

    const result = PathSanitizer.sanitizePath(allocator, base_path, "/etc/passwd");
    try testing.expectError(error.AbsolutePathNotAllowed, result);
}

test "sanitizePath - rejects null bytes" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const base_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base_path);

    const result = PathSanitizer.sanitizePath(allocator, base_path, "test\x00.txt");
    try testing.expectError(error.PathTraversalAttempt, result);
}

test "sanitizePath - nested valid path" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const base_path = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(base_path);

    // Create subdirectory
    try tmp_dir.dir.makeDir("subdir");

    const sanitized = try PathSanitizer.sanitizePath(allocator, base_path, "subdir/test.txt");
    defer allocator.free(sanitized);

    try testing.expect(std.mem.startsWith(u8, sanitized, base_path));
}

test "sanitizeFilename - removes directory separators" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const sanitized = try PathSanitizer.sanitizeFilename(allocator, "../../etc/passwd");
    defer allocator.free(sanitized);

    try testing.expectEqualStrings("etcpasswd", sanitized);
}

test "sanitizeFilename - removes null bytes" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const sanitized = try PathSanitizer.sanitizeFilename(allocator, "test\x00.txt");
    defer allocator.free(sanitized);

    try testing.expectEqualStrings("test.txt", sanitized);
}

test "sanitizeFilename - limits length" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create a filename longer than 255 chars
    const long_name = "a" ** 300;
    const sanitized = try PathSanitizer.sanitizeFilename(allocator, long_name);
    defer allocator.free(sanitized);

    try testing.expectEqual(@as(usize, 255), sanitized.len);
}

test "sanitizeFilename - rejects empty" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const result = PathSanitizer.sanitizeFilename(allocator, "");
    try testing.expectError(error.EmptyFilename, result);
}
