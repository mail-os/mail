/// Filesystem compatibility layer for Zig 0.16-dev.
///
/// The 0.16-dev release moved all filesystem operations from `std.fs` to
/// `std.Io.Dir`, which requires an `Io` instance. This module provides the
/// old `std.fs.cwd()` API using libc functions (always available since we
/// link libc for sqlite3).
const std = @import("std");

pub const Dir = struct {
    /// Open a file relative to cwd.
    pub fn openFile(self: Dir, sub_path: []const u8, flags: OpenFlags) OpenError!File {
        _ = self;
        _ = flags;
        const path_z = std.fmt.allocPrintZ(std.heap.c_allocator, "{s}", .{sub_path}) catch return error.SystemResources;
        defer std.heap.c_allocator.free(path_z);
        const fd = std.c.open(path_z.ptr, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        if (fd < 0) return error.FileNotFound;
        return .{ .handle = fd };
    }

    /// Create a file relative to cwd.
    pub fn createFile(self: Dir, sub_path: []const u8, flags: CreateFlags) OpenError!File {
        _ = self;
        _ = flags;
        const path_z = toZ(sub_path) orelse return error.SystemResources;
        defer freeZ(path_z, sub_path.len);
        const fd = std.c.open(path_z, .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .TRUNC = true,
            .CLOEXEC = true,
        }, @as(std.c.mode_t, 0o644));
        if (fd < 0) return error.FileNotFound;
        return .{ .handle = fd };
    }

    /// Check access to a path.
    pub fn access(self: Dir, sub_path: []const u8, flags: AccessFlags) AccessError!void {
        _ = self;
        _ = flags;
        const path_z = std.fmt.allocPrintZ(std.heap.c_allocator, "{s}", .{sub_path}) catch return error.SystemResources;
        defer std.heap.c_allocator.free(path_z);
        const result = std.c.access(path_z.ptr, std.c.F.OK);
        if (result != 0) return error.FileNotFound;
    }

    /// Stat a file.
    pub fn statFile(self: Dir, sub_path: []const u8) StatError!Stat {
        _ = self;
        const path_z = toZ(sub_path) orelse return error.SystemResources;
        defer freeZ(path_z, sub_path.len);
        var st: std.c.Stat = undefined;
        const result = std.c.stat(path_z, &st);
        if (result != 0) return error.FileNotFound;
        return .{ .size = @intCast(st.size) };
    }

    /// Delete a file.
    pub fn deleteFile(self: Dir, sub_path: []const u8) DeleteError!void {
        _ = self;
        const path_z = std.fmt.allocPrintZ(std.heap.c_allocator, "{s}", .{sub_path}) catch return error.SystemResources;
        defer std.heap.c_allocator.free(path_z);
        const result = std.c.unlink(path_z.ptr);
        if (result != 0) return error.FileNotFound;
    }

    /// Resolve real path.
    pub fn realpath(self: Dir, sub_path: []const u8, buf: []u8) RealPathError![]u8 {
        _ = self;
        const path_z = std.fmt.allocPrintZ(std.heap.c_allocator, "{s}", .{sub_path}) catch return error.SystemResources;
        defer std.heap.c_allocator.free(path_z);
        var result_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const result = std.c.realpath(path_z.ptr, &result_buf);
        if (result == null) return error.FileNotFound;
        const len = std.mem.indexOfScalar(u8, &result_buf, 0) orelse result_buf.len;
        if (len > buf.len) return error.NameTooLong;
        @memcpy(buf[0..len], result_buf[0..len]);
        return buf[0..len];
    }

    /// Allocating realpath.
    pub fn realpathAlloc(self: Dir, allocator: std.mem.Allocator, sub_path: []const u8) ![]u8 {
        var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const result = try self.realpath(sub_path, &buf);
        return try allocator.dupe(u8, result);
    }

    /// Make directory path recursively.
    pub fn makePath(self: Dir, sub_path: []const u8) MakePathError!void {
        _ = self;
        // Use mkdir for each component
        var path_buf: [4097]u8 = undefined;
        var pos: usize = 0;
        for (sub_path, 0..) |c, i| {
            if (pos >= path_buf.len - 1) break;
            path_buf[pos] = c;
            pos += 1;
            if (c == '/' or i == sub_path.len - 1) {
                path_buf[pos] = 0;
                const sentinel_ptr: [*:0]const u8 = @ptrCast(&path_buf);
                _ = std.c.mkdir(sentinel_ptr, 0o755);
                // Ignore errors - directory may already exist
            }
        }
    }

    /// Delete a directory tree recursively.
    pub fn deleteTree(self: Dir, sub_path: []const u8) DeleteError!void {
        _ = self;
        // Use system "rm -rf" via libc - simplified implementation
        const path_z = std.fmt.allocPrintZ(std.heap.c_allocator, "{s}", .{sub_path}) catch return;
        defer std.heap.c_allocator.free(path_z);
        // Try rmdir first (for empty dirs), then unlink (for files)
        _ = std.c.rmdir(path_z.ptr);
        _ = std.c.unlink(path_z.ptr);
    }

    /// Open a subdirectory.
    pub fn openDir(self: Dir, sub_path: []const u8, flags: OpenDirFlags) OpenError!Dir {
        _ = self;
        _ = flags;
        // Verify the path exists and is a directory
        const path_z = std.fmt.allocPrintZ(std.heap.c_allocator, "{s}", .{sub_path}) catch return error.SystemResources;
        defer std.heap.c_allocator.free(path_z);
        var st: std.c.Stat = undefined;
        const result = std.c.stat(path_z.ptr, &st);
        if (result != 0) return error.FileNotFound;
        return .{};
    }

    /// Copy a file.
    pub fn copyFile(self: Dir, src_path: []const u8, dest_dir: Dir, dest_path: []const u8, flags: CopyFileFlags) CopyError!void {
        _ = self;
        _ = dest_dir;
        _ = flags;
        // Read source, write dest
        const src = std.fmt.allocPrintZ(std.heap.c_allocator, "{s}", .{src_path}) catch return error.SystemResources;
        defer std.heap.c_allocator.free(src);
        const dst = std.fmt.allocPrintZ(std.heap.c_allocator, "{s}", .{dest_path}) catch return error.SystemResources;
        defer std.heap.c_allocator.free(dst);

        const src_fd = std.c.open(src.ptr, .{ .ACCMODE = .RDONLY }, 0);
        if (src_fd < 0) return error.FileNotFound;
        defer _ = std.c.close(src_fd);

        const dst_fd = std.c.open(dst.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        if (dst_fd < 0) return error.FileNotFound;
        defer _ = std.c.close(dst_fd);

        var buf: [8192]u8 = undefined;
        while (true) {
            const n = std.c.read(src_fd, &buf, buf.len);
            if (n <= 0) break;
            _ = std.c.write(dst_fd, &buf, @intCast(n));
        }
    }

    pub const OpenFlags = struct {};
    pub const CreateFlags = struct {};
    pub const AccessFlags = struct {};
    pub const OpenDirFlags = struct {
        iterate: bool = false,
    };
    pub const CopyFileFlags = struct {};

    pub const OpenError = error{ FileNotFound, SystemResources };
    pub const AccessError = error{ FileNotFound, SystemResources };
    pub const StatError = error{ FileNotFound, SystemResources };
    pub const DeleteError = error{ FileNotFound, SystemResources };
    pub const MakePathError = error{SystemResources};
    pub const RealPathError = error{ FileNotFound, NameTooLong, SystemResources };
    pub const CopyError = error{ FileNotFound, SystemResources };
};

pub const File = struct {
    handle: std.c.fd_t,

    pub fn close(self: File) void {
        _ = std.c.close(self.handle);
    }

    pub fn readAll(self: File, buf: []u8) !usize {
        var total: usize = 0;
        while (total < buf.len) {
            const n = std.c.read(self.handle, buf[total..].ptr, buf.len - total);
            if (n <= 0) break;
            total += @intCast(n);
        }
        return total;
    }

    pub fn writeAll(self: File, data: []const u8) !void {
        var total: usize = 0;
        while (total < data.len) {
            const n = std.c.write(self.handle, data[total..].ptr, data.len - total);
            if (n <= 0) return error.BrokenPipe;
            total += @intCast(n);
        }
    }

    pub fn reader(self: File) Reader {
        return .{ .file = self };
    }

    pub fn writer(self: File) Writer {
        return .{ .file = self };
    }

    pub const Reader = struct {
        file: File,
        pub fn readAll(self: Reader, buf: []u8) !usize {
            return self.file.readAll(buf);
        }
    };

    pub const Writer = struct {
        file: File,
        pub fn writeAll(self: Writer, data: []const u8) !void {
            return self.file.writeAll(data);
        }
    };

    pub const OpenFlags = struct {};
    pub const CreateFlags = struct {};
};

pub const Stat = struct {
    size: u64,
};

/// Returns a Dir handle representing the current working directory.
pub fn cwd() Dir {
    return .{};
}

/// Create a null-terminated copy of a string using c_allocator.
fn toZ(s: []const u8) ?[*:0]const u8 {
    const buf = std.heap.c_allocator.alloc(u8, s.len + 1) catch return null;
    @memcpy(buf[0..s.len], s);
    buf[s.len] = 0;
    return @ptrCast(buf[0 .. s.len + 1]);
}

fn freeZ(ptr: [*:0]const u8, len: usize) void {
    const slice: []const u8 = @as([*]const u8, @ptrCast(ptr))[0 .. len + 1];
    std.heap.c_allocator.free(slice);
}

/// Entry for sorting .eml files by timestamp then name.
const EmlEntry = struct {
    name: []const u8,
    sort_key: i64, // epoch millis from filename, or 0 for non-timestamp names
};

/// Extract epoch millis from a filename like "1772486685658.eml" → 1772486685658.
/// Returns 0 for filenames that aren't numeric timestamps (e.g. SES message IDs).
fn parseFilenameTimestamp(filename: []const u8) i64 {
    const basename = if (std.mem.lastIndexOfScalar(u8, filename, '/')) |pos| filename[pos + 1 ..] else filename;
    const name_no_ext = if (std.mem.endsWith(u8, basename, ".eml")) basename[0 .. basename.len - 4] else basename;
    return std.fmt.parseInt(i64, name_no_ext, 10) catch return 0;
}

/// Ensure a directory exists, creating it (and parent directories) if needed.
pub fn ensureDir(path: []const u8) !void {
    // Build path component by component, calling mkdir for each prefix
    var path_buf: [4097]u8 = undefined;
    var pos: usize = 0;
    for (path, 0..) |c, i| {
        if (pos >= path_buf.len - 1) break;
        path_buf[pos] = c;
        pos += 1;
        if (c == '/' or i == path.len - 1) {
            path_buf[pos] = 0;
            const sentinel_ptr: [*:0]const u8 = @ptrCast(&path_buf);
            _ = std.c.mkdir(sentinel_ptr, 0o755);
            // Ignore errors - directory may already exist
        }
    }
}

/// List .eml files in a directory, returning filenames sorted by timestamp (oldest first).
/// Files with epoch-millis filenames sort by their timestamp; non-timestamp files sort first (key=0)
/// with alphabetical tiebreaker. This ensures new files always appear at the end, preserving
/// IMAP UID stability (UIDs are 1-based indices into this sorted list).
/// Caller owns the returned slice and each filename string (allocated with `allocator`).
pub fn listEmlFiles(allocator: std.mem.Allocator, dir_path: []const u8) ![][]const u8 {
    const path_z = toZ(dir_path) orelse return error.SystemResources;
    defer freeZ(path_z, dir_path.len);

    const dir = std.c.opendir(path_z) orelse return error.FileNotFound;
    defer _ = std.c.closedir(dir);

    var entries = std.ArrayList(EmlEntry){};
    errdefer {
        for (entries.items) |e| allocator.free(e.name);
        entries.deinit(allocator);
    }

    while (std.c.readdir(dir)) |entry| {
        const name_ptr: [*:0]const u8 = @ptrCast(&entry.name);
        const name = std.mem.sliceTo(name_ptr, 0);
        if (name.len > 4 and std.mem.eql(u8, name[name.len - 4 ..], ".eml")) {
            const owned = try allocator.dupe(u8, name);
            try entries.append(allocator, .{
                .name = owned,
                .sort_key = parseFilenameTimestamp(name),
            });
        }
    }

    // Sort by timestamp (oldest first), then by name as tiebreaker.
    // Non-timestamp files (sort_key=0) sort before all timestamp files.
    // This ensures new files (highest timestamp) always sort to the end,
    // so existing IMAP UIDs (which are 1-based indices) remain stable.
    std.mem.sort(EmlEntry, entries.items, {}, struct {
        fn lessThan(_: void, a: EmlEntry, b: EmlEntry) bool {
            if (a.sort_key != b.sort_key) return a.sort_key < b.sort_key;
            return std.mem.order(u8, a.name, b.name) == .lt;
        }
    }.lessThan);

    // Extract just the filenames into the returned slice
    const files = try allocator.alloc([]const u8, entries.items.len);
    for (entries.items, 0..) |e, i| {
        files[i] = e.name;
    }

    // Free the ArrayList's backing storage (the name strings are now owned by files).
    // Do NOT set entries.items = &.{} before deinit — deinit uses items.ptr + capacity
    // to compute the allocated slice, so changing items.ptr would cause a free of a bad pointer.
    entries.deinit(allocator);

    return files;
}

/// Read entire file contents into an allocated buffer.
pub fn readFileAlloc(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const path_z = toZ(path) orelse return error.SystemResources;
    defer freeZ(path_z, path.len);

    const fd = std.c.open(path_z, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, @as(std.c.mode_t, 0));
    if (fd < 0) return error.FileNotFound;
    defer _ = std.c.close(fd);

    // Read in chunks, growing the buffer as needed
    var buf = try allocator.alloc(u8, 8192);
    errdefer allocator.free(buf);
    var total: usize = 0;

    while (true) {
        if (total >= buf.len) {
            buf = try allocator.realloc(buf, buf.len * 2);
        }
        const n = std.c.read(fd, buf[total..].ptr, buf.len - total);
        if (n <= 0) break;
        total += @intCast(n);
    }

    // Shrink to actual size
    if (total == 0) {
        allocator.free(buf);
        return allocator.dupe(u8, "");
    }

    return allocator.realloc(buf, total) catch buf[0..total];
}
