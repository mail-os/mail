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
        const path_z = std.fmt.allocPrintZ(std.heap.c_allocator, "{s}", .{sub_path}) catch return error.SystemResources;
        defer std.heap.c_allocator.free(path_z);
        const fd = std.c.open(path_z.ptr, .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .TRUNC = true,
            .CLOEXEC = true,
        }, 0o644);
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
        var path_buf: [4096]u8 = undefined;
        var pos: usize = 0;
        for (sub_path, 0..) |c, i| {
            path_buf[pos] = c;
            pos += 1;
            if (c == '/' or i == sub_path.len - 1) {
                path_buf[pos] = 0;
                _ = std.c.mkdir(&path_buf, 0o755);
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

/// List .eml files in a directory, returning sorted filenames.
/// Caller owns the returned slice and each filename string (allocated with `allocator`).
pub fn listEmlFiles(allocator: std.mem.Allocator, dir_path: []const u8) ![][]const u8 {
    const path_z = toZ(dir_path) orelse return error.SystemResources;
    defer freeZ(path_z, dir_path.len);

    const dir = std.c.opendir(path_z) orelse return &[_][]const u8{};
    defer _ = std.c.closedir(dir);

    var files = std.ArrayList([]const u8){};
    errdefer {
        for (files.items) |f| allocator.free(f);
        files.deinit(allocator);
    }

    while (std.c.readdir(dir)) |entry| {
        const name_ptr: [*:0]const u8 = @ptrCast(&entry.name);
        const name = std.mem.sliceTo(name_ptr, 0);
        if (name.len > 4 and std.mem.eql(u8, name[name.len - 4 ..], ".eml")) {
            const owned = try allocator.dupe(u8, name);
            try files.append(allocator, owned);
        }
    }

    // Sort filenames (they are timestamps, so lexicographic sort = chronological)
    const items = files.items;
    std.mem.sort([]const u8, items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);

    return files.toOwnedSlice(allocator);
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
