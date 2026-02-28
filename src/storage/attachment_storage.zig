const std = @import("std");
const io_compat = @import("../core/io_compat.zig");
const mutex_compat = @import("../core/mutex_compat.zig");
const path_sanitizer = @import("../core/path_sanitizer.zig");
const fs = std.fs;
const crypto = std.crypto;
const posix = std.posix;

// =============================================================================
// Attachment Storage Backend
// =============================================================================
//
// ## Overview
// Provides a pluggable storage backend for email attachments supporting:
// - Local disk storage (default)
// - S3-compatible object storage
// - In-memory storage (for testing)
//
// ## Features
// - Unique attachment ID generation
// - MIME type detection
// - File size validation
// - Metadata tracking
// - Automatic cleanup of expired attachments
// - Thread-safe operations
//
// ## Usage
// ```zig
// var storage = try AttachmentStorage.init(allocator, .{
//     .backend = .disk,
//     .base_path = "/var/mail/attachments",
//     .max_file_size = 25 * 1024 * 1024,
// });
// defer storage.deinit();
//
// const id = try storage.store(file_data, "document.pdf", "application/pdf", user_id);
// const data = try storage.retrieve(id);
// try storage.delete(id);
// ```
//
// =============================================================================

/// Attachment storage configuration
pub const AttachmentStorageConfig = struct {
    /// Storage backend type
    backend: BackendType = .disk,
    /// Base path for disk storage
    base_path: []const u8 = "/tmp/mail_attachments",
    /// Maximum file size in bytes (default 25MB)
    max_file_size: usize = 25 * 1024 * 1024,
    /// Maximum attachments per user session
    max_attachments_per_session: usize = 10,
    /// Attachment expiry time in seconds (default 24 hours)
    expiry_seconds: u64 = 86400,
    /// S3 bucket name (for S3 backend)
    s3_bucket: ?[]const u8 = null,
    /// S3 endpoint URL (for S3 backend)
    s3_endpoint: ?[]const u8 = null,
    /// S3 region (for S3 backend)
    s3_region: ?[]const u8 = null,
    /// Enable content-based deduplication
    enable_deduplication: bool = false,
};

/// Storage backend type
pub const BackendType = enum {
    /// Local disk storage
    disk,
    /// S3-compatible object storage
    s3,
    /// In-memory storage (for testing)
    memory,
};

/// Attachment metadata
pub const AttachmentMetadata = struct {
    /// Unique attachment ID
    id: []const u8,
    /// Original filename
    filename: []const u8,
    /// MIME type
    mime_type: []const u8,
    /// File size in bytes
    size: usize,
    /// SHA-256 hash of content
    content_hash: [64]u8,
    /// Upload timestamp (unix epoch)
    created_at: i64,
    /// Expiry timestamp (unix epoch)
    expires_at: i64,
    /// User/session ID that uploaded
    owner_id: ?[]const u8,
    /// Storage path/key
    storage_path: []const u8,

    pub fn deinit(self: *AttachmentMetadata, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.filename);
        allocator.free(self.mime_type);
        if (self.owner_id) |owner| allocator.free(owner);
        allocator.free(self.storage_path);
    }
};

/// Upload result
pub const UploadResult = struct {
    id: []const u8,
    filename: []const u8,
    mime_type: []const u8,
    size: usize,
    expires_at: i64,
};

/// Storage error types
pub const StorageError = error{
    FileTooLarge,
    InvalidFilename,
    StorageNotAvailable,
    AttachmentNotFound,
    AttachmentExpired,
    QuotaExceeded,
    InvalidMimeType,
    IoError,
    OutOfMemory,
};

/// Main attachment storage interface
pub const AttachmentStorage = struct {
    allocator: std.mem.Allocator,
    config: AttachmentStorageConfig,
    /// Metadata index (id -> metadata)
    metadata_index: std.StringHashMap(AttachmentMetadata),
    /// Mutex for thread safety
    mutex: mutex_compat.Mutex,
    /// Disk backend
    disk_backend: ?DiskBackend,
    /// Memory backend (for testing)
    memory_backend: ?MemoryBackend,

    const Self = @This();

    /// Initialize attachment storage
    pub fn init(allocator: std.mem.Allocator, config: AttachmentStorageConfig) !Self {
        var storage = Self{
            .allocator = allocator,
            .config = config,
            .metadata_index = std.StringHashMap(AttachmentMetadata).init(allocator),
            .mutex = .{},
            .disk_backend = null,
            .memory_backend = null,
        };

        // Initialize the appropriate backend
        switch (config.backend) {
            .disk => {
                storage.disk_backend = try DiskBackend.init(allocator, config.base_path);
            },
            .memory => {
                storage.memory_backend = MemoryBackend.init(allocator);
            },
            .s3 => {
                // S3 backend would be initialized here with credentials
                // For now, fall back to disk
                storage.disk_backend = try DiskBackend.init(allocator, config.base_path);
            },
        }

        return storage;
    }

    /// Cleanup and free resources
    pub fn deinit(self: *Self) void {
        // Clean up metadata
        var it = self.metadata_index.iterator();
        while (it.next()) |entry| {
            var metadata = entry.value_ptr.*;
            metadata.deinit(self.allocator);
        }
        self.metadata_index.deinit();

        // Clean up backends
        if (self.disk_backend) |*backend| {
            backend.deinit();
        }
        if (self.memory_backend) |*backend| {
            backend.deinit();
        }
    }

    /// Store an attachment
    pub fn store(
        self: *Self,
        data: []const u8,
        filename: []const u8,
        mime_type: ?[]const u8,
        owner_id: ?[]const u8,
    ) !UploadResult {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Validate file size
        if (data.len > self.config.max_file_size) {
            return StorageError.FileTooLarge;
        }

        // Validate and sanitize filename (prevents path traversal)
        if (filename.len == 0 or filename.len > 255) {
            return StorageError.InvalidFilename;
        }
        // SECURITY: Reject filenames with path traversal or directory separators
        if (std.mem.indexOf(u8, filename, "..") != null or
            std.mem.indexOf(u8, filename, "/") != null or
            std.mem.indexOf(u8, filename, "\\") != null or
            std.mem.indexOf(u8, filename, "\x00") != null)
        {
            return StorageError.InvalidFilename;
        }

        // Generate unique ID
        const id = try self.generateId();
        errdefer self.allocator.free(id);

        // Compute content hash
        var hash: [32]u8 = undefined;
        crypto.hash.sha2.Sha256.hash(data, &hash, .{});
        var hash_hex: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&hash_hex, "{s}", .{std.fmt.fmtSliceHexLower(&hash)}) catch unreachable;

        // Determine MIME type
        const detected_mime = mime_type orelse detectMimeType(filename);
        const mime_copy = try self.allocator.dupe(u8, detected_mime);
        errdefer self.allocator.free(mime_copy);

        // Generate storage path
        const storage_path = try self.generateStoragePath(id, filename);
        errdefer self.allocator.free(storage_path);

        // Store the file
        try self.storeToBackend(storage_path, data);

        // Create metadata
        const now = std.time.timestamp();
        const filename_copy = try self.allocator.dupe(u8, filename);
        errdefer self.allocator.free(filename_copy);

        const owner_copy = if (owner_id) |o| try self.allocator.dupe(u8, o) else null;
        errdefer if (owner_copy) |o| self.allocator.free(o);

        const metadata = AttachmentMetadata{
            .id = id,
            .filename = filename_copy,
            .mime_type = mime_copy,
            .size = data.len,
            .content_hash = hash_hex,
            .created_at = now,
            .expires_at = now + @as(i64, @intCast(self.config.expiry_seconds)),
            .owner_id = owner_copy,
            .storage_path = storage_path,
        };

        // Store metadata
        try self.metadata_index.put(id, metadata);

        return UploadResult{
            .id = id,
            .filename = filename_copy,
            .mime_type = mime_copy,
            .size = data.len,
            .expires_at = metadata.expires_at,
        };
    }

    /// Retrieve an attachment
    pub fn retrieve(self: *Self, id: []const u8) ![]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const metadata = self.metadata_index.get(id) orelse {
            return StorageError.AttachmentNotFound;
        };

        // Check expiry
        const now = std.time.timestamp();
        if (now > metadata.expires_at) {
            return StorageError.AttachmentExpired;
        }

        return self.retrieveFromBackend(metadata.storage_path);
    }

    /// Get attachment metadata
    pub fn getMetadata(self: *Self, id: []const u8) !AttachmentMetadata {
        self.mutex.lock();
        defer self.mutex.unlock();

        const metadata = self.metadata_index.get(id) orelse {
            return StorageError.AttachmentNotFound;
        };

        return metadata;
    }

    /// Delete an attachment
    pub fn delete(self: *Self, id: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const metadata = self.metadata_index.get(id) orelse {
            return StorageError.AttachmentNotFound;
        };

        // Delete from backend
        try self.deleteFromBackend(metadata.storage_path);

        // Remove metadata
        var removed = self.metadata_index.fetchRemove(id);
        if (removed) |*kv| {
            kv.value.deinit(self.allocator);
        }
    }

    /// Clean up expired attachments
    pub fn cleanupExpired(self: *Self) !usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.timestamp();
        var to_delete = std.ArrayList([]const u8).init(self.allocator);
        defer to_delete.deinit();

        // Find expired attachments
        var it = self.metadata_index.iterator();
        while (it.next()) |entry| {
            if (now > entry.value_ptr.expires_at) {
                try to_delete.append(entry.key_ptr.*);
            }
        }

        // Delete them
        for (to_delete.items) |id| {
            if (self.metadata_index.fetchRemove(id)) |*kv| {
                self.deleteFromBackend(kv.value.storage_path) catch {};
                kv.value.deinit(self.allocator);
            }
        }

        return to_delete.items.len;
    }

    /// List attachments for an owner
    pub fn listByOwner(self: *Self, owner_id: []const u8) ![]AttachmentMetadata {
        self.mutex.lock();
        defer self.mutex.unlock();

        var results = std.ArrayList(AttachmentMetadata).init(self.allocator);
        errdefer results.deinit();

        var it = self.metadata_index.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.owner_id) |owner| {
                if (std.mem.eql(u8, owner, owner_id)) {
                    try results.append(entry.value_ptr.*);
                }
            }
        }

        return results.toOwnedSlice();
    }

    /// Get storage statistics
    pub fn getStats(self: *Self) StorageStats {
        self.mutex.lock();
        defer self.mutex.unlock();

        var total_size: usize = 0;
        var it = self.metadata_index.iterator();
        while (it.next()) |entry| {
            total_size += entry.value_ptr.size;
        }

        return StorageStats{
            .total_attachments = self.metadata_index.count(),
            .total_size = total_size,
            .backend_type = self.config.backend,
        };
    }

    // Internal methods

    fn generateId(self: *Self) ![]u8 {
        const timestamp = std.time.timestamp();
        var rand_bytes: [8]u8 = undefined;
        io_compat.randomBytes(&rand_bytes);

        return std.fmt.allocPrint(self.allocator, "att_{x}_{x}", .{
            @as(u64, @intCast(timestamp)),
            std.mem.readInt(u64, &rand_bytes, .big),
        });
    }

    fn generateStoragePath(self: *Self, id: []const u8, filename: []const u8) ![]u8 {
        // Extract extension
        const ext = if (std.mem.lastIndexOf(u8, filename, ".")) |idx|
            filename[idx..]
        else
            "";

        // Create path: base/year/month/day/id.ext
        const now = std.time.timestamp();
        const epoch_seconds: u64 = @intCast(now);
        const days_since_epoch = epoch_seconds / 86400;
        const year: u32 = @intCast(1970 + days_since_epoch / 365);
        const month: u32 = @intCast((days_since_epoch % 365) / 30 + 1);
        const day: u32 = @intCast((days_since_epoch % 365) % 30 + 1);

        return std.fmt.allocPrint(self.allocator, "{d:0>4}/{d:0>2}/{d:0>2}/{s}{s}", .{
            year,
            month,
            day,
            id,
            ext,
        });
    }

    fn storeToBackend(self: *Self, path: []const u8, data: []const u8) !void {
        if (self.disk_backend) |*backend| {
            try backend.store(path, data);
        } else if (self.memory_backend) |*backend| {
            try backend.store(path, data);
        } else {
            return StorageError.StorageNotAvailable;
        }
    }

    fn retrieveFromBackend(self: *Self, path: []const u8) ![]const u8 {
        if (self.disk_backend) |*backend| {
            return backend.retrieve(path);
        } else if (self.memory_backend) |*backend| {
            return backend.retrieve(path);
        } else {
            return StorageError.StorageNotAvailable;
        }
    }

    fn deleteFromBackend(self: *Self, path: []const u8) !void {
        if (self.disk_backend) |*backend| {
            try backend.delete(path);
        } else if (self.memory_backend) |*backend| {
            try backend.delete(path);
        }
    }
};

/// Storage statistics
pub const StorageStats = struct {
    total_attachments: usize,
    total_size: usize,
    backend_type: BackendType,
};

/// Disk-based storage backend
pub const DiskBackend = struct {
    allocator: std.mem.Allocator,
    base_path: []const u8,

    pub fn init(allocator: std.mem.Allocator, base_path: []const u8) !DiskBackend {
        const path = try allocator.dupe(u8, base_path);

        // Ensure base directory exists
        fs.cwd().makePath(base_path) catch |err| {
            if (err != error.PathAlreadyExists) {
                allocator.free(path);
                return StorageError.StorageNotAvailable;
            }
        };

        return .{
            .allocator = allocator,
            .base_path = path,
        };
    }

    pub fn deinit(self: *DiskBackend) void {
        self.allocator.free(self.base_path);
    }

    pub fn store(self: *DiskBackend, relative_path: []const u8, data: []const u8) !void {
        // Build full path
        const full_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{
            self.base_path,
            relative_path,
        });
        defer self.allocator.free(full_path);

        // Ensure directory exists
        if (std.mem.lastIndexOf(u8, full_path, "/")) |idx| {
            const dir_path = full_path[0..idx];
            fs.cwd().makePath(dir_path) catch |err| {
                if (err != error.PathAlreadyExists) {
                    return StorageError.IoError;
                }
            };
        }

        // Write file
        const file = fs.cwd().createFile(full_path, .{}) catch {
            return StorageError.IoError;
        };
        defer file.close();

        file.writeAll(data) catch {
            return StorageError.IoError;
        };
    }

    pub fn retrieve(self: *DiskBackend, relative_path: []const u8) ![]const u8 {
        const full_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{
            self.base_path,
            relative_path,
        });
        defer self.allocator.free(full_path);

        const file = fs.cwd().openFile(full_path, .{}) catch {
            return StorageError.AttachmentNotFound;
        };
        defer file.close();

        const stat = file.stat() catch {
            return StorageError.IoError;
        };

        const data = self.allocator.alloc(u8, stat.size) catch {
            return StorageError.OutOfMemory;
        };

        const bytes_read = file.readAll(data) catch {
            self.allocator.free(data);
            return StorageError.IoError;
        };

        if (bytes_read != stat.size) {
            self.allocator.free(data);
            return StorageError.IoError;
        }

        return data;
    }

    pub fn delete(self: *DiskBackend, relative_path: []const u8) !void {
        const full_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{
            self.base_path,
            relative_path,
        });
        defer self.allocator.free(full_path);

        fs.cwd().deleteFile(full_path) catch {
            // Ignore if file doesn't exist
        };
    }
};

/// In-memory storage backend (for testing)
pub const MemoryBackend = struct {
    allocator: std.mem.Allocator,
    files: std.StringHashMap([]const u8),

    pub fn init(allocator: std.mem.Allocator) MemoryBackend {
        return .{
            .allocator = allocator,
            .files = std.StringHashMap([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *MemoryBackend) void {
        var it = self.files.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.files.deinit();
    }

    pub fn store(self: *MemoryBackend, path: []const u8, data: []const u8) !void {
        const path_copy = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(path_copy);

        const data_copy = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(data_copy);

        // Remove existing if any
        if (self.files.fetchRemove(path)) |old| {
            self.allocator.free(old.key);
            self.allocator.free(old.value);
        }

        try self.files.put(path_copy, data_copy);
    }

    pub fn retrieve(self: *MemoryBackend, path: []const u8) ![]const u8 {
        const data = self.files.get(path) orelse {
            return StorageError.AttachmentNotFound;
        };
        return try self.allocator.dupe(u8, data);
    }

    pub fn delete(self: *MemoryBackend, path: []const u8) !void {
        if (self.files.fetchRemove(path)) |old| {
            self.allocator.free(old.key);
            self.allocator.free(old.value);
        }
    }
};

/// Detect MIME type from filename extension
pub fn detectMimeType(filename: []const u8) []const u8 {
    const ext_start = std.mem.lastIndexOf(u8, filename, ".") orelse return "application/octet-stream";
    const ext = filename[ext_start..];

    // Common MIME types
    const mime_types = [_]struct { ext: []const u8, mime: []const u8 }{
        // Images
        .{ .ext = ".jpg", .mime = "image/jpeg" },
        .{ .ext = ".jpeg", .mime = "image/jpeg" },
        .{ .ext = ".png", .mime = "image/png" },
        .{ .ext = ".gif", .mime = "image/gif" },
        .{ .ext = ".webp", .mime = "image/webp" },
        .{ .ext = ".svg", .mime = "image/svg+xml" },
        .{ .ext = ".ico", .mime = "image/x-icon" },
        .{ .ext = ".bmp", .mime = "image/bmp" },
        // Documents
        .{ .ext = ".pdf", .mime = "application/pdf" },
        .{ .ext = ".doc", .mime = "application/msword" },
        .{ .ext = ".docx", .mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
        .{ .ext = ".xls", .mime = "application/vnd.ms-excel" },
        .{ .ext = ".xlsx", .mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" },
        .{ .ext = ".ppt", .mime = "application/vnd.ms-powerpoint" },
        .{ .ext = ".pptx", .mime = "application/vnd.openxmlformats-officedocument.presentationml.presentation" },
        .{ .ext = ".odt", .mime = "application/vnd.oasis.opendocument.text" },
        .{ .ext = ".ods", .mime = "application/vnd.oasis.opendocument.spreadsheet" },
        // Text
        .{ .ext = ".txt", .mime = "text/plain" },
        .{ .ext = ".html", .mime = "text/html" },
        .{ .ext = ".htm", .mime = "text/html" },
        .{ .ext = ".css", .mime = "text/css" },
        .{ .ext = ".js", .mime = "application/javascript" },
        .{ .ext = ".json", .mime = "application/json" },
        .{ .ext = ".xml", .mime = "application/xml" },
        .{ .ext = ".csv", .mime = "text/csv" },
        .{ .ext = ".md", .mime = "text/markdown" },
        // Archives
        .{ .ext = ".zip", .mime = "application/zip" },
        .{ .ext = ".tar", .mime = "application/x-tar" },
        .{ .ext = ".gz", .mime = "application/gzip" },
        .{ .ext = ".rar", .mime = "application/vnd.rar" },
        .{ .ext = ".7z", .mime = "application/x-7z-compressed" },
        // Audio
        .{ .ext = ".mp3", .mime = "audio/mpeg" },
        .{ .ext = ".wav", .mime = "audio/wav" },
        .{ .ext = ".ogg", .mime = "audio/ogg" },
        .{ .ext = ".flac", .mime = "audio/flac" },
        // Video
        .{ .ext = ".mp4", .mime = "video/mp4" },
        .{ .ext = ".webm", .mime = "video/webm" },
        .{ .ext = ".avi", .mime = "video/x-msvideo" },
        .{ .ext = ".mov", .mime = "video/quicktime" },
        .{ .ext = ".mkv", .mime = "video/x-matroska" },
        // Email
        .{ .ext = ".eml", .mime = "message/rfc822" },
        .{ .ext = ".msg", .mime = "application/vnd.ms-outlook" },
    };

    // Case-insensitive comparison
    var lower_ext: [16]u8 = undefined;
    const len = @min(ext.len, 16);
    for (ext[0..len], 0..) |c, i| {
        lower_ext[i] = std.ascii.toLower(c);
    }

    for (mime_types) |entry| {
        if (std.mem.eql(u8, lower_ext[0..len], entry.ext)) {
            return entry.mime;
        }
    }

    return "application/octet-stream";
}

// =============================================================================
// Tests
// =============================================================================

test "AttachmentStorageConfig defaults" {
    const config = AttachmentStorageConfig{};
    try std.testing.expectEqual(BackendType.disk, config.backend);
    try std.testing.expectEqual(@as(usize, 25 * 1024 * 1024), config.max_file_size);
    try std.testing.expectEqual(@as(u64, 86400), config.expiry_seconds);
}

test "MemoryBackend store and retrieve" {
    const allocator = std.testing.allocator;
    var backend = MemoryBackend.init(allocator);
    defer backend.deinit();

    const test_data = "Hello, World!";
    try backend.store("test/file.txt", test_data);

    const retrieved = try backend.retrieve("test/file.txt");
    defer allocator.free(retrieved);

    try std.testing.expectEqualStrings(test_data, retrieved);
}

test "MemoryBackend delete" {
    const allocator = std.testing.allocator;
    var backend = MemoryBackend.init(allocator);
    defer backend.deinit();

    try backend.store("test/file.txt", "test data");
    try backend.delete("test/file.txt");

    const result = backend.retrieve("test/file.txt");
    try std.testing.expectError(StorageError.AttachmentNotFound, result);
}

test "detectMimeType common extensions" {
    try std.testing.expectEqualStrings("application/pdf", detectMimeType("document.pdf"));
    try std.testing.expectEqualStrings("image/jpeg", detectMimeType("photo.jpg"));
    try std.testing.expectEqualStrings("image/png", detectMimeType("icon.png"));
    try std.testing.expectEqualStrings("text/plain", detectMimeType("readme.txt"));
    try std.testing.expectEqualStrings("application/zip", detectMimeType("archive.zip"));
    try std.testing.expectEqualStrings("application/octet-stream", detectMimeType("unknown.xyz"));
    try std.testing.expectEqualStrings("application/octet-stream", detectMimeType("noextension"));
}

test "AttachmentStorage with memory backend" {
    const allocator = std.testing.allocator;

    var storage = try AttachmentStorage.init(allocator, .{
        .backend = .memory,
        .max_file_size = 1024,
    });
    defer storage.deinit();

    // Test store
    const result = try storage.store("test data content", "test.txt", null, "user123");

    try std.testing.expect(std.mem.startsWith(u8, result.id, "att_"));
    try std.testing.expectEqualStrings("test.txt", result.filename);
    try std.testing.expectEqualStrings("text/plain", result.mime_type);
    try std.testing.expectEqual(@as(usize, 17), result.size);

    // Test retrieve
    const data = try storage.retrieve(result.id);
    defer allocator.free(data);
    try std.testing.expectEqualStrings("test data content", data);

    // Test metadata
    const metadata = try storage.getMetadata(result.id);
    try std.testing.expectEqualStrings("test.txt", metadata.filename);

    // Test delete
    try storage.delete(result.id);
    const deleted = storage.retrieve(result.id);
    try std.testing.expectError(StorageError.AttachmentNotFound, deleted);
}

test "AttachmentStorage file too large" {
    const allocator = std.testing.allocator;

    var storage = try AttachmentStorage.init(allocator, .{
        .backend = .memory,
        .max_file_size = 10, // Very small limit
    });
    defer storage.deinit();

    const result = storage.store("this is way too much data", "file.txt", null, null);
    try std.testing.expectError(StorageError.FileTooLarge, result);
}

test "AttachmentStorage stats" {
    const allocator = std.testing.allocator;

    var storage = try AttachmentStorage.init(allocator, .{
        .backend = .memory,
    });
    defer storage.deinit();

    _ = try storage.store("file1 content", "file1.txt", null, null);
    _ = try storage.store("file2 content here", "file2.txt", null, null);

    const stats = storage.getStats();
    try std.testing.expectEqual(@as(usize, 2), stats.total_attachments);
    try std.testing.expectEqual(@as(usize, 31), stats.total_size); // 13 + 18 bytes
    try std.testing.expectEqual(BackendType.memory, stats.backend_type);
}
