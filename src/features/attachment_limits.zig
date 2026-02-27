const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const database = @import("../storage/database.zig");
const attachment = @import("../message/attachment.zig");

/// Attachment size limit management
/// Enforces per-user and global attachment size restrictions
pub const AttachmentLimitManager = struct {
    allocator: std.mem.Allocator,
    db: *database.Database,
    global_max_size: usize, // Global maximum attachment size
    global_max_total: usize, // Maximum total attachments size per message
    mutex: mutex_compat.Mutex,

    pub fn init(
        allocator: std.mem.Allocator,
        db: *database.Database,
        global_max_size: usize,
        global_max_total: usize,
    ) AttachmentLimitManager {
        return .{
            .allocator = allocator,
            .db = db,
            .global_max_size = global_max_size,
            .global_max_total = global_max_total,
            .mutex = .{},
        };
    }

    /// Set attachment size limit for a user (in bytes)
    pub fn setUserLimit(self: *AttachmentLimitManager, email: []const u8, max_size: usize, max_total: usize) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const query =
            \\UPDATE users SET
            \\  attachment_max_size = ?1,
            \\  attachment_max_total = ?2
            \\WHERE email = ?3
        ;

        var stmt = try self.db.db.?.prepare(query);
        defer stmt.deinit();

        try stmt.bind(0, @as(i64, @intCast(max_size)));
        try stmt.bind(1, @as(i64, @intCast(max_total)));
        try stmt.bind(2, email);
        try stmt.exec();
    }

    /// Get user's attachment limits
    pub fn getUserLimits(self: *AttachmentLimitManager, email: []const u8) !AttachmentLimits {
        self.mutex.lock();
        defer self.mutex.unlock();

        const query =
            \\SELECT attachment_max_size, attachment_max_total FROM users WHERE email = ?1
        ;

        var stmt = try self.db.db.?.prepare(query);
        defer stmt.deinit();

        try stmt.bind(0, email);

        if (try stmt.step()) {
            const max_size = stmt.columnInt64(0);
            const max_total = stmt.columnInt64(1);

            return AttachmentLimits{
                .max_size_per_attachment = if (max_size == 0) self.global_max_size else @intCast(max_size),
                .max_total_size = if (max_total == 0) self.global_max_total else @intCast(max_total),
            };
        }

        // User not found or no custom limits, use global limits
        return AttachmentLimits{
            .max_size_per_attachment = self.global_max_size,
            .max_total_size = self.global_max_total,
        };
    }

    /// Validate a single attachment against user limits
    pub fn validateAttachment(
        self: *AttachmentLimitManager,
        email: []const u8,
        attachment_size: usize,
    ) !ValidationResult {
        const limits = try self.getUserLimits(email);

        if (attachment_size > limits.max_size_per_attachment) {
            return ValidationResult{
                .valid = false,
                .reason = try std.fmt.allocPrint(
                    self.allocator,
                    "Attachment size ({d} bytes) exceeds limit ({d} bytes)",
                    .{ attachment_size, limits.max_size_per_attachment },
                ),
            };
        }

        return ValidationResult{
            .valid = true,
            .reason = null,
        };
    }

    /// Validate all attachments in a message
    pub fn validateAttachments(
        self: *AttachmentLimitManager,
        email: []const u8,
        attachments: []const attachment.Attachment,
    ) !ValidationResult {
        const limits = try self.getUserLimits(email);

        var total_size: usize = 0;

        for (attachments) |att| {
            // Check individual attachment size
            if (att.content.len > limits.max_size_per_attachment) {
                return ValidationResult{
                    .valid = false,
                    .reason = try std.fmt.allocPrint(
                        self.allocator,
                        "Attachment '{s}' ({d} bytes) exceeds per-attachment limit ({d} bytes)",
                        .{ att.filename, att.content.len, limits.max_size_per_attachment },
                    ),
                };
            }

            total_size += att.content.len;
        }

        // Check total size
        if (total_size > limits.max_total_size) {
            return ValidationResult{
                .valid = false,
                .reason = try std.fmt.allocPrint(
                    self.allocator,
                    "Total attachment size ({d} bytes) exceeds limit ({d} bytes)",
                    .{ total_size, limits.max_total_size },
                ),
            };
        }

        return ValidationResult{
            .valid = true,
            .reason = null,
        };
    }

    /// Get attachment count and total size for validation before processing
    pub fn getAttachmentStats(
        self: *AttachmentLimitManager,
        mime_parts: []const MimePart,
    ) AttachmentStats {
        _ = self;

        var count: usize = 0;
        var total_size: usize = 0;

        for (mime_parts) |part| {
            // Check if part is an attachment (has filename or content-disposition)
            if (part.headers.get("Content-Disposition")) |_| {
                count += 1;
                total_size += part.body.len;
            } else if (part.headers.get("Content-Type")) |ct| {
                // Check for attachment in Content-Type
                if (std.mem.indexOf(u8, ct, "name=") != null) {
                    count += 1;
                    total_size += part.body.len;
                }
            }
        }

        return AttachmentStats{
            .count = count,
            .total_size = total_size,
        };
    }
};

pub const AttachmentLimits = struct {
    max_size_per_attachment: usize,
    max_total_size: usize,
};

pub const ValidationResult = struct {
    valid: bool,
    reason: ?[]const u8,

    pub fn deinit(self: *ValidationResult, allocator: std.mem.Allocator) void {
        if (self.reason) |r| {
            allocator.free(r);
        }
    }
};

pub const AttachmentStats = struct {
    count: usize,
    total_size: usize,
};

/// Minimal MIME part representation for attachment stats
pub const MimePart = struct {
    headers: std.StringHashMap([]const u8),
    body: []const u8,
};

/// Preset attachment limit configurations
pub const AttachmentLimitPreset = enum {
    restricted, // 1 MB per attachment, 5 MB total
    standard, // 10 MB per attachment, 25 MB total
    generous, // 25 MB per attachment, 50 MB total
    unlimited, // No limits

    pub fn toLimits(self: AttachmentLimitPreset) AttachmentLimits {
        return switch (self) {
            .restricted => .{
                .max_size_per_attachment = 1 * 1024 * 1024, // 1 MB
                .max_total_size = 5 * 1024 * 1024, // 5 MB
            },
            .standard => .{
                .max_size_per_attachment = 10 * 1024 * 1024, // 10 MB
                .max_total_size = 25 * 1024 * 1024, // 25 MB
            },
            .generous => .{
                .max_size_per_attachment = 25 * 1024 * 1024, // 25 MB
                .max_total_size = 50 * 1024 * 1024, // 50 MB
            },
            .unlimited => .{
                .max_size_per_attachment = 0, // No limit
                .max_total_size = 0, // No limit
            },
        };
    }

    pub fn toString(self: AttachmentLimitPreset) []const u8 {
        return switch (self) {
            .restricted => "Restricted (1 MB/attachment, 5 MB total)",
            .standard => "Standard (10 MB/attachment, 25 MB total)",
            .generous => "Generous (25 MB/attachment, 50 MB total)",
            .unlimited => "Unlimited",
        };
    }
};

test "attachment limit presets" {
    const testing = std.testing;

    const restricted = AttachmentLimitPreset.restricted.toLimits();
    try testing.expectEqual(@as(usize, 1 * 1024 * 1024), restricted.max_size_per_attachment);
    try testing.expectEqual(@as(usize, 5 * 1024 * 1024), restricted.max_total_size);

    const standard = AttachmentLimitPreset.standard.toLimits();
    try testing.expectEqual(@as(usize, 10 * 1024 * 1024), standard.max_size_per_attachment);
    try testing.expectEqual(@as(usize, 25 * 1024 * 1024), standard.max_total_size);
}

test "attachment limits validation" {
    const testing = std.testing;

    const limits = AttachmentLimits{
        .max_size_per_attachment = 1024 * 1024, // 1 MB
        .max_total_size = 5 * 1024 * 1024, // 5 MB
    };

    // Individual attachment within limit
    try testing.expect(512 * 1024 <= limits.max_size_per_attachment);

    // Individual attachment exceeds limit
    try testing.expect(2 * 1024 * 1024 > limits.max_size_per_attachment);

    // Total size validation
    const total = 4 * 1024 * 1024; // 4 MB total
    try testing.expect(total <= limits.max_total_size);
}

test "attachment stats calculation" {
    const testing = std.testing;

    const stats = AttachmentStats{
        .count = 3,
        .total_size = 2 * 1024 * 1024, // 2 MB
    };

    try testing.expectEqual(@as(usize, 3), stats.count);
    try testing.expectEqual(@as(usize, 2 * 1024 * 1024), stats.total_size);
}
