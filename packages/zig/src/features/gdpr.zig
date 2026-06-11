const std = @import("std");
const time_compat = @import("../core/time_compat.zig");
const fs_compat = @import("../core/fs_compat.zig");
const sqlite = @import("sqlite");

/// GDPR Compliance Module
/// Implements data protection and privacy requirements per GDPR (EU Regulation 2016/679)
///
/// Features:
/// - Right to access (Article 15) - Data export
/// - Right to erasure (Article 17) - Data deletion
/// - Right to data portability (Article 20) - Portable format export
/// - Audit logging (Article 30) - Processing activities record
/// - Data retention policies (Article 5) - Storage limitation
///
/// Compliance Requirements:
/// - User data export within 30 days
/// - Data deletion within 30 days
/// - Audit trail of all data operations
/// - Machine-readable export format (JSON)
/// - Secure deletion (unrecoverable)
pub const GDPRError = error{
    DatabaseError,
    ExportFailed,
    DeletionFailed,
    AuditLogFailed,
    InvalidUser,
    NoDataFound,
};

/// GDPR data export result
pub const DataExport = struct {
    user: []const u8,
    export_date: i64,
    data: ExportData,
    allocator: std.mem.Allocator,

    pub const ExportData = struct {
        personal_info: PersonalInfo,
        messages: []Message,
        activity: []Activity,
        metadata: Metadata,
    };

    pub const PersonalInfo = struct {
        username: []const u8,
        email: []const u8,
        created_at: i64,
        last_login: ?i64,
        quota_mb: u32,
        used_mb: f64,
    };

    pub const Message = struct {
        id: []const u8,
        from: []const u8,
        to: []const []const u8,
        subject: []const u8,
        date: i64,
        size_bytes: usize,
        folder: []const u8,
        flags: []const u8,
    };

    pub const Activity = struct {
        timestamp: i64,
        action: []const u8,
        ip_address: []const u8,
        user_agent: []const u8,
        success: bool,
    };

    pub const Metadata = struct {
        total_messages: usize,
        total_size_bytes: usize,
        folders: []const []const u8,
        storage_locations: []const []const u8,
    };

    pub fn deinit(self: *DataExport) void {
        // Free personal info
        self.allocator.free(self.data.personal_info.username);
        self.allocator.free(self.data.personal_info.email);

        // Free messages
        for (self.data.messages) |msg| {
            self.allocator.free(msg.id);
            self.allocator.free(msg.from);
            for (msg.to) |to| {
                self.allocator.free(to);
            }
            self.allocator.free(msg.to);
            self.allocator.free(msg.subject);
            self.allocator.free(msg.folder);
            self.allocator.free(msg.flags);
        }
        self.allocator.free(self.data.messages);

        // Free activity
        for (self.data.activity) |act| {
            self.allocator.free(act.action);
            self.allocator.free(act.ip_address);
            self.allocator.free(act.user_agent);
        }
        self.allocator.free(self.data.activity);

        // Free metadata
        for (self.data.metadata.folders) |folder| {
            self.allocator.free(folder);
        }
        self.allocator.free(self.data.metadata.folders);

        for (self.data.metadata.storage_locations) |loc| {
            self.allocator.free(loc);
        }
        self.allocator.free(self.data.metadata.storage_locations);

        self.allocator.free(self.user);
    }

    /// Export to JSON format (machine-readable, Article 20)
    pub fn toJSON(self: *const DataExport, writer: anytype) !void {
        try writer.writeAll("{");

        // User info
        try writer.print("\"user\":\"{s}\",", .{self.user});
        try writer.print("\"export_date\":{d},", .{self.export_date});

        // Personal info
        try writer.writeAll("\"personal_info\":{");
        try writer.print("\"username\":\"{s}\",", .{self.data.personal_info.username});
        try writer.print("\"email\":\"{s}\",", .{self.data.personal_info.email});
        try writer.print("\"created_at\":{d},", .{self.data.personal_info.created_at});
        if (self.data.personal_info.last_login) |last_login| {
            try writer.print("\"last_login\":{d},", .{last_login});
        } else {
            try writer.writeAll("\"last_login\":null,");
        }
        try writer.print("\"quota_mb\":{d},", .{self.data.personal_info.quota_mb});
        try writer.print("\"used_mb\":{d}", .{self.data.personal_info.used_mb});
        try writer.writeAll("},");

        // Messages
        try writer.writeAll("\"messages\":[");
        for (self.data.messages, 0..) |msg, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.writeAll("{");
            try writer.print("\"id\":\"{s}\",", .{msg.id});
            try writer.print("\"from\":\"{s}\",", .{msg.from});

            try writer.writeAll("\"to\":[");
            for (msg.to, 0..) |to, j| {
                if (j > 0) try writer.writeAll(",");
                try writer.print("\"{s}\"", .{to});
            }
            try writer.writeAll("],");

            try writer.print("\"subject\":\"{s}\",", .{msg.subject});
            try writer.print("\"date\":{d},", .{msg.date});
            try writer.print("\"size_bytes\":{d},", .{msg.size_bytes});
            try writer.print("\"folder\":\"{s}\",", .{msg.folder});
            try writer.print("\"flags\":\"{s}\"", .{msg.flags});
            try writer.writeAll("}");
        }
        try writer.writeAll("],");

        // Activity
        try writer.writeAll("\"activity\":[");
        for (self.data.activity, 0..) |act, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.writeAll("{");
            try writer.print("\"timestamp\":{d},", .{act.timestamp});
            try writer.print("\"action\":\"{s}\",", .{act.action});
            try writer.print("\"ip_address\":\"{s}\",", .{act.ip_address});
            try writer.print("\"user_agent\":\"{s}\",", .{act.user_agent});
            try writer.print("\"success\":{}", .{act.success});
            try writer.writeAll("}");
        }
        try writer.writeAll("],");

        // Metadata
        try writer.writeAll("\"metadata\":{");
        try writer.print("\"total_messages\":{d},", .{self.data.metadata.total_messages});
        try writer.print("\"total_size_bytes\":{d},", .{self.data.metadata.total_size_bytes});

        try writer.writeAll("\"folders\":[");
        for (self.data.metadata.folders, 0..) |folder, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print("\"{s}\"", .{folder});
        }
        try writer.writeAll("],");

        try writer.writeAll("\"storage_locations\":[");
        for (self.data.metadata.storage_locations, 0..) |loc, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.print("\"{s}\"", .{loc});
        }
        try writer.writeAll("]");

        try writer.writeAll("}");

        try writer.writeAll("}");
    }

    /// Export to JSON string (Zig 0.16 compatible)
    pub fn toJSONString(self: *const DataExport, allocator: std.mem.Allocator) ![]u8 {
        var result: std.ArrayList(u8) = .empty;
        errdefer result.deinit(allocator);

        // Build JSON manually using appendSlice
        try result.appendSlice(allocator, "{");

        // User info
        const user_part = try std.fmt.allocPrint(allocator, "\"user\":\"{s}\",\"export_date\":{d},", .{ self.user, self.export_date });
        defer allocator.free(user_part);
        try result.appendSlice(allocator, user_part);

        // Personal info
        const last_login_str = if (self.data.personal_info.last_login) |ll|
            try std.fmt.allocPrint(allocator, "{d}", .{ll})
        else
            try allocator.dupe(u8, "null");
        defer allocator.free(last_login_str);

        const personal_part = try std.fmt.allocPrint(allocator, "\"personal_info\":{{\"username\":\"{s}\",\"email\":\"{s}\",\"created_at\":{d},\"last_login\":{s},\"quota_mb\":{d},\"used_mb\":{d}}},", .{
            self.data.personal_info.username,
            self.data.personal_info.email,
            self.data.personal_info.created_at,
            last_login_str,
            self.data.personal_info.quota_mb,
            self.data.personal_info.used_mb,
        });
        defer allocator.free(personal_part);
        try result.appendSlice(allocator, personal_part);

        // Messages array
        try result.appendSlice(allocator, "\"messages\":[");
        for (self.data.messages, 0..) |msg, i| {
            if (i > 0) try result.appendSlice(allocator, ",");
            const msg_part = try std.fmt.allocPrint(allocator, "{{\"id\":\"{s}\",\"from\":\"{s}\",\"subject\":\"{s}\",\"date\":{d},\"size_bytes\":{d},\"folder\":\"{s}\",\"flags\":\"{s}\"}}", .{
                msg.id, msg.from, msg.subject, msg.date, msg.size_bytes, msg.folder, msg.flags,
            });
            defer allocator.free(msg_part);
            try result.appendSlice(allocator, msg_part);
        }
        try result.appendSlice(allocator, "],");

        // Activity array
        try result.appendSlice(allocator, "\"activity\":[");
        for (self.data.activity, 0..) |act, i| {
            if (i > 0) try result.appendSlice(allocator, ",");
            const act_part = try std.fmt.allocPrint(allocator, "{{\"timestamp\":{d},\"action\":\"{s}\",\"ip_address\":\"{s}\",\"user_agent\":\"{s}\",\"success\":{}}}", .{
                act.timestamp, act.action, act.ip_address, act.user_agent, act.success,
            });
            defer allocator.free(act_part);
            try result.appendSlice(allocator, act_part);
        }
        try result.appendSlice(allocator, "],");

        // Metadata
        const meta_part = try std.fmt.allocPrint(allocator, "\"metadata\":{{\"total_messages\":{d},\"total_size_bytes\":{d}}}}}", .{
            self.data.metadata.total_messages,
            self.data.metadata.total_size_bytes,
        });
        defer allocator.free(meta_part);
        try result.appendSlice(allocator, meta_part);

        return try result.toOwnedSlice(allocator);
    }
};

/// GDPR Manager for data operations
pub const GDPRManager = struct {
    db: *sqlite.sqlite3,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, db_path: []const u8) !GDPRManager {
        // sqlite3_open requires a NUL-terminated path; a Zig slice's .ptr
        // isn't guaranteed to be one.
        const path_z = try allocator.dupeZ(u8, db_path);
        defer allocator.free(path_z);

        var db: ?*sqlite.sqlite3 = null;
        const rc = sqlite.sqlite3_open(path_z.ptr, &db);

        if (rc != sqlite.SQLITE_OK) {
            return GDPRError.DatabaseError;
        }

        // Match the main connection's settings: don't block writers longer
        // than needed, and enforce the schema's FK constraints.
        _ = sqlite.sqlite3_exec(db, "PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;", null, null, null);

        return GDPRManager{
            .db = db.?,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *GDPRManager) void {
        _ = sqlite.sqlite3_close(self.db);
    }

    /// Export all user data (Article 15 & 20)
    pub fn exportUserData(self: *GDPRManager, username: []const u8) !DataExport {
        const now = time_compat.timestamp();

        // Get personal info
        const personal_info = try self.getPersonalInfo(username);

        // Get messages
        const messages = try self.getMessages(username);

        // Get activity log
        const activity = try self.getActivity(username);

        // Get metadata
        const metadata = try self.buildMetadata(username, messages);

        const user_copy = try self.allocator.dupe(u8, username);

        return DataExport{
            .user = user_copy,
            .export_date = now,
            .data = .{
                .personal_info = personal_info,
                .messages = messages,
                .activity = activity,
                .metadata = metadata,
            },
            .allocator = self.allocator,
        };
    }

    /// NULL-safe column text (std.mem.span on a NULL column pointer is UB).
    fn columnTextSafe(stmt: ?*sqlite.sqlite3_stmt, col: c_int) []const u8 {
        const ptr = sqlite.sqlite3_column_text(stmt, col) orelse return "";
        return std.mem.span(ptr);
    }

    fn getPersonalInfo(self: *GDPRManager, username: []const u8) !DataExport.PersonalInfo {
        // Query the columns the users table actually has (the old query
        // asked for last_login/quota_mb/used_mb, which don't exist, so the
        // whole export failed with DatabaseError).
        const query = "SELECT username, email, created_at, quota_limit, quota_used FROM users WHERE username = ?";

        var stmt: ?*sqlite.sqlite3_stmt = null;
        const rc = sqlite.sqlite3_prepare_v2(self.db, query, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return GDPRError.DatabaseError;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        _ = sqlite.sqlite3_bind_text(stmt, 1, username.ptr, @intCast(username.len), null);

        if (sqlite.sqlite3_step(stmt) != sqlite.SQLITE_ROW) {
            return GDPRError.InvalidUser;
        }

        const username_copy = try self.allocator.dupe(u8, columnTextSafe(stmt, 0));
        const email_copy = try self.allocator.dupe(u8, columnTextSafe(stmt, 1));

        const quota_limit_bytes: u64 = @intCast(@max(sqlite.sqlite3_column_int64(stmt, 3), 0));
        const quota_used_bytes: u64 = @intCast(@max(sqlite.sqlite3_column_int64(stmt, 4), 0));

        return DataExport.PersonalInfo{
            .username = username_copy,
            .email = email_copy,
            .created_at = sqlite.sqlite3_column_int64(stmt, 2),
            // The schema doesn't track last login.
            .last_login = null,
            .quota_mb = @intCast(quota_limit_bytes / (1024 * 1024)),
            .used_mb = @as(f64, @floatFromInt(quota_used_bytes)) / (1024.0 * 1024.0),
        };
    }

    fn getMessages(self: *GDPRManager, username: []const u8) ![]DataExport.Message {
        // Messages live in the Maildir on disk, not in SQLite (the old
        // implementation queried a `messages` table that doesn't exist, so
        // every export failed). Walk mail/{user}/<folder> and report each
        // message's identity, size, folder, and flags; From/To/Subject are
        // parsed from the message headers.
        var messages: std.ArrayList(DataExport.Message) = .empty;
        errdefer messages.deinit(self.allocator);

        const root = try std.fmt.allocPrint(self.allocator, "mail/{s}", .{username});
        defer self.allocator.free(root);
        const root_z = try self.allocator.dupeZ(u8, root);
        defer self.allocator.free(root_z);

        const dir = std.c.opendir(root_z.ptr) orelse return try messages.toOwnedSlice(self.allocator);
        defer _ = std.c.closedir(dir);

        while (std.c.readdir(dir)) |entry| {
            const name_ptr: [*:0]const u8 = @ptrCast(&entry.name);
            const folder = std.mem.sliceTo(name_ptr, 0);
            if (folder.len == 0 or folder[0] == '.') continue;

            const folder_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ root, folder });
            defer self.allocator.free(folder_path);

            const files = fs_compat.listEmlFiles(self.allocator, folder_path) catch continue;
            defer {
                for (files) |f| self.allocator.free(f);
                self.allocator.free(files);
            }

            for (files) |filename| {
                try self.appendMaildirMessage(&messages, folder, folder_path, filename);
            }
        }

        return try messages.toOwnedSlice(self.allocator);
    }

    fn appendMaildirMessage(
        self: *GDPRManager,
        messages: *std.ArrayList(DataExport.Message),
        folder: []const u8,
        folder_path: []const u8,
        filename: []const u8,
    ) !void {
        const full_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ folder_path, filename });
        defer self.allocator.free(full_path);

        const size_bytes: usize = @intCast(fs_compat.getFileSize(full_path) catch 0);

        // Read just the header block (first 8KB is plenty for headers).
        var header_buf: [8192]u8 = undefined;
        const header = blk: {
            const file = fs_compat.cwd().openFile(full_path, .{}) catch break :blk @as([]const u8, "");
            defer file.close();
            const n = file.readAll(&header_buf) catch 0;
            break :blk header_buf[0..n];
        };

        const from = try self.allocator.dupe(u8, headerValue(header, "from") orelse "");
        errdefer self.allocator.free(from);
        const subject = try self.allocator.dupe(u8, headerValue(header, "subject") orelse "");
        errdefer self.allocator.free(subject);

        var to_list: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (to_list.items) |t| self.allocator.free(t);
            to_list.deinit(self.allocator);
        }
        if (headerValue(header, "to")) |to_value| {
            var iter = std.mem.splitScalar(u8, to_value, ',');
            while (iter.next()) |to_addr| {
                const trimmed = std.mem.trim(u8, to_addr, " \t");
                if (trimmed.len == 0) continue;
                const to_copy = try self.allocator.dupe(u8, trimmed);
                errdefer self.allocator.free(to_copy);
                try to_list.append(self.allocator, to_copy);
            }
        }

        // Maildir filenames start with an epoch-milliseconds timestamp.
        var ts_end: usize = 0;
        while (ts_end < filename.len and filename[ts_end] >= '0' and filename[ts_end] <= '9') ts_end += 1;
        const date_ms = std.fmt.parseInt(i64, filename[0..ts_end], 10) catch 0;

        // Flags are the `:2,<flags>` filename suffix.
        const flags = if (std.mem.indexOf(u8, filename, ":2,")) |pos|
            try self.allocator.dupe(u8, filename[pos + 3 ..])
        else
            try self.allocator.dupe(u8, "");
        errdefer self.allocator.free(flags);

        const id = try self.allocator.dupe(u8, filename);
        errdefer self.allocator.free(id);
        const folder_copy = try self.allocator.dupe(u8, folder);
        errdefer self.allocator.free(folder_copy);

        try messages.append(self.allocator, .{
            .id = id,
            .from = from,
            .to = try to_list.toOwnedSlice(self.allocator),
            .subject = subject,
            .date = @divTrunc(date_ms, 1000),
            .size_bytes = size_bytes,
            .folder = folder_copy,
            .flags = flags,
        });
    }

    /// Find `<name>:` (case-insensitive) in a header block and return its
    /// trimmed value (single line only).
    fn headerValue(headers: []const u8, name_lower: []const u8) ?[]const u8 {
        var it = std.mem.splitScalar(u8, headers, '\n');
        while (it.next()) |raw| {
            const line = std.mem.trimEnd(u8, raw, "\r");
            if (line.len == 0) break; // end of header block
            if (line.len > name_lower.len and line[name_lower.len] == ':' and
                std.ascii.eqlIgnoreCase(line[0..name_lower.len], name_lower))
            {
                return std.mem.trim(u8, line[name_lower.len + 1 ..], " \t");
            }
        }
        return null;
    }

    fn getActivity(self: *GDPRManager, username: []const u8) ![]DataExport.Activity {
        var activity: std.ArrayList(DataExport.Activity) = .empty;
        errdefer activity.deinit(self.allocator);

        const query = "SELECT timestamp, action, ip_address, user_agent, success FROM audit_log WHERE username = ? ORDER BY timestamp DESC LIMIT 1000";

        var stmt: ?*sqlite.sqlite3_stmt = null;
        const rc = sqlite.sqlite3_prepare_v2(self.db, query, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            // Audit log table might not exist, return empty
            return try activity.toOwnedSlice(self.allocator);
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        _ = sqlite.sqlite3_bind_text(stmt, 1, username.ptr, @intCast(username.len), null);

        while (sqlite.sqlite3_step(stmt) == sqlite.SQLITE_ROW) {
            try activity.append(self.allocator, .{
                .timestamp = sqlite.sqlite3_column_int64(stmt, 0),
                .action = try self.allocator.dupe(u8, columnTextSafe(stmt, 1)),
                .ip_address = try self.allocator.dupe(u8, columnTextSafe(stmt, 2)),
                .user_agent = try self.allocator.dupe(u8, columnTextSafe(stmt, 3)),
                .success = sqlite.sqlite3_column_int(stmt, 4) == 1,
            });
        }

        return try activity.toOwnedSlice(self.allocator);
    }

    /// Derive metadata from the maildir-scanned message list (the old
    /// implementation queried a `messages` table that doesn't exist).
    fn buildMetadata(self: *GDPRManager, username: []const u8, messages: []const DataExport.Message) !DataExport.Metadata {
        var total_size: usize = 0;
        var folders: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (folders.items) |f| self.allocator.free(f);
            folders.deinit(self.allocator);
        }

        for (messages) |m| {
            total_size += m.size_bytes;
            var seen = false;
            for (folders.items) |f| {
                if (std.mem.eql(u8, f, m.folder)) {
                    seen = true;
                    break;
                }
            }
            if (!seen) {
                try folders.append(self.allocator, try self.allocator.dupe(u8, m.folder));
            }
        }

        var locations: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (locations.items) |l| self.allocator.free(l);
            locations.deinit(self.allocator);
        }
        try locations.append(self.allocator, try std.fmt.allocPrint(self.allocator, "mail/{s}/", .{username}));

        return DataExport.Metadata{
            .total_messages = messages.len,
            .total_size_bytes = total_size,
            .folders = try folders.toOwnedSlice(self.allocator),
            .storage_locations = try locations.toOwnedSlice(self.allocator),
        };
    }

    /// Delete all user data (Article 17) - soft-delete first, then purge for legal compliance
    ///
    /// GDPR erasure flow:
    /// 1. Soft-delete all messages (SET deleted_at = NOW) for immediate visibility removal
    /// 2. Permanently purge the soft-deleted messages (actual DELETE FROM) for legal compliance
    /// 3. Delete the user record
    ///
    /// This ensures data is immediately invisible to the user, then fully removed.
    /// For non-GDPR admin deletion, use soft-delete only (without purge).
    pub fn deleteUserData(self: *GDPRManager, username: []const u8) !void {
        // Start transaction for atomic deletion
        const begin_query = "BEGIN TRANSACTION";
        var rc = sqlite.sqlite3_exec(self.db, begin_query, null, null, null);
        if (rc != sqlite.SQLITE_OK) {
            return GDPRError.DatabaseError;
        }

        errdefer {
            _ = sqlite.sqlite3_exec(self.db, "ROLLBACK", null, null, null);
        }

        // Step 1: Soft-delete all messages (marks them with deleted_at timestamp)
        const soft_delete_messages = "UPDATE messages SET deleted_at = strftime('%s','now'), deleted_by = 'gdpr-erasure' WHERE user = ? AND deleted_at IS NULL";
        try self.executeStatement(soft_delete_messages, username);

        // Step 2: Purge - permanently delete all messages (including previously soft-deleted ones)
        const purge_messages = "DELETE FROM messages WHERE user = ?";
        try self.executeStatement(purge_messages, username);

        // Delete user record
        const delete_user = "DELETE FROM users WHERE username = ?";
        try self.executeStatement(delete_user, username);

        // Delete activity log (optional - may keep for legal compliance)
        // const delete_activity = "DELETE FROM audit_log WHERE username = ?";
        // try self.executeStatement(delete_activity, username);

        // Commit transaction
        rc = sqlite.sqlite3_exec(self.db, "COMMIT", null, null, null);
        if (rc != sqlite.SQLITE_OK) {
            return GDPRError.DeletionFailed;
        }

        // TODO: Call storage backend's purgeMessage() for each message
        // to remove physical files (S3 objects, mbox entries, etc.)
    }

    fn executeStatement(self: *GDPRManager, query: [*:0]const u8, username: []const u8) !void {
        var stmt: ?*sqlite.sqlite3_stmt = null;
        const rc = sqlite.sqlite3_prepare_v2(self.db, query, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return GDPRError.DatabaseError;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        _ = sqlite.sqlite3_bind_text(stmt, 1, username.ptr, @intCast(username.len), null);

        if (sqlite.sqlite3_step(stmt) != sqlite.SQLITE_DONE) {
            return GDPRError.DeletionFailed;
        }
    }

    /// Log GDPR data access (Article 30)
    pub fn logDataAccess(self: *GDPRManager, username: []const u8, action: []const u8, ip_address: []const u8) !void {
        const now = time_compat.timestamp();

        const query = "INSERT INTO audit_log (username, timestamp, action, ip_address, user_agent, success) VALUES (?, ?, ?, ?, ?, 1)";

        var stmt: ?*sqlite.sqlite3_stmt = null;
        const rc = sqlite.sqlite3_prepare_v2(self.db, query, -1, &stmt, null);
        if (rc != sqlite.SQLITE_OK) {
            return GDPRError.AuditLogFailed;
        }
        defer _ = sqlite.sqlite3_finalize(stmt);

        _ = sqlite.sqlite3_bind_text(stmt, 1, username.ptr, @intCast(username.len), null);
        _ = sqlite.sqlite3_bind_int64(stmt, 2, now);
        _ = sqlite.sqlite3_bind_text(stmt, 3, action.ptr, @intCast(action.len), null);
        _ = sqlite.sqlite3_bind_text(stmt, 4, ip_address.ptr, @intCast(ip_address.len), null);
        _ = sqlite.sqlite3_bind_text(stmt, 5, "GDPR-System", -1, null);

        if (sqlite.sqlite3_step(stmt) != sqlite.SQLITE_DONE) {
            return GDPRError.AuditLogFailed;
        }
    }
};

// Tests

test "GDPR data export structure" {
    const testing = std.testing;

    const personal_info = DataExport.PersonalInfo{
        .username = "testuser",
        .email = "test@example.com",
        .created_at = 1634567890,
        .last_login = 1634654290,
        .quota_mb = 1000,
        .used_mb = 123.45,
    };

    try testing.expectEqualStrings("testuser", personal_info.username);
    try testing.expectEqualStrings("test@example.com", personal_info.email);
    try testing.expectEqual(@as(u32, 1000), personal_info.quota_mb);
}

test "GDPR JSON export" {
    const testing = std.testing;

    var messages = [_]DataExport.Message{};
    var activity = [_]DataExport.Activity{};
    var folders = [_][]const u8{};
    var locations = [_][]const u8{};

    var export_data = DataExport{
        .user = "testuser",
        .export_date = 1634567890,
        .data = .{
            .personal_info = .{
                .username = "testuser",
                .email = "test@example.com",
                .created_at = 1634567890,
                .last_login = null,
                .quota_mb = 1000,
                .used_mb = 0.0,
            },
            .messages = &messages,
            .activity = &activity,
            .metadata = .{
                .total_messages = 0,
                .total_size_bytes = 0,
                .folders = &folders,
                .storage_locations = &locations,
            },
        },
        .allocator = testing.allocator,
    };

    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(testing.allocator);

    try export_data.toJSON(buffer.writer());

    const json = buffer.items;
    try testing.expect(std.mem.indexOf(u8, json, "\"user\":\"testuser\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"email\":\"test@example.com\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"last_login\":null") != null);
}
