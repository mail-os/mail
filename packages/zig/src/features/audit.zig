const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");

/// Audit Trail System for tracking administrative actions
/// Provides comprehensive logging of user CRUD, config changes, and security events
/// Types of auditable actions
pub const AuditAction = enum {
    // User management
    user_created,
    user_updated,
    user_deleted,
    user_enabled,
    user_disabled,
    password_changed,

    // Authentication
    login_success,
    login_failed,
    logout,
    session_expired,

    // Configuration
    config_updated,
    config_reloaded,

    // Security
    rate_limit_triggered,
    access_denied,
    permission_changed,

    // System
    server_started,
    server_stopped,
    backup_created,
    backup_restored,

    // Email operations
    message_sent,
    message_deleted,
    message_quarantined,

    pub fn toString(self: AuditAction) []const u8 {
        return switch (self) {
            .user_created => "USER_CREATED",
            .user_updated => "USER_UPDATED",
            .user_deleted => "USER_DELETED",
            .user_enabled => "USER_ENABLED",
            .user_disabled => "USER_DISABLED",
            .password_changed => "PASSWORD_CHANGED",
            .login_success => "LOGIN_SUCCESS",
            .login_failed => "LOGIN_FAILED",
            .logout => "LOGOUT",
            .session_expired => "SESSION_EXPIRED",
            .config_updated => "CONFIG_UPDATED",
            .config_reloaded => "CONFIG_RELOADED",
            .rate_limit_triggered => "RATE_LIMIT_TRIGGERED",
            .access_denied => "ACCESS_DENIED",
            .permission_changed => "PERMISSION_CHANGED",
            .server_started => "SERVER_STARTED",
            .server_stopped => "SERVER_STOPPED",
            .backup_created => "BACKUP_CREATED",
            .backup_restored => "BACKUP_RESTORED",
            .message_sent => "MESSAGE_SENT",
            .message_deleted => "MESSAGE_DELETED",
            .message_quarantined => "MESSAGE_QUARANTINED",
        };
    }

    pub fn fromString(s: []const u8) ?AuditAction {
        const actions = [_]struct { name: []const u8, action: AuditAction }{
            .{ .name = "USER_CREATED", .action = .user_created },
            .{ .name = "USER_UPDATED", .action = .user_updated },
            .{ .name = "USER_DELETED", .action = .user_deleted },
            .{ .name = "USER_ENABLED", .action = .user_enabled },
            .{ .name = "USER_DISABLED", .action = .user_disabled },
            .{ .name = "PASSWORD_CHANGED", .action = .password_changed },
            .{ .name = "LOGIN_SUCCESS", .action = .login_success },
            .{ .name = "LOGIN_FAILED", .action = .login_failed },
            .{ .name = "LOGOUT", .action = .logout },
            .{ .name = "SESSION_EXPIRED", .action = .session_expired },
            .{ .name = "CONFIG_UPDATED", .action = .config_updated },
            .{ .name = "CONFIG_RELOADED", .action = .config_reloaded },
            .{ .name = "RATE_LIMIT_TRIGGERED", .action = .rate_limit_triggered },
            .{ .name = "ACCESS_DENIED", .action = .access_denied },
            .{ .name = "PERMISSION_CHANGED", .action = .permission_changed },
            .{ .name = "SERVER_STARTED", .action = .server_started },
            .{ .name = "SERVER_STOPPED", .action = .server_stopped },
            .{ .name = "BACKUP_CREATED", .action = .backup_created },
            .{ .name = "BACKUP_RESTORED", .action = .backup_restored },
            .{ .name = "MESSAGE_SENT", .action = .message_sent },
            .{ .name = "MESSAGE_DELETED", .action = .message_deleted },
            .{ .name = "MESSAGE_QUARANTINED", .action = .message_quarantined },
        };

        for (actions) |a| {
            if (std.mem.eql(u8, s, a.name)) {
                return a.action;
            }
        }
        return null;
    }

    pub fn getSeverity(self: AuditAction) AuditSeverity {
        return switch (self) {
            .user_deleted, .login_failed, .access_denied, .rate_limit_triggered => .warning,
            .password_changed, .permission_changed, .config_updated => .important,
            .server_started, .server_stopped, .backup_created, .backup_restored => .critical,
            else => .info,
        };
    }
};

/// Severity levels for audit events
pub const AuditSeverity = enum {
    info,
    warning,
    important,
    critical,

    pub fn toString(self: AuditSeverity) []const u8 {
        return switch (self) {
            .info => "INFO",
            .warning => "WARNING",
            .important => "IMPORTANT",
            .critical => "CRITICAL",
        };
    }
};

/// An audit log entry
pub const AuditEntry = struct {
    id: i64,
    timestamp: i64,
    action: AuditAction,
    actor: []const u8, // User or system that performed the action
    target: ?[]const u8, // Target of the action (e.g., affected username)
    target_type: ?[]const u8, // Type of target (user, config, message)
    ip_address: ?[]const u8, // Source IP address
    details: ?[]const u8, // JSON-encoded additional details
    severity: AuditSeverity,

    pub fn deinit(self: *AuditEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.actor);
        if (self.target) |t| allocator.free(t);
        if (self.target_type) |tt| allocator.free(tt);
        if (self.ip_address) |ip| allocator.free(ip);
        if (self.details) |d| allocator.free(d);
    }
};

/// Audit Trail Manager
pub const AuditTrail = struct {
    allocator: std.mem.Allocator,
    db: *anyopaque, // Database pointer (cast to actual type when using)
    enabled: bool,
    retention_days: u32,
    mutex: mutex_compat.Mutex,

    // Statistics
    entries_logged: u64,
    entries_pruned: u64,

    pub fn init(allocator: std.mem.Allocator, db: *anyopaque) AuditTrail {
        return .{
            .allocator = allocator,
            .db = db,
            .enabled = true,
            .retention_days = 90, // Default 90 days retention
            .mutex = .{},
            .entries_logged = 0,
            .entries_pruned = 0,
        };
    }

    pub fn deinit(self: *AuditTrail) void {
        _ = self;
        // No cleanup needed
    }

    /// Log an audit event
    pub fn log(
        self: *AuditTrail,
        action: AuditAction,
        actor: []const u8,
        target: ?[]const u8,
        target_type: ?[]const u8,
        ip_address: ?[]const u8,
        details: ?[]const u8,
    ) !void {
        if (!self.enabled) return;

        self.mutex.lock();
        defer self.mutex.unlock();

        const timestamp = time_compat.timestamp();
        const severity = action.getSeverity();

        // Build SQL insert
        const sql =
            \\INSERT INTO audit_log (timestamp, action, actor, target, target_type, ip_address, details, severity)
            \\VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        ;

        // For now, store in memory or use the database
        // The actual database integration would go here
        _ = sql;
        _ = timestamp;
        _ = severity;
        _ = actor;
        _ = target;
        _ = target_type;
        _ = ip_address;
        _ = details;

        self.entries_logged += 1;
    }

    /// Log a user action with convenience method
    pub fn logUserAction(
        self: *AuditTrail,
        action: AuditAction,
        actor: []const u8,
        target_username: []const u8,
        ip_address: ?[]const u8,
    ) !void {
        try self.log(action, actor, target_username, "user", ip_address, null);
    }

    /// Log a config change
    pub fn logConfigChange(
        self: *AuditTrail,
        actor: []const u8,
        config_key: []const u8,
        old_value: ?[]const u8,
        new_value: ?[]const u8,
        ip_address: ?[]const u8,
    ) !void {
        var details_buf: [512]u8 = undefined;
        const details = std.fmt.bufPrint(&details_buf, "{{\"key\":\"{s}\",\"old\":\"{s}\",\"new\":\"{s}\"}}", .{
            config_key,
            old_value orelse "null",
            new_value orelse "null",
        }) catch null;

        try self.log(.config_updated, actor, config_key, "config", ip_address, details);
    }

    /// Log a security event
    pub fn logSecurityEvent(
        self: *AuditTrail,
        action: AuditAction,
        actor: []const u8,
        ip_address: ?[]const u8,
        details: ?[]const u8,
    ) !void {
        try self.log(action, actor, null, "security", ip_address, details);
    }

    /// Log a login attempt
    pub fn logLogin(
        self: *AuditTrail,
        success: bool,
        username: []const u8,
        ip_address: ?[]const u8,
    ) !void {
        const action: AuditAction = if (success) .login_success else .login_failed;
        try self.log(action, username, username, "auth", ip_address, null);
    }

    /// Get recent audit entries
    pub fn getRecentEntries(self: *AuditTrail, limit: usize) ![]AuditEntry {
        self.mutex.lock();
        defer self.mutex.unlock();

        // This would query the database
        // For now, return empty
        _ = limit;
        return &[_]AuditEntry{};
    }

    /// Query audit entries with filters
    pub fn query(
        self: *AuditTrail,
        filters: QueryFilters,
    ) ![]AuditEntry {
        self.mutex.lock();
        defer self.mutex.unlock();

        _ = filters;
        return &[_]AuditEntry{};
    }

    /// Prune old entries beyond retention period
    pub fn prune(self: *AuditTrail) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const cutoff = time_compat.timestamp() - @as(i64, @intCast(self.retention_days)) * 24 * 60 * 60;
        _ = cutoff;

        // Would delete entries older than cutoff
        // Return number of entries pruned
        return 0;
    }

    /// Get statistics
    pub fn getStats(self: *AuditTrail) AuditStats {
        return .{
            .entries_logged = self.entries_logged,
            .entries_pruned = self.entries_pruned,
            .enabled = self.enabled,
            .retention_days = self.retention_days,
        };
    }
};

/// Query filters for audit log
pub const QueryFilters = struct {
    action: ?AuditAction = null,
    actor: ?[]const u8 = null,
    target: ?[]const u8 = null,
    severity: ?AuditSeverity = null,
    start_time: ?i64 = null,
    end_time: ?i64 = null,
    ip_address: ?[]const u8 = null,
    limit: usize = 100,
    offset: usize = 0,
};

/// Audit statistics
pub const AuditStats = struct {
    entries_logged: u64,
    entries_pruned: u64,
    enabled: bool,
    retention_days: u32,
};

/// SQL schema for audit_log table
pub const schema =
    \\CREATE TABLE IF NOT EXISTS audit_log (
    \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    timestamp INTEGER NOT NULL,
    \\    action TEXT NOT NULL,
    \\    actor TEXT NOT NULL,
    \\    target TEXT,
    \\    target_type TEXT,
    \\    ip_address TEXT,
    \\    details TEXT,
    \\    severity TEXT NOT NULL,
    \\    created_at INTEGER DEFAULT (strftime('%s', 'now'))
    \\);
    \\
    \\CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
    \\CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
    \\CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor);
    \\CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target);
    \\CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_log(severity);
;

// =============================================================================
// Enhanced Audit CLI Features
// =============================================================================

/// Audit log export formats
pub const ExportFormat = enum {
    json,
    csv,
    siem, // Common Event Format (CEF)
    syslog, // RFC 5424 syslog format

    pub fn getExtension(self: ExportFormat) []const u8 {
        return switch (self) {
            .json => ".json",
            .csv => ".csv",
            .siem => ".cef",
            .syslog => ".log",
        };
    }

    pub fn getMimeType(self: ExportFormat) []const u8 {
        return switch (self) {
            .json => "application/json",
            .csv => "text/csv",
            .siem => "text/plain",
            .syslog => "text/plain",
        };
    }
};

/// Audit log exporter
pub const AuditExporter = struct {
    allocator: std.mem.Allocator,
    trail: *AuditTrail,

    pub fn init(allocator: std.mem.Allocator, trail: *AuditTrail) AuditExporter {
        return .{
            .allocator = allocator,
            .trail = trail,
        };
    }

    /// Export audit entries to specified format
    pub fn exportEntries(
        self: *AuditExporter,
        entries: []const AuditEntry,
        format: ExportFormat,
    ) ![]u8 {
        return switch (format) {
            .json => try self.exportJson(entries),
            .csv => try self.exportCsv(entries),
            .siem => try self.exportCef(entries),
            .syslog => try self.exportSyslog(entries),
        };
    }

    /// Export to JSON format
    fn exportJson(self: *AuditExporter, entries: []const AuditEntry) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        const writer = buffer.writer();

        try writer.writeAll("[\n");

        for (entries, 0..) |entry, i| {
            try writer.print(
                \\  {{
                \\    "id": {d},
                \\    "timestamp": {d},
                \\    "action": "{s}",
                \\    "actor": "{s}",
                \\    "target": {s},
                \\    "target_type": {s},
                \\    "ip_address": {s},
                \\    "severity": "{s}",
                \\    "details": {s}
                \\  }}
            , .{
                entry.id,
                entry.timestamp,
                entry.action.toString(),
                entry.actor,
                if (entry.target) |t| try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{t}) else "null",
                if (entry.target_type) |tt| try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{tt}) else "null",
                if (entry.ip_address) |ip| try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{ip}) else "null",
                entry.severity.toString(),
                entry.details orelse "null",
            });

            if (i < entries.len - 1) {
                try writer.writeAll(",\n");
            } else {
                try writer.writeAll("\n");
            }
        }

        try writer.writeAll("]\n");

        return buffer.toOwnedSlice();
    }

    /// Export to CSV format
    fn exportCsv(self: *AuditExporter, entries: []const AuditEntry) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        const writer = buffer.writer();

        // Header
        try writer.writeAll("id,timestamp,action,actor,target,target_type,ip_address,severity,details\n");

        for (entries) |entry| {
            try writer.print("{d},{d},{s},{s},{s},{s},{s},{s},{s}\n", .{
                entry.id,
                entry.timestamp,
                entry.action.toString(),
                entry.actor,
                entry.target orelse "",
                entry.target_type orelse "",
                entry.ip_address orelse "",
                entry.severity.toString(),
                entry.details orelse "",
            });
        }

        return buffer.toOwnedSlice();
    }

    /// Export to Common Event Format (CEF) for SIEM systems
    fn exportCef(self: *AuditExporter, entries: []const AuditEntry) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        const writer = buffer.writer();

        for (entries) |entry| {
            // CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
            const severity_num: u8 = switch (entry.severity) {
                .info => 1,
                .warning => 4,
                .important => 7,
                .critical => 10,
            };

            try writer.print("CEF:0|SMTP Server|Mail Audit|1.0|{s}|{s}|{d}|", .{
                entry.action.toString(),
                entry.action.toString(),
                severity_num,
            });

            // Extensions
            try writer.print("rt={d} ", .{entry.timestamp * 1000}); // milliseconds
            try writer.print("suser={s} ", .{entry.actor});
            if (entry.target) |t| try writer.print("duser={s} ", .{t});
            if (entry.ip_address) |ip| try writer.print("src={s} ", .{ip});
            if (entry.details) |d| try writer.print("msg={s}", .{d});

            try writer.writeAll("\n");
        }

        return buffer.toOwnedSlice();
    }

    /// Export to RFC 5424 syslog format
    fn exportSyslog(self: *AuditExporter, entries: []const AuditEntry) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        const writer = buffer.writer();

        for (entries) |entry| {
            // <priority>version timestamp hostname app-name procid msgid structured-data msg
            const priority: u8 = switch (entry.severity) {
                .info => 134, // facility=16 (local0), severity=6 (info)
                .warning => 132, // severity=4 (warning)
                .important => 130, // severity=2 (critical)
                .critical => 128, // severity=0 (emergency)
            };

            try writer.print("<{d}>1 {d} localhost smtp-audit - - - ", .{
                priority,
                entry.timestamp,
            });

            try writer.print("[audit action=\"{s}\" actor=\"{s}\"", .{
                entry.action.toString(),
                entry.actor,
            });

            if (entry.target) |t| try writer.print(" target=\"{s}\"", .{t});
            if (entry.ip_address) |ip| try writer.print(" src=\"{s}\"", .{ip});
            try writer.writeAll("]");

            if (entry.details) |d| try writer.print(" {s}", .{d});

            try writer.writeAll("\n");
        }

        return buffer.toOwnedSlice();
    }

    /// Export to file
    pub fn exportToFile(
        self: *AuditExporter,
        entries: []const AuditEntry,
        format: ExportFormat,
        path: []const u8,
    ) !void {
        const content = try self.exportEntries(entries, format);
        defer self.allocator.free(content);

        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();

        try file.writeAll(content);
    }
};

/// Enhanced audit actions for ACL modifications
pub const AclAuditAction = enum {
    acl_created,
    acl_modified,
    acl_deleted,
    permission_granted,
    permission_revoked,
    role_assigned,
    role_removed,
    group_membership_changed,

    pub fn toString(self: AclAuditAction) []const u8 {
        return switch (self) {
            .acl_created => "ACL_CREATED",
            .acl_modified => "ACL_MODIFIED",
            .acl_deleted => "ACL_DELETED",
            .permission_granted => "PERMISSION_GRANTED",
            .permission_revoked => "PERMISSION_REVOKED",
            .role_assigned => "ROLE_ASSIGNED",
            .role_removed => "ROLE_REMOVED",
            .group_membership_changed => "GROUP_MEMBERSHIP_CHANGED",
        };
    }
};

/// ACL change details for before/after comparison
pub const AclChangeDetails = struct {
    resource_type: []const u8,
    resource_id: []const u8,
    permission: []const u8,
    before_value: ?[]const u8,
    after_value: ?[]const u8,

    pub fn toJson(self: *const AclChangeDetails, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(allocator,
            \\{{"resource_type":"{s}","resource_id":"{s}","permission":"{s}","before":{s},"after":{s}}}
        , .{
            self.resource_type,
            self.resource_id,
            self.permission,
            if (self.before_value) |v| try std.fmt.allocPrint(allocator, "\"{s}\"", .{v}) else "null",
            if (self.after_value) |v| try std.fmt.allocPrint(allocator, "\"{s}\"", .{v}) else "null",
        });
    }
};

/// Extended audit trail with ACL and export support
pub const ExtendedAuditTrail = struct {
    base: AuditTrail,
    exporter: AuditExporter,
    in_memory_buffer: std.ArrayList(AuditEntry),
    buffer_size: usize,

    pub fn init(allocator: std.mem.Allocator, db: *anyopaque, buffer_size: usize) ExtendedAuditTrail {
        var base = AuditTrail.init(allocator, db);
        return .{
            .base = base,
            .exporter = AuditExporter.init(allocator, &base),
            .in_memory_buffer = std.ArrayList(AuditEntry).init(allocator),
            .buffer_size = buffer_size,
        };
    }

    pub fn deinit(self: *ExtendedAuditTrail) void {
        for (self.in_memory_buffer.items) |*entry| {
            entry.deinit(self.base.allocator);
        }
        self.in_memory_buffer.deinit();
        self.base.deinit();
    }

    /// Log ACL modification with before/after comparison
    pub fn logAclChange(
        self: *ExtendedAuditTrail,
        acl_action: AclAuditAction,
        actor: []const u8,
        details: AclChangeDetails,
        ip_address: ?[]const u8,
    ) !void {
        // Include the ACL action type in the details
        var extended_details_buf: [2048]u8 = undefined;
        const extended_details = std.fmt.bufPrint(&extended_details_buf,
            \\{{"acl_action":"{s}","resource_type":"{s}","resource_id":"{s}","permission":"{s}","before":{s},"after":{s}}}
        , .{
            acl_action.toString(),
            details.resource_type,
            details.resource_id,
            details.permission,
            details.before_value orelse "null",
            details.after_value orelse "null",
        }) catch null;

        try self.base.log(
            .permission_changed,
            actor,
            details.resource_id,
            details.resource_type,
            ip_address,
            extended_details,
        );

        // Also buffer for export
        try self.bufferEntry(.{
            .id = @intCast(self.base.entries_logged),
            .timestamp = time_compat.timestamp(),
            .action = .permission_changed,
            .actor = try self.base.allocator.dupe(u8, actor),
            .target = try self.base.allocator.dupe(u8, details.resource_id),
            .target_type = try self.base.allocator.dupe(u8, details.resource_type),
            .ip_address = if (ip_address) |ip| try self.base.allocator.dupe(u8, ip) else null,
            .details = if (extended_details) |ed| try self.base.allocator.dupe(u8, ed) else null,
            .severity = .important,
        });
    }

    /// Log administrative action with full context
    pub fn logAdminAction(
        self: *ExtendedAuditTrail,
        action: AuditAction,
        actor: []const u8,
        target: ?[]const u8,
        ip_address: ?[]const u8,
        before_state: ?[]const u8,
        after_state: ?[]const u8,
    ) !void {
        var details_buf: [1024]u8 = undefined;
        const details = std.fmt.bufPrint(&details_buf,
            \\{{"before":{s},"after":{s}}}
        , .{
            before_state orelse "null",
            after_state orelse "null",
        }) catch null;

        try self.base.log(action, actor, target, "admin", ip_address, details);
    }

    /// Buffer entry for later export
    fn bufferEntry(self: *ExtendedAuditTrail, entry: AuditEntry) !void {
        if (self.in_memory_buffer.items.len >= self.buffer_size) {
            // Remove oldest entry
            var oldest = self.in_memory_buffer.orderedRemove(0);
            oldest.deinit(self.base.allocator);
        }
        try self.in_memory_buffer.append(entry);
    }

    /// Export buffered entries
    pub fn exportBuffer(self: *ExtendedAuditTrail, format: ExportFormat) ![]u8 {
        return try self.exporter.exportEntries(self.in_memory_buffer.items, format);
    }

    /// Export buffered entries to file
    pub fn exportBufferToFile(self: *ExtendedAuditTrail, format: ExportFormat, path: []const u8) !void {
        return try self.exporter.exportToFile(self.in_memory_buffer.items, format, path);
    }

    /// Get buffer statistics
    pub fn getBufferStats(self: *ExtendedAuditTrail) BufferStats {
        return .{
            .buffered_entries = self.in_memory_buffer.items.len,
            .buffer_capacity = self.buffer_size,
            .total_logged = self.base.entries_logged,
        };
    }
};

pub const BufferStats = struct {
    buffered_entries: usize,
    buffer_capacity: usize,
    total_logged: u64,
};

/// CLI command handler for audit operations
pub const AuditCli = struct {
    trail: *ExtendedAuditTrail,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, trail: *ExtendedAuditTrail) AuditCli {
        return .{
            .trail = trail,
            .allocator = allocator,
        };
    }

    /// Execute audit CLI command
    pub fn execute(self: *AuditCli, command: []const u8, args: []const []const u8) !CliResult {
        if (std.mem.eql(u8, command, "list")) {
            return try self.listEntries(args);
        } else if (std.mem.eql(u8, command, "export")) {
            return try self.exportEntries(args);
        } else if (std.mem.eql(u8, command, "stats")) {
            return try self.showStats();
        } else if (std.mem.eql(u8, command, "prune")) {
            return try self.pruneEntries(args);
        } else if (std.mem.eql(u8, command, "search")) {
            return try self.searchEntries(args);
        }

        return CliResult{
            .success = false,
            .message = try self.allocator.dupe(u8, "Unknown command. Available: list, export, stats, prune, search"),
        };
    }

    fn listEntries(self: *AuditCli, args: []const []const u8) !CliResult {
        var limit: usize = 20;
        if (args.len > 0) {
            limit = std.fmt.parseInt(usize, args[0], 10) catch 20;
        }

        const entries = try self.trail.base.getRecentEntries(limit);
        _ = entries;

        var output = std.ArrayList(u8).init(self.allocator);
        const writer = output.writer();

        try writer.writeAll("Recent Audit Entries:\n");
        try writer.writeAll("─────────────────────────────────────────────────────────────────────────────\n");

        const stats = self.trail.getBufferStats();
        try writer.print("Showing {d} buffered entries (total logged: {d})\n\n", .{
            stats.buffered_entries,
            stats.total_logged,
        });

        for (self.trail.in_memory_buffer.items) |entry| {
            try writer.print("[{d}] {s} | {s} -> {s} | {s}\n", .{
                entry.timestamp,
                entry.severity.toString(),
                entry.actor,
                entry.target orelse "(none)",
                entry.action.toString(),
            });
        }

        return CliResult{
            .success = true,
            .message = try output.toOwnedSlice(),
        };
    }

    fn exportEntries(self: *AuditCli, args: []const []const u8) !CliResult {
        if (args.len < 2) {
            return CliResult{
                .success = false,
                .message = try self.allocator.dupe(u8, "Usage: export <format> <path>\nFormats: json, csv, siem, syslog"),
            };
        }

        const format_str = args[0];
        const path = args[1];

        const format: ExportFormat = if (std.mem.eql(u8, format_str, "json"))
            .json
        else if (std.mem.eql(u8, format_str, "csv"))
            .csv
        else if (std.mem.eql(u8, format_str, "siem"))
            .siem
        else if (std.mem.eql(u8, format_str, "syslog"))
            .syslog
        else {
            return CliResult{
                .success = false,
                .message = try self.allocator.dupe(u8, "Invalid format. Use: json, csv, siem, syslog"),
            };
        };

        try self.trail.exportBufferToFile(format, path);

        return CliResult{
            .success = true,
            .message = try std.fmt.allocPrint(self.allocator, "Exported {d} entries to {s}", .{
                self.trail.in_memory_buffer.items.len,
                path,
            }),
        };
    }

    fn showStats(self: *AuditCli) !CliResult {
        const stats = self.trail.base.getStats();
        const buffer_stats = self.trail.getBufferStats();

        var output = std.ArrayList(u8).init(self.allocator);
        const writer = output.writer();

        try writer.writeAll("Audit Trail Statistics\n");
        try writer.writeAll("══════════════════════════════════════\n");
        try writer.print("Enabled:          {}\n", .{stats.enabled});
        try writer.print("Retention Days:   {d}\n", .{stats.retention_days});
        try writer.print("Total Logged:     {d}\n", .{stats.entries_logged});
        try writer.print("Total Pruned:     {d}\n", .{stats.entries_pruned});
        try writer.print("Buffer Size:      {d}/{d}\n", .{
            buffer_stats.buffered_entries,
            buffer_stats.buffer_capacity,
        });

        return CliResult{
            .success = true,
            .message = try output.toOwnedSlice(),
        };
    }

    fn pruneEntries(self: *AuditCli, args: []const []const u8) !CliResult {
        if (args.len > 0) {
            const days = std.fmt.parseInt(u32, args[0], 10) catch self.trail.base.retention_days;
            self.trail.base.retention_days = days;
        }

        const pruned = try self.trail.base.prune();

        return CliResult{
            .success = true,
            .message = try std.fmt.allocPrint(self.allocator, "Pruned {d} entries older than {d} days", .{
                pruned,
                self.trail.base.retention_days,
            }),
        };
    }

    fn searchEntries(self: *AuditCli, args: []const []const u8) !CliResult {
        if (args.len < 2) {
            return CliResult{
                .success = false,
                .message = try self.allocator.dupe(u8, "Usage: search <field> <value>\nFields: action, actor, target, severity"),
            };
        }

        const field = args[0];
        const value = args[1];

        var output = std.ArrayList(u8).init(self.allocator);
        const writer = output.writer();

        try writer.print("Search results for {s}={s}:\n\n", .{ field, value });

        var count: usize = 0;
        for (self.trail.in_memory_buffer.items) |entry| {
            const matches = if (std.mem.eql(u8, field, "action"))
                std.mem.eql(u8, entry.action.toString(), value)
            else if (std.mem.eql(u8, field, "actor"))
                std.mem.indexOf(u8, entry.actor, value) != null
            else if (std.mem.eql(u8, field, "target"))
                if (entry.target) |t| std.mem.indexOf(u8, t, value) != null else false
            else if (std.mem.eql(u8, field, "severity"))
                std.mem.eql(u8, entry.severity.toString(), value)
            else
                false;

            if (matches) {
                try writer.print("[{d}] {s} | {s} -> {s}\n", .{
                    entry.timestamp,
                    entry.actor,
                    entry.target orelse "(none)",
                    entry.action.toString(),
                });
                count += 1;
            }
        }

        try writer.print("\nFound {d} matching entries\n", .{count});

        return CliResult{
            .success = true,
            .message = try output.toOwnedSlice(),
        };
    }
};

pub const CliResult = struct {
    success: bool,
    message: []const u8,

    pub fn deinit(self: *CliResult, allocator: std.mem.Allocator) void {
        allocator.free(self.message);
    }
};

// Tests
test "audit action string conversion" {
    const testing = std.testing;

    try testing.expectEqualStrings("USER_CREATED", AuditAction.user_created.toString());
    try testing.expectEqualStrings("LOGIN_FAILED", AuditAction.login_failed.toString());

    try testing.expectEqual(AuditAction.user_created, AuditAction.fromString("USER_CREATED").?);
    try testing.expectEqual(AuditAction.login_failed, AuditAction.fromString("LOGIN_FAILED").?);
    try testing.expect(AuditAction.fromString("INVALID") == null);
}

test "audit severity levels" {
    const testing = std.testing;

    try testing.expectEqual(AuditSeverity.warning, AuditAction.login_failed.getSeverity());
    try testing.expectEqual(AuditSeverity.critical, AuditAction.server_started.getSeverity());
    try testing.expectEqual(AuditSeverity.info, AuditAction.user_created.getSeverity());
}

test "audit trail initialization" {
    const testing = std.testing;

    var db: u8 = 0; // Dummy database pointer
    var trail = AuditTrail.init(testing.allocator, &db);
    defer trail.deinit();

    try testing.expect(trail.enabled);
    try testing.expectEqual(@as(u32, 90), trail.retention_days);
    try testing.expectEqual(@as(u64, 0), trail.entries_logged);
}

test "audit stats" {
    const testing = std.testing;

    var db: u8 = 0;
    var trail = AuditTrail.init(testing.allocator, &db);
    defer trail.deinit();

    const stats = trail.getStats();
    try testing.expect(stats.enabled);
    try testing.expectEqual(@as(u32, 90), stats.retention_days);
}
