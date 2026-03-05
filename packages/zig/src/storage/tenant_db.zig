const std = @import("std");
const time_compat = @import("../core/time_compat.zig");
// Note: sqlite module not available in Zig 0.16 - using stub
// const sqlite = @import("sqlite");
const multitenancy = @import("../features/multitenancy.zig");

// Stub types for when sqlite is not available
const SqliteDb = struct {
    pub fn init(_: anytype) !SqliteDb {
        return .{};
    }
    pub fn deinit(_: *SqliteDb) void {}
    pub fn exec(_: *SqliteDb, _: []const u8) !void {}
};
const sqlite = struct {
    pub const Db = SqliteDb;
};

/// Database operations for multi-tenancy
pub const TenantDB = struct {
    db: *sqlite.Db,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, db_path: []const u8) !*TenantDB {
        const db = try allocator.create(sqlite.Db);
        errdefer allocator.destroy(db);

        db.* = try sqlite.Db.init(.{
            .mode = sqlite.Db.Mode{ .File = db_path },
            .open_flags = .{
                .write = true,
                .create = true,
            },
            .threading_mode = .MultiThread,
        });

        const tenant_db = try allocator.create(TenantDB);
        tenant_db.* = .{
            .db = db,
            .allocator = allocator,
        };

        return tenant_db;
    }

    pub fn deinit(self: *TenantDB) void {
        self.db.deinit();
        self.allocator.destroy(self.db);
        self.allocator.destroy(self);
    }

    /// Create a new tenant
    pub fn createTenant(self: *TenantDB, tenant: *const multitenancy.Tenant) !void {
        const query =
            \\INSERT INTO tenants (id, name, domain, enabled, created_at, updated_at,
            \\                     max_users, max_domains, max_storage_mb, max_messages_per_day,
            \\                     tier, features, metadata)
            \\VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ;

        // Serialize features to JSON
        var features_json = std.ArrayList(u8).init(self.allocator);
        defer features_json.deinit();

        try std.json.stringify(tenant.features, .{}, features_json.writer());

        var stmt = try self.db.prepareDynamic(query);
        defer stmt.deinit();

        stmt.bind(.text, 1, tenant.id);
        stmt.bind(.text, 2, tenant.name);
        stmt.bind(.text, 3, tenant.domain);
        stmt.bind(.int64, 4, if (tenant.enabled) @as(i64, 1) else @as(i64, 0));
        stmt.bind(.int64, 5, tenant.created_at);
        stmt.bind(.int64, 6, tenant.updated_at);
        stmt.bind(.int64, 7, @intCast(tenant.max_users));
        stmt.bind(.int64, 8, @intCast(tenant.max_domains));
        stmt.bind(.int64, 9, @intCast(tenant.max_storage_mb));
        stmt.bind(.int64, 10, @intCast(tenant.max_messages_per_day));

        // Determine tier from limits
        const tier_name = if (tenant.max_users == 0) "enterprise" else if (tenant.max_users >= 100) "professional" else if (tenant.max_users >= 25) "starter" else "free";
        stmt.bind(.text, 11, tier_name);
        stmt.bind(.text, 12, features_json.items);

        if (tenant.metadata) |metadata| {
            stmt.bind(.text, 13, metadata);
        } else {
            stmt.bind(.null, 13, {});
        }

        try stmt.exec();
    }

    /// Get tenant by ID
    pub fn getTenant(self: *TenantDB, tenant_id: []const u8) !?multitenancy.Tenant {
        const query =
            \\SELECT id, name, domain, enabled, created_at, updated_at,
            \\       max_users, max_domains, max_storage_mb, max_messages_per_day,
            \\       features, metadata
            \\FROM tenants
            \\WHERE id = ?
        ;

        var stmt = try self.db.prepareDynamic(query);
        defer stmt.deinit();

        stmt.bind(.text, 1, tenant_id);

        const row = (try stmt.step()) orelse return null;

        const id = try self.allocator.dupe(u8, row.text(0));
        const name = try self.allocator.dupe(u8, row.text(1));
        const domain = try self.allocator.dupe(u8, row.text(2));
        const enabled = row.int64(3) != 0;
        const created_at = row.int64(4);
        const updated_at = row.int64(5);
        const max_users: u32 = @intCast(row.int64(6));
        const max_domains: u32 = @intCast(row.int64(7));
        const max_storage_mb: u64 = @intCast(row.int64(8));
        const max_messages_per_day: u32 = @intCast(row.int64(9));

        // Parse features JSON
        const features_json = row.text(10);
        const parsed = try std.json.parseFromSlice(
            multitenancy.TenantFeatures,
            self.allocator,
            features_json,
            .{},
        );
        defer parsed.deinit();

        const metadata = if (row.columnType(11) == .null) null else try self.allocator.dupe(u8, row.text(11));

        return multitenancy.Tenant{
            .id = id,
            .name = name,
            .domain = domain,
            .enabled = enabled,
            .created_at = created_at,
            .updated_at = updated_at,
            .max_users = max_users,
            .max_domains = max_domains,
            .max_storage_mb = max_storage_mb,
            .max_messages_per_day = max_messages_per_day,
            .features = parsed.value,
            .metadata = metadata,
            .allocator = self.allocator,
        };
    }

    /// Get tenant by domain
    pub fn getTenantByDomain(self: *TenantDB, domain: []const u8) !?multitenancy.Tenant {
        const query =
            \\SELECT id, name, domain, enabled, created_at, updated_at,
            \\       max_users, max_domains, max_storage_mb, max_messages_per_day,
            \\       features, metadata
            \\FROM tenants
            \\WHERE domain = ? AND enabled = 1
        ;

        var stmt = try self.db.prepareDynamic(query);
        defer stmt.deinit();

        stmt.bind(.text, 1, domain);

        const row = (try stmt.step()) orelse return null;

        const id = try self.allocator.dupe(u8, row.text(0));
        const name = try self.allocator.dupe(u8, row.text(1));
        const domain_str = try self.allocator.dupe(u8, row.text(2));
        const enabled = row.int64(3) != 0;
        const created_at = row.int64(4);
        const updated_at = row.int64(5);
        const max_users: u32 = @intCast(row.int64(6));
        const max_domains: u32 = @intCast(row.int64(7));
        const max_storage_mb: u64 = @intCast(row.int64(8));
        const max_messages_per_day: u32 = @intCast(row.int64(9));

        const features_json = row.text(10);
        const parsed = try std.json.parseFromSlice(
            multitenancy.TenantFeatures,
            self.allocator,
            features_json,
            .{},
        );
        defer parsed.deinit();

        const metadata = if (row.columnType(11) == .null) null else try self.allocator.dupe(u8, row.text(11));

        return multitenancy.Tenant{
            .id = id,
            .name = name,
            .domain = domain_str,
            .enabled = enabled,
            .created_at = created_at,
            .updated_at = updated_at,
            .max_users = max_users,
            .max_domains = max_domains,
            .max_storage_mb = max_storage_mb,
            .max_messages_per_day = max_messages_per_day,
            .features = parsed.value,
            .metadata = metadata,
            .allocator = self.allocator,
        };
    }

    /// Update tenant
    pub fn updateTenant(self: *TenantDB, tenant: *const multitenancy.Tenant) !void {
        const query =
            \\UPDATE tenants
            \\SET name = ?, domain = ?, enabled = ?, updated_at = ?,
            \\    max_users = ?, max_domains = ?, max_storage_mb = ?, max_messages_per_day = ?,
            \\    features = ?, metadata = ?
            \\WHERE id = ?
        ;

        var features_json = std.ArrayList(u8).init(self.allocator);
        defer features_json.deinit();

        try std.json.stringify(tenant.features, .{}, features_json.writer());

        var stmt = try self.db.prepareDynamic(query);
        defer stmt.deinit();

        stmt.bind(.text, 1, tenant.name);
        stmt.bind(.text, 2, tenant.domain);
        stmt.bind(.int64, 3, if (tenant.enabled) @as(i64, 1) else @as(i64, 0));
        stmt.bind(.int64, 4, time_compat.timestamp());
        stmt.bind(.int64, 5, @intCast(tenant.max_users));
        stmt.bind(.int64, 6, @intCast(tenant.max_domains));
        stmt.bind(.int64, 7, @intCast(tenant.max_storage_mb));
        stmt.bind(.int64, 8, @intCast(tenant.max_messages_per_day));
        stmt.bind(.text, 9, features_json.items);

        if (tenant.metadata) |metadata| {
            stmt.bind(.text, 10, metadata);
        } else {
            stmt.bind(.null, 10, {});
        }

        stmt.bind(.text, 11, tenant.id);

        try stmt.exec();
    }

    /// Delete tenant
    pub fn deleteTenant(self: *TenantDB, tenant_id: []const u8) !void {
        const query = "DELETE FROM tenants WHERE id = ?";

        var stmt = try self.db.prepareDynamic(query);
        defer stmt.deinit();

        stmt.bind(.text, 1, tenant_id);

        try stmt.exec();
    }

    /// Get user count for tenant
    pub fn getUserCount(self: *TenantDB, tenant_id: []const u8) !u32 {
        const query = "SELECT COUNT(*) FROM users WHERE tenant_id = ?";

        var stmt = try self.db.prepareDynamic(query);
        defer stmt.deinit();

        stmt.bind(.text, 1, tenant_id);

        const row = (try stmt.step()) orelse return 0;
        return @intCast(row.int64(0));
    }

    /// Get domain count for tenant
    pub fn getDomainCount(self: *TenantDB, tenant_id: []const u8) !u32 {
        const query = "SELECT COUNT(*) FROM tenant_domains WHERE tenant_id = ?";

        var stmt = try self.db.prepareDynamic(query);
        defer stmt.deinit();

        stmt.bind(.text, 1, tenant_id);

        const row = (try stmt.step()) orelse return 1; // At least primary domain
        return @intCast(row.int64(0) + 1); // +1 for primary domain
    }

    /// Get storage usage for tenant
    pub fn getStorageUsageMB(self: *TenantDB, tenant_id: []const u8) !u64 {
        const query =
            \\SELECT storage_used_mb FROM tenant_usage
            \\WHERE tenant_id = ? AND date = date('now')
        ;

        var stmt = try self.db.prepareDynamic(query);
        defer stmt.deinit();

        stmt.bind(.text, 1, tenant_id);

        const row = (try stmt.step()) orelse return 0;
        return @intCast(row.int64(0));
    }

    /// Get today's message count for tenant
    pub fn getTodayMessageCount(self: *TenantDB, tenant_id: []const u8) !u32 {
        const query =
            \\SELECT messages_sent FROM tenant_usage
            \\WHERE tenant_id = ? AND date = date('now')
        ;

        var stmt = try self.db.prepareDynamic(query);
        defer stmt.deinit();

        stmt.bind(.text, 1, tenant_id);

        const row = (try stmt.step()) orelse return 0;
        return @intCast(row.int64(0));
    }

    /// Increment message count for tenant
    pub fn incrementMessageCount(self: *TenantDB, tenant_id: []const u8) !void {
        const query =
            \\INSERT INTO tenant_usage (tenant_id, date, messages_sent, messages_received, storage_used_mb, users_count, domains_count)
            \\VALUES (?, date('now'), 1, 0, 0, 0, 0)
            \\ON CONFLICT(tenant_id, date) DO UPDATE SET messages_sent = messages_sent + 1
        ;

        var stmt = try self.db.prepareDynamic(query);
        defer stmt.deinit();

        stmt.bind(.text, 1, tenant_id);

        try stmt.exec();
    }

    /// List all tenants
    pub fn listTenants(self: *TenantDB) ![]multitenancy.Tenant {
        const query =
            \\SELECT id, name, domain, enabled, created_at, updated_at,
            \\       max_users, max_domains, max_storage_mb, max_messages_per_day,
            \\       features, metadata
            \\FROM tenants
            \\ORDER BY created_at DESC
        ;

        var stmt = try self.db.prepareDynamic(query);
        defer stmt.deinit();

        var tenants = std.ArrayList(multitenancy.Tenant).init(self.allocator);

        while (try stmt.step()) |row| {
            const id = try self.allocator.dupe(u8, row.text(0));
            const name = try self.allocator.dupe(u8, row.text(1));
            const domain = try self.allocator.dupe(u8, row.text(2));
            const enabled = row.int64(3) != 0;
            const created_at = row.int64(4);
            const updated_at = row.int64(5);
            const max_users: u32 = @intCast(row.int64(6));
            const max_domains: u32 = @intCast(row.int64(7));
            const max_storage_mb: u64 = @intCast(row.int64(8));
            const max_messages_per_day: u32 = @intCast(row.int64(9));

            const features_json = row.text(10);
            const parsed = try std.json.parseFromSlice(
                multitenancy.TenantFeatures,
                self.allocator,
                features_json,
                .{},
            );
            defer parsed.deinit();

            const metadata = if (row.columnType(11) == .null) null else try self.allocator.dupe(u8, row.text(11));

            try tenants.append(multitenancy.Tenant{
                .id = id,
                .name = name,
                .domain = domain,
                .enabled = enabled,
                .created_at = created_at,
                .updated_at = updated_at,
                .max_users = max_users,
                .max_domains = max_domains,
                .max_storage_mb = max_storage_mb,
                .max_messages_per_day = max_messages_per_day,
                .features = parsed.value,
                .metadata = metadata,
                .allocator = self.allocator,
            });
        }

        return tenants.toOwnedSlice();
    }
};
