const std = @import("std");
const time_compat = @import("../core/time_compat.zig");

/// Multi-tenancy support for SMTP server
/// Enables multiple isolated organizations to share the same infrastructure
/// Each tenant has isolated data, quotas, and configuration

/// Tenant information
pub const Tenant = struct {
    id: []const u8,
    name: []const u8,
    domain: []const u8,
    enabled: bool,
    created_at: i64,
    updated_at: i64,

    // Resource limits
    max_users: u32,
    max_domains: u32,
    max_storage_mb: u64,
    max_messages_per_day: u32,

    // Features enabled
    features: TenantFeatures,

    // Metadata
    metadata: ?[]const u8, // JSON string

    allocator: std.mem.Allocator,

    pub fn deinit(self: *Tenant, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.name);
        allocator.free(self.domain);
        if (self.metadata) |metadata| {
            allocator.free(metadata);
        }
    }
};

/// Features that can be enabled per tenant
pub const TenantFeatures = struct {
    spam_filtering: bool = true,
    virus_scanning: bool = true,
    dkim_signing: bool = true,
    mailing_lists: bool = false,
    webhooks: bool = false,
    api_access: bool = true,
    custom_domains: bool = false,
    priority_support: bool = false,
};

/// Tenant tier/plan
pub const TenantTier = enum {
    free,
    starter,
    professional,
    enterprise,

    pub fn getLimits(self: TenantTier) TenantLimits {
        return switch (self) {
            .free => TenantLimits{
                .max_users = 5,
                .max_domains = 1,
                .max_storage_mb = 1024, // 1 GB
                .max_messages_per_day = 100,
            },
            .starter => TenantLimits{
                .max_users = 25,
                .max_domains = 3,
                .max_storage_mb = 10240, // 10 GB
                .max_messages_per_day = 1000,
            },
            .professional => TenantLimits{
                .max_users = 100,
                .max_domains = 10,
                .max_storage_mb = 102400, // 100 GB
                .max_messages_per_day = 10000,
            },
            .enterprise => TenantLimits{
                .max_users = 0, // unlimited
                .max_domains = 0, // unlimited
                .max_storage_mb = 0, // unlimited
                .max_messages_per_day = 0, // unlimited
            },
        };
    }

    pub fn getFeatures(self: TenantTier) TenantFeatures {
        return switch (self) {
            .free => TenantFeatures{
                .spam_filtering = true,
                .virus_scanning = false,
                .dkim_signing = false,
                .mailing_lists = false,
                .webhooks = false,
                .api_access = false,
                .custom_domains = false,
                .priority_support = false,
            },
            .starter => TenantFeatures{
                .spam_filtering = true,
                .virus_scanning = true,
                .dkim_signing = true,
                .mailing_lists = false,
                .webhooks = false,
                .api_access = true,
                .custom_domains = false,
                .priority_support = false,
            },
            .professional => TenantFeatures{
                .spam_filtering = true,
                .virus_scanning = true,
                .dkim_signing = true,
                .mailing_lists = true,
                .webhooks = true,
                .api_access = true,
                .custom_domains = true,
                .priority_support = false,
            },
            .enterprise => TenantFeatures{
                .spam_filtering = true,
                .virus_scanning = true,
                .dkim_signing = true,
                .mailing_lists = true,
                .webhooks = true,
                .api_access = true,
                .custom_domains = true,
                .priority_support = true,
            },
        };
    }
};

pub const TenantLimits = struct {
    max_users: u32,
    max_domains: u32,
    max_storage_mb: u64,
    max_messages_per_day: u32,
};

/// Tenant context for request handling
pub const TenantContext = struct {
    tenant_id: []const u8,
    tenant: *Tenant,
    user_id: ?[]const u8,

    pub fn init(tenant_id: []const u8, tenant: *Tenant, user_id: ?[]const u8) TenantContext {
        return .{
            .tenant_id = tenant_id,
            .tenant = tenant,
            .user_id = user_id,
        };
    }
};

const TenantDB = @import("../storage/tenant_db.zig").TenantDB;

/// Multi-tenancy manager
pub const MultiTenancyManager = struct {
    allocator: std.mem.Allocator,
    db: *TenantDB,
    tenant_cache: std.StringHashMap(*Tenant),
    cache_mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator, db: *TenantDB) !*MultiTenancyManager {
        const manager = try allocator.create(MultiTenancyManager);
        manager.* = .{
            .allocator = allocator,
            .db = db,
            .tenant_cache = std.StringHashMap(*Tenant).init(allocator),
            .cache_mutex = std.Thread.Mutex{},
        };
        return manager;
    }

    pub fn deinit(self: *MultiTenancyManager) void {
        // Clear cache
        self.cache_mutex.lock();
        defer self.cache_mutex.unlock();

        var iter = self.tenant_cache.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.*.deinit(self.allocator);
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.tenant_cache.deinit();

        self.allocator.destroy(self);
    }

    /// Get tenant by ID
    pub fn getTenant(self: *MultiTenancyManager, tenant_id: []const u8) !*Tenant {
        // Check cache first
        self.cache_mutex.lock();
        if (self.tenant_cache.get(tenant_id)) |tenant| {
            self.cache_mutex.unlock();
            return tenant;
        }
        self.cache_mutex.unlock();

        // Load from database
        const tenant_opt = try self.db.getTenant(tenant_id);
        if (tenant_opt) |tenant_data| {
            const tenant = try self.allocator.create(Tenant);
            tenant.* = tenant_data;

            // Add to cache
            self.cache_mutex.lock();
            defer self.cache_mutex.unlock();
            try self.tenant_cache.put(try self.allocator.dupe(u8, tenant_id), tenant);

            return tenant;
        }

        return error.TenantNotFound;
    }

    /// Get tenant by domain
    pub fn getTenantByDomain(self: *MultiTenancyManager, domain: []const u8) !*Tenant {
        // Load from database
        const tenant_opt = try self.db.getTenantByDomain(domain);
        if (tenant_opt) |tenant_data| {
            const tenant = try self.allocator.create(Tenant);
            tenant.* = tenant_data;

            // Add to cache
            self.cache_mutex.lock();
            defer self.cache_mutex.unlock();
            try self.tenant_cache.put(try self.allocator.dupe(u8, tenant_data.id), tenant);

            return tenant;
        }

        return error.TenantNotFound;
    }

    /// Create new tenant
    pub fn createTenant(
        self: *MultiTenancyManager,
        name: []const u8,
        domain: []const u8,
        tier: TenantTier,
    ) !*Tenant {
        const tenant_id = try self.generateTenantId();
        defer self.allocator.free(tenant_id);

        const limits = tier.getLimits();
        const features = tier.getFeatures();

        const tenant = try self.allocator.create(Tenant);
        tenant.* = .{
            .id = try self.allocator.dupe(u8, tenant_id),
            .name = try self.allocator.dupe(u8, name),
            .domain = try self.allocator.dupe(u8, domain),
            .enabled = true,
            .created_at = time_compat.timestamp(),
            .updated_at = time_compat.timestamp(),
            .max_users = limits.max_users,
            .max_domains = limits.max_domains,
            .max_storage_mb = limits.max_storage_mb,
            .max_messages_per_day = limits.max_messages_per_day,
            .features = features,
            .metadata = null,
            .allocator = self.allocator,
        };

        // Save to database
        try self.db.createTenant(tenant);

        // Add to cache
        self.cache_mutex.lock();
        defer self.cache_mutex.unlock();
        try self.tenant_cache.put(try self.allocator.dupe(u8, tenant_id), tenant);

        return tenant;
    }

    /// Update tenant
    pub fn updateTenant(self: *MultiTenancyManager, tenant: *Tenant) !void {
        tenant.updated_at = time_compat.timestamp();

        // Update in database
        try self.db.updateTenant(tenant);

        // Update cache
        self.cache_mutex.lock();
        defer self.cache_mutex.unlock();

        if (self.tenant_cache.get(tenant.id)) |cached_tenant| {
            // Update cached tenant
            cached_tenant.name = try self.allocator.dupe(u8, tenant.name);
            cached_tenant.domain = try self.allocator.dupe(u8, tenant.domain);
            cached_tenant.enabled = tenant.enabled;
            cached_tenant.updated_at = tenant.updated_at;
            cached_tenant.max_users = tenant.max_users;
            cached_tenant.max_domains = tenant.max_domains;
            cached_tenant.max_storage_mb = tenant.max_storage_mb;
            cached_tenant.max_messages_per_day = tenant.max_messages_per_day;
            cached_tenant.features = tenant.features;
        }
    }

    /// Delete tenant
    pub fn deleteTenant(self: *MultiTenancyManager, tenant_id: []const u8) !void {
        // Delete from database
        try self.db.deleteTenant(tenant_id);

        // Remove from cache
        self.cache_mutex.lock();
        defer self.cache_mutex.unlock();

        if (self.tenant_cache.fetchRemove(tenant_id)) |entry| {
            entry.value.deinit(self.allocator);
            self.allocator.destroy(entry.value);
        }
    }

    /// Check if tenant has reached limit
    pub fn checkLimit(self: *MultiTenancyManager, tenant_id: []const u8, limit_type: LimitType) !bool {
        const tenant = try self.getTenant(tenant_id);

        return switch (limit_type) {
            .users => tenant.max_users == 0 or try self.getUserCount(tenant_id) < tenant.max_users,
            .domains => tenant.max_domains == 0 or try self.getDomainCount(tenant_id) < tenant.max_domains,
            .storage => tenant.max_storage_mb == 0 or try self.getStorageUsageMB(tenant_id) < tenant.max_storage_mb,
            .messages_per_day => tenant.max_messages_per_day == 0 or try self.getTodayMessageCount(tenant_id) < tenant.max_messages_per_day,
        };
    }

    /// Generate unique tenant ID
    fn generateTenantId(self: *MultiTenancyManager) ![]const u8 {
        var buf: [16]u8 = undefined;
        std.c.arc4random_buf(&buf, buf.len);

        const id = try std.fmt.allocPrint(
            self.allocator,
            "tenant_{s}",
            .{std.fmt.fmtSliceHexLower(&buf)},
        );

        return id;
    }

    // Database-backed usage tracking methods
    fn getUserCount(self: *MultiTenancyManager, tenant_id: []const u8) !u32 {
        return try self.db.getUserCount(tenant_id);
    }

    fn getDomainCount(self: *MultiTenancyManager, tenant_id: []const u8) !u32 {
        return try self.db.getDomainCount(tenant_id);
    }

    fn getStorageUsageMB(self: *MultiTenancyManager, tenant_id: []const u8) !u64 {
        return try self.db.getStorageUsageMB(tenant_id);
    }

    fn getTodayMessageCount(self: *MultiTenancyManager, tenant_id: []const u8) !u32 {
        return try self.db.getTodayMessageCount(tenant_id);
    }
};

pub const LimitType = enum {
    users,
    domains,
    storage,
    messages_per_day,
};

/// Tenant isolation helper
pub const TenantIsolation = struct {
    /// Add tenant filter to SQL WHERE clause
    pub fn addTenantFilter(query: []const u8, tenant_id: []const u8, allocator: std.mem.Allocator) ![]const u8 {
        if (std.mem.indexOf(u8, query, "WHERE")) |_| {
            return try std.fmt.allocPrint(
                allocator,
                "{s} AND tenant_id = '{s}'",
                .{ query, tenant_id },
            );
        } else {
            return try std.fmt.allocPrint(
                allocator,
                "{s} WHERE tenant_id = '{s}'",
                .{ query, tenant_id },
            );
        }
    }

    /// Validate tenant access to resource
    pub fn validateAccess(tenant_id: []const u8, resource_tenant_id: []const u8) !void {
        if (!std.mem.eql(u8, tenant_id, resource_tenant_id)) {
            return error.UnauthorizedTenantAccess;
        }
    }
};

test "tenant tier limits" {
    const free_limits = TenantTier.free.getLimits();
    try std.testing.expectEqual(@as(u32, 5), free_limits.max_users);
    try std.testing.expectEqual(@as(u32, 1), free_limits.max_domains);

    const enterprise_limits = TenantTier.enterprise.getLimits();
    try std.testing.expectEqual(@as(u32, 0), enterprise_limits.max_users); // unlimited
}

test "tenant features by tier" {
    const free_features = TenantTier.free.getFeatures();
    try std.testing.expect(free_features.spam_filtering);
    try std.testing.expect(!free_features.webhooks);

    const enterprise_features = TenantTier.enterprise.getFeatures();
    try std.testing.expect(enterprise_features.priority_support);
}

// ============================================================================
// Connection Integration
// ============================================================================

/// Tenant connection handler for SMTP connections
/// Extracts tenant from email domain and applies tenant-specific settings
pub const TenantConnectionHandler = struct {
    manager: *MultiTenancyManager,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, manager: *MultiTenancyManager) TenantConnectionHandler {
        return .{
            .manager = manager,
            .allocator = allocator,
        };
    }

    /// Extract tenant from MAIL FROM or RCPT TO address
    pub fn resolveTenantFromEmail(self: *TenantConnectionHandler, email: []const u8) !?*Tenant {
        // Extract domain from email
        const domain = extractDomain(email) orelse return null;

        // Look up tenant by domain
        return self.manager.getTenantByDomain(domain) catch |err| switch (err) {
            error.TenantNotFound => return null,
            else => return err,
        };
    }

    /// Extract domain from email address
    fn extractDomain(email: []const u8) ?[]const u8 {
        if (std.mem.indexOf(u8, email, "@")) |at_pos| {
            const domain = email[at_pos + 1 ..];
            // Strip any trailing >
            if (std.mem.indexOf(u8, domain, ">")) |bracket| {
                return domain[0..bracket];
            }
            return domain;
        }
        return null;
    }

    /// Create tenant context for a connection
    pub fn createContext(self: *TenantConnectionHandler, tenant: *Tenant, user_id: ?[]const u8) TenantContext {
        _ = self;
        return TenantContext.init(tenant.id, tenant, user_id);
    }

    /// Validate connection is allowed for tenant
    pub fn validateConnection(self: *TenantConnectionHandler, tenant: *Tenant) !ConnectionValidation {
        if (!tenant.enabled) {
            return .{ .allowed = false, .reason = "Tenant is disabled" };
        }

        // Check daily message limit
        const can_send = self.manager.checkLimit(tenant.id, .messages_per_day) catch false;
        if (!can_send) {
            return .{ .allowed = false, .reason = "Daily message limit exceeded" };
        }

        return .{ .allowed = true, .reason = null };
    }

    pub const ConnectionValidation = struct {
        allowed: bool,
        reason: ?[]const u8,
    };
};

// ============================================================================
// Tenant-Aware Rate Limiting
// ============================================================================

/// Rate limiter that applies per-tenant limits
pub const TenantRateLimiter = struct {
    allocator: std.mem.Allocator,
    tenant_buckets: std.StringHashMap(*TenantBucket),
    mutex: std.Thread.Mutex,
    default_config: RateLimitConfig,

    pub const RateLimitConfig = struct {
        requests_per_second: u32 = 100,
        burst_size: u32 = 200,
        connections_per_ip: u32 = 10,
        messages_per_connection: u32 = 100,
    };

    const TenantBucket = struct {
        tenant_id: []const u8,
        tokens: f64,
        last_update: i64,
        config: RateLimitConfig,
        ip_connections: std.StringHashMap(u32),

        fn init(allocator: std.mem.Allocator, tenant_id: []const u8, config: RateLimitConfig) !*TenantBucket {
            const bucket = try allocator.create(TenantBucket);
            bucket.* = .{
                .tenant_id = try allocator.dupe(u8, tenant_id),
                .tokens = @floatFromInt(config.burst_size),
                .last_update = time_compat.timestamp(),
                .config = config,
                .ip_connections = std.StringHashMap(u32).init(allocator),
            };
            return bucket;
        }

        fn deinit(self: *TenantBucket, allocator: std.mem.Allocator) void {
            allocator.free(self.tenant_id);
            self.ip_connections.deinit();
            allocator.destroy(self);
        }
    };

    pub fn init(allocator: std.mem.Allocator) TenantRateLimiter {
        return .{
            .allocator = allocator,
            .tenant_buckets = std.StringHashMap(*TenantBucket).init(allocator),
            .mutex = std.Thread.Mutex{},
            .default_config = .{},
        };
    }

    pub fn deinit(self: *TenantRateLimiter) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var iter = self.tenant_buckets.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.*.deinit(self.allocator);
        }
        self.tenant_buckets.deinit();
    }

    /// Check if request is allowed for tenant
    pub fn checkRequest(self: *TenantRateLimiter, tenant_id: []const u8, ip_address: ?[]const u8) !RateLimitResult {
        self.mutex.lock();
        defer self.mutex.unlock();

        const bucket = try self.getOrCreateBucket(tenant_id);
        const now = time_compat.timestamp();

        // Refill tokens based on time elapsed
        const elapsed = now - bucket.last_update;
        const refill: f64 = @as(f64, @floatFromInt(elapsed)) * @as(f64, @floatFromInt(bucket.config.requests_per_second));
        bucket.tokens = @min(bucket.tokens + refill, @as(f64, @floatFromInt(bucket.config.burst_size)));
        bucket.last_update = now;

        // Check IP connection limit
        if (ip_address) |ip| {
            const ip_count = bucket.ip_connections.get(ip) orelse 0;
            if (ip_count >= bucket.config.connections_per_ip) {
                return .{
                    .allowed = false,
                    .reason = .ip_limit_exceeded,
                    .retry_after_seconds = 60,
                };
            }
        }

        // Check token bucket
        if (bucket.tokens >= 1.0) {
            bucket.tokens -= 1.0;
            return .{
                .allowed = true,
                .reason = null,
                .retry_after_seconds = null,
            };
        }

        // Calculate retry time
        const tokens_needed: f64 = 1.0 - bucket.tokens;
        const seconds_to_wait: u32 = @intFromFloat(@ceil(tokens_needed / @as(f64, @floatFromInt(bucket.config.requests_per_second))));

        return .{
            .allowed = false,
            .reason = .rate_limit_exceeded,
            .retry_after_seconds = seconds_to_wait,
        };
    }

    /// Record a connection from IP for tenant
    pub fn recordConnection(self: *TenantRateLimiter, tenant_id: []const u8, ip_address: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const bucket = try self.getOrCreateBucket(tenant_id);
        const current = bucket.ip_connections.get(ip_address) orelse 0;
        try bucket.ip_connections.put(ip_address, current + 1);
    }

    /// Release a connection from IP for tenant
    pub fn releaseConnection(self: *TenantRateLimiter, tenant_id: []const u8, ip_address: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.tenant_buckets.get(tenant_id)) |bucket| {
            if (bucket.ip_connections.get(ip_address)) |count| {
                if (count > 1) {
                    bucket.ip_connections.put(ip_address, count - 1) catch {};
                } else {
                    _ = bucket.ip_connections.remove(ip_address);
                }
            }
        }
    }

    /// Set custom rate limit config for tenant
    pub fn setTenantConfig(self: *TenantRateLimiter, tenant_id: []const u8, config: RateLimitConfig) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const bucket = try self.getOrCreateBucket(tenant_id);
        bucket.config = config;
    }

    fn getOrCreateBucket(self: *TenantRateLimiter, tenant_id: []const u8) !*TenantBucket {
        if (self.tenant_buckets.get(tenant_id)) |bucket| {
            return bucket;
        }

        const bucket = try TenantBucket.init(self.allocator, tenant_id, self.default_config);
        try self.tenant_buckets.put(try self.allocator.dupe(u8, tenant_id), bucket);
        return bucket;
    }

    pub const RateLimitResult = struct {
        allowed: bool,
        reason: ?RateLimitReason,
        retry_after_seconds: ?u32,
    };

    pub const RateLimitReason = enum {
        rate_limit_exceeded,
        ip_limit_exceeded,
        connection_limit_exceeded,
    };
};

// ============================================================================
// Tenant-Specific Configuration
// ============================================================================

/// Per-tenant configuration overrides
pub const TenantConfig = struct {
    tenant_id: []const u8,

    // SMTP Settings
    smtp: SmtpConfig,

    // Security Settings
    security: SecurityConfig,

    // Delivery Settings
    delivery: DeliveryConfig,

    // Storage Settings
    storage: StorageConfig,

    pub const SmtpConfig = struct {
        max_message_size: u64 = 10 * 1024 * 1024, // 10 MB default
        max_recipients: u32 = 100,
        require_tls: bool = false,
        allowed_auth_methods: []const AuthMethod = &[_]AuthMethod{ .plain, .login },
        banner: ?[]const u8 = null, // Custom SMTP banner

        pub const AuthMethod = enum { plain, login, cram_md5, oauth2 };
    };

    pub const SecurityConfig = struct {
        require_spf: bool = false,
        require_dkim: bool = false,
        require_dmarc: bool = false,
        spam_threshold: f32 = 5.0,
        virus_scan_enabled: bool = true,
        quarantine_spam: bool = true,
        reject_spam: bool = false,
    };

    pub const DeliveryConfig = struct {
        max_retries: u32 = 3,
        retry_interval_seconds: u32 = 300,
        delivery_timeout_seconds: u32 = 600,
        dsn_enabled: bool = true,
        forward_undeliverable: ?[]const u8 = null, // Email to forward to
    };

    pub const StorageConfig = struct {
        retention_days: u32 = 365,
        archive_after_days: u32 = 90,
        compress_archived: bool = true,
        backup_enabled: bool = true,
    };

    pub fn toJson(self: *const TenantConfig, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator,
            \\{{
            \\  "tenant_id": "{s}",
            \\  "smtp": {{
            \\    "max_message_size": {d},
            \\    "max_recipients": {d},
            \\    "require_tls": {s}
            \\  }},
            \\  "security": {{
            \\    "require_spf": {s},
            \\    "require_dkim": {s},
            \\    "spam_threshold": {d:.1},
            \\    "virus_scan_enabled": {s}
            \\  }},
            \\  "delivery": {{
            \\    "max_retries": {d},
            \\    "retry_interval_seconds": {d},
            \\    "dsn_enabled": {s}
            \\  }},
            \\  "storage": {{
            \\    "retention_days": {d},
            \\    "archive_after_days": {d},
            \\    "backup_enabled": {s}
            \\  }}
            \\}}
        , .{
            self.tenant_id,
            self.smtp.max_message_size,
            self.smtp.max_recipients,
            if (self.smtp.require_tls) "true" else "false",
            if (self.security.require_spf) "true" else "false",
            if (self.security.require_dkim) "true" else "false",
            self.security.spam_threshold,
            if (self.security.virus_scan_enabled) "true" else "false",
            self.delivery.max_retries,
            self.delivery.retry_interval_seconds,
            if (self.delivery.dsn_enabled) "true" else "false",
            self.storage.retention_days,
            self.storage.archive_after_days,
            if (self.storage.backup_enabled) "true" else "false",
        });
    }
};

/// Tenant configuration manager
pub const TenantConfigManager = struct {
    allocator: std.mem.Allocator,
    configs: std.StringHashMap(TenantConfig),
    mutex: std.Thread.Mutex,
    default_config: TenantConfig,

    pub fn init(allocator: std.mem.Allocator) TenantConfigManager {
        return .{
            .allocator = allocator,
            .configs = std.StringHashMap(TenantConfig).init(allocator),
            .mutex = std.Thread.Mutex{},
            .default_config = .{
                .tenant_id = "default",
                .smtp = .{},
                .security = .{},
                .delivery = .{},
                .storage = .{},
            },
        };
    }

    pub fn deinit(self: *TenantConfigManager) void {
        self.configs.deinit();
    }

    /// Get config for tenant (returns default if not found)
    pub fn getConfig(self: *TenantConfigManager, tenant_id: []const u8) TenantConfig {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.configs.get(tenant_id) orelse self.default_config;
    }

    /// Set config for tenant
    pub fn setConfig(self: *TenantConfigManager, tenant_id: []const u8, config: TenantConfig) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.configs.put(tenant_id, config);
    }

    /// Get effective max message size for tenant
    pub fn getMaxMessageSize(self: *TenantConfigManager, tenant_id: []const u8) u64 {
        return self.getConfig(tenant_id).smtp.max_message_size;
    }

    /// Check if TLS is required for tenant
    pub fn requiresTls(self: *TenantConfigManager, tenant_id: []const u8) bool {
        return self.getConfig(tenant_id).smtp.require_tls;
    }

    /// Get spam threshold for tenant
    pub fn getSpamThreshold(self: *TenantConfigManager, tenant_id: []const u8) f32 {
        return self.getConfig(tenant_id).security.spam_threshold;
    }
};

// ============================================================================
// Tenant Storage Isolation
// ============================================================================

/// Tenant-isolated storage paths
pub const TenantStorage = struct {
    allocator: std.mem.Allocator,
    base_path: []const u8,

    pub fn init(allocator: std.mem.Allocator, base_path: []const u8) !TenantStorage {
        return .{
            .allocator = allocator,
            .base_path = try allocator.dupe(u8, base_path),
        };
    }

    pub fn deinit(self: *TenantStorage) void {
        self.allocator.free(self.base_path);
    }

    /// Get maildir path for tenant
    pub fn getMaildirPath(self: *TenantStorage, tenant_id: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/tenants/{s}/maildir", .{
            self.base_path,
            tenant_id,
        });
    }

    /// Get queue path for tenant
    pub fn getQueuePath(self: *TenantStorage, tenant_id: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/tenants/{s}/queue", .{
            self.base_path,
            tenant_id,
        });
    }

    /// Get archive path for tenant
    pub fn getArchivePath(self: *TenantStorage, tenant_id: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/tenants/{s}/archive", .{
            self.base_path,
            tenant_id,
        });
    }

    /// Get database path for tenant
    pub fn getDatabasePath(self: *TenantStorage, tenant_id: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/tenants/{s}/data.db", .{
            self.base_path,
            tenant_id,
        });
    }

    /// Initialize storage directories for tenant
    pub fn initializeTenantStorage(self: *TenantStorage, tenant_id: []const u8) !void {
        const paths = [_][]const u8{
            try self.getMaildirPath(tenant_id),
            try self.getQueuePath(tenant_id),
            try self.getArchivePath(tenant_id),
        };
        defer for (paths) |p| self.allocator.free(p);

        for (paths) |path| {
            std.fs.cwd().makePath(path) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
        }
    }

    /// Calculate storage usage for tenant in MB
    pub fn calculateStorageUsage(self: *TenantStorage, tenant_id: []const u8) !u64 {
        var total_size: u64 = 0;

        const maildir_path = try self.getMaildirPath(tenant_id);
        defer self.allocator.free(maildir_path);

        // Walk maildir and sum file sizes
        var dir = std.fs.cwd().openDir(maildir_path, .{ .iterate = true }) catch return 0;
        defer dir.close();

        var walker = dir.walk(self.allocator) catch return 0;
        defer walker.deinit();

        while (walker.next() catch null) |entry| {
            if (entry.kind == .file) {
                const stat = entry.dir.statFile(entry.basename) catch continue;
                total_size += stat.size;
            }
        }

        return total_size / (1024 * 1024); // Convert to MB
    }
};

// ============================================================================
// Tenant Usage Statistics
// ============================================================================

/// Per-tenant usage statistics
pub const TenantUsageStats = struct {
    tenant_id: []const u8,
    messages_sent_today: std.atomic.Value(u32),
    messages_received_today: std.atomic.Value(u32),
    active_connections: std.atomic.Value(u32),
    storage_used_mb: std.atomic.Value(u64),
    spam_blocked_today: std.atomic.Value(u32),
    virus_blocked_today: std.atomic.Value(u32),
    last_activity: std.atomic.Value(i64),

    pub fn init(tenant_id: []const u8) TenantUsageStats {
        return .{
            .tenant_id = tenant_id,
            .messages_sent_today = std.atomic.Value(u32).init(0),
            .messages_received_today = std.atomic.Value(u32).init(0),
            .active_connections = std.atomic.Value(u32).init(0),
            .storage_used_mb = std.atomic.Value(u64).init(0),
            .spam_blocked_today = std.atomic.Value(u32).init(0),
            .virus_blocked_today = std.atomic.Value(u32).init(0),
            .last_activity = std.atomic.Value(i64).init(0),
        };
    }

    pub fn recordMessageSent(self: *TenantUsageStats) void {
        _ = self.messages_sent_today.fetchAdd(1, .monotonic);
        self.last_activity.store(time_compat.timestamp(), .monotonic);
    }

    pub fn recordMessageReceived(self: *TenantUsageStats) void {
        _ = self.messages_received_today.fetchAdd(1, .monotonic);
        self.last_activity.store(time_compat.timestamp(), .monotonic);
    }

    pub fn recordSpamBlocked(self: *TenantUsageStats) void {
        _ = self.spam_blocked_today.fetchAdd(1, .monotonic);
    }

    pub fn recordVirusBlocked(self: *TenantUsageStats) void {
        _ = self.virus_blocked_today.fetchAdd(1, .monotonic);
    }

    pub fn incrementConnections(self: *TenantUsageStats) void {
        _ = self.active_connections.fetchAdd(1, .monotonic);
    }

    pub fn decrementConnections(self: *TenantUsageStats) void {
        _ = self.active_connections.fetchSub(1, .monotonic);
    }

    pub fn resetDailyCounters(self: *TenantUsageStats) void {
        self.messages_sent_today.store(0, .monotonic);
        self.messages_received_today.store(0, .monotonic);
        self.spam_blocked_today.store(0, .monotonic);
        self.virus_blocked_today.store(0, .monotonic);
    }

    pub fn toJson(self: *const TenantUsageStats, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator,
            \\{{
            \\  "tenant_id": "{s}",
            \\  "messages_sent_today": {d},
            \\  "messages_received_today": {d},
            \\  "active_connections": {d},
            \\  "storage_used_mb": {d},
            \\  "spam_blocked_today": {d},
            \\  "virus_blocked_today": {d},
            \\  "last_activity": {d}
            \\}}
        , .{
            self.tenant_id,
            self.messages_sent_today.load(.monotonic),
            self.messages_received_today.load(.monotonic),
            self.active_connections.load(.monotonic),
            self.storage_used_mb.load(.monotonic),
            self.spam_blocked_today.load(.monotonic),
            self.virus_blocked_today.load(.monotonic),
            self.last_activity.load(.monotonic),
        });
    }
};

/// Usage stats manager for all tenants
pub const TenantUsageManager = struct {
    allocator: std.mem.Allocator,
    stats: std.StringHashMap(*TenantUsageStats),
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator) TenantUsageManager {
        return .{
            .allocator = allocator,
            .stats = std.StringHashMap(*TenantUsageStats).init(allocator),
            .mutex = std.Thread.Mutex{},
        };
    }

    pub fn deinit(self: *TenantUsageManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var iter = self.stats.iterator();
        while (iter.next()) |entry| {
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.stats.deinit();
    }

    pub fn getStats(self: *TenantUsageManager, tenant_id: []const u8) !*TenantUsageStats {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.stats.get(tenant_id)) |stats| {
            return stats;
        }

        const stats = try self.allocator.create(TenantUsageStats);
        stats.* = TenantUsageStats.init(tenant_id);
        try self.stats.put(tenant_id, stats);
        return stats;
    }

    /// Reset all daily counters (call at midnight)
    pub fn resetAllDailyCounters(self: *TenantUsageManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var iter = self.stats.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.*.resetDailyCounters();
        }
    }
};

// ============================================================================
// Additional Tests
// ============================================================================

test "tenant connection handler extracts domain" {
    const email1 = "user@example.com";
    const domain1 = TenantConnectionHandler.extractDomain(email1);
    try std.testing.expectEqualStrings("example.com", domain1.?);

    const email2 = "<user@test.org>";
    const domain2 = TenantConnectionHandler.extractDomain(email2);
    try std.testing.expectEqualStrings("test.org", domain2.?);
}

test "tenant rate limiter token bucket" {
    var limiter = TenantRateLimiter.init(std.testing.allocator);
    defer limiter.deinit();

    // First request should be allowed
    const result1 = try limiter.checkRequest("tenant1", null);
    try std.testing.expect(result1.allowed);

    // Many requests should eventually be rate limited
    var allowed_count: u32 = 0;
    for (0..300) |_| {
        const result = try limiter.checkRequest("tenant1", null);
        if (result.allowed) allowed_count += 1;
    }
    // Should have been rate limited at some point
    try std.testing.expect(allowed_count < 300);
}

test "tenant config to json" {
    const config = TenantConfig{
        .tenant_id = "test-tenant",
        .smtp = .{},
        .security = .{},
        .delivery = .{},
        .storage = .{},
    };

    const json = try config.toJson(std.testing.allocator);
    defer std.testing.allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "test-tenant") != null);
}

test "tenant usage stats atomic operations" {
    var stats = TenantUsageStats.init("test-tenant");

    stats.recordMessageSent();
    stats.recordMessageSent();
    stats.recordMessageReceived();

    try std.testing.expectEqual(@as(u32, 2), stats.messages_sent_today.load(.monotonic));
    try std.testing.expectEqual(@as(u32, 1), stats.messages_received_today.load(.monotonic));

    stats.resetDailyCounters();
    try std.testing.expectEqual(@as(u32, 0), stats.messages_sent_today.load(.monotonic));
}
