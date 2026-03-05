const std = @import("std");
const mutex_compat = @import("../core/mutex_compat.zig");
const Allocator = std.mem.Allocator;
const multitenancy = @import("multitenancy.zig");
const Tenant = multitenancy.Tenant;
const TenantContext = multitenancy.TenantContext;
const MultiTenancyManager = multitenancy.MultiTenancyManager;

/// Tenant Integration for SMTP Connection Handling
/// Integrates multi-tenancy with connection lifecycle, rate limiting, and storage isolation

// =============================================================================
// Connection-Level Tenant Context
// =============================================================================

pub const TenantConnection = struct {
    const Self = @This();

    /// Tenant associated with this connection
    tenant: ?*Tenant = null,
    /// Tenant ID (cached for quick access)
    tenant_id: ?[]const u8 = null,
    /// User ID within tenant (after authentication)
    user_id: ?[]const u8 = null,
    /// Rate limit state for this connection
    rate_limit: RateLimitState = .{},
    /// Storage quota state
    quota: QuotaState = .{},
    /// Feature flags resolved for this connection
    features: ResolvedFeatures = .{},
    /// Client IP address
    client_ip: ?[]const u8 = null,
    /// Connection start time
    connected_at: i64 = 0,
    /// Messages sent in this session
    messages_sent: u32 = 0,
    /// Bytes transferred in this session
    bytes_transferred: u64 = 0,

    allocator: Allocator,

    pub const RateLimitState = struct {
        messages_today: u32 = 0,
        last_reset: i64 = 0,
        burst_count: u32 = 0,
        last_message_time: i64 = 0,
    };

    pub const QuotaState = struct {
        storage_used_mb: u64 = 0,
        storage_limit_mb: u64 = 0,
        users_count: u32 = 0,
        users_limit: u32 = 0,
    };

    pub const ResolvedFeatures = struct {
        spam_filtering: bool = true,
        virus_scanning: bool = false,
        dkim_signing: bool = false,
        size_limit: u64 = 10 * 1024 * 1024, // 10MB default
        rate_limit_per_minute: u32 = 10,
        require_auth: bool = true,
        allow_relay: bool = false,
    };

    pub fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .connected_at = std.time.timestamp(),
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.tenant_id) |id| {
            self.allocator.free(id);
        }
        if (self.user_id) |id| {
            self.allocator.free(id);
        }
        if (self.client_ip) |ip| {
            self.allocator.free(ip);
        }
    }

    /// Bind tenant to this connection
    pub fn bindTenant(self: *Self, tenant: *Tenant) !void {
        self.tenant = tenant;
        self.tenant_id = try self.allocator.dupe(u8, tenant.id);
        self.resolveFeatures();
        self.loadQuota();
    }

    /// Bind user after authentication
    pub fn bindUser(self: *Self, user_id: []const u8) !void {
        self.user_id = try self.allocator.dupe(u8, user_id);
    }

    /// Set client IP
    pub fn setClientIp(self: *Self, ip: []const u8) !void {
        self.client_ip = try self.allocator.dupe(u8, ip);
    }

    /// Resolve features based on tenant configuration
    fn resolveFeatures(self: *Self) void {
        if (self.tenant) |tenant| {
            self.features = ResolvedFeatures{
                .spam_filtering = tenant.features.spam_filtering,
                .virus_scanning = tenant.features.virus_scanning,
                .dkim_signing = tenant.features.dkim_signing,
                .size_limit = tenant.max_storage_mb * 1024 * 1024 / 100, // 1% of total as max message
                .rate_limit_per_minute = @min(tenant.max_messages_per_day / 1440, 100), // Daily limit / minutes
                .require_auth = true,
                .allow_relay = tenant.features.custom_domains,
            };
        }
    }

    /// Load quota information
    fn loadQuota(self: *Self) void {
        if (self.tenant) |tenant| {
            self.quota = QuotaState{
                .storage_limit_mb = tenant.max_storage_mb,
                .users_limit = tenant.max_users,
                // Actual usage would be loaded from database
                .storage_used_mb = 0,
                .users_count = 0,
            };
        }
    }

    /// Check if message can be sent (rate limiting)
    pub fn canSendMessage(self: *Self) bool {
        if (self.tenant == null) return true; // No tenant = no limits

        const now = std.time.timestamp();
        const day_start = @divFloor(now, 86400) * 86400;

        // Reset daily counter if new day
        if (self.rate_limit.last_reset < day_start) {
            self.rate_limit.messages_today = 0;
            self.rate_limit.last_reset = day_start;
        }

        // Check daily limit
        if (self.tenant) |tenant| {
            if (tenant.max_messages_per_day > 0 and
                self.rate_limit.messages_today >= tenant.max_messages_per_day)
            {
                return false;
            }
        }

        // Check burst rate (messages per minute)
        const minute_ago = now - 60;
        if (self.rate_limit.last_message_time > minute_ago) {
            if (self.rate_limit.burst_count >= self.features.rate_limit_per_minute) {
                return false;
            }
        } else {
            self.rate_limit.burst_count = 0;
        }

        return true;
    }

    /// Record message sent
    pub fn recordMessageSent(self: *Self, size: u64) void {
        self.messages_sent += 1;
        self.bytes_transferred += size;
        self.rate_limit.messages_today += 1;
        self.rate_limit.burst_count += 1;
        self.rate_limit.last_message_time = std.time.timestamp();
    }

    /// Check if message size is within limits
    pub fn checkMessageSize(self: *const Self, size: u64) bool {
        return size <= self.features.size_limit;
    }

    /// Check if storage quota allows more data
    pub fn hasStorageQuota(self: *const Self, additional_mb: u64) bool {
        if (self.quota.storage_limit_mb == 0) return true; // Unlimited
        return self.quota.storage_used_mb + additional_mb <= self.quota.storage_limit_mb;
    }

    /// Get context for downstream processing
    pub fn getContext(self: *const Self) ?TenantContext {
        if (self.tenant) |tenant| {
            return TenantContext.init(
                self.tenant_id orelse "",
                tenant,
                self.user_id,
            );
        }
        return null;
    }
};

// =============================================================================
// Tenant Resolver - Determines tenant from connection attributes
// =============================================================================

pub const TenantResolver = struct {
    const Self = @This();

    manager: *MultiTenancyManager,
    /// Resolution strategy
    strategy: ResolutionStrategy = .domain_first,
    /// Default tenant for unresolved connections
    default_tenant_id: ?[]const u8 = null,
    /// Cache of domain -> tenant_id mappings
    domain_cache: std.StringHashMap([]const u8),
    cache_mutex: mutex_compat.Mutex = .{},
    allocator: Allocator,

    pub const ResolutionStrategy = enum {
        /// Try domain first, then IP-based rules
        domain_first,
        /// Use explicit tenant header/parameter
        explicit_only,
        /// Always use default tenant
        default_only,
        /// Try all methods in order
        cascading,
    };

    pub fn init(allocator: Allocator, manager: *MultiTenancyManager) Self {
        return Self{
            .manager = manager,
            .domain_cache = std.StringHashMap([]const u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.domain_cache.deinit();
    }

    /// Resolve tenant from email domain
    pub fn resolveFromDomain(self: *Self, domain: []const u8) !?*Tenant {
        // Check cache first
        self.cache_mutex.lock();
        const cached = self.domain_cache.get(domain);
        self.cache_mutex.unlock();

        if (cached) |tenant_id| {
            return self.manager.getTenant(tenant_id) catch null;
        }

        // Query manager
        const tenant = self.manager.getTenantByDomain(domain) catch |err| {
            if (err == error.TenantNotFound) return null;
            return err;
        };

        // Cache the result
        self.cache_mutex.lock();
        defer self.cache_mutex.unlock();
        self.domain_cache.put(
            self.allocator.dupe(u8, domain) catch return tenant,
            self.allocator.dupe(u8, tenant.id) catch return tenant,
        ) catch {};

        return tenant;
    }

    /// Resolve tenant from MAIL FROM address
    pub fn resolveFromMailFrom(self: *Self, mail_from: []const u8) !?*Tenant {
        // Extract domain from email address
        const at_pos = std.mem.indexOf(u8, mail_from, "@") orelse return null;
        const domain = mail_from[at_pos + 1 ..];

        // Remove any trailing > or whitespace
        var end = domain.len;
        for (domain, 0..) |c, i| {
            if (c == '>' or c == ' ' or c == '\t') {
                end = i;
                break;
            }
        }

        return self.resolveFromDomain(domain[0..end]);
    }

    /// Resolve tenant from RCPT TO address
    pub fn resolveFromRcptTo(self: *Self, rcpt_to: []const u8) !?*Tenant {
        return self.resolveFromMailFrom(rcpt_to);
    }

    /// Resolve tenant using configured strategy
    pub fn resolve(self: *Self, context: ResolutionContext) !?*Tenant {
        return switch (self.strategy) {
            .domain_first => self.resolveDomainFirst(context),
            .explicit_only => self.resolveExplicit(context),
            .default_only => self.resolveDefault(),
            .cascading => self.resolveCascading(context),
        };
    }

    pub const ResolutionContext = struct {
        mail_from: ?[]const u8 = null,
        rcpt_to: ?[]const u8 = null,
        explicit_tenant_id: ?[]const u8 = null,
        client_ip: ?[]const u8 = null,
        helo_domain: ?[]const u8 = null,
    };

    fn resolveDomainFirst(self: *Self, ctx: ResolutionContext) !?*Tenant {
        // Try RCPT TO domain first (receiving mail)
        if (ctx.rcpt_to) |rcpt| {
            if (try self.resolveFromRcptTo(rcpt)) |tenant| {
                return tenant;
            }
        }

        // Try MAIL FROM domain
        if (ctx.mail_from) |from| {
            if (try self.resolveFromMailFrom(from)) |tenant| {
                return tenant;
            }
        }

        // Fall back to default
        return self.resolveDefault();
    }

    fn resolveExplicit(self: *Self, ctx: ResolutionContext) !?*Tenant {
        if (ctx.explicit_tenant_id) |id| {
            return self.manager.getTenant(id) catch null;
        }
        return null;
    }

    fn resolveDefault(self: *Self) !?*Tenant {
        if (self.default_tenant_id) |id| {
            return self.manager.getTenant(id) catch null;
        }
        return null;
    }

    fn resolveCascading(self: *Self, ctx: ResolutionContext) !?*Tenant {
        // Try explicit first
        if (try self.resolveExplicit(ctx)) |tenant| return tenant;

        // Try domain-based
        if (try self.resolveDomainFirst(ctx)) |tenant| return tenant;

        // Finally default
        return self.resolveDefault();
    }

    /// Clear domain cache
    pub fn clearCache(self: *Self) void {
        self.cache_mutex.lock();
        defer self.cache_mutex.unlock();
        self.domain_cache.clearRetainingCapacity();
    }
};

// =============================================================================
// Tenant-Aware Rate Limiter
// =============================================================================

pub const TenantRateLimiter = struct {
    const Self = @This();

    /// Per-tenant rate limit state
    tenant_limits: std.StringHashMap(TenantRateState),
    /// Per-IP rate limit state (across tenants)
    ip_limits: std.StringHashMap(IpRateState),
    mutex: mutex_compat.Mutex = .{},
    allocator: Allocator,

    pub const TenantRateState = struct {
        messages_today: u64 = 0,
        messages_this_hour: u64 = 0,
        bytes_today: u64 = 0,
        last_daily_reset: i64 = 0,
        last_hourly_reset: i64 = 0,
        connections_active: u32 = 0,
    };

    pub const IpRateState = struct {
        connections_today: u32 = 0,
        failed_auths: u32 = 0,
        last_reset: i64 = 0,
        blocked_until: i64 = 0,
    };

    pub fn init(allocator: Allocator) Self {
        return Self{
            .tenant_limits = std.StringHashMap(TenantRateState).init(allocator),
            .ip_limits = std.StringHashMap(IpRateState).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.tenant_limits.deinit();
        self.ip_limits.deinit();
    }

    /// Check if tenant can send more messages
    pub fn checkTenantLimit(self: *Self, tenant_id: []const u8, daily_limit: u64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.timestamp();
        const day_start = @divFloor(now, 86400) * 86400;

        if (self.tenant_limits.getPtr(tenant_id)) |state| {
            // Reset if new day
            if (state.last_daily_reset < day_start) {
                state.messages_today = 0;
                state.last_daily_reset = day_start;
            }

            if (daily_limit > 0 and state.messages_today >= daily_limit) {
                return false;
            }
        }

        return true;
    }

    /// Record message for tenant
    pub fn recordTenantMessage(self: *Self, tenant_id: []const u8, bytes: u64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const gop = try self.tenant_limits.getOrPut(tenant_id);
        if (!gop.found_existing) {
            gop.value_ptr.* = TenantRateState{};
        }

        gop.value_ptr.messages_today += 1;
        gop.value_ptr.messages_this_hour += 1;
        gop.value_ptr.bytes_today += bytes;
    }

    /// Check if IP is blocked
    pub fn isIpBlocked(self: *Self, ip: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.ip_limits.get(ip)) |state| {
            return state.blocked_until > std.time.timestamp();
        }
        return false;
    }

    /// Record failed authentication for IP
    pub fn recordFailedAuth(self: *Self, ip: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const gop = try self.ip_limits.getOrPut(ip);
        if (!gop.found_existing) {
            gop.value_ptr.* = IpRateState{};
        }

        gop.value_ptr.failed_auths += 1;

        // Block after 5 failed attempts
        if (gop.value_ptr.failed_auths >= 5) {
            gop.value_ptr.blocked_until = std.time.timestamp() + 300; // 5 minutes
        }
    }

    /// Get tenant statistics
    pub fn getTenantStats(self: *Self, tenant_id: []const u8) ?TenantRateState {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.tenant_limits.get(tenant_id);
    }
};

// =============================================================================
// Tenant Storage Isolator
// =============================================================================

pub const TenantStorageIsolator = struct {
    const Self = @This();

    base_path: []const u8,
    allocator: Allocator,

    pub fn init(allocator: Allocator, base_path: []const u8) Self {
        return Self{
            .base_path = base_path,
            .allocator = allocator,
        };
    }

    /// Get tenant-specific storage path
    pub fn getTenantPath(self: *const Self, tenant_id: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/tenants/{s}", .{ self.base_path, tenant_id });
    }

    /// Get tenant mailbox path
    pub fn getMailboxPath(self: *const Self, tenant_id: []const u8, user_id: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/tenants/{s}/mailboxes/{s}", .{ self.base_path, tenant_id, user_id });
    }

    /// Get tenant queue path
    pub fn getQueuePath(self: *const Self, tenant_id: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/tenants/{s}/queue", .{ self.base_path, tenant_id });
    }

    /// Get tenant database path
    pub fn getDatabasePath(self: *const Self, tenant_id: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/tenants/{s}/data.db", .{ self.base_path, tenant_id });
    }

    /// Ensure tenant directories exist
    pub fn ensureTenantDirs(self: *const Self, tenant_id: []const u8) !void {
        const paths = [_][]const u8{
            try self.getTenantPath(tenant_id),
            try self.getQueuePath(tenant_id),
        };

        for (paths) |path| {
            defer self.allocator.free(path);
            std.fs.cwd().makePath(path) catch |err| {
                if (err != error.PathAlreadyExists) return err;
            };
        }
    }
};

// =============================================================================
// Tests
// =============================================================================

test "TenantConnection rate limiting" {
    var conn = TenantConnection.init(std.testing.allocator);
    defer conn.deinit();

    // Without tenant, should always allow
    try std.testing.expect(conn.canSendMessage());

    // Record some messages
    conn.recordMessageSent(1024);
    try std.testing.expectEqual(@as(u32, 1), conn.messages_sent);
}

test "TenantConnection message size check" {
    var conn = TenantConnection.init(std.testing.allocator);
    defer conn.deinit();

    // Default limit is 10MB
    try std.testing.expect(conn.checkMessageSize(1024)); // 1KB - OK
    try std.testing.expect(conn.checkMessageSize(5 * 1024 * 1024)); // 5MB - OK
    try std.testing.expect(!conn.checkMessageSize(20 * 1024 * 1024)); // 20MB - Too large
}

test "TenantRateLimiter IP blocking" {
    var limiter = TenantRateLimiter.init(std.testing.allocator);
    defer limiter.deinit();

    const ip = "192.168.1.100";

    // Initially not blocked
    try std.testing.expect(!limiter.isIpBlocked(ip));

    // Record 5 failed auths
    for (0..5) |_| {
        try limiter.recordFailedAuth(ip);
    }

    // Should now be blocked
    try std.testing.expect(limiter.isIpBlocked(ip));
}

test "TenantStorageIsolator paths" {
    var isolator = TenantStorageIsolator.init(std.testing.allocator, "/var/mail");

    const tenant_path = try isolator.getTenantPath("tenant-123");
    defer std.testing.allocator.free(tenant_path);
    try std.testing.expectEqualStrings("/var/mail/tenants/tenant-123", tenant_path);

    const mailbox_path = try isolator.getMailboxPath("tenant-123", "user@example.com");
    defer std.testing.allocator.free(mailbox_path);
    try std.testing.expectEqualStrings("/var/mail/tenants/tenant-123/mailboxes/user@example.com", mailbox_path);
}
