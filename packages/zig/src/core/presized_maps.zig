const std = @import("std");
const Allocator = std.mem.Allocator;

/// Pre-sized Hash Maps for SMTP Server
/// Reduces allocations by reserving capacity upfront for common use cases
/// Based on typical email patterns and RFC specifications

// =============================================================================
// Capacity Constants - Based on Real-World Email Patterns
// =============================================================================

pub const Capacity = struct {
    /// RFC 5321 recommends accepting at least 100 recipients
    pub const recipients: u32 = 128;

    /// Typical email has 15-25 headers, allow for extensions
    pub const headers: u32 = 64;

    /// MIME parts in multipart messages
    pub const mime_parts: u32 = 32;

    /// Connection pool per destination
    pub const connections_per_host: u32 = 16;

    /// Active sessions in memory
    pub const active_sessions: u32 = 1024;

    /// DNS cache entries
    pub const dns_cache: u32 = 512;

    /// Rate limiter buckets per IP
    pub const rate_limit_buckets: u32 = 4096;

    /// DKIM signature cache
    pub const dkim_cache: u32 = 256;

    /// SPF result cache
    pub const spf_cache: u32 = 512;

    /// Mailbox index entries
    pub const mailbox_index: u32 = 10000;

    /// Queue entries
    pub const queue_entries: u32 = 8192;

    /// Plugin hooks
    pub const plugin_hooks: u32 = 64;

    /// Configuration entries
    pub const config_entries: u32 = 256;

    /// Routing rules
    pub const routing_rules: u32 = 128;

    /// TLS session cache
    pub const tls_sessions: u32 = 2048;
};

// =============================================================================
// Pre-sized String Hash Map
// =============================================================================

pub fn PresizedStringHashMap(comptime V: type) type {
    return struct {
        const Self = @This();
        const Map = std.StringHashMap(V);

        map: Map,

        pub fn init(allocator: Allocator, capacity: u32) !Self {
            var map = Map.init(allocator);
            try map.ensureTotalCapacity(capacity);
            return Self{ .map = map };
        }

        pub fn deinit(self: *Self) void {
            self.map.deinit();
        }

        pub fn put(self: *Self, key: []const u8, value: V) !void {
            try self.map.put(key, value);
        }

        pub fn get(self: *const Self, key: []const u8) ?V {
            return self.map.get(key);
        }

        pub fn getPtr(self: *Self, key: []const u8) ?*V {
            return self.map.getPtr(key);
        }

        pub fn remove(self: *Self, key: []const u8) bool {
            return self.map.remove(key);
        }

        pub fn contains(self: *const Self, key: []const u8) bool {
            return self.map.contains(key);
        }

        pub fn count(self: *const Self) usize {
            return self.map.count();
        }

        pub fn iterator(self: *const Self) Map.Iterator {
            return self.map.iterator();
        }

        pub fn clear(self: *Self) void {
            self.map.clearRetainingCapacity();
        }
    };
}

// =============================================================================
// Pre-sized Auto Hash Map
// =============================================================================

pub fn PresizedAutoHashMap(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();
        const Map = std.AutoHashMap(K, V);

        map: Map,

        pub fn init(allocator: Allocator, capacity: u32) !Self {
            var map = Map.init(allocator);
            try map.ensureTotalCapacity(capacity);
            return Self{ .map = map };
        }

        pub fn deinit(self: *Self) void {
            self.map.deinit();
        }

        pub fn put(self: *Self, key: K, value: V) !void {
            try self.map.put(key, value);
        }

        pub fn get(self: *const Self, key: K) ?V {
            return self.map.get(key);
        }

        pub fn getPtr(self: *Self, key: K) ?*V {
            return self.map.getPtr(key);
        }

        pub fn remove(self: *Self, key: K) bool {
            return self.map.remove(key);
        }

        pub fn contains(self: *const Self, key: K) bool {
            return self.map.contains(key);
        }

        pub fn count(self: *const Self) usize {
            return self.map.count();
        }

        pub fn iterator(self: *const Self) Map.Iterator {
            return self.map.iterator();
        }

        pub fn clear(self: *Self) void {
            self.map.clearRetainingCapacity();
        }
    };
}

// =============================================================================
// Specialized Pre-sized Maps for Common Use Cases
// =============================================================================

/// Email headers map (case-insensitive keys)
pub const HeaderMap = struct {
    const Self = @This();

    allocator: Allocator,
    entries: std.StringHashMap(HeaderValue),
    order: std.ArrayList([]const u8),

    pub const HeaderValue = struct {
        value: []const u8,
        raw: []const u8, // Original with folding preserved
    };

    pub fn init(allocator: Allocator) !Self {
        var entries = std.StringHashMap(HeaderValue).init(allocator);
        try entries.ensureTotalCapacity(Capacity.headers);

        var order = std.ArrayList([]const u8).init(allocator);
        try order.ensureTotalCapacity(Capacity.headers);

        return Self{
            .allocator = allocator,
            .entries = entries,
            .order = order,
        };
    }

    pub fn deinit(self: *Self) void {
        self.order.deinit();
        self.entries.deinit();
    }

    pub fn put(self: *Self, name: []const u8, value: []const u8, raw: []const u8) !void {
        const lower_name = try self.toLower(name);
        defer self.allocator.free(lower_name);

        const owned_name = try self.allocator.dupe(u8, lower_name);
        errdefer self.allocator.free(owned_name);

        const gop = try self.entries.getOrPut(owned_name);
        if (!gop.found_existing) {
            try self.order.append(owned_name);
        } else {
            self.allocator.free(owned_name);
        }
        gop.value_ptr.* = HeaderValue{ .value = value, .raw = raw };
    }

    pub fn get(self: *const Self, name: []const u8) ?[]const u8 {
        var lower_buf: [256]u8 = undefined;
        const lower_name = self.toLowerBuf(name, &lower_buf) catch return null;
        if (self.entries.get(lower_name)) |hv| {
            return hv.value;
        }
        return null;
    }

    pub fn getRaw(self: *const Self, name: []const u8) ?[]const u8 {
        var lower_buf: [256]u8 = undefined;
        const lower_name = self.toLowerBuf(name, &lower_buf) catch return null;
        if (self.entries.get(lower_name)) |hv| {
            return hv.raw;
        }
        return null;
    }

    pub fn remove(self: *Self, name: []const u8) bool {
        var lower_buf: [256]u8 = undefined;
        const lower_name = self.toLowerBuf(name, &lower_buf) catch return false;
        return self.entries.remove(lower_name);
    }

    pub fn count(self: *const Self) usize {
        return self.entries.count();
    }

    pub fn orderedIterator(self: *const Self) OrderedIterator {
        return OrderedIterator{ .map = self, .index = 0 };
    }

    pub const OrderedIterator = struct {
        map: *const Self,
        index: usize,

        pub fn next(self: *OrderedIterator) ?struct { name: []const u8, value: HeaderValue } {
            if (self.index >= self.map.order.items.len) return null;
            const name = self.map.order.items[self.index];
            self.index += 1;
            if (self.map.entries.get(name)) |value| {
                return .{ .name = name, .value = value };
            }
            return self.next();
        }
    };

    fn toLower(self: *Self, s: []const u8) ![]u8 {
        const result = try self.allocator.alloc(u8, s.len);
        for (s, 0..) |c, i| {
            result[i] = std.ascii.toLower(c);
        }
        return result;
    }

    fn toLowerBuf(_: *const Self, s: []const u8, buf: []u8) ![]u8 {
        if (s.len > buf.len) return error.BufferTooSmall;
        for (s, 0..) |c, i| {
            buf[i] = std.ascii.toLower(c);
        }
        return buf[0..s.len];
    }
};

/// Recipient list with de-duplication
pub const RecipientSet = struct {
    const Self = @This();

    allocator: Allocator,
    set: std.StringHashMap(RecipientInfo),
    list: std.ArrayList([]const u8),

    pub const RecipientInfo = struct {
        original: []const u8,
        notify: NotifyFlags = .{},
        orcpt: ?[]const u8 = null,
    };

    pub const NotifyFlags = struct {
        success: bool = false,
        failure: bool = true,
        delay: bool = false,
        never: bool = false,
    };

    pub fn init(allocator: Allocator) !Self {
        var set = std.StringHashMap(RecipientInfo).init(allocator);
        try set.ensureTotalCapacity(Capacity.recipients);

        var list = std.ArrayList([]const u8).init(allocator);
        try list.ensureTotalCapacity(Capacity.recipients);

        return Self{
            .allocator = allocator,
            .set = set,
            .list = list,
        };
    }

    pub fn deinit(self: *Self) void {
        self.list.deinit();
        self.set.deinit();
    }

    pub fn add(self: *Self, address: []const u8) !bool {
        return self.addWithInfo(address, .{});
    }

    pub fn addWithInfo(self: *Self, address: []const u8, info: RecipientInfo) !bool {
        const normalized = try self.normalize(address);
        defer self.allocator.free(normalized);

        const gop = try self.set.getOrPut(normalized);
        if (gop.found_existing) {
            return false;
        }

        const owned = try self.allocator.dupe(u8, normalized);
        gop.key_ptr.* = owned;
        gop.value_ptr.* = RecipientInfo{
            .original = info.original,
            .notify = info.notify,
            .orcpt = info.orcpt,
        };
        try self.list.append(owned);
        return true;
    }

    pub fn contains(self: *const Self, address: []const u8) bool {
        var buf: [320]u8 = undefined; // Max email length
        const normalized = self.normalizeBuf(address, &buf) catch return false;
        return self.set.contains(normalized);
    }

    pub fn remove(self: *Self, address: []const u8) bool {
        var buf: [320]u8 = undefined;
        const normalized = self.normalizeBuf(address, &buf) catch return false;
        return self.set.remove(normalized);
    }

    pub fn count(self: *const Self) usize {
        return self.set.count();
    }

    pub fn addresses(self: *const Self) []const []const u8 {
        return self.list.items;
    }

    pub fn getInfo(self: *const Self, address: []const u8) ?RecipientInfo {
        var buf: [320]u8 = undefined;
        const normalized = self.normalizeBuf(address, &buf) catch return null;
        return self.set.get(normalized);
    }

    fn normalize(self: *Self, address: []const u8) ![]u8 {
        // Lowercase the domain part
        const result = try self.allocator.alloc(u8, address.len);
        var in_domain = false;
        for (address, 0..) |c, i| {
            if (c == '@') in_domain = true;
            result[i] = if (in_domain) std.ascii.toLower(c) else c;
        }
        return result;
    }

    fn normalizeBuf(_: *const Self, address: []const u8, buf: []u8) ![]u8 {
        if (address.len > buf.len) return error.BufferTooSmall;
        var in_domain = false;
        for (address, 0..) |c, i| {
            if (c == '@') in_domain = true;
            buf[i] = if (in_domain) std.ascii.toLower(c) else c;
        }
        return buf[0..address.len];
    }
};

/// Connection pool map by host
pub const ConnectionPoolMap = struct {
    const Self = @This();

    pools: std.StringHashMap(ConnectionPool),
    allocator: Allocator,

    pub const ConnectionPool = struct {
        connections: std.ArrayList(Connection),
        max_size: u32,
        created: i64,
    };

    pub const Connection = struct {
        id: u64,
        socket: ?std.posix.socket_t,
        last_used: i64,
        in_use: bool,
    };

    pub fn init(allocator: Allocator) !Self {
        var pools = std.StringHashMap(ConnectionPool).init(allocator);
        try pools.ensureTotalCapacity(Capacity.connections_per_host * 8); // 8 hosts typical
        return Self{
            .pools = pools,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.pools.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.connections.deinit();
        }
        self.pools.deinit();
    }

    pub fn getOrCreatePool(self: *Self, host: []const u8) !*ConnectionPool {
        const gop = try self.pools.getOrPut(host);
        if (!gop.found_existing) {
            var connections = std.ArrayList(Connection).init(self.allocator);
            try connections.ensureTotalCapacity(Capacity.connections_per_host);
            gop.value_ptr.* = ConnectionPool{
                .connections = connections,
                .max_size = Capacity.connections_per_host,
                .created = std.time.timestamp(),
            };
        }
        return gop.value_ptr;
    }

    pub fn getPool(self: *Self, host: []const u8) ?*ConnectionPool {
        return self.pools.getPtr(host);
    }
};

/// Session map with expiration support
pub const SessionMap = struct {
    const Self = @This();

    sessions: PresizedStringHashMap(Session),
    expiry_queue: std.PriorityQueue(ExpiryEntry, void, expiryCompare),
    allocator: Allocator,

    pub const Session = struct {
        id: []const u8,
        data: SessionData,
        created: i64,
        expires: i64,
        last_activity: i64,
    };

    pub const SessionData = struct {
        user: ?[]const u8 = null,
        authenticated: bool = false,
        mail_from: ?[]const u8 = null,
        rcpt_to: std.ArrayList([]const u8),
        state: SessionState = .initial,
    };

    pub const SessionState = enum {
        initial,
        greeted,
        mail_started,
        rcpt_received,
        data_receiving,
        completed,
    };

    const ExpiryEntry = struct {
        session_id: []const u8,
        expires: i64,
    };

    fn expiryCompare(_: void, a: ExpiryEntry, b: ExpiryEntry) std.math.Order {
        return std.math.order(a.expires, b.expires);
    }

    pub fn init(allocator: Allocator) !Self {
        return Self{
            .sessions = try PresizedStringHashMap(Session).init(allocator, Capacity.active_sessions),
            .expiry_queue = std.PriorityQueue(ExpiryEntry, void, expiryCompare).init(allocator, {}),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.expiry_queue.deinit();
        self.sessions.deinit();
    }

    pub fn create(self: *Self, id: []const u8, ttl_seconds: i64) !*Session {
        const now = std.time.timestamp();
        const expires = now + ttl_seconds;

        var rcpt_to = std.ArrayList([]const u8).init(self.allocator);
        try rcpt_to.ensureTotalCapacity(Capacity.recipients);

        try self.sessions.put(id, Session{
            .id = id,
            .data = SessionData{
                .rcpt_to = rcpt_to,
            },
            .created = now,
            .expires = expires,
            .last_activity = now,
        });

        try self.expiry_queue.add(ExpiryEntry{
            .session_id = id,
            .expires = expires,
        });

        return self.sessions.getPtr(id).?;
    }

    pub fn get(self: *Self, id: []const u8) ?*Session {
        if (self.sessions.getPtr(id)) |session| {
            if (session.expires > std.time.timestamp()) {
                session.last_activity = std.time.timestamp();
                return session;
            }
            // Expired
            _ = self.sessions.remove(id);
        }
        return null;
    }

    pub fn remove(self: *Self, id: []const u8) bool {
        return self.sessions.remove(id);
    }

    pub fn cleanExpired(self: *Self) usize {
        const now = std.time.timestamp();
        var removed: usize = 0;

        while (self.expiry_queue.peek()) |entry| {
            if (entry.expires > now) break;
            _ = self.expiry_queue.remove();
            if (self.sessions.remove(entry.session_id)) {
                removed += 1;
            }
        }

        return removed;
    }
};

/// DNS cache with TTL
pub const DnsCache = struct {
    const Self = @This();

    cache: PresizedStringHashMap(CacheEntry),
    allocator: Allocator,

    pub const CacheEntry = struct {
        records: std.ArrayList(DnsRecord),
        expires: i64,
        query_type: QueryType,
    };

    pub const DnsRecord = struct {
        data: []const u8,
        priority: u16 = 0, // For MX records
        ttl: u32,
    };

    pub const QueryType = enum {
        a,
        aaaa,
        mx,
        txt,
        ptr,
        cname,
    };

    pub fn init(allocator: Allocator) !Self {
        return Self{
            .cache = try PresizedStringHashMap(CacheEntry).init(allocator, Capacity.dns_cache),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.cache.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.records.deinit();
        }
        self.cache.deinit();
    }

    pub fn lookup(self: *Self, name: []const u8, query_type: QueryType) ?[]const DnsRecord {
        const key = self.makeKey(name, query_type) catch return null;
        defer self.allocator.free(key);

        if (self.cache.getPtr(key)) |entry| {
            if (entry.expires > std.time.timestamp()) {
                return entry.records.items;
            }
            // Expired
            entry.records.deinit();
            _ = self.cache.remove(key);
        }
        return null;
    }

    pub fn store(self: *Self, name: []const u8, query_type: QueryType, records: []const DnsRecord, ttl: u32) !void {
        const key = try self.makeKey(name, query_type);
        errdefer self.allocator.free(key);

        var record_list = std.ArrayList(DnsRecord).init(self.allocator);
        try record_list.appendSlice(records);

        try self.cache.put(key, CacheEntry{
            .records = record_list,
            .expires = std.time.timestamp() + @as(i64, ttl),
            .query_type = query_type,
        });
    }

    fn makeKey(self: *Self, name: []const u8, query_type: QueryType) ![]u8 {
        const type_str = @tagName(query_type);
        const key = try self.allocator.alloc(u8, name.len + 1 + type_str.len);
        @memcpy(key[0..name.len], name);
        key[name.len] = ':';
        @memcpy(key[name.len + 1 ..], type_str);
        return key;
    }
};

// =============================================================================
// Factory Functions for Common Maps
// =============================================================================

pub const MapFactory = struct {
    /// Create a pre-sized header map
    pub fn createHeaderMap(allocator: Allocator) !HeaderMap {
        return HeaderMap.init(allocator);
    }

    /// Create a pre-sized recipient set
    pub fn createRecipientSet(allocator: Allocator) !RecipientSet {
        return RecipientSet.init(allocator);
    }

    /// Create a pre-sized session map
    pub fn createSessionMap(allocator: Allocator) !SessionMap {
        return SessionMap.init(allocator);
    }

    /// Create a pre-sized DNS cache
    pub fn createDnsCache(allocator: Allocator) !DnsCache {
        return DnsCache.init(allocator);
    }

    /// Create a pre-sized connection pool map
    pub fn createConnectionPoolMap(allocator: Allocator) !ConnectionPoolMap {
        return ConnectionPoolMap.init(allocator);
    }

    /// Create a generic pre-sized string map
    pub fn createStringMap(comptime V: type, allocator: Allocator, capacity: u32) !PresizedStringHashMap(V) {
        return PresizedStringHashMap(V).init(allocator, capacity);
    }

    /// Create a generic pre-sized auto map
    pub fn createAutoMap(comptime K: type, comptime V: type, allocator: Allocator, capacity: u32) !PresizedAutoHashMap(K, V) {
        return PresizedAutoHashMap(K, V).init(allocator, capacity);
    }
};

// =============================================================================
// Tests
// =============================================================================

test "PresizedStringHashMap basic operations" {
    const allocator = std.testing.allocator;

    var map = try PresizedStringHashMap(u32).init(allocator, 16);
    defer map.deinit();

    try map.put("key1", 100);
    try map.put("key2", 200);

    try std.testing.expectEqual(@as(?u32, 100), map.get("key1"));
    try std.testing.expectEqual(@as(?u32, 200), map.get("key2"));
    try std.testing.expectEqual(@as(?u32, null), map.get("key3"));

    try std.testing.expect(map.contains("key1"));
    try std.testing.expect(!map.contains("key3"));

    try std.testing.expect(map.remove("key1"));
    try std.testing.expect(!map.contains("key1"));
}

test "HeaderMap case insensitivity" {
    const allocator = std.testing.allocator;

    var headers = try HeaderMap.init(allocator);
    defer headers.deinit();

    try headers.put("Content-Type", "text/plain", "Content-Type: text/plain");
    try headers.put("FROM", "sender@test.com", "FROM: sender@test.com");

    // Should find regardless of case
    try std.testing.expect(headers.get("content-type") != null);
    try std.testing.expect(headers.get("CONTENT-TYPE") != null);
    try std.testing.expect(headers.get("Content-Type") != null);
    try std.testing.expect(headers.get("from") != null);
}

test "RecipientSet deduplication" {
    const allocator = std.testing.allocator;

    var recipients = try RecipientSet.init(allocator);
    defer recipients.deinit();

    // Add same address twice
    const added1 = try recipients.add("test@EXAMPLE.COM");
    const added2 = try recipients.add("test@example.com");

    try std.testing.expect(added1);
    try std.testing.expect(!added2); // Duplicate, domain normalized

    try std.testing.expectEqual(@as(usize, 1), recipients.count());
}

test "SessionMap expiration" {
    const allocator = std.testing.allocator;

    var sessions = try SessionMap.init(allocator);
    defer sessions.deinit();

    // Create session with very short TTL (can't test actual expiry without time manipulation)
    const session = try sessions.create("test-session", 3600);
    try std.testing.expect(session.data.state == .initial);

    // Should be retrievable
    const retrieved = sessions.get("test-session");
    try std.testing.expect(retrieved != null);
}

test "DnsCache storage and retrieval" {
    const allocator = std.testing.allocator;

    var cache = try DnsCache.init(allocator);
    defer cache.deinit();

    const records = [_]DnsCache.DnsRecord{
        .{ .data = "192.168.1.1", .ttl = 300 },
        .{ .data = "192.168.1.2", .ttl = 300 },
    };

    try cache.store("example.com", .a, &records, 300);

    const result = cache.lookup("example.com", .a);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(usize, 2), result.?.len);
}

test "MapFactory creates all map types" {
    const allocator = std.testing.allocator;

    var headers = try MapFactory.createHeaderMap(allocator);
    defer headers.deinit();

    var recipients = try MapFactory.createRecipientSet(allocator);
    defer recipients.deinit();

    var sessions = try MapFactory.createSessionMap(allocator);
    defer sessions.deinit();

    var dns = try MapFactory.createDnsCache(allocator);
    defer dns.deinit();

    var pools = try MapFactory.createConnectionPoolMap(allocator);
    defer pools.deinit();

    // All created successfully
    try std.testing.expect(true);
}
