//! Shared-calendar checkpoints contain only the public view served to one
//! grantee. Diffing snapshots allows tombstones for formerly visible resources
//! without consulting the owner's journal, which also contains private UIDs.
const std = @import("std");
const random = @import("../core/io_compat.zig");
const Allocator = std.mem.Allocator;

pub const Query = union(enum) { version_only, initial, after: []const u8 };
pub const Member = struct { uid: []const u8, etag: ?[]const u8 };
pub const Report = struct { token: []const u8, members: []const Member };
pub const Scope = [32]u8;

const Digest = [32]u8;
const prefix = "urn:mail:shared-sync:";
pub const max_bytes_per_snapshot = 2 * 1024 * 1024;
const max_cache_bytes = 16 * 1024 * 1024;
const max_checkpoints = 64;

const Checkpoint = struct {
    token: Digest,
    scope: Scope,
    members: []const Member,
    size: usize,
    memory: std.heap.ArenaAllocator,
};

pub const Store = struct {
    allocator: Allocator,
    key: [32]u8,
    entries: std.ArrayList(Checkpoint) = .empty,
    bytes: usize = 0,

    pub fn init(a: Allocator) Store {
        var key: [32]u8 = undefined;
        random.randomBytes(&key);
        return .{ .allocator = a, .key = key };
    }

    pub fn deinit(self: *Store) void {
        for (self.entries.items) |*item| item.memory.deinit();
        self.entries.deinit(self.allocator);
    }

    /// The caller holds the DAV mutex. Each UID appears exactly once in the
    /// current view. Sort to make a checkpoint independent of hash-map order.
    pub fn snapshot(self: *Store, a: Allocator, scope: Scope, current: []Member, query: Query, history: u32) !Report {
        std.mem.sort(Member, current, {}, uidLessThan);
        var size: usize = current.len * @sizeOf(Member);
        var mac = std.crypto.auth.hmac.sha2.HmacSha256.init(&self.key);
        mac.update(&scope);
        for (current) |member| {
            const etag = member.etag.?;
            size += member.uid.len + etag.len;
            if (size > max_bytes_per_snapshot) return error.CalendarExportTooLarge;
            mac.update(std.mem.asBytes(&member.uid.len));
            mac.update(member.uid);
            mac.update(std.mem.asBytes(&etag.len));
            mac.update(etag);
        }
        if (size > max_bytes_per_snapshot) return error.CalendarExportTooLarge;
        var digest: Digest = undefined;
        mac.final(&digest);
        const changes: []const Member = switch (query) {
            .version_only => &.{},
            .initial => current,
            .after => |token| blk: {
                if (token.len != prefix.len + 2 * @sizeOf(Digest) or !std.mem.startsWith(u8, token, prefix))
                    return error.InvalidSyncToken;
                var previous: Digest = undefined;
                _ = std.fmt.hexToBytes(&previous, token[prefix.len..]) catch return error.InvalidSyncToken;
                if (std.mem.eql(u8, &previous, &digest)) break :blk &.{};
                const stored = self.find(scope, previous) orelse return error.InvalidSyncToken;
                break :blk try diff(a, self.entries.items[stored].members, current);
            },
        };
        try self.remember(scope, digest, current, size, @min(@max(1, history), max_checkpoints));
        return .{ .token = try std.fmt.allocPrint(a, prefix ++ "{s}", .{std.fmt.bytesToHex(digest, .lower)}), .members = changes };
    }

    fn find(self: *Store, scope: Scope, digest: Digest) ?usize {
        for (self.entries.items, 0..) |item, i| {
            if (std.mem.eql(u8, &item.token, &digest) and std.mem.eql(u8, &item.scope, &scope)) return i;
        }
        return null;
    }

    fn remember(self: *Store, scope: Scope, digest: Digest, members: []const Member, size: usize, limit: usize) !void {
        if (self.find(scope, digest)) |index| {
            const existing = self.entries.orderedRemove(index);
            self.entries.appendAssumeCapacity(existing);
            return;
        }
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        errdefer arena.deinit();
        const a = arena.allocator();
        const copy = try a.alloc(Member, members.len);
        for (copy, members) |*slot, item| {
            slot.* = .{ .uid = try a.dupe(u8, item.uid), .etag = try a.dupe(u8, item.etag.?) };
        }
        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        while (self.entries.items.len >= limit or self.bytes + size > max_cache_bytes) {
            var oldest = self.entries.orderedRemove(0);
            self.bytes -= oldest.size;
            oldest.memory.deinit();
        }
        self.entries.appendAssumeCapacity(.{ .token = digest, .scope = scope, .members = copy, .size = size, .memory = arena });
        self.bytes += size;
    }
};

fn uidLessThan(_: void, lhs: Member, rhs: Member) bool {
    return std.mem.lessThan(u8, lhs.uid, rhs.uid);
}

fn diff(a: Allocator, before: []const Member, current: []const Member) ![]const Member {
    var changes: std.ArrayList(Member) = .empty;
    var index: usize = 0;
    for (current) |item| {
        while (index < before.len and std.mem.lessThan(u8, before[index].uid, item.uid)) : (index += 1) {
            try changes.append(a, .{ .uid = try a.dupe(u8, before[index].uid), .etag = null });
        }
        if (index < before.len and std.mem.eql(u8, before[index].uid, item.uid)) {
            const same = std.mem.eql(u8, before[index].etag.?, item.etag.?);
            index += 1;
            if (same) continue;
        }
        try changes.append(a, item);
    }
    for (before[index..]) |item| try changes.append(a, .{ .uid = try a.dupe(u8, item.uid), .etag = null });
    return changes.items;
}
