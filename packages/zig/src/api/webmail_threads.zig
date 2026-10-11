//! Conversation grouping uses wire identifiers, never subject similarity.
//! Union-find handles missing ancestors, forward references and cycles without
//! recursion. Individual folder/UID identities remain available for actions.
const std = @import("std");
const maildir = @import("webmail_maildir.zig");

pub const Thread = struct {
    id: []const u8,
    latest: maildir.MessageSummary,
    members: []const maildir.MessageSummary,
    unread: usize,
    matching: usize,
};

const Graph = struct {
    allocator: std.mem.Allocator,
    ids: std.StringHashMap(usize),
    parents: std.ArrayList(usize) = .empty,
    names: std.ArrayList([]const u8) = .empty,

    fn node(self: *Graph, id: []const u8) !usize {
        if (self.ids.get(id)) |known| return known;
        const index = self.parents.items.len;
        const owned = try self.allocator.dupe(u8, id);
        try self.parents.append(self.allocator, index);
        try self.names.append(self.allocator, owned);
        try self.ids.put(owned, index);
        return index;
    }

    fn root(self: *Graph, index: usize) usize {
        var result = index;
        while (self.parents.items[result] != result) result = self.parents.items[result];
        var current = index;
        while (self.parents.items[current] != current) {
            const next = self.parents.items[current];
            self.parents.items[current] = result;
            current = next;
        }
        return result;
    }

    fn join(self: *Graph, left: usize, right: usize) void {
        const a = self.root(left);
        const b = self.root(right);
        if (a == b) return;
        // Stable component identity independent of scan order.
        if (std.mem.order(u8, self.names.items[a], self.names.items[b]) == .lt)
            self.parents.items[b] = a
        else
            self.parents.items[a] = b;
    }

    fn references(self: *Graph, owner: usize, field: []const u8) !void {
        if (field.len > 8192) return;
        var start: usize = 0;
        var count: usize = 0;
        while (count < 64) : (count += 1) {
            const open = std.mem.indexOfScalarPos(u8, field, start, '<') orelse break;
            const close = std.mem.indexOfScalarPos(u8, field, open + 1, '>') orelse break;
            const id = field[open .. close + 1];
            start = close + 1;
            if (id.len > 320 or std.mem.indexOfScalar(u8, id, '@') == null) continue;
            var valid = true;
            for (id[1 .. id.len - 1]) |byte| if (byte <= 0x20 or byte == 0x7f or byte == '<' or byte == '>') {
                valid = false;
                break;
            };
            if (valid) self.join(owner, try self.node(id));
        }
    }
};

pub fn group(allocator: std.mem.Allocator, rows: []const maildir.MessageSummary) ![]Thread {
    var graph = Graph{ .allocator = allocator, .ids = std.StringHashMap(usize).init(allocator) };
    defer graph.ids.deinit();
    defer graph.parents.deinit(allocator);
    defer graph.names.deinit(allocator);
    const row_nodes = try allocator.alloc(usize, rows.len);
    for (rows, 0..) |row, index| {
        const fallback = try std.fmt.allocPrint(allocator, "maildir:{s}:{d}", .{ row.folder, row.uid });
        const owner = try graph.node(fallback);
        row_nodes[index] = owner;
        try graph.references(owner, row.message_id);
        try graph.references(owner, row.in_reply_to);
        try graph.references(owner, row.references);
    }
    var roots = std.AutoHashMap(usize, usize).init(allocator);
    defer roots.deinit();
    var members: std.ArrayList(std.ArrayList(maildir.MessageSummary)) = .empty;
    defer {
        for (members.items) |*list| list.deinit(allocator);
        members.deinit(allocator);
    }
    for (rows, 0..) |row, index| {
        const root = graph.root(row_nodes[index]);
        const position = roots.get(root) orelse blk: {
            const next = members.items.len;
            try members.append(allocator, .empty);
            try roots.put(root, next);
            break :blk next;
        };
        try members.items[position].append(allocator, row);
    }
    var output: std.ArrayList(Thread) = .empty;
    var entries = roots.iterator();
    while (entries.next()) |entry| {
        const list = members.items[entry.value_ptr.*].items;
        var unread: usize = 0;
        var matching: usize = 0;
        for (list) |row| {
            if (!row.flags.seen) unread += 1;
            if (row.matches_filters) matching += 1;
        }
        if (matching == 0) continue;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(graph.names.items[entry.key_ptr.*], &digest, .{});
        const id = try allocator.alloc(u8, 64);
        const hex = "0123456789abcdef";
        for (digest, 0..) |byte, index| {
            id[index * 2] = hex[byte >> 4];
            id[index * 2 + 1] = hex[byte & 15];
        }
        // queryMessages supplies newest-first rows; preserve that order.
        try output.append(allocator, .{ .id = id, .latest = list[0], .members = try allocator.dupe(maildir.MessageSummary, list), .unread = unread, .matching = matching });
    }
    std.mem.sort(Thread, output.items, {}, struct {
        fn lessThan(_: void, left: Thread, right: Thread) bool {
            if (left.latest.timestamp != right.latest.timestamp) return left.latest.timestamp > right.latest.timestamp;
            return std.mem.order(u8, left.id, right.id) == .lt;
        }
    }.lessThan);
    return output.toOwnedSlice(allocator);
}

fn sample(uid: i64, id: []const u8, parent: []const u8, refs: []const u8) maildir.MessageSummary {
    return .{ .uid = uid, .from = "sender@example.com", .to = "owner@example.com", .subject = "Same subject", .date = "", .snippet = "", .flags = .{}, .has_attachments = false, .size = 1, .message_id = id, .in_reply_to = parent, .references = refs, .timestamp = uid };
}

test "conversations link missing parents and cycles without merging identical subjects" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const rows = [_]maildir.MessageSummary{
        sample(5, "<b@example.com>", "<a@example.com>", "<missing@example.com>"),
        sample(4, "<a@example.com>", "<b@example.com>", "<missing@example.com>"),
        sample(3, "<unrelated@example.com>", "", ""),
        sample(2, "", "", ""),
    };
    const threads = try group(arena.allocator(), &rows);
    try t.expectEqual(@as(usize, 3), threads.len);
    try t.expectEqual(@as(usize, 2), threads[0].members.len);
    try t.expectEqual(@as(i64, 5), threads[0].latest.uid);
    var filtered = rows;
    filtered[0].matches_filters = false;
    const matches = try group(arena.allocator(), &filtered);
    try t.expectEqualStrings(threads[0].id, matches[0].id);
    try t.expectEqual(@as(usize, 1), matches[0].matching);
    try t.expectEqual(@as(usize, 2), matches[0].members.len);
}

test "folder UIDs and malformed identifiers do not create accidental conversations" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    var rows = [_]maildir.MessageSummary{ sample(1, "invalid", "", ""), sample(1, "invalid", "", "") };
    rows[1].folder = "Sent";
    try t.expectEqual(@as(usize, 2), (try group(arena.allocator(), &rows)).len);
}
