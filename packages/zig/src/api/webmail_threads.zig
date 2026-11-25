//! Conversation grouping uses wire identifiers and explicit private groups.
//! Union-find handles missing ancestors, forward references and cycles without
//! recursion. Individual folder/UID identities remain available for actions.
const std = @import("std");
const maildir = @import("webmail_maildir.zig");
const submission = @import("../message/submission.zig");
const thread_ids = @import("../message/thread_ids.zig");

pub const Thread = struct {
    id: []const u8,
    latest: maildir.MessageSummary,
    members: []const maildir.MessageSummary,
    unread: usize,
    matching: usize,
};

/// Maildir rows arrive newest first. Keep that order within each read
/// section so a sender can have an unread bundle and a read bundle.
pub fn bundleSenders(a: std.mem.Allocator, rows: []const maildir.MessageSummary) ![]Thread {
    var grouped: std.ArrayList(Thread) = .empty;
    for ([_]bool{ false, true }) |seen| {
        var by_sender: std.StringHashMapUnmanaged(usize) = .empty;
        defer by_sender.deinit(a);
        var lists: std.ArrayList(std.ArrayList(maildir.MessageSummary)) = .empty;
        defer lists.deinit(a);
        var ids: std.ArrayList([]const u8) = .empty;
        defer ids.deinit(a);
        for (rows) |row| {
            if (row.flags.seen != seen) continue;
            const sender = submission.mailbox(row.from) catch std.mem.trim(u8, row.from, " \t");
            const key = if (sender.len > 0)
                try std.ascii.allocLowerString(a, sender)
            else
                try std.fmt.allocPrint(a, "unknown:{d}", .{row.uid});
            const slot = try by_sender.getOrPut(a, key);
            if (!slot.found_existing) {
                slot.value_ptr.* = lists.items.len;
                try lists.append(a, .empty);
                try ids.append(a, try std.fmt.allocPrint(a, "{s}:{s}", .{ if (seen) "read" else "unread", key }));
            }
            try lists.items[slot.value_ptr.*].append(a, row);
        }
        for (lists.items, ids.items) |*list, id| {
            const members = try list.toOwnedSlice(a);
            try grouped.append(a, .{
                .id = id,
                .latest = members[0],
                .members = members,
                .unread = if (seen) 0 else members.len,
                .matching = members.len,
            });
        }
    }
    return grouped.toOwnedSlice(a);
}

pub const Graph = struct {
    allocator: std.mem.Allocator,
    ids: std.StringHashMap(usize),
    parents: std.ArrayList(usize) = .empty,
    names: std.ArrayList([]const u8) = .empty,

    pub fn init(a: std.mem.Allocator) Graph {
        return .{ .allocator = a, .ids = std.StringHashMap(usize).init(a) };
    }

    pub fn deinit(self: *Graph) void {
        self.ids.deinit();
        self.parents.deinit(self.allocator);
        self.names.deinit(self.allocator);
    }

    pub fn node(self: *Graph, id: []const u8) !usize {
        if (self.ids.get(id)) |known| return known;
        const index = self.parents.items.len;
        const owned = try self.allocator.dupe(u8, id);
        try self.parents.append(self.allocator, index);
        try self.names.append(self.allocator, owned);
        try self.ids.put(owned, index);
        return index;
    }

    pub fn root(self: *Graph, index: usize) usize {
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

    pub fn join(self: *Graph, left: usize, right: usize) void {
        const a = self.root(left);
        const b = self.root(right);
        if (a == b) return;
        // Stable component identity independent of scan order.
        if (std.mem.order(u8, self.names.items[a], self.names.items[b]) == .lt)
            self.parents.items[b] = a
        else
            self.parents.items[a] = b;
    }

    pub fn references(self: *Graph, owner: usize, field: []const u8) !void {
        if (field.len > 8192) return;
        var ids: thread_ids.Iterator = .{ .text = field };
        while (ids.next()) |id| self.join(owner, try self.node(id));
    }
};

pub fn group(allocator: std.mem.Allocator, rows: []const maildir.MessageSummary) ![]Thread {
    var graph = Graph.init(allocator);
    defer graph.deinit();
    const row_nodes = try allocator.alloc(usize, rows.len);
    for (rows, 0..) |row, index| {
        const fallback = try std.fmt.allocPrint(allocator, "maildir:{s}:{d}", .{ row.folder, row.uid });
        const owner = try graph.node(fallback);
        row_nodes[index] = owner;
        try graph.references(owner, row.message_id);
        try graph.references(owner, row.in_reply_to);
        try graph.references(owner, row.references);
        if (row.manual_component) |component| graph.join(owner, try graph.node(component));
    }
    var roots = std.AutoHashMap(usize, usize).init(allocator);
    defer roots.deinit();
    var members: std.ArrayList(std.ArrayList(maildir.MessageSummary)) = .empty;
    defer {
        for (members.items) |*list| list.deinit(allocator);
        members.deinit(allocator);
    }
    for (rows, 0..) |row, index| {
        if (!row.matches_filters) continue;
        const root = graph.root(row_nodes[index]);
        const slot = try roots.getOrPut(root);
        if (!slot.found_existing) {
            slot.value_ptr.* = members.items.len;
            try members.append(allocator, .empty);
        }
    }
    for (rows, row_nodes) |row, node| {
        const position = roots.get(graph.root(node)) orelse continue;
        try members.items[position].append(allocator, row);
    }
    var output: std.ArrayList(Thread) = .empty;
    var entries = roots.iterator();
    while (entries.next()) |entry| {
        const list = try members.items[entry.value_ptr.*].toOwnedSlice(allocator);
        maildir.sortSummaries(list);
        var unread: usize = 0;
        var matching: usize = 0;
        for (list) |row| {
            if (!row.flags.seen) unread += 1;
            if (row.matches_filters) matching += 1;
        }
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(graph.names.items[entry.key_ptr.*], &digest, .{});
        const id = try allocator.alloc(u8, 64);
        const hex = "0123456789abcdef";
        for (digest, 0..) |byte, index| {
            id[index * 2] = hex[byte >> 4];
            id[index * 2 + 1] = hex[byte & 15];
        }
        try output.append(allocator, .{ .id = id, .latest = list[0], .members = list, .unread = unread, .matching = matching });
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
        sample(4, "<a@example.com>", "<b@example.com>", "<missing@example.com>"),
        sample(3, "<unrelated@example.com>", "", ""),
        sample(5, "<b@example.com>", "<a@example.com>", "<missing@example.com>"),
        sample(2, "", "", ""),
    };
    const threads = try group(arena.allocator(), &rows);
    try t.expectEqual(@as(usize, 3), threads.len);
    try t.expectEqual(@as(usize, 2), threads[0].members.len);
    try t.expectEqual(@as(i64, 5), threads[0].latest.uid);
    var filtered = rows;
    filtered[1].matches_filters = false;
    filtered[2].matches_filters = false;
    filtered[3].matches_filters = false;
    const matches = try group(arena.allocator(), &filtered);
    try t.expectEqual(@as(usize, 1), matches.len);
    try t.expectEqualStrings(threads[0].id, matches[0].id);
    try t.expectEqual(@as(usize, 1), matches[0].matching);
    try t.expectEqual(@as(usize, 2), matches[0].members.len);
    try t.expectEqual(@as(i64, 5), matches[0].latest.uid);
    try t.expectEqual(@as(i64, 5), matches[0].members[0].uid);
    try t.expectEqual(@as(i64, 4), matches[0].members[1].uid);
}

test "folder UIDs and malformed identifiers do not create accidental conversations" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    var rows = [_]maildir.MessageSummary{ sample(1, "invalid", "", ""), sample(1, "invalid", "", "") };
    rows[1].folder = "Sent";
    try t.expectEqual(@as(usize, 2), (try group(arena.allocator(), &rows)).len);
}
