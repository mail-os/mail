const std = @import("std");
const date = @import("icalendar_time.zig").Date;
const wbxml = @import("wbxml.zig");

const S = wbxml.Search;
const page = wbxml.Page.search;
const page_size = 50;

pub const Query = struct {
    collection: ?[]const u8 = null,
    keywords: ?[]const u8 = null,
    after: ?i64 = null,
    before: ?i64 = null,
    first: usize = 0,
    count: usize = page_size,
    body_limit: ?usize = null,
};

pub fn parse(search: wbxml.Node) !Query {
    if (search.text != null or search.children.items.len != 1) return error.InvalidSearch;
    const store = search.children.items[0];
    if (store.page != page or store.token != S.Store or store.text != null) return error.InvalidSearch;
    var name: ?[]const u8 = null;
    var criteria: ?wbxml.Node = null;
    var options: ?wbxml.Node = null;
    for (store.children.items) |child| {
        if (child.page != page) return error.InvalidSearch;
        switch (child.token) {
            S.Name => {
                if (name != null) return error.InvalidSearch;
                name = try text(child);
            },
            S.Query => {
                if (criteria != null or child.text != null) return error.InvalidSearch;
                criteria = child;
            },
            S.Options => {
                if (options != null or child.text != null) return error.InvalidSearch;
                options = child;
            },
            else => return error.InvalidSearch,
        }
    }
    if (!std.ascii.eqlIgnoreCase(name orelse return error.InvalidSearch, "Mailbox")) return error.InvalidSearch;
    const query = criteria orelse return error.InvalidSearch;
    var nodes = query.children.items;
    if (nodes.len == 1 and nodes[0].page == page and nodes[0].token == S.And) {
        if (nodes[0].text != null) return error.InvalidSearch;
        nodes = nodes[0].children.items;
    }
    var out = Query{};
    var class_seen = false;
    for (nodes) |node| {
        if (node.page == wbxml.Page.air_sync) {
            switch (node.token) {
                wbxml.AirSync.FolderType => {
                    if (class_seen or !std.ascii.eqlIgnoreCase(try text(node), "Email")) return error.InvalidSearch;
                    class_seen = true;
                },
                wbxml.AirSync.FolderId => {
                    if (out.collection != null) return error.InvalidSearch;
                    out.collection = try text(node);
                },
                else => return error.InvalidSearch,
            }
            continue;
        }
        if (node.page != page) return error.InvalidSearch;
        switch (node.token) {
            S.FreeText => {
                if (out.keywords != null) return error.InvalidSearch;
                const value = std.mem.trim(u8, try text(node), &std.ascii.whitespace);
                if (value.len > 256 or !std.unicode.utf8ValidateSlice(value)) return error.InvalidSearch;
                out.keywords = value;
            },
            S.GreaterThan, S.LessThan => {
                const bound = if (node.token == S.GreaterThan) &out.after else &out.before;
                if (bound.* != null) return error.InvalidSearch;
                bound.* = try dateBound(node);
            },
            else => return error.InvalidSearch,
        }
    }
    const keywords: []const u8 = out.keywords orelse "";
    if (keywords.len == 0 and out.after == null and out.before == null) return error.InvalidSearch;
    if (options) |opts| try parseOptions(opts, &out);
    return out;
}

fn text(node: wbxml.Node) ![]const u8 {
    if (node.children.items.len != 0 or node.is_opaque) return error.InvalidSearch;
    return node.text orelse error.InvalidSearch;
}

fn dateBound(node: wbxml.Node) !i64 {
    if (node.text != null or node.children.items.len != 2) return error.InvalidSearch;
    const field = node.children.items[0];
    if (field.page != wbxml.Page.email or field.token != wbxml.Email.DateReceived or
        field.text != null or field.children.items.len != 0) return error.InvalidSearch;
    const value = node.children.items[1];
    if (value.page != page or value.token != S.Value) return error.InvalidSearch;
    return utcMilliseconds(try text(value)) orelse error.InvalidSearch;
}

fn parseOptions(options: wbxml.Node, query: *Query) !void {
    var range_seen = false;
    for (options.children.items) |node| {
        if (node.page == wbxml.Page.air_sync_base and node.token == wbxml.AirSyncBase.BodyPreference) {
            if (node.childText(wbxml.Page.air_sync_base, wbxml.AirSyncBase.Type)) |kind| {
                if (std.mem.eql(u8, kind, "1")) {
                    const length = if (node.childText(wbxml.Page.air_sync_base, wbxml.AirSyncBase.TruncationSize)) |value|
                        try number(value)
                    else
                        32 * 1024;
                    query.body_limit = @min(length, 32 * 1024);
                }
            }
            continue;
        }
        if (node.page != page) return error.InvalidSearch;
        switch (node.token) {
            S.Range => {
                if (range_seen) return error.InvalidSearch;
                range_seen = true;
                const range = try text(node);
                const sep = std.mem.indexOfScalar(u8, range, '-') orelse return error.InvalidSearch;
                query.first = try number(range[0..sep]);
                const last = try number(range[sep + 1 ..]);
                if (last < query.first) return error.InvalidSearch;
                query.count = @min(last - query.first, page_size - 1) + 1;
            },
            S.DeepTraversal, S.RebuildResults => {
                if (node.text != null or node.children.items.len != 0) return error.InvalidSearch;
            },
            else => return error.InvalidSearch,
        }
    }
}

fn number(value: []const u8) !usize {
    for (value) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidSearch;
    return std.fmt.parseInt(u32, value, 10) catch error.InvalidSearch;
}

/// EAS DateTime values are UTC and use extended ISO 8601 with milliseconds.
pub fn utcMilliseconds(value: []const u8) ?i64 {
    if (value.len != 20 and value.len != 24) return null;
    if (value[4] != '-' or value[7] != '-' or value[10] != 'T' or
        value[13] != ':' or value[16] != ':' or value[value.len - 1] != 'Z') return null;
    const milliseconds = if (value.len == 24) blk: {
        if (value[19] != '.') return null;
        break :blk number(value[20..23]) catch return null;
    } else 0;
    var compact: [16]u8 = undefined;
    @memcpy(compact[0..4], value[0..4]);
    @memcpy(compact[4..6], value[5..7]);
    @memcpy(compact[6..8], value[8..10]);
    compact[8] = 'T';
    @memcpy(compact[9..11], value[11..13]);
    @memcpy(compact[11..13], value[14..16]);
    @memcpy(compact[13..15], value[17..19]);
    compact[15] = 'Z';
    const stamp = date.parse(&compact) orelse return null;
    return stamp.epoch() * 1000 + @as(i64, @intCast(milliseconds));
}
