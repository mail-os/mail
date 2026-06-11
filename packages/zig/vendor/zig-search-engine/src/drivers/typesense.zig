//! Typesense driver.
//!
//! Mirrors the shape of @stacksjs/search-engine's typesense driver: a
//! `Schema` (the model's search trait) is turned into a Typesense
//! collection — searchable/displayed attributes become plain fields,
//! filterable attributes become facets, sortable attributes get sort
//! enabled — and documents are plain JSON keyed by a caller-chosen `id`.

const std = @import("std");
const http = @import("../http.zig");
const types = @import("../types.zig");

pub const Config = struct {
    host: [:0]const u8 = "127.0.0.1",
    port: u16 = 8108,
    api_key: []const u8,
    timeout_seconds: u32 = 3,
};

pub const Typesense = struct {
    config: Config,

    pub fn init(config: Config) Typesense {
        return .{ .config = config };
    }

    fn apiHeaders(self: *const Typesense) [2]http.Header {
        return .{
            .{ .name = "X-TYPESENSE-API-KEY", .value = self.config.api_key },
            .{ .name = "Content-Type", .value = "application/json" },
        };
    }

    fn request(
        self: *const Typesense,
        allocator: std.mem.Allocator,
        method: []const u8,
        path: []const u8,
        body: ?[]const u8,
    ) types.Error!http.Response {
        const headers = self.apiHeaders();
        return http.request(
            allocator,
            self.config.host,
            self.config.port,
            self.config.timeout_seconds,
            method,
            path,
            &headers,
            body,
        );
    }

    /// True when the engine answers on /health.
    pub fn healthy(self: *const Typesense, allocator: std.mem.Allocator) bool {
        const resp = self.request(allocator, "GET", "/health", null) catch return false;
        defer resp.deinit(allocator);
        return resp.ok();
    }

    pub fn collectionExists(self: *const Typesense, allocator: std.mem.Allocator, name: []const u8) types.Error!bool {
        var path_buf: [256]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/collections/{s}", .{name}) catch return error.RequestFailed;
        const resp = try self.request(allocator, "GET", path, null);
        defer resp.deinit(allocator);
        return resp.ok();
    }

    /// Create the collection for `schema` if it doesn't exist. The schema's
    /// attribute groups map to Typesense field properties the same way the
    /// stacks driver maps a model's useSearch trait:
    ///   searchable/displayed -> plain field
    ///   filterable           -> facet: true
    ///   sortable             -> sort: true
    /// All fields are optional except `id` (implicit in Typesense).
    pub fn ensureCollection(self: *const Typesense, allocator: std.mem.Allocator, schema: types.Schema) types.Error!void {
        if (try self.collectionExists(allocator, schema.name)) return;

        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(allocator);

        body.appendSlice(allocator, "{\"name\":") catch return error.OutOfMemory;
        http.appendJsonString(&body, allocator, schema.name) catch return error.OutOfMemory;
        body.appendSlice(allocator, ",\"fields\":[") catch return error.OutOfMemory;

        var first = true;
        const groups = [_][]const types.Field{ schema.searchable, schema.filterable, schema.sortable, schema.displayed };
        var seen: std.StringHashMap(void) = std.StringHashMap(void).init(allocator);
        defer seen.deinit();

        for (groups) |group| {
            for (group) |field| {
                if (seen.contains(field.name)) continue;
                seen.put(field.name, {}) catch return error.OutOfMemory;

                if (!first) body.append(allocator, ',') catch return error.OutOfMemory;
                first = false;

                const facet = fieldIn(schema.filterable, field.name);
                const sort = fieldIn(schema.sortable, field.name);
                appendf(&body, allocator, "{{\"name\":\"{s}\",\"type\":\"{s}\",\"facet\":{s},\"sort\":{s},\"optional\":true}}", .{
                    field.name,
                    field.type.typesenseName(),
                    if (facet) "true" else "false",
                    if (sort) "true" else "false",
                }) catch return error.OutOfMemory;
            }
        }
        body.appendSlice(allocator, "]}") catch return error.OutOfMemory;

        const resp = try self.request(allocator, "POST", "/collections", body.items);
        defer resp.deinit(allocator);
        // 409 = created concurrently — fine.
        if (!resp.ok() and resp.status != 409) return error.RequestFailed;
    }

    pub fn deleteCollection(self: *const Typesense, allocator: std.mem.Allocator, name: []const u8) types.Error!void {
        var path_buf: [256]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/collections/{s}", .{name}) catch return error.RequestFailed;
        const resp = try self.request(allocator, "DELETE", path, null);
        resp.deinit(allocator);
    }

    /// Upsert one document (`json_doc` must be a complete JSON object with
    /// an "id" member — build it with DocBuilder).
    pub fn upsertDocument(self: *const Typesense, allocator: std.mem.Allocator, collection: []const u8, json_doc: []const u8) types.Error!void {
        var path_buf: [256]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/collections/{s}/documents?action=upsert", .{collection}) catch return error.RequestFailed;
        const resp = try self.request(allocator, "POST", path, json_doc);
        defer resp.deinit(allocator);
        if (!resp.ok()) return error.RequestFailed;
    }

    /// Bulk upsert documents given as JSONL (one JSON object per line).
    pub fn importDocuments(self: *const Typesense, allocator: std.mem.Allocator, collection: []const u8, jsonl: []const u8) types.Error!void {
        var path_buf: [256]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/collections/{s}/documents/import?action=upsert", .{collection}) catch return error.RequestFailed;
        const headers = [_]http.Header{
            .{ .name = "X-TYPESENSE-API-KEY", .value = self.config.api_key },
            .{ .name = "Content-Type", .value = "text/plain" },
        };
        const resp = try http.request(allocator, self.config.host, self.config.port, self.config.timeout_seconds, "POST", path, &headers, jsonl);
        defer resp.deinit(allocator);
        if (!resp.ok()) return error.RequestFailed;
    }

    pub fn deleteDocument(self: *const Typesense, allocator: std.mem.Allocator, collection: []const u8, id: []const u8) types.Error!void {
        var path_buf: [384]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/collections/{s}/documents/{s}", .{ collection, id }) catch return error.RequestFailed;
        const resp = try self.request(allocator, "DELETE", path, null);
        resp.deinit(allocator);
    }

    /// Run a search. The returned SearchResponse owns the parsed JSON;
    /// callers iterate `hits()` and must call deinit().
    pub fn search(self: *const Typesense, allocator: std.mem.Allocator, collection: []const u8, params: types.SearchParams) types.Error!SearchResponse {
        var path: std.ArrayList(u8) = .empty;
        defer path.deinit(allocator);

        appendf(&path, allocator, "/collections/{s}/documents/search?q=", .{collection}) catch return error.OutOfMemory;
        http.appendUrlEncoded(&path, allocator, params.query) catch return error.OutOfMemory;
        path.appendSlice(allocator, "&query_by=") catch return error.OutOfMemory;
        http.appendUrlEncoded(&path, allocator, params.query_by) catch return error.OutOfMemory;
        appendf(&path, allocator, "&page={d}&per_page={d}", .{ params.page, params.per_page }) catch return error.OutOfMemory;
        if (params.filter_by) |f| {
            path.appendSlice(allocator, "&filter_by=") catch return error.OutOfMemory;
            http.appendUrlEncoded(&path, allocator, f) catch return error.OutOfMemory;
        }
        if (params.sort_by) |s| {
            path.appendSlice(allocator, "&sort_by=") catch return error.OutOfMemory;
            http.appendUrlEncoded(&path, allocator, s) catch return error.OutOfMemory;
        }

        const resp = try self.request(allocator, "GET", path.items, null);
        defer resp.deinit(allocator);
        if (!resp.ok()) return error.RequestFailed;

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, resp.body, .{}) catch return error.BadResponse;
        return .{ .parsed = parsed };
    }
};

/// Parsed search response. `hits()` iterates the hit documents as JSON
/// objects; string values are valid until deinit().
pub const SearchResponse = struct {
    parsed: std.json.Parsed(std.json.Value),

    pub fn deinit(self: *SearchResponse) void {
        self.parsed.deinit();
    }

    pub fn found(self: *const SearchResponse) u64 {
        const root = self.parsed.value;
        if (root != .object) return 0;
        const v = root.object.get("found") orelse return 0;
        return switch (v) {
            .integer => |i| if (i >= 0) @intCast(i) else 0,
            else => 0,
        };
    }

    pub const HitIterator = struct {
        items: []const std.json.Value,
        index: usize = 0,

        /// Returns the next hit's document object, skipping malformed hits.
        pub fn next(self: *HitIterator) ?std.json.ObjectMap {
            while (self.index < self.items.len) {
                const hit = self.items[self.index];
                self.index += 1;
                if (hit != .object) continue;
                const doc = hit.object.get("document") orelse continue;
                if (doc != .object) continue;
                return doc.object;
            }
            return null;
        }
    };

    pub fn hits(self: *const SearchResponse) HitIterator {
        const root = self.parsed.value;
        if (root == .object) {
            if (root.object.get("hits")) |h| {
                if (h == .array) return .{ .items = h.array.items };
            }
        }
        return .{ .items = &.{} };
    }

    /// Convenience: string field of a hit document ("" when absent).
    pub fn docString(doc: std.json.ObjectMap, name: []const u8) []const u8 {
        const v = doc.get(name) orelse return "";
        return switch (v) {
            .string => |s| s,
            else => "",
        };
    }
};

/// Incremental JSON object builder for documents.
pub const DocBuilder = struct {
    allocator: std.mem.Allocator,
    json: std.ArrayList(u8) = .empty,
    first: bool = true,

    pub fn init(allocator: std.mem.Allocator) DocBuilder {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *DocBuilder) void {
        self.json.deinit(self.allocator);
    }

    fn key(self: *DocBuilder, name: []const u8) types.Error!void {
        if (self.first) {
            self.json.append(self.allocator, '{') catch return error.OutOfMemory;
        } else {
            self.json.append(self.allocator, ',') catch return error.OutOfMemory;
        }
        self.first = false;
        http.appendJsonString(&self.json, self.allocator, name) catch return error.OutOfMemory;
        self.json.append(self.allocator, ':') catch return error.OutOfMemory;
    }

    pub fn putString(self: *DocBuilder, name: []const u8, value: []const u8) types.Error!void {
        try self.key(name);
        http.appendJsonString(&self.json, self.allocator, value) catch return error.OutOfMemory;
    }

    pub fn putInt(self: *DocBuilder, name: []const u8, value: i64) types.Error!void {
        try self.key(name);
        var buf: [24]u8 = undefined;
        const s = std.fmt.bufPrint(&buf, "{d}", .{value}) catch return error.OutOfMemory;
        self.json.appendSlice(self.allocator, s) catch return error.OutOfMemory;
    }

    /// Finish and return the JSON object. Caller owns the slice; the
    /// builder is reset to empty.
    pub fn toOwned(self: *DocBuilder) types.Error![]u8 {
        if (self.first) {
            self.json.appendSlice(self.allocator, "{}") catch return error.OutOfMemory;
        } else {
            self.json.append(self.allocator, '}') catch return error.OutOfMemory;
        }
        self.first = true;
        return self.json.toOwnedSlice(self.allocator) catch return error.OutOfMemory;
    }
};

fn fieldIn(fields: []const types.Field, name: []const u8) bool {
    for (fields) |f| {
        if (std.mem.eql(u8, f.name, name)) return true;
    }
    return false;
}

fn appendf(list: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
    const s = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(s);
    try list.appendSlice(allocator, s);
}

// =============================================================================
// Tests (no live server required)
// =============================================================================

test "DocBuilder builds escaped JSON" {
    const testing = std.testing;
    var b = DocBuilder.init(testing.allocator);
    defer b.deinit();
    try b.putString("id", "abc");
    try b.putString("subject", "hello \"world\"");
    try b.putInt("date", 1781094896);
    const json = try b.toOwned();
    defer testing.allocator.free(json);
    try testing.expectEqualStrings("{\"id\":\"abc\",\"subject\":\"hello \\\"world\\\"\",\"date\":1781094896}", json);
}

test "SearchResponse parses hits" {
    const testing = std.testing;
    const body =
        \\{"found":2,"hits":[{"document":{"id":"a","filename":"1.eml"}},{"document":{"id":"b","filename":"2.eml"}}]}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, body, .{});
    var resp = SearchResponse{ .parsed = parsed };
    defer resp.deinit();

    try testing.expectEqual(@as(u64, 2), resp.found());
    var it = resp.hits();
    var names: [2][]const u8 = undefined;
    var i: usize = 0;
    while (it.next()) |doc| : (i += 1) {
        names[i] = SearchResponse.docString(doc, "filename");
    }
    try testing.expectEqual(@as(usize, 2), i);
    try testing.expectEqualStrings("1.eml", names[0]);
    try testing.expectEqualStrings("2.eml", names[1]);
}
