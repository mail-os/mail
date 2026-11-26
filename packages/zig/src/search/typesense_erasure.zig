//! Inspect the Mail-owned Typesense collections and delete verified document IDs.
const std = @import("std");
const se = @import("search-engine");
const env = @import("../core/env.zig");
const typesense = @import("typesense.zig");
const Allocator = std.mem.Allocator;

pub const names = [_][]const u8{ "messages", "messages_v2", typesense.collection };
pub const Stamps = [names.len]?i64;
const Id = typesense.MessageId;

pub const Endpoint = struct {
    host: []const u8,
    port: u16,
};

pub const Collection = struct {
    created_at: i64,
    ids: std.ArrayList(Id) = .empty,
};

pub const Service = struct {
    endpoint: Endpoint,
    headers: [1]std.http.Header,

    pub fn reviewed(endpoint: Endpoint) !Service {
        const host = env.get("TYPESENSE_HOST") orelse "127.0.0.1";
        const port = std.fmt.parseInt(u16, env.get("TYPESENSE_PORT") orelse "8108", 10) catch
            return error.ErasureTypesenseEndpointMismatch;
        if (host.len == 0 or host.len > 253 or port == 0 or
            !std.mem.eql(u8, host, endpoint.host) or port != endpoint.port)
            return error.ErasureTypesenseEndpointMismatch;
        for (host) |byte| {
            if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '.')
                return error.ErasureTypesenseEndpointMismatch;
        }

        const key = env.get("TYPESENSE_API_KEY") orelse return error.ErasureTypesenseUnavailable;
        if (key.len == 0 or key.len > 256) return error.ErasureTypesenseUnavailable;
        for (key) |byte| {
            if (!std.ascii.isPrint(byte)) return error.ErasureTypesenseUnavailable;
        }
        return .{ .endpoint = endpoint, .headers = .{.{ .name = "X-TYPESENSE-API-KEY", .value = key }} };
    }

    fn request(self: *const Service, a: Allocator, client: *std.http.Client, method: std.http.Method, path: []const u8) !std.http.Client.Request {
        const address = try std.fmt.allocPrint(a, "http://{s}:{d}{s}", .{ self.endpoint.host, self.endpoint.port, path });
        errdefer a.free(address);
        var req = try client.request(method, try std.Uri.parse(address), .{
            .redirect_behavior = .unhandled,
            .keep_alive = false,
            .headers = .{ .accept_encoding = .omit },
            .extra_headers = &self.headers,
        });
        errdefer req.deinit();
        const socket = req.connection.?.stream_reader.stream.socket.handle;
        const timeout: std.posix.timeval = .{ .sec = 15, .usec = 0 };
        try std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
        try std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&timeout));
        try req.sendBodiless();
        return req;
    }

    fn requireFraming(response: std.http.Client.Response) !void {
        if (response.head.content_encoding != .identity or
            (response.head.transfer_encoding != .chunked and response.head.content_length == null))
            return error.ErasureTypesenseIncompleteResponse;
    }

    fn metadata(self: *const Service, a: Allocator, client: *std.http.Client, method: std.http.Method, path: []const u8) !struct { status: std.http.Status, value: std.json.Value } {
        var req = try self.request(a, client, method, path);
        defer req.deinit();
        var response = try req.receiveHead(&.{});
        try requireFraming(response);
        const status = response.head.status;
        var buffer: [4096]u8 = undefined;
        const bytes = try response.reader(&buffer).allocRemaining(a, .limited(128 * 1024));
        const data = try std.json.parseFromSliceLeaky(std.json.Value, a, bytes, .{});
        if (data != .object) return error.ErasureTypesenseIncompleteResponse;
        return .{ .status = status, .value = data };
    }

    pub fn verifyService(self: *const Service, a: Allocator, client: *std.http.Client) !void {
        const response = try self.metadata(a, client, .GET, "/health");
        if (response.status != .ok) return error.ErasureTypesenseUnavailable;
        const ok = response.value.object.get("ok") orelse return error.ErasureTypesenseUnavailable;
        if (ok != .bool or !ok.bool) return error.ErasureTypesenseUnavailable;
    }

    fn collectionStamp(self: *const Service, a: Allocator, client: *std.http.Client, name: []const u8) !?i64 {
        const path = try std.fmt.allocPrint(a, "/collections/{s}", .{name});
        const response = try self.metadata(a, client, .GET, path);
        if (response.status == .not_found and std.mem.eql(u8, field(response.value, "message") orelse "", "Collection not found"))
            return null;
        if (response.status != .ok) return error.ErasureTypesenseUnavailable;
        const actual = field(response.value, "name") orelse return error.ErasureTypesenseIncompleteResponse;
        if (!std.mem.eql(u8, actual, name)) return error.ErasureTypesenseCollectionAlias;
        const stamp = response.value.object.get("created_at") orelse return error.ErasureTypesenseIncompleteResponse;
        if (stamp != .integer or stamp.integer < 1) return error.ErasureTypesenseIncompleteResponse;
        return stamp.integer;
    }

    pub fn inspect(self: *const Service, a: Allocator, client: *std.http.Client, name: []const u8, mailbox: []const u8) !?Collection {
        const stamp = (try self.collectionStamp(a, client, name)) orelse return null;
        const filter = try std.fmt.allocPrint(a, "username:=\x60{s}\x60", .{mailbox});
        var path: std.ArrayList(u8) = .empty;
        try path.appendSlice(a, try std.fmt.allocPrint(a, "/collections/{s}/documents/export?include_fields=id,username,mailbox,filename&filter_by=", .{name}));
        try se.http.appendUrlEncoded(&path, a, filter);

        var req = try self.request(a, client, .GET, path.items);
        defer req.deinit();
        var response = try req.receiveHead(&.{});
        if (response.head.status != .ok) return error.ErasureTypesenseUnavailable;
        try requireFraming(response);
        var buffer: [8192]u8 = undefined;
        const reader = response.reader(&buffer);
        var result: Collection = .{ .created_at = stamp };
        var frames = std.heap.ArenaAllocator.init(a);
        defer frames.deinit();
        while (try reader.takeDelimiter('\n')) |line| {
            defer _ = frames.reset(.retain_capacity);
            const document = try std.json.parseFromSliceLeaky(std.json.Value, frames.allocator(), line, .{});
            const username = field(document, "username") orelse return error.ErasureTypesenseIncompleteResponse;
            // Typesense normalizes punctuation and case in its string filters.
            // Exact ownership and the native document identity decide scope.
            if (!std.mem.eql(u8, username, mailbox)) continue;
            const id = field(document, "id") orelse return error.ErasureTypesenseDocumentUnverified;
            const folder = field(document, "mailbox") orelse return error.ErasureTypesenseDocumentUnverified;
            const filename = field(document, "filename") orelse return error.ErasureTypesenseDocumentUnverified;
            var expected: Id = undefined;
            if (folder.len == 0 or filename.len == 0 or
                !std.mem.eql(u8, id, typesense.docId(&expected, username, folder, filename)))
                return error.ErasureTypesenseDocumentUnverified;
            try result.ids.append(a, expected);
        }
        std.mem.sort(Id, result.ids.items, {}, lessId);
        for (result.ids.items, 0..) |*id, index| {
            if (index > 0 and std.mem.eql(u8, id, &result.ids.items[index - 1]))
                return error.ErasureTypesenseIncompleteResponse;
        }
        return result;
    }

    pub fn remove(self: *const Service, a: Allocator, client: *std.http.Client, name: []const u8, collection: Collection) !void {
        if (try self.collectionStamp(a, client, name) != collection.created_at)
            return error.ErasureTypesenseCollectionChanged;
        var request_memory = std.heap.ArenaAllocator.init(a);
        defer request_memory.deinit();
        const temporary = request_memory.allocator();
        var remaining: []const Id = collection.ids.items;
        while (remaining.len > 0) {
            const batch = remaining[0..@min(64, remaining.len)];
            remaining = remaining[batch.len..];
            defer _ = request_memory.reset(.retain_capacity);
            var filter: std.ArrayList(u8) = .empty;
            try filter.appendSlice(temporary, "id:=[");
            for (batch, 0..) |*id, index| {
                if (index != 0) try filter.append(temporary, ',');
                try filter.appendSlice(temporary, id);
            }
            try filter.append(temporary, ']');

            var path: std.ArrayList(u8) = .empty;
            try path.appendSlice(temporary, try std.fmt.allocPrint(temporary, "/collections/{s}/documents?filter_by=", .{name}));
            try se.http.appendUrlEncoded(&path, temporary, filter.items);
            const response = try self.metadata(temporary, client, .DELETE, path.items);
            if (response.status != .ok) return error.ErasureTypesenseUnavailable;
            const deleted = response.value.object.get("num_deleted") orelse return error.ErasureTypesenseIncompleteResponse;
            if (deleted != .integer or deleted.integer != batch.len) return error.ErasureTypesenseCollectionChanged;
        }
    }
};

pub fn validateMailbox(mailbox: []const u8) !void {
    for (mailbox) |byte| {
        if (!std.ascii.isPrint(byte) or byte == 0x60 or byte == '\\')
            return error.ErasureTypesenseDocumentUnverified;
    }
}

fn field(value: std.json.Value, name: []const u8) ?[]const u8 {
    if (value != .object) return null;
    const item = value.object.get(name) orelse return null;
    return if (item == .string) item.string else null;
}

fn lessId(_: void, left: Id, right: Id) bool {
    return std.mem.order(u8, &left, &right) == .lt;
}
