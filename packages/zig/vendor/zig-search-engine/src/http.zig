//! Minimal HTTP/1.1 client over plain TCP via libc, for talking to local
//! search engines (Typesense/Meilisearch listen on localhost without TLS).
//! `Connection: close` keeps response framing trivial; chunked responses
//! are de-chunked defensively.

const std = @import("std");
const types = @import("types.zig");

pub const Response = struct {
    status: u16,
    body: []u8,

    pub fn deinit(self: Response, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
    }

    pub fn ok(self: Response) bool {
        return self.status >= 200 and self.status < 300;
    }
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

fn tcpConnect(host: [:0]const u8, port: u16, timeout_seconds: u32) types.Error!std.posix.socket_t {
    var port_buf: [8]u8 = undefined;
    const port_z = std.fmt.bufPrintZ(&port_buf, "{d}", .{port}) catch return error.ConnectFailed;

    const hints = std.mem.zeroInit(std.c.addrinfo, .{
        .family = std.posix.AF.INET,
        .socktype = std.posix.SOCK.STREAM,
    });
    var result: ?*std.c.addrinfo = null;
    const gai = std.c.getaddrinfo(host.ptr, port_z.ptr, &hints, &result);
    if (@intFromEnum(gai) != 0 or result == null) return error.ConnectFailed;
    defer std.c.freeaddrinfo(result.?);

    const family: c_uint = @intCast(std.posix.AF.INET);
    const sock_type: c_uint = @intCast(@as(u32, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC));
    const raw_fd = std.c.socket(family, sock_type, 0);
    if (raw_fd < 0) return error.ConnectFailed;
    const sock: std.posix.socket_t = @intCast(raw_fd);
    errdefer _ = std.c.close(sock);

    const tv: std.posix.timeval = .{ .sec = @intCast(timeout_seconds), .usec = 0 };
    std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch {};

    if (std.c.connect(sock, result.?.addr.?, result.?.addrlen) < 0) return error.ConnectFailed;
    return sock;
}

fn writeAll(sock: std.posix.socket_t, data: []const u8) types.Error!void {
    var sent: usize = 0;
    while (sent < data.len) {
        const n = std.c.write(sock, data.ptr + sent, data.len - sent);
        if (n <= 0) return error.WriteFailed;
        sent += @intCast(n);
    }
}

/// Maximum response size accepted (search results are paginated; anything
/// bigger than this is a misbehaving server).
const max_response_bytes = 16 * 1024 * 1024;

pub fn request(
    allocator: std.mem.Allocator,
    host: [:0]const u8,
    port: u16,
    timeout_seconds: u32,
    method: []const u8,
    path: []const u8,
    extra_headers: []const Header,
    body: ?[]const u8,
) types.Error!Response {
    const sock = try tcpConnect(host, port, timeout_seconds);
    defer _ = std.c.close(sock);

    var head: std.ArrayList(u8) = .empty;
    defer head.deinit(allocator);

    appendf(&head, allocator, "{s} {s} HTTP/1.1\r\n", .{ method, path }) catch return error.OutOfMemory;
    appendf(&head, allocator, "Host: {s}:{d}\r\n", .{ host, port }) catch return error.OutOfMemory;
    head.appendSlice(allocator, "Connection: close\r\n") catch return error.OutOfMemory;
    for (extra_headers) |h| {
        appendf(&head, allocator, "{s}: {s}\r\n", .{ h.name, h.value }) catch return error.OutOfMemory;
    }
    appendf(&head, allocator, "Content-Length: {d}\r\n\r\n", .{if (body) |b| b.len else 0}) catch return error.OutOfMemory;

    try writeAll(sock, head.items);
    if (body) |b| try writeAll(sock, b);

    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(allocator);
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = std.c.read(sock, &buf, buf.len);
        if (n <= 0) break;
        raw.appendSlice(allocator, buf[0..@intCast(n)]) catch return error.OutOfMemory;
        if (raw.items.len > max_response_bytes) break;
    }

    const data = raw.items;
    if (data.len < 12 or !std.mem.startsWith(u8, data, "HTTP/1.")) return error.BadResponse;
    const status = std.fmt.parseInt(u16, data[9..12], 10) catch return error.BadResponse;
    const hdr_end = std.mem.indexOf(u8, data, "\r\n\r\n") orelse return error.BadResponse;
    var resp_body: []const u8 = data[hdr_end + 4 ..];

    var dechunked: std.ArrayList(u8) = .empty;
    defer dechunked.deinit(allocator);
    if (std.ascii.indexOfIgnoreCase(data[0..hdr_end], "transfer-encoding: chunked") != null) {
        var pos: usize = 0;
        while (pos < resp_body.len) {
            const line_end = std.mem.indexOfPos(u8, resp_body, pos, "\r\n") orelse break;
            const size = std.fmt.parseInt(usize, std.mem.trim(u8, resp_body[pos..line_end], " "), 16) catch break;
            if (size == 0) break;
            const chunk_start = line_end + 2;
            if (chunk_start + size > resp_body.len) break;
            dechunked.appendSlice(allocator, resp_body[chunk_start .. chunk_start + size]) catch return error.OutOfMemory;
            pos = chunk_start + size + 2;
        }
        resp_body = dechunked.items;
    }

    const owned = allocator.dupe(u8, resp_body) catch return error.OutOfMemory;
    return .{ .status = status, .body = owned };
}

fn appendf(list: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
    const s = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(s);
    try list.appendSlice(allocator, s);
}

// =============================================================================
// Encoding helpers (exported for drivers and callers)
// =============================================================================

/// Append `s` as a JSON string literal (with quotes) to `list`.
pub fn appendJsonString(list: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    try list.append(allocator, '"');
    for (s) |c| {
        switch (c) {
            '"' => try list.appendSlice(allocator, "\\\""),
            '\\' => try list.appendSlice(allocator, "\\\\"),
            '\n' => try list.appendSlice(allocator, "\\n"),
            '\r' => try list.appendSlice(allocator, "\\r"),
            '\t' => try list.appendSlice(allocator, "\\t"),
            else => {
                if (c < 0x20) {
                    const hex = "0123456789abcdef";
                    try list.appendSlice(allocator, "\\u00");
                    try list.append(allocator, hex[c >> 4]);
                    try list.append(allocator, hex[c & 0x0f]);
                } else {
                    try list.append(allocator, c);
                }
            },
        }
    }
    try list.append(allocator, '"');
}

/// Append `s` percent-encoded (RFC 3986 unreserved characters pass through).
pub fn appendUrlEncoded(list: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    const hex = "0123456789ABCDEF";
    for (s) |c| {
        const safe = (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or c == '-' or c == '_' or c == '.' or c == '~';
        if (safe) {
            try list.append(allocator, c);
        } else {
            try list.append(allocator, '%');
            try list.append(allocator, hex[c >> 4]);
            try list.append(allocator, hex[c & 0x0f]);
        }
    }
}

test "json string escaping" {
    const testing = std.testing;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try appendJsonString(&list, testing.allocator, "a\"b\\c\nd\x01");
    try testing.expectEqualStrings("\"a\\\"b\\\\c\\nd\\u0001\"", list.items);
}

test "url encoding" {
    const testing = std.testing;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try appendUrlEncoded(&list, testing.allocator, "a b&c=d`");
    try testing.expectEqualStrings("a%20b%26c%3Dd%60", list.items);
}
