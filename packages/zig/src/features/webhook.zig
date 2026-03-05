const std = @import("std");
const posix = std.posix;
const logger = @import("../core/logger.zig");
const time_compat = @import("../core/time_compat.zig");

pub const WebhookConfig = struct {
    url: ?[]const u8,
    enabled: bool,
    timeout_ms: u32,
};

pub const WebhookPayload = struct {
    from: []const u8,
    recipients: []const []const u8,
    size: usize,
    timestamp: i64,
    remote_addr: []const u8,
};

/// Send webhook notification using synchronous POSIX sockets
pub fn sendWebhook(allocator: std.mem.Allocator, cfg: WebhookConfig, payload: WebhookPayload, log: *logger.Logger) !void {
    if (!cfg.enabled or cfg.url == null) {
        return;
    }

    const url = cfg.url.?;

    // Build JSON payload (escape user-supplied strings to prevent injection)
    const escaped_from = try escapeJsonString(allocator, payload.from);
    defer allocator.free(escaped_from);
    const escaped_addr = try escapeJsonString(allocator, payload.remote_addr);
    defer allocator.free(escaped_addr);

    const recipients_json = try formatRecipients(allocator, payload.recipients);
    defer allocator.free(recipients_json);

    const json_body = try std.fmt.allocPrint(allocator,
        \\{{"from":"{s}","recipients":[{s}],"size":{d},"timestamp":{d},"remote_addr":"{s}"}}
    , .{
        escaped_from,
        recipients_json,
        payload.size,
        payload.timestamp,
        escaped_addr,
    });
    defer allocator.free(json_body);

    // Parse URL
    const uri = std.Uri.parse(url) catch |err| {
        log.err("Invalid webhook URL: {s} - {}", .{ url, err });
        return error.InvalidWebhookUrl;
    };

    const host = uri.host orelse {
        log.err("No host in webhook URL: {s}", .{url});
        return error.InvalidWebhookUrl;
    };

    // For percent-encoded host
    const host_str = host.percent_encoded;
    const port: u16 = uri.port orelse 80;
    const path = if (uri.path.percent_encoded.len > 0) uri.path.percent_encoded else "/";

    // HTTPS not supported yet - use HTTP only
    if (std.mem.eql(u8, uri.scheme, "https")) {
        log.warn("HTTPS webhooks not yet supported, skipping: {s}", .{url});
        return;
    }

    // Parse IP address
    const ip = parseIpv4(host_str) orelse {
        log.warn("Could not parse webhook host IP: {s}", .{host_str});
        return;
    };

    // Reject private/loopback IPs to prevent SSRF
    if (isPrivateIp(ip)) {
        log.warn("Webhook target resolves to private/loopback IP — rejected: {s}", .{host_str});
        return;
    }

    // Create socket
    const raw_fd = std.c.socket(@intCast(@as(u32, posix.AF.INET)), @intCast(@as(u32, posix.SOCK.STREAM)), 0);
    if (raw_fd < 0) {
        log.err("Failed to create socket", .{});
        return;
    }
    const fd: posix.socket_t = @intCast(raw_fd);
    defer posix.close(fd);

    // Connect
    const sockaddr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.bytesToValue(u32, &ip),
    };

    if (std.c.connect(fd, @ptrCast(&sockaddr), @sizeOf(posix.sockaddr.in)) < 0) {
        log.err("Failed to connect to webhook: {s}:{d}", .{ host_str, port });
        return;
    }

    // Build HTTP request
    const request = try std.fmt.allocPrint(allocator, "POST {s} HTTP/1.1\r\n" ++
        "Host: {s}\r\n" ++
        "Content-Type: application/json\r\n" ++
        "Content-Length: {d}\r\n" ++
        "User-Agent: SMTP-Server-Zig/1.0\r\n" ++
        "Connection: close\r\n" ++
        "\r\n" ++
        "{s}", .{ path, host_str, json_body.len, json_body });
    defer allocator.free(request);

    // Send request
    if (std.c.write(fd, request.ptr, request.len) < 0) {
        log.err("Failed to send webhook request", .{});
        return;
    }

    // Read response
    var response_buf: [1024]u8 = undefined;
    const bytes_read = std.c.read(fd, &response_buf, response_buf.len);
    if (bytes_read < 0) {
        log.warn("Failed to read webhook response", .{});
        return;
    }

    if (bytes_read > 0) {
        const response = response_buf[0..@intCast(bytes_read)];
        if (std.mem.indexOf(u8, response, "HTTP/1") != null) {
            if (std.mem.indexOf(u8, response, " 2") != null) {
                log.info("Webhook delivered successfully to {s}", .{url});
            } else {
                log.warn("Webhook returned non-2xx status: {s}", .{response[0..@min(50, response.len)]});
            }
        }
    }
}

fn formatRecipients(allocator: std.mem.Allocator, recipients: []const []const u8) ![]u8 {
    if (recipients.len == 0) return try allocator.dupe(u8, "");

    var result = std.ArrayList(u8){};
    errdefer result.deinit(allocator);

    for (recipients, 0..) |rcpt, i| {
        if (i > 0) try result.appendSlice(allocator, ",");
        try result.appendSlice(allocator, "\"");
        const escaped = try escapeJsonString(allocator, rcpt);
        defer allocator.free(escaped);
        try result.appendSlice(allocator, escaped);
        try result.appendSlice(allocator, "\"");
    }

    return try result.toOwnedSlice(allocator);
}

/// Escape a string for safe embedding in JSON values
pub fn escapeJsonString(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var needs_escape = false;
    for (s) |c| {
        if (c == '"' or c == '\\' or c < 0x20) {
            needs_escape = true;
            break;
        }
    }
    if (!needs_escape) return try allocator.dupe(u8, s);

    var result: std.ArrayList(u8) = .{};
    errdefer result.deinit(allocator);

    for (s) |c| {
        switch (c) {
            '"' => try result.appendSlice(allocator, "\\\""),
            '\\' => try result.appendSlice(allocator, "\\\\"),
            '\n' => try result.appendSlice(allocator, "\\n"),
            '\r' => try result.appendSlice(allocator, "\\r"),
            '\t' => try result.appendSlice(allocator, "\\t"),
            else => {
                if (c < 0x20) {
                    // Escape other control characters as \u00XX
                    try result.appendSlice(allocator, "\\u00");
                    const hex = "0123456789abcdef";
                    try result.append(allocator, hex[c >> 4]);
                    try result.append(allocator, hex[c & 0x0f]);
                } else {
                    try result.append(allocator, c);
                }
            },
        }
    }
    return try result.toOwnedSlice(allocator);
}

/// Check if an IPv4 address is in a private/loopback/link-local range (SSRF protection)
pub fn isPrivateIp(ip: [4]u8) bool {
    return ip[0] == 127 or // 127.0.0.0/8 loopback
        ip[0] == 10 or // 10.0.0.0/8
        (ip[0] == 172 and ip[1] >= 16 and ip[1] <= 31) or // 172.16.0.0/12
        (ip[0] == 192 and ip[1] == 168) or // 192.168.0.0/16
        (ip[0] == 169 and ip[1] == 254) or // 169.254.0.0/16 link-local
        (ip[0] == 0 and ip[1] == 0 and ip[2] == 0 and ip[3] == 0); // 0.0.0.0
}

fn parseIpv4(s: []const u8) ?[4]u8 {
    var result: [4]u8 = undefined;
    var idx: usize = 0;
    var octet: u16 = 0;
    var digits: u8 = 0;

    for (s) |c| {
        if (c == '.') {
            if (digits == 0 or idx >= 3) return null;
            result[idx] = @intCast(octet);
            idx += 1;
            octet = 0;
            digits = 0;
        } else if (c >= '0' and c <= '9') {
            octet = octet * 10 + (c - '0');
            if (octet > 255) return null;
            digits += 1;
            if (digits > 3) return null;
        } else {
            return null;
        }
    }
    if (digits == 0 or idx != 3) return null;
    result[3] = @intCast(octet);
    return result;
}
