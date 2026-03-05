// Async I/O wrapper for Zig 0.16
// Provides async networking, DNS resolution, and HTTP client capabilities

const std = @import("std");
const posix = std.posix;
const Io = std.Io;
const net = Io.net;
const time_compat = @import("time_compat.zig");

/// Initialize a threaded Io context for async operations
pub fn initThreadedIo(allocator: std.mem.Allocator) Io.Threaded {
    return Io.Threaded.init(allocator);
}

/// Get the Io interface from a Threaded context
pub fn getIo(threaded: *Io.Threaded) Io {
    return threaded.io();
}

/// TCP Client for outbound connections
pub const TcpClient = struct {
    allocator: std.mem.Allocator,
    io: Io,
    stream: ?net.Stream,

    pub fn init(allocator: std.mem.Allocator, io: Io) TcpClient {
        return .{
            .allocator = allocator,
            .io = io,
            .stream = null,
        };
    }

    pub fn connect(self: *TcpClient, host: []const u8, port: u16) !void {
        // Parse IP address
        const address = try net.IpAddress.parse(host, port);

        // Connect using async Io
        self.stream = try address.connect(self.io, .{});
    }

    pub fn connectWithTimeout(self: *TcpClient, host: []const u8, port: u16, timeout_ms: u32) !void {
        const address = try net.IpAddress.parse(host, port);
        const timeout = Io.Timeout.fromMillis(timeout_ms);
        self.stream = try address.connectTimeout(self.io, .{}, timeout);
    }

    pub fn write(self: *TcpClient, data: []const u8) !usize {
        if (self.stream) |*stream| {
            return stream.write(self.io, data);
        }
        return error.NotConnected;
    }

    pub fn writeAll(self: *TcpClient, data: []const u8) !void {
        if (self.stream) |*stream| {
            try stream.writeAll(self.io, data);
        } else {
            return error.NotConnected;
        }
    }

    pub fn read(self: *TcpClient, buffer: []u8) !usize {
        if (self.stream) |*stream| {
            return stream.read(self.io, buffer);
        }
        return error.NotConnected;
    }

    pub fn close(self: *TcpClient) void {
        if (self.stream) |*stream| {
            stream.close(self.io);
            self.stream = null;
        }
    }

    pub fn deinit(self: *TcpClient) void {
        self.close();
    }
};

/// DNS Resolver using async Io
pub const DnsResolver = struct {
    allocator: std.mem.Allocator,
    io: Io,

    pub fn init(allocator: std.mem.Allocator, io: Io) DnsResolver {
        return .{
            .allocator = allocator,
            .io = io,
        };
    }

    /// Resolve hostname to IP addresses
    pub fn resolve(self: *DnsResolver, hostname: []const u8, port: u16) ![]net.IpAddress {
        // Use the Io.net.HostName resolver
        var host_name = try net.HostName.init(hostname);

        var addresses = std.ArrayList(net.IpAddress).init(self.allocator);
        errdefer addresses.deinit();

        // Resolve addresses
        var iter = host_name.resolve(self.io, port) catch |err| {
            return err;
        };
        defer iter.deinit();

        while (iter.next()) |addr| {
            try addresses.append(addr);
        }

        return addresses.toOwnedSlice();
    }

    /// Reverse DNS lookup
    pub fn reverseLookup(self: *DnsResolver, ip: []const u8) ![]const u8 {
        _ = self;
        _ = ip;
        // Reverse DNS not directly supported, return empty
        return "";
    }

    pub fn deinit(self: *DnsResolver) void {
        _ = self;
    }
};

/// Simple HTTP Client for webhook delivery
pub const HttpClient = struct {
    allocator: std.mem.Allocator,
    io: Io,
    timeout_ms: u32,

    pub const Response = struct {
        status_code: u16,
        body: []u8,
        allocator: std.mem.Allocator,

        pub fn deinit(self: *Response) void {
            if (self.body.len > 0) {
                self.allocator.free(self.body);
            }
        }
    };

    pub fn init(allocator: std.mem.Allocator, io: Io) HttpClient {
        return .{
            .allocator = allocator,
            .io = io,
            .timeout_ms = 30000,
        };
    }

    pub fn setTimeout(self: *HttpClient, timeout_ms: u32) void {
        self.timeout_ms = timeout_ms;
    }

    /// Send HTTP POST request
    pub fn post(self: *HttpClient, url: []const u8, body: []const u8, content_type: []const u8) !Response {
        // Parse URL
        const uri = std.Uri.parse(url) catch return error.InvalidUrl;

        const host = uri.host orelse return error.InvalidUrl;
        const port: u16 = uri.port orelse if (std.mem.eql(u8, uri.scheme, "https")) 443 else 80;
        const path = if (uri.path.len > 0) uri.path else "/";

        // For HTTPS, we'd need TLS - for now just support HTTP
        if (std.mem.eql(u8, uri.scheme, "https")) {
            return error.HttpsNotSupported;
        }

        // Connect
        const address = try net.IpAddress.parse(host, port);
        var stream = try address.connect(self.io, .{});
        defer stream.close(self.io);

        // Build HTTP request
        const request = try std.fmt.allocPrint(self.allocator, "POST {s} HTTP/1.1\r\n" ++
            "Host: {s}\r\n" ++
            "Content-Type: {s}\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Connection: close\r\n" ++
            "\r\n" ++
            "{s}", .{ path, host, content_type, body.len, body });
        defer self.allocator.free(request);

        // Send request
        try stream.writeAll(self.io, request);

        // Read response
        var response_buf: [8192]u8 = undefined;
        const bytes_read = try stream.read(self.io, &response_buf);

        if (bytes_read == 0) {
            return error.EmptyResponse;
        }

        // Parse status code
        const response_str = response_buf[0..bytes_read];
        const status_code = parseStatusCode(response_str) orelse 0;

        // Find body (after \r\n\r\n)
        const body_start = std.mem.indexOf(u8, response_str, "\r\n\r\n");
        const response_body = if (body_start) |start|
            try self.allocator.dupe(u8, response_str[start + 4 ..])
        else
            try self.allocator.alloc(u8, 0);

        return .{
            .status_code = status_code,
            .body = response_body,
            .allocator = self.allocator,
        };
    }

    fn parseStatusCode(response: []const u8) ?u16 {
        // HTTP/1.1 200 OK
        if (response.len < 12) return null;
        if (!std.mem.startsWith(u8, response, "HTTP/1.")) return null;

        const status_start = std.mem.indexOf(u8, response, " ") orelse return null;
        const status_end = std.mem.indexOfPos(u8, response, status_start + 1, " ") orelse return null;

        return std.fmt.parseInt(u16, response[status_start + 1 .. status_end], 10) catch null;
    }

    pub fn deinit(self: *HttpClient) void {
        _ = self;
    }
};

/// DNSBL (DNS Blacklist) checker using async DNS
pub const DnsblChecker = struct {
    allocator: std.mem.Allocator,
    io: Io,
    blacklists: []const []const u8,

    const default_blacklists = &[_][]const u8{
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "b.barracudacentral.org",
    };

    pub fn init(allocator: std.mem.Allocator, io: Io) DnsblChecker {
        return .{
            .allocator = allocator,
            .io = io,
            .blacklists = default_blacklists,
        };
    }

    pub fn setBlacklists(self: *DnsblChecker, lists: []const []const u8) void {
        self.blacklists = lists;
    }

    /// Check if an IP is blacklisted
    /// Returns true if the IP is found in any blacklist
    pub fn isBlacklisted(self: *DnsblChecker, ip_addr: []const u8) !bool {
        // Parse and reverse the IP address
        const reversed = try reverseIp(self.allocator, ip_addr);
        defer self.allocator.free(reversed);

        // Check each blacklist
        for (self.blacklists) |bl| {
            const query = try std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ reversed, bl });
            defer self.allocator.free(query);

            // Try to resolve - if it resolves, the IP is blacklisted
            if (self.checkBlacklist(query)) {
                return true;
            }
        }

        return false;
    }

    fn checkBlacklist(self: *DnsblChecker, query: []const u8) bool {
        var host_name = net.HostName.init(query) catch return false;
        var iter = host_name.resolve(self.io, 0) catch return false;
        defer iter.deinit();

        // If we get any result, the IP is blacklisted
        return iter.next() != null;
    }

    fn reverseIp(allocator: std.mem.Allocator, ip: []const u8) ![]u8 {
        // Parse IPv4: "1.2.3.4" -> "4.3.2.1"
        var parts: [4][]const u8 = undefined;
        var part_count: usize = 0;
        var start: usize = 0;

        for (ip, 0..) |c, i| {
            if (c == '.') {
                if (part_count >= 4) return error.InvalidIp;
                parts[part_count] = ip[start..i];
                part_count += 1;
                start = i + 1;
            }
        }
        if (part_count == 3) {
            parts[3] = ip[start..];
            part_count = 4;
        }

        if (part_count != 4) return error.InvalidIp;

        return std.fmt.allocPrint(allocator, "{s}.{s}.{s}.{s}", .{
            parts[3], parts[2], parts[1], parts[0],
        });
    }

    pub fn deinit(self: *DnsblChecker) void {
        _ = self;
    }
};

// Tests
test "reverse IP" {
    const allocator = std.testing.allocator;
    const reversed = try DnsblChecker.reverseIp(allocator, "192.168.1.1");
    defer allocator.free(reversed);
    try std.testing.expectEqualStrings("1.1.168.192", reversed);
}
