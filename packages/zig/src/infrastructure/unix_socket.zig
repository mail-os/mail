const std = @import("std");
const net = std.net;
const posix = std.posix;
const platform = @import("platform.zig");

/// Unix domain socket support for IPC
/// Provides AF_UNIX socket support on Unix-like systems
///
/// Features:
/// - Stream (SOCK_STREAM) and datagram (SOCK_DGRAM) sockets
/// - Abstract namespace support (Linux)
/// - File permissions handling
/// - Non-blocking I/O
/// - Socket cleanup
///
/// Security considerations:
/// - File permissions control access
/// - Abstract sockets (Linux) bypass filesystem
/// - Automatic cleanup on close
/// - Path length validation
pub const UnixSocketError = error{
    NotSupportedOnThisPlatform,
    PathTooLong,
    InvalidPath,
    SocketExists,
    PermissionDenied,
};

/// Unix socket address
pub const UnixAddress = struct {
    path: []const u8,
    abstract: bool = false, // Linux abstract namespace

    pub fn init(path: []const u8) UnixAddress {
        return .{
            .path = path,
            .abstract = false,
        };
    }

    pub fn initAbstract(name: []const u8) UnixAddress {
        return .{
            .path = name,
            .abstract = true,
        };
    }

    /// Validate path length (typically 108 bytes max)
    pub fn validate(self: UnixAddress) !void {
        // Unix socket path is limited by sun_path size
        // Most systems: 108 bytes (including null terminator)
        const max_len = if (self.abstract) 107 else 107; // Reserve one byte for null/abstract marker
        if (self.path.len > max_len) {
            return UnixSocketError.PathTooLong;
        }
    }
};

/// Unix domain socket listener
pub const UnixListener = struct {
    sockfd: posix.socket_t,
    address: UnixAddress,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, address: UnixAddress) !UnixListener {
        if (!platform.Platform.current().isUnix()) {
            return UnixSocketError.NotSupportedOnThisPlatform;
        }

        try address.validate();

        // Create socket
        const sockfd = try posix.socket(
            posix.AF.UNIX,
            posix.SOCK.STREAM | posix.SOCK.CLOEXEC,
            0,
        );
        errdefer posix.close(sockfd);

        // Remove existing socket file if it exists (non-abstract)
        if (!address.abstract) {
            std.fs.deleteFileAbsolute(address.path) catch |err| {
                if (err != error.FileNotFound) {
                    posix.close(sockfd);
                    return err;
                }
            };
        }

        // Bind socket
        try bindUnixSocket(sockfd, address);

        // Listen
        try posix.listen(sockfd, 128);

        return UnixListener{
            .sockfd = sockfd,
            .address = address,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *UnixListener) void {
        posix.close(self.sockfd);

        // Clean up socket file (non-abstract)
        if (!self.address.abstract) {
            std.fs.deleteFileAbsolute(self.address.path) catch {};
        }
    }

    /// Accept connection
    pub fn accept(self: *UnixListener) !UnixStream {
        var addr: posix.sockaddr.un = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.un);

        const client_fd = try posix.accept(
            self.sockfd,
            @ptrCast(&addr),
            &addr_len,
            posix.SOCK.CLOEXEC,
        );

        return UnixStream{
            .sockfd = client_fd,
            .allocator = self.allocator,
        };
    }

    /// Set non-blocking mode
    pub fn setNonBlocking(self: *UnixListener, non_blocking: bool) !void {
        const flags = try posix.fcntl(self.sockfd, posix.F.GETFL, 0);
        const new_flags = if (non_blocking)
            flags | @as(u32, posix.O.NONBLOCK)
        else
            flags & ~@as(u32, posix.O.NONBLOCK);
        _ = try posix.fcntl(self.sockfd, posix.F.SETFL, new_flags);
    }

    /// Set socket permissions (non-abstract only)
    pub fn setPermissions(self: *UnixListener, mode: u32) !void {
        if (self.address.abstract) {
            return; // Abstract sockets don't have file permissions
        }

        const file = try std.fs.openFileAbsolute(self.address.path, .{});
        defer file.close();

        try file.chmod(mode);
    }
};

/// Unix domain socket stream
pub const UnixStream = struct {
    sockfd: posix.socket_t,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, address: UnixAddress) !UnixStream {
        if (!platform.Platform.current().isUnix()) {
            return UnixSocketError.NotSupportedOnThisPlatform;
        }

        try address.validate();

        // Create socket
        const sockfd = try posix.socket(
            posix.AF.UNIX,
            posix.SOCK.STREAM | posix.SOCK.CLOEXEC,
            0,
        );
        errdefer posix.close(sockfd);

        // Connect
        try connectUnixSocket(sockfd, address);

        return UnixStream{
            .sockfd = sockfd,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *UnixStream) void {
        posix.close(self.sockfd);
    }

    /// Read from socket
    pub fn read(self: *UnixStream, buffer: []u8) !usize {
        const n = try posix.read(self.sockfd, buffer);
        return n;
    }

    /// Write to socket
    pub fn write(self: *UnixStream, data: []const u8) !usize {
        const n = try posix.write(self.sockfd, data);
        return n;
    }

    /// Write all data
    pub fn writeAll(self: *UnixStream, data: []const u8) !void {
        var index: usize = 0;
        while (index < data.len) {
            const written = try self.write(data[index..]);
            if (written == 0) return error.BrokenPipe;
            index += written;
        }
    }

    /// Read until delimiter
    pub fn readUntilDelimiter(
        self: *UnixStream,
        buffer: []u8,
        delimiter: u8,
    ) ![]u8 {
        var index: usize = 0;
        while (index < buffer.len) {
            const n = try self.read(buffer[index .. index + 1]);
            if (n == 0) return error.EndOfStream;
            if (buffer[index] == delimiter) {
                return buffer[0..index];
            }
            index += 1;
        }
        return error.StreamTooLong;
    }

    /// Set non-blocking mode
    pub fn setNonBlocking(self: *UnixStream, non_blocking: bool) !void {
        const flags = try posix.fcntl(self.sockfd, posix.F.GETFL, 0);
        const new_flags = if (non_blocking)
            flags | @as(u32, posix.O.NONBLOCK)
        else
            flags & ~@as(u32, posix.O.NONBLOCK);
        _ = try posix.fcntl(self.sockfd, posix.F.SETFL, new_flags);
    }

    /// Shutdown socket
    pub fn shutdown(self: *UnixStream, how: std.posix.ShutdownHow) !void {
        try posix.shutdown(self.sockfd, how);
    }

    /// Get underlying file descriptor (for integration with event loops)
    pub fn getFd(self: *UnixStream) posix.socket_t {
        return self.sockfd;
    }
};

/// Unix datagram socket
pub const UnixDatagram = struct {
    sockfd: posix.socket_t,
    address: ?UnixAddress,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, address: ?UnixAddress) !UnixDatagram {
        if (!platform.Platform.current().isUnix()) {
            return UnixSocketError.NotSupportedOnThisPlatform;
        }

        if (address) |addr| {
            try addr.validate();
        }

        // Create socket
        const sockfd = try posix.socket(
            posix.AF.UNIX,
            posix.SOCK.DGRAM | posix.SOCK.CLOEXEC,
            0,
        );
        errdefer posix.close(sockfd);

        // Bind if address provided
        if (address) |addr| {
            // Remove existing socket file if it exists (non-abstract)
            if (!addr.abstract) {
                std.fs.deleteFileAbsolute(addr.path) catch |err| {
                    if (err != error.FileNotFound) {
                        posix.close(sockfd);
                        return err;
                    }
                };
            }

            try bindUnixSocket(sockfd, addr);
        }

        return UnixDatagram{
            .sockfd = sockfd,
            .address = address,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *UnixDatagram) void {
        posix.close(self.sockfd);

        // Clean up socket file (non-abstract)
        if (self.address) |addr| {
            if (!addr.abstract) {
                std.fs.deleteFileAbsolute(addr.path) catch {};
            }
        }
    }

    /// Send datagram to address
    pub fn sendTo(self: *UnixDatagram, data: []const u8, dest: UnixAddress) !usize {
        try dest.validate();

        var addr: posix.sockaddr.un = undefined;
        fillUnixAddr(&addr, dest);

        const n = try posix.sendto(
            self.sockfd,
            data,
            0,
            @ptrCast(&addr),
            @sizeOf(posix.sockaddr.un),
        );
        return n;
    }

    /// Receive datagram
    pub fn recvFrom(
        self: *UnixDatagram,
        buffer: []u8,
    ) !struct { data: []u8, from: UnixAddress } {
        var addr: posix.sockaddr.un = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.un);

        const n = try posix.recvfrom(
            self.sockfd,
            buffer,
            0,
            @ptrCast(&addr),
            &addr_len,
        );

        const from = try parseUnixAddr(&addr, self.allocator);
        return .{
            .data = buffer[0..n],
            .from = from,
        };
    }

    /// Connect to destination (for send/recv without address)
    pub fn connect(self: *UnixDatagram, dest: UnixAddress) !void {
        try connectUnixSocket(self.sockfd, dest);
    }

    /// Send data (requires prior connect)
    pub fn send(self: *UnixDatagram, data: []const u8) !usize {
        const n = try posix.send(self.sockfd, data, 0);
        return n;
    }

    /// Receive data (requires prior connect)
    pub fn recv(self: *UnixDatagram, buffer: []u8) !usize {
        const n = try posix.recv(self.sockfd, buffer, 0);
        return n;
    }
};

// Helper functions

fn bindUnixSocket(sockfd: posix.socket_t, address: UnixAddress) !void {
    var addr: posix.sockaddr.un = undefined;
    fillUnixAddr(&addr, address);

    try posix.bind(
        sockfd,
        @ptrCast(&addr),
        @sizeOf(posix.sockaddr.un),
    );
}

fn connectUnixSocket(sockfd: posix.socket_t, address: UnixAddress) !void {
    var addr: posix.sockaddr.un = undefined;
    fillUnixAddr(&addr, address);

    try posix.connect(
        sockfd,
        @ptrCast(&addr),
        @sizeOf(posix.sockaddr.un),
    );
}

fn fillUnixAddr(addr: *posix.sockaddr.un, address: UnixAddress) void {
    @memset(std.mem.asBytes(addr), 0);
    addr.family = posix.AF.UNIX;

    if (address.abstract) {
        // Abstract namespace (Linux): first byte is null, rest is name
        addr.path[0] = 0;
        @memcpy(addr.path[1 .. address.path.len + 1], address.path);
    } else {
        // Filesystem path
        @memcpy(addr.path[0..address.path.len], address.path);
        addr.path[address.path.len] = 0;
    }
}

fn parseUnixAddr(addr: *const posix.sockaddr.un, allocator: std.mem.Allocator) !UnixAddress {
    const path_len = std.mem.indexOfScalar(u8, &addr.path, 0) orelse addr.path.len;

    if (path_len > 0 and addr.path[0] == 0) {
        // Abstract namespace
        const name = try allocator.dupe(u8, addr.path[1..path_len]);
        return UnixAddress.initAbstract(name);
    } else {
        // Filesystem path
        const path = try allocator.dupe(u8, addr.path[0..path_len]);
        return UnixAddress.init(path);
    }
}

// Tests

test "unix address validation" {
    const testing = std.testing;

    const addr = UnixAddress.init("/tmp/test.sock");
    try addr.validate();

    // Test path too long
    var long_path: [200]u8 = undefined;
    @memset(&long_path, 'a');
    const long_addr = UnixAddress.init(&long_path);
    try testing.expectError(UnixSocketError.PathTooLong, long_addr.validate());
}

test "unix socket listener" {
    if (!platform.Platform.current().isUnix()) return error.SkipZigTest;

    const testing = std.testing;

    const socket_path = "/tmp/test_listener.sock";
    const addr = UnixAddress.init(socket_path);

    var listener = try UnixListener.init(testing.allocator, addr);
    defer listener.deinit();

    // Verify socket file exists
    const file = std.fs.openFileAbsolute(socket_path, .{}) catch |err| {
        try testing.expect(false); // Socket file should exist
        return err;
    };
    file.close();
}

test "unix socket stream" {
    if (!platform.Platform.current().isUnix()) return error.SkipZigTest;

    const testing = std.testing;

    const socket_path = "/tmp/test_stream.sock";
    const addr = UnixAddress.init(socket_path);

    // Start listener
    var listener = try UnixListener.init(testing.allocator, addr);
    defer listener.deinit();

    // Connect client in separate thread
    const Client = struct {
        fn run(address: UnixAddress, allocator: std.mem.Allocator) !void {
            std.time.sleep(100 * std.time.ns_per_ms); // Let listener start

            var stream = try UnixStream.init(allocator, address);
            defer stream.deinit();

            try stream.writeAll("Hello, Unix socket!");
        }
    };

    const thread = try std.Thread.spawn(.{}, Client.run, .{ addr, testing.allocator });
    defer thread.join();

    // Accept connection
    var stream = try listener.accept();
    defer stream.deinit();

    // Read message
    var buffer: [1024]u8 = undefined;
    const n = try stream.read(&buffer);
    try testing.expectEqualStrings("Hello, Unix socket!", buffer[0..n]);
}

test "unix socket datagram" {
    if (!platform.Platform.current().isUnix()) return error.SkipZigTest;

    const testing = std.testing;

    const server_path = "/tmp/test_dgram_server.sock";
    const client_path = "/tmp/test_dgram_client.sock";

    const server_addr = UnixAddress.init(server_path);
    const client_addr = UnixAddress.init(client_path);

    // Create server
    var server = try UnixDatagram.init(testing.allocator, server_addr);
    defer server.deinit();

    // Create client
    var client = try UnixDatagram.init(testing.allocator, client_addr);
    defer client.deinit();

    // Send from client to server
    const sent = try client.sendTo("Test datagram", server_addr);
    try testing.expectEqual(@as(usize, 13), sent);

    // Receive at server
    var buffer: [1024]u8 = undefined;
    const result = try server.recvFrom(&buffer);
    try testing.expectEqualStrings("Test datagram", result.data);
}

test "abstract unix socket" {
    if (platform.Platform.current() != .linux) return error.SkipZigTest;

    const testing = std.testing;

    // Abstract sockets are Linux-specific
    const addr = UnixAddress.initAbstract("test_abstract");

    var listener = try UnixListener.init(testing.allocator, addr);
    defer listener.deinit();

    // Connect client
    var stream = try UnixStream.init(testing.allocator, addr);
    defer stream.deinit();

    try stream.writeAll("Abstract socket test");
}

test "unix socket non-blocking" {
    if (!platform.Platform.current().isUnix()) return error.SkipZigTest;

    const testing = std.testing;

    const socket_path = "/tmp/test_nonblocking.sock";
    const addr = UnixAddress.init(socket_path);

    var listener = try UnixListener.init(testing.allocator, addr);
    defer listener.deinit();

    try listener.setNonBlocking(true);

    // Accept should fail with EAGAIN/EWOULDBLOCK since no connections
    const result = listener.accept();
    try testing.expectError(error.WouldBlock, result);
}

test "unix socket permissions" {
    if (!platform.Platform.current().isUnix()) return error.SkipZigTest;

    const testing = std.testing;

    const socket_path = "/tmp/test_perms.sock";
    const addr = UnixAddress.init(socket_path);

    var listener = try UnixListener.init(testing.allocator, addr);
    defer listener.deinit();

    // Set restrictive permissions (owner only)
    try listener.setPermissions(0o600);

    // Verify permissions
    const stat = try std.fs.cwd().statFile(socket_path);
    const mode = stat.mode & 0o777;
    try testing.expectEqual(@as(u32, 0o600), mode);
}
