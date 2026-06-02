// Socket compatibility layer for Zig 0.16
// Provides synchronous socket operations using posix APIs
const std = @import("std");
const posix = std.posix;

pub const AddressFamily = enum { ipv4, ipv6 };

pub const Address = struct {
    family: AddressFamily,
    port: u16,
    addr: union {
        ipv4: [4]u8,
        ipv6: [16]u8,
    },

    pub fn parseIp(host: []const u8, port: u16) !Address {
        // Try IPv4 first
        if (parseIpv4(host)) |ipv4| {
            return .{
                .family = .ipv4,
                .port = port,
                .addr = .{ .ipv4 = ipv4 },
            };
        }
        // Try IPv6
        if (parseIpv6(host)) |ipv6| {
            return .{
                .family = .ipv6,
                .port = port,
                .addr = .{ .ipv6 = ipv6 },
            };
        }
        return error.InvalidAddress;
    }

    fn parseIpv4(s: []const u8) ?[4]u8 {
        var result: [4]u8 = undefined;
        var idx: usize = 0;
        var octet: u8 = 0;
        var digits: u8 = 0;

        for (s) |c| {
            if (c == '.') {
                if (digits == 0 or idx >= 3) return null;
                result[idx] = octet;
                idx += 1;
                octet = 0;
                digits = 0;
            } else if (c >= '0' and c <= '9') {
                const new_octet = @as(u16, octet) * 10 + (c - '0');
                if (new_octet > 255) return null;
                octet = @intCast(new_octet);
                digits += 1;
                if (digits > 3) return null;
            } else {
                return null;
            }
        }
        if (digits == 0 or idx != 3) return null;
        result[3] = octet;
        return result;
    }

    fn parseIpv6(_: []const u8) ?[16]u8 {
        // Simplified - just return null for now
        return null;
    }

    pub fn toSockaddrIn(self: Address) posix.sockaddr.in {
        return .{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, self.port),
            .addr = std.mem.bytesToValue(u32, &self.addr.ipv4),
        };
    }

    pub fn toSockaddrIn6(self: Address) posix.sockaddr.in6 {
        return .{
            .family = posix.AF.INET6,
            .port = std.mem.nativeToBig(u16, self.port),
            .addr = self.addr.ipv6,
            .flowinfo = 0,
            .scope_id = 0,
        };
    }

    pub fn getPosixFamily(self: Address) u32 {
        return if (self.family == .ipv4) posix.AF.INET else posix.AF.INET6;
    }
};

pub const Server = struct {
    fd: posix.socket_t,
    address: Address,

    pub fn listen(address: Address, options: ListenOptions) !Server {
        const family: c_uint = @intCast(address.getPosixFamily());
        // SOCK_CLOEXEC in the socket() type argument is a Linux extension; macOS
        // (and other BSDs) reject it with EINVAL, so set close-on-exec via fcntl
        // after creation instead. On Linux both paths yield the same result.
        const sock_type: c_uint = @intCast(@as(u32, posix.SOCK.STREAM));
        const raw_fd = std.c.socket(family, sock_type, 0);
        if (raw_fd < 0) return error.Unexpected;
        const fd: posix.socket_t = @intCast(raw_fd);
        errdefer _ = std.c.close(fd);

        // Best-effort close-on-exec so child processes don't inherit the socket.
        // Failures are non-fatal but worth a diagnostic — a leaked listen socket
        // could otherwise be inherited by a spawned process.
        const fd_flags = std.c.fcntl(fd, std.c.F.GETFD, @as(c_int, 0));
        if (fd_flags >= 0) {
            if (std.c.fcntl(fd, std.c.F.SETFD, fd_flags | std.c.FD_CLOEXEC) < 0) {
                std.log.warn("Failed to set FD_CLOEXEC on listen socket (port {d}): errno={d}", .{ address.port, std.c._errno().* });
            }
        } else {
            std.log.warn("Failed to read socket flags for FD_CLOEXEC (port {d}): errno={d}", .{ address.port, std.c._errno().* });
        }

        if (options.reuse_address) {
            const one: c_int = 1;
            try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one));
            // Also set SO_REUSEPORT to allow binding even when port is in TIME_WAIT
            posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEPORT, std.mem.asBytes(&one)) catch {};
        }

        if (address.family == .ipv4) {
            const sockaddr = address.toSockaddrIn();
            if (std.c.bind(fd, @ptrCast(&sockaddr), @sizeOf(@TypeOf(sockaddr))) < 0) {
                const e: posix.E = @enumFromInt(std.c._errno().*);
                std.log.err("bind() failed on port {d}: errno={d}", .{ address.port, @intFromEnum(e) });
                return switch (e) {
                    .ADDRINUSE => error.AddressInUse,
                    .ADDRNOTAVAIL => error.AddressNotAvailable,
                    .ACCES => error.PermissionDenied,
                    else => error.Unexpected,
                };
            }
        } else {
            const sockaddr = address.toSockaddrIn6();
            if (std.c.bind(fd, @ptrCast(&sockaddr), @sizeOf(@TypeOf(sockaddr))) < 0) {
                const e: posix.E = @enumFromInt(std.c._errno().*);
                std.log.err("bind() failed on port {d}: errno={d}", .{ address.port, @intFromEnum(e) });
                return switch (e) {
                    .ADDRINUSE => error.AddressInUse,
                    .ADDRNOTAVAIL => error.AddressNotAvailable,
                    .ACCES => error.PermissionDenied,
                    else => error.Unexpected,
                };
            }
        }
        if (std.c.listen(fd, options.kernel_backlog) < 0) return error.Unexpected;

        return .{ .fd = fd, .address = address };
    }

    pub const AcceptError = error{
        ConnectionAborted,
        ProcessFdQuotaExceeded,
        SystemFdQuotaExceeded,
        SystemResources,
        Unexpected,
        WouldBlock,
        OperationCancelled,
    };

    pub fn accept(self: *Server) AcceptError!Connection {
        var client_addr: posix.sockaddr = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        // Use raw syscall to avoid Zig 0.16 error type mismatch
        const rc = std.c.accept(self.fd, &client_addr, &addr_len);
        if (rc < 0) {
            const err: posix.E = @enumFromInt(std.c._errno().*);
            return switch (err) {
                .AGAIN => error.WouldBlock,
                .INTR => error.OperationCancelled,
                .CONNABORTED => error.ConnectionAborted,
                .MFILE => error.ProcessFdQuotaExceeded,
                .NFILE => error.SystemFdQuotaExceeded,
                .NOBUFS, .NOMEM => error.SystemResources,
                else => error.Unexpected,
            };
        }
        const fd: posix.socket_t = @intCast(rc);

        // Set TCP_NODELAY to disable Nagle's algorithm for TLS handshake
        // This ensures all TLS records are sent immediately without coalescing
        const one: c_int = 1;
        // TCP_NODELAY = 1 on Linux, macOS, and most POSIX systems
        const TCP_NODELAY: u32 = 1;
        _ = posix.setsockopt(fd, posix.IPPROTO.TCP, TCP_NODELAY, std.mem.asBytes(&one)) catch {};

        var conn = Connection{ .fd = fd };
        // Record the peer IP as text (for SPF/DNSBL/logging). Best-effort and
        // defensive: any unexpected family just leaves peer_ip_len = 0.
        if (client_addr.family == posix.AF.INET) {
            const sin: *align(1) const posix.sockaddr.in = @ptrCast(&client_addr);
            const a: [4]u8 = @bitCast(sin.addr);
            const s = std.fmt.bufPrint(&conn.peer_ip_buf, "{d}.{d}.{d}.{d}", .{ a[0], a[1], a[2], a[3] }) catch "";
            conn.peer_ip_len = s.len;
        } else if (client_addr.family == posix.AF.INET6) {
            const sin6: *align(1) const posix.sockaddr.in6 = @ptrCast(&client_addr);
            const g = sin6.addr;
            const s = std.fmt.bufPrint(&conn.peer_ip_buf, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{ g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7], g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15] }) catch "";
            conn.peer_ip_len = s.len;
        }
        return conn;
    }

    pub fn setNonBlocking(self: *Server, enabled: bool) !void {
        const flags = std.c.fcntl(self.fd, std.c.F.GETFL, @as(c_int, 0));
        if (flags < 0) return error.Unexpected;
        const nonblock_flag: c_int = @intCast(@as(u32, @bitCast(std.c.O{ .NONBLOCK = true })));
        const new_flags = if (enabled)
            flags | nonblock_flag
        else
            flags & ~nonblock_flag;
        if (std.c.fcntl(self.fd, std.c.F.SETFL, new_flags) < 0) return error.Unexpected;
    }

    pub fn close(self: *Server) void {
        _ = std.c.close(self.fd);
    }
};

pub const ListenOptions = struct {
    reuse_address: bool = false,
    kernel_backlog: u31 = 128,
};

pub const Connection = struct {
    fd: posix.socket_t,
    /// Peer IP address as text, filled by Server.accept. Empty if unknown.
    peer_ip_buf: [46]u8 = undefined,
    peer_ip_len: usize = 0,

    /// The peer's IP address as text ("" if it could not be determined).
    pub fn peerIp(self: *const Connection) []const u8 {
        return self.peer_ip_buf[0..self.peer_ip_len];
    }

    pub fn read(self: Connection, buf: []u8) !usize {
        return posix.read(self.fd, buf);
    }

    pub fn write(self: Connection, data: []const u8) !usize {
        const result = std.c.write(self.fd, data.ptr, data.len);
        if (result < 0) return error.Unexpected;
        return @intCast(result);
    }

    /// Force this connection into blocking mode. A connection accepted from a
    /// non-blocking listener can inherit O_NONBLOCK on some platforms, which
    /// makes a straightforward read() return WouldBlock; callers that want to
    /// block (e.g. a TLS handshake loop) call this once after accept.
    pub fn setBlocking(self: Connection) void {
        const flags = std.c.fcntl(self.fd, std.c.F.GETFL, @as(c_int, 0));
        if (flags < 0) return;
        const nonblock_flag: c_int = @intCast(@as(u32, @bitCast(std.c.O{ .NONBLOCK = true })));
        _ = std.c.fcntl(self.fd, std.c.F.SETFL, flags & ~nonblock_flag);
    }

    pub fn close(self: Connection) void {
        _ = std.c.close(self.fd);
    }
};
