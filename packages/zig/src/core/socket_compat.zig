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
        const sock_type: c_uint = @intCast(@as(u32, posix.SOCK.STREAM | posix.SOCK.CLOEXEC));
        const raw_fd = std.c.socket(family, sock_type, 0);
        if (raw_fd < 0) return error.Unexpected;
        const fd: posix.socket_t = @intCast(raw_fd);
        errdefer _ = std.c.close(fd);

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
            const err = std.posix.errno(rc);
            return switch (err) {
                .AGAIN => error.WouldBlock,
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

        return .{ .fd = fd };
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

    pub fn read(self: Connection, buf: []u8) !usize {
        return posix.read(self.fd, buf);
    }

    pub fn write(self: Connection, data: []const u8) !usize {
        const result = std.c.write(self.fd, data.ptr, data.len);
        if (result < 0) return error.Unexpected;
        return @intCast(result);
    }

    pub fn close(self: Connection) void {
        _ = std.c.close(self.fd);
    }
};
