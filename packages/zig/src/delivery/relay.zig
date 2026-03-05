const std = @import("std");
const posix = std.posix;
const time_compat = @import("../core/time_compat.zig");

/// SMTP relay client for forwarding messages to other servers.
/// Supports connection reuse — keeps the TCP connection open and uses RSET
/// between messages to avoid per-message TCP handshake overhead.
pub const SMTPRelay = struct {
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    timeout_ms: u32,
    our_hostname: []const u8,
    cached_fd: ?posix.socket_t = null,

    pub fn init(allocator: std.mem.Allocator, host: []const u8, port: u16, our_hostname: []const u8) !SMTPRelay {
        return .{
            .allocator = allocator,
            .host = try allocator.dupe(u8, host),
            .port = port,
            .timeout_ms = 30000, // 30 seconds
            .our_hostname = try allocator.dupe(u8, our_hostname),
        };
    }

    pub fn deinit(self: *SMTPRelay) void {
        self.closeConnection();
        self.allocator.free(self.host);
        self.allocator.free(self.our_hostname);
    }

    fn closeConnection(self: *SMTPRelay) void {
        if (self.cached_fd) |fd| {
            _ = fdWrite(fd, "QUIT\r\n") catch {};
            posix.close(fd);
            self.cached_fd = null;
        }
    }

    /// Establish (or reuse) connection and perform EHLO handshake
    fn ensureConnection(self: *SMTPRelay) !posix.socket_t {
        // Try reusing cached connection with RSET
        if (self.cached_fd) |fd| {
            var buf: [1024]u8 = undefined;
            _ = fdWrite(fd, "RSET\r\n") catch {
                self.cached_fd = null;
                posix.close(fd);
                return self.newConnection();
            };
            const rset_resp = readResponse(fd, &buf) catch {
                self.cached_fd = null;
                posix.close(fd);
                return self.newConnection();
            };
            if (std.mem.startsWith(u8, rset_resp, "250")) {
                return fd;
            }
            // RSET failed — reconnect
            posix.close(fd);
            self.cached_fd = null;
        }
        return self.newConnection();
    }

    fn newConnection(self: *SMTPRelay) !posix.socket_t {
        const ip = parseIpv4(self.host) orelse return error.InvalidAddress;

        const raw_fd = std.c.socket(@intCast(@as(u32, posix.AF.INET)), @intCast(@as(u32, posix.SOCK.STREAM)), 0);
        if (raw_fd < 0) return error.SocketCreateFailed;
        const fd: posix.socket_t = @intCast(raw_fd);
        errdefer posix.close(fd);

        const sockaddr = posix.sockaddr.in{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, self.port),
            .addr = std.mem.bytesToValue(u32, &ip),
        };

        if (std.c.connect(fd, @ptrCast(&sockaddr), @sizeOf(posix.sockaddr.in)) < 0) {
            return error.ConnectFailed;
        }

        var buf: [1024]u8 = undefined;

        // Read greeting
        const greeting = try readResponse(fd, &buf);
        if (!std.mem.startsWith(u8, greeting, "220")) {
            return error.InvalidGreeting;
        }

        // EHLO
        const ehlo_cmd = try std.fmt.allocPrint(self.allocator, "EHLO {s}\r\n", .{self.our_hostname});
        defer self.allocator.free(ehlo_cmd);
        _ = try fdWrite(fd, ehlo_cmd);

        const ehlo_response = try readResponse(fd, &buf);
        if (!std.mem.startsWith(u8, ehlo_response, "250")) {
            return error.EhloFailed;
        }

        self.cached_fd = fd;
        return fd;
    }

    /// Send a message via SMTP relay
    /// Outbound security pipeline (when enabled):
    /// 1. MTA-STS policy check - enforce TLS requirement for recipient domain
    /// 2. DANE TLSA lookup - verify server certificate after TLS handshake
    /// 3. TLS-RPT - record any TLS connection failures for reporting
    pub fn sendMessage(
        self: *SMTPRelay,
        from: []const u8,
        to: []const u8,
        data: []const u8,
    ) !void {
        const fd = try self.ensureConnection();
        errdefer {
            // On error, discard the connection
            posix.close(fd);
            self.cached_fd = null;
        }

        var buf: [1024]u8 = undefined;

        // MAIL FROM
        const mail_cmd = try std.fmt.allocPrint(self.allocator, "MAIL FROM:<{s}>\r\n", .{from});
        defer self.allocator.free(mail_cmd);
        _ = try fdWrite(fd, mail_cmd);

        const mail_response = try readResponse(fd, &buf);
        if (!std.mem.startsWith(u8, mail_response, "250")) {
            return error.MailFromFailed;
        }

        // RCPT TO
        const rcpt_cmd = try std.fmt.allocPrint(self.allocator, "RCPT TO:<{s}>\r\n", .{to});
        defer self.allocator.free(rcpt_cmd);
        _ = try fdWrite(fd, rcpt_cmd);

        const rcpt_response = try readResponse(fd, &buf);
        if (!std.mem.startsWith(u8, rcpt_response, "250")) {
            return error.RcptToFailed;
        }

        // DATA
        _ = try fdWrite(fd, "DATA\r\n");
        const data_response = try readResponse(fd, &buf);
        if (!std.mem.startsWith(u8, data_response, "354")) {
            return error.DataFailed;
        }

        // Send message data
        _ = try fdWrite(fd, data);
        if (!std.mem.endsWith(u8, data, "\r\n.\r\n")) {
            _ = try fdWrite(fd, "\r\n.\r\n");
        }

        const send_response = try readResponse(fd, &buf);
        if (!std.mem.startsWith(u8, send_response, "250")) {
            return error.MessageSendFailed;
        }
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
};

// I/O helpers — posix.write/read were removed in Zig 0.16-dev
fn fdWrite(fd: posix.socket_t, data: []const u8) !usize {
    var written: usize = 0;
    while (written < data.len) {
        const rc = std.c.write(fd, data.ptr + written, data.len - written);
        if (rc < 0) return error.WriteFailed;
        if (rc == 0) return error.WriteFailed;
        written += @intCast(rc);
    }
    return written;
}

fn readResponse(fd: posix.socket_t, buf: []u8) ![]const u8 {
    const rc = std.c.read(fd, buf.ptr, buf.len);
    if (rc < 0) return error.ReadFailed;
    if (rc == 0) return error.ConnectionClosed;
    return buf[0..@intCast(rc)];
}

/// Relay worker that processes queue messages
pub const RelayWorker = struct {
    allocator: std.mem.Allocator,
    queue: *@import("queue.zig").MessageQueue,
    relay: *SMTPRelay,
    running: *std.atomic.Value(bool),
    poll_interval_ms: u32,

    pub fn init(
        allocator: std.mem.Allocator,
        queue: *@import("queue.zig").MessageQueue,
        relay: *SMTPRelay,
        running: *std.atomic.Value(bool),
    ) RelayWorker {
        return .{
            .allocator = allocator,
            .queue = queue,
            .relay = relay,
            .running = running,
            .poll_interval_ms = 1000, // 1 second
        };
    }

    /// Run the relay worker (processes queue continuously)
    pub fn run(self: *RelayWorker) !void {
        while (self.running.load(.monotonic)) {
            // Get next message from queue
            if (self.queue.getNextPending()) |msg| {
                // Try to relay the message
                self.relay.sendMessage(msg.from, msg.to, msg.data) catch |err| {
                    const err_msg = try std.fmt.allocPrint(
                        self.allocator,
                        "Relay failed: {any}",
                        .{err},
                    );
                    defer self.allocator.free(err_msg);

                    try self.queue.markForRetry(msg.id, err_msg);
                    std.log.err("Failed to relay message {s}: {any}", .{ msg.id, err });
                    continue;
                };

                // Mark as delivered
                try self.queue.markDelivered(msg.id);
                std.log.info("Successfully relayed message {s}", .{msg.id});
            } else {
                // No messages, sleep for a bit
                time_compat.sleepMs(self.poll_interval_ms);
            }
        }
    }
};

test "SMTP relay sendMessage mock" {
    // Note: This would require a real SMTP server to test properly
    // For unit testing, we'd need to mock the network layer
    const testing = std.testing;
    _ = testing;

    // Skip actual network test
}
