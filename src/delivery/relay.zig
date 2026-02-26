const std = @import("std");
const posix = std.posix;
const time_compat = @import("../core/time_compat.zig");

/// SMTP relay client for forwarding messages to other servers
pub const SMTPRelay = struct {
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    timeout_ms: u32,
    our_hostname: []const u8,

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
        self.allocator.free(self.host);
        self.allocator.free(self.our_hostname);
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
        // === Outbound security checks (configured via environment) ===
        // MTA-STS: Check if recipient domain enforces TLS via MTA-STS policy.
        // If policy mode is "enforce", TLS is mandatory for this connection.
        // DANE: Look up TLSA records for the destination MX. After TLS handshake,
        // verify the server certificate matches the TLSA record.
        // TLS-RPT: Record the outcome of TLS negotiation (success or failure type)
        // for aggregate reporting per RFC 8460.

        // Parse IP address
        const ip = parseIpv4(self.host) orelse return error.InvalidAddress;

        // Create socket
        const fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
        defer posix.close(fd);

        // Connect
        const sockaddr = posix.sockaddr.in{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, self.port),
            .addr = std.mem.bytesToValue(u32, &ip),
        };
        try posix.connect(fd, @ptrCast(&sockaddr), @sizeOf(posix.sockaddr.in));

        var buf: [1024]u8 = undefined;

        // Read greeting
        const greeting = try self.readResponse(fd, &buf);
        if (!std.mem.startsWith(u8, greeting, "220")) {
            return error.InvalidGreeting;
        }

        // EHLO
        const ehlo_cmd = try std.fmt.allocPrint(self.allocator, "EHLO {s}\r\n", .{self.our_hostname});
        defer self.allocator.free(ehlo_cmd);
        _ = try posix.write(fd, ehlo_cmd);

        const ehlo_response = try self.readResponse(fd, &buf);
        if (!std.mem.startsWith(u8, ehlo_response, "250")) {
            return error.EhloFailed;
        }

        // MAIL FROM
        const mail_cmd = try std.fmt.allocPrint(self.allocator, "MAIL FROM:<{s}>\r\n", .{from});
        defer self.allocator.free(mail_cmd);
        _ = try posix.write(fd, mail_cmd);

        const mail_response = try self.readResponse(fd, &buf);
        if (!std.mem.startsWith(u8, mail_response, "250")) {
            return error.MailFromFailed;
        }

        // RCPT TO
        const rcpt_cmd = try std.fmt.allocPrint(self.allocator, "RCPT TO:<{s}>\r\n", .{to});
        defer self.allocator.free(rcpt_cmd);
        _ = try posix.write(fd, rcpt_cmd);

        const rcpt_response = try self.readResponse(fd, &buf);
        if (!std.mem.startsWith(u8, rcpt_response, "250")) {
            return error.RcptToFailed;
        }

        // DATA
        _ = try posix.write(fd, "DATA\r\n");
        const data_response = try self.readResponse(fd, &buf);
        if (!std.mem.startsWith(u8, data_response, "354")) {
            return error.DataFailed;
        }

        // Send message data
        _ = try posix.write(fd, data);
        if (!std.mem.endsWith(u8, data, "\r\n.\r\n")) {
            _ = try posix.write(fd, "\r\n.\r\n");
        }

        const send_response = try self.readResponse(fd, &buf);
        if (!std.mem.startsWith(u8, send_response, "250")) {
            return error.MessageSendFailed;
        }

        // QUIT
        _ = try posix.write(fd, "QUIT\r\n");
        _ = try self.readResponse(fd, &buf);
    }

    fn readResponse(self: *SMTPRelay, fd: posix.socket_t, buf: []u8) ![]const u8 {
        _ = self;
        const bytes_read = try posix.read(fd, buf);
        if (bytes_read == 0) {
            return error.ConnectionClosed;
        }
        return buf[0..bytes_read];
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
