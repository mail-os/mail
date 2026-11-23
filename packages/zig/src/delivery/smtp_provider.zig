//! Authenticated submission to an operator-approved SMTP provider.
const std = @import("std");
const builtin = @import("builtin");
const db_mod = @import("../storage/database.zig");
const io_compat = @import("../core/io_compat.zig");
const socket = @import("../core/socket_compat.zig");
const outbound = @import("outbound.zig");
const smtp_tls = @import("smtp_tls.zig");

pub const Config = struct {
    host: []const u8,
    port: u16 = 587,
    username: []const u8,
    password: []const u8,
    ca_file: ?[]const u8 = null,

    pub fn valid(self: Config) bool {
        return outbound.isSafeHostname(self.host) and self.host.len <= 253 and self.port != 0 and
            self.username.len > 0 and self.password.len > 0 and self.username.len + self.password.len <= 350 and
            std.mem.indexOfScalar(u8, self.username, 0) == null and std.mem.indexOfScalar(u8, self.password, 0) == null and
            (self.ca_file == null or std.fs.path.isAbsolute(self.ca_file.?));
    }
};

const RecipientJournal = struct {
    db: *db_mod.Database,
    delivery_id: []const u8,
};

/// Use one SMTP transaction so a provider receives the approved envelope in
/// full. A lost final acknowledgement leaves only accepted RCPTs uncertain.
/// The caller has already validated and admitted the envelope into the journal.
pub fn submit(a: std.mem.Allocator, cfg: Config, journal: RecipientJournal, hostname: []const u8, from: []const u8, recipients: []const []const u8, mime: []const u8) !void {
    if (!cfg.valid() or !outbound.isSafeHostname(hostname)) return error.ProviderUnavailable;
    const io = io_compat.getIo();
    const now = std.Io.Clock.real.now(io);
    var roots: std.crypto.Certificate.Bundle = .empty;
    defer roots.deinit(a);
    if (cfg.ca_file) |path|
        roots.addCertsFromFilePathAbsolute(a, io, now, path) catch return error.ProviderTlsUnavailable
    else
        roots.rescan(a, io, now) catch return error.ProviderTlsUnavailable;
    const conn = try connect(a, cfg);
    defer conn.close();
    var stream: smtp_tls.Stream = .{ .conn = conn };
    var reply_buffer: [8192]u8 = undefined;
    if ((try readReply(&stream, &reply_buffer)).code != 220) return error.ProviderUnavailable;
    const ehlo = try std.fmt.allocPrint(a, "EHLO {s}\r\n", .{hostname});
    defer a.free(ehlo);
    const plain_ehlo = try command(&stream, &reply_buffer, ehlo);
    if (plain_ehlo.code != 250 or !offered(plain_ehlo.lines, "STARTTLS", null)) return error.ProviderTlsUnavailable;
    if ((try command(&stream, &reply_buffer, "STARTTLS\r\n")).code != 220) return error.ProviderTlsUnavailable;
    stream = smtp_tls.verifiedHandshake(conn, cfg.host, roots) catch return error.ProviderTlsUnavailable;

    const secure_ehlo = try command(&stream, &reply_buffer, ehlo);
    if (secure_ehlo.code != 250 or !offered(secure_ehlo.lines, "AUTH", "PLAIN")) return error.ProviderAuthenticationFailed;
    try authenticate(a, &stream, &reply_buffer, cfg);

    var address_command: [352]u8 = undefined;
    const mail_from = try std.fmt.bufPrint(&address_command, "MAIL FROM:<{s}>\r\n", .{from});
    if ((try command(&stream, &reply_buffer, mail_from)).code != 250) return error.ProviderEnvelopeRejected;
    var accepted: std.ArrayList([]const u8) = .empty;
    defer accepted.deinit(a);
    for (recipients) |recipient| {
        const rcpt = try std.fmt.bufPrint(&address_command, "RCPT TO:<{s}>\r\n", .{recipient});
        switch ((try command(&stream, &reply_buffer, rcpt)).code) {
            250, 251, 252 => try accepted.append(a, recipient),
            400...599 => {},
            else => return error.ProviderUnavailable,
        }
    }
    if (accepted.items.len == 0) return error.ProviderEnvelopeRejected;
    if ((try command(&stream, &reply_buffer, "DATA\r\n")).code != 354) return error.ProviderMessageRejected;
    const raw = try outbound.normalizeForSmtp(a, mime);
    defer a.free(raw);
    stream.writeAll(raw) catch return error.ProviderUnavailable;
    if (!std.mem.endsWith(u8, raw, "\r\n")) stream.writeAll("\r\n") catch return error.ProviderUnavailable;

    // Before the DATA terminator, a closed connection cannot have committed a
    // well-formed message. After it, the provider's acknowledgement may be lost.
    try journal.db.checkpointInteractiveRecipients(journal.delivery_id, accepted.items, .starting);
    const final = command(&stream, &reply_buffer, ".\r\n") catch return error.ProviderDeliveryUnknown;
    switch (final.code) {
        250 => try journal.db.checkpointInteractiveRecipients(journal.delivery_id, accepted.items, .delivered),
        400...599 => {
            try journal.db.checkpointInteractiveRecipients(journal.delivery_id, accepted.items, .failed);
            return error.ProviderMessageRejected;
        },
        else => return error.ProviderDeliveryUnknown,
    }
    stream.writeAll("QUIT\r\n") catch {};
}

fn authenticate(a: std.mem.Allocator, stream: *smtp_tls.Stream, buffer: []u8, cfg: Config) !void {
    const token = try std.mem.concat(a, u8, &.{ "\x00", cfg.username, "\x00", cfg.password });
    defer {
        std.crypto.secureZero(u8, token);
        a.free(token);
    }
    const encoder = std.base64.standard.Encoder;
    var line: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &line);
    const prefix = "AUTH PLAIN ";
    @memcpy(line[0..prefix.len], prefix);
    const end = prefix.len + encoder.calcSize(token.len);
    _ = encoder.encode(line[prefix.len..end], token);
    @memcpy(line[end..][0..2], "\r\n");
    if ((try command(stream, buffer, line[0 .. end + 2])).code != 235) return error.ProviderAuthenticationFailed;
}

const Reply = struct { code: u16, lines: []const u8 };

fn command(stream: *smtp_tls.Stream, buffer: []u8, line: []const u8) !Reply {
    stream.writeAll(line) catch return error.ProviderUnavailable;
    return readReply(stream, buffer);
}

fn readReply(stream: *smtp_tls.Stream, buffer: []u8) !Reply {
    var used: usize = 0;
    var start: usize = 0;
    var expected: ?u16 = null;
    while (used < buffer.len) {
        const count = stream.read(buffer[used..]) catch return error.ProviderUnavailable;
        if (count == 0) return error.ProviderUnavailable;
        used += count;
        while (std.mem.indexOfPos(u8, buffer[0..used], start, "\r\n")) |end| {
            const line = buffer[start..end];
            if (line.len < 3 or line.len > 510) return error.ProviderUnavailable;
            const code = std.fmt.parseInt(u16, line[0..3], 10) catch return error.ProviderUnavailable;
            if (code < 200 or code > 599 or (expected != null and expected.? != code)) return error.ProviderUnavailable;
            expected = code;
            start = end + 2;
            if (line.len == 3 or line[3] == ' ') {
                if (start != used) return error.ProviderUnavailable;
                return .{ .code = code, .lines = buffer[0..used] };
            }
            if (line[3] != '-') return error.ProviderUnavailable;
        }
    }
    return error.ProviderUnavailable;
}

fn offered(lines: []const u8, extension: []const u8, parameter: ?[]const u8) bool {
    var each = std.mem.splitSequence(u8, lines, "\r\n");
    _ = each.next(); // EHLO starts with the server identification.
    while (each.next()) |line| {
        if (line.len <= 4) continue;
        var tokens = std.mem.tokenizeScalar(u8, line[4..], ' ');
        const keyword = tokens.next() orelse continue;
        if (!std.ascii.eqlIgnoreCase(keyword, extension)) continue;
        const required = parameter orelse return true;
        while (tokens.next()) |token| if (std.ascii.eqlIgnoreCase(required, token)) return true;
    }
    return false;
}

fn connect(a: std.mem.Allocator, cfg: Config) !socket.Connection {
    const host = try a.dupeSentinel(u8, cfg.host, 0);
    defer a.free(host);
    var port_buffer: [6]u8 = undefined;
    const port = try std.fmt.bufPrintSentinel(&port_buffer, "{d}", .{cfg.port}, 0);
    const hints = std.mem.zeroInit(std.c.addrinfo, .{ .socktype = std.posix.SOCK.STREAM });
    var addresses: ?*std.c.addrinfo = null;
    if (@backingInt(std.c.getaddrinfo(host.ptr, port.ptr, &hints, &addresses)) != 0) return error.ProviderUnavailable;
    const first = addresses orelse return error.ProviderUnavailable;
    defer std.c.freeaddrinfo(first);
    while (addresses) |address| : (addresses = address.next) {
        const fd = std.c.socket(@intCast(address.family), @intCast(address.socktype), @intCast(address.protocol));
        if (fd < 0) continue;
        if (configureSocket(fd) and std.c.connect(fd, address.addr.?, address.addrlen) == 0) return .{ .fd = fd };
        _ = std.c.close(fd);
    }
    return error.ProviderUnavailable;
}

fn configureSocket(fd: std.posix.socket_t) bool {
    if (std.c.fcntl(fd, std.c.F.SETFD, @as(c_int, std.c.FD_CLOEXEC)) < 0) return false;
    const timeout: std.posix.timeval = .{ .sec = 10, .usec = 0 };
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch return false;
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch return false;
    if (builtin.os.tag == .macos) {
        const enabled: c_int = 1;
        std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.NOSIGPIPE, std.mem.asBytes(&enabled)) catch return false;
    }
    return true;
}
