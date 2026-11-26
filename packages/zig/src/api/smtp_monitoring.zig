//! Optional process-local monitoring for the SMTP listener. No mailbox data.
const std = @import("std");
const io_compat = @import("../core/io_compat.zig");
const socket = @import("../core/socket_compat.zig");
const smtp = @import("../core/smtp.zig");

pub const Listener = struct {
    socket: socket.Server,
    stopped: std.atomic.Value(bool) = .init(false),

    pub fn bind(host: []const u8, port: u16) !Listener {
        var listener = try socket.Server.listen(try socket.Address.parseIp(host, port), .{ .reuse_address = true, .reuse_port = false });
        errdefer listener.close();
        try listener.setNonBlocking(true);
        return .{ .socket = listener };
    }

    pub fn deinit(self: *Listener) void {
        self.socket.close();
    }

    pub fn run(self: *Listener, server: *const smtp.Server, shutdown: *const std.atomic.Value(bool)) void {
        while (!self.stopped.load(.acquire)) {
            self.socket.waitReadable(250);
            const client = self.socket.accept() catch continue;
            defer client.close();
            serve(client, server, shutdown) catch {};
        }
    }
};

fn readHead(client: socket.Connection, buffer: []u8) !std.http.Server.Request.Head {
    const io = io_compat.getIo();
    const deadline = std.Io.Clock.awake.now(io).toMilliseconds() + 2000;
    var used: usize = 0;
    while (used < buffer.len) {
        const left = deadline - std.Io.Clock.awake.now(io).toMilliseconds();
        if (left <= 0) return error.Timeout;
        var fds = [1]std.c.pollfd{.{ .fd = client.fd, .events = std.c.POLL.IN, .revents = 0 }};
        if (std.c.poll(&fds, 1, @intCast(left)) <= 0) return error.Timeout;
        const count = try client.read(buffer[used..]);
        if (count == 0) return error.EndOfStream;
        used += count;
        if (std.mem.indexOf(u8, buffer[0..used], "\r\n\r\n")) |end|
            return std.http.Server.Request.Head.parse(buffer[0 .. end + 4]);
    }
    return error.HttpHeadersOversize;
}

fn serve(client: socket.Connection, server: *const smtp.Server, shutdown: *const std.atomic.Value(bool)) !void {
    var request_buffer: [4096]u8 = undefined;
    const head = try readHead(client, &request_buffer);
    if (head.method != .GET) return respond(client, .method_not_allowed, "text/plain", "Method not allowed\n");

    const ready = server.ready.load(.acquire) and !shutdown.load(.acquire);
    if (std.mem.eql(u8, head.target, "/healthz")) {
        return respond(client, if (ready) .ok else .service_unavailable, "text/plain", if (ready) "ready\n" else "unavailable\n");
    }
    if (!std.mem.eql(u8, head.target, "/metrics")) return respond(client, .not_found, "text/plain", "Not found\n");

    var body_buffer: [768]u8 = undefined;
    const body = try std.fmt.bufPrint(&body_buffer,
        \\# HELP mail_smtp_ready Whether the SMTP listener is ready to accept work.
        \\# TYPE mail_smtp_ready gauge
        \\mail_smtp_ready {d}
        \\# HELP mail_smtp_connections_active SMTP connections currently occupying a session slot.
        \\# TYPE mail_smtp_connections_active gauge
        \\mail_smtp_connections_active {d}
        \\# HELP mail_smtp_connections_admitted_total SMTP connections admitted since process start.
        \\# TYPE mail_smtp_connections_admitted_total counter
        \\mail_smtp_connections_admitted_total {d}
        \\
    , .{ @intFromBool(ready), server.active_connections.load(.monotonic), server.connections_admitted.load(.monotonic) });
    try respond(client, .ok, "text/plain; version=0.0.4; charset=utf-8", body);
}

fn respond(client: socket.Connection, status: std.http.Status, content_type: []const u8, body: []const u8) !void {
    const timeout: std.c.timeval = .{ .sec = 2, .usec = 0 };
    try std.posix.setsockopt(client.fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&timeout));
    var buffer: [1024]u8 = undefined;
    const allow = if (status == .method_not_allowed) "Allow: GET\r\n" else "";
    const response = try std.fmt.bufPrint(&buffer, "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\n{s}Connection: close\r\n\r\n{s}", .{
        @backingInt(status), status.phrase() orelse "", content_type, body.len, allow, body,
    });
    var offset: usize = 0;
    while (offset < response.len) {
        const sent = try client.write(response[offset..]);
        if (sent == 0) return error.EndOfStream;
        offset += sent;
    }
}
