//! Client for the clamd scanning protocol, spoken by ClamAV's clamd and by zavd.
//!
//! A message is streamed with `zINSTREAM`: length-prefixed chunks ended by a
//! zero-length chunk, then one NUL-terminated reply. The client connects over a
//! Unix socket (the usual deployment: the daemon runs on the same host) or TCP.
//!
//! Every exchange runs under a deadline, so a daemon that accepts and then stalls
//! costs a bounded wait instead of a stuck SMTP session. Whatever goes wrong comes
//! back as a `Verdict` rather than an error, because "the scanner could not answer"
//! is a result the caller has to act on, and how it acts is the fail mode:
//!
//!   * `open` delivers the message unscanned and logs that it did. This is the
//!     behaviour the client always had, and stays the default.
//!   * `closed` answers with a temporary failure, so the sender's queue retries
//!     later instead of the mail being delivered unscanned or lost.
//!
//! `disposition` turns a verdict into deliver, reject, or tempfail under the
//! configured mode.

const std = @import("std");
const posix = std.posix;
const mutex_compat = @import("../core/mutex_compat.zig");

const log = std.log.scoped(.clamav);

/// Where zavd listens by default. clamd installs use their own path (often
/// `/run/clamav/clamd.ctl`), which goes in `Config.transport`.
pub const default_socket_path = "/run/zavd/zavd.sock";
pub const default_port: u16 = 3310;

/// The largest message streamed by default. Keep it no larger than the daemon's
/// `StreamMaxLength`: a message between the two limits is refused by the daemon
/// mid-stream, which still maps to `too_large`, but only after the upload.
pub const default_max_stream_bytes: usize = 25 * 1024 * 1024;

/// The longest reply read from the daemon. Replies are one line ("stream: OK",
/// "stream: <signature> FOUND", "... ERROR"), so this only bounds a misbehaving peer.
const max_reply_bytes = 1024;

pub const Transport = union(enum) {
    /// Path of a Unix domain socket.
    unix: []const u8,
    /// An IPv4 or IPv6 literal and a port. Host names are not resolved here, so a
    /// scan never waits on DNS.
    tcp: struct { host: []const u8, port: u16 = default_port },

    /// Parse a transport from a configuration value: `unix:/path`, an absolute
    /// path, `tcp:host:port`, or `host:port` (IPv6 hosts in brackets, `[::1]:3310`).
    /// The returned slices borrow from `text`.
    pub fn parse(text: []const u8) error{InvalidTransport}!Transport {
        if (std.mem.startsWith(u8, text, "unix:")) return unixPath(text["unix:".len..]);
        if (text.len != 0 and text[0] == '/') return unixPath(text);
        const rest = if (std.mem.startsWith(u8, text, "tcp:")) text["tcp:".len..] else text;
        const colon = std.mem.lastIndexOfScalar(u8, rest, ':') orelse return error.InvalidTransport;
        var host = rest[0..colon];
        if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') host = host[1 .. host.len - 1];
        const port = std.fmt.parseInt(u16, rest[colon + 1 ..], 10) catch return error.InvalidTransport;
        if (host.len == 0 or port == 0) return error.InvalidTransport;
        return .{ .tcp = .{ .host = host, .port = port } };
    }

    fn unixPath(path: []const u8) error{InvalidTransport}!Transport {
        if (path.len == 0) return error.InvalidTransport;
        return .{ .unix = path };
    }
};

/// What to do with a message the scanner did not answer for.
pub const FailMode = enum {
    /// Deliver it unscanned, and log that it was.
    open,
    /// Refuse it with a temporary failure so the sender retries.
    closed,

    pub fn parse(text: []const u8) ?FailMode {
        if (std.ascii.eqlIgnoreCase(text, "open")) return .open;
        if (std.ascii.eqlIgnoreCase(text, "closed")) return .closed;
        return null;
    }
};

pub const Config = struct {
    transport: Transport = .{ .unix = default_socket_path },
    /// How long to wait for the connection to be accepted.
    connect_timeout_ms: u32 = 2_000,
    /// How long the whole exchange may take once connected: streaming the message
    /// and waiting for the verdict.
    timeout_ms: u32 = 30_000,
    /// Messages larger than this are not streamed; they are `too_large`.
    max_stream_bytes: usize = default_max_stream_bytes,
    /// Size of each INSTREAM chunk.
    chunk_bytes: u32 = 64 * 1024,
    fail_mode: FailMode = .open,
};

pub const ConfigError = error{
    InvalidSocketPath,
    InvalidAddress,
    InvalidTimeout,
    InvalidSizeLimit,
};

/// Why the scanner could not answer.
pub const Failure = enum {
    /// Nothing accepted the connection: the daemon is down or the path is wrong.
    connect_failed,
    /// The connection or the exchange outlived its timeout.
    timeout,
    /// The connection broke before a reply arrived.
    connection_lost,
    /// The daemon replied with an error of its own (out of memory, database
    /// not loaded, ...).
    scanner_error,
    /// The reply was not one the protocol defines.
    protocol_error,
};

pub const Verdict = union(enum) {
    clean,
    /// The signature name, owned by the scanner's allocator (see `deinit`).
    infected: []const u8,
    /// Larger than `max_stream_bytes`, or than the daemon's `StreamMaxLength`.
    /// The message was not scanned, and retrying will not change that.
    too_large,
    /// The scanner could not answer.
    unavailable: Failure,
    /// Scanning is switched off. Nothing was scanned, which is not the same as
    /// clean, so callers can say so in a header.
    skipped,

    pub fn deinit(self: Verdict, allocator: std.mem.Allocator) void {
        switch (self) {
            .infected => |name| allocator.free(name),
            else => {},
        }
    }
};

pub const Disposition = enum {
    deliver,
    /// A permanent refusal (5xx).
    reject,
    /// A temporary refusal (4xx): the sender keeps the message and retries.
    tempfail,
};

pub const IntakeError = error{ MalwareDetected, MalwareScanUnavailable, MalwareScanTooLarge };

/// Check client data before handing it to storage or submission. The SMTP
/// path uses the same verdict and policy directly to stamp its trace header.
pub fn requireAllowed(scanner: ?*ClamAVScanner, payload: []const u8) IntakeError!void {
    const active = scanner orelse return;
    const verdict = active.scanMessage(payload) catch return error.MalwareScanUnavailable;
    defer verdict.deinit(active.allocator);
    return switch (active.disposition(verdict)) {
        .deliver => {},
        .tempfail => error.MalwareScanUnavailable,
        .reject => switch (verdict) {
            .infected => |name| blk: {
                var buffer: [255]u8 = undefined;
                log.warn("intake rejected by malware scanner: {s}", .{safeSignature(name, &buffer)});
                break :blk error.MalwareDetected;
            },
            .too_large => error.MalwareScanTooLarge,
            else => unreachable,
        },
    };
}

pub fn safeSignature(name: []const u8, buffer: []u8) []const u8 {
    const signature = buffer[0..@min(name.len, buffer.len)];
    for (signature, name[0..signature.len]) |*dest, byte| {
        dest.* = if (std.ascii.isPrint(byte)) byte else '?';
    }
    return signature;
}

pub const ScanStats = struct {
    total_scans: usize = 0,
    clean_messages: usize = 0,
    infected_messages: usize = 0,
    too_large: usize = 0,
    /// Scans the scanner could not answer, timeouts included.
    errors: usize = 0,
    timeouts: usize = 0,
};

pub const ClamAVScanner = struct {
    allocator: std.mem.Allocator,
    config: Config,
    enabled: bool = true,
    stats: ScanStats = .{},
    mutex: mutex_compat.Mutex = .{},

    /// Validate `config` and copy the strings it borrows.
    pub fn init(allocator: std.mem.Allocator, config: Config) (ConfigError || std.mem.Allocator.Error)!ClamAVScanner {
        try validate(config);
        var owned = config;
        switch (config.transport) {
            .unix => |path| owned.transport = .{ .unix = try allocator.dupe(u8, path) },
            .tcp => |tcp| owned.transport = .{ .tcp = .{ .host = try allocator.dupe(u8, tcp.host), .port = tcp.port } },
        }
        return .{ .allocator = allocator, .config = owned };
    }

    pub fn deinit(self: *ClamAVScanner) void {
        switch (self.config.transport) {
            .unix => |path| self.allocator.free(path),
            .tcp => |tcp| self.allocator.free(tcp.host),
        }
    }

    pub fn validate(config: Config) ConfigError!void {
        switch (config.transport) {
            .unix => |path| {
                if (path.len == 0 or path.len >= unix_path_capacity) return error.InvalidSocketPath;
                if (std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidSocketPath;
            },
            .tcp => |tcp| {
                if (tcp.port == 0) return error.InvalidAddress;
                _ = std.Io.net.IpAddress.parse(tcp.host, tcp.port) catch return error.InvalidAddress;
            },
        }
        if (config.connect_timeout_ms == 0 or config.timeout_ms == 0) return error.InvalidTimeout;
        if (config.max_stream_bytes == 0 or config.chunk_bytes == 0) return error.InvalidSizeLimit;
    }

    /// Scan a message. The only error is running out of memory for the signature
    /// name; every scanner failure is a `Verdict`. Free the verdict with `deinit`.
    pub fn scanMessage(self: *ClamAVScanner, message: []const u8) std.mem.Allocator.Error!Verdict {
        if (!self.enabled) return .skipped;
        const verdict = try self.scan(message);
        self.record(verdict);
        switch (verdict) {
            .unavailable => |failure| log.warn("scanner unavailable ({s}); fail mode {s}: message {s}", .{
                @tagName(failure),
                @tagName(self.config.fail_mode),
                if (self.config.fail_mode == .open) "allowed without a scan" else "deferred",
            }),
            .too_large => log.warn("message of {d} bytes exceeds the scan limit; fail mode {s}", .{
                message.len,
                @tagName(self.config.fail_mode),
            }),
            else => {},
        }
        return verdict;
    }

    fn scan(self: *ClamAVScanner, message: []const u8) std.mem.Allocator.Error!Verdict {
        if (message.len > self.config.max_stream_bytes) return .too_large;

        var connection = Connection.open(self.config) catch |err| return .{ .unavailable = failureOf(err) };
        defer connection.close();

        streamMessage(&connection, message, self.config.chunk_bytes) catch |err| switch (err) {
            // The daemon may stop reading and close once the stream passes its
            // StreamMaxLength, after saying why. Read that reply before giving up.
            error.ConnectionLost => {},
            else => return .{ .unavailable = failureOf(err) },
        };

        var buffer: [max_reply_bytes]u8 = undefined;
        const reply = connection.readReply(&buffer) catch |err| return .{ .unavailable = failureOf(err) };
        return parseScanReply(self.allocator, reply);
    }

    fn record(self: *ClamAVScanner, verdict: Verdict) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.stats.total_scans += 1;
        switch (verdict) {
            .clean => self.stats.clean_messages += 1,
            .infected => self.stats.infected_messages += 1,
            .too_large => self.stats.too_large += 1,
            .unavailable => |failure| {
                self.stats.errors += 1;
                if (failure == .timeout) self.stats.timeouts += 1;
            },
            .skipped => {},
        }
    }

    /// What to do with a message given its verdict, under the configured fail
    /// mode. A message too large to scan is refused permanently when failing
    /// closed: a retry would be just as large, so deferring it only delays the
    /// bounce by days.
    pub fn disposition(self: *const ClamAVScanner, verdict: Verdict) Disposition {
        return switch (verdict) {
            .clean, .skipped => .deliver,
            .infected => .reject,
            .unavailable => switch (self.config.fail_mode) {
                .open => .deliver,
                .closed => .tempfail,
            },
            .too_large => switch (self.config.fail_mode) {
                .open => .deliver,
                .closed => .reject,
            },
        };
    }

    /// Whether the daemon answers `zPING` with `PONG` within the timeouts.
    pub fn ping(self: *ClamAVScanner) bool {
        var buffer: [64]u8 = undefined;
        const reply = self.command("zPING\x00", &buffer) catch return false;
        return std.mem.eql(u8, reply, "PONG");
    }

    /// The daemon's `zVERSION` reply, owned by the caller.
    pub fn version(self: *ClamAVScanner, allocator: std.mem.Allocator) (error{ScannerUnavailable} || std.mem.Allocator.Error)![]u8 {
        var buffer: [256]u8 = undefined;
        const reply = self.command("zVERSION\x00", &buffer) catch return error.ScannerUnavailable;
        if (reply.len == 0) return error.ScannerUnavailable;
        return allocator.dupe(u8, reply);
    }

    /// Ask the daemon to reload its signature database.
    pub fn reload(self: *ClamAVScanner) error{ScannerUnavailable}!void {
        var buffer: [64]u8 = undefined;
        const reply = self.command("zRELOAD\x00", &buffer) catch return error.ScannerUnavailable;
        if (!std.mem.eql(u8, reply, "RELOADING")) return error.ScannerUnavailable;
    }

    fn command(self: *ClamAVScanner, request: []const u8, buffer: []u8) TransportError![]const u8 {
        var connection = try Connection.open(self.config);
        defer connection.close();
        try connection.writeAll(request);
        return connection.readReply(buffer);
    }

    pub fn getStats(self: *ClamAVScanner) ScanStats {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.stats;
    }

    pub fn resetStats(self: *ClamAVScanner) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.stats = .{};
    }

    pub fn setEnabled(self: *ClamAVScanner, enabled: bool) void {
        self.enabled = enabled;
    }
};

/// Send `message` as INSTREAM chunks, then the zero-length terminator.
fn streamMessage(connection: *Connection, message: []const u8, chunk_bytes: u32) TransportError!void {
    try connection.writeAll("zINSTREAM\x00");
    var offset: usize = 0;
    while (offset < message.len) {
        const length = @min(message.len - offset, chunk_bytes);
        var prefix: [4]u8 = undefined;
        std.mem.writeInt(u32, &prefix, @intCast(length), .big);
        try connection.writeAll(&prefix);
        try connection.writeAll(message[offset..][0..length]);
        offset += length;
    }
    try connection.writeAll(&[_]u8{ 0, 0, 0, 0 });
}

/// Interpret a scan reply. clamd and zavd answer `stream: OK`,
/// `stream: <signature> FOUND`, or `<reason> ERROR`; a stream past the daemon's
/// limit is refused with `INSTREAM size limit exceeded. ERROR`.
///
/// The reply is matched by its ending, never by a substring: a signature whose
/// name contains "OK" is still an infection.
pub fn parseScanReply(allocator: std.mem.Allocator, reply: []const u8) std.mem.Allocator.Error!Verdict {
    const found_suffix = " FOUND";
    const error_suffix = " ERROR";
    if (std.mem.endsWith(u8, reply, found_suffix)) {
        const body = reply[0 .. reply.len - found_suffix.len];
        const separator = std.mem.lastIndexOf(u8, body, ": ") orelse return .{ .unavailable = .protocol_error };
        const name = std.mem.trim(u8, body[separator + 2 ..], " ");
        if (name.len == 0) return .{ .unavailable = .protocol_error };
        return .{ .infected = try allocator.dupe(u8, name) };
    }
    if (std.mem.endsWith(u8, reply, error_suffix)) {
        if (std.ascii.findIgnoreCase(reply, "size limit exceeded") != null) return .too_large;
        return .{ .unavailable = .scanner_error };
    }
    if (std.mem.endsWith(u8, reply, ": OK")) return .clean;
    return .{ .unavailable = .protocol_error };
}

const TransportError = error{ ConnectFailed, Timeout, ConnectionLost, ProtocolError };

fn failureOf(err: TransportError) Failure {
    return switch (err) {
        error.ConnectFailed => .connect_failed,
        error.Timeout => .timeout,
        error.ConnectionLost => .connection_lost,
        error.ProtocolError => .protocol_error,
    };
}

const unix_path_capacity = @typeInfo(@FieldType(posix.sockaddr.un, "path")).array.len;

/// A non-blocking socket whose every operation waits in poll() for at most the
/// time left before its deadline.
const Connection = struct {
    fd: posix.socket_t,
    deadline_ms: i64,

    fn open(config: Config) TransportError!Connection {
        const ip: ?std.Io.net.IpAddress = switch (config.transport) {
            .unix => null,
            .tcp => |tcp| std.Io.net.IpAddress.parse(tcp.host, tcp.port) catch return error.ConnectFailed,
        };
        const family: c_uint = if (ip) |address| switch (address) {
            .ip4 => posix.AF.INET,
            .ip6 => posix.AF.INET6,
        } else posix.AF.UNIX;
        const raw = std.c.socket(family, posix.SOCK.STREAM, 0);
        if (raw < 0) return error.ConnectFailed;
        var self: Connection = .{ .fd = @intCast(raw), .deadline_ms = monotonicMs() + config.connect_timeout_ms };
        errdefer self.close();
        try self.prepare();

        const rc = if (ip) |address| switch (address) {
            .ip4 => |ip4| blk: {
                const sockaddr: posix.sockaddr.in = .{
                    .family = posix.AF.INET,
                    .port = std.mem.nativeToBig(u16, ip4.port),
                    .addr = @bitCast(ip4.bytes),
                };
                break :blk std.c.connect(self.fd, @ptrCast(&sockaddr), @sizeOf(posix.sockaddr.in));
            },
            .ip6 => |ip6| blk: {
                const sockaddr: posix.sockaddr.in6 = .{
                    .family = posix.AF.INET6,
                    .port = std.mem.nativeToBig(u16, ip6.port),
                    .flowinfo = 0,
                    .addr = ip6.bytes,
                    .scope_id = 0,
                };
                break :blk std.c.connect(self.fd, @ptrCast(&sockaddr), @sizeOf(posix.sockaddr.in6));
            },
        } else blk: {
            const path = config.transport.unix;
            var sockaddr: posix.sockaddr.un = .{ .family = posix.AF.UNIX, .path = @splat(0) };
            @memcpy(sockaddr.path[0..path.len], path);
            break :blk std.c.connect(self.fd, @ptrCast(&sockaddr), @sizeOf(posix.sockaddr.un));
        };
        if (rc != 0) switch (std.c.errno(rc)) {
            // Still connecting: wait for writability, then ask how it went. A Unix
            // socket whose listen backlog is full reports AGAIN the same way.
            .INPROGRESS, .AGAIN, .INTR => {
                try self.wait(std.c.POLL.OUT);
                var pending: c_int = 0;
                var length: posix.socklen_t = @sizeOf(c_int);
                if (std.c.getsockopt(self.fd, posix.SOL.SOCKET, posix.SO.ERROR, &pending, &length) != 0 or pending != 0)
                    return error.ConnectFailed;
            },
            else => return error.ConnectFailed,
        };

        self.deadline_ms = monotonicMs() + config.timeout_ms;
        return self;
    }

    /// Non-blocking, close-on-exec, and never SIGPIPE: a daemon that hangs up
    /// mid-stream must cost this connection, not the process.
    fn prepare(self: *Connection) TransportError!void {
        const fd_flags = std.c.fcntl(self.fd, std.c.F.GETFD, @as(c_int, 0));
        if (fd_flags < 0 or std.c.fcntl(self.fd, std.c.F.SETFD, fd_flags | std.c.FD_CLOEXEC) < 0) return error.ConnectFailed;
        const flags = std.c.fcntl(self.fd, std.c.F.GETFL, @as(c_int, 0));
        const nonblock: c_int = @intCast(@as(u32, @bitCast(std.c.O{ .NONBLOCK = true })));
        if (flags < 0 or std.c.fcntl(self.fd, std.c.F.SETFL, flags | nonblock) < 0) return error.ConnectFailed;
        if (@hasDecl(posix.SO, "NOSIGPIPE")) {
            const one: c_int = 1;
            if (std.c.setsockopt(self.fd, posix.SOL.SOCKET, posix.SO.NOSIGPIPE, &one, @sizeOf(c_int)) != 0) return error.ConnectFailed;
        }
    }

    fn close(self: *Connection) void {
        _ = std.c.close(self.fd);
    }

    /// Wait until the socket is ready for `events`, or the deadline passes.
    fn wait(self: *Connection, events: i16) TransportError!void {
        while (true) {
            const remaining = self.deadline_ms - monotonicMs();
            if (remaining <= 0) return error.Timeout;
            var fds = [1]std.c.pollfd{.{ .fd = self.fd, .events = events, .revents = 0 }};
            const ready = std.c.poll(&fds, 1, @intCast(@min(remaining, std.math.maxInt(c_int))));
            if (ready > 0) return;
            if (ready == 0) return error.Timeout;
            if (std.c.errno(ready) != .INTR) return error.ConnectionLost;
        }
    }

    fn writeAll(self: *Connection, data: []const u8) TransportError!void {
        const flags: u32 = if (@hasDecl(std.c.MSG, "NOSIGNAL")) std.c.MSG.NOSIGNAL else 0;
        var sent: usize = 0;
        while (sent < data.len) {
            const rc = std.c.send(self.fd, data[sent..].ptr, data.len - sent, flags);
            if (rc >= 0) {
                sent += @intCast(rc);
                continue;
            }
            switch (std.c.errno(rc)) {
                .AGAIN => try self.wait(std.c.POLL.OUT),
                .INTR => {},
                else => return error.ConnectionLost,
            }
        }
    }

    /// Read one NUL-terminated reply. A peer that closes without the NUL has
    /// still finished its reply; one that closes having said nothing has not.
    fn readReply(self: *Connection, buffer: []u8) TransportError![]const u8 {
        var length: usize = 0;
        while (true) {
            if (std.mem.indexOfScalar(u8, buffer[0..length], 0)) |end| return trimReply(buffer[0..end]);
            if (length == buffer.len) return error.ProtocolError;
            const rc = std.c.read(self.fd, buffer[length..].ptr, buffer.len - length);
            if (rc > 0) {
                length += @intCast(rc);
                continue;
            }
            if (rc == 0) {
                if (length == 0) return error.ConnectionLost;
                return trimReply(buffer[0..length]);
            }
            switch (std.c.errno(rc)) {
                .AGAIN => try self.wait(std.c.POLL.IN),
                .INTR => {},
                else => return error.ConnectionLost,
            }
        }
    }
};

fn trimReply(reply: []const u8) []const u8 {
    return std.mem.trim(u8, reply, " \t\r\n");
}

fn monotonicMs() i64 {
    var ts: std.c.timespec = undefined;
    if (std.c.clock_gettime(.MONOTONIC, &ts) != 0) return 0;
    return @as(i64, ts.sec) * std.time.ms_per_s + @divFloor(ts.nsec, std.time.ns_per_ms);
}

/// Action to take when a virus is detected
pub const VirusAction = enum {
    reject, // Reject the message
    quarantine, // Move to quarantine folder
    tag, // Add header and deliver
    discard, // Silently discard

    pub fn toString(self: VirusAction) []const u8 {
        return switch (self) {
            .reject => "reject",
            .quarantine => "quarantine",
            .tag => "tag",
            .discard => "discard",
        };
    }
};

/// Virus scanning policy
pub const ScanPolicy = struct {
    scan_enabled: bool = true,
    scan_attachments_only: bool = false, // Only scan attachments, not entire message
    max_scan_size: usize = 25 * 1024 * 1024, // 25 MB max
    action_on_virus: VirusAction = .reject,
    action_on_error: VirusAction = .tag, // What to do if scanning fails
    quarantine_path: ?[]const u8 = null,
    tag_header_name: []const u8 = "X-Virus-Scanned",
    tag_header_value: []const u8 = "ClamAV",

    pub fn shouldScan(self: *ScanPolicy, message_size: usize) bool {
        if (!self.scan_enabled) return false;
        if (message_size > self.max_scan_size) return false;
        return true;
    }
};

// ---- tests ----------------------------------------------------------------

const testing = std.testing;

/// A clamd stand-in on a real socket. It accepts one connection, reads the
/// command (and, for INSTREAM, the chunks), and answers as `behaviour` says.
const FakeClamd = struct {
    listen_fd: posix.socket_t,
    behaviour: Behaviour,
    /// The INSTREAM payload as reassembled from the chunks.
    received: [64 * 1024]u8 = undefined,
    received_len: usize = 0,
    command: [32]u8 = undefined,
    command_len: usize = 0,
    unix_path: ?[:0]const u8 = null,
    thread: ?std.Thread = null,

    const Behaviour = union(enum) {
        /// Read the whole request, then reply with these bytes and a NUL.
        reply: []const u8,
        /// Reply with this as soon as the stream passes `after` bytes, then hang
        /// up without reading the rest, as clamd does past StreamMaxLength.
        refuse_after: struct { after: usize, reply: []const u8 },
        /// Read the request and never answer; return once the client gives up.
        stall,
        /// Read the request and hang up without a word.
        hang_up,
    };

    fn listenTcp(behaviour: Behaviour) !FakeClamd {
        const raw = std.c.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
        if (raw < 0) return error.SocketFailed;
        const fd: posix.socket_t = @intCast(raw);
        errdefer _ = std.c.close(fd);
        const address: posix.sockaddr.in = .{ .family = posix.AF.INET, .port = 0, .addr = @bitCast([4]u8{ 127, 0, 0, 1 }) };
        if (std.c.bind(fd, @ptrCast(&address), @sizeOf(posix.sockaddr.in)) != 0) return error.BindFailed;
        if (std.c.listen(fd, 4) != 0) return error.ListenFailed;
        return .{ .listen_fd = fd, .behaviour = behaviour };
    }

    fn port(self: *const FakeClamd) !u16 {
        var address: posix.sockaddr.in = undefined;
        var length: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        if (std.c.getsockname(self.listen_fd, @ptrCast(&address), &length) != 0) return error.GetSockNameFailed;
        return std.mem.bigToNative(u16, address.port);
    }

    fn listenUnix(path: [:0]const u8, behaviour: Behaviour) !FakeClamd {
        _ = std.c.unlink(path.ptr);
        const raw = std.c.socket(posix.AF.UNIX, posix.SOCK.STREAM, 0);
        if (raw < 0) return error.SocketFailed;
        const fd: posix.socket_t = @intCast(raw);
        errdefer _ = std.c.close(fd);
        var address: posix.sockaddr.un = .{ .family = posix.AF.UNIX, .path = @splat(0) };
        @memcpy(address.path[0..path.len], path);
        if (std.c.bind(fd, @ptrCast(&address), @sizeOf(posix.sockaddr.un)) != 0) return error.BindFailed;
        if (std.c.listen(fd, 4) != 0) return error.ListenFailed;
        return .{ .listen_fd = fd, .behaviour = behaviour, .unix_path = path };
    }

    fn start(self: *FakeClamd) !void {
        self.thread = try std.Thread.spawn(.{}, serve, .{self});
    }

    /// Wait for the connection to finish and release the listener. Safe to call
    /// twice, so a test can finish early and still `defer` it.
    fn finish(self: *FakeClamd) void {
        if (self.thread) |thread| thread.join();
        self.thread = null;
        if (self.listen_fd >= 0) _ = std.c.close(self.listen_fd);
        self.listen_fd = -1;
        if (self.unix_path) |path| _ = std.c.unlink(path.ptr);
        self.unix_path = null;
    }

    fn serve(self: *FakeClamd) void {
        const raw = std.c.accept(self.listen_fd, null, null);
        if (raw < 0) return;
        const fd: posix.socket_t = @intCast(raw);
        defer _ = std.c.close(fd);

        // The command runs up to its NUL.
        while (self.command_len < self.command.len) {
            var byte: [1]u8 = undefined;
            if (std.c.read(fd, &byte, 1) != 1) return;
            if (byte[0] == 0) break;
            self.command[self.command_len] = byte[0];
            self.command_len += 1;
        }
        if (std.mem.eql(u8, self.command[0..self.command_len], "zINSTREAM")) {
            while (true) {
                var prefix: [4]u8 = undefined;
                if (!readExact(fd, &prefix)) return;
                const length = std.mem.readInt(u32, &prefix, .big);
                if (length == 0) break;
                var remaining: usize = length;
                while (remaining > 0) {
                    var chunk: [4096]u8 = undefined;
                    const take = @min(remaining, chunk.len);
                    if (!readExact(fd, chunk[0..take])) return;
                    const keep = @min(take, self.received.len - self.received_len);
                    @memcpy(self.received[self.received_len..][0..keep], chunk[0..keep]);
                    self.received_len += keep;
                    remaining -= take;
                    switch (self.behaviour) {
                        .refuse_after => |refusal| if (self.received_len > refusal.after) {
                            sendReply(fd, refusal.reply);
                            return;
                        },
                        else => {},
                    }
                }
            }
        }
        switch (self.behaviour) {
            .reply => |text| sendReply(fd, text),
            .refuse_after => |refusal| sendReply(fd, refusal.reply),
            // Wait for the client to give up and close its end.
            .stall => {
                var sink: [64]u8 = undefined;
                while (std.c.read(fd, &sink, sink.len) > 0) {}
            },
            .hang_up => {},
        }
    }

    fn readExact(fd: posix.socket_t, buffer: []u8) bool {
        var filled: usize = 0;
        while (filled < buffer.len) {
            const rc = std.c.read(fd, buffer[filled..].ptr, buffer.len - filled);
            if (rc <= 0) return false;
            filled += @intCast(rc);
        }
        return true;
    }

    fn sendReply(fd: posix.socket_t, text: []const u8) void {
        _ = std.c.write(fd, text.ptr, text.len);
        _ = std.c.write(fd, "\x00", 1);
    }
};

/// A Unix socket path short enough for sockaddr_un on every platform, unique
/// per process and per test.
fn testSocketPath(buffer: []u8, label: []const u8) ![:0]const u8 {
    return std.fmt.bufPrintSentinel(buffer, "/tmp/mail-clamav-{d}-{s}.sock", .{ std.c.getpid(), label }, 0);
}

fn tcpScanner(fake: *const FakeClamd, overrides: Config) !ClamAVScanner {
    var config = overrides;
    config.transport = .{ .tcp = .{ .host = "127.0.0.1", .port = try fake.port() } };
    return ClamAVScanner.init(testing.allocator, config);
}

const eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

test "a clean reply over TCP, with the message reassembled from its chunks" {
    var fake = try FakeClamd.listenTcp(.{ .reply = "stream: OK" });
    try fake.start();
    defer fake.finish();
    // A chunk size that does not divide the message proves the framing.
    var scanner = try tcpScanner(&fake, .{ .chunk_bytes = 7 });
    defer scanner.deinit();

    const message = "From: a@example.com\r\nSubject: hello\r\n\r\nNothing to see here.\r\n";
    const verdict = try scanner.scanMessage(message);
    defer verdict.deinit(testing.allocator);
    fake.finish();

    try testing.expect(verdict == .clean);
    try testing.expectEqual(Disposition.deliver, scanner.disposition(verdict));
    try testing.expectEqualStrings("zINSTREAM", fake.command[0..fake.command_len]);
    try testing.expectEqualStrings(message, fake.received[0..fake.received_len]);
    try testing.expectEqual(@as(usize, 1), scanner.getStats().clean_messages);
}

test "an infection over a Unix socket names its signature" {
    var path_buffer: [96]u8 = undefined;
    const path = try testSocketPath(&path_buffer, "found");
    var fake = try FakeClamd.listenUnix(path, .{ .reply = "stream: Eicar-Test-Signature FOUND" });
    try fake.start();
    defer fake.finish();
    var scanner = try ClamAVScanner.init(testing.allocator, .{ .transport = .{ .unix = path } });
    defer scanner.deinit();

    const verdict = try scanner.scanMessage(eicar);
    defer verdict.deinit(testing.allocator);
    try testing.expectEqualStrings("Eicar-Test-Signature", verdict.infected);
    try testing.expectEqual(Disposition.reject, scanner.disposition(verdict));
    try testing.expectEqual(@as(usize, 1), scanner.getStats().infected_messages);
}

test "a daemon error is unavailable, and the fail mode decides" {
    var fake = try FakeClamd.listenTcp(.{ .reply = "stream: Can't allocate memory ERROR" });
    try fake.start();
    defer fake.finish();
    var scanner = try tcpScanner(&fake, .{ .fail_mode = .closed });
    defer scanner.deinit();

    const verdict = try scanner.scanMessage("hello");
    try testing.expectEqual(Verdict{ .unavailable = .scanner_error }, verdict);
    try testing.expectEqual(Disposition.tempfail, scanner.disposition(verdict));
    scanner.config.fail_mode = .open;
    try testing.expectEqual(Disposition.deliver, scanner.disposition(verdict));
    try testing.expectEqual(@as(usize, 1), scanner.getStats().errors);
}

test "a daemon that stalls is a timeout, not a stuck session" {
    var path_buffer: [96]u8 = undefined;
    const path = try testSocketPath(&path_buffer, "stall");
    var fake = try FakeClamd.listenUnix(path, .stall);
    try fake.start();
    defer fake.finish();
    var scanner = try ClamAVScanner.init(testing.allocator, .{
        .transport = .{ .unix = path },
        .timeout_ms = 150,
        .fail_mode = .closed,
    });
    defer scanner.deinit();

    const started = monotonicMs();
    const verdict = try scanner.scanMessage("hello");
    const elapsed = monotonicMs() - started;
    try testing.expectEqual(Verdict{ .unavailable = .timeout }, verdict);
    try testing.expectEqual(Disposition.tempfail, scanner.disposition(verdict));
    try testing.expect(elapsed >= 100 and elapsed < 5_000);
    try testing.expectEqual(@as(usize, 1), scanner.getStats().timeouts);
}

test "nothing listening is a connect failure, on either transport" {
    var path_buffer: [96]u8 = undefined;
    const path = try testSocketPath(&path_buffer, "absent");
    _ = std.c.unlink(path.ptr);
    var unix_scanner = try ClamAVScanner.init(testing.allocator, .{ .transport = .{ .unix = path }, .fail_mode = .closed });
    defer unix_scanner.deinit();
    const unix_verdict = try unix_scanner.scanMessage("hello");
    try testing.expectEqual(Verdict{ .unavailable = .connect_failed }, unix_verdict);
    try testing.expectEqual(Disposition.tempfail, unix_scanner.disposition(unix_verdict));
    try testing.expect(!unix_scanner.ping());

    // A port that was just bound and released has nothing listening on it.
    var fake = try FakeClamd.listenTcp(.hang_up);
    const free_port = try fake.port();
    fake.finish();
    var tcp_scanner = try ClamAVScanner.init(testing.allocator, .{ .transport = .{ .tcp = .{ .host = "127.0.0.1", .port = free_port } } });
    defer tcp_scanner.deinit();
    const tcp_verdict = try tcp_scanner.scanMessage("hello");
    try testing.expectEqual(Verdict{ .unavailable = .connect_failed }, tcp_verdict);
    // Failing open delivers, as the client always did.
    try testing.expectEqual(Disposition.deliver, tcp_scanner.disposition(tcp_verdict));
}

test "a hang-up without a reply is a lost connection" {
    var fake = try FakeClamd.listenTcp(.hang_up);
    try fake.start();
    defer fake.finish();
    var scanner = try tcpScanner(&fake, .{});
    defer scanner.deinit();
    try testing.expectEqual(Verdict{ .unavailable = .connection_lost }, try scanner.scanMessage("hello"));
}

test "a stream past the daemon's StreamMaxLength is too large, not an error" {
    // Over a Unix socket the refusal stays readable after the daemon hangs up,
    // so this exercises reading the reply after the upload broke off.
    var path_buffer: [96]u8 = undefined;
    const path = try testSocketPath(&path_buffer, "toolarge");
    var fake = try FakeClamd.listenUnix(path, .{ .refuse_after = .{ .after = 1024, .reply = "INSTREAM size limit exceeded. ERROR" } });
    try fake.start();
    defer fake.finish();
    var scanner = try ClamAVScanner.init(testing.allocator, .{ .transport = .{ .unix = path }, .chunk_bytes = 512, .fail_mode = .closed });
    defer scanner.deinit();

    const message: [256 * 1024]u8 = @splat('a');
    const verdict = try scanner.scanMessage(&message);
    try testing.expect(verdict == .too_large);
    // A retry would be just as large, so failing closed refuses it outright.
    try testing.expectEqual(Disposition.reject, scanner.disposition(verdict));
    try testing.expectEqual(@as(usize, 1), scanner.getStats().too_large);
}

test "a message over the configured limit is not streamed at all" {
    var path_buffer: [96]u8 = undefined;
    const path = try testSocketPath(&path_buffer, "limit");
    _ = std.c.unlink(path.ptr);
    // Nothing listens: a scan that tried to connect would be unavailable instead.
    var scanner = try ClamAVScanner.init(testing.allocator, .{ .transport = .{ .unix = path }, .max_stream_bytes = 4 });
    defer scanner.deinit();
    const verdict = try scanner.scanMessage("hello");
    try testing.expect(verdict == .too_large);
    try testing.expectEqual(Disposition.deliver, scanner.disposition(verdict));
}

test "zPING and zVERSION" {
    {
        var fake = try FakeClamd.listenTcp(.{ .reply = "PONG" });
        try fake.start();
        defer fake.finish();
        var scanner = try tcpScanner(&fake, .{});
        defer scanner.deinit();
        try testing.expect(scanner.ping());
        fake.finish();
        try testing.expectEqualStrings("zPING", fake.command[0..fake.command_len]);
    }
    {
        var path_buffer: [96]u8 = undefined;
        const path = try testSocketPath(&path_buffer, "version");
        var fake = try FakeClamd.listenUnix(path, .{ .reply = "ClamAV 1.4.1/27460/Mon Nov 16 09:30:00 2026" });
        try fake.start();
        defer fake.finish();
        var scanner = try ClamAVScanner.init(testing.allocator, .{ .transport = .{ .unix = path } });
        defer scanner.deinit();
        const reported = try scanner.version(testing.allocator);
        defer testing.allocator.free(reported);
        fake.finish();
        try testing.expectEqualStrings("ClamAV 1.4.1/27460/Mon Nov 16 09:30:00 2026", reported);
        try testing.expectEqualStrings("zVERSION", fake.command[0..fake.command_len]);
    }
}

test "replies are matched by their ending, not by a substring" {
    const allocator = testing.allocator;
    try testing.expect((try parseScanReply(allocator, "stream: OK")) == .clean);

    // The old parser looked for "OK" anywhere, which read this infection as clean.
    const tricky = try parseScanReply(allocator, "stream: Win.Trojan.OKiller-1 FOUND");
    defer tricky.deinit(allocator);
    try testing.expectEqualStrings("Win.Trojan.OKiller-1", tricky.infected);

    try testing.expect((try parseScanReply(allocator, "INSTREAM size limit exceeded. ERROR")) == .too_large);
    try testing.expectEqual(Verdict{ .unavailable = .scanner_error }, try parseScanReply(allocator, "stream: lstat() failed ERROR"));
    try testing.expectEqual(Verdict{ .unavailable = .protocol_error }, try parseScanReply(allocator, "stream: FOUND"));
    try testing.expectEqual(Verdict{ .unavailable = .protocol_error }, try parseScanReply(allocator, ""));
    try testing.expectEqual(Verdict{ .unavailable = .protocol_error }, try parseScanReply(allocator, "PONG"));
}

test "configuration is validated and transports parse" {
    const allocator = testing.allocator;
    try testing.expectError(error.InvalidSocketPath, ClamAVScanner.init(allocator, .{ .transport = .{ .unix = "" } }));
    var long_path: [200]u8 = @splat('a');
    long_path[0] = '/';
    try testing.expectError(error.InvalidSocketPath, ClamAVScanner.init(allocator, .{ .transport = .{ .unix = &long_path } }));
    try testing.expectError(error.InvalidAddress, ClamAVScanner.init(allocator, .{ .transport = .{ .tcp = .{ .host = "clamd.internal" } } }));
    try testing.expectError(error.InvalidAddress, ClamAVScanner.init(allocator, .{ .transport = .{ .tcp = .{ .host = "127.0.0.1", .port = 0 } } }));
    try testing.expectError(error.InvalidTimeout, ClamAVScanner.init(allocator, .{ .timeout_ms = 0 }));
    try testing.expectError(error.InvalidSizeLimit, ClamAVScanner.init(allocator, .{ .max_stream_bytes = 0 }));

    var scanner = try ClamAVScanner.init(allocator, .{});
    defer scanner.deinit();
    try testing.expectEqualStrings(default_socket_path, scanner.config.transport.unix);
    try testing.expectEqual(FailMode.open, scanner.config.fail_mode);

    try testing.expectEqualStrings("/run/clamav/clamd.ctl", (try Transport.parse("unix:/run/clamav/clamd.ctl")).unix);
    try testing.expectEqualStrings("/run/zavd/zavd.sock", (try Transport.parse("/run/zavd/zavd.sock")).unix);
    const tcp = try Transport.parse("tcp:127.0.0.1:3310");
    try testing.expectEqualStrings("127.0.0.1", tcp.tcp.host);
    try testing.expectEqual(@as(u16, 3310), tcp.tcp.port);
    try testing.expectEqualStrings("::1", (try Transport.parse("[::1]:3310")).tcp.host);
    try testing.expectError(error.InvalidTransport, Transport.parse("unix:"));
    try testing.expectError(error.InvalidTransport, Transport.parse("127.0.0.1"));
    try testing.expectError(error.InvalidTransport, Transport.parse("127.0.0.1:0"));

    try testing.expectEqual(FailMode.closed, FailMode.parse("Closed").?);
    try testing.expectEqual(FailMode.open, FailMode.parse("open").?);
    try testing.expect(FailMode.parse("maybe") == null);
}

test "a disabled scanner skips rather than calling the message clean" {
    var scanner = try ClamAVScanner.init(testing.allocator, .{ .fail_mode = .closed });
    defer scanner.deinit();
    scanner.setEnabled(false);
    const verdict = try scanner.scanMessage(eicar);
    try testing.expect(verdict == .skipped);
    try testing.expectEqual(Disposition.deliver, scanner.disposition(verdict));
    try testing.expectEqual(@as(usize, 0), scanner.getStats().total_scans);
}

test "scan policy" {
    var policy = ScanPolicy{};
    try testing.expect(policy.shouldScan(1024));
    try testing.expect(!policy.shouldScan(30 * 1024 * 1024));
    policy.scan_enabled = false;
    try testing.expect(!policy.shouldScan(1024));
}

test "virus action enum" {
    try testing.expectEqualStrings("reject", VirusAction.reject.toString());
    try testing.expectEqualStrings("quarantine", VirusAction.quarantine.toString());
    try testing.expectEqualStrings("tag", VirusAction.tag.toString());
}
