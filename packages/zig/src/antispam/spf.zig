const std = @import("std");
const posix = std.posix;
const time_compat = @import("../core/time_compat.zig");
const dns_cache = @import("dns_cache.zig");

// =============================================================================
// DNS query helpers (TXT / A / MX over UDP) - RFC 1035
// =============================================================================
//
// The repository does not ship a TXT/MX-capable resolver (the existing
// `infrastructure/dns_resolver.zig` only wraps getAddressList for A/AAAA), so
// SPF/DMARC need raw DNS queries. We implement a minimal, self-contained UDP
// resolver here and expose it for reuse (DMARC imports `dnsQueryTxt`).
//
// We talk to the system resolver. The nameserver is read from
// /etc/resolv.conf (first `nameserver` line); if that is unavailable we fall
// back to the public resolver 1.1.1.1.
// =============================================================================

pub const DnsError = error{
    DNSTimeout,
    DNSTemporaryFailure,
    DNSFormatError,
    DNSNameError, // NXDOMAIN
    DNSNoAnswer,
    OutOfMemory,
};

const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_TXT: u16 = 16;
const DNS_TYPE_MX: u16 = 15;
const DNS_CLASS_IN: u16 = 1;

/// Read the first nameserver from /etc/resolv.conf into `buf`.
/// Returns the IPv4 string slice or null if none found.
fn readSystemNameserver(buf: []u8) ?[]const u8 {
    const fd = std.c.open("/etc/resolv.conf".ptr, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, @as(std.c.mode_t, 0));
    if (fd < 0) return null;
    defer _ = std.c.close(fd);

    var file_buf: [4096]u8 = undefined;
    const n = std.c.read(fd, &file_buf, file_buf.len);
    if (n <= 0) return null;
    const contents = file_buf[0..@intCast(n)];

    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (!std.mem.startsWith(u8, trimmed, "nameserver")) continue;
        const rest = std.mem.trim(u8, trimmed["nameserver".len..], " \t\r");
        if (rest.len == 0 or rest.len > buf.len) continue;
        // Only accept IPv4 here (UDP socket below is AF.INET)
        if (parseIp4(rest) == null) continue;
        @memcpy(buf[0..rest.len], rest);
        return buf[0..rest.len];
    }
    return null;
}

/// Parse a dotted-quad IPv4 string into a host-order u32 (null if malformed).
fn parseIp4(s: []const u8) ?u32 {
    var octets: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (it.next()) |part| {
        if (i >= 4) return null;
        octets[i] = std.fmt.parseInt(u8, part, 10) catch return null;
        i += 1;
    }
    if (i != 4) return null;
    return (@as(u32, octets[0]) << 24) | (@as(u32, octets[1]) << 16) | (@as(u32, octets[2]) << 8) | @as(u32, octets[3]);
}

/// Parse an IPv6 string (full form, one "::", or a trailing embedded IPv4
/// like ::ffff:1.2.3.4) into 16 bytes (null on error). Pub so DNSBL can
/// reuse it for nibble-format queries.
pub fn parseIp6(s: []const u8) ?[16]u8 {
    // Embedded IPv4 tail: rewrite "...:a.b.c.d" into two 16-bit hex groups
    // so the group parser below handles everything uniformly.
    if (std.mem.indexOfScalar(u8, s, '.') != null) {
        const last_colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return null;
        const v4 = parseIp4(s[last_colon + 1 ..]) orelse return null;
        var buf: [64]u8 = undefined;
        const rewritten = std.fmt.bufPrint(&buf, "{s}{x}:{x}", .{
            s[0 .. last_colon + 1],
            v4 >> 16,
            v4 & 0xffff,
        }) catch return null;
        return parseIp6Groups(rewritten);
    }
    return parseIp6Groups(s);
}

fn parseIp6Groups(s: []const u8) ?[16]u8 {
    var out: [16]u8 = std.mem.zeroes([16]u8);
    if (std.mem.indexOf(u8, s, "::")) |pos| {
        var head: [8]u16 = undefined;
        var hn: usize = 0;
        var tail: [8]u16 = undefined;
        var tn: usize = 0;
        if (pos > 0) {
            var it = std.mem.splitScalar(u8, s[0..pos], ':');
            while (it.next()) |g| {
                if (g.len == 0) continue;
                if (hn >= 8) return null;
                head[hn] = std.fmt.parseInt(u16, g, 16) catch return null;
                hn += 1;
            }
        }
        const tpart = s[pos + 2 ..];
        if (tpart.len > 0) {
            var it = std.mem.splitScalar(u8, tpart, ':');
            while (it.next()) |g| {
                if (g.len == 0) continue;
                if (tn >= 8) return null;
                tail[tn] = std.fmt.parseInt(u16, g, 16) catch return null;
                tn += 1;
            }
        }
        if (hn + tn > 8) return null;
        var idx: usize = 0;
        var k: usize = 0;
        while (k < hn) : (k += 1) {
            out[idx] = @intCast(head[k] >> 8);
            out[idx + 1] = @intCast(head[k] & 0xff);
            idx += 2;
        }
        idx = 16 - tn * 2;
        k = 0;
        while (k < tn) : (k += 1) {
            out[idx] = @intCast(tail[k] >> 8);
            out[idx + 1] = @intCast(tail[k] & 0xff);
            idx += 2;
        }
    } else {
        var groups: [8]u16 = undefined;
        var n: usize = 0;
        var it = std.mem.splitScalar(u8, s, ':');
        while (it.next()) |g| {
            if (n >= 8) return null;
            groups[n] = std.fmt.parseInt(u16, g, 16) catch return null;
            n += 1;
        }
        if (n != 8) return null;
        var k: usize = 0;
        while (k < 8) : (k += 1) {
            out[k * 2] = @intCast(groups[k] >> 8);
            out[k * 2 + 1] = @intCast(groups[k] & 0xff);
        }
    }
    return out;
}

/// Encode a DNS QNAME (sequence of length-prefixed labels) into `out`.
/// Returns number of bytes written.
fn encodeQName(name: []const u8, out: []u8) !usize {
    var pos: usize = 0;
    var labels = std.mem.splitScalar(u8, name, '.');
    while (labels.next()) |label| {
        if (label.len == 0) continue; // skip empty (e.g. trailing dot)
        if (label.len > 63) return error.DNSFormatError;
        if (pos + 1 + label.len + 1 > out.len) return error.DNSFormatError;
        out[pos] = @intCast(label.len);
        pos += 1;
        @memcpy(out[pos .. pos + label.len], label);
        pos += label.len;
    }
    if (pos + 1 > out.len) return error.DNSFormatError;
    out[pos] = 0; // root label terminator
    pos += 1;
    return pos;
}

/// Build a DNS query packet for `name`/`qtype`. Returns bytes written.
fn buildQuery(id: u16, name: []const u8, qtype: u16, out: []u8) !usize {
    if (out.len < 12) return error.DNSFormatError;
    // Header
    std.mem.writeInt(u16, out[0..2], id, .big);
    std.mem.writeInt(u16, out[2..4], 0x0100, .big); // RD = 1 (recursion desired)
    std.mem.writeInt(u16, out[4..6], 1, .big); // QDCOUNT
    std.mem.writeInt(u16, out[6..8], 0, .big); // ANCOUNT
    std.mem.writeInt(u16, out[8..10], 0, .big); // NSCOUNT
    std.mem.writeInt(u16, out[10..12], 1, .big); // ARCOUNT (EDNS0 OPT below)

    var pos: usize = 12;
    pos += try encodeQName(name, out[pos..]);
    if (pos + 4 > out.len) return error.DNSFormatError;
    std.mem.writeInt(u16, out[pos..][0..2], qtype, .big);
    std.mem.writeInt(u16, out[pos + 2 ..][0..2], DNS_CLASS_IN, .big);
    pos += 4;

    // EDNS0 OPT pseudo-RR (RFC 6891). Without it responses are capped at 512
    // bytes and resolvers TRUNCATE large answers — e.g. outlook.com's DKIM key
    // (CNAME chain + 2048-bit TXT) or fat SPF record sets — which then looked
    // like a missing record (dkim=permerror). Advertise our 4096-byte buffer.
    if (pos + 11 > out.len) return error.DNSFormatError;
    out[pos] = 0; // root name
    std.mem.writeInt(u16, out[pos + 1 ..][0..2], 41, .big); // TYPE = OPT
    std.mem.writeInt(u16, out[pos + 3 ..][0..2], 4096, .big); // CLASS = UDP payload size
    std.mem.writeInt(u32, out[pos + 5 ..][0..4], 0, .big); // TTL = extended RCODE/flags
    std.mem.writeInt(u16, out[pos + 9 ..][0..2], 0, .big); // RDLENGTH
    pos += 11;
    return pos;
}

/// Skip a (possibly compressed) name in the answer, return offset just after it.
fn skipName(msg: []const u8, start: usize) !usize {
    var pos = start;
    while (true) {
        if (pos >= msg.len) return error.DNSFormatError;
        const len = msg[pos];
        if (len == 0) return pos + 1;
        if ((len & 0xC0) == 0xC0) {
            // Compression pointer: 2 bytes, name ends here for skipping purposes
            if (pos + 2 > msg.len) return error.DNSFormatError;
            return pos + 2;
        }
        pos += 1 + len;
    }
}

/// Send one UDP DNS query to `server` (IPv4 string) and read the reply into `recv`.
/// Returns the number of bytes received.
fn udpExchange(server: []const u8, query: []const u8, recv: []u8) DnsError!usize {
    const server_ip = parseIp4(server) orelse return error.DNSTemporaryFailure;

    const family: c_uint = @intCast(@as(u32, posix.AF.INET));
    const sock_type: c_uint = @intCast(@as(u32, posix.SOCK.DGRAM));
    const raw_fd = std.c.socket(family, sock_type, 0);
    if (raw_fd < 0) return error.DNSTemporaryFailure;
    const fd: posix.socket_t = @intCast(raw_fd);
    defer _ = std.c.close(fd);

    // 5 second receive timeout so we never block forever.
    const tv: posix.timeval = .{ .sec = 5, .usec = 0 };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch {};

    // Build the destination sockaddr_in for <server>:53 (addr in network order).
    const sa: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 53),
        .addr = std.mem.nativeToBig(u32, server_ip),
    };
    if (std.c.connect(fd, @ptrCast(&sa), @sizeOf(@TypeOf(sa))) < 0) {
        return error.DNSTemporaryFailure;
    }

    if (std.c.write(fd, query.ptr, query.len) < 0) {
        return error.DNSTemporaryFailure;
    }

    const n = std.c.read(fd, recv.ptr, recv.len);
    if (n <= 0) return error.DNSTimeout;
    return @intCast(n);
}

/// Generic DNS query. Calls `handler` for each answer RR matching `qtype`.
/// The handler receives the full message and the RDATA slice.
fn dnsQuery(
    name: []const u8,
    qtype: u16,
    server: []const u8,
    comptime Ctx: type,
    ctx: Ctx,
    comptime handler: fn (Ctx, msg: []const u8, rdata: []const u8) anyerror!void,
) DnsError!void {
    var qbuf: [512]u8 = undefined;
    const id: u16 = @truncate(@as(u64, @bitCast(time_compat.milliTimestamp())));
    const qlen = buildQuery(id, name, qtype, &qbuf) catch return error.DNSFormatError;

    var recv: [4096]u8 = undefined;
    const rlen = try udpExchange(server, qbuf[0..qlen], &recv);
    const msg = recv[0..rlen];

    if (msg.len < 12) return error.DNSFormatError;

    // RCODE is low nibble of byte 3.
    const flags = std.mem.readInt(u16, msg[2..4], .big);
    const rcode: u4 = @truncate(flags & 0x000F);
    switch (rcode) {
        0 => {},
        2 => return error.DNSTemporaryFailure, // SERVFAIL
        3 => return error.DNSNameError, // NXDOMAIN
        else => return error.DNSFormatError,
    }
    // Truncated (TC): the answer didn't fit even with EDNS0. Treat as a
    // transient failure rather than parsing a partial answer set — a missing
    // TXT here would otherwise read as "no such record" (permerror for DKIM).
    if ((flags & 0x0200) != 0) return error.DNSTemporaryFailure;

    const qdcount = std.mem.readInt(u16, msg[4..6], .big);
    const ancount = std.mem.readInt(u16, msg[6..8], .big);

    var pos: usize = 12;

    // Skip the questions.
    var q: u16 = 0;
    while (q < qdcount) : (q += 1) {
        pos = skipName(msg, pos) catch return error.DNSFormatError;
        if (pos + 4 > msg.len) return error.DNSFormatError;
        pos += 4; // QTYPE + QCLASS
    }

    // Walk the answers.
    var a: u16 = 0;
    while (a < ancount) : (a += 1) {
        pos = skipName(msg, pos) catch return error.DNSFormatError;
        if (pos + 10 > msg.len) return error.DNSFormatError;
        const rr_type = std.mem.readInt(u16, msg[pos..][0..2], .big);
        const rdlength = std.mem.readInt(u16, msg[pos + 8 ..][0..2], .big);
        pos += 10;
        if (pos + rdlength > msg.len) return error.DNSFormatError;
        const rdata = msg[pos .. pos + rdlength];
        pos += rdlength;

        if (rr_type == qtype) {
            handler(ctx, msg, rdata) catch return error.DNSFormatError;
        }
    }
}

/// Resolve the nameserver to use. Falls back to public resolvers.
fn pickNameserver(buf: []u8) []const u8 {
    if (readSystemNameserver(buf)) |ns| return ns;
    return "1.1.1.1";
}

/// Query a TXT record. Returns the first concatenated TXT string that starts
/// with `prefix` (use "" to accept the first TXT). Caller owns the result.
/// Answers are served from the process-wide TTL cache when possible — this
/// single choke point covers SPF records, DKIM public keys, and DMARC
/// policies (dkim.zig and dmarc.zig both resolve through here).
pub fn dnsQueryTxt(
    allocator: std.mem.Allocator,
    name: []const u8,
    prefix: []const u8,
) DnsError!?[]const u8 {
    var key_buf: [512]u8 = undefined;
    const cache_key: ?[]const u8 = std.fmt.bufPrint(&key_buf, "txt:{s}:{s}", .{ name, prefix }) catch null;

    if (cache_key) |key| {
        switch (dns_cache.get(allocator, key)) {
            .hit => |v| return v,
            .negative => return null,
            .miss => {},
        }
    }

    const result = dnsQueryTxtUncached(allocator, name, prefix) catch |err| {
        // Don't cache transient failures — retry on the next message.
        return err;
    };
    if (cache_key) |key| {
        dns_cache.put(key, result, if (result != null) dns_cache.positive_ttl else dns_cache.negative_ttl);
    }
    return result;
}

fn dnsQueryTxtUncached(
    allocator: std.mem.Allocator,
    name: []const u8,
    prefix: []const u8,
) DnsError!?[]const u8 {
    const Collector = struct {
        allocator: std.mem.Allocator,
        prefix: []const u8,
        result: ?[]const u8 = null,

        fn onRr(self: *@This(), msg: []const u8, rdata: []const u8) anyerror!void {
            _ = msg;
            if (self.result != null) return;
            // TXT RDATA is one or more <len><bytes> character-strings; concat them.
            var combined: std.ArrayList(u8) = .empty;
            defer combined.deinit(self.allocator);
            var i: usize = 0;
            while (i < rdata.len) {
                const seg_len = rdata[i];
                i += 1;
                if (i + seg_len > rdata.len) break;
                try combined.appendSlice(self.allocator, rdata[i .. i + seg_len]);
                i += seg_len;
            }
            if (self.prefix.len == 0 or std.mem.startsWith(u8, combined.items, self.prefix)) {
                self.result = try self.allocator.dupe(u8, combined.items);
            }
        }
    };

    var ns_buf: [64]u8 = undefined;
    const ns = pickNameserver(&ns_buf);

    var collector = Collector{ .allocator = allocator, .prefix = prefix };
    dnsQuery(name, DNS_TYPE_TXT, ns, *Collector, &collector, Collector.onRr) catch |err| switch (err) {
        error.DNSNameError, error.DNSNoAnswer => return null,
        else => return err,
    };
    return collector.result;
}

/// Query A records, collecting IPv4 addresses (as u32 big-endian-host values)
/// into `out`. Returns the number of addresses written.
fn dnsQueryA(name: []const u8, out: *std.ArrayList([4]u8), allocator: std.mem.Allocator) DnsError!void {
    const Collector = struct {
        list: *std.ArrayList([4]u8),
        allocator: std.mem.Allocator,

        fn onRr(self: *@This(), msg: []const u8, rdata: []const u8) anyerror!void {
            _ = msg;
            if (rdata.len != 4) return;
            try self.list.append(self.allocator, .{ rdata[0], rdata[1], rdata[2], rdata[3] });
        }
    };

    var ns_buf: [64]u8 = undefined;
    const ns = pickNameserver(&ns_buf);

    var collector = Collector{ .list = out, .allocator = allocator };
    dnsQuery(name, DNS_TYPE_A, ns, *Collector, &collector, Collector.onRr) catch |err| switch (err) {
        // No record / no answer is not fatal for a/mx — just no matches.
        error.DNSNameError, error.DNSNoAnswer => {},
        else => return err,
    };
}

/// Read a (possibly compressed) domain name from `msg` at `start` into `out`.
/// Returns the decoded name length written to `out`.
fn readNameInto(msg: []const u8, start: usize, out: []u8) !usize {
    var pos = start;
    var out_pos: usize = 0;
    var guard: usize = 0;
    while (true) {
        if (pos >= msg.len) return error.DNSFormatError;
        const len = msg[pos];
        if (len == 0) {
            break;
        } else if ((len & 0xC0) == 0xC0) {
            if (pos + 2 > msg.len) return error.DNSFormatError;
            const ptr = (@as(usize, len & 0x3F) << 8) | msg[pos + 1];
            pos = ptr;
            guard += 1;
            if (guard > 128) return error.DNSFormatError;
            continue;
        } else {
            if (out_pos != 0) {
                if (out_pos + 1 > out.len) return error.DNSFormatError;
                out[out_pos] = '.';
                out_pos += 1;
            }
            if (pos + 1 + len > msg.len) return error.DNSFormatError;
            if (out_pos + len > out.len) return error.DNSFormatError;
            @memcpy(out[out_pos .. out_pos + len], msg[pos + 1 .. pos + 1 + len]);
            out_pos += len;
            pos += 1 + len;
        }
    }
    return out_pos;
}

pub const MxHost = struct {
    preference: u16,
    host: []const u8,
};

/// Query MX records, returning exchange hosts sorted by preference (best
/// first). Caller owns the slice and each host string. An empty slice means
/// the domain has no MX records (implicit-MX rules apply, RFC 5321 §5.1).
pub fn dnsQueryMxRecords(allocator: std.mem.Allocator, name: []const u8) DnsError![]MxHost {
    const Collector = struct {
        list: *std.ArrayList(MxHost),
        allocator: std.mem.Allocator,

        fn onRr(self: *@This(), msg: []const u8, rdata: []const u8) anyerror!void {
            // MX RDATA: 2-byte preference + exchange name (may be compressed).
            if (rdata.len < 3) return;
            const pref = std.mem.readInt(u16, rdata[0..2], .big);
            const rdata_off = @intFromPtr(rdata.ptr) - @intFromPtr(msg.ptr);
            var namebuf: [256]u8 = undefined;
            const nlen = readNameInto(msg, rdata_off + 2, &namebuf) catch return;
            if (nlen == 0) return;
            const host = try self.allocator.dupe(u8, namebuf[0..nlen]);
            errdefer self.allocator.free(host);
            try self.list.append(self.allocator, .{ .preference = pref, .host = host });
        }
    };

    var ns_buf: [64]u8 = undefined;
    const ns = pickNameserver(&ns_buf);

    var list: std.ArrayList(MxHost) = .empty;
    errdefer {
        for (list.items) |h| allocator.free(h.host);
        list.deinit(allocator);
    }

    var collector = Collector{ .list = &list, .allocator = allocator };
    dnsQuery(name, DNS_TYPE_MX, ns, *Collector, &collector, Collector.onRr) catch |err| switch (err) {
        error.DNSNameError, error.DNSNoAnswer => {},
        else => return err,
    };

    std.mem.sort(MxHost, list.items, {}, struct {
        fn lessThan(_: void, a: MxHost, b: MxHost) bool {
            return a.preference < b.preference;
        }
    }.lessThan);

    return list.toOwnedSlice(allocator) catch return error.DNSTemporaryFailure;
}

/// Query MX records and resolve each exchange host's A records, appending the
/// IPv4 addresses to `out`.
fn dnsQueryMxAddrs(name: []const u8, out: *std.ArrayList([4]u8), allocator: std.mem.Allocator) DnsError!void {
    const Collector = struct {
        hosts: std.ArrayList([]const u8),
        allocator: std.mem.Allocator,

        fn onRr(self: *@This(), msg: []const u8, rdata: []const u8) anyerror!void {
            // MX RDATA: 2-byte preference + exchange name (may be compressed).
            if (rdata.len < 3) return;
            // rdata is a slice of msg; compute its absolute offset to resolve
            // compression pointers correctly.
            const rdata_off = @intFromPtr(rdata.ptr) - @intFromPtr(msg.ptr);
            var namebuf: [256]u8 = undefined;
            const nlen = readNameInto(msg, rdata_off + 2, &namebuf) catch return;
            if (nlen == 0) return;
            const host = try self.allocator.dupe(u8, namebuf[0..nlen]);
            try self.hosts.append(self.allocator, host);
        }
    };

    var ns_buf: [64]u8 = undefined;
    const ns = pickNameserver(&ns_buf);

    var collector = Collector{ .hosts = .empty, .allocator = allocator };
    defer {
        for (collector.hosts.items) |h| allocator.free(h);
        collector.hosts.deinit(allocator);
    }

    dnsQuery(name, DNS_TYPE_MX, ns, *Collector, &collector, Collector.onRr) catch |err| switch (err) {
        error.DNSNameError, error.DNSNoAnswer => {},
        else => return err,
    };

    for (collector.hosts.items) |host| {
        dnsQueryA(host, out, allocator) catch continue;
    }
}

// =============================================================================
// SPF (Sender Policy Framework) Implementation - RFC 7208
// =============================================================================
//
// ## Overview
// SPF is an email authentication method that allows domain owners to specify
// which mail servers are authorized to send email on behalf of their domain.
// This prevents email spoofing by verifying the sending server's IP address
// against the domain's published SPF record in DNS.
//
// ## Algorithm Flow
// 1. Extract the domain from the MAIL FROM address (or HELO if empty)
// 2. Query DNS for TXT records at the domain
// 3. Find the record starting with "v=spf1"
// 4. Evaluate each mechanism in order (left to right)
// 5. Return the result of the first matching mechanism (or default neutral)
//
// ## Mechanism Evaluation Order (RFC 7208 Section 4.6)
// Mechanisms are evaluated strictly in order. First match wins:
//
//   +all    → PASS      (IP is authorized)
//   -all    → FAIL      (IP is NOT authorized - reject)
//   ~all    → SOFTFAIL  (IP probably not authorized - accept but mark)
//   ?all    → NEUTRAL   (No policy assertion)
//
// ## Supported Mechanisms
// - `all`          : Matches all IPs (usually last, with qualifier)
// - `ip4:x.x.x.x`  : Match specific IPv4 address or CIDR range
// - `ip6:xxxx::xx` : Match specific IPv6 address or CIDR range
// - `a`            : Match if IP is in domain's A/AAAA records
// - `mx`           : Match if IP is in domain's MX records
// - `include:dom`  : Recursively check another domain's SPF
//
// ## CIDR Matching Algorithm
// For `ip4:192.168.1.0/24`:
// 1. Parse the IP address from the mechanism (192.168.1.0)
// 2. Parse the prefix length (24)
// 3. Create a bitmask: ~0 << (32 - prefix_len) = 0xFFFFFF00
// 4. Compare: (client_ip & mask) == (network_ip & mask)
//
// Example: Client IP 192.168.1.100 vs 192.168.1.0/24
//   Client:  192.168.1.100 = 0xC0A80164
//   Network: 192.168.1.0   = 0xC0A80100
//   Mask:    /24           = 0xFFFFFF00
//   Client & Mask  = 0xC0A80100
//   Network & Mask = 0xC0A80100  → MATCH!
//
// ## Security Considerations
// - Limit DNS lookups to 10 to prevent DoS (RFC 7208 Section 4.6.4)
// - Void lookups (failed DNS) count toward the limit
// - Handle DNS timeouts gracefully with TempError result
// =============================================================================

/// SPF validation result
pub const SPFResult = enum {
    none, // No SPF record found
    neutral, // Domain does not assert policy
    pass, // IP is authorized
    fail, // IP is not authorized
    softfail, // IP is probably not authorized
    temperror, // Temporary error during lookup
    permerror, // Permanent error in SPF record

    pub fn toString(self: SPFResult) []const u8 {
        return switch (self) {
            .none => "none",
            .neutral => "neutral",
            .pass => "pass",
            .fail => "fail",
            .softfail => "softfail",
            .temperror => "temperror",
            .permerror => "permerror",
        };
    }

    pub fn shouldAccept(self: SPFResult) bool {
        return switch (self) {
            .pass, .neutral, .none, .softfail => true,
            .fail, .temperror, .permerror => false,
        };
    }
};

/// SPF validator for incoming mail (RFC 7208)
pub const SPFValidator = struct {
    allocator: std.mem.Allocator,
    dns_timeout_ms: u32,

    pub fn init(allocator: std.mem.Allocator) SPFValidator {
        return .{
            .allocator = allocator,
            .dns_timeout_ms = 5000,
        };
    }

    /// Validate SPF for a given sender and IP
    /// Returns SPFResult indicating whether the IP is authorized
    pub fn validate(
        self: *SPFValidator,
        ip_addr: []const u8,
        mail_from: []const u8,
        helo_domain: []const u8,
    ) !SPFResult {
        // RFC 7208 §2.4: the checked identity is MAIL FROM; if it is empty
        // (e.g. bounce), fall back to the HELO domain.
        const domain = self.extractDomain(mail_from) orelse blk: {
            if (helo_domain.len == 0) return .none;
            break :blk helo_domain;
        };

        // DNS lookup budget (RFC 7208 §4.6.4): max 10 mechanism lookups.
        var lookups: u32 = 0;
        return self.checkHost(domain, ip_addr, &lookups) catch |err| switch (err) {
            error.DNSTemporaryFailure => .temperror,
            else => .permerror, // InvalidSPF, LookupLimitExceeded, OOM, etc.
        };
    }

    /// check_host() per RFC 7208 §4: query the SPF record for `domain` and
    /// evaluate its mechanisms against `ip_addr`.
    fn checkHost(self: *SPFValidator, domain: []const u8, ip_addr: []const u8, lookups: *u32) !SPFResult {
        const spf_record = dnsQueryTxt(self.allocator, domain, "v=spf1") catch |err| switch (err) {
            // Genuine DNS transient failures => SPF temperror; anything else
            // (NXDOMAIN, malformed answer, etc.) => treat as "no SPF record".
            error.DNSTimeout, error.DNSTemporaryFailure => return error.DNSTemporaryFailure,
            else => return .none,
        };
        defer if (spf_record) |record| self.allocator.free(record);

        if (spf_record == null) return .none;

        return self.evaluateSPF(spf_record.?, ip_addr, domain, lookups);
    }

    fn extractDomain(self: *SPFValidator, email: []const u8) ?[]const u8 {
        _ = self;
        const at_pos = std.mem.indexOf(u8, email, "@") orelse return null;
        if (at_pos + 1 >= email.len) return null;
        return email[at_pos + 1 ..];
    }

    fn evaluateSPF(self: *SPFValidator, record: []const u8, ip_addr: []const u8, domain: []const u8, lookups: *u32) !SPFResult {
        // Parse SPF mechanisms
        var mechanisms = std.mem.splitScalar(u8, record, ' ');

        // First should be version
        const version = mechanisms.next() orelse return error.InvalidSPF;
        if (!std.mem.eql(u8, version, "v=spf1")) {
            return error.InvalidSPF;
        }

        // Evaluate mechanisms in order
        while (mechanisms.next()) |mechanism| {
            const result = try self.evaluateMechanism(mechanism, ip_addr, domain, lookups);
            if (result != .neutral) {
                return result;
            }
        }

        // Default is neutral
        return .neutral;
    }

    // Explicit error set (anyerror) breaks the inferred-error-set dependency
    // loop between checkHost -> evaluateSPF -> evaluateMechanism -> checkHost.
    fn evaluateMechanism(self: *SPFValidator, mechanism: []const u8, ip_addr: []const u8, domain: []const u8, lookups: *u32) anyerror!SPFResult {
        const trimmed = std.mem.trim(u8, mechanism, " \t");
        if (trimmed.len == 0) return .neutral;

        // Ignore modifiers (e.g. redirect=, exp=); they contain '='.
        // A bare 'all'/ip4:/etc never contains '=' before the ':'.
        if (std.mem.indexOfScalar(u8, trimmed, '=')) |eq| {
            // Distinguish ip4:1.2.3.4 (no '=') from redirect=... ; modifiers
            // have '=' before any ':'. Skip them here (redirect handled below).
            const colon = std.mem.indexOfScalar(u8, trimmed, ':');
            if (colon == null or eq < colon.?) {
                // It's a modifier — handle redirect, ignore others.
                if (std.mem.startsWith(u8, trimmed, "redirect=")) {
                    const target = trimmed["redirect=".len..];
                    lookups.* += 1;
                    if (lookups.* > 10) return error.LookupLimitExceeded;
                    return self.checkHost(target, ip_addr, lookups);
                }
                return .neutral;
            }
        }

        // Parse qualifier (+ - ~ ?)
        var qualifier: u8 = '+';
        var mech = trimmed;

        if (trimmed[0] == '+' or trimmed[0] == '-' or trimmed[0] == '~' or trimmed[0] == '?') {
            qualifier = trimmed[0];
            mech = trimmed[1..];
        }

        // Evaluate mechanism type
        const is_match = blk: {
            if (std.mem.eql(u8, mech, "all")) {
                break :blk true;
            } else if (std.mem.startsWith(u8, mech, "ip4:")) {
                break :blk self.matchIPv4(ip_addr, mech[4..]);
            } else if (std.mem.startsWith(u8, mech, "ip6:")) {
                break :blk self.matchIPv6(ip_addr, mech[4..]);
            } else if (std.mem.eql(u8, mech, "a") or std.mem.startsWith(u8, mech, "a:") or std.mem.startsWith(u8, mech, "a/")) {
                lookups.* += 1;
                if (lookups.* > 10) return error.LookupLimitExceeded;
                break :blk try self.matchA(mech, ip_addr, domain);
            } else if (std.mem.eql(u8, mech, "mx") or std.mem.startsWith(u8, mech, "mx:") or std.mem.startsWith(u8, mech, "mx/")) {
                lookups.* += 1;
                if (lookups.* > 10) return error.LookupLimitExceeded;
                break :blk try self.matchMX(mech, ip_addr, domain);
            } else if (std.mem.startsWith(u8, mech, "include:")) {
                lookups.* += 1;
                if (lookups.* > 10) return error.LookupLimitExceeded;
                const inc_domain = mech["include:".len..];
                const inc_result = try self.checkHost(inc_domain, ip_addr, lookups);
                // RFC 7208 §5.2: include matches only on a 'pass' result.
                break :blk inc_result == .pass;
            } else {
                // Unknown mechanism — ignore (do not match).
                break :blk false;
            }
        };

        if (!is_match) {
            return .neutral;
        }

        // Return result based on qualifier
        return switch (qualifier) {
            '+' => .pass,
            '-' => .fail,
            '~' => .softfail,
            '?' => .neutral,
            else => .neutral,
        };
    }

    /// Parse an optional `/cidr` suffix and the target domain from an a/mx
    /// mechanism. Returns the (domain, prefix_len) where prefix_len is 32 if
    /// none specified. The `default_domain` is used when no explicit domain.
    fn parseDomainSpec(mech: []const u8, kind_len: usize, default_domain: []const u8) struct { domain: []const u8, prefix: u8 } {
        // mech examples: "a", "a:example.com", "a/24", "a:example.com/24"
        var rest = mech[kind_len..];
        var prefix: u8 = 32;
        if (std.mem.indexOfScalar(u8, rest, '/')) |slash| {
            prefix = std.fmt.parseInt(u8, rest[slash + 1 ..], 10) catch 32;
            rest = rest[0..slash];
        }
        var dom = default_domain;
        if (rest.len > 0 and rest[0] == ':') {
            dom = rest[1..];
        }
        return .{ .domain = dom, .prefix = prefix };
    }

    fn matchA(self: *SPFValidator, mech: []const u8, ip_addr: []const u8, domain: []const u8) !bool {
        const spec = parseDomainSpec(mech, 1, domain); // "a".len == 1
        var addrs: std.ArrayList([4]u8) = .empty;
        defer addrs.deinit(self.allocator);
        dnsQueryA(spec.domain, &addrs, self.allocator) catch return false;
        return self.matchAnyAddr(ip_addr, addrs.items, spec.prefix);
    }

    fn matchMX(self: *SPFValidator, mech: []const u8, ip_addr: []const u8, domain: []const u8) !bool {
        const spec = parseDomainSpec(mech, 2, domain); // "mx".len == 2
        var addrs: std.ArrayList([4]u8) = .empty;
        defer addrs.deinit(self.allocator);
        dnsQueryMxAddrs(spec.domain, &addrs, self.allocator) catch return false;
        return self.matchAnyAddr(ip_addr, addrs.items, spec.prefix);
    }

    fn matchAnyAddr(self: *SPFValidator, ip_addr: []const u8, addrs: []const [4]u8, prefix: u8) bool {
        for (addrs) |a| {
            var netbuf: [16]u8 = undefined;
            const net = std.fmt.bufPrint(&netbuf, "{d}.{d}.{d}.{d}", .{ a[0], a[1], a[2], a[3] }) catch continue;
            if (self.matchCIDR(ip_addr, net, prefix)) return true;
        }
        return false;
    }

    fn matchIPv6(self: *SPFValidator, ip_addr: []const u8, ip_spec: []const u8) bool {
        _ = self;
        var prefix_len: u8 = 128;
        var network = ip_spec;
        if (std.mem.indexOfScalar(u8, ip_spec, '/')) |slash_pos| {
            network = ip_spec[0..slash_pos];
            prefix_len = std.fmt.parseInt(u8, ip_spec[slash_pos + 1 ..], 10) catch return false;
        }

        const addr_bytes: [16]u8 = parseIp6(ip_addr) orelse return false;
        const net_bytes: [16]u8 = parseIp6(network) orelse return false;

        var bits_left: u16 = prefix_len;
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            if (bits_left == 0) break;
            if (bits_left >= 8) {
                if (addr_bytes[i] != net_bytes[i]) return false;
                bits_left -= 8;
            } else {
                const mask: u8 = @as(u8, 0xFF) << @intCast(8 - bits_left);
                if ((addr_bytes[i] & mask) != (net_bytes[i] & mask)) return false;
                bits_left = 0;
            }
        }
        return true;
    }

    fn matchIPv4(self: *SPFValidator, ip_addr: []const u8, ip_spec: []const u8) bool {
        // Handle CIDR notation (e.g., 192.168.1.0/24)
        if (std.mem.indexOf(u8, ip_spec, "/")) |slash_pos| {
            const network = ip_spec[0..slash_pos];
            const prefix_len_str = ip_spec[slash_pos + 1 ..];
            const prefix_len = std.fmt.parseInt(u8, prefix_len_str, 10) catch return false;

            return self.matchCIDR(ip_addr, network, prefix_len);
        }

        // Exact match
        return std.mem.eql(u8, ip_addr, ip_spec);
    }

    fn matchCIDR(self: *SPFValidator, ip_addr: []const u8, network: []const u8, prefix_len: u8) bool {
        _ = self;

        // Parse both addresses as IPv4 (host order).
        const addr_bits = parseIp4(ip_addr) orelse return false;
        const net_bits = parseIp4(network) orelse return false;

        // Create network mask (guard prefix_len to avoid shift overflow).
        const mask: u32 = if (prefix_len == 0) 0 else if (prefix_len >= 32) ~@as(u32, 0) else ~@as(u32, 0) << @intCast(32 - prefix_len);

        return (addr_bits & mask) == (net_bits & mask);
    }
};

/// SPF record builder for publishing
pub const SPFRecordBuilder = struct {
    mechanisms: std.ArrayList([]const u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) SPFRecordBuilder {
        return .{
            .mechanisms = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *SPFRecordBuilder) void {
        for (self.mechanisms.items) |mech| {
            self.allocator.free(mech);
        }
        self.mechanisms.deinit(self.allocator);
    }

    pub fn allowIP(self: *SPFRecordBuilder, ip: []const u8) !void {
        const mech = try std.fmt.allocPrint(self.allocator, "ip4:{s}", .{ip});
        try self.mechanisms.append(self.allocator, mech);
    }

    pub fn allowMX(self: *SPFRecordBuilder) !void {
        const mech = try self.allocator.dupe(u8, "mx");
        try self.mechanisms.append(self.allocator, mech);
    }

    pub fn allowA(self: *SPFRecordBuilder) !void {
        const mech = try self.allocator.dupe(u8, "a");
        try self.mechanisms.append(self.allocator, mech);
    }

    pub fn includeDomain(self: *SPFRecordBuilder, domain: []const u8) !void {
        const mech = try std.fmt.allocPrint(self.allocator, "include:{s}", .{domain});
        try self.mechanisms.append(self.allocator, mech);
    }

    pub fn setAll(self: *SPFRecordBuilder, policy: SPFResult) !void {
        const qualifier: []const u8 = switch (policy) {
            .pass => "+",
            .fail => "-",
            .softfail => "~",
            .neutral => "?",
            else => "?",
        };
        const mech = try std.fmt.allocPrint(self.allocator, "{s}all", .{qualifier});
        try self.mechanisms.append(self.allocator, mech);
    }

    pub fn build(self: *SPFRecordBuilder) ![]const u8 {
        var record: std.ArrayList(u8) = .empty;
        defer record.deinit(self.allocator);

        try record.appendSlice(self.allocator, "v=spf1");

        for (self.mechanisms.items) |mech| {
            try record.appendSlice(self.allocator, " ");
            try record.appendSlice(self.allocator, mech);
        }

        return try record.toOwnedSlice(self.allocator);
    }
};

test "SPF result conversion" {
    const testing = std.testing;

    try testing.expectEqualStrings("pass", SPFResult.pass.toString());
    try testing.expectEqualStrings("fail", SPFResult.fail.toString());

    try testing.expect(SPFResult.pass.shouldAccept());
    try testing.expect(!SPFResult.fail.shouldAccept());
}

test "SPF domain extraction" {
    const testing = std.testing;
    var validator = SPFValidator.init(testing.allocator);

    const domain = validator.extractDomain("user@example.com");
    try testing.expectEqualStrings("example.com", domain.?);
}

test "SPF IPv4 CIDR matching" {
    const testing = std.testing;
    var validator = SPFValidator.init(testing.allocator);

    // Same network
    try testing.expect(validator.matchCIDR("192.168.1.100", "192.168.1.0", 24));

    // Different network
    try testing.expect(!validator.matchCIDR("192.168.2.100", "192.168.1.0", 24));

    // Exact match with /32
    try testing.expect(validator.matchCIDR("192.168.1.100", "192.168.1.100", 32));
}

test "SPF record builder" {
    const testing = std.testing;
    var builder = SPFRecordBuilder.init(testing.allocator);
    defer builder.deinit();

    try builder.allowIP("192.168.1.1");
    try builder.allowMX();
    try builder.setAll(.softfail);

    const record = try builder.build();
    defer testing.allocator.free(record);

    try testing.expectEqualStrings("v=spf1 ip4:192.168.1.1 mx ~all", record);
}
