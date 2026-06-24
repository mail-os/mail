const std = @import("std");
const io_compat = @import("../core/io_compat.zig");
const time_compat = @import("../core/time_compat.zig");
const config = @import("../core/config.zig");
const dkim_sign = @import("../antispam/dkim_sign.zig");
const spf = @import("../antispam/spf.zig");
const dns_cache = @import("../antispam/dns_cache.zig");
const socket_compat = @import("../core/socket_compat.zig");
const smtp_tls = @import("smtp_tls.zig");

/// SMTP I/O transport: either a plain socket fd or a STARTTLS-upgraded stream.
/// Lets the linear SMTP conversation run unchanged over both.
const Transport = union(enum) {
    plain: std.posix.socket_t,
    tls: *smtp_tls.Stream,

    fn writeAll(self: Transport, data: []const u8) !void {
        switch (self) {
            .plain => |fd| try sendAll(fd, data),
            .tls => |s| try s.writeAll(data),
        }
    }

    fn readChunk(self: Transport, buf: []u8) !usize {
        switch (self) {
            .plain => |fd| {
                const n = std.c.read(fd, buf.ptr, buf.len);
                if (n <= 0) return error.SocketReadFailed;
                return @intCast(n);
            },
            .tls => |s| {
                const n = try s.read(buf);
                if (n == 0) return error.SocketReadFailed;
                return n;
            },
        }
    }
};

/// Read a complete (possibly multi-line) SMTP reply over a Transport. The final
/// line is "code<space>…"; continuation lines are "code-…".
fn readReply(t: Transport, buf: []u8) !usize {
    var total: usize = 0;
    while (total < buf.len) {
        total += try t.readChunk(buf[total..]);
        if (total >= 5 and buf[total - 1] == '\n' and buf[total - 2] == '\r') {
            var last_line_start: usize = 0;
            if (total > 2) {
                var j: usize = total - 3;
                while (j > 0) : (j -= 1) {
                    if (buf[j] == '\n') {
                        last_line_start = j + 1;
                        break;
                    }
                }
            }
            if (last_line_start + 3 < total and buf[last_line_start + 3] == ' ') return total;
        }
    }
    return total;
}

/// Case-insensitive substring search (for spotting "STARTTLS" in an EHLO reply).
fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or haystack.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

/// Process-wide outbound DKIM signers, selected per-message by the envelope
/// sender's domain so each hosted domain signs with its own key (for DMARC
/// alignment). Built once at startup (before delivery workers spawn) via
/// configureDkim; read-only afterward, so no locking is needed. The first
/// registered signer is the primary fallback for domains without their own key
/// (preserving the legacy single-domain behaviour).
const max_dkim_signers = 32;
var g_dkim_signers: [max_dkim_signers]dkim_sign.Signer = undefined;
var g_dkim_count: usize = 0;

/// Register an outbound DKIM signer for `domain`. `domain`/`selector` must
/// outlive the process (pass env-backed slices). `pem` is a PKCS#1 RSA private
/// key; it is parsed and not retained. A duplicate domain or a full table is
/// silently ignored. Returns an error only if the key can't be parsed.
pub fn configureDkim(domain: []const u8, selector: []const u8, pem: []const u8) !void {
    if (g_dkim_count >= max_dkim_signers) return;
    if (dkimSignerFor(domain) != null) return;
    g_dkim_signers[g_dkim_count] = try dkim_sign.Signer.initFromPem(domain, selector, pem);
    g_dkim_count += 1;
}

/// Find the signer registered for `domain` (case-insensitive), if any.
fn dkimSignerFor(domain: []const u8) ?*dkim_sign.Signer {
    var i: usize = 0;
    while (i < g_dkim_count) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(g_dkim_signers[i].domain, domain)) return &g_dkim_signers[i];
    }
    return null;
}

/// Pick the DKIM signer for an envelope sender: the domain's own signer if it
/// has one, else the primary (first-registered) signer, else none.
fn selectDkimSigner(from: []const u8) ?*dkim_sign.Signer {
    const from_domain: []const u8 = if (std.mem.indexOfScalar(u8, from, '@')) |at| from[at + 1 ..] else "";
    if (dkimSignerFor(from_domain)) |s| return s;
    if (g_dkim_count > 0) return &g_dkim_signers[0];
    return null;
}

/// Reject email addresses that contain CR, LF, control characters, double
/// quotes, or backslashes. These could be used for SMTP command injection
/// (CRLF) or JSON injection (quotes/backslashes) when interpolated into
/// downstream commands or JSON payloads.
fn isSafeAddress(addr: []const u8) bool {
    if (addr.len == 0) return false;
    for (addr) |c| {
        if (c < 0x20 or c == 0x7f) return false; // control chars (incl. CR/LF)
        if (c == '"' or c == '\\') return false; // JSON / quoting hazards
    }
    return true;
}

/// Validate an MX hostname before using it in a shell command. Only allow
/// characters valid in DNS hostnames ([A-Za-z0-9.-]) to prevent shell
/// injection via the `dig` invocation.
fn isSafeHostname(host: []const u8) bool {
    if (host.len == 0 or host.len > 253) return false;
    for (host) |c| {
        const ok = (c >= 'A' and c <= 'Z') or
            (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or
            c == '.' or c == '-';
        if (!ok) return false;
    }
    return true;
}

/// Normalize a message body for SMTP transmission: convert bare LF/CR line
/// endings to CRLF and re-apply dot-stuffing (RFC 5321 section 4.5.2) by
/// prepending '.' to any line that begins with '.'. The returned buffer is
/// owned by the caller and must be freed with `allocator.free`.
fn normalizeForSmtp(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var i: usize = 0;
    var at_line_start = true;
    while (i < data.len) {
        const c = data[i];
        if (c == '\r') {
            // Treat CRLF or bare CR as a line terminator.
            if (i + 1 < data.len and data[i + 1] == '\n') {
                i += 1;
            }
            try out.appendSlice(allocator, "\r\n");
            i += 1;
            at_line_start = true;
            continue;
        }
        if (c == '\n') {
            try out.appendSlice(allocator, "\r\n");
            i += 1;
            at_line_start = true;
            continue;
        }
        // Dot-stuffing: a line starting with '.' gets an extra leading '.'.
        if (at_line_start and c == '.') {
            try out.append(allocator, '.');
        }
        try out.append(allocator, c);
        at_line_start = false;
        i += 1;
    }

    return out.toOwnedSlice(allocator);
}

/// Outbound email delivery with configurable method.
///
/// Supports two delivery methods:
/// - `ses`: Relay through AWS SES (works when outbound port 25 is blocked, e.g., on EC2)
/// - `direct`: Direct MX delivery (requires outbound port 25 access)
///
/// Deliver an email to a remote recipient using the configured method.
pub fn deliverToRemote(
    allocator: std.mem.Allocator,
    from: []const u8,
    to: []const u8,
    message_data: []const u8,
    our_hostname: []const u8,
    delivery_method: config.DeliveryMethod,
    ses_region: []const u8,
) !void {
    // Reject addresses containing CR/LF/control/quote chars before they are
    // interpolated into SMTP commands or JSON payloads downstream.
    if (!isSafeAddress(from) or !isSafeAddress(to)) {
        std.log.err("Refusing delivery: unsafe characters in envelope address", .{});
        return error.InvalidAddress;
    }

    // DKIM-sign with the sender domain's key if configured (best-effort: never
    // block delivery on a sign error).
    var signed: ?[]u8 = null;
    defer if (signed) |s| allocator.free(s);
    var msg = message_data;
    if (selectDkimSigner(from)) |signer| {
        if (signer.buildHeader(allocator, message_data, time_compat.timestamp())) |hdr| {
            defer allocator.free(hdr);
            if (std.mem.concat(allocator, u8, &.{ hdr, message_data })) |combined| {
                signed = combined;
                msg = combined;
            } else |_| {}
        } else |err| {
            std.log.warn("DKIM signing failed ({s}); sending unsigned", .{@errorName(err)});
        }
    }

    switch (delivery_method) {
        .direct => try deliverDirect(allocator, from, to, msg, our_hostname),
        .ses => try deliverViaSes(allocator, from, to, msg, ses_region),
    }
}

/// Direct SMTP delivery: look up MX records and deliver to the recipient's mail server.
fn deliverDirect(
    allocator: std.mem.Allocator,
    from: []const u8,
    to: []const u8,
    message_data: []const u8,
    our_hostname: []const u8,
) !void {
    // Extract domain from recipient address
    const at_pos = std.mem.indexOf(u8, to, "@") orelse return error.InvalidRecipient;
    const domain = to[at_pos + 1 ..];

    // Look up MX records
    const mx_host = try lookupMx(allocator, domain);
    defer allocator.free(mx_host);

    // The MX hostname is used inside getaddrinfo / SNI; reject anything outside
    // the DNS hostname character set to prevent injection.
    if (!isSafeHostname(mx_host)) {
        std.log.err("Refusing delivery: unsafe MX hostname", .{});
        return error.MxResolutionFailed;
    }

    std.log.info("Direct delivery to {s} via MX: {s}", .{ to, mx_host });

    // Build the full RFC 5322 message if not already present
    var raw_message: []const u8 = message_data;
    var owned_message: ?[]u8 = null;
    defer if (owned_message) |m| allocator.free(m);

    if (!hasHeader(message_data, "From:")) {
        owned_message = try std.fmt.allocPrint(allocator, "From: {s}\r\nTo: {s}\r\n{s}", .{ from, to, message_data });
        raw_message = owned_message.?;
    }

    // Prefer STARTTLS. Receivers (notably Gmail) penalize cleartext SMTP, so we
    // upgrade the connection whenever the MX advertises STARTTLS. If the TLS
    // handshake itself fails after we've committed to STARTTLS, the connection
    // can't be reused for cleartext — reconnect once and deliver unencrypted
    // rather than drop the message (opportunistic-TLS semantics).
    deliverOnce(allocator, from, to, raw_message, our_hostname, mx_host, true) catch |err| {
        if (err == error.TlsHandshakeFallback) {
            std.log.warn("STARTTLS to {s} failed; retrying delivery in cleartext", .{mx_host});
            return deliverOnce(allocator, from, to, raw_message, our_hostname, mx_host, false);
        }
        return err;
    };
}

/// One delivery attempt to `mx_host` on port 25. When `attempt_tls` is set and
/// the server advertises STARTTLS, the connection is upgraded before MAIL FROM.
/// Returns error.TlsHandshakeFallback when STARTTLS was negotiated (server said
/// 220) but the TLS handshake failed, so the caller can retry in cleartext on a
/// fresh connection.
fn deliverOnce(
    allocator: std.mem.Allocator,
    from: []const u8,
    to: []const u8,
    raw_message: []const u8,
    our_hostname: []const u8,
    mx_host: []const u8,
    attempt_tls: bool,
) !void {
    const mx_host_z = try allocator.dupeZ(u8, mx_host);
    defer allocator.free(mx_host_z);

    // Resolve hostname to IP using getaddrinfo
    const hints = std.mem.zeroInit(std.c.addrinfo, .{
        .family = std.posix.AF.INET,
        .socktype = std.posix.SOCK.STREAM,
    });

    var result: ?*std.c.addrinfo = null;
    const gai_ret = std.c.getaddrinfo(mx_host_z.ptr, "25", &hints, &result);
    if (@intFromEnum(gai_ret) != 0 or result == null) {
        std.log.err("Failed to resolve MX host {s}", .{mx_host});
        return error.MxResolutionFailed;
    }
    defer std.c.freeaddrinfo(result.?);

    // Create socket and connect (use libc API like socket_compat.zig)
    const family: c_uint = @intCast(std.posix.AF.INET);
    const sock_type: c_uint = @intCast(@as(u32, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC));
    const raw_fd = std.c.socket(family, sock_type, 0);
    if (raw_fd < 0) return error.SocketCreateFailed;
    const sock: std.posix.socket_t = @intCast(raw_fd);
    defer _ = std.c.close(sock);

    // Set socket timeout (30 seconds)
    const tv: std.posix.timeval = .{ .sec = 30, .usec = 0 };
    std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch {};

    if (std.c.connect(sock, result.?.addr.?, result.?.addrlen) < 0) {
        std.log.err("Failed to connect to MX host {s}:25", .{mx_host});
        return error.MxConnectFailed;
    }

    // SMTP conversation
    var recv_buf: [4096]u8 = undefined;
    var transport: Transport = .{ .plain = sock };
    var tls_stream: smtp_tls.Stream = undefined;
    var used_tls = false;

    // Read greeting (220)
    const greeting_len = readReply(transport, &recv_buf) catch return error.SmtpGreetingFailed;
    if (greeting_len < 3 or !std.mem.startsWith(u8, recv_buf[0..greeting_len], "220")) {
        std.log.err("MX server {s} greeting not 220: {s}", .{ mx_host, recv_buf[0..@min(greeting_len, 100)] });
        return error.SmtpGreetingFailed;
    }

    // EHLO (cleartext) — note whether STARTTLS is on offer.
    const ehlo_len = try ehlo(allocator, transport, our_hostname, &recv_buf);
    const starttls_offered = containsIgnoreCase(recv_buf[0..ehlo_len], "STARTTLS");

    // STARTTLS upgrade (RFC 3207).
    if (attempt_tls and starttls_offered) {
        try transport.writeAll("STARTTLS\r\n");
        const st_len = readReply(transport, &recv_buf) catch return error.SmtpStartTlsFailed;
        if (st_len >= 3 and std.mem.startsWith(u8, recv_buf[0..st_len], "220")) {
            tls_stream = smtp_tls.clientHandshake(socket_compat.Connection{ .fd = sock }, mx_host) catch {
                // We already sent STARTTLS; this socket can't fall back to
                // cleartext. Ask the caller to reconnect plaintext.
                return error.TlsHandshakeFallback;
            };
            transport = .{ .tls = &tls_stream };
            used_tls = true;
            // Re-EHLO over the encrypted channel (the prior EHLO is discarded).
            _ = try ehlo(allocator, transport, our_hostname, &recv_buf);
        } else {
            std.log.warn("STARTTLS refused by {s} after advertising it: {s}", .{ mx_host, recv_buf[0..@min(st_len, 100)] });
            // Continue cleartext on the same connection.
        }
    }

    // MAIL FROM
    {
        const cmd = try std.fmt.allocPrint(allocator, "MAIL FROM:<{s}>\r\n", .{from});
        defer allocator.free(cmd);
        try transport.writeAll(cmd);
        const n = readReply(transport, &recv_buf) catch return error.SmtpMailFromFailed;
        if (n < 3 or !std.mem.startsWith(u8, recv_buf[0..n], "250")) {
            std.log.err("MAIL FROM rejected by {s}: {s}", .{ mx_host, recv_buf[0..@min(n, 100)] });
            return error.SmtpMailFromFailed;
        }
    }

    // RCPT TO
    {
        const cmd = try std.fmt.allocPrint(allocator, "RCPT TO:<{s}>\r\n", .{to});
        defer allocator.free(cmd);
        try transport.writeAll(cmd);
        const n = readReply(transport, &recv_buf) catch return error.SmtpRcptToFailed;
        if (n < 3 or !std.mem.startsWith(u8, recv_buf[0..n], "250")) {
            std.log.err("RCPT TO rejected by {s}: {s}", .{ mx_host, recv_buf[0..@min(n, 100)] });
            return error.SmtpRcptToFailed;
        }
    }

    // DATA
    try transport.writeAll("DATA\r\n");
    {
        const n = readReply(transport, &recv_buf) catch return error.SmtpDataFailed;
        if (n < 3 or !std.mem.startsWith(u8, recv_buf[0..n], "354")) {
            std.log.err("DATA rejected by {s}: {s}", .{ mx_host, recv_buf[0..@min(n, 100)] });
            return error.SmtpDataFailed;
        }
    }

    // Normalize line endings to CRLF and re-apply dot-stuffing before sending
    // the body downstream. The body was reassembled internally with bare LF
    // and without transparency, so sending it raw would enable SMTP smuggling.
    const smtp_body = try normalizeForSmtp(allocator, raw_message);
    defer allocator.free(smtp_body);

    try transport.writeAll(smtp_body);

    // Ensure message ends with \r\n.\r\n (normalizeForSmtp guarantees CRLF
    // line endings, so we only need to add the terminator when missing).
    if (!std.mem.endsWith(u8, smtp_body, "\r\n")) {
        try transport.writeAll("\r\n");
    }
    try transport.writeAll(".\r\n");

    {
        const n = readReply(transport, &recv_buf) catch return error.SmtpDataFailed;
        if (n < 3 or !std.mem.startsWith(u8, recv_buf[0..n], "250")) {
            std.log.err("Message rejected by {s}: {s}", .{ mx_host, recv_buf[0..@min(n, 100)] });
            return error.SmtpDeliveryRejected;
        }
    }

    // QUIT (best effort, socket closed by defer)
    transport.writeAll("QUIT\r\n") catch {};

    std.log.info("Email delivered to {s} via direct SMTP to {s} ({s})", .{
        to, mx_host, if (used_tls) "STARTTLS" else "cleartext",
    });
}

/// Send EHLO (with a HELO fallback) and require a 250. Returns the byte length
/// of the reply left in `recv_buf` so the caller can scan it for capabilities.
fn ehlo(allocator: std.mem.Allocator, transport: Transport, our_hostname: []const u8, recv_buf: []u8) !usize {
    const ehlo_cmd = try std.fmt.allocPrint(allocator, "EHLO {s}\r\n", .{our_hostname});
    defer allocator.free(ehlo_cmd);
    try transport.writeAll(ehlo_cmd);
    const ehlo_len = readReply(transport, recv_buf) catch return error.SmtpEhloFailed;
    if (ehlo_len >= 3 and std.mem.startsWith(u8, recv_buf[0..ehlo_len], "250")) return ehlo_len;

    // HELO fallback for non-ESMTP servers.
    const helo_cmd = try std.fmt.allocPrint(allocator, "HELO {s}\r\n", .{our_hostname});
    defer allocator.free(helo_cmd);
    try transport.writeAll(helo_cmd);
    const helo_len = readReply(transport, recv_buf) catch return error.SmtpHeloFailed;
    if (helo_len < 3 or !std.mem.startsWith(u8, recv_buf[0..helo_len], "250")) return error.SmtpHeloFailed;
    return helo_len;
}

/// Send all bytes over a socket.
fn sendAll(sock: std.posix.socket_t, data: []const u8) !void {
    var sent: usize = 0;
    while (sent < data.len) {
        const n = std.c.write(sock, data[sent..].ptr, data.len - sent);
        if (n <= 0) return error.SocketWriteFailed;
        sent += @intCast(n);
    }
}

/// Look up MX records for a domain using the built-in DNS resolver (in-process
/// UDP query with a 5s timeout — replaces shelling out to `dig` via a temp
/// file, which blocked a delivery worker on process spawn + disk I/O per
/// message). Returns the best-preference MX hostname, or the domain itself
/// when no MX exists (implicit MX, RFC 5321 §5.1). Results are cached.
fn lookupMx(allocator: std.mem.Allocator, domain: []const u8) ![]u8 {
    // Sanity-check that the value looks like a hostname before resolving it.
    if (!isSafeHostname(domain)) {
        std.log.err("Refusing MX lookup: unsafe domain", .{});
        return error.MxResolutionFailed;
    }

    var key_buf: [320]u8 = undefined;
    const cache_key: ?[]const u8 = std.fmt.bufPrint(&key_buf, "mx:{s}", .{domain}) catch null;
    if (cache_key) |key| {
        switch (dns_cache.get(allocator, key)) {
            .hit => |v| return v,
            .negative => return try allocator.dupe(u8, domain),
            .miss => {},
        }
    }

    const records = spf.dnsQueryMxRecords(allocator, domain) catch {
        // Transient DNS failure: fall back to the implicit MX (the domain),
        // matching the old dig-based behavior. Not cached.
        return try allocator.dupe(u8, domain);
    };
    defer {
        for (records) |r| allocator.free(r.host);
        allocator.free(records);
    }

    if (records.len == 0) {
        if (cache_key) |key| dns_cache.put(key, null, dns_cache.negative_ttl);
        return try allocator.dupe(u8, domain);
    }

    if (cache_key) |key| dns_cache.put(key, records[0].host, dns_cache.positive_ttl);
    return try allocator.dupe(u8, records[0].host);
}

/// Deliver an email via AWS SES.
/// Base64-encodes the raw message, writes a JSON input file, and calls
/// `aws ses send-raw-email --cli-input-json`.
fn deliverViaSes(
    allocator: std.mem.Allocator,
    from: []const u8,
    to: []const u8,
    message_data: []const u8,
    ses_region: []const u8,
) !void {
    // Build the full RFC 5322 message if not already present.
    var raw_message: []const u8 = message_data;
    var owned_message: ?[]u8 = null;
    defer if (owned_message) |m| allocator.free(m);

    if (!hasHeader(message_data, "From:")) {
        owned_message = try std.fmt.allocPrint(allocator, "From: {s}\r\nTo: {s}\r\n{s}", .{ from, to, message_data });
        raw_message = owned_message.?;
    }

    // Base64-encode the raw message
    const encoder = std.base64.standard;
    const b64_len = encoder.Encoder.calcSize(raw_message.len);
    const b64_buf = try allocator.alloc(u8, b64_len);
    defer allocator.free(b64_buf);
    const b64_data = encoder.Encoder.encode(b64_buf, raw_message);

    // Build JSON input for AWS CLI. `from`/`to` are interpolated into the JSON
    // string, so they must not contain JSON-significant characters (quotes,
    // backslashes) or control characters that could break out of the string
    // and inject additional JSON fields. deliverToRemote already validates
    // these, but we re-check here as defense-in-depth since this function
    // builds untrusted-data JSON directly. b64_data is base64 and therefore
    // safe by construction.
    if (!isSafeAddress(from) or !isSafeAddress(to)) {
        std.log.err("Refusing SES delivery: unsafe characters in envelope address", .{});
        return error.InvalidAddress;
    }
    const json_input = try std.fmt.allocPrint(
        allocator,
        "{{\"Source\":\"{s}\",\"Destinations\":[\"{s}\"],\"RawMessage\":{{\"Data\":\"{s}\"}}}}",
        .{ from, to, b64_data },
    );
    defer allocator.free(json_input);

    // Write JSON to temp file
    const timestamp = time_compat.milliTimestamp();
    const tmp_path_z = try std.fmt.allocPrint(allocator, "/tmp/ses-input-{d}.json", .{timestamp});
    defer allocator.free(tmp_path_z);

    const path_z = try allocator.dupeZ(u8, tmp_path_z);
    defer allocator.free(path_z);

    const fd = std.c.open(path_z.ptr, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .TRUNC = true,
        .CLOEXEC = true,
    }, @as(std.c.mode_t, 0o644));
    if (fd < 0) return error.TempFileCreateFailed;

    var written: usize = 0;
    while (written < json_input.len) {
        const n = std.c.write(fd, json_input[written..].ptr, json_input.len - written);
        if (n <= 0) {
            _ = std.c.close(fd);
            return error.TempFileWriteFailed;
        }
        written += @intCast(n);
    }
    _ = std.c.close(fd);

    // Build file:// argument for AWS CLI
    const file_arg = try std.fmt.allocPrint(allocator, "file://{s}", .{tmp_path_z});
    defer allocator.free(file_arg);

    const io = io_compat.getIo();

    // Spawn `aws ses send-raw-email --cli-input-json file:///tmp/ses-input-{ts}.json`
    var child = try std.process.spawn(io, .{
        .argv = &[_][]const u8{
            "aws",            "ses",
            "send-raw-email", "--region",
            ses_region,       "--cli-input-json",
            file_arg,
        },
    });

    const term = try child.wait(io);

    // Clean up temp file
    _ = std.c.unlink(path_z.ptr);

    // Check exit status
    switch (term) {
        .exited => |code| {
            if (code != 0) {
                std.log.err("aws ses send-raw-email exited with code {d} for recipient {s}", .{ code, to });
                return error.SesDeliveryFailed;
            }
        },
        else => {
            std.log.err("aws ses send-raw-email terminated abnormally for recipient {s}", .{to});
            return error.SesDeliveryFailed;
        },
    }

    std.log.info("Email delivered to {s} via AWS SES", .{to});
}

/// Check if a message contains a specific header.
fn hasHeader(data: []const u8, header: []const u8) bool {
    var pos: usize = 0;
    while (pos < data.len) {
        if (pos + header.len <= data.len) {
            if (std.ascii.startsWithIgnoreCase(data[pos..], header)) {
                return true;
            }
        }

        // Find next line
        while (pos < data.len and data[pos] != '\n') : (pos += 1) {}
        pos += 1;

        // Empty line = end of headers
        if (pos < data.len and (data[pos] == '\n' or
            (pos + 1 < data.len and data[pos] == '\r' and data[pos + 1] == '\n')))
        {
            break;
        }
    }
    return false;
}
