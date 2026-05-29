const std = @import("std");
const io_compat = @import("../core/io_compat.zig");
const time_compat = @import("../core/time_compat.zig");
const config = @import("../core/config.zig");

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
    switch (delivery_method) {
        .direct => try deliverDirect(allocator, from, to, message_data, our_hostname),
        .ses => try deliverViaSes(allocator, from, to, message_data, ses_region),
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

    // Look up MX records using dig
    const mx_host = try lookupMx(allocator, domain);
    defer allocator.free(mx_host);

    // The MX hostname is used inside a shell command (and getaddrinfo); reject
    // anything outside the DNS hostname character set to prevent injection.
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

    // Connect to MX server on port 25
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

    // Read greeting (220)
    const greeting_len = readResponse(sock, &recv_buf) catch {
        return error.SmtpGreetingFailed;
    };
    if (greeting_len < 3 or !std.mem.startsWith(u8, recv_buf[0..greeting_len], "220")) {
        std.log.err("MX server {s} greeting not 220: {s}", .{ mx_host, recv_buf[0..@min(greeting_len, 100)] });
        return error.SmtpGreetingFailed;
    }

    // Send EHLO
    const ehlo_cmd = try std.fmt.allocPrint(allocator, "EHLO {s}\r\n", .{our_hostname});
    defer allocator.free(ehlo_cmd);
    try sendAll(sock, ehlo_cmd);

    const ehlo_len = readResponse(sock, &recv_buf) catch {
        return error.SmtpEhloFailed;
    };
    if (ehlo_len < 3 or !std.mem.startsWith(u8, recv_buf[0..ehlo_len], "250")) {
        // Try HELO fallback
        const helo_cmd = try std.fmt.allocPrint(allocator, "HELO {s}\r\n", .{our_hostname});
        defer allocator.free(helo_cmd);
        try sendAll(sock, helo_cmd);

        const helo_len = readResponse(sock, &recv_buf) catch {
            return error.SmtpHeloFailed;
        };
        if (helo_len < 3 or !std.mem.startsWith(u8, recv_buf[0..helo_len], "250")) {
            return error.SmtpHeloFailed;
        }
    }

    // MAIL FROM
    const mail_cmd = try std.fmt.allocPrint(allocator, "MAIL FROM:<{s}>\r\n", .{from});
    defer allocator.free(mail_cmd);
    try sendAll(sock, mail_cmd);

    const mail_len = readResponse(sock, &recv_buf) catch {
        return error.SmtpMailFromFailed;
    };
    if (mail_len < 3 or !std.mem.startsWith(u8, recv_buf[0..mail_len], "250")) {
        std.log.err("MAIL FROM rejected by {s}: {s}", .{ mx_host, recv_buf[0..@min(mail_len, 100)] });
        return error.SmtpMailFromFailed;
    }

    // RCPT TO
    const rcpt_cmd = try std.fmt.allocPrint(allocator, "RCPT TO:<{s}>\r\n", .{to});
    defer allocator.free(rcpt_cmd);
    try sendAll(sock, rcpt_cmd);

    const rcpt_len = readResponse(sock, &recv_buf) catch {
        return error.SmtpRcptToFailed;
    };
    if (rcpt_len < 3 or !std.mem.startsWith(u8, recv_buf[0..rcpt_len], "250")) {
        std.log.err("RCPT TO rejected by {s}: {s}", .{ mx_host, recv_buf[0..@min(rcpt_len, 100)] });
        return error.SmtpRcptToFailed;
    }

    // DATA
    try sendAll(sock, "DATA\r\n");

    const data_len = readResponse(sock, &recv_buf) catch {
        return error.SmtpDataFailed;
    };
    if (data_len < 3 or !std.mem.startsWith(u8, recv_buf[0..data_len], "354")) {
        std.log.err("DATA rejected by {s}: {s}", .{ mx_host, recv_buf[0..@min(data_len, 100)] });
        return error.SmtpDataFailed;
    }

    // Normalize line endings to CRLF and re-apply dot-stuffing before sending
    // the body downstream. The body was reassembled internally with bare LF
    // and without transparency, so sending it raw would enable SMTP smuggling.
    const smtp_body = try normalizeForSmtp(allocator, raw_message);
    defer allocator.free(smtp_body);

    // Send message content
    try sendAll(sock, smtp_body);

    // Ensure message ends with \r\n.\r\n (normalizeForSmtp guarantees CRLF
    // line endings, so we only need to add the terminator when missing).
    if (!std.mem.endsWith(u8, smtp_body, "\r\n")) {
        try sendAll(sock, "\r\n");
    }
    try sendAll(sock, ".\r\n");

    const result_len = readResponse(sock, &recv_buf) catch {
        return error.SmtpDataFailed;
    };
    if (result_len < 3 or !std.mem.startsWith(u8, recv_buf[0..result_len], "250")) {
        std.log.err("Message rejected by {s}: {s}", .{ mx_host, recv_buf[0..@min(result_len, 100)] });
        return error.SmtpDeliveryRejected;
    }

    // QUIT (best effort, socket closed by defer)
    _ = sendAll(sock, "QUIT\r\n") catch {};

    std.log.info("Email delivered to {s} via direct SMTP to {s}", .{ to, mx_host });
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

/// Read a complete SMTP response (handles multi-line responses).
/// Multi-line responses use "code-text\r\n" for continuation and "code text\r\n" for the final line.
fn readResponse(sock: std.posix.socket_t, buf: []u8) !usize {
    var total: usize = 0;
    while (total < buf.len) {
        const n = std.c.read(sock, buf[total..].ptr, buf.len - total);
        if (n <= 0) {
            if (total > 0) return total;
            return error.SocketReadFailed;
        }
        total += @intCast(n);

        // Check if we have a complete final line ending with \r\n
        if (total >= 5 and buf[total - 1] == '\n' and buf[total - 2] == '\r') {
            // Find the start of the last line
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
            // Final line has "code space" (not "code dash")
            if (last_line_start + 3 < total and buf[last_line_start + 3] == ' ') {
                return total;
            }
        }
    }
    return total;
}

/// Look up MX records for a domain using the dig command.
/// Returns the highest-priority MX hostname.
fn lookupMx(allocator: std.mem.Allocator, domain: []const u8) ![]u8 {
    // The domain is interpolated into a /bin/sh command, so it must only
    // contain DNS hostname characters to prevent shell injection.
    if (!isSafeHostname(domain)) {
        std.log.err("Refusing MX lookup: unsafe domain", .{});
        return error.MxResolutionFailed;
    }

    const io = io_compat.getIo();
    const timestamp = time_compat.milliTimestamp();

    // Write dig output to a temp file since we can't capture stdout directly
    const tmp_path = try std.fmt.allocPrint(allocator, "/tmp/mx-lookup-{d}.txt", .{timestamp});
    defer allocator.free(tmp_path);

    const shell_cmd = try std.fmt.allocPrint(allocator, "dig +short MX {s} > {s} 2>/dev/null", .{ domain, tmp_path });
    defer allocator.free(shell_cmd);

    const shell_cmd_z = try allocator.dupeZ(u8, shell_cmd);
    defer allocator.free(shell_cmd_z);

    // Use /bin/sh -c to run the command with shell redirection
    var child = std.process.spawn(io, .{
        .argv = &[_][]const u8{ "/bin/sh", "-c", shell_cmd },
    }) catch {
        return try allocator.dupe(u8, domain);
    };

    _ = child.wait(io) catch {};

    // Read the temp file
    const tmp_path_z = try allocator.dupeZ(u8, tmp_path);
    defer allocator.free(tmp_path_z);

    const fd = std.c.open(tmp_path_z.ptr, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, @as(std.c.mode_t, 0));
    defer {
        _ = std.c.unlink(tmp_path_z.ptr);
    }
    if (fd < 0) return try allocator.dupe(u8, domain);
    defer _ = std.c.close(fd);

    var stdout_buf: [4096]u8 = undefined;
    var stdout_len: usize = 0;
    while (stdout_len < stdout_buf.len) {
        const n = std.c.read(fd, stdout_buf[stdout_len..].ptr, stdout_buf.len - stdout_len);
        if (n <= 0) break;
        stdout_len += @intCast(n);
    }

    if (stdout_len == 0) {
        return try allocator.dupe(u8, domain);
    }

    // Parse MX output: "priority hostname\n" — pick lowest priority (highest preference)
    // Example: "10 alt1.aspmx.l.google.com.\n20 alt2.aspmx.l.google.com.\n"
    const output = stdout_buf[0..stdout_len];
    var best_priority: u32 = std.math.maxInt(u32);
    var best_host: ?[]const u8 = null;

    var line_iter = std.mem.splitScalar(u8, output, '\n');
    while (line_iter.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        if (trimmed.len == 0) continue;

        // Parse "priority hostname"
        const space_pos = std.mem.indexOfScalar(u8, trimmed, ' ') orelse continue;
        const priority = std.fmt.parseInt(u32, trimmed[0..space_pos], 10) catch continue;
        var hostname = std.mem.trim(u8, trimmed[space_pos + 1 ..], " \t");

        // Remove trailing dot from DNS name
        if (hostname.len > 0 and hostname[hostname.len - 1] == '.') {
            hostname = hostname[0 .. hostname.len - 1];
        }

        if (hostname.len > 0 and priority < best_priority) {
            best_priority = priority;
            best_host = hostname;
        }
    }

    if (best_host) |host| {
        return try allocator.dupe(u8, host);
    }

    return try allocator.dupe(u8, domain);
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
