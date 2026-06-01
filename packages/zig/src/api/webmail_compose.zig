//! Webmail outbound compose: build an RFC 5322 message and send it through the
//! SAME delivery path SMTP submission uses, so webmail mail is DKIM-signed and
//! delivered identically.
//!
//! Pipeline (mirrors src/core/protocol.zig saveMessage + outbound):
//!   1. Build the RFC 5322 message (headers + text/plain, or multipart/* with
//!      html and/or attachments). Generate Message-ID and Date.
//!   2. For each recipient: local domain -> write to that user's INBOX Maildir;
//!      remote -> outbound.deliverToRemote (which auto-DKIM-signs via the
//!      process-wide g_dkim signer configured at startup).
//!   3. Append a copy to the sender's Sent Maildir folder.
//!
//! Allocation: arena-friendly (the HTTP layer passes a per-request arena).
//! Security: address fields are validated for header injection (CR/LF) before
//! use; deliverToRemote also rejects unsafe envelope addresses as a backstop.

const std = @import("std");
const fs_compat = @import("../core/fs_compat.zig");
const time_compat = @import("../core/time_compat.zig");
const outbound = @import("../delivery/outbound.zig");
const core_config = @import("../core/config.zig");

pub const ComposeError = error{
    NoRecipients,
    InvalidAddress,
    InvalidHeader,
    BuildFailed,
};

/// Writer over an unmanaged ArrayList(u8) + arena (the unmanaged ArrayList in
/// this Zig has no `.writer(allocator)`). Mirrors the JsonWriter in webmail_http.
const W = struct {
    list: *std.ArrayList(u8),
    arena: std.mem.Allocator,
    fn writeAll(self: W, bytes: []const u8) !void {
        try self.list.appendSlice(self.arena, bytes);
    }
    fn print(self: W, comptime fmt: []const u8, args: anytype) !void {
        const s = try std.fmt.allocPrint(self.arena, fmt, args);
        try self.list.appendSlice(self.arena, s);
    }
};
fn writerFor(list: *std.ArrayList(u8), arena: std.mem.Allocator) W {
    return .{ .list = list, .arena = arena };
}

pub const Attachment = struct {
    filename: []const u8,
    content_type: []const u8,
    /// Raw (already-decoded) bytes of the attachment.
    data: []const u8,
};

pub const Message = struct {
    from: []const u8, // full address, e.g. "alice@mail.stacksjs.com"
    to: []const []const u8,
    cc: []const []const u8 = &.{},
    bcc: []const []const u8 = &.{},
    subject: []const u8 = "",
    text_body: []const u8 = "",
    html_body: []const u8 = "", // empty -> text-only
    in_reply_to: []const u8 = "", // Message-ID being replied to (optional)
    references: []const u8 = "", // References header value (optional)
    attachments: []const Attachment = &.{},
};

pub const SendConfig = struct {
    hostname: []const u8,
    delivery_method: core_config.DeliveryMethod,
    ses_region: []const u8,
    /// Local part of the sender (used for the Sent folder path).
    sender_user: []const u8,
};

pub const SendResult = struct {
    message_id: []const u8,
    delivered: usize, // recipients we attempted delivery for
};

/// A header VALUE must not contain CR/LF (header injection) and stays short
/// enough to be sane. Addresses additionally must not contain header-special
/// chars beyond what an address needs.
fn isSafeHeaderValue(v: []const u8) bool {
    for (v) |c| {
        if (c == '\r' or c == '\n' or c == 0) return false;
    }
    return true;
}

fn isSafeAddress(a: []const u8) bool {
    if (a.len == 0 or a.len > 320) return false;
    for (a) |c| {
        if (c == '\r' or c == '\n' or c == 0 or c == '"' or c == '<' or c == '>') return false;
    }
    // Must look like an address (one @, non-empty local/domain).
    const at = std.mem.indexOfScalar(u8, a, '@') orelse return false;
    if (at == 0 or at == a.len - 1) return false;
    if (std.mem.indexOfScalarPos(u8, a, at + 1, '@') != null) return false;
    return true;
}

/// RFC 5322 date, e.g. "Mon, 01 Jun 2026 10:00:00 +0000" (UTC).
fn formatDate(allocator: std.mem.Allocator, ts: i64) ![]const u8 {
    const days = [_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    const es: u64 = @intCast(@max(ts, 0));
    const secs_of_day: u64 = es % 86400;
    const day_num: u64 = es / 86400; // days since 1970-01-01 (Thursday)
    const hour = secs_of_day / 3600;
    const minute = (secs_of_day % 3600) / 60;
    const second = secs_of_day % 60;
    const dow = (day_num + 4) % 7; // 1970-01-01 was Thursday(4)

    // Civil-from-days (Howard Hinnant's algorithm).
    var z: i64 = @intCast(day_num);
    z += 719468;
    const era: i64 = @divFloor(if (z >= 0) z else z - 146096, 146097);
    const doe: u64 = @intCast(z - era * 146097);
    const yoe: u64 = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const y: i64 = @as(i64, @intCast(yoe)) + era * 400;
    const doy: u64 = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const mp: u64 = (5 * doy + 2) / 153;
    const d: u64 = doy - (153 * mp + 2) / 5 + 1;
    const m: u64 = if (mp < 10) mp + 3 else mp - 9;
    const year: i64 = if (m <= 2) y + 1 else y;

    return std.fmt.allocPrint(allocator, "{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} +0000", .{
        days[@intCast(dow)],
        d,
        months[m - 1],
        year,
        hour,
        minute,
        second,
    });
}

fn joinAddrs(allocator: std.mem.Allocator, addrs: []const []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (addrs, 0..) |a, i| {
        if (i > 0) try out.appendSlice(allocator, ", ");
        try out.appendSlice(allocator, a);
    }
    return out.toOwnedSlice(allocator);
}

/// Base64-encode `data` wrapped at 76 columns (RFC 2045).
fn base64Wrapped(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    const enc = std.base64.standard.Encoder;
    const raw = try allocator.alloc(u8, enc.calcSize(data.len));
    defer allocator.free(raw);
    _ = enc.encode(raw, data);
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < raw.len) : (i += 76) {
        const end = @min(i + 76, raw.len);
        try out.appendSlice(allocator, raw[i..end]);
        try out.appendSlice(allocator, "\r\n");
    }
    return out.toOwnedSlice(allocator);
}

/// Build the full RFC 5322 message bytes (CRLF line endings). Arena-allocated.
/// `msgid` is the already-formed Message-ID (with angle brackets).
pub fn buildMime(allocator: std.mem.Allocator, msg: Message, ts: i64, msgid: []const u8) ![]const u8 {
    // Validate everything that lands in a header.
    if (!isSafeAddress(msg.from)) return ComposeError.InvalidAddress;
    for (msg.to) |a| if (!isSafeAddress(a)) return ComposeError.InvalidAddress;
    for (msg.cc) |a| if (!isSafeAddress(a)) return ComposeError.InvalidAddress;
    if (!isSafeHeaderValue(msg.subject)) return ComposeError.InvalidHeader;
    if (!isSafeHeaderValue(msg.in_reply_to)) return ComposeError.InvalidHeader;
    if (!isSafeHeaderValue(msg.references)) return ComposeError.InvalidHeader;

    var out: std.ArrayList(u8) = .empty;
    const w = writerFor(&out, allocator);

    const date = try formatDate(allocator, ts);
    try w.print("From: {s}\r\n", .{msg.from});
    if (msg.to.len > 0) try w.print("To: {s}\r\n", .{try joinAddrs(allocator, msg.to)});
    if (msg.cc.len > 0) try w.print("Cc: {s}\r\n", .{try joinAddrs(allocator, msg.cc)});
    try w.print("Subject: {s}\r\n", .{msg.subject});
    try w.print("Date: {s}\r\n", .{date});
    try w.print("Message-ID: {s}\r\n", .{msgid});
    if (msg.in_reply_to.len > 0) try w.print("In-Reply-To: {s}\r\n", .{msg.in_reply_to});
    if (msg.references.len > 0) try w.print("References: {s}\r\n", .{msg.references});
    try w.writeAll("MIME-Version: 1.0\r\n");

    const has_attachments = msg.attachments.len > 0;
    const has_html = msg.html_body.len > 0;

    if (!has_attachments and !has_html) {
        // Simple text/plain.
        try w.writeAll("Content-Type: text/plain; charset=utf-8\r\n");
        try w.writeAll("Content-Transfer-Encoding: 8bit\r\n\r\n");
        try writeBodyCrlf(allocator, &out, msg.text_body);
        return out.toOwnedSlice(allocator);
    }

    // Multipart. Outer is mixed if there are attachments, else alternative.
    // Layout: multipart/mixed [ multipart/alternative [text, html] | text, attachments... ]
    const boundary = try std.fmt.allocPrint(allocator, "=_wm_{d}_{s}", .{ ts, "b0" });
    const alt_boundary = try std.fmt.allocPrint(allocator, "=_wm_{d}_{s}", .{ ts, "a0" });

    if (has_attachments) {
        try w.print("Content-Type: multipart/mixed; boundary=\"{s}\"\r\n\r\n", .{boundary});
        try w.writeAll("This is a multipart message in MIME format.\r\n");
        // First part: the body (alternative if html present, else plain).
        try w.print("--{s}\r\n", .{boundary});
        try writeBodyPart(allocator, &out, msg, alt_boundary);
        // Attachment parts.
        for (msg.attachments) |att| {
            if (!isSafeHeaderValue(att.filename) or !isSafeHeaderValue(att.content_type)) return ComposeError.InvalidHeader;
            try w.print("--{s}\r\n", .{boundary});
            try w.print("Content-Type: {s}\r\n", .{att.content_type});
            try w.writeAll("Content-Transfer-Encoding: base64\r\n");
            try w.print("Content-Disposition: attachment; filename=\"{s}\"\r\n\r\n", .{att.filename});
            try w.writeAll(try base64Wrapped(allocator, att.data));
            try w.writeAll("\r\n");
        }
        try w.print("--{s}--\r\n", .{boundary});
        return out.toOwnedSlice(allocator);
    }

    // html present, no attachments -> multipart/alternative at top level.
    try w.print("Content-Type: multipart/alternative; boundary=\"{s}\"\r\n\r\n", .{alt_boundary});
    try writeAltParts(allocator, &out, msg, alt_boundary);
    return out.toOwnedSlice(allocator);
}

/// Write a body "part" — either a nested multipart/alternative (when html is
/// present) or a single text/plain part — for use inside multipart/mixed.
fn writeBodyPart(allocator: std.mem.Allocator, out: *std.ArrayList(u8), msg: Message, alt_boundary: []const u8) !void {
    const w = writerFor(out, allocator);
    if (msg.html_body.len > 0) {
        try w.print("Content-Type: multipart/alternative; boundary=\"{s}\"\r\n\r\n", .{alt_boundary});
        try writeAltParts(allocator, out, msg, alt_boundary);
    } else {
        try w.writeAll("Content-Type: text/plain; charset=utf-8\r\n");
        try w.writeAll("Content-Transfer-Encoding: 8bit\r\n\r\n");
        try writeBodyCrlf(allocator, out, msg.text_body);
    }
}

fn writeAltParts(allocator: std.mem.Allocator, out: *std.ArrayList(u8), msg: Message, alt_boundary: []const u8) !void {
    const w = writerFor(out, allocator);
    try w.print("--{s}\r\n", .{alt_boundary});
    try w.writeAll("Content-Type: text/plain; charset=utf-8\r\n");
    try w.writeAll("Content-Transfer-Encoding: 8bit\r\n\r\n");
    try writeBodyCrlf(allocator, out, msg.text_body);
    try w.writeAll("\r\n");
    try w.print("--{s}\r\n", .{alt_boundary});
    try w.writeAll("Content-Type: text/html; charset=utf-8\r\n");
    try w.writeAll("Content-Transfer-Encoding: 8bit\r\n\r\n");
    try writeBodyCrlf(allocator, out, msg.html_body);
    try w.writeAll("\r\n");
    try w.print("--{s}--\r\n", .{alt_boundary});
}

/// Write a body, normalizing bare LF to CRLF and dot-unstuffing is NOT needed
/// here (deliverToRemote handles SMTP dot-stuffing).
fn writeBodyCrlf(allocator: std.mem.Allocator, out: *std.ArrayList(u8), body: []const u8) !void {
    var i: usize = 0;
    while (i < body.len) : (i += 1) {
        const c = body[i];
        if (c == '\r') {
            if (i + 1 < body.len and body[i + 1] == '\n') {
                try out.appendSlice(allocator, "\r\n");
                i += 1;
            } else {
                try out.appendSlice(allocator, "\r\n");
            }
        } else if (c == '\n') {
            try out.appendSlice(allocator, "\r\n");
        } else {
            try out.append(allocator, c);
        }
    }
}

fn isLocalDomain(domain: []const u8, hostname: []const u8) bool {
    if (std.mem.eql(u8, domain, hostname)) return true;
    if (std.mem.indexOfScalar(u8, hostname, '.')) |dot| {
        if (std.mem.eql(u8, domain, hostname[dot + 1 ..])) return true;
    }
    return false;
}

/// Deliver `raw` to one recipient: local -> Maildir INBOX, remote -> outbound.
fn deliverOne(allocator: std.mem.Allocator, cfg: SendConfig, from: []const u8, rcpt: []const u8, raw: []const u8) void {
    const at = std.mem.indexOfScalar(u8, rcpt, '@');
    const domain = if (at) |p| rcpt[p + 1 ..] else "";
    if (at != null and isLocalDomain(domain, cfg.hostname)) {
        const user = rcpt[0..at.?];
        writeMaildir(allocator, user, "new", raw) catch |err| {
            std.log.err("webmail local delivery to {s} failed: {}", .{ rcpt, err });
        };
    } else {
        outbound.deliverToRemote(allocator, from, rcpt, raw, cfg.hostname, cfg.delivery_method, cfg.ses_region) catch |err| {
            std.log.err("webmail outbound delivery to {s} failed: {}", .{ rcpt, err });
        };
    }
}

/// Write a message into mail/{user}/{subdir}/{ts}.eml. subdir is "new" (INBOX
/// delivery) or "Sent". Uses a unique-ish name to avoid same-ms collisions.
fn writeMaildir(allocator: std.mem.Allocator, user: []const u8, subdir: []const u8, raw: []const u8) !void {
    const dir = try std.fmt.allocPrint(allocator, "mail/{s}/{s}", .{ user, subdir });
    fs_compat.ensureDir(dir) catch {};
    // Unique name: ms timestamp + a process-monotonic counter to dodge collisions.
    const seq = nameSeq.fetchAdd(1, .monotonic);
    const path = try std.fmt.allocPrint(allocator, "{s}/{d}.{d}.eml", .{ dir, time_compat.milliTimestamp(), seq });
    const f = try fs_compat.cwd().createFile(path, .{});
    defer f.close();
    try f.writeAll(raw);
}

var nameSeq = std.atomic.Value(u64).init(0);

/// Build + send a composed message. Returns the generated Message-ID.
pub fn send(allocator: std.mem.Allocator, msg: Message, cfg: SendConfig) !SendResult {
    if (msg.to.len == 0 and msg.cc.len == 0 and msg.bcc.len == 0) return ComposeError.NoRecipients;

    const ts = time_compat.timestamp();
    const seq = nameSeq.fetchAdd(1, .monotonic);
    const msgid = try std.fmt.allocPrint(allocator, "<{d}.{d}@{s}>", .{ ts, seq, cfg.hostname });

    const raw = try buildMime(allocator, msg, ts, msgid);

    // Deliver to every recipient (To + Cc + Bcc). Bcc recipients receive the
    // message but are not in the headers (buildMime never emits a Bcc header).
    var count: usize = 0;
    for (msg.to) |r| {
        deliverOne(allocator, cfg, msg.from, r, raw);
        count += 1;
    }
    for (msg.cc) |r| {
        deliverOne(allocator, cfg, msg.from, r, raw);
        count += 1;
    }
    for (msg.bcc) |r| {
        if (!isSafeAddress(r)) continue;
        deliverOne(allocator, cfg, msg.from, r, raw);
        count += 1;
    }

    // Save a copy to the sender's Sent folder (best-effort).
    writeMaildir(allocator, cfg.sender_user, "Sent", raw) catch |err| {
        std.log.warn("webmail: failed to save to Sent: {}", .{err});
    };

    return .{ .message_id = msgid, .delivered = count };
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "isSafeAddress rejects injection and malformed" {
    const t = std.testing;
    try t.expect(isSafeAddress("alice@example.com"));
    try t.expect(!isSafeAddress("a@b\r\nBcc: evil@x.com"));
    try t.expect(!isSafeAddress("no-at-sign"));
    try t.expect(!isSafeAddress("two@@x.com"));
    try t.expect(!isSafeAddress("@x.com"));
    try t.expect(!isSafeAddress("a@"));
}

test "formatDate produces RFC5322 shape" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    // 1700000000 = 2023-11-14T22:13:20Z (Tue)
    const d = try formatDate(arena.allocator(), 1700000000);
    try t.expectEqualStrings("Tue, 14 Nov 2023 22:13:20 +0000", d);
}

test "buildMime simple text message" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const msg = Message{
        .from = "alice@mail.test",
        .to = &.{"bob@example.com"},
        .subject = "Hi",
        .text_body = "Hello\nWorld",
    };
    const raw = try buildMime(a, msg, 1700000000, "<x@mail.test>");
    try t.expect(std.mem.indexOf(u8, raw, "From: alice@mail.test\r\n") != null);
    try t.expect(std.mem.indexOf(u8, raw, "To: bob@example.com\r\n") != null);
    try t.expect(std.mem.indexOf(u8, raw, "Subject: Hi\r\n") != null);
    try t.expect(std.mem.indexOf(u8, raw, "Message-ID: <x@mail.test>\r\n") != null);
    try t.expect(std.mem.indexOf(u8, raw, "Hello\r\nWorld") != null); // LF normalized to CRLF
}

test "buildMime rejects header injection in subject" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const msg = Message{
        .from = "a@b.test",
        .to = &.{"c@d.test"},
        .subject = "Hi\r\nBcc: evil@x.com",
        .text_body = "x",
    };
    try t.expectError(ComposeError.InvalidHeader, buildMime(arena.allocator(), msg, 1, "<m@b.test>"));
}

test "buildMime multipart with html and attachment" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const msg = Message{
        .from = "a@b.test",
        .to = &.{"c@d.test"},
        .subject = "Multi",
        .text_body = "plain",
        .html_body = "<b>rich</b>",
        .attachments = &.{.{ .filename = "x.txt", .content_type = "text/plain", .data = "ATTACH" }},
    };
    const raw = try buildMime(a, msg, 1, "<m@b.test>");
    try t.expect(std.mem.indexOf(u8, raw, "multipart/mixed") != null);
    try t.expect(std.mem.indexOf(u8, raw, "multipart/alternative") != null);
    try t.expect(std.mem.indexOf(u8, raw, "text/html") != null);
    try t.expect(std.mem.indexOf(u8, raw, "Content-Disposition: attachment; filename=\"x.txt\"") != null);
    // "ATTACH" base64 = "QVRUQUNI"
    try t.expect(std.mem.indexOf(u8, raw, "QVRUQUNI") != null);
}
