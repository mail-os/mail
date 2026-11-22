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
const submission = @import("../delivery/submission.zig");
const fs_compat = @import("../core/fs_compat.zig");
const time_compat = @import("../core/time_compat.zig");
const core_config = @import("../core/config.zig");
const auth_mod = @import("../auth/auth.zig");

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
    mime_id: ?[32]u8 = null,
    content_id: []const u8 = "",
    inline_part: bool = false,
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
    /// Only drafts and the sender's private Sent copy retain Bcc headers.
    include_bcc: bool = false,
    /// Mark a message the server wrote itself (RFC 3834), so vacation
    /// responders and auto-forwarders do not answer it.
    auto_submitted: bool = false,
    notice_recipient_id: ?i64 = null,
};

pub const SendConfig = struct {
    hostname: []const u8,
    delivery_method: core_config.DeliveryMethod,
    ses_region: []const u8,
    mail_config: ?*const core_config.Config = null,
    auth: ?*auth_mod.AuthBackend = null,
    /// Canonical mailbox key of the sender (used for the Sent folder path).
    sender_user: []const u8,
    delegated_sender_id: ?i64 = null,

    fn delivery(self: SendConfig) submission.Delivery {
        return .{
            .hostname = self.hostname,
            .delivery_method = self.delivery_method,
            .ses_region = self.ses_region,
            .mail_config = self.mail_config,
            .db = if (self.auth) |auth| auth.db else null,
        };
    }
};

pub const SendResult = struct {
    message_id: []const u8,
    delivered: usize, // recipients accepted locally or delivered to a remote server
    failed: []const []const u8, // recipients delivery failed for (arena-allocated)
    sent_saved: bool,
    limit_notice: ?[]const u8 = null,
    unknown: []const []const u8 = &.{},
};

pub const OutboxDispatch = struct {
    from_address: ?[]const u8 = null,
    delivery_id: []const u8,
    sent_delivery_id: []const u8,
    message_id: []const u8,
    message_date: i64,
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

pub const isSafeAddress = submission.isSafeAddress;

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

/// Generate a unique, unpredictable MIME boundary that does NOT occur anywhere
/// in `parts` (so a crafted body/attachment can't inject a spurious delimiter).
/// Uses crypto random; retries with fresh randomness on the rare collision.
fn uniqueBoundary(allocator: std.mem.Allocator, parts: []const []const u8) ![]const u8 {
    var attempt: u8 = 0;
    while (attempt < 8) : (attempt += 1) {
        var rnd: [18]u8 = undefined;
        io_random(&rnd);
        var hex: [36]u8 = undefined;
        const hexchars = "0123456789abcdef";
        for (rnd, 0..) |b, i| {
            hex[i * 2] = hexchars[b >> 4];
            hex[i * 2 + 1] = hexchars[b & 0x0f];
        }
        const boundary = try std.fmt.allocPrint(allocator, "=_wm_{s}", .{hex});
        var collides = false;
        for (parts) |p| {
            if (std.mem.indexOf(u8, p, boundary) != null) {
                collides = true;
                break;
            }
        }
        if (!collides) return boundary;
    }
    return ComposeError.BuildFailed;
}

/// Fill `buf` with cryptographically secure random bytes via the project's
/// io_compat helper (CSPRNG when initialized).
fn io_random(buf: []u8) void {
    @import("../core/io_compat.zig").randomBytes(buf);
}

/// Choose a Content-Transfer-Encoding: 8bit raises interop issues with strict
/// relays for non-ASCII, so use base64 when the body has any byte >= 0x80.
fn needsBase64(body: []const u8) bool {
    for (body) |c| {
        if (c >= 0x80) return true;
    }
    return false;
}

/// Base64-encode `data` wrapped at 76 columns (RFC 2045).
pub fn base64Wrapped(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
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
    // Validate everything that lands in a header OR a delivery path. Bcc is
    // validated too (it never reaches a header but is used for delivery), so a
    // bad Bcc fails loudly instead of being silently dropped.
    if (!isSafeAddress(msg.from)) return ComposeError.InvalidAddress;
    for (msg.to) |a| if (!isSafeAddress(a)) return ComposeError.InvalidAddress;
    for (msg.cc) |a| if (!isSafeAddress(a)) return ComposeError.InvalidAddress;
    for (msg.bcc) |a| if (!isSafeAddress(a)) return ComposeError.InvalidAddress;
    if (!isSafeHeaderValue(msg.subject)) return ComposeError.InvalidHeader;
    if (!isSafeHeaderValue(msg.in_reply_to)) return ComposeError.InvalidHeader;
    if (!isSafeHeaderValue(msg.references)) return ComposeError.InvalidHeader;

    var out: std.ArrayList(u8) = .empty;
    const w = writerFor(&out, allocator);

    const date = try formatDate(allocator, ts);
    try w.print("From: {s}\r\n", .{msg.from});
    if (msg.to.len > 0) try w.print("To: {s}\r\n", .{try joinAddrs(allocator, msg.to)});
    if (msg.cc.len > 0) try w.print("Cc: {s}\r\n", .{try joinAddrs(allocator, msg.cc)});
    if (msg.include_bcc and msg.bcc.len > 0) try w.print("Bcc: {s}\r\n", .{try joinAddrs(allocator, msg.bcc)});
    if (needsBase64(msg.subject)) {
        // RFC 2047 limits each encoded-word to 75 bytes. Fold between words,
        // taking care not to split a UTF-8 code point between independently
        // encoded chunks.
        try w.writeAll("Subject: ");
        const enc = std.base64.standard.Encoder;
        var offset: usize = 0;
        while (offset < msg.subject.len) {
            var end = @min(offset + 42, msg.subject.len);
            while (end < msg.subject.len and (msg.subject[end] & 0xc0) == 0x80) end -= 1;
            const chunk = msg.subject[offset..end];
            const encoded = try allocator.alloc(u8, enc.calcSize(chunk.len));
            _ = enc.encode(encoded, chunk);
            if (offset > 0) try w.writeAll("\r\n ");
            try w.print("=?UTF-8?B?{s}?=", .{encoded});
            offset = end;
        }
        try w.writeAll("\r\n");
    } else try w.print("Subject: {s}\r\n", .{msg.subject});
    try w.print("Date: {s}\r\n", .{date});
    try w.print("Message-ID: {s}\r\n", .{msgid});
    if (msg.in_reply_to.len > 0) try w.print("In-Reply-To: {s}\r\n", .{msg.in_reply_to});
    if (msg.references.len > 0) try w.print("References: {s}\r\n", .{msg.references});
    if (msg.auto_submitted) try w.writeAll("Auto-Submitted: auto-generated\r\n");
    try w.writeAll("MIME-Version: 1.0\r\n");

    const has_attachments = msg.attachments.len > 0;
    const has_html = msg.html_body.len > 0;

    if (!has_attachments and !has_html) {
        // Simple text/plain. base64 for non-ASCII to avoid 8bit interop issues.
        try w.writeAll("Content-Type: text/plain; charset=utf-8\r\n");
        if (needsBase64(msg.text_body)) {
            try w.writeAll("Content-Transfer-Encoding: base64\r\n\r\n");
            try w.writeAll(try base64Wrapped(allocator, msg.text_body));
        } else {
            try w.writeAll("Content-Transfer-Encoding: 8bit\r\n\r\n");
            try writeBodyCrlf(allocator, &out, msg.text_body);
        }
        return out.toOwnedSlice(allocator);
    }

    // Multipart. Boundaries are crypto-random and verified absent from the body
    // and attachments so content can't inject a spurious delimiter.
    const boundary = try uniqueBoundary(allocator, &.{ msg.text_body, msg.html_body });
    const alt_boundary = try uniqueBoundary(allocator, &.{ msg.text_body, msg.html_body, boundary });

    if (has_attachments) {
        try w.print("Content-Type: multipart/mixed; boundary=\"{s}\"\r\n\r\n", .{boundary});
        try w.writeAll("This is a multipart message in MIME format.\r\n");
        // First part: the body (alternative if html present, else plain).
        try w.print("--{s}\r\n", .{boundary});
        try writeBodyPart(allocator, &out, msg, alt_boundary);
        // RFC 2046 delimiters begin on a new line, including when a plain
        // text body has no trailing newline. Otherwise a standards parser
        // treats the attachment headers and data as part of the text body.
        try w.writeAll("\r\n");
        // Attachment parts.
        for (msg.attachments) |att| {
            if (!isSafeHeaderValue(att.filename) or !isSafeHeaderValue(att.content_type)) return ComposeError.InvalidHeader;
            try w.print("--{s}\r\n", .{boundary});
            try w.print("Content-Type: {s}\r\n", .{att.content_type});
            try w.writeAll("Content-Transfer-Encoding: base64\r\n");
            if (msg.include_bcc) {
                if (att.mime_id) |mime_id| try w.print("X-Mail-Ews-Attachment-Id: {s}\r\n", .{mime_id});
            }
            if (att.content_id.len > 0) {
                if (!isSafeHeaderValue(att.content_id)) return ComposeError.InvalidHeader;
                try w.print("Content-ID: <{s}>\r\n", .{att.content_id});
            }
            // Quote/backslash in a filename must not terminate its parameter.
            try w.print("Content-Disposition: {s}; filename=\"", .{if (att.inline_part) "inline" else "attachment"});
            for (att.filename) |c| {
                if (c == '"' or c == '\\') try w.writeAll("\\");
                try out.append(allocator, c);
            }
            try w.writeAll("\"\r\n\r\n");
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

/// Emit a `text/<sub>` body with the right transfer encoding (base64 for
/// non-ASCII, else 8bit). Does not write part boundaries — caller frames it.
fn writeTextBody(allocator: std.mem.Allocator, out: *std.ArrayList(u8), sub: []const u8, body: []const u8) !void {
    const w = writerFor(out, allocator);
    try w.print("Content-Type: text/{s}; charset=utf-8\r\n", .{sub});
    if (needsBase64(body)) {
        try w.writeAll("Content-Transfer-Encoding: base64\r\n\r\n");
        try w.writeAll(try base64Wrapped(allocator, body));
    } else {
        try w.writeAll("Content-Transfer-Encoding: 8bit\r\n\r\n");
        try writeBodyCrlf(allocator, out, body);
    }
}

/// Write a body "part" — either a nested multipart/alternative (when html is
/// present) or a single text/plain part — for use inside multipart/mixed.
fn writeBodyPart(allocator: std.mem.Allocator, out: *std.ArrayList(u8), msg: Message, alt_boundary: []const u8) !void {
    const w = writerFor(out, allocator);
    if (msg.html_body.len > 0) {
        try w.print("Content-Type: multipart/alternative; boundary=\"{s}\"\r\n\r\n", .{alt_boundary});
        try writeAltParts(allocator, out, msg, alt_boundary);
    } else {
        try writeTextBody(allocator, out, "plain", msg.text_body);
    }
}

fn writeAltParts(allocator: std.mem.Allocator, out: *std.ArrayList(u8), msg: Message, alt_boundary: []const u8) !void {
    const w = writerFor(out, allocator);
    try w.print("--{s}\r\n", .{alt_boundary});
    try writeTextBody(allocator, out, "plain", msg.text_body);
    try w.writeAll("\r\n");
    try w.print("--{s}\r\n", .{alt_boundary});
    try writeTextBody(allocator, out, "html", msg.html_body);
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

var nameSeq = std.atomic.Value(u64).init(0);

/// Build + send a composed message. Returns the generated Message-ID.
pub fn send(allocator: std.mem.Allocator, msg: Message, cfg: SendConfig) !SendResult {
    return sendWithJournal(allocator, msg, cfg, null);
}

pub fn sendWithJournal(allocator: std.mem.Allocator, msg: Message, cfg: SendConfig, dispatch: ?OutboxDispatch) !SendResult {
    if (msg.to.len == 0 and msg.cc.len == 0 and msg.bcc.len == 0) return ComposeError.NoRecipients;

    const ts = if (dispatch) |send_record| send_record.message_date else time_compat.timestamp();
    const seq = nameSeq.fetchAdd(1, .monotonic);
    const msgid = if (dispatch) |send_record| send_record.message_id else try std.fmt.allocPrint(allocator, "<{d}.{d}@{s}>", .{ ts, seq, cfg.hostname });

    const raw = try buildMime(allocator, msg, ts, msgid);
    var private_msg = msg;
    private_msg.include_bcc = true;
    const sent_raw = try buildMime(allocator, private_msg, ts, msgid);

    // To, Cc and Bcc share one allowance. Keep only the first occurrence of
    // each address, and reserve the full envelope before starting delivery.
    const recipients = try submission.distinctRecipients(allocator, &.{ msg.to, msg.cc, msg.bcc });
    defer allocator.free(recipients);
    const delivery = cfg.delivery();
    const result = try submission.dispatch(allocator, delivery, msg.from, recipients, raw, .{
        .sender = cfg.sender_user,
        .delegated_sender_id = cfg.delegated_sender_id,
        .interactive_id = if (dispatch) |send_record| send_record.delivery_id else null,
    });
    errdefer allocator.free(result.failed);
    const first_limit_error = result.first_limit_error;
    if (result.delivered == 0 and first_limit_error != null) return first_limit_error.?;

    // Save a copy to the sender's Sent folder (best-effort; doesn't affect the
    // delivered count, but a failure is logged).
    var sent_saved = false;
    var limit_notice: ?[]const u8 = if (first_limit_error != null) "Some recipient mailboxes are full or disabled." else null;
    if (result.delivered > 0) {
        if (fileSent(allocator, cfg, sent_raw, if (dispatch) |send_record| send_record.sent_delivery_id else null)) |saved| {
            sent_saved = saved;
        } else |err| {
            if (err == error.HostedStorageFull and limit_notice == null)
                limit_notice = "Message delivered. Your mailbox is full, so a Sent copy could not be saved.";
            std.log.warn("webmail: failed to save to Sent: {}", .{err});
        }
    }

    return .{ .message_id = msgid, .delivered = result.delivered, .failed = result.failed, .sent_saved = sent_saved, .limit_notice = limit_notice };
}

pub fn recoverSent(a: std.mem.Allocator, msg: Message, cfg: SendConfig, dispatch: OutboxDispatch) !bool {
    var private_msg = msg;
    private_msg.include_bcc = true;
    const raw = try buildMime(a, private_msg, dispatch.message_date, dispatch.message_id);
    return fileSent(a, cfg, raw, dispatch.sent_delivery_id);
}

fn fileSent(a: std.mem.Allocator, cfg: SendConfig, raw: []const u8, id: ?[]const u8) !bool {
    const db = cfg.delivery().db;
    if (id) |value| return submission.fileInteractiveSent(a, db orelse return error.DatabaseUnavailable, cfg.sender_user, value, raw);
    try submission.writeMaildir(a, db, cfg.sender_user, "Sent", raw);
    return true;
}

/// Deliver a message the server writes on its own behalf (password reset
/// links and account notices): the same local-or-remote path and DKIM signing
/// as a composed message, with no Sent copy, because no mailbox sent it.
pub fn deliverSystem(allocator: std.mem.Allocator, msg: Message, cfg: SendConfig) !void {
    if (msg.to.len == 0) return ComposeError.NoRecipients;
    const ts = time_compat.timestamp();
    const seq = nameSeq.fetchAdd(1, .monotonic);
    const msgid = try std.fmt.allocPrint(allocator, "<{d}.{d}@{s}>", .{ ts, seq, cfg.hostname });
    const raw = try buildMime(allocator, msg, ts, msgid);
    for (msg.to) |recipient| try submission.deliverNotice(allocator, cfg.delivery(), msg.from, recipient, raw, msg.notice_recipient_id);
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "isSafeAddress rejects injection, path traversal, and malformed" {
    const t = std.testing;
    try t.expect(isSafeAddress("alice@example.com"));
    try t.expect(!isSafeAddress("a@b\r\nBcc: evil@x.com"));
    try t.expect(!isSafeAddress("no-at-sign"));
    try t.expect(!isSafeAddress("two@@x.com"));
    try t.expect(!isSafeAddress("@x.com"));
    try t.expect(!isSafeAddress("a@"));
    // Path-traversal / separator chars must be rejected (local-delivery safety).
    try t.expect(!isSafeAddress("../../etc@mail.test"));
    try t.expect(!isSafeAddress("a/b@mail.test"));
    try t.expect(!isSafeAddress("a\\b@mail.test"));
    try t.expect(!isSafeAddress(".hidden@mail.test"));
}

test "isSafeLocalPart guards the maildir path component" {
    const t = std.testing;
    try t.expect(submission.isSafeLocalPart("alice"));
    try t.expect(!submission.isSafeLocalPart("../../etc"));
    try t.expect(!submission.isSafeLocalPart("a/b"));
    try t.expect(!submission.isSafeLocalPart(".hidden"));
    try t.expect(!submission.isSafeLocalPart(""));
}

test "buildMime validates bcc and uses base64 for non-ASCII" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Bad bcc -> hard error (no silent skip).
    const bad = Message{ .from = "a@b.test", .to = &.{"c@d.test"}, .bcc = &.{"x@y\r\nevil"}, .text_body = "x" };
    try t.expectError(ComposeError.InvalidAddress, buildMime(a, bad, 1, "<m@b.test>"));
    // Non-ASCII body -> base64 CTE, not 8bit.
    const utf8 = Message{ .from = "a@b.test", .to = &.{"c@d.test"}, .text_body = "Caf\u{00E9}" };
    const raw = try buildMime(a, utf8, 1, "<m@b.test>");
    try t.expect(std.mem.indexOf(u8, raw, "Content-Transfer-Encoding: base64") != null);
    try t.expect(std.mem.indexOf(u8, raw, "Content-Transfer-Encoding: 8bit") == null);
}

test "uniqueBoundary avoids a boundary present in the body" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const b = try uniqueBoundary(a, &.{"some body text"});
    try t.expect(std.mem.startsWith(u8, b, "=_wm_"));
    // Build a body that literally contains the boundary; the next call must differ.
    const b2 = try uniqueBoundary(a, &.{ b, b });
    try t.expect(!std.mem.eql(u8, b, b2));
}

test "multipart attachment delimiters start on complete MIME lines" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_][]const u8{ "No trailing newline", "First line\nLast line", "Caf\u{00E9}" }) |text| {
        const raw = try buildMime(a, .{
            .from = "sender@unit.test",
            .to = &.{"recipient@unit.test"},
            .text_body = text,
            .attachments = &.{.{ .filename = "fixture.bin", .content_type = "application/octet-stream", .data = &.{ 0, 1, 255 } }},
        }, 1, "<mime@unit.test>");
        const marker = "boundary=\"";
        const start = std.mem.indexOf(u8, raw, marker).? + marker.len;
        const end = start + std.mem.indexOfScalar(u8, raw[start..], '"').?;
        const delimiter = try std.fmt.allocPrint(a, "--{s}", .{raw[start..end]});
        var offset: usize = 0;
        var count: usize = 0;
        while (std.mem.indexOfPos(u8, raw, offset, delimiter)) |position| {
            try t.expect(position >= 2);
            try t.expectEqualStrings("\r\n", raw[position - 2 .. position]);
            const suffix = raw[position + delimiter.len ..][0..2];
            try t.expect(std.mem.eql(u8, suffix, "\r\n") or std.mem.eql(u8, suffix, "--"));
            offset = position + delimiter.len;
            count += 1;
        }
        try t.expectEqual(@as(usize, 3), count);
        try t.expect(std.mem.indexOf(u8, raw, "Content-Disposition: attachment; filename=\"fixture.bin\"") != null);
    }
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

test "compose deduplicates envelope recipients and reports partial delivery" {
    const t = std.testing;
    const db_mod = @import("../storage/database.zig");
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var db = try db_mod.Database.init(t.allocator, ":memory:");
    defer db.deinit();
    var auth = auth_mod.AuthBackend.init(t.allocator, &db);
    defer auth.deinit();
    const user = try std.fmt.allocPrint(a, "webmail-unit-{d}@unit.test", .{time_compat.milliTimestamp()});
    _ = try auth.createUser(user, "test-only-password", user);
    const root = try std.fmt.allocPrint(a, "mail/{s}", .{user});
    defer fs_compat.cwd().deleteTree(root) catch {};
    const msg = Message{ .from = user, .to = &.{ user, "missing@unit.test" }, .cc = &.{user}, .bcc = &.{user}, .text_body = "test" };
    const result = try send(a, msg, .{ .hostname = "mail.unit.test", .delivery_method = .direct, .ses_region = "", .sender_user = user, .auth = &auth });
    try t.expectEqual(@as(usize, 1), result.delivered);
    try t.expectEqual(@as(usize, 1), result.failed.len);
    try t.expectEqualStrings("missing@unit.test", result.failed[0]);
    try t.expect(result.sent_saved);
    const inbox = try std.fmt.allocPrint(a, "{s}/new", .{root});
    const sent = try std.fmt.allocPrint(a, "{s}/Sent", .{root});
    try t.expectEqual(@as(usize, 1), fs_compat.countEmlFiles(inbox));
    try t.expectEqual(@as(usize, 1), fs_compat.countEmlFiles(sent));
    const files = try fs_compat.listEmlFiles(a, inbox);
    const received = try fs_compat.readFileAlloc(a, try std.fmt.allocPrint(a, "{s}/{s}", .{ inbox, files[0] }));
    try t.expect(std.mem.indexOf(u8, received, "\r\nBcc:") == null);
    const sent_files = try fs_compat.listEmlFiles(a, sent);
    const private_copy = try fs_compat.readFileAlloc(a, try std.fmt.allocPrint(a, "{s}/{s}", .{ sent, sent_files[0] }));
    try t.expect(std.mem.indexOf(u8, private_copy, "\r\nBcc:") != null);
}
