//! Header policy and wire format for mailbox vacation replies.
const std = @import("std");
const addresses = @import("submission.zig");
const thread_ids = @import("thread_ids.zig");
const time = @import("../core/time_compat.zig");
const io = @import("../core/io_compat.zig");

pub const cooldown_seconds = 7 * 86400;
pub const daily_limit = 100;

pub fn safeCorrespondent(address: []const u8) bool {
    if (address.len > 254 or !addresses.validMailbox(address)) return false;
    for (address) |byte| if (byte > 126 or byte == '/' or byte == '\\') return false;
    const local = std.mem.sliceTo(address, '@');
    const base = std.mem.sliceTo(local, '+');
    for ([_][]const u8{ "mailer-daemon", "listserv", "majordomo", "no-reply", "noreply", "bounce", "bounces", "auto-reply", "autoreply" }) |system| {
        if (std.ascii.eqlIgnoreCase(base, system)) return false;
    }
    return !std.ascii.startsWithIgnoreCase(base, "owner-") and
        !std.ascii.startsWithIgnoreCase(base, "bounce-") and !std.ascii.endsWithIgnoreCase(base, "-request");
}

pub const Headers = struct {
    recipients: std.ArrayList([]const u8) = .empty,
    message_id: ?[]const u8 = null,

    pub fn namesMailbox(self: Headers, address: []const u8) bool {
        for (self.recipients.items) |recipient| {
            if (std.ascii.eqlIgnoreCase(recipient, address)) return true;
        }
        return false;
    }
};

const Field = enum { ignore, recipient, message_id, automatic, precedence, suppress, content_type };

fn fieldFor(name: []const u8) Field {
    for ([_][]const u8{ "To", "Cc", "Bcc" }) |recipient| {
        if (std.ascii.eqlIgnoreCase(name, recipient)) return .recipient;
    }
    for ([_]struct { []const u8, Field }{
        .{ "Auto-Submitted", .automatic },          .{ "Precedence", .precedence },
        .{ "X-Auto-Response-Suppress", .suppress }, .{ "Content-Type", .content_type },
        .{ "Message-ID", .message_id },
    }) |entry| {
        if (std.ascii.eqlIgnoreCase(name, entry[0])) return entry[1];
    }
    return .ignore;
}

fn parseField(a: std.mem.Allocator, headers: *Headers, field: Field, value: []const u8) !bool {
    const token = std.mem.trim(u8, std.mem.sliceTo(value, ';'), " \t");
    switch (field) {
        .ignore => {},
        .automatic => if (!std.ascii.eqlIgnoreCase(token, "no")) return false,
        .precedence => for ([_][]const u8{ "list", "bulk", "junk" }) |kind| {
            if (std.ascii.eqlIgnoreCase(token, kind)) return false;
        },
        .suppress => {
            var flags = std.mem.tokenizeAny(u8, value, ", \t");
            while (flags.next()) |flag| {
                if (std.ascii.eqlIgnoreCase(flag, "All") or std.ascii.eqlIgnoreCase(flag, "OOF") or std.ascii.eqlIgnoreCase(flag, "AutoReply")) return false;
            }
        },
        .content_type => {
            if (std.ascii.eqlIgnoreCase(token, "multipart/report") or std.ascii.eqlIgnoreCase(token, "message/delivery-status")) return false;
        },
        .recipient => addresses.appendMailboxes(a, value, &headers.recipients) catch |err| switch (err) {
            error.InvalidAddress => return false,
            else => return err,
        },
        .message_id => {
            var ids: thread_ids.Iterator = .{ .text = value };
            if (headers.message_id == null) {
                if (ids.next()) |id| headers.message_id = try a.dupe(u8, id);
            }
        },
    }
    return true;
}

/// A null result suppresses a reply. All returned strings use the delivery arena.
pub fn inspect(a: std.mem.Allocator, raw: []const u8) !?Headers {
    var result: Headers = .{};
    var field: Field = .ignore;
    var value: std.ArrayList(u8) = .empty;
    defer value.deinit(a);
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |physical| {
        const line = std.mem.trimEnd(u8, physical, "\r");
        if (line.len > 0 and (line[0] == ' ' or line[0] == '\t')) {
            if (field != .ignore) {
                if (value.items.len + line.len > 8192) return null;
                try value.append(a, ' ');
                try value.appendSlice(a, std.mem.trim(u8, line, " \t"));
            }
            continue;
        }
        if (!try parseField(a, &result, field, value.items)) return null;
        if (line.len == 0) return result;
        value.clearRetainingCapacity();
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return null;
        const name = std.mem.trimEnd(u8, line[0..colon], " \t");
        if (std.ascii.startsWithIgnoreCase(name, "List-") or std.ascii.eqlIgnoreCase(name, "X-Mail-Forwarded") or
            std.ascii.eqlIgnoreCase(name, "X-Autoreply") or std.ascii.eqlIgnoreCase(name, "X-Autorespond")) return null;
        field = fieldFor(name);
        if (field != .ignore) {
            if (line.len > 8192) return null;
            try value.appendSlice(a, std.mem.trim(u8, line[colon + 1 ..], " \t"));
        }
    }
    return null;
}

pub fn render(a: std.mem.Allocator, author: []const u8, to: []const u8, subject: []const u8, body: []const u8, parent: ?[]const u8, now: i64) ![]const u8 {
    if (!addresses.validMailbox(author) or !addresses.validMailbox(to)) return error.InvalidAddress;
    if (!std.unicode.utf8ValidateSlice(subject)) return error.InvalidSubject;
    const domain = author[std.mem.indexOfScalar(u8, author, '@').? + 1 ..];
    const date = try time.formatRfc5322Date(a, now);
    defer a.free(date);
    var nonce: [16]u8 = undefined;
    io.randomBytes(&nonce);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    try out.print(a, "From: {s}\r\nTo: {s}\r\nDate: {s}\r\nMessage-ID: <vacation-{s}@{s}>\r\nSubject: Auto: ", .{
        author, to, date, std.fmt.bytesToHex(nonce, .lower), domain,
    });
    // Encode complete UTF-8 characters in each RFC 2047 word, and fold between words.
    const encoder = std.base64.standard.Encoder;
    var encoded: [76]u8 = undefined;
    var offset: usize = 0;
    while (offset < subject.len) {
        var end = @min(offset + 42, subject.len);
        while (end < subject.len and (subject[end] & 0xc0) == 0x80) end -= 1;
        if (offset != 0) try out.appendSlice(a, "\r\n ");
        try out.print(a, "=?UTF-8?B?{s}?=", .{encoder.encode(&encoded, subject[offset..end])});
        offset = end;
    }
    try out.appendSlice(a, "\r\nAuto-Submitted: auto-replied\r\nX-Auto-Response-Suppress: All\r\n");
    if (parent) |id| try out.print(a, "In-Reply-To: {s}\r\nReferences: {s}\r\n", .{ id, id });
    try out.appendSlice(a, "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n");
    var canonical: std.ArrayList(u8) = .empty;
    defer canonical.deinit(a);
    for (body, 0..) |byte, i| {
        if (byte == '\r' and i + 1 < body.len and body[i + 1] == '\n') continue;
        if (byte == '\r' or byte == '\n') try canonical.appendSlice(a, "\r\n") else try canonical.append(a, byte);
    }
    offset = 0;
    while (offset < canonical.items.len) : (offset += 57) {
        try out.appendSlice(a, encoder.encode(&encoded, canonical.items[offset..@min(offset + 57, canonical.items.len)]));
        try out.appendSlice(a, "\r\n");
    }
    return out.toOwnedSlice(a);
}
