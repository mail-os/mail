//! Headers and wire messages for verified mailbox forwarding.
const std = @import("std");
const time = @import("../core/time_compat.zig");
const io = @import("../core/io_compat.zig");
const addressing = @import("submission.zig");

pub const loop_header = "X-Mail-Forwarded: yes\r\n";

pub const Headers = struct {
    forwarded: bool = false,
    automatic: bool = false,
    subject: []const u8 = "",

    pub fn read(raw: []const u8) Headers {
        var result: Headers = .{};
        var lines = std.mem.splitScalar(u8, raw, '\n');
        while (lines.next()) |physical| {
            const line = std.mem.trimEnd(u8, physical, "\r");
            if (line.len == 0) break;
            if (line[0] == ' ' or line[0] == '\t') continue;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const name = std.mem.trimEnd(u8, line[0..colon], " \t");
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (std.ascii.eqlIgnoreCase(name, "X-Mail-Forwarded")) result.forwarded = true;
            if (std.ascii.eqlIgnoreCase(name, "Auto-Submitted")) {
                const token = std.mem.sliceTo(value, ';');
                result.automatic = result.automatic or !std.ascii.eqlIgnoreCase(std.mem.trimEnd(u8, token, " \t"), "no");
            }
            if (std.ascii.eqlIgnoreCase(name, "Subject") and value.len <= 240) {
                for (value) |byte| {
                    if (byte < ' ' or byte >= 0x7f) break;
                } else result.subject = value;
            }
        }
        return result;
    }
};

pub fn sender(a: std.mem.Allocator, owner: []const u8, hostname: []const u8) ![]const u8 {
    const domain = if (std.mem.lastIndexOfScalar(u8, owner, '@')) |at| owner[at + 1 ..] else hostname;
    return std.fmt.allocPrint(a, "no-reply@{s}", .{domain});
}

pub fn fitsSes(raw_len: usize) bool {
    // Reserve 2 KiB for the envelope headers and multipart delimiters.
    return raw_len <= (10 * 1024 * 1024 - 2048) / 78 * 57;
}

/// Give external copies a local sender for SPF, DKIM and SES. The attached
/// original is byte-for-byte intact, including signatures and attachments.
pub fn wrap(a: std.mem.Allocator, from: []const u8, to: []const u8, subject: []const u8, raw: []const u8) ![]const u8 {
    if (!addressing.validMailbox(from) or !addressing.validMailbox(to)) return error.InvalidAddress;
    // Hyphens in the boundary cannot occur in the Base64 attachment part.
    const boundary = "mail-forward-original";
    const date = try time.formatRfc5322Date(a, time.timestamp());
    defer a.free(date);
    const domain = from[std.mem.indexOfScalar(u8, from, '@').? + 1 ..];
    var nonce: [16]u8 = undefined;
    io.randomBytes(&nonce);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    try out.print(a, "From: {s}\r\nTo: {s}\r\nSubject: {s}{s}\r\nDate: {s}\r\nMessage-ID: <forward-{s}@{s}>\r\n", .{
        from, to, if (subject.len == 0) "Forwarded message" else "Fwd: ", subject, date, std.fmt.bytesToHex(nonce, .lower), domain,
    });
    try out.appendSlice(a, loop_header ++ "Auto-Submitted: auto-generated\r\nMIME-Version: 1.0\r\n" ++
        "Content-Type: multipart/mixed; boundary=\"" ++ boundary ++ "\"\r\n\r\n" ++
        "--" ++ boundary ++ "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" ++
        "The original message is attached.\r\n\r\n" ++
        "--" ++ boundary ++ "\r\nContent-Type: application/octet-stream; name=\"original.eml\"\r\n" ++
        "Content-Disposition: attachment; filename=\"original.eml\"\r\nContent-Transfer-Encoding: base64\r\n\r\n");
    const encoder = std.base64.standard.Encoder;
    var encoded: [76]u8 = undefined;
    var offset: usize = 0;
    while (offset < raw.len) : (offset += 57) {
        try out.appendSlice(a, encoder.encode(&encoded, raw[offset..@min(offset + 57, raw.len)]));
        try out.appendSlice(a, "\r\n");
    }
    try out.appendSlice(a, "--" ++ boundary ++ "--\r\n");
    return out.toOwnedSlice(a);
}
