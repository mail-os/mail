const std = @import("std");

pub const Destination = enum {
    inbox,
    newsletters,
    receipts,

    pub fn folder(self: Destination) []const u8 {
        return switch (self) {
            .inbox => "new",
            .newsletters => "Newsletters",
            .receipts => "Receipts",
        };
    }
};

pub const Reason = enum { sender_rule, mailing_list, receipt_subject, sender_review, spam_filter, junk_feedback, not_junk_feedback };
pub const Placement = struct { destination: Destination, reason: Reason };

pub fn isCategory(folder: []const u8) bool {
    return std.mem.eql(u8, folder, "Newsletters") or std.mem.eql(u8, folder, "Receipts");
}

const Header = struct {
    bytes: [2048]u8 = undefined,
    len: usize = 0,
    present: bool = false,
    invalid: bool = false,

    fn append(self: *Header, value: []const u8, continuation: bool) void {
        if (!continuation) {
            self.invalid = self.present;
            self.present = true;
        }
        if (self.invalid or value.len == 0) return;
        const separator: usize = @intFromBool(self.len > 0);
        if (value.len + separator > self.bytes.len - self.len) {
            self.invalid = true;
            return;
        }
        if (separator != 0) self.bytes[self.len] = ' ';
        self.len += separator;
        @memcpy(self.bytes[self.len..][0..value.len], value);
        self.len += value.len;
    }

    fn text(self: *const Header) []const u8 {
        return if (self.invalid) "" else self.bytes[0..self.len];
    }
};

pub fn classify(raw: []const u8) ?Placement {
    var list_id: Header = .{};
    var subject: Header = .{};
    var active: ?*Header = null;
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (line.len == 0) break;
        if (line[0] == ' ' or line[0] == '\t') {
            if (active) |header| header.append(std.mem.trim(u8, line, " \t"), true);
            continue;
        }
        active = null;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = line[0..colon];
        if (std.ascii.eqlIgnoreCase(name, "Subject")) active = &subject;
        if (std.ascii.eqlIgnoreCase(name, "List-Id")) active = &list_id;
        if (active) |header| header.append(std.mem.trim(u8, line[colon + 1 ..], " \t"), false);
    }
    if (isReceipt(subject.text())) return .{ .destination = .receipts, .reason = .receipt_subject };
    if (isListId(list_id.text())) return .{ .destination = .newsletters, .reason = .mailing_list };
    return null;
}

fn isReceipt(subject: []const u8) bool {
    const prefixes = [_][]const u8{
        "your receipt", "payment receipt", "order confirmation", "your invoice", "invoice", "payment received",
    };
    for (prefixes) |prefix| {
        if (!std.ascii.startsWithIgnoreCase(subject, prefix)) continue;
        if (subject.len == prefix.len or std.mem.indexOfScalar(u8, " \t:#-", subject[prefix.len]) != null) return true;
    }
    return false;
}

fn isListId(value: []const u8) bool {
    if (!std.mem.endsWith(u8, value, ">")) return false;
    const start = std.mem.indexOfScalar(u8, value, '<') orelse return false;
    const id = value[start + 1 .. value.len - 1];
    const dot = std.mem.indexOfScalar(u8, id, '.') orelse return false;
    if (dot == 0 or dot == id.len - 1) return false;
    for (id) |byte| {
        if (std.ascii.isWhitespace(byte) or std.ascii.isControl(byte) or byte == '<' or byte == '>') return false;
    }
    return true;
}

test "classify only top level list and receipt signals" {
    try std.testing.expectEqual(Reason.mailing_list, classify("List-Id: Digest <digest.example.test>\r\n\r\n").?.reason);
    try std.testing.expectEqual(Reason.mailing_list, classify("List-Id: Digest\r\n <digest.example.test>\r\n\r\n").?.reason);
    try std.testing.expectEqual(Reason.receipt_subject, classify("List-Id: <buy.example.test>\r\nSubject: Your receipt #543\r\n\r\n").?.reason);
    try std.testing.expectEqual(Reason.receipt_subject, classify("Subject: Your\r\n receipt #543\r\n\r\n").?.reason);
    try std.testing.expect(classify("Subject: Invoiceable time\r\nList-Unsubscribe: <https://example.test>\r\n\r\nList-Id: <bad.body.test>") == null);
    try std.testing.expect(classify("Subject: Re: Your receipt\nList-Id: <invalid>\n\n") == null);
    try std.testing.expect(classify("Subject: Something else\nSubject: Your receipt\nList-Id: <one.example>\nList-Id: <two.example>\n\n") == null);
}
