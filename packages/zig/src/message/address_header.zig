//! Iterate address-list parts without splitting quoted strings, comments,
//! domain literals, or angle addresses on their internal punctuation.
const std = @import("std");

pub const Iterator = struct {
    value: []const u8,
    start: usize = 0,
    finished: bool = false,

    pub const Part = struct {
        text: []const u8,
        /// Byte position of the opening angle bracket, relative to text.
        angle_start: ?usize,
        separator: ?u8,
    };

    pub fn next(self: *Iterator) ?Part {
        if (self.finished) return null;
        const rest = self.value[self.start..];
        var angle_start: ?usize = null;
        var quoted = false;
        var escaped = false;
        var comments: usize = 0;
        var angled = false;
        var domain_literal = false;
        for (rest, 0..) |byte, index| {
            if (escaped) {
                escaped = false;
                continue;
            }
            if (byte == '\\' and (quoted or comments != 0 or domain_literal)) {
                escaped = true;
                continue;
            }
            if (!quoted and !domain_literal and byte == '(') {
                comments += 1;
                continue;
            }
            if (comments != 0) {
                if (byte == ')') comments -= 1;
                continue;
            }
            if (!domain_literal and byte == '"') quoted = !quoted;
            if (quoted) continue;
            if (byte == '[') domain_literal = true;
            if (byte == ']') domain_literal = false;
            if (domain_literal) continue;
            if (byte == '<') {
                if (angle_start == null) angle_start = index;
                angled = true;
            }
            if (byte == '>') angled = false;
            if (angled) continue;
            switch (byte) {
                ':', ',', ';' => {
                    self.start += index + 1;
                    return .{ .text = rest[0..index], .angle_start = angle_start, .separator = byte };
                },
                else => {},
            }
        }
        self.finished = true;
        return .{ .text = rest, .angle_start = angle_start, .separator = null };
    }
};

test "address separators respect quotes, comments, domain literals and routes" {
    const value = "Group: \"A, B\" (team: primary) <@relay:a@[IPv6:123]>, second@host;";
    var list: Iterator = .{ .value = value };
    const group = list.next().?;
    try std.testing.expectEqualStrings("Group", group.text);
    try std.testing.expectEqual(@as(?u8, ':'), group.separator);
    const first = list.next().?;
    try std.testing.expectEqualStrings("<@relay:a@[IPv6:123]>", first.text[first.angle_start.?..]);
    try std.testing.expectEqual(@as(?u8, ','), first.separator);
    const second = list.next().?;
    try std.testing.expectEqualStrings(" second@host", second.text);
    try std.testing.expectEqual(@as(?u8, ';'), second.separator);
    try std.testing.expectEqualStrings("", list.next().?.text);
    try std.testing.expect(list.next() == null);
}
