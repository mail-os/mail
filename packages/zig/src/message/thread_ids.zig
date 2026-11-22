const std = @import("std");

pub const Iterator = struct {
    text: []const u8,
    remaining: usize = 64,

    pub fn next(self: *Iterator) ?[]const u8 {
        while (self.remaining > 0) : (self.remaining -= 1) {
            const open = std.mem.indexOfScalar(u8, self.text, '<') orelse return null;
            const close = std.mem.indexOfScalarPos(u8, self.text, open + 1, '>') orelse return null;
            const id = self.text[open .. close + 1];
            self.text = self.text[close + 1 ..];
            if (id.len < 5 or id.len > 320 or std.mem.indexOfScalar(u8, id, '@') == null) continue;
            for (id[1 .. id.len - 1]) |byte| {
                if (byte <= 0x20 or byte >= 0x7f or byte == '<' or byte == '>') break;
            } else {
                self.remaining -= 1;
                return id;
            }
        }
        return null;
    }
};

pub const Headers = struct {
    own: ?[]const u8 = null,
    parents: []const []const u8 = &.{},
    automatic: bool = false,

    pub fn keys(self: Headers, a: std.mem.Allocator) ![]const []const u8 {
        const own = self.own orelse return self.parents;
        const all = try a.alloc([]const u8, self.parents.len + 1);
        all[0] = own;
        @memcpy(all[1..], self.parents);
        return all;
    }
};

/// Message identifiers cannot fold internally, so an unfolded header can be
/// read one physical line at a time. Only inspect the top-level MIME headers.
pub fn parse(a: std.mem.Allocator, raw: []const u8) !Headers {
    const Field = enum { ignore, own, parent, automatic };
    var field: Field = .ignore;
    var result: Headers = .{};
    var parents: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) break;
        var value = trimmed;
        if (line[0] != ' ' and line[0] != '\t') {
            field = .ignore;
            const colon = std.mem.indexOfScalar(u8, trimmed, ':') orelse continue;
            const name = trimmed[0..colon];
            value = std.mem.trim(u8, trimmed[colon + 1 ..], " \t");
            if (std.ascii.eqlIgnoreCase(name, "Message-ID")) field = .own;
            if (std.ascii.eqlIgnoreCase(name, "In-Reply-To") or std.ascii.eqlIgnoreCase(name, "References")) field = .parent;
            if (std.ascii.eqlIgnoreCase(name, "Auto-Submitted")) field = .automatic;
        }
        var ids: Iterator = .{ .text = value };
        switch (field) {
            .ignore => {},
            .own => if (result.own == null) {
                result.own = ids.next();
            },
            .parent => while (parents.items.len < 64) {
                const id = ids.next() orelse break;
                try parents.append(a, id);
            },
            .automatic => if (value.len > 0 and !std.ascii.eqlIgnoreCase(value, "no")) {
                result.automatic = true;
            },
        }
    }
    result.parents = try parents.toOwnedSlice(a);
    return result;
}

pub fn fromFields(a: std.mem.Allocator, own: []const u8, parent: []const u8, references: []const u8) !Headers {
    var id: Iterator = .{ .text = own };
    var parents: std.ArrayList([]const u8) = .empty;
    for ([_][]const u8{ parent, references }) |field| {
        var ids: Iterator = .{ .text = field };
        while (parents.items.len < 64) {
            const value = ids.next() orelse break;
            try parents.append(a, value);
        }
    }
    return .{ .own = id.next(), .parents = try parents.toOwnedSlice(a) };
}
