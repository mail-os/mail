//! Parse IMAP SEARCH into predicates without interpreting string arguments as keys.
const std = @import("std");
const maildir_keywords = @import("../storage/maildir_keywords.zig");

const Allocator = std.mem.Allocator;
const ParseError = Allocator.Error || error{ InvalidSearch, UnsupportedCharset, UnsupportedSearchKey };

const FlagName = enum { answered, deleted, draft, flagged, seen };
pub const Flags = struct { name: FlagName, required: bool };

pub const Keyword = struct { name: []const u8, required: bool };

pub const Range = struct {
    first: u32,
    last: u32,
};

pub const Set = struct {
    uid: bool,
    ranges: []const Range,

    pub fn contains(self: Set, value: i64, maximum: i64) bool {
        for (self.ranges) |range| {
            const first = if (range.first == 0) maximum else range.first;
            const last = if (range.last == 0) maximum else range.last;
            if (value >= @min(first, last) and value <= @max(first, last)) return true;
        }
        return false;
    }
};

/// Parse a sequence-set operand in full using the request's arena.
pub fn parseSet(a: Allocator, raw: []const u8, uid: bool) ParseError!Set {
    var ranges: std.ArrayList(Range) = .empty;
    var parts = std.mem.splitScalar(u8, raw, ',');
    while (parts.next()) |part| {
        var bounds = std.mem.splitScalar(u8, part, ':');
        const first = try endpoint(bounds.next() orelse return error.InvalidSearch);
        const last = if (bounds.next()) |raw_last| try endpoint(raw_last) else first;
        if (bounds.next() != null) return error.InvalidSearch;
        try ranges.append(a, .{ .first = first, .last = last });
    }
    return .{ .uid = uid, .ranges = ranges.items };
}

const TextField = enum { header, body, message };
pub const Text = struct {
    field: TextField,
    header: []const u8 = "",
    term: []const u8,
    index_field: ?[]const u8 = null,
};

const DateRelation = enum { before, on, since };
pub const Date = struct {
    day: u32,
    relation: DateRelation,
    sent: bool,
};

pub const Node = union(enum) {
    all,
    none,
    flag: Flags,
    keyword: Keyword,
    set: Set,
    text: usize,
    date: Date,
    size: struct { bytes: u64, larger: bool },
    group: []const *const Node,
    either: [2]*const Node,
    negate: *const Node,

    pub fn matches(self: *const Node, message: anytype) anyerror!bool {
        return switch (self.*) {
            .all => true,
            .none => false,
            .group => |children| blk: {
                for (children) |child| {
                    if (!try child.matches(message)) break :blk false;
                }
                break :blk true;
            },
            .either => |children| (try children[0].matches(message)) or (try children[1].matches(message)),
            .negate => |child| !try child.matches(message),
            else => message.matchesLeaf(self.*),
        };
    }
};

pub const Query = struct { root: *const Node, text: []const Text };

pub fn parse(a: Allocator, source: []const u8) ParseError!Query {
    var parser = Parser{ .a = a, .rest = source };
    const first = parser.trim();
    if (first.len > 0 and first[0] != '(' and first[0] != '"' and first[0] != ')') {
        const key = try parser.atom();
        if (std.ascii.eqlIgnoreCase(key, "CHARSET")) {
            const charset = try parser.value();
            if (!std.ascii.eqlIgnoreCase(charset, "US-ASCII") and !std.ascii.eqlIgnoreCase(charset, "UTF-8"))
                return error.UnsupportedCharset;
        } else {
            parser.rest = first;
        }
    }
    if (parser.trim().len == 0) return error.InvalidSearch;
    const root = try parser.group(0, false);
    return .{ .root = root, .text = parser.text.items };
}

const Parser = struct {
    a: Allocator,
    rest: []const u8,
    text: std.ArrayList(Text) = .empty,

    fn trim(self: *Parser) []const u8 {
        self.rest = std.mem.trimStart(u8, self.rest, " \t");
        return self.rest;
    }

    fn atom(self: *Parser) ParseError![]const u8 {
        const rest = self.trim();
        const end = std.mem.indexOfAny(u8, rest, " \t()\"") orelse rest.len;
        if (end == 0) return error.InvalidSearch;
        self.rest = rest[end..];
        return rest[0..end];
    }

    fn value(self: *Parser) ParseError![]const u8 {
        const rest = self.trim();
        if (rest.len == 0 or rest[0] == '{') return error.InvalidSearch;
        if (rest[0] != '"') return self.atom();
        for (rest[1..], 1..) |byte, i| {
            if (byte == '\\') break;
            if (byte == '"') {
                self.rest = rest[i + 1 ..];
                return rest[1..i];
            }
        }
        var decoded: std.ArrayList(u8) = .empty;
        var i: usize = 1;
        while (i < rest.len) : (i += 1) {
            switch (rest[i]) {
                '"' => {
                    self.rest = rest[i + 1 ..];
                    return decoded.items;
                },
                '\\' => {
                    i += 1;
                    if (i == rest.len or (rest[i] != '"' and rest[i] != '\\')) return error.InvalidSearch;
                },
                else => {},
            }
            try decoded.append(self.a, rest[i]);
        }
        return error.InvalidSearch;
    }

    fn node(self: *Parser, value_node: Node) ParseError!*const Node {
        const result = try self.a.create(Node);
        result.* = value_node;
        return result;
    }

    fn group(self: *Parser, depth: usize, nested: bool) ParseError!*const Node {
        var children: std.ArrayList(*const Node) = .empty;
        while (self.trim().len > 0 and self.rest[0] != ')') {
            try children.append(self.a, try self.key(depth));
        }
        if (children.items.len == 0) return error.InvalidSearch;
        if (nested) {
            if (self.rest.len == 0) return error.InvalidSearch;
            self.rest = self.rest[1..];
        } else if (self.rest.len != 0) return error.InvalidSearch;
        return if (children.items.len == 1) children.items[0] else self.node(.{ .group = children.items });
    }

    fn key(self: *Parser, depth: usize) ParseError!*const Node {
        if (depth >= 32 or self.trim().len == 0) return error.InvalidSearch;
        if (self.rest[0] == '(') {
            self.rest = self.rest[1..];
            return self.group(depth + 1, true);
        }
        const name = try self.atom();
        if (std.ascii.eqlIgnoreCase(name, "OR")) {
            const first = try self.key(depth + 1);
            const second = try self.key(depth + 1);
            return self.node(.{ .either = .{ first, second } });
        }
        if (std.ascii.eqlIgnoreCase(name, "NOT")) return self.node(.{ .negate = try self.key(depth + 1) });
        if (std.ascii.eqlIgnoreCase(name, "ALL") or std.ascii.eqlIgnoreCase(name, "OLD")) return self.node(.all);
        if (std.ascii.eqlIgnoreCase(name, "RECENT") or std.ascii.eqlIgnoreCase(name, "NEW")) return self.node(.none);

        // UN* prefixes both system-flag and keyword predicates.
        const positive = name.len < 2 or !std.ascii.eqlIgnoreCase(name[0..2], "UN");
        const flag_name = if (positive) name else name[2..];
        const flag = lookup(FlagName, flag_name);
        if (flag) |system| return self.node(.{ .flag = .{ .name = system, .required = positive } });
        if (std.ascii.eqlIgnoreCase(flag_name, "KEYWORD")) {
            const word = try self.atom();
            if (!maildir_keywords.validName(word)) return error.InvalidSearch;
            return self.node(.{ .keyword = .{ .name = word, .required = positive } });
        }

        if (std.ascii.eqlIgnoreCase(name, "UID")) return self.sequence(try self.atom(), true);
        if (std.ascii.isDigit(name[0]) or name[0] == '*') return self.sequence(name, false);

        const size_larger = std.ascii.eqlIgnoreCase(name, "LARGER");
        if (size_larger or std.ascii.eqlIgnoreCase(name, "SMALLER")) {
            const bytes = std.fmt.parseUnsigned(u64, try self.atom(), 10) catch return error.InvalidSearch;
            return self.node(.{ .size = .{ .bytes = bytes, .larger = size_larger } });
        }

        const sent = name.len > 4 and std.ascii.eqlIgnoreCase(name[0..4], "SENT");
        const date_name = if (sent) name[4..] else name;
        const relation = lookup(DateRelation, date_name);
        if (relation) |date_relation| {
            const day = parseDay(try self.value()) orelse return error.InvalidSearch;
            return self.node(.{ .date = .{ .day = day, .relation = date_relation, .sent = sent } });
        }

        return self.textKey(name);
    }

    fn sequence(self: *Parser, raw: []const u8, uid: bool) ParseError!*const Node {
        return self.node(.{ .set = try parseSet(self.a, raw, uid) });
    }

    fn textKey(self: *Parser, name: []const u8) ParseError!*const Node {
        const criteria = [_]struct { name: []const u8, field: TextField, header: []const u8 = "", index_field: ?[]const u8 = null }{
            .{ .name = "FROM", .field = .header, .header = "From", .index_field = "sender" },
            .{ .name = "TO", .field = .header, .header = "To", .index_field = "recipients" },
            .{ .name = "CC", .field = .header, .header = "Cc" },
            .{ .name = "BCC", .field = .header, .header = "Bcc" },
            .{ .name = "SUBJECT", .field = .header, .header = "Subject", .index_field = "subject" },
            .{ .name = "BODY", .field = .body, .index_field = "body" },
            .{ .name = "TEXT", .field = .message, .index_field = "subject,sender,recipients,body" },
        };
        const item: Text = if (std.ascii.eqlIgnoreCase(name, "HEADER"))
            .{ .field = .header, .header = try self.value(), .term = try self.value() }
        else for (criteria) |criterion| {
            if (std.ascii.eqlIgnoreCase(criterion.name, name))
                break .{ .field = criterion.field, .header = criterion.header, .term = try self.value(), .index_field = criterion.index_field };
        } else return error.UnsupportedSearchKey;
        const index = self.text.items.len;
        try self.text.append(self.a, item);
        return self.node(.{ .text = index });
    }
};

fn lookup(comptime E: type, value: []const u8) ?E {
    inline for (comptime std.meta.fieldNames(E)) |name| {
        if (std.ascii.eqlIgnoreCase(name, value)) return @field(E, name);
    }
    return null;
}

fn endpoint(value: []const u8) ParseError!u32 {
    if (std.mem.eql(u8, value, "*")) return 0;
    for (value) |byte| {
        if (!std.ascii.isDigit(byte)) return error.InvalidSearch;
    }
    const number = std.fmt.parseUnsigned(u32, value, 10) catch return error.InvalidSearch;
    return if (number > 0) number else error.InvalidSearch;
}

/// IMAP compares calendar dates without a time or timezone.
pub fn parseDay(value: []const u8) ?u32 {
    var parts = std.mem.splitScalar(u8, value, '-');
    const day = std.fmt.parseUnsigned(u8, parts.next() orelse return null, 10) catch return null;
    const month = parts.next() orelse return null;
    const year_text = parts.next() orelse return null;
    if (year_text.len != 4 or parts.next() != null) return null;
    const year = std.fmt.parseUnsigned(u16, year_text, 10) catch return null;
    if (year == 0 or day == 0) return null;
    for ([_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" }, 1..) |name, index| {
        if (!std.ascii.eqlIgnoreCase(month, name)) continue;
        const epoch_month: std.time.epoch.Month = @fromBackingInt(@intCast(index));
        if (day > std.time.epoch.getDaysInMonth(year, epoch_month)) return null;
        return @as(u32, year) * 10_000 + @as(u32, @intCast(index)) * 100 + day;
    }
    return null;
}
