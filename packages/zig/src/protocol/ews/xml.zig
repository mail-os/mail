//! Bounded XML element traversal for EWS and DAV requests.
const std = @import("std");

const whitespace = " \t\r\n";
const ParseError = error{InvalidXml};

pub const Element = struct {
    name: []const u8,
    qualified_name: []const u8,
    attributes: []const u8,
    content: []const u8,

    pub fn children(self: Element) Iterator {
        return .{ .input = self.content };
    }

    pub fn child(self: Element, name: []const u8) ParseError!?Element {
        var items = self.children();
        while (try items.next()) |item| {
            if (std.mem.eql(u8, item.name, name)) return item;
        }
        return null;
    }

    pub fn attribute(self: Element, name: []const u8) ?[]const u8 {
        var rest = self.attributes;
        while (true) {
            rest = std.mem.trimStart(u8, rest, whitespace);
            const equal = std.mem.indexOfScalar(u8, rest, '=') orelse return null;
            const key = std.mem.trimEnd(u8, rest[0..equal], whitespace);
            rest = std.mem.trimStart(u8, rest[equal + 1 ..], whitespace);
            if (rest.len == 0 or (rest[0] != '"' and rest[0] != '\'')) return null;
            const end = std.mem.indexOfScalarPos(u8, rest, 1, rest[0]) orelse return null;
            if (std.mem.eql(u8, key, name)) return rest[1..end];
            rest = rest[end + 1 ..];
        }
    }
};

const Tag = struct { name: []const u8, attributes: []const u8, start: usize, closing: bool, empty: bool };

pub const Iterator = struct {
    input: []const u8,
    pos: usize = 0,
    element_only: bool = false,

    fn nextTag(self: *Iterator, element_only: bool) ParseError!?Tag {
        while (std.mem.indexOfScalarPos(u8, self.input, self.pos, '<')) |start| {
            if (element_only and std.mem.trim(u8, self.input[self.pos..start], whitespace).len != 0) return error.InvalidXml;
            const tail = self.input[start + 1 ..];
            const skipped: ?struct { prefix: []const u8, suffix: []const u8 } =
                if (std.mem.startsWith(u8, tail, "!--")) .{ .prefix = "!--", .suffix = "-->" } else if (std.mem.startsWith(u8, tail, "![CDATA[")) .{ .prefix = "![CDATA[", .suffix = "]]>" } else if (std.mem.startsWith(u8, tail, "?")) .{ .prefix = "?", .suffix = "?>" } else null;
            if (skipped) |section| {
                if (element_only and std.mem.eql(u8, section.prefix, "![CDATA[")) return error.InvalidXml;
                const end = std.mem.indexOfPos(u8, tail, section.prefix.len, section.suffix) orelse return error.InvalidXml;
                self.pos = start + 1 + end + section.suffix.len;
                continue;
            }
            var quote: u8 = 0;
            const end = for (tail, 0..) |byte, index| {
                if (quote != 0) {
                    if (byte == quote) quote = 0;
                } else if (byte == '"' or byte == '\'') {
                    quote = byte;
                } else if (byte == '>') break index else if (byte == '<') return error.InvalidXml;
            } else return error.InvalidXml;
            self.pos = start + end + 2;
            var inside = std.mem.trimEnd(u8, tail[0..end], whitespace);
            const closing = std.mem.startsWith(u8, inside, "/");
            if (closing) inside = inside[1..];
            const empty = std.mem.endsWith(u8, inside, "/");
            if (empty) inside = inside[0 .. inside.len - 1];
            const name_end = std.mem.indexOfAny(u8, inside, whitespace) orelse inside.len;
            const name = inside[0..name_end];
            if (name.len == 0 or name[0] == '!' or (closing and empty)) return error.InvalidXml;
            return .{ .name = name, .attributes = inside[name_end..], .start = start, .closing = closing, .empty = empty };
        }
        if (element_only and std.mem.trim(u8, self.input[self.pos..], whitespace).len != 0) return error.InvalidXml;
        return null;
    }

    pub fn next(self: *Iterator) ParseError!?Element {
        const start = (try self.nextTag(self.element_only)) orelse return null;
        if (start.closing) return error.InvalidXml;
        const local = if (std.mem.indexOfScalar(u8, start.name, ':')) |colon| start.name[colon + 1 ..] else start.name;
        if (start.empty) return .{ .name = local, .qualified_name = start.name, .attributes = start.attributes, .content = "" };
        const content_start = self.pos;
        var stack: [64][]const u8 = undefined;
        stack[0] = start.name;
        var depth: usize = 1;
        while (try self.nextTag(false)) |tag| {
            if (tag.closing) {
                if (!std.mem.eql(u8, tag.name, stack[depth - 1])) return error.InvalidXml;
                depth -= 1;
                if (depth == 0) return .{ .name = local, .qualified_name = start.name, .attributes = start.attributes, .content = self.input[content_start..tag.start] };
            } else if (!tag.empty) {
                if (depth == stack.len) return error.InvalidXml;
                stack[depth] = tag.name;
                depth += 1;
            }
        }
        return error.InvalidXml;
    }
};

pub fn operation(soap: []const u8, expected: []const u8) ParseError!Element {
    var document = Iterator{ .input = soap };
    const envelope = (try document.next()) orelse return error.InvalidXml;
    if (!std.mem.eql(u8, envelope.name, "Envelope")) return error.InvalidXml;
    const body = (try envelope.child("Body")) orelse return error.InvalidXml;
    var operations = body.children();
    const request = (try operations.next()) orelse return error.InvalidXml;
    if (!std.mem.eql(u8, request.name, expected) or try operations.next() != null) return error.InvalidXml;
    return request;
}

/// Decode XML character references in element text.
pub fn unescapeText(a: std.mem.Allocator, s: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(a);
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == '&') {
            if (std.mem.startsWith(u8, s[i..], "&amp;")) {
                try buf.append(a, '&');
                i += 5;
                continue;
            }
            if (std.mem.startsWith(u8, s[i..], "&lt;")) {
                try buf.append(a, '<');
                i += 4;
                continue;
            }
            if (std.mem.startsWith(u8, s[i..], "&gt;")) {
                try buf.append(a, '>');
                i += 4;
                continue;
            }
            if (std.mem.startsWith(u8, s[i..], "&quot;")) {
                try buf.append(a, '"');
                i += 6;
                continue;
            }
            if (std.mem.startsWith(u8, s[i..], "&apos;")) {
                try buf.append(a, '\'');
                i += 6;
                continue;
            }
            if (std.mem.startsWith(u8, s[i..], "&#")) {
                if (std.mem.indexOfScalarPos(u8, s, i, ';')) |semi| {
                    const num = s[i + 2 .. semi];
                    const cp: ?u21 = if (num.len > 1 and (num[0] == 'x' or num[0] == 'X'))
                        (std.fmt.parseInt(u21, num[1..], 16) catch null)
                    else
                        (std.fmt.parseInt(u21, num, 10) catch null);
                    if (cp) |code| {
                        var utf8: [4]u8 = undefined;
                        if (std.unicode.utf8Encode(code, &utf8)) |n| {
                            try buf.appendSlice(a, utf8[0..n]);
                            i = semi + 1;
                            continue;
                        } else |_| {}
                    }
                }
            }
        }
        try buf.append(a, s[i]);
        i += 1;
    }
    return buf.toOwnedSlice(a);
}
