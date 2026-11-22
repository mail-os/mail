//! Collection metadata for DAV:propertyupdate requests.
const std = @import("std");
const store = @import("../storage/caldav_store.zig");
const xml = @import("ews/xml.zig");

pub const dav = "DAV:";
pub const caldav = "urn:ietf:params:xml:ns:caldav";
pub const carddav = "urn:ietf:params:xml:ns:carddav";
pub const ical = "http://apple.com/ns/ical/";
pub const xml_namespace = "http://www.w3.org/XML/1998/namespace";
const whitespace = " \t\r\n";
const Allocator = std.mem.Allocator;

pub const Status = enum {
    ok,
    forbidden,
    protected,
    conflict,
    dependency_failed,
    store_failed,

    pub fn line(self: Status) []const u8 {
        return switch (self) {
            .ok => "200 OK",
            .forbidden, .protected => "403 Forbidden",
            .conflict => "409 Conflict",
            .dependency_failed => "424 Failed Dependency",
            .store_failed => "500 Internal Server Error",
        };
    }
};

pub const Result = struct { name: []const u8, namespace: []const u8, status: Status = .ok };
pub const Update = struct {
    patch: store.CollectionPropertyPatch = .{},
    results: std.ArrayList(Result) = .empty,
};

pub fn parse(a: Allocator, body: []const u8, kind: store.SyncChange.ResourceType) !Update {
    if (body.len > 64 * 1024) return error.PropertyUpdateTooLarge;
    const input = if (std.mem.startsWith(u8, body, "\xef\xbb\xbf")) body[3..] else body;
    var document: xml.Iterator = .{ .input = input, .element_only = true };
    const root = (try document.next()) orelse return error.InvalidXml;
    if (!equal(root.name, "propertyupdate") or !equal(try namespace(a, root, &.{}), dav) or try document.next() != null)
        return error.InvalidXml;

    var update: Update = .{};
    var operations: xml.Iterator = .{ .input = root.content, .element_only = true };
    var failed = false;
    // The folded patch preserves document order, including repeated changes
    // to the same property. A failing instruction invalidates the whole patch.
    while (try operations.next()) |operation| {
        if (!equal(try namespace(a, operation, &.{root}), dav)) return error.InvalidXml;
        const remove = equal(operation.name, "remove");
        if (!remove and !equal(operation.name, "set")) return error.InvalidXml;
        var children: xml.Iterator = .{ .input = operation.content, .element_only = true };
        const prop = (try children.next()) orelse return error.InvalidXml;
        if (!equal(prop.name, "prop") or !equal(try namespace(a, prop, &.{ operation, root }), dav) or try children.next() != null)
            return error.InvalidXml;
        var properties: xml.Iterator = .{ .input = prop.content, .element_only = true };
        const start = update.results.items.len;
        while (try properties.next()) |element| {
            if (update.results.items.len == 128) return error.PropertyUpdateTooLarge;
            const ns = try namespace(a, element, &.{ prop, operation, root });
            const result = try update.results.addOne(a);
            result.* = .{ .name = element.name, .namespace = ns, .status = try setProperty(a, &update.patch, kind, ns, element, remove) };
            failed = failed or result.status != .ok;
        }
        if (start == update.results.items.len) return error.InvalidXml;
    }
    if (update.results.items.len == 0) return error.InvalidXml;
    if (failed) {
        update.patch = .{};
        for (update.results.items) |*result| {
            if (result.status == .ok) result.status = .dependency_failed;
        }
    }
    return update;
}

fn equal(left: []const u8, right: []const u8) bool {
    return std.mem.eql(u8, left, right);
}

fn namespace(a: Allocator, element: xml.Element, ancestors: []const xml.Element) ![]const u8 {
    if (!validName(element.name)) return error.InvalidXml;
    const prefix = element.qualified_name[0 .. element.qualified_name.len - element.name.len];
    var key: [262]u8 = undefined;
    const attribute = if (prefix.len == 0) "xmlns" else blk: {
        const name = prefix[0 .. prefix.len - 1];
        if (!validName(name)) return error.InvalidXml;
        if (equal(name, "xml")) return xml_namespace;
        if (equal(name, "xmlns")) return error.InvalidXml;
        break :blk try std.fmt.bufPrint(&key, "xmlns:{s}", .{name});
    };
    const raw = element.attribute(attribute) orelse for (ancestors) |ancestor| {
        if (ancestor.attribute(attribute)) |uri| break uri;
    } else if (prefix.len == 0) return "" else return error.InvalidXml;
    if (raw.len > 2048 or std.mem.indexOfScalar(u8, raw, '<') != null) return error.InvalidXml;
    const uri = readText(a, raw) catch |err| switch (err) {
        error.InvalidValue => return error.InvalidXml,
        else => return err,
    };
    if (uri.len == 0 and prefix.len != 0) return error.InvalidXml;
    if (equal(uri, xml_namespace) or equal(uri, "http://www.w3.org/2000/xmlns/")) return error.InvalidXml;
    return uri;
}

fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > 256) return false;
    const view = std.unicode.Utf8View.init(name) catch return false;
    var iterator = view.iterator();
    if (!nameStart(iterator.nextCodepoint().?)) return false;
    while (iterator.nextCodepoint()) |cp| {
        if (!nameStart(cp) and !(cp >= '0' and cp <= '9') and cp != '-' and cp != '.' and cp != 0xb7 and
            (cp < 0x0300 or cp > 0x036f) and (cp < 0x203f or cp > 0x2040)) return false;
    }
    return true;
}

fn nameStart(cp: u21) bool {
    // XML NCNameStartChar, excluding the namespace separator.
    return switch (cp) {
        'A'...'Z',
        'a'...'z',
        '_',
        0xc0...0xd6,
        0xd8...0xf6,
        0xf8...0x2ff,
        0x370...0x37d,
        0x37f...0x1fff,
        0x200c...0x200d,
        0x2070...0x218f,
        0x2c00...0x2fef,
        0x3001...0xd7ff,
        0xf900...0xfdcf,
        0xfdf0...0xfffd,
        0x10000...0xeffff,
        => true,
        else => false,
    };
}

fn setProperty(a: Allocator, patch: *store.CollectionPropertyPatch, kind: store.SyncChange.ResourceType, ns: []const u8, element: xml.Element, remove: bool) !Status {
    const name = element.name;
    const is_calendar = kind == .event;
    const field: *store.CollectionProperty = if (equal(ns, dav) and equal(name, "displayname"))
        &patch.display_name
    else if ((is_calendar and equal(ns, caldav) and equal(name, "calendar-description")) or
        (!is_calendar and equal(ns, carddav) and equal(name, "addressbook-description")))
        &patch.description
    else if (is_calendar and equal(ns, ical) and equal(name, "calendar-color"))
        &patch.color
    else
        return if (protectedProperty(ns, name)) .protected else .forbidden;
    if (remove) {
        if (std.mem.trim(u8, element.content, whitespace).len != 0) return .conflict;
        field.* = .remove;
        return .ok;
    }
    var value = readText(a, element.content) catch |err| switch (err) {
        error.InvalidValue => return .conflict,
        else => return err,
    };
    if (field == &patch.color) {
        value = std.mem.trim(u8, value, whitespace);
        if ((value.len != 7 and value.len != 9) or value[0] != '#') return .conflict;
        for (value[1..]) |byte| if (!std.ascii.isHex(byte)) return .conflict;
    } else if (value.len > (if (field == &patch.description) @as(usize, 16 * 1024) else 1024)) {
        return .conflict;
    }
    field.* = .{ .set = value };
    return .ok;
}

fn protectedProperty(ns: []const u8, name: []const u8) bool {
    const protected: []const []const u8 = if (equal(ns, dav))
        &.{ "resourcetype", "getetag", "sync-token", "getlastmodified", "getcontenttype", "getcontentlength", "creationdate", "supported-report-set", "current-user-privilege-set" }
    else if (equal(ns, caldav))
        &.{ "supported-calendar-component-set", "supported-calendar-data", "calendar-home-set" }
    else if (equal(ns, carddav))
        &.{ "supported-address-data", "addressbook-home-set" }
    else if (equal(ns, "http://calendarserver.org/ns/"))
        &.{"getctag"}
    else
        &.{};
    for (protected) |property| if (equal(name, property)) return true;
    return false;
}

fn readText(a: Allocator, content: []const u8) ![]const u8 {
    var text: std.ArrayList(u8) = .empty;
    var remaining = content;
    while (remaining.len != 0) {
        const end = std.mem.indexOfScalar(u8, remaining, '<') orelse remaining.len;
        const plain = remaining[0..end];
        try validateReferences(plain);
        try text.appendSlice(a, try xml.unescapeText(a, plain));
        remaining = remaining[end..];
        if (remaining.len == 0) break;
        if (std.mem.startsWith(u8, remaining, "<![CDATA[")) {
            const close = std.mem.indexOfPos(u8, remaining, 9, "]]>") orelse return error.InvalidValue;
            try text.appendSlice(a, remaining[9..close]);
            remaining = remaining[close + 3 ..];
        } else if (std.mem.startsWith(u8, remaining, "<!--")) {
            const close = std.mem.indexOfPos(u8, remaining, 4, "-->") orelse return error.InvalidValue;
            remaining = remaining[close + 3 ..];
        } else return error.InvalidValue;
    }
    const view = std.unicode.Utf8View.init(text.items) catch return error.InvalidValue;
    var iterator = view.iterator();
    while (iterator.nextCodepoint()) |cp| if (!allowedCharacter(cp)) return error.InvalidValue;
    return text.items;
}

fn validateReferences(text: []const u8) !void {
    if (std.mem.indexOf(u8, text, "]]>") != null) return error.InvalidValue;
    var start: usize = 0;
    while (std.mem.indexOfScalarPos(u8, text, start, '&')) |amp| {
        const semi = std.mem.indexOfScalarPos(u8, text, amp + 1, ';') orelse return error.InvalidValue;
        const reference = text[amp + 1 .. semi];
        if (std.mem.startsWith(u8, reference, "#")) {
            const hex = std.mem.startsWith(u8, reference, "#x");
            const digit_start: usize = if (hex) 2 else 1;
            const digits = reference[digit_start..];
            for (digits) |digit| if (!(if (hex) std.ascii.isHex(digit) else std.ascii.isDigit(digit))) return error.InvalidValue;
            const cp = std.fmt.parseInt(u21, digits, if (hex) 16 else 10) catch return error.InvalidValue;
            if (!allowedCharacter(cp)) return error.InvalidValue;
        } else if (!equal(reference, "amp") and !equal(reference, "lt") and !equal(reference, "gt") and !equal(reference, "quot") and !equal(reference, "apos")) {
            return error.InvalidValue;
        }
        start = semi + 1;
    }
}

fn allowedCharacter(cp: u21) bool {
    return switch (cp) {
        '\t', '\n', '\r', 0x20...0xd7ff, 0xe000...0xfffd, 0x10000...0x10ffff => true,
        else => false,
    };
}
