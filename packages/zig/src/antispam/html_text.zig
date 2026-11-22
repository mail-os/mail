const std = @import("std");
const ascii_compat = @import("ascii-compat");

/// Replace a leading HTML entity with its character. Returns null when `s`
/// doesn't start with a known entity.
fn matchEntity(s: []const u8) ?struct { ch: u8, len: usize } {
    const table = [_]struct { name: []const u8, ch: u8 }{
        .{ .name = "&nbsp;", .ch = ' ' },
        .{ .name = "&amp;", .ch = '&' },
        .{ .name = "&lt;", .ch = '<' },
        .{ .name = "&gt;", .ch = '>' },
        .{ .name = "&quot;", .ch = '"' },
        .{ .name = "&#39;", .ch = '\'' },
        .{ .name = "&#32;", .ch = ' ' },
        .{ .name = "&#x20;", .ch = ' ' },
        .{ .name = "&#X20;", .ch = ' ' },
    };
    for (table) |e| {
        if (std.ascii.startsWithIgnoreCase(s, e.name)) return .{ .ch = e.ch, .len = e.name.len };
    }
    return null;
}

/// Reduce HTML to the text a mail client would render: drop <style>/<script>
/// blocks wholesale, drop tags, decode common entities, and collapse
/// whitespace runs to single spaces. Phrase matching runs on this, so markup
/// (or an entity like "mobile&nbsp;app") can't break up a phrase. Plain text
/// passes through with only whitespace collapsed.
pub fn extract(in: []const u8, out: []u8) []const u8 {
    var i: usize = 0;
    var o: usize = 0;
    var pending_space = false;
    while (i < in.len and o < out.len) {
        var c = in[i];
        // Zero-width Unicode characters and their common HTML encodings are
        // invisible in clients but otherwise split phrases such as "pay​ment".
        const zero_width = [_][]const u8{ "\xE2\x80\x8B", "\xE2\x80\x8C", "\xE2\x80\x8D", "&#8203;", "&#x200b;", "&#x200B;" };
        var skipped_zero_width = false;
        for (zero_width) |zw| {
            if (std.mem.startsWith(u8, in[i..], zw)) {
                i += zw.len;
                skipped_zero_width = true;
                break;
            }
        }
        if (skipped_zero_width) continue;
        if (c == '<') {
            if (std.ascii.startsWithIgnoreCase(in[i..], "<style")) {
                if (ascii_compat.indexOfIgnoreCase(in[i..], "</style")) |rel| {
                    const close = i + rel;
                    i = if (std.mem.indexOfScalarPos(u8, in, close, '>')) |gt| gt + 1 else in.len;
                } else i = in.len;
            } else if (std.ascii.startsWithIgnoreCase(in[i..], "<script")) {
                if (ascii_compat.indexOfIgnoreCase(in[i..], "</script")) |rel| {
                    const close = i + rel;
                    i = if (std.mem.indexOfScalarPos(u8, in, close, '>')) |gt| gt + 1 else in.len;
                } else i = in.len;
            } else {
                i = if (std.mem.indexOfScalarPos(u8, in, i, '>')) |gt| gt + 1 else in.len;
            }
            pending_space = true;
            continue;
        }
        if (c == '&') {
            if (matchEntity(in[i..])) |e| {
                c = e.ch;
                i += e.len;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
        if (c == ' ' or c == '\t' or c == '\r' or c == '\n') {
            pending_space = true;
            continue;
        }
        if (pending_space) {
            out[o] = ' ';
            o += 1;
            pending_space = false;
            if (o >= out.len) break;
        }
        out[o] = c;
        o += 1;
    }
    return out[0..o];
}
