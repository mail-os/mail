//! Associate MIME walker events with the original source lines.
const std = @import("std");
const mime = @import("zig-mime");

pub const Location = struct {
    start: usize = 0,
    end: usize = 0,
    blank: bool = false,
    eof: bool = false,

    pub fn bodyStart(self: Location) usize {
        // A missing separator leaves the current source line in the body.
        return if (self.blank) self.end else self.start;
    }

    pub fn bodyEnd(self: Location, raw: []const u8) usize {
        if (self.eof) return raw.len;
        // The newline immediately before a delimiter belongs to its framing.
        if (self.start >= 2 and std.mem.eql(u8, raw[self.start - 2 .. self.start], "\r\n")) return self.start - 2;
        if (self.start >= 1 and raw[self.start - 1] == '\n') return self.start - 1;
        return self.start;
    }
};

/// Feed one physical line at a time so part begin/end events can recover
/// original source bytes even for containers that emit no leaf body data.
pub fn walk(walker: *mime.Walker, scratch: []u8, raw: []const u8, headers: ?[]const u8, receiver: anytype, options: mime.Options) mime.Sink.Error!void {
    const Receiver = @TypeOf(receiver);
    const Source = struct {
        receiver: Receiver,
        location: Location = .{},
        boundaries: [mime.walker.max_depth_cap + 1][]const []const u8 = @splat(&.{}),

        pub fn onEvent(self: *@This(), event: mime.Event) mime.Sink.Error!void {
            switch (event) {
                .part_begin => |part| self.boundaries[part.depth] = part.boundaries,
                .part_end => |end| self.boundaries[end.part.depth] = &.{},
                else => {},
            }
            try self.receiver.onEvent(event, self.location);
        }

        fn terminalDelimiter(self: *const @This(), line: []const u8) bool {
            if (!std.mem.startsWith(u8, line, "--")) return false;
            for (self.boundaries) |open| {
                for (open) |boundary| {
                    if (std.mem.startsWith(u8, line[2..], boundary)) return true;
                }
            }
            return false;
        }
    };

    var source: Source = .{ .receiver = receiver };
    walker.* = mime.Walker.init(scratch, mime.Sink.init(&source), options);
    if (headers) |block| try walker.beginWithHeaders(block);
    var pos: usize = 0;
    while (pos < raw.len) {
        const end = if (std.mem.indexOfScalarPos(u8, raw, pos, '\n')) |nl| nl + 1 else raw.len;
        const line = raw[pos..end];
        source.location = .{ .start = pos, .end = end, .blank = std.mem.eql(u8, line, "\n") or std.mem.eql(u8, line, "\r\n") };
        try walker.feed(line);
        // Resolve a final delimiter before finish. Only a line matching an
        // open boundary gets a synthetic newline, so body bytes stay exact.
        if (end == raw.len and line[line.len - 1] != '\n' and source.terminalDelimiter(line)) try walker.feed("\n");
        pos = end;
    }
    source.location = .{ .start = raw.len, .end = raw.len, .eof = true };
    try walker.finish();
}

test "MIME source offsets preserve encoded section bytes with CRLF and LF" {
    const Sink = struct {
        raw: []const u8,
        start: usize = 0,
        section: []const u8 = "",

        pub fn onEvent(self: *@This(), event: mime.Event, location: Location) mime.Sink.Error!void {
            switch (event) {
                .part_begin => |part| if (part.depth == 1) {
                    self.start = location.bodyStart();
                },
                .part_end => |end| if (end.part.depth == 1) {
                    self.section = self.raw[self.start..location.bodyEnd(self.raw)];
                },
                else => {},
            }
        }
    };
    const messages = [_][]const u8{
        "--outer\r\nContent-Transfer-Encoding: base64\r\n\r\nAAEC/w==\r\n--outer--",
        "--outer\nContent-Transfer-Encoding: base64\n\nAAEC/w==\n--outer--",
    };
    var scratch: [4096]u8 = undefined;
    var walker: mime.Walker = undefined;
    for (messages) |raw| {
        var sink: Sink = .{ .raw = raw };
        try walk(&walker, &scratch, raw, "Content-Type: multipart/mixed; boundary=outer", &sink, .{});
        try std.testing.expectEqualStrings("AAEC/w==", sink.section);
    }
}
