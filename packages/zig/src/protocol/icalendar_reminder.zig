const std = @import("std");
const ical = @import("icalendar.zig");
const clock = @import("icalendar_time.zig");

const Range = struct {
    first: i64,
    last: i64,

    fn include(range: *?Range, first: i64, last: i64) void {
        range.* = if (range.*) |prior| .{ .first = @min(first, prior.first), .last = @max(last, prior.last) } else .{ .first = first, .last = last };
    }

    fn overlaps(range: Range, start: i64, end: i64) bool {
        return range.first <= end and range.last >= start;
    }
};

/// Coarse absolute and relative firing ranges used to avoid fetching old,
/// unrelated resources. Clients expand the source and compute exact dates.
pub const Coverage = struct {
    absolute: ?Range = null,
    relative: ?Range = null,

    pub fn mayFire(self: Coverage, start: i64, end: i64, event_start: i64, event_end: ?i64, recurring: bool) bool {
        if (self.absolute) |range| if (range.overlaps(start, end)) return true;
        const relative = self.relative orelse return false;
        if (recurring) return true;
        // A DATE alarm uses the user's midnight. Nominal calendar-day
        // durations can also cross a time zone offset change.
        const pad = 2 * 86_400;
        return (Range{
            .first = event_start +| relative.first -| pad,
            .last = (event_end orelse event_start) +| relative.last +| pad,
        }).overlaps(start, end);
    }
};

pub fn coverage(allocator: std.mem.Allocator, source: []const u8) !Coverage {
    // Only parse resources containing an alarm. Component/Property parsing
    // handles folding and keeps nested properties out of the event itself.
    if (@import("ascii-compat").indexOfIgnoreCase(source, "VALARM") == null) return .{};
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const a = scratch.allocator();
    return readCoverage(a, source) catch |err| switch (err) {
        error.InvalidCalendar => .{},
        else => return err,
    };
}

fn readCoverage(a: std.mem.Allocator, source: []const u8) !Coverage {
    var result: Coverage = .{};
    for (try ical.components(a, source)) |event| {
        if (!std.ascii.eqlIgnoreCase(event.name, "VEVENT")) continue;
        for (try ical.childComponents(a, event)) |alarm| {
            if (!std.ascii.eqlIgnoreCase(alarm.name, "VALARM")) continue;
            var action: []const u8 = "";
            var trigger: ?ical.Property = null;
            var repeat: i64 = 0;
            var interval: i64 = 0;
            var fields = ical.Properties.init(alarm);
            while (try fields.next(a)) |field| {
                if (field.named("ACTION")) action = field.value;
                if (field.named("TRIGGER")) trigger = field;
                if (field.named("REPEAT")) repeat = std.fmt.parseInt(u32, field.value, 10) catch 0;
                if (field.named("DURATION")) interval = seconds(field.value) orelse 0;
            }
            if (!std.ascii.eqlIgnoreCase(action, "DISPLAY")) continue;
            const when = trigger orelse continue;
            const last = @min(repeat, 10000) * @max(interval, 0);
            if (clock.Date.parse(when.value)) |absolute| {
                if (absolute.kind == .utc) {
                    const first = absolute.epoch();
                    Range.include(&result.absolute, first, first + last);
                }
            } else if (seconds(when.value)) |offset| {
                Range.include(&result.relative, offset, offset + last);
            }
        }
    }
    return result;
}

fn seconds(value: []const u8) ?i64 {
    if (value.len == 0) return null;
    const sign: i64 = if (value[0] == '-') -1 else 1;
    const duration = if (value[0] == '-' or value[0] == '+') value[1..] else value;
    const parsed = clock.duration(duration) orelse return null;
    return sign * (parsed.days * 86_400 + parsed.seconds);
}
