//! Project saved iCalendar series into the ActiveSync Calendar wire model.
const std = @import("std");
const ical = @import("icalendar.zig");
const clock = @import("icalendar_time.zig");
const recurrence = @import("icalendar_busy.zig");
const store = @import("../storage/caldav_store.zig");
const Allocator = std.mem.Allocator;
const day = 86400;

const Pattern = struct {
    kind: u8,
    interval: i64,
    count: ?i64,
    until: ?i64 = null,
    weekdays: ?u8 = null,
    first_day: ?i64 = null,
    month_day: ?u8 = null,
    week: ?u8 = null,
    month: ?u8 = null,
};

const Exception = struct {
    original: i64,
    moved: ?struct {
        start: i64,
        end: i64,
        summary: ?[]const u8,
        description: ?[]const u8,
        location: ?[]const u8,
    } = null,
};

pub const Series = struct {
    start: i64,
    end: i64,
    timezone: ?[172]u8,
    pattern: Pattern,
    title: []const u8,
    description: ?[]const u8,
    location: ?[]const u8,
    exceptions: []const Exception,
};

pub fn project(a: Allocator, detail: store.CalendarEventDetail, timezone: []const u8, version: u8) !Series {
    const source = if (detail.ics_data.len != 0) detail.ics_data else try legacySeries(a, detail);
    const components = try ical.components(a, source);
    var master: ?ical.Component = null;
    var detached: std.ArrayList(ical.Component) = .empty;
    for (components) |component| {
        if (!std.ascii.eqlIgnoreCase(component.name, "VEVENT")) continue;
        if (try property(a, component, "RECURRENCE-ID")) |id| {
            if (id.param("RANGE") != null or detached.items.len >= 256) return error.UnrepresentableSeries;
            try detached.append(a, component);
        } else {
            if (master != null) return error.UnrepresentableSeries;
            master = component;
        }
    }
    const event = master orelse return error.UnrepresentableSeries;
    var props = ical.Properties.init(event);
    var parsed_rule: ?recurrence.Rule = null;
    var excluded: std.ArrayList(ical.Property) = .empty;
    while (try props.next(a)) |field| {
        if (field.named("RDATE") or field.named("EXRULE")) return error.UnrepresentableSeries;
        if (field.named("RRULE")) {
            if (parsed_rule != null) return error.UnrepresentableSeries;
            parsed_rule = try recurrence.Rule.parse(a, field.value);
        }
        if (field.named("EXDATE")) try excluded.append(a, field);
        if (field.named("STATUS") and std.ascii.eqlIgnoreCase(field.value, "CANCELLED")) return error.UnrepresentableSeries;
    }
    const rule = parsed_rule orelse return error.UnrepresentableSeries;
    var projection = try recurrence.RangeProjection.initWithTimezone(a, event, components, timezone);
    const date = projection.seed.date;
    const start = projection.seed.stamp();
    const end = try projection.seedEnd(a);
    const duration = end - start;
    var pattern = try wirePattern(rule, date, version);
    const min_gap: i64 = switch (pattern.kind) {
        0 => pattern.interval * day,
        1 => if (@popCount(pattern.weekdays.?) == 1) pattern.interval * 7 * day else day,
        2, 3 => 21 * day * pattern.interval,
        5, 6 => 360 * day * pattern.interval,
        else => unreachable,
    };
    const offsets = if (projection.seed.zone) |zone|
        zone.annualOffsets(date) orelse return error.UnrepresentableSeries
    else
        clock.Zone.AnnualOffsets{ .standard = 0 };
    if (duration < 0 or duration > min_gap) return error.UnrepresentableSeries;
    if (offsets.daylight) |dst| {
        const shift = dst.offset - offsets.standard;
        if (duration > min_gap - shift or
            touchesTransition(date.seconds, duration, dst.starts.seconds, shift) or
            touchesTransition(date.seconds, duration, dst.ends.seconds, shift))
            return error.UnrepresentableSeries;
    }

    // Search a bounded slice of the same original grid used by ComposeMail.
    const neighbor_window = pattern.interval * day * @as(i64, switch (pattern.kind) {
        0 => 2,
        1 => 8,
        2, 3 => 33,
        else => 370,
    });
    var budget = recurrence.expansion_budget;
    if (rule.until) |until| {
        const cutoff = if (until.kind == .utc) until.epoch() else until.epoch() - if (projection.seed.zone) |zone| zone.offsetAt(until) else @as(i64, 0);
        pattern.until = try lastSlot(a, &projection, cutoff, neighbor_window, &budget) orelse return error.UnrepresentableSeries;
    }

    var changes: std.AutoHashMapUnmanaged(i64, Exception) = .empty;
    for (excluded.items) |field| {
        var values = std.mem.splitScalar(u8, field.value, ',');
        while (values.next()) |value| {
            if (changes.count() >= 256) return error.UnrepresentableSeries;
            var single = field;
            single.value = value;
            const key = try projection.stamp(a, single);
            if (try hasSlot(a, &projection, key, &budget)) try changes.put(a, key, .{ .original = key });
        }
    }
    var seen: std.AutoHashMapUnmanaged(i64, void) = .empty;
    for (detached.items) |component| {
        const id = (try property(a, component, "RECURRENCE-ID")).?;
        const key = try projection.stamp(a, id);
        if ((try seen.getOrPut(a, key)).found_existing or !try hasSlot(a, &projection, key, &budget))
            return error.UnrepresentableSeries;
        const status = (try ical.componentText(a, component, "STATUS")) orelse "";
        var exception = Exception{ .original = key };
        if (!std.ascii.eqlIgnoreCase(status, "CANCELLED")) {
            var scratch = std.heap.ArenaAllocator.init(a);
            defer scratch.deinit();
            const found = try recurrence.findInstance(scratch.allocator(), source, timezone, key) orelse return error.UnrepresentableSeries;
            const previous = try lastSlot(a, &projection, key - 1, neighbor_window, &budget);
            const next = try projection.nextNominal(a, key, key + neighbor_window, &.{}, &budget, true);
            if (previous) |stamp| {
                if (found.start < stamp + duration) return error.UnrepresentableSeries;
            }
            if (next) |slot| {
                if (found.end > try projection.stamp(a, slot.field)) return error.UnrepresentableSeries;
            }
            exception.moved = .{
                .start = found.start,
                .end = found.end,
                .summary = try ical.componentText(a, component, "SUMMARY"),
                .description = try ical.componentText(a, component, "DESCRIPTION"),
                .location = try ical.componentText(a, component, "LOCATION"),
            };
        }
        try changes.put(a, key, exception);
        if (changes.count() > 256) return error.UnrepresentableSeries;
    }
    var exceptions: std.ArrayList(Exception) = .empty;
    var iterator = changes.valueIterator();
    while (iterator.next()) |item| try exceptions.append(a, item.*);
    std.mem.sort(Exception, exceptions.items, {}, struct {
        fn before(_: void, left: Exception, right: Exception) bool {
            return left.original < right.original;
        }
    }.before);
    var previous_end: ?i64 = null;
    for (exceptions.items) |item| {
        if (item.moved) |moved| {
            if (previous_end) |past| if (moved.start < past) return error.UnrepresentableSeries;
            previous_end = moved.end;
        }
    }
    return .{
        .start = start,
        .end = end,
        .timezone = if (date.kind == .date) null else try wireTimezone(offsets),
        .pattern = pattern,
        .title = (try ical.componentText(a, event, "SUMMARY")) orelse "",
        .description = try ical.componentText(a, event, "DESCRIPTION"),
        .location = try ical.componentText(a, event, "LOCATION"),
        .exceptions = exceptions.items,
    };
}

fn touchesTransition(wall: i64, duration: i64, onset: i64, shift: i64) bool {
    return @mod(wall - onset + shift, day) < 2 * shift or
        duration >= @mod(onset - shift - wall, day);
}

fn wirePattern(rule: recurrence.Rule, seed: clock.Date, version: u8) !Pattern {
    if (rule.interval > 999 or (rule.count orelse 0) > 999 or rule.year_days.len != 0 or
        rule.hours != 0 or rule.minutes != 0 or rule.seconds != 0 or !rule.matches(seed, seed))
        return error.UnrepresentableSeries;
    var result: Pattern = .{ .kind = 0, .interval = rule.interval, .count = rule.count };
    switch (rule.frequency) {
        .daily => {
            if (rule.months != 0 or rule.month_days.len != 0 or rule.positions.len != 0)
                return error.UnrepresentableSeries;
            const mask = dayMask(rule);
            if (mask != 0 and mask != 127) {
                if (rule.interval != 1) return error.UnrepresentableSeries;
                result.kind = 1;
                result.weekdays = mask;
            }
        },
        .weekly => {
            if (rule.months != 0 or rule.positions.len != 0) return error.UnrepresentableSeries;
            result.kind = 1;
            result.weekdays = if (rule.weekdays.len == 0) weekdayBit(seed) else dayMask(rule);
            if (version >= 141) {
                result.first_day = rule.week_start;
            } else if (rule.interval != 1 and @popCount(result.weekdays.?) > 1 and rule.week_start != 0) {
                return error.UnrepresentableSeries;
            }
        },
        .monthly, .yearly => {
            const yearly = rule.frequency == .yearly;
            if (yearly) {
                if (@popCount(rule.months) > 1 or
                    (rule.months == 0 and (rule.weekdays.len != 0 or rule.month_days.len != 0)))
                    return error.UnrepresentableSeries;
                result.month = seed.month;
            } else if (rule.months != 0) return error.UnrepresentableSeries;
            if (rule.weekdays.len == 0) {
                if (rule.positions.len != 0 or rule.month_days.len > 1) return error.UnrepresentableSeries;
                const selected: i16 = if (rule.month_days.len == 0) seed.day else rule.month_days[0];
                if (selected == -1) {
                    result.month_day = 31;
                } else {
                    const ceiling = if (yearly) daysInMonth(seed.month, 2001) else shortestMonth(seed.month, rule.interval);
                    if (selected < 1 or selected > ceiling) return error.UnrepresentableSeries;
                    result.month_day = @intCast(selected);
                }
                result.kind = if (yearly) 5 else 2;
            } else {
                if (rule.month_days.len != 0 or rule.positions.len > 1) return error.UnrepresentableSeries;
                const ordinal = if (rule.positions.len == 1) blk: {
                    for (rule.weekdays) |weekday| if (weekday.ordinal != 0) return error.UnrepresentableSeries;
                    break :blk rule.positions[0];
                } else if (rule.weekdays.len == 1) rule.weekdays[0].ordinal else return error.UnrepresentableSeries;
                if (ordinal != -1 and (ordinal < 1 or ordinal > 4)) return error.UnrepresentableSeries;
                const mask = dayMask(rule);
                if (@popCount(mask) > 1 and mask != 62 and mask != 65 and mask != 127)
                    return error.UnrepresentableSeries;
                if (nthDay(seed, mask, ordinal) != seed.day) return error.UnrepresentableSeries;
                result.kind = if (yearly) 6 else 3;
                result.weekdays = mask;
                result.week = if (ordinal == -1) 5 else @intCast(ordinal);
            }
        },
        else => return error.UnrepresentableSeries,
    }
    return result;
}

fn weekdayBit(date: clock.Date) u8 {
    return @as(u8, 1) << @intCast(@mod(@divFloor(date.epoch(), day) + 4, 7));
}

fn dayMask(rule: recurrence.Rule) u8 {
    var result: u8 = 0;
    for (rule.weekdays) |weekday| result |= @as(u8, 1) << @intCast(weekday.day_of_week);
    return result;
}

fn daysInMonth(month: u8, year: i64) u8 {
    const next = clock.Date{ .year = year + @intFromBool(month == 12), .month = month % 12 + 1, .day = 1, .seconds = 0, .kind = .date };
    return clock.Date.fromEpoch(next.epoch() - day, .date).day;
}

fn shortestMonth(start: u8, interval: i64) u8 {
    var length = daysInMonth(start, 2001);
    var month: i64 = start;
    while (true) {
        month = @mod(month - 1 + interval, 12) + 1;
        if (month == start) return length;
        length = @min(length, daysInMonth(@intCast(month), 2001));
    }
}

fn nthDay(seed: clock.Date, mask: u8, ordinal: i16) u8 {
    var date = seed;
    const last = daysInMonth(date.month, date.year);
    var count: i16 = 0;
    var index: u8 = 1;
    while (index <= last) : (index += 1) {
        date.day = if (ordinal < 0) last + 1 - index else index;
        if (weekdayBit(date) & mask == 0) continue;
        count += 1;
        if (count == @abs(ordinal)) return date.day;
    }
    return 0;
}

fn property(a: Allocator, component: ical.Component, name: []const u8) !?ical.Property {
    var fields = ical.Properties.init(component);
    while (try fields.next(a)) |field| if (field.named(name)) return field;
    return null;
}

fn hasSlot(a: Allocator, projection: *recurrence.RangeProjection, key: i64, budget: *usize) !bool {
    return (try projection.nextNominal(a, key - 1, key + 1, &.{}, budget, true)) != null;
}

fn lastSlot(a: Allocator, projection: *recurrence.RangeProjection, cutoff: i64, window: i64, budget: *usize) !?i64 {
    var cursor = cutoff - window;
    var last: ?i64 = null;
    while (try projection.nextNominal(a, cursor, cutoff + 1, &.{}, budget, true)) |slot| {
        cursor = try projection.stamp(a, slot.field);
        last = cursor;
    }
    return last;
}

fn wireTimezone(offsets: clock.Zone.AnnualOffsets) ![172]u8 {
    if (@mod(offsets.standard, 60) != 0) return error.UnrepresentableSeries;
    var blob: [172]u8 = @splat(0);
    std.mem.writeInt(i32, blob[0..4], @intCast(-@divExact(offsets.standard, 60)), .little);
    if (offsets.daylight) |daylight| {
        if (@mod(daylight.offset, 60) != 0) return error.UnrepresentableSeries;
        writeTransition(blob[68..84], daylight.ends);
        writeTransition(blob[152..168], daylight.starts);
        std.mem.writeInt(i32, blob[168..172], @intCast(@divExact(offsets.standard - daylight.offset, 60)), .little);
    }
    return blob;
}

fn writeTransition(out: *[16]u8, value: clock.Zone.AnnualTransition) void {
    const words = [_]u16{
        0,                                        value.month,                                      value.weekday,                     value.week,
        @intCast(@divFloor(value.seconds, 3600)), @intCast(@mod(@divFloor(value.seconds, 60), 60)), @intCast(@mod(value.seconds, 60)), 0,
    };
    for (words, 0..) |word, index| std.mem.writeInt(u16, out[index * 2 ..][0..2], word, .little);
}

fn legacySeries(a: Allocator, detail: store.CalendarEventDetail) ![]const u8 {
    const event = detail.event;
    var result = try ical.Export.init(a, "Calendar");
    try result.addEvent(.{
        .uid = event.uid,
        .modified_at = detail.modified_at,
        .summary = event.summary,
        .description = detail.description,
        .location = event.location,
        .organizer = detail.organizer,
        .start = event.start,
        .end = event.end,
        .all_day = event.all_day,
        .recurrence = event.recurrence_rule,
        .status = if (event.status == .cancelled) "CANCELLED" else "CONFIRMED",
    });
    return result.finish();
}
