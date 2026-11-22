//! Expand calendar resources privately. Callers may serialize only the merged
//! busy periods, never the original event data or recurrence properties.
const std = @import("std");
const ical = @import("icalendar.zig");
const clock = @import("icalendar_time.zig");
const Allocator = std.mem.Allocator;
const Date = clock.Date;
const day: i64 = 86400;

pub const Window = struct { start: i64, end: i64 };
pub const Period = struct { start: i64, end: i64 };
pub const Source = struct {
    icalendar: []const u8,
    start: i64,
    end: ?i64,
    all_day: bool,
    cancelled: bool,
};

pub fn calculate(a: Allocator, scratch_allocator: Allocator, sources: []const Source, window: Window, timezone: []const u8) ![]Period {
    var periods: std.ArrayList(Period) = .empty;
    var budget: usize = 250_000;
    for (sources) |source| {
        if (source.icalendar.len == 0) {
            if (!source.cancelled) try appendPeriod(a, &periods, window, source.start, source.end orelse (source.start +| if (source.all_day) day else 0));
            continue;
        }
        var scratch = std.heap.ArenaAllocator.init(scratch_allocator);
        defer scratch.deinit();
        try appendResource(a, &periods, scratch.allocator(), source.icalendar, window, timezone, &budget);
    }
    std.mem.sort(Period, periods.items, {}, struct {
        fn lessThan(_: void, left: Period, right: Period) bool {
            return left.start < right.start;
        }
    }.lessThan);
    var count: usize = 0;
    for (periods.items) |period| {
        if (count > 0 and period.start <= periods.items[count - 1].end) {
            periods.items[count - 1].end = @max(periods.items[count - 1].end, period.end);
        } else {
            periods.items[count] = period;
            count += 1;
        }
    }
    return periods.items[0..count];
}

fn appendPeriod(a: Allocator, periods: *std.ArrayList(Period), window: Window, start: i64, end: i64) !void {
    const clipped = Period{ .start = @max(window.start, start), .end = @min(window.end, end) };
    if (clipped.start >= clipped.end) return;
    if (periods.items.len >= 32_000) return error.AvailabilityLimit;
    try periods.append(a, clipped);
}

const Zones = struct {
    parsed: std.StringHashMapUnmanaged(clock.Zone) = .empty,
    embedded: std.StringHashMapUnmanaged(ical.Component) = .empty,

    fn get(self: *Zones, a: Allocator, name: []const u8) !clock.Zone {
        if (self.parsed.get(name)) |value| return value;
        const component: ical.Component = self.embedded.get(name) orelse .{
            .name = "VTIMEZONE",
            .bytes = clock.bundledTimezone(name) orelse return error.AvailabilityUnsupported,
        };
        const zone = try clock.Zone.parse(a, component);
        try self.parsed.put(a, name, zone);
        return zone;
    }
};

const Moment = struct {
    date: Date,
    zone: ?clock.Zone,

    fn read(a: Allocator, zones: *Zones, value: []const u8, property: ical.Property, fallback: ?clock.Zone) !Moment {
        const date = Date.parse(value) orelse return error.InvalidCalendar;
        const zone = if (date.kind == .utc) null else if (property.param("TZID")) |name|
            if (std.ascii.eqlIgnoreCase(name, "UTC")) null else try zones.get(a, name)
        else
            fallback;
        return .{ .date = date, .zone = zone };
    }

    fn stamp(self: Moment) i64 {
        return self.date.epoch() - (if (self.zone) |zone| zone.offsetAt(self.date) else 0);
    }

    fn withDate(self: Moment, date: Date) Moment {
        return .{ .date = date, .zone = self.zone };
    }
};

const Length = union(enum) {
    exact: i64,
    wall: clock.Duration,

    fn end(self: Length, start: Moment) i64 {
        return switch (self) {
            .exact => |seconds| start.stamp() + seconds,
            .wall => |interval| start.withDate(Date.fromEpoch(start.date.epoch() + interval.days * day, start.date.kind)).stamp() + interval.seconds,
        };
    }
};

const Event = struct {
    component: ical.Component,
    start: ?ical.Property = null,
    finish: ?ical.Property = null,
    duration: ?[]const u8 = null,
    recurrence_id: ?ical.Property = null,
    cancelled: ?bool = null,
    transparent: ?bool = null,

    fn read(a: Allocator, component: ical.Component) !Event {
        var event = Event{ .component = component };
        var fields = ical.Properties.init(component);
        while (try fields.next(a)) |field| {
            if (field.named("DTSTART")) event.start = field;
            if (field.named("DTEND")) event.finish = field;
            if (field.named("DURATION")) event.duration = field.value;
            if (field.named("RECURRENCE-ID")) event.recurrence_id = field;
            if (field.named("TRANSP")) event.transparent = std.ascii.eqlIgnoreCase(field.value, "TRANSPARENT");
            if (field.named("STATUS")) event.cancelled = std.ascii.eqlIgnoreCase(field.value, "CANCELLED");
            if (field.named("EXRULE")) return error.AvailabilityUnsupported;
        }
        return event;
    }

    fn length(self: Event, a: Allocator, zones: *Zones, start: Moment) !Length {
        if (self.finish) |field| {
            const end = try Moment.read(a, zones, field.value, field, start.zone);
            if (self.duration != null or end.stamp() < start.stamp() or (start.date.kind == .date) != (end.date.kind == .date))
                return error.InvalidCalendar;
            return if (start.date.kind == .date)
                .{ .wall = .{ .days = @divExact(end.date.epoch() - start.date.epoch(), day) } }
            else
                .{ .exact = end.stamp() - start.stamp() };
        }
        if (self.duration) |raw| {
            const interval = clock.duration(raw) orelse return error.InvalidCalendar;
            if (start.date.kind == .date and interval.seconds != 0) return error.InvalidCalendar;
            return .{ .wall = interval };
        }
        return if (start.date.kind == .date) .{ .wall = .{ .days = 1 } } else .{ .exact = 0 };
    }
};

fn appendResource(a: Allocator, periods: *std.ArrayList(Period), scratch: Allocator, source: []const u8, window: Window, timezone: []const u8, budget: *usize) !void {
    var zones = Zones{};
    var master: ?Event = null;
    var detached: std.ArrayList(Event) = .empty;
    for (try ical.components(scratch, source)) |component| {
        if (std.ascii.eqlIgnoreCase(component.name, "VTIMEZONE")) {
            const name = try ical.componentText(scratch, component, "TZID") orelse return error.InvalidCalendar;
            const result = try zones.embedded.getOrPut(scratch, name);
            if (result.found_existing and !std.mem.eql(u8, result.value_ptr.bytes, component.bytes)) return error.InvalidCalendar;
            result.value_ptr.* = component;
        } else if (std.ascii.eqlIgnoreCase(component.name, "VEVENT")) {
            const event = try Event.read(scratch, component);
            if (event.recurrence_id != null) {
                try detached.append(scratch, event);
            } else {
                if (master != null) return error.InvalidCalendar;
                master = event;
            }
        } else return error.AvailabilityUnsupported;
    }
    const event = master orelse return error.InvalidCalendar;
    const start_field = event.start orelse return error.InvalidCalendar;
    const fallback = if (std.ascii.eqlIgnoreCase(timezone, "UTC")) null else try zones.get(scratch, timezone);
    const start = try Moment.read(scratch, &zones, start_field.value, start_field, fallback);
    var exclude: std.AutoHashMapUnmanaged(i64, void) = .empty;
    for (detached.items) |item| {
        const original = item.recurrence_id.?;
        if (original.param("RANGE") != null) return error.AvailabilityUnsupported;
        const recurrence = try Moment.read(scratch, &zones, original.value, original, start.zone);
        if ((try exclude.getOrPut(scratch, recurrence.stamp())).found_existing) return error.InvalidCalendar;
        if ((item.cancelled orelse event.cancelled orelse false) or (item.transparent orelse event.transparent orelse false)) continue;
        const start_value = item.start orelse return error.InvalidCalendar;
        const moved = try Moment.read(scratch, &zones, start_value.value, start_value, start.zone);
        const length = if (item.finish == null and item.duration == null) try event.length(scratch, &zones, start) else try item.length(scratch, &zones, moved);
        try appendPeriod(a, periods, window, moved.stamp(), length.end(moved));
    }
    if ((event.cancelled orelse false) or (event.transparent orelse false)) return;

    var properties = ical.Properties.init(event.component);
    while (try properties.next(scratch)) |property| {
        if (!property.named("EXDATE")) continue;
        var values = std.mem.splitScalar(u8, property.value, ',');
        while (values.next()) |value| {
            const removed = try Moment.read(scratch, &zones, value, property, start.zone);
            try exclude.put(scratch, removed.stamp(), {});
        }
    }
    const length = try event.length(scratch, &zones, start);

    // Explicit RDATE periods can replace the event's usual duration.
    const ExplicitInstance = struct { end: i64, has_period: bool };
    var included: std.AutoHashMapUnmanaged(i64, ExplicitInstance) = .empty;
    properties = ical.Properties.init(event.component);
    while (try properties.next(scratch)) |property| {
        if (!property.named("RDATE")) continue;
        var values = std.mem.splitScalar(u8, property.value, ',');
        while (values.next()) |value| {
            const division = std.mem.indexOfScalar(u8, value, '/') orelse value.len;
            const candidate = try Moment.read(scratch, &zones, value[0..division], property, start.zone);
            if (exclude.contains(candidate.stamp())) continue;
            const end = if (division == value.len) length.end(candidate) else blk: {
                const right = value[division + 1 ..];
                if (clock.duration(right)) |interval| break :blk (Length{ .wall = interval }).end(candidate);
                const finish = try Moment.read(scratch, &zones, right, property, start.zone);
                break :blk finish.stamp();
            };
            const explicit = try included.getOrPut(scratch, candidate.stamp());
            const period = division != value.len;
            if (period and (candidate.date.kind == .date or end <= candidate.stamp())) return error.InvalidCalendar;
            if (explicit.found_existing and explicit.value_ptr.has_period) {
                if (period and explicit.value_ptr.end != end) return error.InvalidCalendar;
            } else {
                explicit.value_ptr.* = .{ .end = end, .has_period = period };
            }
        }
    }
    var explicit = included.iterator();
    while (explicit.next()) |item| {
        try appendPeriod(a, periods, window, item.key_ptr.*, item.value_ptr.end);
        try exclude.put(scratch, item.key_ptr.*, {});
    }
    var expansion = Expansion{ .a = a, .periods = periods, .window = window, .seed = start, .length = length, .exclude = &exclude, .budget = budget };
    try expansion.append(start);
    properties = ical.Properties.init(event.component);
    while (try properties.next(scratch)) |property| {
        if (property.named("RRULE")) try expansion.rule(try Rule.parse(scratch, property.value));
    }
}

const Frequency = enum { daily, weekly, monthly, yearly };
const Weekday = struct { day_of_week: i64, ordinal: i8 = 0 };

const Rule = struct {
    frequency: Frequency,
    interval: i64 = 1,
    count: ?i64 = null,
    until: ?Date = null,
    week_start: i64 = 1, // Monday
    months: u12 = 0,
    weekdays: []const Weekday = &.{},
    month_days: []const i8 = &.{},
    positions: []const i16 = &.{},

    fn parse(a: Allocator, source: []const u8) !Rule {
        var result: Rule = .{ .frequency = .daily };
        var frequency: ?Frequency = null;
        var seen: std.StringHashMapUnmanaged(void) = .empty;
        var parts = std.mem.splitScalar(u8, source, ';');
        while (parts.next()) |part| {
            const equals = std.mem.indexOfScalar(u8, part, '=') orelse return error.InvalidCalendar;
            const name = try std.ascii.allocUpperString(a, part[0..equals]);
            const value = part[equals + 1 ..];
            if ((try seen.getOrPut(a, name)).found_existing) return error.InvalidCalendar;
            if (std.mem.eql(u8, name, "FREQ")) {
                const lower = try std.ascii.allocLowerString(a, value);
                frequency = std.meta.stringToEnum(Frequency, lower) orelse return error.AvailabilityUnsupported;
            } else if (std.mem.eql(u8, name, "INTERVAL")) {
                result.interval = try int(i64, value, 1, 9999);
            } else if (std.mem.eql(u8, name, "COUNT")) {
                result.count = try int(i64, value, 1, std.math.maxInt(i32));
            } else if (std.mem.eql(u8, name, "UNTIL")) {
                result.until = Date.parse(value) orelse return error.InvalidCalendar;
            } else if (std.mem.eql(u8, name, "WKST")) {
                result.week_start = weekday(value) orelse return error.InvalidCalendar;
            } else if (std.mem.eql(u8, name, "BYMONTH")) {
                var values = std.mem.splitScalar(u8, value, ',');
                while (values.next()) |month| result.months |= @as(u12, 1) << @intCast((try int(u8, month, 1, 12)) - 1);
            } else if (std.mem.eql(u8, name, "BYMONTHDAY")) {
                result.month_days = try intList(i8, a, value, 31);
            } else if (std.mem.eql(u8, name, "BYSETPOS")) {
                result.positions = try intList(i16, a, value, 366);
            } else if (std.mem.eql(u8, name, "BYDAY")) {
                var items: std.ArrayList(Weekday) = .empty;
                var values = std.mem.splitScalar(u8, value, ',');
                while (values.next()) |item| {
                    if (item.len < 2) return error.InvalidCalendar;
                    const prefix = item[0 .. item.len - 2];
                    const ordinal = if (prefix.len == 0) 0 else try int(i8, prefix, -53, 53);
                    try items.append(a, .{ .day_of_week = weekday(item[item.len - 2 ..]) orelse return error.InvalidCalendar, .ordinal = ordinal });
                }
                result.weekdays = items.items;
            } else return error.AvailabilityUnsupported;
        }
        result.frequency = frequency orelse return error.InvalidCalendar;
        if (result.count != null and result.until != null) return error.InvalidCalendar;
        if (result.frequency == .weekly and result.month_days.len != 0) return error.InvalidCalendar;
        for (result.weekdays) |item| {
            if (item.ordinal != 0 and (result.frequency == .daily or result.frequency == .weekly)) return error.InvalidCalendar;
        }
        return result;
    }

    fn matches(self: Rule, seed: Date, date: Date) bool {
        if (self.months != 0 and self.months & (@as(u12, 1) << @intCast(date.month - 1)) == 0) return false;
        if (self.frequency == .yearly and self.months == 0 and self.month_days.len == 0 and self.weekdays.len == 0 and date.month != seed.month)
            return false;
        const month_start = dayStart(.{ .year = date.year, .month = date.month, .day = 1, .seconds = 0, .kind = .date });
        const month_end = monthStart(date.year, @as(i64, date.month));
        const days_in_month = @divExact(month_end - month_start, day);
        if (self.month_days.len != 0 and !matchesOrdinal(i8, self.month_days, date.day, days_in_month)) return false;
        if (self.weekdays.len == 0) {
            if (self.frequency == .weekly) return dayOfWeek(date.epoch()) == dayOfWeek(seed.epoch());
            if ((self.frequency == .monthly or self.frequency == .yearly) and self.month_days.len == 0) return date.day == seed.day;
            return true;
        }
        const dow = dayOfWeek(date.epoch());
        for (self.weekdays) |entry| {
            if (entry.day_of_week != dow) continue;
            if (entry.ordinal == 0) return true;
            const first = if (self.frequency == .yearly and self.months == 0) monthStart(date.year, 0) else month_start;
            const last = if (self.frequency == .yearly and self.months == 0) monthStart(date.year + 1, 0) else month_end;
            const ordinal = if (entry.ordinal > 0)
                @divFloor(dayStart(date) - first, 7 * day) + 1
            else
                -1 - @divFloor(last - day - dayStart(date), 7 * day);
            if (ordinal == entry.ordinal) return true;
        }
        return false;
    }
};

fn int(comptime T: type, text: []const u8, minimum: T, maximum: T) !T {
    const value = std.fmt.parseInt(T, text, 10) catch return error.InvalidCalendar;
    if (value < minimum or value > maximum or value == 0) return error.InvalidCalendar;
    return value;
}

fn intList(comptime T: type, a: Allocator, text: []const u8, maximum: T) ![]T {
    var result: std.ArrayList(T) = .empty;
    var parts = std.mem.splitScalar(u8, text, ',');
    while (parts.next()) |part| try result.append(a, try int(T, part, -maximum, maximum));
    return result.items;
}

fn weekday(value: []const u8) ?i64 {
    for ([_][]const u8{ "SU", "MO", "TU", "WE", "TH", "FR", "SA" }, 0..) |name, index| {
        if (std.ascii.eqlIgnoreCase(name, value)) return @intCast(index);
    }
    return null;
}

fn dayOfWeek(value: i64) i64 {
    return @mod(@divFloor(value, day) + 4, 7);
}

fn dayStart(date: Date) i64 {
    return date.epoch() - date.seconds;
}

fn monthStart(year: i64, offset: i64) i64 {
    return (Date{ .year = year + @divFloor(offset, 12), .month = @intCast(@mod(offset, 12) + 1), .day = 1, .seconds = 0, .kind = .date }).epoch();
}

fn matchesOrdinal(comptime T: type, choices: []const T, index: i64, length: i64) bool {
    for (choices) |choice| if (choice == index or choice == index - length - 1) return true;
    return false;
}

const Expansion = struct {
    a: Allocator,
    periods: *std.ArrayList(Period),
    window: Window,
    seed: Moment,
    length: Length,
    exclude: *const std.AutoHashMapUnmanaged(i64, void),
    budget: *usize,

    fn append(self: *Expansion, candidate: Moment) !void {
        const stamp = candidate.stamp();
        if (self.exclude.contains(stamp)) return;
        try appendPeriod(self.a, self.periods, self.window, stamp, self.length.end(candidate));
    }

    fn rule(self: *Expansion, recur: Rule) !void {
        const seed = self.seed.date;
        const initial = dayStart(seed);
        var current = switch (recur.frequency) {
            .daily => initial,
            .weekly => initial - @mod(dayOfWeek(initial) - recur.week_start, 7) * day,
            .monthly => monthStart(seed.year, @as(i64, seed.month) - 1),
            .yearly => monthStart(seed.year, 0),
        };
        var remaining = if (recur.count) |count| count - 1 else std.math.maxInt(i64);
        // Date candidates are wall times. A legal UTC offset is less than
        // a day, so include the neighboring day before cutting off the scan.
        const until = if (recur.until) |date| date.epoch() else null;
        const through = @min(self.window.end, until orelse self.window.end) + day;
        while (current <= through and remaining > 0) {
            const first = Date.fromEpoch(current, .date);
            const month = @as(i64, first.month) - 1;
            const step = switch (recur.frequency) {
                .daily => current + day,
                .weekly => current + 7 * day,
                .monthly => monthStart(first.year, month + 1),
                .yearly => monthStart(first.year + 1, 0),
            };
            var matched: [366]Moment = undefined;
            var count: usize = 0;
            var timestamp = current;
            while (timestamp < step) : (timestamp += day) {
                if (self.budget.* == 0) return error.AvailabilityLimit;
                self.budget.* -= 1;
                const date = Date.fromEpoch(timestamp + seed.seconds, seed.kind);
                if (!recur.matches(seed, date)) continue;
                if (self.seed.zone) |zone| {
                    if (zone.isGap(date)) continue;
                }
                matched[count] = self.seed.withDate(date);
                count += 1;
            }
            for (matched[0..count], 1..) |candidate, index| {
                if (recur.positions.len != 0 and !matchesOrdinal(i16, recur.positions, @intCast(index), @intCast(count))) continue;
                if (candidate.date.epoch() <= seed.epoch()) continue;
                const stamp = candidate.stamp();
                if (stamp >= self.window.end) return;
                if (until) |end| {
                    const value = if (recur.until.?.kind == .utc) stamp else candidate.date.epoch();
                    if (value > end) return;
                }
                try self.append(candidate);
                remaining -= 1;
                if (remaining == 0) return;
            }
            current = switch (recur.frequency) {
                .daily => current + day * recur.interval,
                .weekly => current + 7 * day * recur.interval,
                .monthly => monthStart(first.year, month + recur.interval),
                .yearly => monthStart(first.year + recur.interval, 0),
            };
        }
    }
};
