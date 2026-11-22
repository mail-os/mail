//! Expand calendar occurrences for free/busy and time-range matching.
//! Availability responses expose only merged busy periods.
const std = @import("std");
const ical = @import("icalendar.zig");
const clock = @import("icalendar_time.zig");
const Allocator = std.mem.Allocator;
const Date = clock.Date;
const day: i64 = 86400;

pub const Window = struct { start: i64, end: i64 };
pub const BusyType = enum {
    busy,
    tentative,
    unavailable,

    pub fn label(self: BusyType) []const u8 {
        return switch (self) {
            .busy => "BUSY",
            .tentative => "BUSY-TENTATIVE",
            .unavailable => "BUSY-UNAVAILABLE",
        };
    }
};
pub const Period = struct { start: i64, end: i64, kind: BusyType };
pub const Grouping = enum { combined, by_type };
pub const expansion_budget: usize = 250_000;
pub const Source = struct {
    icalendar: []const u8,
    start: i64,
    end: ?i64,
    all_day: bool,
    cancelled: bool,
    tentative: bool,
};

pub fn calculate(a: Allocator, scratch_allocator: Allocator, sources: []const Source, window: Window, timezone: []const u8, grouping: Grouping) ![]Period {
    var periods: std.ArrayList(Period) = .empty;
    const output = OccurrenceOutput{ .window = window, .busy = .{ .allocator = a, .items = &periods } };
    var budget = expansion_budget;
    for (sources) |source| {
        if (source.icalendar.len == 0) {
            const end = source.end orelse (source.start +| if (source.all_day) day else 0);
            if (!source.cancelled) try output.add(source.start, end, if (source.tentative) .tentative else .busy);
            continue;
        }
        var scratch = std.heap.ArenaAllocator.init(scratch_allocator);
        defer scratch.deinit();
        try appendResource(output, scratch.allocator(), source.icalendar, timezone, null, &budget);
    }
    std.mem.sort(Period, periods.items, {}, struct {
        fn lessThan(_: void, left: Period, right: Period) bool {
            return left.start < right.start or (left.start == right.start and left.end < right.end);
        }
    }.lessThan);
    var count: usize = 0;
    var previous: [std.meta.tags(BusyType).len]?usize = @splat(null);
    for (periods.items) |period| {
        const slot = &previous[if (grouping == .combined) 0 else @backingInt(period.kind)];
        if (slot.*) |index| {
            if (period.start <= periods.items[index].end) {
                periods.items[index].end = @max(periods.items[index].end, period.end);
                continue;
            }
        }
        periods.items[count] = period;
        slot.* = count;
        count += 1;
    }
    return periods.items[0..count];
}

pub fn overlaps(a: Allocator, source: Source, window: Window, timezone: []const u8, query_zone: ?clock.Zone, budget: *usize) !bool {
    if (source.icalendar.len == 0) {
        const end = source.end orelse (source.start +| if (source.all_day) day else 0);
        return !source.cancelled and occurrenceOverlaps(window, source.start, end);
    }
    var scratch = std.heap.ArenaAllocator.init(a);
    defer scratch.deinit();
    appendResource(.{ .window = window }, scratch.allocator(), source.icalendar, timezone, query_zone, budget) catch |err| switch (err) {
        error.OccurrenceFound => return true,
        else => return err,
    };
    return false;
}

const OccurrenceOutput = struct {
    window: Window,
    busy: ?struct { allocator: Allocator, items: *std.ArrayList(Period) } = null,

    fn add(self: OccurrenceOutput, start: i64, end: i64, kind: BusyType) !void {
        if (self.busy) |periods| {
            return appendPeriod(periods.allocator, periods.items, self.window, start, end, kind);
        }
        if (occurrenceOverlaps(self.window, start, end)) return error.OccurrenceFound;
    }

    fn ignores(self: OccurrenceOutput, status: Event.Status, transparent: bool) bool {
        return status == .cancelled or (self.busy != null and transparent);
    }
};

fn occurrenceOverlaps(window: Window, start: i64, end: i64) bool {
    if (start == end) return window.start <= start and start < window.end;
    return window.start < end and start < window.end;
}

fn appendPeriod(a: Allocator, periods: *std.ArrayList(Period), window: Window, start: i64, end: i64, kind: BusyType) !void {
    const clipped = Period{ .start = @max(window.start, start), .end = @min(window.end, end), .kind = kind };
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

    fn wallIn(self: Moment, target: ?clock.Zone) !i64 {
        if (target) |zone| {
            if (self.zone) |source| {
                if (zone.rules.ptr == source.rules.ptr) return self.date.epoch();
            }
            const date = zone.dateAt(self.stamp(), self.date.kind) orelse return error.AvailabilityUnsupported;
            return date.epoch();
        }
        return self.stamp();
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

    fn wallSeconds(self: Length) i64 {
        return switch (self) {
            .exact => |seconds| seconds,
            .wall => |interval| interval.days * day + interval.seconds,
        };
    }
};

const Event = struct {
    component: ical.Component,
    start: ?ical.Property = null,
    finish: ?ical.Property = null,
    duration: ?[]const u8 = null,
    recurrence_id: ?ical.Property = null,
    status: ?Status = null,
    transparent: ?bool = null,

    const Status = enum { confirmed, tentative, cancelled };

    fn busyKind(self: Event, output: OccurrenceOutput, master: Event) ?BusyType {
        const status = self.status orelse master.status orelse .confirmed;
        if (output.ignores(status, self.transparent orelse master.transparent orelse false)) return null;
        return if (status == .tentative) .tentative else .busy;
    }

    fn read(a: Allocator, component: ical.Component) !Event {
        var event = Event{ .component = component };
        var fields = ical.Properties.init(component);
        while (try fields.next(a)) |field| {
            if (field.named("DTSTART")) event.start = field;
            if (field.named("DTEND")) event.finish = field;
            if (field.named("DURATION")) event.duration = field.value;
            if (field.named("RECURRENCE-ID")) event.recurrence_id = field;
            if (field.named("TRANSP")) event.transparent = std.ascii.eqlIgnoreCase(field.value, "TRANSPARENT");
            if (field.named("STATUS")) event.status = if (std.ascii.eqlIgnoreCase(field.value, "CANCELLED"))
                .cancelled
            else if (std.ascii.eqlIgnoreCase(field.value, "TENTATIVE"))
                .tentative
            else
                .confirmed;
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

const RangeEdit = struct {
    key: i64,
    replacement: ?Replacement,

    const Replacement = struct {
        shift: i64,
        anchor: Moment,
        length: ?Length,
        kind: BusyType,
    };

    fn lessThan(_: void, lhs: RangeEdit, rhs: RangeEdit) bool {
        return lhs.key < rhs.key;
    }

    fn anchorOrder(key: i64, item: RangeEdit) std.math.Order {
        return std.math.order(key, item.key);
    }
};

fn appendStoredFreeBusy(a: Allocator, periods: *std.ArrayList(Period), scratch: Allocator, component: ical.Component, window: Window) !void {
    var fields = ical.Properties.init(component);
    while (try fields.next(scratch)) |field| {
        if (!field.named("FREEBUSY")) continue;
        const kind = if (field.param("FBTYPE")) |name| blk: {
            if (std.ascii.eqlIgnoreCase(name, "FREE")) continue;
            if (std.ascii.eqlIgnoreCase(name, "BUSY-TENTATIVE")) break :blk BusyType.tentative;
            if (std.ascii.eqlIgnoreCase(name, "BUSY-UNAVAILABLE")) break :blk BusyType.unavailable;
            break :blk BusyType.busy;
        } else .busy;
        var values = std.mem.splitScalar(u8, field.value, ',');
        while (values.next()) |value| {
            const slash = std.mem.indexOfScalar(u8, value, '/') orelse return error.InvalidCalendar;
            const start = Date.parse(value[0..slash]) orelse return error.InvalidCalendar;
            if (start.kind != .utc) return error.InvalidCalendar;
            const right = value[slash + 1 ..];
            const end = if (clock.duration(right)) |duration|
                start.epoch() + duration.days * day + duration.seconds
            else blk: {
                const date = Date.parse(right) orelse return error.InvalidCalendar;
                if (date.kind != .utc) return error.InvalidCalendar;
                break :blk date.epoch();
            };
            if (end <= start.epoch()) return error.InvalidCalendar;
            try appendPeriod(a, periods, window, start.epoch(), end, kind);
        }
    }
}

fn appendResource(output: OccurrenceOutput, scratch: Allocator, source: []const u8, timezone: []const u8, query_zone: ?clock.Zone, budget: *usize) !void {
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
        } else if (std.ascii.eqlIgnoreCase(component.name, "VFREEBUSY")) {
            if (output.busy) |periods| try appendStoredFreeBusy(periods.allocator, periods.items, scratch, component, output.window);
        } else if (!std.ascii.eqlIgnoreCase(component.name, "VTODO") and !std.ascii.eqlIgnoreCase(component.name, "VJOURNAL")) {
            if (output.busy != null) return error.AvailabilityUnsupported;
        }
    }
    if (master == null and detached.items.len == 0) return;
    const fallback = query_zone orelse if (std.ascii.eqlIgnoreCase(timezone, "UTC")) null else try zones.get(scratch, timezone);
    const event = master orelse {
        if (output.busy != null) return error.InvalidCalendar;
        for (detached.items) |item| {
            if (output.ignores(item.status orelse .confirmed, item.transparent orelse false)) continue;
            if (item.recurrence_id.?.param("RANGE") != null) return error.AvailabilityUnsupported;
            const field = item.start orelse return error.InvalidCalendar;
            const start = try Moment.read(scratch, &zones, field.value, field, fallback);
            const length = try item.length(scratch, &zones, start);
            try output.add(start.stamp(), length.end(start), .busy);
        }
        return;
    };
    const start_field = event.start orelse return error.InvalidCalendar;
    const start = try Moment.read(scratch, &zones, start_field.value, start_field, fallback);
    const length = try event.length(scratch, &zones, start);
    var exclude: std.AutoHashMapUnmanaged(i64, void) = .empty;
    var ranges: std.ArrayList(RangeEdit) = .empty;
    for (detached.items) |item| {
        const original = item.recurrence_id.?;
        const range = original.param("RANGE");
        if (range) |value| if (!std.ascii.eqlIgnoreCase(value, "THISANDFUTURE")) return error.AvailabilityUnsupported;
        const recurrence = try Moment.read(scratch, &zones, original.value, original, start.zone);
        const key = recurrence.stamp();
        if ((try exclude.getOrPut(scratch, key)).found_existing) return error.InvalidCalendar;
        const kind = item.busyKind(output, event) orelse {
            if (range != null) try ranges.append(scratch, .{ .key = key, .replacement = null });
            continue;
        };
        const start_value = item.start orelse return error.InvalidCalendar;
        const moved = try Moment.read(scratch, &zones, start_value.value, start_value, start.zone);
        if ((moved.date.kind == .date) != (start.date.kind == .date) or (recurrence.date.kind == .date) != (start.date.kind == .date))
            return error.InvalidCalendar;
        const modified_length = if (item.finish == null and item.duration == null) null else try item.length(scratch, &zones, moved);
        if (range != null) try ranges.append(scratch, .{
            .key = key,
            .replacement = .{
                .shift = moved.date.epoch() - try recurrence.wallIn(start.zone),
                .anchor = moved,
                .length = modified_length,
                .kind = kind,
            },
        });
        try output.add(moved.stamp(), (modified_length orelse length).end(moved), kind);
    }
    const kind = event.busyKind(output, event);
    if (kind == null and ranges.items.len == 0) return;
    std.mem.sort(RangeEdit, ranges.items, {}, RangeEdit.lessThan);

    var properties = ical.Properties.init(event.component);
    while (try properties.next(scratch)) |property| {
        if (!property.named("EXDATE")) continue;
        var values = std.mem.splitScalar(u8, property.value, ',');
        while (values.next()) |value| {
            const removed = try Moment.read(scratch, &zones, value, property, start.zone);
            try exclude.put(scratch, removed.stamp(), {});
        }
    }
    // Explicit RDATE periods can replace the event's usual duration.
    const ExplicitInstance = struct { start: Moment, length: ?Length };
    var included: std.AutoHashMapUnmanaged(i64, ExplicitInstance) = .empty;
    properties = ical.Properties.init(event.component);
    while (try properties.next(scratch)) |property| {
        if (!property.named("RDATE")) continue;
        var values = std.mem.splitScalar(u8, property.value, ',');
        while (values.next()) |value| {
            const division = std.mem.indexOfScalar(u8, value, '/') orelse value.len;
            const candidate = try Moment.read(scratch, &zones, value[0..division], property, start.zone);
            if (exclude.contains(candidate.stamp())) continue;
            const period: ?Length = if (division == value.len) null else blk: {
                const right = value[division + 1 ..];
                if (clock.duration(right)) |interval| break :blk .{ .wall = interval };
                const finish = try Moment.read(scratch, &zones, right, property, start.zone);
                break :blk .{ .exact = finish.stamp() - candidate.stamp() };
            };
            const explicit = try included.getOrPut(scratch, candidate.stamp());
            if (period) |duration| {
                if (candidate.date.kind == .date or duration.end(candidate) <= candidate.stamp()) return error.InvalidCalendar;
                if (explicit.found_existing) {
                    if (explicit.value_ptr.length) |prior| {
                        if (prior.end(explicit.value_ptr.start) != duration.end(candidate)) return error.InvalidCalendar;
                        continue;
                    }
                }
            } else if (explicit.found_existing) {
                continue;
            }
            explicit.value_ptr.* = .{ .start = candidate, .length = period };
        }
    }
    var expansion = Expansion{
        .output = output,
        .seed = start,
        .length = length,
        .kind = kind,
        .ranges = ranges.items,
        .exclude = &exclude,
        .budget = budget,
    };
    var explicit = included.iterator();
    while (explicit.next()) |item| {
        try expansion.add(item.value_ptr.start, item.value_ptr.length orelse length);
        try exclude.put(scratch, item.key_ptr.*, {});
    }
    try expansion.append(start);
    properties = ical.Properties.init(event.component);
    while (try properties.next(scratch)) |property| {
        if (property.named("RRULE")) try expansion.rule(scratch, try Rule.parse(scratch, property.value));
    }
}

const Frequency = enum { secondly, minutely, hourly, daily, weekly, monthly, yearly };
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
    year_days: []const i16 = &.{},
    positions: []const i16 = &.{},
    hours: u64 = 0,
    minutes: u64 = 0,
    seconds: u64 = 0,

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
            } else if (std.mem.eql(u8, name, "BYYEARDAY")) {
                result.year_days = try intList(i16, a, value, 366);
            } else if (std.mem.eql(u8, name, "BYHOUR")) {
                result.hours = try timeMask(value, 23);
            } else if (std.mem.eql(u8, name, "BYMINUTE")) {
                result.minutes = try timeMask(value, 59);
            } else if (std.mem.eql(u8, name, "BYSECOND")) {
                result.seconds = try timeMask(value, 60);
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
        switch (result.frequency) {
            .daily, .weekly, .monthly => if (result.year_days.len != 0) return error.InvalidCalendar,
            else => {},
        }
        for (result.weekdays) |item| {
            if (item.ordinal != 0 and result.frequency != .monthly and result.frequency != .yearly)
                return error.InvalidCalendar;
        }
        return result;
    }

    fn matches(self: Rule, seed: Date, date: Date) bool {
        if (self.months != 0 and self.months & (@as(u12, 1) << @intCast(date.month - 1)) == 0) return false;
        if (self.frequency == .yearly and self.months == 0 and self.month_days.len == 0 and
            self.year_days.len == 0 and self.weekdays.len == 0 and date.month != seed.month)
            return false;
        if (self.year_days.len != 0) {
            const year_start = monthStart(date.year, 0);
            const year_end = monthStart(date.year + 1, 0);
            if (!matchesOrdinal(i16, self.year_days, @divFloor(date.epoch() - year_start, day) + 1, @divExact(year_end - year_start, day)))
                return false;
        }
        const month_start = dayStart(.{ .year = date.year, .month = date.month, .day = 1, .seconds = 0, .kind = .date });
        const month_end = monthStart(date.year, @as(i64, date.month));
        const days_in_month = @divExact(month_end - month_start, day);
        if (self.month_days.len != 0 and !matchesOrdinal(i8, self.month_days, date.day, days_in_month)) return false;
        if (self.weekdays.len == 0) {
            if (self.frequency == .weekly) return dayOfWeek(date.epoch()) == dayOfWeek(seed.epoch());
            if ((self.frequency == .monthly or self.frequency == .yearly) and self.month_days.len == 0 and self.year_days.len == 0)
                return date.day == seed.day;
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

    fn fixedPeriod(self: Rule) ?i64 {
        return switch (self.frequency) {
            .secondly => 1,
            .minutely => 60,
            .hourly => 3600,
            .daily => day,
            .weekly => 7 * day,
            .monthly, .yearly => null,
        };
    }

    fn firstPeriod(self: Rule, seed: Date) i64 {
        return switch (self.frequency) {
            .weekly => dayStart(seed) - @mod(dayOfWeek(seed.epoch()) - self.week_start, 7) * day,
            .monthly => monthStart(seed.year, @as(i64, seed.month) - 1),
            .yearly => monthStart(seed.year, 0),
            else => seed.epoch() - @mod(seed.epoch(), self.fixedPeriod().?),
        };
    }

    fn advance(self: Rule, current: i64, periods: i64) i64 {
        if (self.fixedPeriod()) |seconds| return current + seconds * periods;
        const date = Date.fromEpoch(current, .date);
        const months = if (self.frequency == .yearly) 12 * periods else periods;
        return monthStart(date.year, @as(i64, date.month) - 1 + months);
    }

    fn clocks(self: Rule, seed: Date, period_start: i64) [3]u64 {
        if (seed.kind == .date) return @splat(1);
        const current = @mod(period_start, day);
        const hourly = @backingInt(self.frequency) <= @backingInt(Frequency.hourly);
        const minutely = @backingInt(self.frequency) <= @backingInt(Frequency.minutely);
        return .{
            selectTime(self.hours, @divFloor(if (hourly) current else seed.seconds, 3600), hourly),
            selectTime(self.minutes, @mod(@divFloor(if (minutely) current else seed.seconds, 60), 60), minutely),
            selectTime(self.seconds, @mod(if (self.frequency == .secondly) current else seed.seconds, 60), self.frequency == .secondly),
        };
    }
};

fn timeMask(text: []const u8, maximum: u8) !u64 {
    var result: u64 = 0;
    var parts = std.mem.splitScalar(u8, text, ',');
    while (parts.next()) |part| {
        if (part.len == 0 or part.len > 2) return error.InvalidCalendar;
        for (part) |char| if (!std.ascii.isDigit(char)) return error.InvalidCalendar;
        const value = std.fmt.parseInt(u8, part, 10) catch return error.InvalidCalendar;
        if (value > maximum) return error.InvalidCalendar;
        result |= @as(u64, 1) << @intCast(@min(value, 59));
    }
    return result;
}

fn selectTime(mask: u64, value: i64, limit: bool) u64 {
    const bit = @as(u64, 1) << @intCast(value);
    return if (mask == 0) bit else if (limit) mask & bit else mask;
}

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
    output: OccurrenceOutput,
    seed: Moment,
    length: Length,
    kind: ?BusyType,
    ranges: []const RangeEdit,
    exclude: *const std.AutoHashMapUnmanaged(i64, void),
    budget: *usize,

    fn add(self: *Expansion, candidate: Moment, length: Length) !void {
        const key = candidate.stamp();
        if (self.exclude.contains(key)) return;
        const next = std.sort.upperBound(RangeEdit, self.ranges, key, RangeEdit.anchorOrder);
        if (next != 0) {
            const replacement = self.ranges[next - 1].replacement orelse return;
            const date = Date.fromEpoch(candidate.date.epoch() + replacement.shift, replacement.anchor.date.kind);
            const moved = replacement.anchor.withDate(date);
            try self.output.add(moved.stamp(), (replacement.length orelse length).end(moved), replacement.kind);
        } else if (self.kind) |kind| {
            try self.output.add(key, length.end(candidate), kind);
        }
    }

    fn append(self: *Expansion, candidate: Moment) !void {
        try self.add(candidate, self.length);
    }

    fn spend(self: *Expansion) !void {
        if (self.budget.* == 0) return error.AvailabilityLimit;
        self.budget.* -= 1;
    }

    fn lastWallTime(self: *Expansion, until: ?Date) i64 {
        // An override can move a later nominal key into the current window.
        // Bound the scan using the largest possible UTC offset for each shift.
        var offset = latestOffset(self.seed.zone);
        for (self.ranges) |range| {
            if (range.replacement) |replacement|
                offset = @max(offset, latestOffset(replacement.anchor.zone) - replacement.shift);
        }
        const last = self.output.window.end + offset - 1;
        if (until) |date| return @min(last, date.epoch() + if (date.kind == .utc) latestOffset(self.seed.zone) else 0);
        return last;
    }

    fn firstPeriod(self: *Expansion, recur: Rule) i64 {
        const first = recur.firstPeriod(self.seed.date);
        if (recur.count != null or @backingInt(recur.frequency) >= @backingInt(Frequency.daily)) return first;

        // With no COUNT to preserve, skip periods whose latest possible end
        // precedes the window. Keep the occurrence grid anchored to DTSTART.
        var end_shift = self.length.wallSeconds() - earliestOffset(self.seed.zone);
        for (self.ranges) |range| {
            if (range.replacement) |replacement| {
                end_shift = @max(end_shift, replacement.shift +
                    (replacement.length orelse self.length).wallSeconds() - earliestOffset(replacement.anchor.zone));
            }
        }
        const first_wall = self.output.window.start - end_shift;
        const stride = recur.fixedPeriod().? * recur.interval;
        return first + @divFloor(@max(0, first_wall - first), stride) * stride;
    }

    fn rule(self: *Expansion, a: Allocator, recur: Rule) !void {
        const seed = self.seed.date;
        if (seed.kind == .date and @backingInt(recur.frequency) < @backingInt(Frequency.daily))
            return error.InvalidCalendar;
        var remaining = if (recur.count) |count| count - 1 else std.math.maxInt(i64);
        const through = self.lastWallTime(recur.until);
        var selected: std.ArrayList(i64) = .empty;
        defer selected.deinit(a);
        var current = self.firstPeriod(recur);
        while (current <= through and remaining > 0) : (current = recur.advance(current, recur.interval)) {
            selected.clearRetainingCapacity();
            const stop = recur.advance(current, 1);
            const clocks = recur.clocks(seed, current);
            var start_of_day = current - @mod(current, day);
            while (start_of_day < stop) : (start_of_day += day) {
                try self.spend();
                if (!recur.matches(seed, Date.fromEpoch(start_of_day, seed.kind))) continue;
                var hours = clocks[0];
                while (takeTime(&hours)) |hour| {
                    var minutes = clocks[1];
                    while (takeTime(&minutes)) |minute| {
                        var seconds = clocks[2];
                        while (takeTime(&seconds)) |second| {
                            try self.spend();
                            const wall = start_of_day + hour * 3600 + minute * 60 + second;
                            const candidate = self.seed.withDate(Date.fromEpoch(wall, seed.kind));
                            if (self.seed.zone) |zone| {
                                if (zone.isGap(candidate.date)) continue;
                            }
                            if (recur.positions.len != 0) {
                                try selected.append(a, wall);
                            } else if (try self.emit(candidate, through, recur.until, &remaining)) {
                                return;
                            }
                        }
                    }
                }
            }
            for (selected.items, 1..) |wall, index| {
                if (!matchesOrdinal(i16, recur.positions, @intCast(index), @intCast(selected.items.len))) continue;
                const candidate = self.seed.withDate(Date.fromEpoch(wall, seed.kind));
                if (try self.emit(candidate, through, recur.until, &remaining)) return;
            }
        }
    }

    fn emit(self: *Expansion, candidate: Moment, through: i64, until: ?Date, remaining: *i64) !bool {
        const wall = candidate.date.epoch();
        if (wall <= self.seed.date.epoch()) return false;
        if (wall > through) return true;
        if (until) |date| {
            const value = if (date.kind == .utc) candidate.stamp() else wall;
            if (value > date.epoch()) return true;
        }
        try self.append(candidate);
        // COUNT counts RRULE instances, including those suppressed by EXDATE.
        remaining.* -= 1;
        return remaining.* == 0;
    }
};

fn latestOffset(zone: ?clock.Zone) i64 {
    return if (zone) |value| value.offsetLimit(.latest) else 0;
}

fn earliestOffset(zone: ?clock.Zone) i64 {
    return if (zone) |value| value.offsetLimit(.earliest) else 0;
}

fn takeTime(bits: *u64) ?i64 {
    if (bits.* == 0) return null;
    const next: i64 = @ctz(bits.*);
    bits.* &= bits.* - 1;
    return next;
}
