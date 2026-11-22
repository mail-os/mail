const std = @import("std");
const icalendar = @import("icalendar.zig");
const Allocator = std.mem.Allocator;

pub fn bundledTimezone(name: []const u8) ?[]const u8 {
    const catalog = @embedFile("../api/webmail_dist/calendar_timezones.ics");
    var buf: [160]u8 = undefined;
    const marker = std.fmt.bufPrint(&buf, "BEGIN:VTIMEZONE\r\nTZID:{s}\r\n", .{name}) catch return null;
    const start = std.mem.indexOf(u8, catalog, marker) orelse return null;
    const after = start + marker.len;
    const suffix = "END:VTIMEZONE\r\n";
    const end = std.mem.indexOfPos(u8, catalog, after, suffix) orelse return null;
    return catalog[start .. end + suffix.len];
}

pub const Date = struct {
    year: i64,
    month: u8,
    day: u8,
    seconds: i64,
    kind: Kind,

    pub const Kind = enum { date, local, utc };

    pub fn parse(value: []const u8) ?Date {
        if (value.len != 8 and value.len != 15 and value.len != 16) return null;
        const year = digits(value[0..4]) orelse return null;
        const month = digits(value[4..6]) orelse return null;
        const day = digits(value[6..8]) orelse return null;
        if (year == 0 or month < 1 or month > 12 or day < 1 or day > monthDays(year, @intCast(month))) return null;
        var result = Date{ .year = year, .month = @intCast(month), .day = @intCast(day), .seconds = 0, .kind = .date };
        if (value.len == 8) return result;
        if (value[8] != 'T' or (value.len == 16 and value[15] != 'Z')) return null;
        const hour = digits(value[9..11]) orelse return null;
        const minute = digits(value[11..13]) orelse return null;
        const second = digits(value[13..15]) orelse return null;
        if (hour > 23 or minute > 59 or second > 60) return null;
        result.seconds = hour * 3600 + minute * 60 + @min(second, 59);
        result.kind = if (value.len == 16) .utc else .local;
        return result;
    }

    pub fn epoch(self: Date) i64 {
        const year = self.year - @intFromBool(self.month <= 2);
        const month: i64 = self.month;
        const march_month = month + @as(i64, if (month > 2) -3 else 9);
        const year_days = year * 365 + @divFloor(year, 4) - @divFloor(year, 100) + @divFloor(year, 400);
        const month_days = @divFloor(153 * march_month + 2, 5);
        return (year_days + month_days + @as(i64, self.day) - 719469) * 86400 + self.seconds;
    }

    pub fn fromEpoch(value: i64, kind: Kind) Date {
        const days = @divFloor(value, 86400) + 719468;
        const era = @divFloor(days, 146097);
        const era_day = days - era * 146097;
        const era_year = @divFloor(era_day - @divFloor(era_day, 1460) + @divFloor(era_day, 36524) - @divFloor(era_day, 146096), 365);
        const year_day = era_day - (365 * era_year + @divFloor(era_year, 4) - @divFloor(era_year, 100));
        const march_month = @divFloor(5 * year_day + 2, 153);
        const month = march_month + @as(i64, if (march_month < 10) 3 else -9);
        return .{
            .year = era_year + era * 400 + @intFromBool(month <= 2),
            .month = @intCast(month),
            .day = @intCast(year_day - @divFloor(153 * march_month + 2, 5) + 1),
            .seconds = @mod(value, 86400),
            .kind = kind,
        };
    }
};

fn digits(value: []const u8) ?i64 {
    if (value.len == 0) return null;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return null;
    return std.fmt.parseInt(i64, value, 10) catch null;
}

fn monthDays(year: i64, month: u8) u8 {
    return switch (month) {
        4, 6, 9, 11 => 30,
        2 => if (@mod(year, 4) == 0 and (@mod(year, 100) != 0 or @mod(year, 400) == 0)) 29 else 28,
        else => 31,
    };
}

fn utcOffset(value: []const u8) ?i64 {
    if (value.len != 5 and value.len != 7) return null;
    if (value[0] != '+' and value[0] != '-') return null;
    const hours = digits(value[1..3]) orelse return null;
    const minutes = digits(value[3..5]) orelse return null;
    const seconds = if (value.len == 7) digits(value[5..7]) orelse return null else 0;
    if (hours > 23 or minutes > 59 or seconds > 59) return null;
    const offset = hours * 3600 + minutes * 60 + seconds;
    return if (value[0] == '-') -offset else offset;
}

pub const Duration = struct { days: i64 = 0, seconds: i64 = 0 };

pub fn duration(value: []const u8) ?Duration {
    if (value.len < 3 or value[0] != 'P') return null;
    var result = Duration{};
    var start: usize = 1;
    var time = false;
    var last_unit: u8 = 0;
    for (value[1..], 1..) |byte, index| {
        if (std.ascii.isDigit(byte)) continue;
        if (byte == 'T' and index == start and !time) {
            time = true;
            start = index + 1;
            continue;
        }
        const count = std.fmt.parseInt(u32, value[start..index], 10) catch return null;
        const rank: u8 = switch (byte) {
            'W' => 1,
            'D' => 2,
            'H' => 3,
            'M' => 4,
            'S' => 5,
            else => return null,
        };
        if (rank <= last_unit) return null;
        last_unit = rank;
        switch (byte) {
            'W' => if (!time and index + 1 == value.len) {
                result.days += @as(i64, count) * 7;
            } else return null,
            'D' => if (!time) {
                result.days += count;
            } else return null,
            'H' => if (time) {
                result.seconds += @as(i64, count) * 3600;
            } else return null,
            'M' => if (time) {
                result.seconds += @as(i64, count) * 60;
            } else return null,
            'S' => if (time) {
                result.seconds += count;
            } else return null,
            else => return null,
        }
        start = index + 1;
    }
    const total = result.days * 86400 + result.seconds;
    if (start != value.len or total > 3155760000 or value[value.len - 1] == 'T') return null;
    return result;
}

const Weekday = struct { ordinal: i8, day: i64 };
const Yearly = struct {
    month: ?u8 = null,
    month_day: ?i8 = null,
    weekday: ?Weekday = null,
    interval: i64 = 1,
    until: ?Date = null,
    count: ?i64 = null,

    fn parse(value: []const u8) error{UnsupportedTimezone}!Yearly {
        var result = Yearly{};
        var fields = std.mem.splitScalar(u8, value, ';');
        var yearly = false;
        while (fields.next()) |field| {
            const eq = std.mem.indexOfScalar(u8, field, '=') orelse return error.UnsupportedTimezone;
            const key = field[0..eq];
            const val = field[eq + 1 ..];
            if (std.ascii.eqlIgnoreCase(key, "FREQ") and std.ascii.eqlIgnoreCase(val, "YEARLY")) {
                yearly = true;
            } else if (std.ascii.eqlIgnoreCase(key, "BYMONTH")) {
                const month = digits(val) orelse return error.UnsupportedTimezone;
                if (month < 1 or month > 12) return error.UnsupportedTimezone;
                result.month = @intCast(month);
            } else if (std.ascii.eqlIgnoreCase(key, "BYMONTHDAY")) {
                const day = std.fmt.parseInt(i8, val, 10) catch return error.UnsupportedTimezone;
                if (day == 0 or day < -31 or day > 31) return error.UnsupportedTimezone;
                result.month_day = day;
            } else if (std.ascii.eqlIgnoreCase(key, "BYDAY") and val.len >= 2) {
                const ordinal = if (val.len > 2) std.fmt.parseInt(i8, val[0 .. val.len - 2], 10) catch return error.UnsupportedTimezone else 0;
                if (ordinal < -5 or ordinal > 5) return error.UnsupportedTimezone;
                const days = [_][]const u8{ "SU", "MO", "TU", "WE", "TH", "FR", "SA" };
                for (days, 0..) |day, index| {
                    if (std.ascii.eqlIgnoreCase(val[val.len - 2 ..], day)) {
                        result.weekday = .{ .ordinal = ordinal, .day = @intCast(index) };
                        break;
                    }
                } else return error.UnsupportedTimezone;
            } else if (std.ascii.eqlIgnoreCase(key, "INTERVAL")) {
                result.interval = digits(val) orelse return error.UnsupportedTimezone;
                if (result.interval < 1 or result.interval > 9999) return error.UnsupportedTimezone;
            } else if (std.ascii.eqlIgnoreCase(key, "UNTIL")) {
                result.until = Date.parse(val) orelse return error.UnsupportedTimezone;
            } else if (std.ascii.eqlIgnoreCase(key, "COUNT")) {
                result.count = digits(val) orelse return error.UnsupportedTimezone;
                if (result.count.? < 1 or result.count.? > 10000) return error.UnsupportedTimezone;
            } else return error.UnsupportedTimezone;
        }
        if (!yearly) return error.UnsupportedTimezone;
        if (result.count != null and result.until != null) return error.UnsupportedTimezone;
        if (result.weekday) |weekday| {
            if (weekday.ordinal == 0 and result.month_day == null) return error.UnsupportedTimezone;
            if (weekday.ordinal != 0 and result.month == null) return error.UnsupportedTimezone;
        }
        return result;
    }

    fn occurrence(self: Yearly, seed: Date, year: i64) ?Date {
        var date = seed;
        date.year = year;
        date.month = self.month orelse seed.month;
        const length: i64 = monthDays(year, date.month);
        var day: i64 = seed.day;
        if (self.month_day) |value| day = if (value < 0) length + value + 1 else value;
        if (self.weekday) |weekday| {
            date.day = if (weekday.ordinal < 0) @intCast(length) else 1;
            const anchor_weekday = @mod(@divFloor(date.epoch(), 86400) + 4, 7);
            const selected = if (weekday.ordinal > 0)
                1 + @mod(weekday.day - anchor_weekday, 7) + 7 * (@as(i64, weekday.ordinal) - 1)
            else
                length - @mod(anchor_weekday - weekday.day, 7) + 7 * (@as(i64, weekday.ordinal) + 1);
            if (weekday.ordinal != 0) {
                if (self.month_day != null and selected != day) return null;
                day = selected;
            } else if (@mod(anchor_weekday + day - 1, 7) != weekday.day) return null;
        }
        if (day < 1 or day > length) return null;
        date.day = @intCast(day);
        return date;
    }
};

const Observance = struct {
    start: Date,
    from: i64,
    to: i64,
    rule: ?Yearly,
    dates: std.ArrayList(Date),
};

fn observance(a: Allocator, component: icalendar.Component) !Observance {
    var fields = icalendar.Properties.init(component);
    var start: ?Date = null;
    var from: ?i64 = null;
    var to: ?i64 = null;
    var rule: ?Yearly = null;
    var dates: std.ArrayList(Date) = .empty;
    while (try fields.next(a)) |prop| {
        if (prop.named("DTSTART")) start = Date.parse(prop.value);
        if (prop.named("TZOFFSETFROM")) from = utcOffset(prop.value);
        if (prop.named("TZOFFSETTO")) to = utcOffset(prop.value);
        if (prop.named("RRULE")) rule = try Yearly.parse(prop.value);
        if (prop.named("RDATE")) {
            var items = std.mem.splitScalar(u8, prop.value, ',');
            while (items.next()) |item| try dates.append(a, Date.parse(item) orelse return error.UnsupportedTimezone);
        }
    }
    const onset = start orelse return error.UnsupportedTimezone;
    if (onset.kind != .local) return error.UnsupportedTimezone;
    return .{ .start = onset, .from = from orelse return error.UnsupportedTimezone, .to = to orelse return error.UnsupportedTimezone, .rule = rule, .dates = dates };
}

pub const Zone = struct {
    rules: []const Observance,

    pub fn parse(a: Allocator, component: icalendar.Component) !Zone {
        var rules: std.ArrayList(Observance) = .empty;
        for (try icalendar.childComponents(a, component)) |child| {
            if (std.ascii.eqlIgnoreCase(child.name, "STANDARD") or std.ascii.eqlIgnoreCase(child.name, "DAYLIGHT"))
                try rules.append(a, try observance(a, child));
        }
        if (rules.items.len == 0) return error.UnsupportedTimezone;
        return .{ .rules = rules.items };
    }

    pub fn offsetAt(self: Zone, date: Date) i64 {
        return self.wallOffset(date).offset;
    }

    pub fn isGap(self: Zone, date: Date) bool {
        return self.wallOffset(date).gap;
    }

    fn wallOffset(self: Zone, date: Date) struct { offset: i64, gap: bool } {
        const wall = date.epoch();
        var earliest = self.rules[0];
        var latest: ?Transition = null;
        var gap = false;
        for (self.rules) |rule| {
            if (rule.start.epoch() - rule.from < earliest.start.epoch() - earliest.from) earliest = rule;
            _ = consider(&latest, &gap, rule, rule.start.epoch(), wall);
            for (rule.dates.items) |extra| _ = consider(&latest, &gap, rule, extra.epoch() + if (extra.kind == .utc) rule.from else @as(i64, 0), wall);
            if (rule.rule) |yearly| {
                if (yearly.count) |count| {
                    var remaining = count - 1; // DTSTART is the first occurrence.
                    var year = rule.start.year;
                    while (remaining > 0 and year <= date.year) : (year += yearly.interval) {
                        const occurrence = yearly.occurrence(rule.start, year) orelse continue;
                        const local = occurrence.epoch();
                        if (local <= rule.start.epoch()) continue;
                        if (!consider(&latest, &gap, rule, local, wall)) break;
                        remaining -= 1;
                    }
                    continue;
                }
                var last_year = if (yearly.until) |until| @min(until.year, date.year) else date.year;
                if (last_year < rule.start.year) continue;
                last_year -= @mod(last_year - rule.start.year, yearly.interval);
                // Find the latest applicable occurrence, including the prior year
                // when the current year's clock change has not happened yet.
                var year = last_year;
                while (year >= rule.start.year) : (year -= yearly.interval) {
                    const occurrence = yearly.occurrence(rule.start, year) orelse continue;
                    const local = occurrence.epoch();
                    if (local < rule.start.epoch()) break;
                    if (yearly.until) |until| {
                        if (local - (if (until.kind == .utc) rule.from else @as(i64, 0)) > until.epoch()) continue;
                    }
                    if (consider(&latest, &gap, rule, local, wall)) break;
                }
            }
        }
        return .{ .offset = if (latest) |transition| transition.offset else earliest.from, .gap = gap };
    }
};

const Transition = struct { onset: i64, offset: i64 };

fn consider(latest: *?Transition, gap: *bool, rule: Observance, local: i64, wall: i64) bool {
    // RFC 5545 uses the offset before a forward jump for times in the gap.
    const effective = local + @max(rule.to - rule.from, 0);
    if (wall < effective) {
        if (wall >= local) gap.* = true;
        return false;
    }
    if (latest.* == null or latest.*.?.onset < effective) latest.* = .{ .onset = effective, .offset = rule.to };
    return true;
}

test "timezone offsets around spring gaps and autumn folds use the first wall-clock occurrence" {
    const data =
        \\BEGIN:VTIMEZONE
        \\TZID:Europe/Vienna
        \\BEGIN:STANDARD
        \\DTSTART:19961027T030000
        \\RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU
        \\TZOFFSETFROM:+0200
        \\TZOFFSETTO:+0100
        \\END:STANDARD
        \\BEGIN:DAYLIGHT
        \\DTSTART:19810329T020000
        \\RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU
        \\TZOFFSETFROM:+0100
        \\TZOFFSETTO:+0200
        \\END:DAYLIGHT
        \\END:VTIMEZONE
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const zone = try Zone.parse(arena.allocator(), .{ .name = "VTIMEZONE", .bytes = data });
    try std.testing.expectEqual(@as(i64, 3600), zone.offsetAt(Date.parse("20260329T023000").?));
    try std.testing.expectEqual(@as(i64, 7200), zone.offsetAt(Date.parse("20260329T033000").?));
    try std.testing.expectEqual(@as(i64, 7200), zone.offsetAt(Date.parse("20261025T023000").?));
    try std.testing.expectEqual(@as(i64, 3600), zone.offsetAt(Date.parse("20261025T033000").?));
    try std.testing.expectEqual(@as(i64, -86400), Date.parse("19691231").?.epoch());
    try std.testing.expect(Date.parse("20260229") == null);
}
