//! Calendar extras are opt-in, private mailbox metadata. The versioned document
//! travels between installations without carrying an account ID or revision.
const std = @import("std");
const database = @import("database.zig");
const teams = @import("team_store.zig");
const Date = @import("../protocol/icalendar_time.zig").Date;

pub const max_bytes = 512 * 1024;
pub const Appearance = enum { standard, compact };

pub const Habit = struct { id: []const u8, title: []const u8, days: []const []const u8 };
pub const Countdown = struct { id: []const u8, title: []const u8, day: []const u8 };
pub const Journal = struct { day: []const u8, text: []const u8 };
pub const TimeEntry = struct { id: []const u8, title: []const u8, day: []const u8, minutes: u16 };

pub const Tools = struct {
    version: u8,
    enabled: bool,
    appearance: Appearance,
    habits: []const Habit,
    countdowns: []const Countdown,
    journal: []const Journal,
    time: []const TimeEntry,
};

pub const Snapshot = struct { revision: i64, tools: Tools };

pub fn load(a: std.mem.Allocator, db: *database.Database, mailbox: []const u8) !Snapshot {
    const stmt = try db.prepare(
        \\SELECT payload,revision FROM mail_calendar_tools
        \\WHERE user_id=(SELECT id FROM users WHERE username=?1 AND enabled=1)
    );
    defer stmt.finalize();
    try stmt.bind(1, mailbox);
    if (!try stmt.step()) return .{
        .revision = 0,
        .tools = .{ .version = 1, .enabled = false, .appearance = .standard, .habits = &.{}, .countdowns = &.{}, .journal = &.{}, .time = &.{} },
    };
    return .{
        .revision = stmt.columnInt64(1),
        .tools = try std.json.parseFromSliceLeaky(Tools, a, stmt.columnText(0), .{ .allocate = .alloc_always }),
    };
}

pub fn isCompact(db: *database.Database, mailbox: []const u8) !bool {
    const stmt = try db.prepare(
        \\SELECT json_extract(payload,'$.enabled')=1 AND json_extract(payload,'$.appearance')='compact'
        \\FROM mail_calendar_tools WHERE user_id=(SELECT id FROM users WHERE username=?1 AND enabled=1)
    );
    defer stmt.finalize();
    try stmt.bind(1, mailbox);
    return try stmt.step() and stmt.columnInt64(0) == 1;
}

pub fn save(a: std.mem.Allocator, db: *database.Database, mailbox: []const u8, change: Snapshot) !Snapshot {
    if (change.revision < 0 or change.revision == std.math.maxInt(i64)) return error.InvalidPersonalTools;
    try validate(a, change.tools);
    const payload = try std.json.Stringify.valueAlloc(a, change.tools, .{});
    if (payload.len > max_bytes) return error.PersonalToolsTooLarge;

    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const owner = (try teams.activeMailboxId(tx, mailbox)) orelse return error.PersonalToolsUnavailable;
    const revision = blk: {
        const stmt = try tx.prepare(if (change.revision == 0)
            \\INSERT INTO mail_calendar_tools(user_id,payload,revision) VALUES(?1,?2,1)
            \\ON CONFLICT(user_id) DO NOTHING RETURNING revision
        else
            \\UPDATE mail_calendar_tools SET payload=?2,revision=revision+1
            \\WHERE user_id=?1 AND revision=?3 RETURNING revision
        );
        defer stmt.finalize();
        try stmt.bind(1, owner);
        try stmt.bind(2, payload);
        if (change.revision != 0) try stmt.bind(3, change.revision);
        if (!try stmt.step()) return error.PersonalToolsChanged;
        break :blk stmt.columnInt64(0);
    };
    try tx.commit();
    return .{ .revision = revision, .tools = change.tools };
}

fn validate(a: std.mem.Allocator, tools: Tools) !void {
    if (tools.version != 1 or tools.habits.len > 24 or tools.countdowns.len > 64 or tools.journal.len > 366 or tools.time.len > 1000)
        return error.InvalidPersonalTools;

    var keys: std.StringHashMapUnmanaged(void) = .empty;
    defer keys.deinit(a);
    for (tools.habits) |habit| {
        try addItemKey(a, &keys, habit.id, habit.title);
        if (habit.days.len > 730) return error.InvalidPersonalTools;
        var previous: []const u8 = "";
        for (habit.days) |day| {
            if (Date.parseCivil(day) == null or std.mem.order(u8, previous, day) != .lt) return error.InvalidPersonalTools;
            previous = day;
        }
    }
    keys.clearRetainingCapacity();
    for (tools.countdowns) |countdown| {
        try addItemKey(a, &keys, countdown.id, countdown.title);
        if (Date.parseCivil(countdown.day) == null) return error.InvalidPersonalTools;
    }
    keys.clearRetainingCapacity();
    for (tools.journal) |entry| {
        if (Date.parseCivil(entry.day) == null or !validText(entry.text, 2_000, true)) return error.InvalidPersonalTools;
        if ((try keys.getOrPut(a, entry.day)).found_existing) return error.InvalidPersonalTools;
    }
    keys.clearRetainingCapacity();
    for (tools.time) |entry| {
        try addItemKey(a, &keys, entry.id, entry.title);
        if (Date.parseCivil(entry.day) == null or entry.minutes == 0 or entry.minutes > 1440) return error.InvalidPersonalTools;
    }
}

fn addItemKey(a: std.mem.Allocator, keys: *std.StringHashMapUnmanaged(void), key: []const u8, title: []const u8) !void {
    if (key.len != 32 or !validText(title, 100, false)) return error.InvalidPersonalTools;
    for (key) |byte| if (!std.ascii.isHex(byte) or std.ascii.isUpper(byte)) return error.InvalidPersonalTools;
    if ((try keys.getOrPut(a, key)).found_existing) return error.InvalidPersonalTools;
}

fn validText(text: []const u8, max: usize, multiline: bool) bool {
    if (text.len > max * 4 or std.mem.trim(u8, text, " \t\r\n").len == 0) return false;
    if ((std.unicode.utf8CountCodepoints(text) catch return false) > max) return false;
    for (text) |byte| {
        if (multiline and (byte == '\n' or byte == '\r' or byte == '\t')) continue;
        if (byte < 32 or byte == 127) return false;
    }
    return true;
}
