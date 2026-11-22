//! Private planning tasks use civil dates and the stable mailbox owner ID.
const std = @import("std");
const database = @import("database.zig");
const teams = @import("team_store.zig");
const Date = @import("../protocol/icalendar_time.zig").Date;

pub const max_tasks = 500;
pub const max_title = 120;

pub const Task = struct {
    id: i64,
    title: []const u8,
    day: ?[]const u8,
    completed: bool,
    revision: i64,
};

pub const Edit = struct {
    title: []const u8,
    day: ?[]const u8,
    completed: bool,
    revision: i64,
};

pub fn list(a: std.mem.Allocator, db: *database.Database, mailbox: []const u8) ![]Task {
    const stmt = try db.prepare(
        \\SELECT id,title,day,completed,revision FROM mail_calendar_tasks
        \\WHERE user_id=(SELECT id FROM users WHERE username=?1 AND enabled=1)
        \\ORDER BY day IS NULL,day,id
    );
    defer stmt.finalize();
    try stmt.bind(1, mailbox);
    var rows: std.ArrayList(Task) = .empty;
    while (try stmt.step()) {
        try rows.append(a, .{
            .id = stmt.columnInt64(0),
            .title = try a.dupe(u8, stmt.columnText(1)),
            .day = if (stmt.columnIsNull(2)) null else try a.dupe(u8, stmt.columnText(2)),
            .completed = stmt.columnInt64(3) != 0,
            .revision = stmt.columnInt64(4),
        });
    }
    return rows.toOwnedSlice(a);
}

pub fn save(db: *database.Database, mailbox: []const u8, id: ?i64, edit: Edit) !Task {
    const title = std.mem.trim(u8, edit.title, " ");
    if (title.len == 0 or title.len > max_title * 4 or
        (std.unicode.utf8CountCodepoints(title) catch return error.InvalidCalendarTask) > max_title)
        return error.InvalidCalendarTask;
    for (title) |byte| if (byte < 32 or byte == 127) return error.InvalidCalendarTask;
    if (edit.day) |day| if (Date.parseCivil(day) == null) return error.InvalidCalendarTask;
    if ((id == null and edit.revision != 0) or (id != null and !validRevision(edit.revision)))
        return error.InvalidCalendarTask;

    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const owner = (try teams.activeMailboxId(tx, mailbox)) orelse return error.InvalidCalendarTaskOwner;
    const task = blk: {
        const stmt = try tx.prepare(if (id != null)
            \\UPDATE mail_calendar_tasks SET title=?2,day=?3,completed=?4,revision=revision+1
            \\WHERE user_id=?1 AND id=?5 AND revision=?6 RETURNING id,revision
        else
            \\INSERT INTO mail_calendar_tasks(user_id,title,day,completed,revision)
            \\SELECT ?1,?2,?3,?4,1 WHERE (SELECT count(*) FROM mail_calendar_tasks WHERE user_id=?1) < ?5
            \\RETURNING id,revision
        );
        defer stmt.finalize();
        try stmt.bind(1, owner);
        try stmt.bind(2, title);
        try stmt.bindOpt(3, edit.day);
        try stmt.bind(4, @as(i64, @intFromBool(edit.completed)));
        if (id) |task_id| {
            try stmt.bind(5, task_id);
            try stmt.bind(6, edit.revision);
        } else try stmt.bind(5, @as(i64, max_tasks));
        if (!try stmt.step()) return if (id != null) error.CalendarTaskChanged else error.CalendarTaskLimit;
        break :blk Task{
            .id = stmt.columnInt64(0),
            .revision = stmt.columnInt64(1),
            .title = title,
            .day = edit.day,
            .completed = edit.completed,
        };
    };
    try tx.commit();
    return task;
}

pub fn remove(db: *database.Database, mailbox: []const u8, id: i64, revision: i64) !void {
    if (!validRevision(revision)) return error.InvalidCalendarTask;
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const owner = (try teams.activeMailboxId(tx, mailbox)) orelse return error.InvalidCalendarTaskOwner;
    {
        const stmt = try tx.prepare("DELETE FROM mail_calendar_tasks WHERE user_id=?1 AND id=?2 AND revision=?3 RETURNING id");
        defer stmt.finalize();
        try stmt.bind(1, owner);
        try stmt.bind(2, id);
        try stmt.bind(3, revision);
        if (!try stmt.step()) return error.CalendarTaskChanged;
    }
    try tx.commit();
}

fn validRevision(revision: i64) bool {
    return revision > 0 and revision < std.math.maxInt(i64);
}
