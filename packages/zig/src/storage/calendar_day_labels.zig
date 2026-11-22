//! Private planning labels belong to a mailbox and a civil date.
const std = @import("std");
const database = @import("database.zig");
const teams = @import("team_store.zig");
const Date = @import("../protocol/icalendar_time.zig").Date;

pub const Label = struct {
    day: []const u8,
    label: ?[]const u8,
    revision: i64,
};

pub const Edit = struct { label: ?[]const u8, revision: i64 };
pub const max_label_bytes = 320;

pub fn list(a: std.mem.Allocator, db: *database.Database, mailbox: []const u8, start: []const u8, end: []const u8) ![]Label {
    const first = Date.parseCivil(start) orelse return error.InvalidDayLabelRange;
    const last = Date.parseCivil(end) orelse return error.InvalidDayLabelRange;
    const distance = last.epoch() - first.epoch();
    if (distance < 0 or distance >= 366 * 86400) return error.InvalidDayLabelRange;

    const stmt = try db.prepare(
        \\SELECT day,label,revision FROM mail_calendar_day_labels
        \\WHERE user_id=(SELECT id FROM users WHERE username=?1 AND enabled=1) AND day BETWEEN ?2 AND ?3
        \\ORDER BY day
    );
    defer stmt.finalize();
    try stmt.bind(1, mailbox);
    try stmt.bind(2, start);
    try stmt.bind(3, end);
    var rows: std.ArrayList(Label) = .empty;
    while (try stmt.step()) {
        try rows.append(a, .{
            .day = try a.dupe(u8, stmt.columnText(0)),
            .label = if (stmt.columnIsNull(1)) null else try a.dupe(u8, stmt.columnText(1)),
            .revision = stmt.columnInt64(2),
        });
    }
    return rows.toOwnedSlice(a);
}

/// Rows retain a revision after clearing, so stale edits cannot restore text
/// that the owner removed in another tab.
pub fn save(db: *database.Database, mailbox: []const u8, day: []const u8, edit: Edit) !Label {
    if (Date.parseCivil(day) == null or edit.revision < 0 or edit.revision == std.math.maxInt(i64))
        return error.InvalidDayLabel;
    const label = if (edit.label) |value| blk: {
        const trimmed = std.mem.trim(u8, value, " ");
        if (trimmed.len == 0 or trimmed.len > max_label_bytes or
            (std.unicode.utf8CountCodepoints(trimmed) catch return error.InvalidDayLabel) > 80)
            return error.InvalidDayLabel;
        for (trimmed) |byte| if (byte < 32 or byte == 127) return error.InvalidDayLabel;
        break :blk trimmed;
    } else null;
    if (label == null and edit.revision == 0) return error.InvalidDayLabel;

    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const owner = (try teams.activeMailboxId(tx, mailbox)) orelse return error.InvalidDayLabelOwner;
    const revision = blk: {
        const stmt = try tx.prepare(if (edit.revision == 0)
            \\INSERT INTO mail_calendar_day_labels(user_id,day,label,revision) VALUES(?1,?2,?3,1)
            \\ON CONFLICT(user_id,day) DO NOTHING RETURNING revision
        else
            \\UPDATE mail_calendar_day_labels SET label=?3,revision=revision+1
            \\WHERE user_id=?1 AND day=?2 AND revision=?4 RETURNING revision
        );
        defer stmt.finalize();
        try stmt.bind(1, owner);
        try stmt.bind(2, day);
        if (label) |value| try stmt.bind(3, value) else try stmt.bindNull(3);
        if (edit.revision != 0) try stmt.bind(4, edit.revision);
        if (!try stmt.step()) return error.DayLabelChanged;
        break :blk stmt.columnInt64(0);
    };
    try tx.commit();
    return .{ .day = day, .label = label, .revision = revision };
}
