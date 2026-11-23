//! Portable, mailbox-owned Calendar metadata for the local operator tools.
const std = @import("std");
const database = @import("database.zig");
const day_labels = @import("calendar_day_labels.zig");
const tasks = @import("calendar_tasks.zig");
const tools = @import("calendar_tools.zig");
const teams = @import("team_store.zig");
const Date = @import("../protocol/icalendar_time.zig").Date;

const Allocator = std.mem.Allocator;
const Transaction = database.Database.Transaction;
const PortableTask = struct { title: []const u8, day: ?[]const u8, completed: bool };
const PortableLabel = struct { day: []const u8, label: []const u8 };
pub const archive_path = "CalendarWorkflow.json";

pub const Document = struct {
    version: u8,
    tasks: []const PortableTask,
    dayLabels: []const PortableLabel,
    personalTools: ?tools.Tools,
};

/// The operator has already resolved the canonical owner. Read directly by ID
/// so an account with sign-in disabled can still receive its data.
pub fn snapshot(a: Allocator, db: *database.Database, owner: i64) !Document {
    var tx = try db.beginTransaction(.read);
    defer tx.deinit();
    const document: Document = .{
        .version = 1,
        .tasks = try readTasks(a, tx, owner),
        .dayLabels = try readLabels(a, tx, owner),
        .personalTools = try readTools(a, tx, owner),
    };
    try tx.commit();
    return document;
}

fn readTasks(a: Allocator, tx: Transaction, owner: i64) ![]PortableTask {
    const stmt = try tx.prepare(
        \\SELECT title,day,completed FROM mail_calendar_tasks
        \\WHERE user_id=?1 ORDER BY day IS NULL,day,id
    );
    defer stmt.finalize();
    try stmt.bind(1, owner);
    var rows: std.ArrayList(PortableTask) = .empty;
    while (try stmt.step()) try rows.append(a, .{
        .title = try a.dupe(u8, stmt.columnText(0)),
        .day = if (stmt.columnIsNull(1)) null else try a.dupe(u8, stmt.columnText(1)),
        .completed = stmt.columnInt64(2) != 0,
    });
    return rows.toOwnedSlice(a);
}

fn readLabels(a: Allocator, tx: Transaction, owner: i64) ![]PortableLabel {
    const stmt = try tx.prepare(
        \\SELECT day,label FROM mail_calendar_day_labels
        \\WHERE user_id=?1 AND label IS NOT NULL ORDER BY day
    );
    defer stmt.finalize();
    try stmt.bind(1, owner);
    var rows: std.ArrayList(PortableLabel) = .empty;
    while (try stmt.step()) try rows.append(a, .{
        .day = try a.dupe(u8, stmt.columnText(0)),
        .label = try a.dupe(u8, stmt.columnText(1)),
    });
    return rows.toOwnedSlice(a);
}

fn readTools(a: Allocator, tx: Transaction, owner: i64) !?tools.Tools {
    const stmt = try tx.prepare("SELECT payload FROM mail_calendar_tools WHERE user_id=?1");
    defer stmt.finalize();
    try stmt.bind(1, owner);
    if (!try stmt.step()) return null;
    return try std.json.parseFromSliceLeaky(tools.Tools, a, stmt.columnText(0), .{ .allocate = .alloc_always });
}

/// Restore each populated section into an empty destination section. Check
/// and insert under the same write transaction to avoid overwrites and duplicates.
pub fn restore(a: Allocator, db: *database.Database, mailbox: []const u8, doc: Document) !void {
    if (doc.version != 1 or doc.tasks.len > tasks.max_tasks) return error.InvalidCalendarWorkflow;
    const payload = if (doc.personalTools) |document| try tools.encode(a, document) else null;
    defer if (payload) |bytes| a.free(bytes);

    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const owner = (try teams.activeMailboxId(tx, mailbox)) orelse return error.CalendarWorkflowOwnerUnavailable;
    {
        const occupied = try tx.prepare(
            \\SELECT (?2 AND EXISTS(SELECT 1 FROM mail_calendar_tasks WHERE user_id=?1))
            \\OR (?3 AND EXISTS(SELECT 1 FROM mail_calendar_day_labels WHERE user_id=?1))
            \\OR (?4 AND EXISTS(SELECT 1 FROM mail_calendar_tools WHERE user_id=?1))
        );
        defer occupied.finalize();
        try occupied.bind(1, owner);
        try occupied.bind(2, @intFromBool(doc.tasks.len != 0));
        try occupied.bind(3, @intFromBool(doc.dayLabels.len != 0));
        try occupied.bind(4, @intFromBool(payload != null));
        if (!try occupied.step() or occupied.columnInt64(0) != 0) return error.CalendarWorkflowAlreadyExists;
    }
    if (doc.tasks.len != 0) try insertTasks(tx, owner, doc.tasks);
    if (doc.dayLabels.len != 0) try insertLabels(tx, owner, doc.dayLabels);
    if (payload) |bytes| {
        const stmt = try tx.prepare("INSERT INTO mail_calendar_tools(user_id,payload,revision) VALUES(?1,?2,1)");
        defer stmt.finalize();
        try stmt.bind(1, owner);
        try stmt.bind(2, bytes);
        _ = try stmt.step();
    }
    try tx.commit();
}

fn insertTasks(tx: Transaction, owner: i64, input: []const PortableTask) !void {
    const stmt = try tx.prepare("INSERT INTO mail_calendar_tasks(user_id,title,day,completed,revision) VALUES(?1,?2,?3,?4,1)");
    defer stmt.finalize();
    try stmt.bind(1, owner);
    for (input) |task| {
        try stmt.bind(2, try tasks.validateContent(task.title, task.day));
        try stmt.bindOpt(3, task.day);
        try stmt.bind(4, @intFromBool(task.completed));
        _ = try stmt.step();
        try stmt.reset();
    }
}

fn insertLabels(tx: Transaction, owner: i64, input: []const PortableLabel) !void {
    const stmt = try tx.prepare(
        \\INSERT INTO mail_calendar_day_labels(user_id,day,label,revision) VALUES(?1,?2,?3,1)
        \\ON CONFLICT(user_id,day) DO NOTHING RETURNING day
    );
    defer stmt.finalize();
    try stmt.bind(1, owner);
    for (input) |entry| {
        if (Date.parseCivil(entry.day) == null) return error.InvalidDayLabel;
        try stmt.bind(2, entry.day);
        try stmt.bind(3, try day_labels.validateLabel(entry.label));
        if (!try stmt.step()) return error.DuplicateCalendarWorkflowDay;
        try stmt.reset();
    }
}
