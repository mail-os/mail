const std = @import("std");
const database = @import("../storage/database.zig");
const time = @import("../core/time_compat.zig");
const thread_ids = @import("../message/thread_ids.zig");

pub const Kind = database.Database.AttentionKind;

pub fn isInboxView(folder: []const u8) bool {
    return std.ascii.eqlIgnoreCase(folder, "INBOX") or @import("../message/categories.zig").isCategory(folder);
}

pub const Status = struct {
    follow_up: bool = false,
    saved: bool = false,
    muted: bool = false,
    snooze_until: ?i64 = null,
    remind_at: ?i64 = null,
};

const Mark = struct {
    kind: Kind,
    reference: []const u8,
    folder: []const u8,
    basename: []const u8,
    stamp: []const u8,
    wire: []const []const u8,
    waiting_id: []const u8,
    deadline: i64,

    fn at(mark: Mark, folder: []const u8, basename: []const u8, stamp: []const u8) bool {
        return std.mem.eql(u8, mark.folder, folder) and std.mem.eql(u8, mark.basename, basename) and std.mem.eql(u8, mark.stamp, stamp);
    }
};

pub const Snapshot = struct {
    marks: []const Mark,

    pub fn hasHidden(self: Snapshot) bool {
        for (self.marks) |mark| if (mark.kind == .snoozed or mark.kind == .muted) return true;
        return false;
    }

    pub fn mayContain(self: Snapshot, kind: Kind, folder: []const u8, basename: []const u8) bool {
        for (self.marks) |mark| {
            if (mark.kind == kind and std.mem.eql(u8, mark.folder, folder) and std.mem.eql(u8, mark.basename, basename)) return true;
        }
        return false;
    }

    pub fn deadline(self: Snapshot, kind: Kind, folder: []const u8, basename: []const u8, stamp: []const u8) ?i64 {
        for (self.marks) |mark| if (mark.kind == kind and mark.at(folder, basename, stamp)) return mark.deadline;
        return null;
    }

    pub fn dueCount(self: Snapshot, now: i64) usize {
        var count: usize = 0;
        for (self.marks) |mark| {
            if (mark.kind == .reminders and mark.deadline <= now) count += 1;
        }
        return count;
    }

    pub fn status(self: Snapshot, reference: []const u8, folder: []const u8, basename: []const u8, stamp: []const u8, ids: thread_ids.Headers) Status {
        var result: Status = .{};
        for (self.marks) |mark| {
            const current = std.mem.eql(u8, mark.reference, reference) or mark.at(folder, basename, stamp);
            switch (mark.kind) {
                .saved => result.saved = result.saved or current,
                .reminders => if (current or (ids.own != null and std.mem.eql(u8, mark.waiting_id, ids.own.?))) {
                    result.remind_at = @min(result.remind_at orelse mark.deadline, mark.deadline);
                },
                else => {
                    if (!current and !intersects(mark.wire, ids)) continue;
                    switch (mark.kind) {
                        .follow_up => result.follow_up = true,
                        .muted => result.muted = true,
                        .snoozed => result.snooze_until = @max(result.snooze_until orelse 0, mark.deadline),
                        else => unreachable,
                    }
                },
            }
        }
        return result;
    }
};

fn intersects(keys: []const []const u8, ids: thread_ids.Headers) bool {
    for (keys) |key| {
        if (ids.own) |own| if (std.mem.eql(u8, key, own)) return true;
        for (ids.parents) |parent| if (std.mem.eql(u8, key, parent)) return true;
    }
    return false;
}

/// The request arena owns the snapshot and the decoded identifier lists.
pub fn load(a: std.mem.Allocator, db: *database.Database, user: []const u8) !Snapshot {
    const s = try db.prepare(
        \\SELECT m.kind,r.folder,r.basename,r.file_stamp,m.wire_ids,m.waiting_id,m.deadline,m.reference
        \\FROM mail_attention m JOIN mailbox_message_refs r USING(user_id,reference)
        \\WHERE m.user_id=(SELECT id FROM users WHERE username=?1)
        \\  AND (m.kind<>'snoozed' OR m.deadline>?2)
    );
    defer s.finalize();
    try s.bind(1, user);
    try s.bind(2, time.timestamp());
    var marks: std.ArrayList(Mark) = .empty;
    while (try s.step()) {
        const kind = std.meta.stringToEnum(Kind, s.columnText(0)) orelse continue;
        const wire = try std.json.parseFromSliceLeaky([]const []const u8, a, s.columnText(4), .{ .allocate = .alloc_always });
        try marks.append(a, .{
            .kind = kind,
            .reference = try a.dupe(u8, s.columnText(7)),
            .folder = try a.dupe(u8, s.columnText(1)),
            .basename = try a.dupe(u8, s.columnText(2)),
            .stamp = try a.dupe(u8, s.columnText(3)),
            .wire = wire,
            .waiting_id = try a.dupe(u8, s.columnText(5)),
            .deadline = s.columnInt64(6),
        });
    }
    return .{ .marks = try marks.toOwnedSlice(a) };
}
