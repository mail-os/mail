//! A team workflow belongs to the shared mailbox and stable message reference.
//! Mailbox grants confer access to Inbox without impersonating the source user.
const std = @import("std");
const database = @import("database.zig");
const time = @import("../core/time_compat.zig");
const Allocator = std.mem.Allocator;
const Tx = database.Database.Transaction;

pub const schema =
    \\CREATE TABLE IF NOT EXISTS mail_shared_inbox_state (
    \\    team_id TEXT NOT NULL,
    \\    source_id INTEGER NOT NULL,
    \\    reference TEXT NOT NULL,
    \\    assignee_id INTEGER,
    \\    resolved INTEGER NOT NULL DEFAULT 0 CHECK(resolved IN (0,1)),
    \\    revision INTEGER NOT NULL CHECK(revision>0),
    \\    changed_by TEXT,
    \\    changed_at INTEGER NOT NULL,
    \\    action TEXT NOT NULL,
    \\    PRIMARY KEY(team_id,source_id,reference),
    \\    FOREIGN KEY(team_id,source_id) REFERENCES mail_team_members(team_id,user_id) ON DELETE CASCADE,
    \\    FOREIGN KEY(source_id,reference) REFERENCES mailbox_message_refs(user_id,reference) ON DELETE CASCADE ON UPDATE CASCADE
    \\);
    \\CREATE INDEX IF NOT EXISTS mail_shared_inbox_reference ON mail_shared_inbox_state(source_id,reference);
    \\CREATE INDEX IF NOT EXISTS mail_shared_inbox_assignee ON mail_shared_inbox_state(team_id,source_id,assignee_id);
    \\CREATE TRIGGER IF NOT EXISTS mail_shared_inbox_offboard AFTER DELETE ON mail_team_grants
    \\WHEN OLD.scope='mailbox' AND OLD.resource='' BEGIN
    \\    UPDATE mail_shared_inbox_state
    \\    SET assignee_id=NULL,revision=revision+1,changed_by=NULL,changed_at=unixepoch(),action='access_removed'
    \\    WHERE team_id=OLD.team_id AND source_id=OLD.source_id AND assignee_id=OLD.grantee_id;
    \\END;
    \\CREATE TRIGGER IF NOT EXISTS mail_shared_inbox_replaced_ref BEFORE UPDATE OF reference ON mailbox_message_refs
    \\WHEN OLD.reference<>NEW.reference BEGIN
    \\    DELETE FROM mail_shared_inbox_state WHERE source_id=OLD.user_id AND reference=OLD.reference;
    \\END;
;

const selectInboxes =
    \\SELECT DISTINCT g.team_id,t.name,source.id,source.username,source.email FROM mail_team_grants g
    \\JOIN mail_teams t ON t.id=g.team_id
    \\JOIN users source ON source.id=g.source_id AND source.enabled=1
    \\JOIN users teammate ON teammate.id=g.grantee_id AND teammate.enabled=1
    \\JOIN users viewer ON viewer.id IN (source.id,teammate.id) AND viewer.enabled=1
    \\WHERE viewer.username=?1 AND g.scope='mailbox' AND g.resource=''
;
pub const Inbox = struct { team: []const u8, name: []const u8, id: []const u8, address: []const u8 };
pub const Source = struct { username: []const u8 };
pub const Target = struct { id: []const u8, address: []const u8 };
pub const Action = enum { assign, unassign, resolve, reopen };
pub const Workflow = struct {
    assignee: ?Target = null,
    resolved: bool = false,
    revision: i64 = 0,
    changedBy: ?[]const u8 = null,
    changedAt: ?i64 = null,
    action: ?[]const u8 = null,
};
pub const Change = struct {
    action: Action,
    assignee: ?[]const u8 = null,
    revision: i64,
    messageRevision: []const u8,
};

pub fn positiveId(text: []const u8) ?i64 {
    if (text.len == 0 or text.len > 19 or text[0] == '0') return null;
    for (text) |byte| if (!std.ascii.isDigit(byte)) return null;
    return std.fmt.parseInt(i64, text, 10) catch null;
}

fn bind(stmt: database.Statement, values: anytype) !void {
    inline for (values, 1..) |value, index| try stmt.bind(index, value);
}

pub fn list(a: Allocator, db: *database.Database, actor: []const u8) ![]Inbox {
    const stmt = try db.prepare(selectInboxes ++ " ORDER BY t.name,source.email,g.team_id");
    defer stmt.finalize();
    try stmt.bind(1, actor);
    var rows: std.ArrayList(Inbox) = .empty;
    while (try stmt.step()) try rows.append(a, .{
        .team = try a.dupe(u8, stmt.columnText(0)),
        .name = try a.dupe(u8, stmt.columnText(1)),
        .id = try std.fmt.allocPrint(a, "{d}", .{stmt.columnInt64(2)}),
        .address = try a.dupe(u8, stmt.columnText(4)),
    });
    return rows.toOwnedSlice(a);
}

pub fn available(db: *database.Database, actor: []const u8) !bool {
    const stmt = try db.prepare(selectInboxes ++ " LIMIT 1");
    defer stmt.finalize();
    try stmt.bind(1, actor);
    return stmt.step();
}

const selectSource = selectInboxes ++ " AND g.team_id=?2 AND g.source_id=?3 LIMIT 1";

pub fn source(a: Allocator, db: *database.Database, actor: []const u8, team: []const u8, id: i64) !Source {
    const stmt = try db.prepare(selectSource);
    defer stmt.finalize();
    try bind(stmt, .{ actor, team, id });
    if (!try stmt.step()) return error.SharedInboxNotFound;
    return .{ .username = try a.dupe(u8, stmt.columnText(3)) };
}

pub fn canDownload(db: *database.Database, actor: []const u8, team: []const u8, id: i64, reference: []const u8) !bool {
    const stmt = try db.prepare(selectInboxes ++
        \\ AND g.team_id=?2 AND g.source_id=?3 AND (viewer.id=source.id OR EXISTS(
        \\    SELECT 1 FROM mail_team_grants attachment WHERE attachment.team_id=g.team_id
        \\    AND attachment.source_id=source.id AND attachment.grantee_id=viewer.id
        \\    AND attachment.scope='attachments' AND attachment.resource=?4)) LIMIT 1
    );
    defer stmt.finalize();
    try bind(stmt, .{ actor, team, id, reference });
    return stmt.step();
}

const selectTargets =
    \\SELECT u.id,u.email FROM users u WHERE u.enabled=1 AND (u.id=?2 OR EXISTS(
    \\    SELECT 1 FROM mail_team_grants g WHERE g.team_id=?1 AND g.source_id=?2
    \\    AND g.grantee_id=u.id AND g.scope='mailbox' AND g.resource=''))
;

pub fn targets(a: Allocator, db: *database.Database, team: []const u8, id: i64) ![]Target {
    const stmt = try db.prepare(selectTargets ++ " ORDER BY u.email");
    defer stmt.finalize();
    try bind(stmt, .{ team, id });
    var rows: std.ArrayList(Target) = .empty;
    while (try stmt.step()) try rows.append(a, .{
        .id = try std.fmt.allocPrint(a, "{d}", .{stmt.columnInt64(0)}),
        .address = try a.dupe(u8, stmt.columnText(1)),
    });
    return rows.toOwnedSlice(a);
}

const selectWorkflow =
    \\SELECT s.resolved,s.revision,s.changed_by,s.changed_at,s.action,u.id,u.email
    \\FROM mail_shared_inbox_state s LEFT JOIN users u ON u.id=s.assignee_id
    \\WHERE s.team_id=?1 AND s.source_id=?2 AND s.reference=?3
;

fn readWorkflow(a: Allocator, stmt: database.Statement, team: []const u8, id: i64, ref: []const u8) !Workflow {
    try bind(stmt, .{ team, id, ref });
    if (!try stmt.step()) return .{};
    return .{
        .resolved = stmt.columnInt64(0) != 0,
        .revision = stmt.columnInt64(1),
        .changedBy = if (stmt.columnTextOpt(2)) |by| try a.dupe(u8, by) else null,
        .changedAt = stmt.columnInt64(3),
        .action = try a.dupe(u8, stmt.columnText(4)),
        .assignee = if (stmt.columnIsNull(5)) null else .{
            .id = try std.fmt.allocPrint(a, "{d}", .{stmt.columnInt64(5)}),
            .address = try a.dupe(u8, stmt.columnText(6)),
        },
    };
}

pub fn workflow(a: Allocator, db: *database.Database, team: []const u8, id: i64, ref: []const u8) !Workflow {
    const stmt = try db.prepare(selectWorkflow);
    defer stmt.finalize();
    return readWorkflow(a, stmt, team, id, ref);
}

/// Called with the mailbox lock after the handler checked the current Inbox
/// file revision. Recheck the grant inside the transaction that writes state.
pub fn change(a: Allocator, db: *database.Database, actor: []const u8, team: []const u8, id: i64, ref: []const u8, patch: Change) !Workflow {
    if (patch.revision < 0 or (patch.action == .assign) != (patch.assignee != null)) return error.InvalidSharedChange;
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    {
        const stmt = try tx.prepare(selectSource);
        defer stmt.finalize();
        try bind(stmt, .{ actor, team, id });
        if (!try stmt.step()) return error.SharedInboxNotFound;
    }
    const current = blk: {
        const stmt = try tx.prepare(selectWorkflow);
        defer stmt.finalize();
        break :blk try readWorkflow(a, stmt, team, id, ref);
    };
    if (current.revision != patch.revision) return error.SharedInboxConflict;
    const selected: ?Target = if (patch.assignee) |value| blk: {
        const assignee = positiveId(value) orelse return error.InvalidSharedChange;
        const stmt = try tx.prepare(selectTargets ++ " AND u.id=?3");
        defer stmt.finalize();
        try bind(stmt, .{ team, id, assignee });
        if (!try stmt.step()) return error.AssigneeUnavailable;
        break :blk .{ .id = value, .address = try a.dupe(u8, stmt.columnText(1)) };
    } else if (patch.action == .unassign) null else current.assignee;
    const resolved = switch (patch.action) {
        .assign, .unassign => current.resolved,
        .resolve => true,
        .reopen => false,
    };
    if (current.resolved == resolved and std.mem.eql(u8, if (selected) |item| item.id else "", if (current.assignee) |item| item.id else ""))
        return current;
    const at = time.timestamp();
    const event = @tagName(patch.action);
    {
        const stmt = try tx.prepare(
            \\INSERT INTO mail_shared_inbox_state(team_id,source_id,reference,assignee_id,resolved,revision,changed_by,changed_at,action)
            \\VALUES(?1,?2,?3,NULLIF(?4,0),?5,?6,?7,?8,?9)
            \\ON CONFLICT(team_id,source_id,reference) DO UPDATE SET assignee_id=excluded.assignee_id,
            \\resolved=excluded.resolved,revision=excluded.revision,changed_by=excluded.changed_by,
            \\changed_at=excluded.changed_at,action=excluded.action
        );
        defer stmt.finalize();
        try bind(stmt, .{ team, id, ref, if (selected) |item| positiveId(item.id).? else @as(i64, 0), @as(i64, @intFromBool(resolved)), current.revision + 1, actor, at, event });
        _ = try stmt.step();
    }
    {
        const stmt = try tx.prepare(
            \\INSERT INTO audit_log(timestamp,action,actor,target,target_type,details,severity)
            \\VALUES(?1,?2,?3,?4,'team_inbox_message',?5,'info')
        );
        defer stmt.finalize();
        const target = try std.fmt.allocPrint(a, "{s}/{d}/{s}", .{ team, id, ref });
        const details = try std.json.Stringify.valueAlloc(a, .{ .before = current.assignee, .after = selected, .resolved = resolved }, .{});
        const audit_action = try std.fmt.allocPrint(a, "team.inbox.{s}", .{event});
        try bind(stmt, .{ at, audit_action, actor, target, details });
        _ = try stmt.step();
    }
    try tx.commit();
    return .{ .assignee = selected, .resolved = resolved, .revision = current.revision + 1, .changedBy = actor, .changedAt = at, .action = event };
}
