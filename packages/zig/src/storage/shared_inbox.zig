//! A team workflow belongs to the shared mailbox and stable message reference.
//! Mailbox grants confer access to Inbox without impersonating the source user.
const std = @import("std");
const database = @import("database.zig");
const time = @import("../core/time_compat.zig");
const addresses = @import("../message/submission.zig");
const Allocator = std.mem.Allocator;
const Tx = database.Database.Transaction;

pub const schema =
    \\CREATE TABLE IF NOT EXISTS mail_shared_inbox_stages (
    \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    team_id TEXT NOT NULL,
    \\    source_id INTEGER NOT NULL,
    \\    name TEXT NOT NULL COLLATE NOCASE,
    \\    sender TEXT COLLATE NOCASE,
    \\    revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),
    \\    retired_at INTEGER,
    \\    FOREIGN KEY(team_id,source_id) REFERENCES mail_team_members(team_id,user_id) ON DELETE CASCADE
    \\);
    \\CREATE UNIQUE INDEX IF NOT EXISTS mail_shared_inbox_stage_name
    \\ON mail_shared_inbox_stages(team_id,source_id,name) WHERE retired_at IS NULL;
    \\CREATE UNIQUE INDEX IF NOT EXISTS mail_shared_inbox_stage_sender
    \\ON mail_shared_inbox_stages(source_id,team_id,sender) WHERE retired_at IS NULL AND sender IS NOT NULL;
    \\CREATE TABLE IF NOT EXISTS mail_shared_inbox_state (
    \\    team_id TEXT NOT NULL,
    \\    source_id INTEGER NOT NULL,
    \\    reference TEXT NOT NULL,
    \\    assignee_id INTEGER,
    \\    stage_id INTEGER REFERENCES mail_shared_inbox_stages(id) ON DELETE SET NULL,
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
    \\CREATE TABLE IF NOT EXISTS mail_shared_reply_claims (
    \\    source_id INTEGER NOT NULL,
    \\    reference TEXT NOT NULL,
    \\    team_id TEXT NOT NULL,
    \\    actor_id INTEGER NOT NULL,
    \\    actor TEXT NOT NULL,
    \\    send_id TEXT NOT NULL,
    \\    state TEXT NOT NULL CHECK(state IN ('queued','sending','review','replied')),
    \\    due_at INTEGER NOT NULL,
    \\    PRIMARY KEY(source_id,reference),
    \\    UNIQUE(actor_id,send_id),
    \\    FOREIGN KEY(source_id,reference) REFERENCES mailbox_message_refs(user_id,reference) ON DELETE CASCADE ON UPDATE CASCADE
    \\);
    \\CREATE TRIGGER IF NOT EXISTS mail_shared_reply_account_deleted BEFORE DELETE ON users BEGIN
    \\    DELETE FROM mail_shared_reply_claims WHERE actor_id=OLD.id AND state='queued';
    \\    UPDATE mail_shared_reply_claims SET state='review' WHERE actor_id=OLD.id AND state='sending';
    \\END;
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
    \\CREATE TRIGGER IF NOT EXISTS mail_shared_reply_replaced_ref BEFORE UPDATE OF reference ON mailbox_message_refs
    \\WHEN OLD.reference<>NEW.reference BEGIN
    \\    DELETE FROM mail_shared_reply_claims WHERE source_id=OLD.user_id AND reference=OLD.reference;
    \\END;
;

const selectInboxes =
    \\SELECT DISTINCT g.team_id,t.name,source.id,source.username,source.email,m.role IN ('owner','admin') FROM mail_team_grants g
    \\JOIN mail_teams t ON t.id=g.team_id
    \\JOIN users source ON source.id=g.source_id AND source.enabled=1
    \\JOIN users teammate ON teammate.id=g.grantee_id AND teammate.enabled=1
    \\JOIN users viewer ON viewer.id IN (source.id,teammate.id) AND viewer.enabled=1
    \\JOIN mail_team_members m ON m.team_id=g.team_id AND m.user_id=viewer.id
    \\WHERE viewer.username=?1 AND g.scope='mailbox' AND g.resource=''
;
pub const Inbox = struct { team: []const u8, name: []const u8, id: []const u8, address: []const u8 };
pub const Source = struct { username: []const u8, address: []const u8, can_manage: bool };
pub const Target = struct { id: []const u8, address: []const u8 };
pub const StageLabel = struct { id: []const u8, name: []const u8 };
pub const Stage = struct { id: []const u8, name: []const u8, sender: ?[]const u8, revision: i64 };
pub const StageChange = struct {
    action: enum { create, update, retire },
    id: ?[]const u8 = null,
    revision: ?i64 = null,
    name: ?[]const u8 = null,
    sender: ?[]const u8 = null,
};
pub const Action = enum { assign, unassign, resolve, reopen, move };
pub const Workflow = struct {
    assignee: ?Target = null,
    stage: ?StageLabel = null,
    resolved: bool = false,
    revision: i64 = 0,
    changedBy: ?[]const u8 = null,
    changedAt: ?i64 = null,
    action: ?[]const u8 = null,
};
pub const Change = struct {
    action: Action,
    assignee: ?[]const u8 = null,
    stageId: ?[]const u8 = null,
    revision: i64,
    messageRevision: []const u8,
};

pub const ReplyContext = struct {
    team: []const u8,
    sourceId: []const u8,
    reference: []const u8,
    messageRevision: []const u8,
};
pub const ReplyDelivery = struct { context: ReplyContext, send_id: []const u8 };
pub const ReplyStatus = struct {
    state: enum { queued, sending, review, replied },
    actor: ?[]const u8,
    dueAt: ?i64,
};

const replyScope = selectInboxes ++
    \\ AND g.team_id=?2 AND g.source_id=?3 AND (viewer.id=source.id OR EXISTS(
    \\   SELECT 1 FROM mail_team_grants sg WHERE sg.team_id=g.team_id AND sg.source_id=source.id
    \\   AND sg.grantee_id=viewer.id AND sg.scope='sender' AND sg.resource=''))
    \\ AND EXISTS(SELECT 1 FROM mailbox_message_refs m WHERE m.user_id=source.id
    \\   AND m.reference=?4 AND m.folder='INBOX' AND m.next_folder IS NULL)
    \\ AND NOT EXISTS(SELECT 1 FROM mail_shared_inbox_state w WHERE w.team_id=g.team_id
    \\   AND w.source_id=source.id AND w.reference=?4
    \\   AND (w.resolved=1 OR (w.assignee_id IS NOT NULL AND w.assignee_id<>viewer.id)))
;

fn bindContext(stmt: database.Statement, actor: []const u8, ctx: ReplyContext) !void {
    try bind(stmt, .{ actor, ctx.team, positiveId(ctx.sourceId) orelse return error.SharedReplyUnavailable, ctx.reference });
}

pub fn sameReply(left: ?ReplyContext, right: ?ReplyContext) bool {
    const a = left orelse return right == null;
    const b = right orelse return false;
    return std.mem.eql(u8, a.team, b.team) and std.mem.eql(u8, a.sourceId, b.sourceId) and
        std.mem.eql(u8, a.reference, b.reference) and std.mem.eql(u8, a.messageRevision, b.messageRevision);
}

pub fn canReply(db: *database.Database, actor: []const u8, ctx: ReplyContext) !bool {
    const stmt = try db.prepare(replyScope ++ " LIMIT 1");
    defer stmt.finalize();
    try bindContext(stmt, actor, ctx);
    return stmt.step();
}

pub fn replyStatus(a: Allocator, db: *database.Database, team: []const u8, id: i64, ref: []const u8) !?ReplyStatus {
    const stmt = try db.prepare("SELECT state,actor,due_at,team_id FROM mail_shared_reply_claims WHERE source_id=?1 AND reference=?2");
    defer stmt.finalize();
    try bind(stmt, .{ id, ref });
    if (!try stmt.step()) return null;
    const same_team = std.mem.eql(u8, team, stmt.columnText(3));
    const result: ReplyStatus = .{
        .state = std.meta.stringToEnum(@FieldType(ReplyStatus, "state"), stmt.columnText(0)) orelse return error.InvalidSharedChange,
        .actor = if (same_team) try a.dupe(u8, stmt.columnText(1)) else null,
        .dueAt = if (same_team) stmt.columnInt64(2) else null,
    };
    return result;
}

/// The caller commits the reservation and the draft freeze together.
pub fn reserveReply(tx: Tx, actor: []const u8, ctx: ReplyContext, send_id: []const u8, due_at: i64) !void {
    {
        const permission = try tx.prepare(replyScope ++ " LIMIT 1");
        defer permission.finalize();
        try bindContext(permission, actor, ctx);
        if (!try permission.step()) return error.SharedReplyUnavailable;
    }
    const stmt = try tx.prepare(
        \\INSERT INTO mail_shared_reply_claims(source_id,reference,team_id,actor_id,actor,send_id,state,due_at)
        \\VALUES(?1,?2,?3,(SELECT id FROM users WHERE username=?4),?4,?5,'queued',?6)
        \\ON CONFLICT(source_id,reference) DO NOTHING RETURNING 1
    );
    defer stmt.finalize();
    try bind(stmt, .{ positiveId(ctx.sourceId).?, ctx.reference, ctx.team, actor, send_id, due_at });
    if (!try stmt.step()) return error.SharedReplyConflict;
    _ = try stmt.step();
}

/// Runs within the delivery admission transaction, before debit or publication.
pub fn requireReplyAdmission(tx: Tx, actor: []const u8, address: []const u8, reply: ReplyDelivery) !void {
    const stmt = try tx.prepare(replyScope ++
        \\ AND source.email=?5 AND EXISTS(SELECT 1 FROM mail_shared_reply_claims r
        \\   WHERE r.source_id=source.id AND r.reference=?4 AND r.team_id=g.team_id
        \\   AND r.actor_id=viewer.id AND r.send_id=?6 AND r.state='sending') LIMIT 1
    );
    defer stmt.finalize();
    try bindContext(stmt, actor, reply.context);
    try stmt.bind(5, address);
    try stmt.bind(6, reply.send_id);
    if (!try stmt.step()) return error.SharedReplyUnavailable;
}

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
    return .{ .username = try a.dupe(u8, stmt.columnText(3)), .address = try a.dupe(u8, stmt.columnText(4)), .can_manage = stmt.columnInt64(5) != 0 };
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

const selectStages =
    \\SELECT id,name,sender,revision FROM mail_shared_inbox_stages
    \\WHERE team_id=?1 AND source_id=?2 AND retired_at IS NULL
;

fn readStage(a: Allocator, stmt: database.Statement, include_sender: bool) !Stage {
    return .{
        .id = try std.fmt.allocPrint(a, "{d}", .{stmt.columnInt64(0)}),
        .name = try a.dupe(u8, stmt.columnText(1)),
        .sender = if (include_sender and !stmt.columnIsNull(2)) try a.dupe(u8, stmt.columnText(2)) else null,
        .revision = stmt.columnInt64(3),
    };
}

pub fn stages(a: Allocator, db: *database.Database, team: []const u8, id: i64, include_sender: bool) ![]Stage {
    const stmt = try db.prepare(selectStages ++ " ORDER BY id");
    defer stmt.finalize();
    try bind(stmt, .{ team, id });
    var rows: std.ArrayList(Stage) = .empty;
    while (try stmt.step()) try rows.append(a, try readStage(a, stmt, include_sender));
    return rows.toOwnedSlice(a);
}

fn findStage(a: Allocator, tx: Tx, team: []const u8, id: i64, key: i64) !Stage {
    const stmt = try tx.prepare(selectStages ++ " AND id=?3");
    defer stmt.finalize();
    try bind(stmt, .{ team, id, key });
    if (!try stmt.step()) return error.StageUnavailable;
    return readStage(a, stmt, true);
}

fn validStageName(name: []const u8) bool {
    if (name.len == 0 or name.len > 96 or !std.unicode.utf8ValidateSlice(name)) return false;
    for (name) |byte| if (byte < 32 or byte == 127) return false;
    return true;
}

pub fn changeStage(a: Allocator, db: *database.Database, actor: []const u8, team: []const u8, id: i64, patch: StageChange) !void {
    const creating = patch.action == .create;
    const retiring = patch.action == .retire;
    if (creating != (patch.id == null and patch.revision == null) or retiring != (patch.name == null))
        return error.InvalidSharedChange;
    const name = std.mem.trim(u8, patch.name orelse "", " ");
    if (!retiring and !validStageName(name)) return error.InvalidSharedChange;
    if (patch.sender) |sender| {
        if (retiring or sender.len > 254 or !addresses.validMailbox(sender)) return error.InvalidSharedChange;
    }
    const key = if (creating) 0 else positiveId(patch.id orelse return error.InvalidSharedChange) orelse return error.InvalidSharedChange;
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    {
        const stmt = try tx.prepare(selectSource);
        defer stmt.finalize();
        try bind(stmt, .{ actor, team, id });
        if (!try stmt.step()) return error.SharedInboxNotFound;
        if (stmt.columnInt64(5) == 0) return error.StageAdminRequired;
    }
    const previous = if (creating) null else try findStage(a, tx, team, id, key);
    if (previous) |current| if (patch.revision != current.revision) return error.StageConfigConflict;
    if (!retiring) {
        const duplicate = try tx.prepare(selectStages ++ " AND id<>?3 AND (name=?4 OR sender=?5)");
        defer duplicate.finalize();
        try bind(duplicate, .{ team, id, key, name });
        try duplicate.bindOpt(5, patch.sender);
        if (try duplicate.step()) return error.StageNameOrSenderConflict;
    }
    const changed = blk: {
        const stmt = try tx.prepare(switch (patch.action) {
            .create => "INSERT INTO mail_shared_inbox_stages(team_id,source_id,name,sender) VALUES(?1,?2,?4,?5) RETURNING id,name,sender,revision",
            .update => "UPDATE mail_shared_inbox_stages SET name=?4,sender=?5,revision=revision+1 WHERE team_id=?1 AND source_id=?2 AND id=?3 RETURNING id,name,sender,revision",
            .retire => "UPDATE mail_shared_inbox_stages SET retired_at=unixepoch(),revision=revision+1 WHERE team_id=?1 AND source_id=?2 AND id=?3 RETURNING id,name,sender,revision",
        });
        defer stmt.finalize();
        try bind(stmt, .{ team, id });
        if (!creating) try stmt.bind(3, key);
        if (!retiring) {
            try stmt.bind(4, name);
            try stmt.bindOpt(5, patch.sender);
        }
        if (!try stmt.step()) return error.StageUnavailable;
        const row = try readStage(a, stmt, true);
        _ = try stmt.step();
        break :blk row;
    };
    if (retiring) {
        const stmt = try tx.prepare(
            \\UPDATE mail_shared_inbox_state SET stage_id=NULL,revision=revision+1,changed_by=?4,changed_at=unixepoch(),action='stage_retired'
            \\WHERE team_id=?1 AND source_id=?2 AND stage_id=?3
        );
        defer stmt.finalize();
        try bind(stmt, .{ team, id, key, actor });
        _ = try stmt.step();
    }
    const target = try std.fmt.allocPrint(a, "{s}/{d}/{s}", .{ team, id, changed.id });
    const event = try std.fmt.allocPrint(a, "team.inbox.stage.{s}", .{@tagName(patch.action)});
    const details = try std.json.Stringify.valueAlloc(a, .{ .before = previous, .after = if (retiring) null else changed }, .{});
    try audit(tx, event, actor, target, "team_inbox_stage", details);
    try tx.commit();
}

fn audit(tx: Tx, event: []const u8, actor: []const u8, target: []const u8, kind: []const u8, details: []const u8) !void {
    const stmt = try tx.prepare(
        \\INSERT INTO audit_log(timestamp,action,actor,target,target_type,details,severity)
        \\VALUES(unixepoch(),?1,?2,?3,?4,?5,'info')
    );
    defer stmt.finalize();
    try bind(stmt, .{ event, actor, target, kind, details });
    _ = try stmt.step();
}

/// Apply stage rules while checkpointing accepted local delivery. Match the
/// verified author of direct mail to the shared address and keep the message
/// in Inbox so the team and normal mail clients see the same copy.
pub const route_delivery_sql =
    \\INSERT INTO mail_shared_inbox_state(team_id,source_id,reference,stage_id,revision,changed_at,action)
    \\SELECT s.team_id,t.mailbox_id,r.reference,s.id,1,unixepoch(),'route'
    \\FROM accepted_mail_targets t JOIN accepted_mail m ON m.id=t.delivery_id
    \\JOIN mailbox_message_refs r ON r.user_id=t.mailbox_id AND r.folder='INBOX' AND r.basename=?3 AND r.file_stamp=?4
    \\JOIN mail_shared_inbox_stages s ON s.source_id=t.mailbox_id AND s.retired_at IS NULL AND s.sender=m.author
    \\WHERE t.delivery_id=?1 AND t.ordinal=?2 AND t.is_primary=1 AND t.folder='new'
    \\  AND t.recipient=t.mailbox COLLATE NOCASE AND m.verified_author=1 AND m.envelope_from=m.author COLLATE NOCASE
    \\  AND EXISTS(SELECT 1 FROM mail_team_grants g JOIN users teammate ON teammate.id=g.grantee_id AND teammate.enabled=1
    \\    WHERE g.team_id=s.team_id AND g.source_id=s.source_id AND g.scope='mailbox' AND g.resource='')
    \\ON CONFLICT(team_id,source_id,reference) DO NOTHING
    \\RETURNING team_id,source_id,reference,stage_id
;

pub const audit_route_sql =
    \\INSERT INTO audit_log(timestamp,action,actor,target,target_type,details,severity)
    \\VALUES(unixepoch(),'team.inbox.route','delivery',?1||'/'||?2||'/'||?3,'team_inbox_message',json_object('stageId',?4),'info')
;

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
    \\SELECT s.resolved,s.revision,s.changed_by,s.changed_at,s.action,u.id,u.email,st.id,st.name
    \\FROM mail_shared_inbox_state s LEFT JOIN users u ON u.id=s.assignee_id
    \\LEFT JOIN mail_shared_inbox_stages st ON st.id=s.stage_id AND st.retired_at IS NULL
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
        .stage = if (stmt.columnIsNull(7)) null else .{
            .id = try std.fmt.allocPrint(a, "{d}", .{stmt.columnInt64(7)}),
            .name = try a.dupe(u8, stmt.columnText(8)),
        },
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
    if (patch.revision < 0 or (patch.action == .assign) != (patch.assignee != null) or
        (patch.action != .move and patch.stageId != null)) return error.InvalidSharedChange;
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
    const stage: ?StageLabel = if (patch.action != .move) current.stage else if (patch.stageId) |value| blk: {
        const item = try findStage(a, tx, team, id, positiveId(value) orelse return error.InvalidSharedChange);
        break :blk .{ .id = item.id, .name = item.name };
    } else null;
    const resolved = switch (patch.action) {
        .assign, .unassign, .move => current.resolved,
        .resolve => true,
        .reopen => false,
    };
    if (current.resolved == resolved and
        std.mem.eql(u8, if (selected) |item| item.id else "", if (current.assignee) |item| item.id else "") and
        std.mem.eql(u8, if (stage) |item| item.id else "", if (current.stage) |item| item.id else ""))
        return current;
    const at = time.timestamp();
    const event = @tagName(patch.action);
    {
        const stmt = try tx.prepare(
            \\INSERT INTO mail_shared_inbox_state(team_id,source_id,reference,assignee_id,resolved,revision,changed_by,changed_at,action,stage_id)
            \\VALUES(?1,?2,?3,NULLIF(?4,0),?5,?6,?7,?8,?9,NULLIF(?10,0))
            \\ON CONFLICT(team_id,source_id,reference) DO UPDATE SET assignee_id=excluded.assignee_id,
            \\resolved=excluded.resolved,revision=excluded.revision,changed_by=excluded.changed_by,
            \\changed_at=excluded.changed_at,action=excluded.action,stage_id=excluded.stage_id
        );
        defer stmt.finalize();
        try bind(stmt, .{ team, id, ref, if (selected) |item| positiveId(item.id).? else @as(i64, 0), @as(i64, @intFromBool(resolved)), current.revision + 1, actor, at, event });
        try stmt.bind(10, if (stage) |item| positiveId(item.id).? else @as(i64, 0));
        _ = try stmt.step();
    }
    {
        const target = try std.fmt.allocPrint(a, "{s}/{d}/{s}", .{ team, id, ref });
        const details = try std.json.Stringify.valueAlloc(a, .{
            .before = current.assignee,
            .after = selected,
            .resolved = resolved,
            .beforeStage = current.stage,
            .afterStage = stage,
        }, .{});
        const audit_action = try std.fmt.allocPrint(a, "team.inbox.{s}", .{event});
        try audit(tx, audit_action, actor, target, "team_inbox_message", details);
    }
    try tx.commit();
    return .{ .assignee = selected, .stage = stage, .resolved = resolved, .revision = current.revision + 1, .changedBy = actor, .changedAt = at, .action = event };
}
