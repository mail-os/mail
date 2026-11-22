//! Team authorization keyed by stable user IDs. The SMTP database owns grants
//! and membership so a domain rename preserves access and account reuse does not.
const std = @import("std");
const database = @import("database.zig");
const Tx = database.Database.Transaction;
const Allocator = std.mem.Allocator;

pub const schema =
    \\CREATE TABLE IF NOT EXISTS mail_teams (
    \\    id TEXT PRIMARY KEY NOT NULL,
    \\    name TEXT NOT NULL
    \\);
    \\CREATE TABLE IF NOT EXISTS mail_team_members (
    \\    team_id TEXT NOT NULL REFERENCES mail_teams(id) ON DELETE CASCADE,
    \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    \\    role TEXT NOT NULL CHECK(role IN ('owner','admin','member')),
    \\    PRIMARY KEY(team_id,user_id)
    \\);
    \\CREATE INDEX IF NOT EXISTS mail_team_members_user ON mail_team_members(user_id);
    \\CREATE TABLE IF NOT EXISTS mail_team_grants (
    \\    team_id TEXT NOT NULL,
    \\    source_id INTEGER NOT NULL,
    \\    grantee_id INTEGER NOT NULL,
    \\    scope TEXT NOT NULL CHECK(scope IN ('mailbox','sender','calendar','search','attachments','comments')),
    \\    resource TEXT NOT NULL,
    \\    CHECK(source_id <> grantee_id),
    \\    PRIMARY KEY(team_id,source_id,grantee_id,scope,resource),
    \\    FOREIGN KEY(team_id,source_id) REFERENCES mail_team_members(team_id,user_id) ON DELETE CASCADE,
    \\    FOREIGN KEY(team_id,grantee_id) REFERENCES mail_team_members(team_id,user_id) ON DELETE CASCADE
    \\);
    \\CREATE INDEX IF NOT EXISTS mail_team_grants_grantee ON mail_team_grants(team_id,grantee_id);
    \\CREATE TABLE IF NOT EXISTS mail_team_calendar_shares (
    \\    team_id TEXT NOT NULL,
    \\    source_id INTEGER NOT NULL,
    \\    grantee_id INTEGER NOT NULL,
    \\    calendar_share_id TEXT NOT NULL CHECK(length(calendar_share_id)=32),
    \\    access TEXT NOT NULL CHECK(access IN ('free_busy','viewer','editor')),
    \\    CHECK(source_id <> grantee_id),
    \\    PRIMARY KEY(team_id,source_id,grantee_id,calendar_share_id),
    \\    FOREIGN KEY(team_id,source_id) REFERENCES mail_team_members(team_id,user_id) ON DELETE CASCADE,
    \\    FOREIGN KEY(team_id,grantee_id) REFERENCES mail_team_members(team_id,user_id) ON DELETE CASCADE
    \\);
    \\CREATE INDEX IF NOT EXISTS mail_team_calendar_grantee ON mail_team_calendar_shares(grantee_id);
    \\CREATE INDEX IF NOT EXISTS mail_team_calendar_source ON mail_team_calendar_shares(source_id);
    \\CREATE TABLE IF NOT EXISTS mail_team_calendar_share_epochs (
    \\    team_id TEXT NOT NULL,
    \\    source_id INTEGER NOT NULL,
    \\    grantee_id INTEGER NOT NULL,
    \\    calendar_share_id TEXT NOT NULL,
    \\    epoch TEXT NOT NULL CHECK(length(epoch)=32),
    \\    PRIMARY KEY(team_id,source_id,grantee_id,calendar_share_id),
    \\    FOREIGN KEY(team_id,source_id,grantee_id,calendar_share_id)
    \\        REFERENCES mail_team_calendar_shares(team_id,source_id,grantee_id,calendar_share_id) ON DELETE CASCADE
    \\);
    \\CREATE INDEX IF NOT EXISTS mail_calendar_share_epochs_lookup
    \\ON mail_team_calendar_share_epochs(grantee_id,source_id,calendar_share_id,team_id);
    \\CREATE TRIGGER IF NOT EXISTS mail_calendar_grant_epoch_insert AFTER INSERT ON mail_team_calendar_shares
    \\BEGIN
    \\    INSERT INTO mail_team_calendar_share_epochs VALUES(NEW.team_id,NEW.source_id,NEW.grantee_id,NEW.calendar_share_id,lower(hex(randomblob(16))));
    \\END;
    \\CREATE TRIGGER IF NOT EXISTS mail_calendar_grant_epoch_update AFTER UPDATE OF access ON mail_team_calendar_shares
    \\WHEN NEW.access<>OLD.access
    \\BEGIN
    \\    UPDATE mail_team_calendar_share_epochs SET epoch=lower(hex(randomblob(16)))
    \\    WHERE team_id=NEW.team_id AND source_id=NEW.source_id AND grantee_id=NEW.grantee_id AND calendar_share_id=NEW.calendar_share_id;
    \\END;
    \\INSERT OR IGNORE INTO mail_team_calendar_share_epochs
    \\SELECT team_id,source_id,grantee_id,calendar_share_id,lower(hex(randomblob(16))) FROM mail_team_calendar_shares;
    \\CREATE TRIGGER IF NOT EXISTS mail_team_keep_owner_delete BEFORE DELETE ON mail_team_members
    \\WHEN OLD.role='owner' AND EXISTS(SELECT 1 FROM mail_teams WHERE id=OLD.team_id)
    \\AND NOT EXISTS(SELECT 1 FROM mail_team_members WHERE team_id=OLD.team_id AND user_id<>OLD.user_id AND role='owner')
    \\BEGIN SELECT RAISE(ABORT,'team requires an owner'); END;
    \\CREATE TRIGGER IF NOT EXISTS mail_team_keep_owner_update BEFORE UPDATE OF role ON mail_team_members
    \\WHEN OLD.role='owner' AND NEW.role<>'owner'
    \\AND NOT EXISTS(SELECT 1 FROM mail_team_members WHERE team_id=OLD.team_id AND user_id<>OLD.user_id AND role='owner')
    \\BEGIN SELECT RAISE(ABORT,'team requires an owner'); END;
;

pub const Role = enum { owner, admin, member };
pub const Scope = enum { mailbox, sender, calendar, search, attachments, comments };
pub const Actor = union(enum) { mailbox: []const u8, operator: []const u8 };
pub const Team = struct { id: []const u8, name: []const u8, role: ?Role = null };
pub const Member = struct { mailbox: []const u8, role: Role, enabled: bool };
pub const Grant = struct { source: []const u8, grantee: []const u8, scope: Scope, resource: []const u8 = "" };
pub const CalendarAccess = enum { free_busy, viewer, editor };
pub const CalendarShareId = [32]u8;
pub const CalendarShare = struct {
    team: []const u8,
    source_id: i64,
    source: []const u8,
    grantee: []const u8,
    calendar_share_id: CalendarShareId,
    access: CalendarAccess,
};
pub const SenderIdentity = struct { id: []const u8, address: []const u8 };
pub const senderIdentityQuery =
    \\SELECT DISTINCT source.id, source.email FROM mail_team_grants g
    \\JOIN users actor ON actor.id=g.grantee_id
    \\JOIN users source ON source.id=g.source_id
    \\WHERE actor.username=?1 AND actor.enabled=1 AND source.enabled=1
    \\AND g.scope='sender' AND g.resource=''
;
pub const Details = struct { team: Team, members: []Member, grants: []Grant };
const Identity = struct { id: i64, enabled: bool };

pub fn validTeamId(id: []const u8) bool {
    if (id.len == 0 or id.len > 64 or id[0] == '-' or id[id.len - 1] == '-') return false;
    for (id) |byte| {
        if (!(std.ascii.isLower(byte) or std.ascii.isDigit(byte) or byte == '-')) return false;
    }
    return true;
}

fn validText(value: []const u8, max: usize) bool {
    if (value.len > max or !std.unicode.utf8ValidateSlice(value)) return false;
    for (value) |byte| {
        if (byte < 32 or byte == 127) return false;
    }
    return true;
}

fn bind(stmt: database.Statement, values: anytype) !void {
    inline for (values, 1..) |value, index| try stmt.bind(index, value);
}

fn execute(tx: Tx, sql: []const u8, values: anytype) !void {
    const stmt = try tx.prepare(sql);
    defer stmt.finalize();
    try bind(stmt, values);
    _ = try stmt.step();
}

fn identity(tx: Tx, mailbox: []const u8) !?Identity {
    const stmt = try tx.prepare("SELECT id,enabled FROM users WHERE username=?1");
    defer stmt.finalize();
    try stmt.bind(1, mailbox);
    if (!try stmt.step()) return null;
    return .{ .id = stmt.columnInt64(0), .enabled = stmt.columnInt64(1) != 0 };
}

pub fn activeMailboxId(tx: Tx, mailbox: []const u8) !?i64 {
    const user = (try identity(tx, mailbox)) orelse return null;
    return if (user.enabled) user.id else null;
}

fn memberRole(tx: Tx, team: []const u8, id: i64) !?Role {
    const stmt = try tx.prepare("SELECT role FROM mail_team_members WHERE team_id=?1 AND user_id=?2");
    defer stmt.finalize();
    try bind(stmt, .{ team, id });
    if (!try stmt.step()) return null;
    return std.meta.stringToEnum(Role, stmt.columnText(0)) orelse error.InvalidTeamData;
}

const Access = struct { id: i64, role: Role };

fn access(tx: Tx, team: []const u8, actor: Actor) !Access {
    switch (actor) {
        .operator => {
            const stmt = try tx.prepare("SELECT 1 FROM mail_teams WHERE id=?1");
            defer stmt.finalize();
            try stmt.bind(1, team);
            if (!try stmt.step()) return error.TeamNotFound;
            return .{ .id = 0, .role = .owner };
        },
        .mailbox => |mailbox| {
            const principal = (try identity(tx, mailbox)) orelse return error.TeamNotFound;
            if (!principal.enabled) return error.TeamNotFound;
            return .{ .id = principal.id, .role = (try memberRole(tx, team, principal.id)) orelse return error.TeamNotFound };
        },
    }
}

fn audit(tx: Tx, a: Allocator, actor: Actor, team: []const u8, action: []const u8, context: anytype) !void {
    const actor_id = switch (actor) {
        .mailbox => |s| s,
        .operator => |s| s,
    };
    const payload = try std.json.Stringify.valueAlloc(a, context, .{});
    defer a.free(payload);
    try execute(
        tx,
        "INSERT INTO audit_log(timestamp,action,actor,target,target_type,details,severity) VALUES(unixepoch(),?1,?2,?3,'team',?4,'info')",
        .{ action, actor_id, team, payload },
    );
}

pub fn create(db: *database.Database, a: Allocator, operator: []const u8, team: []const u8, name: []const u8, owner: []const u8) !void {
    if (!validTeamId(team) or !validText(name, 100) or std.mem.trim(u8, name, " ").len == 0) return error.InvalidTeamData;
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const member = (try identity(tx, owner)) orelse return error.TeamMemberNotFound;
    if (!member.enabled) return error.DisabledTeamAccount;
    const actor: Actor = .{ .operator = operator };
    if (access(tx, team, actor)) |_| return error.TeamAlreadyExists else |err| {
        if (err != error.TeamNotFound) return err;
    }
    try execute(tx, "INSERT INTO mail_teams(id,name) VALUES(?1,?2)", .{ team, name });
    try execute(tx, "INSERT INTO mail_team_members(team_id,user_id,role) VALUES(?1,?2,'owner')", .{ team, member.id });
    try audit(tx, a, actor, team, "team.create", .{ .name = name, .owner = owner });
    try tx.commit();
}

fn requireOtherOwner(tx: Tx, team: []const u8, user_id: i64) !void {
    const stmt = try tx.prepare("SELECT 1 FROM mail_team_members WHERE team_id=?1 AND user_id<>?2 AND role='owner' LIMIT 1");
    defer stmt.finalize();
    try bind(stmt, .{ team, user_id });
    if (!try stmt.step()) return error.LastTeamOwner;
}

pub fn setMember(db: *database.Database, a: Allocator, actor: Actor, team: []const u8, mailbox: []const u8, next: ?Role) !void {
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const admin = try access(tx, team, actor);
    if (admin.role == .member) return error.TeamForbidden;
    const subject = (try identity(tx, mailbox)) orelse return error.TeamMemberNotFound;
    const previous = try memberRole(tx, team, subject.id);
    if (actor == .mailbox and previous == null) return error.TeamMemberNotFound;
    if (admin.role == .admin and ((previous != null and previous != .member) or (next != null and next != .member)))
        return error.TeamForbidden;
    if (previous == next) return;
    if (previous == .owner) try requireOtherOwner(tx, team, subject.id);
    if (next) |role| {
        if ((previous == null or role == .owner) and !subject.enabled) return error.DisabledTeamAccount;
        try execute(
            tx,
            "INSERT INTO mail_team_members(team_id,user_id,role) VALUES(?1,?2,?3) ON CONFLICT(team_id,user_id) DO UPDATE SET role=excluded.role",
            .{ team, subject.id, @tagName(role) },
        );
    } else {
        try execute(tx, "DELETE FROM mail_team_members WHERE team_id=?1 AND user_id=?2", .{ team, subject.id });
    }
    if (previous != null) try execute(tx, "DELETE FROM webmail_sessions WHERE username=?1", .{mailbox});
    try audit(tx, a, actor, team, "team.membership", .{ .mailbox = mailbox, .previous = previous, .role = next });
    try tx.commit();
}

fn validGrant(grant: Grant) bool {
    if (!validText(grant.resource, 255)) return false;
    return switch (grant.scope) {
        .mailbox, .sender, .search => grant.resource.len == 0,
        .calendar, .attachments, .comments => grant.resource.len > 0,
    };
}

pub fn setGrant(db: *database.Database, a: Allocator, actor: Actor, team: []const u8, grant: Grant, allowed: bool) !void {
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const principal = try access(tx, team, actor);
    if (!validGrant(grant)) return error.InvalidTeamData;
    const source_id, const grantee_id = try authorizeGrant(tx, principal, actor, team, grant.source, grant.grantee, allowed);
    const sql = if (allowed)
        "INSERT INTO mail_team_grants(team_id,source_id,grantee_id,scope,resource) VALUES(?1,?2,?3,?4,?5) ON CONFLICT DO NOTHING RETURNING 1"
    else
        "DELETE FROM mail_team_grants WHERE team_id=?1 AND source_id=?2 AND grantee_id=?3 AND scope=?4 AND resource=?5 RETURNING 1";
    const changed = blk: {
        const stmt = try tx.prepare(sql);
        defer stmt.finalize();
        try bind(stmt, .{ team, source_id, grantee_id, @tagName(grant.scope), grant.resource });
        break :blk try stmt.step();
    };
    if (!changed) return;
    try audit(tx, a, actor, team, if (allowed) "team.grant" else "team.revoke", grant);
    try tx.commit();
}

fn authorizeGrant(tx: Tx, principal: Access, actor: Actor, team: []const u8, source_name: []const u8, grantee_name: []const u8, allowed: bool) !struct { i64, i64 } {
    // A team administrator can revoke any grant. Granting access to someone
    // else's resources requires the local operator or the resource owner.
    if (actor == .mailbox and !std.mem.eql(u8, actor.mailbox, source_name) and (allowed or principal.role == .member))
        return error.TeamForbidden;
    const source = (try identity(tx, source_name)) orelse return error.TeamMemberNotFound;
    const grantee = (try identity(tx, grantee_name)) orelse return error.TeamMemberNotFound;
    if (try memberRole(tx, team, source.id) == null or try memberRole(tx, team, grantee.id) == null)
        return error.TeamMemberNotFound;
    if (source.id == grantee.id) return error.InvalidTeamData;
    if (allowed and (!source.enabled or !grantee.enabled)) return error.DisabledTeamAccount;
    return .{ source.id, grantee.id };
}

pub fn setCalendarShare(db: *database.Database, a: Allocator, owner: []const u8, team: []const u8, grantee: []const u8, share_id: CalendarShareId, policy: ?CalendarAccess) !void {
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const actor: Actor = .{ .mailbox = owner };
    const principal = try access(tx, team, actor);
    const source_id, const grantee_id = try authorizeGrant(tx, principal, actor, team, owner, grantee, policy != null);
    const share_key: []const u8 = &share_id;
    const changed = blk: {
        const stmt = try tx.prepare(if (policy != null)
            \\INSERT INTO mail_team_calendar_shares(team_id,source_id,grantee_id,calendar_share_id,access) VALUES(?1,?2,?3,?4,?5)
            \\ON CONFLICT(team_id,source_id,grantee_id,calendar_share_id) DO UPDATE SET access=excluded.access
            \\WHERE access<>excluded.access RETURNING 1
        else
            "DELETE FROM mail_team_calendar_shares WHERE team_id=?1 AND source_id=?2 AND grantee_id=?3 AND calendar_share_id=?4 RETURNING 1");
        defer stmt.finalize();
        try bind(stmt, .{ team, source_id, grantee_id, share_key });
        if (policy) |role| try stmt.bind(5, @tagName(role));
        break :blk try stmt.step();
    };
    if (!changed) return;
    try audit(tx, a, actor, team, if (policy != null) "team.calendar.share" else "team.calendar.revoke", .{
        .grantee = grantee,
        .calendarShareId = share_key,
        .access = policy,
    });
    try tx.commit();
}

pub fn calendarShares(db: *database.Database, a: Allocator, mailbox: []const u8) ![]CalendarShare {
    var tx = try db.beginTransaction(.read);
    defer tx.deinit();
    const principal = (try identity(tx, mailbox)) orelse return &.{};
    if (!principal.enabled) return &.{};
    return calendarSharesFor(tx, a, principal.id, false);
}

pub fn calendarSharesFor(tx: Tx, a: Allocator, user_id: i64, incoming_only: bool) ![]CalendarShare {
    const stmt = try tx.prepare(
        \\SELECT p.team_id,p.source_id,s.username,g.username,p.calendar_share_id,p.access
        \\FROM mail_team_calendar_shares p JOIN users s ON s.id=p.source_id JOIN users g ON g.id=p.grantee_id
        \\WHERE (p.grantee_id=?1 OR (NOT ?2 AND p.source_id=?1)) AND s.enabled=1 AND g.enabled=1
        \\ORDER BY s.username,g.username,p.team_id,p.calendar_share_id
    );
    defer stmt.finalize();
    try bind(stmt, .{ user_id, @as(i64, @intFromBool(incoming_only)) });
    var rows: std.ArrayList(CalendarShare) = .empty;
    while (try stmt.step()) {
        const share_id = stmt.columnText(4);
        if (share_id.len != @sizeOf(CalendarShareId)) return error.InvalidTeamData;
        try rows.append(a, .{
            .team = try a.dupe(u8, stmt.columnText(0)),
            .source_id = stmt.columnInt64(1),
            .source = try a.dupe(u8, stmt.columnText(2)),
            .grantee = try a.dupe(u8, stmt.columnText(3)),
            .calendar_share_id = share_id[0..@sizeOf(CalendarShareId)].*,
            .access = std.meta.stringToEnum(CalendarAccess, stmt.columnText(5)) orelse return error.InvalidTeamData,
        });
    }
    return rows.toOwnedSlice(a);
}

/// Resolve the strongest current grant for one exact calendar. The caller
/// holds the account transaction through the corresponding DAV operation.
pub fn calendarAccess(tx: Tx, grantee_id: i64, source_id: i64, share_id: CalendarShareId) !?CalendarAccess {
    const stmt = try tx.prepare(
        \\SELECT p.access FROM mail_team_calendar_shares p
        \\JOIN users s ON s.id=p.source_id AND s.enabled=1
        \\WHERE p.grantee_id=?1 AND p.source_id=?2 AND p.calendar_share_id=?3
        \\ORDER BY CASE p.access WHEN 'editor' THEN 1 WHEN 'viewer' THEN 2 ELSE 3 END
        \\LIMIT 1
    );
    defer stmt.finalize();
    const key: []const u8 = &share_id;
    try bind(stmt, .{ grantee_id, source_id, key });
    if (!try stmt.step()) return null;
    return std.meta.stringToEnum(CalendarAccess, stmt.columnText(0)) orelse error.InvalidTeamData;
}

/// Grant instances carry their own epochs so an old checkpoint cannot cross
/// a revoke/regrant, even when no DAV request observes the intermediate state.
pub fn calendarGrantEpoch(tx: Tx, grantee_id: i64, source_id: i64, share_id: CalendarShareId) !?[32]u8 {
    const stmt = try tx.prepare(
        \\SELECT epoch FROM mail_team_calendar_share_epochs
        \\WHERE grantee_id=?1 AND source_id=?2 AND calendar_share_id=?3 ORDER BY team_id
    );
    defer stmt.finalize();
    const key: []const u8 = &share_id;
    try bind(stmt, .{ grantee_id, source_id, key });
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var found = false;
    while (try stmt.step()) {
        const epoch = stmt.columnText(0);
        if (epoch.len != 32) return error.InvalidTeamData;
        hash.update(epoch);
        found = true;
    }
    return if (found) hash.finalResult() else null;
}

pub fn list(db: *database.Database, a: Allocator, mailbox: []const u8) ![]Team {
    const stmt = try db.prepare(
        \\SELECT t.id,t.name,m.role FROM mail_team_members m JOIN mail_teams t ON t.id=m.team_id
        \\JOIN users u ON u.id=m.user_id WHERE u.username=?1 AND u.enabled=1 ORDER BY t.id
    );
    defer stmt.finalize();
    try stmt.bind(1, mailbox);
    var rows: std.ArrayList(Team) = .empty;
    while (try stmt.step()) try rows.append(a, .{
        .id = try a.dupe(u8, stmt.columnText(0)),
        .name = try a.dupe(u8, stmt.columnText(1)),
        .role = std.meta.stringToEnum(Role, stmt.columnText(2)) orelse return error.InvalidTeamData,
    });
    return rows.toOwnedSlice(a);
}

pub fn senderIdentities(db: *database.Database, a: Allocator, mailbox: []const u8) ![]SenderIdentity {
    const stmt = try db.prepare(senderIdentityQuery ++ " ORDER BY source.email");
    defer stmt.finalize();
    try stmt.bind(1, mailbox);
    var rows: std.ArrayList(SenderIdentity) = .empty;
    while (try stmt.step()) try rows.append(a, .{
        .id = try std.fmt.allocPrint(a, "{d}", .{stmt.columnInt64(0)}),
        .address = try a.dupe(u8, stmt.columnText(1)),
    });
    return rows.toOwnedSlice(a);
}

/// The read transaction gives role checks and returned records one snapshot.
pub fn details(db: *database.Database, a: Allocator, actor: Actor, team: []const u8) !Details {
    var tx = try db.beginTransaction(.read);
    defer tx.deinit();
    const principal = try access(tx, team, actor);
    const header = try tx.prepare("SELECT name FROM mail_teams WHERE id=?1");
    defer header.finalize();
    try header.bind(1, team);
    if (!try header.step()) return error.TeamNotFound;
    const full = principal.role != .member;
    const members = try tx.prepare(
        \\SELECT u.username,m.role,u.enabled FROM mail_team_members m JOIN users u ON u.id=m.user_id
        \\WHERE m.team_id=?1 AND (?2 OR m.user_id=?3) ORDER BY u.username
    );
    defer members.finalize();
    try bind(members, .{ team, @as(i64, @intFromBool(full)), principal.id });
    var member_rows: std.ArrayList(Member) = .empty;
    while (try members.step()) try member_rows.append(a, .{
        .mailbox = try a.dupe(u8, members.columnText(0)),
        .role = std.meta.stringToEnum(Role, members.columnText(1)) orelse return error.InvalidTeamData,
        .enabled = members.columnInt64(2) != 0,
    });
    const grants = try tx.prepare(
        \\SELECT s.username,g.username,p.scope,p.resource FROM mail_team_grants p
        \\JOIN users s ON s.id=p.source_id JOIN users g ON g.id=p.grantee_id
        \\WHERE p.team_id=?1 AND (?2 OR p.source_id=?3 OR p.grantee_id=?3)
        \\ORDER BY s.username,g.username,p.scope,p.resource
    );
    defer grants.finalize();
    try bind(grants, .{ team, @as(i64, @intFromBool(full)), principal.id });
    var grant_rows: std.ArrayList(Grant) = .empty;
    while (try grants.step()) try grant_rows.append(a, .{
        .source = try a.dupe(u8, grants.columnText(0)),
        .grantee = try a.dupe(u8, grants.columnText(1)),
        .scope = std.meta.stringToEnum(Scope, grants.columnText(2)) orelse return error.InvalidTeamData,
        .resource = try a.dupe(u8, grants.columnText(3)),
    });
    const result: Details = .{
        .team = .{ .id = team, .name = try a.dupe(u8, header.columnText(0)), .role = if (actor == .operator) null else principal.role },
        .members = try member_rows.toOwnedSlice(a),
        .grants = try grant_rows.toOwnedSlice(a),
    };
    try tx.commit();
    return result;
}

pub fn beforeAccountDeletion(tx: Tx, mailbox: []const u8) !void {
    const found = (try identity(tx, mailbox)) orelse return;
    const teams = try tx.prepare("SELECT team_id FROM mail_team_members WHERE user_id=?1 AND role='owner'");
    defer teams.finalize();
    try teams.bind(1, found.id);
    while (try teams.step()) try requireOtherOwner(tx, teams.columnText(0), found.id);
    try execute(tx,
        \\INSERT INTO audit_log(timestamp,action,actor,target,target_type,details,severity)
        \\SELECT unixepoch(),'team.account_deleted','account-deletion',team_id,'team',json_object('mailbox',?1,'role',role),'info'
        \\FROM mail_team_members WHERE user_id=?2
    , .{ mailbox, found.id });
}
