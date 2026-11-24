//! Team authorization keyed by stable user IDs. The SMTP database owns grants
//! and membership so a domain rename preserves access and account reuse does not.
const std = @import("std");
const database = @import("database.zig");
const Tx = database.Database.Transaction;
const Allocator = std.mem.Allocator;
const mailbox_domains = @import("../core/mailbox_domains.zig");
const time = @import("../core/time_compat.zig");

pub const schema =
    \\CREATE TABLE IF NOT EXISTS mail_teams (
    \\    id TEXT PRIMARY KEY NOT NULL,
    \\    name TEXT NOT NULL
    \\);
    \\CREATE TABLE IF NOT EXISTS mail_hosted_teams (
    \\    domain TEXT PRIMARY KEY NOT NULL,
    \\    team_id TEXT NOT NULL UNIQUE REFERENCES mail_teams(id) ON DELETE CASCADE
    \\);
    \\CREATE TABLE IF NOT EXISTS mail_team_members (
    \\    team_id TEXT NOT NULL REFERENCES mail_teams(id) ON DELETE CASCADE,
    \\    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    \\    role TEXT NOT NULL CHECK(role IN ('owner','admin','member')),
    \\    PRIMARY KEY(team_id,user_id)
    \\);
    \\CREATE INDEX IF NOT EXISTS mail_team_members_user ON mail_team_members(user_id);
    \\CREATE TABLE IF NOT EXISTS mail_team_owner_handoffs (
    \\    operation_id TEXT PRIMARY KEY, team_id TEXT NOT NULL, departing TEXT NOT NULL, successor TEXT NOT NULL
    \\);
    \\CREATE TABLE IF NOT EXISTS mail_team_invitations (
    \\    id TEXT PRIMARY KEY NOT NULL DEFAULT(lower(hex(randomblob(16)))),
    \\    team_id TEXT NOT NULL,
    \\    inviter_id INTEGER NOT NULL,
    \\    recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    \\    expires_at INTEGER NOT NULL,
    \\    UNIQUE(team_id,recipient_id),
    \\    FOREIGN KEY(team_id,inviter_id) REFERENCES mail_team_members(team_id,user_id) ON DELETE CASCADE
    \\);
    \\CREATE INDEX IF NOT EXISTS mail_team_invites_recipient ON mail_team_invitations(recipient_id);
    \\CREATE INDEX IF NOT EXISTS mail_team_invites_inviter ON mail_team_invitations(inviter_id);
    \\CREATE TRIGGER IF NOT EXISTS mail_team_invites_owner_change AFTER UPDATE OF role ON mail_team_members
    \\WHEN OLD.role='owner' AND NEW.role<>'owner'
    \\BEGIN DELETE FROM mail_team_invitations WHERE team_id=OLD.team_id AND inviter_id=OLD.user_id; END;
    \\CREATE TRIGGER IF NOT EXISTS mail_team_invites_member_added AFTER INSERT ON mail_team_members
    \\BEGIN DELETE FROM mail_team_invitations WHERE team_id=NEW.team_id AND recipient_id=NEW.user_id; END;
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

pub const InvitationDecision = enum { accept, decline, revoke };
pub const Invitation = struct {
    id: []const u8,
    team: []const u8,
    team_name: []const u8,
    inviter: []const u8,
    recipient: []const u8,
    expires_at: i64,
};
pub const InvitationPanel = struct { teams: []const Team = &.{}, incoming: []const Invitation = &.{}, sent: []const Invitation = &.{} };

fn paidIdentity(tx: Tx, mailbox: []const u8, now: i64) !?i64 {
    const stmt = try tx.prepare(
        \\SELECT u.id FROM users u JOIN provisioned_mailboxes p ON p.user_id=u.id AND p.mailbox=u.username
        \\WHERE u.username=?1 AND u.enabled=1 AND p.service_until>?2
    );
    defer stmt.finalize();
    try bind(stmt, .{ mailbox, now });
    return if (try stmt.step()) stmt.columnInt64(0) else null;
}

fn sameMailboxDomain(first: []const u8, second: []const u8) bool {
    const domain = mailbox_domains.addressDomain(first) orelse return false;
    const other = mailbox_domains.addressDomain(second) orelse return false;
    return domain.len > 0 and std.ascii.eqlIgnoreCase(domain, other);
}

const invitationsQuery =
    \\SELECT i.id,i.team_id,t.name,s.username,u.username,i.expires_at,i.inviter_id,i.recipient_id
    \\FROM mail_team_invitations i JOIN mail_teams t ON t.id=i.team_id
    \\JOIN mail_team_members m ON m.team_id=i.team_id AND m.user_id=i.inviter_id AND m.role='owner'
    \\JOIN users s ON s.id=i.inviter_id AND s.enabled=1
    \\JOIN provisioned_mailboxes p ON p.user_id=s.id AND p.mailbox=s.username AND p.service_until>?2
    \\JOIN users u ON u.id=i.recipient_id AND u.enabled=1
    \\WHERE i.expires_at>?2
;

pub fn invitations(db: *database.Database, a: Allocator, mailbox: []const u8) !InvitationPanel {
    var tx = try db.beginTransaction(.read);
    defer tx.deinit();
    const now = time.timestamp();
    const user_id = (try paidIdentity(tx, mailbox, now)) orelse return .{};
    const owner_teams = try tx.prepare(
        \\SELECT t.id,t.name FROM mail_team_members m JOIN mail_teams t ON t.id=m.team_id
        \\WHERE m.user_id=?1 AND m.role='owner' ORDER BY t.name,t.id
    );
    defer owner_teams.finalize();
    try owner_teams.bind(1, user_id);
    var owned: std.ArrayList(Team) = .empty;
    while (try owner_teams.step()) try owned.append(a, .{
        .id = try a.dupe(u8, owner_teams.columnText(0)),
        .name = try a.dupe(u8, owner_teams.columnText(1)),
    });
    const rows = try tx.prepare(invitationsQuery ++ " AND (i.inviter_id=?1 OR i.recipient_id=?1) ORDER BY i.expires_at,i.id");
    defer rows.finalize();
    try bind(rows, .{ user_id, now });
    var incoming: std.ArrayList(Invitation) = .empty;
    var sent: std.ArrayList(Invitation) = .empty;
    while (try rows.step()) {
        const inviter = rows.columnText(3);
        const recipient = rows.columnText(4);
        if (!sameMailboxDomain(inviter, recipient)) continue;
        const target = if (user_id == rows.columnInt64(6)) &sent else &incoming;
        try target.append(a, .{
            .id = try a.dupe(u8, rows.columnText(0)),
            .team = try a.dupe(u8, rows.columnText(1)),
            .team_name = try a.dupe(u8, rows.columnText(2)),
            .inviter = try a.dupe(u8, inviter),
            .recipient = try a.dupe(u8, recipient),
            .expires_at = rows.columnInt64(5),
        });
    }
    try tx.commit();
    return .{ .teams = try owned.toOwnedSlice(a), .incoming = try incoming.toOwnedSlice(a), .sent = try sent.toOwnedSlice(a) };
}

pub fn invite(db: *database.Database, a: Allocator, mailbox: []const u8, team: []const u8, recipient: []const u8) !void {
    if (!validTeamId(team) or !validText(recipient, 254)) return error.InvalidTeamData;
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const actor: Actor = .{ .mailbox = mailbox };
    const owner = try access(tx, team, actor);
    const now = time.timestamp();
    if (owner.role != .owner or try paidIdentity(tx, mailbox, now) == null) return error.TeamForbidden;
    if (!sameMailboxDomain(mailbox, recipient)) return error.TeamInviteeUnavailable;
    const person = (try paidIdentity(tx, recipient, now)) orelse return error.TeamInviteeUnavailable;
    if (try memberRole(tx, team, person) != null) return error.TeamAlreadyJoined;
    try execute(tx,
        \\DELETE FROM mail_team_invitations WHERE team_id=?1 AND (expires_at<=?2 OR (recipient_id=?3 AND NOT EXISTS (
        \\    SELECT 1 FROM users u JOIN provisioned_mailboxes p ON p.user_id=u.id AND p.mailbox=u.username
        \\    WHERE u.id=mail_team_invitations.inviter_id AND u.enabled=1 AND p.service_until>?2
        \\)))
    , .{ team, now, person });

    const insert = try tx.prepare(
        \\INSERT INTO mail_team_invitations(team_id,inviter_id,recipient_id,expires_at) VALUES(?1,?2,?3,?4)
        \\ON CONFLICT(team_id,recipient_id) DO NOTHING RETURNING id
    );
    defer insert.finalize();
    try bind(insert, .{ team, owner.id, person, now + 7 * 86400 });
    if (try insert.step()) {
        const id = try a.dupe(u8, insert.columnText(0));
        _ = try insert.step();
        try audit(tx, a, actor, team, "team.invitation_created", .{ .invitation = id, .mailbox = recipient });
    }
    try tx.commit();
}

pub fn decideInvitation(db: *database.Database, a: Allocator, mailbox: []const u8, id: []const u8, decision: InvitationDecision) !void {
    if (id.len != 32) return error.TeamInvitationNotFound;
    for (id) |ch| if (!std.ascii.isHex(ch)) return error.TeamInvitationNotFound;
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const now = time.timestamp();
    const actor_id = (try paidIdentity(tx, mailbox, now)) orelse return error.TeamInvitationNotFound;
    const lookup = try tx.prepare(invitationsQuery ++ " AND i.id=?1 AND CASE WHEN ?3 THEN i.inviter_id ELSE i.recipient_id END=?4");
    defer lookup.finalize();
    try bind(lookup, .{ id, now, @as(i64, @intFromBool(decision == .revoke)), actor_id });
    if (!try lookup.step()) return error.TeamInvitationNotFound;
    const team = try a.dupe(u8, lookup.columnText(1));
    const inviter = lookup.columnText(3);
    const recipient = try a.dupe(u8, lookup.columnText(4));
    if (!sameMailboxDomain(inviter, recipient)) return error.TeamInvitationNotFound;
    _ = try lookup.step();
    const actor: Actor = .{ .mailbox = mailbox };
    if (decision == .accept) {
        try execute(tx, "INSERT INTO mail_team_members(team_id,user_id,role) VALUES(?1,?2,'member')", .{ team, actor_id });
        try audit(tx, a, actor, team, "team.membership", .{ .mailbox = mailbox, .previous = @as(?Role, null), .role = Role.member });
    } else {
        try execute(tx, "DELETE FROM mail_team_invitations WHERE id=?1", .{id});
    }
    try audit(tx, a, actor, team, "team.invitation_decided", .{ .invitation = id, .mailbox = recipient, .decision = decision });
    try tx.commit();
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
    try insertTeam(tx, a, actor, team, name, owner, member.id);
    try tx.commit();
}

fn insertTeam(tx: Tx, a: Allocator, actor: Actor, team: []const u8, name: []const u8, owner: []const u8, owner_id: i64) !void {
    try execute(tx, "INSERT INTO mail_teams(id,name) VALUES(?1,?2)", .{ team, name });
    try execute(tx, "INSERT INTO mail_team_members(team_id,user_id,role) VALUES(?1,?2,'owner')", .{ team, owner_id });
    try audit(tx, a, actor, team, "team.create", .{ .name = name, .owner = owner });
}

pub const HostedTeam = struct { id: []const u8, name: []const u8, domain: []const u8 };
pub const HostedTeamResult = struct { team: ?HostedTeam, created: bool = false, can_invite: bool = false };
pub const HostedMailboxInvitation = struct { team: []const u8, owner: []const u8, owner_actor: []const u8 };

/// Authorize against the provisioning assignment and current service window
/// inside the same transaction that reads or creates the domain's team.
pub fn hostedTeam(db: *database.Database, a: Allocator, mailbox: []const u8, actor_id: []const u8, requested_name: ?[]const u8) !HostedTeamResult {
    const domain = mailbox_domains.addressDomain(mailbox) orelse return error.InvalidTeamData;
    const name = if (requested_name) |value| std.mem.trim(u8, value, " ") else null;
    if (name) |value| if (!validText(value, 100) or value.len == 0) return error.InvalidTeamData;

    var tx = try db.beginTransaction(if (name == null) .read else .write);
    defer tx.deinit();
    const owner_id = blk: {
        const stmt = try tx.prepare(
            \\SELECT u.id FROM provisioned_mailboxes p JOIN users u ON u.id=p.user_id AND u.username=p.mailbox
            \\WHERE p.mailbox=?1 AND p.actor=?2 AND u.enabled=1 AND p.service_until>unixepoch()
        );
        defer stmt.finalize();
        try bind(stmt, .{ mailbox, actor_id });
        if (!try stmt.step()) return error.MailboxNotFound;
        break :blk stmt.columnInt64(0);
    };
    const existing: ?HostedTeam = blk: {
        const stmt = try tx.prepare("SELECT t.id,t.name FROM mail_hosted_teams h JOIN mail_teams t ON t.id=h.team_id WHERE h.domain=?1");
        defer stmt.finalize();
        try stmt.bind(1, domain);
        if (!try stmt.step()) break :blk null;
        break :blk .{ .id = try a.dupe(u8, stmt.columnText(0)), .name = try a.dupe(u8, stmt.columnText(1)), .domain = domain };
    };
    if (existing != null or name == null) {
        const can_invite = if (existing) |team| try memberRole(tx, team.id, owner_id) == .owner else false;
        try tx.commit();
        return .{ .team = existing, .can_invite = can_invite };
    }

    var nonce: [16]u8 = undefined;
    @import("../core/io_compat.zig").randomBytes(&nonce);
    const id = try std.fmt.allocPrint(a, "hosted-{s}", .{&std.fmt.bytesToHex(nonce, .lower)});
    try insertTeam(tx, a, .{ .operator = "hosted-provisioning" }, id, name.?, mailbox, owner_id);
    try execute(tx, "INSERT INTO mail_hosted_teams(domain,team_id) VALUES(?1,?2)", .{ domain, id });
    try tx.commit();
    return .{ .team = .{ .id = id, .name = name.?, .domain = domain }, .created = true, .can_invite = true };
}

/// Called inside the initial mailbox provisioning transaction so an obsolete
/// invitation cannot leave a mailbox or a partial membership behind.
pub fn enrollProvisionedMailbox(tx: Tx, a: Allocator, invitation: HostedMailboxInvitation, mailbox: []const u8, member_id: i64) !void {
    const domain = mailbox_domains.addressDomain(mailbox) orelse return error.TeamInvitationNotFound;
    if (!sameMailboxDomain(mailbox, invitation.owner)) return error.TeamInvitationNotFound;
    const owner = try tx.prepare(
        \\SELECT 1 FROM mail_hosted_teams h JOIN mail_team_members m ON m.team_id=h.team_id AND m.role='owner'
        \\JOIN users u ON u.id=m.user_id AND u.enabled=1
        \\JOIN provisioned_mailboxes p ON p.user_id=u.id AND p.mailbox=u.username AND p.service_until>unixepoch()
        \\WHERE h.domain=?1 AND h.team_id=?2 AND p.mailbox=?3 AND p.actor=?4
    );
    defer owner.finalize();
    try bind(owner, .{ domain, invitation.team, invitation.owner, invitation.owner_actor });
    if (!try owner.step()) return error.TeamInvitationNotFound;
    try execute(tx, "INSERT INTO mail_team_members(team_id,user_id,role) VALUES(?1,?2,'member')", .{ invitation.team, member_id });
    try audit(tx, a, .{ .mailbox = mailbox }, invitation.team, "team.membership", .{ .mailbox = mailbox, .previous = @as(?Role, null), .role = Role.member, .invited_by = invitation.owner });
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
    }
    try writeMembership(tx, team, mailbox, subject.id, previous, next);
    try audit(tx, a, actor, team, "team.membership", .{ .mailbox = mailbox, .previous = previous, .role = next });
    try tx.commit();
}

fn writeMembership(tx: Tx, team: []const u8, mailbox: []const u8, user_id: i64, previous: ?Role, next: ?Role) !void {
    if (next) |role| {
        try execute(
            tx,
            "INSERT INTO mail_team_members(team_id,user_id,role) VALUES(?1,?2,?3) ON CONFLICT(team_id,user_id) DO UPDATE SET role=excluded.role",
            .{ team, user_id, @tagName(role) },
        );
    } else {
        try execute(tx, "DELETE FROM mail_team_members WHERE team_id=?1 AND user_id=?2", .{ team, user_id });
    }
    if (previous != null) try execute(tx, "DELETE FROM webmail_sessions WHERE username=?1", .{mailbox});
}

pub fn offboardOwner(db: *database.Database, a: Allocator, operator: []const u8, operation: []const u8, team: []const u8, departing: []const u8, successor: []const u8) !void {
    if (operation.len < 16 or operation.len > 64 or std.mem.eql(u8, departing, successor)) return error.InvalidTeamData;
    for (operation) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return error.InvalidTeamData;

    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    {
        const receipt = try tx.prepare("SELECT team_id,departing,successor FROM mail_team_owner_handoffs WHERE operation_id=?1");
        defer receipt.finalize();
        try receipt.bind(1, operation);
        if (try receipt.step()) {
            if (!std.mem.eql(u8, receipt.columnText(0), team) or !std.mem.eql(u8, receipt.columnText(1), departing) or
                !std.mem.eql(u8, receipt.columnText(2), successor)) return error.OperationConflict;
            return;
        }
    }

    const actor: Actor = .{ .operator = operator };
    _ = try access(tx, team, actor);
    const previous = (try identity(tx, departing)) orelse return error.TeamMemberNotFound;
    const replacement = (try identity(tx, successor)) orelse return error.TeamMemberNotFound;
    if (try memberRole(tx, team, previous.id) != .owner) return error.DepartingOwnerChanged;
    const successor_role = (try memberRole(tx, team, replacement.id)) orelse return error.TeamMemberNotFound;
    if (!replacement.enabled) return error.DisabledTeamAccount;
    {
        const eligibility = try tx.prepare(
            \\SELECT h.domain, p.service_until, unixepoch()
            \\FROM users u LEFT JOIN mail_hosted_teams h ON h.team_id=?1
            \\LEFT JOIN provisioned_mailboxes p ON p.user_id=u.id AND p.mailbox=u.username
            \\WHERE u.id=?2
        );
        defer eligibility.finalize();
        try bind(eligibility, .{ team, replacement.id });
        if (!try eligibility.step()) return error.TeamMemberNotFound;
        const service_until = eligibility.columnInt64Opt(1);
        if (service_until) |deadline| if (deadline <= eligibility.columnInt64(2)) return error.DisabledTeamAccount;
        if (eligibility.columnTextOpt(0)) |team_domain| {
            const domain = mailbox_domains.addressDomain(successor) orelse return error.DisabledTeamAccount;
            if (!std.ascii.eqlIgnoreCase(team_domain, domain) or service_until == null) return error.DisabledTeamAccount;
        }
    }

    if (successor_role != .owner) try writeMembership(tx, team, successor, replacement.id, successor_role, .owner);
    try writeMembership(tx, team, departing, previous.id, .owner, null);
    try execute(tx, "INSERT INTO mail_team_owner_handoffs VALUES(?1,?2,?3,?4)", .{ operation, team, departing, successor });
    try audit(tx, a, actor, team, "team.owner_handoff", .{
        .operation_id = operation,
        .departing = departing,
        .successor = successor,
        .successor_previous_role = successor_role,
    });
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
