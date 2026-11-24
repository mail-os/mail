//! Limited credentials for one mailbox and one named integration.
const std = @import("std");
const database = @import("../storage/database.zig");
const maildir = @import("webmail_maildir.zig");
const refs = @import("../storage/message_refs.zig");
const html_text = @import("../antispam/html_text.zig");
const service = @import("webmail_service.zig");
const store = @import("webmail_store.zig");
const teams = @import("../storage/team_store.zig");
const tokens = @import("webmail_link_tokens.zig");

const Allocator = std.mem.Allocator;
const Database = database.Database;
const owner = "user_id=(SELECT id FROM users WHERE username=?1 AND enabled=1)";
const max_messages = 10;
const max_bytes = 128 * 1024;

pub const Input = struct {
    integration: []const u8,
    read: bool,
    draft: bool,
    lifetime: i64,
    references: []const []const u8 = &.{},
    digest: ?[]const u8 = null,
};
pub const Message = struct { reference: []const u8, subject: []const u8, text: []const u8 };
const Entry = struct { message: Message, content_revision: [64]u8 };
const Policy = struct { integration: []const u8, read: bool, draft: bool, lifetime: i64, entries: []const Entry };
pub const Preview = struct {
    integration: []const u8,
    read: bool,
    draft: bool,
    lifetime: i64,
    messages: []const Message,
    digest: [64]u8,
};
pub const Prepared = struct { data: Policy, preview: Preview, payload: []const u8 };
pub const Grant = struct {
    id: i64,
    integration: []const u8,
    read: bool,
    draft: bool,
    message_count: i64,
    expires_at: i64,
    subjects: []const []const u8 = &.{},
};
pub const Issued = struct { grant: Grant, token: [64]u8 };
pub const Access = struct { grant_id: i64, username: []const u8, email: []const u8, data: ?Policy };
pub const Action = enum { create, revoke, read, draft };
pub const Outcome = enum { ok, denied, failed };
pub const Audit = struct { integration: []const u8, actor: []const u8, action: []const u8, outcome: []const u8, occurred_at: i64 };
pub const Status = struct { grants: []const Grant, audit: []const Audit };
pub const DraftInput = struct {
    request_id: []const u8,
    to: []const []const u8 = &.{},
    cc: []const []const u8 = &.{},
    bcc: []const []const u8 = &.{},
    subject: []const u8 = "",
    text: []const u8 = "",
};

fn isLink(word: []const u8) bool {
    const token = std.mem.trimStart(u8, word, "<[({'\"*\x60");
    if (std.mem.indexOf(u8, token, "://") != null or std.mem.indexOf(u8, token, "#token=") != null) return true;
    for ([_][]const u8{ "www.", "mailto:", "tel:", "data:", "javascript:", "/snapshot", "/file-link" }) |prefix| {
        if (token.len >= prefix.len and std.ascii.eqlIgnoreCase(token[0..prefix.len], prefix)) return true;
    }
    return false;
}

fn redactLinks(a: Allocator, text: []const u8) ![]const u8 {
    var safe: std.ArrayList(u8) = .empty;
    var pos: usize = 0;
    while (pos < text.len) {
        if (std.ascii.isWhitespace(text[pos])) {
            try safe.append(a, text[pos]);
            pos += 1;
            continue;
        }
        const end = std.mem.indexOfAnyPos(u8, text, pos, " \t\r\n\x0b\x0c") orelse text.len;
        const word = text[pos..end];
        try safe.appendSlice(a, if (isLink(word)) "[link removed]" else word);
        pos = end;
    }
    return safe.toOwnedSlice(a);
}

fn allowedMessage(a: Allocator, db: *Database, user: []const u8, reference: []const u8, junk: []const u8) !maildir.MessageDetail {
    const msg = try maildir.getByReference(a, db, user, reference);
    if (!maildir.isPersonalFolder(msg.folder) or msg.flags.deleted or msg.flags.draft or
        std.ascii.eqlIgnoreCase(msg.folder, "Trash") or std.ascii.eqlIgnoreCase(msg.folder, "Junk") or
        std.ascii.eqlIgnoreCase(msg.folder, junk)) return error.MessageNotFound;
    return msg;
}

pub fn prepare(a: Allocator, db: *Database, user: []const u8, input: Input, junk: []const u8) !Prepared {
    const integration = std.mem.trim(u8, input.integration, " \t");
    if (integration.len == 0 or integration.len > 80 or !std.unicode.utf8ValidateSlice(integration) or
        (!input.read and !input.draft) or !tokens.validLifetime(input.lifetime) or
        input.references.len > max_messages or (input.read != (input.references.len > 0))) return error.InvalidAssistantGrant;
    for (integration) |byte| if (byte < 32 or byte == 127) return error.InvalidAssistantGrant;

    const entries = try a.alloc(Entry, input.references.len);
    const messages = try a.alloc(Message, entries.len);
    var bytes: usize = 0;
    for (input.references, entries, messages, 0..) |reference, *entry, *message, index| {
        if (!refs.valid(reference)) return error.InvalidAssistantGrant;
        for (input.references[0..index]) |prior| {
            if (std.mem.eql(u8, prior, reference)) return error.InvalidAssistantGrant;
        }
        var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer scratch.deinit();
        const msg = try allowedMessage(scratch.allocator(), db, user, reference, junk);
        const plain = if (msg.text_body.len == 0 and msg.html_body.len > 0) blk: {
            const buffer = try scratch.allocator().alloc(u8, @min(msg.html_body.len, max_bytes + 1));
            break :blk std.mem.trim(u8, html_text.extract(msg.html_body, buffer), " ");
        } else msg.text_body;
        if (msg.subject.len + plain.len > max_bytes - bytes) return error.AssistantPreviewTooLarge;
        if (!std.unicode.utf8ValidateSlice(msg.subject) or !std.unicode.utf8ValidateSlice(plain)) return error.InvalidAssistantText;
        bytes += msg.subject.len + plain.len;
        message.* = .{ .reference = reference, .subject = try redactLinks(a, msg.subject), .text = try redactLinks(a, plain) };
        entry.* = .{ .message = message.*, .content_revision = msg.version.?.content_revision };
    }
    const policy: Policy = .{ .integration = integration, .read = input.read, .draft = input.draft, .lifetime = input.lifetime, .entries = entries };
    const payload = try service.json(a, policy);
    if (payload.len > max_bytes) return error.AssistantPreviewTooLarge;
    return .{ .data = policy, .preview = .{
        .integration = integration,
        .read = input.read,
        .draft = input.draft,
        .lifetime = input.lifetime,
        .messages = messages,
        .digest = tokens.digest(payload),
    }, .payload = payload };
}

pub fn issue(db: *Database, user: []const u8, prepared: Prepared, now: i64) !Issued {
    const token = tokens.new();
    const hash = tokens.digest(&token);
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const user_id = (try teams.activeMailboxId(tx, user)) orelse return error.AssistantUnavailable;
    const expiry = now + prepared.data.lifetime;
    const id = blk: {
        const stmt = try tx.prepare(
            \\INSERT INTO mail_assistant_grants(user_id,integration,token_hash,read_allowed,draft_allowed,payload,expires_at)
            \\SELECT ?1,?2,?3,?4,?5,?6,?7 WHERE (SELECT count(*) FROM mail_assistant_grants
            \\ WHERE user_id=?1 AND expires_at>?8 AND revoked_at IS NULL)<20 RETURNING id
        );
        defer stmt.finalize();
        try stmt.bind(1, user_id);
        try stmt.bind(2, prepared.data.integration);
        try stmt.bind(3, @as([]const u8, &hash));
        try stmt.bind(4, @intFromBool(prepared.data.read));
        try stmt.bind(5, @intFromBool(prepared.data.draft));
        try stmt.bind(6, prepared.payload);
        try stmt.bind(7, expiry);
        try stmt.bind(8, now);
        if (!try stmt.step()) return error.AssistantGrantLimit;
        break :blk stmt.columnInt64(0);
    };
    try appendAudit(tx, id, "owner", .create, .ok, now);
    try tx.commit();
    return .{ .token = token, .grant = .{
        .id = id,
        .integration = prepared.data.integration,
        .read = prepared.data.read,
        .draft = prepared.data.draft,
        .message_count = @intCast(prepared.data.entries.len),
        .expires_at = expiry,
    } };
}

pub fn status(a: Allocator, db: *Database, user: []const u8, now: i64) !Status {
    var grants: std.ArrayList(Grant) = .empty;
    {
        const stmt = try db.prepare(
            \\SELECT id,integration,read_allowed,draft_allowed,json_array_length(payload,'$.entries'),expires_at,
            \\ (SELECT json_group_array(json_extract(value,'$.message.subject')) FROM json_each(payload,'$.entries'))
            \\FROM mail_assistant_grants WHERE
        ++ " " ++ owner ++ " AND revoked_at IS NULL AND expires_at>?2 ORDER BY id DESC");
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, now);
        while (try stmt.step()) try grants.append(a, .{
            .id = stmt.columnInt64(0),
            .integration = try a.dupe(u8, stmt.columnText(1)),
            .read = stmt.columnInt64(2) != 0,
            .draft = stmt.columnInt64(3) != 0,
            .message_count = stmt.columnInt64(4),
            .expires_at = stmt.columnInt64(5),
            .subjects = try std.json.parseFromSliceLeaky([]const []const u8, a, try a.dupe(u8, stmt.columnText(6)), .{}),
        });
    }
    var rows: std.ArrayList(Audit) = .empty;
    const stmt = try db.prepare("SELECT g.integration,a.actor,a.action,a.outcome,a.occurred_at FROM mail_assistant_audit a JOIN mail_assistant_grants g ON g.id=a.grant_id WHERE g." ++ owner ++ " ORDER BY a.id DESC LIMIT 100");
    defer stmt.finalize();
    try stmt.bind(1, user);
    while (try stmt.step()) try rows.append(a, .{
        .integration = try a.dupe(u8, stmt.columnText(0)),
        .actor = try a.dupe(u8, stmt.columnText(1)),
        .action = try a.dupe(u8, stmt.columnText(2)),
        .outcome = try a.dupe(u8, stmt.columnText(3)),
        .occurred_at = stmt.columnInt64(4),
    });
    return .{ .grants = grants.items, .audit = rows.items };
}

pub fn revoke(db: *Database, user: []const u8, id: i64, now: i64) !void {
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    {
        const stmt = try tx.prepare("UPDATE mail_assistant_grants SET revoked_at=?3,payload='{}' WHERE " ++ owner ++ " AND id=?2 AND revoked_at IS NULL RETURNING id");
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, id);
        try stmt.bind(3, now);
        if (!try stmt.step()) return error.AssistantUnavailable;
    }
    try appendAudit(tx, id, "owner", .revoke, .ok, now);
    try tx.commit();
}

fn appendAudit(target: anytype, id: i64, actor: []const u8, action: Action, outcome: Outcome, now: i64) !void {
    const stmt = try target.prepare("INSERT INTO mail_assistant_audit(grant_id,actor,action,outcome,occurred_at) VALUES(?1,?2,?3,?4,?5)");
    defer stmt.finalize();
    try stmt.bind(1, id);
    try stmt.bind(2, actor);
    try stmt.bind(3, @tagName(action));
    try stmt.bind(4, @tagName(outcome));
    try stmt.bind(5, now);
    _ = try stmt.step();
}

pub fn audit(db: *Database, access: Access, action: Action, outcome: Outcome, now: i64) !void {
    try appendAudit(db, access.grant_id, "integration", action, outcome, now);
}

pub fn authenticate(a: Allocator, db: *Database, token: []const u8, action: Action, now: i64) !Access {
    if (!tokens.valid(token)) return error.AssistantUnavailable;
    const hash = tokens.digest(token);
    const access: Access = blk: {
        const stmt = try db.prepare("SELECT g.id,u.username,u.email,g.expires_at,u.enabled,g.revoked_at,g.payload FROM mail_assistant_grants g JOIN users u ON u.id=g.user_id WHERE g.token_hash=?1");
        defer stmt.finalize();
        try stmt.bind(1, @as([]const u8, &hash));
        if (!try stmt.step()) return error.AssistantUnavailable;
        const active = stmt.columnInt64(3) > now and stmt.columnInt64(4) == 1 and stmt.columnInt64Opt(5) == null;
        break :blk .{
            .grant_id = stmt.columnInt64(0),
            .username = try a.dupe(u8, stmt.columnText(1)),
            .email = try a.dupe(u8, stmt.columnText(2)),
            .data = if (active) try std.json.parseFromSliceLeaky(Policy, a, try a.dupe(u8, stmt.columnText(6)), .{}) else null,
        };
    };
    const mailbox_access = try db.mailboxAccess(access.username);
    if (!mailbox_access.readable() or access.data == null or (action == .read and !access.data.?.read) or
        (action == .draft and (mailbox_access != .full or !access.data.?.draft)))
    {
        try audit(db, access, action, .denied, now);
        return error.AssistantUnavailable;
    }
    return access;
}

pub fn read(a: Allocator, db: *Database, access: Access, reference: []const u8, junk: []const u8) !Message {
    for (access.data.?.entries) |entry| {
        if (!std.mem.eql(u8, entry.message.reference, reference)) continue;
        const live = try allowedMessage(a, db, access.username, reference, junk);
        if (!std.mem.eql(u8, &entry.content_revision, &live.version.?.content_revision)) return error.AssistantUnavailable;
        return entry.message;
    }
    return error.AssistantUnavailable;
}

pub fn prepareDraft(a: Allocator, svc: *service.Service, access: Access, input: DraftInput) !service.DraftAck {
    if (!store.validId(input.request_id) or input.subject.len > 512 or input.text.len > 64 * 1024 or
        input.to.len + input.cc.len + input.bcc.len > 50 or
        (input.subject.len == 0 and input.text.len == 0)) return error.InvalidAssistantDraft;
    const digest = tokens.digest(try service.json(a, input));
    const id = tokens.digest(try std.fmt.allocPrint(a, "assistant:{d}:{s}", .{ access.grant_id, input.request_id }));
    const draft_id = try a.dupe(u8, id[0..32]);
    const payload: service.Payload = .{
        .to = input.to,
        .cc = input.cc,
        .bcc = input.bcc,
        .subject = input.subject,
        .text = input.text,
        .draftId = draft_id,
        .saveToken = input.request_id,
    };
    {
        const stmt = try svc.db.prepare("SELECT digest,acknowledgement FROM mail_assistant_requests WHERE grant_id=?1 AND request_id=?2");
        defer stmt.finalize();
        try stmt.bind(1, access.grant_id);
        try stmt.bind(2, input.request_id);
        if (try stmt.step()) {
            if (!std.mem.eql(u8, &digest, stmt.columnText(0))) return error.AssistantDraftConflict;
            if (stmt.columnTextOpt(1)) |ack| return std.json.parseFromSliceLeaky(service.DraftAck, a, try a.dupe(u8, ack), .{});
            // An interrupted write may have left a draft the owner already handled.
            return error.AssistantDraftConflict;
        }
    }
    {
        const stmt = try svc.db.prepare("INSERT INTO mail_assistant_requests(grant_id,request_id,digest) SELECT ?1,?2,?3 WHERE (SELECT count(*) FROM mail_assistant_requests WHERE grant_id=?1)<25 RETURNING grant_id");
        defer stmt.finalize();
        try stmt.bind(1, access.grant_id);
        try stmt.bind(2, input.request_id);
        try stmt.bind(3, @as([]const u8, &digest));
        if (!try stmt.step()) return error.AssistantDraftLimit;
    }
    const ack = try svc.saveDraft(a, access.username, access.email, payload);
    const stmt = try svc.db.prepare("UPDATE mail_assistant_requests SET acknowledgement=?3 WHERE grant_id=?1 AND request_id=?2");
    defer stmt.finalize();
    try stmt.bind(1, access.grant_id);
    try stmt.bind(2, input.request_id);
    try stmt.bind(3, try service.json(a, ack));
    _ = try stmt.step();
    return ack;
}

pub fn sweep(db: *Database, now: i64) !void {
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const queries = [_][]const u8{
        "UPDATE mail_assistant_grants SET payload='{}' WHERE expires_at<=?1 AND payload<>'{}'",
        "DELETE FROM mail_assistant_grants WHERE expires_at<=?1-30*86400",
        "DELETE FROM mail_assistant_audit WHERE occurred_at<=?1-30*86400",
    };
    for (&queries) |sql| {
        const stmt = try tx.prepare(sql);
        defer stmt.finalize();
        try stmt.bind(1, now);
        _ = try stmt.step();
    }
    try tx.commit();
}
