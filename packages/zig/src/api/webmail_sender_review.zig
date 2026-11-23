//! Sender Review uses the original intake provenance and stable Maildir
//! references. Rules and their held-copy work commit before a file is moved.
const std = @import("std");
const database = @import("../storage/database.zig");
const maildir = @import("webmail_maildir.zig");
const durable = @import("../core/durable_maildir.zig");
const fs = @import("../core/fs_compat.zig");
const routing = @import("../delivery/local_routing.zig");
const time = @import("../core/time_compat.zig");
const config = @import("../core/config.zig");
const addressing = @import("../message/submission.zig");
const link_tokens = @import("webmail_link_tokens.zig");

const Allocator = std.mem.Allocator;
const Database = database.Database;
const page_size = 30;
const owner = "user_id=(SELECT id FROM users WHERE username=?1)";
const journal_fields = "basename,folder,envelope_from,author,verified_author,recipient,remote_addr,file_stamp,reference,next_folder,operation,forward_release";

pub const View = enum { pending, declined, decisions, invitations };
pub const Request = struct {
    action: Database.SenderDecision,
    reference: ?[]const u8 = null,
    author: ?[]const u8 = null,
    apply_to_sender: bool = false,
    rule_revision: i64 = 0,
    forward: ?bool = null,
};

const Review = struct {
    basename: []const u8,
    folder: []const u8,
    envelope_from: []const u8,
    author: []const u8,
    verified: bool,
    recipient: []const u8,
    remote_addr: []const u8,
    stamp: []const u8,
    reference: ?[]const u8,
    destination: ?[]const u8,
    operation: ?[]const u8,
    forward: bool,
};

fn readReview(a: Allocator, stmt: database.Statement) !Review {
    const stamp = try a.dupe(u8, stmt.columnText(7));
    return .{
        .basename = try a.dupe(u8, stmt.columnText(0)),
        .folder = try a.dupe(u8, stmt.columnText(1)),
        .envelope_from = try a.dupe(u8, stmt.columnText(2)),
        .author = try a.dupe(u8, stmt.columnText(3)),
        // Rows from the routing-only version lack file identity. The user
        // can review that copy, but it cannot establish trust for future mail.
        .verified = stamp.len > 0 and stmt.columnInt64(4) != 0,
        .recipient = try a.dupe(u8, stmt.columnText(5)),
        .remote_addr = try a.dupe(u8, stmt.columnText(6)),
        .stamp = stamp,
        .reference = if (stmt.columnIsNull(8)) null else try a.dupe(u8, stmt.columnText(8)),
        .destination = if (stmt.columnIsNull(9)) null else try a.dupe(u8, stmt.columnText(9)),
        .operation = if (stmt.columnIsNull(10)) null else try a.dupe(u8, stmt.columnText(10)),
        .forward = stmt.columnInt64(11) != 0,
    };
}

const Item = struct {
    reference: []const u8,
    revision: []const u8,
    folder: []const u8,
    uid: i64,
    author: []const u8,
    verified: bool,
    envelope_from: []const u8,
    recipient: []const u8,
    from: []const u8,
    subject: []const u8,
    date: []const u8,
    rule_revision: i64,
    applying: bool,
};

const Rule = struct { author: []const u8, action: []const u8, forward: bool, revision: i64 };
const Invitation = struct { id: []const u8, author: []const u8, expires_at: i64 };
pub const InvitationRequest = struct { author: []const u8, lifetime: i64 };

fn displayText(value: []const u8) []const u8 {
    return if (std.unicode.utf8ValidateSlice(value)) value else "Invalid text";
}
pub const Page = struct {
    status: Database.SenderReviewStatus,
    items: []const Item = &.{},
    rules: []const Rule = &.{},
    invitations: []const Invitation = &.{},
    page: usize,
    page_size: usize = 30,
    has_more: bool = false,
};

pub fn list(a: Allocator, db: *Database, user: []const u8, view: View, page: usize) !Page {
    const offset = std.math.mul(usize, page -| 1, page_size) catch return error.InvalidReviewDecision;
    if (offset > std.math.maxInt(i64) - page_size) return error.InvalidReviewDecision;
    var response: Page = .{ .status = try db.senderReviewStatus(user), .page = page };
    if (view == .invitations) {
        const stmt = try db.prepare(
            "SELECT id,author,expires_at FROM sender_review_invitations WHERE " ++ owner ++
                " AND expires_at>unixepoch() ORDER BY expires_at,author LIMIT ?2 OFFSET ?3",
        );
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, page_size + 1);
        try stmt.bind(3, offset);
        var invitations: std.ArrayList(Invitation) = .empty;
        while (try stmt.step()) {
            if (invitations.items.len == page_size) {
                response.has_more = true;
                break;
            }
            try invitations.append(a, .{
                .id = try a.dupe(u8, stmt.columnText(0)),
                .author = try a.dupe(u8, stmt.columnText(1)),
                .expires_at = stmt.columnInt64(2),
            });
        }
        response.invitations = invitations.items;
        return response;
    }
    if (view == .decisions) {
        const stmt = try db.prepare("SELECT author,action,forward,revision FROM sender_screening_rules WHERE " ++ owner ++ " ORDER BY author LIMIT ?2 OFFSET ?3");
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, page_size + 1);
        try stmt.bind(3, offset);
        var rules: std.ArrayList(Rule) = .empty;
        while (try stmt.step()) {
            if (rules.items.len == page_size) {
                response.has_more = true;
                break;
            }
            try rules.append(a, .{ .author = try a.dupe(u8, stmt.columnText(0)), .action = try a.dupe(u8, stmt.columnText(1)), .forward = stmt.columnInt64(2) != 0, .revision = stmt.columnInt64(3) });
        }
        response.rules = rules.items;
        return response;
    }
    const folder: []const u8 = if (view == .pending) "Screening" else "Declined";
    var rows: std.ArrayList(Review) = .empty;
    {
        const stmt = try db.prepare("SELECT " ++ journal_fields ++ " FROM sender_review_messages WHERE " ++ owner ++ " AND folder=?2 ORDER BY basename DESC LIMIT ?3 OFFSET ?4");
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, folder);
        try stmt.bind(3, page_size + 1);
        try stmt.bind(4, offset);
        while (try stmt.step()) {
            if (rows.items.len == page_size) {
                response.has_more = true;
                break;
            }
            try rows.append(a, try readReview(a, stmt));
        }
    }
    var items: std.ArrayList(Item) = .empty;
    var removed = false;
    for (rows.items) |row| {
        var scratch = std.heap.ArenaAllocator.init(a);
        defer scratch.deinit();
        const tmp = scratch.allocator();
        db.lockMailboxes();
        defer db.unlockMailboxes();
        const file = maildir.observeReviewFile(tmp, db, user, row.folder, row.basename, row.stamp) catch |err| switch (err) {
            maildir.MaildirError.MessageNotFound, error.FileNotFound => {
                if (row.operation == null) {
                    try forget(db, user, row);
                    removed = true;
                }
                continue;
            },
            else => return err,
        };
        const headers = try maildir.reviewHeaders(tmp, file.raw);
        try items.append(a, .{
            .reference = try a.dupe(u8, file.version.reference),
            .revision = try a.dupe(u8, file.version.revision),
            .uid = file.locator.uid,
            .folder = row.folder,
            .author = displayText(row.author),
            .verified = row.verified,
            .envelope_from = displayText(row.envelope_from),
            .recipient = displayText(if (row.recipient.len > 0) row.recipient else user),
            .from = try a.dupe(u8, displayText(headers.from)),
            .subject = try a.dupe(u8, displayText(headers.subject)),
            .date = try a.dupe(u8, displayText(headers.date)),
            .rule_revision = if (row.verified) try ruleRevision(db, user, row.author) else 0,
            .applying = row.operation != null,
        });
    }
    if (removed) response.status = try db.senderReviewStatus(user);
    response.items = items.items;
    return response;
}

pub fn invite(a: Allocator, db: *Database, user: []const u8, request: InvitationRequest) !Invitation {
    const author = std.mem.trim(u8, request.author, " \t");
    if (author.len > 254 or !std.unicode.utf8ValidateSlice(author) or !addressing.validMailbox(author) or
        !link_tokens.validLifetime(request.lifetime)) return error.InvalidSenderInvitation;
    db.lockMailboxes();
    defer db.unlockMailboxes();
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const now = time.timestamp();
    const status = try tx.prepare(
        \\SELECT u.id,s.enabled,r.author IS NOT NULL
        \\FROM users u LEFT JOIN sender_screening s ON s.user_id=u.id
        \\LEFT JOIN sender_screening_rules r ON r.user_id=u.id AND r.author=?2
        \\WHERE u.username=?1 AND u.enabled=1
    );
    defer status.finalize();
    try status.bind(1, user);
    try status.bind(2, author);
    if (!try status.step()) return error.NotFound;
    if (status.columnInt64(1) == 0) return error.InvitationRequiresReview;
    if (status.columnInt64(2) != 0) return error.InvitationHasDecision;
    const user_id = status.columnInt64(0);
    const expired = try tx.prepare("DELETE FROM sender_review_invitations WHERE user_id=?1 AND expires_at<=?2");
    defer expired.finalize();
    try expired.bind(1, user_id);
    try expired.bind(2, now);
    _ = try expired.step();
    const expires_at = now + request.lifetime;
    const insert = try tx.prepare(
        \\INSERT INTO sender_review_invitations(user_id,author,id,expires_at)
        \\SELECT ?1,?2,lower(hex(randomblob(16))),?3
        \\WHERE (SELECT COUNT(*) FROM sender_review_invitations WHERE user_id=?1)<50
        \\ON CONFLICT(user_id,author) DO NOTHING RETURNING id
    );
    defer insert.finalize();
    try insert.bind(1, user_id);
    try insert.bind(2, author);
    try insert.bind(3, expires_at);
    if (!try insert.step()) return error.InvitationUnavailable;
    const id = try a.dupe(u8, insert.columnText(0));
    _ = try insert.step();
    try tx.commit();
    return .{ .id = id, .author = author, .expires_at = expires_at };
}

pub fn revokeInvitation(db: *Database, user: []const u8, id: []const u8) !void {
    db.lockMailboxes();
    defer db.unlockMailboxes();
    const stmt = try db.prepare("DELETE FROM sender_review_invitations WHERE " ++ owner ++ " AND id=?2 RETURNING id");
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bind(2, id);
    if (!try stmt.step()) return error.NotFound;
    _ = try stmt.step();
}

fn forget(db: *Database, user: []const u8, row: Review) !void {
    const stmt = try db.prepare("DELETE FROM sender_review_messages WHERE " ++ owner ++ " AND basename=?2 AND folder=?3 AND file_stamp=?4 AND operation IS NULL");
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bind(2, row.basename);
    try stmt.bind(3, row.folder);
    try stmt.bind(4, row.stamp);
    _ = try stmt.step();
}

fn ruleRevision(db: *Database, user: []const u8, author: []const u8) !i64 {
    const stmt = try db.prepare("SELECT revision FROM sender_screening_rules WHERE " ++ owner ++ " AND author=?2");
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bind(2, author);
    return if (try stmt.step()) stmt.columnInt64(0) else 0;
}

fn recordedReview(a: Allocator, db: *Database, user: []const u8, locator: maildir.VersionedFile) !Review {
    const stmt = try db.prepare("SELECT " ++ journal_fields ++ " FROM sender_review_messages WHERE " ++ owner ++ " AND basename=?2 AND folder=?3");
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bind(2, database.maildirBaseName(locator.name));
    try stmt.bind(3, locator.locator.folder);
    if (!try stmt.step()) return maildir.MaildirError.MessageNotFound;
    const row = try readReview(a, stmt);
    if (row.stamp.len > 0 and !std.mem.eql(u8, row.stamp, locator.stamp)) return maildir.MaildirError.MessageNotFound;
    if (row.operation != null) return error.ReviewInProgress;
    return row;
}

pub fn schedule(a: Allocator, db: *Database, user: []const u8, request: Request, expected: ?[]const u8) !void {
    db.lockMailboxes();
    defer db.unlockMailboxes();
    const scope: Database.SenderDecisionScope = if (request.reference) |reference| blk: {
        if (request.author != null) return error.InvalidReviewDecision;
        const locator = try maildir.resolveVersioned(a, db, user, reference);
        if (!std.mem.eql(u8, locator.version.revision, expected orelse return error.InvalidReviewDecision)) return maildir.MaildirError.RevisionMismatch;
        const row = try recordedReview(a, db, user, locator);
        if (request.action == .recover and !std.mem.eql(u8, row.folder, "Declined")) return error.InvalidReviewDecision;
        if (request.apply_to_sender) {
            if (!row.verified or row.author.len == 0) return error.UnverifiedSender;
            break :blk .{ .author = .{ .address = row.author, .revision = request.rule_revision, .forward = request.forward } };
        }
        break :blk .{ .copy = .{ .basename = row.basename, .reference = locator.version.reference, .stamp = locator.stamp } };
    } else blk: {
        const author = request.author orelse return error.InvalidReviewDecision;
        if (request.rule_revision < 1 or author.len == 0 or author.len > 320) return error.InvalidReviewDecision;
        break :blk .{ .author = .{ .address = author, .revision = request.rule_revision, .forward = request.forward } };
    };
    try db.scheduleSenderDecision(user, scope, request.action);
}

const Job = struct { user: []const u8, review: Review };

fn nextJob(a: Allocator, db: *Database, user: ?[]const u8) !?Job {
    const sql = "SELECT " ++ journal_fields ++ ", (SELECT username FROM users WHERE id=r.user_id) FROM sender_review_messages r WHERE operation IS NOT NULL AND retry_at<=?1";
    const stmt = try db.prepare(if (user != null) sql ++ " AND user_id=(SELECT id FROM users WHERE username=?2) ORDER BY retry_at,operation LIMIT 1" else sql ++ " ORDER BY retry_at,operation LIMIT 1");
    defer stmt.finalize();
    try stmt.bind(1, time.timestamp());
    if (user) |username| try stmt.bind(2, username);
    if (!try stmt.step()) return null;
    return .{ .user = try a.dupe(u8, stmt.columnText(12)), .review = try readReview(a, stmt) };
}

pub fn drain(allocator: Allocator, db: *Database, user: ?[]const u8, hostname: []const u8, mail_config: ?*const config.Config, limit: usize) !bool {
    var worked = false;
    for (0..limit) |_| {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        db.lockMailboxes();
        defer db.unlockMailboxes();
        const next = (try nextJob(a, db, user)) orelse break;
        worked = true;
        process(a, db, next, hostname, mail_config) catch |err| {
            const delay = try db.prepare("UPDATE sender_review_messages SET retry_at=?3 WHERE " ++ owner ++ " AND operation=?2");
            defer delay.finalize();
            try delay.bind(1, next.user);
            try delay.bind(2, next.review.operation.?);
            try delay.bind(3, time.timestamp() + 5);
            _ = try delay.step();
            std.log.warn("Sender Review placement will retry: {}", .{err});
        };
    }
    return worked;
}

fn process(a: Allocator, db: *Database, job: Job, hostname: []const u8, mail_config: ?*const config.Config) !void {
    const row = job.review;
    const operation = row.operation.?;
    const destination = row.destination.?;
    var current = (if (row.reference) |reference|
        maildir.resolveVersioned(a, db, job.user, reference)
    else
        maildir.observeReviewFile(a, db, job.user, row.folder, row.basename, row.stamp)) catch |err| switch (err) {
        maildir.MaildirError.MessageNotFound, error.FileNotFound => return db.finishReviewPlacement(job.user, operation, null),
        else => return err,
    };
    if (std.mem.eql(u8, current.locator.folder, row.folder)) {
        if (row.reference == null) {
            const attach = try db.prepare("UPDATE sender_review_messages SET reference=?3 WHERE " ++ owner ++ " AND operation=?2");
            defer attach.finalize();
            try attach.bind(1, job.user);
            try attach.bind(2, operation);
            try attach.bind(3, current.version.reference);
            _ = try attach.step();
        }
        _ = try maildir.moveMessageLocked(a, db, job.user, row.folder, current.locator.uid, destination);
        current = try maildir.resolveVersioned(a, db, job.user, current.version.reference);
    }
    if (!std.mem.eql(u8, current.locator.folder, destination) or !std.mem.eql(u8, database.maildirBaseName(current.name), row.basename)) {
        return db.finishReviewPlacement(job.user, operation, null);
    }
    const original_dir = try std.fmt.allocPrint(a, "mail/{s}/{s}", .{ job.user, row.folder });
    if (fs.cwd().access(original_dir, .{})) try durable.syncDirectory(a, original_dir) else |_| {}
    try durable.syncDirectory(a, std.fs.path.dirname(current.path).?);
    const attention = try routing.attentionArrival(a, current.raw);
    var placed: Database.FiledCopy = .{
        .basename = row.basename,
        .stamp = current.stamp,
        .attention = attention,
        .notification_key = if (try db.browserNotificationsEnabled(job.user)) try routing.browserNotificationKey(a, current.raw, attention) else "",
    };
    if (!std.mem.eql(u8, destination, "INBOX")) return db.finishReviewPlacement(job.user, operation, placed);

    const identity: routing.SenderIdentity = .{ .author = row.author, .verified = row.verified };
    if (identity.verified) {
        var mailbox = try db.getUserByUsername(job.user);
        defer mailbox.deinit(db.allocator);
        placed.calendar_revisions = try maildir.calendarRevisions(a, current.raw, mailbox.email, identity.author);
    }
    var plan: routing.Plan = .{
        .allocator = a,
        .db = db,
        .bytes = current.raw.len,
        .raw = current.raw,
        .junk_folder = if (mail_config) |cfg| cfg.junkFolder() else "Junk",
        .automatic_category = if (identity.verified) routing.categories.classify(current.raw) else null,
    };
    try plan.add(.{ .recipient = if (row.recipient.len > 0) row.recipient else job.user, .mailbox = job.user, .folder = "new", .placement_reason = .sender_review });
    if (row.forward) try plan.forward(0, row.envelope_from, hostname, mail_config, identity);
    try db.acceptDelivery(.{
        .id = operation,
        .from = row.envelope_from,
        .author = row.author,
        .verified_author = row.verified,
        .notification_origin = row.remote_addr,
        .mime = current.raw,
        .accepted_at = time.timestamp(),
        .accepted_ms = time.milliTimestamp(),
        .targets = plan.targets.items,
        .review_release = placed,
    });
}
