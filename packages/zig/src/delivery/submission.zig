//! Shared recipient validation and local delivery for interactive submissions.
const std = @import("std");
const hosted_limits = @import("../storage/hosted_limits.zig");
const durable_maildir = @import("../core/durable_maildir.zig");
const ews_drafts = @import("ews_drafts.zig");
const database = @import("../storage/database.zig");
const shared_inbox = @import("../storage/shared_inbox.zig");
const fs_compat = @import("../core/fs_compat.zig");
const time_compat = @import("../core/time_compat.zig");
const outbound = @import("outbound.zig");
const core_config = @import("../core/config.zig");
const routing = @import("local_routing.zig");
const smtp_provider = @import("smtp_provider.zig");
const message_refs = @import("../storage/message_refs.zig");
const thread_ids = @import("../message/thread_ids.zig");

pub const Delivery = struct {
    hostname: []const u8,
    delivery_method: core_config.DeliveryMethod,
    ses_region: []const u8,
    mail_config: ?*const core_config.Config = null,
    db: ?*database.Database = null,
    local_hosted_only: bool = false,
};

pub fn isSafeAddress(a: []const u8) bool {
    if (a.len == 0 or a.len > 320) return false;
    for (a) |c| {
        // Reject header-injection chars, and '/' '\' (which would let a crafted
        // local-part escape the mail/{user}/ path on local delivery) plus '..'.
        // The '\' set also matches outbound.zig's validator so a webmail-accepted
        // address never fails the outbound backstop.
        if (c <= 0x20 or c == 0x7f or c == ',' or c == ';' or c == ':' or c == '"' or c == '<' or c == '>' or c == '/' or c == '\\') return false;
    }
    if (std.mem.indexOf(u8, a, "..") != null) return false;
    // Must look like an address (one @, non-empty local/domain, no leading dot).
    const at = std.mem.indexOfScalar(u8, a, '@') orelse return false;
    if (at == 0 or at == a.len - 1) return false;
    if (a[0] == '.') return false;
    if (std.mem.indexOfScalarPos(u8, a, at + 1, '@') != null) return false;
    return true;
}

/// A Maildir user (local-part) must be a single safe path component — defense in
/// depth for the mail/{user}/... path even though isSafeAddress already guards.
pub fn isSafeLocalPart(user: []const u8) bool {
    if (user.len == 0 or user.len > 256) return false;
    if (user[0] == '.') return false;
    for (user) |c| {
        if (c == '/' or c == '\\' or c == 0) return false;
    }
    if (std.mem.indexOf(u8, user, "..") != null) return false;
    return true;
}

/// One reservation covers the actual envelope, including blind copies.
pub fn distinctRecipients(a: std.mem.Allocator, groups: []const []const []const u8) ![][]const u8 {
    var recipients: std.ArrayList([]const u8) = .empty;
    var seen = std.StringHashMap(void).init(a);
    defer {
        var keys = seen.keyIterator();
        while (keys.next()) |key| a.free(key.*);
        seen.deinit();
    }
    errdefer recipients.deinit(a);
    for (groups) |group| {
        for (group) |address| {
            if (!isSafeAddress(address)) return error.InvalidAddress;
            const key = try std.ascii.allocLowerString(a, address);
            const entry = seen.getOrPut(key) catch |err| {
                a.free(key);
                return err;
            };
            if (entry.found_existing) {
                a.free(key);
                continue;
            }
            try recipients.append(a, address);
        }
    }
    return recipients.toOwnedSlice(a);
}

fn localMailbox(a: std.mem.Allocator, cfg: Delivery, recipient: []const u8) !?[]const u8 {
    if (!isSafeAddress(recipient)) return error.InvalidAddress;
    if (!routing.isLocal(recipient, cfg.hostname, cfg.mail_config)) return null;
    const user = routing.resolveMailbox(a, cfg.db, cfg.mail_config, recipient) catch |err| switch (err) {
        error.UnknownLocalMailbox => return error.InvalidAddress,
        else => return err,
    };
    errdefer a.free(user);
    if (!isSafeLocalPart(user)) return error.InvalidAddress;
    if (cfg.local_hosted_only) {
        if (cfg.db == null or (try cfg.db.?.hostedLimits(user)) == null) {
            a.free(user);
            return null;
        }
    }
    if (cfg.db) |db| if (!(try db.userExists(user))) return error.InvalidAddress;
    return user;
}

pub fn deliverNotice(a: std.mem.Allocator, cfg: Delivery, from: []const u8, rcpt: []const u8, raw: []const u8, mailbox_id: ?i64) !void {
    if (mailbox_id != null and cfg.db == null) return error.DatabaseUnavailable;
    const result = try dispatch(a, cfg, from, &.{rcpt}, raw, .{ .account_notice = true, .recipient_id = mailbox_id });
    defer a.free(result.failed);
    if (result.first_error) |err| return err;
}

pub const SentCopy = struct {
    path: []const u8,
    bytes: []const u8,
};

const RawSubmission = struct {
    mailbox: []const u8,
    from: []const u8,
    recipients: []const []const u8,
    raw: []const u8,
    sent: ?SentCopy = null,
    receipt: ?database.Database.ActiveSyncReceipt = null,
    ews_draft: ?database.Database.EwsDraftSend = null,
    native_reply: ?NativeReply = null,
};

pub const NativeReply = struct {
    archive: []const u8,
    source: database.Database.TeamReplySource,
    wire_id: []const u8,
};

/// A source supplied by an authenticated native reply operation can fill in
/// missing reply metadata. Preserve conflicting client-provided fields and
/// leave that submission outside the grant.
pub fn prepareNativeReply(a: std.mem.Allocator, db: *database.Database, user: []const u8, archive: []const u8, recipients: []const []const u8, source: database.Database.TeamReplySource, hostname: []const u8, max_bytes: usize) !?NativeReply {
    const info = try thread_ids.parse(a, archive);
    if (info.automatic or info.message_id_fields > 1 or info.reply_fields > 1) return null;
    if (info.reply_parent) |parent| {
        if (!std.mem.eql(u8, parent, source.wire_id)) return null;
    } else if (info.reply_fields != 0 or info.parents.len != 0) return null;
    if (info.own) |id| {
        if (std.mem.eql(u8, id, source.wire_id)) return null;
    } else if (info.message_id_fields != 0) return null;
    const audience = try std.json.Stringify.valueAlloc(a, recipients, .{});
    if (!try db.canFollowNativeSent(user, source, audience)) return null;
    const wire_id = info.own orelse blk: {
        for (hostname) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '.' and byte != '-') return null;
        if (hostname.len == 0 or hostname.len > 253) return null;
        const id = routing.newId();
        break :blk try std.fmt.allocPrint(a, "<{s}@{s}>", .{ &id, hostname });
    };
    var extra: std.ArrayList(u8) = .empty;
    if (info.own == null) try extra.print(a, "Message-ID: {s}\r\n", .{wire_id});
    if (info.reply_parent == null) try extra.print(a, "In-Reply-To: {s}\r\n", .{source.wire_id});
    if (archive.len > max_bytes or extra.items.len > max_bytes - archive.len) return null;
    return .{
        .archive = if (extra.items.len == 0) archive else try std.mem.concat(a, u8, &.{ extra.items, archive }),
        .source = source,
        .wire_id = wire_id,
    };
}

pub const DispatchOptions = struct {
    sender: ?[]const u8 = null,
    delegated_sender_id: ?i64 = null,
    linked_account: ?[]const u8 = null,
    shared_reply: ?shared_inbox.ReplyDelivery = null,
    calendar_reply: ?@import("../api/webmail_calendar_invite.zig").Revision = null,
    sent: ?SentCopy = null,
    interactive_id: ?[]const u8 = null,
    receipt: ?database.Database.ActiveSyncReceipt = null,
    ews_draft: ?database.Database.EwsDraftSend = null,
    account_notice: bool = false,
    recipient_id: ?i64 = null,
    team_reply_submission: ?database.Database.TeamReplySource = null,
    native_reply_wire_id: ?[]const u8 = null,
};

pub const DispatchResult = struct {
    delivered: usize = 0,
    failed: []const []const u8,
    first_error: ?anyerror = null,
    first_limit_error: ?anyerror = null,
    unknown: []const []const u8 = &.{},
    notice: ?[]const u8 = null,
};

pub fn dispatchExternal(a: std.mem.Allocator, cfg: Delivery, provider: smtp_provider.Config, from: []const u8, recipients: []const []const u8, raw: []const u8, sender: []const u8, id: []const u8, identity: database.Database.ExternalSenderAdmission, linked_account: ?[]const u8, team_reply_submission: ?database.Database.TeamReplySource) !DispatchResult {
    const db = cfg.db orelse return error.DatabaseUnavailable;
    if (!isSafeAddress(from) or recipients.len == 0) return error.InvalidAddress;
    const targets = try a.alloc(database.Database.DeliveryTarget, recipients.len);
    defer a.free(targets);
    for (recipients, targets) |recipient, *target| {
        if (!isSafeAddress(recipient)) return error.InvalidAddress;
        target.* = .{ .recipient = recipient, .interactive_remote = true };
    }
    try db.acceptDelivery(.{
        .id = id,
        .from = from,
        .author = from,
        .mime = raw,
        .accepted_at = time_compat.timestamp(),
        .accepted_ms = time_compat.milliTimestamp(),
        .targets = targets,
        .sender = sender,
        .external_sender = identity,
        .linked_account = linked_account,
        .charge_recipients = recipients.len,
        .team_reply_submission = team_reply_submission,
    });
    var notice: ?[]const u8 = null;
    smtp_provider.submit(a, provider, .{ .db = db, .delivery_id = id }, cfg.hostname, from, recipients, raw) catch |err| {
        notice = switch (err) {
            error.ProviderUnavailable => "The external SMTP provider did not complete this submission.",
            error.ProviderTlsUnavailable => "The external SMTP provider could not be verified over TLS.",
            error.ProviderAuthenticationFailed => "The external SMTP provider rejected authentication.",
            error.ProviderEnvelopeRejected => "The external SMTP provider refused the sender or recipients.",
            error.ProviderMessageRejected => "The external SMTP provider rejected the message.",
            error.ProviderDeliveryUnknown => "The external SMTP provider did not confirm acceptance. Review this delivery before retrying.",
            else => return err,
        };
    };
    const outcome = (try db.interactiveDelivery(a, id)) orelse return error.ProviderUnavailable;
    return .{ .delivered = outcome.delivered, .failed = outcome.failed, .unknown = outcome.unknown, .notice = notice };
}

/// Check and admit all local recipients as one journaled operation. Remote
/// app submissions keep their synchronous delivery results for partial-send UI.
pub fn dispatch(a: std.mem.Allocator, cfg: Delivery, from: []const u8, recipients: []const []const u8, raw: []const u8, options: DispatchOptions) !DispatchResult {
    if (recipients.len == 0) return error.NoRecipients;
    if ((options.interactive_id != null or options.delegated_sender_id != null or options.shared_reply != null) and cfg.db == null) return error.DatabaseUnavailable;
    const failed = try a.alloc([]const u8, recipients.len);
    errdefer a.free(failed);
    const errors = try a.alloc(?anyerror, recipients.len);
    defer a.free(errors);
    @memset(errors, null);
    var scratch = std.heap.ArenaAllocator.init(a);
    defer scratch.deinit();
    const temp = scratch.allocator();
    const remote = try temp.alloc(bool, recipients.len);
    @memset(remote, false);
    if (cfg.db) |db| {
        const generated_id = routing.newId();
        const id = options.interactive_id orelse &generated_id;
        try acceptLocal(temp, cfg, db, from, recipients, raw, options, id, remote, errors);
        routing.publish(a, db, id);
    } else {
        for (recipients, 0..) |recipient, i| {
            const user = localMailbox(temp, cfg, recipient) catch |err| {
                errors[i] = err;
                continue;
            };
            if (user) |mailbox| {
                writeMaildir(a, null, mailbox, "new", raw) catch |err| {
                    errors[i] = err;
                };
            } else remote[i] = true;
        }
    }
    var count: usize = 0;
    var result: DispatchResult = .{ .failed = undefined };
    for (recipients, remote, errors) |recipient, deliver_remote, local_error| {
        const failure: ?anyerror = if (deliver_remote) blk: {
            if (options.interactive_id) |id| try cfg.db.?.checkpointInteractiveRecipient(id, recipient, .starting, false);
            outbound.deliverToRemote(a, from, recipient, raw, cfg.hostname, cfg.delivery_method, cfg.ses_region) catch |err| break :blk err;
            break :blk null;
        } else local_error;
        if (deliver_remote) if (options.interactive_id) |id| {
            try cfg.db.?.checkpointInteractiveRecipient(id, recipient, if (failure == null) .delivered else .failed, options.native_reply_wire_id != null);
        };
        if (failure) |err| {
            std.log.warn("Message delivery to {s} failed: {}", .{ recipient, err });
            if (result.first_error == null) result.first_error = err;
            if (result.first_limit_error == null) switch (err) {
                error.HostedStorageFull, error.HostedRecipientDisabled, error.HostedRecipientReadOnly, error.HostedRecipientExpired => result.first_limit_error = err,
                else => {},
            };
            failed[count] = recipient;
            count += 1;
        } else result.delivered += 1;
    }
    result.failed = try a.realloc(failed, count);
    return result;
}

fn acceptLocal(a: std.mem.Allocator, cfg: Delivery, db: *database.Database, from: []const u8, recipients: []const []const u8, raw: []const u8, options: DispatchOptions, id: []const u8, remote: []bool, errors: []?anyerror) !void {
    db.lockMailboxes();
    defer db.unlockMailboxes();
    const now = time_compat.timestamp();
    if (options.sender) |sender| {
        if (options.ews_draft) |draft| {
            if (try db.ewsSendReceipt(a, sender, draft) != null or
                try ews_drafts.replay(db, sender, database.maildirBaseName(std.fs.path.basename(draft.path)), &draft.revision, draft.save_copy))
                return error.EwsDraftAlreadyAccepted;
            const file = message_refs.fileFingerprint(a, draft.path) catch return error.StaleDraft;
            if (!std.mem.eql(u8, file.fingerprint, draft.fingerprint)) return error.StaleDraft;
        }
        if (options.receipt) |receipt| {
            if (try db.activeSyncAccepted(sender, receipt, now)) return error.MessagePreviouslySent;
        }
        _ = try db.checkHostedSend(sender, recipients.len, now);
    }
    var sent_written = false;
    var native_sent_reply: ?database.Database.NativeSentReply = null;
    errdefer if (sent_written) fs_compat.cwd().deleteFile(options.sent.?.path) catch {};
    if (options.sent) |copy| {
        try hosted_limits.checkStorage(db, options.sender.?, copy.bytes.len, null);
        try durable_maildir.write(a, copy.path, copy.bytes);
        sent_written = true;
        if (options.native_reply_wire_id) |wire_id| {
            if (message_refs.fileStamp(a, copy.path) catch null) |stamp| native_sent_reply = .{
                .basename = database.maildirBaseName(std.fs.path.basename(copy.path)),
                .stamp = stamp,
                .revision = message_refs.digest(copy.bytes),
                .wire_id = wire_id,
            };
        }
    }

    const identity = try routing.SenderIdentity.fromHeaders(a, raw, true);
    var plan: routing.Plan = .{
        .allocator = a,
        .db = db,
        .bytes = raw.len,
        .raw = raw,
        .junk_folder = if (cfg.mail_config) |config| config.junkFolder() else "Junk",
        .automatic_category = if (identity.verified) routing.categories.classify(raw) else null,
    };
    for (recipients, 0..) |recipient, i| {
        const user = localMailbox(a, cfg, recipient) catch |err| switch (err) {
            error.InvalidAddress => {
                errors[i] = err;
                try plan.add(.{ .recipient = recipient, .refusal = "invalid_recipient" });
                continue;
            },
            else => return err,
        };
        if (options.recipient_id) |expected| {
            const current = if (user) |mailbox| try db.enabledMailboxId(mailbox) else null;
            if (current != expected) return error.InvalidAddress;
        }
        if (user) |mailbox| {
            var target: routing.Target = .{ .recipient = recipient, .mailbox = mailbox, .folder = "new" };
            if (!options.account_notice) try plan.classify(&target, identity);
            plan.addLocal(target) catch |err| {
                target.refusal = switch (err) {
                    error.HostedStorageFull => "recipient_storage_full",
                    error.HostedRecipientDisabled => "recipient_disabled",
                    error.HostedRecipientReadOnly => "recipient_read_only",
                    error.HostedRecipientExpired => "recipient_expired",
                    error.InvalidMailboxPath => "invalid_recipient",
                    else => return err,
                };
                errors[i] = err;
                try plan.add(target);
            };
        } else {
            remote[i] = true;
            if (options.interactive_id != null) try plan.add(.{ .recipient = recipient, .interactive_remote = true });
        }
    }
    const primary_count = plan.targets.items.len;
    if (!options.account_notice) {
        for (0..primary_count) |i| {
            const target = plan.targets.items[i];
            if (target.refusal == null and !target.interactive_remote and target.forward_allowed) try plan.forward(i, from, cfg.hostname, cfg.mail_config, identity, target.recipient);
        }
        try plan.vacationReplies(primary_count, from, cfg.hostname, cfg.mail_config, identity, now);
    }
    try db.acceptDelivery(.{
        .id = id,
        .from = from,
        .author = identity.author,
        .verified_author = identity.verified,
        .mime = raw,
        .accepted_at = now,
        .accepted_ms = time_compat.milliTimestamp(),
        .targets = plan.targets.items,
        .sender = options.sender,
        .delegated_sender_id = options.delegated_sender_id,
        .linked_account = options.linked_account,
        .shared_reply = options.shared_reply,
        .calendar_reply = options.calendar_reply,
        .charge_recipients = recipients.len,
        .receipt = options.receipt,
        .ews_draft_send = options.ews_draft,
        .team_reply_submission = options.team_reply_submission,
        .native_sent_reply = native_sent_reply,
    });
}

fn ewsSendResult(result: database.Database.EwsSendResult) !void {
    return switch (result) {
        .delivered => {},
        .partial => error.PartialDelivery,
        .storage_full => error.HostedStorageFull,
        .disabled => error.HostedRecipientDisabled,
        .failed, .uncertain => error.EwsDeliveryUnconfirmed,
    };
}

/// An admitted draft has an authoritative delivery journal. A lost response
/// can be recovered from it without dispatching or charging the envelope again.
pub fn replayEwsDraft(a: std.mem.Allocator, db: *database.Database, user: []const u8, draft: database.Database.EwsDraftSend) !bool {
    const receipt = (try db.ewsSendReceipt(a, user, draft)) orelse
        return ews_drafts.replay(db, user, database.maildirBaseName(std.fs.path.basename(draft.path)), &draft.revision, draft.save_copy);
    if (receipt.save_copy != draft.save_copy) return error.EwsSendSettingsChanged;
    if (receipt.result) |result| {
        try ewsSendResult(result);
        finalizeEwsDraft(a, db, receipt.delivery_id);
        return true;
    }
    const recovery = (try db.interactiveDelivery(a, receipt.delivery_id)) orelse return error.EwsDeliveryUnconfirmed;
    if (recovery.unknown.len != 0 or recovery.unattempted) return error.EwsDeliveryUnconfirmed;
    const result: database.Database.EwsSendResult = if (recovery.delivered != 0)
        (if (recovery.failed.len == 0) .delivered else .partial)
    else if (recovery.refused_for_disabled)
        .disabled
    else if (recovery.refused_for_limit)
        .storage_full
    else
        .failed;
    try db.finishEwsDraftSend(receipt.delivery_id, result);
    try ewsSendResult(result);
    finalizeEwsDraft(a, db, receipt.delivery_id);
    return true;
}

fn finalizeEwsDraft(a: std.mem.Allocator, db: *database.Database, id: []const u8) void {
    ews_drafts.finalize(a, db, id) catch |err| std.log.warn("EWS draft finalization will be retried: {}", .{err});
}

pub fn sendRaw(a: std.mem.Allocator, cfg: Delivery, message: RawSubmission) !void {
    const db = cfg.db orelse return error.DatabaseUnavailable;
    // Eligibility stays tied to the approved MIME, including absence of a
    // blind envelope, and to the requested Sent copy.
    const native = if (message.native_reply) |reply| candidate: {
        const copy = message.sent orelse break :candidate null;
        if (!std.mem.eql(u8, copy.bytes, reply.archive) or !std.mem.eql(u8, message.raw, reply.archive)) break :candidate null;
        break :candidate reply;
    } else null;
    const journaled = native != null or message.ews_draft != null;
    const delivery_id = if (journaled) routing.newId() else undefined;
    const result = dispatch(a, cfg, message.from, message.recipients, message.raw, .{
        .sender = message.mailbox,
        .sent = message.sent,
        .receipt = message.receipt,
        .ews_draft = message.ews_draft,
        .interactive_id = if (journaled) &delivery_id else null,
        .team_reply_submission = if (native) |reply| reply.source else null,
        .native_reply_wire_id = if (native) |reply| reply.wire_id else null,
    }) catch |err| {
        if (err == error.EwsDraftAlreadyAccepted and try replayEwsDraft(a, db, message.mailbox, message.ews_draft.?)) return;
        return err;
    };
    defer a.free(result.failed);
    if (result.delivered == 0) {
        if (message.sent) |copy| fs_compat.cwd().deleteFile(copy.path) catch {};
    }
    if (message.ews_draft != null) {
        const outcome: database.Database.EwsSendResult = if (result.delivered != 0)
            (if (result.failed.len == 0) .delivered else .partial)
        else if (result.first_error) |err| switch (err) {
            error.HostedStorageFull => .storage_full,
            error.HostedRecipientDisabled, error.HostedRecipientExpired => .disabled,
            else => .failed,
        } else .failed;
        try db.finishEwsDraftSend(&delivery_id, outcome);
        try ewsSendResult(outcome);
        finalizeEwsDraft(a, db, &delivery_id);
        return;
    }
    if (result.delivered == 0) {
        return result.first_error orelse error.NoRecipients;
    }
    if (result.failed.len > 0) return error.PartialDelivery;
}

pub fn maildirPath(a: std.mem.Allocator, user: []const u8, subdir: []const u8, suffix: []const u8) ![]const u8 {
    if (!isSafeLocalPart(user)) return error.InvalidAddress;
    const dir = try std.fmt.allocPrint(a, "mail/{s}/{s}", .{ user, subdir });
    defer a.free(dir);
    try fs_compat.cwd().makePath(dir);
    const seq = nameSeq.fetchAdd(1, .monotonic);
    return std.fmt.allocPrint(a, "{s}/{d}.{d}.submission.eml{s}", .{ dir, time_compat.milliTimestamp(), seq, suffix });
}

pub fn writeMaildir(allocator: std.mem.Allocator, db: ?*database.Database, user: []const u8, subdir: []const u8, raw: []const u8) !void {
    const path = try maildirPath(allocator, user, subdir, "");
    defer allocator.free(path);
    try hosted_limits.write(db, allocator, user, path, raw);
}

/// Reserve and file an Outbox Sent copy under its own durable delivery ID.
pub fn fileInteractiveSent(a: std.mem.Allocator, db: *database.Database, user: []const u8, id: []const u8, source: []const u8, raw: []const u8) !bool {
    {
        db.lockMailboxes();
        defer db.unlockMailboxes();
        if (!try db.hasAcceptedDelivery(id)) {
            try hosted_limits.checkStorage(db, user, raw.len, null);
            try db.acceptDelivery(.{
                .id = id,
                .from = user,
                .mime = raw,
                .accepted_at = time_compat.timestamp(),
                .accepted_ms = time_compat.milliTimestamp(),
                .targets = &.{.{ .recipient = user, .mailbox = user, .folder = "Sent" }},
                .sent_copy_of = source,
            });
        }
    }
    routing.publish(a, db, id);
    return db.hasFiledDelivery(id);
}

var nameSeq = std.atomic.Value(u64).init(0);
