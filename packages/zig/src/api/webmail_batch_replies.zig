//! Queue a reviewed set of independent replies from one mailbox. Recipient
//! addresses and thread headers always come from the mailbox's own messages.
const std = @import("std");
const database = @import("../storage/database.zig");
const message_refs = @import("../storage/message_refs.zig");
const addresses = @import("../message/submission.zig");
const thread_ids = @import("../message/thread_ids.zig");
const time = @import("../core/time_compat.zig");
const compose = @import("webmail_compose.zig");
const maildir = @import("webmail_maildir.zig");
const service_mod = @import("webmail_service.zig");
const store = @import("webmail_store.zig");

pub const max_replies = 20;
pub const kind = "reply-batch";

pub const Review = struct { reference: []const u8, to: []const u8, subject: []const u8 };
pub const Preview = struct { account: []const u8, from: []const u8, replies: []const Review, digest: []const u8 };
pub const Request = struct {
    batchId: []const u8,
    references: []const []const u8,
    digest: []const u8,
    text: []const u8,
    delaySeconds: ?u32 = null,
};
pub const Receipt = struct { id: []const u8, sends: []const []const u8, dueAt: i64 };
const Ledger = struct { request_hash: []const u8, receipt: Receipt };
const Reply = struct {
    review: Review,
    in_reply_to: []const u8,
    references: []const u8,
    content_revision: [64]u8,
    context: service_mod.MessageRef,
};
const Prepared = struct { preview: Preview, replies: []Reply };

pub fn validBatchId(id: []const u8) bool {
    return id.len == 32 and std.mem.indexOfNone(u8, id, "0123456789abcdef") == null;
}

pub fn preview(a: std.mem.Allocator, service: *service_mod.Service, user: []const u8, from: []const u8, references: []const []const u8) !Preview {
    service.db.lockMailboxes();
    defer service.db.unlockMailboxes();
    return (try prepareLocked(a, service, user, from, references)).preview;
}

fn prepareLocked(a: std.mem.Allocator, service: *service_mod.Service, user: []const u8, from: []const u8, references: []const []const u8) !Prepared {
    if (references.len == 0 or references.len > max_replies) return error.InvalidReplyBatchSelection;
    if (!compose.isSafeAddress(from)) return error.ReplyBatchAccountChanged;
    const replies = try a.alloc(Reply, references.len);
    const review = try a.alloc(Review, references.len);
    for (references, 0..) |reference, index| {
        if (!message_refs.valid(reference)) return error.InvalidReplyBatchSelection;
        for (references[0..index]) |prior| {
            if (std.mem.eql(u8, prior, reference)) return error.InvalidReplyBatchSelection;
        }
        const row = try prepareReplyLocked(a, service, user, from, reference);
        for (replies[0..index]) |prior| {
            if (std.mem.eql(u8, prior.in_reply_to, row.in_reply_to)) return error.DuplicateReplyBatchSource;
        }
        replies[index] = row;
        review[index] = row.review;
    }
    const input = try service_mod.json(a, .{ .account = user, .from = from, .replies = replies });
    const digest = message_refs.digest(input);
    return .{
        .preview = .{ .account = user, .from = from, .replies = review, .digest = try a.dupe(u8, &digest) },
        .replies = replies,
    };
}

fn prepareReplyLocked(a: std.mem.Allocator, service: *service_mod.Service, user: []const u8, from: []const u8, reference: []const u8) !Reply {
    var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer scratch.deinit();
    const b = scratch.allocator();
    const source = try maildir.resolveVersioned(b, service.db, user, reference);
    const folder = source.locator.folder;
    const flags = maildir.flagsFrom(source.name);
    if (!maildir.isPersonalFolder(folder) or flags.deleted or flags.draft or
        std.ascii.eqlIgnoreCase(folder, "Sent") or std.ascii.eqlIgnoreCase(folder, "Trash") or
        std.ascii.eqlIgnoreCase(folder, "Junk") or std.ascii.eqlIgnoreCase(folder, service.junkFolder()))
        return error.ReplyBatchSourceUnavailable;
    const ids = try thread_ids.parse(b, source.raw);
    const message_id = ids.own orelse return error.ReplyBatchSourceUnavailable;
    const reply_to = try maildir.mimeHeader(b, source.raw, "Reply-To");
    const sender = if (reply_to.len > 0) reply_to else try maildir.mimeHeader(b, source.raw, "From");
    const to = addresses.mailbox(sender) catch return error.ReplyBatchRecipientUnavailable;
    if (!compose.isSafeAddress(to) or !std.unicode.utf8ValidateSlice(to) or std.ascii.eqlIgnoreCase(to, from))
        return error.ReplyBatchRecipientUnavailable;
    const original = try maildir.mimeHeader(b, source.raw, "Subject");
    if (original.len > 512 or !compose.isSafeHeaderValue(original) or !std.unicode.utf8ValidateSlice(original))
        return error.ReplyBatchSourceUnavailable;
    const subject = if (std.ascii.startsWithIgnoreCase(original, "Re:")) try a.dupe(u8, original) else try std.fmt.allocPrint(a, "Re: {s}", .{if (original.len > 0) original else "(No subject)"});

    // Leave room on the RFC 5322 header line, keeping the newest ancestors.
    var first = ids.parents.len;
    var length = message_id.len;
    while (first > 0 and length + 1 + ids.parents[first - 1].len <= 900) {
        first -= 1;
        length += 1 + ids.parents[first].len;
    }
    var chain: std.ArrayList(u8) = .empty;
    for (ids.parents[first..]) |id| {
        if (std.mem.eql(u8, id, message_id)) continue;
        try chain.appendSlice(a, id);
        try chain.append(a, ' ');
    }
    try chain.appendSlice(a, message_id);
    return .{
        .review = .{ .reference = reference, .to = try a.dupe(u8, to), .subject = subject },
        .in_reply_to = try a.dupe(u8, message_id),
        .references = try chain.toOwnedSlice(a),
        .content_revision = source.version.content_revision,
        .context = .{ .uid = source.locator.uid, .folder = try a.dupe(u8, folder), .reference = reference },
    };
}

fn loadLedger(a: std.mem.Allocator, db: *database.Database, user: []const u8, id: []const u8) !Ledger {
    const row = try store.get(a, db, user, kind, id);
    return std.json.parseFromSliceLeaky(Ledger, a, row.payload, .{});
}

pub fn status(a: std.mem.Allocator, db: *database.Database, user: []const u8, id: []const u8) !Receipt {
    if (!validBatchId(id)) return store.StoreError.NotFound;
    return (try loadLedger(a, db, user, id)).receipt;
}

pub fn queue(a: std.mem.Allocator, service: *service_mod.Service, user: []const u8, from: []const u8, request: Request, now: i64) !Receipt {
    if (!validBatchId(request.batchId) or request.digest.len != 64 or request.text.len > 256 * 1024 or
        !std.unicode.utf8ValidateSlice(request.text) or std.mem.trim(u8, request.text, " \t\r\n").len == 0)
        return error.InvalidReplyBatch;
    const delay = request.delaySeconds orelse service.config.undo_send_seconds;
    if (delay > 30) return error.InvalidReplyBatch;
    for (request.text) |byte| {
        if (byte < 32 and byte != '\r' and byte != '\n' and byte != '\t') return error.InvalidReplyBatch;
    }
    const hash = message_refs.digest(try service_mod.json(a, request));
    service.mutations.lock();
    defer service.mutations.unlock();
    if (loadLedger(a, service.db, user, request.batchId)) |existing| {
        if (!std.mem.eql(u8, existing.request_hash, &hash)) return error.ReplyBatchConflict;
        return existing.receipt;
    } else |err| if (err != store.StoreError.NotFound) return err;

    service.db.lockMailboxes();
    defer service.db.unlockMailboxes();
    const prepared = try prepareLocked(a, service, user, from, request.references);
    if (!std.mem.eql(u8, prepared.preview.digest, request.digest)) return error.ReplyBatchPreviewChanged;
    const ids = try a.alloc([]const u8, prepared.replies.len);
    const rows = try a.alloc(store.Record, ids.len);
    const due_at = now + delay;
    const cutoff = time.milliTimestamp();
    for (prepared.replies, 0..) |reply, i| {
        const id = try std.fmt.allocPrint(a, "{s}-{d}", .{ request.batchId, i + 1 });
        const to = try a.dupe([]const u8, &.{reply.review.to});
        const msg = compose.Message{
            .from = from,
            .to = to,
            .subject = reply.review.subject,
            .text_body = request.text,
            .in_reply_to = reply.in_reply_to,
            .references = reply.references,
        };
        var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer scratch.deinit();
        const raw = try compose.buildMime(scratch.allocator(), msg, now, "<validation@localhost>");
        if (raw.len > service.config.max_message_bytes) return service_mod.ServiceError.AttachmentLimit;
        const doc: service_mod.Outbox = .{
            .message = .{
                .sendId = id,
                .to = to,
                .subject = msg.subject,
                .text = msg.text_body,
                .inReplyTo = msg.in_reply_to,
                .references = msg.references,
                .replyContext = reply.context,
                .delaySeconds = delay,
            },
            .reply_cutoff_ms = cutoff,
            .expected_from = from,
        };
        ids[i] = id;
        rows[i] = .{
            .username = user,
            .kind = "outbox",
            .id = id,
            .payload = try service_mod.json(a, doc),
            .state = "pending",
            .revision = 0,
            .due_at = due_at,
            .expires_at = 0,
        };
    }
    const receipt: Receipt = .{ .id = request.batchId, .sends = ids, .dueAt = due_at };
    const ledger: store.Record = .{
        .username = user,
        .kind = kind,
        .id = request.batchId,
        .payload = try service_mod.json(a, .{ .request_hash = @as([]const u8, &hash), .receipt = receipt }),
        .state = "queued",
        .revision = 0,
        .due_at = 0,
        .expires_at = due_at + store.terminal_retention,
    };
    const budget = try service.hostedOutboxBudget(user);
    store.enqueueReplyBatch(service.db, from, ledger, rows, budget) catch |err| switch (err) {
        store.StoreError.OutboxStorageLimit => {
            try store.sweep(service.db, now, user);
            try store.enqueueReplyBatch(service.db, from, ledger, rows, budget);
        },
        else => return err,
    };
    return receipt;
}
