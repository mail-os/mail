//! Mailbox operations shared by HTTP handlers and the persistent outbox worker.
//! Draft metadata preserves unfinished recipient entry separately from safe MIME
//! headers. Undo receipts are server-owned, expiring, and bound to one account.
const std = @import("std");
const database = @import("../storage/database.zig");
const auth_mod = @import("../auth/auth.zig");
const core_config = @import("../core/config.zig");
const time = @import("../core/time_compat.zig");
const mutex = @import("../core/mutex_compat.zig");
const maildir = @import("webmail_maildir.zig");
const compose = @import("webmail_compose.zig");
const store = @import("webmail_store.zig");

pub const ServiceError = error{ InvalidPayload, AttachmentLimit, InvalidAttachment, Conflict, NotFound, InvalidAction, MessageChanged };
pub const Payload = struct {
    to: []const []const u8 = &.{},
    cc: []const []const u8 = &.{},
    bcc: []const []const u8 = &.{},
    subject: []const u8 = "",
    text: []const u8 = "",
    html: []const u8 = "",
    inReplyTo: []const u8 = "",
    references: []const u8 = "",
    draftUid: ?i64 = null,
    draftId: ?[]const u8 = null,
    draftRevision: i64 = 0,
    saveToken: []const u8 = "",
    sendId: ?[]const u8 = null,
    delaySeconds: ?u32 = null,
    recipientInputs: struct { to: []const u8 = "", cc: []const u8 = "", bcc: []const u8 = "" } = .{},
    recipientLabels: struct { to: []const []const u8 = &.{}, cc: []const []const u8 = &.{}, bcc: []const []const u8 = &.{} } = .{},
    replyContext: ?MessageRef = null,
    attachments: []const struct {
        filename: []const u8 = "",
        contentType: []const u8 = "application/octet-stream",
        size: usize = 0,
        data: []const u8 = "",
        uploadId: ?[]const u8 = null,
    } = &.{},
};
pub const Draft = struct { uid: i64, folder: []const u8 = "Drafts", message: Payload };
pub const DraftAck = struct { ok: bool = true, uid: i64, draftId: []const u8, revision: i64 };
pub const MessageRef = struct { uid: i64, folder: []const u8 };
pub const BulkAction = enum { move, trash, read, unread, flag, unflag, purge };
pub const BulkPayload = struct { action: BulkAction, messages: []const MessageRef, folder: []const u8 = "Archive" };
pub const ActionResult = struct { uid: i64, folder: []const u8, ok: bool, new_uid: ?i64 = null, new_folder: ?[]const u8 = null, error_code: ?[]const u8 = null };
const UndoEntry = struct { original: MessageRef, current: MessageRef, before: maildir.Flags, after: maildir.Flags, fingerprint: []const u8, moved: bool };
const UndoDocument = struct { entries: []const UndoEntry, results: []const ActionResult = &.{} };
pub const BulkResult = struct { ok: bool, results: []const ActionResult, undoId: ?[]const u8 = null, expiresAt: ?i64 = null };
pub const Outbox = struct { message: Payload, result: ?compose.SendResult = null, error_message: ?[]const u8 = null };
pub const Limits = struct { maxFileBytes: usize, maxTotalBytes: usize, maxCount: usize, maxMessageBytes: usize, undoSendSeconds: u32 };

pub const Config = struct {
    hostname: []const u8 = "localhost",
    delivery_method: core_config.DeliveryMethod = .direct,
    ses_region: []const u8 = "us-east-1",
    mail_config: ?*const core_config.Config = null,
    max_file_bytes: usize = 20 * 1024 * 1024,
    max_total_bytes: usize = 20 * 1024 * 1024,
    max_count: usize = 20,
    max_message_bytes: usize = 25 * 1024 * 1024,
    undo_send_seconds: u32 = 10,
};

pub const Service = struct {
    db: *database.Database,
    auth: *auth_mod.AuthBackend,
    config: Config,
    mutations: mutex.Mutex = .{},

    pub fn init(db: *database.Database, auth: *auth_mod.AuthBackend, config: Config) !Service {
        try store.initSchema(db);
        return .{ .db = db, .auth = auth, .config = config };
    }

    pub fn limits(self: *Service, user: []const u8) !Limits {
        const account = try store.accountAttachmentLimits(self.db, user);
        // Reserve space for text, MIME headers, base64 line wrapping and framing.
        const mime_budget = (self.config.max_message_bytes -| 512 * 1024) / 100 * 70;
        const total = @min(self.config.max_total_bytes, mime_budget);
        return .{
            .maxFileBytes = @min(@min(self.config.max_file_bytes, total), if (account.file > 0) @as(usize, @intCast(account.file)) else total),
            .maxTotalBytes = @min(total, if (account.total > 0) @as(usize, @intCast(account.total)) else total),
            .maxCount = self.config.max_count,
            .maxMessageBytes = self.config.max_message_bytes,
            .undoSendSeconds = self.config.undo_send_seconds,
        };
    }

    pub fn payloadMessage(self: *Service, a: std.mem.Allocator, payload: Payload, user: []const u8, email: []const u8, draft: bool) !compose.Message {
        const allowed = try self.limits(user);
        if (payload.attachments.len > allowed.maxCount or payload.to.len + payload.cc.len + payload.bcc.len > 100 or payload.subject.len > 2000 or payload.text.len > 256 * 1024 or payload.html.len > 256 * 1024) return ServiceError.InvalidPayload;
        for ([_][]const u8{ payload.recipientInputs.to, payload.recipientInputs.cc, payload.recipientInputs.bcc }) |input| if (input.len > 2000) return ServiceError.InvalidPayload;
        if (!draft and (payload.recipientInputs.to.len > 0 or payload.recipientInputs.cc.len > 0 or payload.recipientInputs.bcc.len > 0)) return ServiceError.InvalidPayload;
        var attachments: std.ArrayList(compose.Attachment) = .empty;
        var total: usize = 0;
        for (payload.attachments) |attachment| {
            var name = attachment.filename;
            var content_type = attachment.contentType;
            const bytes = if (attachment.uploadId) |id| blk: {
                if (!store.validId(id)) return ServiceError.InvalidAttachment;
                const upload = try store.getUpload(a, self.db, user, id);
                name = upload.filename;
                content_type = upload.content_type;
                break :blk upload.data;
            } else blk: {
                const size = std.base64.standard.Decoder.calcSizeForSlice(attachment.data) catch return ServiceError.InvalidAttachment;
                if (size > allowed.maxFileBytes) return ServiceError.AttachmentLimit;
                const buffer = try a.alloc(u8, size);
                std.base64.standard.Decoder.decode(buffer, attachment.data) catch return ServiceError.InvalidAttachment;
                break :blk buffer;
            };
            if (!validFilename(name) or !validContentType(content_type)) return ServiceError.InvalidAttachment;
            total = std.math.add(usize, total, bytes.len) catch return ServiceError.AttachmentLimit;
            if (bytes.len > allowed.maxFileBytes or total > allowed.maxTotalBytes) return ServiceError.AttachmentLimit;
            try attachments.append(a, .{ .filename = name, .content_type = content_type, .data = bytes });
        }
        return .{
            .from = email,
            .to = if (draft) try validDraftAddresses(a, payload.to) else payload.to,
            .cc = if (draft) try validDraftAddresses(a, payload.cc) else payload.cc,
            .bcc = if (draft) try validDraftAddresses(a, payload.bcc) else payload.bcc,
            .subject = payload.subject,
            .text_body = payload.text,
            .html_body = payload.html,
            .in_reply_to = payload.inReplyTo,
            .references = payload.references,
            .attachments = try attachments.toOwnedSlice(a),
            .include_bcc = draft,
        };
    }

    pub fn saveDraft(self: *Service, a: std.mem.Allocator, user: []const u8, email: []const u8, payload: Payload) !DraftAck {
        self.mutations.lock();
        defer self.mutations.unlock();
        return self.saveDraftLocked(a, user, email, payload);
    }

    fn saveDraftLocked(self: *Service, a: std.mem.Allocator, user: []const u8, email: []const u8, payload: Payload) !DraftAck {
        return self.saveDraftState(a, user, email, payload, false);
    }

    fn saveDraftState(self: *Service, a: std.mem.Allocator, user: []const u8, email: []const u8, payload: Payload, resume_queued: bool) !DraftAck {
        const id = payload.draftId orelse try store.newId(a);
        if (!store.validId(id) or payload.draftRevision < 0 or payload.saveToken.len > 64) return ServiceError.InvalidPayload;
        const previous: ?store.Record = store.get(a, self.db, user, "draft", id) catch |err| blk: {
            if (err != store.StoreError.NotFound) return err;
            break :blk null;
        };
        var existing = payload.draftUid;
        var expected: i64 = 0;
        if (previous) |row| {
            const doc = try std.json.parseFromSlice(Draft, a, row.payload, .{ .ignore_unknown_fields = true });
            defer doc.deinit();
            if (!std.mem.eql(u8, doc.value.folder, "Drafts") or (!std.mem.eql(u8, row.state, "saved") and !(resume_queued and std.mem.eql(u8, row.state, "queued")))) return ServiceError.Conflict;
            if (row.revision != payload.draftRevision) {
                // A retried acknowledgement must not create a second draft.
                var retry = payload;
                retry.draftId = id;
                retry.draftUid = doc.value.uid;
                if (payload.saveToken.len > 0 and std.mem.eql(u8, payload.saveToken, doc.value.message.saveToken) and std.mem.eql(u8, try json(a, retry), try json(a, doc.value.message))) return .{ .uid = doc.value.uid, .draftId = id, .revision = row.revision };
                return ServiceError.Conflict;
            }
            existing = doc.value.uid;
            expected = row.revision;
        } else if (payload.draftRevision != 0) return ServiceError.Conflict;
        const msg = try self.payloadMessage(a, payload, user, email, true);
        const raw = try compose.buildMime(a, msg, time.timestamp(), try std.fmt.allocPrint(a, "<draft.{s}@{s}>", .{ id, self.config.hostname }));
        if (raw.len > self.config.max_message_bytes) return ServiceError.AttachmentLimit;
        const uid = try maildir.saveDraft(a, self.db, user, raw, existing);
        var saved = payload;
        saved.draftId = id;
        saved.draftUid = uid;
        const record = store.Record{ .username = user, .kind = "draft", .id = id, .payload = try json(a, Draft{ .uid = uid, .message = saved }), .state = "saved", .revision = expected, .due_at = 0, .expires_at = 0 };
        const revision = try store.put(self.db, record, expected);
        return .{ .uid = uid, .draftId = id, .revision = revision };
    }

    pub fn queue(self: *Service, a: std.mem.Allocator, user: []const u8, email: []const u8, payload: Payload, now: i64) !store.Record {
        self.mutations.lock();
        defer self.mutations.unlock();
        const id = payload.sendId orelse return ServiceError.InvalidPayload;
        if (!store.validId(id)) return ServiceError.InvalidPayload;
        const delay = payload.delaySeconds orelse self.config.undo_send_seconds;
        if (delay > 30) return ServiceError.InvalidPayload;
        const serialized = try json(a, Outbox{ .message = payload });
        if (store.get(a, self.db, user, "outbox", id)) |known| {
            const parsed = try std.json.parseFromSlice(Outbox, a, known.payload, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            if (!std.mem.eql(u8, try json(a, parsed.value.message), try json(a, payload))) return ServiceError.Conflict;
            return known;
        } else |err| if (err != store.StoreError.NotFound) return err;
        const msg = try self.payloadMessage(a, payload, user, email, false);
        if (msg.to.len + msg.cc.len + msg.bcc.len == 0) return compose.ComposeError.NoRecipients;
        for ([_][]const []const u8{ msg.to, msg.cc, msg.bcc }) |addresses| for (addresses) |address| if (!compose.isSafeAddress(address)) return compose.ComposeError.InvalidAddress;
        const raw = try compose.buildMime(a, msg, now, "<validation@localhost>");
        if (raw.len > self.config.max_message_bytes) return ServiceError.AttachmentLimit;
        if (payload.draftId) |draft_id| {
            const row = try store.get(a, self.db, user, "draft", draft_id);
            if (row.revision != payload.draftRevision or !std.mem.eql(u8, row.state, "saved")) return ServiceError.Conflict;
        }
        var row = store.Record{ .username = user, .kind = "outbox", .id = id, .payload = serialized, .state = "pending", .revision = 0, .due_at = now + delay, .expires_at = 0 };
        row.revision = try store.put(self.db, row, 0);
        if (payload.draftId) |draft_id| {
            var draft = try store.get(a, self.db, user, "draft", draft_id);
            draft.state = "queued";
            draft.revision = try store.put(self.db, draft, draft.revision);
        }
        return row;
    }

    pub fn cancel(self: *Service, a: std.mem.Allocator, user: []const u8, id: []const u8, now: i64) !store.Record {
        self.mutations.lock();
        defer self.mutations.unlock();
        const existing = try store.get(a, self.db, user, "outbox", id);
        if (std.mem.eql(u8, existing.state, "cancelled")) return existing;
        const row = try store.cancelSend(a, self.db, user, id, now);
        const doc = try std.json.parseFromSlice(Outbox, a, row.payload, .{ .ignore_unknown_fields = true });
        defer doc.deinit();
        if (doc.value.message.draftId) |draft_id| {
            var draft = store.get(a, self.db, user, "draft", draft_id) catch return row;
            if (std.mem.eql(u8, draft.state, "queued")) {
                draft.state = "saved";
                _ = try store.put(self.db, draft, draft.revision);
            }
        }
        return row;
    }

    pub fn dispatchDue(self: *Service, a: std.mem.Allocator, now: i64) !bool {
        var row = (try store.claimDue(a, self.db, now)) orelse return false;
        const parsed = try std.json.parseFromSlice(Outbox, a, row.payload, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();
        var doc = parsed.value;
        self.deliver(a, row.username, &doc) catch {
            row.state = "failed";
            doc.error_message = "Delivery failed. Review this message before retrying.";
        };
        if (doc.result) |result| row.state = if (result.failed.len == 0) (if (result.sent_saved) "sent" else "sent_unfiled") else (if (result.delivered > 0) "partial" else "failed");
        row.payload = try json(a, doc);
        row.expires_at = now + 7 * 86400;
        row.revision = try store.put(self.db, row, row.revision);
        self.finishDraft(a, row.username, doc) catch |err| {
            std.log.warn("webmail could not reconcile the draft after delivery: {}", .{err});
            doc.error_message = "Draft cleanup needs attention. Review the delivery result in Outbox before sending again.";
            row.payload = try json(a, doc);
            _ = try store.put(self.db, row, row.revision);
        };
        return true;
    }

    pub fn resolveUnknown(self: *Service, a: std.mem.Allocator, user: []const u8, id: []const u8, now: i64) !store.Record {
        self.mutations.lock();
        defer self.mutations.unlock();
        var row = try store.get(a, self.db, user, "outbox", id);
        if (std.mem.eql(u8, row.state, "resolved")) return row;
        if (!std.mem.eql(u8, row.state, "unknown")) return ServiceError.Conflict;
        const doc = try std.json.parseFromSlice(Outbox, a, row.payload, .{ .ignore_unknown_fields = true });
        defer doc.deinit();
        if (doc.value.message.draftId) |draft_id| {
            if (store.get(a, self.db, user, "draft", draft_id)) |previous| {
                var draft = previous;
                if (std.mem.eql(u8, draft.state, "queued")) {
                    draft.state = "saved";
                    _ = try store.put(self.db, draft, draft.revision);
                }
            } else |err| if (err != store.StoreError.NotFound) return err;
        }
        row.state = "resolved";
        row.expires_at = now + 7 * 86400;
        row.revision = try store.put(self.db, row, row.revision);
        return row;
    }

    fn deliver(self: *Service, a: std.mem.Allocator, user: []const u8, doc: *Outbox) !void {
        var account = try self.db.getUserByUsername(user);
        defer account.deinit(self.db.allocator);
        if (!account.enabled) return ServiceError.InvalidPayload;
        const msg = try self.payloadMessage(a, doc.message, user, account.email, false);
        doc.result = try compose.send(a, msg, .{ .hostname = self.config.hostname, .delivery_method = self.config.delivery_method, .ses_region = self.config.ses_region, .sender_user = user, .mail_config = self.config.mail_config, .auth = self.auth });
        if (doc.result.?.delivered > 0) {
            if (doc.message.replyContext) |context| {
                const replied = maildir.getMessage(a, self.db, user, context.folder, context.uid) catch return;
                var flags = replied.flags;
                flags.answered = true;
                _ = maildir.setFlags(a, self.db, user, context.folder, context.uid, flags) catch {};
            }
        }
    }

    fn finishDraft(self: *Service, a: std.mem.Allocator, user: []const u8, doc: Outbox) !void {
        const id = doc.message.draftId orelse return;
        self.mutations.lock();
        defer self.mutations.unlock();
        const row = store.get(a, self.db, user, "draft", id) catch return;
        if (!std.mem.eql(u8, row.state, "queued")) return;
        const draft = try std.json.parseFromSlice(Draft, a, row.payload, .{ .ignore_unknown_fields = true });
        defer draft.deinit();
        if (doc.result) |result| {
            if (result.failed.len == 0 and result.delivered > 0) {
                if (std.mem.eql(u8, draft.value.folder, "Drafts")) _ = try maildir.moveMessage(a, self.db, user, "Drafts", draft.value.uid, "Trash");
                try store.remove(self.db, user, "draft", id);
                return;
            }
        }
        if (!std.mem.eql(u8, draft.value.folder, "Drafts")) return ServiceError.Conflict;
        var retry = draft.value.message;
        if (doc.result) |result| {
            retry.recipientLabels.to = try failedLabels(a, retry.to, retry.recipientLabels.to, result.failed);
            retry.recipientLabels.cc = try failedLabels(a, retry.cc, retry.recipientLabels.cc, result.failed);
            retry.recipientLabels.bcc = try failedLabels(a, retry.bcc, retry.recipientLabels.bcc, result.failed);
            retry.to = try failedAddresses(a, retry.to, result.failed);
            retry.cc = try failedAddresses(a, retry.cc, result.failed);
            retry.bcc = try failedAddresses(a, retry.bcc, result.failed);
        }
        retry.draftRevision = row.revision;
        retry.saveToken = try store.newId(a);
        var account = try self.db.getUserByUsername(user);
        defer account.deinit(self.db.allocator);
        _ = try self.saveDraftState(a, user, account.email, retry, true);
    }

    pub fn updateDraftLocation(self: *Service, a: std.mem.Allocator, user: []const u8, original: MessageRef, current: ?MessageRef) !void {
        var row = store.findDraft(a, self.db, user, original.folder, original.uid) catch |err| {
            if (err == store.StoreError.NotFound) return;
            return err;
        };
        if (current) |location| {
            const parsed = try std.json.parseFromSlice(Draft, a, row.payload, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            var doc = parsed.value;
            doc.uid = location.uid;
            doc.folder = location.folder;
            doc.message.draftUid = location.uid;
            row.payload = try json(a, doc);
            _ = try store.put(self.db, row, row.revision);
        } else try store.remove(self.db, user, "draft", row.id);
    }

    pub fn bulk(self: *Service, a: std.mem.Allocator, user: []const u8, payload: BulkPayload, now: i64) !BulkResult {
        self.mutations.lock();
        defer self.mutations.unlock();
        if (payload.messages.len == 0 or payload.messages.len > 100) return ServiceError.InvalidPayload;
        if (payload.action == .move and !maildir.isValidFolderName(payload.folder)) return ServiceError.InvalidAction;
        // Preflight the complete selection, without retaining decoded attachments.
        for (payload.messages, 0..) |ref, index| {
            if (ref.uid < 1 or !maildir.isValidFolderName(ref.folder)) return ServiceError.InvalidPayload;
            if (payload.action == .purge and !std.mem.eql(u8, ref.folder, "Trash")) return ServiceError.InvalidAction;
            for (payload.messages[0..index]) |prior| if (prior.uid == ref.uid and std.mem.eql(u8, prior.folder, ref.folder)) return ServiceError.InvalidPayload;
            var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer scratch.deinit();
            _ = try maildir.rawMessage(scratch.allocator(), self.db, user, ref.folder, ref.uid);
        }
        var entries: std.ArrayList(UndoEntry) = .empty;
        var results: std.ArrayList(ActionResult) = .empty;
        var all_ok = true;
        for (payload.messages) |ref| {
            var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer scratch.deinit();
            const temp = scratch.allocator();
            const item = maildir.getMessage(temp, self.db, user, ref.folder, ref.uid) catch {
                all_ok = false;
                try results.append(a, .{ .uid = ref.uid, .folder = ref.folder, .ok = false, .error_code = "message_changed" });
                continue;
            };
            var after = item.flags;
            var destination = ref;
            const moved = payload.action == .move or payload.action == .trash;
            const action_ok = blk: {
                if (payload.action == .purge) {
                    maildir.deleteMessage(temp, self.db, user, ref.folder, ref.uid) catch break :blk false;
                    self.updateDraftLocation(a, user, ref, null) catch {};
                } else if (moved) {
                    destination.folder = if (payload.action == .trash) "Trash" else payload.folder;
                    destination.uid = maildir.moveMessage(temp, self.db, user, ref.folder, ref.uid, destination.folder) catch break :blk false;
                    self.updateDraftLocation(a, user, ref, destination) catch {};
                } else {
                    switch (payload.action) {
                        .read => after.seen = true,
                        .unread => after.seen = false,
                        .flag => after.flagged = true,
                        .unflag => after.flagged = false,
                        else => unreachable,
                    }
                    _ = maildir.setFlags(temp, self.db, user, ref.folder, ref.uid, after) catch break :blk false;
                }
                break :blk true;
            };
            if (action_ok and payload.action != .purge) {
                const raw = try maildir.rawMessage(temp, self.db, user, destination.folder, destination.uid);
                try entries.append(a, .{ .original = ref, .current = destination, .before = item.flags, .after = after, .fingerprint = try fingerprint(a, raw), .moved = moved });
            }
            all_ok = all_ok and action_ok;
            try results.append(a, .{ .uid = ref.uid, .folder = ref.folder, .ok = action_ok, .new_uid = if (action_ok) destination.uid else null, .new_folder = if (action_ok) destination.folder else null, .error_code = if (action_ok) null else "operation_failed" });
        }
        var response = BulkResult{ .ok = all_ok, .results = try results.toOwnedSlice(a) };
        if (entries.items.len > 0) {
            const id = try store.newId(a);
            const expires = now + 30;
            _ = try store.put(self.db, .{ .username = user, .kind = "undo", .id = id, .payload = try json(a, UndoDocument{ .entries = entries.items }), .state = "ready", .revision = 0, .due_at = 0, .expires_at = expires }, 0);
            response.undoId = id;
            response.expiresAt = expires;
        }
        return response;
    }

    pub fn undo(self: *Service, a: std.mem.Allocator, user: []const u8, id: []const u8, now: i64) !BulkResult {
        self.mutations.lock();
        defer self.mutations.unlock();
        var row = try store.get(a, self.db, user, "undo", id);
        if (row.expires_at <= now) return ServiceError.Conflict;
        const parsed = try std.json.parseFromSlice(UndoDocument, a, row.payload, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();
        if (std.mem.eql(u8, row.state, "done")) {
            var ok = true;
            for (parsed.value.results) |result| ok = ok and result.ok;
            return .{ .ok = ok, .results = parsed.value.results };
        }
        var results: std.ArrayList(ActionResult) = .empty;
        var all_ok = true;
        for (parsed.value.entries) |entry| {
            const restored = self.restore(a, user, entry) catch |err| {
                std.log.warn("webmail undo could not restore a message: {}", .{err});
                all_ok = false;
                try results.append(a, .{ .uid = entry.current.uid, .folder = entry.current.folder, .ok = false, .error_code = if (err == ServiceError.MessageChanged or err == maildir.MaildirError.Conflict) "message_changed" else "operation_failed" });
                continue;
            };
            try results.append(a, .{ .uid = entry.current.uid, .folder = entry.current.folder, .ok = true, .new_uid = restored.uid, .new_folder = restored.folder });
        }
        const items = try results.toOwnedSlice(a);
        row.state = "done";
        row.payload = try json(a, UndoDocument{ .entries = parsed.value.entries, .results = items });
        _ = try store.put(self.db, row, row.revision);
        return .{ .ok = all_ok, .results = items };
    }

    fn restore(self: *Service, a: std.mem.Allocator, user: []const u8, entry: UndoEntry) !MessageRef {
        var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer scratch.deinit();
        const temp = scratch.allocator();
        const message = try maildir.getMessage(temp, self.db, user, entry.current.folder, entry.current.uid);
        const raw = try maildir.rawMessage(temp, self.db, user, entry.current.folder, entry.current.uid);
        if (!std.meta.eql(message.flags, entry.after) or !std.mem.eql(u8, try fingerprint(temp, raw), entry.fingerprint)) return ServiceError.MessageChanged;
        var location = entry.current;
        if (entry.moved and !std.mem.eql(u8, entry.current.folder, entry.original.folder)) {
            location.folder = entry.original.folder;
            location.uid = try maildir.moveMessage(temp, self.db, user, entry.current.folder, entry.current.uid, location.folder);
            try self.updateDraftLocation(a, user, entry.current, location);
        } else _ = try maildir.setFlags(temp, self.db, user, location.folder, location.uid, entry.before);
        return location;
    }
};

pub fn json(a: std.mem.Allocator, value: anytype) ![]const u8 {
    return std.json.Stringify.valueAlloc(a, value, .{});
}

pub fn validFilename(name: []const u8) bool {
    if (name.len == 0 or name.len > 255 or !std.unicode.utf8ValidateSlice(name)) return false;
    for (name) |byte| if (byte < 0x20 or byte == 0x7f or byte == '/' or byte == '\\') return false;
    return true;
}

pub fn validContentType(value: []const u8) bool {
    if (value.len == 0 or value.len > 100 or std.mem.indexOfScalar(u8, value, '/') == null) return false;
    for (value) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '/' and byte != '-' and byte != '.' and byte != '+') return false;
    return true;
}

fn validDraftAddresses(a: std.mem.Allocator, addresses: []const []const u8) ![]const []const u8 {
    var valid: std.ArrayList([]const u8) = .empty;
    for (addresses) |address| {
        if (address.len > 1000) return ServiceError.InvalidPayload;
        if (compose.isSafeAddress(address)) try valid.append(a, address);
    }
    return valid.toOwnedSlice(a);
}

fn failedAddresses(a: std.mem.Allocator, addresses: []const []const u8, failed: []const []const u8) ![]const []const u8 {
    var output: std.ArrayList([]const u8) = .empty;
    for (addresses) |address| for (failed) |missing| if (std.ascii.eqlIgnoreCase(address, missing)) {
        try output.append(a, address);
        break;
    };
    return output.toOwnedSlice(a);
}

fn failedLabels(a: std.mem.Allocator, addresses: []const []const u8, labels: []const []const u8, failed: []const []const u8) ![]const []const u8 {
    var output: std.ArrayList([]const u8) = .empty;
    for (addresses, 0..) |address, index| for (failed) |missing| if (std.ascii.eqlIgnoreCase(address, missing)) {
        try output.append(a, if (index < labels.len) labels[index] else "");
        break;
    };
    return output.toOwnedSlice(a);
}

fn fingerprint(a: std.mem.Allocator, raw: []const u8) ![]const u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &digest, .{});
    const output = try a.alloc(u8, 64);
    const hex = "0123456789abcdef";
    for (digest, 0..) |byte, index| {
        output[index * 2] = hex[byte >> 4];
        output[index * 2 + 1] = hex[byte & 15];
    }
    return output;
}
