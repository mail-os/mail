//! Mailbox operations shared by HTTP handlers and the persistent outbox worker.
//! Draft metadata preserves unfinished recipient entry separately from safe MIME
//! headers. Undo receipts are server-owned, expiring, and bound to one account.
const std = @import("std");
const external_senders = @import("webmail_external_senders.zig");
const io_compat = @import("../core/io_compat.zig");
const attachment_metadata = @import("../message/attachment_metadata.zig");
const clamav = @import("../antispam/clamav.zig");
const database = @import("../storage/database.zig");
const auth_mod = @import("../auth/auth.zig");
const core_config = @import("../core/config.zig");
const fs = @import("../core/fs_compat.zig");
const time = @import("../core/time_compat.zig");
const mutex = @import("../core/mutex_compat.zig");
const maildir = @import("webmail_maildir.zig");
const calendar_invite = @import("webmail_calendar_invite.zig");
const compose = @import("webmail_compose.zig");
const store = @import("webmail_store.zig");
const message_refs = @import("../storage/message_refs.zig");
const shared_inbox = @import("../storage/shared_inbox.zig");
const thread_ids = @import("../message/thread_ids.zig");

pub const ServiceError = error{ InvalidPayload, AttachmentLimit, InvalidAttachment, Conflict, NotFound, InvalidAction, MessageChanged };
pub const max_schedule_seconds = 365 * 24 * 60 * 60;

fn decodeInlineAttachment(a: std.mem.Allocator, encoded: []const u8, limit: usize) ![]u8 {
    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(encoded) catch return ServiceError.InvalidAttachment;
    if (size > limit) return ServiceError.AttachmentLimit;
    const bytes = try a.alloc(u8, size);
    errdefer a.free(bytes);
    decoder.decode(bytes, encoded) catch return ServiceError.InvalidAttachment;
    return bytes;
}

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
    scheduleAt: ?i64 = null,
    recipientInputs: struct { to: []const u8 = "", cc: []const u8 = "", bcc: []const u8 = "" } = .{},
    recipientLabels: struct { to: []const []const u8 = &.{}, cc: []const []const u8 = &.{}, bcc: []const []const u8 = &.{} } = .{},
    replyContext: ?MessageRef = null,
    clearFollowUp: bool = false,
    attachments: []const struct {
        filename: []const u8 = "",
        contentType: []const u8 = "application/octet-stream",
        size: usize = 0,
        data: []const u8 = "",
        uploadId: ?[]const u8 = null,
    } = &.{},
    senderId: ?[]const u8 = null,
    externalReview: ?[]const u8 = null,
    sharedReply: ?shared_inbox.ReplyContext = null,

    pub fn delegatedSender(self: Payload) !?i64 {
        const id = self.senderId orelse return null;
        if (try self.externalSender() != null) return null;
        if (id.len == 0 or id.len > 19 or id[0] == '0') return ServiceError.InvalidPayload;
        for (id) |byte| if (!std.ascii.isDigit(byte)) return ServiceError.InvalidPayload;
        return std.fmt.parseInt(i64, id, 10) catch return ServiceError.InvalidPayload;
    }

    pub fn externalSender(self: Payload) !?[]const u8 {
        const id = self.senderId orelse return null;
        if (!std.mem.startsWith(u8, id, external_senders.prefix)) return null;
        if (!external_senders.validId(id)) return ServiceError.InvalidPayload;
        return id;
    }
};
pub const ExternalReviewRequest = struct {
    senderId: []const u8,
    to: []const []const u8 = &.{},
    cc: []const []const u8 = &.{},
    bcc: []const []const u8 = &.{},
};
pub const ExternalReview = struct {
    account: []const u8,
    from: []const u8,
    to: []const []const u8,
    cc: []const []const u8,
    bcc: []const []const u8,
    token: []const u8,
};
pub const Draft = struct { uid: i64, folder: []const u8 = "Drafts", message: Payload };
pub const DraftAttachmentEdit = union(enum) {
    add: []const store.Upload,
    remove: struct { index: usize, count: usize, filename: []const u8, content_type: []const u8, data: []const u8 },
};
pub const DraftAck = struct { ok: bool = true, uid: i64, draftId: []const u8, revision: i64 };
pub const MessageRef = struct { uid: i64, folder: []const u8, reference: ?[]const u8 = null, revision: ?[]const u8 = null };
pub const BulkAction = enum { move, trash, read, unread, flag, unflag, purge, delete, junk, not_junk };
pub const BulkPayload = struct { action: BulkAction, messages: []const MessageRef, folder: []const u8 = "Archive" };
pub const ActionResult = struct { uid: i64, folder: []const u8, ok: bool, new_uid: ?i64 = null, new_folder: ?[]const u8 = null, error_code: ?[]const u8 = null };
const UndoEntry = struct {
    original: MessageRef,
    current: MessageRef,
    before: maildir.Flags,
    after: maildir.Flags,
    fingerprint: []const u8,
    moved: bool,
    junkReceipt: ?[]const u8 = null,
};
const UndoDocument = struct { entries: []const UndoEntry, results: []const ActionResult = &.{} };
pub const BulkResult = struct { ok: bool, results: []const ActionResult, undoId: ?[]const u8 = null, expiresAt: ?i64 = null };
pub const Outbox = struct {
    message: Payload,
    scheduled: bool = false,
    result: ?compose.SendResult = null,
    error_message: ?[]const u8 = null,
    request_hash: ?[]const u8 = null,
    expected_from: ?[]const u8 = null,
    external_binding: ?[]const u8 = null,
    reply_cutoff_ms: i64 = 0,
    dispatch: ?compose.OutboxDispatch = null,
    calendarReply: ?struct {
        key: []const u8,
        attendee: []const u8,
        body: []const u8,
        revision: ?calendar_invite.Revision = null,
    } = null,
};

const RsvpDecision = struct {
    sequence: u32,
    dtstamp: i64,
    response: calendar_invite.Response,
    sendId: []const u8,
};

pub const RsvpStatus = struct {
    decision: RsvpDecision,
    state: []const u8,

    fn read(a: std.mem.Allocator, row: store.Record) !RsvpStatus {
        const decision = try std.json.parseFromSliceLeaky(RsvpDecision, a, row.payload, .{});
        return .{ .decision = decision, .state = row.state };
    }
};
pub const Limits = struct {
    maxFileBytes: usize,
    maxTotalBytes: usize,
    maxCount: usize,
    maxMessageBytes: usize,
    maxFileLinkBytes: usize = 0,
    undoSendSeconds: u32,
    calendarAvailable: bool = false,
    sharedInboxesAvailable: bool = false,
    junkFolder: []const u8 = "Junk",
};

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
    external_review_key: [32]u8 = undefined,

    pub fn init(db: *database.Database, auth: *auth_mod.AuthBackend, config: Config) !Service {
        try store.initSchema(db);
        var service: Service = .{ .db = db, .auth = auth, .config = config };
        io_compat.randomBytes(&service.external_review_key);
        try service.recoverDraftEdits();
        return service;
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
            .junkFolder = self.junkFolder(),
        };
    }

    pub fn junkFolder(self: *const Service) []const u8 {
        return if (self.config.mail_config) |config| config.junkFolder() else "Junk";
    }

    fn isJunkFolder(self: *const Service, folder: []const u8) bool {
        return std.mem.eql(u8, folder, self.junkFolder()) or std.mem.eql(u8, folder, "Junk");
    }

    fn canMarkJunk(self: *const Service, folder: []const u8) bool {
        if (self.isJunkFolder(folder)) return false;
        for ([_][]const u8{ "Sent", "Drafts", "Trash", "Screening", "Declined" }) |protected| {
            if (std.ascii.eqlIgnoreCase(folder, protected)) return false;
        }
        return true;
    }

    fn recoverJunkFolder(self: *const Service, a: std.mem.Allocator, user: []const u8, reference: []const u8) ![]const u8 {
        const source = (try self.db.junkSource(a, user, reference)) orelse return "INBOX";
        if (!self.canMarkJunk(source) or !(try maildir.folderExists(a, user, source))) return "INBOX";
        return source;
    }

    pub fn stageUpload(self: *Service, user: []const u8, upload: store.Upload, allowed: Limits, now: i64) !void {
        // The caller holds mutations across the idempotent lookup and insert.
        const hosted = (try self.db.hostedLimits(user)) != null;
        const bytes = @max(allowed.maxTotalBytes * (if (hosted) @as(usize, 2) else 10), 1024 * 1024);
        const count: usize = if (hosted) 128 else std.math.maxInt(i64);
        store.addUpload(self.db, user, upload, now, bytes, count) catch |err| switch (err) {
            store.StoreError.StorageLimit => {
                try store.sweep(self.db, now, user);
                try store.addUpload(self.db, user, upload, now, bytes, count);
            },
            else => return err,
        };
    }

    pub fn sweep(self: *Service, now: i64) !void {
        self.mutations.lock();
        defer self.mutations.unlock();
        try store.sweep(self.db, now, null);
    }

    /// Legacy clients can submit base64 attachments without staging an upload.
    /// Check them at request time, outside the shared webmail mutation lock.
    pub fn scanInlineAttachments(self: *Service, scanner: ?*clamav.ClamAVScanner, a: std.mem.Allocator, user: []const u8, payload: Payload) !void {
        const active = scanner orelse return;
        if (payload.attachments.len == 0) return;
        const allowed = try self.limits(user);
        if (payload.attachments.len > allowed.maxCount) return ServiceError.AttachmentLimit;
        var total: usize = 0;
        for (payload.attachments) |attachment| {
            if (attachment.uploadId != null) continue;
            const bytes = try decodeInlineAttachment(a, attachment.data, @min(allowed.maxFileBytes, allowed.maxTotalBytes - total));
            defer a.free(bytes);
            total += bytes.len;
            try clamav.requireAllowed(active, bytes);
        }
    }

    pub fn payloadMessage(self: *Service, a: std.mem.Allocator, payload: Payload, user: []const u8, email: []const u8, draft: bool) !compose.Message {
        if (draft) _ = try payload.delegatedSender();
        const allowed = try self.limits(user);
        if (payload.attachments.len > allowed.maxCount or payload.to.len + payload.cc.len + payload.bcc.len > 100 or payload.subject.len > 2000 or payload.text.len > 256 * 1024 or payload.html.len > 256 * 1024) return ServiceError.InvalidPayload;
        for ([_][]const u8{ payload.recipientInputs.to, payload.recipientInputs.cc, payload.recipientInputs.bcc }) |input| if (input.len > 2000) return ServiceError.InvalidPayload;
        if (!draft and (payload.recipientInputs.to.len > 0 or payload.recipientInputs.cc.len > 0 or payload.recipientInputs.bcc.len > 0)) return ServiceError.InvalidPayload;
        var attachments: std.ArrayList(compose.Attachment) = .empty;
        var total: usize = 0;
        for (payload.attachments) |attachment| {
            const file = try self.resolveAttachment(a, user, attachment, allowed.maxFileBytes);
            if (!validFilename(file.filename) or !validContentType(file.content_type)) return ServiceError.InvalidAttachment;
            total = std.math.add(usize, total, file.data.len) catch return ServiceError.AttachmentLimit;
            if (file.data.len > allowed.maxFileBytes or total > allowed.maxTotalBytes) return ServiceError.AttachmentLimit;
            try attachments.append(a, file);
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

    pub fn sendAddress(self: *Service, a: std.mem.Allocator, user: []const u8, own_address: []const u8, delegated_id: ?i64) ![]const u8 {
        const id = delegated_id orelse return own_address;
        const address = (try self.db.delegatedSenderAddress(a, user, id)) orelse return error.SenderIdentityUnavailable;
        if (!compose.isSafeAddress(address)) return error.SenderIdentityUnavailable;
        return address;
    }

    pub fn externalSendersFile(self: *const Service) ?[]const u8 {
        return if (self.config.mail_config) |cfg| cfg.webmail_external_senders_file else null;
    }

    pub fn reviewExternalSend(self: *Service, a: std.mem.Allocator, user: []const u8, request: ExternalReviewRequest) !ExternalReview {
        const grant = try external_senders.find(a, self.externalSendersFile(), user, request.senderId);
        const binding = (try external_senders.verifiedBinding(a, self.db, grant)) orelse return error.ExternalSenderUnavailable;
        return self.reviewExternalEnvelope(a, grant, request, binding);
    }

    fn reviewExternalEnvelope(self: *Service, a: std.mem.Allocator, grant: external_senders.Grant, request: ExternalReviewRequest, binding: []const u8) !ExternalReview {
        const count = request.to.len + request.cc.len + request.bcc.len;
        if (count == 0) return compose.ComposeError.NoRecipients;
        if (count > 100) return ServiceError.InvalidPayload;
        for ([_][]const []const u8{ request.to, request.cc, request.bcc }) |addresses| {
            for (addresses) |address| if (!compose.isSafeAddress(address)) return compose.ComposeError.InvalidAddress;
        }
        const input = try json(a, .{ .grant = binding, .request = request });
        var mac: [32]u8 = undefined;
        std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, input, &self.external_review_key);
        const token = std.fmt.bytesToHex(mac, .lower);
        return .{
            .account = grant.mailbox,
            .from = grant.address,
            .to = request.to,
            .cc = request.cc,
            .bcc = request.bcc,
            .token = try a.dupe(u8, &token),
        };
    }

    fn resolveAttachment(self: *Service, a: std.mem.Allocator, user: []const u8, attachment: std.meta.Elem(@FieldType(Payload, "attachments")), limit: usize) !compose.Attachment {
        if (attachment.uploadId) |id| {
            if (!store.validId(id)) return ServiceError.InvalidAttachment;
            const upload = try store.getUpload(a, self.db, user, id);
            const mime_id = if (id.len == 32 and std.mem.indexOfNone(u8, id, "0123456789abcdef") == null)
                id[0..32].*
            else
                (try fingerprint(a, id))[0..32].*;
            return .{ .filename = upload.filename, .content_type = upload.content_type, .data = upload.data, .mime_id = mime_id, .content_id = upload.content_id, .inline_part = upload.inline_part };
        }
        return .{ .filename = attachment.filename, .content_type = attachment.contentType, .data = try decodeInlineAttachment(a, attachment.data, limit) };
    }

    /// Coordinate edits with webmail autosave and the frozen Outbox snapshot.
    /// Store the new draft document before replacing the file so startup can
    /// finish a write that stopped between the Maildir rename and SQLite update.
    pub fn editDraftAttachments(self: *Service, a: std.mem.Allocator, user: []const u8, path: []const u8, previous: []const u8, raw: []const u8, edit: DraftAttachmentEdit) !void {
        self.mutations.lock();
        defer self.mutations.unlock();
        self.db.lockMailboxes();
        defer self.db.unlockMailboxes();
        const current = fs.readFileAlloc(a, path) catch return ServiceError.Conflict;
        if (!std.mem.eql(u8, previous, current)) return ServiceError.Conflict;
        const uid = (try self.db.getUidForFile(user, "Drafts", std.fs.path.basename(path))) orelse
            return maildir.replaceDraftFile(a, self.db, user, path, raw);
        var row = store.findDraft(a, self.db, user, "Drafts", uid) catch |err| {
            if (err == store.StoreError.NotFound) return maildir.replaceDraftFile(a, self.db, user, path, raw);
            return err;
        };
        if (try self.settleDraftEdit(a, user, row.id)) row = try store.get(a, self.db, user, "draft", row.id);
        if (!std.mem.eql(u8, row.state, "saved")) return ServiceError.Conflict;
        var draft = try std.json.parseFromSliceLeaky(Draft, a, row.payload, .{ .ignore_unknown_fields = true });

        const had = draft.message.attachments;
        var staged: []const store.Upload = &.{};
        errdefer for (staged) |upload| store.removeUpload(self.db, user, upload.id) catch {};
        switch (edit) {
            .add => |uploads| {
                const allowed = try self.limits(user);
                if (uploads.len > allowed.maxCount -| had.len) return ServiceError.AttachmentLimit;
                const attachments = try a.alloc(std.meta.Elem(@FieldType(Payload, "attachments")), had.len + uploads.len);
                @memcpy(attachments[0..had.len], had);
                for (uploads, attachments[had.len..], 0..) |upload, *attachment, index| {
                    if (upload.data.len > allowed.maxFileBytes) return ServiceError.AttachmentLimit;
                    try self.stageUpload(user, upload, allowed, time.timestamp());
                    staged = uploads[0 .. index + 1];
                    attachment.* = .{ .uploadId = upload.id, .filename = upload.filename, .contentType = upload.content_type, .size = upload.data.len };
                }
                draft.message.attachments = attachments;
                _ = try self.payloadMessage(a, draft.message, user, user, true);
            },
            .remove => |file| {
                if (had.len != file.count or file.index >= had.len) return ServiceError.Conflict;
                const attachment = try self.resolveAttachment(a, user, had[file.index], self.config.max_message_bytes);
                if (!std.mem.eql(u8, attachment.filename, file.filename) or
                    !std.ascii.eqlIgnoreCase(attachment.content_type, file.content_type) or
                    !std.mem.eql(u8, attachment.data, file.data)) return ServiceError.Conflict;
                draft.message.attachments = try std.mem.concat(a, std.meta.Elem(@FieldType(Payload, "attachments")), &.{ had[0..file.index], had[file.index + 1 ..] });
            },
        }
        draft.message.saveToken = "";
        draft.message.draftRevision = row.revision + 1;
        row.payload = try json(a, draft);
        if ((try self.db.hostedLimits(user)) != null)
            try store.checkRecordCapacity(self.db, row, @max(1024 * 1024, 2 * self.config.max_message_bytes), 200);

        var pending = row;
        pending.kind = "draft-edit";
        pending.state = try fingerprint(a, raw);
        pending.due_at = row.revision;
        _ = try store.put(self.db, pending, 0);
        maildir.replaceDraftFile(a, self.db, user, path, raw) catch |err| {
            store.remove(self.db, user, pending.kind, pending.id) catch {};
            return err;
        };
        _ = store.put(self.db, row, row.revision) catch |err| {
            // If the rollback also fails, keep the intent for recovery.
            maildir.replaceDraftFile(a, self.db, user, path, previous) catch return err;
            store.remove(self.db, user, pending.kind, pending.id) catch {};
            return err;
        };
        store.remove(self.db, user, pending.kind, pending.id) catch {};
    }

    fn recoverDraftEdits(self: *Service) !void {
        self.db.lockMailboxes();
        defer self.db.unlockMailboxes();
        var cursor: i64 = 0;
        while (true) {
            var arena = std.heap.ArenaAllocator.init(self.db.allocator);
            defer arena.deinit();
            const a = arena.allocator();
            const pending = (try store.nextDraftEdit(a, self.db, &cursor)) orelse break;
            try self.finishDraftEdit(a, pending);
        }
    }

    fn settleDraftEdit(self: *Service, a: std.mem.Allocator, user: []const u8, id: []const u8) !bool {
        const pending = store.get(a, self.db, user, "draft-edit", id) catch |err| {
            if (err == store.StoreError.NotFound) return false;
            return err;
        };
        try self.finishDraftEdit(a, pending);
        return true;
    }

    fn finishDraftEdit(self: *Service, a: std.mem.Allocator, pending: store.Record) !void {
        const row = store.get(a, self.db, pending.username, "draft", pending.id) catch |err| {
            if (err != store.StoreError.NotFound) return err;
            return store.remove(self.db, pending.username, pending.kind, pending.id);
        };
        if (row.revision == pending.due_at and std.mem.eql(u8, row.state, "saved")) {
            const draft = try std.json.parseFromSliceLeaky(Draft, a, pending.payload, .{ .ignore_unknown_fields = true });
            const raw = maildir.rawMessage(a, self.db, row.username, draft.folder, draft.uid) catch |err| {
                if (err != maildir.MaildirError.MessageNotFound and err != error.FileNotFound) return err;
                return store.remove(self.db, pending.username, pending.kind, pending.id);
            };
            if (std.mem.eql(u8, pending.state, try fingerprint(a, raw))) {
                var updated = row;
                updated.payload = pending.payload;
                _ = try store.put(self.db, updated, row.revision);
            }
        }
        try store.remove(self.db, pending.username, pending.kind, pending.id);
    }

    pub fn loadDraft(self: *Service, a: std.mem.Allocator, user: []const u8, folder: []const u8, uid: i64) !store.Record {
        self.mutations.lock();
        defer self.mutations.unlock();
        const row = try store.findDraft(a, self.db, user, folder, uid);
        return self.readyDraft(a, user, row.id);
    }

    fn readyDraft(self: *Service, a: std.mem.Allocator, user: []const u8, id: []const u8) !store.Record {
        self.db.lockMailboxes();
        defer self.db.unlockMailboxes();
        _ = try self.settleDraftEdit(a, user, id);
        return store.get(a, self.db, user, "draft", id);
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
        const previous: ?store.Record = self.readyDraft(a, user, id) catch |err| blk: {
            if (err != store.StoreError.NotFound) return err;
            break :blk null;
        };
        var existing = payload.draftUid;
        var expected: i64 = 0;
        if (previous) |row| {
            const doc = try std.json.parseFromSlice(Draft, a, row.payload, .{ .ignore_unknown_fields = true });
            defer doc.deinit();
            if (!std.mem.eql(u8, doc.value.folder, "Drafts") or (!std.mem.eql(u8, row.state, "saved") and !(resume_queued and std.mem.eql(u8, row.state, "queued")))) return ServiceError.Conflict;
            if (!shared_inbox.sameReply(doc.value.message.sharedReply, payload.sharedReply)) return error.SharedReplyUnavailable;
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
        self.db.lockMailboxes();
        defer self.db.unlockMailboxes();
        const write = try maildir.prepareDraft(a, self.db, user, raw.len, existing);
        const uid = write.uid;
        const record: store.Record = blk: {
            errdefer if (existing == null) write.forgetUid(self.db, user);
            var saved = payload;
            saved.draftId = id;
            saved.draftUid = uid;
            const record = store.Record{ .username = user, .kind = "draft", .id = id, .payload = try json(a, Draft{ .uid = uid, .message = saved }), .state = "saved", .revision = expected, .due_at = 0, .expires_at = 0 };
            if (!resume_queued and (try self.db.hostedLimits(user)) != null) {
                try store.checkRecordCapacity(self.db, record, @max(1024 * 1024, 2 * self.config.max_message_bytes), 200);
            }
            try write.save(a, self.db, user, raw);
            break :blk record;
        };
        const revision = try store.put(self.db, record, expected);
        return .{ .uid = uid, .draftId = id, .revision = revision };
    }

    pub fn queue(self: *Service, a: std.mem.Allocator, user: []const u8, email: []const u8, payload: Payload, now: i64) !store.Record {
        self.mutations.lock();
        defer self.mutations.unlock();
        const id = payload.sendId orelse return ServiceError.InvalidPayload;
        if (!store.validId(id)) return ServiceError.InvalidPayload;
        if (store.get(a, self.db, user, "outbox", id)) |known| {
            const parsed = try std.json.parseFromSlice(Outbox, a, known.payload, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            const incoming = try json(a, payload);
            const matches = if (parsed.value.request_hash) |digest|
                std.mem.eql(u8, digest, try sendFingerprint(a, payload))
            else
                std.mem.eql(u8, try json(a, parsed.value.message), incoming);
            if (!matches) return ServiceError.Conflict;
            return known;
        } else |err| if (err != store.StoreError.NotFound) return err;
        const due_at = if (payload.scheduleAt) |schedule_at| blk: {
            if (payload.delaySeconds != null or schedule_at <= now or schedule_at > now + max_schedule_seconds)
                return error.InvalidSendSchedule;
            break :blk schedule_at;
        } else blk: {
            const delay = payload.delaySeconds orelse self.config.undo_send_seconds;
            if (delay > 30) return ServiceError.InvalidPayload;
            break :blk now + delay;
        };
        const external_id = try payload.externalSender();
        var queued: Outbox = .{ .message = payload, .scheduled = payload.scheduleAt != null, .reply_cutoff_ms = time.milliTimestamp() };
        const from = if (external_id) |sender_id| blk: {
            if (payload.sharedReply != null) return error.ExternalSenderUnavailable;
            const grant = try external_senders.find(a, self.externalSendersFile(), user, sender_id);
            const binding = (try external_senders.verifiedBinding(a, self.db, grant)) orelse return error.ExternalSenderUnavailable;
            const review = try self.reviewExternalEnvelope(a, grant, .{ .senderId = sender_id, .to = payload.to, .cc = payload.cc, .bcc = payload.bcc }, binding);
            const supplied = payload.externalReview orelse return error.ExternalReviewRequired;
            if (supplied.len != 64 or !std.crypto.timing_safe.eql([64]u8, supplied[0..64].*, review.token[0..64].*)) return error.ExternalReviewRequired;
            queued.external_binding = binding;
            queued.expected_from = grant.address;
            break :blk grant.address;
        } else try self.sendAddress(a, user, email, try payload.delegatedSender());
        const msg = try self.payloadMessage(a, payload, user, from, false);
        if (msg.to.len + msg.cc.len + msg.bcc.len == 0) return compose.ComposeError.NoRecipients;
        for ([_][]const []const u8{ msg.to, msg.cc, msg.bcc }) |addresses| for (addresses) |address| if (!compose.isSafeAddress(address)) return compose.ComposeError.InvalidAddress;
        const raw = try compose.buildMime(a, msg, now, "<validation@localhost>");
        if (raw.len > self.config.max_message_bytes) return ServiceError.AttachmentLimit;
        if (payload.draftId) |draft_id| {
            const row = try self.readyDraft(a, user, draft_id);
            if (row.revision != payload.draftRevision or !std.mem.eql(u8, row.state, "saved")) return ServiceError.Conflict;
            const doc = try std.json.parseFromSliceLeaky(Draft, a, row.payload, .{ .ignore_unknown_fields = true });
            if (!shared_inbox.sameReply(doc.message.sharedReply, payload.sharedReply)) return error.SharedReplyUnavailable;
        }
        if (payload.sharedReply != null) {
            if (payload.draftId == null or payload.replyContext != null) return error.SharedReplyUnavailable;
            try self.checkSharedReply(a, user, from, payload);
        }
        var row = store.Record{ .username = user, .kind = "outbox", .id = id, .payload = try json(a, queued), .state = "pending", .revision = 0, .due_at = due_at, .expires_at = 0 };
        try self.checkOutboxCapacity(row, now);
        row.revision = if (payload.sharedReply) |context|
            try store.enqueueShared(self.db, row, payload.draftId.?, payload.draftRevision, context)
        else
            try store.enqueue(self.db, row, payload.draftId, payload.draftRevision);
        return row;
    }

    pub fn hostedOutboxBudget(self: *Service, user: []const u8) !?usize {
        if ((try self.db.hostedLimits(user)) == null) return null;
        return @max(1024 * 1024, 2 * self.config.max_message_bytes);
    }

    fn checkOutboxCapacity(self: *Service, row: store.Record, now: i64) !void {
        if (try self.hostedOutboxBudget(row.username)) |bytes| {
            store.checkRecordCapacity(self.db, row, bytes, store.hosted_outbox_count) catch |err| switch (err) {
                store.StoreError.OutboxStorageLimit => {
                    try store.sweep(self.db, now, row.username);
                    try store.checkRecordCapacity(self.db, row, bytes, store.hosted_outbox_count);
                },
                else => return err,
            };
        }
    }

    fn rsvpRecord(self: *Service, a: std.mem.Allocator, user: []const u8, key: []const u8) !?store.Record {
        return store.get(a, self.db, user, "calendar-rsvp", key) catch |err| switch (err) {
            store.StoreError.NotFound => null,
            else => return err,
        };
    }

    pub fn rsvpStatus(self: *Service, a: std.mem.Allocator, user: []const u8, invite: calendar_invite.Invitation) !?RsvpStatus {
        const key = try invite.key(a);
        const row = (try self.rsvpRecord(a, user, &key)) orelse return null;
        return try RsvpStatus.read(a, row);
    }

    pub fn queueRsvp(self: *Service, a: std.mem.Allocator, user: []const u8, attendee: []const u8, invite: calendar_invite.Invitation, response: calendar_invite.Response, previous_id: ?[]const u8, scanner: ?*clamav.ClamAVScanner, now: i64) !RsvpStatus {
        if (!invite.canReply(attendee)) return error.CalendarReplyUnavailable;
        const revision = try invite.revision(a);
        const key = revision.component;
        self.mutations.lock();
        defer self.mutations.unlock();
        try database.Database.requireCurrentCalendarInvitation(self.db, user, revision);

        // An optimistic receipt prevents an older tab from reversing a newer
        // decision. The transaction also guards callers on separate listeners.
        const previous = try self.rsvpRecord(a, user, &key);
        if (previous) |entry| {
            const status = try RsvpStatus.read(a, entry);
            const order = switch (std.math.order(invite.preview.sequence, status.decision.sequence)) {
                .eq => std.math.order(invite.preview.dtstamp, status.decision.dtstamp),
                else => |different| different,
            };
            if (order == .lt) return error.CalendarInvitationStale;
            const acknowledged = if (previous_id) |id| std.mem.eql(u8, id, status.decision.sendId) else false;
            const retryable = std.mem.eql(u8, status.state, "failed") or std.mem.eql(u8, status.state, "cancelled");
            if (order == .eq and response == status.decision.response and !(acknowledged and retryable)) return status;
            if (std.mem.eql(u8, status.state, "pending") or std.mem.eql(u8, status.state, "sending") or std.mem.eql(u8, status.state, "unknown"))
                return error.CalendarReplyInProgress;
            if (order == .eq and !acknowledged) return ServiceError.Conflict;
        }

        const id = try store.newId(a);
        const body = try invite.reply(a, attendee, response, now);
        const allowed = try self.limits(user);
        if (body.len > @min(allowed.maxFileBytes, allowed.maxTotalBytes) or allowed.maxCount == 0)
            return ServiceError.AttachmentLimit;
        try clamav.requireAllowed(scanner, body);
        const label = switch (response) {
            .accepted => "Accepted",
            .tentative => "Tentative",
            .declined => "Declined",
        };
        const summary = invite.preview.summary orelse "Calendar invitation";
        const subject = if (summary.len <= 512 and compose.isSafeHeaderValue(summary))
            try std.fmt.allocPrint(a, "{s}: {s}", .{ label, summary })
        else
            try std.fmt.allocPrint(a, "{s}: Calendar invitation", .{label});
        const doc: Outbox = .{
            .message = .{ .to = &.{invite.preview.organizer}, .subject = subject, .text = subject, .sendId = id },
            .calendarReply = .{ .key = &key, .attendee = attendee, .body = body, .revision = revision },
        };
        const msg = try self.outboxMessage(a, doc, user, attendee);
        const raw = try compose.buildMime(a, msg, now, "<validation@localhost>");
        if (raw.len > allowed.maxMessageBytes) return ServiceError.AttachmentLimit;
        const row: store.Record = .{ .username = user, .kind = "outbox", .id = id, .payload = try json(a, doc), .state = "pending", .revision = 0, .due_at = now, .expires_at = 0 };
        const decision: RsvpDecision = .{ .sequence = invite.preview.sequence, .dtstamp = invite.preview.dtstamp, .response = response, .sendId = id };
        try self.checkOutboxCapacity(row, now);
        try store.enqueueCalendarReply(self.db, row, .{
            .username = user,
            .kind = "calendar-rsvp",
            .id = &key,
            .payload = try json(a, decision),
            .state = row.state,
            .revision = if (previous) |entry| entry.revision else 0,
            .due_at = 0,
            .expires_at = 0,
        }, revision);
        return .{ .decision = decision, .state = row.state };
    }

    fn outboxMessage(self: *Service, a: std.mem.Allocator, doc: Outbox, user: []const u8, from: []const u8) !compose.Message {
        var message = try self.payloadMessage(a, doc.message, user, from, false);
        if (doc.calendarReply) |reply| {
            if (!std.ascii.eqlIgnoreCase(reply.attendee, from) or reply.body.len == 0) return error.CalendarReplyUnavailable;
            const attachments = try a.alloc(compose.Attachment, 1);
            attachments[0] = .{ .filename = "reply.ics", .content_type = "text/calendar; method=REPLY; charset=utf-8", .data = reply.body, .inline_part = true };
            message.attachments = attachments;
        }
        return message;
    }

    fn checkSharedReply(self: *Service, a: std.mem.Allocator, actor: []const u8, from: []const u8, payload: Payload) !void {
        const context = payload.sharedReply orelse return;
        const id = shared_inbox.positiveId(context.sourceId) orelse return error.SharedReplyUnavailable;
        if (!message_refs.valid(context.reference) or !try shared_inbox.canReply(self.db, actor, context)) return error.SharedReplyUnavailable;
        const source = shared_inbox.source(a, self.db, actor, context.team, id) catch |err| switch (err) {
            error.SharedInboxNotFound => return error.SharedReplyUnavailable,
            else => return err,
        };
        if (!std.mem.eql(u8, source.address, from)) return error.SharedReplyUnavailable;
        const original = maildir.getSharedInboxMessage(a, self.db, source.username, context.reference) catch |err| switch (err) {
            error.SharedInboxNotFound, maildir.MaildirError.MessageNotFound => return error.SharedReplyUnavailable,
            else => return err,
        };
        if (!std.mem.eql(u8, payload.inReplyTo, original.message_id)) return error.SharedReplyUnavailable;
    }

    pub fn requireOrdinaryDirectSend(self: *Service, a: std.mem.Allocator, actor: []const u8, payload: Payload) !void {
        if (try payload.externalSender() != null) return error.ExternalReviewRequired;
        if (payload.sharedReply != null) return error.SharedReplyQueueRequired;
        const draft_id = payload.draftId orelse return;
        const row = store.get(a, self.db, actor, "draft", draft_id) catch |err| switch (err) {
            store.StoreError.NotFound => return,
            else => return err,
        };
        const doc = try std.json.parseFromSliceLeaky(Draft, a, row.payload, .{ .ignore_unknown_fields = true });
        if (doc.message.sharedReply != null) return error.SharedReplyQueueRequired;
    }

    pub fn cancel(self: *Service, a: std.mem.Allocator, user: []const u8, id: []const u8, now: i64) !store.Record {
        self.mutations.lock();
        defer self.mutations.unlock();
        const existing = try store.get(a, self.db, user, "outbox", id);
        if (std.mem.eql(u8, existing.state, "cancelled")) return existing;
        return store.cancelSend(a, self.db, user, id, now);
    }

    pub fn dispatchDue(self: *Service, a: std.mem.Allocator, now: i64) !bool {
        var row = (try store.claimDue(a, self.db, now)) orelse return false;
        const parsed = try std.json.parseFromSlice(Outbox, a, row.payload, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();
        var doc = parsed.value;
        const delivery_id = try store.newId(a);
        doc.dispatch = .{
            .delivery_id = delivery_id,
            .sent_delivery_id = try store.newId(a),
            .message_id = try std.fmt.allocPrint(a, "<{s}@{s}>", .{ delivery_id, self.config.hostname }),
            .message_date = time.timestamp(),
        };
        self.deliver(a, &row, &doc) catch |err| {
            if (!try self.reconcileDelivery(a, row.username, &doc)) {
                doc.error_message = switch (err) {
                    error.SenderIdentityUnavailable => "This From address is no longer available. Choose another address before sending.",
                    error.ExternalSenderUnavailable => "The external From address or its provider is no longer authorized. Review this message before sending.",
                    error.SharedReplyUnavailable => "This shared reply no longer has permission to send. Check the original message and its assignment.",
                    error.CalendarInvitationStale => "The organizer sent an updated invitation before this RSVP could be sent.",
                    error.CalendarInvitationCancelled => "The organizer cancelled this invitation before this RSVP could be sent.",
                    error.CalendarReplyNeedsReview => "Open the invitation and retry this RSVP after the upgrade.",
                    error.HostedSendingLimit => "Daily recipient allowance exhausted. Try again after midnight UTC.",
                    error.HostedSenderDisabled => "This mailbox is disabled. The message was not sent.",
                    error.HostedStorageFull => "A recipient mailbox is full. Review the recipients before retrying.",
                    error.HostedRecipientDisabled => "A recipient mailbox is disabled. Review the recipients before retrying.",
                    else => "Delivery failed. Review this message before retrying.",
                };
            }
        };
        try self.finishDispatch(a, &row, doc, now);
        return true;
    }

    pub fn recoverInterrupted(self: *Service, now: i64) !void {
        try store.recoverInterrupted(self.db);
        var cursor: i64 = 0;
        while (true) {
            var scratch = std.heap.ArenaAllocator.init(self.db.allocator);
            defer scratch.deinit();
            const a = scratch.allocator();
            var row = (try store.nextInterruptedDelivery(a, self.db, &cursor)) orelse break;
            self.recoverDispatch(a, &row, now) catch |err| {
                std.log.warn("could not reconcile interrupted webmail dispatch: {}", .{err});
            };
        }
    }

    fn recoverDispatch(self: *Service, a: std.mem.Allocator, row: *store.Record, now: i64) !void {
        const parsed = try std.json.parseFromSlice(Outbox, a, row.payload, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();
        var doc = parsed.value;
        if (try self.reconcileDelivery(a, row.username, &doc)) {
            try self.finishDispatch(a, row, doc, now);
        } else if (doc.message.sharedReply != null or doc.calendarReply != null) {
            if (doc.dispatch) |dispatch| if (try self.db.hasAcceptedDelivery(dispatch.delivery_id)) return;
            doc.error_message = if (doc.calendarReply != null)
                "The server restarted before sending this RSVP. Retry from the invitation."
            else
                "The server restarted before admitting this shared reply. The saved draft can be retried.";
            try self.finishDispatch(a, row, doc, now);
        }
    }

    fn reconcileDelivery(self: *Service, a: std.mem.Allocator, user: []const u8, doc: *Outbox) !bool {
        const dispatch = doc.dispatch orelse return false;
        const checkpoint = (try self.db.interactiveDelivery(a, dispatch.delivery_id)) orelse return false;
        var result: compose.SendResult = .{
            .message_id = dispatch.message_id,
            .delivered = checkpoint.delivered,
            .failed = checkpoint.failed,
            .unknown = checkpoint.unknown,
            .sent_saved = false,
            .limit_notice = if (checkpoint.refused_for_limit) "Some recipient mailboxes are full or disabled." else null,
        };
        if (result.delivered > 0) {
            result.sent_saved = self.reconcileSent(a, user, doc.*, dispatch) catch |err| blk: {
                std.log.warn("webmail could not reconcile the Sent copy: {}", .{err});
                if (result.limit_notice == null and err == error.HostedStorageFull)
                    result.limit_notice = "Message delivered. Your mailbox is full, so a Sent copy could not be saved.";
                break :blk false;
            };
        }
        doc.result = result;
        return true;
    }

    fn reconcileSent(self: *Service, a: std.mem.Allocator, user: []const u8, doc: Outbox, dispatch: compose.OutboxDispatch) !bool {
        if (try self.db.hasFiledDelivery(dispatch.sent_delivery_id)) return true;
        var account = try self.db.getUserByUsername(user);
        defer account.deinit(self.db.allocator);
        const message = try self.outboxMessage(a, doc, user, dispatch.from_address orelse account.email);
        return compose.recoverSent(a, message, self.sendConfig(user), dispatch);
    }

    fn finishDispatch(self: *Service, a: std.mem.Allocator, row: *store.Record, doc: Outbox, now: i64) !void {
        var retained = doc;
        row.state = "failed";
        if (doc.result) |result| {
            row.state = if (result.unknown.len > 0) "unknown" else if (result.failed.len == 0) (if (result.sent_saved) "sent" else "sent_unfiled") else (if (result.delivered > 0) "partial" else "failed");
            retained.error_message = result.limit_notice;
            if (result.delivered > 0) if (doc.message.replyContext) |context| {
                self.finishReply(a, row.username, context, doc) catch |err| std.log.warn("could not update the replied-to message: {}", .{err});
            };
        }
        if (!std.mem.eql(u8, row.state, "unknown")) self.finishDraft(a, row.username, doc) catch |err| {
            std.log.warn("webmail could not reconcile the draft after delivery: {}", .{err});
            retained.error_message = "Draft cleanup needs attention. Review the delivery result in Outbox before sending again.";
        };
        const compact = (std.mem.eql(u8, row.state, "sent") or std.mem.eql(u8, row.state, "sent_unfiled")) and
            (try self.db.hostedLimits(row.username)) != null;
        if (compact) {
            retained.request_hash = try sendFingerprint(a, doc.message);
            retained.message = .{ .subject = doc.message.subject, .to = doc.message.to, .senderId = doc.message.senderId };
        }
        if (!std.mem.eql(u8, row.state, "unknown")) {
            if (retained.calendarReply) |*reply| reply.body = "";
        }
        row.payload = try json(a, retained);
        row.expires_at = now + store.terminal_retention;
        row.revision = try store.put(self.db, row.*, row.revision);
    }

    pub fn resolveUnknown(self: *Service, a: std.mem.Allocator, user: []const u8, id: []const u8, now: i64) !store.Record {
        self.mutations.lock();
        defer self.mutations.unlock();
        var row = try store.get(a, self.db, user, "outbox", id);
        if (std.mem.eql(u8, row.state, "resolved")) return row;
        if (!std.mem.eql(u8, row.state, "unknown")) return ServiceError.Conflict;
        const doc = try std.json.parseFromSlice(Outbox, a, row.payload, .{ .ignore_unknown_fields = true });
        defer doc.deinit();
        if (doc.value.calendarReply != null) return ServiceError.Conflict;
        if (doc.value.result == null) if (doc.value.dispatch) |dispatch| {
            // Never offer the original envelope when a durable acceptance
            // still needs to be reconciled.
            if (try self.db.hasAcceptedDelivery(dispatch.delivery_id)) return ServiceError.Conflict;
        };
        if (doc.value.result) |result| {
            var retry = doc.value;
            retry.result.?.failed = try std.mem.concat(a, []const u8, &.{ result.failed, result.unknown });
            try self.finishDraftLocked(a, user, retry);
        } else if (doc.value.message.draftId) |draft_id| {
            if (store.get(a, self.db, user, "draft", draft_id)) |previous| {
                var draft = previous;
                if (std.mem.eql(u8, draft.state, "queued")) {
                    draft.state = "saved";
                    _ = try store.put(self.db, draft, draft.revision);
                }
            } else |err| if (err != store.StoreError.NotFound) return err;
        }
        row.state = "resolved";
        row.expires_at = now + store.terminal_retention;
        row.revision = try store.put(self.db, row, row.revision);
        return row;
    }

    fn deliver(self: *Service, a: std.mem.Allocator, row: *store.Record, doc: *Outbox) !void {
        const user = row.username;
        var account = try self.db.getUserByUsername(user);
        defer account.deinit(self.db.allocator);
        if (!account.enabled) return error.HostedSenderDisabled;
        const delegated_id = try doc.message.delegatedSender();
        const external_id = try doc.message.externalSender();
        const grant: ?external_senders.Grant = if (external_id) |id| try external_senders.find(a, self.externalSendersFile(), user, id) else null;
        const from = if (grant) |approved| blk: {
            const binding = doc.external_binding orelse return error.ExternalSenderUnavailable;
            const current = (try external_senders.verifiedBinding(a, self.db, approved)) orelse return error.ExternalSenderUnavailable;
            if (!std.mem.eql(u8, binding, current)) return error.ExternalSenderUnavailable;
            break :blk approved.address;
        } else try self.sendAddress(a, user, account.email, delegated_id);
        if (doc.expected_from) |expected| {
            if (!std.mem.eql(u8, from, expected)) return error.SenderIdentityUnavailable;
        }
        try self.checkSharedReply(a, user, from, doc.message);
        if (doc.calendarReply) |*reply| if (reply.revision == null) {
            if (doc.message.to.len != 1) return error.CalendarReplyNeedsReview;
            const receipt = (try self.rsvpRecord(a, user, reply.key)) orelse return error.CalendarReplyNeedsReview;
            const decision = (try RsvpStatus.read(a, receipt)).decision;
            if (!std.mem.eql(u8, decision.sendId, row.id)) return error.CalendarReplyNeedsReview;
            reply.revision = calendar_invite.queuedReplyRevision(a, reply.body, reply.attendee, doc.message.to[0], reply.key, decision.sequence, decision.dtstamp) catch |err| switch (err) {
                error.InvalidCalendar, error.InvalidInvitation => return error.CalendarReplyNeedsReview,
                else => return err,
            };
        };
        const msg = try self.outboxMessage(a, doc.*, user, from);
        // Recovery files Sent with the address used at admission, even after
        // a grant is revoked or the shared mailbox changes its address.
        doc.dispatch.?.from_address = try a.dupe(u8, from);
        row.payload = try json(a, doc.*);
        row.revision = try store.put(self.db, row.*, row.revision);
        var cfg = self.sendConfig(user);
        cfg.delegated_sender_id = delegated_id;
        const secret = if (grant) |approved| try external_senders.readFile(a, approved.password_file, 352) else null;
        defer if (secret) |bytes| {
            std.crypto.secureZero(u8, bytes);
            a.free(bytes);
        };
        if (grant) |approved| cfg.external_provider = .{
            .config = approved.provider(std.mem.trimEnd(u8, secret.?, "\r\n")),
            .identity = .{ .id = approved.id, .generation = doc.external_binding.? },
        };
        if (doc.message.sharedReply) |context| cfg.shared_reply = .{ .context = context, .send_id = row.id };
        if (doc.calendarReply) |reply| cfg.calendar_reply = reply.revision;
        doc.result = try compose.sendWithJournal(a, msg, cfg, doc.dispatch);
    }

    fn sendConfig(self: *Service, user: []const u8) compose.SendConfig {
        return .{ .hostname = self.config.hostname, .delivery_method = self.config.delivery_method, .ses_region = self.config.ses_region, .sender_user = user, .mail_config = self.config.mail_config, .auth = self.auth };
    }

    fn finishReply(self: *Service, a: std.mem.Allocator, user: []const u8, context: MessageRef, doc: Outbox) !void {
        self.db.lockMailboxes();
        defer self.db.unlockMailboxes();
        if (context.reference) |reference| {
            const original = try maildir.resolveVersioned(a, self.db, user, reference);
            if (doc.message.clearFollowUp and doc.result.?.failed.len == 0 and doc.result.?.unknown.len == 0 and doc.reply_cutoff_ms > 0) {
                const ids = try thread_ids.parse(a, original.raw);
                const keys = try std.json.Stringify.valueAlloc(a, try ids.keys(a), .{});
                try self.db.clearFollowUp(user, reference, keys, doc.reply_cutoff_ms);
            }
            const detail = try maildir.getMessage(a, self.db, user, original.locator.folder, original.locator.uid);
            var flags = detail.flags;
            flags.answered = true;
            _ = try maildir.setFlagsLocked(a, self.db, user, original.locator.folder, original.locator.uid, flags);
        } else {
            const detail = try maildir.getMessage(a, self.db, user, context.folder, context.uid);
            var flags = detail.flags;
            flags.answered = true;
            _ = try maildir.setFlagsLocked(a, self.db, user, context.folder, context.uid, flags);
        }
    }

    fn finishDraft(self: *Service, a: std.mem.Allocator, user: []const u8, doc: Outbox) !void {
        self.mutations.lock();
        defer self.mutations.unlock();
        try self.finishDraftLocked(a, user, doc);
    }

    fn finishDraftLocked(self: *Service, a: std.mem.Allocator, user: []const u8, doc: Outbox) !void {
        const id = doc.message.draftId orelse return;
        const row = store.get(a, self.db, user, "draft", id) catch |err| {
            if (err == store.StoreError.NotFound) return;
            return err;
        };
        if (!std.mem.eql(u8, row.state, "queued")) return;
        const draft = try std.json.parseFromSlice(Draft, a, row.payload, .{ .ignore_unknown_fields = true });
        defer draft.deinit();
        if (doc.result) |result| {
            if (result.failed.len == 0 and result.delivered > 0) {
                if (std.mem.eql(u8, draft.value.folder, "Drafts")) _ = maildir.moveMessage(a, self.db, user, "Drafts", draft.value.uid, "Trash") catch |err| blk: {
                    if (err != maildir.MaildirError.MessageNotFound) return err;
                    // A previous cleanup may have moved the file before dropping the draft record.
                    break :blk 0;
                };
                try store.remove(self.db, user, "draft", id);
                return;
            }
        }
        if (!std.mem.eql(u8, draft.value.folder, "Drafts")) return ServiceError.Conflict;
        var retry = draft.value.message;
        retry.scheduleAt = null;
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
        const gives_feedback = payload.action == .junk or payload.action == .not_junk;
        self.db.lockMailboxes();
        defer self.db.unlockMailboxes();
        const selection = try a.dupe(MessageRef, payload.messages);
        // Preflight the complete selection, without retaining decoded attachments.
        for (selection, 0..) |*ref, index| {
            var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer scratch.deinit();
            if (ref.reference) |id| {
                const expected = ref.revision orelse return ServiceError.InvalidPayload;
                const locator = try maildir.checkRevision(scratch.allocator(), self.db, user, id, expected);
                ref.uid = locator.uid;
                ref.folder = try a.dupe(u8, locator.folder);
            } else {
                if (gives_feedback or ref.revision != null or ref.uid < 1 or !maildir.isValidFolderName(ref.folder)) return ServiceError.InvalidPayload;
                if (std.ascii.eqlIgnoreCase(ref.folder, "INBOX")) ref.folder = "INBOX";
                _ = try maildir.rawMessage(scratch.allocator(), self.db, user, ref.folder, ref.uid);
            }
            if (payload.action == .purge and !std.mem.eql(u8, ref.folder, "Trash")) return ServiceError.InvalidAction;
            if (payload.action == .junk and !self.canMarkJunk(ref.folder)) return ServiceError.InvalidAction;
            if (payload.action == .not_junk and !self.isJunkFolder(ref.folder)) return ServiceError.InvalidAction;
            for (selection[0..index]) |prior| if (prior.uid == ref.uid and std.mem.eql(u8, prior.folder, ref.folder)) return ServiceError.InvalidPayload;
        }
        var entries: std.ArrayList(UndoEntry) = .empty;
        var results: std.ArrayList(ActionResult) = .empty;
        var all_ok = true;
        for (selection) |ref| {
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
            const feedback: ?message_refs.JunkChange = if (gives_feedback) .{
                .action = if (payload.action == .junk) .junk else .not_junk,
                .receipt = try store.newId(a),
            } else null;
            const purge = payload.action == .purge or (payload.action == .delete and std.mem.eql(u8, ref.folder, "Trash"));
            const moved = gives_feedback or payload.action == .move or payload.action == .trash or (payload.action == .delete and !purge);
            const action_ok = blk: {
                if (purge) {
                    maildir.deleteMessageLocked(temp, self.db, user, ref.folder, ref.uid) catch break :blk false;
                    self.updateDraftLocation(a, user, ref, null) catch {};
                } else if (moved) {
                    destination.folder = switch (payload.action) {
                        .move => payload.folder,
                        .junk => self.junkFolder(),
                        .not_junk => try self.recoverJunkFolder(a, user, ref.reference.?),
                        else => "Trash",
                    };
                    destination.uid = maildir.moveWithFeedbackLocked(temp, self.db, user, ref.folder, ref.uid, destination.folder, feedback) catch break :blk false;
                    self.updateDraftLocation(a, user, ref, destination) catch {};
                } else {
                    switch (payload.action) {
                        .read => after.seen = true,
                        .unread => after.seen = false,
                        .flag => after.flagged = true,
                        .unflag => after.flagged = false,
                        else => unreachable,
                    }
                    _ = maildir.setFlagsLocked(temp, self.db, user, ref.folder, ref.uid, after) catch break :blk false;
                }
                break :blk true;
            };
            if (action_ok and !purge) {
                const raw = try maildir.rawMessage(temp, self.db, user, destination.folder, destination.uid);
                if (ref.reference != null) {
                    const version = try maildir.versionAt(temp, self.db, user, destination.folder, destination.uid);
                    destination.reference = try a.dupe(u8, version.reference);
                    destination.revision = try a.dupe(u8, version.revision);
                }
                try entries.append(a, .{
                    .original = ref,
                    .current = destination,
                    .before = item.flags,
                    .after = after,
                    .fingerprint = try fingerprint(a, raw),
                    .moved = moved,
                    .junkReceipt = if (feedback) |change| change.receipt else null,
                });
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
        self.db.lockMailboxes();
        defer self.db.unlockMailboxes();
        var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer scratch.deinit();
        const temp = scratch.allocator();
        if (entry.current.reference) |id| {
            _ = maildir.checkRevision(temp, self.db, user, id, entry.current.revision.?) catch |err| switch (err) {
                maildir.MaildirError.MessageNotFound, maildir.MaildirError.RevisionMismatch => return ServiceError.MessageChanged,
                else => return err,
            };
        }
        const message = try maildir.getMessage(temp, self.db, user, entry.current.folder, entry.current.uid);
        const raw = try maildir.rawMessage(temp, self.db, user, entry.current.folder, entry.current.uid);
        if (!std.meta.eql(message.flags, entry.after) or !std.mem.eql(u8, try fingerprint(temp, raw), entry.fingerprint)) return ServiceError.MessageChanged;
        var location = entry.current;
        if (entry.moved and !std.mem.eql(u8, entry.current.folder, entry.original.folder)) {
            location.folder = entry.original.folder;
            const feedback: ?message_refs.JunkChange = if (entry.junkReceipt) |receipt| .{ .action = .undo, .receipt = receipt } else null;
            location.uid = try maildir.moveWithFeedbackLocked(temp, self.db, user, entry.current.folder, entry.current.uid, location.folder, feedback);
            try self.updateDraftLocation(a, user, entry.current, location);
        } else _ = try maildir.setFlagsLocked(temp, self.db, user, location.folder, location.uid, entry.before);
        return location;
    }
};

pub fn json(a: std.mem.Allocator, value: anytype) ![]const u8 {
    return std.json.Stringify.valueAlloc(a, value, .{});
}

pub const validFilename = attachment_metadata.validFilename;
pub const validContentType = attachment_metadata.validContentType;

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

fn sendFingerprint(a: std.mem.Allocator, payload: Payload) ![]const u8 {
    const raw = try json(a, payload);
    // Compact receipts retain the request digest after the message is pruned.
    // Omit new optional fields when absent to match receipts from older builds.
    var legacy = try std.json.parseFromSliceLeaky(std.json.Value, a, raw, .{});
    if (!payload.clearFollowUp) _ = legacy.object.orderedRemove("clearFollowUp");
    if (payload.scheduleAt == null) _ = legacy.object.orderedRemove("scheduleAt");
    if (payload.senderId == null) _ = legacy.object.orderedRemove("senderId");
    if (payload.externalReview == null) _ = legacy.object.orderedRemove("externalReview");
    if (payload.sharedReply == null) _ = legacy.object.orderedRemove("sharedReply");
    return fingerprint(a, try json(a, legacy));
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
