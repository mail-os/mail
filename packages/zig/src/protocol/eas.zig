const std = @import("std");
const clamav = @import("../antispam/clamav.zig");
const smart_mime = @import("../message/smart_mime.zig");
const message_headers = @import("../message/submission.zig");
const submission = @import("../delivery/submission.zig");
const config = @import("../core/config.zig");
const wbxml = @import("wbxml.zig");
const database = @import("../storage/database.zig");
const caldav_store = @import("../storage/caldav_store.zig");
const search = @import("eas_search.zig");
const sync_state = @import("eas_state.zig");
const webmail_maildir = @import("../api/webmail_maildir.zig");
const webmail_store = @import("../api/webmail_store.zig");
const snapshots = @import("../api/webmail_snapshots.zig");
const message_refs = @import("../storage/message_refs.zig");
const thread_ids = @import("../message/thread_ids.zig");
const fs_compat = @import("../core/fs_compat.zig");
const io_compat = @import("../core/io_compat.zig");
const maildir_path = @import("../core/maildir_path.zig");
const time_compat = @import("../core/time_compat.zig");

/// Exchange ActiveSync command handlers (MS-ASCMD), transport-agnostic.
///
/// Each handler decodes the WBXML request body and produces a WBXML response.
/// The caller (the TLS HTTP front-end) handles HTTP framing, Basic auth, and
/// the query string (`?Cmd=`, `DeviceId=`).
///
/// Data sources:
///   * Email — the Maildir, with a persistent per-mailbox, device and collection
///     snapshot in SQLite so Add/Change(read flag)/Delete are computed by diff.
///   * Calendar / Contacts — revisions from the persistent CalDAV/CardDAV
///     store, compared with the same per-mailbox snapshot.
const CONTENT_TYPE = "application/vnd.ms-sync.wbxml";

/// Maximum email items emitted in a single Sync response.
const SYNC_WINDOW: usize = 50;
/// Maximum message body bytes sent inline.
const MAX_BODY: usize = 32 * 1024;
/// Ping poll granularity and ceiling (seconds).
const PING_INTERVAL_S: u64 = 20;
const PING_MAX_HEARTBEAT_S: u64 = 600;

pub const Context = struct {
    allocator: std.mem.Allocator,
    db: *database.Database,
    store: *caldav_store.CalDavStore,
    /// Login identity (full email address).
    username: []const u8,
    /// Maildir key. Hosted accounts use their canonical full address.
    local_part: []const u8,
    /// Device identifier from the query string (sync state is keyed on it).
    device_id: []const u8,
    protocol_version: u8 = 141,
    hosted: bool = false,
    mail_config: ?*const config.Config = null,
    scanner: ?*clamav.ClamAVScanner = null,
    send_format: SendFormat = .wbxml,
    save_legacy_copy: bool = false,
    legacy_source: MessageSource = .{},
    legacy_forward_attachment: bool = false,
};

pub const SendFormat = enum { wbxml, mime, invalid };

pub const Response = struct {
    status: u16 = 200,
    /// WBXML body allocated from `Context.allocator`; caller owns and frees it
    /// when non-empty. The default empty body is a static literal (never freed).
    body: []const u8 = "",
    content_type: []const u8 = CONTENT_TYPE,
};

const FolderDef = struct {
    id: []const u8,
    parent: []const u8,
    name: []const u8,
    /// EAS folder type (2=Inbox,3=Drafts,4=Trash,5=Sent,8=Calendar,9=Contacts).
    kind: u8,
    /// Maildir mailbox backing this folder, or null for non-mail collections.
    mailbox: ?[]const u8,
    /// True for the Calendar collection, false for Contacts (only meaningful
    /// when `mailbox` is null).
    is_calendar: bool,
};

const FOLDERS = [_]FolderDef{
    .{ .id = "1", .parent = "0", .name = "Inbox", .kind = 2, .mailbox = "INBOX", .is_calendar = false },
    .{ .id = "2", .parent = "0", .name = "Drafts", .kind = 3, .mailbox = "Drafts", .is_calendar = false },
    .{ .id = "3", .parent = "0", .name = "Sent", .kind = 5, .mailbox = "Sent", .is_calendar = false },
    .{ .id = "4", .parent = "0", .name = "Trash", .kind = 4, .mailbox = "Trash", .is_calendar = false },
    .{ .id = "5", .parent = "0", .name = "Calendar", .kind = 8, .mailbox = null, .is_calendar = true },
    .{ .id = "6", .parent = "0", .name = "Contacts", .kind = 9, .mailbox = null, .is_calendar = false },
};

fn folderById(id: []const u8) ?FolderDef {
    for (FOLDERS) |f| {
        if (std.mem.eql(u8, f.id, id)) return f;
    }
    return null;
}

// ============================================================================
// Dispatch
// ============================================================================

/// Route an EAS command to its handler. `cmd` is the `Cmd` query value; `body`
/// is the raw WBXML request body (possibly empty).
pub fn dispatch(ctx: *Context, cmd: []const u8, body: []const u8) !Response {
    if (std.ascii.eqlIgnoreCase(cmd, "SendMail")) return handleComposeMail(ctx, .send_mail, body);
    if (std.ascii.eqlIgnoreCase(cmd, "SmartReply")) return handleComposeMail(ctx, .smart_reply, body);
    if (std.ascii.eqlIgnoreCase(cmd, "SmartForward")) return handleComposeMail(ctx, .smart_forward, body);
    if (std.ascii.eqlIgnoreCase(cmd, "Search")) return handleSearch(ctx, body);
    if (std.ascii.eqlIgnoreCase(cmd, "MoveItems")) return handleMoveItems(ctx, body);
    if (std.mem.eql(u8, cmd, "Provision")) return handleProvision(ctx, body);
    if (std.mem.eql(u8, cmd, "FolderSync")) return handleFolderSync(ctx, body);
    const command = std.meta.stringToEnum(enum { Sync, GetItemEstimate, Ping }, cmd) orelse return .{ .status = 501 };
    if (!validDevice(ctx.device_id)) return .{ .status = 400 };
    var user = ctx.db.getUserByUsername(ctx.username) catch |err| return .{ .status = if (err == error.NotFound) 401 else 503 };
    defer user.deinit(ctx.db.allocator);
    if (!user.enabled) return .{ .status = 403 };
    const account = sync_state.Account{ .db = ctx.db, .user_id = user.id, .device_id = ctx.device_id };
    return switch (command) {
        .Sync => handleSync(ctx, account, body),
        .GetItemEstimate => handleGetItemEstimate(ctx, account, body),
        .Ping => handlePing(ctx, account, body),
    };
}

fn validDevice(id: []const u8) bool {
    if (id.len == 0 or id.len > 32) return false;
    for (id) |byte| if (!std.ascii.isAlphanumeric(byte)) return false;
    return true;
}

// ComposeMail in EAS 14.x uses opaque WBXML MIME. Older advertised clients
// submit MIME directly and receive HTTP errors instead of ComposeMail status.
const SendStatus = enum(u8) {
    protocol_error = 103,
    invalid_datetime = 104,
    invalid_id_combination = 105,
    invalid_ids = 106,
    invalid_mime = 107,
    invalid_device = 108,
    retry_later = 111,
    mailbox_quota = 113,
    send_quota = 115,
    invalid_recipient = 116,
    already_accepted = 118,
    no_recipients = 119,
    submission_failed = 120,
    message_too_large = 122,
    no_mailbox = 123,
    access_denied = 130,
    unsupported_item = 147,
    item_not_found = 150,
};

const ComposeCommand = enum(u8) {
    send_mail = wbxml.ComposeMail.SendMail,
    smart_forward = wbxml.ComposeMail.SmartForward,
    smart_reply = wbxml.ComposeMail.SmartReply,
};

fn sendError(ctx: *Context, op: ComposeCommand, status: SendStatus) !Response {
    if (ctx.send_format != .wbxml) return .{ .status = switch (status) {
        .mailbox_quota => 507,
        .send_quota => 503,
        .access_denied, .no_mailbox => 403,
        .message_too_large => 413,
        .retry_later => 503,
        .submission_failed => 500,
        .item_not_found => 404,
        .unsupported_item => 501,
        else => 400,
    } };
    var w = wbxml.Writer.init(ctx.allocator);
    errdefer w.deinit();
    try w.writeHeader();
    try w.startTag(wbxml.Page.compose_mail, @backingInt(op));
    try w.elementInt(wbxml.Page.compose_mail, wbxml.ComposeMail.Status, @backingInt(status));
    try w.end();
    return .{ .body = try w.toOwnedSlice() };
}

pub const MessageSource = struct {
    folder_id: ?[]const u8 = null,
    item_id: ?[]const u8 = null,
    long_id: ?[]const u8 = null,
    instance_id: ?[]const u8 = null,
};

const SendRequest = struct {
    mime: []const u8,
    save_copy: bool = false,
    client_id: ?[]const u8 = null,
    source: ?MessageSource = null,
    replace_mime: bool = false,
};

fn composeMailRequest(a: std.mem.Allocator, op: ComposeCommand, body: []const u8) !SendRequest {
    const root = try wbxml.decode(a, body);
    const page = wbxml.Page.compose_mail;
    const tags = wbxml.ComposeMail;
    if (root.children.items.len != 1) return error.InvalidRequest;
    const command = root.children.items[0];
    if (command.page != page or command.token != @backingInt(op) or command.text != null) return error.InvalidRequest;
    var mime: ?[]const u8 = null;
    var client_id: ?[]const u8 = null;
    var save_copy = false;
    var source: ?MessageSource = null;
    var replace_mime = false;
    for (command.children.items) |node| {
        if (node.page != page) return error.InvalidRequest;
        if (node.token == tags.Source) {
            if (op == .send_mail or source != null) return error.InvalidRequest;
            source = try composeSource(node);
            continue;
        }
        if (node.children.items.len != 0) return error.InvalidRequest;
        switch (node.token) {
            tags.Mime => {
                if (mime != null or !node.is_opaque) return error.InvalidMime;
                mime = node.text orelse return error.InvalidMime;
            },
            tags.ClientId => {
                if (client_id != null or node.is_opaque) return error.InvalidRequest;
                const value = node.text orelse return error.InvalidRequest;
                const characters = std.unicode.utf8CountCodepoints(value) catch return error.InvalidRequest;
                if (characters == 0 or characters > 40) return error.InvalidRequest;
                for (value) |b| {
                    if (b < 32 or b == 127) return error.InvalidRequest;
                }
                client_id = value;
            },
            tags.SaveInSentItems => {
                if (save_copy or node.text != null) return error.InvalidRequest;
                save_copy = true;
            },
            tags.ReplaceMime => {
                if (op == .send_mail or replace_mime or node.text != null) return error.InvalidRequest;
                replace_mime = true;
            },
            tags.AccountId => return error.AlternateAccount,
            else => return error.InvalidRequest,
        }
    }
    if (op != .send_mail and source == null) return error.InvalidIds;
    return .{
        .mime = mime orelse return error.InvalidMime,
        .client_id = client_id orelse return error.InvalidRequest,
        .save_copy = save_copy,
        .source = source,
        .replace_mime = replace_mime,
    };
}

fn composeSource(node: wbxml.Node) !MessageSource {
    const tags = wbxml.ComposeMail;
    if (node.text != null) return error.InvalidIds;
    var source: MessageSource = .{};
    for (node.children.items) |child| {
        if (child.page != wbxml.Page.compose_mail or child.is_opaque or child.children.items.len != 0) return error.InvalidIds;
        const value = child.text orelse return error.InvalidIds;
        if (value.len == 0 or value.len > 256) return error.InvalidIds;
        const slot = switch (child.token) {
            tags.FolderId => &source.folder_id,
            tags.ItemId => &source.item_id,
            tags.LongId => &source.long_id,
            tags.InstanceId => &source.instance_id,
            else => return error.InvalidIds,
        };
        if (slot.* != null) return error.InvalidIdCombination;
        slot.* = value;
    }
    return source;
}

fn handleComposeMail(ctx: *Context, op: ComposeCommand, body: []const u8) !Response {
    if (ctx.send_format == .invalid) return .{ .status = 400 };
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const req = if (ctx.send_format == .wbxml)
        composeMailRequest(a, op, body) catch |err| return sendError(ctx, op, switch (err) {
            error.AlternateAccount => .access_denied,
            error.InvalidMime => .invalid_mime,
            error.InvalidIds, error.InvalidIdCombination => sourceStatus(err),
            error.OutOfMemory => .retry_later,
            else => .protocol_error,
        })
    else
        SendRequest{
            .mime = body,
            .save_copy = ctx.save_legacy_copy,
            .source = if (op == .send_mail) null else ctx.legacy_source,
        };
    if (req.client_id != null and !validDevice(ctx.device_id)) return sendError(ctx, op, .invalid_device);

    const limits = ctx.mail_config orelse return sendError(ctx, op, .retry_later);
    if (req.mime.len > limits.max_message_size) return sendError(ctx, op, .message_too_large);
    var user = ctx.db.getUserByUsername(ctx.username) catch |err| return sendError(ctx, op, if (err == error.NotFound) .no_mailbox else .retry_later);
    defer user.deinit(ctx.db.allocator);
    if (!user.enabled) return sendError(ctx, op, .access_denied);

    const message = message_headers.prepareClientMime(a, req.mime, user.email) catch |err|
        return sendError(ctx, op, switch (err) {
            error.InvalidAddress => .invalid_recipient,
            error.OutOfMemory => .retry_later,
            else => .invalid_mime,
        });
    const receipt: ?database.Database.ActiveSyncReceipt = if (req.client_id) |id| .{ .device_id = ctx.device_id, .client_id = id } else null;
    // A replay of an accepted operation needs neither the original item nor
    // another scan. The send reservation repeats this check under lock.
    if (receipt) |accepted| {
        if (ctx.db.activeSyncAccepted(ctx.username, accepted, time_compat.timestamp()) catch
            return sendError(ctx, op, .retry_later)) return sendError(ctx, op, .already_accepted);
    }
    const capture_reply = op == .smart_reply and req.save_copy and !message.has_bcc and
        (ctx.db.hasFollowedSentReplies(ctx.username) catch false);
    var parent: ?database.Database.TeamReplySource = null;
    var archive = if (req.source) |source| blk: {
        const original = sourceMime(a, ctx, user.id, source, !req.replace_mime, capture_reply, limits.max_message_size) catch |err|
            return sendError(ctx, op, sourceStatus(err));
        parent = original.reply_source;
        if (req.replace_mime) break :blk message.archive;
        const mode: smart_mime.Mode = if (op == .smart_reply) .reply else if (ctx.legacy_forward_attachment) .attachment else .forward;
        break :blk smart_mime.withOriginal(a, message.archive, original.mime, mode, limits.max_message_size) catch |err|
            return sendError(ctx, op, switch (err) {
                error.MessageTooLarge => .message_too_large,
                error.OutOfMemory => .retry_later,
                else => .invalid_mime,
            });
    } else message.archive;
    if (archive.len > limits.max_message_size) return sendError(ctx, op, .message_too_large);
    const recipients = submission.distinctRecipients(a, &.{message.recipients}) catch |err|
        return sendError(ctx, op, if (err == error.InvalidAddress) .invalid_recipient else .retry_later);
    if (recipients.len == 0) return sendError(ctx, op, .no_recipients);
    const native_reply = if (parent) |reply_source|
        submission.prepareNativeReply(a, ctx.db, ctx.username, archive, recipients, reply_source, limits.hostname, limits.max_message_size) catch null
    else
        null;
    if (native_reply) |reply| archive = reply.archive;
    // SmartReply and SmartForward can add content from the original message.
    // Scan the assembled MIME before allocating a receipt or filing a copy.
    clamav.requireAllowed(ctx.scanner, archive) catch |err| return sendError(ctx, op, switch (err) {
        error.MalwareDetected => .submission_failed,
        error.MalwareScanTooLarge => .message_too_large,
        error.MalwareScanUnavailable => .retry_later,
    });
    const raw = try message_headers.withoutBcc(a, archive);
    const sent_path = if (req.save_copy)
        submission.maildirPath(a, ctx.local_part, "Sent", ":2,S") catch return sendError(ctx, op, .retry_later)
    else
        null;

    submission.sendRaw(a, .{
        .hostname = limits.hostname,
        .delivery_method = limits.delivery_method,
        .ses_region = limits.ses_region,
        .mail_config = limits,
        .db = ctx.db,
    }, .{
        .mailbox = ctx.username,
        .from = user.email,
        .recipients = recipients,
        .raw = raw,
        .sent = if (sent_path) |path| .{ .path = path, .bytes = archive } else null,
        .receipt = receipt,
        .native_reply = native_reply,
    }) catch |err| return sendError(ctx, op, switch (err) {
        error.HostedStorageFull => .mailbox_quota,
        error.HostedSendingLimit => .send_quota,
        error.HostedSenderDisabled, error.HostedRecipientDisabled => .access_denied,
        error.MessagePreviouslySent => .already_accepted,
        error.InvalidAddress => .invalid_recipient,
        else => .submission_failed,
    });
    return .{};
}

fn sourceStatus(err: anyerror) SendStatus {
    return switch (err) {
        error.InvalidIds => .invalid_ids,
        error.InvalidDateTime => .invalid_datetime,
        error.InvalidIdCombination => .invalid_id_combination,
        error.ItemNotFound => .item_not_found,
        error.UnsupportedItem => .unsupported_item,
        error.AmbiguousMailbox => .access_denied,
        error.MessageTooLarge => .message_too_large,
        else => .retry_later,
    };
}

const ComposeSource = struct {
    mime: []const u8 = "",
    reply_source: ?database.Database.TeamReplySource = null,
};

fn sourceMime(a: std.mem.Allocator, ctx: *Context, user_id: i64, source: MessageSource, include_contents: bool, capture_reply: bool, max_bytes: usize) !ComposeSource {
    if (source.long_id != null and (source.item_id != null or source.folder_id != null)) return error.InvalidIdCombination;
    if (source.instance_id) |instance| {
        if (search.utcMilliseconds(instance) == null) return error.InvalidDateTime;
        return error.UnsupportedItem; // Calendar occurrences need scheduling MIME, not mail quoting.
    }
    ctx.db.lockMailboxes();
    defer ctx.db.unlockMailboxes();
    try requireMailboxOwner(a, ctx);

    const reference = if (source.long_id) |id| try resolveSearchId(a, ctx, user_id, id) else blk: {
        const folder = folderById(source.folder_id orelse "1") orelse return error.ItemNotFound;
        if (folder.mailbox == null) return error.UnsupportedItem;
        const id = source.item_id orelse return error.InvalidIds;
        const uid = if (std.mem.count(u8, id, ":") == 2)
            (try resolveMailItemId(a, ctx, user_id, folder, id)).uid
        else
            try itemUid(folder.id, id);
        break :blk MailReference{ .folder = folder, .uid = uid };
    };
    const folder = reference.folder;
    const mailbox = folder.mailbox orelse return error.UnsupportedItem;
    const base = (try ctx.db.getFilenameForUid(a, ctx.username, mailbox, reference.uid)) orelse return error.ItemNotFound;
    for (try mailboxDirs(a, ctx, mailbox)) |dir| {
        const files = fs_compat.listEmlFiles(a, dir) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        for (files) |name| {
            if (!std.mem.eql(u8, base, maildirBaseName(name))) continue;
            const path = try std.fmt.allocPrint(a, "{s}/{s}", .{ dir, name });
            const size = fs_compat.getFileSize(path) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => return err,
            };
            const eligible = capture_reply and snapshots.canShareFile(mailbox, webmail_maildir.flagsFrom(name), if (ctx.mail_config) |cfg| cfg.junkFolder() else "Junk");
            if (!include_contents and (!eligible or size > max_bytes)) return .{};
            if (size > max_bytes) return error.MessageTooLarge;
            const bytes = fs_compat.readFileAlloc(a, path) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => if (include_contents) return err else return .{},
            };
            if (bytes.len > max_bytes) return if (include_contents) error.MessageTooLarge else .{};
            return .{
                .mime = bytes,
                .reply_source = if (eligible) followedReplySource(a, ctx, mailbox, name, path, bytes) catch null else null,
            };
        }
    }
    return error.ItemNotFound;
}

fn followedReplySource(a: std.mem.Allocator, ctx: *Context, mailbox: []const u8, name: []const u8, path: []const u8, bytes: []const u8) !?database.Database.TeamReplySource {
    const stamp = try message_refs.fileStamp(a, path);
    const reference = (try message_refs.findAt(a, ctx.db, ctx.username, message_refs.location(mailbox, name), stamp)) orelse return null;
    const ids = try thread_ids.parse(a, bytes);
    if (ids.message_id_fields != 1) return null;
    return .{
        .reference = reference,
        .revision = message_refs.digest(bytes),
        .wire_id = ids.own orelse return null,
    };
}

fn itemUid(folder_id: []const u8, item: []const u8) !i64 {
    if (item.len == 0 or item.len > 64) return error.InvalidIds;
    const uid_text = if (std.mem.indexOfScalar(u8, item, ':')) |colon| blk: {
        if (!std.mem.eql(u8, folder_id, item[0..colon])) return error.InvalidIdCombination;
        break :blk item[colon + 1 ..];
    } else item;
    if (uid_text.len == 0) return error.InvalidIds;
    for (uid_text) |byte| {
        if (!std.ascii.isDigit(byte)) return error.InvalidIds;
    }
    const uid = std.fmt.parseInt(i64, uid_text, 10) catch return error.InvalidIds;
    if (uid < 1) return error.InvalidIds;
    return uid;
}

fn requireMailboxOwner(a: std.mem.Allocator, ctx: *Context) !void {
    // Legacy EAS roots use a short name. Resolve a source there only when
    // that key uniquely identifies the authenticated mailbox.
    if (!std.mem.eql(u8, ctx.local_part, ctx.username)) {
        if (try ctx.db.userExists(ctx.local_part)) return error.AmbiguousMailbox;
        const owner = (try ctx.db.uniqueUsernameForLocalPart(ctx.local_part, a)) orelse return error.AmbiguousMailbox;
        if (!std.mem.eql(u8, owner, ctx.username)) return error.AmbiguousMailbox;
    }
}

// A Search LongId is valid only for the issuing account and the original
// UID in its folder. A move or UID generation change requires another search.
const MailReference = struct { folder: FolderDef, uid: i64 };
const SearchKey = [32]u8;

fn searchKey(db: *database.Database, user_id: i64, create: bool) !SearchKey {
    if (create) {
        const put = try db.prepare("INSERT OR IGNORE INTO eas_search_keys(user_id,key) VALUES (?1,?2)");
        defer put.finalize();
        var key: SearchKey = undefined;
        io_compat.randomBytes(&key);
        try put.bind(1, user_id);
        try put.bindBlob(2, &key);
        _ = try put.step();
    }
    const get = try db.prepare("SELECT hex(key) FROM eas_search_keys WHERE user_id=?1");
    defer get.finalize();
    try get.bind(1, user_id);
    if (!try get.step()) return error.ItemNotFound;
    const raw = get.columnText(0);
    if (raw.len != 2 * @sizeOf(SearchKey)) return error.InvalidSearchKey;
    var key: SearchKey = undefined;
    _ = try std.fmt.hexToBytes(&key, raw);
    return key;
}

fn mailIdSignature(key: SearchKey, domain: []const u8, folder_id: []const u8, uid: i64, validity: i64, filename: []const u8) [64]u8 {
    const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac = Hmac.init(&key);
    mac.update(domain);
    var numbers: [16]u8 = undefined;
    std.mem.writeInt(i64, numbers[0..8], uid, .big);
    std.mem.writeInt(i64, numbers[8..16], validity, .big);
    mac.update(&numbers);
    mac.update(folder_id);
    mac.update("\x00");
    mac.update(filename);
    var digest: [Hmac.mac_length]u8 = undefined;
    mac.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

fn searchSignature(key: SearchKey, folder_id: []const u8, uid: i64, validity: i64, filename: []const u8) [64]u8 {
    return mailIdSignature(key, "mail/eas-search/v1\x00", folder_id, uid, validity, filename);
}

const item_tag_len = 32; // 128 bits, to keep Sync and MoveItems IDs within 64 characters.
const item_id_domain = "mail/eas-item/v1\x00";

fn formatMailItemId(buf: []u8, key: SearchKey, folder: FolderDef, uid: i64, validity: i64, base: []const u8) []const u8 {
    const tag = mailIdSignature(key, item_id_domain, folder.id, uid, validity, base);
    return std.fmt.bufPrint(buf, "{s}:{d}:{s}", .{ folder.id, uid, tag[0..item_tag_len] }) catch unreachable;
}

fn resolveMailItemId(a: std.mem.Allocator, ctx: *Context, user_id: i64, folder: FolderDef, id: []const u8) !struct { uid: i64, base: []const u8 } {
    if (id.len > 64) return error.ItemNotFound;
    var parts = std.mem.splitScalar(u8, id, ':');
    if (!std.mem.eql(u8, parts.first(), folder.id)) return error.InvalidIdCombination;
    const uid = itemUid(folder.id, parts.next() orelse return error.ItemNotFound) catch return error.ItemNotFound;
    const tag = parts.next() orelse return error.ItemNotFound;
    if (tag.len != item_tag_len or parts.next() != null) return error.ItemNotFound;
    const mailbox = folder.mailbox orelse return error.ItemNotFound;
    const base = (try ctx.db.getFilenameForUid(a, ctx.username, mailbox, uid)) orelse return error.ItemNotFound;
    const generation = try ctx.db.getOrCreateMailbox(ctx.username, mailbox);
    const key = try searchKey(ctx.db, user_id, false);
    const expected = mailIdSignature(key, item_id_domain, folder.id, uid, generation.uidvalidity, base);
    if (!std.crypto.timing_safe.eql([item_tag_len]u8, expected[0..item_tag_len].*, tag[0..item_tag_len].*)) return error.ItemNotFound;
    return .{ .uid = uid, .base = base };
}

fn resolveSearchId(a: std.mem.Allocator, ctx: *Context, user_id: i64, id: []const u8) !MailReference {
    var parts = std.mem.splitScalar(u8, id, ':');
    if (!std.mem.eql(u8, parts.first(), "s1")) return error.ItemNotFound;
    const folder = folderById(parts.next() orelse return error.ItemNotFound) orelse return error.ItemNotFound;
    const mailbox = folder.mailbox orelse return error.ItemNotFound;
    const uid = itemUid(folder.id, parts.next() orelse return error.ItemNotFound) catch return error.ItemNotFound;
    const tag = parts.next() orelse return error.ItemNotFound;
    if (tag.len != 64 or parts.next() != null) return error.ItemNotFound;
    const key = try searchKey(ctx.db, user_id, false);
    const base = (try ctx.db.getFilenameForUid(a, ctx.username, mailbox, uid)) orelse return error.ItemNotFound;
    const generation = try ctx.db.getOrCreateMailbox(ctx.username, mailbox);
    const expected = searchSignature(key, folder.id, uid, generation.uidvalidity, base);
    if (!std.crypto.timing_safe.eql([64]u8, expected, tag[0..64].*)) return error.ItemNotFound;
    return .{ .folder = folder, .uid = uid };
}

const SearchItem = struct { mail: MailItem, folder: FolderDef, validity: i64 };

fn handleSearch(ctx: *Context, body: []const u8) !Response {
    if (ctx.protocol_version < 120) return .{ .status = 501 };
    if (body.len > 16 * 1024) return .{ .status = 400 };
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const page = wbxml.Page.search;
    const S = wbxml.Search;
    const root = wbxml.decode(a, body) catch return .{ .status = 400 };
    if (root.children.items.len != 1) return .{ .status = 400 };
    const command = root.child(page, S.Search) orelse return .{ .status = 400 };
    const query = search.parse(command.*) catch return searchStatus(ctx, 2);
    if (query.collection) |id| {
        const folder = folderById(id) orelse return searchStatus(ctx, 11);
        if (folder.mailbox == null) return searchStatus(ctx, 2);
    }
    requireMailboxOwner(a, ctx) catch |err| return searchStatus(ctx, if (err == error.AmbiguousMailbox) 5 else 3);
    return searchMailbox(ctx, a, query) catch |err| searchStatus(ctx, if (err == error.SearchLimit) 10 else 3);
}

fn searchStatus(ctx: *Context, status: u8) !Response {
    var w = wbxml.Writer.init(ctx.allocator);
    errdefer w.deinit();
    try startSearchResponse(&w, status);
    try w.end(); // Store
    try w.end(); // Response
    try w.end(); // Search
    return .{ .body = try w.toOwnedSlice() };
}

fn startSearchResponse(w: *wbxml.Writer, status: u8) !void {
    const S = wbxml.Search;
    const page = wbxml.Page.search;
    try w.writeHeader();
    try w.startTag(page, S.Search);
    try w.element(page, S.Status, "1");
    try w.startTag(page, S.Response);
    try w.startTag(page, S.Store);
    try w.elementInt(page, S.Status, status);
}

fn searchCandidates(ctx: *Context, a: std.mem.Allocator, query: search.Query) ![]SearchItem {
    ctx.db.lockMailboxes();
    defer ctx.db.unlockMailboxes();
    var candidates: std.ArrayList(SearchItem) = .empty;
    for (FOLDERS) |folder| {
        const mailbox = folder.mailbox orelse continue;
        if (query.collection) |id| if (!std.mem.eql(u8, id, folder.id)) continue;
        var items: std.ArrayList(MailItem) = .empty;
        try collectMail(a, ctx, mailbox, 10_000 - candidates.items.len, &items);
        if (items.items.len == 0) continue;
        const generation = try ctx.db.getOrCreateMailbox(ctx.username, mailbox);
        var seen: std.AutoHashMapUnmanaged(i64, void) = .empty;
        for (items.items) |item| {
            if ((try seen.getOrPut(a, item.uid)).found_existing) continue;
            try candidates.append(a, .{ .mail = item, .folder = folder, .validity = generation.uidvalidity });
        }
    }
    return candidates.items;
}

fn searchMailbox(ctx: *Context, a: std.mem.Allocator, query: search.Query) !Response {
    const S = wbxml.Search;
    const page = wbxml.Page.search;
    var user = try ctx.db.getUserByUsername(ctx.username);
    defer user.deinit(ctx.db.allocator);
    if (!user.enabled) return searchStatus(ctx, 5);
    const candidates = try searchCandidates(ctx, a, query);
    std.mem.sort(SearchItem, candidates, {}, struct {
        fn less(_: void, left: SearchItem, right: SearchItem) bool {
            if (left.mail.epoch != right.mail.epoch) return left.mail.epoch > right.mail.epoch;
            if (left.folder.kind != right.folder.kind) return left.folder.kind < right.folder.kind;
            return left.mail.uid > right.mail.uid;
        }
    }.less);
    var w = wbxml.Writer.init(ctx.allocator);
    errdefer w.deinit();
    try startSearchResponse(&w, 1);
    var scanned: u64 = 0;
    var total: usize = 0;
    var emitted: usize = 0;
    var key: ?SearchKey = null;
    for (candidates) |item| {
        const epoch = item.mail.epoch;
        const timestamp = std.math.mul(i64, epoch, 1000) catch continue;
        if (query.after) |after| if (timestamp <= after) continue;
        if (query.before) |before| if (timestamp >= before) continue;
        const bytes = fs_compat.getFileSize(item.mail.path) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        if (bytes > 256 * 1024 * 1024 - scanned) return error.SearchLimit;
        scanned += bytes;
        var scratch = std.heap.ArenaAllocator.init(ctx.allocator);
        defer scratch.deinit();
        const temp = scratch.allocator();
        const raw = fs_compat.readFileAlloc(temp, item.mail.path) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        const hit = (try webmail_maildir.matchMime(temp, raw, query.keywords orelse "")) orelse continue;
        const index = total;
        total += 1;
        if (index < query.first or emitted == query.count) continue;
        if (key == null) key = try searchKey(ctx.db, user.id, true);
        try writeSearchResult(temp, &w, key.?, item, hit, query.body_limit);
        emitted += 1;
    }
    if (emitted > 0) {
        try w.element(page, S.Range, try std.fmt.allocPrint(a, "{d}-{d}", .{ query.first, query.first + emitted - 1 }));
    } else {
        try w.emptyTag(page, S.Result);
    }
    try w.elementInt(page, S.Total, @intCast(total));
    try w.end(); // Store
    try w.end(); // Response
    try w.end(); // Search
    return .{ .body = try w.toOwnedSlice() };
}

fn boundedSearchText(value: []const u8, limit: usize) []const u8 {
    var end = @min(value.len, limit);
    while (end > 0 and end < value.len and value[end] & 0xc0 == 0x80) end -= 1;
    return if (std.unicode.utf8ValidateSlice(value[0..end])) value[0..end] else "";
}

fn writeSearchResult(a: std.mem.Allocator, w: *wbxml.Writer, key: SearchKey, hit: SearchItem, match: webmail_maildir.SearchMatch, body_limit: ?usize) !void {
    const S = wbxml.Search;
    const page = wbxml.Page.search;
    const A = wbxml.AirSync;
    const E = wbxml.Email;
    const B = wbxml.AirSyncBase;
    const uid = hit.mail.uid;
    const base = maildirBaseName(std.fs.path.basename(hit.mail.path));
    const signature = searchSignature(key, hit.folder.id, uid, hit.validity, base);
    const id = try std.fmt.allocPrint(a, "s1:{s}:{d}:{s}", .{ hit.folder.id, uid, &signature });
    try w.startTag(page, S.Result);
    try w.element(wbxml.Page.air_sync, A.FolderType, "Email");
    try w.element(page, S.LongId, id);
    try w.element(wbxml.Page.air_sync, A.FolderId, hit.folder.id);
    try w.startTag(page, S.Properties);
    try w.element(wbxml.Page.email, E.Subject, boundedSearchText(match.subject, 2048));
    try w.element(wbxml.Page.email, E.From, boundedSearchText(match.from, 2048));
    try w.element(wbxml.Page.email, E.To, boundedSearchText(match.to, 2048));
    try w.element(wbxml.Page.email, E.DateReceived, isoFromEpoch(a, hit.mail.epoch));
    try w.element(wbxml.Page.email, E.Read, if (hit.mail.seen) "1" else "0");
    try w.element(wbxml.Page.email, E.MessageClass, "IPM.Note");
    if (body_limit) |limit| {
        const data = boundedSearchText(match.text, limit);
        try w.startTag(wbxml.Page.air_sync_base, B.Body);
        try w.element(wbxml.Page.air_sync_base, B.Type, "1");
        try w.elementInt(wbxml.Page.air_sync_base, B.EstimatedDataSize, @intCast(match.text.len));
        try w.element(wbxml.Page.air_sync_base, B.Truncated, if (data.len < match.text.len) "1" else "0");
        if (data.len > 0) try w.element(wbxml.Page.air_sync_base, B.Data, data);
        try w.end(); // Body
    }
    try w.end(); // Properties
    try w.end(); // Result
}

// ============================================================================
// Provision (MS-ASPROV)
// ============================================================================

fn handleProvision(ctx: *Context, body: []const u8) !Response {
    var is_ack = false;
    var page = wbxml.Page.provision;
    if (body.len > 0) {
        var root = wbxml.decode(ctx.allocator, body) catch wbxml.Node{ .page = 0xFF, .token = 0xFF };
        defer root.deinit(ctx.allocator);
        if (root.child(13, wbxml.Provision.Provision) != null) page = 13;
        is_ack = root.find(page, wbxml.Provision.PolicyKey) != null;
    }

    var w = wbxml.Writer.init(ctx.allocator);
    errdefer w.deinit();
    try w.writeHeader();

    const P = wbxml.Provision;

    try w.startTag(page, P.Provision);
    try w.element(page, P.Status, "1");
    try w.startTag(page, P.Policies);
    try w.startTag(page, P.Policy);
    try w.element(page, P.PolicyType, "MS-EAS-Provisioning-WBXML");
    try w.element(page, P.Status, "1");
    try w.element(page, P.PolicyKey, "1");
    if (!is_ack) {
        // Empty EASProvisionDoc => no device restrictions enforced.
        try w.startTag(page, P.Data);
        try w.startTag(page, P.EASProvisionDoc);
        try w.end();
        try w.end();
    }
    try w.end(); // Policy
    try w.end(); // Policies
    try w.end(); // Provision

    return Response{ .body = try w.toOwnedSlice() };
}

// ============================================================================
// FolderSync (MS-ASCMD §2.2.2.4)
// ============================================================================

fn handleFolderSync(ctx: *Context, body: []const u8) !Response {
    var sync_key: []const u8 = "0";
    if (body.len > 0) {
        var root = wbxml.decode(ctx.allocator, body) catch wbxml.Node{ .page = 0xFF, .token = 0xFF };
        defer root.deinit(ctx.allocator);
        if (root.find(wbxml.Page.folder_hierarchy, wbxml.FolderHierarchy.SyncKey)) |k| {
            if (k.text) |t| sync_key = t;
        }
    }
    const initial = std.mem.eql(u8, sync_key, "0");

    var w = wbxml.Writer.init(ctx.allocator);
    errdefer w.deinit();
    try w.writeHeader();

    const F = wbxml.FolderHierarchy;
    const page = wbxml.Page.folder_hierarchy;

    try w.startTag(page, F.FolderSync);
    try w.element(page, F.Status, "1");
    try w.element(page, F.SyncKey, "1");
    try w.startTag(page, F.Changes);
    if (initial) {
        try w.elementInt(page, F.Count, @intCast(FOLDERS.len));
        for (FOLDERS) |f| {
            try w.startTag(page, F.Add);
            try w.element(page, F.ServerEntryId, f.id);
            try w.element(page, F.ParentId, f.parent);
            try w.element(page, F.DisplayName, f.name);
            try w.elementInt(page, F.Type, f.kind);
            try w.end();
        }
    } else {
        try w.element(page, F.Count, "0");
    }
    try w.end(); // Changes
    try w.end(); // FolderSync

    return Response{ .body = try w.toOwnedSlice() };
}

const MoveRequest = struct {
    id: []const u8,
    source: []const u8,
    destination: []const u8,
};

fn parseMove(node: wbxml.Node) !MoveRequest {
    const M = wbxml.Move;
    const page = wbxml.Page.move;
    if (node.page != page or node.token != M.Move or node.text != null) return error.InvalidMove;
    var fields: [3]?[]const u8 = .{ null, null, null };
    for (node.children.items) |field| {
        if (field.page != page or field.token < M.SrcMsgId or field.token > M.DstFldId or
            field.is_opaque or field.children.items.len != 0) return error.InvalidMove;
        const value = field.text orelse return error.InvalidMove;
        if (value.len == 0 or value.len > 64) return error.InvalidMove;
        const slot = &fields[field.token - M.SrcMsgId];
        if (slot.* != null) return if (field.token == M.DstFldId) error.MultipleDestinations else error.InvalidMove;
        slot.* = value;
    }
    return .{
        .id = fields[0] orelse return error.InvalidMove,
        .source = fields[1] orelse return error.InvalidMove,
        .destination = fields[2] orelse return error.InvalidMove,
    };
}

fn handleMoveItems(ctx: *Context, body: []const u8) !Response {
    if (!validDevice(ctx.device_id) or ctx.protocol_version == 0 or body.len > 32 * 1024) return .{ .status = 400 };
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = wbxml.decode(a, body) catch return .{ .status = 400 };
    const M = wbxml.Move;
    const page = wbxml.Page.move;
    const command = root.child(page, M.MoveItems) orelse return .{ .status = 400 };
    if (root.children.items.len != 1 or command.text != null or command.children.items.len == 0) return .{ .status = 400 };
    const moves = try a.alloc(MoveRequest, command.children.items.len);
    for (command.children.items, moves) |node, *move| {
        move.* = parseMove(node) catch |err| switch (err) {
            error.MultipleDestinations => return moveCommandStatus(ctx, 5),
            else => return .{ .status = 400 },
        };
    }

    ctx.db.lockMailboxes();
    defer ctx.db.unlockMailboxes();
    const user_id = (try ctx.db.enabledMailboxId(ctx.username)) orelse return .{ .status = 403 };
    maildir_path.validate(ctx.local_part) catch return .{ .status = 403 };
    requireMailboxOwner(a, ctx) catch |err| return if (err == error.AmbiguousMailbox) .{ .status = 403 } else err;

    var w = wbxml.Writer.init(ctx.allocator);
    errdefer w.deinit();
    try w.writeHeader();
    try w.startTag(page, M.MoveItems);
    for (moves) |move| {
        var item_arena = std.heap.ArenaAllocator.init(ctx.allocator);
        defer item_arena.deinit();
        var new_id: [64]u8 = undefined;
        var status: u8 = 3;
        const moved: ?[]const u8 = moveMailItemLocked(item_arena.allocator(), ctx, user_id, move, &new_id) catch |err| blk: {
            status = switch (err) {
                error.ItemNotFound, error.InvalidIdCombination => 1,
                error.InvalidDestination => 2,
                error.SameFolder => 4,
                else => 7,
            };
            break :blk null;
        };
        try w.startTag(page, M.Response);
        try w.element(page, M.SrcMsgId, move.id);
        try w.elementInt(page, M.Status, status);
        if (moved) |id| try w.element(page, M.DstMsgId, id);
        try w.end();
    }
    try w.end();
    return .{ .body = try w.toOwnedSlice() };
}

fn moveCommandStatus(ctx: *Context, status: u8) !Response {
    var w = wbxml.Writer.init(ctx.allocator);
    errdefer w.deinit();
    try w.writeHeader();
    try w.startTag(wbxml.Page.move, wbxml.Move.MoveItems);
    try w.elementInt(wbxml.Page.move, wbxml.Move.Status, status);
    try w.end();
    return .{ .body = try w.toOwnedSlice() };
}

fn moveMailItemLocked(a: std.mem.Allocator, ctx: *Context, user_id: i64, move: MoveRequest, buf: []u8) ![]const u8 {
    const source = folderById(move.source) orelse return error.ItemNotFound;
    const source_mailbox = source.mailbox orelse return error.ItemNotFound;
    const item = try resolveMailItemId(a, ctx, user_id, source, move.id);
    const file = try locateMoveFile(a, ctx, source_mailbox, item.base);
    const destination = folderById(move.destination) orelse return error.InvalidDestination;
    const mailbox = destination.mailbox orelse return error.InvalidDestination;
    if (std.mem.eql(u8, source.id, destination.id)) return error.SameFolder;
    if (try webmail_store.managesDraftAt(ctx.db, ctx.username, source_mailbox, item.uid)) return error.ManagedDraft;

    const dirs = try mailboxDirs(a, ctx, mailbox);
    const generation = try ctx.db.getOrCreateMailbox(ctx.username, mailbox);
    const key = try searchKey(ctx.db, user_id, false);
    const uid = try webmail_maildir.moveResolvedFileLocked(a, ctx.db, ctx.username, source_mailbox, file, mailbox, dirs, null);
    return formatMailItemId(buf, key, destination, uid, generation.uidvalidity, item.base);
}

fn locateMoveFile(a: std.mem.Allocator, ctx: *Context, folder: []const u8, base: []const u8) !webmail_maildir.FileRef {
    var result: ?webmail_maildir.FileRef = null;
    for (try mailboxDirs(a, ctx, folder)) |dir| {
        const files = fs_compat.listEmlFiles(a, dir) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        for (files) |name| {
            if (!std.mem.eql(u8, base, maildirBaseName(name))) continue;
            if (result != null) return error.AmbiguousItem;
            result = .{ .dir = dir, .name = name };
        }
    }
    return result orelse error.ItemNotFound;
}

// ============================================================================
// Sync (MS-ASCMD §2.2.2.20)
// ============================================================================

fn handleSync(ctx: *Context, account: sync_state.Account, body: []const u8) !Response {
    var w = wbxml.Writer.init(ctx.allocator);
    errdefer w.deinit();
    try w.writeHeader();

    const A = wbxml.AirSync;
    const page = wbxml.Page.air_sync;

    try w.startTag(page, A.Synchronize);
    try w.startTag(page, A.Folders);

    if (body.len > 0) {
        var root = wbxml.decode(ctx.allocator, body) catch {
            w.deinit();
            return .{ .status = 400 };
        };
        defer root.deinit(ctx.allocator);
        if (root.child(page, A.Synchronize)) |sync_root| {
            const folders_node = sync_root.child(page, A.Folders) orelse sync_root;
            for (folders_node.children.items) |*coll| {
                if (coll.token != A.Folder or coll.page != page) continue;
                const collection_id = coll.childText(page, A.FolderId) orelse continue;
                const req_key = coll.childText(page, A.SyncKey) orelse "";
                const folder = folderById(collection_id) orelse continue;
                if (coll.child(page, A.Perform)) |commands| {
                    if (commands.children.items.len != 0) {
                        try writeSyncStatus(&w, collection_id, req_key, "6");
                        continue;
                    }
                }
                const length = w.buf.items.len;
                const code_page = w.current_page;
                writeSyncCollection(ctx, account, &w, folder, req_key) catch |err| {
                    w.buf.shrinkRetainingCapacity(length);
                    w.current_page = code_page;
                    if (err == error.InvalidSyncKey) {
                        try writeSyncStatus(&w, collection_id, "0", "3");
                    } else {
                        try writeSyncStatus(&w, collection_id, req_key, "5");
                    }
                };
            }
        }
    }

    try w.end(); // Folders
    try w.end(); // Synchronize
    return Response{ .body = try w.toOwnedSlice() };
}

fn writeSyncStatus(w: *wbxml.Writer, collection: []const u8, key: []const u8, status: []const u8) !void {
    try beginSyncCollection(w, collection, key, status);
    try w.end();
}

fn beginSyncCollection(w: *wbxml.Writer, collection: []const u8, key: []const u8, status: []const u8) !void {
    const A = wbxml.AirSync;
    const page = wbxml.Page.air_sync;
    try w.startTag(page, A.Folder);
    try w.element(page, A.FolderId, collection);
    try w.element(page, A.SyncKey, key);
    try w.element(page, A.Status, status);
}

const SyncItem = struct {
    id: []const u8,
    tag: []const u8,
    data: union(enum) { mail: MailItem, event: u64, contact: u64 },
};

const SyncChange = struct {
    kind: u8,
    id: []const u8,
    item: ?SyncItem = null,
};

fn collectionChanges(a: std.mem.Allocator, ctx: *Context, user_id: i64, folder: FolderDef, previous: sync_state.Items) ![]SyncChange {
    const A = wbxml.AirSync;
    var current: std.StringHashMapUnmanaged(void) = .empty;
    var changes: std.ArrayList(SyncChange) = .empty;
    if (folder.mailbox) |mailbox| {
        var mail: std.ArrayList(MailItem) = .empty;
        ctx.db.lockMailboxes();
        defer ctx.db.unlockMailboxes();
        try requireMailboxOwner(a, ctx);
        try collectMail(a, ctx, mailbox, std.math.maxInt(usize), &mail);
        if (mail.items.len != 0) {
            const key = searchKey(ctx.db, user_id, false) catch |err| switch (err) {
                error.ItemNotFound => try searchKey(ctx.db, user_id, true),
                else => return err,
            };
            const generation = try ctx.db.getOrCreateMailbox(ctx.username, mailbox);
            for (mail.items) |message| {
                const base = maildirBaseName(std.fs.path.basename(message.path));
                var id_buffer: [64]u8 = undefined;
                const id = try a.dupe(u8, formatMailItemId(&id_buffer, key, folder, message.uid, generation.uidvalidity, base));
                if ((try current.getOrPut(a, id)).found_existing) continue;
                const tag: []const u8 = if (message.seen) "1" else "0";
                try appendChanged(a, &changes, previous, .{ .id = id, .tag = tag, .data = .{ .mail = message } });
            }
        }
    } else {
        const items = try ctx.store.snapshotActiveSyncResources(a, ctx.username, folder.is_calendar);
        for (items) |item| {
            const id = try std.fmt.allocPrint(a, "{d}", .{item.id});
            try current.put(a, id, {});
            try appendChanged(a, &changes, previous, .{
                .id = id,
                .tag = item.etag,
                .data = if (folder.is_calendar) .{ .event = item.id } else .{ .contact = item.id },
            });
        }
    }
    var seen = previous.keyIterator();
    while (seen.next()) |id| {
        if (!current.contains(id.*)) try changes.append(a, .{ .kind = A.Remove, .id = id.* });
    }
    return changes.items;
}

fn usesLegacyMailIds(folder: FolderDef, items: sync_state.Items) bool {
    if (folder.mailbox == null) return false;
    var ids = items.keyIterator();
    while (ids.next()) |id| {
        if (std.mem.count(u8, id.*, ":") != 2) return true;
    }
    return false;
}

fn appendChanged(a: std.mem.Allocator, changes: *std.ArrayList(SyncChange), previous: sync_state.Items, item: SyncItem) !void {
    const A = wbxml.AirSync;
    const old = previous.get(item.id);
    if (old) |tag| {
        if (std.mem.eql(u8, tag, item.tag)) return;
    }
    try changes.append(a, .{ .kind = if (old == null) A.Add else A.Modify, .id = item.id, .item = item });
}

fn writeSyncCollection(ctx: *Context, account: sync_state.Account, w: *wbxml.Writer, folder: FolderDef, requested_key: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const page = wbxml.Page.air_sync;
    const A = wbxml.AirSync;

    if (std.mem.eql(u8, requested_key, "0")) {
        const key = try sync_state.newKey(a);
        try writeSyncStatus(w, folder.id, key, "1");
        try account.reset(folder.id, key);
        return;
    }
    const snapshot = (try account.load(a, folder.id)) orelse return error.InvalidSyncKey;
    if (!std.mem.eql(u8, snapshot.key, requested_key) or usesLegacyMailIds(folder, snapshot.items)) return error.InvalidSyncKey;
    var items = snapshot.items;
    const pending = try collectionChanges(a, ctx, account.user_id, folder, items);
    if (pending.len == 0) return writeSyncStatus(w, folder.id, requested_key, "1");

    const key = try sync_state.newKey(a);
    try beginSyncCollection(w, folder.id, key, "1");
    try w.startTag(page, A.Perform);
    const window = @min(SYNC_WINDOW, pending.len);
    var emitted: usize = 0;
    for (pending[0..window]) |change| {
        const length = w.buf.items.len;
        const code_page = w.current_page;
        writeSyncChange(a, ctx, w, change) catch |err| switch (err) {
            error.FileNotFound, error.EventNotFound, error.ContactNotFound, error.RevisionChanged => {
                w.buf.shrinkRetainingCapacity(length);
                w.current_page = code_page;
                continue;
            },
            else => return err,
        };
        if (change.item) |item| {
            try items.put(a, item.id, item.tag);
        } else {
            _ = items.remove(change.id);
        }
        emitted += 1;
    }
    try w.end(); // Perform
    if (emitted < pending.len) try w.emptyTag(page, A.MoreAvailable);
    try w.end(); // Collection
    try account.advance(a, folder.id, requested_key, key, items);
}

fn writeSyncChange(a: std.mem.Allocator, ctx: *Context, w: *wbxml.Writer, change: SyncChange) !void {
    const A = wbxml.AirSync;
    const page = wbxml.Page.air_sync;
    try w.startTag(page, change.kind);
    try w.element(page, A.ServerEntryId, change.id);
    if (change.item) |item| {
        try w.startTag(page, A.Data);
        switch (item.data) {
            .mail => |mail| try writeMailAppData(a, w, mail),
            .event => |id| {
                const event = try ctx.store.snapshotMailboxEvent(a, ctx.username, id);
                if (!std.mem.eql(u8, item.tag, event.event.etag)) return error.RevisionChanged;
                try writeEventAppData(a, w, event);
            },
            .contact => |id| {
                const contact = try ctx.store.snapshotActiveSyncContact(a, ctx.username, id);
                if (!std.mem.eql(u8, item.tag, contact.etag)) return error.RevisionChanged;
                try writeContactAppData(w, contact);
            },
        }
        try w.end(); // ApplicationData
    }
    try w.end(); // Add/Change/Delete
}

// ============================================================================
// GetItemEstimate / Ping
// ============================================================================

fn handleGetItemEstimate(ctx: *Context, account: sync_state.Account, body: []const u8) !Response {
    var root = wbxml.decode(ctx.allocator, body) catch return .{ .status = 400 };
    defer root.deinit(ctx.allocator);
    const G = wbxml.GetItemEstimate;
    const page = wbxml.Page.get_item_estimate;
    const command = root.child(page, G.GetItemEstimate) orelse return .{ .status = 400 };
    const folders = command.child(page, G.Folders) orelse return .{ .status = 400 };

    var w = wbxml.Writer.init(ctx.allocator);
    errdefer w.deinit();
    try w.writeHeader();
    try w.startTag(page, G.GetItemEstimate);
    for (folders.children.items) |*collection| {
        if (collection.page != page or collection.token != G.Folder) continue;
        const id = collection.childText(page, G.FolderId) orelse "";
        const key = collection.childText(wbxml.Page.air_sync, wbxml.AirSync.SyncKey) orelse "";
        var arena = std.heap.ArenaAllocator.init(ctx.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var status: u8 = 2;
        var count: usize = 0;
        if (folderById(id)) |folder| {
            if (try account.load(a, id)) |snapshot| {
                status = 4;
                if (std.mem.eql(u8, snapshot.key, key) and !usesLegacyMailIds(folder, snapshot.items)) {
                    count = (try collectionChanges(a, ctx, account.user_id, folder, snapshot.items)).len;
                    status = 1;
                }
            } else {
                status = 3;
            }
        }
        try w.startTag(page, G.Response);
        try w.elementInt(page, G.Status, status);
        try w.startTag(page, G.Folder);
        try w.element(page, G.FolderId, id);
        if (status == 1) try w.elementInt(page, G.Estimate, @intCast(count));
        try w.end(); // Collection
        try w.end(); // Response
    }
    try w.end(); // GetItemEstimate
    return .{ .body = try w.toOwnedSlice() };
}

fn handlePing(ctx: *Context, account: sync_state.Account, body: []const u8) !Response {
    const Pg = wbxml.Ping;
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const request_allocator = arena.allocator();
    var page = wbxml.Page.ping;
    var heartbeat: ?u64 = null;
    var ids: [FOLDERS.len][]const u8 = undefined;
    var requested_folders: ?[]const []const u8 = null;
    if (body.len != 0) {
        const root = wbxml.decode(request_allocator, body) catch return pingResponse(ctx, page, 4, &.{});
        if (root.child(11, Pg.Ping) != null) page = 11;
        const command = root.child(page, Pg.Ping) orelse return pingResponse(ctx, page, 4, &.{});
        if (command.childText(page, Pg.LifeTime)) |value| {
            const interval = std.fmt.parseInt(u64, value, 10) catch return pingResponse(ctx, page, 4, &.{});
            heartbeat = std.math.clamp(interval, PING_INTERVAL_S, PING_MAX_HEARTBEAT_S);
        }
        if (command.child(page, Pg.Folders)) |folders| {
            if (folders.children.items.len > ids.len) return pingResponse(ctx, page, 6, &.{});
            if (folders.children.items.len == 0) return pingResponse(ctx, page, 4, &.{});
            for (folders.children.items, 0..) |*node, index| {
                if (node.page != page or node.token != Pg.Folder) return pingResponse(ctx, page, 4, &.{});
                const id = node.childText(page, Pg.ServerEntryId) orelse return pingResponse(ctx, page, 4, &.{});
                const folder = folderById(id) orelse return pingResponse(ctx, page, 7, &.{});
                ids[index] = folder.id;
            }
            requested_folders = ids[0..folders.children.items.len];
        }
        if (heartbeat == null and requested_folders == null) return pingResponse(ctx, page, 3, &.{});
    }

    const settings = (account.ping(request_allocator, heartbeat, requested_folders) catch
        return pingResponse(ctx, page, 8, &.{})) orelse return pingResponse(ctx, page, 3, &.{});
    var remaining = settings.heartbeat;
    while (true) {
        var changed: [FOLDERS.len][]const u8 = undefined;
        var count: usize = 0;
        for (settings.folders) |id| {
            const folder = folderById(id) orelse return pingResponse(ctx, page, 7, &.{});
            var round_arena = std.heap.ArenaAllocator.init(ctx.allocator);
            defer round_arena.deinit();
            const a = round_arena.allocator();
            const snapshot = account.load(a, folder.id) catch return pingResponse(ctx, page, 8, &.{});
            const items: sync_state.Items = if (snapshot) |state| state.items else .empty;
            const pending = collectionChanges(a, ctx, account.user_id, folder, items) catch return pingResponse(ctx, page, 8, &.{});
            if (pending.len != 0) {
                changed[count] = folder.id;
                count += 1;
            }
        }
        if (count != 0) return pingResponse(ctx, page, 2, changed[0..count]);
        if (remaining == 0) return pingResponse(ctx, page, 1, &.{});
        const delay: u64 = @min(remaining, PING_INTERVAL_S);
        time_compat.sleep(delay * std.time.ns_per_s);
        remaining -= delay;
    }
}

fn pingResponse(ctx: *Context, page: u8, status: u8, changes: []const []const u8) !Response {
    const Pg = wbxml.Ping;
    var w = wbxml.Writer.init(ctx.allocator);
    errdefer w.deinit();
    try w.writeHeader();
    try w.startTag(page, Pg.Ping);
    try w.elementInt(page, Pg.Status, status);
    if (changes.len != 0) {
        try w.startTag(page, Pg.Folders);
        for (changes) |id| try w.element(page, Pg.Folder, id);
        try w.end();
    }
    if (status == 6) try w.elementInt(page, Pg.MaxFolders, FOLDERS.len);
    try w.end();
    return .{ .body = try w.toOwnedSlice() };
}

// ============================================================================
// Maildir access
// ============================================================================

const MailItem = struct {
    uid: i64,
    path: []const u8,
    seen: bool,
    epoch: i64,
};

fn mailboxDirs(a: std.mem.Allocator, ctx: *Context, mailbox: []const u8) ![][]const u8 {
    const root = try std.fmt.allocPrint(a, "mail/{s}", .{ctx.local_part});
    const inbox = std.mem.eql(u8, mailbox, "INBOX");
    const base = if (inbox) root else try std.fmt.allocPrint(a, "{s}/{s}", .{ root, mailbox });
    const new = try std.fmt.allocPrint(a, "{s}/new", .{base});
    const cur = try std.fmt.allocPrint(a, "{s}/cur", .{base});
    return if (inbox) a.dupe([]const u8, &.{ new, cur }) else a.dupe([]const u8, &.{ base, new, cur });
}

fn collectMail(a: std.mem.Allocator, ctx: *Context, mailbox: []const u8, limit: usize, out: *std.ArrayList(MailItem)) !void {
    for (try mailboxDirs(a, ctx, mailbox)) |dir| try collectDir(a, ctx, mailbox, dir, limit, out);
}

fn collectDir(a: std.mem.Allocator, ctx: *Context, mailbox: []const u8, dir_path: []const u8, limit: usize, out: *std.ArrayList(MailItem)) !void {
    const files = fs_compat.listEmlFiles(a, dir_path) catch return;
    if (files.len > limit - out.items.len) return error.SearchLimit;
    for (files) |fname| {
        const base = maildirBaseName(fname);
        const uid = ctx.db.getUidForFile(ctx.username, mailbox, base) catch null orelse
            ctx.db.assignUid(ctx.username, mailbox, base) catch continue;
        try out.append(a, .{
            .uid = uid,
            .path = try std.fmt.allocPrint(a, "{s}/{s}", .{ dir_path, fname }),
            .seen = maildirSeen(fname),
            .epoch = maildirEpoch(base),
        });
    }
}

fn maildirBaseName(filename: []const u8) []const u8 {
    if (std.mem.indexOf(u8, filename, ":2,")) |idx| return filename[0..idx];
    return filename;
}

fn maildirSeen(filename: []const u8) bool {
    if (std.mem.indexOf(u8, filename, ":2,")) |idx| {
        return std.mem.indexOfScalar(u8, filename[idx + 3 ..], 'S') != null;
    }
    return false;
}

fn maildirEpoch(base: []const u8) i64 {
    var end: usize = 0;
    while (end < base.len and base[end] >= '0' and base[end] <= '9') end += 1;
    if (end == 0) return 0;
    const stamp = std.fmt.parseInt(i64, base[0..end], 10) catch return 0;
    const seconds = if (stamp > 9_999_999_999) @divTrunc(stamp, 1000) else stamp;
    return if (seconds <= 253_402_300_799) seconds else 0;
}

// ============================================================================
// WBXML item serialisation
// ============================================================================

fn writeMailAppData(a: std.mem.Allocator, w: *wbxml.Writer, it: MailItem) !void {
    const E = wbxml.Email;
    const B = wbxml.AirSyncBase;

    const raw = try fs_compat.readFileAlloc(a, it.path);
    const split = headerBodySplit(raw);
    const headers = raw[0..split.header_end];
    const body_raw = raw[split.body_start..];
    const body = if (body_raw.len > MAX_BODY) body_raw[0..MAX_BODY] else body_raw;

    try w.element(wbxml.Page.email, E.From, headerValue(a, headers, "from") orelse "");
    try w.element(wbxml.Page.email, E.To, headerValue(a, headers, "to") orelse "");
    try w.element(wbxml.Page.email, E.Subject, headerValue(a, headers, "subject") orelse "(no subject)");
    try w.element(wbxml.Page.email, E.DateReceived, isoFromEpoch(a, it.epoch));
    try w.element(wbxml.Page.email, E.DisplayTo, headerValue(a, headers, "to") orelse "");
    try w.element(wbxml.Page.email, E.Importance, "1");
    try w.element(wbxml.Page.email, E.Read, if (it.seen) "1" else "0");
    try w.element(wbxml.Page.email, E.MessageClass, "IPM.Note");
    try w.element(wbxml.Page.email, E.ContentClass, "urn:content-classes:message");

    try w.startTag(wbxml.Page.air_sync_base, B.Body);
    try w.element(wbxml.Page.air_sync_base, B.Type, "1"); // plain text
    try w.elementInt(wbxml.Page.air_sync_base, B.EstimatedDataSize, @intCast(body.len));
    try w.element(wbxml.Page.air_sync_base, B.Truncated, if (body_raw.len > MAX_BODY) "1" else "0");
    if (body.len > 0) {
        try w.startTag(wbxml.Page.air_sync_base, B.Data);
        try w.opaqueData(body);
        try w.end();
    }
    try w.end(); // Body
}

fn writeEventAppData(a: std.mem.Allocator, w: *wbxml.Writer, detail: caldav_store.CalendarEventDetail) !void {
    const C = wbxml.Calendar;
    const B = wbxml.AirSyncBase;
    const page = wbxml.Page.calendar;

    const ev = detail.event;
    try w.element(page, C.UID, ev.uid);
    try w.element(page, C.Subject, ev.summary);
    if (ev.location) |loc| try w.element(page, C.Location, loc);
    try w.element(page, C.StartTime, compactFromEpoch(a, ev.start));
    try w.element(page, C.EndTime, compactFromEpoch(a, ev.end orelse (ev.start + 3600)));
    try w.element(page, C.DtStamp, compactFromEpoch(a, detail.modified_at));
    try w.element(page, C.AllDayEvent, if (ev.all_day) "1" else "0");
    try w.element(page, C.BusyStatus, "2"); // busy
    try w.element(page, C.Sensitivity, "0"); // normal
    try w.element(page, C.MeetingStatus, "0"); // not a meeting
    if (detail.organizer) |org| {
        try w.element(page, C.OrganizerEmail, org);
        try w.element(page, C.OrganizerName, org);
    }
    if (detail.description) |desc| {
        try w.startTag(wbxml.Page.air_sync_base, B.Body);
        try w.element(wbxml.Page.air_sync_base, B.Type, "1");
        try w.elementInt(wbxml.Page.air_sync_base, B.EstimatedDataSize, @intCast(desc.len));
        try w.element(wbxml.Page.air_sync_base, B.Truncated, "0");
        try w.startTag(wbxml.Page.air_sync_base, B.Data);
        try w.text(desc);
        try w.end();
        try w.end();
    }
}

fn writeContactAppData(w: *wbxml.Writer, c: caldav_store.ActiveSyncContact) !void {
    const K = wbxml.Contacts;
    const B = wbxml.AirSyncBase;
    const page = wbxml.Page.contacts;

    if (c.given_name) |v| try w.element(page, K.FirstName, v);
    if (c.family_name) |v| try w.element(page, K.LastName, v);
    try w.element(page, K.FileAs, c.full_name);
    if (c.organization) |v| try w.element(page, K.CompanyName, v);
    if (c.title) |v| try w.element(page, K.JobTitle, v);

    if (c.emails.len > 0) try w.element(page, K.Email1Address, c.emails[0]);
    if (c.emails.len > 1) try w.element(page, K.Email2Address, c.emails[1]);
    if (c.emails.len > 2) try w.element(page, K.Email3Address, c.emails[2]);

    for (c.phones) |ph| {
        switch (ph.phone_type) {
            .mobile => try w.element(page, K.MobilePhoneNumber, ph.number),
            .home => try w.element(page, K.HomePhoneNumber, ph.number),
            .work => try w.element(page, K.BusinessPhoneNumber, ph.number),
            else => {},
        }
    }

    if (c.note) |note| {
        try w.startTag(wbxml.Page.air_sync_base, B.Body);
        try w.element(wbxml.Page.air_sync_base, B.Type, "1");
        try w.elementInt(wbxml.Page.air_sync_base, B.EstimatedDataSize, @intCast(note.len));
        try w.element(wbxml.Page.air_sync_base, B.Truncated, "0");
        try w.startTag(wbxml.Page.air_sync_base, B.Data);
        try w.text(note);
        try w.end();
        try w.end();
    }
}

// ============================================================================
// Header / date helpers
// ============================================================================

const Split = struct { header_end: usize, body_start: usize };

fn headerBodySplit(raw: []const u8) Split {
    if (std.mem.indexOf(u8, raw, "\r\n\r\n")) |i| return .{ .header_end = i, .body_start = i + 4 };
    if (std.mem.indexOf(u8, raw, "\n\n")) |i| return .{ .header_end = i, .body_start = i + 2 };
    return .{ .header_end = raw.len, .body_start = raw.len };
}

fn headerValue(a: std.mem.Allocator, headers: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, headers, '\n');
    var collecting = false;
    var acc = std.ArrayList(u8).empty;
    while (lines.next()) |line_raw| {
        const line = std.mem.trimEnd(u8, line_raw, "\r");
        if (collecting) {
            if (line.len > 0 and (line[0] == ' ' or line[0] == '\t')) {
                acc.append(a, ' ') catch {};
                acc.appendSlice(a, std.mem.trim(u8, line, " \t")) catch {};
                continue;
            }
            return acc.items;
        }
        if (line.len < name.len + 1) continue;
        if (std.ascii.eqlIgnoreCase(line[0..name.len], name) and line[name.len] == ':') {
            const val = std.mem.trim(u8, line[name.len + 1 ..], " \t");
            acc.appendSlice(a, val) catch return val;
            collecting = true;
        }
    }
    if (collecting) return acc.items;
    return null;
}

/// EAS DateReceived form `YYYY-MM-DDTHH:MM:SS.000Z`.
fn isoFromEpoch(a: std.mem.Allocator, epoch: i64) []const u8 {
    const c = civilFromEpoch(epoch);
    return std.fmt.allocPrint(a, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.000Z", .{
        c.year, c.month, c.day, c.hour, c.minute, c.second,
    }) catch "1970-01-01T00:00:00.000Z";
}

/// EAS compact form `YYYYMMDDTHHMMSSZ` (used for calendar times).
fn compactFromEpoch(a: std.mem.Allocator, epoch: i64) []const u8 {
    const c = civilFromEpoch(epoch);
    return std.fmt.allocPrint(a, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
        c.year, c.month, c.day, c.hour, c.minute, c.second,
    }) catch "19700101T000000Z";
}

const Civil = struct { year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8 };

fn civilFromEpoch(epoch: i64) Civil {
    const secs: u64 = if (epoch <= 0) 0 else @intCast(epoch);
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const day = es.getEpochDay();
    const year_day = day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const ds = es.getDaySeconds();
    return .{
        .year = year_day.year,
        .month = @backingInt(month_day.month),
        .day = @as(u8, month_day.day_index) + 1,
        .hour = ds.getHoursIntoDay(),
        .minute = ds.getMinutesIntoHour(),
        .second = ds.getSecondsIntoMinute(),
    };
}

test "maildir helpers" {
    try std.testing.expectEqualStrings("1700000000.abc", maildirBaseName("1700000000.abc:2,S"));
    try std.testing.expect(maildirSeen("1700000000.abc:2,S"));
    try std.testing.expect(!maildirSeen("1700000000.abc:2,"));
    try std.testing.expectEqual(@as(i64, 1700000000), maildirEpoch("1700000000.abc"));
}

test "header value lookup is case-insensitive and unfolds" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const h = "From: a@b.com\r\nSubject: hello\r\n world\r\nTo: c@d.com";
    try std.testing.expectEqualStrings("a@b.com", headerValue(arena.allocator(), h, "from").?);
    try std.testing.expectEqualStrings("hello world", headerValue(arena.allocator(), h, "subject").?);
}

test "epoch formatting" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("2023-11-14T22:13:20.000Z", isoFromEpoch(arena.allocator(), 1700000000));
    try std.testing.expectEqualStrings("20231114T221320Z", compactFromEpoch(arena.allocator(), 1700000000));
}
