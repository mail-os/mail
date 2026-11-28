const std = @import("std");
const clamav = @import("../../antispam/clamav.zig");
const xml = @import("xml.zig");
const item_sync = @import("item_sync.zig");
const file_attachments = @import("attachments.zig");
const metadata = @import("../../message/attachment_metadata.zig");
const webmail_maildir = @import("../../api/webmail_maildir.zig");
const webmail_store = @import("../../api/webmail_store.zig");
const webmail_service = @import("../../api/webmail_service.zig");
const logger = @import("../../core/logger.zig");
// NOTE: for a future standalone `zig-ews`, reach the mailbox/store through a
// callback interface on Context instead of importing these directly.
const database = @import("../../storage/database.zig");
const caldav_store = @import("../../storage/caldav_store.zig");
const fs_compat = @import("../../core/fs_compat.zig");
const time_compat = @import("../../core/time_compat.zig");
const submission = @import("../../delivery/submission.zig");
const hosted_limits = @import("../../storage/hosted_limits.zig");
const message_headers = @import("../../message/submission.zig");
const thread_ids = @import("../../message/thread_ids.zig");
const message_refs = @import("../../storage/message_refs.zig");
const snapshots = @import("../../api/webmail_snapshots.zig");
const durable_maildir = @import("../../core/durable_maildir.zig");
const ews_drafts = @import("../../delivery/ews_drafts.zig");
const maildir_path = @import("../../core/maildir_path.zig");
const config = @import("../../core/config.zig");

pub const autodiscover = @import("autodiscover.zig");

/// Exchange Web Services (EWS) — the SOAP protocol macOS Mail/Calendar/Contacts
/// use for "Microsoft Exchange" accounts (iOS uses ActiveSync; macOS uses EWS).
///
/// This is a minimal, log-driven implementation: every request is logged so the
/// exact macOS request sequence can be observed and implemented against. The
/// module depends only on std + the logger so it can be lifted into a standalone
/// `zig-ews` package; storage is reached through `Context` callbacks/fields.
///
/// EWS namespaces:
///   s = http://schemas.xmlsoap.org/soap/envelope/
///   m = http://schemas.microsoft.com/exchange/services/2006/messages
///   t = http://schemas.microsoft.com/exchange/services/2006/types
pub const Context = struct {
    allocator: std.mem.Allocator,
    /// Authenticated user (full email).
    username: []const u8,
    /// Canonical Maildir key for hosted accounts, legacy local part otherwise.
    local_part: []const u8,
    hosted: bool = false,
    /// Public hostname (for self-referential URLs).
    hostname: []const u8,
    /// Database (IMAP UID mapping for stable item ids).
    db: *database.Database,
    /// CalDAV/CardDAV store backing the Calendar and Contacts folders.
    store: ?*caldav_store.CalDavStore = null,
    /// Outbound delivery method (SES on AWS, direct MX on Hetzner/self-host).
    delivery_method: config.DeliveryMethod = .direct,
    /// AWS SES region (only used when delivery_method == .ses).
    ses_region: []const u8 = "us-east-1",
    mail_config: ?*const config.Config = null,
    scanner: ?*clamav.ClamAVScanner = null,
    draft_service: ?*webmail_service.Service = null,
};

pub const Response = struct {
    status: u16 = 200,
    body: []const u8 = "",
    content_type: []const u8 = "text/xml; charset=utf-8",
};

/// Advertised server version. macOS gates schema/features on this; 15.x =
/// Exchange 2013+/2016, which selects modern behavior.
const SERVER_VERSION =
    \\<h:ServerVersionInfo MajorVersion="15" MinorVersion="1" MajorBuildNumber="2308" MinorBuildNumber="27" Version="V2017_07_11" xmlns:h="http://schemas.microsoft.com/exchange/services/2006/types"/>
;

const ENVELOPE_HEAD =
    \\<?xml version="1.0" encoding="utf-8"?>
    \\<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
    \\<s:Header>
;
const ENVELOPE_MID =
    \\</s:Header>
    \\<s:Body>
;
const ENVELOPE_TAIL =
    \\</s:Body>
    \\</s:Envelope>
;

/// Wrap an operation response body in a full SOAP envelope (with version header).
fn envelope(allocator: std.mem.Allocator, inner: []const u8) ![]u8 {
    return std.mem.concat(allocator, u8, &.{
        ENVELOPE_HEAD, SERVER_VERSION, ENVELOPE_MID, inner, ENVELOPE_TAIL,
    });
}

/// The folders advertised to clients. The EWS folder id IS the distinguished
/// name, so GetFolder / SyncFolderHierarchy / SyncFolderItems all agree on it.
const FolderDef = struct {
    /// EWS folder id = distinguished folder name (e.g. "inbox").
    id: []const u8,
    name: []const u8,
    kind: enum { mail, calendar, contacts },
    /// Maildir mailbox backing this folder (null for calendar/contacts).
    mailbox: ?[]const u8,
};

const FOLDERS = [_]FolderDef{
    .{ .id = "inbox", .name = "Inbox", .kind = .mail, .mailbox = "INBOX" },
    .{ .id = "drafts", .name = "Drafts", .kind = .mail, .mailbox = "Drafts" },
    .{ .id = "sentitems", .name = "Sent Items", .kind = .mail, .mailbox = "Sent" },
    .{ .id = "deleteditems", .name = "Deleted Items", .kind = .mail, .mailbox = "Trash" },
    .{ .id = "calendar", .name = "Calendar", .kind = .calendar, .mailbox = null },
    .{ .id = "contacts", .name = "Contacts", .kind = .contacts, .mailbox = null },
};

const ROOT_ID = "msgfolderroot";

fn folderById(id: []const u8) ?FolderDef {
    for (FOLDERS) |f| {
        if (std.mem.eql(u8, f.id, id)) return f;
    }
    return null;
}

// ============================================================================
// Dispatch
// ============================================================================

/// Handle one EWS SOAP request. `soap` is the request body.
pub fn handleSoap(ctx: *Context, soap: []const u8) !Response {
    const op = extractOperation(soap);
    logger.info("EWS: op={s} user={s} bytes={d}", .{ op, ctx.username, soap.len });

    if (ctx.hosted) {
        const access = try ctx.db.mailboxAccess(ctx.username);
        if (!access.readable()) return .{ .status = 403, .body = "" };
        if (access == .read_only and !readOnlyOperation(op)) return .{ .status = 403, .body = "" };
    }

    if (std.mem.eql(u8, op, "GetFolder")) return getFolder(ctx, soap);
    if (std.mem.eql(u8, op, "SyncFolderHierarchy")) return syncFolderHierarchy(ctx, soap);
    if (std.mem.eql(u8, op, "SyncFolderItems")) return syncFolderItems(ctx, soap);
    if (std.mem.eql(u8, op, "GetItem")) return getItem(ctx, soap);
    if (std.mem.eql(u8, op, "CreateItem")) return createItem(ctx, soap);
    if (std.mem.eql(u8, op, "CreateAttachment")) return createAttachment(ctx, soap);
    if (std.mem.eql(u8, op, "GetAttachment")) return attachmentOperation(ctx, soap, "GetAttachment");
    if (std.mem.eql(u8, op, "DeleteAttachment")) return attachmentOperation(ctx, soap, "DeleteAttachment");
    if (std.mem.eql(u8, op, "SendItem")) return sendItem(ctx, soap);
    if (std.mem.eql(u8, op, "DeleteItem")) return deleteItem(ctx, soap);
    if (std.mem.eql(u8, op, "FindFolder")) return findFolder(ctx, soap);
    if (std.mem.eql(u8, op, "FindItem")) return findItem(ctx, soap);
    if (std.mem.eql(u8, op, "GetUserConfiguration")) return userConfigurationFault(ctx);
    if (std.mem.eql(u8, op, "GetUserOofSettings")) return oofSettings(ctx);
    if (std.mem.eql(u8, op, "Subscribe")) return subscribe(ctx);

    // Unknown/unimplemented: a soft success keeps setup probing rather than
    // erroring the account, while the request log tells us what to implement.
    return softFault(ctx, op);
}

fn readOnlyOperation(op: []const u8) bool {
    for ([_][]const u8{
        "GetFolder",          "SyncFolderHierarchy", "SyncFolderItems", "GetItem",
        "GetAttachment",      "FindFolder",          "FindItem",        "GetUserConfiguration",
        "GetUserOofSettings", "Subscribe",
    }) |allowed| {
        if (std.mem.eql(u8, op, allowed)) return true;
    }
    return false;
}

/// The EWS operation is the first element inside <s:Body>. Find it by scanning
/// for the Body open tag then the next element name (stripping any namespace
/// prefix).
fn extractOperation(soap: []const u8) []const u8 {
    const body_pos = std.mem.indexOf(u8, soap, ":Body") orelse std.mem.indexOf(u8, soap, "<Body") orelse return "";
    var i = body_pos;
    // advance past the Body tag's '>'
    while (i < soap.len and soap[i] != '>') i += 1;
    // find next '<' that starts an element (skip whitespace/text)
    while (i < soap.len) : (i += 1) {
        if (soap[i] == '<') {
            var j = i + 1;
            // skip a namespace prefix like "m:"
            const start = j;
            while (j < soap.len and soap[j] != '>' and soap[j] != ' ' and soap[j] != '/' and soap[j] != '\r' and soap[j] != '\n') j += 1;
            var name = soap[start..j];
            if (std.mem.indexOfScalar(u8, name, ':')) |c| name = name[c + 1 ..];
            return name;
        }
    }
    return "";
}

// ============================================================================
// Operations (Phase 1 best-effort; refined from captured requests)
// ============================================================================

const DistInfo = struct { tag: []const u8, name: []const u8 };

/// Map an EWS distinguished folder id to its element type + display name.
fn distFolderInfo(dist: []const u8) DistInfo {
    if (std.mem.eql(u8, dist, "calendar")) return .{ .tag = "CalendarFolder", .name = "Calendar" };
    if (std.mem.eql(u8, dist, "contacts")) return .{ .tag = "ContactsFolder", .name = "Contacts" };
    if (std.mem.eql(u8, dist, "tasks")) return .{ .tag = "TasksFolder", .name = "Tasks" };
    if (std.mem.eql(u8, dist, "inbox")) return .{ .tag = "Folder", .name = "Inbox" };
    if (std.mem.eql(u8, dist, "drafts")) return .{ .tag = "Folder", .name = "Drafts" };
    if (std.mem.eql(u8, dist, "sentitems")) return .{ .tag = "Folder", .name = "Sent Items" };
    if (std.mem.eql(u8, dist, "deleteditems")) return .{ .tag = "Folder", .name = "Deleted Items" };
    if (std.mem.eql(u8, dist, "junkemail")) return .{ .tag = "Folder", .name = "Junk Email" };
    if (std.mem.eql(u8, dist, "outbox")) return .{ .tag = "Folder", .name = "Outbox" };
    if (std.mem.eql(u8, dist, "notes")) return .{ .tag = "Folder", .name = "Notes" };
    if (std.mem.eql(u8, dist, "journal")) return .{ .tag = "Folder", .name = "Journal" };
    if (std.mem.eql(u8, dist, "msgfolderroot") or std.mem.eql(u8, dist, "root"))
        return .{ .tag = "Folder", .name = "Top of Information Store" };
    return .{ .tag = "Folder", .name = dist };
}

/// EWS requires EXACTLY one response message per requested folder, in order —
/// a count mismatch makes macOS Mail assert and abort(). We echo one
/// GetFolderResponseMessage for every (Distinguished)FolderId in the request,
/// returning the requested id verbatim so later ops reference a stable id.
fn getFolder(ctx: *Context, soap: []const u8) !Response {
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(ctx.allocator);
    const a = ctx.allocator;

    try buf.appendSlice(a, "<m:GetFolderResponse><m:ResponseMessages>");
    var count: usize = 0;
    var idx: usize = 0;
    // Matches both `DistinguishedFolderId Id="..."` and `FolderId Id="..."`.
    const needle = "FolderId Id=\"";
    while (std.mem.indexOfPos(u8, soap, idx, needle)) |p| {
        const vstart = p + needle.len;
        const vend = std.mem.indexOfScalarPos(u8, soap, vstart, '"') orelse break;
        const id = soap[vstart..vend];
        const info = distFolderInfo(id);
        try buf.print(a,
            \\<m:GetFolderResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:Folders><t:{s}><t:FolderId Id="{s}" ChangeKey="ck0"/><t:DisplayName>{s}</t:DisplayName><t:TotalCount>0</t:TotalCount><t:ChildFolderCount>0</t:ChildFolderCount><t:UnreadCount>0</t:UnreadCount></t:{s}></m:Folders></m:GetFolderResponseMessage>
        , .{ info.tag, id, info.name, info.tag });
        count += 1;
        idx = vend + 1;
    }
    if (count == 0) {
        try buf.appendSlice(a,
            \\<m:GetFolderResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:Folders><t:Folder><t:FolderId Id="msgfolderroot" ChangeKey="ck0"/><t:DisplayName>Top of Information Store</t:DisplayName></t:Folder></m:Folders></m:GetFolderResponseMessage>
        );
    }
    try buf.appendSlice(a, "</m:ResponseMessages></m:GetFolderResponse>");
    return Response{ .body = try envelope(ctx.allocator, buf.items) };
}

/// We don't offer streaming/push subscriptions. Return a proper error response
/// (not an empty body) so the client stops hammering Subscribe and falls back
/// to periodic sync.
fn subscribe(ctx: *Context) !Response {
    const inner =
        \\<m:SubscribeResponse><m:ResponseMessages><m:SubscribeResponseMessage ResponseClass="Error"><m:MessageText>Subscriptions are not supported</m:MessageText><m:ResponseCode>ErrorInvalidServerVersion</m:ResponseCode><m:DescriptiveLinkKey>0</m:DescriptiveLinkKey></m:SubscribeResponseMessage></m:ResponseMessages></m:SubscribeResponse>
    ;
    return Response{ .body = try envelope(ctx.allocator, inner) };
}

fn appendFolder(buf: *std.ArrayList(u8), a: std.mem.Allocator, f: FolderDef) !void {
    const tag = switch (f.kind) {
        .mail => "Folder",
        .calendar => "CalendarFolder",
        .contacts => "ContactsFolder",
    };
    const class = switch (f.kind) {
        .mail => "IPF.Note",
        .calendar => "IPF.Appointment",
        .contacts => "IPF.Contact",
    };
    try buf.print(a,
        \\<t:{s}><t:FolderId Id="{s}" ChangeKey="ck0"/><t:ParentFolderId Id="{s}" ChangeKey="ck0"/><t:FolderClass>{s}</t:FolderClass><t:DisplayName>{s}</t:DisplayName><t:TotalCount>0</t:TotalCount><t:ChildFolderCount>0</t:ChildFolderCount><t:UnreadCount>0</t:UnreadCount></t:{s}>
    , .{ tag, f.id, ROOT_ID, class, f.name, tag });
}

fn syncFolderHierarchy(ctx: *Context, soap: []const u8) !Response {
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(ctx.allocator);
    const a = ctx.allocator;

    // If the client already has a SyncState, there are no further changes.
    const has_state = std.mem.indexOf(u8, soap, "SyncState>") != null and
        std.mem.indexOf(u8, soap, "<m:SyncState/>") == null;

    try buf.appendSlice(a,
        \\<m:SyncFolderHierarchyResponse><m:ResponseMessages><m:SyncFolderHierarchyResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:SyncState>SYNCSTATE1</m:SyncState><m:IncludesLastFolderInRange>true</m:IncludesLastFolderInRange><m:Changes>
    );
    if (!has_state) {
        for (FOLDERS) |f| {
            try buf.appendSlice(a, "<t:Create>");
            try appendFolder(&buf, a, f);
            try buf.appendSlice(a, "</t:Create>");
        }
    }
    try buf.appendSlice(a, "</m:Changes></m:SyncFolderHierarchyResponseMessage></m:ResponseMessages></m:SyncFolderHierarchyResponse>");

    return Response{ .body = try envelope(ctx.allocator, buf.items) };
}

/// Find the value of the FolderId inside a <SyncFolderId>/<ParentFolderId>.
fn extractScopedFolderId(soap: []const u8, scope: []const u8) ?[]const u8 {
    const p = std.mem.indexOf(u8, soap, scope) orelse return null;
    const idp = std.mem.indexOfPos(u8, soap, p, "Id=\"") orelse return null;
    const vstart = idp + 4;
    const vend = std.mem.indexOfScalarPos(u8, soap, vstart, '"') orelse return null;
    return soap[vstart..vend];
}

/// Advance a mailbox- and folder-scoped cursor by one page of changes.
fn syncFolderItems(ctx: *Context, soap: []const u8) !Response {
    const request = xml.operation(soap, "SyncFolderItems") catch return itemSyncError(ctx, "ErrorInvalidRequest", "Invalid sync request");
    const folder_id = if (try request.child("SyncFolderId")) |scope| blk: {
        const id = (try scope.child("FolderId")) orelse (try scope.child("DistinguishedFolderId")) orelse
            return itemSyncError(ctx, "ErrorFolderNotFound", "Unknown sync folder");
        break :blk id.attribute("Id") orelse "";
    } else "inbox";
    const folder = folderById(folder_id) orelse return itemSyncError(ctx, "ErrorFolderNotFound", "Unknown sync folder");
    const max_changes = if (try childText(request, "MaxChangesReturned")) |value|
        std.fmt.parseInt(usize, std.mem.trim(u8, value, " \t\r\n"), 10) catch 0
    else
        512;
    if (max_changes == 0 or max_changes > 512)
        return itemSyncError(ctx, "ErrorInvalidRequest", "MaxChangesReturned must be between 1 and 512");

    const previous = std.mem.trim(u8, (try childText(request, "SyncState")) orelse "", " \t\r\n");
    const user_id = (try ctx.db.enabledMailboxId(ctx.username)) orelse return .{ .status = 403 };
    const cursor: item_sync.Cursor = .{ .db = ctx.db, .user_id = user_id, .folder = folder.id };
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const saved = if (previous.len == 0) null else (try cursor.load(a, previous, max_changes)) orelse return invalidItemSyncState(ctx);
    if (saved) |value| switch (value) {
        .replay => |body| return .{ .body = try ctx.allocator.dupe(u8, body) },
        .current => {},
    };

    const current = folderSyncItems(a, ctx, folder) catch |err| {
        logger.warn("EWS SyncFolderItems: could not read {s}: {s}", .{ folder.id, @errorName(err) });
        return itemSyncError(ctx, "ErrorInternalServerError", "Could not read the sync folder");
    };
    const known = if (saved) |value| value.current.items else &.{};
    const page = try item_sync.page(a, known, current, max_changes);
    const advances = saved == null or page.changes.len > 0;
    const key = if (advances) try item_sync.newKey(a) else previous;
    const response = try itemSyncResponse(a, folder, key, page);
    if (advances) {
        const items = try std.json.Stringify.valueAlloc(a, page.items, .{});
        if (saved == null) {
            try cursor.create(key, items);
        } else if (!try cursor.advance(previous, key, items, response, page.changes.len)) {
            if (try cursor.load(a, previous, max_changes)) |retry| {
                if (retry == .replay) return .{ .body = try ctx.allocator.dupe(u8, retry.replay) };
            }
            return invalidItemSyncState(ctx);
        }
    } else {
        try cursor.touch(key, saved.?.current.touched_at);
    }
    logger.info("EWS SyncFolderItems: folder={s} changes={d} last={any}", .{ folder.id, page.changes.len, page.last });
    return .{ .body = try ctx.allocator.dupe(u8, response) };
}

fn itemSyncError(ctx: *Context, code: []const u8, message: []const u8) !Response {
    const a = ctx.allocator;
    const inner = try std.fmt.allocPrint(a,
        \\<m:SyncFolderItemsResponse><m:ResponseMessages><m:SyncFolderItemsResponseMessage ResponseClass="Error"><m:MessageText>{s}</m:MessageText><m:ResponseCode>{s}</m:ResponseCode><m:SyncState/><m:IncludesLastItemInRange>true</m:IncludesLastItemInRange></m:SyncFolderItemsResponseMessage></m:ResponseMessages></m:SyncFolderItemsResponse>
    , .{ message, code });
    defer a.free(inner);
    return .{ .body = try envelope(a, inner) };
}

fn invalidItemSyncState(ctx: *Context) !Response {
    return itemSyncError(ctx, "ErrorInvalidSyncStateData", "Start a new folder sync without SyncState");
}

fn itemSyncResponse(a: std.mem.Allocator, folder: FolderDef, key: []const u8, page: item_sync.Page) ![]const u8 {
    const tag = switch (folder.kind) {
        .mail => "Message",
        .calendar => "CalendarItem",
        .contacts => "Contact",
    };
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(a);
    try buf.print(a,
        \\<m:SyncFolderItemsResponse><m:ResponseMessages><m:SyncFolderItemsResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:SyncState>{s}</m:SyncState><m:IncludesLastItemInRange>{s}</m:IncludesLastItemInRange><m:Changes>
    , .{ key, if (page.last) "true" else "false" });
    for (page.changes) |change| {
        const id = xmlEscape(a, change.item.id);
        switch (change.kind) {
            .create => try buf.print(a,
                \\<t:Create><t:{s}><t:ItemId Id="{s}" ChangeKey="ck0"/></t:{s}></t:Create>
            , .{ tag, id, tag }),
            .delete => try buf.print(a,
                \\<t:Delete><t:ItemId Id="{s}"/></t:Delete>
            , .{id}),
            .read_flag => try buf.print(a,
                \\<t:ReadFlagChange><t:ItemId Id="{s}"/><t:IsRead>{s}</t:IsRead></t:ReadFlagChange>
            , .{ id, if (change.item.seen.?) "true" else "false" }),
        }
    }
    try buf.appendSlice(a, "</m:Changes></m:SyncFolderItemsResponseMessage></m:ResponseMessages></m:SyncFolderItemsResponse>");
    return envelope(a, buf.items);
}

fn folderSyncItems(a: std.mem.Allocator, ctx: *Context, folder: FolderDef) ![]item_sync.Item {
    var items: std.ArrayList(item_sync.Item) = .empty;
    switch (folder.kind) {
        .mail => try collectSyncMail(a, ctx, folder, &items),
        .calendar => if (ctx.store) |store| {
            const uid = try store.getOrCreateUserId(ctx.username);
            const calendars = try store.getUserCalendars(uid);
            defer store.allocator.free(calendars);
            for (calendars) |calendar| {
                const events = try store.getCalendarEvents(calendar.id);
                defer store.allocator.free(events);
                for (events) |event| {
                    try items.append(a, .{ .id = try std.fmt.allocPrint(a, "calendar:{d}", .{event.id}) });
                }
            }
        },
        .contacts => if (ctx.store) |store| {
            const uid = try store.getOrCreateUserId(ctx.username);
            const books = try store.getUserAddressBooks(uid);
            defer store.allocator.free(books);
            for (books) |book| {
                const contacts = try store.getAddressBookContacts(book.id);
                defer store.allocator.free(contacts);
                for (contacts) |contact| {
                    try items.append(a, .{ .id = try std.fmt.allocPrint(a, "contacts:{d}", .{contact.id}) });
                }
            }
        },
    }
    std.mem.sort(item_sync.Item, items.items, {}, item_sync.Item.lessThan);
    return items.items;
}

/// GetItem: return the message content for each requested ItemId.
fn getItem(ctx: *Context, soap: []const u8) !Response {
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(ctx.allocator);
    const a = ctx.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const aa = arena.allocator();

    try buf.appendSlice(a, "<m:GetItemResponse><m:ResponseMessages>");
    var idx: usize = 0;
    const needle = "ItemId Id=\"";
    while (std.mem.indexOfPos(u8, soap, idx, needle)) |p| {
        const vstart = p + needle.len;
        const vend = std.mem.indexOfScalarPos(u8, soap, vstart, '"') orelse break;
        const id = soap[vstart..vend];
        appendItemMessage(&buf, aa, ctx, try xmlUnescape(aa, id)) catch {
            try buf.appendSlice(a, "<m:GetItemResponseMessage ResponseClass=\"Error\"><m:ResponseCode>ErrorItemNotFound</m:ResponseCode><m:Items/></m:GetItemResponseMessage>");
        };
        idx = vend + 1;
    }
    try buf.appendSlice(a, "</m:ResponseMessages></m:GetItemResponse>");
    return Response{ .body = try envelope(ctx.allocator, buf.items) };
}

fn appendItemMessage(buf: *std.ArrayList(u8), aa: std.mem.Allocator, ctx: *Context, id: []const u8) !void {
    const colon = std.mem.indexOfScalar(u8, id, ':') orelse return error.BadId;
    const folder_id = id[0..colon];
    const rest = id[colon + 1 ..];
    const folder = folderById(folder_id) orelse return error.BadId;
    switch (folder.kind) {
        .calendar => return appendCalendarItem(buf, aa, ctx, id, rest),
        .contacts => return appendContactItem(buf, aa, ctx, id, rest),
        .mail => {},
    }
    const basename = rest;
    const mailbox = folder.mailbox orelse return error.BadId;

    const found = readMailFile(aa, ctx, mailbox, basename) orelse return error.NotFound;
    const raw = found.content;
    const split = headerBodySplit(raw);
    const headers = raw[0..split.header_end];
    const body_raw = raw[split.body_start..];
    const body = if (body_raw.len > 64 * 1024) body_raw[0 .. 64 * 1024] else body_raw;

    const subject = xmlEscape(aa, headerValue(aa, headers, "subject") orelse "(no subject)");
    const from = parseEmail(headerValue(aa, headers, "from") orelse "");
    const to = parseEmail(headerValue(aa, headers, "to") orelse "");
    const date_epoch = parseRfc2822Date(headerValue(aa, headers, "date") orelse "");
    const date = ewsDate(aa, if (date_epoch > 0) date_epoch else found.epoch);
    const a = ctx.allocator;

    // MimeContent MUST be the FIRST element (EWS ItemType xs:sequence) and MUST
    // be valid base64 of the full RFC822. macOS's MFEWSBodyFetchOperation
    // requests it and base64-decodes it via -[NSData initWithBase64EncodedString:];
    // if it's missing, macOS passes nil and Mail CRASHES (SIGABRT in
    // +[MFEWSMessage dataFromMimeContent:]). Encoding the whole raw message also
    // lets macOS render the real MIME (HTML parts, attachments) itself.
    const mime_b64 = aa.alloc(u8, std.base64.standard.Encoder.calcSize(raw.len)) catch return error.NotFound;
    _ = std.base64.standard.Encoder.encode(mime_b64, raw);
    const parts = file_attachments.list(aa, raw) catch &.{};

    // Element order follows the EWS Item/Message xs:sequence (macOS parses it
    // strictly): MimeContent, ItemId, ItemClass, Subject, Body, Attachments, DateTimeReceived,
    // Size, DateTimeSent, then the Message-specific ToRecipients, From, IsRead.
    try buf.appendSlice(a, "<m:GetItemResponseMessage ResponseClass=\"Success\"><m:ResponseCode>NoError</m:ResponseCode><m:Items><t:Message>");
    try buf.print(a, "<t:MimeContent CharacterSet=\"UTF-8\">{s}</t:MimeContent>", .{mime_b64});
    try buf.print(a, "<t:ItemId Id=\"{s}\" ChangeKey=\"{s}\"/>", .{ xmlEscape(aa, id), changeKey(raw) });
    try buf.appendSlice(a, "<t:ItemClass>IPM.Note</t:ItemClass>");
    try buf.print(a, "<t:Subject>{s}</t:Subject>", .{subject});
    try buf.print(a, "<t:Body BodyType=\"Text\">{s}</t:Body>", .{xmlEscape(aa, body)});
    if (parts.len > 0) {
        try buf.appendSlice(a, "<t:Attachments>");
        for (parts) |part| try appendFileAttachment(a, aa, buf, ctx, id, part, null);
        try buf.appendSlice(a, "</t:Attachments>");
    }
    try buf.print(a, "<t:DateTimeReceived>{s}</t:DateTimeReceived>", .{date});
    try buf.print(a, "<t:Size>{d}</t:Size>", .{raw.len});
    try buf.print(a, "<t:HasAttachments>{s}</t:HasAttachments>", .{if (parts.len > 0) "true" else "false"});
    try buf.print(a, "<t:DateTimeSent>{s}</t:DateTimeSent>", .{date});
    if (to.email.len > 0) {
        try buf.print(a, "<t:ToRecipients><t:Mailbox><t:Name>{s}</t:Name><t:EmailAddress>{s}</t:EmailAddress></t:Mailbox></t:ToRecipients>", .{ xmlEscape(aa, to.name), xmlEscape(aa, to.email) });
    }
    try buf.print(a, "<t:From><t:Mailbox><t:Name>{s}</t:Name><t:EmailAddress>{s}</t:EmailAddress></t:Mailbox></t:From>", .{ xmlEscape(aa, from.name), xmlEscape(aa, from.email) });
    try buf.print(a, "<t:IsRead>{s}</t:IsRead>", .{if (found.seen) "true" else "false"});
    try buf.appendSlice(a, "</t:Message></m:Items></m:GetItemResponseMessage>");
}

// ----------------------------------------------------------------------------
// Calendar + Contacts item serialization (from the CalDAV/CardDAV store).
// Element order follows the EWS CalendarItemType/ContactItemType xs:sequence —
// all inherited ItemType elements first, then the type-specific ones. macOS
// parses strictly, so order matters.
// ----------------------------------------------------------------------------

/// Write a complete `<t:CalendarItem>…</t:CalendarItem>` element.
fn writeCalendarItemEl(buf: *std.ArrayList(u8), aa: std.mem.Allocator, a: std.mem.Allocator, full_id: []const u8, ev: caldav_store.Event) !void {
    const start = ewsDate(aa, ev.dtstart);
    const default_len: i64 = if (ev.all_day) 86400 else 3600;
    const end = ewsDate(aa, ev.dtend orelse (ev.dtstart + default_len));

    try buf.appendSlice(a, "<t:CalendarItem>");
    try buf.print(a, "<t:ItemId Id=\"{s}\" ChangeKey=\"ck0\"/>", .{xmlEscape(aa, full_id)});
    try buf.appendSlice(a, "<t:ItemClass>IPM.Appointment</t:ItemClass>");
    try buf.print(a, "<t:Subject>{s}</t:Subject>", .{xmlEscape(aa, ev.summary)});
    try buf.print(a, "<t:Body BodyType=\"Text\">{s}</t:Body>", .{xmlEscape(aa, ev.description orelse "")});
    try buf.appendSlice(a, "<t:HasAttachments>false</t:HasAttachments>");
    // CalendarItemType: UID, Start, End, IsAllDayEvent, LegacyFreeBusyStatus, Location, Organizer.
    try buf.print(a, "<t:UID>{s}</t:UID>", .{xmlEscape(aa, ev.uid)});
    try buf.print(a, "<t:Start>{s}</t:Start>", .{start});
    try buf.print(a, "<t:End>{s}</t:End>", .{end});
    try buf.print(a, "<t:IsAllDayEvent>{s}</t:IsAllDayEvent>", .{if (ev.all_day) "true" else "false"});
    try buf.appendSlice(a, "<t:LegacyFreeBusyStatus>Busy</t:LegacyFreeBusyStatus>");
    if (ev.location) |loc| if (loc.len > 0) try buf.print(a, "<t:Location>{s}</t:Location>", .{xmlEscape(aa, loc)});
    if (ev.organizer) |org| {
        var oaddr = parseEmail(org);
        if (std.mem.startsWith(u8, oaddr.email, "mailto:")) oaddr.email = oaddr.email["mailto:".len..];
        if (oaddr.email.len > 0)
            try buf.print(a, "<t:Organizer><t:Mailbox><t:Name>{s}</t:Name><t:EmailAddress>{s}</t:EmailAddress></t:Mailbox></t:Organizer>", .{ xmlEscape(aa, oaddr.name), xmlEscape(aa, oaddr.email) });
    }
    try buf.appendSlice(a, "</t:CalendarItem>");
}

/// Write a complete `<t:Contact>…</t:Contact>` element.
fn writeContactEl(buf: *std.ArrayList(u8), aa: std.mem.Allocator, a: std.mem.Allocator, full_id: []const u8, c: caldav_store.Contact, emails: []caldav_store.EmailAddress, phones: []caldav_store.PhoneNumber) !void {
    try buf.appendSlice(a, "<t:Contact>");
    try buf.print(a, "<t:ItemId Id=\"{s}\" ChangeKey=\"ck0\"/>", .{xmlEscape(aa, full_id)});
    try buf.appendSlice(a, "<t:ItemClass>IPM.Contact</t:ItemClass>");
    try buf.print(a, "<t:Subject>{s}</t:Subject>", .{xmlEscape(aa, c.full_name)});
    try buf.appendSlice(a, "<t:HasAttachments>false</t:HasAttachments>");
    // ContactItemType: FileAs, DisplayName, GivenName, Nickname, CompanyName,
    // EmailAddresses, PhoneNumbers, JobTitle, Surname.
    try buf.print(a, "<t:FileAs>{s}</t:FileAs>", .{xmlEscape(aa, c.full_name)});
    try buf.print(a, "<t:DisplayName>{s}</t:DisplayName>", .{xmlEscape(aa, c.full_name)});
    if (c.given_name) |gn| if (gn.len > 0) try buf.print(a, "<t:GivenName>{s}</t:GivenName>", .{xmlEscape(aa, gn)});
    if (c.nickname) |nn| if (nn.len > 0) try buf.print(a, "<t:Nickname>{s}</t:Nickname>", .{xmlEscape(aa, nn)});
    if (c.organization) |org| if (org.len > 0) try buf.print(a, "<t:CompanyName>{s}</t:CompanyName>", .{xmlEscape(aa, org)});
    if (emails.len > 0) {
        try buf.appendSlice(a, "<t:EmailAddresses>");
        var n: usize = 0;
        for (emails) |em| {
            if (n >= 3 or em.email.len == 0) continue;
            n += 1;
            try buf.print(a, "<t:Entry Key=\"EmailAddress{d}\">{s}</t:Entry>", .{ n, xmlEscape(aa, em.email) });
        }
        try buf.appendSlice(a, "</t:EmailAddresses>");
    }
    if (phones.len > 0) {
        try buf.appendSlice(a, "<t:PhoneNumbers>");
        var home: u8 = 0;
        var work: u8 = 0;
        var mobile: u8 = 0;
        var fax: u8 = 0;
        var other: u8 = 0;
        for (phones) |ph| {
            if (ph.number.len == 0) continue;
            const key: ?[]const u8 = switch (ph.phone_type) {
                .home => kk: {
                    home += 1;
                    break :kk @as(?[]const u8, if (home == 1) "HomePhone" else if (home == 2) "HomePhone2" else null);
                },
                .work => kk: {
                    work += 1;
                    break :kk @as(?[]const u8, if (work == 1) "BusinessPhone" else if (work == 2) "BusinessPhone2" else null);
                },
                .mobile => kk: {
                    mobile += 1;
                    break :kk @as(?[]const u8, if (mobile == 1) "MobilePhone" else null);
                },
                .fax => kk: {
                    fax += 1;
                    break :kk @as(?[]const u8, if (fax == 1) "HomeFax" else if (fax == 2) "BusinessFax" else null);
                },
                .other => kk: {
                    other += 1;
                    break :kk @as(?[]const u8, if (other == 1) "OtherTelephone" else null);
                },
            };
            if (key) |k| try buf.print(a, "<t:Entry Key=\"{s}\">{s}</t:Entry>", .{ k, xmlEscape(aa, ph.number) });
        }
        try buf.appendSlice(a, "</t:PhoneNumbers>");
    }
    if (c.title) |t| if (t.len > 0) try buf.print(a, "<t:JobTitle>{s}</t:JobTitle>", .{xmlEscape(aa, t)});
    if (c.family_name) |fam| if (fam.len > 0) try buf.print(a, "<t:Surname>{s}</t:Surname>", .{xmlEscape(aa, fam)});
    try buf.appendSlice(a, "</t:Contact>");
}

/// GetItem for `calendar:<event-id>`.
fn appendCalendarItem(buf: *std.ArrayList(u8), aa: std.mem.Allocator, ctx: *Context, full_id: []const u8, rest: []const u8) !void {
    const store = ctx.store orelse return error.NotFound;
    const ev_id = std.fmt.parseInt(u64, rest, 10) catch return error.BadId;
    const ev = store.getEvent(ev_id) orelse return error.NotFound;
    const a = ctx.allocator;
    try buf.appendSlice(a, "<m:GetItemResponseMessage ResponseClass=\"Success\"><m:ResponseCode>NoError</m:ResponseCode><m:Items>");
    try writeCalendarItemEl(buf, aa, a, full_id, ev);
    try buf.appendSlice(a, "</m:Items></m:GetItemResponseMessage>");
}

/// GetItem for `contacts:<contact-id>`.
fn appendContactItem(buf: *std.ArrayList(u8), aa: std.mem.Allocator, ctx: *Context, full_id: []const u8, rest: []const u8) !void {
    const store = ctx.store orelse return error.NotFound;
    const c_id = std.fmt.parseInt(u64, rest, 10) catch return error.BadId;
    const c = store.getContact(c_id) orelse return error.NotFound;
    const a = ctx.allocator;
    const emails = store.getContactEmails(c.id);
    const phones = store.getContactPhones(c.id);
    try buf.appendSlice(a, "<m:GetItemResponseMessage ResponseClass=\"Success\"><m:ResponseCode>NoError</m:ResponseCode><m:Items>");
    try writeContactEl(buf, aa, a, full_id, c, emails, phones);
    try buf.appendSlice(a, "</m:Items></m:GetItemResponseMessage>");
}

// ---------------------------------------------------------------------------
// Maildir access + helpers
// ---------------------------------------------------------------------------

const FoundMail = struct { path: []const u8, content: []const u8, seen: bool, epoch: i64 };

fn mailboxDirs(a: std.mem.Allocator, ctx: *Context, mailbox: []const u8) ![][]const u8 {
    try maildir_path.validate(mailbox);
    if (std.mem.eql(u8, mailbox, "INBOX")) {
        return a.dupe([]const u8, &.{
            try std.fmt.allocPrint(a, "mail/{s}/new", .{ctx.local_part}),
            try std.fmt.allocPrint(a, "mail/{s}/cur", .{ctx.local_part}),
        });
    }
    const base = try std.fmt.allocPrint(a, "mail/{s}/{s}", .{ ctx.local_part, mailbox });
    const nested = [_][]const u8{
        try std.fmt.allocPrint(a, "{s}/new", .{base}),
        try std.fmt.allocPrint(a, "{s}/cur", .{base}),
    };
    if (std.mem.eql(u8, ctx.username, ctx.local_part)) return a.dupe([]const u8, &.{ base, nested[0], nested[1] });
    // Webmail drafts use the canonical account even when native EWS still
    // writes its own legacy drafts under the account's local part.
    if (std.mem.eql(u8, mailbox, "Drafts") and !std.mem.eql(u8, ctx.username, ctx.local_part)) {
        try maildir_path.validate(ctx.username);
        const canonical = try std.fmt.allocPrint(a, "mail/{s}/Drafts", .{ctx.username});
        return a.dupe([]const u8, &.{ canonical, nested[0], nested[1] });
    }
    return a.dupe([]const u8, &nested);
}

fn collectSyncMail(a: std.mem.Allocator, ctx: *Context, folder: FolderDef, out: *std.ArrayList(item_sync.Item)) !void {
    const dirs = try mailboxDirs(a, ctx, folder.mailbox.?);
    var visited: std.StringHashMapUnmanaged(void) = .empty;
    ctx.db.lockMailboxes();
    defer ctx.db.unlockMailboxes();
    for (dirs) |dir| {
        const files = fs_compat.listEmlFiles(a, dir) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        for (files) |name| {
            const basename = maildirBaseName(name);
            // GetItem resolves a duplicated basename from the first directory.
            const entry = try visited.getOrPut(a, basename);
            if (entry.found_existing) continue;
            try out.append(a, .{
                .id = try std.fmt.allocPrint(a, "{s}:{s}", .{ folder.id, basename }),
                .seen = maildirSeen(name),
            });
        }
    }
}

fn readMailFile(a: std.mem.Allocator, ctx: *Context, mailbox: []const u8, basename: []const u8) ?FoundMail {
    const dirs = mailboxDirs(a, ctx, mailbox) catch return null;
    for (dirs) |dir| {
        const files = fs_compat.listEmlFiles(a, dir) catch continue;
        for (files) |fname| {
            if (std.mem.eql(u8, maildirBaseName(fname), basename)) {
                const path = std.fmt.allocPrint(a, "{s}/{s}", .{ dir, fname }) catch return null;
                const content = fs_compat.readFileAlloc(a, path) catch return null;
                return .{ .path = path, .content = content, .seen = maildirSeen(fname), .epoch = maildirEpoch(basename) };
            }
        }
    }
    return null;
}

fn maildirBaseName(filename: []const u8) []const u8 {
    if (std.mem.indexOf(u8, filename, ":2,")) |i| return filename[0..i];
    return filename;
}
fn maildirSeen(filename: []const u8) bool {
    if (std.mem.indexOf(u8, filename, ":2,")) |i| return std.mem.indexOfScalar(u8, filename[i + 3 ..], 'S') != null;
    return false;
}
fn maildirEpoch(base: []const u8) i64 {
    var end: usize = 0;
    while (end < base.len and base[end] >= '0' and base[end] <= '9') end += 1;
    if (end == 0) return 0;
    return std.fmt.parseInt(i64, base[0..end], 10) catch 0;
}

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

const Addr = struct { name: []const u8, email: []const u8 };
/// Parse "Name <email@host>" or "email@host" into name + email.
fn parseEmail(s: []const u8) Addr {
    if (std.mem.indexOfScalar(u8, s, '<')) |lt| {
        if (std.mem.indexOfScalarPos(u8, s, lt, '>')) |gt| {
            const email = s[lt + 1 .. gt];
            var name = std.mem.trim(u8, s[0..lt], " \t\"");
            if (name.len == 0) name = email;
            return .{ .name = name, .email = email };
        }
    }
    const t = std.mem.trim(u8, s, " \t");
    return .{ .name = t, .email = t };
}

fn monthFromName(s: []const u8) ?i64 {
    const names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    for (names, 0..) |n, i| {
        if (s.len >= 3 and std.ascii.eqlIgnoreCase(s[0..3], n)) return @intCast(i + 1);
    }
    return null;
}

/// Days since the unix epoch for a civil date (Howard Hinnant's algorithm).
fn daysFromCivil(y0: i64, m: i64, d: i64) i64 {
    const y = if (m <= 2) y0 - 1 else y0;
    const era = @divFloor(if (y >= 0) y else y - 399, 400);
    const yoe = y - era * 400;
    const mp = if (m > 2) m - 3 else m + 9;
    const doy = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

/// Parse an RFC 2822 Date header ("Sat, 03 May 2026 15:55:14 +0000") to unix
/// seconds. Returns 0 if it can't be parsed.
fn parseRfc2822Date(s_in: []const u8) i64 {
    var s = std.mem.trim(u8, s_in, " \t");
    if (std.mem.indexOfScalar(u8, s, ',')) |c| s = std.mem.trim(u8, s[c + 1 ..], " \t");
    var it = std.mem.tokenizeScalar(u8, s, ' ');
    const day = std.fmt.parseInt(i64, it.next() orelse return 0, 10) catch return 0;
    const month = monthFromName(it.next() orelse return 0) orelse return 0;
    const year = std.fmt.parseInt(i64, it.next() orelse return 0, 10) catch return 0;
    const time = it.next() orelse return 0;
    var tp = std.mem.splitScalar(u8, time, ':');
    const hh = std.fmt.parseInt(i64, tp.next() orelse "0", 10) catch 0;
    const mm = std.fmt.parseInt(i64, tp.next() orelse "0", 10) catch 0;
    const ss = std.fmt.parseInt(i64, tp.next() orelse "0", 10) catch 0;
    var tz_off: i64 = 0;
    if (it.next()) |tz| {
        if (tz.len >= 5 and (tz[0] == '+' or tz[0] == '-')) {
            const h = std.fmt.parseInt(i64, tz[1..3], 10) catch 0;
            const m2 = std.fmt.parseInt(i64, tz[3..5], 10) catch 0;
            tz_off = (h * 3600 + m2 * 60) * (if (tz[0] == '-') @as(i64, -1) else 1);
        }
    }
    return daysFromCivil(year, month, day) * 86400 + hh * 3600 + mm * 60 + ss - tz_off;
}

/// EWS date: `YYYY-MM-DDTHH:MM:SSZ`.
fn ewsDate(a: std.mem.Allocator, epoch: i64) []const u8 {
    const secs: u64 = if (epoch <= 0) 0 else @intCast(epoch);
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.allocPrint(a, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,              @backingInt(md.month),   @as(u32, md.day_index) + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch "1970-01-01T00:00:00Z";
}

/// Escape XML text and replace invalid UTF-8 from legacy MIME headers and bodies.
fn xmlEscape(a: std.mem.Allocator, s: []const u8) []const u8 {
    var buf = std.ArrayList(u8).empty;
    var index: usize = 0;
    while (index < s.len) {
        switch (s[index]) {
            '&' => buf.appendSlice(a, "&amp;") catch {},
            '<' => buf.appendSlice(a, "&lt;") catch {},
            '>' => buf.appendSlice(a, "&gt;") catch {},
            '"' => buf.appendSlice(a, "&quot;") catch {},
            '\'' => buf.appendSlice(a, "&apos;") catch {},
            '\t', '\n', '\r' => buf.append(a, s[index]) catch {},
            0...8, 11, 12, 14...31 => {}, // illegal in XML 1.0 — drop
            0x80...0xff => {
                const len = std.unicode.utf8ByteSequenceLength(s[index]) catch 0;
                if (len != 0 and len <= s.len - index) {
                    const bytes = s[index..][0..len];
                    if (std.unicode.utf8Decode(bytes)) |codepoint| {
                        if (codepoint != 0xfffe and codepoint != 0xffff) buf.appendSlice(a, bytes) catch {};
                        index += len;
                        continue;
                    } else |_| {}
                }
                buf.appendSlice(a, "\u{FFFD}") catch {};
            },
            else => buf.append(a, s[index]) catch {},
        }
        index += 1;
    }
    return buf.items;
}

// ============================================================================
// Sending — CreateItem / SendItem, wired to the server's outbound delivery.
// macOS Mail composes via CreateItem (MessageDisposition="SendAndSaveCopy") for
// a direct send, or SaveOnly (a draft) followed by SendItem referencing the
// draft's ItemId. Both are handled here.
// ============================================================================

/// Monotonic counter to make saved-message filenames unique within a process.
var send_seq: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

/// Value of an XML attribute `name="..."` (first occurrence). Attribute names
/// here are short constants, so we build the needle on the stack.
fn attrValue(soap: []const u8, name: []const u8) ?[]const u8 {
    var nbuf: [64]u8 = undefined;
    if (name.len + 2 > nbuf.len) return null;
    @memcpy(nbuf[0..name.len], name);
    nbuf[name.len] = '=';
    nbuf[name.len + 1] = '"';
    const needle = nbuf[0 .. name.len + 2];
    const p = std.mem.indexOf(u8, soap, needle) orelse return null;
    const vstart = p + needle.len;
    const vend = std.mem.indexOfScalarPos(u8, soap, vstart, '"') orelse return null;
    return soap[vstart..vend];
}

/// Inner text of the first `<...:name ...>...</...:name>` element (namespace
/// prefix and attributes ignored). Null if absent or self-closing.
fn elementText(soap: []const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (std.mem.indexOfScalarPos(u8, soap, i, '<')) |lt| {
        if (lt + 1 >= soap.len or soap[lt + 1] == '/' or soap[lt + 1] == '!' or soap[lt + 1] == '?') {
            i = lt + 1;
            continue;
        }
        var j = lt + 1;
        while (j < soap.len and soap[j] != '>' and soap[j] != ' ' and soap[j] != '/' and
            soap[j] != '\t' and soap[j] != '\r' and soap[j] != '\n') j += 1;
        var tag = soap[lt + 1 .. j];
        if (std.mem.indexOfScalar(u8, tag, ':')) |c| tag = tag[c + 1 ..];
        if (std.mem.eql(u8, tag, name)) {
            const gt = std.mem.indexOfScalarPos(u8, soap, j, '>') orelse return null;
            if (gt > 0 and soap[gt - 1] == '/') return null; // self-closing
            const content_start = gt + 1;
            var k = content_start;
            while (std.mem.indexOfPos(u8, soap, k, "</")) |close| {
                var m = close + 2;
                const cs = m;
                while (m < soap.len and soap[m] != '>' and soap[m] != ' ') m += 1;
                var ct = soap[cs..m];
                if (std.mem.indexOfScalar(u8, ct, ':')) |c| ct = ct[c + 1 ..];
                if (std.mem.eql(u8, ct, name)) return soap[content_start..close];
                k = close + 2;
            }
            return null;
        }
        i = j;
    }
    return null;
}

const xmlUnescape = xml.unescapeText;

/// Collect the `<t:EmailAddress>` values inside a recipients block.
fn collectEmails(a: std.mem.Allocator, block: []const u8, out: *std.ArrayList([]const u8)) !void {
    var pos: usize = 0;
    while (std.mem.indexOfScalarPos(u8, block, pos, '<')) |start| {
        const end = std.mem.indexOfScalarPos(u8, block, start + 1, '>') orelse break;
        const tag = block[start + 1 .. end];
        pos = end + 1;
        if (tag.len == 0 or tag[0] == '/') continue;
        const name_end = std.mem.indexOfAny(u8, tag, " \t\r\n/") orelse tag.len;
        const name = tag[0..name_end];
        const local = if (std.mem.indexOfScalar(u8, name, ':')) |colon| name[colon + 1 ..] else name;
        if (!std.mem.eql(u8, local, "EmailAddress")) continue;
        if (tag[tag.len - 1] == '/') return error.InvalidAddress;
        const close = std.mem.indexOfScalarPos(u8, block, pos, '<') orelse return error.InvalidAddress;
        const email = std.mem.trim(u8, block[pos..close], " \t\r\n");
        try out.append(a, try xmlUnescape(a, email));
        pos = close;
    }
}

/// Collect addresses from a `To`/`Cc` header value (comma-separated, may carry
/// display names).
fn collectHeaderAddrs(a: std.mem.Allocator, headers: []const u8, name: []const u8, out: *std.ArrayList([]const u8)) !void {
    const val = headerValue(a, headers, name) orelse return;
    var it = std.mem.splitScalar(u8, val, ',');
    while (it.next()) |part| {
        const addr = parseEmail(std.mem.trim(u8, part, " \t"));
        if (addr.email.len > 0 and std.mem.indexOfScalar(u8, addr.email, '@') != null) {
            try out.append(a, addr.email);
        }
    }
}

/// Strip CR/LF from a header value so a crafted Subject/recipient can't inject
/// additional headers.
fn headerSafe(a: std.mem.Allocator, s: []const u8) []const u8 {
    var buf = std.ArrayList(u8).empty;
    for (s) |c| buf.append(a, if (c == '\r' or c == '\n') ' ' else c) catch {};
    return buf.items;
}

/// RFC 2822 Date header, e.g. "Sat, 31 May 2026 15:55:14 +0000".
fn rfc2822Date(a: std.mem.Allocator, epoch: i64) []const u8 {
    const secs: u64 = if (epoch <= 0) 0 else @intCast(epoch);
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const ed = es.getEpochDay();
    const yd = ed.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    // Unix day 0 (1970-01-01) was a Thursday.
    const wdays = [_][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" };
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    const wd = wdays[@intCast(ed.day % 7)];
    const mon = months[@backingInt(md.month) - 1];
    return std.fmt.allocPrint(a, "{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} +0000", .{
        wd,                   @as(u32, md.day_index) + 1, mon,                       yd.year,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(),    ds.getSecondsIntoMinute(),
    }) catch "Thu, 01 Jan 1970 00:00:00 +0000";
}

fn savedMailPath(a: std.mem.Allocator, ctx: *Context, mailbox: []const u8, sub: []const u8, filename: []const u8) ![]const u8 {
    const dir = if (std.mem.eql(u8, ctx.username, ctx.local_part))
        try std.fmt.allocPrint(a, "mail/{s}/{s}", .{ ctx.local_part, mailbox })
    else
        try std.fmt.allocPrint(a, "mail/{s}/{s}/{s}", .{ ctx.local_part, mailbox, sub });
    try fs_compat.cwd().makePath(dir);
    return std.fmt.allocPrint(a, "{s}/{s}", .{ dir, filename });
}

fn appendMailResult(a: std.mem.Allocator, buf: *std.ArrayList(u8), comptime op: []const u8, err: ?anyerror) !void {
    if (err) |failure| {
        const code, const message = switch (failure) {
            error.HostedSendingLimit => .{ "ErrorSubmissionQuotaExceeded", "Daily recipient allowance exhausted. Try again after midnight UTC." },
            error.HostedStorageFull, error.StorageLimit, error.DraftStorageLimit => .{ "ErrorQuotaExceeded", "Mailbox storage is full." },
            error.HostedRecipientDisabled, error.HostedSenderDisabled => .{ "ErrorAccessDenied", "Mailbox is disabled." },
            error.HostedSenderReadOnly, error.HostedRecipientReadOnly => .{ "ErrorAccessDenied", "Mailbox is read-only." },
            error.HostedSendingHeld => .{ "ErrorMessageSubmissionBlocked", "Sending is on hold for this mailbox." },
            error.HostedRecipientExpired => .{ "ErrorAccessDenied", "Recipient mailbox service ended." },
            error.NoRecipients => .{ "ErrorMissingRecipients", "At least one recipient is required." },
            error.InvalidAddress => .{ "ErrorInvalidRecipients", "Check the recipient addresses." },
            error.ItemNotFound => .{ "ErrorItemNotFound", "The message could not be found." },
            error.PartialDelivery => .{ "ErrorMessageSubmissionBlocked", "Some recipients received the message. Review delivery before retrying." },
            error.EwsDeliveryUnconfirmed => .{ "ErrorMessageSubmissionBlocked", "The original submission may still be running or could not be confirmed. Review delivery before sending again." },
            error.EwsSendSettingsChanged => .{ "ErrorInvalidSendItemSaveSettings", "This draft revision was already submitted with different Sent settings." },
            error.InvalidXml, error.InvalidMime => .{ "ErrorInvalidRequest", "The message or attachment is not well formed." },
            error.InvalidBase64 => .{ "ErrorInvalidPropertyValue", "Attachment content must be valid base64." },
            error.InvalidMimeBase64 => .{ "ErrorMimeContentInvalidBase64String", "MIME content must be valid base64." },
            error.InvalidAttachment => .{ "ErrorInvalidPropertyValue", "Check the file attachment name, media type, and content." },
            error.InvalidAttachmentId => .{ "ErrorInvalidAttachmentId", "The attachment could not be found." },
            error.UnsupportedAttachment => .{ "ErrorInvalidOperation", "This operation supports file attachments on mail drafts." },
            error.ManagedDraft => .{ "ErrorInvalidOperation", "Open this webmail draft in webmail to change its attachments." },
            error.UnsupportedItem => .{ "ErrorInvalidOperation", "This operation does not support the requested item type." },
            error.StaleSource => .{ "ErrorIrresolvableConflict", "The original message changed. Retrieve its current change key and retry." },
            error.StaleDraft, error.Conflict => .{ "ErrorIrresolvableConflict", "The draft changed or is queued for sending. Retrieve its current change key and retry." },
            error.MalwareDetected => .{ "ErrorVirusDetected", "The malware scanner rejected this message or attachment." },
            error.MessageTooLarge, error.MalwareScanTooLarge, error.AttachmentLimit => .{ "ErrorMessageSizeExceeded", "The message or attachment exceeds the allowed size." },
            error.MalwareScanUnavailable => .{ "ErrorServerBusy", "The malware scanner is temporarily unavailable. Retry the operation." },
            else => .{ "ErrorInternalServerError", "The message could not be processed." },
        };
        try buf.print(a, "<m:" ++ op ++ "ResponseMessage ResponseClass=\"Error\"><m:MessageText>{s}</m:MessageText><m:ResponseCode>{s}</m:ResponseCode></m:" ++ op ++ "ResponseMessage>", .{ message, code });
    } else {
        try buf.appendSlice(a, "<m:" ++ op ++ "ResponseMessage ResponseClass=\"Success\"><m:ResponseCode>NoError</m:ResponseCode></m:" ++ op ++ "ResponseMessage>");
    }
}

fn mailResult(ctx: *Context, a: std.mem.Allocator, comptime op: []const u8, err: ?anyerror) !Response {
    var buf: std.ArrayList(u8) = .empty;
    try buf.appendSlice(a, "<m:" ++ op ++ "Response><m:ResponseMessages>");
    try appendMailResult(a, &buf, op, err);
    try buf.appendSlice(a, "</m:ResponseMessages></m:" ++ op ++ "Response>");
    return .{ .body = try envelope(ctx.allocator, buf.items) };
}

fn maxMailBytes(ctx: *const Context) usize {
    return if (ctx.mail_config) |settings| settings.max_message_size else clamav.default_max_stream_bytes;
}

fn scanMail(ctx: *const Context, message: []const u8) !void {
    if (message.len > maxMailBytes(ctx)) return error.MessageTooLarge;
    try clamav.requireAllowed(ctx.scanner, message);
}

fn submitMail(a: std.mem.Allocator, ctx: *Context, recipients: []const []const u8, raw: []const u8, sent_path: ?[]const u8, sent_copy: []const u8, reply: ?submission.NativeReply, draft: ?database.Database.EwsDraftSend) !void {
    try submission.sendRaw(a, .{
        .hostname = ctx.hostname,
        .mail_config = ctx.mail_config,
        .delivery_method = ctx.delivery_method,
        .ses_region = ctx.ses_region,
        .db = ctx.db,
        .local_hosted_only = true,
    }, .{
        .mailbox = ctx.username,
        .from = ctx.username,
        .recipients = recipients,
        .raw = raw,
        .sent = if (sent_path) |path| .{ .path = path, .bytes = sent_copy } else null,
        .ews_draft = draft,
        .native_reply = reply,
    });
}

/// Map an EWS distinguished folder id back to the Maildir mailbox name.
fn ewsFolderToMailbox(folder: []const u8) []const u8 {
    if (std.mem.eql(u8, folder, "inbox")) return "INBOX";
    if (std.mem.eql(u8, folder, "drafts")) return "Drafts";
    if (std.mem.eql(u8, folder, "sentitems")) return "Sent";
    if (std.mem.eql(u8, folder, "deleteditems")) return "Trash";
    return folder;
}

fn childText(parent: xml.Element, name: []const u8) !?[]const u8 {
    const child = (try parent.child(name)) orelse return null;
    return child.content;
}

fn parseFiles(a: std.mem.Allocator, ctx: *Context, container: xml.Element) ![]const file_attachments.File {
    var result: std.ArrayList(file_attachments.File) = .empty;
    var children = container.children();
    var remaining = maxMailBytes(ctx);
    while (try children.next()) |item| {
        if (!std.mem.eql(u8, item.name, "FileAttachment")) return error.UnsupportedAttachment;
        const name = try xmlUnescape(a, (try childText(item, "Name")) orelse return error.InvalidAttachment);
        const media_type = try xmlUnescape(a, (try childText(item, "ContentType")) orelse "application/octet-stream");
        if (!metadata.validFilename(name) or !metadata.validContentType(media_type)) return error.InvalidAttachment;
        const encoded = try xmlUnescape(a, (try childText(item, "Content")) orelse return error.InvalidAttachment);
        const data = try file_attachments.decode(a, encoded, remaining);
        remaining -= data.len;
        const content_id = if (try childText(item, "ContentId")) |value| blk: {
            const decoded = std.mem.trim(u8, try xmlUnescape(a, value), " \t\r\n");
            const value_id = if (decoded.len >= 2 and decoded[0] == '<' and decoded[decoded.len - 1] == '>') decoded[1 .. decoded.len - 1] else decoded;
            if (value_id.len == 0 or value_id.len > 255) return error.InvalidAttachment;
            for (value_id) |byte| if (byte <= 32 or byte >= 127 or byte == '<' or byte == '>') return error.InvalidAttachment;
            break :blk value_id;
        } else null;
        const inline_text = (try childText(item, "IsInline")) orelse "false";
        try clamav.requireAllowed(ctx.scanner, data);
        try result.append(a, .{
            .id = file_attachments.id(),
            .name = name,
            .content_type = media_type,
            .data = data,
            .content_id = content_id,
            .inline_part = std.ascii.eqlIgnoreCase(inline_text, "true") or std.mem.eql(u8, inline_text, "1"),
        });
    }
    return result.items;
}

fn addFiles(a: std.mem.Allocator, ctx: *Context, raw: []const u8, files: []const file_attachments.File) ![]const u8 {
    const split = headerBodySplit(raw);
    return file_attachments.add(a, raw, split.header_end, split.body_start, headerValue(a, raw[0..split.header_end], "Content-Type"), files, maxMailBytes(ctx));
}

fn createItem(ctx: *Context, soap: []const u8) !Response {
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const request = xml.operation(soap, "CreateItem") catch |err| return mailResult(ctx, a, "CreateItem", err);
    const items = (request.child("Items") catch |err| return mailResult(ctx, a, "CreateItem", err)) orelse
        return mailResult(ctx, a, "CreateItem", error.InvalidXml);
    var children = items.children();
    var batch: std.ArrayList(xml.Element) = .empty;
    while (children.next() catch |err| return mailResult(ctx, a, "CreateItem", err)) |item| try batch.append(a, item);
    if (batch.items.len == 0) return mailResult(ctx, a, "CreateItem", error.InvalidXml);
    if (batch.items.len == 1) {
        const item = batch.items[0];
        if (std.mem.eql(u8, item.name, "CalendarItem")) return createCalendarItem(ctx, item.content);
        if (std.mem.eql(u8, item.name, "Contact")) return createContactItem(ctx, item.content);
    }

    const disposition = request.attribute("MessageDisposition") orelse "SendAndSaveCopy";
    const do_send = !std.mem.eql(u8, disposition, "SaveOnly");
    const save_copy = !std.mem.eql(u8, disposition, "SendOnly");
    if (do_send and save_copy and !std.mem.eql(u8, disposition, "SendAndSaveCopy"))
        return mailResult(ctx, a, "CreateItem", error.InvalidXml);

    var buf: std.ArrayList(u8) = .empty;
    try buf.appendSlice(a, "<m:CreateItemResponse><m:ResponseMessages>");
    for (batch.items) |item| {
        var scratch = std.heap.ArenaAllocator.init(ctx.allocator);
        defer scratch.deinit();
        const saved = createMail(scratch.allocator(), ctx, item, do_send, save_copy) catch |err| {
            try appendMailResult(a, &buf, "CreateItem", err);
            continue;
        };
        if (saved) |item_id| {
            try buf.print(a,
                \\<m:CreateItemResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:Items><t:Message><t:ItemId Id="{s}" ChangeKey="{s}"/></t:Message></m:Items></m:CreateItemResponseMessage>
            , .{ xmlEscape(a, item_id.id), item_id.change_key });
        } else try appendMailResult(a, &buf, "CreateItem", null);
    }
    try buf.appendSlice(a, "</m:ResponseMessages></m:CreateItemResponse>");
    return .{ .body = try envelope(ctx.allocator, buf.items) };
}

fn changeKey(raw: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

const SavedItem = struct { id: []const u8, change_key: [64]u8 };

const Reply = struct {
    original: []const u8,
    ids: thread_ids.Headers,
    source: ?database.Database.TeamReplySource,
    all: bool,
};

fn requireReplyMailbox(a: std.mem.Allocator, ctx: *Context) !void {
    if (std.mem.eql(u8, ctx.local_part, ctx.username)) return;
    if (try ctx.db.userExists(ctx.local_part)) return error.ItemNotFound;
    const owner = (try ctx.db.uniqueUsernameForLocalPart(ctx.local_part, a)) orelse return error.ItemNotFound;
    if (!std.mem.eql(u8, owner, ctx.username)) return error.ItemNotFound;
}

fn shareableReplyParent(ctx: *const Context, mailbox: []const u8, path: []const u8) bool {
    return snapshots.canShareFile(mailbox, webmail_maildir.flagsFrom(std.fs.path.basename(path)), if (ctx.mail_config) |settings| settings.junkFolder() else "Junk");
}

fn loadReply(a: std.mem.Allocator, ctx: *Context, item: xml.Element, keep_source: bool) !Reply {
    const reference = (try item.child("ReferenceItemId")) orelse return error.InvalidXml;
    const id = try xmlUnescape(a, reference.attribute("Id") orelse return error.InvalidXml);
    const colon = std.mem.indexOfScalar(u8, id, ':') orelse return error.ItemNotFound;
    const folder = folderById(id[0..colon]) orelse return error.ItemNotFound;
    const mailbox = folder.mailbox orelse return error.UnsupportedItem;
    const basename = id[colon + 1 ..];
    maildir_path.validate(basename) catch return error.ItemNotFound;

    ctx.db.lockMailboxes();
    defer ctx.db.unlockMailboxes();
    try requireReplyMailbox(a, ctx);
    const found = readMailFile(a, ctx, mailbox, basename) orelse return error.ItemNotFound;
    if (found.content.len > maxMailBytes(ctx)) return error.MessageTooLarge;
    if (reference.attribute("ChangeKey")) |key| {
        // SyncFolderItems supplies ck0. GetItem supplies a content revision.
        if (!std.mem.eql(u8, key, "ck0") and !std.mem.eql(u8, key, &changeKey(found.content))) return error.StaleSource;
    }
    const ids = try thread_ids.parse(a, found.content);
    const source = if (ids.message_id_fields == 1 and ids.own != null and shareableReplyParent(ctx, mailbox, found.path)) source: {
        const stamp = try message_refs.fileStamp(a, found.path);
        const at = message_refs.location(mailbox, basename);
        const ref = if (keep_source)
            try message_refs.issue(a, ctx.db, ctx.username, at, stamp)
        else
            (try message_refs.findAt(a, ctx.db, ctx.username, at, stamp)) orelse break :source null;
        break :source database.Database.TeamReplySource{ .reference = ref, .revision = changeKey(found.content), .wire_id = ids.own.? };
    } else null;
    return .{ .original = found.content, .ids = ids, .source = source, .all = std.mem.eql(u8, item.name, "ReplyAllToItem") };
}

fn saveReplyDraft(a: std.mem.Allocator, ctx: *Context, path: []const u8, raw: []const u8, source: database.Database.TeamReplySource, wire_id: []const u8) !void {
    ctx.db.lockMailboxes();
    defer ctx.db.unlockMailboxes();
    try hosted_limits.checkStorage(ctx.db, ctx.username, raw.len, null);
    try durable_maildir.write(a, path, raw);
    const at = message_refs.location("Drafts", std.fs.path.basename(path));
    errdefer {
        fs_compat.cwd().deleteFile(path) catch {};
        message_refs.forget(ctx.db, ctx.username, at) catch {};
    }
    if (try message_refs.lookup(a, ctx.db, ctx.username, source.reference) == null) return;
    const draft = try message_refs.issue(a, ctx.db, ctx.username, at, try message_refs.fileStamp(a, path));
    try message_refs.recordEwsReplyDraft(ctx.db, ctx.username, draft, wire_id, source);
}

fn createMail(a: std.mem.Allocator, ctx: *Context, item: xml.Element, do_send: bool, save_copy: bool) !?SavedItem {
    const reply = if (std.mem.eql(u8, item.name, "Message"))
        null
    else if (std.mem.eql(u8, item.name, "ReplyToItem") or std.mem.eql(u8, item.name, "ReplyAllToItem"))
        try loadReply(a, ctx, item, !do_send)
    else
        return error.UnsupportedItem;
    const epoch = time_compat.timestamp();
    const nanos = time_compat.nanoTimestamp();
    const seq = send_seq.fetchAdd(1, .monotonic);
    const wire_id = try std.fmt.allocPrint(a, "<{d}.{d}.{d}@{s}>", .{ epoch, nanos, seq, ctx.hostname });
    const mime = try childText(item, "MimeContent");
    const mail = if (mime) |value| blk: {
        if (reply != null) return error.InvalidXml;
        const encoded = try xmlUnescape(a, value);
        const raw = file_attachments.decode(a, encoded, maxMailBytes(ctx)) catch |err|
            return if (err == error.InvalidBase64) error.InvalidMimeBase64 else err;
        break :blk try message_headers.prepareClientMime(a, raw, ctx.username);
    } else try buildMail(a, ctx, item, epoch, wire_id, reply);

    const recipients = try submission.distinctRecipients(a, &.{mail.recipients});
    if (do_send and recipients.len == 0) return error.InvalidAddress;
    var message_data = if (try item.child("Attachments")) |container|
        try addFiles(a, ctx, mail.archive, try parseFiles(a, ctx, container))
    else
        mail.archive;
    const source = if (reply) |parent| parent.source else null;
    const native = if (do_send and save_copy and !mail.has_bcc and source != null)
        try submission.prepareNativeReply(a, ctx.db, ctx.username, message_data, recipients, source.?, ctx.hostname, maxMailBytes(ctx))
    else
        null;
    if (native) |approved| message_data = approved.archive;
    try scanMail(ctx, message_data);

    const target_mailbox: []const u8 = if (do_send) "Sent" else "Drafts";
    const sub: []const u8 = if (do_send) "cur" else "new";
    const suffix: []const u8 = if (do_send) ":2,S" else ":2,D";
    const filename = try std.fmt.allocPrint(a, "{d}.{d}{d}.{s}.eml{s}", .{ epoch, nanos, seq, ctx.hostname, suffix });
    const path = if (save_copy) try savedMailPath(a, ctx, target_mailbox, sub, filename) else null;
    if (do_send) {
        const raw = try message_headers.withoutBcc(a, message_data);
        try submitMail(a, ctx, recipients, raw, path, message_data, native, null);
    } else if (path) |draft| {
        if (source) |parent|
            try saveReplyDraft(a, ctx, draft, message_data, parent, wire_id)
        else
            try hosted_limits.write(ctx.db, a, ctx.username, draft, message_data);
    }
    if (path == null) return null;
    const folder = if (do_send) "sentitems" else "drafts";
    return .{ .id = try std.fmt.allocPrint(a, "{s}:{s}", .{ folder, maildirBaseName(filename) }), .change_key = changeKey(message_data) };
}

fn buildMail(a: std.mem.Allocator, ctx: *Context, item: xml.Element, epoch: i64, wire_id: []const u8, reply: ?Reply) !message_headers.ClientMime {
    const original_headers = if (reply) |parent| parent.original[0..headerBodySplit(parent.original).header_end] else "";
    const subject = if (try childText(item, "Subject")) |value| try xmlUnescape(a, value) else subject: {
        if (reply == null) break :subject "";
        const original = headerValue(a, original_headers, "Subject") orelse "";
        if (std.ascii.startsWithIgnoreCase(original, "Re:")) break :subject original;
        break :subject try std.fmt.allocPrint(a, "Re: {s}", .{original});
    };
    const new_body = if (reply != null) try item.child("NewBodyContent") else null;
    const element = new_body orelse try item.child("Body");
    const body = if (element) |el| try xmlUnescape(a, el.content) else "";
    const body_type = if (element) |el| el.attribute("BodyType") orelse "Text" else "Text";
    const html = std.ascii.eqlIgnoreCase(body_type, "HTML");
    const ctype: []const u8 = if (html) "text/html; charset=utf-8" else "text/plain; charset=utf-8";

    var msg: std.ArrayList(u8) = .empty;
    try msg.print(a, "From: {s}\r\n", .{ctx.username});
    const fields = [_][]const u8{ "To", "Cc", "Bcc" };
    const xml_names = [_][]const u8{ "ToRecipients", "CcRecipients", "BccRecipients" };
    var recipients: std.ArrayList([]const u8) = .empty;
    var has_bcc = false;
    for (fields, xml_names, 0..) |name, element_name, index| {
        const first = recipients.items.len;
        if (try childText(item, element_name)) |block| {
            try collectEmails(a, block, &recipients);
            has_bcc = has_bcc or index == 2;
        } else if (reply) |parent| {
            try defaultReplyRecipients(a, ctx.username, original_headers, index, parent.all, &recipients);
        }
        for (recipients.items[first..]) |address| if (!submission.isSafeAddress(address)) return error.InvalidAddress;
        if (recipients.items.len > first) try msg.print(a, "{s}: {s}\r\n", .{ name, try std.mem.join(a, ", ", recipients.items[first..]) });
    }
    try msg.print(a, "Subject: {s}\r\n", .{headerSafe(a, subject)});
    try msg.print(a, "Date: {s}\r\n", .{rfc2822Date(a, epoch)});
    try msg.print(a, "Message-ID: {s}\r\n", .{wire_id});
    if (reply) |parent| {
        if (parent.ids.message_id_fields == 1) {
            if (parent.ids.own) |id| {
                try msg.print(a, "In-Reply-To: {s}\r\nReferences:", .{id});
                const ancestors = parent.ids.parents;
                for (ancestors[ancestors.len -| 30..]) |ancestor| {
                    if (!std.mem.eql(u8, ancestor, id)) try msg.print(a, "\r\n {s}", .{ancestor});
                }
                try msg.print(a, "\r\n {s}\r\n", .{id});
            }
        }
    }
    try msg.print(a, "MIME-Version: 1.0\r\nContent-Type: {s}\r\nContent-Transfer-Encoding: 8bit\r\n\r\n", .{ctype});
    try msg.appendSlice(a, body);
    if (reply) |parent| {
        // Body can carry a complete client-edited response. NewBodyContent
        // precedes the inline quote in the same rendered body.
        if (new_body != null or element == null)
            try appendReplyQuote(a, &msg, parent.original, html, maxMailBytes(ctx));
    }
    if (!std.mem.endsWith(u8, msg.items, "\n")) try msg.appendSlice(a, "\r\n");
    return .{ .archive = msg.items, .recipients = recipients.items, .has_bcc = has_bcc };
}

fn appendReplyQuote(a: std.mem.Allocator, msg: *std.ArrayList(u8), original: []const u8, html: bool, max_bytes: usize) !void {
    const quote = std.mem.trimEnd(u8, try webmail_maildir.clipText(a, original), "\n");
    if (quote.len == 0) return;
    if (html) {
        try msg.appendSlice(a, "\r\n<blockquote><pre>");
        for (quote) |byte| {
            if (msg.items.len >= max_bytes) return error.MessageTooLarge;
            switch (byte) {
                '&' => try msg.appendSlice(a, "&amp;"),
                '<' => try msg.appendSlice(a, "&lt;"),
                '>' => try msg.appendSlice(a, "&gt;"),
                '\n' => try msg.appendSlice(a, "\r\n"),
                else => try msg.append(a, byte),
            }
        }
        try msg.appendSlice(a, "</pre></blockquote>");
    } else {
        try msg.appendSlice(a, "\r\n\r\n");
        var lines = std.mem.splitScalar(u8, quote, '\n');
        while (lines.next()) |line| {
            if (msg.items.len >= max_bytes) return error.MessageTooLarge;
            try msg.print(a, "> {s}\r\n", .{line});
        }
    }
}

fn defaultReplyRecipients(a: std.mem.Allocator, user: []const u8, headers: []const u8, index: usize, all: bool, recipients: *std.ArrayList([]const u8)) !void {
    if (index == 2 or (index == 1 and !all)) return;
    var inferred: std.ArrayList([]const u8) = .empty;
    if (index == 0) {
        const author = headerValue(a, headers, "Reply-To") orelse headerValue(a, headers, "From") orelse "";
        try message_headers.appendMailboxes(a, author, &inferred);
    }
    const own_message = inferred.items.len == 1 and std.ascii.eqlIgnoreCase(inferred.items[0], user);
    if (index == 1 or all or own_message) {
        if (headerValue(a, headers, if (index == 0) "To" else "Cc")) |value|
            try message_headers.appendMailboxes(a, value, &inferred);
    }
    for (inferred.items) |address| {
        if (std.ascii.eqlIgnoreCase(address, user)) continue;
        for (recipients.items) |present| {
            if (std.ascii.eqlIgnoreCase(address, present)) break;
        } else try recipients.append(a, address);
    }
}

fn createAttachment(ctx: *Context, soap: []const u8) !Response {
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    return addAttachmentsToDraft(a, ctx, soap) catch |err| return mailResult(ctx, a, "CreateAttachment", err);
}

fn attachmentScope(ctx: *const Context) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(ctx.username, &digest, .{});
    return std.fmt.bytesToHex(digest[0..16].*, .lower);
}

fn appendFileAttachment(a: std.mem.Allocator, scratch: std.mem.Allocator, buf: *std.ArrayList(u8), ctx: *Context, item: []const u8, part: file_attachments.Part, content: ?[]const u8) !void {
    try buf.print(a, "<t:FileAttachment><t:AttachmentId Id=\"{s}:{s}:{s}\"/>", .{ attachmentScope(ctx), xmlEscape(scratch, item), part.id });
    try buf.print(a, "<t:Name>{s}</t:Name><t:ContentType>{s}</t:ContentType>", .{ xmlEscape(scratch, part.info.filename), xmlEscape(scratch, part.info.content_type) });
    if (part.info.content_id.len > 0)
        try buf.print(a, "<t:ContentId>{s}</t:ContentId>", .{xmlEscape(scratch, part.info.content_id)});
    try buf.print(a, "<t:Size>{d}</t:Size><t:IsInline>{s}</t:IsInline>", .{ part.info.size, if (part.inline_part) "true" else "false" });
    if (content) |bytes| {
        const encoder = std.base64.standard.Encoder;
        try buf.appendSlice(a, "<t:Content>");
        _ = encoder.encode(try buf.addManyAsSlice(a, encoder.calcSize(bytes.len)), bytes);
        try buf.appendSlice(a, "</t:Content>");
    }
    try buf.appendSlice(a, "</t:FileAttachment>");
}

fn attachmentOperation(ctx: *Context, soap: []const u8, comptime op: []const u8) !Response {
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const request = xml.operation(soap, op) catch |err| return mailResult(ctx, a, op, err);
    const ids = (try request.child("AttachmentIds")) orelse return mailResult(ctx, a, op, error.InvalidXml);
    var count: usize = 0;
    var elements = ids.children();
    while (try elements.next()) |_| {
        count += 1;
        if (count > 100) return mailResult(ctx, a, op, error.InvalidXml);
    }
    if (count == 0) return mailResult(ctx, a, op, error.InvalidXml);
    var buf: std.ArrayList(u8) = .empty;
    var remaining = maxMailBytes(ctx);
    try buf.appendSlice(a, "<m:" ++ op ++ "Response><m:ResponseMessages>");
    elements = ids.children();
    while (try elements.next()) |element| {
        var item_arena = std.heap.ArenaAllocator.init(ctx.allocator);
        defer item_arena.deinit();
        const start = buf.items.len;
        appendAttachmentResult(a, item_arena.allocator(), &buf, &remaining, ctx, element, op) catch |err| {
            buf.shrinkRetainingCapacity(start);
            try appendMailResult(a, &buf, op, err);
        };
    }
    try buf.appendSlice(a, "</m:ResponseMessages></m:" ++ op ++ "Response>");
    return .{ .body = try envelope(ctx.allocator, buf.items) };
}

fn appendAttachmentResult(a: std.mem.Allocator, scratch: std.mem.Allocator, buf: *std.ArrayList(u8), remaining: *usize, ctx: *Context, element: xml.Element, comptime op: []const u8) !void {
    if (!std.mem.eql(u8, element.name, "AttachmentId")) return error.InvalidAttachmentId;
    const id = try xmlUnescape(scratch, element.attribute("Id") orelse return error.InvalidAttachmentId);
    const scope = attachmentScope(ctx);
    if (id.len <= scope.len or id[scope.len] != ':' or !std.mem.eql(u8, id[0..scope.len], &scope))
        return error.InvalidAttachmentId;
    const root_end = std.mem.lastIndexOfScalar(u8, id, ':') orelse unreachable;
    if (root_end <= scope.len or !file_attachments.isId(id[root_end + 1 ..])) return error.InvalidAttachmentId;
    const item = id[scope.len + 1 .. root_end];
    const folder_end = std.mem.indexOfScalar(u8, item, ':') orelse return error.InvalidAttachmentId;
    const folder = folderById(item[0..folder_end]) orelse return error.InvalidAttachmentId;
    const mailbox = folder.mailbox orelse return error.UnsupportedAttachment;
    const basename = item[folder_end + 1 ..];
    const found = readMailFile(scratch, ctx, mailbox, basename) orelse return error.InvalidAttachmentId;
    const parts = try file_attachments.list(scratch, found.content);
    const index = for (parts, 0..) |part, index| {
        if (std.mem.eql(u8, &part.id, id[root_end + 1 ..])) break index;
    } else return error.InvalidAttachmentId;

    if (comptime std.mem.eql(u8, op, "GetAttachment")) {
        const part = parts[index];
        if (part.info.size > remaining.*) return error.MessageTooLarge;
        const content = try part.readData(scratch, found.content);
        if (content.len > remaining.*) return error.MessageTooLarge;
        try buf.appendSlice(a, "<m:GetAttachmentResponseMessage ResponseClass=\"Success\"><m:ResponseCode>NoError</m:ResponseCode><m:Attachments>");
        try appendFileAttachment(a, scratch, buf, ctx, item, part, content);
        try buf.appendSlice(a, "</m:Attachments></m:GetAttachmentResponseMessage>");
        remaining.* -= content.len;
    } else {
        if (!std.mem.eql(u8, folder.id, "drafts")) return error.UnsupportedAttachment;
        if (element.attribute("RootItemChangeKey")) |key| {
            if (!std.mem.eql(u8, key, &changeKey(found.content))) return error.StaleDraft;
        }
        const updated = try file_attachments.remove(scratch, found.content, parts, index);
        const part = parts[index];
        try replaceDraftAttachments(scratch, ctx, basename, found, updated, .{ .remove = .{
            .index = index,
            .count = parts.len,
            .filename = part.info.filename,
            .content_type = part.info.content_type,
            .data = try part.readData(scratch, found.content),
        } });
        try buf.print(a,
            \\<m:DeleteAttachmentResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:RootItemId RootItemId="{s}" RootItemChangeKey="{s}"/></m:DeleteAttachmentResponseMessage>
        , .{ xmlEscape(scratch, item), changeKey(updated) });
    }
}

fn replaceDraftAttachments(a: std.mem.Allocator, ctx: *Context, filename: []const u8, previous: FoundMail, updated: []const u8, edit: webmail_service.DraftAttachmentEdit) !void {
    try scanMail(ctx, updated);
    if (ctx.draft_service) |service| return service.editDraftAttachments(a, ctx.username, previous.path, previous.content, updated, edit);
    ctx.db.lockMailboxes();
    defer ctx.db.unlockMailboxes();
    const current = readMailFile(a, ctx, "Drafts", filename) orelse return error.ItemNotFound;
    if (!std.mem.eql(u8, current.content, previous.content)) return error.StaleDraft;
    if (try webmail_store.managesDraftFile(ctx.db, ctx.username, filename)) return error.ManagedDraft;
    try webmail_maildir.replaceDraftFile(a, ctx.db, ctx.username, current.path, updated);
}

fn addAttachmentsToDraft(a: std.mem.Allocator, ctx: *Context, soap: []const u8) !Response {
    const request = try xml.operation(soap, "CreateAttachment");
    const parent = (try request.child("ParentItemId")) orelse return error.InvalidXml;
    const item_id = try xmlUnescape(a, parent.attribute("Id") orelse return error.InvalidXml);
    const prefix = "drafts:";
    if (!std.mem.startsWith(u8, item_id, prefix)) return error.UnsupportedAttachment;
    const filename = item_id[prefix.len..];
    const draft = readMailFile(a, ctx, "Drafts", filename) orelse return error.ItemNotFound;
    if (parent.attribute("ChangeKey")) |key| {
        if (!std.mem.eql(u8, key, "ck0") and !std.mem.eql(u8, key, &changeKey(draft.content))) return error.StaleDraft;
    }
    const container = (try request.child("Attachments")) orelse return error.InvalidXml;
    const files = try parseFiles(a, ctx, container);
    if (files.len == 0) return error.InvalidAttachment;
    const updated = try addFiles(a, ctx, draft.content, files);
    const uploads = try a.alloc(webmail_store.Upload, files.len);
    for (files, uploads) |*file, *upload| upload.* = .{
        .id = &file.id,
        .filename = file.name,
        .content_type = file.content_type,
        .data = file.data,
        .content_id = file.content_id orelse "",
        .inline_part = file.inline_part,
    };
    try replaceDraftAttachments(a, ctx, filename, draft, updated, .{ .add = uploads });

    const item = xmlEscape(a, item_id);
    const scope = attachmentScope(ctx);
    const updated_key = changeKey(updated);
    var buf: std.ArrayList(u8) = .empty;
    try buf.appendSlice(a, "<m:CreateAttachmentResponse><m:ResponseMessages>");
    for (files) |file| {
        try buf.print(a,
            \\<m:CreateAttachmentResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:Attachments><t:FileAttachment><t:AttachmentId Id="{s}:{s}:{s}" RootItemId="{s}" RootItemChangeKey="{s}"/></t:FileAttachment></m:Attachments></m:CreateAttachmentResponseMessage>
        , .{ scope, item, file.id, item, updated_key });
    }
    try buf.appendSlice(a, "</m:ResponseMessages></m:CreateAttachmentResponse>");
    return .{ .body = try envelope(ctx.allocator, buf.items) };
}

// ----------------------------------------------------------------------------
// CreateItem for Calendar + Contacts (writes to the CalDAV/CardDAV store).
// The store stores the passed string pointers directly (no dup), so every
// dynamic string handed to createEvent/createContact is duped on the store's
// long-lived allocator; folder-name literals are static and passed as-is.
// ----------------------------------------------------------------------------

/// Parse an EWS dateTime ("2026-06-01T15:00:00Z" or with ±HH:MM) to unix secs.
fn parseEwsDate(s_in: []const u8) i64 {
    const s = std.mem.trim(u8, s_in, " \t\r\n");
    if (s.len < 19) return 0;
    const year = std.fmt.parseInt(i64, s[0..4], 10) catch return 0;
    const month = std.fmt.parseInt(i64, s[5..7], 10) catch return 0;
    const day = std.fmt.parseInt(i64, s[8..10], 10) catch return 0;
    const hh = std.fmt.parseInt(i64, s[11..13], 10) catch return 0;
    const mm = std.fmt.parseInt(i64, s[14..16], 10) catch return 0;
    const ss = std.fmt.parseInt(i64, s[17..19], 10) catch return 0;
    var epoch = daysFromCivil(year, month, day) * 86400 + hh * 3600 + mm * 60 + ss;
    if (s.len >= 25 and (s[19] == '+' or s[19] == '-')) {
        const tz = s[19..];
        const oh = std.fmt.parseInt(i64, tz[1..3], 10) catch 0;
        const om = std.fmt.parseInt(i64, tz[4..6], 10) catch 0;
        const off = oh * 3600 + om * 60;
        epoch += if (tz[0] == '-') off else -off;
    }
    return epoch;
}

const Entry = struct { key: []const u8, value: []const u8 };

/// Collect `<t:Entry Key="…">value</t:Entry>` pairs inside a dictionary block
/// (EmailAddresses / PhoneNumbers).
fn collectEntries(block: []const u8, out: *std.ArrayList(Entry), a: std.mem.Allocator) !void {
    var i: usize = 0;
    while (std.mem.indexOfScalarPos(u8, block, i, '<')) |lt| {
        if (lt + 1 >= block.len or block[lt + 1] == '/' or block[lt + 1] == '!' or block[lt + 1] == '?') {
            i = lt + 1;
            continue;
        }
        var j = lt + 1;
        while (j < block.len and block[j] != '>' and block[j] != ' ' and block[j] != '/' and
            block[j] != '\t' and block[j] != '\r' and block[j] != '\n') j += 1;
        var tag = block[lt + 1 .. j];
        if (std.mem.indexOfScalar(u8, tag, ':')) |c| tag = tag[c + 1 ..];
        if (!std.mem.eql(u8, tag, "Entry")) {
            i = j;
            continue;
        }
        const gt = std.mem.indexOfScalarPos(u8, block, j, '>') orelse break;
        const key = attrValue(block[lt .. gt + 1], "Key") orelse "";
        if (gt > 0 and block[gt - 1] == '/') {
            i = gt + 1;
            continue;
        }
        const close = std.mem.indexOfPos(u8, block, gt + 1, "<") orelse break;
        try out.append(a, .{ .key = key, .value = std.mem.trim(u8, block[gt + 1 .. close], " \t\r\n") });
        i = close + 1;
    }
}

fn phoneTypeFromKey(key: []const u8) caldav_store.PhoneNumber.PhoneType {
    if (std.mem.indexOf(u8, key, "Mobile") != null or std.mem.indexOf(u8, key, "Cell") != null) return .mobile;
    if (std.mem.indexOf(u8, key, "Business") != null or std.mem.indexOf(u8, key, "Work") != null) return .work;
    if (std.mem.indexOf(u8, key, "Fax") != null) return .fax;
    if (std.mem.indexOf(u8, key, "Home") != null) return .home;
    return .other;
}

/// xmlUnescape an element's inner text onto `sa`, or null if empty/absent.
fn dupOpt(sa: std.mem.Allocator, el: []const u8, name: []const u8) ?[]const u8 {
    const v = elementText(el, name) orelse return null;
    if (v.len == 0) return null;
    const u = xmlUnescape(sa, v) catch return null;
    return if (u.len == 0) null else u;
}

fn resolveCalendarId(ctx: *Context) ?u64 {
    const store = ctx.store orelse return null;
    const uid = store.getOrCreateUserId(ctx.username) catch return null;
    const cals = store.getUserCalendars(uid) catch return null;
    defer store.allocator.free(cals);
    if (cals.len > 0) return cals[0].id;
    return store.createCalendar(uid, "Calendar", null) catch null;
}

fn resolveAddressBookId(ctx: *Context) ?u64 {
    const store = ctx.store orelse return null;
    const uid = store.getOrCreateUserId(ctx.username) catch return null;
    const abs = store.getUserAddressBooks(uid) catch return null;
    defer store.allocator.free(abs);
    if (abs.len > 0) return abs[0].id;
    return store.createAddressBook(uid, "Contacts", null) catch null;
}

fn createItemError(ctx: *Context) !Response {
    const inner =
        \\<m:CreateItemResponse><m:ResponseMessages><m:CreateItemResponseMessage ResponseClass="Error"><m:MessageText>Could not create item</m:MessageText><m:ResponseCode>ErrorInternalServerError</m:ResponseCode></m:CreateItemResponseMessage></m:ResponseMessages></m:CreateItemResponse>
    ;
    return Response{ .body = try envelope(ctx.allocator, inner) };
}

fn createItemOk(ctx: *Context, item_tag: []const u8, full_id: []const u8) !Response {
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(ctx.allocator);
    const a = ctx.allocator;
    try buf.print(a,
        \\<m:CreateItemResponse><m:ResponseMessages><m:CreateItemResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:Items><t:{s}><t:ItemId Id="{s}" ChangeKey="ck0"/></t:{s}></m:Items></m:CreateItemResponseMessage></m:ResponseMessages></m:CreateItemResponse>
    , .{ item_tag, full_id, item_tag });
    return Response{ .body = try envelope(a, buf.items) };
}

/// CreateItem carrying a <t:CalendarItem> → store.createEvent.
fn createCalendarItem(ctx: *Context, el: []const u8) !Response {
    const store = ctx.store orelse return createItemError(ctx);
    const sa = store.allocator;
    const cal_id = resolveCalendarId(ctx) orelse return createItemError(ctx);

    const subject = xmlUnescape(sa, elementText(el, "Subject") orelse "(no title)") catch return createItemError(ctx);
    const body = xmlUnescape(sa, elementText(el, "Body") orelse "") catch "";
    const location = xmlUnescape(sa, elementText(el, "Location") orelse "") catch "";
    const start = parseEwsDate(elementText(el, "Start") orelse "");
    const end_t = parseEwsDate(elementText(el, "End") orelse "");
    const all_day = std.mem.eql(u8, elementText(el, "IsAllDayEvent") orelse "false", "true");
    const uid = std.fmt.allocPrint(sa, "ews-{d}-{d}@{s}", .{ time_compat.timestamp(), send_seq.fetchAdd(1, .monotonic), ctx.hostname }) catch return createItemError(ctx);

    const ev_id = store.createEvent(cal_id, .{
        .uid = uid,
        .summary = subject,
        .description = if (body.len > 0) body else null,
        .location = if (location.len > 0) location else null,
        .dtstart = if (start > 0) start else time_compat.timestamp(),
        .dtend = if (end_t > 0) end_t else null,
        .all_day = all_day,
    }) catch return createItemError(ctx);

    logger.info("EWS CreateItem CalendarItem: id={d} cal={d} subj_len={d} start={d} end={d}", .{ ev_id, cal_id, subject.len, start, end_t });

    const full_id = std.fmt.allocPrint(ctx.allocator, "calendar:{d}", .{ev_id}) catch return createItemError(ctx);
    defer ctx.allocator.free(full_id);
    return createItemOk(ctx, "CalendarItem", full_id);
}

/// CreateItem carrying a <t:Contact> → store.createContact (+ emails/phones).
fn createContactItem(ctx: *Context, el: []const u8) !Response {
    const store = ctx.store orelse return createItemError(ctx);
    const sa = store.allocator;
    const ab_id = resolveAddressBookId(ctx) orelse return createItemError(ctx);

    // Request-scoped scratch for the entry lists; the strings themselves live on
    // `sa` so they outlive this request inside the store.
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    const display = elementText(el, "DisplayName") orelse elementText(el, "FileAs") orelse "Unnamed";
    const full_name = xmlUnescape(sa, display) catch return createItemError(ctx);

    var emails = std.ArrayList(caldav_store.CalDavStore.EmailData).empty;
    var phones = std.ArrayList(caldav_store.CalDavStore.PhoneData).empty;
    if (elementText(el, "EmailAddresses")) |eb| {
        var entries = std.ArrayList(Entry).empty;
        collectEntries(eb, &entries, aa) catch {};
        for (entries.items) |en| {
            if (en.value.len == 0) continue;
            const dup = xmlUnescape(sa, en.value) catch continue;
            emails.append(aa, .{ .email = dup, .email_type = .other, .is_primary = emails.items.len == 0 }) catch {};
        }
    }
    if (elementText(el, "PhoneNumbers")) |pb| {
        var entries = std.ArrayList(Entry).empty;
        collectEntries(pb, &entries, aa) catch {};
        for (entries.items) |en| {
            if (en.value.len == 0) continue;
            const dup = xmlUnescape(sa, en.value) catch continue;
            phones.append(aa, .{ .number = dup, .phone_type = phoneTypeFromKey(en.key), .is_primary = phones.items.len == 0 }) catch {};
        }
    }

    const uid = std.fmt.allocPrint(sa, "ews-{d}-{d}@{s}", .{ time_compat.timestamp(), send_seq.fetchAdd(1, .monotonic), ctx.hostname }) catch return createItemError(ctx);
    const c_id = store.createContact(ab_id, .{
        .uid = uid,
        .full_name = full_name,
        .given_name = dupOpt(sa, el, "GivenName"),
        .family_name = dupOpt(sa, el, "Surname"),
        .nickname = dupOpt(sa, el, "Nickname"),
        .organization = dupOpt(sa, el, "CompanyName"),
        .title = dupOpt(sa, el, "JobTitle"),
        .emails = emails.items,
        .phones = phones.items,
    }) catch return createItemError(ctx);

    logger.info("EWS CreateItem Contact: id={d} ab={d} name_len={d} emails={d} phones={d}", .{ c_id, ab_id, full_name.len, emails.items.len, phones.items.len });

    const full_id = std.fmt.allocPrint(ctx.allocator, "contacts:{d}", .{c_id}) catch return createItemError(ctx);
    defer ctx.allocator.free(full_id);
    return createItemOk(ctx, "Contact", full_id);
}

/// Delete a Maildir message file (hard delete). Returns true on success.
fn deleteMailFile(a: std.mem.Allocator, ctx: *Context, mailbox: []const u8, basename: []const u8) bool {
    const dirs = mailboxDirs(a, ctx, mailbox) catch return false;
    for (dirs) |dir| {
        const files = fs_compat.listEmlFiles(a, dir) catch continue;
        for (files) |fname| {
            if (std.mem.eql(u8, maildirBaseName(fname), basename)) {
                const path = std.fmt.allocPrint(a, "{s}/{s}", .{ dir, fname }) catch return false;
                fs_compat.cwd().deleteFile(path) catch return false;
                return true;
            }
        }
    }
    return false;
}

/// Resolve one DeleteItem ItemId to the right backing store and delete it.
fn deleteOne(ctx: *Context, a: std.mem.Allocator, id: []const u8) bool {
    const colon = std.mem.indexOfScalar(u8, id, ':') orelse return false;
    const folder = folderById(id[0..colon]) orelse return false;
    const rest = id[colon + 1 ..];
    switch (folder.kind) {
        .calendar => {
            const store = ctx.store orelse return false;
            const ev_id = std.fmt.parseInt(u64, rest, 10) catch return false;
            store.deleteEvent(ev_id) catch return false;
            return true;
        },
        .contacts => {
            const store = ctx.store orelse return false;
            const c_id = std.fmt.parseInt(u64, rest, 10) catch return false;
            store.deleteContact(c_id) catch return false;
            return true;
        },
        .mail => {
            const mailbox = folder.mailbox orelse return false;
            return deleteMailFile(a, ctx, mailbox, rest);
        },
    }
}

/// DeleteItem: remove the referenced item(s) from their backing store
/// (calendar event / contact / Maildir message). One ResponseMessage per id.
fn deleteItem(ctx: *Context, soap: []const u8) !Response {
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    const a = ctx.allocator;

    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(a);
    try buf.appendSlice(a, "<m:DeleteItemResponse><m:ResponseMessages>");

    const needle = "ItemId Id=\"";
    var i: usize = 0;
    var n: usize = 0;
    while (std.mem.indexOfPos(u8, soap, i, needle)) |p| {
        const vs = p + needle.len;
        const ve = std.mem.indexOfScalarPos(u8, soap, vs, '"') orelse break;
        const id = soap[vs..ve];
        i = ve + 1;
        n += 1;
        if (deleteOne(ctx, aa, id)) {
            try buf.appendSlice(a, "<m:DeleteItemResponseMessage ResponseClass=\"Success\"><m:ResponseCode>NoError</m:ResponseCode></m:DeleteItemResponseMessage>");
        } else {
            try buf.appendSlice(a, "<m:DeleteItemResponseMessage ResponseClass=\"Error\"><m:MessageText>Item not found</m:MessageText><m:ResponseCode>ErrorItemNotFound</m:ResponseCode></m:DeleteItemResponseMessage>");
        }
    }
    if (n == 0) {
        try buf.appendSlice(a, "<m:DeleteItemResponseMessage ResponseClass=\"Success\"><m:ResponseCode>NoError</m:ResponseCode></m:DeleteItemResponseMessage>");
    }
    try buf.appendSlice(a, "</m:ResponseMessages></m:DeleteItemResponse>");
    logger.info("EWS DeleteItem: items={d}", .{n});
    return Response{ .body = try envelope(a, buf.items) };
}

/// SendItem: send previously-saved draft(s) referenced by ItemId. Reads each
/// draft's RFC822 from its Maildir, extracts recipients from the headers,
/// delivers, and (if SaveItemToFolder) copies it to Sent.
fn sendItem(ctx: *Context, soap: []const u8) !Response {
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const request = xml.operation(soap, "SendItem") catch |err| return mailResult(ctx, a, "SendItem", err);
    const items = (request.child("ItemIds") catch |err| return mailResult(ctx, a, "SendItem", err)) orelse
        return mailResult(ctx, a, "SendItem", error.InvalidXml);
    const save = request.attribute("SaveItemToFolder") orelse "true";
    const save_copy = std.mem.eql(u8, save, "true") or std.mem.eql(u8, save, "1");
    if (!save_copy and !std.mem.eql(u8, save, "false") and !std.mem.eql(u8, save, "0"))
        return mailResult(ctx, a, "SendItem", error.InvalidXml);
    var ids: std.ArrayList(xml.Element) = .empty;
    var children = items.children();
    while (children.next() catch |err| return mailResult(ctx, a, "SendItem", err)) |item| try ids.append(a, item);

    var buf = std.ArrayList(u8).empty;
    try buf.appendSlice(a, "<m:SendItemResponse><m:ResponseMessages>");
    for (ids.items) |item| {
        var scratch = std.heap.ArenaAllocator.init(ctx.allocator);
        defer scratch.deinit();
        sendSavedItem(scratch.allocator(), ctx, item, save_copy) catch |err| {
            try appendMailResult(a, &buf, "SendItem", err);
            continue;
        };
        try appendMailResult(a, &buf, "SendItem", null);
    }
    if (ids.items.len == 0) try appendMailResult(a, &buf, "SendItem", error.ItemNotFound);
    try buf.appendSlice(a, "</m:ResponseMessages></m:SendItemResponse>");
    return Response{ .body = try envelope(ctx.allocator, buf.items) };
}

fn draftReplySource(a: std.mem.Allocator, ctx: *Context, found: FoundMail, reference: []const u8) !?database.Database.TeamReplySource {
    const ids = try thread_ids.parse(a, found.content);
    const wire_id = ids.own orelse return null;
    if (ids.message_id_fields != 1 or ids.reply_fields != 1) return null;
    const proof = (try message_refs.ewsReplyDraft(a, ctx.db, ctx.username, reference, wire_id)) orelse return null;
    const parent = try webmail_maildir.resolveVersioned(a, ctx.db, ctx.username, proof.reference);
    if (!shareableReplyParent(ctx, parent.locator.folder, parent.path)) return null;
    if (!std.mem.eql(u8, &proof.revision, &changeKey(parent.raw))) return null;
    return proof;
}

fn sendSavedItem(a: std.mem.Allocator, ctx: *Context, item: xml.Element, save_copy: bool) !void {
    if (!std.mem.eql(u8, item.name, "ItemId")) return error.UnsupportedItem;
    const id = try xmlUnescape(a, item.attribute("Id") orelse return error.InvalidXml);
    const colon = std.mem.indexOfScalar(u8, id, ':') orelse return error.ItemNotFound;
    const mailbox = ewsFolderToMailbox(id[0..colon]);
    const basename = id[colon + 1 ..];
    const is_draft = std.mem.eql(u8, mailbox, "Drafts");
    const key = if (item.attribute("ChangeKey")) |value| (if (std.mem.eql(u8, value, "ck0")) null else value) else null;
    const found, const draft, const source = blk: {
        ctx.db.lockMailboxes();
        defer ctx.db.unlockMailboxes();
        try requireReplyMailbox(a, ctx);
        const found = readMailFile(a, ctx, mailbox, basename) orelse {
            if (is_draft and try ews_drafts.replay(ctx.db, ctx.username, basename, key, save_copy)) return;
            return error.ItemNotFound;
        };
        const revision = changeKey(found.content);
        if (key) |value| {
            if (!std.mem.eql(u8, value, &revision)) {
                if (is_draft and try ews_drafts.replay(ctx.db, ctx.username, basename, value, save_copy)) return;
                return error.StaleDraft;
            }
        }
        if (!is_draft) break :blk .{ found, null, null };
        const identity = try message_refs.fileFingerprint(a, found.path);
        const at = message_refs.location(mailbox, std.fs.path.basename(found.path));
        const reference = (try message_refs.recoverAt(a, ctx.db, ctx.username, at, identity.stamp, &revision)) orelse
            try message_refs.issue(a, ctx.db, ctx.username, at, identity.stamp);
        const draft: database.Database.EwsDraftSend = .{
            .reference = reference,
            .revision = revision,
            .save_copy = save_copy,
            .path = found.path,
            .fingerprint = identity.fingerprint,
        };
        const source = if (save_copy) draftReplySource(a, ctx, found, reference) catch null else null;
        break :blk .{ found, draft, source };
    };
    if (draft) |saved| if (try submission.replayEwsDraft(a, ctx.db, ctx.username, saved)) return;
    const split = headerBodySplit(found.content);
    const headers = found.content[0..split.header_end];
    var addresses: std.ArrayList([]const u8) = .empty;
    for ([_][]const u8{ "To", "Cc", "Bcc" }) |field| try collectHeaderAddrs(a, headers, field, &addresses);
    const recipients = try submission.distinctRecipients(a, &.{addresses.items});
    const has_bcc = headerValue(a, headers, "Bcc") != null;
    const native = if (!has_bcc and source != null)
        try submission.prepareNativeReply(a, ctx.db, ctx.username, found.content, recipients, source.?, ctx.hostname, maxMailBytes(ctx))
    else
        null;
    const archive = if (native) |approved| approved.archive else found.content;
    try scanMail(ctx, archive);
    const raw = if (has_bcc) try message_headers.withoutBcc(a, archive) else archive;
    const path = if (save_copy) blk: {
        const seq = send_seq.fetchAdd(1, .monotonic);
        const filename = try std.fmt.allocPrint(a, "{d}.{d}{d}.{s}.eml:2,S", .{ time_compat.timestamp(), time_compat.nanoTimestamp(), seq, ctx.hostname });
        break :blk try savedMailPath(a, ctx, "Sent", "cur", filename);
    } else null;
    try submitMail(a, ctx, recipients, raw, path, archive, native, draft);
}

fn findFolder(ctx: *Context, soap: []const u8) !Response {
    _ = soap;
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(ctx.allocator);
    const a = ctx.allocator;
    try buf.print(a,
        \\<m:FindFolderResponse><m:ResponseMessages><m:FindFolderResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:RootFolder TotalItemsInView="{d}" IncludesLastItemInRange="true"><t:Folders>
    , .{FOLDERS.len});
    for (FOLDERS) |f| try appendFolder(&buf, a, f);
    try buf.appendSlice(a, "</t:Folders></m:RootFolder></m:FindFolderResponseMessage></m:ResponseMessages></m:FindFolderResponse>");
    return Response{ .body = try envelope(ctx.allocator, buf.items) };
}

/// FindItem: macOS Calendar/Contacts may enumerate via FindItem rather than
/// SyncFolderItems+GetItem. Return the fully-serialized items for the
/// calendar/contacts parent folder; mail folders stay empty (they use
/// SyncFolderItems). The id scheme matches GetItem (calendar:<id>/contacts:<id>).
fn findItem(ctx: *Context, soap: []const u8) !Response {
    // First (Distinguished)FolderId inside ParentFolderIds.
    const needle = "FolderId Id=\"";
    const parent: []const u8 = if (std.mem.indexOf(u8, soap, needle)) |p| blk: {
        const vs = p + needle.len;
        const ve = std.mem.indexOfScalarPos(u8, soap, vs, '"') orelse break :blk "";
        break :blk soap[vs..ve];
    } else "";

    const a = ctx.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const aa = arena.allocator();

    var items = std.ArrayList(u8).empty; // serialized items, built on the arena
    var count: usize = 0;

    if (folderById(parent)) |folder| {
        if (ctx.store) |store| switch (folder.kind) {
            .calendar => {
                const uid = store.getOrCreateUserId(ctx.username) catch 0;
                if (uid != 0) {
                    const cals = store.getUserCalendars(uid) catch &[_]caldav_store.Calendar{};
                    defer store.allocator.free(cals);
                    for (cals) |cal| {
                        const evs = store.getCalendarEvents(cal.id) catch &[_]caldav_store.Event{};
                        defer store.allocator.free(evs);
                        for (evs) |ev| {
                            const fid = std.fmt.allocPrint(aa, "calendar:{d}", .{ev.id}) catch continue;
                            writeCalendarItemEl(&items, aa, aa, fid, ev) catch continue;
                            count += 1;
                        }
                    }
                }
            },
            .contacts => {
                const uid = store.getOrCreateUserId(ctx.username) catch 0;
                if (uid != 0) {
                    const abs = store.getUserAddressBooks(uid) catch &[_]caldav_store.AddressBook{};
                    defer store.allocator.free(abs);
                    for (abs) |ab| {
                        const cts = store.getAddressBookContacts(ab.id) catch &[_]caldav_store.Contact{};
                        defer store.allocator.free(cts);
                        for (cts) |c| {
                            const fid = std.fmt.allocPrint(aa, "contacts:{d}", .{c.id}) catch continue;
                            const emails = store.getContactEmails(c.id);
                            const phones = store.getContactPhones(c.id);
                            writeContactEl(&items, aa, aa, fid, c, emails, phones) catch continue;
                            count += 1;
                        }
                    }
                }
            },
            .mail => {},
        };
    }

    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(a);
    try buf.print(a,
        \\<m:FindItemResponse><m:ResponseMessages><m:FindItemResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:RootFolder TotalItemsInView="{d}" IncludesLastItemInRange="true"><t:Items>
    , .{count});
    try buf.appendSlice(a, items.items);
    try buf.appendSlice(a, "</t:Items></m:RootFolder></m:FindItemResponseMessage></m:ResponseMessages></m:FindItemResponse>");
    return Response{ .body = try envelope(a, buf.items) };
}

fn oofSettings(ctx: *Context) !Response {
    const inner =
        \\<m:GetUserOofSettingsResponse><m:ResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode></m:ResponseMessage><t:OofSettings><t:OofState>Disabled</t:OofState><t:ExternalAudience>All</t:ExternalAudience></t:OofSettings></m:GetUserOofSettingsResponse>
    ;
    return Response{ .body = try envelope(ctx.allocator, inner) };
}

fn userConfigurationFault(ctx: *Context) !Response {
    // No user configuration; report ErrorItemNotFound so the client uses defaults.
    const inner =
        \\<m:GetUserConfigurationResponse><m:ResponseMessages><m:GetUserConfigurationResponseMessage ResponseClass="Error"><m:MessageText>Not found</m:MessageText><m:ResponseCode>ErrorItemNotFound</m:ResponseCode></m:GetUserConfigurationResponseMessage></m:ResponseMessages></m:GetUserConfigurationResponse>
    ;
    return Response{ .body = try envelope(ctx.allocator, inner) };
}

fn softFault(ctx: *Context, op: []const u8) !Response {
    _ = op;
    // Minimal benign success envelope (no operation-specific body). Logged above.
    return Response{ .body = try envelope(ctx.allocator, "") };
}

test "extract operation strips namespace" {
    const soap =
        \\<s:Envelope><s:Body><m:GetFolder xmlns:m="..."><m:FolderShape/></m:GetFolder></s:Body></s:Envelope>
    ;
    try std.testing.expectEqualStrings("GetFolder", extractOperation(soap));
}
