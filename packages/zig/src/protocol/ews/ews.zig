const std = @import("std");
const logger = @import("../../core/logger.zig");
// NOTE: for a future standalone `zig-ews`, reach the mailbox/store through a
// callback interface on Context instead of importing these directly.
const database = @import("../../storage/database.zig");
const caldav_store = @import("../../storage/caldav_store.zig");
const fs_compat = @import("../../core/fs_compat.zig");
const time_compat = @import("../../core/time_compat.zig");
const outbound = @import("../../delivery/outbound.zig");
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
    /// Maildir directory name for the user (local part of the address).
    local_part: []const u8,
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
    // Log a chunk of the request so the exact macOS SOAP can be implemented.
    const peek = soap[0..@min(soap.len, 1400)];
    logger.info("EWS req: {s}", .{peek});

    if (std.mem.eql(u8, op, "GetFolder")) return getFolder(ctx, soap);
    if (std.mem.eql(u8, op, "SyncFolderHierarchy")) return syncFolderHierarchy(ctx, soap);
    if (std.mem.eql(u8, op, "SyncFolderItems")) return syncFolderItems(ctx, soap);
    if (std.mem.eql(u8, op, "GetItem")) return getItem(ctx, soap);
    if (std.mem.eql(u8, op, "CreateItem")) return createItem(ctx, soap);
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

/// SyncFolderItems: on the first sync (no SyncState) return every message in the
/// folder as an Add (IdOnly — macOS then GetItems them). Subsequent syncs (the
/// client echoes our SyncState) return no changes.
fn syncFolderItems(ctx: *Context, soap: []const u8) !Response {
    const folder_id = extractScopedFolderId(soap, "SyncFolderId") orelse "inbox";
    const has_state = std.mem.indexOf(u8, soap, "SyncState") != null;

    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(ctx.allocator);
    const a = ctx.allocator;

    try buf.appendSlice(a,
        \\<m:SyncFolderItemsResponse><m:ResponseMessages><m:SyncFolderItemsResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:SyncState>SS1</m:SyncState><m:IncludesLastItemInRange>true</m:IncludesLastItemInRange><m:Changes>
    );

    if (!has_state) {
        if (folderById(folder_id)) |folder| {
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const aa = arena.allocator();
            switch (folder.kind) {
                .mail => if (folder.mailbox) |mailbox| {
                    var items = std.ArrayList(MailItem).empty;
                    collectMail(aa, ctx, mailbox, &items) catch {};
                    for (items.items) |it| {
                        const id = std.fmt.allocPrint(aa, "{s}:{s}", .{ folder_id, it.basename }) catch continue;
                        try buf.print(a,
                            \\<t:Create><t:Message><t:ItemId Id="{s}" ChangeKey="ck0"/></t:Message></t:Create>
                        , .{id});
                    }
                },
                .calendar => try appendCalendarSyncCreates(&buf, a, ctx),
                .contacts => try appendContactSyncCreates(&buf, a, ctx),
            }
        }
    }

    try buf.appendSlice(a, "</m:Changes></m:SyncFolderItemsResponseMessage></m:ResponseMessages></m:SyncFolderItemsResponse>");
    return Response{ .body = try envelope(ctx.allocator, buf.items) };
}

/// Emit a `<t:Create><t:CalendarItem><t:ItemId/></t:CalendarItem></t:Create>`
/// for every event across all of the user's calendars. The item id is
/// `calendar:<event.id>` (a globally-unique store id GetItem can resolve).
fn appendCalendarSyncCreates(buf: *std.ArrayList(u8), a: std.mem.Allocator, ctx: *Context) !void {
    const store = ctx.store orelse return;
    const uid = store.getOrCreateUserId(ctx.username) catch return;
    const cals = store.getUserCalendars(uid) catch return;
    defer store.allocator.free(cals);
    for (cals) |cal| {
        const events = store.getCalendarEvents(cal.id) catch continue;
        defer store.allocator.free(events);
        for (events) |ev| {
            try buf.print(a,
                \\<t:Create><t:CalendarItem><t:ItemId Id="calendar:{d}" ChangeKey="ck0"/></t:CalendarItem></t:Create>
            , .{ev.id});
        }
    }
}

/// Emit a `<t:Create><t:Contact><t:ItemId/></t:Contact></t:Create>` for every
/// contact across all of the user's address books. Id is `contacts:<contact.id>`.
fn appendContactSyncCreates(buf: *std.ArrayList(u8), a: std.mem.Allocator, ctx: *Context) !void {
    const store = ctx.store orelse return;
    const uid = store.getOrCreateUserId(ctx.username) catch return;
    const abs = store.getUserAddressBooks(uid) catch return;
    defer store.allocator.free(abs);
    for (abs) |ab| {
        const contacts = store.getAddressBookContacts(ab.id) catch continue;
        defer store.allocator.free(contacts);
        for (contacts) |c| {
            try buf.print(a,
                \\<t:Create><t:Contact><t:ItemId Id="contacts:{d}" ChangeKey="ck0"/></t:Contact></t:Create>
            , .{c.id});
        }
    }
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
        appendItemMessage(&buf, aa, ctx, id) catch {
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

    // Element order follows the EWS Item/Message xs:sequence (macOS parses it
    // strictly): ItemId, ItemClass, Subject, Body, DateTimeReceived, Size,
    // DateTimeSent, then the Message-specific ToRecipients, From, IsRead.
    try buf.appendSlice(a, "<m:GetItemResponseMessage ResponseClass=\"Success\"><m:ResponseCode>NoError</m:ResponseCode><m:Items><t:Message>");
    try buf.print(a, "<t:ItemId Id=\"{s}\" ChangeKey=\"ck0\"/>", .{xmlEscape(aa, id)});
    try buf.appendSlice(a, "<t:ItemClass>IPM.Note</t:ItemClass>");
    try buf.print(a, "<t:Subject>{s}</t:Subject>", .{subject});
    try buf.print(a, "<t:Body BodyType=\"Text\">{s}</t:Body>", .{xmlEscape(aa, body)});
    try buf.print(a, "<t:DateTimeReceived>{s}</t:DateTimeReceived>", .{date});
    try buf.print(a, "<t:Size>{d}</t:Size>", .{raw.len});
    try buf.appendSlice(a, "<t:HasAttachments>false</t:HasAttachments>");
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

const MailItem = struct {
    basename: []const u8,
    path: []const u8,
    seen: bool,
    epoch: i64,
};

const FoundMail = struct { content: []const u8, seen: bool, epoch: i64 };

fn mailboxDirs(a: std.mem.Allocator, ctx: *Context, mailbox: []const u8) ![2][]const u8 {
    if (std.mem.eql(u8, mailbox, "INBOX")) {
        return .{
            try std.fmt.allocPrint(a, "mail/{s}/new", .{ctx.local_part}),
            try std.fmt.allocPrint(a, "mail/{s}/cur", .{ctx.local_part}),
        };
    }
    const base = try std.fmt.allocPrint(a, "mail/{s}/{s}", .{ ctx.local_part, mailbox });
    return .{
        try std.fmt.allocPrint(a, "{s}/new", .{base}),
        try std.fmt.allocPrint(a, "{s}/cur", .{base}),
    };
}

fn collectMail(a: std.mem.Allocator, ctx: *Context, mailbox: []const u8, out: *std.ArrayList(MailItem)) !void {
    const dirs = try mailboxDirs(a, ctx, mailbox);
    for (dirs) |dir| {
        const files = fs_compat.listEmlFiles(a, dir) catch continue;
        for (files) |fname| {
            try out.append(a, .{
                .basename = maildirBaseName(fname),
                .path = try std.fmt.allocPrint(a, "{s}/{s}", .{ dir, fname }),
                .seen = maildirSeen(fname),
                .epoch = maildirEpoch(maildirBaseName(fname)),
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
                return .{ .content = content, .seen = maildirSeen(fname), .epoch = maildirEpoch(basename) };
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
        yd.year, @intFromEnum(md.month), @as(u32, md.day_index) + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch "1970-01-01T00:00:00Z";
}

/// Escape text for XML and strip characters illegal in XML 1.0 (control chars),
/// so raw MIME bodies can't corrupt the SOAP response (which macOS parses strictly).
fn xmlEscape(a: std.mem.Allocator, s: []const u8) []const u8 {
    var buf = std.ArrayList(u8).empty;
    for (s) |c| {
        switch (c) {
            '&' => buf.appendSlice(a, "&amp;") catch {},
            '<' => buf.appendSlice(a, "&lt;") catch {},
            '>' => buf.appendSlice(a, "&gt;") catch {},
            '"' => buf.appendSlice(a, "&quot;") catch {},
            '\'' => buf.appendSlice(a, "&apos;") catch {},
            '\t', '\n', '\r' => buf.append(a, c) catch {},
            0...8, 11, 12, 14...31 => {}, // illegal in XML 1.0 — drop
            else => buf.append(a, c) catch {},
        }
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

/// Decode the XML entities EWS uses to escape Subject/Body text.
fn xmlUnescape(a: std.mem.Allocator, s: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(a);
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == '&') {
            if (std.mem.startsWith(u8, s[i..], "&amp;")) {
                try buf.append(a, '&');
                i += 5;
                continue;
            }
            if (std.mem.startsWith(u8, s[i..], "&lt;")) {
                try buf.append(a, '<');
                i += 4;
                continue;
            }
            if (std.mem.startsWith(u8, s[i..], "&gt;")) {
                try buf.append(a, '>');
                i += 4;
                continue;
            }
            if (std.mem.startsWith(u8, s[i..], "&quot;")) {
                try buf.append(a, '"');
                i += 6;
                continue;
            }
            if (std.mem.startsWith(u8, s[i..], "&apos;")) {
                try buf.append(a, '\'');
                i += 6;
                continue;
            }
            if (std.mem.startsWith(u8, s[i..], "&#")) {
                if (std.mem.indexOfScalarPos(u8, s, i, ';')) |semi| {
                    const num = s[i + 2 .. semi];
                    const cp: ?u21 = if (num.len > 1 and (num[0] == 'x' or num[0] == 'X'))
                        (std.fmt.parseInt(u21, num[1..], 16) catch null)
                    else
                        (std.fmt.parseInt(u21, num, 10) catch null);
                    if (cp) |code| {
                        var utf8: [4]u8 = undefined;
                        if (std.unicode.utf8Encode(code, &utf8)) |n| {
                            try buf.appendSlice(a, utf8[0..n]);
                            i = semi + 1;
                            continue;
                        } else |_| {}
                    }
                }
            }
        }
        try buf.append(a, s[i]);
        i += 1;
    }
    return buf.toOwnedSlice(a);
}

/// Collect the `<t:EmailAddress>` values inside a recipients block.
fn collectEmails(a: std.mem.Allocator, block: []const u8, out: *std.ArrayList([]const u8)) !void {
    const tag = "EmailAddress>";
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, block, i, tag)) |p| {
        const vstart = p + tag.len;
        const close = std.mem.indexOfScalarPos(u8, block, vstart, '<') orelse break;
        const email = std.mem.trim(u8, block[vstart..close], " \t\r\n");
        if (email.len > 0 and std.mem.indexOfScalar(u8, email, '@') != null) {
            try out.append(a, email);
        }
        i = close + 1;
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
    const mon = months[@intFromEnum(md.month) - 1];
    return std.fmt.allocPrint(a, "{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} +0000", .{
        wd,                      @as(u32, md.day_index) + 1, mon, yd.year,
        ds.getHoursIntoDay(),    ds.getMinutesIntoHour(),    ds.getSecondsIntoMinute(),
    }) catch "Thu, 01 Jan 1970 00:00:00 +0000";
}

/// Write `data` into mail/{user}/{mailbox}/{sub}/{filename} (Maildir).
fn saveToMailbox(a: std.mem.Allocator, ctx: *Context, mailbox: []const u8, sub: []const u8, filename: []const u8, data: []const u8) !void {
    const dir = try std.fmt.allocPrint(a, "mail/{s}/{s}/{s}", .{ ctx.local_part, mailbox, sub });
    fs_compat.cwd().makePath(dir) catch {};
    const path = try std.fmt.allocPrint(a, "{s}/{s}", .{ dir, filename });
    const file = try fs_compat.cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll(data);
}

/// Map an EWS distinguished folder id back to the Maildir mailbox name.
fn ewsFolderToMailbox(folder: []const u8) []const u8 {
    if (std.mem.eql(u8, folder, "inbox")) return "INBOX";
    if (std.mem.eql(u8, folder, "drafts")) return "Drafts";
    if (std.mem.eql(u8, folder, "sentitems")) return "Sent";
    if (std.mem.eql(u8, folder, "deleteditems")) return "Trash";
    return folder;
}

/// CreateItem: build an RFC822 message from the composed EWS Message, deliver it
/// via the server's outbound path (SES on AWS, direct MX on Hetzner), and save a
/// copy to Sent (or Drafts for MessageDisposition="SaveOnly").
fn createItem(ctx: *Context, soap: []const u8) !Response {
    // Calendar/Contacts creates carry a <t:CalendarItem>/<t:Contact> instead of
    // a <t:Message>; route those to the CalDAV/CardDAV store.
    if (elementText(soap, "CalendarItem") != null) return createCalendarItem(ctx, soap);
    if (elementText(soap, "Contact") != null) return createContactItem(ctx, soap);

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const disposition = attrValue(soap, "MessageDisposition") orelse "SendAndSaveCopy";
    const do_send = !std.mem.eql(u8, disposition, "SaveOnly");
    const save_copy = !std.mem.eql(u8, disposition, "SendOnly");

    // Scope field extraction to the <t:Message> element. Without this, the
    // prefix-stripping elementText("Body") would match the SOAP envelope's
    // <soap:Body> (which appears first) and swallow the whole request as the
    // message body. Subject/recipients are unique, but Message scoping is the
    // robust fix for any field that collides with an envelope element name.
    const scope = elementText(soap, "Message") orelse soap;

    const subject = try xmlUnescape(a, elementText(scope, "Subject") orelse "");
    const body = try xmlUnescape(a, elementText(scope, "Body") orelse "");
    const body_type = attrValue(scope, "BodyType") orelse "Text";
    const is_html = std.ascii.eqlIgnoreCase(body_type, "HTML");

    var to_list = std.ArrayList([]const u8).empty;
    var cc_list = std.ArrayList([]const u8).empty;
    if (elementText(scope, "ToRecipients")) |blk| try collectEmails(a, blk, &to_list);
    if (elementText(scope, "CcRecipients")) |blk| try collectEmails(a, blk, &cc_list);

    logger.info("EWS CreateItem: disp={s} subj_len={d} to={d} cc={d} bodytype={s}", .{
        disposition, subject.len, to_list.items.len, cc_list.items.len, body_type,
    });

    // Build the RFC822 message.
    const epoch = time_compat.timestamp();
    const nanos = time_compat.nanoTimestamp();
    const seq = send_seq.fetchAdd(1, .monotonic);
    const msgid = try std.fmt.allocPrint(a, "{d}.{d}.{d}@{s}", .{ epoch, nanos, seq, ctx.hostname });
    const date_hdr = rfc2822Date(a, epoch);
    const ctype: []const u8 = if (is_html) "text/html; charset=utf-8" else "text/plain; charset=utf-8";

    var msg = std.ArrayList(u8).empty;
    try msg.print(a, "From: {s}\r\n", .{ctx.username});
    if (to_list.items.len > 0) {
        try msg.appendSlice(a, "To: ");
        for (to_list.items, 0..) |r, idx| {
            if (idx > 0) try msg.appendSlice(a, ", ");
            try msg.appendSlice(a, headerSafe(a, r));
        }
        try msg.appendSlice(a, "\r\n");
    }
    if (cc_list.items.len > 0) {
        try msg.appendSlice(a, "Cc: ");
        for (cc_list.items, 0..) |r, idx| {
            if (idx > 0) try msg.appendSlice(a, ", ");
            try msg.appendSlice(a, headerSafe(a, r));
        }
        try msg.appendSlice(a, "\r\n");
    }
    try msg.print(a, "Subject: {s}\r\n", .{headerSafe(a, subject)});
    try msg.print(a, "Date: {s}\r\n", .{date_hdr});
    try msg.print(a, "Message-ID: <{s}>\r\n", .{msgid});
    try msg.appendSlice(a, "MIME-Version: 1.0\r\n");
    try msg.print(a, "Content-Type: {s}\r\n", .{ctype});
    try msg.appendSlice(a, "Content-Transfer-Encoding: 8bit\r\n\r\n");
    try msg.appendSlice(a, body);
    if (!std.mem.endsWith(u8, msg.items, "\n")) try msg.appendSlice(a, "\r\n");
    const message_data = msg.items;

    // Deliver to every recipient (To + Cc).
    var delivered: usize = 0;
    var failed: usize = 0;
    if (do_send) {
        var all = std.ArrayList([]const u8).empty;
        try all.appendSlice(a, to_list.items);
        try all.appendSlice(a, cc_list.items);
        for (all.items) |rcpt| {
            outbound.deliverToRemote(ctx.allocator, ctx.username, rcpt, message_data, ctx.hostname, ctx.delivery_method, ctx.ses_region) catch |err| {
                logger.err("EWS CreateItem: delivery to {s} failed: {s}", .{ rcpt, @errorName(err) });
                failed += 1;
                continue;
            };
            delivered += 1;
        }
        logger.info("EWS CreateItem: delivered={d} failed={d}", .{ delivered, failed });
    }

    // Save a copy: Sent (read) for sends, Drafts (unread) for SaveOnly.
    const target_mailbox: []const u8 = if (do_send) "Sent" else "Drafts";
    const sub: []const u8 = if (do_send) "cur" else "new";
    const suffix: []const u8 = if (do_send) ":2,S" else ":2,";
    const filename = try std.fmt.allocPrint(a, "{d}.{d}{d}.{s}.eml{s}", .{ epoch, nanos, seq, ctx.hostname, suffix });
    const item_folder: []const u8 = if (do_send) "sentitems" else "drafts";
    if (save_copy) {
        saveToMailbox(a, ctx, target_mailbox, sub, filename, message_data) catch |err| {
            logger.err("EWS CreateItem: save to {s} failed: {s}", .{ target_mailbox, @errorName(err) });
        };
    }

    const item_basename = maildirBaseName(filename);
    var buf = std.ArrayList(u8).empty;
    try buf.print(a,
        \\<m:CreateItemResponse><m:ResponseMessages><m:CreateItemResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:Items><t:Message><t:ItemId Id="{s}:{s}" ChangeKey="ck0"/></t:Message></m:Items></m:CreateItemResponseMessage></m:ResponseMessages></m:CreateItemResponse>
    , .{ item_folder, item_basename });
    return Response{ .body = try envelope(ctx.allocator, buf.items) };
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
fn createCalendarItem(ctx: *Context, soap: []const u8) !Response {
    const store = ctx.store orelse return createItemError(ctx);
    const el = elementText(soap, "CalendarItem") orelse return createItemError(ctx);
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
fn createContactItem(ctx: *Context, soap: []const u8) !Response {
    const store = ctx.store orelse return createItemError(ctx);
    const el = elementText(soap, "Contact") orelse return createItemError(ctx);
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

    const save_copy = blk: {
        const v = attrValue(soap, "SaveItemToFolder") orelse break :blk true;
        break :blk std.mem.eql(u8, v, "true");
    };

    var ids = std.ArrayList([]const u8).empty;
    {
        const needle = "ItemId Id=\"";
        var i: usize = 0;
        while (std.mem.indexOfPos(u8, soap, i, needle)) |p| {
            const vs = p + needle.len;
            const ve = std.mem.indexOfScalarPos(u8, soap, vs, '"') orelse break;
            try ids.append(a, soap[vs..ve]);
            i = ve + 1;
        }
    }
    logger.info("EWS SendItem: items={d} save_copy={any}", .{ ids.items.len, save_copy });

    var buf = std.ArrayList(u8).empty;
    try buf.appendSlice(a, "<m:SendItemResponse><m:ResponseMessages>");
    for (ids.items) |id| {
        var ok = true;
        const colon = std.mem.indexOfScalar(u8, id, ':');
        if (colon) |cpos| {
            const folder = id[0..cpos];
            const basename = id[cpos + 1 ..];
            const mailbox = ewsFolderToMailbox(folder);
            if (readMailFile(a, ctx, mailbox, basename)) |found| {
                const split = headerBodySplit(found.content);
                const headers = found.content[0..split.header_end];
                var rcpts = std.ArrayList([]const u8).empty;
                try collectHeaderAddrs(a, headers, "To", &rcpts);
                try collectHeaderAddrs(a, headers, "Cc", &rcpts);
                for (rcpts.items) |rcpt| {
                    outbound.deliverToRemote(ctx.allocator, ctx.username, rcpt, found.content, ctx.hostname, ctx.delivery_method, ctx.ses_region) catch |err| {
                        logger.err("EWS SendItem: delivery to {s} failed: {s}", .{ rcpt, @errorName(err) });
                        ok = false;
                    };
                }
                if (save_copy) {
                    const epoch = time_compat.timestamp();
                    const seq = send_seq.fetchAdd(1, .monotonic);
                    const fname = try std.fmt.allocPrint(a, "{d}.{d}.{s}.eml:2,S", .{ epoch, seq, ctx.hostname });
                    saveToMailbox(a, ctx, "Sent", "cur", fname, found.content) catch {};
                }
            } else {
                logger.err("EWS SendItem: item {s} not found", .{id});
                ok = false;
            }
        } else ok = false;

        if (ok) {
            try buf.appendSlice(a, "<m:SendItemResponseMessage ResponseClass=\"Success\"><m:ResponseCode>NoError</m:ResponseCode></m:SendItemResponseMessage>");
        } else {
            try buf.appendSlice(a, "<m:SendItemResponseMessage ResponseClass=\"Error\"><m:MessageText>Item could not be sent</m:MessageText><m:ResponseCode>ErrorItemNotFound</m:ResponseCode></m:SendItemResponseMessage>");
        }
    }
    if (ids.items.len == 0) {
        try buf.appendSlice(a, "<m:SendItemResponseMessage ResponseClass=\"Success\"><m:ResponseCode>NoError</m:ResponseCode></m:SendItemResponseMessage>");
    }
    try buf.appendSlice(a, "</m:ResponseMessages></m:SendItemResponse>");
    return Response{ .body = try envelope(ctx.allocator, buf.items) };
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
