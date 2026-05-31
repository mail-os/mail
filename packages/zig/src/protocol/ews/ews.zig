const std = @import("std");
const logger = @import("../../core/logger.zig");
// NOTE: for a future standalone `zig-ews`, reach the mailbox/store through a
// callback interface on Context instead of importing these directly.
const database = @import("../../storage/database.zig");
const fs_compat = @import("../../core/fs_compat.zig");

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
    if (std.mem.eql(u8, op, "FindFolder")) return findFolder(ctx, soap);
    if (std.mem.eql(u8, op, "FindItem")) return emptyFindItem(ctx);
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
            if (folder.mailbox) |mailbox| {
                var arena = std.heap.ArenaAllocator.init(a);
                defer arena.deinit();
                const aa = arena.allocator();
                var items = std.ArrayList(MailItem).empty;
                collectMail(aa, ctx, mailbox, &items) catch {};
                for (items.items) |it| {
                    const id = std.fmt.allocPrint(aa, "{s}:{s}", .{ folder_id, it.basename }) catch continue;
                    try buf.print(a,
                        \\<t:Create><t:Message><t:ItemId Id="{s}" ChangeKey="ck0"/></t:Message></t:Create>
                    , .{id});
                }
            }
        }
    }

    try buf.appendSlice(a, "</m:Changes></m:SyncFolderItemsResponseMessage></m:ResponseMessages></m:SyncFolderItemsResponse>");
    return Response{ .body = try envelope(ctx.allocator, buf.items) };
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
    const basename = id[colon + 1 ..];
    const folder = folderById(folder_id) orelse return error.BadId;
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

fn emptyFindItem(ctx: *Context) !Response {
    const inner =
        \\<m:FindItemResponse><m:ResponseMessages><m:FindItemResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:RootFolder TotalItemsInView="0" IncludesLastItemInRange="true"><t:Items/></m:RootFolder></m:FindItemResponseMessage></m:ResponseMessages></m:FindItemResponse>
    ;
    return Response{ .body = try envelope(ctx.allocator, inner) };
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
