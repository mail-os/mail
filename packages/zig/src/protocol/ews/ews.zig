const std = @import("std");
const logger = @import("../../core/logger.zig");

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
    /// Public hostname (for self-referential URLs).
    hostname: []const u8,
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

/// The folders advertised to clients.
const FolderDef = struct {
    /// EWS distinguished folder id (lowercase) used in GetFolder requests.
    dist: []const u8,
    /// Opaque-but-stable folder id we hand back.
    id: []const u8,
    name: []const u8,
    /// EWS element + class: .mail -> <t:Folder> IPF.Note, .calendar ->
    /// <t:CalendarFolder> IPF.Appointment, .contacts -> <t:ContactsFolder>.
    kind: enum { mail, calendar, contacts },
};

const FOLDERS = [_]FolderDef{
    .{ .dist = "inbox", .id = "f-inbox", .name = "Inbox", .kind = .mail },
    .{ .dist = "drafts", .id = "f-drafts", .name = "Drafts", .kind = .mail },
    .{ .dist = "sentitems", .id = "f-sent", .name = "Sent Items", .kind = .mail },
    .{ .dist = "deleteditems", .id = "f-trash", .name = "Deleted Items", .kind = .mail },
    .{ .dist = "calendar", .id = "f-calendar", .name = "Calendar", .kind = .calendar },
    .{ .dist = "contacts", .id = "f-contacts", .name = "Contacts", .kind = .contacts },
};

const ROOT_ID = "f-root";

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

fn syncFolderItems(ctx: *Context, soap: []const u8) !Response {
    _ = soap;
    // No items yet — report an empty, completed range so the client moves on.
    const inner =
        \\<m:SyncFolderItemsResponse><m:ResponseMessages><m:SyncFolderItemsResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:SyncState>SYNCSTATE1</m:SyncState><m:IncludesLastItemInRange>true</m:IncludesLastItemInRange><m:Changes/></m:SyncFolderItemsResponseMessage></m:ResponseMessages></m:SyncFolderItemsResponse>
    ;
    return Response{ .body = try envelope(ctx.allocator, inner) };
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
