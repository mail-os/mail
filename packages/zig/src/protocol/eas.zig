const std = @import("std");
const wbxml = @import("wbxml.zig");
const database = @import("../storage/database.zig");
const caldav_store = @import("../storage/caldav_store.zig");
const fs_compat = @import("../core/fs_compat.zig");
const time_compat = @import("../core/time_compat.zig");

/// Exchange ActiveSync command handlers (MS-ASCMD), transport-agnostic.
///
/// Each handler decodes the WBXML request body and produces a WBXML response.
/// The caller (the TLS HTTP front-end) handles HTTP framing, Basic auth, and
/// the query string (`?Cmd=`, `DeviceId=`).
///
/// Data sources:
///   * Email — the Maildir, with a persistent per-(device,collection) item
///     snapshot in SQLite so Add/Change(read flag)/Delete are computed by diff.
///   * Calendar / Contacts — the CalDAV/CardDAV in-memory store, using its
///     sync-token change log for Add/Change/Delete.
///
/// NOTE: the CalDAV store is in-memory and non-persistent (see caldav_store.zig);
/// calendar/contacts items exist only for the current server uptime. That is a
/// storage-layer limitation shared with CalDAV, independent of this protocol code.
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
    /// Maildir directory name for this user (local part of the address).
    local_part: []const u8,
    /// Device identifier from the query string (sync state is keyed on it).
    device_id: []const u8,
};

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
    ensureStateTables(ctx.db) catch {};
    if (std.mem.eql(u8, cmd, "Provision")) return handleProvision(ctx, body);
    if (std.mem.eql(u8, cmd, "FolderSync")) return handleFolderSync(ctx, body);
    if (std.mem.eql(u8, cmd, "Sync")) return handleSync(ctx, body);
    if (std.mem.eql(u8, cmd, "GetItemEstimate")) return handleGetItemEstimate(ctx, body);
    if (std.mem.eql(u8, cmd, "Ping")) return handlePing(ctx, body);
    if (std.mem.eql(u8, cmd, "SendMail")) return Response{ .status = 200 };
    return Response{ .status = 200 };
}

// ============================================================================
// Provision (MS-ASPROV)
// ============================================================================

fn handleProvision(ctx: *Context, body: []const u8) !Response {
    var is_ack = false;
    if (body.len > 0) {
        var root = wbxml.decode(ctx.allocator, body) catch wbxml.Node{ .page = 0xFF, .token = 0xFF };
        defer root.deinit(ctx.allocator);
        if (root.find(wbxml.Page.provision, wbxml.Provision.PolicyKey) != null) is_ack = true;
    }

    var w = wbxml.Writer.init(ctx.allocator);
    errdefer w.deinit();
    try w.writeHeader();

    const P = wbxml.Provision;
    const page = wbxml.Page.provision;

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

// ============================================================================
// Sync (MS-ASCMD §2.2.2.20)
// ============================================================================

fn handleSync(ctx: *Context, body: []const u8) !Response {
    var w = wbxml.Writer.init(ctx.allocator);
    errdefer w.deinit();
    try w.writeHeader();

    const A = wbxml.AirSync;
    const page = wbxml.Page.air_sync;

    try w.startTag(page, A.Synchronize);
    try w.startTag(page, A.Folders);

    if (body.len > 0) {
        var root = try wbxml.decode(ctx.allocator, body);
        defer root.deinit(ctx.allocator);

        if (root.child(page, A.Synchronize)) |sync_root| {
            const folders_node = sync_root.child(page, A.Folders) orelse sync_root;
            for (folders_node.children.items) |*coll| {
                if (coll.token != A.Folder or coll.page != page) continue;
                const collection_id = coll.childText(page, A.FolderId) orelse continue;
                const req_key = coll.childText(page, A.SyncKey) orelse "0";
                const folder = folderById(collection_id) orelse continue;
                if (folder.mailbox) |mailbox| {
                    writeMailCollection(ctx, &w, collection_id, mailbox, req_key) catch {};
                } else {
                    writeDavCollection(ctx, &w, folder, req_key) catch {};
                }
            }
        }
    }

    try w.end(); // Folders
    try w.end(); // Synchronize
    return Response{ .body = try w.toOwnedSlice() };
}

// ---------------------------------------------------------------------------
// Email collection sync (Maildir + SQLite snapshot diff)
// ---------------------------------------------------------------------------

fn writeMailCollection(ctx: *Context, w: *wbxml.Writer, collection_id: []const u8, mailbox: []const u8, req_key: []const u8) !void {
    const A = wbxml.AirSync;
    const page = wbxml.Page.air_sync;

    try w.startTag(page, A.Folder);
    try w.element(page, A.FolderId, collection_id);

    const stored_key = getSyncKey(ctx, collection_id);

    if (std.mem.eql(u8, req_key, "0")) {
        clearItemState(ctx, collection_id) catch {};
        setSyncKey(ctx, collection_id, 1, 0) catch {};
        try w.element(page, A.SyncKey, "1");
        try w.element(page, A.Status, "1");
        try w.end();
        return;
    }
    const req_key_n = std.fmt.parseInt(i64, req_key, 10) catch -1;
    if (req_key_n != stored_key) {
        try w.element(page, A.SyncKey, "0");
        try w.element(page, A.Status, "3");
        try w.end();
        return;
    }

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var items = std.ArrayList(MailItem).empty;
    collectMail(a, ctx, mailbox, &items) catch {};

    // Previous snapshot: server_id -> tag (read flag "0"/"1").
    var snap = std.StringHashMap([]const u8).init(a);
    loadItemState(a, ctx, collection_id, &snap) catch {};

    const Op = struct { kind: u8, server_id: []const u8, item: ?MailItem };
    var ops = std.ArrayList(Op).empty;
    var current = std.StringHashMap(void).init(a);

    for (items.items) |it| {
        const sid = std.fmt.allocPrint(a, "{s}:{d}", .{ collection_id, it.uid }) catch continue;
        current.put(sid, {}) catch {};
        const tag: []const u8 = if (it.seen) "1" else "0";
        if (snap.get(sid)) |old_tag| {
            if (!std.mem.eql(u8, old_tag, tag)) ops.append(a, .{ .kind = A.Modify, .server_id = sid, .item = it }) catch {};
        } else {
            ops.append(a, .{ .kind = A.Add, .server_id = sid, .item = it }) catch {};
        }
    }
    var snap_it = snap.iterator();
    while (snap_it.next()) |e| {
        if (!current.contains(e.key_ptr.*)) {
            ops.append(a, .{ .kind = A.Remove, .server_id = e.key_ptr.*, .item = null }) catch {};
        }
    }

    const total = ops.items.len;
    const emit = @min(total, SYNC_WINDOW);
    const more = total > emit;
    const next_key = stored_key + 1;

    try w.elementInt(page, A.SyncKey, next_key);
    try w.element(page, A.Status, "1");

    if (emit > 0) {
        try w.startTag(page, A.Perform);
        for (ops.items[0..emit]) |op| {
            switch (op.kind) {
                A.Add, A.Modify => {
                    try w.startTag(page, op.kind);
                    try w.element(page, A.ServerEntryId, op.server_id);
                    try w.startTag(page, A.Data);
                    writeMailAppData(a, w, op.item.?) catch {};
                    try w.end(); // Data
                    try w.end(); // Add/Change
                    const tag: []const u8 = if (op.item.?.seen) "1" else "0";
                    upsertItem(ctx, collection_id, op.server_id, tag) catch {};
                },
                A.Remove => {
                    try w.startTag(page, A.Remove);
                    try w.element(page, A.ServerEntryId, op.server_id);
                    try w.end();
                    deleteItem(ctx, collection_id, op.server_id) catch {};
                },
                else => {},
            }
        }
        try w.end(); // Perform
    }
    if (more) try w.emptyTag(page, A.MoreAvailable);

    setSyncKey(ctx, collection_id, next_key, 0) catch {};
    try w.end(); // Folder
}

// ---------------------------------------------------------------------------
// Calendar / Contacts collection sync (CalDAV store change log)
// ---------------------------------------------------------------------------

fn writeDavCollection(ctx: *Context, w: *wbxml.Writer, folder: FolderDef, req_key: []const u8) !void {
    const A = wbxml.AirSync;
    const page = wbxml.Page.air_sync;

    try w.startTag(page, A.Folder);
    try w.element(page, A.FolderId, folder.id);

    const stored_key = getSyncKey(ctx, folder.id);

    if (std.mem.eql(u8, req_key, "0")) {
        setSyncKey(ctx, folder.id, 1, 0) catch {};
        try w.element(page, A.SyncKey, "1");
        try w.element(page, A.Status, "1");
        try w.end();
        return;
    }
    const req_key_n = std.fmt.parseInt(i64, req_key, 10) catch -1;
    if (req_key_n != stored_key) {
        try w.element(page, A.SyncKey, "0");
        try w.element(page, A.Status, "3");
        try w.end();
        return;
    }

    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const store_coll = resolveStoreCollection(ctx, folder.is_calendar) orelse {
        // No backing calendar/addressbook yet — nothing to send. Echo the
        // client's key (do NOT advance) so the next sync still matches.
        try w.element(page, A.SyncKey, req_key);
        try w.element(page, A.Status, "1");
        try w.end();
        return;
    };

    const since = getSyncToken(ctx, folder.id);

    // Build the operations to send. `new_token` is the sync-token baseline to
    // persist once we've sent them.
    const Op = struct { kind: u8, rid: u64 };
    var ops = std.ArrayList(Op).empty;
    var new_token: i64 = since;

    if (since == 0) {
        // First data sync (or the first after a restart, where the in-memory
        // change log is empty but data was loaded from SQLite): enumerate ALL
        // current items as Adds rather than relying on the change log.
        new_token = @intCast(ctx.store.getSyncToken(store_coll, folder.is_calendar));
        if (folder.is_calendar) {
            const events = ctx.store.getCalendarEvents(store_coll) catch &[_]caldav_store.Event{};
            defer ctx.allocator.free(events);
            for (events) |ev| ops.append(a, .{ .kind = A.Add, .rid = ev.id }) catch {};
        } else {
            const contacts = ctx.store.getAddressBookContacts(store_coll) catch &[_]caldav_store.Contact{};
            defer ctx.allocator.free(contacts);
            for (contacts) |ct| ops.append(a, .{ .kind = A.Add, .rid = ct.id }) catch {};
        }
    } else {
        // Incremental: collapse the change log (create+modify -> Add,
        // *+delete -> Delete, create+delete -> skip).
        const report = ctx.store.getChangesSince(store_coll, @intCast(since), folder.is_calendar) catch caldav_store.SyncReport{
            .changes = &.{},
            .new_sync_token = @intCast(since),
            .more_available = false,
        };
        defer ctx.allocator.free(report.changes);
        new_token = @intCast(report.new_sync_token);

        const Agg = struct { has_create: bool, deleted: bool };
        var byId = std.AutoHashMap(u64, Agg).init(a);
        var order = std.ArrayList(u64).empty;
        for (report.changes) |ch| {
            const gop = byId.getOrPut(ch.resource_id) catch continue;
            if (!gop.found_existing) {
                gop.value_ptr.* = .{ .has_create = false, .deleted = false };
                order.append(a, ch.resource_id) catch {};
            }
            switch (ch.change_type) {
                .created => gop.value_ptr.has_create = true,
                .deleted => gop.value_ptr.deleted = true,
                .modified => {},
            }
        }
        for (order.items) |rid| {
            const agg = byId.get(rid).?;
            if (agg.deleted and agg.has_create) continue; // client never saw it
            const kind: u8 = if (agg.deleted) A.Remove else if (agg.has_create) A.Add else A.Modify;
            ops.append(a, .{ .kind = kind, .rid = rid }) catch {};
        }
    }

    // No changes: echo the client's key (don't signal a change). Still persist
    // the advanced token so the next incremental sync has the right baseline.
    if (ops.items.len == 0) {
        if (new_token != since) setSyncKey(ctx, folder.id, stored_key, new_token) catch {};
        try w.element(page, A.SyncKey, req_key);
        try w.element(page, A.Status, "1");
        try w.end();
        return;
    }

    // Changes to send: advance the key and emit the commands.
    const next_key = stored_key + 1;
    try w.elementInt(page, A.SyncKey, next_key);
    try w.element(page, A.Status, "1");
    try w.startTag(page, A.Perform);
    for (ops.items) |op| {
        const sid = std.fmt.allocPrint(a, "{d}", .{op.rid}) catch continue;
        if (op.kind == A.Remove) {
            try w.startTag(page, A.Remove);
            try w.element(page, A.ServerEntryId, sid);
            try w.end();
            continue;
        }
        // Fetch the item before emitting so we can skip cleanly if it vanished.
        if (folder.is_calendar) {
            const ev = ctx.store.getEvent(op.rid) orelse continue;
            try w.startTag(page, op.kind);
            try w.element(page, A.ServerEntryId, sid);
            try w.startTag(page, A.Data);
            writeEventAppData(a, w, ev) catch {};
            try w.end(); // Data
            try w.end(); // Add/Change
        } else {
            const ct = ctx.store.getContact(op.rid) orelse continue;
            try w.startTag(page, op.kind);
            try w.element(page, A.ServerEntryId, sid);
            try w.startTag(page, A.Data);
            writeContactAppData(a, w, ctx, ct) catch {};
            try w.end(); // Data
            try w.end(); // Add/Change
        }
    }
    try w.end(); // Perform

    setSyncKey(ctx, folder.id, next_key, new_token) catch {};
    try w.end(); // Folder
}

/// Resolve the EAS Calendar/Contacts folder to the user's first store
/// collection id, or null if the user has none.
fn resolveStoreCollection(ctx: *Context, is_calendar: bool) ?u64 {
    const user_id = ctx.store.getOrCreateUserId(ctx.username) catch return null;
    if (is_calendar) {
        const cals = ctx.store.getUserCalendars(user_id) catch return null;
        defer ctx.allocator.free(cals);
        if (cals.len == 0) return null;
        return cals[0].id;
    } else {
        const abs = ctx.store.getUserAddressBooks(user_id) catch return null;
        defer ctx.allocator.free(abs);
        if (abs.len == 0) return null;
        return abs[0].id;
    }
}

// ============================================================================
// GetItemEstimate / Ping
// ============================================================================

fn handleGetItemEstimate(ctx: *Context, body: []const u8) !Response {
    var w = wbxml.Writer.init(ctx.allocator);
    errdefer w.deinit();
    try w.writeHeader();

    const G = wbxml.GetItemEstimate;
    const page = wbxml.Page.get_item_estimate;

    var collection_id: []const u8 = "1";
    if (body.len > 0) {
        var root = wbxml.decode(ctx.allocator, body) catch wbxml.Node{ .page = 0xFF, .token = 0xFF };
        defer root.deinit(ctx.allocator);
        if (root.find(page, G.FolderId)) |f| {
            if (f.text) |t| collection_id = t;
        }
    }

    try w.startTag(page, G.GetItemEstimate);
    try w.startTag(page, G.Response);
    try w.element(page, G.Status, "1");
    try w.startTag(page, G.Folder);
    try w.element(page, G.FolderId, collection_id);
    try w.elementInt(page, G.Estimate, estimatePending(ctx, collection_id));
    try w.end();
    try w.end();
    try w.end();

    return Response{ .body = try w.toOwnedSlice() };
}

/// Count of pending changes for the collection (best-effort hint for the client).
fn estimatePending(ctx: *Context, collection_id: []const u8) i64 {
    const folder = folderById(collection_id) orelse return 0;
    if (folder.mailbox) |mailbox| {
        var arena = std.heap.ArenaAllocator.init(ctx.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        return @intCast(mailChangeCount(a, ctx, collection_id, mailbox));
    }
    const store_coll = resolveStoreCollection(ctx, folder.is_calendar) orelse return 0;
    const since = getSyncToken(ctx, collection_id);
    const report = ctx.store.getChangesSince(store_coll, @intCast(since), folder.is_calendar) catch return 0;
    defer ctx.allocator.free(report.changes);
    return @intCast(report.changes.len);
}

fn handlePing(ctx: *Context, body: []const u8) !Response {
    var arena = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var heartbeat: u64 = PING_MAX_HEARTBEAT_S;
    var folder_ids = std.ArrayList([]const u8).empty;

    if (body.len > 0) {
        var root = wbxml.decode(ctx.allocator, body) catch wbxml.Node{ .page = 0xFF, .token = 0xFF };
        defer root.deinit(ctx.allocator);
        if (root.find(wbxml.Page.ping, wbxml.Ping.LifeTime)) |lt| {
            if (lt.text) |t| heartbeat = std.fmt.parseInt(u64, t, 10) catch PING_MAX_HEARTBEAT_S;
        }
        // Collect monitored folder ids (dupe into arena: source tree is freed here).
        if (root.find(wbxml.Page.ping, wbxml.Ping.Folders)) |folders| {
            for (folders.children.items) |*f| {
                if (f.token != wbxml.Ping.Folder or f.page != wbxml.Page.ping) continue;
                if (f.childText(wbxml.Page.ping, wbxml.Ping.ServerEntryId)) |id| {
                    folder_ids.append(a, a.dupe(u8, id) catch continue) catch {};
                }
            }
        }
    }
    if (heartbeat > PING_MAX_HEARTBEAT_S) heartbeat = PING_MAX_HEARTBEAT_S;
    if (heartbeat < PING_INTERVAL_S) heartbeat = PING_INTERVAL_S;

    var changed = std.ArrayList([]const u8).empty;
    const iterations = heartbeat / PING_INTERVAL_S;
    var i: u64 = 0;
    while (i < iterations) : (i += 1) {
        for (folder_ids.items) |fid| {
            if (collectionHasChanges(ctx, fid)) changed.append(a, fid) catch {};
        }
        if (changed.items.len > 0) break;
        time_compat.sleep(PING_INTERVAL_S * std.time.ns_per_s);
    }

    var w = wbxml.Writer.init(ctx.allocator);
    errdefer w.deinit();
    try w.writeHeader();
    const Pg = wbxml.Ping;
    const page = wbxml.Page.ping;
    try w.startTag(page, Pg.Ping);
    if (changed.items.len > 0) {
        // Status 2: changes detected in the listed folders.
        try w.element(page, Pg.Status, "2");
        try w.startTag(page, Pg.Folders);
        for (changed.items) |fid| try w.element(page, Pg.Folder, fid);
        try w.end();
    } else {
        // Status 1: heartbeat expired with no changes.
        try w.element(page, Pg.Status, "1");
    }
    try w.end();
    return Response{ .body = try w.toOwnedSlice() };
}

/// Read-only check: does the collection have unsynced changes right now?
fn collectionHasChanges(ctx: *Context, collection_id: []const u8) bool {
    const folder = folderById(collection_id) orelse return false;
    if (folder.mailbox) |mailbox| {
        var arena = std.heap.ArenaAllocator.init(ctx.allocator);
        defer arena.deinit();
        return mailChangeCount(arena.allocator(), ctx, collection_id, mailbox) > 0;
    }
    const store_coll = resolveStoreCollection(ctx, folder.is_calendar) orelse return false;
    const since = getSyncToken(ctx, collection_id);
    return ctx.store.getSyncToken(store_coll, folder.is_calendar) > @as(u64, @intCast(since));
}

/// Number of email Add+Change+Delete pending versus the stored snapshot.
fn mailChangeCount(a: std.mem.Allocator, ctx: *Context, collection_id: []const u8, mailbox: []const u8) usize {
    var items = std.ArrayList(MailItem).empty;
    collectMail(a, ctx, mailbox, &items) catch return 0;
    var snap = std.StringHashMap([]const u8).init(a);
    loadItemState(a, ctx, collection_id, &snap) catch return 0;

    var current = std.StringHashMap(void).init(a);
    var count: usize = 0;
    for (items.items) |it| {
        const sid = std.fmt.allocPrint(a, "{s}:{d}", .{ collection_id, it.uid }) catch continue;
        current.put(sid, {}) catch {};
        const tag: []const u8 = if (it.seen) "1" else "0";
        if (snap.get(sid)) |old| {
            if (!std.mem.eql(u8, old, tag)) count += 1;
        } else count += 1;
    }
    var it = snap.iterator();
    while (it.next()) |e| {
        if (!current.contains(e.key_ptr.*)) count += 1;
    }
    return count;
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

fn collectMail(a: std.mem.Allocator, ctx: *Context, mailbox: []const u8, out: *std.ArrayList(MailItem)) !void {
    if (std.mem.eql(u8, mailbox, "INBOX")) {
        try collectDir(a, ctx, mailbox, try std.fmt.allocPrint(a, "mail/{s}/new", .{ctx.local_part}), out);
        try collectDir(a, ctx, mailbox, try std.fmt.allocPrint(a, "mail/{s}/cur", .{ctx.local_part}), out);
    } else {
        const base = try std.fmt.allocPrint(a, "mail/{s}/{s}", .{ ctx.local_part, mailbox });
        try collectDir(a, ctx, mailbox, try std.fmt.allocPrint(a, "{s}/new", .{base}), out);
        try collectDir(a, ctx, mailbox, try std.fmt.allocPrint(a, "{s}/cur", .{base}), out);
    }
}

fn collectDir(a: std.mem.Allocator, ctx: *Context, mailbox: []const u8, dir_path: []const u8, out: *std.ArrayList(MailItem)) !void {
    const files = fs_compat.listEmlFiles(a, dir_path) catch return;
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
    return std.fmt.parseInt(i64, base[0..end], 10) catch 0;
}

// ============================================================================
// WBXML item serialisation
// ============================================================================

fn writeMailAppData(a: std.mem.Allocator, w: *wbxml.Writer, it: MailItem) !void {
    const E = wbxml.Email;
    const B = wbxml.AirSyncBase;

    const raw: []const u8 = fs_compat.readFileAlloc(a, it.path) catch "";
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

fn writeEventAppData(a: std.mem.Allocator, w: *wbxml.Writer, ev: caldav_store.Event) !void {
    const C = wbxml.Calendar;
    const B = wbxml.AirSyncBase;
    const page = wbxml.Page.calendar;

    try w.element(page, C.UID, ev.uid);
    try w.element(page, C.Subject, ev.summary);
    if (ev.location) |loc| try w.element(page, C.Location, loc);
    try w.element(page, C.StartTime, compactFromEpoch(a, ev.dtstart));
    try w.element(page, C.EndTime, compactFromEpoch(a, ev.dtend orelse (ev.dtstart + 3600)));
    try w.element(page, C.DtStamp, compactFromEpoch(a, ev.modified_at));
    try w.element(page, C.AllDayEvent, if (ev.all_day) "1" else "0");
    try w.element(page, C.BusyStatus, "2"); // busy
    try w.element(page, C.Sensitivity, "0"); // normal
    try w.element(page, C.MeetingStatus, "0"); // not a meeting
    if (ev.organizer) |org| {
        try w.element(page, C.OrganizerEmail, org);
        try w.element(page, C.OrganizerName, org);
    }
    if (ev.description) |desc| {
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

fn writeContactAppData(a: std.mem.Allocator, w: *wbxml.Writer, ctx: *Context, c: caldav_store.Contact) !void {
    const K = wbxml.Contacts;
    const B = wbxml.AirSyncBase;
    const page = wbxml.Page.contacts;

    if (c.given_name) |v| try w.element(page, K.FirstName, v);
    if (c.family_name) |v| try w.element(page, K.LastName, v);
    try w.element(page, K.FileAs, c.full_name);
    if (c.organization) |v| try w.element(page, K.CompanyName, v);
    if (c.title) |v| try w.element(page, K.JobTitle, v);

    const emails = ctx.store.getContactEmails(c.id);
    defer ctx.allocator.free(emails);
    if (emails.len > 0) try w.element(page, K.Email1Address, emails[0].email);
    if (emails.len > 1) try w.element(page, K.Email2Address, emails[1].email);
    if (emails.len > 2) try w.element(page, K.Email3Address, emails[2].email);

    const phones = ctx.store.getContactPhones(c.id);
    defer ctx.allocator.free(phones);
    for (phones) |ph| {
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
    _ = a;
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

// ============================================================================
// Per-device sync + item state (SQLite)
// ============================================================================

fn ensureStateTables(db: *database.Database) !void {
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS eas_sync_state (
        \\  device_id TEXT NOT NULL,
        \\  collection_id TEXT NOT NULL,
        \\  sync_key INTEGER NOT NULL DEFAULT 0,
        \\  token INTEGER NOT NULL DEFAULT 0,
        \\  PRIMARY KEY (device_id, collection_id)
        \\);
    );
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS eas_item_state (
        \\  device_id TEXT NOT NULL,
        \\  collection_id TEXT NOT NULL,
        \\  server_id TEXT NOT NULL,
        \\  tag TEXT NOT NULL,
        \\  PRIMARY KEY (device_id, collection_id, server_id)
        \\);
    );
}

fn getSyncKey(ctx: *Context, collection_id: []const u8) i64 {
    var stmt = ctx.db.prepare(
        "SELECT sync_key FROM eas_sync_state WHERE device_id = ?1 AND collection_id = ?2",
    ) catch return 0;
    defer stmt.finalize();
    stmt.bind(1, ctx.device_id) catch return 0;
    stmt.bind(2, collection_id) catch return 0;
    if (stmt.step() catch false) return stmt.columnInt64(0);
    return 0;
}

fn getSyncToken(ctx: *Context, collection_id: []const u8) i64 {
    var stmt = ctx.db.prepare(
        "SELECT token FROM eas_sync_state WHERE device_id = ?1 AND collection_id = ?2",
    ) catch return 0;
    defer stmt.finalize();
    stmt.bind(1, ctx.device_id) catch return 0;
    stmt.bind(2, collection_id) catch return 0;
    if (stmt.step() catch false) return stmt.columnInt64(0);
    return 0;
}

fn setSyncKey(ctx: *Context, collection_id: []const u8, sync_key: i64, token: i64) !void {
    var stmt = try ctx.db.prepare(
        \\INSERT INTO eas_sync_state (device_id, collection_id, sync_key, token)
        \\VALUES (?1, ?2, ?3, ?4)
        \\ON CONFLICT(device_id, collection_id) DO UPDATE SET sync_key = ?3, token = ?4
    );
    defer stmt.finalize();
    try stmt.bind(1, ctx.device_id);
    try stmt.bind(2, collection_id);
    try stmt.bind(3, sync_key);
    try stmt.bind(4, token);
    _ = try stmt.step();
}

fn loadItemState(a: std.mem.Allocator, ctx: *Context, collection_id: []const u8, out: *std.StringHashMap([]const u8)) !void {
    var stmt = try ctx.db.prepare(
        "SELECT server_id, tag FROM eas_item_state WHERE device_id = ?1 AND collection_id = ?2",
    );
    defer stmt.finalize();
    try stmt.bind(1, ctx.device_id);
    try stmt.bind(2, collection_id);
    while (stmt.step() catch false) {
        const sid = try a.dupe(u8, stmt.columnText(0));
        const tag = try a.dupe(u8, stmt.columnText(1));
        try out.put(sid, tag);
    }
}

fn upsertItem(ctx: *Context, collection_id: []const u8, server_id: []const u8, tag: []const u8) !void {
    var stmt = try ctx.db.prepare(
        \\INSERT INTO eas_item_state (device_id, collection_id, server_id, tag)
        \\VALUES (?1, ?2, ?3, ?4)
        \\ON CONFLICT(device_id, collection_id, server_id) DO UPDATE SET tag = ?4
    );
    defer stmt.finalize();
    try stmt.bind(1, ctx.device_id);
    try stmt.bind(2, collection_id);
    try stmt.bind(3, server_id);
    try stmt.bind(4, tag);
    _ = try stmt.step();
}

fn deleteItem(ctx: *Context, collection_id: []const u8, server_id: []const u8) !void {
    var stmt = try ctx.db.prepare(
        "DELETE FROM eas_item_state WHERE device_id = ?1 AND collection_id = ?2 AND server_id = ?3",
    );
    defer stmt.finalize();
    try stmt.bind(1, ctx.device_id);
    try stmt.bind(2, collection_id);
    try stmt.bind(3, server_id);
    _ = try stmt.step();
}

fn clearItemState(ctx: *Context, collection_id: []const u8) !void {
    var stmt = try ctx.db.prepare(
        "DELETE FROM eas_item_state WHERE device_id = ?1 AND collection_id = ?2",
    );
    defer stmt.finalize();
    try stmt.bind(1, ctx.device_id);
    try stmt.bind(2, collection_id);
    _ = try stmt.step();
}

// ============================================================================
// Tests
// ============================================================================

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
