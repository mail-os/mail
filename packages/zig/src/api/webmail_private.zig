//! Account-local notebook and conversation grouping. Wire content and message
//! references retain their existing meaning in all other mail protocols.
const std = @import("std");
const database = @import("../storage/database.zig");
const time = @import("../core/time_compat.zig");
const maildir = @import("webmail_maildir.zig");
const Graph = @import("webmail_threads.zig").Graph;
const thread_ids = @import("../message/thread_ids.zig");

const Allocator = std.mem.Allocator;
const Database = database.Database;
const owner = "user_id=(SELECT id FROM users WHERE username=?1)";

pub const Label = struct {
    value: []const u8 = "",
    revision: []const u8 = "",
    changed_ms: i64 = 0,
};

const Anchor = struct {
    reference: []const u8,
    keys: []const []const u8,
    location: ?maildir.SummaryLocation,
    label: Label,
};

const Group = struct { id: []const u8, anchors: []const []const u8 };
pub const Collection = struct { id: []const u8, name: []const u8, revision: i64, included: bool, explicit: bool, shared: bool };
pub const EntryKind = enum { note, clip };
pub const Entry = struct {
    id: []const u8,
    kind: EntryKind,
    body: []const u8,
    source_subject: []const u8,
    created_at: i64,
    revision: i64,
};

pub const MessageTools = struct {
    label: Label,
    entries: []const Entry,
    collections: []const Collection,
    clip_source: []const u8,
};

pub const Context = struct {
    label: Label,
    natural_wire: []const []const u8,
    natural_anchors: []const u8,
    conversation_anchors: []const u8,
};

const Snapshot = struct {
    anchors: []Anchor,
    groups: []Group,
};

fn load(a: Allocator, db: *Database, user: []const u8) !Snapshot {
    var anchors: std.ArrayList(Anchor) = .empty;
    {
        const stmt = try db.prepare(
            \\SELECT a.reference,a.wire_ids,r.folder,r.basename,r.file_stamp,l.label,l.revision,l.changed_ms
            \\FROM mail_private_anchors a
            \\LEFT JOIN mailbox_message_refs r USING(user_id,reference)
            \\LEFT JOIN mail_private_labels l ON l.user_id=a.user_id AND l.anchor=a.reference
            \\WHERE a.user_id=(SELECT id FROM users WHERE username=?1)
        );
        defer stmt.finalize();
        try stmt.bind(1, user);
        while (try stmt.step()) {
            try anchors.append(a, .{
                .reference = try a.dupe(u8, stmt.columnText(0)),
                .keys = try std.json.parseFromSliceLeaky([]const []const u8, a, stmt.columnText(1), .{ .allocate = .alloc_always }),
                .location = if (stmt.columnIsNull(2)) null else .{
                    .folder = try a.dupe(u8, stmt.columnText(2)),
                    .basename = try a.dupe(u8, stmt.columnText(3)),
                    .stamp = try a.dupe(u8, stmt.columnText(4)),
                },
                .label = .{
                    .value = try a.dupe(u8, stmt.columnText(5)),
                    .revision = try a.dupe(u8, stmt.columnText(6)),
                    .changed_ms = stmt.columnInt64(7),
                },
            });
        }
    }
    var groups: std.ArrayList(Group) = .empty;
    {
        const stmt = try db.prepare("SELECT id,anchors FROM mail_private_groups WHERE " ++ owner ++ " ORDER BY id");
        defer stmt.finalize();
        try stmt.bind(1, user);
        while (try stmt.step()) {
            try groups.append(a, .{
                .id = try a.dupe(u8, stmt.columnText(0)),
                .anchors = try std.json.parseFromSliceLeaky([]const []const u8, a, stmt.columnText(1), .{ .allocate = .alloc_always }),
            });
        }
    }
    return .{ .anchors = try anchors.toOwnedSlice(a), .groups = try groups.toOwnedSlice(a) };
}

fn connectKeys(graph: *Graph, node: usize, keys: []const []const u8) !void {
    for (keys) |key| graph.join(node, try graph.node(key));
}

fn connectAnchors(graph: *Graph, snapshot: Snapshot, live_links: []const []const []const u8) !void {
    for (snapshot.anchors) |anchor| {
        const node = try graph.node(anchor.reference);
        try connectKeys(graph, node, anchor.keys);
    }
    for (live_links) |link| try connectKeys(graph, try graph.node(link[0]), link[1..]);
}

fn connectGroups(graph: *Graph, snapshot: Snapshot) !void {
    for (snapshot.groups) |group| {
        const marker = try std.fmt.allocPrint(graph.allocator, "private:{s}", .{group.id});
        const node = try graph.node(marker);
        try connectKeys(graph, node, group.anchors);
    }
}

fn laterLabel(left: Label, right: Label) bool {
    if (left.changed_ms != right.changed_ms) return left.changed_ms > right.changed_ms;
    return std.mem.order(u8, left.revision, right.revision) == .gt;
}

fn matchingAnchors(a: Allocator, graph: *Graph, snapshot: Snapshot, node: usize, reference: []const u8) ![]const []const u8 {
    var refs: std.ArrayList([]const u8) = .empty;
    try refs.append(a, reference);
    const root = graph.root(node);
    for (snapshot.anchors) |anchor| {
        if (!std.mem.eql(u8, anchor.reference, reference) and graph.root(graph.ids.get(anchor.reference).?) == root)
            try refs.append(a, anchor.reference);
    }
    return refs.toOwnedSlice(a);
}

fn naturalWire(a: Allocator, graph: *Graph, root: usize) ![]const []const u8 {
    var wire: std.ArrayList([]const u8) = .empty;
    for (graph.names.items, 0..) |name, index| {
        if (name[0] == '<' and graph.root(index) == root) try wire.append(a, name);
    }
    return wire.toOwnedSlice(a);
}

pub fn hasAnchors(db: *Database, user: []const u8) !bool {
    const stmt = try db.prepare("SELECT 1 FROM mail_private_anchors WHERE " ++ owner ++ " LIMIT 1");
    defer stmt.finalize();
    try stmt.bind(1, user);
    return stmt.step();
}

pub fn context(a: Allocator, db: *Database, user: []const u8, reference: []const u8, keys: []const []const u8, live_links: []const []const []const u8) !Context {
    const snapshot = try load(a, db, user);
    var graph = Graph.init(a);
    defer graph.deinit();
    try connectAnchors(&graph, snapshot, live_links);
    const node = try graph.node(reference);
    try connectKeys(&graph, node, keys);
    const natural_anchors = try matchingAnchors(a, &graph, snapshot, node, reference);
    var label: Label = .{};
    const root = graph.root(node);
    for (snapshot.anchors) |anchor| {
        if (graph.root(graph.ids.get(anchor.reference).?) == root and laterLabel(anchor.label, label)) label = anchor.label;
    }
    const wire = try naturalWire(a, &graph, root);
    try connectGroups(&graph, snapshot);
    return .{
        .label = label,
        .natural_wire = wire,
        .natural_anchors = try std.json.Stringify.valueAlloc(a, natural_anchors, .{}),
        .conversation_anchors = try std.json.Stringify.valueAlloc(a, try matchingAnchors(a, &graph, snapshot, node, reference), .{}),
    };
}

const LocationContext = struct {
    pub fn hash(_: LocationContext, key: maildir.SummaryLocation) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(key.folder);
        hasher.update(key.basename);
        hasher.update(key.stamp);
        return hasher.final();
    }

    pub fn eql(_: LocationContext, a: maildir.SummaryLocation, b: maildir.SummaryLocation) bool {
        return std.mem.eql(u8, a.folder, b.folder) and std.mem.eql(u8, a.basename, b.basename) and std.mem.eql(u8, a.stamp, b.stamp);
    }
};

/// Apply only to an authenticated personal mailbox list. Collection filters
/// are evaluated against live visible rows before counting and pagination.
pub fn decorate(a: Allocator, db: *Database, user: []const u8, rows: []maildir.MessageSummary, collection: ?[]const u8) ![]maildir.MessageSummary {
    var member_ids: std.ArrayList([]const u8) = .empty;
    const snapshot = snapshot: {
        db.lockMailboxes();
        defer db.unlockMailboxes();
        if (collection) |id| {
            if (!try hasCollection(db, user, id)) return error.NotFound;
            const members = try db.prepare("SELECT anchor FROM mail_private_members WHERE " ++ owner ++ " AND collection=?2");
            defer members.finalize();
            try members.bind(1, user);
            try members.bind(2, id);
            while (try members.step()) try member_ids.append(a, try a.dupe(u8, members.columnText(0)));
        }
        break :snapshot try load(a, db, user);
    };
    if (snapshot.anchors.len == 0) return if (collection != null) rows[0..0] else rows;
    var graph = Graph.init(a);
    defer graph.deinit();
    const live_links = if (collection != null and member_ids.items.len > 0) try maildir.conversationLinks(a, db, user) else &.{};
    try connectAnchors(&graph, snapshot, live_links);
    var locations = std.HashMap(maildir.SummaryLocation, []const u8, LocationContext, 80).init(a);
    defer locations.deinit();
    for (snapshot.anchors) |anchor| if (anchor.location) |location| {
        try locations.put(location, anchor.reference);
    };
    const nodes = try a.alloc(usize, rows.len);
    defer a.free(nodes);
    for (rows, nodes, 0..) |row, *node, index| {
        const visible = maildir.isPersonalFolder(row.folder);
        const location = if (visible) maildir.summaryLocation(row) else null;
        const reference = if (location) |at| locations.get(at) else null;
        node.* = try graph.node(reference orelse try std.fmt.allocPrint(a, "row:{d}", .{index}));
        if (!visible) continue;
        try graph.references(node.*, row.message_id);
        try graph.references(node.*, row.in_reply_to);
        try graph.references(node.*, row.references);
    }
    var labels = std.AutoHashMap(usize, Label).init(a);
    defer labels.deinit();
    for (snapshot.anchors) |anchor| {
        if (anchor.label.value.len == 0) continue;
        const root = graph.root(graph.ids.get(anchor.reference).?);
        const slot = try labels.getOrPut(root);
        if (!slot.found_existing or laterLabel(anchor.label, slot.value_ptr.*)) slot.value_ptr.* = anchor.label;
    }
    for (rows, nodes) |*row, node| {
        if (labels.get(graph.root(node))) |label| row.personal_subject = label.value;
    }

    try connectGroups(&graph, snapshot);
    var manual = std.AutoHashMap(usize, []const u8).init(a);
    defer manual.deinit();
    for (snapshot.groups) |group| {
        const marker = try std.fmt.allocPrint(a, "private:{s}", .{group.id});
        const slot = try manual.getOrPut(graph.root(graph.ids.get(marker).?));
        if (!slot.found_existing) slot.value_ptr.* = marker;
    }
    for (rows, nodes) |*row, node| row.manual_component = manual.get(graph.root(node));

    if (collection == null) return rows;
    var roots = std.AutoHashMap(usize, void).init(a);
    defer roots.deinit();
    for (member_ids.items) |id| {
        if (graph.ids.get(id)) |node| try roots.put(graph.root(node), {});
    }
    var kept: usize = 0;
    for (rows, nodes) |row, node| {
        if (!roots.contains(graph.root(node))) continue;
        rows[kept] = row;
        kept += 1;
    }
    return rows[0..kept];
}

pub fn listCollections(a: Allocator, db: *Database, user: []const u8, anchors: []const u8, reference: ?[]const u8) ![]Collection {
    const stmt = try db.prepare(
        \\SELECT c.id,c.name,c.revision,EXISTS(SELECT 1 FROM mail_private_members m WHERE m.user_id=c.user_id
        \\  AND m.collection=c.id AND m.anchor IN (SELECT value FROM json_each(?2))),
        \\EXISTS(SELECT 1 FROM mail_private_members m WHERE m.user_id=c.user_id AND m.collection=c.id AND m.anchor=?3),
        \\EXISTS(SELECT 1 FROM mail_team_collection_shares s WHERE s.owner_id=c.user_id AND s.collection_id=c.id)
        \\FROM mail_private_collections c WHERE c.user_id=(SELECT id FROM users WHERE username=?1)
        \\ORDER BY c.name,c.id
    );
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bind(2, anchors);
    try stmt.bindOpt(3, reference);
    var out: std.ArrayList(Collection) = .empty;
    while (try stmt.step()) try out.append(a, .{
        .id = try a.dupe(u8, stmt.columnText(0)),
        .name = try a.dupe(u8, stmt.columnText(1)),
        .revision = stmt.columnInt64(2),
        .included = stmt.columnInt64(3) != 0,
        .explicit = stmt.columnInt64(4) != 0,
        .shared = stmt.columnInt64(5) != 0,
    });
    return out.toOwnedSlice(a);
}

pub fn hasCollection(db: *Database, user: []const u8, id: []const u8) !bool {
    const stmt = try db.prepare("SELECT 1 FROM mail_private_collections WHERE " ++ owner ++ " AND id=?2");
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bind(2, id);
    return stmt.step();
}

pub fn tools(a: Allocator, db: *Database, user: []const u8, reference: []const u8, current: Context, clip_source: []const u8) !MessageTools {
    var entries: std.ArrayList(Entry) = .empty;
    {
        const stmt = try db.prepare(
            "SELECT id,kind,body,source_subject,created_at,revision FROM mail_private_entries WHERE " ++ owner ++
                " AND anchor IN (SELECT value FROM json_each(?2)) ORDER BY created_at DESC,rowid DESC",
        );
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, current.conversation_anchors);
        while (try stmt.step()) try entries.append(a, .{
            .id = try a.dupe(u8, stmt.columnText(0)),
            .kind = std.meta.stringToEnum(EntryKind, stmt.columnText(1)) orelse continue,
            .body = try a.dupe(u8, stmt.columnText(2)),
            .source_subject = try a.dupe(u8, stmt.columnText(3)),
            .created_at = stmt.columnInt64(4),
            .revision = stmt.columnInt64(5),
        });
    }
    return .{
        .label = current.label,
        .entries = try entries.toOwnedSlice(a),
        .collections = try listCollections(a, db, user, current.conversation_anchors, reference),
        .clip_source = clip_source,
    };
}

pub const Target = struct { reference: []const u8, revision: []const u8 };

pub fn resolve(a: Allocator, db: *Database, user: []const u8, reference: []const u8, expected: ?[]const u8) !maildir.VersionedFile {
    const file = try maildir.resolveVersioned(a, db, user, reference);
    if (!maildir.isPersonalFolder(file.locator.folder)) return error.NotFound;
    if (expected) |revision| {
        if (!std.mem.eql(u8, file.version.revision, revision)) return error.RevisionMismatch;
    }
    return file;
}

pub fn wireKeys(a: Allocator, file: maildir.VersionedFile) ![]const []const u8 {
    const headers = try thread_ids.parse(a, file.raw);
    return headers.keys(a);
}

pub fn remember(a: Allocator, db: *Database, user: []const u8, reference: []const u8, wire: []const []const u8) !void {
    const stmt = try db.prepare(
        \\INSERT INTO mail_private_anchors(user_id,reference,wire_ids)
        \\SELECT id,?2,?3 FROM users WHERE username=?1
        \\ON CONFLICT(user_id,reference) DO UPDATE SET wire_ids=excluded.wire_ids WHERE wire_ids<>excluded.wire_ids
    );
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bind(2, reference);
    try stmt.bind(3, try std.json.Stringify.valueAlloc(a, wire, .{}));
    _ = try stmt.step();
}

pub fn addEntry(db: *Database, user: []const u8, reference: []const u8, kind: EntryKind, body: []const u8, subject: []const u8) !void {
    const stmt = try db.prepare(
        \\INSERT INTO mail_private_entries(user_id,anchor,kind,body,source_subject)
        \\SELECT id,?2,?3,?4,?5 FROM users WHERE username=?1
    );
    defer stmt.finalize();
    for ([_][]const u8{ user, reference, @tagName(kind), body, subject }, 1..) |arg, pos| try stmt.bind(pos, arg);
    _ = try stmt.step();
}

pub fn changeEntry(db: *Database, user: []const u8, current: Context, id: []const u8, revision: i64, body: ?[]const u8) !void {
    const filter = " WHERE " ++ owner ++ " AND id=?2 AND revision=?3 AND anchor IN (SELECT value FROM json_each(?4))";
    const stmt = try db.prepare(if (body != null)
        "UPDATE mail_private_entries SET body=?5,revision=revision+1" ++ filter ++ " AND kind='note' RETURNING id"
    else
        "DELETE FROM mail_private_entries" ++ filter ++ " RETURNING id");
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bind(2, id);
    try stmt.bind(3, revision);
    try stmt.bind(4, current.conversation_anchors);
    if (body) |text| try stmt.bind(5, text);
    if (!try stmt.step()) return error.RevisionMismatch;
    _ = try stmt.step();
}

pub fn setLabel(db: *Database, user: []const u8, reference: []const u8, current: Context, label: []const u8, expected: []const u8) !void {
    if (!std.mem.eql(u8, current.label.revision, expected)) return error.RevisionMismatch;
    const stmt = try db.prepare(if (label.len == 0)
        "DELETE FROM mail_private_labels WHERE " ++ owner ++ " AND anchor IN (SELECT value FROM json_each(?2))"
    else
        \\INSERT INTO mail_private_labels(user_id,anchor,label,revision,changed_ms)
        \\SELECT id,?2,?3,lower(hex(randomblob(16))),?4 FROM users WHERE username=?1
        \\ON CONFLICT(user_id,anchor) DO UPDATE SET label=excluded.label,revision=excluded.revision,changed_ms=excluded.changed_ms
    );
    defer stmt.finalize();
    try stmt.bind(1, user);
    if (label.len == 0) try stmt.bind(2, current.natural_anchors) else {
        try stmt.bind(2, reference);
        try stmt.bind(3, label);
        try stmt.bind(4, @max(time.milliTimestamp(), current.label.changed_ms + 1));
    }
    _ = try stmt.step();
}

pub const GroupReceipt = struct { undoId: []const u8, expiresAt: i64 };

/// The caller holds the mailbox lock after validating every target.
pub fn createGroup(a: Allocator, db: *Database, user: []const u8, refs: []const []const u8, wire: []const []const []const u8, live_links: []const []const []const u8) !GroupReceipt {
    const snapshot = try load(a, db, user);
    var graph = Graph.init(a);
    defer graph.deinit();
    try connectAnchors(&graph, snapshot, live_links);
    for (refs, wire) |reference, keys| try connectKeys(&graph, try graph.node(reference), keys);
    var captured = std.AutoHashMap(usize, []const []const u8).init(a);
    defer captured.deinit();
    for (refs) |reference| {
        const root = graph.root(graph.ids.get(reference).?);
        const slot = try captured.getOrPut(root);
        if (!slot.found_existing) slot.value_ptr.* = try naturalWire(a, &graph, root);
        try remember(a, db, user, reference, slot.value_ptr.*);
    }
    const stmt = try db.prepare(
        \\INSERT INTO mail_private_groups(user_id,anchors,undo_until)
        \\SELECT id,?2,unixepoch()+30 FROM users WHERE username=?1 RETURNING id,undo_until
    );
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bind(2, try std.json.Stringify.valueAlloc(a, refs, .{}));
    if (!try stmt.step()) return error.NotFound;
    const result: GroupReceipt = .{ .undoId = try a.dupe(u8, stmt.columnText(0)), .expiresAt = stmt.columnInt64(1) };
    _ = try stmt.step();
    return result;
}

pub fn undoGroup(db: *Database, user: []const u8, id: []const u8) !void {
    const stmt = try db.prepare("DELETE FROM mail_private_groups WHERE " ++ owner ++ " AND id=?2 AND undo_until>unixepoch() RETURNING id");
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bind(2, id);
    if (!try stmt.step()) return error.NotFound;
    _ = try stmt.step();
}

pub const CollectionAction = enum { create, rename, delete };

pub fn changeCollection(db: *Database, user: []const u8, action: CollectionAction, id: ?[]const u8, revision: ?i64, name: ?[]const u8) !void {
    const filter = " WHERE " ++ owner ++ " AND id=?2 AND revision=?3";
    const stmt = try db.prepare(switch (action) {
        .create => "INSERT INTO mail_private_collections(user_id,name) SELECT id,?2 FROM users WHERE username=?1 ON CONFLICT(user_id,name) DO NOTHING RETURNING id",
        .rename => "UPDATE mail_private_collections SET name=?4,revision=revision+1" ++ filter ++
            " AND NOT EXISTS(SELECT 1 FROM mail_private_collections c WHERE c.user_id=mail_private_collections.user_id AND c.name=?4 AND c.id<>?2) RETURNING id",
        .delete => "DELETE FROM mail_private_collections" ++ filter ++ " RETURNING id",
    });
    defer stmt.finalize();
    try stmt.bind(1, user);
    if (action == .create) try stmt.bind(2, name.?) else {
        try stmt.bind(2, id.?);
        try stmt.bind(3, revision.?);
        if (action == .rename) try stmt.bind(4, name.?);
    }
    if (!try stmt.step()) return error.CollectionChanged;
    _ = try stmt.step();
}

pub fn setMember(db: *Database, user: []const u8, reference: []const u8, collection: []const u8, included: bool, exact: bool, current: Context) !void {
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    {
        const stmt = try tx.prepare(
            \\SELECT EXISTS(SELECT 1 FROM mail_team_collection_shares s WHERE s.owner_id=c.user_id AND s.collection_id=c.id)
            \\FROM mail_private_collections c WHERE c.user_id=(SELECT id FROM users WHERE username=?1) AND c.id=?2
        );
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, collection);
        if (!try stmt.step()) return error.NotFound;
        if (included and !exact and stmt.columnInt64(0) != 0) return error.CollectionShareConfirmationRequired;
    }
    {
        const stmt = try tx.prepare(if (included)
            "INSERT OR IGNORE INTO mail_private_members(user_id,collection,anchor) SELECT id,?2,?3 FROM users WHERE username=?1"
        else if (exact)
            "DELETE FROM mail_private_members WHERE " ++ owner ++ " AND collection=?2 AND anchor=?3"
        else
            "DELETE FROM mail_private_members WHERE " ++ owner ++ " AND collection=?2 AND anchor IN (SELECT value FROM json_each(?3))");
        defer stmt.finalize();
        try stmt.bind(1, user);
        try stmt.bind(2, collection);
        try stmt.bind(3, if (included or exact) reference else current.conversation_anchors);
        _ = try stmt.step();
    }
    try tx.commit();
}
