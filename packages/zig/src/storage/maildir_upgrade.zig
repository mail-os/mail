//! Recover local-account mail from the old short-name root before serving it.
const std = @import("std");
const database = @import("database.zig");
const Database = database.Database;
const folders = @import("maildir_folders.zig");
const keywords = @import("maildir_keywords.zig");
const refs = @import("message_refs.zig");
const paths = @import("../core/maildir_path.zig");
const index = @import("../search/maildir_index.zig");
const durable = @import("../core/durable_maildir.zig");
const fs = @import("../core/fs_compat.zig");
const io_compat = @import("../core/io_compat.zig");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const slot_names = [_][]const u8{ "new", "cur" };

const Move = struct { from: []const u8, to: []const u8, container: bool = false };
const Copy = struct { path: []const u8, bytes: []const u8 };
const Alias = struct { current: []const u8, previous: []const u8 };

const Plan = struct {
    directories: std.ArrayList([]const u8) = .empty,
    moves: std.ArrayList(Move) = .empty,
    maps: std.ArrayList(Copy) = .empty,
    drafts: std.ArrayList(Move) = .empty,
    aliases: std.ArrayList(Alias) = .empty,
    registered: std.ArrayList([]const u8) = .empty,
    indexed: std.ArrayList(refs.Location) = .empty,
};

const Physical = struct {
    name: []const u8,
    plus: bool,
};

pub fn recover(allocator: Allocator, db: *Database) !void {
    const io = io_compat.getIo();
    const root = (try folders.openRoot(io)) orelse return;
    defer root.close(io);
    db.lockMailboxes();
    defer db.unlockMailboxes();

    const users = try db.getAllUsers();
    defer {
        for (users) |*user| user.deinit(db.allocator);
        db.allocator.free(users);
    }
    var owners_arena = std.heap.ArenaAllocator.init(allocator);
    defer owners_arena.deinit();
    const owners_allocator = owners_arena.allocator();
    var owners: std.StringHashMapUnmanaged(usize) = .empty;
    for (users) |user| {
        const short = user.username[0 .. std.mem.indexOfScalar(u8, user.username, '@') orelse user.username.len];
        const key = try std.ascii.allocLowerString(owners_allocator, short);
        const row = try owners.getOrPut(owners_allocator, key);
        if (!row.found_existing) row.value_ptr.* = 0;
        row.value_ptr.* += 1;
    }
    for (users) |user| {
        paths.validate(user.username) catch continue;
        if (isRootSlot(user.username) or user.username[0] == '.') continue;
        if ((try db.hostedLimits(user.username)) != null) continue;
        if (std.mem.indexOfScalar(u8, user.username, '@')) |at| {
            const short = user.username[0..at];
            if (short.len != 0 and short[0] != '.' and !isRootSlot(short)) {
                const key = try std.ascii.allocLowerString(allocator, short);
                defer allocator.free(key);
                try recoverLegacy(allocator, io, root, db, user.username, short, owners.get(key).? == 1);
            }
        }
        try recoverCanonical(allocator, io, root, db, user.username);
    }

    // All new readers and writers use the authenticated username. Old index
    // work must resolve the canonical file after this upgrade.
    const rebase = try db.prepare("UPDATE mail_search_pending SET short_root=0 WHERE short_root<>0");
    defer rebase.finalize();
    _ = try rebase.step();
}

fn recoverLegacy(allocator: Allocator, io: std.Io, root: Dir, db: *Database, user: []const u8, short: []const u8, unique: bool) !void {
    const legacy = (try folders.open(io, root, short)) orelse return;
    defer legacy.close(io);
    if (!unique) {
        std.log.warn("legacy Maildir mail/{s} has ambiguous ownership; use the canonical mailbox and review the legacy files", .{short});
        return;
    }
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const plan = planMailbox(a, io, root, legacy, short, user) catch |err| switch (err) {
        error.MaildirConflict, error.InvalidMailboxPath => {
            std.log.warn("legacy Maildir mail/{s} conflicts with {s}; files are preserved for review", .{ short, user });
            return;
        },
        else => return err,
    };
    checkpoint(a, db, user, plan) catch |err| switch (err) {
        error.MaildirConflict => {
            std.log.warn("legacy Maildir mail/{s} conflicts with the existing folder IDs for {s}; files are preserved for review", .{ short, user });
            return;
        },
        else => return err,
    };
    try apply(a, io, root, plan);

    // Keep private residual metadata and temporary files. Moving the
    // remaining directory also makes a second startup a no-op.
    var nonce: [8]u8 = undefined;
    io_compat.randomBytes(&nonce);
    const retired = try std.fmt.allocPrint(a, ".relocated-maildir-{s}", .{std.fmt.bytesToHex(nonce, .lower)});
    try Dir.renamePreserve(root, short, root, retired, io);
    try durable.syncDirectory(a, "mail");
    std.log.info("legacy Maildir mail/{s} moved to {s}; residual files retained at mail/{s}", .{ short, user, retired });
}

fn recoverCanonical(allocator: Allocator, io: std.Io, root: Dir, db: *Database, user: []const u8) !void {
    const canonical = (try folders.open(io, root, user)) orelse return;
    defer canonical.close(io);
    var entries = canonical.iterate();
    while (try entries.next(io)) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.name, "INBOX") or isRootSlot(entry.name)) continue;
        paths.validate(entry.name) catch continue;
        folders.validateName(entry.name) catch continue;
        const layout = (try folders.layout(io, canonical, entry.name)) orelse continue;
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const plus = layout == .maildir_plus;
        const physical = if (plus) try std.fmt.allocPrint(a, ".{s}", .{entry.name}) else entry.name;
        const destination = (try folders.open(io, canonical, physical)) orelse continue;
        defer destination.close(io);
        var plan: Plan = .{};
        planCanonical(a, io, destination, user, physical, entry.name, plus, &plan) catch |err| switch (err) {
            error.MaildirConflict => {
                std.log.warn("Maildir folder {s} for {s} has conflicting contents; files are preserved for review", .{ entry.name, user });
                continue;
            },
            else => return err,
        };
        if (plan.moves.items.len == 0) continue;
        try checkpoint(a, db, user, plan);
        try apply(a, io, root, plan);
    }
}

fn planCanonical(a: Allocator, io: std.Io, destination: Dir, user: []const u8, physical: []const u8, name: []const u8, plus: bool, plan: *Plan) !void {
    // Skip scanning the visible messages when there are no imports in a
    // second slot. The normal layout therefore needs no database writes.
    for (slot_names) |slot| {
        if (plus and std.mem.eql(u8, slot, "cur")) continue;
        const child = (try optionalDirectory(io, destination, slot)) orelse continue;
        defer child.close(io);
        var files = child.iterate();
        while (try files.next(io)) |file| {
            if (!fs.isEmlFilename(file.name)) continue;
            const target_root = try join(a, user, physical);
            const target_files = if (plus) try join(a, target_root, "cur") else target_root;
            var names: Names = .{};
            _ = try normalizeSlots(a, io, destination, target_root, target_files, name, plus, &names, plan);
            try plan.registered.append(a, name);
            return;
        }
    }
}

fn planMailbox(a: Allocator, io: std.Io, root: Dir, legacy: Dir, short: []const u8, user: []const u8) !Plan {
    var plan: Plan = .{};
    const canonical = try optionalDirectory(io, root, user);
    defer if (canonical) |dir| dir.close(io);
    try plan.directories.append(a, user);
    try planInbox(a, io, legacy, canonical, short, user, &plan);
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    var entries = legacy.iterate();
    while (try entries.next(io)) |entry| {
        if (isRootSlot(entry.name)) continue;
        if (entry.kind != .directory) {
            if (fs.isEmlFilename(entry.name)) return error.MaildirConflict;
            continue;
        }
        const plus = entry.name[0] == '.';
        const logical = if (plus) entry.name[1..] else entry.name;
        if (std.ascii.eqlIgnoreCase(logical, "INBOX") or isRootSlot(logical)) return error.MaildirConflict;
        const source = (try optionalDirectory(io, legacy, entry.name)) orelse return error.MaildirConflict;
        defer source.close(io);
        if (plus) {
            const slot = (try optionalDirectory(io, source, "cur")) orelse (try optionalDirectory(io, source, "new")) orelse continue;
            slot.close(io);
            const visible = try stat(io, legacy, logical);
            if (visible != null and (try folders.layout(io, legacy, logical)) != .maildir_plus)
                return error.MaildirConflict;
        }
        try folders.validateName(logical);
        try paths.validate(logical);
        if ((try seen.getOrPut(a, try std.ascii.allocLowerString(a, logical))).found_existing) return error.MaildirConflict;
        const name = try a.dupe(u8, logical);
        const source_path = try join(a, short, entry.name);
        try planFolder(a, io, source, source_path, canonical, user, name, &plan);
        try plan.registered.append(a, name);
    }
    return plan;
}

fn planInbox(a: Allocator, io: std.Io, legacy: Dir, canonical: ?Dir, short: []const u8, user: []const u8, plan: *Plan) !void {
    var names: Names = .{};
    var has_target_keywords = false;
    if (canonical) |target| {
        for (slot_names) |slot| {
            const child = (try optionalDirectory(io, target, slot)) orelse continue;
            defer child.close(io);
            has_target_keywords = (try claimExisting(a, io, child, &names)) or has_target_keywords;
        }
    }
    const source_map = try keywordMap(a, io, legacy);
    const target_map = if (canonical) |target| try keywordMap(a, io, target) else null;
    try mergeMaps(a, user, source_map, target_map, has_target_keywords, plan);
    for (slot_names) |slot| {
        const child = (try optionalDirectory(io, legacy, slot)) orelse continue;
        defer child.close(io);
        const from = try join(a, short, slot);
        const to = try join(a, user, slot);
        try plan.directories.append(a, to);
        _ = try collect(a, io, child, from, to, to, "INBOX", source_map == null and target_map != null, &names, plan);
    }
}

fn planFolder(a: Allocator, io: std.Io, source: Dir, source_path: []const u8, canonical: ?Dir, user: []const u8, name: []const u8, plan: *Plan) !void {
    const existing = if (canonical) |root| try canonicalFolder(a, io, root, name) else null;
    const target_root = try join(a, user, if (existing) |parts| parts.name else name);
    const target_files = if (existing != null and existing.?.plus) try join(a, target_root, "cur") else target_root;
    var names: Names = .{};
    var missing_source_map = false;
    if (existing) |parts| {
        const root = canonical.?;
        const destination = (try optionalDirectory(io, root, parts.name)) orelse return error.MaildirConflict;
        defer destination.close(io);
        const source_map = try keywordMap(a, io, source);
        const target_map = try keywordMap(a, io, destination);
        const has_target_keywords = try normalizeSlots(a, io, destination, target_root, target_files, name, parts.plus, &names, plan);
        try mergeMaps(a, target_root, source_map, target_map, has_target_keywords, plan);
        missing_source_map = source_map == null and target_map != null;
        const previous = try refs.directoryStamp(a, try join(a, "mail", source_path));
        const current = try refs.directoryStamp(a, try join(a, "mail", target_root));
        try plan.aliases.append(a, .{ .current = current, .previous = previous });
        _ = try collect(a, io, source, source_path, target_files, target_files, name, missing_source_map, &names, plan);
    } else {
        // A directory rename preserves the inode-based ActiveSync folder ID.
        // Normalize nested messages first so a crash can resume in place.
        _ = try claimExisting(a, io, source, &names);
        var entries = source.iterate();
        while (try entries.next(io)) |entry| {
            if (!fs.isEmlFilename(entry.name)) continue;
            try plan.indexed.append(a, refs.location(name, try a.dupe(u8, entry.name)));
            if (std.mem.eql(u8, name, "Drafts"))
                try plan.drafts.append(a, .{ .from = try join(a, source_path, entry.name), .to = try join(a, target_root, entry.name) });
        }
    }
    const publish_files = if (existing == null) source_path else target_files;
    for (slot_names) |slot| {
        const child = (try optionalDirectory(io, source, slot)) orelse continue;
        defer child.close(io);
        _ = try collect(a, io, child, try join(a, source_path, slot), publish_files, target_files, name, missing_source_map, &names, plan);
    }
    if (existing == null) try plan.moves.append(a, .{ .from = source_path, .to = target_root, .container = true });
}

// IMAP and webmail expose the flat folder, or the cur/ alias for Maildir++.
// Put all messages in the same visible location before starting readers.
fn normalizeSlots(a: Allocator, io: std.Io, destination: Dir, target_root: []const u8, target_files: []const u8, name: []const u8, plus: bool, names: *Names, plan: *Plan) !bool {
    const visible = if (plus) (try optionalDirectory(io, destination, "cur")) orelse return error.MaildirConflict else destination;
    defer if (plus) visible.close(io);
    var has_keywords = try claimExisting(a, io, visible, names);
    for (slot_names) |slot| {
        if (plus and std.mem.eql(u8, slot, "cur")) continue;
        const child = (try optionalDirectory(io, destination, slot)) orelse continue;
        defer child.close(io);
        const slot_path = try join(a, target_root, slot);
        has_keywords = (try collect(a, io, child, slot_path, target_files, target_files, name, false, names, plan)) or has_keywords;
    }
    return has_keywords;
}

const Names = std.StringHashMapUnmanaged(void);

fn claim(a: Allocator, names: *Names, filename: []const u8) !void {
    const base = database.maildirBaseName(filename);
    if ((try names.getOrPut(a, try std.ascii.allocLowerString(a, base))).found_existing) return error.MaildirConflict;
}

fn claimExisting(a: Allocator, io: std.Io, dir: Dir, names: *Names) !bool {
    var custom_keywords = false;
    var entries = dir.iterate();
    while (try entries.next(io)) |entry| {
        if (!fs.isEmlFilename(entry.name)) continue;
        if (entry.kind != .file) return error.MaildirConflict;
        try claim(a, names, entry.name);
        custom_keywords = custom_keywords or keywords.fromFilename(entry.name) != 0;
    }
    return custom_keywords;
}

fn collect(a: Allocator, io: std.Io, dir: Dir, from: []const u8, to: []const u8, final: []const u8, folder: []const u8, missing_source_map: bool, names: *Names, plan: *Plan) !bool {
    var custom_keywords = false;
    var entries = dir.iterate();
    while (try entries.next(io)) |entry| {
        if (!fs.isEmlFilename(entry.name)) continue;
        const has_keywords = keywords.fromFilename(entry.name) != 0;
        if (entry.kind != .file or (missing_source_map and has_keywords)) return error.MaildirConflict;
        custom_keywords = custom_keywords or has_keywords;
        try claim(a, names, entry.name);
        const source = try join(a, from, entry.name);
        try plan.moves.append(a, .{ .from = source, .to = try join(a, to, entry.name) });
        if (std.mem.eql(u8, folder, "Drafts"))
            try plan.drafts.append(a, .{ .from = source, .to = try join(a, final, entry.name) });
        try plan.indexed.append(a, refs.location(folder, try a.dupe(u8, entry.name)));
    }
    return custom_keywords;
}

fn mergeMaps(a: Allocator, target: []const u8, source_map: ?[]const u8, target_map: ?[]const u8, existing_flags: bool, plan: *Plan) !void {
    const source = source_map orelse return;
    if (target_map) |present| {
        if (!std.mem.eql(u8, source, present)) return error.MaildirConflict;
        return;
    }
    if (existing_flags) return error.MaildirConflict;
    try plan.maps.append(a, .{ .path = try join(a, target, keywords.mapping_name), .bytes = source });
}

fn keywordMap(a: Allocator, io: std.Io, dir: Dir) !?[]const u8 {
    const meta = (try stat(io, dir, keywords.mapping_name)) orelse return null;
    if (meta.kind != .file or meta.size > 64 * 1024) return error.MaildirConflict;
    return try dir.readFileAlloc(io, keywords.mapping_name, a, .limited(64 * 1024));
}

fn canonicalFolder(a: Allocator, io: std.Io, root: Dir, name: []const u8) !?Physical {
    const hidden = try std.fmt.allocPrint(a, ".{s}", .{name});
    var entries = root.iterate();
    while (try entries.next(io)) |entry| {
        if ((!std.mem.eql(u8, entry.name, name) and std.ascii.eqlIgnoreCase(entry.name, name)) or
            (!std.mem.eql(u8, entry.name, hidden) and std.ascii.eqlIgnoreCase(entry.name, hidden)))
            return error.MaildirConflict;
    }
    const physical = try stat(io, root, hidden);
    if (try folders.layout(io, root, name)) |layout| {
        if (layout == .maildir_plus) return .{ .name = hidden, .plus = true };
        if (physical != null) return error.MaildirConflict;
        return .{ .name = name, .plus = false };
    }
    if (physical != null or try stat(io, root, name) != null) return error.MaildirConflict;
    return null;
}

fn checkpoint(a: Allocator, db: *Database, user: []const u8, plan: Plan) !void {
    {
        var tx = try db.beginTransaction(.write);
        defer tx.deinit();
        const insert = try tx.prepare(
            \\INSERT INTO eas_folder_stamp_aliases(user_id,stamp,previous_stamp)
            \\SELECT id,?2,?3 FROM users WHERE username=?1
            \\ON CONFLICT(user_id,stamp) DO UPDATE SET previous_stamp=excluded.previous_stamp
            \\WHERE previous_stamp=excluded.previous_stamp RETURNING 1
        );
        defer insert.finalize();
        for (plan.aliases.items) |alias| {
            try insert.reset();
            try insert.bind(1, user);
            try insert.bind(2, alias.current);
            try insert.bind(3, alias.previous);
            if (!try insert.step()) return error.MaildirConflict;
            _ = try insert.step();
        }
        const draft = try tx.prepare(
            \\UPDATE mail_ews_draft_finalizations SET path=?3
            \\WHERE user_id=(SELECT id FROM users WHERE username=?1) AND path=?2 AND retired_at IS NULL
        );
        defer draft.finalize();
        for (plan.drafts.items) |move| {
            try draft.reset();
            try draft.bind(1, user);
            try draft.bind(2, try join(a, "mail", move.from));
            try draft.bind(3, try join(a, "mail", move.to));
            _ = try draft.step();
        }
        try tx.commit();
    }
    for (plan.registered.items) |folder| _ = try db.getOrCreateMailbox(user, folder);
    try index.markLocked(db, user, false, plan.indexed.items);
}

pub fn previousFolderStamp(a: Allocator, db: *Database, user_id: i64, stamp: []const u8) ![]const u8 {
    const stmt = try db.prepare("SELECT previous_stamp FROM eas_folder_stamp_aliases WHERE user_id=?1 AND stamp=?2");
    defer stmt.finalize();
    try stmt.bind(1, user_id);
    try stmt.bind(2, stamp);
    return if (try stmt.step()) try a.dupe(u8, stmt.columnText(0)) else stamp;
}

fn apply(a: Allocator, io: std.Io, root: Dir, plan: Plan) !void {
    for (plan.directories.items) |path| {
        const directory = try descendant(io, root, path, true);
        directory.close(io);
    }
    for (plan.maps.items) |map| {
        const parent = try descendant(io, root, std.fs.path.dirname(map.path).?, false);
        defer parent.close(io);
        try durable.resumeWrite(a, try join(a, "mail", map.path), map.bytes);
    }
    var touched: std.StringHashMapUnmanaged(void) = .empty;
    for (plan.moves.items) |move| {
        const from_path = std.fs.path.dirname(move.from).?;
        const to_path = std.fs.path.dirname(move.to).?;
        // Before a whole-folder rename, persist every slot affected by
        // normalization. Those paths disappear after the rename.
        if (move.container) try syncTouched(a, &touched);
        const from = try descendant(io, root, from_path, false);
        defer from.close(io);
        const to = try descendant(io, root, to_path, false);
        defer to.close(io);
        try Dir.renamePreserve(from, std.fs.path.basename(move.from), to, std.fs.path.basename(move.to), io);
        try touched.put(a, from_path, {});
        try touched.put(a, to_path, {});
    }
    try syncTouched(a, &touched);
}

fn syncTouched(a: Allocator, touched: *std.StringHashMapUnmanaged(void)) !void {
    var changed = touched.keyIterator();
    while (changed.next()) |path| try durable.syncDirectory(a, try join(a, "mail", path.*));
    touched.clearRetainingCapacity();
}

fn descendant(io: std.Io, root: Dir, path: []const u8, create: bool) !Dir {
    var current = try root.openDir(io, ".", .{ .follow_symlinks = false });
    errdefer current.close(io);
    var names = std.mem.splitScalar(u8, path, '/');
    while (names.next()) |name| {
        try paths.validate(name);
        if (create) current.createDir(io, name, .default_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        const child = try current.openDir(io, name, .{ .follow_symlinks = false });
        current.close(io);
        current = child;
    }
    return current;
}

fn optionalDirectory(io: std.Io, parent: Dir, name: []const u8) !?Dir {
    const found = (try stat(io, parent, name)) orelse return null;
    if (found.kind != .directory) return error.MaildirConflict;
    return try parent.openDir(io, name, .{ .iterate = true, .follow_symlinks = false });
}

fn stat(io: std.Io, dir: Dir, name: []const u8) !?Dir.Stat {
    return dir.statFile(io, name, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
}

fn isRootSlot(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "tmp") or std.ascii.eqlIgnoreCase(name, "new") or std.ascii.eqlIgnoreCase(name, "cur");
}

fn join(a: Allocator, parent: []const u8, name: []const u8) ![]const u8 {
    return std.fmt.allocPrint(a, "{s}/{s}", .{ parent, name });
}
