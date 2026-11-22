//! Portable, operator-owned export of one canonical mailbox.
const std = @import("std");
const database = @import("database.zig");
const dav_store = @import("caldav_store.zig");
const submission = @import("../delivery/submission.zig");
const time_compat = @import("../core/time_compat.zig");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Tar = std.tar.Writer;
const Collection = struct { name: []const u8, path: []const u8 };
const Manifest = struct {
    mailbox: []const u8,
    folders: std.ArrayList(Collection) = .empty,
    calendars: std.ArrayList(Collection) = .empty,
    addressBooks: std.ArrayList(Collection) = .empty,
};
const Folder = struct { canonical: bool = false, flat: bool = false };

pub const Options = struct {
    mail_root: []const u8,
    dav_path: []const u8,
    require_dav: bool = false,
};

pub fn write(gpa: Allocator, io: std.Io, db: *database.Database, username: []const u8, destination: []const u8, options: Options) !void {
    var user = try db.getUserByUsername(username);
    defer user.deinit(db.allocator);
    if (!submission.isSafeLocalPart(user.username)) return error.InvalidMailbox;

    var private_file = try Dir.cwd().createFileAtomic(io, destination, .{ .permissions = .fromMode(0o600) });
    defer private_file.deinit(io);
    var output_buffer: [64 * 1024]u8 = undefined;
    var output = private_file.file.writer(io, &output_buffer);
    var archive: Tar = .{ .underlying_writer = &output.interface };

    var metadata = std.heap.ArenaAllocator.init(gpa);
    defer metadata.deinit();
    const a = metadata.allocator();
    var manifest: Manifest = .{ .mailbox = user.username };
    try writeMail(a, io, &archive, &manifest, options.mail_root, user.username);
    try writeDav(gpa, a, io, db, &archive, &manifest, user.id, options);

    const json = try std.json.Stringify.valueAlloc(a, .{
        .version = 1,
        .mailbox = manifest.mailbox,
        .folders = manifest.folders.items,
        .calendars = manifest.calendars.items,
        .addressBooks = manifest.addressBooks.items,
    }, .{ .whitespace = .indent_2 });
    try archive.writeFileBytes("manifest.json", json, .{ .mode = 0o600 });
    try archive.finishPedantically();
    try output.interface.flush();
    try private_file.file.sync(io);
    try private_file.link(io);
}

fn openOptionalDir(dir: Dir, io: std.Io, path: []const u8) !?Dir {
    return dir.openDir(io, path, .{ .iterate = true, .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
}

fn writeMail(a: Allocator, io: std.Io, archive: *Tar, manifest: *Manifest, mail_root: []const u8, username: []const u8) !void {
    try writeMaildir(a, archive, "Maildir");
    try manifest.folders.append(a, .{ .name = "INBOX", .path = "Maildir" });
    const root = Dir.cwd().openDir(io, mail_root, .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer root.close(io);
    const user_dir = try openOptionalDir(root, io, username) orelse return;
    defer user_dir.close(io);
    var sequence: u64 = 0;
    try writeSlots(io, archive, user_dir, "Maildir", &sequence);

    var folders: std.StringArrayHashMapUnmanaged(Folder) = .empty;
    var entries = user_dir.iterate();
    while (try entries.next(io)) |entry| {
        // Current IMAP folders have a physical .Name Maildir++ directory.
        // The visible Name symlink is a compatibility alias for its cur/.
        if (entry.kind != .directory) continue;
        const canonical = std.mem.startsWith(u8, entry.name, ".");
        const name = if (canonical) entry.name[1..] else entry.name;
        if (!submission.isSafeLocalPart(name) or (!canonical and isSlot(name))) continue;
        if (!std.unicode.utf8ValidateSlice(name)) return error.InvalidMailboxFolderName;
        if (canonical and !try containsMaildirSlot(user_dir, io, entry.name)) continue;
        const row = try folders.getOrPut(a, name);
        if (!row.found_existing) {
            row.key_ptr.* = try a.dupe(u8, name);
            row.value_ptr.* = .{};
        }
        if (canonical) row.value_ptr.canonical = true else row.value_ptr.flat = true;
    }

    for (folders.keys(), folders.values()) |name, folder| {
        const source_name = try std.fmt.allocPrint(a, ".{s}", .{name});
        const path = try std.fmt.allocPrint(a, "Maildir/{s}", .{source_name});
        try writeMaildir(a, archive, path);
        try archive.writeFileBytes(try std.fmt.allocPrint(a, "{s}/maildirfolder", .{path}), "", .{ .mode = 0o600 });
        try manifest.folders.append(a, .{ .name = name, .path = path });
        if (folder.canonical) {
            const source = try openOptionalDir(user_dir, io, source_name) orelse return error.MailboxChangedDuringExport;
            defer source.close(io);
            try writeSlots(io, archive, source, path, &sequence);
        }
        if (folder.flat) {
            const source = try openOptionalDir(user_dir, io, name) orelse return error.MailboxChangedDuringExport;
            defer source.close(io);
            try writeMessages(io, archive, source, path, "cur", &sequence);
        }
    }
}

fn isSlot(name: []const u8) bool {
    return std.mem.eql(u8, name, "cur") or std.mem.eql(u8, name, "new") or std.mem.eql(u8, name, "tmp");
}

fn containsMaildirSlot(parent: Dir, io: std.Io, name: []const u8) !bool {
    const dir = try openOptionalDir(parent, io, name) orelse return error.MailboxChangedDuringExport;
    defer dir.close(io);
    inline for (.{ "cur", "new" }) |slot| {
        if (try openOptionalDir(dir, io, slot)) |child| {
            child.close(io);
            return true;
        }
    }
    return false;
}

fn writeMaildir(a: Allocator, archive: *Tar, path: []const u8) !void {
    // Maildir readers compare new/ and cur/ mtimes to detect messages.
    const attributes: Tar.Options = .{ .mode = 0o700, .mtime = @intCast(@max(1, time_compat.timestamp())) };
    try archive.writeDir(path, attributes);
    inline for (.{ "cur", "new", "tmp" }) |slot| {
        try archive.writeDir(try std.fmt.allocPrint(a, "{s}/{s}", .{ path, slot }), attributes);
    }
}

fn writeSlots(io: std.Io, archive: *Tar, parent: Dir, path: []const u8, sequence: *u64) !void {
    inline for (.{ "cur", "new" }) |slot| {
        if (try openOptionalDir(parent, io, slot)) |dir| {
            defer dir.close(io);
            try writeMessages(io, archive, dir, path, slot, sequence);
        }
    }
}

fn writeMessages(io: std.Io, archive: *Tar, dir: Dir, path: []const u8, slot: []const u8, sequence: *u64) !void {
    var iterator = dir.iterate();
    var read_buffer: [32 * 1024]u8 = undefined;
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .file) continue;
        const marker = std.mem.indexOf(u8, entry.name, ".eml:2,");
        if (marker == null and !std.mem.endsWith(u8, entry.name, ".eml")) continue;
        const flags = if (marker) |index| entry.name[index + ".eml:2,".len ..] else "";
        for (flags) |flag| {
            if (!std.ascii.isAlphabetic(flag)) return error.InvalidMaildirFlags;
        }
        const file = try dir.openFile(io, entry.name, .{ .follow_symlinks = false });
        defer file.close(io);
        const before = try file.stat(io);
        if (before.kind != .file) return error.MailboxChangedDuringExport;
        const seconds: u64 = @intCast(@max(0, before.mtime.toSeconds()));
        // Fresh names prevent collisions when a folder has both storage layouts.
        var name_buffer: [1024]u8 = undefined;
        const archive_name = try std.fmt.bufPrint(&name_buffer, "{s}/{s}/{d}.{d}.portable.eml{s}{s}", .{
            path,                                                              slot,  seconds, sequence.*,
            if (std.mem.eql(u8, slot, "cur") or flags.len != 0) ":2," else "", flags,
        });
        sequence.* += 1;
        var reader = file.reader(io, &read_buffer);
        try archive.writeFileStream(archive_name, before.size, &reader.interface, .{ .mode = 0o600, .mtime = seconds });
        const after = try file.stat(io);
        if (after.size != before.size or after.mtime.nanoseconds != before.mtime.nanoseconds)
            return error.MailboxChangedDuringExport;
    }
}

fn writeDav(gpa: Allocator, a: Allocator, io: std.Io, db: *database.Database, archive: *Tar, manifest: *Manifest, mailbox_id: i64, options: Options) !void {
    _ = Dir.cwd().statFile(io, options.dav_path, .{}) catch |err| switch (err) {
        error.FileNotFound => if (options.require_dav) return err else return,
        else => return err,
    };
    var store = try dav_store.CalDavStore.init(gpa, .{ .db_path = options.dav_path, .account_db = db });
    defer store.deinit();
    const owner_id = store.exportOwnerForMailbox(mailbox_id) orelse return;
    const calendars = try store.getUserCalendars(owner_id);
    defer gpa.free(calendars);
    if (calendars.len != 0) try archive.writeDir("Calendars", .{ .mode = 0o700 });
    for (calendars) |calendar| {
        var scratch = std.heap.ArenaAllocator.init(gpa);
        defer scratch.deinit();
        const path = try std.fmt.allocPrint(a, "Calendars/{d}.ics", .{calendar.id});
        const content = try store.exportCalendarForMailbox(scratch.allocator(), mailbox_id, calendar.id);
        try archive.writeFileBytes(path, content, .{ .mode = 0o600 });
        try manifest.calendars.append(a, .{ .path = path, .name = try a.dupe(u8, calendar.name) });
    }
    const books = try store.getUserAddressBooks(owner_id);
    defer gpa.free(books);
    if (books.len != 0) try archive.writeDir("Contacts", .{ .mode = 0o700 });
    for (books) |book| {
        const path = try std.fmt.allocPrint(a, "Contacts/{d}", .{book.id});
        try archive.writeDir(path, .{ .mode = 0o700 });
        try manifest.addressBooks.append(a, .{ .path = path, .name = try a.dupe(u8, book.name) });
        const contacts = try store.getAddressBookContacts(book.id);
        defer gpa.free(contacts);
        for (contacts) |contact| {
            var name_buffer: [128]u8 = undefined;
            const name = try std.fmt.bufPrint(&name_buffer, "{s}/{d}.vcf", .{ path, contact.id });
            const card = try store.generateVcf(contact);
            defer gpa.free(card);
            try archive.writeFileBytes(name, card, .{ .mode = 0o600 });
        }
    }
}
