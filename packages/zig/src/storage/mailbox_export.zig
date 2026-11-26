//! Portable, operator-owned export of one canonical mailbox.
const std = @import("std");
const calendar_workflow = @import("calendar_workflow_transfer.zig");
const database = @import("database.zig");
const dav_store = @import("caldav_store.zig");
const retained_threads = @import("retained_thread_store.zig");
const webmail_store = @import("../api/webmail_store.zig");
const maildir_keywords = @import("maildir_keywords.zig");
const submission = @import("../delivery/submission.zig");
const time_compat = @import("../core/time_compat.zig");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Tar = std.tar.Writer;
const archive_path_capacity = 1024;
const Collection = struct { name: []const u8, path: []const u8 };
const RetainedMail = struct {
    version: u8 = 1,
    copies: []const Copy,

    const Copy = struct { id: []const u8, path: []const u8 };
};
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
    var pending = try prepare(gpa, io, db, username, destination, options, null);
    defer pending.deinit(io);
    try pending.link(io);
}

/// Build and sync a private file. The caller links the destination after any
/// required audit is durable. Hash exactly the bytes written to the archive.
pub fn prepare(
    gpa: Allocator,
    io: std.Io,
    db: *database.Database,
    username: []const u8,
    destination: []const u8,
    options: Options,
    digest: ?*[32]u8,
) !std.Io.File.Atomic {
    var user = try db.getUserByUsername(username);
    defer user.deinit(db.allocator);
    if (!submission.isSafeLocalPart(user.username)) return error.InvalidMailbox;

    var private_file = try Dir.cwd().createFileAtomic(io, destination, .{ .permissions = .fromMode(0o600) });
    errdefer private_file.deinit(io);
    var output_buffer: [64 * 1024]u8 = undefined;
    var output = private_file.file.writer(io, &output_buffer);
    var hash_buffer: [4096]u8 = undefined;
    var hashed = output.interface.hashed(std.crypto.hash.sha2.Sha256.init(.{}), &hash_buffer);
    var archive: Tar = .{ .underlying_writer = if (digest != null) &hashed.writer else &output.interface };

    var metadata = std.heap.ArenaAllocator.init(gpa);
    defer metadata.deinit();
    const a = metadata.allocator();
    var manifest: Manifest = .{ .mailbox = user.username };
    try writeMail(a, io, &archive, &manifest, options.mail_root, user.username);
    try writeDav(gpa, a, io, db, &archive, &manifest, user.id, options);
    const workflow = try calendar_workflow.snapshot(a, db, user.id);
    const portable_workflow = try std.json.Stringify.valueAlloc(a, workflow, .{});
    try archive.writeFileBytes(calendar_workflow.archive_path, portable_workflow, .{ .mode = 0o600 });

    const retained_mail = try writeRetainedMail(a, db, &archive, user.id);
    const json = try std.json.Stringify.valueAlloc(a, .{
        .version = 1,
        .mailbox = manifest.mailbox,
        .folders = manifest.folders.items,
        .calendars = manifest.calendars.items,
        .addressBooks = manifest.addressBooks.items,
        .calendarWorkflow = calendar_workflow.archive_path,
        .retainedMail = retained_mail,
    }, .{ .whitespace = .indent_2, .emit_null_optional_fields = false });
    try archive.writeFileBytes("manifest.json", json, .{ .mode = 0o600 });
    try archive.finishPedantically();
    if (digest) |sha| {
        try hashed.writer.flush();
        sha.* = hashed.hasher.finalResult();
    }
    try output.interface.flush();
    try private_file.file.sync(io);
    return private_file;
}

fn writeRetainedMail(a: Allocator, db: *database.Database, archive: *Tar, owner: i64) !?RetainedMail {
    const rows = try retained_threads.portableRows(db, owner);
    defer rows.close();
    var copies: std.ArrayList(RetainedMail.Copy) = .empty;
    while (try rows.next()) |entry| {
        if (!webmail_store.validId(entry.id)) return error.InvalidRetainedMailId;
        const path = try std.fmt.allocPrint(a, "RetainedMail/{s}.json", .{entry.id});
        try archive.writeFileBytes(path, entry.document, .{ .mode = 0o600 });
        try copies.append(a, .{ .id = try a.dupe(u8, entry.id), .path = path });
    }
    return if (copies.items.len != 0) .{ .copies = copies.items } else null;
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
    var inbox_keywords: maildir_keywords.Names = .{};
    try writeSlots(a, io, archive, user_dir, "Maildir", &inbox_keywords, &sequence);
    try writeKeywordMap(a, archive, "Maildir", &inbox_keywords);

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
        var keywords: maildir_keywords.Names = .{};
        if (folder.canonical) {
            const source = try openOptionalDir(user_dir, io, source_name) orelse return error.MailboxChangedDuringExport;
            defer source.close(io);
            try writeSlots(a, io, archive, source, path, &keywords, &sequence);
        }
        if (folder.flat) {
            const source = try openOptionalDir(user_dir, io, name) orelse return error.MailboxChangedDuringExport;
            defer source.close(io);
            const source_keywords = try maildir_keywords.load(a, io, source);
            try writeMessages(io, archive, source, path, "cur", &source_keywords, &keywords, &sequence);
        }
        try writeKeywordMap(a, archive, path, &keywords);
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

fn writeKeywordMap(a: Allocator, archive: *Tar, path: []const u8, keywords: *const maildir_keywords.Names) !void {
    if (keywords.defined() == 0) return;
    const name = try std.fmt.allocPrint(a, "{s}/{s}", .{ path, maildir_keywords.mapping_name });
    try archive.writeFileBytes(name, try keywords.encode(a), .{ .mode = 0o600 });
}

fn writeSlots(a: Allocator, io: std.Io, archive: *Tar, parent: Dir, path: []const u8, keywords: *maildir_keywords.Names, sequence: *u64) !void {
    const source_keywords = try maildir_keywords.load(a, io, parent);
    inline for (.{ "cur", "new" }) |slot| {
        if (try openOptionalDir(parent, io, slot)) |dir| {
            defer dir.close(io);
            try writeMessages(io, archive, dir, path, slot, &source_keywords, keywords, sequence);
        }
    }
}

fn writeMessages(io: std.Io, archive: *Tar, dir: Dir, path: []const u8, slot: []const u8, source_keywords: *const maildir_keywords.Names, keywords: *maildir_keywords.Names, sequence: *u64) !void {
    var iterator = dir.iterate();
    var read_buffer: [32 * 1024]u8 = undefined;
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .file) continue;
        const marker = std.mem.indexOf(u8, entry.name, ".eml:2,");
        if (marker == null and !std.mem.endsWith(u8, entry.name, ".eml")) continue;
        const stored_flags = if (marker) |index| entry.name[index + ".eml:2,".len ..] else "";
        var flag_buffer: [256]u8 = undefined;
        var flags_writer = std.Io.Writer.fixed(&flag_buffer);
        for (stored_flags) |flag| {
            if (!std.ascii.isAlphabetic(flag)) return error.InvalidMaildirFlags;
            if (std.ascii.isUpper(flag)) try flags_writer.writeAll(&.{flag});
        }
        const bits = try keywords.translate(source_keywords, maildir_keywords.fromFilename(entry.name));
        try maildir_keywords.writeLetters(&flags_writer, bits);
        const flags = flags_writer.buffered();
        const file = try dir.openFile(io, entry.name, .{ .follow_symlinks = false });
        defer file.close(io);
        const before = try file.stat(io);
        if (before.kind != .file) return error.MailboxChangedDuringExport;
        const seconds: i64 = @intCast(@divFloor(before.mtime.nanoseconds, std.time.ns_per_s));
        // USTAR has eleven unsigned octal digits for the modification time.
        const ustar_mtime: ?u64 = if (seconds >= 0 and seconds <= std.math.maxInt(u33)) @intCast(seconds) else null;
        // Fresh names prevent collisions when a folder has both storage layouts.
        var name_buffer: [archive_path_capacity]u8 = undefined;
        const archive_name = try std.fmt.bufPrint(&name_buffer, "{s}/{s}/{d}.{d}.portable.eml{s}{s}", .{
            path,                                                              slot,  ustar_mtime orelse 0, sequence.*,
            if (std.mem.eql(u8, slot, "cur") or flags.len != 0) ":2," else "", flags,
        });
        sequence.* += 1;
        var header_name: []const u8 = archive_name;
        if (ustar_mtime == null) {
            // Keep the local PAX header immediately before the regular header.
            // Carry long paths in PAX too, instead of inserting a GNU long-name header here.
            var probe: Tar.Header = .{};
            const long_path = if (probe.setPath("", archive_name)) |_| false else |_| true;
            try writePaxTime(archive.underlying_writer, seconds, if (long_path) archive_name else null);
            if (long_path) header_name = "Maildir/portable-message";
        }
        var reader = file.reader(io, &read_buffer);
        try archive.writeFileStream(header_name, before.size, &reader.interface, .{ .mode = 0o600, .mtime = ustar_mtime orelse 0 });
        const after = try file.stat(io);
        if (after.size != before.size or after.mtime.nanoseconds != before.mtime.nanoseconds)
            return error.MailboxChangedDuringExport;
    }
}

fn writePaxTime(output: *std.Io.Writer, seconds: i64, path: ?[]const u8) !void {
    var time_buffer: [24]u8 = undefined;
    const time = try std.fmt.bufPrint(&time_buffer, "{d}", .{seconds});
    var record_buffer: [archive_path_capacity + 64]u8 = undefined;
    var records = std.Io.Writer.fixed(&record_buffer);
    try writePaxRecord(&records, "mtime", time);
    if (path) |name| try writePaxRecord(&records, "path", name);
    const payload = records.buffered();

    // std.tar.Writer has no PAX output API. Reuse its USTAR layout and numeric
    // fields, then set the local extended-header type and checksum on the bytes.
    var header: Tar.Header = .{};
    try header.setPath("", "PaxHeaders/mail-export");
    try header.setMode(0o600);
    try header.setSize(payload.len);
    var bytes = std.mem.asBytes(&header).*;
    bytes[@offsetOf(Tar.Header, "typeflag")] = 'x';
    const checksum_offset = @offsetOf(Tar.Header, "checksum");
    const checksum_field = bytes[checksum_offset..][0..8];
    @memset(checksum_field, ' ');
    var checksum: u32 = 0;
    for (bytes) |byte| checksum += byte;
    _ = try std.fmt.bufPrint(checksum_field, "{o:0>6}\x00 ", .{checksum});

    try output.writeAll(&bytes);
    try output.writeAll(payload);
    const block_size = @sizeOf(Tar.Header);
    try output.splatByteAll(0, (block_size - payload.len % block_size) % block_size);
}

fn writePaxRecord(writer: *std.Io.Writer, key: []const u8, value: []const u8) !void {
    // The decimal length includes itself, the separator, and the final newline.
    const body_length = key.len + value.len + " =\n".len;
    var length = body_length + 1;
    while (true) {
        const total = body_length + std.math.log10_int(length) + 1;
        if (length == total) break;
        length = total;
    }
    try writer.print("{d} {s}={s}\n", .{ length, key, value });
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
