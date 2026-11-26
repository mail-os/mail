//! Standalone Maildir reader for webmail.
//!
//! The IMAP server reads mail through a stateful per-connection `ImapSession`,
//! which we can't reuse from an HTTP handler. This module provides a small,
//! stateless reader over the same on-disk layout and the same SQLite UID tables,
//! so webmail and IMAP agree on folders, message identity (UID), and flags.
//!
//! Layout (relative to the server's cwd, matching imap.zig):
//!   INBOX        -> mail/{user}/new  +  mail/{user}/cur   (aggregated)
//!   <Folder>     -> mail/{user}/<Folder>
//! where {user} is the local part of the address (no domain).
//!
//! Flags come from the Maildir `:2,FLAGS` filename suffix (see imap.MaildirFlags).
//! UIDs are resolved via db.getUidForFile / db.assignUid, which key on the
//! Maildir BASE name (suffix stripped, see database.maildirBaseName) — identical
//! to what IMAP's syncUids resolves to — so a message keeps the same UID across
//! flag changes and is identified the same way in webmail and over IMAP.
//!
//! Allocation model: callers pass an allocator that is expected to be an arena
//! (the HTTP layer uses a per-request arena). Nothing here frees individually;
//! the caller frees the arena wholesale. This deliberately trades a little
//! transient memory for a large reduction in free-path bugs in a security- and
//! correctness-sensitive module.

const std = @import("std");
const builtin = @import("builtin");
const categories = @import("../message/categories.zig");
const attention = @import("webmail_attention.zig");
const calendar_invite = @import("webmail_calendar_invite.zig");
const search_index = @import("webmail_index.zig");
const html_text = @import("../antispam/html_text.zig");
const mime_lib = @import("../message/mime.zig").lib;
const webmail_mime = @import("webmail_mime.zig");
const thread_ids = @import("../message/thread_ids.zig");
const maildir_index = @import("../search/maildir_index.zig");
const ascii_compat = @import("ascii-compat");
const fs_compat = @import("../core/fs_compat.zig");
const hosted_limits = @import("../storage/hosted_limits.zig");
const database = @import("../storage/database.zig");
const maildir_keywords = @import("../storage/maildir_keywords.zig");
const message_refs = @import("../storage/message_refs.zig");
const imap = @import("../protocol/imap.zig");
const time_compat = @import("../core/time_compat.zig");

pub const MaildirError = error{
    InvalidFolderName,
    MessageNotFound,
    WriteFailed,
    Conflict,
    RevisionMismatch,
};

/// The set of folders webmail exposes. Order is the display order.
pub const standard_folders = [_][]const u8{
    "INBOX",
    "Newsletters",
    "Receipts",
    "Sent",
    "Drafts",
    "Trash",
    "Junk",
    "Archive",
};

pub const FolderInfo = struct {
    name: []const u8,
    total: usize,
    unread: usize,
};

pub const Flags = struct {
    seen: bool = false,
    answered: bool = false,
    flagged: bool = false,
    draft: bool = false,
    deleted: bool = false,
};

/// A message summary for list views (no body).
pub const MessageSummary = struct {
    uid: i64,
    from: []const u8,
    to: []const u8,
    subject: []const u8,
    date: []const u8,
    /// First ~200 chars of the decoded text body, best-effort.
    snippet: []const u8,
    flags: Flags,
    has_attachments: bool,
    size: u64,
    folder: []const u8 = "INBOX",
    message_id: []const u8 = "",
    in_reply_to: []const u8 = "",
    references: []const u8 = "",
    timestamp: i64 = 0,
    matches_filters: bool = true,
    snapshot: ?SummarySnapshot = null,
    attention_deadline: i64 = 0,
    indexed_attachments: []const search_index.Attachment = &.{},
    personal_subject: ?[]const u8 = null,
    manual_component: ?[]const u8 = null,
};

const SummarySnapshot = struct { file: FileRef, stamp: []const u8, digest: [64]u8, fingerprint: ?[]const u8 = null };

/// A fully parsed message for the reading pane.
pub const MessageDetail = struct {
    uid: i64,
    folder: []const u8 = "INBOX",
    timestamp: i64 = 0,
    version: ?MessageVersion = null,
    from: []const u8,
    to: []const u8,
    cc: []const u8,
    bcc: []const u8,
    reply_to: []const u8,
    in_reply_to: []const u8,
    references: []const u8,
    subject: []const u8,
    date: []const u8,
    message_id: []const u8,
    /// Decoded text/plain part (may be empty).
    text_body: []const u8,
    /// Raw text/html part (may be empty). NOT sanitized — the frontend renders
    /// it in a sandboxed iframe (WEBMAIL.md Phase 8).
    html_body: []const u8,
    flags: Flags,
    attachments: []const AttachmentInfo,
    calendar_parts: []const calendar_invite.Part = &.{},
    calendar_only: bool = false,
    size: u64,
};

pub const MessageVersion = struct {
    reference: []const u8,
    revision: []const u8,
    content_revision: [64]u8,
};

pub const MessageLocator = struct { folder: []const u8, uid: i64 };

pub const SummaryLocation = struct { folder: []const u8, basename: []const u8, stamp: []const u8 };

pub fn summaryLocation(row: MessageSummary) ?SummaryLocation {
    const snapshot = row.snapshot orelse return null;
    const location = message_refs.location(row.folder, snapshot.file.name);
    return .{ .folder = location.folder, .basename = location.basename, .stamp = snapshot.stamp };
}

pub fn isPersonalFolder(folder: []const u8) bool {
    for ([_][]const u8{ "Drafts", "Screening", "Declined" }) |hidden| {
        if (std.ascii.eqlIgnoreCase(folder, hidden)) return false;
    }
    return true;
}

pub const AttachmentInfo = webmail_mime.AttachmentInfo;

/// Validate a folder name against path traversal and separators. We only allow
/// the standard set plus simple alphanumeric user folders.
pub fn isValidFolderName(name: []const u8) bool {
    if (name.len == 0 or name.len > 128) return false;
    for (standard_folders) |f| {
        if (std.mem.eql(u8, name, f)) return true;
    }
    // Allow simple custom folders: letters, digits, space, underscore, dash.
    for (name) |c| {
        const ok = std.ascii.isAlphanumeric(c) or c == ' ' or c == '_' or c == '-';
        if (!ok) return false;
    }
    // Reject anything that could traverse or reference hidden/special dirs.
    if (std.mem.indexOf(u8, name, "..") != null) return false;
    if (name[0] == '.') return false;
    return true;
}

pub fn flagsFrom(filename: []const u8) Flags {
    const mf = imap.MaildirFlags.fromFilename(filename);
    return .{
        .seen = mf.seen,
        .answered = mf.answered,
        .flagged = mf.flagged,
        .draft = mf.draft,
        .deleted = mf.deleted,
    };
}

/// One physical message file: which directory it lives in and its filename.
pub const FileRef = struct {
    dir: []const u8,
    name: []const u8,
    sort_key: i64 = 0,
};

const extractBody = webmail_mime.extract;
const BodyParts = webmail_mime.BodyParts;
pub const inspectAttachment = webmail_mime.inspectAttachment;

/// Collect the message files for a folder, in stable IMAP order. The returned
/// slices are arena-allocated.
pub fn collectFiles(allocator: std.mem.Allocator, user: []const u8, folder: []const u8) ![]FileRef {
    return collectFilesAtRoot(allocator, "mail", user, folder);
}

fn collectFilesAtRoot(allocator: std.mem.Allocator, root: []const u8, user: []const u8, folder: []const u8) ![]FileRef {
    var refs: std.ArrayList(FileRef) = .empty;

    if (std.ascii.eqlIgnoreCase(folder, "INBOX")) {
        const new_dir = try std.fmt.allocPrint(allocator, "{s}/{s}/new", .{ root, user });
        const cur_dir = try std.fmt.allocPrint(allocator, "{s}/{s}/cur", .{ root, user });
        try appendDir(allocator, &refs, new_dir);
        try appendDir(allocator, &refs, cur_dir);
    } else {
        const dir = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}", .{ root, user, folder });
        try appendDir(allocator, &refs, dir);
    }

    // Merge new/ and cur/ in the same oldest-first order IMAP uses before
    // assigning UIDs. Concatenating directory lists changes identity/order.
    std.mem.sort(FileRef, refs.items, {}, struct {
        fn lessThan(_: void, left: FileRef, right: FileRef) bool {
            if (left.sort_key != right.sort_key) return left.sort_key < right.sort_key;
            return std.mem.order(u8, left.name, right.name) == .lt;
        }
    }.lessThan);
    return refs.toOwnedSlice(allocator);
}

fn appendDir(allocator: std.mem.Allocator, refs: *std.ArrayList(FileRef), dir: []const u8) !void {
    const files = fs_compat.listEmlFilesUnsorted(allocator, dir) catch return;
    for (files) |name| {
        try refs.append(allocator, .{ .dir = dir, .name = name, .sort_key = imap.parseMessageSortKey(name) });
    }
}

/// Resolve the UID for a file via the shared SQLite tables (same as IMAP).
fn uidFor(db: *database.Database, user: []const u8, folder: []const u8, filename: []const u8, fallback: i64) i64 {
    if (db.getUidForFile(user, folder, filename) catch null) |uid| return uid;
    return db.assignUid(user, folder, filename) catch fallback;
}

/// Pre-assign UIDs for all files in oldest-first order.
///
/// CRITICAL for IMAP consistency: IMAP's syncUids assigns UIDs by iterating
/// files oldest-first (so the oldest message gets the lowest UID). Webmail
/// displays newest-first, so if we assigned UIDs lazily during the reverse
/// display walk, the newest message would grab UID 1 on a fresh mailbox —
/// disagreeing with IMAP. Walking forward here guarantees the same UID->file
/// mapping regardless of which service touches the mailbox first.
fn preassignUids(db: *database.Database, user: []const u8, folder: []const u8, refs: []const FileRef) void {
    for (refs, 0..) |r, i| {
        _ = uidFor(db, user, folder, r.name, @intCast(i + 1));
    }
}

fn syncFolderUids(a: std.mem.Allocator, db: *database.Database, user: []const u8, folder: []const u8, refs: []const FileRef) !?[]i64 {
    if (refs.len == 0) return &.{};
    const names = try a.alloc([]const u8, refs.len);
    defer a.free(names);
    for (refs, names) |ref, *name| name.* = ref.name;
    return db.syncMailboxUids(a, user, folder, names) catch {
        preassignUids(db, user, folder, refs);
        return null;
    };
}

/// List visible standard and custom folders with total and unread counts.
pub fn listFolders(allocator: std.mem.Allocator, db: *database.Database, user: []const u8, junk_folder: []const u8) ![]FolderInfo {
    var out: std.ArrayList(FolderInfo) = .empty;
    var names: std.ArrayList([]const u8) = .empty;
    try names.appendSlice(allocator, try folderNames(allocator, db, user));
    for (names.items) |folder| {
        if (std.mem.eql(u8, folder, junk_folder)) break;
    } else try names.append(allocator, junk_folder);
    for (names.items) |folder| {
        const refs = collectFiles(allocator, user, folder) catch &[_]FileRef{};
        var unread: usize = 0;
        for (refs) |r| {
            const fl = flagsFrom(r.name);
            if (!fl.seen and !fl.deleted) unread += 1;
        }
        try out.append(allocator, .{
            .name = folder,
            .total = refs.len,
            .unread = unread,
        });
    }
    return out.toOwnedSlice(allocator);
}

pub fn folderExists(allocator: std.mem.Allocator, user: []const u8, folder: []const u8) !bool {
    if (!isValidFolderName(folder)) return false;
    if (std.ascii.eqlIgnoreCase(folder, "INBOX")) return true;
    const path = try std.fmt.allocPrintSentinel(allocator, "mail/{s}/{s}", .{ user, folder }, 0);
    defer allocator.free(path);
    const directory = std.c.opendir(path) orelse return false;
    _ = std.c.closedir(directory);
    return true;
}

/// List message summaries for a folder, newest first, paginated.
/// `page` is 1-based; `per_page` caps the result count.
pub fn listMessages(
    allocator: std.mem.Allocator,
    db: *database.Database,
    user: []const u8,
    folder: []const u8,
    page: usize,
    per_page: usize,
) ![]MessageSummary {
    return (try listMessagePage(allocator, db, user, folder, page, per_page, "")).items;
}

pub const MessagePage = struct { items: []MessageSummary, total: usize };

/// Search the complete folder before pagination. Per-file scratch arenas keep
/// scanning large mailboxes from retaining every decoded body in memory.
pub fn listMessagePage(
    allocator: std.mem.Allocator,
    db: *database.Database,
    user: []const u8,
    folder: []const u8,
    page: usize,
    per_page: usize,
    query: []const u8,
) !MessagePage {
    return listPage(allocator, db, user, folder, page, per_page, query, false);
}

pub fn listSharedInboxPage(a: std.mem.Allocator, db: *database.Database, user: []const u8, page: usize, per_page: usize) !MessagePage {
    return listPage(a, db, user, "INBOX", page, per_page, "", true);
}

fn listPage(
    allocator: std.mem.Allocator,
    db: *database.Database,
    user: []const u8,
    folder: []const u8,
    page: usize,
    per_page: usize,
    query: []const u8,
    shared: bool,
) !MessagePage {
    if (!isValidFolderName(folder)) return MaildirError.InvalidFolderName;
    _ = try db.getOrCreateMailbox(user, folder);
    const refs = try collectFiles(allocator, user, folder);
    preassignUids(db, user, folder, refs);
    const start = std.math.mul(usize, page -| 1, per_page) catch std.math.maxInt(usize);
    var out: std.ArrayList(MessageSummary) = .empty;
    var total: usize = 0;
    var remaining = refs.len;
    while (remaining > 0) {
        remaining -= 1;
        const r = refs[remaining];
        const flags = flagsFrom(r.name);
        if (shared and flags.deleted) continue;
        if (query.len == 0 and (total < start or out.items.len >= per_page)) {
            total += 1;
            continue;
        }
        var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer scratch.deinit();
        const a = scratch.allocator();
        const path = try std.fmt.allocPrint(a, "{s}/{s}", .{ r.dir, r.name });
        const captured: FileSnapshot = if (shared) snapFile(a, db, path) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        } else .{ .raw = fs_compat.readFileAlloc(a, path) catch continue, .stamp = "" };
        const raw = captured.raw;
        const headers = parseHeaders(a, raw) catch HeaderSet{};
        const body = extractBody(a, raw, .preview) catch BodyParts{};
        if (query.len > 0 and !matchesQuery(headers, body, query)) continue;
        const position = total;
        total += 1;
        if (position < start or out.items.len >= per_page) continue;
        try out.append(allocator, .{
            .uid = uidFor(db, user, folder, r.name, @intCast(remaining + 1)),
            .from = try allocator.dupe(u8, headers.from),
            .to = try allocator.dupe(u8, headers.to),
            .subject = try allocator.dupe(u8, headers.subject),
            .date = try allocator.dupe(u8, headers.date),
            .snippet = try makeSnippet(allocator, body.text),
            .flags = flags,
            .has_attachments = body.has_attachments,
            .size = raw.len,
            .folder = try allocator.dupe(u8, folder),
            .message_id = try allocator.dupe(u8, headers.message_id),
            .in_reply_to = try allocator.dupe(u8, headers.in_reply_to),
            .references = try allocator.dupe(u8, headers.references),
            .timestamp = messageTimestamp(headers.date, r.name),
            .snapshot = if (shared) .{ .file = r, .stamp = try allocator.dupe(u8, captured.stamp), .digest = message_refs.digest(raw) } else null,
        });
    }
    return .{ .items = try out.toOwnedSlice(allocator), .total = total };
}

fn matchesQuery(headers: HeaderSet, body: BodyParts, query: []const u8) bool {
    for ([_][]const u8{ headers.from, headers.to, headers.cc, headers.subject, body.text }) |value| {
        if (ascii_compat.indexOfIgnoreCase(value, query) != null) return true;
    }
    return false;
}

pub const SearchMatch = struct { from: []const u8, to: []const u8, subject: []const u8, text: []const u8 };

/// Search decoded headers and plain text without decoding binary attachments.
pub fn matchMime(allocator: std.mem.Allocator, raw: []const u8, keywords: []const u8) !?SearchMatch {
    const headers = try parseHeaders(allocator, raw);
    const body = try extractBody(allocator, raw, .preview);
    var terms = std.mem.tokenizeAny(u8, keywords, &std.ascii.whitespace);
    while (terms.next()) |term| {
        if (!matchesQuery(headers, body, term)) return null;
    }
    return .{ .from = headers.from, .to = headers.to, .subject = headers.subject, .text = body.text };
}

pub const QueryOptions = struct {
    include_versions: bool = false,
    folder: []const u8 = "INBOX",
    query: []const u8 = "",
    sender: []const u8 = "",
    recipient: []const u8 = "",
    filename: []const u8 = "",
    after: ?i64 = null,
    before: ?i64 = null,
    unread: bool = false,
    read: bool = false,
    answered: bool = false,
    flagged: bool = false,
    attachments: bool = false,
    /// Include conversation context in scan order. Grouping sorts the members
    /// of retained conversations after determining which components match.
    include_context: bool = false,
    attention_snapshot: ?attention.Snapshot = null,
    attention_view: ?attention.Kind = null,
    headers_only: bool = false,
    unread_queue: bool = false,
    list_attachments: bool = false,
    index_budget: usize = std.math.maxInt(usize),
    index_progress: ?*search_index.Progress = null,
};

/// Includes custom folders already known to IMAP. All results stay within the
/// canonical full-address account; no global Maildir fallback is permitted.
pub fn folderNames(allocator: std.mem.Allocator, db: *database.Database, user: []const u8) ![]const []const u8 {
    var names: std.ArrayList([]const u8) = .empty;
    try names.appendSlice(allocator, &standard_folders);
    const s = try db.prepare(
        \\SELECT m.mailbox,g.uidvalidity FROM imap_mailboxes m
        \\LEFT JOIN imap_mailbox_generations g USING(username,mailbox)
        \\WHERE m.username=?1 ORDER BY m.mailbox
    );
    defer s.finalize();
    try s.bind(1, user);
    while (try s.step()) {
        const name = s.columnText(0);
        if (!isValidFolderName(name) or std.ascii.eqlIgnoreCase(name, "Screening") or std.ascii.eqlIgnoreCase(name, "Declined")) continue;
        if (s.columnInt64Opt(1) != null and !try folderExists(allocator, user, name)) continue;
        var exists = false;
        for (names.items) |known| {
            // Existing custom folders may differ from the category only by
            // case. Keep them searchable on case-sensitive Maildir volumes.
            if (!std.ascii.eqlIgnoreCase(known, name)) continue;
            if (categories.isCategory(known) and !std.mem.eql(u8, known, name) and
                !try sameFolderDirectory(allocator, user, known, name)) continue;
            exists = true;
            break;
        }
        if (!exists) try names.append(allocator, try allocator.dupe(u8, name));
    }
    return names.toOwnedSlice(allocator);
}

fn sameFolderDirectory(a: std.mem.Allocator, user: []const u8, first: []const u8, second: []const u8) !bool {
    const left = try std.fmt.allocPrintSentinel(a, "mail/{s}/{s}", .{ user, first }, 0);
    const right = try std.fmt.allocPrintSentinel(a, "mail/{s}/{s}", .{ user, second }, 0);
    defer a.free(left);
    defer a.free(right);
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var l = std.mem.zeroes(linux.Statx);
        var r = std.mem.zeroes(linux.Statx);
        if (linux.errno(linux.statx(linux.AT.FDCWD, left, linux.AT.SYMLINK_NOFOLLOW, .{ .INO = true }, &l)) != .SUCCESS or !l.mask.INO) return false;
        if (linux.errno(linux.statx(linux.AT.FDCWD, right, linux.AT.SYMLINK_NOFOLLOW, .{ .INO = true }, &r)) != .SUCCESS or !r.mask.INO) return false;
        return l.ino == r.ino and l.dev_major == r.dev_major and l.dev_minor == r.dev_minor;
    }
    var l: std.c.Stat = undefined;
    var r: std.c.Stat = undefined;
    if (std.c.fstatat(std.c.AT.FDCWD, left, &l, std.c.AT.SYMLINK_NOFOLLOW) != 0) return false;
    if (std.c.fstatat(std.c.AT.FDCWD, right, &r, std.c.AT.SYMLINK_NOFOLLOW) != 0) return false;
    return l.ino == r.ino and l.dev == r.dev;
}

/// Header-only conversation links across this account's visible mail. A
/// private action can retain a link through an intermediate reply without
/// reading or indexing every attachment in the account.
pub fn conversationLinks(a: std.mem.Allocator, db: *database.Database, user: []const u8) ![][]const []const u8 {
    var links: std.ArrayList([]const []const u8) = .empty;
    var header: [32 * 1024]u8 = undefined;
    for (try folderNames(a, db, user)) |folder| {
        if (!isPersonalFolder(folder)) continue;
        var scan = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer scan.deinit();
        for (try collectFiles(scan.allocator(), user, folder)) |ref| {
            var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer scratch.deinit();
            const temporary = scratch.allocator();
            const path = try std.fmt.allocPrint(temporary, "{s}/{s}", .{ ref.dir, ref.name });
            const file = fs_compat.cwd().openFile(path, .{}) catch continue;
            defer file.close();
            const length = file.readAll(&header) catch continue;
            const ids = try thread_ids.parse(temporary, header[0..length]);
            const keys = try ids.keys(temporary);
            if (keys.len < 2) continue;
            const owned = try a.alloc([]const u8, keys.len);
            for (keys, owned) |key, *item| item.* = try a.dupe(u8, key);
            try links.append(a, owned);
        }
    }
    return links.toOwnedSlice(a);
}

/// Scan once, filter before pagination, and avoid decoding binary attachments
/// for search and list previews. Threading consumes these same header records.
pub fn queryMessages(allocator: std.mem.Allocator, db: *database.Database, user: []const u8, options: QueryOptions) ![]MessageSummary {
    const names = if (std.mem.eql(u8, options.folder, "*")) try folderNames(allocator, db, user) else blk: {
        if (!isValidFolderName(options.folder)) return MaildirError.InvalidFolderName;
        const one = try allocator.alloc([]const u8, 1);
        one[0] = if (std.ascii.eqlIgnoreCase(options.folder, "INBOX")) "INBOX" else options.folder;
        break :blk one;
    };
    if (options.query.len > 0 or options.sender.len > 0 or options.recipient.len > 0 or options.filename.len > 0 or
        options.attachments or options.list_attachments or options.after != null or options.before != null or
        options.read or options.answered or options.flagged or (options.unread and !options.unread_queue))
        return queryIndexed(allocator, db, user, names, options);
    var rows: std.ArrayList(MessageSummary) = .empty;
    for (names) |folder| {
        if (options.unread_queue and std.ascii.eqlIgnoreCase(folder, "Drafts")) continue;
        _ = try db.getOrCreateMailbox(user, folder);
        const refs = try collectFiles(allocator, user, folder);
        const uids = try syncFolderUids(allocator, db, user, folder, refs);
        for (refs, 0..) |ref, index| {
            const basename = database.maildirBaseName(ref.name);
            if (options.attention_view) |kind| {
                if (!options.attention_snapshot.?.mayContain(kind, folder, basename)) continue;
            }
            const flags = flagsFrom(ref.name);
            if (options.unread_queue and flags.deleted) continue;
            const flags_match = !(options.unread and flags.seen) and !(options.flagged and !flags.flagged);
            if (!flags_match and !options.include_context) continue;
            var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer scratch.deinit();
            const a = scratch.allocator();
            const path = try std.fmt.allocPrint(a, "{s}/{s}", .{ ref.dir, ref.name });
            const stamped = options.include_versions or options.attention_snapshot != null;
            const captured: FileSnapshot = if (stamped) snapFile(a, db, path) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => return err,
            } else .{ .raw = fs_compat.readFileAlloc(a, path) catch continue, .stamp = "" };
            const raw = captured.raw;
            const attention_deadline: i64 = if (options.attention_view) |kind|
                options.attention_snapshot.?.deadline(kind, folder, basename, captured.stamp) orelse continue
            else
                0;
            if (options.attention_view == null and attention.isInboxView(options.folder)) {
                if (options.attention_snapshot) |snapshot| {
                    const status = snapshot.status("", folder, basename, captured.stamp, try thread_ids.parse(a, raw));
                    if (status.muted or status.snooze_until != null) continue;
                }
            }
            const headers = parseHeaders(a, raw) catch HeaderSet{};
            const stamp = messageTimestamp(headers.date, ref.name);
            const body = if (options.headers_only) BodyParts{} else extractBody(a, raw, .preview) catch BodyParts{};
            const matches = flags_match and
                (options.sender.len == 0 or ascii_compat.indexOfIgnoreCase(headers.from, options.sender) != null) and
                (options.after == null or stamp >= options.after.?) and
                (options.before == null or stamp <= options.before.?) and
                (!options.attachments or body.has_attachments) and
                (options.query.len == 0 or matchesQuery(headers, body, options.query));
            if (!matches and !options.include_context) continue;
            try rows.append(allocator, .{
                .uid = if (uids) |assigned| assigned[index] else uidFor(db, user, folder, ref.name, @intCast(index + 1)),
                .folder = try allocator.dupe(u8, folder),
                .from = try allocator.dupe(u8, headers.from),
                .to = try allocator.dupe(u8, headers.to),
                .subject = try allocator.dupe(u8, headers.subject),
                .date = try allocator.dupe(u8, headers.date),
                .message_id = try allocator.dupe(u8, headers.message_id),
                .in_reply_to = try allocator.dupe(u8, headers.in_reply_to),
                .references = try allocator.dupe(u8, headers.references),
                .timestamp = stamp,
                .snippet = try makeSnippet(allocator, body.text),
                .flags = flags,
                .has_attachments = body.has_attachments,
                .size = raw.len,
                .matches_filters = matches,
                .attention_deadline = attention_deadline,
                .snapshot = if (options.include_versions) .{
                    .file = ref,
                    .stamp = try allocator.dupe(u8, captured.stamp),
                    .digest = message_refs.digest(raw),
                } else null,
            });
        }
    }
    if (!options.include_context) sortSummaries(rows.items);
    return rows.toOwnedSlice(allocator);
}

pub fn sortSummaries(rows: []MessageSummary) void {
    std.mem.sort(MessageSummary, rows, {}, struct {
        fn lessThan(_: void, left: MessageSummary, right: MessageSummary) bool {
            if (left.attention_deadline != right.attention_deadline) return left.attention_deadline < right.attention_deadline;
            return messagePosition(left).before(messagePosition(right));
        }
    }.lessThan);
}

fn queryIndexed(a: std.mem.Allocator, db: *database.Database, user: []const u8, folders: []const []const u8, options: QueryOptions) ![]MessageSummary {
    var rows: std.ArrayList(MessageSummary) = .empty;
    var progress: search_index.Progress = .{};
    var remaining = options.index_budget;
    const include_unmatched = options.include_context or options.attention_snapshot != null;
    for (folders) |folder| {
        // Review copies appear only in the explicit Sender Review workspace.
        if (std.ascii.eqlIgnoreCase(folder, "Screening") or std.ascii.eqlIgnoreCase(folder, "Declined")) continue;
        if (options.unread_queue and std.ascii.eqlIgnoreCase(folder, "Drafts")) continue;
        var scope = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer scope.deinit();
        const temporary = scope.allocator();
        _ = try db.getOrCreateMailbox(user, folder);
        // File names and their UIDs must be assigned in IMAP order. The
        // catalogue uses the same folder and Maildir basename as webmail.
        const refs = try collectFiles(a, user, folder);
        var cached = try search_index.load(temporary, db, user, folder, options.query, include_unmatched);
        var needs_uid_sync = false;
        for (refs) |ref| {
            if (cached.getPtr(database.maildirBaseName(ref.name))) |item| {
                item.observed = true;
                if (item.uid != null) continue;
            }
            needs_uid_sync = true;
        }
        // A warm catalogue can read the existing UID mappings in the same
        // snapshot. New files still use the ordered, transactional assignment.
        const uids = if (needs_uid_sync) try syncFolderUids(temporary, db, user, folder, refs) else null;
        var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer scratch.deinit();
        for (refs, 0..) |ref, index| {
            const basename = database.maildirBaseName(ref.name);
            const cached_doc = cached.getPtr(basename);
            if (options.attention_view) |kind| {
                if (!options.attention_snapshot.?.mayContain(kind, folder, basename)) continue;
            }
            _ = scratch.reset(.retain_capacity);
            const work = scratch.allocator();
            const path = try std.fmt.allocPrint(work, "{s}/{s}", .{ ref.dir, ref.name });
            const identity = message_refs.fileFingerprint(work, path) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => return err,
            };
            const doc = document: {
                if (cached_doc) |item| {
                    if (std.mem.startsWith(u8, item.fingerprint, index_fingerprint_prefix) and
                        std.mem.eql(u8, item.fingerprint[index_fingerprint_prefix.len..], identity.fingerprint)) break :document item.*;
                }
                if (remaining == 0) {
                    progress.total += 1;
                    continue;
                }
                const item = (try indexFile(work, db, user, folder, basename, path, identity.fingerprint, options.query)) orelse continue;
                remaining -= 1;
                break :document item;
            };
            progress.total += 1;
            progress.indexed += 1;
            if (!doc.matches and !include_unmatched) continue;
            const flags = flagsFrom(ref.name);
            if (options.unread_queue and flags.deleted) continue;
            const deadline = if (options.attention_view) |kind|
                options.attention_snapshot.?.deadline(kind, folder, basename, identity.stamp) orelse continue
            else
                0;
            if (options.attention_view == null and attention.isInboxView(options.folder)) {
                if (options.attention_snapshot) |workflow| {
                    const ids = try thread_ids.fromFields(work, doc.message_id, doc.in_reply_to, doc.references);
                    const status = workflow.status("", folder, basename, identity.stamp, ids);
                    if (status.muted or status.snooze_until != null) continue;
                }
            }
            const timestamp = messageTimestamp(doc.date, ref.name);
            const has_attachments = !std.mem.eql(u8, doc.attachment_metadata, "[]");
            const matches_message = doc.matches and
                (!options.unread or !flags.seen) and (!options.read or flags.seen) and
                (!options.answered or flags.answered) and (!options.flagged or flags.flagged) and
                contains(doc.sender, options.sender) and
                (contains(doc.recipient, options.recipient) or contains(doc.cc, options.recipient) or contains(doc.bcc, options.recipient)) and
                (options.after == null or timestamp >= options.after.?) and
                (options.before == null or timestamp <= options.before.?) and
                (!options.attachments or has_attachments);
            var files: std.ArrayList(search_index.Attachment) = .empty;
            if (matches_message and has_attachments and (options.list_attachments or options.filename.len > 0)) {
                const metadata = try std.json.parseFromSliceLeaky([]const search_index.Attachment, work, doc.attachment_metadata, .{});
                for (metadata) |file| if (contains(file.filename, options.filename)) {
                    try files.append(work, file);
                };
            }
            const matches = matches_message and
                (!(options.list_attachments or options.filename.len > 0) or files.items.len > 0);
            if (!matches and !options.include_context) continue;
            const attachments: []search_index.Attachment = if (options.list_attachments) try a.dupe(search_index.Attachment, files.items) else &.{};
            for (attachments) |*file| {
                file.filename = try a.dupe(u8, file.filename);
                file.content_type = try a.dupe(u8, file.content_type);
            }
            try rows.append(a, .{
                .uid = if (uids) |assigned| assigned[index] else if (needs_uid_sync)
                    uidFor(db, user, folder, ref.name, @intCast(index + 1))
                else
                    cached_doc.?.uid.?,
                .folder = folder,
                .from = try a.dupe(u8, doc.sender),
                .to = try a.dupe(u8, doc.recipient),
                .subject = try a.dupe(u8, doc.subject),
                .date = try a.dupe(u8, doc.date),
                .message_id = try a.dupe(u8, doc.message_id),
                .in_reply_to = try a.dupe(u8, doc.in_reply_to),
                .references = try a.dupe(u8, doc.references),
                .timestamp = timestamp,
                .snippet = try a.dupe(u8, doc.snippet),
                .flags = flags,
                .has_attachments = has_attachments,
                .size = identity.size,
                .matches_filters = matches,
                .attention_deadline = deadline,
                .indexed_attachments = attachments,
                .snapshot = if (options.include_versions) .{
                    .file = ref,
                    .stamp = try a.dupe(u8, identity.stamp),
                    .digest = doc.digest,
                    .fingerprint = try a.dupe(u8, identity.fingerprint),
                } else null,
            });
        }
        var documents = cached.valueIterator();
        while (documents.next()) |doc| {
            if (doc.observed) continue;
            try pruneSearchFolder(temporary, db, user, folder, &cached);
            break;
        }
    }
    if (std.mem.eql(u8, options.folder, "*")) {
        db.lockMailboxes();
        defer db.unlockMailboxes();
        const current = try folderNames(a, db, user);
        try search_index.pruneFolders(db, user, try std.json.Stringify.valueAlloc(a, current, .{}));
    }
    if (options.index_progress) |report| report.* = progress;
    if (!progress.complete()) return rows.items[0..0];
    if (!options.include_context) sortSummaries(rows.items);
    return rows.toOwnedSlice(a);
}

fn pruneSearchFolder(a: std.mem.Allocator, db: *database.Database, user: []const u8, folder: []const u8, cached: *std.StringHashMap(search_index.Document)) !void {
    db.lockMailboxes();
    defer db.unlockMailboxes();
    // A folder may have changed since enumeration. Recheck before
    // removing a document another request could need.
    for (try collectFiles(a, user, folder)) |file| {
        if (cached.getPtr(database.maildirBaseName(file.name))) |item| item.observed = true;
    }
    var previous = cached.iterator();
    while (previous.next()) |record| {
        if (!record.value_ptr.observed)
            try search_index.prune(db, user, folder, record.key_ptr.*, record.value_ptr.fingerprint);
    }
}

fn contains(value: []const u8, needle: []const u8) bool {
    return needle.len == 0 or ascii_compat.indexOfIgnoreCase(value, needle) != null;
}

// Reconcile cached headers, text and attachment indexes after the MIME parser changes.
const index_fingerprint_prefix = "mime-v2:";

fn indexFile(a: std.mem.Allocator, db: *database.Database, user: []const u8, folder: []const u8, basename: []const u8, path: []const u8, fingerprint: []const u8, query: []const u8) !?search_index.Document {
    const raw = fs_compat.readFileAlloc(a, path) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    const headers = try parseHeaders(a, raw);
    var body = try extractBody(a, raw, .metadata);
    if (body.text.len == 0 and body.html.len > 0) body.text = html_text.extract(body.html, try a.alloc(u8, body.html.len));
    var metadata: std.ArrayList(search_index.Attachment) = .empty;
    for (body.attachments, 0..) |file, index| {
        try metadata.append(a, .{
            .filename = if (std.unicode.utf8ValidateSlice(file.filename)) file.filename else "attachment",
            .content_type = if (std.unicode.utf8ValidateSlice(file.content_type)) file.content_type else "application/octet-stream",
            .size = file.size,
            .index = index,
        });
    }
    const doc: search_index.Document = .{
        .fingerprint = try std.mem.concat(a, u8, &.{ index_fingerprint_prefix, fingerprint }),
        .digest = message_refs.digest(raw),
        .sender = headers.from,
        .recipient = headers.to,
        .cc = headers.cc,
        .bcc = headers.bcc,
        .subject = headers.subject,
        .date = headers.date,
        .message_id = headers.message_id,
        .in_reply_to = headers.in_reply_to,
        .references = headers.references,
        .snippet = try makeSnippet(a, body.text),
        .attachment_metadata = try std.json.Stringify.valueAlloc(a, metadata.items, .{}),
        .matches = query.len == 0 or matchesQuery(headers, body, query) or contains(headers.bcc, query),
    };
    db.lockMailboxes();
    defer db.unlockMailboxes();
    const fresh = message_refs.fileFingerprint(a, path) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    if (!std.mem.eql(u8, fingerprint, fresh.fingerprint)) return null;
    try search_index.store(db, user, folder, basename, doc, body.text);
    return doc;
}

pub const MessagePosition = struct {
    timestamp: i64,
    folder: []const u8,
    uid: i64,

    pub fn before(left: MessagePosition, right: MessagePosition) bool {
        if (left.timestamp != right.timestamp) return left.timestamp > right.timestamp;
        const order = std.mem.order(u8, left.folder, right.folder);
        if (order != .eq) return order == .lt;
        return left.uid > right.uid;
    }
};

pub fn messagePosition(row: MessageSummary) MessagePosition {
    return .{ .timestamp = row.timestamp, .folder = row.folder, .uid = row.uid };
}

const FileSnapshot = struct { raw: []const u8, stamp: []const u8 };

fn snapFile(a: std.mem.Allocator, db: *database.Database, path: []const u8) !FileSnapshot {
    db.lockMailboxes();
    defer db.unlockMailboxes();
    return .{ .stamp = try message_refs.fileStamp(a, path), .raw = try fs_compat.readFileAlloc(a, path) };
}

pub fn rawMessage(allocator: std.mem.Allocator, db: *database.Database, user: []const u8, folder: []const u8, uid: i64) ![]const u8 {
    if (!isValidFolderName(folder)) return MaildirError.InvalidFolderName;
    const ref = (try findByUid(allocator, db, user, folder, uid)) orelse return MaildirError.MessageNotFound;
    return fs_compat.readFileAlloc(allocator, try std.fmt.allocPrint(allocator, "{s}/{s}", .{ ref.dir, ref.name }));
}

/// RFC 5322 numeric-offset dates, with arrival-time fallback for malformed or
/// obsolete dates. Filters and ordering use the same timestamp.
pub fn messageTimestamp(date: []const u8, filename: []const u8) i64 {
    if (parseDate(date)) |stamp| return stamp;
    const arrival = imap.parseMessageSortKey(filename);
    return if (arrival > 10_000_000_000) @divTrunc(arrival, 1000) else arrival;
}

fn parseDate(date: []const u8) ?i64 {
    var words: [10][]const u8 = undefined;
    var count: usize = 0;
    var it = std.mem.tokenizeAny(u8, date, " ,:\t\r\n");
    while (it.next()) |word| {
        if (count == words.len) break;
        words[count] = word;
        count += 1;
    }
    if (count < 7) return null;
    const start: usize = if (std.ascii.isDigit(words[0][0])) 0 else 1;
    if (count < start + 7) return null;
    const day = std.fmt.parseInt(i64, words[start], 10) catch return null;
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    var month: i64 = 0;
    for (months, 0..) |name, index| if (std.ascii.eqlIgnoreCase(name, words[start + 1])) {
        month = @intCast(index + 1);
        break;
    };
    var year = std.fmt.parseInt(i64, words[start + 2], 10) catch return null;
    if (year < 100) year += if (year < 50) @as(i64, 2000) else @as(i64, 1900);
    const hour = std.fmt.parseInt(i64, words[start + 3], 10) catch return null;
    const minute = std.fmt.parseInt(i64, words[start + 4], 10) catch return null;
    const second = std.fmt.parseInt(i64, words[start + 5], 10) catch return null;
    if (month < 1 or year < 1601 or year > 9999 or day < 1 or hour < 0 or hour > 23 or minute < 0 or minute > 59 or second < 0 or second > 60) return null;
    const month_days = [_]i64{ 31, if (@mod(year, 4) == 0 and (@mod(year, 100) != 0 or @mod(year, 400) == 0)) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (day > month_days[@intCast(month - 1)]) return null;
    const zone = words[start + 6];
    var offset: i64 = 0;
    if (zone.len == 5 and (zone[0] == '+' or zone[0] == '-')) {
        const zh = std.fmt.parseInt(i64, zone[1..3], 10) catch return null;
        const zm = std.fmt.parseInt(i64, zone[3..5], 10) catch return null;
        if (zh > 23 or zm > 59) return null;
        offset = (zh * 60 + zm) * 60 * (if (zone[0] == '-') @as(i64, -1) else @as(i64, 1));
    } else if (!std.ascii.eqlIgnoreCase(zone, "GMT") and !std.ascii.eqlIgnoreCase(zone, "UT") and !std.ascii.eqlIgnoreCase(zone, "Z")) return null;
    year -= if (month <= 2) @as(i64, 1) else @as(i64, 0);
    const era = @divFloor(year, 400);
    const yoe = year - era * 400;
    const m = month + (if (month > 2) @as(i64, -3) else @as(i64, 9));
    const days = era * 146097 + yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + @divFloor(153 * m + 2, 5) + day - 1 - 719468;
    return days * 86400 + hour * 3600 + minute * 60 + second - offset;
}

/// Load one message's full detail by UID.
pub fn getMessage(
    allocator: std.mem.Allocator,
    db: *database.Database,
    user: []const u8,
    folder: []const u8,
    uid: i64,
) !MessageDetail {
    if (!isValidFolderName(folder)) return MaildirError.InvalidFolderName;
    _ = db.getOrCreateMailbox(user, folder) catch {};
    const file = (try findByUid(allocator, db, user, folder, uid)) orelse return MaildirError.MessageNotFound;
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ file.dir, file.name });
    const raw = try fs_compat.readFileAlloc(allocator, path);
    return parseDetail(allocator, folder, uid, file.name, raw, null);
}

fn parseDetail(allocator: std.mem.Allocator, folder: []const u8, uid: i64, name: []const u8, raw: []const u8, version: ?MessageVersion) MessageDetail {
    const headers = parseHeaders(allocator, raw) catch HeaderSet{};
    const body = extractBestBody(allocator, raw) catch BodyParts{};
    return .{
        .uid = uid,
        .folder = folder,
        .timestamp = messageTimestamp(headers.date, name),
        .version = version,
        .from = headers.from,
        .to = headers.to,
        .cc = headers.cc,
        .bcc = headers.bcc,
        .reply_to = headers.reply_to,
        .in_reply_to = headers.in_reply_to,
        .references = headers.references,
        .subject = headers.subject,
        .date = headers.date,
        .message_id = headers.message_id,
        .text_body = body.text,
        .html_body = body.html,
        .flags = flagsFrom(name),
        .attachments = body.attachments,
        .calendar_parts = body.calendar_parts,
        .calendar_only = body.calendar_parts.len != 0 and calendar_invite.mimeMethod(headers.content_type) != null,
        .size = raw.len,
    };
}

pub const VersionedFile = struct {
    locator: MessageLocator,
    name: []const u8,
    path: []const u8,
    stamp: []const u8,
    raw: []const u8,
    version: MessageVersion,
};

fn makeVersion(a: std.mem.Allocator, id: []const u8, at: MessageLocator, name: []const u8, raw_digest: *const [64]u8) !MessageVersion {
    var sha: std.crypto.hash.sha2.Sha256 = .init(.{});
    const metadata = try std.fmt.allocPrint(a, "{s}\x00{s}\x00{d}\x00{s}\x00", .{ id, at.folder, at.uid, name });
    sha.update(metadata);
    sha.update(raw_digest);
    const hex = std.fmt.bytesToHex(sha.finalResult(), .lower);
    return .{
        .reference = id,
        .revision = try std.fmt.allocPrint(a, "\"{s}\"", .{&hex}),
        .content_revision = raw_digest.*,
    };
}

fn fileAt(a: std.mem.Allocator, user: []const u8, location: message_refs.Location) !?FileRef {
    return fileIn(try collectFiles(a, user, location.folder), location.basename);
}

fn fileIn(files: []const FileRef, basename: []const u8) ?FileRef {
    for (files) |file| {
        if (std.mem.eql(u8, basename, database.maildirBaseName(file.name))) return file;
    }
    return null;
}

/// Reuse one directory listing across a history batch. A pending rename or
/// changed file stamp falls back to a fresh lookup under the mailbox lock.
const HistoryFolder = struct {
    arena: std.heap.ArenaAllocator,
    user: []const u8 = "",
    name: []const u8 = "",
    files: []const FileRef = &.{},

    fn lookup(self: *HistoryFolder, user: []const u8, at: message_refs.Location) !?FileRef {
        if (!std.mem.eql(u8, self.user, user) or !std.mem.eql(u8, self.name, at.folder)) {
            _ = self.arena.reset(.retain_capacity);
            const a = self.arena.allocator();
            self.user = try a.dupe(u8, user);
            self.name = try a.dupe(u8, at.folder);
            self.files = try collectFiles(a, user, at.folder);
        }
        return fileIn(self.files, at.basename);
    }
};

fn matchesStamp(a: std.mem.Allocator, file: FileRef, stamp: []const u8) !bool {
    const path = try std.fmt.allocPrint(a, "{s}/{s}", .{ file.dir, file.name });
    const actual = message_refs.fileStamp(a, path) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return std.mem.eql(u8, stamp, actual);
}

pub const ReferencedFile = struct {
    file: FileRef,
    folder: []const u8,
    path: []const u8,
    stamp: []const u8,
    raw: []const u8,
};

/// Read a tracked file while the caller holds the mailbox lock. This avoids
/// assigning IMAP UIDs when only the saved content and location are needed.
pub fn resolveReferenceFileLocked(a: std.mem.Allocator, db: *database.Database, user: []const u8, id: []const u8) !ReferencedFile {
    return resolveReferenceFile(a, db, user, id, null, true);
}

fn resolveReferenceFile(a: std.mem.Allocator, db: *database.Database, user: []const u8, id: []const u8, history: ?*HistoryFolder, repair: bool) !ReferencedFile {
    if (!message_refs.valid(id)) return MaildirError.MessageNotFound;
    const entry = (try message_refs.lookup(a, db, user, id)) orelse return MaildirError.MessageNotFound;
    var at = entry.location;
    var current: ?FileRef = null;
    if (history) |cached| {
        if (try cached.lookup(user, at)) |file| {
            if (try matchesStamp(a, file, entry.stamp)) current = file;
        }
    }
    if (current == null) current = try fileAt(a, user, at);
    const recovering = current == null or !try matchesStamp(a, current.?, entry.stamp);
    if (recovering) {
        const pending = entry.pending orelse return MaildirError.MessageNotFound;
        if (!repair) return error.ErasureReferenceNeedsRepair;
        at = pending.location;
        current = try fileAt(a, user, at);
    }
    const file = current orelse return MaildirError.MessageNotFound;
    const path = try std.fmt.allocPrint(a, "{s}/{s}", .{ file.dir, file.name });
    const stamp = try message_refs.fileStamp(a, path);
    const raw = try fs_compat.readFileAlloc(a, path);
    if (recovering) {
        const checksum = message_refs.digest(raw);
        if (!std.mem.eql(u8, &checksum, entry.pending.?.digest)) return MaildirError.MessageNotFound;
        try message_refs.finish(db, user, id, at, stamp);
    }
    return .{ .file = file, .folder = at.folder, .path = path, .stamp = stamp, .raw = raw };
}

pub fn resolveVersioned(a: std.mem.Allocator, db: *database.Database, user: []const u8, id: []const u8) !VersionedFile {
    const entry = try resolveReferenceFileLocked(a, db, user, id);
    _ = try db.getOrCreateMailbox(user, entry.folder);
    preassignUids(db, user, entry.folder, try collectFiles(a, user, entry.folder));
    const uid = (try db.getUidForFile(user, entry.folder, entry.file.name)) orelse return MaildirError.MessageNotFound;
    const locator: MessageLocator = .{ .folder = entry.folder, .uid = uid };
    const checksum = message_refs.digest(entry.raw);
    return .{
        .locator = locator,
        .name = entry.file.name,
        .path = entry.path,
        .stamp = entry.stamp,
        .raw = entry.raw,
        .version = try makeVersion(a, id, locator, entry.file.name, &checksum),
    };
}

/// Scan a bounded batch under the same per-message lock as Maildir moves.
/// A missing or replaced file can no longer authenticate its old contents.
/// Return true when all pending history in this scope has been checked.
pub fn indexCalendarHistory(db: *database.Database, scope: ?database.Database.CalendarHistoryScope) !bool {
    var arena = std.heap.ArenaAllocator.init(db.allocator);
    defer arena.deinit();
    var history: HistoryFolder = .{ .arena = std.heap.ArenaAllocator.init(db.allocator) };
    defer history.arena.deinit();
    for (0..12) |_| {
        _ = arena.reset(.retain_capacity);
        const a = arena.allocator();
        db.lockMailboxes();
        defer db.unlockMailboxes();
        const source = (try db.nextCalendarHistory(a, scope)) orelse return true;
        const file = resolveReferenceFile(a, db, source.username, source.reference, &history, true) catch |err| switch (err) {
            error.MessageNotFound, error.FileNotFound => {
                try db.finishCalendarHistory(source, &.{});
                continue;
            },
            else => return err,
        };
        const revisions = try calendarRevisions(a, file.raw, source.attendee, source.author);
        try db.finishCalendarHistory(source, revisions);
    }
    return try db.nextCalendarHistory(arena.allocator(), scope) == null;
}

/// The caller holds the mailbox lock for the complete conditional operation.
pub fn checkRevision(a: std.mem.Allocator, db: *database.Database, user: []const u8, id: []const u8, expected: []const u8) !MessageLocator {
    const entry = try resolveVersioned(a, db, user, id);
    if (!std.mem.eql(u8, entry.version.revision, expected)) return MaildirError.RevisionMismatch;
    return entry.locator;
}

/// The caller holds the mailbox lock through the shared workflow mutation.
pub fn checkSharedInboxRevision(a: std.mem.Allocator, db: *database.Database, user: []const u8, id: []const u8, expected: []const u8) !void {
    const entry = try resolveVersioned(a, db, user, id);
    if (!std.mem.eql(u8, entry.locator.folder, "INBOX") or flagsFrom(entry.name).deleted) return MaildirError.MessageNotFound;
    if (!std.mem.eql(u8, entry.version.revision, expected)) return MaildirError.RevisionMismatch;
}

pub fn getByReference(a: std.mem.Allocator, db: *database.Database, user: []const u8, id: []const u8) !MessageDetail {
    db.lockMailboxes();
    const entry = resolveVersioned(a, db, user, id);
    db.unlockMailboxes();
    const file = try entry;
    return parseDetail(a, file.locator.folder, file.locator.uid, file.name, file.raw, file.version);
}

/// Read the same tracked bytes offline without assigning UIDs or recovering a
/// pending rename. The operator must hold the canonical Maildir writer lock.
pub fn readForRetention(a: std.mem.Allocator, db: *database.Database, user: []const u8, id: []const u8) !MessageDetail {
    const entry = try resolveReferenceFile(a, db, user, id, null, false);
    const locator: MessageLocator = .{ .folder = entry.folder, .uid = 0 };
    const digest = message_refs.digest(entry.raw);
    const version = try makeVersion(a, id, locator, entry.file.name, &digest);
    return parseDetail(a, entry.folder, locator.uid, entry.file.name, entry.raw, version);
}

/// Resolve the user's own message and read only the header needed to seed
/// the calendar editor. The stable reference follows normal mailbox moves.
pub fn calendarSourceSubject(a: std.mem.Allocator, db: *database.Database, user: []const u8, id: []const u8) ![]const u8 {
    db.lockMailboxes();
    defer db.unlockMailboxes();
    const file = try resolveVersioned(a, db, user, id);
    if (!isPersonalFolder(file.locator.folder)) return MaildirError.MessageNotFound;
    const subject = std.mem.trim(u8, try mimeHeader(a, file.raw, "Subject"), " \t\r\n");
    if (!std.unicode.utf8ValidateSlice(subject)) return "";
    for (subject) |byte| if ((byte < 32 and byte != '\t') or byte == 127) return "";
    var length = @min(subject.len, 512);
    while (length < subject.len and subject[length] & 0xc0 == 0x80) length -= 1;
    return subject[0..length];
}

pub fn getSharedInboxMessage(a: std.mem.Allocator, db: *database.Database, user: []const u8, id: []const u8) !MessageDetail {
    const message = try getByReference(a, db, user, id);
    if (!std.mem.eql(u8, message.folder, "INBOX") or message.flags.deleted) return error.SharedInboxNotFound;
    return message;
}

fn observeVersion(a: std.mem.Allocator, db: *database.Database, user: []const u8, folder: []const u8, uid: i64) !VersionedFile {
    if (!isValidFolderName(folder)) return MaildirError.InvalidFolderName;
    const file = (try findByUid(a, db, user, folder, uid)) orelse return MaildirError.MessageNotFound;
    return versionForFile(a, db, user, folder, uid, file);
}

/// Resolve a journaled Sender Review copy under the mailbox mutation lock.
pub fn observeReviewFile(a: std.mem.Allocator, db: *database.Database, user: []const u8, folder: []const u8, basename: []const u8, expected_stamp: []const u8) !VersionedFile {
    if (!std.mem.eql(u8, folder, "Screening") and !std.mem.eql(u8, folder, "Declined")) return MaildirError.InvalidFolderName;
    const file = (try fileAt(a, user, .{ .folder = folder, .basename = basename })) orelse return MaildirError.MessageNotFound;
    if (expected_stamp.len != 0 and !try matchesStamp(a, file, expected_stamp)) return MaildirError.MessageNotFound;
    preassignUids(db, user, folder, try collectFiles(a, user, folder));
    const uid = (try db.getUidForFile(user, folder, file.name)) orelse return MaildirError.MessageNotFound;
    return versionForFile(a, db, user, folder, uid, file);
}

fn versionForFile(a: std.mem.Allocator, db: *database.Database, user: []const u8, folder: []const u8, uid: i64, file: FileRef) !VersionedFile {
    const path = try std.fmt.allocPrint(a, "{s}/{s}", .{ file.dir, file.name });
    const stamp = try message_refs.fileStamp(a, path);
    const raw = try fs_compat.readFileAlloc(a, path);
    const at = message_refs.location(folder, file.name);
    const locator: MessageLocator = .{ .folder = at.folder, .uid = uid };
    const checksum = message_refs.digest(raw);
    const id = try observeReference(a, db, user, at, stamp, &checksum);
    return .{ .locator = locator, .name = file.name, .path = path, .stamp = stamp, .raw = raw, .version = try makeVersion(a, id, locator, file.name, &checksum) };
}

pub fn reviewHeaders(a: std.mem.Allocator, raw: []const u8) !struct { from: []const u8, subject: []const u8, date: []const u8 } {
    const headers = try parseHeaders(a, raw);
    return .{ .from = headers.from, .subject = headers.subject, .date = headers.date };
}

/// Return the message text a private clip can quote. HTML-only mail uses the
/// same text extraction as search and leaves tag attributes out of clips.
pub fn clipText(a: std.mem.Allocator, raw: []const u8) ![]const u8 {
    const body = try extractBody(a, raw, .preview);
    const text = if (body.text.len > 0) body.text else html_text.extract(body.html, try a.alloc(u8, body.html.len));
    if (std.mem.indexOfScalar(u8, text, '\r') == null and std.unicode.utf8ValidateSlice(text)) return text;
    var clean: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < text.len) {
        if (text[i] == '\r') {
            try clean.append(a, '\n');
            i += if (i + 1 < text.len and text[i + 1] == '\n') @as(usize, 2) else 1;
            continue;
        }
        const length = std.unicode.utf8ByteSequenceLength(text[i]) catch 0;
        if (length == 0 or i + length > text.len or !std.unicode.utf8ValidateSlice(text[i .. i + length])) {
            try clean.appendSlice(a, "\u{fffd}");
            i += 1;
        } else {
            try clean.appendSlice(a, text[i .. i + length]);
            i += length;
        }
    }
    return clean.toOwnedSlice(a);
}

fn observeReference(a: std.mem.Allocator, db: *database.Database, user: []const u8, at: message_refs.Location, stamp: []const u8, checksum: []const u8) ![]const u8 {
    if (try message_refs.recoverAt(a, db, user, at, stamp, checksum)) |id| return id;
    return message_refs.issue(a, db, user, at, stamp);
}

/// Register only the rows that will be returned after pagination.
pub fn summaryVersion(a: std.mem.Allocator, db: *database.Database, user: []const u8, row: MessageSummary) !?MessageVersion {
    const snapshot = row.snapshot orelse return null;
    db.lockMailboxes();
    defer db.unlockMailboxes();
    if (snapshot.fingerprint) |expected| {
        const path = try std.fmt.allocPrint(a, "{s}/{s}", .{ snapshot.file.dir, snapshot.file.name });
        const identity = message_refs.fileFingerprint(a, path) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        if (!std.mem.eql(u8, expected, identity.fingerprint)) return null;
    } else if (!try matchesStamp(a, snapshot.file, snapshot.stamp)) return null;
    const at = message_refs.location(row.folder, snapshot.file.name);
    const id = try observeReference(a, db, user, at, snapshot.stamp, &snapshot.digest);
    return try makeVersion(a, id, .{ .folder = at.folder, .uid = row.uid }, snapshot.file.name, &snapshot.digest);
}

/// The caller holds the mailbox lock.
pub fn versionAt(a: std.mem.Allocator, db: *database.Database, user: []const u8, folder: []const u8, uid: i64) !MessageVersion {
    return (try observeVersion(a, db, user, folder, uid)).version;
}

pub fn getVersionedMessage(a: std.mem.Allocator, db: *database.Database, user: []const u8, folder: []const u8, uid: i64) !MessageDetail {
    db.lockMailboxes();
    const entry = observeVersion(a, db, user, folder, uid);
    db.unlockMailboxes();
    const file = try entry;
    return parseDetail(a, file.locator.folder, file.locator.uid, file.name, file.raw, file.version);
}

// ── Write operations (flags / move / delete) ─────────────────────────────────
//
// These persist by renaming/moving Maildir files exactly as the IMAP server
// does (imap.zig handleStore/handleMove/handleExpunge), so a change made in
// webmail is seen identically over IMAP and vice versa. UIDs are keyed on the
// Maildir base name (database.maildirBaseName), so a flag rename keeps the same
// UID — no imap_uids update is needed for flag changes.

/// Locate the FileRef for a UID within a folder. Returns null if not found.
/// Caller must have called preassignUids first (so UIDs are assigned).
fn findByUid(allocator: std.mem.Allocator, db: *database.Database, user: []const u8, folder: []const u8, uid: i64) !?FileRef {
    const refs = try collectFiles(allocator, user, folder);
    preassignUids(db, user, folder, refs);
    for (refs, 0..) |r, idx| {
        if (uidFor(db, user, folder, r.name, @intCast(idx + 1)) == uid) return r;
    }
    return null;
}

/// POSIX rename via libc (mirrors imap.zig renameFile). Returns true on success.
fn renamePath(old_path: []const u8, new_path: []const u8) bool {
    var ob: [4097]u8 = undefined;
    var nb: [4097]u8 = undefined;
    if (old_path.len >= ob.len or new_path.len >= nb.len) return false;
    @memcpy(ob[0..old_path.len], old_path);
    ob[old_path.len] = 0;
    @memcpy(nb[0..new_path.len], new_path);
    nb[new_path.len] = 0;
    return std.c.rename(@ptrCast(&ob), @ptrCast(&nb)) == 0;
}

/// Unlink a path, propagating failure. Callers must NOT ignore the error: a
/// silently-ignored unlink leaves a deleted/moved message on disk while the
/// caller reports success (data-consistency bug).
fn unlinkPath(allocator: std.mem.Allocator, path: []const u8) !void {
    const z = try allocator.dupeSentinel(u8, path, 0);
    defer allocator.free(z);
    if (std.c.unlink(z.ptr) != 0) return MaildirError.WriteFailed;
}

/// A Maildir entry name must be a single path component. Reject anything with a
/// separator or parent ref so a planted/crafted filename can't make rename or
/// unlink escape the mailbox directory (defense-in-depth alongside the symlink
/// skip in fs_compat.listEmlFiles).
fn isSafeName(name: []const u8) bool {
    if (name.len == 0) return false;
    if (std.mem.indexOfScalar(u8, name, '/') != null) return false;
    if (std.mem.indexOf(u8, name, "..") != null) return false;
    if (name[0] == '.') return false;
    return true;
}

/// Set the flags on a message (by UID) by renaming its Maildir file's suffix.
/// The base name (and thus the UID) is unchanged. Returns the resulting Flags.
pub fn setFlags(
    allocator: std.mem.Allocator,
    db: *database.Database,
    user: []const u8,
    folder: []const u8,
    uid: i64,
    flags: Flags,
) !Flags {
    db.lockMailboxes();
    defer db.unlockMailboxes();
    return setFlagsLocked(allocator, db, user, folder, uid, flags);
}

pub fn setFlagsLocked(allocator: std.mem.Allocator, db: *database.Database, user: []const u8, folder: []const u8, uid: i64, flags: Flags) !Flags {
    if (!isValidFolderName(folder)) return MaildirError.InvalidFolderName;
    _ = db.getOrCreateMailbox(user, folder) catch {};

    // Retry once: a concurrent rename (IMAP STORE, or another webmail request)
    // between resolving the file and renaming it would otherwise fail as a
    // generic write error and silently drop the flag change. Re-resolve the
    // current on-disk name and try again before reporting a conflict.
    var attempt: u8 = 0;
    while (attempt < 2) : (attempt += 1) {
        const ref = (try findByUid(allocator, db, user, folder, uid)) orelse return MaildirError.MessageNotFound;
        if (!isSafeName(ref.name)) return MaildirError.WriteFailed;

        const base = imap.MaildirFlags.baseName(ref.name);
        const full_flags: imap.MaildirFlags = .{
            .seen = flags.seen,
            .answered = flags.answered,
            .flagged = flags.flagged,
            .draft = flags.draft,
            .deleted = flags.deleted,
            .keywords = maildir_keywords.fromFilename(ref.name),
        };
        var suffix_buf: [maildir_keywords.suffix_capacity]u8 = undefined;
        const suffix = full_flags.toSuffix(&suffix_buf);
        const new_name = try std.fmt.allocPrint(allocator, "{s}{s}", .{ base, suffix });

        if (std.mem.eql(u8, ref.name, new_name)) return flags; // already in the desired state

        const old_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ ref.dir, ref.name });
        const new_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ ref.dir, new_name });
        if (renamePath(old_path, new_path)) return flags;
        // Rename failed — the file may have been renamed out from under us. Loop
        // to re-resolve; if it fails again, report a conflict.
    }
    return MaildirError.Conflict;
}

/// Move a message (by UID) to another folder. The file is physically moved and
/// a UID is assigned in the destination mailbox; the source UID becomes stale on
/// the next sync. Returns the new UID in the destination folder.
pub fn moveMessage(
    allocator: std.mem.Allocator,
    db: *database.Database,
    user: []const u8,
    src_folder: []const u8,
    uid: i64,
    dst_folder: []const u8,
) !i64 {
    db.lockMailboxes();
    defer db.unlockMailboxes();
    return moveMessageLocked(allocator, db, user, src_folder, uid, dst_folder);
}

pub fn moveMessageLocked(allocator: std.mem.Allocator, db: *database.Database, user: []const u8, src_folder: []const u8, uid: i64, dst_folder: []const u8) !i64 {
    return moveWithFeedbackLocked(allocator, db, user, src_folder, uid, dst_folder, null);
}

pub fn moveWithFeedbackLocked(allocator: std.mem.Allocator, db: *database.Database, user: []const u8, src_folder: []const u8, uid: i64, dst_folder: []const u8, junk: ?message_refs.JunkChange) !i64 {
    if (!isValidFolderName(src_folder) or !isValidFolderName(dst_folder)) return MaildirError.InvalidFolderName;
    const source_folder = message_refs.location(src_folder, "").folder;
    const target_folder = message_refs.location(dst_folder, "").folder;
    if (std.mem.eql(u8, source_folder, target_folder)) return uid;
    _ = db.getOrCreateMailbox(user, src_folder) catch {};
    _ = db.getOrCreateMailbox(user, dst_folder) catch {};

    const ref = (try findByUid(allocator, db, user, src_folder, uid)) orelse return MaildirError.MessageNotFound;
    return moveFileLocked(allocator, db, user, src_folder, ref, dst_folder, if (junk) |change| .{ .junk = change } else null);
}

/// Called under the mailbox lock. Register the reference before staging the
/// move so the same handoff that changes its folder also records recovery.
pub fn moveForRetentionLocked(a: std.mem.Allocator, db: *database.Database, user: []const u8, source_folder: []const u8, ref: FileRef, now: i64) !void {
    if (!isSafeName(ref.name)) return MaildirError.WriteFailed;
    const path = try std.fmt.allocPrint(a, "{s}/{s}", .{ ref.dir, ref.name });
    const at = message_refs.location(source_folder, ref.name);
    const stamp = try message_refs.fileStamp(a, path);
    if (try message_refs.pendingAt(a, db, user, at) != null) {
        const raw = try fs_compat.readFileAlloc(a, path);
        _ = try observeReference(a, db, user, at, stamp, &message_refs.digest(raw));
    } else _ = try message_refs.issue(a, db, user, at, stamp);
    _ = try db.getOrCreateMailbox(user, "Trash");
    _ = try moveFileLocked(a, db, user, source_folder, ref, "Trash", .{ .retention = now });
}

fn moveFileLocked(allocator: std.mem.Allocator, db: *database.Database, user: []const u8, src_folder: []const u8, ref: FileRef, dst_folder: []const u8, effect: ?message_refs.MoveEffect) !i64 {
    const folder = message_refs.location(dst_folder, ref.name).folder;
    if (std.mem.eql(u8, folder, "INBOX")) return moveResolvedFileLocked(allocator, db, user, src_folder, ref, dst_folder, &.{
        try std.fmt.allocPrint(allocator, "mail/{s}/new", .{user}),
        try std.fmt.allocPrint(allocator, "mail/{s}/cur", .{user}),
    }, effect, false);
    const dir = try std.fmt.allocPrint(allocator, "mail/{s}/{s}", .{ user, folder });
    return moveResolvedFileLocked(allocator, db, user, src_folder, ref, dst_folder, &.{dir}, effect, false);
}

/// Move a resolved file within one mailbox under the mutation lock. The
/// resolver supplies the collection's directories, preferred destination first.
pub fn moveResolvedFileLocked(allocator: std.mem.Allocator, db: *database.Database, user: []const u8, src_folder: []const u8, ref: FileRef, dst_folder: []const u8, destination_dirs: []const []const u8, effect: ?message_refs.MoveEffect, short_root: bool) !i64 {
    if (!isSafeName(ref.name)) return MaildirError.WriteFailed;
    const source = message_refs.location(src_folder, ref.name);
    const target = message_refs.location(dst_folder, ref.name);
    const dst_dir = destination_dirs[0];
    try fs_compat.ensureDir(dst_dir);
    for (destination_dirs) |dir| {
        const names = fs_compat.listEmlFiles(allocator, dir) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        for (names) |name| {
            if (std.mem.eql(u8, database.maildirBaseName(name), target.basename)) return MaildirError.Conflict;
        }
    }

    const old_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ ref.dir, ref.name });
    const source_bits = maildir_keywords.fromFilename(ref.name);
    const target_bits = try maildir_keywords.transferredBits(allocator, ref.dir, dst_dir, source_bits);
    const target_name = if (source_bits == target_bits) ref.name else try maildir_keywords.withBits(allocator, ref.name, target_bits);
    const new_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dst_dir, target_name });

    // Assign the destination UID FIRST. UID keying is on the base name, so this
    // is correct regardless of the physical move; doing it before the move means
    // a UID failure aborts cleanly without leaving an orphaned file, and the
    // returned UID is always the real destination UID (never a stale source one).
    const dst_uid = try db.assignFreshUid(user, dst_folder, ref.name);
    errdefer db.discardMoveUid(user, dst_folder, dst_uid) catch |err| std.log.warn("could not discard an unpublished move UID: {}", .{err});
    const transfer = try message_refs.stageMove(allocator, db, user, source, old_path, target, null, effect);
    if (effect != null and transfer == null) return MaildirError.Conflict;
    errdefer if (transfer) |id| message_refs.cancel(db, user, id);
    try maildir_index.markLocked(db, user, short_root, &.{ source, target });

    // Prefer an atomic rename; fall back to copy+unlink across filesystems.
    if (!renamePath(old_path, new_path)) {
        const content = fs_compat.readFileAlloc(allocator, old_path) catch return MaildirError.WriteFailed;
        const f = fs_compat.cwd().createFileExclusive(new_path) catch return MaildirError.WriteFailed;
        f.writeAll(content) catch {
            f.close();
            unlinkPath(allocator, new_path) catch {}; // don't leave a partial copy
            return MaildirError.WriteFailed;
        };
        f.close();
        // If the source unlink fails, the message would exist in BOTH folders.
        // Roll back the destination copy and fail rather than duplicate.
        unlinkPath(allocator, old_path) catch {
            unlinkPath(allocator, new_path) catch {};
            return MaildirError.WriteFailed;
        };
    }

    if (transfer) |id| message_refs.finishFile(allocator, db, user, id, target, new_path);
    message_refs.forgetReviewCopy(db, user, source) catch |err| std.log.warn("could not retire a manually moved review copy: {}", .{err});
    return dst_uid;
}

var draft_sequence = std.atomic.Value(u64).init(0);

pub const DraftWrite = struct {
    uid: i64,
    temporary: []const u8,
    destination: []const u8,
    replacing: bool,

    pub fn forgetUid(self: DraftWrite, db: *database.Database, user: []const u8) void {
        const s = db.prepare("DELETE FROM imap_uids WHERE username=?1 AND mailbox='Drafts' AND uid=?2") catch return;
        defer s.finalize();
        s.bind(1, user) catch return;
        s.bind(2, self.uid) catch return;
        _ = s.step() catch return;
    }

    /// A temporary name is invisible until the complete message is ready.
    pub fn save(self: DraftWrite, allocator: std.mem.Allocator, db: *database.Database, user: []const u8, raw: []const u8) !void {
        try saveDraftFile(allocator, db, user, self.temporary, self.destination, self.replacing, raw);
    }
};

/// Replace a draft at its current location, preserving its message identity.
/// The caller holds the mailbox mutation lock and has verified the snapshot.
pub fn replaceDraftFile(a: std.mem.Allocator, db: *database.Database, user: []const u8, destination: []const u8, raw: []const u8) !void {
    try hosted_limits.checkStorage(db, user, raw.len, destination);
    const directory = std.fs.path.dirname(destination) orelse return MaildirError.WriteFailed;
    const temporary = try std.fmt.allocPrint(a, "{s}/.draft-{d}.{d}.tmp", .{ directory, time_compat.milliTimestamp(), draft_sequence.fetchAdd(1, .monotonic) });
    defer a.free(temporary);
    try saveDraftFile(a, db, user, temporary, destination, true, raw);
}

fn saveDraftFile(a: std.mem.Allocator, db: *database.Database, user: []const u8, temporary: []const u8, destination: []const u8, replacing: bool, raw: []const u8) !void {
    const file = try fs_compat.cwd().createFileExclusive(temporary);
    defer unlinkPath(a, temporary) catch {};
    file.writeAll(raw) catch |err| {
        file.close();
        return err;
    };
    file.close();
    const at = message_refs.location("Drafts", std.fs.path.basename(destination));
    const transfer = if (replacing) try message_refs.stage(a, db, user, at, destination, at, raw) else null;
    errdefer if (transfer) |id| message_refs.cancel(db, user, id);
    if (!renamePath(temporary, destination)) return MaildirError.WriteFailed;
    if (transfer) |id| message_refs.finishFile(a, db, user, id, at, destination);
}

/// The caller holds the mailbox mutation lock through the write. This gives
/// webmail the UID needed to check the draft metadata before replacing the file.
pub fn prepareDraft(allocator: std.mem.Allocator, db: *database.Database, user: []const u8, bytes: usize, existing: ?i64) !DraftWrite {
    _ = try db.getOrCreateMailbox(user, "Drafts");
    const dir = try std.fmt.allocPrint(allocator, "mail/{s}/Drafts", .{user});
    try fs_compat.ensureDir(dir);
    const seq = draft_sequence.fetchAdd(1, .monotonic);
    const now = time_compat.milliTimestamp();
    const name = if (existing) |uid| blk: {
        const ref = (try findByUid(allocator, db, user, "Drafts", uid)) orelse return MaildirError.MessageNotFound;
        break :blk ref.name;
    } else try std.fmt.allocPrint(allocator, "{d}.{d}.eml:2,DS", .{ now, seq });
    const temporary = try std.fmt.allocPrint(allocator, "{s}/.draft-{d}.{d}.tmp", .{ dir, now, seq });
    const destination = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir, name });
    try hosted_limits.checkStorage(db, user, bytes, if (existing != null) destination else null);
    const uid = try db.assignUid(user, "Drafts", name);
    return .{ .uid = uid, .temporary = temporary, .destination = destination, .replacing = existing != null };
}

/// Delete a message (by UID): move it to Trash, or permanently unlink if it is
/// already in Trash. Returns true on success.
pub fn deleteMessage(
    allocator: std.mem.Allocator,
    db: *database.Database,
    user: []const u8,
    folder: []const u8,
    uid: i64,
) !void {
    db.lockMailboxes();
    defer db.unlockMailboxes();
    return deleteMessageLocked(allocator, db, user, folder, uid);
}

pub fn deleteMessageLocked(allocator: std.mem.Allocator, db: *database.Database, user: []const u8, folder: []const u8, uid: i64) !void {
    if (!isValidFolderName(folder)) return MaildirError.InvalidFolderName;

    if (std.ascii.eqlIgnoreCase(folder, "Trash")) {
        // Permanent delete from Trash.
        _ = db.getOrCreateMailbox(user, folder) catch {};
        const ref = (try findByUid(allocator, db, user, folder, uid)) orelse return MaildirError.MessageNotFound;
        if (!isSafeName(ref.name)) return MaildirError.WriteFailed;
        const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ ref.dir, ref.name });
        try maildir_index.markLocked(db, user, false, &.{message_refs.location(folder, ref.name)});
        try unlinkPath(allocator, path); // propagate failure — don't report a phantom success
        message_refs.forget(db, user, message_refs.location(folder, ref.name)) catch |err| std.log.warn("could not retire webmail message reference: {}", .{err});
        return;
    }

    _ = try moveMessageLocked(allocator, db, user, folder, uid, "Trash");
}

// ── Minimal RFC 5322 / MIME parsing ──────────────────────────────────────────
//
// Intentionally small and defensive: enough to populate the inbox and reading
// pane. Robust MIME (nested multipart, all transfer encodings, charsets) is
// future work; everything here degrades to empty strings rather than erroring.

const HeaderSet = struct {
    from: []const u8 = "",
    to: []const u8 = "",
    cc: []const u8 = "",
    bcc: []const u8 = "",
    reply_to: []const u8 = "",
    in_reply_to: []const u8 = "",
    references: []const u8 = "",
    subject: []const u8 = "",
    date: []const u8 = "",
    message_id: []const u8 = "",
    content_type: []const u8 = "",
};

fn mimeHeaders(a: std.mem.Allocator, raw: []const u8) !mime_lib.Headers {
    var pos: usize = 0;
    var end = raw.len;
    while (std.mem.indexOfScalarPos(u8, raw, pos, '\n')) |nl| {
        if (nl == pos or (nl == pos + 1 and raw[pos] == '\r')) {
            end = pos;
            break;
        }
        pos = nl + 1;
    }
    return .{ .block = mime_lib.headers.unfold(try a.dupe(u8, raw[0..end])) };
}

fn decodeMimeWords(a: std.mem.Allocator, value: []const u8) ![]const u8 {
    if (std.mem.indexOf(u8, value, "=?") == null) return value;
    const buffer = try a.alloc(u8, value.len * 3);
    return mime_lib.decodeWords(value, buffer).text;
}

pub fn mimeHeader(a: std.mem.Allocator, raw: []const u8, name: []const u8) ![]const u8 {
    const headers = try mimeHeaders(a, raw);
    const value = headers.get(name) orelse "";
    if (std.ascii.eqlIgnoreCase(name, "Subject") or std.ascii.eqlIgnoreCase(name, "From") or std.ascii.eqlIgnoreCase(name, "Reply-To"))
        return decodeMimeWords(a, value);
    return value;
}

fn parseHeaders(a: std.mem.Allocator, raw: []const u8) !HeaderSet {
    const block = try mimeHeaders(a, raw);
    return .{
        .from = try decodeMimeWords(a, block.get("From") orelse ""),
        .to = try decodeMimeWords(a, block.get("To") orelse ""),
        .cc = try decodeMimeWords(a, block.get("Cc") orelse ""),
        .bcc = try decodeMimeWords(a, block.get("Bcc") orelse ""),
        .reply_to = try decodeMimeWords(a, block.get("Reply-To") orelse ""),
        .in_reply_to = block.get("In-Reply-To") orelse "",
        .references = block.get("References") orelse "",
        .subject = try decodeMimeWords(a, block.get("Subject") orelse ""),
        .date = block.get("Date") orelse "",
        .message_id = block.get("Message-ID") orelse "",
        .content_type = block.get("Content-Type") orelse "",
    };
}

fn extractBestBody(a: std.mem.Allocator, raw: []const u8) !BodyParts {
    return extractBody(a, raw, .full);
}

/// Use the same MIME boundaries and transfer rules as the message reader
/// without decoding unrelated body parts or attachments during delivery.
pub fn calendarRevisions(a: std.mem.Allocator, raw: []const u8, attendee: []const u8, verified_author: []const u8) ![]const calendar_invite.Revision {
    if (verified_author.len == 0 or ascii_compat.indexOfIgnoreCase(raw, "text/calendar") == null) return &.{};
    const body = try extractBody(a, raw, .calendar);
    var revisions: std.ArrayList(calendar_invite.Revision) = .empty;
    for (try calendar_invite.invitations(a, body.calendar_parts, attendee, verified_author)) |invite| {
        if (invite.canTrack(attendee)) try revisions.append(a, try invite.revision(a));
    }
    return revisions.items;
}

pub fn embeddedImageType(att: AttachmentInfo) ?[]const u8 {
    if (att.content_id.len == 0 or att.data.len == 0 or att.data.len > 2 * 1024 * 1024) return null;
    const end = std.mem.indexOfScalar(u8, att.content_type, ';') orelse att.content_type.len;
    const mime = std.mem.trim(u8, att.content_type[0..end], " \t");
    const data = att.data;
    if (std.ascii.eqlIgnoreCase(mime, "image/png") and std.mem.startsWith(u8, data, "\x89PNG\r\n\x1a\n")) return "image/png";
    if (std.ascii.eqlIgnoreCase(mime, "image/jpeg") and std.mem.startsWith(u8, data, "\xff\xd8\xff")) return "image/jpeg";
    if (std.ascii.eqlIgnoreCase(mime, "image/gif") and (std.mem.startsWith(u8, data, "GIF87a") or std.mem.startsWith(u8, data, "GIF89a"))) return "image/gif";
    if (std.ascii.eqlIgnoreCase(mime, "image/webp") and data.len >= 12 and std.mem.eql(u8, data[0..4], "RIFF") and std.mem.eql(u8, data[8..12], "WEBP")) return "image/webp";
    if (std.ascii.eqlIgnoreCase(mime, "image/avif") and data.len >= 12 and std.mem.eql(u8, data[4..12], "ftypavif")) return "image/avif";
    return null;
}

/// Build a short plain-text snippet from a body, collapsing whitespace.
fn makeSnippet(allocator: std.mem.Allocator, text: []const u8) ![]const u8 {
    if (text.len == 0) return "";
    var out: std.ArrayList(u8) = .empty;
    var last_space = false;
    for (text) |c| {
        const is_ws = c == ' ' or c == '\t' or c == '\r' or c == '\n';
        if (is_ws) {
            if (!last_space and out.items.len > 0) {
                try out.append(allocator, ' ');
                last_space = true;
            }
        } else {
            try out.append(allocator, c);
            last_space = false;
            if (out.items.len >= 200) break;
        }
    }
    return std.mem.trim(u8, try out.toOwnedSlice(allocator), " ");
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "isValidFolderName accepts standard and simple, rejects traversal" {
    const t = std.testing;
    try t.expect(isValidFolderName("INBOX"));
    try t.expect(isValidFolderName("Sent"));
    try t.expect(isValidFolderName("My Folder_1"));
    try t.expect(!isValidFolderName("../etc"));
    try t.expect(!isValidFolderName(".hidden"));
    try t.expect(!isValidFolderName("a/b"));
    try t.expect(!isValidFolderName(""));
}

test "parseHeaders extracts and unfolds" {
    const t = std.testing;
    // Arena: this module is designed for arena allocation (the HTTP layer frees
    // wholesale). Header lookup returns sub-slices, so individual frees are unsafe
    // by design — the arena owns everything.
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const raw =
        "From: Alice <alice@example.com>\r\n" ++
        "Subject: Hello\r\n World\r\n" ++
        "To: bob@example.com\r\n" ++
        "\r\n" ++
        "body text here";
    const h = try parseHeaders(a, raw);
    try t.expectEqualStrings("Alice <alice@example.com>", h.from);
    try t.expectEqualStrings("Hello World", h.subject); // folded
    try t.expectEqualStrings("bob@example.com", h.to);
}

test "extractBestBody single-part text" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const raw =
        "Content-Type: text/plain\r\n" ++
        "\r\n" ++
        "Hello body";
    const b = try extractBestBody(a, raw);
    try t.expectEqualStrings("Hello body", b.text);
    try t.expectEqualStrings("", b.html);
}

test "extractBestBody multipart alternative picks text and html" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const raw =
        "Content-Type: multipart/alternative; boundary=\"XYZ\"\r\n" ++
        "\r\n" ++
        "--XYZ\r\n" ++
        "Content-Type: text/plain\r\n\r\n" ++
        "plain version\r\n" ++
        "--XYZ\r\n" ++
        "Content-Type: text/html\r\n\r\n" ++
        "<b>html version</b>\r\n" ++
        "--XYZ--\r\n";
    const b = try extractBestBody(a, raw);
    try t.expect(std.mem.indexOf(u8, b.text, "plain version") != null);
    try t.expect(std.mem.indexOf(u8, b.html, "html version") != null);
}

test "mime encoded-word Q and B decode" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const q = try decodeMimeWords(a, "=?utf-8?Q?Hello_World?=");
    try t.expectEqualStrings("Hello World", q);
}

test "snippet collapses whitespace and caps length" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = try makeSnippet(a, "  hello\r\n\r\n   world  ");
    try t.expectEqualStrings("hello world", s);
}

test "parseMultipart bounds recursion on deeply nested input" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Build a message nested far deeper than max_multipart_depth. The point is
    // that this returns (degrades) rather than overflowing the stack.
    var buf: std.ArrayList(u8) = .empty;
    var d: usize = 0;
    while (d < 50) : (d += 1) {
        try buf.appendSlice(a, "Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\n");
    }
    try buf.appendSlice(a, "Content-Type: text/plain\r\n\r\ndeep body\r\n--B--\r\n");
    // Must not crash/hang; returns some BodyParts.
    const b = try extractBestBody(a, buf.items);
    _ = b;
}

test "empty users stay isolated and new-cur merge follows IMAP ordering" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try std.fmt.allocPrint(a, "/tmp/mail-webmail-isolation-{d}", .{time_compat.milliTimestamp()});
    defer fs_compat.cwd().deleteTree(root) catch {};
    const shared = try std.fmt.allocPrint(a, "{s}/new", .{root});
    const new_dir = try std.fmt.allocPrint(a, "{s}/alice/new", .{root});
    const cur_dir = try std.fmt.allocPrint(a, "{s}/alice/cur", .{root});
    for ([_][]const u8{ shared, new_dir, cur_dir }) |dir| try fs_compat.ensureDir(dir);
    const paths = [_][]const u8{
        try std.fmt.allocPrint(a, "{s}/100.0.eml", .{shared}),
        try std.fmt.allocPrint(a, "{s}/200.0.eml", .{new_dir}),
        try std.fmt.allocPrint(a, "{s}/100.0.eml:2,S", .{cur_dir}),
        try std.fmt.allocPrint(a, "{s}/300.0.eml:2,S", .{cur_dir}),
    };
    for (paths) |path| {
        const file = try fs_compat.cwd().createFile(path, .{});
        file.close();
    }
    const empty = try collectFilesAtRoot(a, root, "bob", "INBOX");
    try t.expectEqual(@as(usize, 0), empty.len);
    const alice = try collectFilesAtRoot(a, root, "alice", "INBOX");
    try t.expectEqual(@as(usize, 3), alice.len);
    try t.expectEqualStrings("100.0.eml:2,S", alice[0].name);
    try t.expectEqualStrings("200.0.eml", alice[1].name);
    try t.expectEqualStrings("300.0.eml:2,S", alice[2].name);
}

test "nested attachments decode exact bytes and quoted filenames" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const raw = "Content-Type: multipart/mixed; boundary=outer\r\n\r\n" ++
        "--outer\r\nContent-Type: multipart/mixed; boundary=inner\r\n\r\n" ++
        "--inner\r\nContent-Type: application/octet-stream\r\n" ++
        "Content-Disposition: attachment; filename=\"a\\\"b.txt\"\r\n" ++
        "Content-Transfer-Encoding: base64\r\n\r\nAAEC/w==\r\n--inner--\r\n--outer--\r\n";
    const body = try extractBestBody(arena.allocator(), raw);
    try t.expectEqual(@as(usize, 1), body.attachments.len);
    try t.expectEqualStrings("a\"b.txt", body.attachments[0].filename);
    try t.expectEqual(@as(usize, 4), body.attachments[0].size);
    try t.expectEqualSlices(u8, &.{ 0, 1, 2, 255 }, body.attachments[0].data);
}

test "search includes complete decoded text and reply headers survive parsing" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const raw = "From: sender@example.com\r\nReply-To: replies@example.com\r\nReferences: <earlier@example.com>\r\nBcc: private@example.com\r\n\r\nBody";
    const headers = try parseHeaders(a, raw);
    try t.expectEqualStrings("replies@example.com", headers.reply_to);
    try t.expectEqualStrings("<earlier@example.com>", headers.references);
    try t.expectEqualStrings("private@example.com", headers.bcc);
    const prefix = try a.alloc(u8, 300);
    @memset(prefix, 'a');
    const text = try std.fmt.allocPrint(a, "{s} UNIQUE-TAIL", .{prefix});
    try t.expect(matchesQuery(headers, .{ .text = text }, "unique-tail"));
    try t.expect(!matchesQuery(headers, .{ .text = text }, "absent"));
}

fn writeTestDraft(a: std.mem.Allocator, db: *database.Database, user: []const u8, raw: []const u8, existing: ?i64) !i64 {
    db.lockMailboxes();
    defer db.unlockMailboxes();
    const write = try prepareDraft(a, db, user, raw.len, existing);
    try write.save(a, db, user, raw);
    return write.uid;
}

test "first draft initializes UIDNEXT and replacement preserves identity" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var db = try database.Database.init(t.allocator, ":memory:");
    defer db.deinit();
    const user = try std.fmt.allocPrint(a, "webmail-drafts-{d}", .{time_compat.milliTimestamp()});
    const root = try std.fmt.allocPrint(a, "mail/{s}", .{user});
    defer fs_compat.cwd().deleteTree(root) catch {};
    const first = try writeTestDraft(a, &db, user, "Subject: first\r\n\r\nOld body", null);
    const same = try writeTestDraft(a, &db, user, "Subject: first\r\n\r\nNew body", first);
    try t.expectEqual(first, same);
    const second = try writeTestDraft(a, &db, user, "Subject: second\r\n\r\nSecond body", null);
    try t.expect(second > first);
    const messages = try listMessages(a, &db, user, "Drafts", 1, 50);
    try t.expectEqual(@as(usize, 2), messages.len);
    const detail = try getMessage(a, &db, user, "Drafts", first);
    try t.expectEqualStrings("New body", detail.text_body);
}

test "adjacent MIME encoded words unfold without inserting body spaces" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const decoded = try decodeMimeWords(arena.allocator(), "=?UTF-8?B?Y2Fm?= =?UTF-8?B?w6k=?= ordinary text");
    try std.testing.expectEqualStrings("café ordinary text", decoded);
}

test "moving a message back into a folder never resurrects its old UID" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var db = try database.Database.init(t.allocator, ":memory:");
    defer db.deinit();
    const user = try std.fmt.allocPrint(a, "webmail-moves-{d}", .{time_compat.milliTimestamp()});
    const root = try std.fmt.allocPrint(a, "mail/{s}", .{user});
    defer fs_compat.cwd().deleteTree(root) catch {};
    const original = try writeTestDraft(a, &db, user, "Subject: move\r\n\r\nBody", null);
    const archived = try moveMessage(a, &db, user, "Drafts", original, "Archive");
    const restored = try moveMessage(a, &db, user, "Archive", archived, "Drafts");
    try t.expect(restored > original);
    try t.expectError(MaildirError.MessageNotFound, getMessage(a, &db, user, "Drafts", original));
    try t.expectEqualStrings("Body", (try getMessage(a, &db, user, "Drafts", restored)).text_body);
}
