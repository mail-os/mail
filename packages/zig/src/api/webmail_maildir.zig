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
const search_index = @import("webmail_index.zig");
const html_text = @import("../antispam/html_text.zig");
const thread_ids = @import("../message/thread_ids.zig");
const typesense = @import("../search/typesense.zig");
const ascii_compat = @import("ascii-compat");
const fs_compat = @import("../core/fs_compat.zig");
const hosted_limits = @import("../storage/hosted_limits.zig");
const database = @import("../storage/database.zig");
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
    size: u64,
};

pub const MessageVersion = struct { reference: []const u8, revision: []const u8 };

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

pub const AttachmentInfo = struct {
    filename: []const u8,
    content_type: []const u8,
    size: usize,
    data: []const u8 = "",
    content_id: []const u8 = "",
};

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

fn flagsFrom(filename: []const u8) Flags {
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
const FileRef = struct {
    dir: []const u8,
    name: []const u8,
};

const BodyMode = enum { preview, metadata, full };

/// Collect the message files for a folder, in stable IMAP order. The returned
/// slices are arena-allocated.
fn collectFiles(allocator: std.mem.Allocator, user: []const u8, folder: []const u8) ![]FileRef {
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
            const a = imap.parseMessageSortKey(left.name);
            const b = imap.parseMessageSortKey(right.name);
            if (a != b) return a < b;
            return std.mem.order(u8, left.name, right.name) == .lt;
        }
    }.lessThan);
    return refs.toOwnedSlice(allocator);
}

fn appendDir(allocator: std.mem.Allocator, refs: *std.ArrayList(FileRef), dir: []const u8) !void {
    const files = fs_compat.listEmlFiles(allocator, dir) catch return;
    // listEmlFiles already returns oldest-first stable order.
    for (files) |name| {
        try refs.append(allocator, .{ .dir = dir, .name = name });
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
        if (query.len == 0 and (total < start or out.items.len >= per_page)) {
            total += 1;
            continue;
        }
        var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer scratch.deinit();
        const a = scratch.allocator();
        const path = try std.fmt.allocPrint(a, "{s}/{s}", .{ r.dir, r.name });
        const raw = fs_compat.readFileAlloc(a, path) catch continue;
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
            .flags = flagsFrom(r.name),
            .has_attachments = body.has_attachments,
            .size = raw.len,
            .folder = try allocator.dupe(u8, folder),
            .message_id = try allocator.dupe(u8, headers.message_id),
            .in_reply_to = try allocator.dupe(u8, headers.in_reply_to),
            .references = try allocator.dupe(u8, headers.references),
            .timestamp = messageTimestamp(headers.date, r.name),
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
    const s = try db.prepare("SELECT mailbox FROM imap_mailboxes WHERE username=?1 ORDER BY mailbox");
    defer s.finalize();
    try s.bind(1, user);
    while (try s.step()) {
        const name = s.columnText(0);
        if (!isValidFolderName(name) or std.ascii.eqlIgnoreCase(name, "Screening") or std.ascii.eqlIgnoreCase(name, "Declined")) continue;
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
        preassignUids(db, user, folder, refs);
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
                .uid = uidFor(db, user, folder, ref.name, @intCast(index + 1)),
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
    sortSummaries(rows.items);
    return rows.toOwnedSlice(allocator);
}

fn sortSummaries(rows: []MessageSummary) void {
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
        preassignUids(db, user, folder, refs);
        var cached = try search_index.load(temporary, db, user, folder, options.query);
        var live = std.StringHashMap(void).init(temporary);
        for (refs, 0..) |ref, index| {
            const basename = database.maildirBaseName(ref.name);
            try live.put(basename, {});
            if (options.attention_view) |kind| {
                if (!options.attention_snapshot.?.mayContain(kind, folder, basename)) continue;
            }
            var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer scratch.deinit();
            const work = scratch.allocator();
            const path = try std.fmt.allocPrint(work, "{s}/{s}", .{ ref.dir, ref.name });
            const identity = message_refs.fileFingerprint(work, path) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => return err,
            };
            const doc = document: {
                if (cached.get(basename)) |item| {
                    if (std.mem.eql(u8, item.fingerprint, identity.fingerprint)) break :document item;
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
                .uid = uidFor(db, user, folder, ref.name, @intCast(index + 1)),
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
        if (cached.count() > 0) {
            var keys = cached.keyIterator();
            while (keys.next()) |name| {
                if (live.contains(name.*)) continue;
                try pruneSearchFolder(temporary, db, user, folder, &cached, &live);
                break;
            }
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
    sortSummaries(rows.items);
    return rows.toOwnedSlice(a);
}

fn pruneSearchFolder(a: std.mem.Allocator, db: *database.Database, user: []const u8, folder: []const u8, cached: *std.StringHashMap(search_index.Document), live: *std.StringHashMap(void)) !void {
    db.lockMailboxes();
    defer db.unlockMailboxes();
    // A folder may have changed since enumeration. Recheck before
    // removing a document another request could need.
    for (try collectFiles(a, user, folder)) |file| try live.put(database.maildirBaseName(file.name), {});
    var previous = cached.iterator();
    while (previous.next()) |record| {
        if (!live.contains(record.key_ptr.*))
            try search_index.prune(db, user, folder, record.key_ptr.*, record.value_ptr.fingerprint);
    }
}

fn contains(value: []const u8, needle: []const u8) bool {
    return needle.len == 0 or ascii_compat.indexOfIgnoreCase(value, needle) != null;
}

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
        .fingerprint = fingerprint,
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

fn makeVersion(a: std.mem.Allocator, id: []const u8, at: MessageLocator, name: []const u8, raw_digest: []const u8) !MessageVersion {
    var sha: std.crypto.hash.sha2.Sha256 = .init(.{});
    const metadata = try std.fmt.allocPrint(a, "{s}\x00{s}\x00{d}\x00{s}\x00", .{ id, at.folder, at.uid, name });
    sha.update(metadata);
    sha.update(raw_digest);
    const hex = std.fmt.bytesToHex(sha.finalResult(), .lower);
    return .{ .reference = id, .revision = try std.fmt.allocPrint(a, "\"{s}\"", .{&hex}) };
}

fn fileAt(a: std.mem.Allocator, user: []const u8, location: message_refs.Location) !?FileRef {
    for (try collectFiles(a, user, location.folder)) |file| {
        if (std.mem.eql(u8, location.basename, database.maildirBaseName(file.name))) return file;
    }
    return null;
}

fn matchesStamp(a: std.mem.Allocator, file: FileRef, stamp: []const u8) !bool {
    const path = try std.fmt.allocPrint(a, "{s}/{s}", .{ file.dir, file.name });
    const actual = message_refs.fileStamp(a, path) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return std.mem.eql(u8, stamp, actual);
}

pub fn resolveVersioned(a: std.mem.Allocator, db: *database.Database, user: []const u8, id: []const u8) !VersionedFile {
    if (!message_refs.valid(id)) return MaildirError.MessageNotFound;
    const entry = (try message_refs.lookup(a, db, user, id)) orelse return MaildirError.MessageNotFound;
    var at = entry.location;
    var current = try fileAt(a, user, at);
    const recovering = current == null or !try matchesStamp(a, current.?, entry.stamp);
    if (recovering) {
        const pending = entry.pending orelse return MaildirError.MessageNotFound;
        at = pending.location;
        current = try fileAt(a, user, at);
    }
    const file = current orelse return MaildirError.MessageNotFound;
    const path = try std.fmt.allocPrint(a, "{s}/{s}", .{ file.dir, file.name });
    const stamp = try message_refs.fileStamp(a, path);
    const raw = try fs_compat.readFileAlloc(a, path);
    const checksum = message_refs.digest(raw);
    if (recovering) {
        if (!std.mem.eql(u8, &checksum, entry.pending.?.digest)) return MaildirError.MessageNotFound;
        try message_refs.finish(db, user, id, at, stamp);
    }
    _ = try db.getOrCreateMailbox(user, at.folder);
    preassignUids(db, user, at.folder, try collectFiles(a, user, at.folder));
    const uid = (try db.getUidForFile(user, at.folder, file.name)) orelse return MaildirError.MessageNotFound;
    const locator: MessageLocator = .{ .folder = at.folder, .uid = uid };
    return .{ .locator = locator, .name = file.name, .path = path, .stamp = stamp, .raw = raw, .version = try makeVersion(a, id, locator, file.name, &checksum) };
}

/// The caller holds the mailbox lock for the complete conditional operation.
pub fn checkRevision(a: std.mem.Allocator, db: *database.Database, user: []const u8, id: []const u8, expected: []const u8) !MessageLocator {
    const entry = try resolveVersioned(a, db, user, id);
    if (!std.mem.eql(u8, entry.version.revision, expected)) return MaildirError.RevisionMismatch;
    return entry.locator;
}

pub fn getByReference(a: std.mem.Allocator, db: *database.Database, user: []const u8, id: []const u8) !MessageDetail {
    db.lockMailboxes();
    const entry = resolveVersioned(a, db, user, id);
    db.unlockMailboxes();
    const file = try entry;
    return parseDetail(a, file.locator.folder, file.locator.uid, file.name, file.raw, file.version);
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

/// Build the `:2,FLAGS` Maildir suffix from a Flags value (alphabetical order,
/// matching imap.MaildirFlags.toSuffix: D,F,R,S,T).
fn suffixFor(flags: Flags, buf: []u8) []const u8 {
    var n: usize = 0;
    const prefix = ":2,";
    @memcpy(buf[0..prefix.len], prefix);
    n = prefix.len;
    if (flags.draft) {
        buf[n] = 'D';
        n += 1;
    }
    if (flags.flagged) {
        buf[n] = 'F';
        n += 1;
    }
    if (flags.answered) {
        buf[n] = 'R';
        n += 1;
    }
    if (flags.seen) {
        buf[n] = 'S';
        n += 1;
    }
    if (flags.deleted) {
        buf[n] = 'T';
        n += 1;
    }
    return buf[0..n];
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
        var suffix_buf: [16]u8 = undefined;
        const suffix = suffixFor(flags, &suffix_buf);
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
    if (!isSafeName(ref.name)) return MaildirError.WriteFailed;

    // Destination dir: INBOX lives in new/, other folders in the folder dir.
    const dst_dir = if (std.ascii.eqlIgnoreCase(dst_folder, "INBOX"))
        try std.fmt.allocPrint(allocator, "mail/{s}/new", .{user})
    else
        try std.fmt.allocPrint(allocator, "mail/{s}/{s}", .{ user, dst_folder });
    fs_compat.ensureDir(dst_dir) catch {};

    const old_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ ref.dir, ref.name });
    const new_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dst_dir, ref.name });

    // Assign the destination UID FIRST. UID keying is on the base name, so this
    // is correct regardless of the physical move; doing it before the move means
    // a UID failure aborts cleanly without leaving an orphaned file, and the
    // returned UID is always the real destination UID (never a stale source one).
    // A destination that already contains this name must not be overwritten.
    const source = message_refs.location(src_folder, ref.name);
    const target = message_refs.location(dst_folder, ref.name);
    if (try fileAt(allocator, user, target) != null) return MaildirError.Conflict;
    const dst_uid = try db.assignFreshUid(user, dst_folder, ref.name);
    const transfer = try message_refs.stageMove(allocator, db, user, source, old_path, target, null, junk);
    if (junk != null and transfer == null) return MaildirError.Conflict;
    errdefer if (transfer) |id| message_refs.cancel(db, user, id);

    // Prefer an atomic rename; fall back to copy+unlink across filesystems.
    if (!renamePath(old_path, new_path)) {
        const content = fs_compat.readFileAlloc(allocator, old_path) catch return MaildirError.WriteFailed;
        const f = fs_compat.cwd().createFile(new_path, .{}) catch return MaildirError.WriteFailed;
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
    if (typesense.enabled() and (junk != null or categories.isCategory(source_folder) or categories.isCategory(target_folder))) {
        if (fs_compat.readFileAlloc(allocator, new_path)) |raw| {
            defer allocator.free(raw);
            typesense.indexMessageAsync(std.heap.page_allocator, user, target_folder, ref.name, raw);
        } else |err| std.log.warn("could not read moved mail for search: {}", .{err});
    }
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

const BodyParts = struct {
    text: []const u8 = "",
    html: []const u8 = "",
    has_attachments: bool = false,
    attachments: []const AttachmentInfo = &[_]AttachmentInfo{},
};

/// Find the end of the header block (the blank line). Returns the index just
/// past the CRLF CRLF (or LF LF), or raw.len if no body.
fn headerEnd(raw: []const u8) usize {
    if (std.mem.indexOf(u8, raw, "\r\n\r\n")) |i| return i + 4;
    if (std.mem.indexOf(u8, raw, "\n\n")) |i| return i + 2;
    return raw.len;
}

/// Unfold a header value (RFC 5322 folding: a CRLF followed by WSP is a single
/// space) and trim. Arena-allocated.
fn unfold(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < value.len) : (i += 1) {
        const c = value[i];
        if (c == '\r') continue;
        if (c == '\n') {
            // Folded continuation if next is WSP; collapse to a space.
            if (i + 1 < value.len and (value[i + 1] == ' ' or value[i + 1] == '\t')) {
                try out.append(allocator, ' ');
                // Skip the following run of WSP.
                while (i + 1 < value.len and (value[i + 1] == ' ' or value[i + 1] == '\t')) : (i += 1) {}
                continue;
            }
            break; // unfolded end of value
        }
        try out.append(allocator, c);
    }
    return std.mem.trim(u8, try out.toOwnedSlice(allocator), " \t");
}

/// Case-insensitive header lookup over the header block. Returns the unfolded,
/// decoded value, or "".
fn getHeader(allocator: std.mem.Allocator, header_block: []const u8, name: []const u8) ![]const u8 {
    var line_start: usize = 0;
    while (line_start < header_block.len) {
        // Find end of this logical line (account for folding).
        var line_end = std.mem.indexOfScalarPos(u8, header_block, line_start, '\n') orelse header_block.len;
        // Extend over folded continuations.
        while (line_end + 1 < header_block.len and (header_block[line_end + 1] == ' ' or header_block[line_end + 1] == '\t')) {
            line_end = std.mem.indexOfScalarPos(u8, header_block, line_end + 1, '\n') orelse header_block.len;
        }
        const line = header_block[line_start..line_end];
        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            const key = std.mem.trim(u8, line[0..colon], " \t");
            if (std.ascii.eqlIgnoreCase(key, name)) {
                const raw_val = line[colon + 1 ..];
                const unfolded = try unfold(allocator, raw_val);
                return decodeMimeWords(allocator, unfolded) catch unfolded;
            }
        }
        line_start = line_end + 1;
    }
    return "";
}

pub fn mimeHeader(a: std.mem.Allocator, raw: []const u8, name: []const u8) ![]const u8 {
    return getHeader(a, raw[0..headerEnd(raw)], name);
}

fn parseHeaders(allocator: std.mem.Allocator, raw: []const u8) !HeaderSet {
    const he = headerEnd(raw);
    const block = raw[0..he];
    return HeaderSet{
        .from = try getHeader(allocator, block, "From"),
        .to = try getHeader(allocator, block, "To"),
        .cc = try getHeader(allocator, block, "Cc"),
        .bcc = try getHeader(allocator, block, "Bcc"),
        .reply_to = try getHeader(allocator, block, "Reply-To"),
        .in_reply_to = try getHeader(allocator, block, "In-Reply-To"),
        .references = try getHeader(allocator, block, "References"),
        .subject = try getHeader(allocator, block, "Subject"),
        .date = try getHeader(allocator, block, "Date"),
        .message_id = try getHeader(allocator, block, "Message-ID"),
        .content_type = try getHeader(allocator, block, "Content-Type"),
    };
}

/// Extract the best text and html body parts. Handles:
///   - single-part text/plain or text/html
///   - simple multipart/* (splits on boundary, picks text + html parts)
/// Quoted-printable and base64 transfer encodings are decoded for text parts.
fn extractBestBody(allocator: std.mem.Allocator, raw: []const u8) !BodyParts {
    return extractBody(allocator, raw, .full);
}

fn extractBody(allocator: std.mem.Allocator, raw: []const u8, mode: BodyMode) !BodyParts {
    const he = headerEnd(raw);
    const header_block = raw[0..he];
    const body = if (he < raw.len) raw[he..] else "";

    const ctype = try getHeader(allocator, header_block, "Content-Type");

    if (ascii_compat.indexOfIgnoreCase(ctype, "multipart/") != null) {
        return parseMultipartMode(allocator, ctype, body, 0, mode);
    }

    const cte = try getHeader(allocator, header_block, "Content-Transfer-Encoding");
    if (try attachmentName(allocator, header_block, ctype)) |name| {
        if (mode == .preview) return .{ .has_attachments = true };
        const files = try allocator.alloc(AttachmentInfo, 1);
        files[0] = try readAttachment(allocator, body, ctype, cte, name, mode);
        return .{ .has_attachments = true, .attachments = files };
    }
    const decoded = decodeBody(allocator, body, cte) catch body;
    if (ascii_compat.indexOfIgnoreCase(ctype, "text/html") != null) {
        return BodyParts{ .html = decoded, .text = "" };
    }
    return BodyParts{ .text = decoded, .html = "" };
}

/// Cap on nested multipart depth. A crafted message with deeply nested
/// multipart/* parts would otherwise recurse until the handler thread's stack
/// overflows. Real mail nests 2-3 levels; 10 is generous.
const max_multipart_depth = 10;

fn parseMultipart(allocator: std.mem.Allocator, ctype: []const u8, body: []const u8, depth: u32) !BodyParts {
    return parseMultipartMode(allocator, ctype, body, depth, .full);
}

fn parseMultipartMode(allocator: std.mem.Allocator, ctype: []const u8, body: []const u8, depth: u32, mode: BodyMode) !BodyParts {
    // Bound recursion: beyond the cap, treat the remainder as opaque text.
    if (depth >= max_multipart_depth) return BodyParts{ .text = body };

    const boundary = extractBoundary(ctype) orelse return BodyParts{ .text = body };
    // A null/empty boundary would make delim "--", splitting on every "--" run
    // and spawning spurious parts. Treat as single-part.
    if (boundary.len == 0) return BodyParts{ .text = body };
    const delim = try std.fmt.allocPrint(allocator, "--{s}", .{boundary});

    var result = BodyParts{};
    var attachments: std.ArrayList(AttachmentInfo) = .empty;

    var it = std.mem.splitSequence(u8, body, delim);
    while (it.next()) |part_raw| {
        const part = std.mem.trim(u8, part_raw, "\r\n");
        if (part.len == 0 or std.mem.eql(u8, part, "--")) continue;

        const phe = headerEnd(part);
        const part_headers = part[0..phe];
        const part_body = if (phe < part.len) part[phe..] else "";

        const pct = try getHeader(allocator, part_headers, "Content-Type");
        const pcte = try getHeader(allocator, part_headers, "Content-Transfer-Encoding");
        if (try attachmentName(allocator, part_headers, pct)) |name| {
            result.has_attachments = true;
            if (mode != .preview) try attachments.append(allocator, try readAttachment(allocator, part_body, pct, pcte, name, mode));
            continue;
        }

        if (ascii_compat.indexOfIgnoreCase(pct, "text/html") != null and result.html.len == 0) {
            result.html = decodeBody(allocator, part_body, pcte) catch part_body;
        } else if (ascii_compat.indexOfIgnoreCase(pct, "text/plain") != null and result.text.len == 0) {
            result.text = decodeBody(allocator, part_body, pcte) catch part_body;
        } else if (ascii_compat.indexOfIgnoreCase(pct, "multipart/") != null) {
            // Nested multipart (e.g. multipart/alternative inside multipart/mixed).
            const nested = parseMultipartMode(allocator, pct, part_body, depth + 1, mode) catch BodyParts{};
            if (result.text.len == 0) result.text = nested.text;
            if (result.html.len == 0) result.html = nested.html;
            if (nested.has_attachments) result.has_attachments = true;
            try attachments.appendSlice(allocator, nested.attachments);
        }
    }

    result.attachments = try attachments.toOwnedSlice(allocator);
    return result;
}

const AttachmentName = struct { filename: []const u8, id: []const u8 };

/// Read one already-framed MIME entity using the same file conventions as webmail.
pub fn inspectAttachment(a: std.mem.Allocator, raw: []const u8, include_data: bool) !?AttachmentInfo {
    const end = headerEnd(raw);
    const headers = raw[0..end];
    const mime = try getHeader(a, headers, "Content-Type");
    const name = (try attachmentName(a, headers, mime)) orelse return null;
    const encoding = try getHeader(a, headers, "Content-Transfer-Encoding");
    var info = try readAttachment(a, raw[end..], mime, encoding, name, if (include_data) .full else .metadata);
    info.content_id = contentId(try getHeader(a, headers, "Content-ID"));
    return info;
}

fn attachmentName(a: std.mem.Allocator, headers: []const u8, mime: []const u8) !?AttachmentName {
    const disposition = try getHeader(a, headers, "Content-Disposition");
    const id = if (std.ascii.startsWithIgnoreCase(mime, "image/"))
        contentId(try getHeader(a, headers, "Content-ID"))
    else
        "";
    const extended = try extractParam(a, disposition, "filename*");
    if (extended.len > 0) {
        if (std.mem.indexOfScalar(u8, extended, '\'')) |charset_end| {
            if (std.mem.indexOfScalarPos(u8, extended, charset_end + 1, '\'')) |lang_end| {
                const encoded = extended[lang_end + 1 ..];
                const decoded = std.Uri.percentDecodeBackwards(try a.alloc(u8, encoded.len), encoded);
                if (decoded.len > 0 and std.unicode.utf8ValidateSlice(decoded)) return .{ .filename = decoded, .id = id };
            }
        }
    }
    const filename = try extractParam(a, disposition, "filename");
    if (filename.len > 0) return .{ .filename = filename, .id = id };
    if (!std.ascii.startsWithIgnoreCase(mime, "multipart/")) {
        const name = try extractParam(a, mime, "name");
        if (name.len > 0) return .{ .filename = name, .id = id };
    }
    if (id.len > 0) return .{ .filename = "inline-image", .id = id };
    const separator = std.mem.indexOfScalar(u8, disposition, ';') orelse disposition.len;
    const kind = std.mem.trim(u8, disposition[0..separator], " \t");
    if (std.ascii.eqlIgnoreCase(kind, "attachment")) return .{ .filename = "attachment", .id = "" };
    return null;
}

fn readAttachment(a: std.mem.Allocator, raw: []const u8, mime: []const u8, encoding: []const u8, name: AttachmentName, mode: BodyMode) !AttachmentInfo {
    const data = if (mode == .full) try decodeBody(a, raw, encoding) else "";
    return .{
        .filename = name.filename,
        .content_type = if (mime.len > 0) mime else "application/octet-stream",
        .size = if (mode == .full) data.len else try attachmentSize(a, raw, encoding),
        .data = data,
        .content_id = name.id,
    };
}

fn contentId(s: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, s, " \t\r\n");
    const id = if (trimmed.len >= 2 and trimmed[0] == '<' and trimmed[trimmed.len - 1] == '>') trimmed[1 .. trimmed.len - 1] else trimmed;
    if (id.len > 320) return "";
    for (id) |byte| {
        if (!std.ascii.isPrint(byte) or byte == ' ' or byte == '<' or byte == '>') return "";
    }
    return id;
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

// RFC 2046: a boundary is at most 70 characters. Capping it prevents a crafted
// unterminated quoted boundary from becoming a huge delimiter, which would make
// splitSequence O(body.len * boundary.len) — a quadratic-CPU DoS on one email.
const max_boundary_len = 70;

fn extractBoundary(ctype: []const u8) ?[]const u8 {
    const idx = ascii_compat.indexOfIgnoreCase(ctype, "boundary=") orelse return null;
    var v = ctype[idx + "boundary=".len ..];
    if (v.len > 0 and v[0] == '"') {
        v = v[1..];
        if (std.mem.indexOfScalar(u8, v, '"')) |end| {
            if (end > max_boundary_len) return null;
            return v[0..end];
        }
        // Unterminated quoted boundary — reject rather than swallow the rest.
        return null;
    }
    // Unquoted: ends at ; or whitespace.
    var end: usize = 0;
    while (end < v.len and v[end] != ';' and v[end] != ' ' and v[end] != '\t' and v[end] != '\r' and v[end] != '\n') : (end += 1) {}
    if (end == 0 or end > max_boundary_len) return null;
    return v[0..end];
}

/// Extract a parameter value like filename="x" from a header value.
fn extractParam(allocator: std.mem.Allocator, header_val: []const u8, param: []const u8) ![]const u8 {
    const needle = try std.fmt.allocPrint(allocator, "{s}=", .{param});
    const idx = ascii_compat.indexOfIgnoreCase(header_val, needle) orelse return "";
    var v = header_val[idx + needle.len ..];
    if (v.len > 0 and v[0] == '"') {
        var decoded: std.ArrayList(u8) = .empty;
        var i: usize = 1;
        while (i < v.len) : (i += 1) {
            if (v[i] == '"') break;
            if (v[i] == '\\' and i + 1 < v.len) i += 1;
            try decoded.append(allocator, v[i]);
        }
        return decoded.toOwnedSlice(allocator);
    }
    var end: usize = 0;
    while (end < v.len and v[end] != ';' and v[end] != ' ' and v[end] != '\r' and v[end] != '\n') : (end += 1) {}
    return v[0..end];
}

/// Decode a body per Content-Transfer-Encoding. Falls back to the raw bytes.
fn decodeBody(allocator: std.mem.Allocator, body: []const u8, cte: []const u8) ![]const u8 {
    if (ascii_compat.indexOfIgnoreCase(cte, "base64") != null) {
        return decodeBase64(allocator, body) catch body;
    }
    if (ascii_compat.indexOfIgnoreCase(cte, "quoted-printable") != null) {
        return decodeQuotedPrintable(allocator, body) catch body;
    }
    return body;
}

fn attachmentSize(a: std.mem.Allocator, body: []const u8, cte: []const u8) !usize {
    if (ascii_compat.indexOfIgnoreCase(cte, "base64") == null) return (try decodeBody(a, body, cte)).len;
    var length: usize = 0;
    var padding: usize = 0;
    var last: u8 = 0;
    for (body) |c| switch (c) {
        ' ', '\t', '\r', '\n' => continue,
        '=' => padding += 1,
        else => {
            if (padding != 0) return body.len;
            last = @intCast(std.mem.indexOfScalar(u8, &std.base64.standard_alphabet_chars, c) orelse return body.len);
            length += 1;
        },
    };
    if (padding > 2 or (length + padding) % 4 != 0 or (padding == 1 and last % 4 != 0) or
        (padding == 2 and last % 16 != 0)) return body.len;
    return length * 6 / 8;
}

fn decodeBase64(allocator: std.mem.Allocator, body: []const u8) ![]const u8 {
    // Strip whitespace/newlines before decoding.
    var clean: std.ArrayList(u8) = .empty;
    for (body) |c| {
        if (c == '\r' or c == '\n' or c == ' ' or c == '\t') continue;
        try clean.append(allocator, c);
    }
    const cleaned = try clean.toOwnedSlice(allocator);
    const decoder = std.base64.standard.Decoder;
    const len = decoder.calcSizeForSlice(cleaned) catch return body;
    const out = try allocator.alloc(u8, len);
    decoder.decode(out, cleaned) catch return body;
    return out;
}

fn decodeQuotedPrintable(allocator: std.mem.Allocator, body: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < body.len) : (i += 1) {
        const c = body[i];
        if (c == '=' and i + 2 < body.len) {
            // Soft line break "=\r\n" or "=\n"
            if (body[i + 1] == '\r' and body[i + 2] == '\n') {
                i += 2;
                continue;
            }
            if (body[i + 1] == '\n') {
                i += 1;
                continue;
            }
            const hi = hexVal(body[i + 1]);
            const lo = hexVal(body[i + 2]);
            if (hi != null and lo != null) {
                try out.append(allocator, hi.? * 16 + lo.?);
                i += 2;
                continue;
            }
        }
        try out.append(allocator, c);
    }
    return out.toOwnedSlice(allocator);
}

fn hexVal(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'A'...'F' => c - 'A' + 10,
        'a'...'f' => c - 'a' + 10,
        else => null,
    };
}

/// Decode RFC 2047 encoded-words in a header (=?charset?B?...?= / ?Q?...?=).
/// Best-effort: only the encoded-word payloads are decoded; charset is ignored
/// (assumed UTF-8/Latin-1 compatible for display).
fn decodeMimeWords(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    if (std.mem.indexOf(u8, value, "=?") == null) return value;

    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < value.len) {
        if (i + 1 < value.len and value[i] == '=' and value[i + 1] == '?') {
            // Parse =?charset?enc?text?=
            const start = i + 2;
            const q1 = std.mem.indexOfScalarPos(u8, value, start, '?') orelse {
                try out.append(allocator, value[i]);
                i += 1;
                continue;
            };
            if (q1 + 2 >= value.len or value[q1 + 2] != '?') {
                try out.append(allocator, value[i]);
                i += 1;
                continue;
            }
            const enc = value[q1 + 1];
            const text_start = q1 + 3;
            const end = std.mem.indexOfPos(u8, value, text_start, "?=") orelse {
                try out.append(allocator, value[i]);
                i += 1;
                continue;
            };
            const encoded = value[text_start..end];
            const decoded = switch (enc) {
                'B', 'b' => decodeBase64(allocator, encoded) catch encoded,
                'Q', 'q' => decodeEncodedWordQ(allocator, encoded) catch encoded,
                else => encoded,
            };
            try out.appendSlice(allocator, decoded);
            i = end + 2;
            // RFC 2047: whitespace between adjacent encoded-words is folding,
            // not part of the decoded header value.
            var next = i;
            while (next < value.len and std.ascii.isWhitespace(value[next])) next += 1;
            if (std.mem.startsWith(u8, value[next..], "=?")) i = next;
        } else {
            try out.append(allocator, value[i]);
            i += 1;
        }
    }
    return out.toOwnedSlice(allocator);
}

/// RFC 2047 "Q" encoding: like quoted-printable but '_' means space.
fn decodeEncodedWordQ(allocator: std.mem.Allocator, encoded: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < encoded.len) : (i += 1) {
        const c = encoded[i];
        if (c == '_') {
            try out.append(allocator, ' ');
        } else if (c == '=' and i + 2 < encoded.len) {
            const hi = hexVal(encoded[i + 1]);
            const lo = hexVal(encoded[i + 2]);
            if (hi != null and lo != null) {
                try out.append(allocator, hi.? * 16 + lo.?);
                i += 2;
            } else {
                try out.append(allocator, c);
            }
        } else {
            try out.append(allocator, c);
        }
    }
    return out.toOwnedSlice(allocator);
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
    // wholesale). unfold()/trim return sub-slices, so individual frees are unsafe
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

test "quoted-printable decode" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const decoded = try decodeQuotedPrintable(a, "Hi=20there=3D");
    try t.expectEqualStrings("Hi there=", decoded);
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

test "extractBoundary rejects oversized and unterminated boundaries" {
    const t = std.testing;
    // Normal quoted boundary.
    try t.expectEqualStrings("XYZ", extractBoundary("multipart/mixed; boundary=\"XYZ\"").?);
    // Unquoted boundary.
    try t.expectEqualStrings("abc", extractBoundary("multipart/mixed; boundary=abc").?);
    // Unterminated quoted boundary -> rejected (would otherwise become a huge delimiter).
    try t.expect(extractBoundary("multipart/mixed; boundary=\"aaaaaaaaaa") == null);
    // Over 70 chars -> rejected.
    const long = "multipart/mixed; boundary=" ++ @as([80]u8, @splat('a'));
    try t.expect(extractBoundary(long) == null);
    // Missing boundary -> null.
    try t.expect(extractBoundary("multipart/mixed") == null);
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
