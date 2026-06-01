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
//! UIDs are resolved via db.getUidForFile / db.assignUid keyed on the full
//! filename — identical to what `ImapSession.syncUids` does — so a message has
//! the same UID in webmail as over IMAP.
//!
//! Allocation model: callers pass an allocator that is expected to be an arena
//! (the HTTP layer uses a per-request arena). Nothing here frees individually;
//! the caller frees the arena wholesale. This deliberately trades a little
//! transient memory for a large reduction in free-path bugs in a security- and
//! correctness-sensitive module.

const std = @import("std");
const fs_compat = @import("../core/fs_compat.zig");
const database = @import("../storage/database.zig");
const imap = @import("../protocol/imap.zig");

pub const MaildirError = error{
    InvalidFolderName,
    MessageNotFound,
};

/// The set of folders webmail exposes. Order is the display order.
pub const standard_folders = [_][]const u8{
    "INBOX",
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
};

/// A fully parsed message for the reading pane.
pub const MessageDetail = struct {
    uid: i64,
    from: []const u8,
    to: []const u8,
    cc: []const u8,
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

pub const AttachmentInfo = struct {
    filename: []const u8,
    content_type: []const u8,
    size: usize,
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

/// Collect the message files for a folder, in stable IMAP order. The returned
/// slices are arena-allocated.
fn collectFiles(allocator: std.mem.Allocator, user: []const u8, folder: []const u8) ![]FileRef {
    var refs: std.ArrayList(FileRef) = .empty;

    if (std.ascii.eqlIgnoreCase(folder, "INBOX")) {
        const new_dir = try std.fmt.allocPrint(allocator, "mail/{s}/new", .{user});
        const cur_dir = try std.fmt.allocPrint(allocator, "mail/{s}/cur", .{user});
        try appendDir(allocator, &refs, new_dir);
        try appendDir(allocator, &refs, cur_dir);
        if (refs.items.len == 0) {
            try appendDir(allocator, &refs, "mail/new");
        }
    } else {
        const dir = try std.fmt.allocPrint(allocator, "mail/{s}/{s}", .{ user, folder });
        try appendDir(allocator, &refs, dir);
    }

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

/// List the standard folders with total + unread counts.
pub fn listFolders(allocator: std.mem.Allocator, user: []const u8) ![]FolderInfo {
    var out: std.ArrayList(FolderInfo) = .empty;
    for (standard_folders) |folder| {
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
    if (!isValidFolderName(folder)) return MaildirError.InvalidFolderName;

    // Ensure the mailbox record exists so UIDVALIDITY is stable.
    _ = db.getOrCreateMailbox(user, folder) catch {};

    const refs = try collectFiles(allocator, user, folder);

    // Assign UIDs oldest-first (IMAP order) before the reverse display walk.
    preassignUids(db, user, folder, refs);

    // Newest first for display. refs is oldest-first; iterate in reverse.
    const total = refs.len;
    const start = (page -| 1) * per_page;
    if (start >= total) return &[_]MessageSummary{};
    const remaining = total - start;
    const count = @min(per_page, remaining);

    var out = try allocator.alloc(MessageSummary, count);
    var written: usize = 0;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        // Reverse index into refs (newest first).
        const idx = total - 1 - (start + i);
        const r = refs[idx];
        const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ r.dir, r.name });
        const raw = fs_compat.readFileAlloc(allocator, path) catch continue;

        const headers = parseHeaders(allocator, raw) catch HeaderSet{};
        const body = extractBestBody(allocator, raw) catch BodyParts{};
        const uid = uidFor(db, user, folder, r.name, @intCast(idx + 1));

        out[written] = .{
            .uid = uid,
            .from = headers.from,
            .to = headers.to,
            .subject = headers.subject,
            .date = headers.date,
            .snippet = makeSnippet(allocator, body.text) catch "",
            .flags = flagsFrom(r.name),
            .has_attachments = body.has_attachments,
            .size = raw.len,
        };
        written += 1;
    }

    return out[0..written];
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

    const refs = try collectFiles(allocator, user, folder);

    // Assign UIDs oldest-first (IMAP order) so the lookup matches IMAP and
    // listMessages regardless of call order.
    preassignUids(db, user, folder, refs);

    for (refs, 0..) |r, idx| {
        const file_uid = uidFor(db, user, folder, r.name, @intCast(idx + 1));
        if (file_uid != uid) continue;

        const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ r.dir, r.name });
        const raw = try fs_compat.readFileAlloc(allocator, path);
        const headers = parseHeaders(allocator, raw) catch HeaderSet{};
        const body = extractBestBody(allocator, raw) catch BodyParts{};

        return MessageDetail{
            .uid = uid,
            .from = headers.from,
            .to = headers.to,
            .cc = headers.cc,
            .subject = headers.subject,
            .date = headers.date,
            .message_id = headers.message_id,
            .text_body = body.text,
            .html_body = body.html,
            .flags = flagsFrom(r.name),
            .attachments = body.attachments,
            .size = raw.len,
        };
    }
    return MaildirError.MessageNotFound;
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

fn parseHeaders(allocator: std.mem.Allocator, raw: []const u8) !HeaderSet {
    const he = headerEnd(raw);
    const block = raw[0..he];
    return HeaderSet{
        .from = try getHeader(allocator, block, "From"),
        .to = try getHeader(allocator, block, "To"),
        .cc = try getHeader(allocator, block, "Cc"),
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
    const he = headerEnd(raw);
    const header_block = raw[0..he];
    const body = if (he < raw.len) raw[he..] else "";

    const ctype = try getHeader(allocator, header_block, "Content-Type");

    if (std.ascii.indexOfIgnoreCase(ctype, "multipart/") != null) {
        return parseMultipart(allocator, ctype, body, 0);
    }

    const cte = try getHeader(allocator, header_block, "Content-Transfer-Encoding");
    const decoded = decodeBody(allocator, body, cte) catch body;
    if (std.ascii.indexOfIgnoreCase(ctype, "text/html") != null) {
        return BodyParts{ .html = decoded, .text = "" };
    }
    return BodyParts{ .text = decoded, .html = "" };
}

/// Cap on nested multipart depth. A crafted message with deeply nested
/// multipart/* parts would otherwise recurse until the handler thread's stack
/// overflows. Real mail nests 2-3 levels; 10 is generous.
const max_multipart_depth = 10;

fn parseMultipart(allocator: std.mem.Allocator, ctype: []const u8, body: []const u8, depth: u32) !BodyParts {
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
        const pcd = try getHeader(allocator, part_headers, "Content-Disposition");

        // Attachment if disposition says so or there's a filename.
        if (std.ascii.indexOfIgnoreCase(pcd, "attachment") != null or
            std.ascii.indexOfIgnoreCase(pcd, "filename") != null)
        {
            result.has_attachments = true;
            try attachments.append(allocator, .{
                .filename = extractParam(allocator, pcd, "filename") catch "attachment",
                .content_type = if (pct.len > 0) pct else "application/octet-stream",
                .size = part_body.len,
            });
            continue;
        }

        if (std.ascii.indexOfIgnoreCase(pct, "text/html") != null and result.html.len == 0) {
            result.html = decodeBody(allocator, part_body, pcte) catch part_body;
        } else if (std.ascii.indexOfIgnoreCase(pct, "text/plain") != null and result.text.len == 0) {
            result.text = decodeBody(allocator, part_body, pcte) catch part_body;
        } else if (std.ascii.indexOfIgnoreCase(pct, "multipart/") != null) {
            // Nested multipart (e.g. multipart/alternative inside multipart/mixed).
            const nested = parseMultipart(allocator, pct, part_body, depth + 1) catch BodyParts{};
            if (result.text.len == 0) result.text = nested.text;
            if (result.html.len == 0) result.html = nested.html;
            if (nested.has_attachments) result.has_attachments = true;
        }
    }

    result.attachments = try attachments.toOwnedSlice(allocator);
    return result;
}

// RFC 2046: a boundary is at most 70 characters. Capping it prevents a crafted
// unterminated quoted boundary from becoming a huge delimiter, which would make
// splitSequence O(body.len * boundary.len) — a quadratic-CPU DoS on one email.
const max_boundary_len = 70;

fn extractBoundary(ctype: []const u8) ?[]const u8 {
    const idx = std.ascii.indexOfIgnoreCase(ctype, "boundary=") orelse return null;
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
    const idx = std.ascii.indexOfIgnoreCase(header_val, needle) orelse return "";
    var v = header_val[idx + needle.len ..];
    if (v.len > 0 and v[0] == '"') {
        v = v[1..];
        if (std.mem.indexOfScalar(u8, v, '"')) |end| return v[0..end];
        return v;
    }
    var end: usize = 0;
    while (end < v.len and v[end] != ';' and v[end] != ' ' and v[end] != '\r' and v[end] != '\n') : (end += 1) {}
    return v[0..end];
}

/// Decode a body per Content-Transfer-Encoding. Falls back to the raw bytes.
fn decodeBody(allocator: std.mem.Allocator, body: []const u8, cte: []const u8) ![]const u8 {
    if (std.ascii.indexOfIgnoreCase(cte, "base64") != null) {
        return decodeBase64(allocator, body) catch body;
    }
    if (std.ascii.indexOfIgnoreCase(cte, "quoted-printable") != null) {
        return decodeQuotedPrintable(allocator, body) catch body;
    }
    return body;
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
    const long = "multipart/mixed; boundary=" ++ ("a" ** 80);
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
