const std = @import("std");
const imap_mime = @import("imap_mime.zig");
const clamav = @import("../antispam/clamav.zig");
const builtin = @import("builtin");
const ascii_compat = @import("ascii-compat");
const mutex_compat = @import("../core/mutex_compat.zig");
const posix = std.posix;
const time_compat = @import("../core/time_compat.zig");
const socket = @import("../core/socket_compat.zig");
const io_compat = @import("../core/io_compat.zig");
const auth = @import("../auth/auth.zig");
const logger = @import("../core/logger.zig");
const log_safe = @import("../core/log_safe.zig");
const tls_mod = @import("../core/tls.zig");
const tls = @import("tls");
const search = @import("imap_search.zig");
const hosted_limits = @import("../storage/hosted_limits.zig");
const folder_edits = @import("../storage/folder_edits.zig");
const maildir_folders = @import("../storage/maildir_folders.zig");
const maildir_keywords = @import("../storage/maildir_keywords.zig");
const message_refs = @import("../storage/message_refs.zig");
const sent_replies = @import("../delivery/smtp_sent_replies.zig");
const durable_maildir = @import("../core/durable_maildir.zig");
const fs_compat = @import("../core/fs_compat.zig");
const database = @import("../storage/database.zig");
const client_passwords = @import("../storage/client_passwords.zig");
const typesense = @import("../search/typesense.zig");
const maildir_index = @import("../search/maildir_index.zig");
const draft_expunge = @import("../api/webmail_draft_expunge.zig");

// std.posix.getpid is not available on this Zig version's std; libc is linked
// (the binary links sqlite3 + libc), so declare the C symbol directly.
extern "c" fn getpid() c_int;
extern "c" fn readlink(path: [*:0]const u8, buf: [*]u8, bufsiz: usize) isize;
extern "c" fn symlink(target: [*:0]const u8, linkpath: [*:0]const u8) c_int;

/// Upper bound on an APPEND literal we are willing to buffer in memory, to
/// prevent a client from exhausting server memory with a huge {N} literal.
/// Matches the server's default max_message_size (50 MB).
const max_append_literal_size: usize = 50 * 1024 * 1024;

/// Strip surrounding double quotes from an IMAP token.
/// IMAP clients (e.g. Python imaplib) quote usernames and passwords.
fn stripQuotes(s: []const u8) []const u8 {
    if (s.len >= 2 and s[0] == '"' and s[s.len - 1] == '"') {
        return s[1 .. s.len - 1];
    }
    return s;
}

/// Reject mailbox names that could escape the user's maildir when interpolated
/// into a filesystem path (path traversal / cross-user access). Mailbox paths
/// are built as `mail/{local_part}/{name}`, so any '/', '\\', NUL, a leading
/// '.', or a ".." segment is forbidden. The hierarchy separator advertised to
/// clients is "/", but this server stores folders as flat single-level names,
/// so a legitimate mailbox name never contains a path separator.
fn isSafeMailboxName(raw: []const u8) bool {
    maildir_folders.validateName(stripQuotes(raw)) catch return false;
    return true;
}

fn canonicalMailboxName(name: []const u8) []const u8 {
    if (std.ascii.eqlIgnoreCase(name, "INBOX")) return "INBOX";
    if (std.ascii.eqlIgnoreCase(name, "All Mail") or std.ascii.eqlIgnoreCase(name, "All")) return "All Mail";
    return name;
}

/// IMAP4rev1 Server Implementation (RFC 3501)
/// Provides mail retrieval and mailbox management via IMAP protocol
///
/// Features:
/// - IMAP4rev1 protocol support (RFC 3501)
/// - IDLE support for push notifications (RFC 2177)
/// - Multiple mailbox support
/// - Message flags and keywords
/// - Search capabilities
/// - SSL/TLS support (STARTTLS)
/// - SASL authentication
/// - Mailbox subscriptions
/// - Message status tracking
/// IMAP server configuration
pub const ImapConfig = struct {
    port: u16 = 143,
    ssl_port: u16 = 993,
    /// Interface to bind. Defaults to every interface, which is what a mail
    /// server wants — a client connects from another machine by definition.
    /// A server confined to one host (a development catcher, a box behind a
    /// proxy that terminates TLS) passes its own bind address here instead.
    bind_host: []const u8 = "0.0.0.0",
    enable_ssl: bool = true,
    max_connections: usize = 100,
    connection_timeout_seconds: u64 = 300,
    idle_timeout_seconds: u64 = 1800,
    max_message_size: usize = 50 * 1024 * 1024, // 50 MB
    mailbox_path: []const u8 = "/var/spool/mail",
    // TLS configuration
    cert_path: ?[]const u8 = null,
    key_path: ?[]const u8 = null,
    /// Advertise the optional Gmail-style aggregate/category mailboxes.
    enable_gmail_labels: bool = true,
    junk_folder: []const u8 = "Junk",
};

/// IMAP connection state
pub const ImapState = enum {
    not_authenticated,
    authenticated,
    selected,
    logout,
};

/// IMAP capabilities
pub const ImapCapability = enum {
    imap4rev1,
    starttls,
    auth_plain,
    auth_login,
    idle,
    namespace,
    uidplus,
    unselect,
    children,
    quota,
    sort,
    thread,
    special_use, // RFC 6154 - SPECIAL-USE for Gmail-style folders
    move, // RFC 6851 - MOVE extension
    maildir_keywords,

    pub fn toString(self: ImapCapability) []const u8 {
        return switch (self) {
            .imap4rev1 => "IMAP4rev1",
            .starttls => "STARTTLS",
            .auth_plain => "AUTH=PLAIN",
            .auth_login => "AUTH=LOGIN",
            .idle => "IDLE",
            .namespace => "NAMESPACE",
            .uidplus => "UIDPLUS",
            .unselect => "UNSELECT",
            .children => "CHILDREN",
            .quota => "QUOTA",
            .sort => "SORT",
            .thread => "THREAD",
            .special_use => "SPECIAL-USE",
            .move => "MOVE",
            .maildir_keywords => "XMAILDIR-KEYWORDS",
        };
    }
};

/// Folder type for Gmail-style folders
pub const FolderType = enum {
    inbox,
    sent,
    drafts,
    trash,
    junk,
    archive,
    all_mail,
    starred,
    important,
    social,
    forums,
    updates,
    promotions,
    notes,
    regular,

    /// Get the SPECIAL-USE attributes for this folder type
    pub fn getAttributes(self: FolderType) []const u8 {
        return switch (self) {
            .inbox => "\\HasNoChildren",
            .sent => "\\HasNoChildren \\Sent",
            .drafts => "\\HasNoChildren \\Drafts",
            .trash => "\\HasNoChildren \\Trash",
            .junk => "\\HasNoChildren \\Junk",
            .archive => "\\HasNoChildren \\Archive",
            // Keep All Mail visible without claiming Gmail's canonical `\\All`
            // semantics. Apple Mail otherwise moves the Inbox unread badge to
            // this aggregate view even though the message is still in INBOX.
            .all_mail => "\\HasNoChildren",
            .starred => "\\HasNoChildren \\Flagged",
            .important => "\\HasNoChildren \\Important",
            .social => "\\HasNoChildren",
            .forums => "\\HasNoChildren",
            .updates => "\\HasNoChildren",
            .promotions => "\\HasNoChildren",
            .notes => "\\HasNoChildren",
            .regular => "\\HasNoChildren",
        };
    }

    /// Get the display name for this folder type
    pub fn getName(self: FolderType) []const u8 {
        return switch (self) {
            .inbox => "INBOX",
            .sent => "Sent",
            .drafts => "Drafts",
            .trash => "Trash",
            .junk => "Junk",
            .archive => "Archive",
            .all_mail => "All Mail",
            .starred => "Starred",
            .important => "Important",
            .social => "Social",
            .forums => "Forums",
            .updates => "Updates",
            .promotions => "Promotions",
            .notes => "Notes",
            .regular => "",
        };
    }

    /// Check if this is a virtual folder (computed from flags, not stored separately)
    pub fn isVirtual(self: FolderType) bool {
        return switch (self) {
            .starred, .important, .all_mail => true,
            else => false,
        };
    }
};

/// Standard and optional Gmail-style mailboxes in display order.
pub const GmailFolders = [_]FolderType{
    .inbox,
    .starred,
    .important,
    .sent,
    .drafts,
    .all_mail,
    .junk,
    .trash,
    .archive,
    .notes,
    .social,
    .forums,
    .updates,
    .promotions,
};

/// IMAP message flags
pub const MessageFlags = struct {
    seen: bool = false,
    answered: bool = false,
    flagged: bool = false,
    deleted: bool = false,
    draft: bool = false,
    recent: bool = false,

    pub fn toString(self: MessageFlags, allocator: std.mem.Allocator) ![]const u8 {
        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();

        try writer.writeAll("(");
        var has_flag = false;

        if (self.seen) {
            try writer.writeAll("\\Seen");
            has_flag = true;
        }
        if (self.answered) {
            if (has_flag) try writer.writeAll(" ");
            try writer.writeAll("\\Answered");
            has_flag = true;
        }
        if (self.flagged) {
            if (has_flag) try writer.writeAll(" ");
            try writer.writeAll("\\Flagged");
            has_flag = true;
        }
        if (self.deleted) {
            if (has_flag) try writer.writeAll(" ");
            try writer.writeAll("\\Deleted");
            has_flag = true;
        }
        if (self.draft) {
            if (has_flag) try writer.writeAll(" ");
            try writer.writeAll("\\Draft");
            has_flag = true;
        }
        if (self.recent) {
            if (has_flag) try writer.writeAll(" ");
            try writer.writeAll("\\Recent");
        }
        try writer.writeAll(")");

        return allocator.dupe(u8, fbs.getWritten());
    }
};

/// IMAP mailbox
pub const Mailbox = struct {
    name: []const u8,
    path: []const u8,
    exists: usize = 0, // Number of messages
    recent: usize = 0, // Number of recent messages
    unseen: usize = 0, // Number of unseen messages
    uidvalidity: u32,
    uidnext: u32,
    flags: std.ArrayList([]const u8),
    permanent_flags: std.ArrayList([]const u8),

    pub fn init(allocator: std.mem.Allocator, name: []const u8, path: []const u8) !Mailbox {
        return Mailbox{
            .name = try allocator.dupe(u8, name),
            .path = try allocator.dupe(u8, path),
            .uidvalidity = @intCast(time_compat.timestamp()),
            .uidnext = 1,
            .flags = .empty,
            .permanent_flags = .empty,
        };
    }

    pub fn deinit(self: *Mailbox, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.path);
        for (self.flags.items) |flag| {
            allocator.free(flag);
        }
        self.flags.deinit(allocator);
        for (self.permanent_flags.items) |flag| {
            allocator.free(flag);
        }
        self.permanent_flags.deinit(allocator);
    }
};

/// IMAP message
pub const ImapMessage = struct {
    uid: u32,
    sequence: u32,
    size: usize,
    flags: MessageFlags,
    internal_date: i64,
    envelope: ?[]const u8 = null,
    body_structure: ?[]const u8 = null,

    pub fn deinit(self: *ImapMessage, allocator: std.mem.Allocator) void {
        if (self.envelope) |env| allocator.free(env);
        if (self.body_structure) |bs| allocator.free(bs);
    }
};

/// IMAP command
pub const ImapCommand = enum {
    // Any state
    capability,
    noop,
    logout,

    // Not authenticated
    starttls,
    authenticate,
    login,

    // Authenticated
    select,
    examine,
    create,
    delete,
    rename,
    subscribe,
    unsubscribe,
    list,
    xlist, // Gmail extension
    lsub,
    status,
    append,

    // Selected
    check,
    close,
    unselect,
    expunge,
    search,
    fetch,
    store,
    copy,
    move,
    uid,
    idle,
    namespace,
    enable,
    id,

    pub fn fromString(cmd: []const u8) ?ImapCommand {
        const upper = std.ascii.allocUpperString(std.heap.page_allocator, cmd) catch return null;
        defer std.heap.page_allocator.free(upper);

        const commands = std.StaticStringMap(ImapCommand).initComptime(.{
            .{ "CAPABILITY", .capability },
            .{ "NOOP", .noop },
            .{ "LOGOUT", .logout },
            .{ "STARTTLS", .starttls },
            .{ "AUTHENTICATE", .authenticate },
            .{ "LOGIN", .login },
            .{ "SELECT", .select },
            .{ "EXAMINE", .examine },
            .{ "CREATE", .create },
            .{ "DELETE", .delete },
            .{ "RENAME", .rename },
            .{ "SUBSCRIBE", .subscribe },
            .{ "UNSUBSCRIBE", .unsubscribe },
            .{ "LIST", .list },
            .{ "XLIST", .xlist },
            .{ "LSUB", .lsub },
            .{ "STATUS", .status },
            .{ "APPEND", .append },
            .{ "CHECK", .check },
            .{ "CLOSE", .close },
            .{ "UNSELECT", .unselect },
            .{ "EXPUNGE", .expunge },
            .{ "SEARCH", .search },
            .{ "FETCH", .fetch },
            .{ "STORE", .store },
            .{ "COPY", .copy },
            .{ "MOVE", .move },
            .{ "UID", .uid },
            .{ "IDLE", .idle },
            .{ "NAMESPACE", .namespace },
            .{ "ENABLE", .enable },
            .{ "ID", .id },
        });

        return commands.get(upper);
    }
};

/// Parse IMAP sequence sets like "1", "1:5", "1,3,5", "1:3,7", "*".
/// Sequence numbers are 1-based. "*" maps to max_seq.
pub const SequenceIterator = struct {
    data: []const u8,
    pos: usize = 0,
    // Current range state
    range_current: u32 = 0,
    range_end: u32 = 0,
    max_seq: u32,

    pub fn init(seq_set: []const u8, file_count: usize) SequenceIterator {
        return .{
            .data = seq_set,
            .max_seq = if (file_count > 0) @intCast(file_count) else 0,
        };
    }

    pub fn next(self: *SequenceIterator) ?u32 {
        // Continue yielding from current range
        while (self.range_current <= self.range_end) {
            const val = self.range_current;
            self.range_current += 1;
            if (val >= 1 and val <= self.max_seq) return val;
        }

        // Parse next element from sequence set
        if (self.pos >= self.data.len) return null;

        // Skip comma separators
        if (self.pos < self.data.len and self.data[self.pos] == ',') {
            self.pos += 1;
        }
        if (self.pos >= self.data.len) return null;

        // Parse first number (or *)
        const start_num = self.parseNum() orelse return null;

        // Check for range ':'
        if (self.pos < self.data.len and self.data[self.pos] == ':') {
            self.pos += 1;
            const end_num = self.parseNum() orelse return null;
            if (start_num <= end_num) {
                self.range_current = start_num + 1;
                self.range_end = end_num;
            } else {
                // Reverse range
                self.range_current = end_num + 1;
                self.range_end = start_num;
                if (end_num >= 1 and end_num <= self.max_seq) return end_num;
                return self.next();
            }
            if (start_num >= 1 and start_num <= self.max_seq) return start_num;
            return self.next();
        }

        if (start_num >= 1 and start_num <= self.max_seq) return start_num;
        return self.next();
    }

    fn parseNum(self: *SequenceIterator) ?u32 {
        if (self.pos >= self.data.len) return null;
        if (self.data[self.pos] == '*') {
            self.pos += 1;
            return self.max_seq;
        }
        const start = self.pos;
        while (self.pos < self.data.len and self.data[self.pos] >= '0' and self.data[self.pos] <= '9') {
            self.pos += 1;
        }
        if (self.pos == start) return null;
        return std.fmt.parseInt(u32, self.data[start..self.pos], 10) catch null;
    }
};

/// Maildir flag helpers.
/// Flags are encoded in the filename as `:2,<flags>` where flags are single letters:
///   S = \Seen, R = \Answered, F = \Flagged, D = \Draft, T = \Deleted
pub const MaildirFlags = struct {
    seen: bool = false,
    answered: bool = false,
    flagged: bool = false,
    draft: bool = false,
    deleted: bool = false,
    keywords: maildir_keywords.Bits = 0,

    /// Parse flags from a Maildir filename (e.g. "1234.eml:2,SF" -> seen+flagged).
    pub fn fromFilename(filename: []const u8) MaildirFlags {
        var flags = MaildirFlags{};
        if (std.mem.indexOf(u8, filename, ":2,")) |pos| {
            const suffix = filename[pos + 3 ..];
            for (suffix) |c| {
                switch (c) {
                    'S' => flags.seen = true,
                    'R' => flags.answered = true,
                    'F' => flags.flagged = true,
                    'D' => flags.draft = true,
                    'T' => flags.deleted = true,
                    else => {},
                }
            }
        }
        flags.keywords = maildir_keywords.fromFilename(filename);
        return flags;
    }

    /// Get the base filename without the `:2,` flag suffix.
    pub fn baseName(filename: []const u8) []const u8 {
        if (std.mem.indexOf(u8, filename, ":2,")) |pos| {
            return filename[0..pos];
        }
        return filename;
    }

    /// Format flags as an IMAP flag string (e.g. "\\Seen \\Flagged").
    pub fn toImapString(self: MaildirFlags, buf: *[256]u8) []const u8 {
        var fbs = io_compat.fixedBufferStream(buf);
        const writer = fbs.writer();
        var has = false;
        if (self.seen) {
            writer.writeAll("\\Seen") catch {};
            has = true;
        }
        if (self.answered) {
            if (has) writer.writeAll(" ") catch {};
            writer.writeAll("\\Answered") catch {};
            has = true;
        }
        if (self.flagged) {
            if (has) writer.writeAll(" ") catch {};
            writer.writeAll("\\Flagged") catch {};
            has = true;
        }
        if (self.draft) {
            if (has) writer.writeAll(" ") catch {};
            writer.writeAll("\\Draft") catch {};
            has = true;
        }
        if (self.deleted) {
            if (has) writer.writeAll(" ") catch {};
            writer.writeAll("\\Deleted") catch {};
        }
        return fbs.getWritten();
    }

    /// Build the `:2,XXX` suffix string.
    pub fn toSuffix(self: MaildirFlags, buf: []u8) []const u8 {
        var fbs = io_compat.fixedBufferStream(buf);
        const writer = fbs.writer();
        writer.writeAll(":2,") catch {};
        // Flags must be in alphabetical order per Maildir spec
        if (self.draft) writer.writeAll("D") catch {};
        if (self.flagged) writer.writeAll("F") catch {};
        if (self.answered) writer.writeAll("R") catch {};
        if (self.seen) writer.writeAll("S") catch {};
        if (self.deleted) writer.writeAll("T") catch {};
        maildir_keywords.writeLetters(writer, self.keywords) catch {};
        return fbs.getWritten();
    }

    pub fn applyStoreFlags(before: MaildirFlags, requested: MaildirFlags, mode: FlagMode) MaildirFlags {
        return switch (mode) {
            .replace => requested,
            .add => .{
                .seen = before.seen or requested.seen,
                .answered = before.answered or requested.answered,
                .flagged = before.flagged or requested.flagged,
                .draft = before.draft or requested.draft,
                .deleted = before.deleted or requested.deleted,
                .keywords = before.keywords | requested.keywords,
            },
            .remove => .{
                .seen = before.seen and !requested.seen,
                .answered = before.answered and !requested.answered,
                .flagged = before.flagged and !requested.flagged,
                .draft = before.draft and !requested.draft,
                .deleted = before.deleted and !requested.deleted,
                .keywords = before.keywords & ~requested.keywords,
            },
        };
    }
};

const FlagMode = enum { replace, add, remove };

const FlagList = struct {
    system: MaildirFlags = .{},
    keywords: [maildir_keywords.count][]const u8 = undefined,
    keyword_count: usize = 0,

    fn parse(raw: []const u8) !FlagList {
        var result: FlagList = .{};
        var words = std.mem.tokenizeAny(u8, raw, " \t");
        while (words.next()) |word| {
            if (std.ascii.eqlIgnoreCase(word, "\\Seen")) result.system.seen = true else if (std.ascii.eqlIgnoreCase(word, "\\Answered")) result.system.answered = true else if (std.ascii.eqlIgnoreCase(word, "\\Flagged")) result.system.flagged = true else if (std.ascii.eqlIgnoreCase(word, "\\Draft")) result.system.draft = true else if (std.ascii.eqlIgnoreCase(word, "\\Deleted")) result.system.deleted = true else {
                if (!maildir_keywords.validName(word)) return error.InvalidKeyword;
                for (result.keywords[0..result.keyword_count]) |old| {
                    if (std.ascii.eqlIgnoreCase(old, word)) break;
                } else {
                    if (result.keyword_count == result.keywords.len) return error.KeywordLimit;
                    result.keywords[result.keyword_count] = word;
                    result.keyword_count += 1;
                }
            }
        }
        return result;
    }

    fn resolve(self: *const FlagList, names: *maildir_keywords.Names, mode: FlagMode) !MaildirFlags {
        var result = self.system;
        for (self.keywords[0..self.keyword_count]) |word|
            result.keywords |= if (mode == .remove) names.find(word) else try names.insert(word);
        return result;
    }
};

const StoreFlags = struct {
    mode: FlagMode,
    silent: bool,
    flags: FlagList,

    fn parse(raw: []const u8) !StoreFlags {
        const end = std.mem.indexOfAny(u8, raw, " \t") orelse return error.InvalidStoreFlags;
        const operation = raw[0..end];
        const mode: FlagMode = if (std.mem.startsWith(u8, operation, "+")) .add else if (std.mem.startsWith(u8, operation, "-")) .remove else .replace;
        const command = if (mode == .replace) operation else operation[1..];
        const silent = std.ascii.eqlIgnoreCase(command, "FLAGS.SILENT");
        if (!silent and !std.ascii.eqlIgnoreCase(command, "FLAGS")) return error.InvalidStoreFlags;
        const list = std.mem.trim(u8, raw[end..], " \t");
        if (list.len == 0) return error.InvalidStoreFlags;
        const inner = if (list[0] == '(' and list[list.len - 1] == ')') list[1 .. list.len - 1] else list;
        return .{ .mode = mode, .silent = silent, .flags = try FlagList.parse(inner) };
    }
};

const AggregateMailboxEntry = struct {
    filename: []const u8,
    dir: []const u8,
    uid_key: []const u8,
    sort_key: i64,
};

const AppendArgs = struct {
    mailbox: []const u8,
    flags: ?[]const u8 = null,
    internal_date: ?i64 = null,
};

/// Parse the APPEND arguments that precede the `{N}` literal:
/// `mailbox [(\Flag ...)] ["date-time"]`.
fn parseAppendArgs(args_raw: []const u8) !AppendArgs {
    const args = std.mem.trim(u8, args_raw, " \t");
    const mailbox = parseImapArg(args) orelse return .{ .mailbox = "INBOX" };
    if (args[0] == '"' and mailbox.value.len + 1 >= args.len) return error.InvalidAppendArgs;
    var result: AppendArgs = .{ .mailbox = mailbox.value };
    var tail = mailbox.rest;
    if (std.mem.startsWith(u8, tail, "(")) {
        const close = std.mem.indexOfScalar(u8, tail, ')') orelse return error.InvalidAppendArgs;
        result.flags = tail[1..close];
        tail = std.mem.trimStart(u8, tail[close + 1 ..], " \t");
    }
    if (tail.len != 0) {
        if (tail.len < 2 or tail[0] != '"' or tail[tail.len - 1] != '"')
            return error.InvalidAppendDate;
        result.internal_date = try parseAppendDate(tail[1 .. tail.len - 1]);
    }
    return result;
}

const imap_months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

fn daysBeforeYear(year: i64) i64 {
    const completed = year - 1;
    return completed * 365 + @divFloor(completed, 4) - @divFloor(completed, 100) + @divFloor(completed, 400);
}

const earliest_internal_date = (daysBeforeYear(1) - daysBeforeYear(1970)) * 86400;
const latest_internal_date = (daysBeforeYear(10000) - daysBeforeYear(1970)) * 86400 - 1;

fn parseDateDigits(digits: []const u8) !u16 {
    for (digits) |digit| {
        if (!std.ascii.isDigit(digit)) return error.InvalidAppendDate;
    }
    return std.fmt.parseUnsigned(u16, digits, 10) catch return error.InvalidAppendDate;
}

fn parseAppendDate(date: []const u8) !i64 {
    if (date.len != 26 or date[2] != '-' or date[6] != '-' or date[11] != ' ' or date[14] != ':' or
        date[17] != ':' or date[20] != ' ' or (date[21] != '+' and date[21] != '-'))
        return error.InvalidAppendDate;
    const year = try parseDateDigits(date[7..11]);
    if (year == 0) return error.InvalidAppendDate;
    const month = for (imap_months, 1..) |label, number| {
        if (std.ascii.eqlIgnoreCase(date[3..6], label)) break @as(std.time.epoch.Month, @fromBackingInt(@intCast(number)));
    } else return error.InvalidAppendDate;
    const day = try parseDateDigits(if (date[0] == ' ') date[1..2] else date[0..2]);
    const hour = try parseDateDigits(date[12..14]);
    const minute = try parseDateDigits(date[15..17]);
    const second = try parseDateDigits(date[18..20]);
    const zone_hour = try parseDateDigits(date[22..24]);
    const zone_minute = try parseDateDigits(date[24..26]);
    if (day == 0 or day > std.time.epoch.getDaysInMonth(year, month) or hour > 23 or minute > 59 or
        second > 59 or zone_hour > 23 or zone_minute > 59)
        return error.InvalidAppendDate;

    var day_index = daysBeforeYear(year) - daysBeforeYear(1970) + @as(i64, day) - 1;
    for (1..@backingInt(month)) |m| day_index += std.time.epoch.getDaysInMonth(year, @fromBackingInt(@intCast(m)));
    const offset = @as(i64, zone_hour) * 3600 + @as(i64, zone_minute) * 60;
    const local = day_index * 86400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + second;
    const utc = local - if (date[21] == '+') offset else -offset;
    if (utc < earliest_internal_date or utc > latest_internal_date) return error.InvalidAppendDate;
    return utc;
}

/// Keep the persisted date separate from the numeric filename prefix that
/// determines sequence order. Copy and move can change that prefix.
pub fn storedInternalDate(filename: []const u8) ?i64 {
    const basename = MaildirFlags.baseName(std.fs.path.basename(filename));
    if (!std.mem.endsWith(u8, basename, ".eml")) return null;
    const stem = basename[0 .. basename.len - ".eml".len];
    const start = std.mem.lastIndexOf(u8, stem, ",I=") orelse return null;
    const seconds = std.fmt.parseInt(i64, stem[start + ",I=".len ..], 10) catch return null;
    return if (seconds >= earliest_internal_date and seconds <= latest_internal_date) seconds else null;
}

fn filenameInternalDate(filename: []const u8) ?i64 {
    if (storedInternalDate(filename)) |seconds| return seconds;
    const base = MaildirFlags.baseName(std.fs.path.basename(filename));
    const stem = if (std.mem.endsWith(u8, base, ".eml")) base[0 .. base.len - 4] else base;
    const millis = std.fmt.parseInt(i64, stem, 10) catch return null;
    return @divFloor(millis, 1000);
}

fn legacyInternalDate(header: []const u8, buf: *[64]u8) []const u8 {
    const start = (std.mem.indexOf(u8, header, "Date: ") orelse return "01-Jan-2026 00:00:00 +0000") + 6;
    const raw = header[start .. std.mem.indexOfAnyPos(u8, header, start, "\r\n") orelse header.len];
    return parseAndFormatRfc2822Date(raw, buf) orelse raw;
}

pub fn parseMessageSortKey(filename: []const u8) i64 {
    const basename = if (std.mem.lastIndexOfScalar(u8, filename, '/')) |pos| filename[pos + 1 ..] else filename;
    const no_flags = MaildirFlags.baseName(basename);
    const name_no_ext = if (std.mem.endsWith(u8, no_flags, ".eml")) no_flags[0 .. no_flags.len - 4] else no_flags;
    // Current Maildir names are `<millis>.<counter>.eml`. Parsing the whole
    // stem fails on the counter separator and returns 0, which sorts each new
    // delivery into the legacy-name block near the start of the mailbox. That
    // shifts every following IMAP sequence number without an EXPUNGE and makes
    // clients re-scan their complete cache. Sort on the numeric timestamp
    // prefix so newly delivered messages are always appended at the end.
    const numeric_prefix = if (std.mem.indexOfScalar(u8, name_no_ext, '.')) |dot| name_no_ext[0..dot] else name_no_ext;
    return std.fmt.parseInt(i64, numeric_prefix, 10) catch return 0;
}

fn isLegacySyntheticMailbox(name: []const u8) bool {
    const legacy = [_][]const u8{
        "All", "All Mail", "Starred", "Important", "Social", "Forums", "Updates", "Promotions",
    };
    for (legacy) |candidate| {
        if (std.ascii.eqlIgnoreCase(name, candidate)) return true;
    }
    return false;
}

/// Match an IMAP LIST wildcard pattern against a folder name.
/// `*` matches zero or more characters including hierarchy delimiter.
/// `%` matches zero or more characters excluding hierarchy delimiter `/`.
fn matchListPattern(pattern: []const u8, name: []const u8) bool {
    // Common case: bare "*" or "%" matches everything at the right level
    if (std.mem.eql(u8, pattern, "*")) return true;
    if (std.mem.eql(u8, pattern, "%")) return std.mem.indexOfScalar(u8, name, '/') == null;

    var pi: usize = 0;
    var ni: usize = 0;
    while (pi < pattern.len) {
        if (pattern[pi] == '*') {
            // Match rest greedily
            pi += 1;
            if (pi >= pattern.len) return true;
            while (ni <= name.len) {
                if (matchListPattern(pattern[pi..], if (ni < name.len) name[ni..] else "")) return true;
                ni += 1;
            }
            return false;
        } else if (pattern[pi] == '%') {
            pi += 1;
            if (pi >= pattern.len) return std.mem.indexOfScalarPos(u8, name, ni, '/') == null;
            while (ni < name.len and name[ni] != '/') {
                if (matchListPattern(pattern[pi..], name[ni..])) return true;
                ni += 1;
            }
            return matchListPattern(pattern[pi..], if (ni < name.len) name[ni..] else "");
        } else {
            if (ni >= name.len or pattern[pi] != name[ni]) return false;
            pi += 1;
            ni += 1;
        }
    }
    return ni >= name.len;
}

const ParsedImapArg = struct {
    value: []const u8,
    rest: []const u8,
};

/// Parse one IMAP astring from a command remainder.
/// Unlike whitespace splitting, this keeps quoted mailbox names like
/// "All Mail" together and returns the remainder after the argument.
fn parseImapArg(rest: []const u8) ?ParsedImapArg {
    const trimmed = std.mem.trimStart(u8, rest, " \t");
    if (trimmed.len == 0) return null;

    if (trimmed[0] == '"') {
        var i: usize = 1;
        while (i < trimmed.len) : (i += 1) {
            if (trimmed[i] == '"' and (i == 1 or trimmed[i - 1] != '\\')) {
                return .{
                    .value = trimmed[1..i],
                    .rest = std.mem.trimStart(u8, trimmed[i + 1 ..], " \t"),
                };
            }
        }

        return .{ .value = trimmed[1..], .rest = "" };
    }

    if (trimmed.len >= "All Mail".len and std.ascii.eqlIgnoreCase(trimmed[0.."All Mail".len], "All Mail")) {
        const arg_end = "All Mail".len;
        if (trimmed.len == arg_end or trimmed[arg_end] == ' ' or trimmed[arg_end] == '\t') {
            return .{
                .value = trimmed[0..arg_end],
                .rest = std.mem.trimStart(u8, trimmed[arg_end..], " \t"),
            };
        }
    }

    const end = std.mem.indexOfAny(u8, trimmed, " \t") orelse trimmed.len;
    return .{
        .value = trimmed[0..end],
        .rest = std.mem.trimStart(u8, trimmed[end..], " \t"),
    };
}

fn parseSingleMailboxArg(rest: []const u8) ?[]const u8 {
    const trimmed = std.mem.trimStart(u8, rest, " \t");
    const arg = parseImapArg(trimmed) orelse return null;
    if (arg.rest.len != 0) return null;
    if (trimmed[0] == '"' and arg.value.len + 1 >= trimmed.len) return null;
    return arg.value;
}

/// Rename a file in the same directory using libc.
fn renameFile(old_path: []const u8, new_path: []const u8) bool {
    var old_buf: [4097]u8 = undefined;
    var new_buf: [4097]u8 = undefined;
    if (old_path.len >= old_buf.len or new_path.len >= new_buf.len) return false;
    @memcpy(old_buf[0..old_path.len], old_path);
    old_buf[old_path.len] = 0;
    @memcpy(new_buf[0..new_path.len], new_path);
    new_buf[new_path.len] = 0;
    const old_z: [*:0]const u8 = @ptrCast(&old_buf);
    const new_z: [*:0]const u8 = @ptrCast(&new_buf);
    return std.c.rename(old_z, new_z) == 0;
}

/// Finds the name a message's file has on disk now.
///
/// A session caches the filenames it listed at SELECT, but a message's flags
/// live in its name (`base.eml` -> `base.eml:2,S`), so another connection
/// marking it read renames the file out from under the cache. Apple Mail keeps
/// several connections open, which makes that the ordinary case, not a race.
/// The base name is the message's identity, so a stale name is looked up by
/// its base. Each directory is listed at most once per command, however many
/// cached names in it turn out to be stale.
const MaildirNameResolver = struct {
    allocator: std.mem.Allocator,
    /// "{dir}/{base}" -> current filename. Both owned.
    names: std.StringHashMapUnmanaged([]const u8) = .empty,
    /// Directories already listed into `names`. Owned.
    listed: std.ArrayList([]const u8) = .empty,

    fn init(allocator: std.mem.Allocator) MaildirNameResolver {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *MaildirNameResolver) void {
        var it = self.names.iterator();
        while (it.next()) |e| {
            self.allocator.free(e.key_ptr.*);
            self.allocator.free(e.value_ptr.*);
        }
        self.names.deinit(self.allocator);
        for (self.listed.items) |d| self.allocator.free(d);
        self.listed.deinit(self.allocator);
    }

    /// The current name of the message cached as `cached` in `dir`: `cached`
    /// itself while that file exists, otherwise the file with the same base
    /// name, or null when there is none (expunged by another connection). The
    /// returned slice is borrowed from `cached` or from the resolver.
    fn resolve(self: *MaildirNameResolver, dir: []const u8, cached: []const u8) !?[]const u8 {
        var path_buf: [4097]u8 = undefined;
        const cached_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ dir, cached }) catch return cached;
        if (fs_compat.cwd().access(cached_path, .{})) |_| {
            return cached;
        } else |_| {}

        try self.listDir(dir);
        const key = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ dir, MaildirFlags.baseName(cached) }) catch return null;
        return self.names.get(key);
    }

    fn listDir(self: *MaildirNameResolver, dir: []const u8) !void {
        for (self.listed.items) |d| {
            if (std.mem.eql(u8, d, dir)) return;
        }
        try self.listed.append(self.allocator, try self.allocator.dupe(u8, dir));

        const files = fs_compat.listEmlFiles(self.allocator, dir) catch return;
        defer self.allocator.free(files);
        for (files) |name| {
            const key = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ dir, MaildirFlags.baseName(name) }) catch {
                self.allocator.free(name);
                continue;
            };
            const gop = self.names.getOrPut(self.allocator, key) catch {
                self.allocator.free(key);
                self.allocator.free(name);
                continue;
            };
            if (gop.found_existing) {
                // Two files with one base name should not exist; keep the first.
                self.allocator.free(key);
                self.allocator.free(name);
            } else {
                gop.value_ptr.* = name;
            }
        }
    }
};

/// Offset just past the blank line that ends a message's header block.
///
/// The first blank line wins, whichever line ending it uses. Searching for
/// "\r\n\r\n" first and falling back to "\n\n" would end a bare-LF header at
/// a CRLF blank line further down in the body. With no blank line at all the
/// whole message is header.
fn headerEnd(content: []const u8) usize {
    if (std.mem.startsWith(u8, content, "\r\n")) return 2;
    if (std.mem.startsWith(u8, content, "\n")) return 1;
    var pos: usize = 0;
    while (std.mem.indexOfScalarPos(u8, content, pos, '\n')) |nl| {
        const next = nl + 1;
        if (next < content.len and content[next] == '\n') return next + 1;
        if (next + 1 < content.len and content[next] == '\r' and content[next + 1] == '\n') return next + 2;
        pos = next;
    }
    return content.len;
}

/// Match an exact field name and search its unfolded value. An empty term
/// checks for the presence of the named field.
fn searchHeader(a: std.mem.Allocator, header: []const u8, field: []const u8, term: []const u8) !?[]const u8 {
    var lines = std.mem.splitScalar(u8, header, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) break;
        if (line[0] == ' ' or line[0] == '\t') continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], field)) continue;

        var value = line[colon + 1 ..];
        var unfolded: std.ArrayList(u8) = .empty;
        while (lines.peek()) |continuation| {
            if (continuation.len == 0 or (continuation[0] != ' ' and continuation[0] != '\t')) break;
            _ = lines.next();
            if (unfolded.items.len == 0) try unfolded.appendSlice(a, value);
            try unfolded.appendSlice(a, std.mem.trimEnd(u8, continuation, "\r"));
        }
        if (unfolded.items.len != 0) value = unfolded.items;
        if (ascii_compat.indexOfIgnoreCase(value, term) != null) return value;
    }
    return null;
}

const HeaderSection = struct {
    const Kind = enum { all, fields, fields_not };

    kind: Kind,
    fields: []const u8 = "",
};

fn parseHeaderSpec(spec: []const u8) ?HeaderSection {
    if (!std.ascii.startsWithIgnoreCase(spec, "HEADER")) return null;
    const rest = spec[6..];
    if (rest.len == 0) return .{ .kind = .all };
    const kind: HeaderSection.Kind = if (std.ascii.startsWithIgnoreCase(rest, ".FIELDS.NOT "))
        .fields_not
    else if (std.ascii.startsWithIgnoreCase(rest, ".FIELDS "))
        .fields
    else
        return null;
    const lp = std.mem.indexOfScalar(u8, rest, '(') orelse return null;
    const rp = std.mem.indexOfScalarPos(u8, rest, lp + 1, ')') orelse return null;
    return .{ .kind = kind, .fields = rest[lp + 1 .. rp] };
}

/// The header fields of `header` whose names are (`keep_listed`) or are not
/// (`!keep_listed`) in the space-separated `fields`, in their original order
/// with continuation lines kept, followed by the blank line that ends a header
/// block (RFC 3501 6.4.5). Caller owns the returned slice.
fn filterHeaderFields(allocator: std.mem.Allocator, header: []const u8, fields: []const u8, keep_listed: bool) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var pos: usize = 0;
    while (pos < header.len) {
        var end = lineEndAfter(header, pos);
        const first_line = header[pos..end];
        if (std.mem.trim(u8, first_line, "\r\n").len == 0) break;
        // Folded continuation lines start with a space or tab.
        while (end < header.len and (header[end] == ' ' or header[end] == '\t')) end = lineEndAfter(header, end);

        const colon = std.mem.indexOfScalar(u8, first_line, ':');
        const name = if (colon) |c| std.mem.trim(u8, first_line[0..c], " \t") else "";
        if (name.len > 0 and headerFieldListed(fields, name) == keep_listed) {
            const field = header[pos..end];
            try out.appendSlice(allocator, field);
            if (!std.mem.endsWith(u8, field, "\n")) try out.appendSlice(allocator, "\r\n");
        }
        pos = end;
    }
    try out.appendSlice(allocator, "\r\n");
    return out.toOwnedSlice(allocator);
}

fn lineEndAfter(buf: []const u8, start: usize) usize {
    return if (std.mem.indexOfScalarPos(u8, buf, start, '\n')) |nl| nl + 1 else buf.len;
}

fn headerFieldListed(fields: []const u8, name: []const u8) bool {
    var it = std.mem.tokenizeAny(u8, fields, " \t\"");
    while (it.next()) |f| {
        if (std.ascii.eqlIgnoreCase(f, name)) return true;
    }
    return false;
}

const FetchSections = struct {
    items: []const u8,
    cursor: usize = 0,

    const Partial = struct { offset: usize, count: usize };

    const Section = struct {
        spec: []const u8,
        peek: bool,
        partial: ?Partial = null,

        fn numbered(self: Section) bool {
            return self.spec.len != 0 and std.ascii.isDigit(self.spec[0]);
        }

        fn appendReply(self: Section, a: std.mem.Allocator, reply: *std.ArrayList([]const u8), raw: []const u8, header: []const u8, tree: ?imap_mime.Tree) !void {
            var data: ?[]const u8 = null;
            var filter: ?HeaderSection = null;
            if (self.numbered()) {
                if (tree.?.section(self.spec)) |section| {
                    data = section.bytes;
                    if (section.header_filter) |spec| {
                        filter = parseHeaderSpec(spec);
                        if (filter == null) data = null;
                    }
                }
            } else if (self.spec.len == 0) {
                data = raw;
            } else if (std.ascii.eqlIgnoreCase(self.spec, "TEXT")) {
                data = raw[header.len..];
            } else if (parseHeaderSpec(self.spec)) |parsed| {
                data = header;
                filter = parsed;
            }

            const bytes = data orelse {
                try reply.append(a, try std.fmt.allocPrint(a, " BODY[{s}] NIL", .{self.spec}));
                return;
            };
            const selected = if (filter) |hs| switch (hs.kind) {
                .all => bytes,
                .fields => try filterHeaderFields(a, bytes, hs.fields, true),
                .fields_not => try filterHeaderFields(a, bytes, hs.fields, false),
            } else bytes;

            if (self.partial) |partial| {
                const start = @min(partial.offset, selected.len);
                const slice = selected[start..][0..@min(partial.count, selected.len - start)];
                const label = try std.fmt.allocPrint(a, " BODY[{s}]<{d}> {{{d}}}\r\n", .{ self.spec, partial.offset, slice.len });
                try reply.appendSlice(a, &.{ label, slice });
            } else {
                const label = try std.fmt.allocPrint(a, " BODY[{s}] {{{d}}}\r\n", .{ self.spec, selected.len });
                try reply.appendSlice(a, &.{ label, selected });
            }
        }
    };

    fn next(self: *FetchSections) ?Section {
        while (ascii_compat.indexOfIgnoreCasePos(self.items, self.cursor, "BODY")) |at| {
            self.cursor = at + 4;
            if (at != 0 and self.items[at - 1] != ' ' and self.items[at - 1] != '(') continue;
            const peek = std.ascii.startsWithIgnoreCase(self.items[self.cursor..], ".PEEK");
            const open = self.cursor + @as(usize, if (peek) 5 else 0);
            if (open >= self.items.len or self.items[open] != '[') continue;
            const close = std.mem.indexOfScalarPos(u8, self.items, open + 1, ']') orelse return null;
            self.cursor = close + 1;

            var partial: ?Partial = null;
            if (self.cursor < self.items.len and self.items[self.cursor] == '<') parse: {
                const stop = std.mem.indexOfScalarPos(u8, self.items, self.cursor + 1, '>') orelse break :parse;
                const range = self.items[self.cursor + 1 .. stop];
                const dot = std.mem.indexOfScalar(u8, range, '.') orelse break :parse;
                const offset = std.fmt.parseInt(usize, range[0..dot], 10) catch break :parse;
                const count = std.fmt.parseInt(usize, range[dot + 1 ..], 10) catch break :parse;
                partial = .{ .offset = offset, .count = count };
                self.cursor = stop + 1;
            }
            return .{ .spec = self.items[open + 1 .. close], .peek = peek, .partial = partial };
        }
        return null;
    }
};

/// Look for an item outside BODY brackets, where a HEADER.FIELDS list may
/// itself contain strings that look like FETCH item names.
fn fetchHasAtom(items: []const u8, name: []const u8) bool {
    var at: usize = 0;
    while (at < items.len) {
        if (items[at] == '[') {
            at = (std.mem.indexOfScalarPos(u8, items, at + 1, ']') orelse return false) + 1;
            continue;
        }
        if (items[at] == ' ' or items[at] == '(' or items[at] == ')') {
            at += 1;
            continue;
        }
        const start = at;
        while (at < items.len and std.mem.indexOfScalar(u8, " ()[", items[at]) == null) : (at += 1) {}
        if (std.ascii.eqlIgnoreCase(items[start..at], name) and (at == items.len or items[at] != '[')) return true;
    }
    return false;
}

fn pathIsSymlink(path: []const u8) bool {
    var path_buf: [4097]u8 = undefined;
    var target_buf: [1]u8 = undefined;
    if (path.len >= path_buf.len) return false;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&path_buf);
    return readlink(path_z, &target_buf, target_buf.len) >= 0;
}

fn createRelativeSymlink(target: []const u8, path: []const u8) bool {
    var target_buf: [4097]u8 = undefined;
    var path_buf: [4097]u8 = undefined;
    if (target.len >= target_buf.len or path.len >= path_buf.len) return false;
    @memcpy(target_buf[0..target.len], target);
    target_buf[target.len] = 0;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;
    const target_z: [*:0]const u8 = @ptrCast(&target_buf);
    const path_z: [*:0]const u8 = @ptrCast(&path_buf);
    return symlink(target_z, path_z) == 0;
}

/// IMAP session
pub const ImapSession = struct {
    scanner: ?*clamav.ClamAVScanner = null,
    allocator: std.mem.Allocator,
    connection: socket.Connection,
    state: ImapState,
    username: ?[]const u8 = null,
    selected_mailbox: ?*Mailbox = null,
    tag: ?[]const u8 = null,
    command_buffer: std.ArrayList(u8),
    idle_mode: bool = false,
    idle_tag: ?[]const u8 = null,
    mailbox_read_only: bool = false,
    auth_backend: *auth.AuthBackend,
    client_password_id: ?i64 = null,
    db: ?*database.Database = null,
    // TLS support for encrypted responses
    tls_connection: ?*tls.nonblock.Connection = null,
    // Cached list of message filenames in the selected mailbox (sorted)
    mailbox_files: ?[]const []const u8 = null,
    // Per-message source directories for virtual mailboxes such as All Mail.
    mailbox_file_dirs: ?[]const []const u8 = null,
    // Per-message UID keys for virtual mailboxes where filenames can collide across folders.
    mailbox_uid_keys: ?[]const []const u8 = null,
    // Path to the selected mailbox's new/ directory
    mailbox_dir: ?[]const u8 = null,
    // UID persistence: parallel array of UIDs for mailbox_files (same indices)
    mailbox_uids: ?[]i64 = null,
    // Reverse index UID -> sequence number, rebuilt with mailbox_uids, so
    // UID FETCH/STORE on large mailboxes is O(1) per UID instead of O(n).
    uid_seq_map: std.AutoHashMapUnmanaged(i64, usize) = .empty,
    // Cheap IDLE-poll signature: maildir entry count at the last poll.
    idle_scan_count: ?usize = null,
    // inotify fd watching the selected mailbox's dirs during IDLE (Linux).
    // null = not set up yet, -1 = unavailable (non-Linux or setup failed,
    // fall back to timed polling).
    idle_watch_fd: ?i32 = null,
    mailbox_uidvalidity: i64 = 0,
    mailbox_name: ?[]const u8 = null,
    mailbox_is_virtual: bool = false,
    gmail_labels_enabled: bool = true,
    junk_folder: []const u8 = "Junk",
    // Pending APPEND literal state
    append_tag: ?[]u8 = null,
    append_mailbox: ?[]u8 = null,
    append_flags: ?[]u8 = null,
    append_internal_date: ?i64 = null,
    append_literal_size: usize = 0,
    append_literal_buf: ?[]u8 = null,
    append_literal_pos: usize = 0,
    // STARTTLS upgrade requested (port 143 → TLS)
    starttls_requested: bool = false,

    pub fn init(allocator: std.mem.Allocator, connection: socket.Connection, auth_backend: *auth.AuthBackend, db: ?*database.Database, gmail_labels_enabled: bool) ImapSession {
        return .{
            .allocator = allocator,
            .connection = connection,
            .state = .not_authenticated,
            .command_buffer = .empty,
            .auth_backend = auth_backend,
            .db = db,
            .gmail_labels_enabled = gmail_labels_enabled,
            .tls_connection = null,
        };
    }

    /// Set the TLS connection for encrypted I/O
    pub fn setTlsConnection(self: *ImapSession, tls_conn: *tls.nonblock.Connection) void {
        self.tls_connection = tls_conn;
    }

    pub fn deinit(self: *ImapSession) void {
        if (self.username) |username| {
            self.allocator.free(username);
        }
        if (self.tag) |tag| {
            self.allocator.free(tag);
        }
        if (self.idle_tag) |idle_tag| {
            self.allocator.free(idle_tag);
        }
        self.cleanupAppend();
        self.closeIdleWatch();
        self.freeMailboxFiles();
        self.uid_seq_map.deinit(self.allocator);
        if (self.mailbox_name) |n| self.allocator.free(n);
        self.command_buffer.deinit(self.allocator);
    }

    fn freeMailboxFiles(self: *ImapSession) void {
        if (self.mailbox_files) |files| {
            for (files) |f| self.allocator.free(f);
            self.allocator.free(files);
            self.mailbox_files = null;
        }
        if (self.mailbox_file_dirs) |dirs| {
            for (dirs) |d| self.allocator.free(d);
            self.allocator.free(dirs);
            self.mailbox_file_dirs = null;
        }
        if (self.mailbox_uid_keys) |keys| {
            for (keys) |k| self.allocator.free(k);
            self.allocator.free(keys);
            self.mailbox_uid_keys = null;
        }
        if (self.mailbox_dir) |d| {
            self.allocator.free(d);
            self.mailbox_dir = null;
        }
        if (self.mailbox_uids) |uids| {
            self.allocator.free(uids);
            self.mailbox_uids = null;
        }
        self.uid_seq_map.clearRetainingCapacity();
        self.mailbox_is_virtual = false;
    }

    fn selectedMessageDirForIndex(self: *ImapSession, idx: usize) ?[]const u8 {
        if (self.mailbox_file_dirs) |dirs| {
            if (idx < dirs.len) return dirs[idx];
        }
        return self.mailbox_dir;
    }

    fn allocSelectedMessagePath(self: *ImapSession, idx: usize, filename: []const u8) ![]u8 {
        const dir = self.selectedMessageDirForIndex(idx) orelse return error.NoMailboxSelected;
        return try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ dir, filename });
    }

    /// The filename message `idx` has on disk now, adopted into the cached
    /// listing, or null when its file is gone. See `MaildirNameResolver`.
    fn adoptCurrentName(self: *ImapSession, resolver: *MaildirNameResolver, idx: usize) ?[]const u8 {
        const files = self.mailbox_files orelse return null;
        if (idx >= files.len) return null;
        const cached = files[idx];
        const dir = self.selectedMessageDirForIndex(idx) orelse return null;
        // A failed lookup keeps the cached name: the next file operation then
        // fails on it and reports that, rather than dropping the message here.
        const current = (resolver.resolve(dir, cached) catch return cached) orelse return null;
        if (current.ptr == cached.ptr) return cached;

        const owned = self.allocator.dupe(u8, current) catch return cached;
        self.allocator.free(cached);
        @constCast(files)[idx] = owned;
        return owned;
    }

    /// Give message `idx`, currently named `filename`, exactly `flags` by
    /// renaming its file. True when the file on disk now carries them.
    fn writeMessageFlags(self: *ImapSession, idx: usize, filename: []const u8, flags: MaildirFlags) bool {
        const db = self.auth_backend.db;
        db.lockMailboxes();
        defer db.unlockMailboxes();
        return self.writeMessageFlagsLocked(idx, filename, flags);
    }

    fn writeMessageFlagsLocked(self: *ImapSession, idx: usize, filename: []const u8, flags: MaildirFlags) bool {
        const base = MaildirFlags.baseName(filename);
        var suffix_buf: [maildir_keywords.suffix_capacity]u8 = undefined;
        const suffix = flags.toSuffix(&suffix_buf);
        var new_name_buf: [512]u8 = undefined;
        const new_name = std.fmt.bufPrint(&new_name_buf, "{s}{s}", .{ base, suffix }) catch return false;
        if (std.mem.eql(u8, filename, new_name)) return true;

        const dir = self.selectedMessageDirForIndex(idx) orelse return false;
        const old_path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ dir, filename }) catch return false;
        defer self.allocator.free(old_path);
        const new_path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ dir, new_name }) catch return false;
        defer self.allocator.free(new_path);
        if (!renameFile(old_path, new_path)) return false;

        // The rename happened; keep the cache in step with it. If the copy
        // fails the cached name is stale, which the next command resolves.
        const files = self.mailbox_files orelse return true;
        if (idx < files.len and files[idx].ptr == filename.ptr) {
            const owned = self.allocator.dupe(u8, new_name) catch return true;
            self.allocator.free(files[idx]);
            @constCast(files)[idx] = owned;
        }
        return true;
    }

    var maildir_write_sequence = std.atomic.Value(u64).init(0);

    /// Build a destination name unique across IMAP threads, including when
    /// two new files carry different flags but share the same timestamp.
    fn allocUniqueMaildirPath(self: *ImapSession, dir: []const u8, flag_suffix: []const u8, internal_date: ?i64) ![]u8 {
        var date_buf: [32]u8 = undefined;
        const date = if (internal_date) |seconds| try std.fmt.bufPrint(&date_buf, ",I={d}", .{seconds}) else "";
        return std.fmt.allocPrint(self.allocator, "{s}/{d}.{d}.imap.{d}{s}.eml{s}", .{
            dir, time_compat.milliTimestamp(), getpid(), maildir_write_sequence.fetchAdd(1, .monotonic), date, flag_suffix,
        });
    }

    fn sendMaildirWriteError(self: *ImapSession, tag: []const u8, err: anyerror) !void {
        const detail = switch (err) {
            error.HostedStorageFull => "[OVERQUOTA] Mailbox storage is full",
            error.HostedRecipientDisabled => "[NOPERM] Mailbox is disabled",
            error.HostedRecipientReadOnly => "[READ-ONLY] Mailbox is available for export",
            error.HostedRecipientExpired => "[NOPERM] Mailbox service ended",
            error.KeywordLimit => "[LIMIT] Mailbox keyword limit reached",
            else => "[SERVERBUG] Mailbox write failed",
        };
        try self.sendResponse(tag, "NO", detail);
    }

    fn freeSelectedMessageLists(self: *ImapSession) void {
        if (self.mailbox_files) |files| {
            for (files) |f| self.allocator.free(f);
            self.allocator.free(files);
            self.mailbox_files = null;
        }
        if (self.mailbox_file_dirs) |dirs| {
            for (dirs) |d| self.allocator.free(d);
            self.allocator.free(dirs);
            self.mailbox_file_dirs = null;
        }
        if (self.mailbox_uid_keys) |keys| {
            for (keys) |k| self.allocator.free(k);
            self.allocator.free(keys);
            self.mailbox_uid_keys = null;
        }
        if (self.mailbox_uids) |uids| {
            self.allocator.free(uids);
            self.mailbox_uids = null;
        }
        self.uid_seq_map.clearRetainingCapacity();
    }

    fn freeAggregateEntries(self: *ImapSession, entries: []AggregateMailboxEntry) void {
        for (entries) |entry| {
            self.allocator.free(entry.filename);
            self.allocator.free(entry.dir);
            self.allocator.free(entry.uid_key);
        }
    }

    fn appendAggregateFolder(self: *ImapSession, entries: *std.ArrayList(AggregateMailboxEntry), dir_path: []const u8, folder_name: []const u8) !void {
        const files = fs_compat.listEmlFiles(self.allocator, dir_path) catch return;
        defer {
            for (files) |f| self.allocator.free(f);
            self.allocator.free(files);
        }

        for (files) |filename| {
            const owned_filename = try self.allocator.dupe(u8, filename);
            errdefer self.allocator.free(owned_filename);

            const owned_dir = try self.allocator.dupe(u8, dir_path);
            errdefer self.allocator.free(owned_dir);

            const base = MaildirFlags.baseName(filename);
            const uid_key = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ folder_name, base });
            errdefer self.allocator.free(uid_key);

            try entries.append(self.allocator, .{
                .filename = owned_filename,
                .dir = owned_dir,
                .uid_key = uid_key,
                .sort_key = parseMessageSortKey(filename),
            });
        }
    }

    fn loadAggregateMailboxFiles(self: *ImapSession, local_part: []const u8) !void {
        var entries: std.ArrayList(AggregateMailboxEntry) = .empty;
        defer entries.deinit(self.allocator);
        errdefer self.freeAggregateEntries(entries.items);

        const root = try std.fmt.allocPrint(self.allocator, "mail/{s}", .{local_part});
        defer self.allocator.free(root);

        const root_z = try self.allocator.dupeSentinel(u8, root, 0);
        defer self.allocator.free(root_z);

        if (std.c.opendir(root_z.ptr)) |dir| {
            defer _ = std.c.closedir(dir);

            while (std.c.readdir(dir)) |entry| {
                const name_ptr: [*:0]const u8 = @ptrCast(&entry.name);
                const folder = std.mem.sliceTo(name_ptr, 0);
                if (!shouldIncludeInAggregate(folder, false)) continue;

                const folder_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ root, folder });
                defer self.allocator.free(folder_path);

                const display_folder = if (std.mem.eql(u8, folder, "new")) "INBOX" else folder;
                try self.appendAggregateFolder(&entries, folder_path, display_folder);
            }
        }

        std.mem.sort(AggregateMailboxEntry, entries.items, {}, struct {
            fn lessThan(_: void, a: AggregateMailboxEntry, b: AggregateMailboxEntry) bool {
                if (a.sort_key != b.sort_key) return a.sort_key < b.sort_key;
                return std.mem.order(u8, a.uid_key, b.uid_key) == .lt;
            }
        }.lessThan);

        if (entries.items.len == 0) return;

        const files = try self.allocator.alloc([]const u8, entries.items.len);
        errdefer self.allocator.free(files);
        const dirs = try self.allocator.alloc([]const u8, entries.items.len);
        errdefer self.allocator.free(dirs);
        const uid_keys = try self.allocator.alloc([]const u8, entries.items.len);
        errdefer self.allocator.free(uid_keys);

        for (entries.items, 0..) |entry, i| {
            files[i] = entry.filename;
            dirs[i] = entry.dir;
            uid_keys[i] = entry.uid_key;
        }

        self.mailbox_files = files;
        self.mailbox_file_dirs = dirs;
        self.mailbox_uid_keys = uid_keys;
        entries.clearRetainingCapacity();
    }

    /// Append every message file in a single maildir directory to `entries`,
    /// recording its source directory so per-message paths resolve correctly.
    /// uid_key is the full filename (matching the historical INBOX scheme) so
    /// existing UID assignments are preserved.
    fn appendInboxFolder(self: *ImapSession, entries: *std.ArrayList(AggregateMailboxEntry), dir_path: []const u8) !void {
        const files = fs_compat.listEmlFiles(self.allocator, dir_path) catch return;
        defer {
            for (files) |f| self.allocator.free(f);
            self.allocator.free(files);
        }
        for (files) |filename| {
            const owned_filename = try self.allocator.dupe(u8, filename);
            errdefer self.allocator.free(owned_filename);
            const owned_dir = try self.allocator.dupe(u8, dir_path);
            errdefer self.allocator.free(owned_dir);
            const uid_key = try self.allocator.dupe(u8, filename);
            errdefer self.allocator.free(uid_key);
            try entries.append(self.allocator, .{
                .filename = owned_filename,
                .dir = owned_dir,
                .uid_key = uid_key,
                .sort_key = parseMessageSortKey(filename),
            });
        }
    }

    /// Load INBOX from both the maildir `new/` and `cur/` directories so that
    /// messages are never lost if a client/migration moves them into `cur/`.
    /// Populates mailbox_files + mailbox_file_dirs (per-message source dir) so
    /// FETCH/STORE/COPY/MOVE resolve each message in the directory it lives in.
    fn loadInboxFiles(self: *ImapSession, local_part: []const u8) !void {
        var entries: std.ArrayList(AggregateMailboxEntry) = .empty;
        defer entries.deinit(self.allocator);
        errdefer self.freeAggregateEntries(entries.items);

        const new_dir = try std.fmt.allocPrint(self.allocator, "mail/{s}/new", .{local_part});
        defer self.allocator.free(new_dir);
        const cur_dir = try std.fmt.allocPrint(self.allocator, "mail/{s}/cur", .{local_part});
        defer self.allocator.free(cur_dir);

        try self.appendInboxFolder(&entries, new_dir);
        try self.appendInboxFolder(&entries, cur_dir);

        std.mem.sort(AggregateMailboxEntry, entries.items, {}, struct {
            fn lessThan(_: void, a: AggregateMailboxEntry, b: AggregateMailboxEntry) bool {
                if (a.sort_key != b.sort_key) return a.sort_key < b.sort_key;
                return std.mem.order(u8, a.filename, b.filename) == .lt;
            }
        }.lessThan);

        if (entries.items.len == 0) return;

        const files = try self.allocator.alloc([]const u8, entries.items.len);
        errdefer self.allocator.free(files);
        const dirs = try self.allocator.alloc([]const u8, entries.items.len);
        errdefer self.allocator.free(dirs);
        const uid_keys = try self.allocator.alloc([]const u8, entries.items.len);
        errdefer self.allocator.free(uid_keys);

        for (entries.items, 0..) |entry, i| {
            files[i] = entry.filename;
            dirs[i] = entry.dir;
            uid_keys[i] = entry.uid_key;
        }

        self.mailbox_files = files;
        self.mailbox_file_dirs = dirs;
        self.mailbox_uid_keys = uid_keys;
        entries.clearRetainingCapacity();
    }

    /// Sync UIDs for the current mailbox_files using the database.
    /// Assigns UIDs to new files and builds the mailbox_uids parallel array.
    fn syncUids(self: *ImapSession) !void {
        const db = self.db orelse return;
        const files = self.mailbox_files orelse return;
        const uid_keys = self.mailbox_uid_keys orelse files;

        const full_username = self.username orelse return;
        const username = full_username;

        const mailbox = self.mailbox_name orelse "INBOX";

        // Ensure mailbox record exists
        const mb_info = db.getOrCreateMailbox(username, mailbox) catch return;
        self.mailbox_uidvalidity = mb_info.uidvalidity;

        // Remove stale UIDs for files that no longer exist
        db.removeStaleUids(username, mailbox, uid_keys) catch {};

        // Build UID array in one bulk DB call: a single transaction with
        // reused prepared statements instead of 1-2 round-trips per message.
        if (self.mailbox_uids) |old| self.allocator.free(old);
        self.mailbox_uids = null;

        const keys = try self.allocator.alloc([]const u8, files.len);
        defer self.allocator.free(keys);
        for (files, 0..) |f, i| keys[i] = if (i < uid_keys.len) uid_keys[i] else f;

        const uids = db.syncMailboxUids(self.allocator, username, mailbox, keys) catch blk: {
            // Fallback: UID == sequence number (matches the old per-file
            // fallback when assignment failed)
            const fallback = try self.allocator.alloc(i64, files.len);
            for (fallback, 0..) |*u, i| u.* = @intCast(i + 1);
            break :blk fallback;
        };

        self.mailbox_uids = uids;
        self.rebuildUidSeqMap() catch {};
    }

    /// Give every message in `mailbox` its UID without selecting it, listing
    /// the mailbox exactly as SELECT would so both assign the same UIDs. The
    /// selected mailbox's listing is set aside for the duration and restored.
    fn assignUidsForStatus(self: *ImapSession, db: *database.Database, username: []const u8, mailbox: []const u8) void {
        // The selected mailbox was synced when it was selected.
        if (self.state == .selected) {
            if (self.mailbox_name) |selected| {
                if (std.mem.eql(u8, selected, mailbox)) return;
            }
        }

        const saved_files = self.mailbox_files;
        const saved_dirs = self.mailbox_file_dirs;
        const saved_keys = self.mailbox_uid_keys;
        self.mailbox_files = null;
        self.mailbox_file_dirs = null;
        self.mailbox_uid_keys = null;
        defer {
            if (self.mailbox_files) |files| {
                for (files) |f| self.allocator.free(f);
                self.allocator.free(files);
            }
            if (self.mailbox_file_dirs) |dirs| {
                for (dirs) |d| self.allocator.free(d);
                self.allocator.free(dirs);
            }
            if (self.mailbox_uid_keys) |keys| {
                for (keys) |k| self.allocator.free(k);
                self.allocator.free(keys);
            }
            self.mailbox_files = saved_files;
            self.mailbox_file_dirs = saved_dirs;
            self.mailbox_uid_keys = saved_keys;
        }

        if (std.mem.eql(u8, mailbox, "All Mail")) {
            self.loadAggregateMailboxFiles(username) catch return;
        } else if (std.mem.eql(u8, mailbox, "INBOX")) {
            self.loadInboxFiles(username) catch return;
        } else {
            const dir = std.fmt.allocPrint(self.allocator, "mail/{s}/{s}", .{ username, mailbox }) catch return;
            defer self.allocator.free(dir);
            const files = fs_compat.listEmlFiles(self.allocator, dir) catch return;
            if (files.len == 0) {
                self.allocator.free(files);
                return;
            }
            self.mailbox_files = files;
        }

        const files = self.mailbox_files orelse return;
        const keys = self.mailbox_uid_keys orelse files;
        const uids = db.syncMailboxUids(self.allocator, username, mailbox, keys) catch return;
        self.allocator.free(uids);
    }

    /// Rebuild the UID -> sequence number reverse index after mailbox_uids
    /// changes. On duplicate UIDs the FIRST occurrence wins (matching the
    /// old linear-scan semantics).
    fn rebuildUidSeqMap(self: *ImapSession) !void {
        self.uid_seq_map.clearRetainingCapacity();
        if (self.mailbox_uids) |uids| {
            try self.uid_seq_map.ensureTotalCapacity(self.allocator, @intCast(uids.len));
            for (uids, 0..) |u, i| {
                const gop = self.uid_seq_map.getOrPutAssumeCapacity(u);
                if (!gop.found_existing) gop.value_ptr.* = i + 1;
            }
        }
    }

    /// Get the UID for a given sequence number (1-based).
    fn getUidForSeq(self: *ImapSession, seq: usize) i64 {
        if (self.mailbox_uids) |uids| {
            if (seq >= 1 and seq <= uids.len) {
                return uids[seq - 1];
            }
        }
        return @intCast(seq);
    }

    /// Find sequence number (1-based) for a given UID. Returns null if not found.
    fn getSeqForUid(self: *ImapSession, uid: i64) ?usize {
        if (self.mailbox_uids != null) {
            return self.uid_seq_map.get(uid);
        }
        // Fallback: UID == sequence number
        if (uid >= 1) return @intCast(uid);
        return null;
    }

    /// Translate a UID set string (e.g. "5", "1:10", "3:*") to a sequence number set.
    /// For UID ranges, finds matching sequence numbers and returns a "start:end" string.
    fn uidSetToSeqSet(self: *ImapSession, uid_set: []const u8) ![]const u8 {
        const files = self.mailbox_files orelse return uid_set;
        const uids = self.mailbox_uids orelse return uid_set;

        // Handle comma-separated UID sets (e.g., "83,85,88,90"). Grows
        // dynamically — a fixed buffer here used to silently drop elements
        // of large UID sets once it filled up.
        if (std.mem.indexOf(u8, uid_set, ",") != null) {
            var result: std.ArrayList(u8) = .empty;
            defer result.deinit(self.allocator);
            var parts = std.mem.splitScalar(u8, uid_set, ',');
            var first = true;
            while (parts.next()) |part| {
                const trimmed = std.mem.trim(u8, part, " ");
                if (trimmed.len == 0) continue;
                // Recursively convert each element (handles both single UIDs and ranges)
                const converted = try self.uidSetToSeqSet(trimmed);
                defer if (converted.ptr != trimmed.ptr) self.allocator.free(converted);
                if (!first) try result.append(self.allocator, ',');
                first = false;
                try result.appendSlice(self.allocator, converted);
            }
            return try self.allocator.dupe(u8, result.items);
        }

        if (std.mem.indexOf(u8, uid_set, ":")) |colon| {
            const start_str = uid_set[0..colon];
            const end_str = uid_set[colon + 1 ..];

            const start_uid = std.fmt.parseInt(i64, start_str, 10) catch 1;
            const is_star = std.mem.eql(u8, end_str, "*");
            const end_uid = if (is_star) std.math.maxInt(i64) else (std.fmt.parseInt(i64, end_str, 10) catch @as(i64, @intCast(files.len)));

            // Find min and max sequence numbers that fall in this UID range
            var min_seq: ?usize = null;
            var max_seq: ?usize = null;
            for (uids, 0..) |u, i| {
                if (u >= start_uid and u <= end_uid) {
                    const seq = i + 1;
                    if (min_seq == null or seq < min_seq.?) min_seq = seq;
                    if (max_seq == null or seq > max_seq.?) max_seq = seq;
                }
            }

            if (min_seq) |mn| {
                if (max_seq) |mx| {
                    if (mn == mx) {
                        return try std.fmt.allocPrint(self.allocator, "{d}", .{mn});
                    }
                    return try std.fmt.allocPrint(self.allocator, "{d}:{d}", .{ mn, mx });
                }
            }
            // No matches — return "0:0" which won't match anything
            return try self.allocator.dupe(u8, "0:0");
        } else {
            // Single UID
            const target_uid = std.fmt.parseInt(i64, uid_set, 10) catch return uid_set;
            if (self.getSeqForUid(target_uid)) |seq| {
                return try std.fmt.allocPrint(self.allocator, "{d}", .{seq});
            }
            return try self.allocator.dupe(u8, "0");
        }
    }

    /// Count maildir entries across the same directories the mailbox loader
    /// scans, without allocating, sorting, or touching the database.
    fn currentMailboxEntryCount(self: *ImapSession) usize {
        if (self.mailbox_is_virtual) {
            const full_username = self.username orelse return 0;
            const username = full_username;

            var root_buf: [512]u8 = undefined;
            const root = std.fmt.bufPrintSentinel(&root_buf, "mail/{s}", .{username}, 0) catch return 0;

            var total: usize = 0;
            if (std.c.opendir(root.ptr)) |dir| {
                defer _ = std.c.closedir(dir);
                var folder_buf: [1024]u8 = undefined;
                while (std.c.readdir(dir)) |entry| {
                    const name_ptr: [*:0]const u8 = @ptrCast(&entry.name);
                    const folder = std.mem.sliceTo(name_ptr, 0);
                    if (!shouldIncludeInAggregate(folder, false)) continue;
                    const folder_path = std.fmt.bufPrint(&folder_buf, "{s}/{s}", .{ root, folder }) catch continue;
                    total += fs_compat.countEmlFiles(folder_path);
                }
            }
            return total;
        }

        if (self.mailbox_name) |mname| {
            if (std.ascii.eqlIgnoreCase(mname, "INBOX")) {
                const full_username = self.username orelse return 0;
                const username = full_username;
                var new_buf: [512]u8 = undefined;
                var cur_buf: [512]u8 = undefined;
                const new_dir = std.fmt.bufPrint(&new_buf, "mail/{s}/new", .{username}) catch return 0;
                const cur_dir = std.fmt.bufPrint(&cur_buf, "mail/{s}/cur", .{username}) catch return 0;
                const total = fs_compat.countEmlFiles(new_dir) + fs_compat.countEmlFiles(cur_dir);
                return total;
            }
        }

        const dir = self.mailbox_dir orelse return 0;
        return fs_compat.countEmlFiles(dir);
    }

    /// Set up inotify watches over the selected mailbox's directories so
    /// IDLE pushes EXISTS the moment a message file lands instead of
    /// polling. Linux only; returns null on any failure (callers fall back
    /// to the count-gated timed poll).
    fn setupIdleWatch(self: *ImapSession) ?i32 {
        if (builtin.os.tag != .linux) return null;
        const linux = std.os.linux;

        const init_res = linux.inotify_init1(linux.IN.CLOEXEC | linux.IN.NONBLOCK);
        if (@as(isize, @bitCast(init_res)) < 0) return null;
        const fd: i32 = @intCast(init_res);

        var watched: usize = 0;

        if (self.mailbox_is_virtual) {
            // Watch the user's root (folder add/remove) and every folder.
            const full_username = self.username orelse {
                _ = std.c.close(fd);
                return null;
            };
            const username = full_username;

            var root_buf: [512]u8 = undefined;
            const root = std.fmt.bufPrintSentinel(&root_buf, "mail/{s}", .{username}, 0) catch {
                _ = std.c.close(fd);
                return null;
            };
            if (addIdleWatchDir(fd, root)) watched += 1;

            if (std.c.opendir(root.ptr)) |dir| {
                defer _ = std.c.closedir(dir);
                var folder_buf: [1024]u8 = undefined;
                while (std.c.readdir(dir)) |entry| {
                    const name_ptr: [*:0]const u8 = @ptrCast(&entry.name);
                    const folder = std.mem.sliceTo(name_ptr, 0);
                    if (!shouldIncludeInAggregate(folder, false)) continue;
                    const folder_path = std.fmt.bufPrintSentinel(&folder_buf, "{s}/{s}", .{ root, folder }, 0) catch continue;
                    if (addIdleWatchDir(fd, folder_path)) watched += 1;
                }
            }
        } else if (self.mailbox_name != null and std.ascii.eqlIgnoreCase(self.mailbox_name.?, "INBOX")) {
            const full_username = self.username orelse {
                _ = std.c.close(fd);
                return null;
            };
            const username = full_username;
            var new_buf: [512]u8 = undefined;
            var cur_buf: [512]u8 = undefined;
            if (std.fmt.bufPrintSentinel(&new_buf, "mail/{s}/new", .{username}, 0)) |p| {
                if (addIdleWatchDir(fd, p)) watched += 1;
            } else |_| {}
            if (std.fmt.bufPrintSentinel(&cur_buf, "mail/{s}/cur", .{username}, 0)) |p| {
                if (addIdleWatchDir(fd, p)) watched += 1;
            } else |_| {}
        } else if (self.mailbox_dir) |dir| {
            var dir_buf: [1024]u8 = undefined;
            if (std.fmt.bufPrintSentinel(&dir_buf, "{s}", .{dir}, 0)) |p| {
                if (addIdleWatchDir(fd, p)) watched += 1;
            } else |_| {}
        }

        if (watched == 0) {
            _ = std.c.close(fd);
            return null;
        }
        return fd;
    }

    fn addIdleWatchDir(fd: i32, path: [:0]const u8) bool {
        if (builtin.os.tag != .linux) return false;
        const linux = std.os.linux;
        const mask = linux.IN.CREATE | linux.IN.MOVED_TO | linux.IN.MOVED_FROM | linux.IN.DELETE;
        const res = linux.inotify_add_watch(fd, path.ptr, mask);
        return @as(isize, @bitCast(res)) >= 0;
    }

    /// Drain pending inotify events (we only care THAT something changed).
    fn drainIdleWatch(fd: i32) void {
        var buf: [4096]u8 = undefined;
        while (true) {
            const n = std.c.read(fd, &buf, buf.len);
            if (n <= 0) break;
        }
    }

    fn closeIdleWatch(self: *ImapSession) void {
        if (self.idle_watch_fd) |fd| {
            if (fd >= 0) _ = std.c.close(fd);
            self.idle_watch_fd = null;
        }
    }

    /// Block until the IDLE connection has socket data or the mailbox
    /// changed. Returns true when the caller should proceed to read() from
    /// the socket, false when it should re-loop (a mailbox event or
    /// safety-net timeout was handled here).
    ///
    /// Push mode (Linux, inotify available): poll() on socket + watch fd —
    /// new mail is announced the moment the file lands, with a 60s
    /// safety-net rescan. Fallback mode: 2s socket RCVTIMEO; the read's
    /// WouldBlock drives the count-gated poll (pre-inotify behavior).
    fn idleWaitReadable(self: *ImapSession, sock_fd: std.posix.socket_t) bool {
        if (self.idle_watch_fd == null) {
            self.idle_watch_fd = self.setupIdleWatch() orelse -1;
        }
        const wfd = self.idle_watch_fd.?;

        if (wfd < 0) {
            const idle_tv: std.posix.timeval = .{ .sec = 2, .usec = 0 };
            std.posix.setsockopt(sock_fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&idle_tv)) catch {};
            return true;
        }

        var fds = [2]std.c.pollfd{
            .{ .fd = sock_fd, .events = std.c.POLL.IN, .revents = 0 },
            .{ .fd = wfd, .events = std.c.POLL.IN, .revents = 0 },
        };
        const timeout: c_int = if (self.client_password_id != null) 2_000 else 60_000;
        const n = std.c.poll(&fds, 2, timeout);
        if (n <= 0) {
            // Timeout/EINTR: safety-net rescan in case an event was missed
            if (self.state == .selected) self.idlePollRescan();
            return false;
        }
        if (fds[1].revents != 0) {
            drainIdleWatch(wfd);
            if (self.state == .selected) self.idlePollRescan();
        }
        return fds[0].revents != 0;
    }

    /// Cheap IDLE poll: run the full rescan (directory listing + sort + UID
    /// sync) only when the maildir entry count actually changed. The full
    /// rescan also only reports on count changes, so this is equivalent —
    /// minus the per-poll allocations and database traffic.
    fn idlePollRescan(self: *ImapSession) void {
        if (!(self.checkClientPassword() catch false)) return;
        const count = self.currentMailboxEntryCount();
        if (self.idle_scan_count) |last| {
            if (count == last) return;
        }
        self.idle_scan_count = count;
        _ = self.rescanMailbox() catch {};
    }

    fn reloadGroupedMessages(self: *ImapSession, user: []const u8) !void {
        const db = self.auth_backend.db;
        db.lockMailboxes();
        defer db.unlockMailboxes();
        try self.reloadGroupedMessagesLocked(user);
    }

    fn reloadGroupedMessagesLocked(self: *ImapSession, user: []const u8) !void {
        self.freeSelectedMessageLists();
        if (self.mailbox_is_virtual) try self.loadAggregateMailboxFiles(user) else try self.loadInboxFiles(user);
        self.syncUids() catch {};
    }

    /// Keep the directory snapshot and UID pruning in the same mutation window.
    fn reloadFolderMessages(self: *ImapSession, dir: []const u8, only_if_count_changed: bool) !bool {
        const db = self.auth_backend.db;
        db.lockMailboxes();
        defer db.unlockMailboxes();
        return self.reloadFolderMessagesLocked(dir, only_if_count_changed);
    }

    fn reloadFolderMessagesLocked(self: *ImapSession, dir: []const u8, only_if_count_changed: bool) !bool {
        const files = try fs_compat.listEmlFiles(self.allocator, dir);
        const old_count = if (self.mailbox_files) |previous| previous.len else 0;
        if (only_if_count_changed and files.len == old_count) {
            for (files) |file| self.allocator.free(file);
            self.allocator.free(files);
            return false;
        }
        self.freeSelectedMessageLists();
        if (files.len == 0) self.allocator.free(files) else self.mailbox_files = files;
        self.syncUids() catch {};
        return true;
    }

    /// Re-scan the current mailbox for new messages.
    /// If the message count changed, sends untagged EXISTS/RECENT responses
    /// so the client knows to fetch new messages. Returns true if new mail found.
    fn rescanMailbox(self: *ImapSession) !bool {
        const old_count: usize = if (self.mailbox_files) |f| f.len else 0;

        if (self.mailbox_is_virtual) {
            const full_username = self.username orelse return false;
            const username = full_username;

            try self.reloadGroupedMessages(username);

            const new_count: usize = if (self.mailbox_files) |f| f.len else 0;
            if (new_count != old_count) {
                const exists_msg = try std.fmt.allocPrint(self.allocator, "{d} EXISTS", .{new_count});
                defer self.allocator.free(exists_msg);
                try self.sendUntagged(exists_msg);

                const recent_count = if (new_count > old_count) new_count - old_count else 0;
                const recent_msg = try std.fmt.allocPrint(self.allocator, "{d} RECENT", .{recent_count});
                defer self.allocator.free(recent_msg);
                try self.sendUntagged(recent_msg);

                std.log.info("IMAP virtual mailbox rescan: {d} -> {d} messages ({d} new)", .{ old_count, new_count, recent_count });
                return true;
            }
            return false;
        }

        // INBOX is backed by new/ + cur/ with per-message source dirs; reload it
        // through the same loader SELECT used so the mapping stays consistent.
        if (self.mailbox_name) |mname| {
            if (std.ascii.eqlIgnoreCase(mname, "INBOX")) {
                const full_username = self.username orelse return false;
                const username = full_username;
                try self.reloadGroupedMessages(username);
                const new_count: usize = if (self.mailbox_files) |f| f.len else 0;
                if (new_count != old_count) {
                    const exists_msg = try std.fmt.allocPrint(self.allocator, "{d} EXISTS", .{new_count});
                    defer self.allocator.free(exists_msg);
                    try self.sendUntagged(exists_msg);
                    const recent_count = if (new_count > old_count) new_count - old_count else 0;
                    const recent_msg = try std.fmt.allocPrint(self.allocator, "{d} RECENT", .{recent_count});
                    defer self.allocator.free(recent_msg);
                    try self.sendUntagged(recent_msg);
                    std.log.info("IMAP INBOX rescan: {d} -> {d} messages ({d} new)", .{ old_count, new_count, recent_count });
                    return true;
                }
                return false;
            }
        }

        const dir = self.mailbox_dir orelse return false;

        if (self.reloadFolderMessages(dir, true) catch false) {
            const new_count = if (self.mailbox_files) |files| files.len else 0;

            // Notify client of new message count
            const exists_msg = try std.fmt.allocPrint(self.allocator, "{d} EXISTS", .{new_count});
            defer self.allocator.free(exists_msg);
            try self.sendUntagged(exists_msg);

            const recent_count = if (new_count > old_count) new_count - old_count else 0;
            const recent_msg = try std.fmt.allocPrint(self.allocator, "{d} RECENT", .{recent_count});
            defer self.allocator.free(recent_msg);
            try self.sendUntagged(recent_msg);

            std.log.info("IMAP mailbox rescan: {d} -> {d} messages ({d} new)", .{ old_count, new_count, recent_count });
            return true;
        }

        return false;
    }

    /// Clean up pending APPEND state
    fn cleanupAppend(self: *ImapSession) void {
        if (self.append_tag) |t| {
            self.allocator.free(t);
            self.append_tag = null;
        }
        if (self.append_mailbox) |m| {
            self.allocator.free(m);
            self.append_mailbox = null;
        }
        if (self.append_flags) |f| {
            self.allocator.free(f);
            self.append_flags = null;
        }
        self.append_internal_date = null;
        if (self.append_literal_buf) |b| {
            self.allocator.free(b);
            self.append_literal_buf = null;
        }
        self.append_literal_size = 0;
        self.append_literal_pos = 0;
    }

    /// Finalize a pending APPEND: save message to Maildir and send OK response
    pub fn finalizeAppend(self: *ImapSession) !void {
        const tag = self.append_tag orelse return;
        const mailbox = self.append_mailbox orelse return;
        const data = self.append_literal_buf orelse return;
        const size = self.append_literal_size;
        defer self.cleanupAppend();

        const username = self.username orelse {
            try self.sendResponse(tag, "NO", "Not authenticated");
            return;
        };

        if (!isSafeMailboxName(mailbox)) {
            try self.sendResponse(tag, "NO", "Invalid mailbox name");
            return;
        }

        clamav.requireAllowed(self.scanner, data[0..size]) catch |err| {
            const response = switch (err) {
                error.MalwareDetected => "Message rejected by malware scanner",
                error.MalwareScanTooLarge => "[TOOBIG] Message exceeds scanner size limit",
                error.MalwareScanUnavailable => "[UNAVAILABLE] Malware scanner unavailable; please retry",
            };
            return self.sendResponse(tag, "NO", response);
        };
        if (!try self.checkClientPassword()) return;

        const local_part = username;

        // Determine folder directory
        const folder_dir = if (std.ascii.eqlIgnoreCase(mailbox, "INBOX"))
            try std.fmt.allocPrint(self.allocator, "mail/{s}/new", .{local_part})
        else
            try std.fmt.allocPrint(self.allocator, "mail/{s}/{s}", .{ local_part, mailbox });
        defer self.allocator.free(folder_dir);

        // Write message file with timestamp-based name, honoring the flags
        // from the APPEND command (e.g. APPEND "Sent" (\Seen) {...}). Without
        // this, sent/draft copies saved by clients land on disk flagless and
        // surface as "unread" in folder counts (STATUS UNSEEN, webmail, and
        // client badges such as Apple Mail's).
        var flags = if (self.append_flags) |raw| FlagList.parse(raw) catch
            return self.sendResponse(tag, "BAD", "Invalid APPEND flags") else FlagList{};
        if (self.append_flags == null and (std.ascii.eqlIgnoreCase(mailbox, "Sent") or std.ascii.eqlIgnoreCase(mailbox, "Drafts"))) {
            // Clients that omit the flag list for Sent/Drafts still expect
            // those copies to be read — they are the user's own messages.
            flags.system.seen = true;
        }
        const internal_date = self.append_internal_date orelse time_compat.timestamp();
        const assigned = self.writeAppend(username, mailbox, folder_dir, &flags, data[0..size], internal_date) catch |err|
            return self.sendMaildirWriteError(tag, err);

        // Send OK, including APPENDUID only when we have a real UID/UIDVALIDITY.
        if (flags.keyword_count != 0 and !self.mailbox_is_virtual) {
            if (self.mailbox_name) |selected| {
                if (std.mem.eql(u8, canonicalMailboxName(mailbox), selected)) try self.sendFlagCapabilities(false);
            }
        }
        if (assigned) |identity| {
            var resp_buf: [256]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&resp_buf);
            fbs.writer().print("[APPENDUID {d} {d}] APPEND completed", .{ identity.validity, identity.uid }) catch {
                try self.sendResponse(tag, "OK", "APPEND completed");
                return;
            };
            try self.sendResponse(tag, "OK", fbs.getWritten());
        } else {
            try self.sendResponse(tag, "OK", "APPEND completed");
        }
    }

    const AppendIdentity = struct { validity: i64, uid: i64 };

    fn writeAppend(self: *ImapSession, user: []const u8, mailbox: []const u8, dir: []const u8, flags: *const FlagList, raw: []const u8, date: i64) !?AppendIdentity {
        const db = self.auth_backend.db;
        db.lockMailboxes();
        defer db.unlockMailboxes();
        try hosted_limits.checkStorage(db, user, raw.len, null);
        try fs_compat.cwd().makePath(dir);
        var resolved = flags.system;
        if (flags.keyword_count != 0) {
            var scratch = std.heap.ArenaAllocator.init(self.allocator);
            defer scratch.deinit();
            const a = scratch.allocator();
            var mapping = try maildir_keywords.Mapping.open(a, dir);
            resolved = try flags.resolve(&mapping.names, .replace);
            try mapping.save(a);
        }
        var suffix: [maildir_keywords.suffix_capacity]u8 = undefined;
        const path = try self.allocUniqueMaildirPath(dir, resolved.toSuffix(&suffix), date);
        defer self.allocator.free(path);
        try maildir_index.markLocked(db, user, false, &.{message_refs.location(mailbox, std.fs.path.basename(path))});
        try durable_maildir.writeWithMtime(self.allocator, path, raw, date);
        if (std.mem.eql(u8, mailbox, "Sent") and !resolved.deleted and !resolved.draft) {
            var scratch = std.heap.ArenaAllocator.init(self.allocator);
            defer scratch.deinit();
            sent_replies.observeCopy(scratch.allocator(), db, user, path, raw) catch |err|
                std.log.warn("could not record a client-filed Sent copy: {}", .{err});
        }
        std.log.info("IMAP APPEND: Saved {d} bytes to {s}", .{ raw.len, path });

        // Keep APPENDUID assignment in the same mutation window as the
        // Maildir publication so RENAME cannot split the message and its UID.
        const uid_db = self.db orelse return null;
        const uid_mailbox = canonicalMailboxName(mailbox);
        const info = uid_db.getOrCreateMailbox(user, uid_mailbox) catch return null;
        const uid = uid_db.assignUid(user, uid_mailbox, std.fs.path.basename(path)) catch return null;
        return .{ .validity = info.uidvalidity, .uid = uid };
    }

    /// Count messages in a mailbox folder
    fn countMailboxMessages(self: *ImapSession, mailbox_name: []const u8) usize {
        return self.countMailboxStats(mailbox_name).messages;
    }

    const MailboxStats = struct {
        messages: usize = 0,
        unseen: usize = 0,
        recent: usize = 0,
    };

    fn countDirStats(self: *ImapSession, path: []const u8) MailboxStats {
        const files = fs_compat.listEmlFiles(self.allocator, path) catch return .{};
        defer {
            for (files) |f| self.allocator.free(f);
            self.allocator.free(files);
        }

        var stats = MailboxStats{ .messages = files.len };
        for (files) |fname| {
            const flags = MaildirFlags.fromFilename(fname);
            if (!flags.seen) stats.unseen += 1;
        }
        return stats;
    }

    fn addDirStats(self: *ImapSession, stats: *MailboxStats, path: []const u8) void {
        const next = self.countDirStats(path);
        stats.messages += next.messages;
        stats.unseen += next.unseen;
        stats.recent += next.recent;
    }

    fn countMailboxStats(self: *ImapSession, mailbox_name: []const u8) MailboxStats {
        const username = self.username orelse return .{};
        const local_part = username;

        const clean_name = stripQuotes(mailbox_name);

        if (std.ascii.eqlIgnoreCase(clean_name, "All Mail") or std.ascii.eqlIgnoreCase(clean_name, "All")) {
            return self.countAggregateMailboxStats(local_part, false);
        }

        if (std.ascii.eqlIgnoreCase(clean_name, "Starred")) {
            return self.countFlaggedStats(local_part);
        }

        // INBOX spans both the maildir new/ and cur/ directories.
        if (std.ascii.eqlIgnoreCase(clean_name, "INBOX")) {
            var stats = MailboxStats{};
            const new_path = std.fmt.allocPrint(self.allocator, "mail/{s}/new", .{local_part}) catch return stats;
            defer self.allocator.free(new_path);
            const cur_path = std.fmt.allocPrint(self.allocator, "mail/{s}/cur", .{local_part}) catch return stats;
            defer self.allocator.free(cur_path);
            self.addDirStats(&stats, new_path);
            self.addDirStats(&stats, cur_path);
            return stats;
        }

        const path = std.fmt.allocPrint(self.allocator, "mail/{s}/{s}", .{ local_part, clean_name }) catch return .{};
        defer self.allocator.free(path);

        return self.countDirStats(path);
    }

    fn shouldIncludeInAggregate(folder: []const u8, include_excluded: bool) bool {
        if (folder.len == 0 or folder[0] == '.') return false;
        if (std.mem.eql(u8, folder, "tmp") or std.mem.eql(u8, folder, "cur")) return false;
        if (!include_excluded and (std.ascii.eqlIgnoreCase(folder, "Trash") or std.ascii.eqlIgnoreCase(folder, "Junk"))) return false;
        return true;
    }

    fn countAggregateMailboxStats(self: *ImapSession, local_part: []const u8, include_excluded: bool) MailboxStats {
        const root = std.fmt.allocPrint(self.allocator, "mail/{s}", .{local_part}) catch return .{};
        defer self.allocator.free(root);

        var stats = MailboxStats{};
        const path_z = self.allocator.dupeSentinel(u8, root, 0) catch return stats;
        defer self.allocator.free(path_z);

        const dir = std.c.opendir(path_z.ptr) orelse {
            const inbox_path = std.fmt.allocPrint(self.allocator, "{s}/new", .{root}) catch return stats;
            defer self.allocator.free(inbox_path);
            self.addDirStats(&stats, inbox_path);
            return stats;
        };
        defer _ = std.c.closedir(dir);

        while (std.c.readdir(dir)) |entry| {
            const name_ptr: [*:0]const u8 = @ptrCast(&entry.name);
            const folder = std.mem.sliceTo(name_ptr, 0);
            if (!shouldIncludeInAggregate(folder, include_excluded)) continue;

            const path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ root, folder }) catch continue;
            defer self.allocator.free(path);
            self.addDirStats(&stats, path);
        }

        return stats;
    }

    fn countFlaggedStats(self: *ImapSession, local_part: []const u8) MailboxStats {
        var stats = MailboxStats{};
        const root = std.fmt.allocPrint(self.allocator, "mail/{s}", .{local_part}) catch return stats;
        defer self.allocator.free(root);

        const path_z = self.allocator.dupeSentinel(u8, root, 0) catch return stats;
        defer self.allocator.free(path_z);

        const dir = std.c.opendir(path_z.ptr) orelse return stats;
        defer _ = std.c.closedir(dir);

        while (std.c.readdir(dir)) |entry| {
            const name_ptr: [*:0]const u8 = @ptrCast(&entry.name);
            const folder = std.mem.sliceTo(name_ptr, 0);
            if (!shouldIncludeInAggregate(folder, false)) continue;

            const path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ root, folder }) catch continue;
            defer self.allocator.free(path);

            const files = fs_compat.listEmlFiles(self.allocator, path) catch continue;
            defer {
                for (files) |f| self.allocator.free(f);
                self.allocator.free(files);
            }

            for (files) |fname| {
                const flags = MaildirFlags.fromFilename(fname);
                if (!flags.flagged) continue;

                stats.messages += 1;
                if (!flags.seen) stats.unseen += 1;
            }
        }

        return stats;
    }

    /// Write data to connection (plain or TLS encrypted)
    /// Handles large data by chunking into TLS-record-sized pieces
    fn writeData(self: *ImapSession, data: []const u8) !void {
        // Never copy response bodies into the journal. FETCH responses can
        // contain private message content and high-volume synchronization
        // traffic should not consume production CPU and disk at info level.
        std.log.debug("IMAP response: {d} bytes", .{data.len});
        if (self.tls_connection) |tls_conn| {
            // TLS max plaintext per record is ~16KB; chunk to stay safe
            const chunk_size: usize = 8192;
            var offset: usize = 0;
            while (offset < data.len) {
                const end = @min(offset + chunk_size, data.len);
                const chunk = data[offset..end];

                var send_buf: [tls.output_buffer_len]u8 = undefined;
                const enc_result = tls_conn.encrypt(chunk, &send_buf) catch |err| {
                    logger.err("Failed to encrypt IMAP response: {}", .{err});
                    return error.TlsEncryptFailed;
                };
                var sent: usize = 0;
                while (sent < enc_result.ciphertext.len) {
                    const n = self.connection.write(enc_result.ciphertext[sent..]) catch |err| {
                        logger.err("Failed to write encrypted IMAP response: {}", .{err});
                        return err;
                    };
                    if (n == 0) return error.ConnectionClosed;
                    sent += n;
                }
                offset = end;
            }
        } else {
            // Plain text write
            _ = try self.connection.write(data);
        }
    }

    fn readAuthenticationLine(self: *ImapSession, buf: *[1024]u8) ![]const u8 {
        if (self.tls_connection) |tls_conn| {
            var ciphertext: [tls.input_buffer_len * 2]u8 = undefined;
            var ciphertext_len: usize = 0;
            var cleartext_len: usize = 0;

            while (cleartext_len < buf.len) {
                if (ciphertext_len == ciphertext.len) return error.AuthenticationFieldTooLong;
                const bytes_read = try self.connection.read(ciphertext[ciphertext_len..]);
                if (bytes_read == 0) return error.ConnectionClosed;
                ciphertext_len += bytes_read;

                const dec_result = try tls_conn.decrypt(ciphertext[0..ciphertext_len], buf[cleartext_len..]);
                cleartext_len += dec_result.cleartext.len;
                if (dec_result.ciphertext_pos > 0) {
                    const remaining = ciphertext_len - dec_result.ciphertext_pos;
                    if (remaining > 0)
                        std.mem.copyForwards(u8, &ciphertext, ciphertext[dec_result.ciphertext_pos..ciphertext_len]);
                    ciphertext_len = remaining;
                }

                if (std.mem.indexOfScalar(u8, buf[0..cleartext_len], '\n')) |line_end|
                    return std.mem.trim(u8, buf[0..line_end], "\r");
                if (dec_result.closed) return error.ConnectionClosed;
            }
            return error.AuthenticationFieldTooLong;
        }

        var used: usize = 0;
        while (used < buf.len) {
            const bytes_read = try self.connection.read(buf[used..]);
            if (bytes_read == 0) return error.ConnectionClosed;
            used += bytes_read;
            if (std.mem.indexOfScalar(u8, buf[0..used], '\n')) |line_end|
                return std.mem.trim(u8, buf[0..line_end], "\r");
        }
        return error.AuthenticationFieldTooLong;
    }

    pub fn decodeAuthenticationField(encoded: []const u8, output: []u8) ![]const u8 {
        const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(encoded);
        if (decoded_len > output.len) return error.AuthenticationFieldTooLong;
        try std.base64.standard.Decoder.decode(output[0..decoded_len], encoded);
        return output[0..decoded_len];
    }

    /// Send greeting
    pub fn sendGreeting(self: *ImapSession) !void {
        const greeting = "* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN AUTH=LOGIN IDLE NAMESPACE UIDPLUS SPECIAL-USE MOVE XMAILDIR-KEYWORDS] Mail Server IMAP4rev1 ready\r\n";
        try self.writeData(greeting);
    }

    /// Send response
    pub fn sendResponse(self: *ImapSession, tag: []const u8, status: []const u8, message: []const u8) !void {
        var buf: [4096]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        try writer.print("{s} {s} {s}\r\n", .{ tag, status, message });

        try self.writeData(fbs.getWritten());
    }

    /// Send untagged response
    pub fn sendUntagged(self: *ImapSession, message: []const u8) !void {
        var buf: [4096]u8 = undefined;
        if (message.len > buf.len - "* \r\n".len) {
            const frame = try std.fmt.allocPrint(self.allocator, "* {s}\r\n", .{message});
            defer self.allocator.free(frame);
            return self.writeData(frame);
        }
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        try writer.print("* {s}\r\n", .{message});

        try self.writeData(fbs.getWritten());
    }

    /// Handle CAPABILITY command
    fn handleCapability(self: *ImapSession, tag: []const u8) !void {
        const capabilities = [_]ImapCapability{
            .imap4rev1,
            .starttls,
            .auth_plain,
            .auth_login,
            .idle,
            .namespace,
            .uidplus,
            .special_use, // RFC 6154 - Gmail-style folders
            .move, // RFC 6851
            .maildir_keywords,
        };

        var buf: [1024]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        try writer.writeAll("CAPABILITY");

        for (capabilities) |cap| {
            try writer.print(" {s}", .{cap.toString()});
        }

        try self.sendUntagged(fbs.getWritten());
        try self.sendResponse(tag, "OK", "CAPABILITY completed");
    }

    /// Handle LIST command - returns Gmail-style folder listing plus user-created folders.
    /// Supports `*` (all levels) and `%` (current level only) wildcard patterns.
    fn handleList(self: *ImapSession, tag: []const u8, reference: []const u8, pattern: []const u8) !void {
        _ = reference; // Reference name (usually empty)

        if (self.state == .not_authenticated) {
            try self.sendResponse(tag, "NO", "Must authenticate first");
            return;
        }

        // If pattern is empty, return hierarchy delimiter
        const clean_pattern = stripQuotes(pattern);
        if (clean_pattern.len == 0) {
            try self.sendUntagged("LIST (\\Noselect) \"/\" \"\"");
            try self.sendResponse(tag, "OK", "LIST completed");
            return;
        }

        // Return standard Gmail-style folders (filtered by pattern)
        for (GmailFolders) |folder_type| {
            if (!self.gmail_labels_enabled and folder_type.isVirtual()) continue;
            if (!self.gmail_labels_enabled and switch (folder_type) {
                .important, .social, .forums, .updates, .promotions => true,
                else => false,
            }) continue;
            const attrs = if (folder_type == .junk and !std.mem.eql(u8, self.junk_folder, "Junk")) "\\HasNoChildren" else folder_type.getAttributes();
            const name = folder_type.getName();
            if (!matchListPattern(clean_pattern, name)) continue;

            var buf: [512]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&buf);
            const writer = fbs.writer();
            try writer.print("LIST ({s}) \"/\" \"{s}\"", .{ attrs, name });
            try self.sendUntagged(fbs.getWritten());
        }

        if (!std.mem.eql(u8, self.junk_folder, "Junk") and matchListPattern(clean_pattern, self.junk_folder)) {
            var response: [512]u8 = undefined;
            try self.sendUntagged(try std.fmt.bufPrint(&response, "LIST (\\HasNoChildren \\Junk) \"/\" \"{s}\"", .{self.junk_folder}));
        }

        // Scan user-created folders on disk
        if (self.username) |uname| {
            const local = uname;
            const mail_dir = std.fmt.allocPrint(self.allocator, "mail/{s}", .{local}) catch null;
            if (mail_dir) |md| {
                defer self.allocator.free(md);
                self.listUserFolders(md, clean_pattern) catch {};
            }
        }

        try self.sendResponse(tag, "OK", "LIST completed");
    }

    /// Scan the user's mail directory for non-standard folders and list them.
    fn listUserFolders(self: *ImapSession, mail_dir: []const u8, pattern: []const u8) !void {
        // Standard folder names that are already listed via GmailFolders
        const standard = [_][]const u8{
            "INBOX",      "Sent",    "Drafts",    "Trash",  "Junk",   "Archive",
            "All Mail",   "Starred", "Important", "Social", "Forums", "Updates",
            "Promotions", "Notes",   "new",       "cur",    "tmp",
        };

        var path_buf: [4097]u8 = undefined;
        if (mail_dir.len >= path_buf.len) return;
        @memcpy(path_buf[0..mail_dir.len], mail_dir);
        path_buf[mail_dir.len] = 0;
        const dir_z: [*:0]const u8 = @ptrCast(&path_buf);

        const dirp = std.c.opendir(dir_z) orelse return;
        defer _ = std.c.closedir(dirp);

        while (std.c.readdir(dirp)) |entry| {
            const name_ptr: [*:0]const u8 = @ptrCast(&entry.name);
            const name = std.mem.sliceTo(name_ptr, 0);
            if (name.len == 0 or name[0] == '.') continue;

            // Skip standard folders
            var is_standard = false;
            for (standard) |s| {
                if (std.mem.eql(u8, name, s)) {
                    is_standard = true;
                    break;
                }
            }
            if (is_standard or std.mem.eql(u8, name, self.junk_folder)) continue;

            // Check if this is actually a directory
            var sub_buf: [4097]u8 = undefined;
            const sub_path = std.fmt.bufPrint(&sub_buf, "{s}/{s}", .{ mail_dir, name }) catch continue;
            sub_buf[sub_path.len] = 0;
            const sub_z: [*:0]const u8 = @ptrCast(&sub_buf);
            const sub_dir = std.c.opendir(sub_z) orelse continue;
            _ = std.c.closedir(sub_dir);

            if (!matchListPattern(pattern, name)) continue;

            var resp_buf: [512]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&resp_buf);
            fbs.writer().print("LIST (\\HasNoChildren) \"/\" \"{s}\"", .{name}) catch continue;
            self.sendUntagged(fbs.getWritten()) catch continue;
        }
    }

    /// Handle STATUS command - returns folder status
    fn handleStatus(self: *ImapSession, tag: []const u8, mailbox_name: []const u8, status_items: []const u8) !void {
        if (self.state == .not_authenticated) {
            try self.sendResponse(tag, "NO", "Must authenticate first");
            return;
        }

        if (!isSafeMailboxName(mailbox_name)) {
            try self.sendResponse(tag, "NO", "Invalid mailbox name");
            return;
        }

        // Parse which status items are requested
        const want_messages = std.mem.indexOf(u8, status_items, "MESSAGES") != null;
        const want_recent = std.mem.indexOf(u8, status_items, "RECENT") != null;
        const want_uidnext = std.mem.indexOf(u8, status_items, "UIDNEXT") != null;
        const want_uidvalidity = std.mem.indexOf(u8, status_items, "UIDVALIDITY") != null;
        const want_unseen = std.mem.indexOf(u8, status_items, "UNSEEN") != null;

        // Build status response (would be populated from actual mailbox data)
        var buf: [1024]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        const clean_mailbox = stripQuotes(mailbox_name);

        if (!self.gmail_labels_enabled and isLegacySyntheticMailbox(clean_mailbox)) {
            try self.sendResponse(tag, "NO", "[NONEXISTENT] Mailbox does not exist");
            return;
        }

        // Derive UIDVALIDITY/UIDNEXT from the database so STATUS matches what
        // SELECT reports. If STATUS advertises different values than SELECT,
        // clients such as Apple Mail treat the mailbox as invalidated on every
        // poll, repeatedly discard their cache, and fail to show unread counts.
        const canonical_mailbox = canonicalMailboxName(clean_mailbox);
        var stats: MailboxStats = undefined;
        var uidvalidity: i64 = 1;
        var uidnext: i64 = 1;
        {
            const db = self.auth_backend.db;
            db.lockMailboxes();
            defer db.unlockMailboxes();
            stats = self.countMailboxStats(clean_mailbox);
            uidnext = @as(i64, @intCast(stats.messages)) + 1;
            if (self.db) |uid_db| {
                if (self.username) |user| {
                    if (uid_db.getOrCreateMailbox(user, canonical_mailbox)) |info| {
                        uidvalidity = info.uidvalidity;
                        // Assign UIDs to files a client has not selected yet.
                        if (want_uidnext) self.assignUidsForStatus(uid_db, user, canonical_mailbox);
                        uidnext = uid_db.getUidNext(user, canonical_mailbox) catch uidnext;
                    } else |_| {}
                }
            }
        }

        try writer.print("STATUS \"{s}\" (", .{clean_mailbox});

        var first = true;
        if (want_messages) {
            try writer.print("MESSAGES {d}", .{stats.messages});
            first = false;
        }
        if (want_recent) {
            if (!first) try writer.writeAll(" ");
            try writer.print("RECENT {d}", .{stats.recent});
            first = false;
        }
        if (want_uidnext) {
            if (!first) try writer.writeAll(" ");
            try writer.print("UIDNEXT {d}", .{uidnext});
            first = false;
        }
        if (want_uidvalidity) {
            if (!first) try writer.writeAll(" ");
            try writer.print("UIDVALIDITY {d}", .{uidvalidity});
            first = false;
        }
        if (want_unseen) {
            if (!first) try writer.writeAll(" ");
            try writer.print("UNSEEN {d}", .{stats.unseen});
        }
        try writer.writeAll(")");

        const response = fbs.getWritten();
        std.log.info("IMAP STATUS for {s}: {s}", .{ clean_mailbox, response });
        try self.sendUntagged(response);
        try self.sendResponse(tag, "OK", "STATUS completed");
    }

    /// Handle XLIST command (Gmail extension, same as LIST)
    fn handleXList(self: *ImapSession, tag: []const u8, reference: []const u8, pattern: []const u8) !void {
        // XLIST is a Gmail extension that's equivalent to LIST with SPECIAL-USE
        try self.handleList(tag, reference, pattern);
    }

    /// Handle LOGIN command
    fn handleLogin(self: *ImapSession, tag: []const u8, username: []const u8, password: []const u8) !void {
        if (self.state != .not_authenticated) {
            try self.sendResponse(tag, "BAD", "Already authenticated");
            return;
        }

        // Validate credentials against auth backend
        const valid = self.authenticateClient(username, password) catch |err| {
            if (err == error.AuthenticationRateLimited)
                std.log.warn("IMAP authentication rate-limited for {s}", .{self.connection.peerIp()})
            else
                std.log.err("Authentication error: {}", .{err});
            try self.sendResponse(tag, "NO", "LOGIN failed");
            return;
        };

        var name_buf: log_safe.Buffer = undefined;
        if (!valid) {
            std.log.warn("Failed IMAP authentication for {s} from {s}", .{ log_safe.account(&name_buf, username), self.connection.peerIp() });
            try self.sendResponse(tag, "NO", "LOGIN failed");
            return;
        }

        std.log.info("Successful IMAP login for user: {s}", .{log_safe.account(&name_buf, username)});
        try self.sendResponse(tag, "OK", "LOGIN completed");
    }

    /// Handle AUTHENTICATE command (RFC 3501 Section 6.2.2)
    fn handleAuthenticate(self: *ImapSession, tag: []const u8, mechanism: []const u8, initial_response: ?[]const u8) !void {
        if (self.state != .not_authenticated) {
            try self.sendResponse(tag, "BAD", "Already authenticated");
            return;
        }

        if (!std.ascii.eqlIgnoreCase(mechanism, "PLAIN") and !std.ascii.eqlIgnoreCase(mechanism, "LOGIN")) {
            try self.sendResponse(tag, "NO", "Unsupported authentication mechanism");
            return;
        }

        if (std.ascii.eqlIgnoreCase(mechanism, "LOGIN")) {
            var username_line_buf: [1024]u8 = undefined;
            const encoded_username = if (initial_response) |resp| resp else blk: {
                try self.writeData("+ VXNlcm5hbWU6\r\n");
                break :blk self.readAuthenticationLine(&username_line_buf) catch {
                    try self.sendResponse(tag, "NO", "Authentication failed");
                    return;
                };
            };
            if (std.mem.eql(u8, encoded_username, "*")) {
                try self.sendResponse(tag, "BAD", "Authentication cancelled");
                return;
            }

            var username_buf: [512]u8 = undefined;
            const username = decodeAuthenticationField(encoded_username, &username_buf) catch {
                try self.sendResponse(tag, "NO", "Authentication failed");
                return;
            };

            try self.writeData("+ UGFzc3dvcmQ6\r\n");
            var password_line_buf: [1024]u8 = undefined;
            const encoded_password = self.readAuthenticationLine(&password_line_buf) catch {
                try self.sendResponse(tag, "NO", "Authentication failed");
                return;
            };
            if (std.mem.eql(u8, encoded_password, "*")) {
                try self.sendResponse(tag, "BAD", "Authentication cancelled");
                return;
            }

            var password_buf: [512]u8 = undefined;
            const password = decodeAuthenticationField(encoded_password, &password_buf) catch {
                try self.sendResponse(tag, "NO", "Authentication failed");
                return;
            };
            defer @memset(password_buf[0..password.len], 0);

            const valid = self.authenticateClient(username, password) catch {
                try self.sendResponse(tag, "NO", "Authentication failed");
                return;
            };
            var name_buf: log_safe.Buffer = undefined;
            if (!valid) {
                std.log.warn("Failed IMAP authentication for {s} from {s}", .{ log_safe.account(&name_buf, username), self.connection.peerIp() });
                try self.sendResponse(tag, "NO", "Authentication failed");
                return;
            }

            std.log.info("Successful IMAP AUTH LOGIN for user: {s}", .{log_safe.account(&name_buf, username)});
            try self.sendResponse(tag, "OK", "AUTHENTICATE completed");
            return;
        }

        var encoded: []const u8 = undefined;

        if (initial_response) |resp| {
            // Initial response provided on the same line (RFC 4959)
            encoded = resp;
        } else {
            try self.writeData("+ \r\n");

            var buf: [1024]u8 = undefined;
            encoded = self.readAuthenticationLine(&buf) catch {
                try self.sendResponse(tag, "NO", "Authentication failed");
                return;
            };
        }

        // Handle "*" (cancel)
        if (std.mem.eql(u8, encoded, "*")) {
            try self.sendResponse(tag, "BAD", "Authentication cancelled");
            return;
        }

        // Decode base64 PLAIN credentials: \0username\0password
        const credentials = auth.decodeBase64Auth(self.allocator, encoded) catch {
            try self.sendResponse(tag, "NO", "Authentication failed");
            return;
        };
        defer {
            self.allocator.free(credentials.username);
            @memset(@constCast(credentials.password), 0);
            self.allocator.free(credentials.password);
        }

        // Verify credentials
        const valid = self.authenticateClient(credentials.username, credentials.password) catch {
            try self.sendResponse(tag, "NO", "Authentication failed");
            return;
        };

        var name_buf: log_safe.Buffer = undefined;
        if (!valid) {
            std.log.warn("Failed IMAP authentication for {s} from {s}", .{ log_safe.account(&name_buf, credentials.username), self.connection.peerIp() });
            try self.sendResponse(tag, "NO", "Authentication failed");
            return;
        }

        std.log.info("Successful IMAP AUTHENTICATE for user: {s}", .{log_safe.account(&name_buf, credentials.username)});
        try self.sendResponse(tag, "OK", "AUTHENTICATE completed");
    }

    fn authenticateClient(self: *ImapSession, username: []const u8, password: []const u8) !bool {
        const account = (try self.auth_backend.authenticateClient(self.allocator, self.connection.peerIp(), username, password, if (self.tls_connection != null) .mail else null)) orelse return false;
        self.username = account.username;
        self.client_password_id = account.credential_id;
        self.state = .authenticated;
        return true;
    }

    fn checkClientPassword(self: *ImapSession) !bool {
        const id = self.client_password_id orelse return true;
        if (client_passwords.active(self.auth_backend.db, id) catch false) return true;
        self.state = .logout;
        try self.sendUntagged("BYE App password is no longer available");
        return false;
    }

    /// Handle SELECT command
    fn handleSelect(self: *ImapSession, tag: []const u8, mailbox_name: []const u8) !void {
        if (self.state == .not_authenticated) {
            try self.sendResponse(tag, "NO", "Must authenticate first");
            return;
        }

        const full_username = self.username orelse {
            try self.sendResponse(tag, "NO", "No username set");
            return;
        };

        // Extract local part from email address (chris@stacksjs.com -> chris)
        // SMTP delivers to mail/{local_part}/new/ so IMAP must use the same path
        const username = full_username;

        // Free previous mailbox state
        self.freeMailboxFiles();
        if (self.mailbox_name) |n| {
            self.allocator.free(n);
            self.mailbox_name = null;
        }

        // Strip quotes from mailbox name (Apple Mail sends "INBOX" with quotes sometimes)
        const mailbox = stripQuotes(mailbox_name);
        if (!isSafeMailboxName(mailbox)) {
            try self.sendResponse(tag, "NO", "Invalid mailbox name");
            return;
        }
        if (!self.gmail_labels_enabled and isLegacySyntheticMailbox(mailbox)) {
            try self.sendResponse(tag, "NO", "[NONEXISTENT] Mailbox does not exist");
            return;
        }
        const canonical = canonicalMailboxName(mailbox);
        self.mailbox_name = try self.allocator.dupe(u8, canonical);
        self.mailbox_is_virtual = std.mem.eql(u8, canonical, "All Mail");
        const is_inbox = std.mem.eql(u8, canonical, "INBOX");
        const dir = if (self.mailbox_is_virtual)
            try std.fmt.allocPrint(self.allocator, "mail/{s}", .{username})
        else
            try std.fmt.allocPrint(self.allocator, "mail/{s}/{s}", .{ username, if (is_inbox) "new" else mailbox });
        self.mailbox_dir = dir;

        var count: usize = 0;
        var validity: i64 = 1;
        var uidnext: i64 = 1;
        {
            const db = self.auth_backend.db;
            db.lockMailboxes();
            defer db.unlockMailboxes();
            if (self.mailbox_is_virtual or is_inbox) {
                // INBOX aggregates new and cur. All Mail scans the account.
                try self.reloadGroupedMessagesLocked(username);
            } else {
                fs_compat.ensureDir(dir) catch {};
                _ = self.reloadFolderMessagesLocked(dir, false) catch false;
            }
            count = if (self.mailbox_files) |files| files.len else 0;
            uidnext = @as(i64, @intCast(count)) + 1;
            if (self.db) |uid_db| {
                if (uid_db.getOrCreateMailbox(username, canonical)) |info| {
                    validity = info.uidvalidity;
                    uidnext = info.uidnext;
                } else |_| {}
                self.mailbox_uidvalidity = validity;
            }
        }
        try self.sendSelectResponse(tag, count, validity, uidnext);
    }

    /// Send the mailbox snapshot captured before releasing the mutation lock.
    fn sendSelectResponse(self: *ImapSession, tag: []const u8, msg_count: usize, uidvalidity: i64, uidnext: i64) !void {
        const exists_msg = try std.fmt.allocPrint(self.allocator, "{d} EXISTS", .{msg_count});
        defer self.allocator.free(exists_msg);
        try self.sendUntagged(exists_msg);

        // This server uses \Seen and UNSEEN for unread state.
        try self.sendUntagged("0 RECENT");

        var first_unseen: usize = 0;
        if (self.mailbox_files) |mfiles| {
            for (mfiles, 0..) |fname, i| {
                const flags = MaildirFlags.fromFilename(fname);
                if (!flags.seen) {
                    first_unseen = i + 1;
                    break;
                }
            }
        }
        if (first_unseen > 0) {
            const unseen_msg = try std.fmt.allocPrint(self.allocator, "OK [UNSEEN {d}]", .{first_unseen});
            defer self.allocator.free(unseen_msg);
            try self.sendUntagged(unseen_msg);
        }

        const uidvalidity_msg = try std.fmt.allocPrint(self.allocator, "OK [UIDVALIDITY {d}]", .{uidvalidity});
        defer self.allocator.free(uidvalidity_msg);
        try self.sendUntagged(uidvalidity_msg);

        const uidnext_msg = try std.fmt.allocPrint(self.allocator, "OK [UIDNEXT {d}]", .{uidnext});
        defer self.allocator.free(uidnext_msg);
        try self.sendUntagged(uidnext_msg);

        try self.sendFlagCapabilities(true);

        self.state = .selected;
        try self.sendResponse(tag, "OK", if (self.mailbox_read_only) "[READ-ONLY] EXAMINE completed" else "[READ-WRITE] SELECT completed");
    }

    fn sendFlagCapabilities(self: *ImapSession, announce_flags: bool) !void {
        var scratch = std.heap.ArenaAllocator.init(self.allocator);
        defer scratch.deinit();
        const a = scratch.allocator();
        var names: maildir_keywords.Names = .{};
        var allow_new = false;
        if (!self.mailbox_is_virtual) {
            if (self.mailbox_dir) |dir| {
                if (maildir_keywords.Mapping.open(a, dir)) |mapping| {
                    names = mapping.names;
                    allow_new = names.hasCapacity();
                } else |err| {
                    if (err == error.FileNotFound) allow_new = true;
                }
            }
        }
        var out: std.Io.Writer.Allocating = .init(a);
        try out.writer.writeAll("\\Answered \\Flagged \\Deleted \\Seen \\Draft");
        try names.writeImap(&out.writer, names.defined(), true);
        const list = out.written();
        if (announce_flags) try self.sendUntagged(try std.fmt.allocPrint(a, "FLAGS ({s})", .{list}));
        const permanent = if (self.mailbox_read_only) "" else list;
        const wildcard = if (allow_new and !self.mailbox_read_only) " \\*" else "";
        try self.sendUntagged(try std.fmt.allocPrint(a, "OK [PERMANENTFLAGS ({s}{s})]", .{ permanent, wildcard }));
    }

    fn formatMessageFlags(self: *ImapSession, a: std.mem.Allocator, index: usize, flags: MaildirFlags, system: *[256]u8) ![]const u8 {
        const standard = flags.toImapString(system);
        if (flags.keywords == 0) return standard;
        const dir = self.selectedMessageDirForIndex(index) orelse return error.NoMailboxSelected;
        const mapping = try maildir_keywords.Mapping.open(a, dir);
        var out: std.Io.Writer.Allocating = .init(a);
        try out.writer.writeAll(standard);
        try mapping.names.writeImap(&out.writer, flags.keywords, standard.len != 0);
        return out.written();
    }

    /// Handle FETCH command
    fn handleFetch(self: *ImapSession, tag: []const u8, sequence_set: []const u8, items_raw: []const u8) !void {
        if (self.state != .selected) {
            try self.sendResponse(tag, "NO", "Must select mailbox first");
            return;
        }

        const files = self.mailbox_files orelse {
            try self.sendResponse(tag, "OK", "FETCH completed");
            return;
        };

        const want_internaldate = fetchHasAtom(items_raw, "INTERNALDATE");
        const want_rfc822_size = fetchHasAtom(items_raw, "RFC822.SIZE");
        const want_rfc822_header = fetchHasAtom(items_raw, "RFC822.HEADER");
        const want_rfc822_body = fetchHasAtom(items_raw, "RFC822") or fetchHasAtom(items_raw, "RFC822.TEXT");
        const want_bodystructure = fetchHasAtom(items_raw, "BODYSTRUCTURE");

        var sections: FetchSections = .{ .items = items_raw };
        var has_sections = false;
        var has_numbered = false;
        var marks_seen = want_rfc822_body;
        while (sections.next()) |section| {
            has_sections = true;
            has_numbered = has_numbered or section.numbered();
            marks_seen = marks_seen or !section.peek;
        }
        const should_set_seen = marks_seen and !self.mailbox_read_only;

        // Don't read the message file for a flags, UID or size-only request.
        const metadata_only = !has_sections and !want_rfc822_header and !want_rfc822_body and
            !want_bodystructure and !want_internaldate;

        var resolver = MaildirNameResolver.init(self.allocator);
        defer resolver.deinit();

        // The whole set: "1,3,5", "2:4,7", "*". Only "n" and "n:m" used to be
        // understood here, so a UID FETCH of a list answered with message 1.
        var iter = SequenceIterator.init(sequence_set, files.len);
        while (iter.next()) |seq_u32| {
            const seq: usize = seq_u32;
            // Flags are part of the name; another connection may have changed
            // them since this session listed the mailbox.
            const filename = self.adoptCurrentName(&resolver, seq - 1) orelse continue;
            const uid = self.getUidForSeq(seq);
            var flag_scratch = std.heap.ArenaAllocator.init(self.allocator);
            defer flag_scratch.deinit();

            // For metadata-only requests (FLAGS, UID, RFC822.SIZE), skip reading file content
            if (metadata_only) {
                const msg_flags = MaildirFlags.fromFilename(filename);
                var flag_str_buf: [256]u8 = undefined;
                const flag_str = try self.formatMessageFlags(flag_scratch.allocator(), seq - 1, msg_flags, &flag_str_buf);

                if (want_rfc822_size) {
                    const filepath = self.allocSelectedMessagePath(seq - 1, filename) catch continue;
                    defer self.allocator.free(filepath);
                    const file_size = fs_compat.getFileSize(filepath) catch 0;
                    const resp = try std.fmt.allocPrint(self.allocator, "* {d} FETCH (UID {d} FLAGS ({s}) RFC822.SIZE {d})", .{
                        seq, uid, flag_str, file_size,
                    });
                    defer self.allocator.free(resp);
                    try self.writeData(resp);
                } else {
                    const resp = try std.fmt.allocPrint(self.allocator, "* {d} FETCH (UID {d} FLAGS ({s}))", .{
                        seq, uid, flag_str,
                    });
                    defer self.allocator.free(resp);
                    try self.writeData(resp);
                }
                try self.writeData("\r\n");
                continue;
            }

            const filepath = self.allocSelectedMessagePath(seq - 1, filename) catch continue;
            defer self.allocator.free(filepath);

            const content = fs_compat.readFileAlloc(self.allocator, filepath) catch |err| {
                std.log.warn("Failed to read message {s}: {}", .{ filepath, err });
                continue;
            };
            defer self.allocator.free(content);

            // Find header/body boundary
            const header_end = headerEnd(content);

            const header = content[0..header_end];

            // Use the recorded internal date. Older messages keep their
            // existing timestamp or Date-header fallback.
            var date_buf: [64]u8 = undefined;
            const date_str = if (filenameInternalDate(filename)) |seconds|
                formatImapDate(seconds, &date_buf)
            else
                legacyInternalDate(header, &date_buf);

            const tree = if (want_bodystructure or has_numbered)
                try imap_mime.Tree.parse(flag_scratch.allocator(), content, header_end)
            else
                null;

            // Read actual flags from Maildir filename
            var msg_flags = MaildirFlags.fromFilename(filename);

            // RFC 3501: BODY[] (non-PEEK) implicitly sets \Seen. Report it only
            // once it is on disk.
            if (should_set_seen and !msg_flags.seen) {
                var seen_flags = msg_flags;
                seen_flags.seen = true;
                if (self.writeMessageFlags(seq - 1, filename, seen_flags)) msg_flags = seen_flags;
            }

            var flag_str_buf: [256]u8 = undefined;
            const flag_str = try self.formatMessageFlags(flag_scratch.allocator(), seq - 1, msg_flags, &flag_str_buf);

            var id_part_buf: [128]u8 = undefined;
            const id_part = if (want_internaldate) blk: {
                var ifbs = io_compat.fixedBufferStream(&id_part_buf);
                ifbs.writer().print(" INTERNALDATE \"{s}\"", .{date_str}) catch break :blk @as([]const u8, "");
                break :blk ifbs.getWritten();
            } else @as([]const u8, "");

            const a = flag_scratch.allocator();
            var reply: std.ArrayList([]const u8) = .empty;
            try reply.append(a, try std.fmt.allocPrint(a, "* {d} FETCH (UID {d} FLAGS ({s}) RFC822.SIZE {d}{s}", .{
                seq, uid, flag_str, content.len, id_part,
            }));
            if (want_bodystructure) {
                var structure: std.Io.Writer.Allocating = .init(a);
                try tree.?.writeStructure(a, &structure.writer);
                try reply.appendSlice(a, &.{ " BODYSTRUCTURE ", structure.written() });
            }
            if (want_rfc822_header) {
                const label = try std.fmt.allocPrint(a, " RFC822.HEADER {{{d}}}\r\n", .{header.len});
                try reply.appendSlice(a, &.{ label, header });
            }
            sections.cursor = 0;
            while (sections.next()) |section| try section.appendReply(a, &reply, content, header, tree);
            if (want_rfc822_body and !has_sections) {
                const legacy: FetchSections.Section = .{ .spec = "", .peek = false };
                try legacy.appendReply(a, &reply, content, header, null);
            }

            // Send the literal slices in order without copying attachments
            // into another message-sized buffer for each requested section.
            for (reply.items) |bytes| try self.writeData(bytes);
            try self.writeData(")\r\n");
        }

        try self.sendResponse(tag, "OK", "FETCH completed");
    }

    const SearchIdentity = struct {
        username: []const u8,
        mailbox: ?[]const u8,
    };

    /// Index-time mailbox name for the message at `idx` in the selected
    /// listing. For regular mailboxes that's the selected name; for
    /// virtual/aggregate mailboxes the per-message uid_key carries the real
    /// folder as a "{folder}/{base}" prefix (with new/ already mapped to
    /// INBOX by the loader).
    fn sourceMailboxForIndex(self: *ImapSession, idx: usize) []const u8 {
        if (self.mailbox_is_virtual) {
            if (self.mailbox_uid_keys) |keys| {
                if (idx < keys.len) {
                    if (std.mem.indexOfScalar(u8, keys[idx], '/')) |slash| {
                        return keys[idx][0..slash];
                    }
                }
            }
            return "INBOX";
        }
        const name = self.mailbox_name orelse return "INBOX";
        return if (std.ascii.eqlIgnoreCase(name, "INBOX")) "INBOX" else name;
    }

    /// Identity for search-index operations: the local-part username and
    /// the selected mailbox (null for virtual/aggregate mailboxes, which
    /// span folders and therefore search the whole account).
    fn searchIdentity(self: *ImapSession) ?SearchIdentity {
        const full_username = self.username orelse return null;
        const username = full_username;
        if (self.mailbox_is_virtual) return .{ .username = username, .mailbox = null };
        return .{ .username = username, .mailbox = self.mailbox_name orelse "INBOX" };
    }

    fn searchTextIndex(self: *ImapSession, term: search.Text) !?typesense.MessageIds {
        const ident = self.searchIdentity() orelse return null;
        const field = term.index_field orelse return null;
        if (term.term.len == 0) return null;
        return try typesense.searchMessageIds(self.allocator, ident.username, ident.mailbox, term.term, field);
    }

    const SearchMessage = struct {
        const KeywordMaps = std.StringHashMapUnmanaged(maildir_keywords.Names);

        session: *ImapSession,
        resolver: *MaildirNameResolver,
        keyword_maps: *KeywordMaps,
        query_allocator: std.mem.Allocator,
        allocator: std.mem.Allocator,
        seq: usize,
        uid: i64,
        max_seq: i64,
        max_uid: i64,
        terms: []const search.Text,
        indexed: []const ?typesense.MessageIds,
        index_id: ?typesense.MessageId = null,
        filename: ?[]const u8 = null,
        filepath: ?[]const u8 = null,
        content: ?[]const u8 = null,

        fn name(self: *SearchMessage) ![]const u8 {
            if (self.filename) |value| return value;
            const value = self.session.adoptCurrentName(self.resolver, self.seq - 1) orelse return error.FileNotFound;
            self.filename = value;
            return value;
        }

        fn path(self: *SearchMessage) ![]const u8 {
            if (self.filepath) |value| return value;
            const dir = self.session.selectedMessageDirForIndex(self.seq - 1) orelse return error.NoMailboxSelected;
            const value = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ dir, try self.name() });
            self.filepath = value;
            return value;
        }

        fn read(self: *SearchMessage) ![]const u8 {
            if (self.content) |value| return value;
            const value = try fs_compat.readFileAlloc(self.allocator, try self.path());
            self.content = value;
            return value;
        }

        fn hasKeyword(self: *SearchMessage, keyword: []const u8) !bool {
            const bits = MaildirFlags.fromFilename(try self.name()).keywords;
            if (bits == 0) return false;
            const dir = self.session.selectedMessageDirForIndex(self.seq - 1) orelse return error.NoMailboxSelected;
            const a = self.query_allocator;
            if (self.keyword_maps.getPtr(dir)) |names| {
                // A STORE from another connection may have introduced a letter
                // after this search cached the mapping.
                if (bits & ~names.defined() != 0)
                    names.* = (try maildir_keywords.Mapping.open(a, dir)).names;
                return bits & names.find(keyword) != 0;
            }
            const names = (try maildir_keywords.Mapping.open(a, dir)).names;
            try self.keyword_maps.put(a, dir, names);
            return bits & names.find(keyword) != 0;
        }

        fn matchesText(self: *SearchMessage, id: usize) !bool {
            if (self.indexed[id]) |hits| {
                if (self.index_id == null) {
                    const user = self.session.username orelse return error.NoMailboxSelected;
                    const mailbox = self.session.sourceMailboxForIndex(self.seq - 1);
                    const base = MaildirFlags.baseName(try self.name());
                    var message_id: typesense.MessageId = undefined;
                    _ = typesense.docId(&message_id, user, mailbox, base);
                    self.index_id = message_id;
                }
                return hits.contains(self.index_id.?);
            }

            const term = self.terms[id];
            const content = try self.read();
            return switch (term.field) {
                .message => ascii_compat.indexOfIgnoreCase(content, term.term) != null,
                .body => ascii_compat.indexOfIgnoreCase(content[headerEnd(content)..], term.term) != null,
                .header => (try searchHeader(self.allocator, content[0..headerEnd(content)], term.header, term.term)) != null,
            };
        }

        fn matchesDate(self: *SearchMessage, criterion: search.Date) !bool {
            var date_buf: [64]u8 = undefined;
            const formatted = if (criterion.sent) blk: {
                const content = try self.read();
                const raw = try searchHeader(self.allocator, content[0..headerEnd(content)], "Date", "") orelse return false;
                break :blk parseAndFormatRfc2822Date(raw, &date_buf) orelse return false;
            } else if (filenameInternalDate(try self.name())) |seconds|
                formatImapDate(seconds, &date_buf)
            else blk: {
                const content = try self.read();
                break :blk legacyInternalDate(content[0..headerEnd(content)], &date_buf);
            };
            const day = search.parseDay(formatted[0 .. std.mem.indexOfScalar(u8, formatted, ' ') orelse formatted.len]) orelse return false;
            return switch (criterion.relation) {
                .before => day < criterion.day,
                .on => day == criterion.day,
                .since => day >= criterion.day,
            };
        }

        pub fn matchesLeaf(self: *SearchMessage, predicate: search.Node) !bool {
            return switch (predicate) {
                .flag => |flag| blk: {
                    const flags = MaildirFlags.fromFilename(try self.name());
                    const set = switch (flag.name) {
                        .answered => flags.answered,
                        .deleted => flags.deleted,
                        .draft => flags.draft,
                        .flagged => flags.flagged,
                        .seen => flags.seen,
                    };
                    break :blk set == flag.required;
                },
                .keyword => |keyword| (try self.hasKeyword(keyword.name)) == keyword.required,
                .set => |set| if (set.uid) set.contains(self.uid, self.max_uid) else set.contains(@intCast(self.seq), self.max_seq),
                .text => |id| self.matchesText(id),
                .date => |criterion| self.matchesDate(criterion),
                .size => |size| blk: {
                    const bytes = try fs_compat.getFileSize(try self.path());
                    break :blk if (size.larger) bytes > size.bytes else bytes < size.bytes;
                },
                else => unreachable,
            };
        }
    };

    fn handleSearch(self: *ImapSession, tag: []const u8, criteria: []const u8) !void {
        return self.handleSearchImpl(tag, criteria, false);
    }

    fn handleUidSearch(self: *ImapSession, tag: []const u8, criteria: []const u8) !void {
        return self.handleSearchImpl(tag, criteria, true);
    }

    fn handleSearchImpl(self: *ImapSession, tag: []const u8, criteria: []const u8, is_uid: bool) !void {
        if (self.state != .selected) {
            try self.sendResponse(tag, "NO", "Must select mailbox first");
            return;
        }

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const query = search.parse(a, if (criteria.len == 0) "ALL" else criteria) catch |err| switch (err) {
            error.UnsupportedCharset => return self.sendResponse(tag, "NO", "[BADCHARSET (US-ASCII UTF-8)] Unsupported search charset"),
            error.UnsupportedSearchKey => return self.sendResponse(tag, "BAD", "Unsupported SEARCH key"),
            error.InvalidSearch => return self.sendResponse(tag, "BAD", "Invalid SEARCH criteria"),
            else => return err,
        };

        const count = if (self.mailbox_files) |files| files.len else 0;
        const identity = if (count > 0 and query.text.len > 0 and typesense.enabled()) self.searchIdentity() else null;
        const db = self.auth_backend.db;
        const epoch: ?i64 = if (identity) |ident| maildir_index.searchEpoch(db, ident.username, ident.mailbox) catch null else null;
        const indexed = try a.alloc(?typesense.MessageIds, query.text.len);
        for (query.text, indexed) |term, *hits| {
            hits.* = if (epoch != null) self.searchTextIndex(term) catch null else null;
        }
        defer {
            for (indexed) |*hits| {
                if (hits.*) |*set| set.deinit(self.allocator);
            }
        }
        if (epoch != null) {
            const ident = identity.?;
            const current = maildir_index.searchEpoch(db, ident.username, ident.mailbox) catch null;
            if (current != epoch) {
                for (indexed) |*hits| {
                    if (hits.*) |*set| set.deinit(self.allocator);
                    hits.* = null;
                }
            }
        }

        var max_uid: i64 = 0;
        if (self.mailbox_uids) |uids| {
            for (uids) |uid| max_uid = @max(max_uid, uid);
        } else {
            max_uid = @intCast(count);
        }

        var resolver = MaildirNameResolver.init(self.allocator);
        defer resolver.deinit();
        var keyword_maps: SearchMessage.KeywordMaps = .empty;
        var response = std.Io.Writer.Allocating.init(self.allocator);
        defer response.deinit();
        try response.writer.writeAll("SEARCH");

        for (0..count) |i| {
            var scratch = std.heap.ArenaAllocator.init(self.allocator);
            defer scratch.deinit();
            const seq = i + 1;
            var message = SearchMessage{
                .session = self,
                .resolver = &resolver,
                .keyword_maps = &keyword_maps,
                .query_allocator = a,
                .allocator = scratch.allocator(),
                .seq = seq,
                .uid = self.getUidForSeq(seq),
                .max_seq = @intCast(count),
                .max_uid = max_uid,
                .terms = query.text,
                .indexed = indexed,
            };
            const matches = query.root.matches(&message) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => {
                    std.log.warn("Could not evaluate IMAP SEARCH: {s}", .{@errorName(err)});
                    return self.sendResponse(tag, "NO", "[SERVERBUG] Could not search mailbox");
                },
            };
            if (matches) try response.writer.print(" {d}", .{if (is_uid) message.uid else @as(i64, @intCast(seq))});
        }

        try self.sendUntagged(response.written());
        try self.sendResponse(tag, "OK", "SEARCH completed");
    }

    /// Handle COPY command — copy messages to destination mailbox.
    /// Implements RFC 3501 Section 6.4.7.
    fn handleCopy(self: *ImapSession, tag: []const u8, sequence_set: []const u8, dest_mailbox: []const u8) !void {
        if (self.state != .selected) {
            try self.sendResponse(tag, "NO", "Must select mailbox first");
            return;
        }
        if (!isSafeMailboxName(dest_mailbox)) {
            try self.sendResponse(tag, "NO", "Invalid mailbox name");
            return;
        }

        const files = self.mailbox_files orelse {
            try self.sendResponse(tag, "NO", "Mailbox is empty");
            return;
        };
        const full_username = self.username orelse {
            try self.sendResponse(tag, "NO", "Not authenticated");
            return;
        };

        const local_part = full_username;

        const dest_name = stripQuotes(dest_mailbox);

        // Build destination directory path
        const dest_dir = if (std.ascii.eqlIgnoreCase(dest_name, "INBOX"))
            try std.fmt.allocPrint(self.allocator, "mail/{s}/new", .{local_part})
        else
            try std.fmt.allocPrint(self.allocator, "mail/{s}/{s}", .{ local_part, dest_name });
        defer self.allocator.free(dest_dir);

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var selected: std.ArrayList(usize) = .empty;
        var seen = std.AutoHashMap(usize, void).init(a);
        var iter = SequenceIterator.init(sequence_set, files.len);
        while (iter.next()) |seq| {
            const idx = seq - 1;
            if (!(try seen.getOrPut(idx)).found_existing) try selected.append(a, idx);
        }

        const copies = self.copyMessages(a, full_username, dest_name, dest_dir, selected.items) catch |err|
            return self.sendMaildirWriteError(tag, err);

        std.log.info("IMAP COPY: Copied {d} messages to {s}", .{ copies.len, dest_name });
        try self.sendResponse(tag, "OK", "COPY completed");
    }

    fn copyMessages(self: *ImapSession, a: std.mem.Allocator, user: []const u8, folder: []const u8, dir: []const u8, indexes: []const usize) ![][]const u8 {
        const db = self.auth_backend.db;
        db.lockMailboxes();
        defer db.unlockMailboxes();

        const cwd = fs_compat.cwd();
        const sources = try a.alloc([]const u8, indexes.len);
        const destinations = try a.alloc([]const u8, indexes.len);
        var total: u64 = 0;
        var names = MaildirNameResolver.init(self.allocator);
        defer names.deinit();
        for (indexes, sources) |idx, *path| {
            const filename = self.adoptCurrentName(&names, idx) orelse return error.FileNotFound;
            const source = try self.allocSelectedMessagePath(idx, filename);
            defer self.allocator.free(source);
            path.* = try a.dupe(u8, source);
            total = try std.math.add(u64, total, try fs_compat.getFileSize(source));
        }
        try hosted_limits.checkStorage(db, user, total, null);
        try cwd.makePath(dir);

        var published: usize = 0;
        errdefer for (destinations[0..published]) |path| {
            cwd.deleteFile(path) catch |err| std.log.err("IMAP COPY could not roll back {s}: {}", .{ path, err });
        };
        for (sources, destinations) |source, *destination| {
            const content = try fs_compat.readFileAlloc(self.allocator, source);
            defer self.allocator.free(content);
            var flags = MaildirFlags.fromFilename(std.fs.path.basename(source));
            flags.keywords = try maildir_keywords.transferredBits(a, std.fs.path.dirname(source).?, dir, flags.keywords);
            const internal_date = storedInternalDate(source);
            var suffix: [maildir_keywords.suffix_capacity]u8 = undefined;
            const path = try self.allocUniqueMaildirPath(dir, flags.toSuffix(&suffix), internal_date);
            defer self.allocator.free(path);
            destination.* = try a.dupe(u8, path);
            try maildir_index.markLocked(db, user, false, &.{message_refs.location(folder, std.fs.path.basename(path))});
            try durable_maildir.writeWithMtime(self.allocator, path, content, internal_date);
            published += 1;
        }
        return destinations;
    }

    /// Handle MOVE command (RFC 6851) — move messages to destination mailbox.
    /// Atomically copies to destination and removes from source.
    fn handleMove(self: *ImapSession, tag: []const u8, sequence_set: []const u8, dest_mailbox: []const u8) !void {
        if (self.state != .selected) {
            try self.sendResponse(tag, "NO", "Must select mailbox first");
            return;
        }
        if (!isSafeMailboxName(dest_mailbox)) {
            try self.sendResponse(tag, "NO", "Invalid mailbox name");
            return;
        }

        const files = self.mailbox_files orelse {
            try self.sendResponse(tag, "NO", "Mailbox is empty");
            return;
        };
        const full_username = self.username orelse {
            try self.sendResponse(tag, "NO", "Not authenticated");
            return;
        };

        const local_part = full_username;

        const dest_name = stripQuotes(dest_mailbox);

        const dest_dir = if (std.ascii.eqlIgnoreCase(dest_name, "INBOX"))
            try std.fmt.allocPrint(self.allocator, "mail/{s}/new", .{local_part})
        else
            try std.fmt.allocPrint(self.allocator, "mail/{s}/{s}", .{ local_part, dest_name });
        defer self.allocator.free(dest_dir);

        fs_compat.ensureDir(dest_dir) catch {};

        // Collect sequence numbers to move, then process in reverse for correct EXPUNGE numbering
        var to_move: std.ArrayList(u32) = .empty;
        defer to_move.deinit(self.allocator);

        var iter = SequenceIterator.init(sequence_set, files.len);
        while (iter.next()) |seq| {
            if (seq >= 1 and seq <= files.len) {
                to_move.append(self.allocator, seq) catch continue;
            }
        }

        // Sort descending for EXPUNGE responses
        std.mem.sort(u32, to_move.items, {}, struct {
            fn desc(_: void, a: u32, b: u32) bool {
                return a > b;
            }
        }.desc);

        var names = MaildirNameResolver.init(self.allocator);
        defer names.deinit();
        var failed = false;
        for (to_move.items) |seq| {
            const idx = seq - 1;
            var scratch = std.heap.ArenaAllocator.init(self.allocator);
            defer scratch.deinit();
            self.moveMessageOnDisk(scratch.allocator(), &names, idx, local_part, dest_name, dest_dir) catch {
                failed = true;
                continue;
            };

            // Send EXPUNGE notification
            var resp_buf: [32]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&resp_buf);
            fbs.writer().print("{d} EXPUNGE", .{seq}) catch continue;
            self.sendUntagged(fbs.getWritten()) catch continue;
        }

        // Refresh mailbox
        _ = self.rescanMailbox() catch {};

        if (failed) return self.sendResponse(tag, "NO", "MOVE failed for some messages");
        try self.sendResponse(tag, "OK", "MOVE completed");
    }

    fn moveMessageOnDisk(self: *ImapSession, a: std.mem.Allocator, names: *MaildirNameResolver, idx: usize, user: []const u8, folder: []const u8, dir: []const u8) !void {
        const db = self.auth_backend.db;
        db.lockMailboxes();
        defer db.unlockMailboxes();
        const name = self.adoptCurrentName(names, idx) orelse return error.FileNotFound;
        const source_path = try self.allocSelectedMessagePath(idx, name);
        defer self.allocator.free(source_path);
        var suffix: [maildir_keywords.suffix_capacity]u8 = undefined;
        const internal_date = storedInternalDate(name);
        var flags = MaildirFlags.fromFilename(name);
        flags.keywords = try maildir_keywords.transferredBits(a, std.fs.path.dirname(source_path).?, dir, flags.keywords);
        const destination_path = try self.allocUniqueMaildirPath(dir, flags.toSuffix(&suffix), internal_date);
        defer self.allocator.free(destination_path);
        const raw = try fs_compat.readFileAlloc(a, source_path);
        const source = message_refs.location(self.sourceMailboxForIndex(idx), name);
        const target = message_refs.location(folder, std.fs.path.basename(destination_path));
        const transfer = try message_refs.stage(a, db, user, source, source_path, target, raw);
        errdefer if (transfer) |id| message_refs.cancel(db, user, id);
        try maildir_index.markLocked(db, user, false, &.{ source, target });
        if (!renameFile(source_path, destination_path)) {
            try durable_maildir.writeWithMtime(self.allocator, destination_path, raw, internal_date);
            errdefer fs_compat.cwd().deleteFile(destination_path) catch {};
            try fs_compat.cwd().deleteFile(source_path);
        }
        if (transfer) |id| message_refs.finishFile(a, db, user, id, target, destination_path);
        message_refs.forgetReviewCopy(db, user, source) catch |err| std.log.warn("could not retire an IMAP-moved review copy: {}", .{err});
    }

    /// Handle EXAMINE command — same as SELECT but read-only.
    /// Implements RFC 3501 Section 6.3.2.
    fn handleExamine(self: *ImapSession, tag: []const u8, mailbox_name: []const u8) !void {
        self.mailbox_read_only = true;
        try self.handleSelect(tag, mailbox_name);
    }

    /// Handle DELETE command — remove a mailbox.
    /// Implements RFC 3501 Section 6.3.4.
    fn handleDelete(self: *ImapSession, tag: []const u8, mailbox_name: []const u8) !void {
        if (self.state == .not_authenticated) {
            try self.sendResponse(tag, "NO", "Must authenticate first");
            return;
        }
        if (!isSafeMailboxName(mailbox_name)) {
            try self.sendResponse(tag, "NO", "Invalid mailbox name");
            return;
        }

        const full_username = self.username orelse {
            try self.sendResponse(tag, "NO", "Not authenticated");
            return;
        };
        const local_part = full_username;

        const name = stripQuotes(mailbox_name);

        // Cannot delete INBOX
        if (std.ascii.eqlIgnoreCase(name, "INBOX")) {
            try self.sendResponse(tag, "NO", "Cannot delete INBOX");
            return;
        }

        const db = self.auth_backend.db;
        db.lockMailboxes();
        defer db.unlockMailboxes();
        if ((try db.enabledMailboxId(full_username)) == null) return self.sendResponse(tag, "NO", "Mailbox is disabled");
        const dir_path = try std.fmt.allocPrint(self.allocator, "mail/{s}/{s}", .{ local_part, name });
        defer self.allocator.free(dir_path);

        // Delete all files in the directory, then the directory itself
        const eml_files = fs_compat.listEmlFiles(self.allocator, dir_path) catch {
            // Directory doesn't exist — try rmdir anyway
            var buf: [4097]u8 = undefined;
            const written = std.fmt.bufPrint(&buf, "{s}", .{dir_path}) catch {
                try self.sendResponse(tag, "NO", "DELETE failed");
                return;
            };
            buf[written.len] = 0;
            _ = std.c.rmdir(@ptrCast(&buf));
            try self.sendResponse(tag, "OK", "DELETE completed");
            return;
        };
        defer {
            for (eml_files) |f| self.allocator.free(f);
            self.allocator.free(eml_files);
        }

        for (eml_files) |f| {
            var path_buf: [4097]u8 = undefined;
            const written = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ dir_path, f }) catch continue;
            path_buf[written.len] = 0;
            _ = std.c.unlink(@ptrCast(&path_buf));
        }

        if (pathIsSymlink(dir_path)) {
            var visible_buf: [4097]u8 = undefined;
            const visible = std.fmt.bufPrint(&visible_buf, "{s}", .{dir_path}) catch {
                try self.sendResponse(tag, "NO", "DELETE failed");
                return;
            };
            visible_buf[visible.len] = 0;
            _ = std.c.unlink(@ptrCast(&visible_buf));

            const canonical = try std.fmt.allocPrint(self.allocator, "mail/{s}/.{s}", .{ local_part, name });
            defer self.allocator.free(canonical);
            for ([_][]const u8{ "tmp", "new", "cur" }) |component| {
                const child = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ canonical, component });
                defer self.allocator.free(child);
                const child_files = fs_compat.listEmlFiles(self.allocator, child) catch &.{};
                defer {
                    for (child_files) |file_name| self.allocator.free(file_name);
                    if (child_files.len > 0) self.allocator.free(child_files);
                }
                for (child_files) |file_name| {
                    var child_file_buf: [4097]u8 = undefined;
                    const child_file = std.fmt.bufPrint(&child_file_buf, "{s}/{s}", .{ child, file_name }) catch continue;
                    child_file_buf[child_file.len] = 0;
                    _ = std.c.unlink(@ptrCast(&child_file_buf));
                }
                var child_buf: [4097]u8 = undefined;
                const child_path = std.fmt.bufPrint(&child_buf, "{s}", .{child}) catch continue;
                child_buf[child_path.len] = 0;
                _ = std.c.rmdir(@ptrCast(&child_buf));
            }
            const mapping_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ canonical, maildir_keywords.mapping_name });
            defer self.allocator.free(mapping_path);
            fs_compat.cwd().deleteFile(mapping_path) catch {};
            var canonical_buf: [4097]u8 = undefined;
            const canonical_path = std.fmt.bufPrint(&canonical_buf, "{s}", .{canonical}) catch {
                try self.sendResponse(tag, "NO", "DELETE failed");
                return;
            };
            canonical_buf[canonical_path.len] = 0;
            if (std.c.rmdir(@ptrCast(&canonical_buf)) != 0) {
                try self.sendResponse(tag, "NO", "DELETE failed");
                return;
            }
            std.log.info("IMAP DELETE: Removed Maildir++ mailbox {s}", .{name});
            try self.sendResponse(tag, "OK", "DELETE completed");
            return;
        }

        const mapping_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ dir_path, maildir_keywords.mapping_name });
        defer self.allocator.free(mapping_path);
        fs_compat.cwd().deleteFile(mapping_path) catch {};
        var dir_buf: [4097]u8 = undefined;
        const dir_written = std.fmt.bufPrint(&dir_buf, "{s}", .{dir_path}) catch {
            try self.sendResponse(tag, "OK", "DELETE completed");
            return;
        };
        dir_buf[dir_written.len] = 0;
        _ = std.c.rmdir(@ptrCast(&dir_buf));

        std.log.info("IMAP DELETE: Removed mailbox {s}", .{name});
        try self.sendResponse(tag, "OK", "DELETE completed");
    }

    /// Handle RENAME command — rename a mailbox.
    /// Implements RFC 3501 Section 6.3.5.
    fn handleRename(self: *ImapSession, tag: []const u8, old_name: []const u8, new_name: []const u8) !void {
        if (self.state == .not_authenticated) {
            try self.sendResponse(tag, "NO", "Must authenticate first");
            return;
        }
        if (!isSafeMailboxName(old_name) or !isSafeMailboxName(new_name)) {
            try self.sendResponse(tag, "NO", "Invalid mailbox name");
            return;
        }

        const full_username = self.username orelse {
            try self.sendResponse(tag, "NO", "Not authenticated");
            return;
        };
        const old = stripQuotes(old_name);
        const new = stripQuotes(new_name);

        for ([_][]const u8{ "INBOX", "new", "cur", "tmp" }) |reserved| {
            if (std.ascii.eqlIgnoreCase(old, reserved) or std.ascii.eqlIgnoreCase(new, reserved))
                return self.sendResponse(tag, "NO", "Cannot rename INBOX or its Maildir slots");
        }

        self.renameMailboxOnDisk(full_username, old, new) catch |err| return switch (err) {
            error.FileNotFound => self.sendResponse(tag, "NO", "[NONEXISTENT] Mailbox does not exist"),
            error.PathAlreadyExists => self.sendResponse(tag, "NO", "[ALREADYEXISTS] Destination mailbox exists"),
            else => self.sendMaildirWriteError(tag, err),
        };
        std.log.info("IMAP RENAME: {s} -> {s}", .{ old, new });
        try self.sendResponse(tag, "OK", "RENAME completed");
    }

    fn renameMailboxOnDisk(self: *ImapSession, user: []const u8, old: []const u8, new: []const u8) !void {
        const db = self.auth_backend.db;
        db.lockMailboxes();
        defer db.unlockMailboxes();
        if ((try db.enabledMailboxId(user)) == null) return error.HostedRecipientDisabled;
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const io = io_compat.getIo();
        const base = try std.fmt.allocPrint(a, "mail/{s}", .{user});
        const root = (try maildir_folders.open(io, .cwd(), base)) orelse return error.FileNotFound;
        defer root.close(io);
        const source = try maildir_folders.storedName(a, io, root, old);
        var edit = try folder_edits.Edit.init(a, root, user, source, new);
        if (std.mem.eql(u8, source, new)) return;
        try edit.stage(a, db, root, user);
        defer edit.finish(a, db, root);
        var tx = try db.beginTransaction(.write);
        defer tx.deinit();
        try edit.applyMetadata(tx, user);
        try tx.commit();
        edit.committed = true;
    }

    /// Handle STORE command — set/add/remove message flags.
    /// Persists flags by renaming files with Maildir-style `:2,FLAGS` suffix.
    /// Implements RFC 3501 Section 6.4.6.
    ///
    /// Only flags that reached the disk are reported. A message whose file
    /// could not be renamed gets an untagged FETCH with the flags it still
    /// has — even under .SILENT, since the client now holds the wrong ones —
    /// and the command ends NO. Reporting the requested flags regardless used
    /// to leave a client showing a message as read that the server still
    /// counted as unread.
    fn handleStore(self: *ImapSession, tag: []const u8, sequence_set: []const u8, flags_action: []const u8) !void {
        if (self.state != .selected) {
            try self.sendResponse(tag, "NO", "Must select mailbox first");
            return;
        }
        if (self.mailbox_read_only) return self.sendResponse(tag, "NO", "[READ-ONLY] Cannot change flags");

        const action = StoreFlags.parse(flags_action) catch |err| switch (err) {
            error.KeywordLimit => return self.sendMaildirWriteError(tag, err),
            else => return self.sendResponse(tag, "BAD", "Invalid STORE flags"),
        };
        if (self.mailbox_is_virtual and action.flags.keyword_count != 0)
            return self.sendResponse(tag, "NO", "[CANNOT] Set keywords in the message's own folder");

        const files = self.mailbox_files orelse {
            try self.sendResponse(tag, "OK", "STORE completed");
            return;
        };

        var resolver = MaildirNameResolver.init(self.allocator);
        defer resolver.deinit();
        var failed = false;
        var limit_reached = false;

        var iter = SequenceIterator.init(sequence_set, files.len);
        while (iter.next()) |seq| {
            if (seq < 1 or seq > files.len) continue;
            const idx = seq - 1;

            // Start from the flags on disk, not the ones cached at SELECT:
            // another connection may have changed them since.
            var scratch = std.heap.ArenaAllocator.init(self.allocator);
            defer scratch.deinit();
            const a = scratch.allocator();
            var stored = false;
            const flags = blk: {
                const db = self.auth_backend.db;
                db.lockMailboxes();
                defer db.unlockMailboxes();
                const filename = self.adoptCurrentName(&resolver, idx) orelse {
                    failed = true;
                    continue;
                };
                const before = MaildirFlags.fromFilename(filename);
                var requested = action.flags.system;
                if (action.flags.keyword_count != 0) {
                    const dir = self.selectedMessageDirForIndex(idx) orelse break :blk before;
                    var mapping = maildir_keywords.Mapping.open(a, dir) catch break :blk before;
                    requested = action.flags.resolve(&mapping.names, action.mode) catch |err| {
                        limit_reached = limit_reached or err == error.KeywordLimit;
                        break :blk before;
                    };
                    mapping.save(a) catch break :blk before;
                    limit_reached = limit_reached or !mapping.names.hasCapacity();
                }
                const next = before.applyStoreFlags(requested, action.mode);
                stored = self.writeMessageFlagsLocked(idx, filename, next);
                break :blk if (stored) next else before;
            };
            if (!stored) failed = true;
            if (action.silent and stored) continue;

            // Always include UID: a UID STORE (which Apple Mail uses to mark
            // read/unread) requires the UID in the FETCH response so the client
            // can correlate the flag change to its UID-keyed message and update
            // its unread count. Without it the badge never reflects the change.
            var flag_str_buf: [256]u8 = undefined;
            const flag_str = try self.formatMessageFlags(a, idx, flags, &flag_str_buf);
            const uid = self.getUidForSeq(seq);
            try self.sendUntagged(try std.fmt.allocPrint(a, "{d} FETCH (UID {d} FLAGS ({s}))", .{ seq, uid, flag_str }));
        }

        if (limit_reached) {
            try self.sendFlagCapabilities(false);
            if (failed) return self.sendMaildirWriteError(tag, error.KeywordLimit);
        }
        if (failed) {
            try self.sendResponse(tag, "NO", "STORE failed for some messages; their current flags were sent");
        } else {
            try self.sendResponse(tag, "OK", "STORE completed");
        }
    }

    /// Handle EXPUNGE command — remove messages marked with \Deleted flag.
    /// Reads \Deleted from Maildir filename suffix. Sends untagged EXPUNGE
    /// responses in descending order per RFC 3501 Section 6.4.3.
    fn handleExpunge(self: *ImapSession, tag: []const u8, uid_set: ?[]const u8) !void {
        if (self.state != .selected) {
            try self.sendResponse(tag, "NO", "Must select mailbox first");
            return;
        }
        if (self.mailbox_read_only) return self.sendResponse(tag, "NO", "Mailbox is read-only");

        var scratch = std.heap.ArenaAllocator.init(self.allocator);
        defer scratch.deinit();
        const selection = if (uid_set) |raw|
            search.parseSet(scratch.allocator(), raw, true) catch |err| switch (err) {
                error.InvalidSearch => return self.sendResponse(tag, "BAD", "Invalid UID set"),
                else => return err,
            }
        else
            null;
        const completed = if (uid_set == null) "EXPUNGE completed" else "UID EXPUNGE completed";

        const files = self.mailbox_files orelse {
            try self.sendResponse(tag, "OK", completed);
            return;
        };
        if (files.len == 0) return self.sendResponse(tag, "OK", completed);
        const uids: []const i64 = if (selection == null) &.{} else self.mailbox_uids orelse return self.sendResponse(tag, "NO", "Mailbox UIDs unavailable");
        if (selection != null and uids.len != files.len)
            return self.sendResponse(tag, "NO", "Mailbox UIDs unavailable");
        const max_uid = if (uids.len > 0) std.mem.max(i64, uids) else 0;

        var names = MaildirNameResolver.init(self.allocator);
        defer names.deinit();
        var seq = files.len;
        while (seq > 0) : (seq -= 1) {
            if (selection) |set| {
                if (!set.contains(uids[seq - 1], max_uid)) continue;
            }
            const filename = self.expungeDeleted(&names, seq - 1) orelse continue;

            // Send untagged EXPUNGE
            var resp_buf: [32]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&resp_buf);
            fbs.writer().print("{d} EXPUNGE", .{seq}) catch continue;
            self.sendUntagged(fbs.getWritten()) catch continue;

            std.log.info("IMAP EXPUNGE: Deleted {s}", .{filename});
        }

        // Refresh mailbox file list after deletions
        _ = self.rescanMailbox() catch {};

        try self.sendResponse(tag, "OK", completed);
    }

    fn expungeDeleted(self: *ImapSession, names: *MaildirNameResolver, idx: usize) ?[]const u8 {
        const user = self.username orelse return null;
        const db = self.auth_backend.db;
        db.lockMailboxes();
        defer db.unlockMailboxes();
        const filename = self.adoptCurrentName(names, idx) orelse return null;
        if (!MaildirFlags.fromFilename(filename).deleted) return null;
        const path = self.allocSelectedMessagePath(idx, filename) catch return null;
        defer self.allocator.free(path);
        const at = message_refs.location(self.sourceMailboxForIndex(idx), filename);
        maildir_index.markLocked(db, user, false, &.{at}) catch |err| {
            std.log.warn("could not queue expunged mail for search: {}", .{err});
            return null;
        };
        var scratch = std.heap.ArenaAllocator.init(self.allocator);
        defer scratch.deinit();
        draft_expunge.remove(scratch.allocator(), db, user, at, path) catch |err| {
            std.log.warn("could not expunge mail: {}", .{err});
            return null;
        };
        message_refs.forget(db, user, at) catch |err| std.log.warn("could not retire expunged message reference: {}", .{err});
        return filename;
    }

    /// Handle LOGOUT command
    fn handleLogout(self: *ImapSession, tag: []const u8) !void {
        try self.sendUntagged("BYE IMAP4rev1 Server logging out");
        try self.sendResponse(tag, "OK", "LOGOUT completed");
        self.state = .logout;
    }

    /// Process a single command
    pub fn processCommand(self: *ImapSession, line: []const u8) !void {
        if (!try self.checkClientPassword()) return;
        const hosted = if (self.username) |user| try self.auth_backend.db.hostedLimits(user) else null;
        const access = if (hosted) |limits| limits.accessAt(time_compat.timestamp()) else .full;
        if (!access.readable()) {
            try self.sendUntagged("BYE Mailbox is unavailable");
            self.state = .logout;
            return;
        }
        const hosted_read_only = access == .read_only;
        if (hosted_read_only) self.mailbox_read_only = true;

        // Handle DONE (ends IDLE mode) - DONE has no tag
        if (self.idle_mode) {
            const trimmed = std.mem.trim(u8, line, " \t\r\n");
            if (std.ascii.eqlIgnoreCase(trimmed, "DONE")) {
                self.idle_mode = false;
                self.closeIdleWatch();
                // Rescan mailbox for new messages before ending IDLE
                if (self.state == .selected) {
                    _ = self.rescanMailbox() catch {};
                }
                if (self.idle_tag) |saved_tag| {
                    try self.sendResponse(saved_tag, "OK", "IDLE terminated");
                    self.allocator.free(saved_tag);
                    self.idle_tag = null;
                } else {
                    try self.sendResponse("*", "OK", "IDLE terminated");
                }
                return;
            }
        }

        // Parse command: TAG COMMAND [ARGS...]
        var parts = std.mem.splitScalar(u8, line, ' ');

        const tag = parts.next() orelse {
            try self.sendResponse("*", "BAD", "Missing tag");
            return;
        };

        const cmd_str = parts.next() orelse {
            try self.sendResponse(tag, "BAD", "Missing command");
            return;
        };

        const command = ImapCommand.fromString(cmd_str) orelse {
            try self.sendResponse(tag, "BAD", "Unknown command");
            return;
        };
        if (hosted_read_only) {
            switch (command) {
                .create, .delete, .rename, .subscribe, .unsubscribe, .append, .expunge, .store, .copy, .move => return self.sendResponse(tag, "NO", "[READ-ONLY] Mailbox is available for export"),
                .uid => {
                    var args = parts;
                    const sub = args.next() orelse "";
                    if (!std.ascii.eqlIgnoreCase(sub, "FETCH") and !std.ascii.eqlIgnoreCase(sub, "SEARCH"))
                        return self.sendResponse(tag, "NO", "[READ-ONLY] Mailbox is available for export");
                },
                else => {},
            }
        }

        // Log only the command verb, never arguments. LOGIN and AUTHENTICATE
        // arguments can contain clear or base64-encoded credentials; SEARCH
        // and other commands can contain private message data.
        std.log.debug("IMAP command: {s}", .{cmd_str});

        // Handle command
        switch (command) {
            .capability => try self.handleCapability(tag),
            .noop => {
                // RFC 3501: NOOP - check for new messages in selected mailbox
                if (self.state == .selected) {
                    _ = self.rescanMailbox() catch {};
                }
                try self.sendResponse(tag, "OK", "NOOP completed");
            },
            .logout => try self.handleLogout(tag),
            .starttls => {
                // RFC 3501 Section 6.2.1 - STARTTLS
                if (self.tls_connection != null) {
                    try self.sendResponse(tag, "BAD", "TLS already active");
                } else {
                    try self.sendResponse(tag, "OK", "Begin TLS negotiation now");
                    self.starttls_requested = true;
                }
            },
            .authenticate => {
                const mechanism = parts.next() orelse "";
                // Check for initial response on the same line (RFC 4959)
                const initial_response = parts.next();
                try self.handleAuthenticate(tag, mechanism, initial_response);
            },
            .login => {
                const raw_username = parts.next() orelse "";
                // Password may contain spaces if quoted, so join remaining parts
                const raw_password = if (parts.next()) |first_part| blk: {
                    // If it starts with a quote, collect until closing quote
                    if (first_part.len > 0 and first_part[0] == '"') {
                        if (first_part.len > 1 and first_part[first_part.len - 1] == '"') {
                            // Entire password in one token: "password"
                            break :blk first_part;
                        }
                        // Password spans multiple tokens due to spaces
                        var end_idx = @intFromPtr(first_part.ptr) + first_part.len - @intFromPtr(line.ptr);
                        while (parts.next()) |part| {
                            end_idx = @intFromPtr(part.ptr) + part.len - @intFromPtr(line.ptr);
                            if (part.len > 0 and part[part.len - 1] == '"') break;
                        }
                        const start_idx = @intFromPtr(first_part.ptr) - @intFromPtr(line.ptr);
                        break :blk line[start_idx..end_idx];
                    }
                    break :blk first_part;
                } else "";
                // Strip surrounding double quotes from username and password (IMAP clients quote these)
                const username = stripQuotes(raw_username);
                const password = stripQuotes(raw_password);
                try self.handleLogin(tag, username, password);
            },
            .select => {
                self.mailbox_read_only = hosted_read_only;
                const cmd_end = @intFromPtr(cmd_str.ptr) + cmd_str.len - @intFromPtr(line.ptr);
                const rest = if (cmd_end < line.len) line[cmd_end..] else "";
                const mailbox = if (parseImapArg(rest)) |arg| arg.value else "INBOX";
                try self.handleSelect(tag, mailbox);
            },
            .list, .xlist => {
                const cmd_end = @intFromPtr(cmd_str.ptr) + cmd_str.len - @intFromPtr(line.ptr);
                const rest = if (cmd_end < line.len) line[cmd_end..] else "";
                const reference_arg = parseImapArg(rest);
                const reference = if (reference_arg) |arg| arg.value else "";
                const pattern = if (reference_arg) |arg|
                    if (parseImapArg(arg.rest)) |pattern_arg| pattern_arg.value else "*"
                else
                    "*";
                if (command == .xlist) {
                    try self.handleXList(tag, reference, pattern);
                } else {
                    try self.handleList(tag, reference, pattern);
                }
            },
            .lsub => {
                const cmd_end = @intFromPtr(cmd_str.ptr) + cmd_str.len - @intFromPtr(line.ptr);
                const rest = if (cmd_end < line.len) line[cmd_end..] else "";
                const reference_arg = parseImapArg(rest);
                const reference = if (reference_arg) |arg| arg.value else "";
                const pattern = if (reference_arg) |arg|
                    if (parseImapArg(arg.rest)) |pattern_arg| pattern_arg.value else "*"
                else
                    "*";
                try self.handleList(tag, reference, pattern);
            },
            .status => {
                const cmd_end = @intFromPtr(cmd_str.ptr) + cmd_str.len - @intFromPtr(line.ptr);
                const rest = if (cmd_end < line.len) line[cmd_end..] else "";
                const mailbox_arg = parseImapArg(rest) orelse ParsedImapArg{ .value = "INBOX", .rest = "" };
                const status_items = std.mem.trim(u8, mailbox_arg.rest, " \t");
                try self.handleStatus(tag, mailbox_arg.value, status_items);
            },
            .fetch => {
                const sequence_set = parts.next() orelse "1:*";
                // Items may contain spaces (e.g. "(FLAGS UID BODY.PEEK[HEADER])"), get rest of line
                const seq_end = @intFromPtr(sequence_set.ptr) + sequence_set.len - @intFromPtr(line.ptr);
                const items = if (seq_end < line.len) std.mem.trim(u8, line[seq_end..], " \t") else "FLAGS";
                try self.handleFetch(tag, sequence_set, if (items.len > 0) items else "FLAGS");
            },
            .search => {
                // Collect rest of line as search criteria
                const cmd_end_s = @intFromPtr(cmd_str.ptr) + cmd_str.len - @intFromPtr(line.ptr);
                const search_criteria = if (cmd_end_s < line.len) std.mem.trim(u8, line[cmd_end_s..], " \t") else "";
                try self.handleSearch(tag, search_criteria);
            },
            .expunge => try self.handleExpunge(tag, null),
            .close => {
                // RFC 3501 Section 6.4.2: CLOSE implicitly expunges \Deleted messages
                // (without sending untagged EXPUNGE responses)
                if (!self.mailbox_read_only) if (self.mailbox_files) |files| {
                    var names = MaildirNameResolver.init(self.allocator);
                    defer names.deinit();
                    for (0..files.len) |i| _ = self.expungeDeleted(&names, i);
                };
                self.freeMailboxFiles();
                self.state = .authenticated;
                try self.sendResponse(tag, "OK", "CLOSE completed");
            },
            .namespace => {
                // RFC 2342: NAMESPACE - return personal, other users, shared
                try self.sendUntagged("NAMESPACE ((\"\" \"/\")) NIL NIL");
                try self.sendResponse(tag, "OK", "NAMESPACE completed");
            },
            .idle => {
                // RFC 2177: IDLE - enter idle mode and wait for DONE
                self.idle_mode = true;
                // Save the tag so we can respond when DONE arrives
                if (self.idle_tag) |old_tag| {
                    self.allocator.free(old_tag);
                }
                self.idle_tag = self.allocator.dupe(u8, tag) catch null;
                try self.writeData("+ idling\r\n");
            },
            .uid => {
                // UID command - translate UID sets to sequence numbers, then dispatch
                const sub_cmd = parts.next() orelse "";
                if (std.ascii.eqlIgnoreCase(sub_cmd, "FETCH")) {
                    const uid_set_str = parts.next() orelse "1:*";
                    // Items may contain spaces (e.g. "(FLAGS UID BODY.PEEK[HEADER])"), get rest of line
                    const seq_end = @intFromPtr(uid_set_str.ptr) + uid_set_str.len - @intFromPtr(line.ptr);
                    const items = if (seq_end < line.len) std.mem.trim(u8, line[seq_end..], " \t") else "FLAGS";
                    // Translate UID set to sequence set
                    const seq_set = self.uidSetToSeqSet(uid_set_str) catch uid_set_str;
                    defer if (seq_set.ptr != uid_set_str.ptr) self.allocator.free(seq_set);
                    try self.handleFetch(tag, seq_set, if (items.len > 0) items else "FLAGS");
                } else if (std.ascii.eqlIgnoreCase(sub_cmd, "SEARCH")) {
                    // Collect rest of line after "UID SEARCH" as criteria
                    const sub_end = @intFromPtr(sub_cmd.ptr) + sub_cmd.len - @intFromPtr(line.ptr);
                    const uid_search_criteria = if (sub_end < line.len) std.mem.trim(u8, line[sub_end..], " \t") else "";
                    try self.handleUidSearch(tag, uid_search_criteria);
                } else if (std.ascii.eqlIgnoreCase(sub_cmd, "MOVE")) {
                    const uid_set = parts.next() orelse "1:*";
                    const uid_end = @intFromPtr(uid_set.ptr) + uid_set.len - @intFromPtr(line.ptr);
                    const rest = if (uid_end < line.len) line[uid_end..] else "";
                    const dest_arg = parseImapArg(rest) orelse ParsedImapArg{ .value = "INBOX", .rest = "" };
                    const dest = dest_arg.value;
                    const seq_set = self.uidSetToSeqSet(uid_set) catch uid_set;
                    defer if (seq_set.ptr != uid_set.ptr) self.allocator.free(seq_set);
                    try self.handleMove(tag, seq_set, dest);
                } else if (std.ascii.eqlIgnoreCase(sub_cmd, "COPY")) {
                    const uid_set = parts.next() orelse "1:*";
                    const uid_end = @intFromPtr(uid_set.ptr) + uid_set.len - @intFromPtr(line.ptr);
                    const rest = if (uid_end < line.len) line[uid_end..] else "";
                    const dest_arg = parseImapArg(rest) orelse ParsedImapArg{ .value = "INBOX", .rest = "" };
                    const dest = dest_arg.value;
                    const seq_set = self.uidSetToSeqSet(uid_set) catch uid_set;
                    defer if (seq_set.ptr != uid_set.ptr) self.allocator.free(seq_set);
                    try self.handleCopy(tag, seq_set, dest);
                } else if (std.ascii.eqlIgnoreCase(sub_cmd, "STORE")) {
                    const uid_set = parts.next() orelse "1:*";
                    const uid_end = @intFromPtr(uid_set.ptr) + uid_set.len - @intFromPtr(line.ptr);
                    const flags_action = if (uid_end < line.len) std.mem.trim(u8, line[uid_end..], " \t") else "";
                    const seq_set = self.uidSetToSeqSet(uid_set) catch uid_set;
                    defer if (seq_set.ptr != uid_set.ptr) self.allocator.free(seq_set);
                    try self.handleStore(tag, seq_set, flags_action);
                } else if (std.ascii.eqlIgnoreCase(sub_cmd, "EXPUNGE")) {
                    const end = @intFromPtr(sub_cmd.ptr) + sub_cmd.len - @intFromPtr(line.ptr);
                    try self.handleExpunge(tag, std.mem.trim(u8, line[end..], " \t"));
                } else {
                    try self.sendResponse(tag, "OK", "UID command completed");
                }
            },
            .append => {
                // APPEND mailbox (\flags) {size} - read literal data and save to Maildir
                // RFC 3501: APPEND is only valid in the authenticated or
                // selected state. Reject it otherwise so unauthenticated
                // clients cannot trigger message storage / literal allocation.
                if (self.state == .not_authenticated or self.username == null) {
                    try self.sendResponse(tag, "NO", "Must authenticate first");
                    return;
                }

                // Parse rest of command line to find {N} literal size
                const cmd_end = @intFromPtr(cmd_str.ptr) + cmd_str.len - @intFromPtr(line.ptr);
                const rest = if (cmd_end < line.len) std.mem.trim(u8, line[cmd_end..], " \t") else "";

                // Find {N} at end of line
                if (std.mem.lastIndexOfScalar(u8, rest, '{')) |brace_start| {
                    if (std.mem.lastIndexOfScalar(u8, rest, '}')) |brace_end| {
                        if (brace_end > brace_start) {
                            const size_str = rest[brace_start + 1 .. brace_end];
                            const literal_size = std.fmt.parseInt(usize, size_str, 10) catch {
                                try self.sendResponse(tag, "BAD", "Invalid literal size");
                                return;
                            };

                            // Reject oversized literals before allocating to
                            // avoid a memory-exhaustion DoS (a client could
                            // otherwise request an arbitrarily large buffer).
                            if (literal_size > max_append_literal_size) {
                                try self.sendResponse(tag, "NO", "[TOOBIG] Message too large");
                                return;
                            }

                            // Parse mailbox name plus the optional flag list
                            // and date-time preceding the {N} literal, e.g.
                            //   APPEND "Sent" (\Seen) "14-Jul-2026 09:58:00 +0000" {1234}
                            // Parsing from `rest` (not the space-split `parts`)
                            // keeps quoted names with spaces ("All Mail") intact.
                            const parsed = parseAppendArgs(rest[0..brace_start]) catch |err| {
                                if (err == error.InvalidAppendDate)
                                    return self.sendResponse(tag, "NO", "Invalid APPEND date-time");
                                return self.sendResponse(tag, "BAD", "Invalid APPEND arguments");
                            };
                            const mailbox = parsed.mailbox;

                            // Reject invalid/unsafe mailbox names up front rather
                            // than after buffering the whole literal.
                            if (!isSafeMailboxName(mailbox)) {
                                try self.sendResponse(tag, "NO", "[TRYCREATE] Invalid mailbox name");
                                return;
                            }
                            if (parsed.flags) |raw| {
                                _ = FlagList.parse(raw) catch |err| switch (err) {
                                    error.KeywordLimit => return self.sendMaildirWriteError(tag, err),
                                    else => return self.sendResponse(tag, "BAD", "Invalid APPEND flags"),
                                };
                            }

                            // Set up pending append state
                            self.cleanupAppend();
                            self.append_tag = try self.allocator.dupe(u8, tag);
                            self.append_mailbox = try self.allocator.dupe(u8, mailbox);
                            self.append_internal_date = parsed.internal_date;
                            if (parsed.flags) |fs| {
                                self.append_flags = try self.allocator.dupe(u8, fs);
                            }
                            self.append_literal_size = literal_size;
                            self.append_literal_buf = try self.allocator.alloc(u8, literal_size);
                            self.append_literal_pos = 0;

                            // Send continuation response - client will send literal data
                            try self.writeData("+ Ready for literal data\r\n");

                            std.log.info("IMAP APPEND: Expecting {d} bytes for mailbox {s}", .{ literal_size, mailbox });
                            return;
                        }
                    }
                }

                // No literal found - nothing was stored, so do not fabricate an
                // APPENDUID (a hardcoded value would lie to the client and
                // corrupt its UID cache). Acknowledge without UIDPLUS data.
                try self.sendResponse(tag, "OK", "APPEND completed");
            },
            .enable => {
                // RFC 5161: ENABLE extension
                try self.sendUntagged("ENABLED");
                try self.sendResponse(tag, "OK", "ENABLE completed");
            },
            .id => {
                // RFC 2971: ID extension
                try self.sendUntagged("ID NIL");
                try self.sendResponse(tag, "OK", "ID completed");
            },
            .create => {
                // CREATE mailbox in canonical Maildir++ form. The visible
                // folder symlink preserves compatibility with older server
                // paths while external Maildir tools use .Folder/{tmp,new,cur}.
                const end = @intFromPtr(cmd_str.ptr) + cmd_str.len - @intFromPtr(line.ptr);
                const create_name = parseSingleMailboxArg(line[end..]) orelse return self.sendResponse(tag, "BAD", "CREATE requires one mailbox name");
                if (!isSafeMailboxName(create_name)) {
                    // Rejects empty names and any path-traversal attempt.
                    try self.sendResponse(tag, "NO", "Invalid mailbox name");
                } else {
                    var created = false;
                    if (self.username) |uname| {
                        const db = self.auth_backend.db;
                        db.lockMailboxes();
                        defer db.unlockMailboxes();
                        const local = uname;
                        const visible = std.fmt.allocPrint(self.allocator, "mail/{s}/{s}", .{ local, create_name }) catch null;
                        const canonical = std.fmt.allocPrint(self.allocator, "mail/{s}/.{s}", .{ local, create_name }) catch null;
                        const target = std.fmt.allocPrint(self.allocator, ".{s}/cur", .{create_name}) catch null;
                        if (visible != null and canonical != null and target != null) {
                            const tmp = std.fmt.allocPrint(self.allocator, "{s}/tmp", .{canonical.?}) catch null;
                            const new = std.fmt.allocPrint(self.allocator, "{s}/new", .{canonical.?}) catch null;
                            const cur = std.fmt.allocPrint(self.allocator, "{s}/cur", .{canonical.?}) catch null;
                            const exists = if (fs_compat.cwd().access(visible.?, .{})) |_| true else |_| pathIsSymlink(visible.?);
                            if (!exists and (try db.enabledMailboxId(uname)) != null and tmp != null and new != null and cur != null) {
                                fs_compat.cwd().makePath(tmp.?) catch {};
                                fs_compat.cwd().makePath(new.?) catch {};
                                fs_compat.cwd().makePath(cur.?) catch {};
                                created = createRelativeSymlink(target.?, visible.?);
                            }
                            if (tmp) |value| self.allocator.free(value);
                            if (new) |value| self.allocator.free(value);
                            if (cur) |value| self.allocator.free(value);
                        }
                        if (visible) |value| self.allocator.free(value);
                        if (canonical) |value| self.allocator.free(value);
                        if (target) |value| self.allocator.free(value);
                    }
                    if (created)
                        try self.sendResponse(tag, "OK", "CREATE completed")
                    else
                        try self.sendResponse(tag, "NO", "Mailbox already exists or could not be created");
                }
            },
            .subscribe => {
                try self.sendResponse(tag, "OK", "SUBSCRIBE completed");
            },
            .unsubscribe => {
                try self.sendResponse(tag, "OK", "UNSUBSCRIBE completed");
            },
            .store => {
                const seq_set = parts.next() orelse "1:*";
                // Flags action is rest of line after sequence set
                const seq_end = @intFromPtr(seq_set.ptr) + seq_set.len - @intFromPtr(line.ptr);
                const flags_action = if (seq_end < line.len) std.mem.trim(u8, line[seq_end..], " \t") else "";
                try self.handleStore(tag, seq_set, flags_action);
            },
            .copy => {
                const seq_set = parts.next() orelse "1:*";
                const seq_end = @intFromPtr(seq_set.ptr) + seq_set.len - @intFromPtr(line.ptr);
                const rest = if (seq_end < line.len) line[seq_end..] else "";
                const dest_arg = parseImapArg(rest) orelse ParsedImapArg{ .value = "INBOX", .rest = "" };
                const dest = dest_arg.value;
                try self.handleCopy(tag, seq_set, dest);
            },
            .examine => {
                const cmd_end = @intFromPtr(cmd_str.ptr) + cmd_str.len - @intFromPtr(line.ptr);
                const rest = if (cmd_end < line.len) line[cmd_end..] else "";
                const mailbox = if (parseImapArg(rest)) |arg| arg.value else "INBOX";
                try self.handleExamine(tag, mailbox);
            },
            .delete => {
                const end = @intFromPtr(cmd_str.ptr) + cmd_str.len - @intFromPtr(line.ptr);
                const mailbox = parseSingleMailboxArg(line[end..]) orelse return self.sendResponse(tag, "BAD", "DELETE requires one mailbox name");
                try self.handleDelete(tag, mailbox);
            },
            .rename => {
                const end = @intFromPtr(cmd_str.ptr) + cmd_str.len - @intFromPtr(line.ptr);
                const old = parseImapArg(line[end..]) orelse return self.sendResponse(tag, "BAD", "RENAME requires two mailbox names");
                const new = parseImapArg(old.rest) orelse return self.sendResponse(tag, "BAD", "RENAME requires two mailbox names");
                if (new.rest.len != 0) return self.sendResponse(tag, "BAD", "RENAME requires two mailbox names");
                try self.handleRename(tag, old.value, new.value);
            },
            .move => {
                const seq_set = parts.next() orelse "1:*";
                const seq_end = @intFromPtr(seq_set.ptr) + seq_set.len - @intFromPtr(line.ptr);
                const rest = if (seq_end < line.len) line[seq_end..] else "";
                const dest_arg = parseImapArg(rest) orelse ParsedImapArg{ .value = "INBOX", .rest = "" };
                const dest = dest_arg.value;
                try self.handleMove(tag, seq_set, dest);
            },
            .unselect => {
                // RFC 3691: UNSELECT - like CLOSE but without expunging
                self.freeMailboxFiles();
                self.state = .authenticated;
                self.mailbox_read_only = false;
                try self.sendResponse(tag, "OK", "UNSELECT completed");
            },
            .check => {
                try self.sendResponse(tag, "OK", "CHECK completed");
            },
        }
    }
};

/// IMAP server
pub const ImapServer = struct {
    scanner: ?*clamav.ClamAVScanner = null,
    allocator: std.mem.Allocator,
    config: ImapConfig,
    listener: ?socket.Server = null,
    ssl_listener: ?socket.Server = null,
    sessions: std.ArrayList(*ImapSession),
    running: std.atomic.Value(bool),
    mutex: mutex_compat.Mutex = .{},
    auth_backend: *auth.AuthBackend,
    db: ?*database.Database = null,
    tls_context: ?*tls_mod.TlsContext = null,
    cert_key_pair: ?tls.config.CertKeyPair = null,

    pub fn init(allocator: std.mem.Allocator, config: ImapConfig, auth_backend: *auth.AuthBackend, db: ?*database.Database) ImapServer {
        var server = ImapServer{
            .allocator = allocator,
            .config = config,
            .sessions = .empty,
            .running = std.atomic.Value(bool).init(false),
            .auth_backend = auth_backend,
            .db = db,
            .tls_context = null,
            .cert_key_pair = null,
        };

        // Load TLS certificate if configured
        if (config.enable_ssl and config.cert_path != null and config.key_path != null) {
            server.cert_key_pair = tls.config.CertKeyPair.fromFilePathAbsolute(
                allocator,
                io_compat.getIo(),
                config.cert_path.?,
                config.key_path.?,
            ) catch |err| {
                logger.err("Failed to load TLS certificate for IMAPS: {}", .{err});
                return server;
            };
            logger.info("Loaded TLS certificate for IMAPS", .{});
        }

        return server;
    }

    pub fn deinit(self: *ImapServer) void {
        self.stop();
        for (self.sessions.items) |session| {
            session.deinit();
            self.allocator.destroy(session);
        }
        self.sessions.deinit(self.allocator);
        if (self.tls_context) |ctx| {
            var tls_ctx = ctx;
            tls_ctx.deinit();
            self.allocator.destroy(ctx);
        }
        if (self.cert_key_pair) |*ckp| {
            ckp.deinit(self.allocator);
        }
    }

    /// Start the IMAP server (plain text on port 143)
    pub fn start(self: *ImapServer) !void {
        const address = try socket.Address.parseIp(self.config.bind_host, self.config.port);
        self.listener = try socket.Server.listen(address, .{
            .reuse_address = true,
        });
        try self.listener.?.setNonBlocking(true);

        self.running.store(true, .monotonic);

        logger.info("IMAP server listening on port {d}", .{self.config.port});

        // Also start IMAPS (port 993) if SSL is enabled and certs are configured
        if (self.config.enable_ssl and self.config.cert_path != null and self.config.key_path != null) {
            _ = std.Thread.spawn(.{}, startImapsListener, .{self}) catch |err| {
                logger.warn("Failed to start IMAPS listener: {} (IMAP on port {d} still available)", .{ err, self.config.port });
            };
        }

        while (self.running.load(.monotonic)) {
            const connection = self.listener.?.accept() catch |err| {
                if (!self.running.load(.monotonic)) break;
                if (err == error.OperationCancelled or err == error.WouldBlock) {
                    self.listener.?.waitReadable(1000);
                    continue;
                }
                logger.warn("IMAP accept error: {}", .{err});
                time_compat.sleepMs(500);
                continue;
            };

            // Handle connection in a new thread for concurrent processing
            const ctx = ImapConnCtx{ .server = self, .connection = connection, .is_ssl = false };
            const thread = std.Thread.spawn(.{}, handleConnectionThread, .{ctx}) catch |err| {
                logger.err("Failed to spawn IMAP handler: {}", .{err});
                connection.close();
                continue;
            };
            thread.detach();
        }
    }

    /// Start the IMAPS listener on port 993 (runs in separate thread)
    fn startImapsListener(self: *ImapServer) void {
        const ssl_address = socket.Address.parseIp(self.config.bind_host, self.config.ssl_port) catch |err| {
            logger.err("Failed to parse IMAPS address: {}", .{err});
            return;
        };

        self.ssl_listener = socket.Server.listen(ssl_address, .{
            .reuse_address = true,
        }) catch |err| {
            logger.err("Failed to start IMAPS listener: {}", .{err});
            return;
        };
        self.ssl_listener.?.setNonBlocking(true) catch |err| {
            logger.err("Failed to set IMAPS listener nonblocking: {}", .{err});
            return;
        };

        logger.info("IMAPS server listening on port {d} (SSL/TLS)", .{self.config.ssl_port});

        while (self.running.load(.monotonic)) {
            const connection = self.ssl_listener.?.accept() catch |err| {
                if (!self.running.load(.monotonic)) break; // Server is stopping
                if (err == error.OperationCancelled or err == error.WouldBlock) {
                    self.ssl_listener.?.waitReadable(1000);
                    continue;
                }
                logger.warn("IMAPS accept error: {}", .{err});
                time_compat.sleepMs(500);
                continue;
            };

            // Handle SSL connection in a new thread for concurrent processing
            const ctx = ImapConnCtx{ .server = self, .connection = connection, .is_ssl = true };
            const thread = std.Thread.spawn(.{}, handleConnectionThread, .{ctx}) catch |err| {
                logger.err("Failed to spawn IMAPS handler: {}", .{err});
                connection.close();
                continue;
            };
            thread.detach();
        }
    }

    /// Stop the IMAP server
    pub fn stop(self: *ImapServer) void {
        self.running.store(false, .monotonic);
        if (self.listener) |*listener| {
            listener.close();
            self.listener = null;
        }
        if (self.ssl_listener) |*ssl_listener| {
            ssl_listener.close();
            self.ssl_listener = null;
        }
    }

    const ImapConnCtx = struct {
        server: *ImapServer,
        connection: socket.Connection,
        is_ssl: bool,
    };

    fn handleConnectionThread(ctx: ImapConnCtx) void {
        ctx.server.handleConnection(ctx.connection, ctx.is_ssl) catch |err| {
            const label = if (ctx.is_ssl) "IMAPS" else "IMAP";
            logger.err("{s} connection error: {}", .{ label, err });
            ctx.connection.close();
        };
    }

    /// Handle a client connection
    fn handleConnection(self: *ImapServer, connection: socket.Connection, is_ssl: bool) !void {
        // The listener is non-blocking, and on BSD/macOS an accepted socket
        // inherits that. Every read below expects to block.
        connection.setBlocking();
        var session = try self.allocator.create(ImapSession);
        session.* = ImapSession.init(self.allocator, connection, self.auth_backend, self.db, self.config.enable_gmail_labels);
        session.junk_folder = self.config.junk_folder;
        session.scanner = self.scanner;
        defer {
            session.deinit();
            self.allocator.destroy(session);
            connection.close();
        }

        // IMAPS: the TLS handshake comes first, then the greeting over TLS.
        if (is_ssl) {
            if (self.cert_key_pair == null) {
                logger.err("IMAPS connection attempted but no certificate loaded", .{});
                return error.TlsNotConfigured;
            }

            logger.info("Starting TLS handshake for IMAPS connection", .{});
            var recv_buf: [tls.input_buffer_len]u8 = undefined;
            const handshake = try self.tlsHandshake(connection, &recv_buf, &.{});
            logger.info("IMAPS TLS handshake completed successfully", .{});
            runTlsSession(session, connection, handshake.cipher, recv_buf[0..handshake.leftover_len], .implicit);
            return;
        }

        // Plain text session (non-SSL)
        try session.sendGreeting();

        // Input is framed into lines here, not one command per read(): a
        // client may pipeline, and after STARTTLS the bytes that follow the
        // command in the same segment are the start of its ClientHello.
        var input: [16384]u8 = undefined;
        var input_len: usize = 0;
        while (session.state != .logout and !session.starttls_requested) {
            // During IDLE: set a short socket timeout so we can poll for new mail
            if (session.idle_mode) {
                if (!session.idleWaitReadable(connection.fd)) continue;
            }

            if (input_len == input.len) {
                logger.warn("IMAP: command line longer than {d} bytes; closing", .{input.len});
                break;
            }
            const bytes_read = connection.read(input[input_len..]) catch |err| {
                if (session.idle_mode and (err == error.WouldBlock or err == error.ConnectionTimedOut)) {
                    if (session.state == .selected) {
                        session.idlePollRescan();
                    }
                    continue;
                }
                break;
            };
            if (bytes_read == 0) break;
            input_len += bytes_read;

            // Restore normal timeout when leaving IDLE
            if (!session.idle_mode) {
                const no_tv: std.posix.timeval = .{ .sec = 0, .usec = 0 };
                std.posix.setsockopt(connection.fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&no_tv)) catch {};
            }

            const processed = processInput(session, input[0..input_len]);
            const leftover = input_len - processed;
            if (processed > 0 and leftover > 0) {
                std.mem.copyForwards(u8, &input, input[processed..input_len]);
            }
            input_len = leftover;
        }

        // STARTTLS upgrade: perform TLS handshake on the existing connection.
        // processInput stopped at the STARTTLS line, so whatever is still in
        // `input` arrived behind it. It goes to the handshake as TLS records,
        // never to the session as commands: cleartext injected ahead of the
        // handshake cannot reach the encrypted session.
        if (session.starttls_requested and self.cert_key_pair != null) {
            logger.info("Starting STARTTLS upgrade on port 143", .{});
            var recv_buf: [tls.input_buffer_len]u8 = undefined;
            const handshake = self.tlsHandshake(connection, &recv_buf, input[0..input_len]) catch return;
            logger.info("STARTTLS handshake completed successfully", .{});
            session.starttls_requested = false;
            runTlsSession(session, connection, handshake.cipher, recv_buf[0..handshake.leftover_len], .starttls);
        }
    }

    /// Feed client input to the session: complete command lines, and APPEND
    /// literal bytes while a literal is being collected. Returns how many
    /// bytes were consumed; the rest is an incomplete line to keep.
    ///
    /// Stops right after a line that requests STARTTLS. What follows it was
    /// sent before TLS began and must not run as commands.
    fn processInput(session: *ImapSession, input: []const u8) usize {
        var processed: usize = 0;
        while (processed < input.len) {
            // If collecting APPEND literal data, consume bytes directly
            if (session.append_literal_buf) |buf| {
                const needed = session.append_literal_size - session.append_literal_pos;
                const lit_len = @min(needed, input.len - processed);
                @memcpy(buf[session.append_literal_pos..][0..lit_len], input[processed..][0..lit_len]);
                session.append_literal_pos += lit_len;
                processed += lit_len;

                if (session.append_literal_pos >= session.append_literal_size) {
                    // Literal complete - save message and send OK
                    session.finalizeAppend() catch |err| {
                        logger.err("IMAP APPEND finalize error: {}", .{err});
                    };
                    if (session.state == .logout) break;
                    // Skip trailing \r\n after literal data
                    if (processed + 2 <= input.len and input[processed] == '\r' and input[processed + 1] == '\n') {
                        processed += 2;
                    }
                }
                continue;
            }

            // Normal: find next \r\n delimited command line
            const remaining = input[processed..];
            const line_end = std.mem.indexOf(u8, remaining, "\r\n") orelse break;
            if (line_end > 0) {
                session.processCommand(remaining[0..line_end]) catch |err| {
                    logger.err("IMAP command processing error: {}", .{err});
                };
            }
            processed += line_end + 2; // skip \r\n
            if (session.state == .logout or session.starttls_requested) break;
        }
        return processed;
    }

    const TlsHandshake = struct {
        cipher: tls.Cipher,
        /// Bytes at the front of the caller's `recv_buf` that arrived after
        /// the client's final handshake flight.
        leftover_len: usize,
    };

    /// Run the server side of a TLS handshake on `connection`.
    ///
    /// A client may send application data in the same TCP segment as its
    /// Finished message: nothing obliges it to wait for the greeting. Those
    /// bytes are already encrypted under the application keys, so they are
    /// handed back (at the front of `recv_buf`) rather than dropped. Dropping
    /// one record does not just lose a command: every later record is then
    /// decrypted with a sequence number one short, and fails as
    /// error.TlsBadRecordMac.
    ///
    /// `received` is handshake input already read from the socket (a
    /// ClientHello sent in the same segment as the STARTTLS command).
    fn tlsHandshake(self: *ImapServer, connection: socket.Connection, recv_buf: *[tls.input_buffer_len]u8, received: []const u8) !TlsHandshake {
        var tls_server = tls.nonblock.Server.init(.{
            .auth = &self.cert_key_pair.?,
        });
        var send_buf: [tls.output_buffer_len]u8 = undefined;
        if (received.len > recv_buf.len) return error.TlsHandshakeFailed;
        @memcpy(recv_buf[0..received.len], received);
        var recv_len: usize = received.len;

        while (!tls_server.done()) {
            const result = tls_server.run(recv_buf[0..recv_len], &send_buf) catch |err| {
                logger.debug("TLS handshake error: {}", .{err});
                return error.TlsHandshakeFailed;
            };

            if (result.recv_pos > 0) {
                const remaining = recv_len - result.recv_pos;
                if (remaining > 0) {
                    std.mem.copyForwards(u8, recv_buf, recv_buf[result.recv_pos..recv_len]);
                }
                recv_len = remaining;
            }

            var sent: usize = 0;
            while (sent < result.send.len) {
                const n = connection.write(result.send[sent..]) catch |err| {
                    logger.debug("TLS handshake write error: {}", .{err});
                    return error.TlsHandshakeFailed;
                };
                if (n == 0) {
                    logger.debug("TLS handshake: connection closed during write", .{});
                    return error.TlsHandshakeFailed;
                }
                sent += n;
            }

            if (!tls_server.done()) {
                const n = connection.read(recv_buf[recv_len..]) catch |err| {
                    logger.debug("TLS handshake read error: {}", .{err});
                    return error.TlsHandshakeFailed;
                };
                if (n == 0) {
                    logger.debug("TLS handshake: connection closed during read", .{});
                    return error.TlsHandshakeFailed;
                }
                recv_len += n;
            }
        }

        return .{ .cipher = tls_server.cipher().?, .leftover_len = recv_len };
    }

    const TlsMode = enum {
        /// IMAPS: the server greets the client once TLS is up.
        implicit,
        /// STARTTLS: the greeting was already sent in cleartext.
        starttls,
    };

    /// Serve an IMAP session over an established TLS connection until the
    /// client logs out or disconnects. `handshake_leftover` is ciphertext the
    /// client sent after its Finished message; it is decrypted before the
    /// socket is read again, because the client may be waiting for an answer
    /// to it and send nothing more.
    fn runTlsSession(session: *ImapSession, connection: socket.Connection, cipher: tls.Cipher, handshake_leftover: []const u8, mode: TlsMode) void {
        const label = switch (mode) {
            .implicit => "IMAP TLS",
            .starttls => "IMAP STARTTLS",
        };

        var tls_conn = tls.nonblock.Connection.init(cipher);
        session.setTlsConnection(&tls_conn);
        defer session.tls_connection = null;

        if (mode == .implicit) {
            session.sendGreeting() catch |err| {
                logger.err("Failed to send IMAP greeting: {}", .{err});
                return;
            };
        }

        var recv_buf: [tls.input_buffer_len]u8 = undefined;
        var cleartext_buf: [16384]u8 = undefined;
        var ciphertext_accum: [tls.input_buffer_len * 2]u8 = undefined;
        @memcpy(ciphertext_accum[0..handshake_leftover.len], handshake_leftover);
        var ciphertext_len: usize = handshake_leftover.len;
        // Buffer for leftover cleartext (partial lines across TLS records)
        var cleartext_accum: [16384]u8 = undefined;
        var cleartext_accum_len: usize = 0;
        // Decrypt what is already buffered before blocking on the socket.
        var buffered = ciphertext_len > 0;

        while (session.state != .logout) {
            if (session.idle_mode and !(session.checkClientPassword() catch false)) break;
            if (!buffered) {
                // During IDLE: set a short socket timeout so we can poll for new mail
                if (session.idle_mode) {
                    if (!session.idleWaitReadable(connection.fd)) continue;
                }

                const bytes_read = connection.read(recv_buf[0..]) catch |err| {
                    // During IDLE, timeout is expected — poll for new mail
                    if (session.idle_mode and (err == error.WouldBlock or err == error.ConnectionTimedOut)) {
                        if (session.state == .selected) {
                            session.idlePollRescan();
                        }
                        continue;
                    }
                    break;
                };
                if (bytes_read == 0) break;

                // Restore normal (no timeout) when not in IDLE
                if (!session.idle_mode) {
                    const no_tv: std.posix.timeval = .{ .sec = 0, .usec = 0 };
                    std.posix.setsockopt(connection.fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&no_tv)) catch {};
                }

                if (ciphertext_len + bytes_read <= ciphertext_accum.len) {
                    @memcpy(ciphertext_accum[ciphertext_len..][0..bytes_read], recv_buf[0..bytes_read]);
                    ciphertext_len += bytes_read;
                } else {
                    logger.err("{s}: ciphertext buffer overflow", .{label});
                    break;
                }
            }

            const dec_result = tls_conn.decrypt(ciphertext_accum[0..ciphertext_len], &cleartext_buf) catch |err| {
                switch (mode) {
                    .implicit => logger.err("TLS decrypt error: {}", .{err}),
                    .starttls => logger.err("STARTTLS decrypt error: {}", .{err}),
                }
                break;
            };
            // A full cleartext buffer can leave whole records behind; go
            // round again without reading until decrypt makes no progress.
            buffered = dec_result.ciphertext_pos > 0 or dec_result.cleartext.len > 0;

            // Handle decrypted data - may contain multiple IMAP commands
            if (dec_result.cleartext.len > 0) {
                const avail = cleartext_accum.len - cleartext_accum_len;
                const copy_len = @min(dec_result.cleartext.len, avail);
                @memcpy(cleartext_accum[cleartext_accum_len..][0..copy_len], dec_result.cleartext[0..copy_len]);
                cleartext_accum_len += copy_len;

                const processed = processInput(session, cleartext_accum[0..cleartext_accum_len]);
                const leftover = cleartext_accum_len - processed;
                if (processed > 0 and leftover > 0) {
                    std.mem.copyForwards(u8, &cleartext_accum, cleartext_accum[processed..cleartext_accum_len]);
                }
                cleartext_accum_len = leftover;
            }

            // Remove consumed ciphertext
            if (dec_result.ciphertext_pos > 0) {
                const remaining = ciphertext_len - dec_result.ciphertext_pos;
                if (remaining > 0) {
                    std.mem.copyForwards(u8, &ciphertext_accum, ciphertext_accum[dec_result.ciphertext_pos..ciphertext_len]);
                }
                ciphertext_len = remaining;
            }

            if (dec_result.closed) break;
        }

        // Send close notify
        var close_buf: [64]u8 = undefined;
        if (tls_conn.close(&close_buf)) |close_data| {
            _ = connection.write(close_data) catch {};
        } else |_| {}
    }
};

/// Format epoch seconds as IMAP INTERNALDATE: "DD-Mon-YYYY HH:MM:SS +0000"
fn formatImapDate(epoch_secs: i64, buf: *[64]u8) []const u8 {
    // Convert epoch seconds to date components
    const SECS_PER_DAY: i64 = 86400;
    var days = @divFloor(epoch_secs, SECS_PER_DAY);
    var remaining_secs = @mod(epoch_secs, SECS_PER_DAY);
    if (remaining_secs < 0) {
        remaining_secs += SECS_PER_DAY;
        days -= 1;
    }

    const hours: u32 = @intCast(@divFloor(remaining_secs, 3600));
    const mins: u32 = @intCast(@divFloor(@mod(remaining_secs, 3600), 60));
    const secs: u32 = @intCast(@mod(remaining_secs, 60));

    // Days since Unix epoch (1 Jan 1970) to date
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    const z = days + 719468;
    const era: i64 = @divFloor(if (z >= 0) z else z - 146096, 146097);
    const doe: u32 = @intCast(z - era * 146097); // day of era [0, 146096]
    const yoe: u32 = @intCast(@divFloor(doe - doe / 1460 + doe / 36524 - doe / 146096, 365));
    const y: i64 = @as(i64, @intCast(yoe)) + era * 400;
    const doy: u32 = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    const mp: u32 = (5 * doy + 2) / 153; // [0, 11]
    const day: u32 = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    const month_idx: u32 = if (mp < 10) mp + 3 else mp - 9; // [1, 12]
    const year: i64 = if (month_idx <= 2) y + 1 else y;

    const mon = imap_months[@as(usize, month_idx) - 1];
    const len = (std.fmt.bufPrint(buf, "{d:0>2}-{s}-{d} {d:0>2}:{d:0>2}:{d:0>2} +0000", .{
        day, mon, year, hours, mins, secs,
    }) catch return "01-Jan-2026 00:00:00 +0000").len;
    return buf[0..len];
}

/// Try to parse RFC 2822 date and reformat as IMAP INTERNALDATE
/// Input: "Thu, 26 Feb 2026 05:39:21 +0000 (UTC)" or similar
/// Output: "26-Feb-2026 05:39:21 +0000"
fn parseAndFormatRfc2822Date(raw: []const u8, buf: *[64]u8) ?[]const u8 {
    // Try to find day, month, year, time pattern
    // Skip optional day-of-week prefix (e.g., "Thu, ")
    var s = raw;
    if (std.mem.indexOf(u8, s, ", ")) |comma_pos| {
        s = s[comma_pos + 2 ..];
    }
    s = std.mem.trim(u8, s, " \t");

    // Parse: DD Mon YYYY HH:MM:SS +ZZZZ
    var parts_iter = std.mem.tokenizeAny(u8, s, " \t");
    const day_s = parts_iter.next() orelse return null;
    const mon_s = parts_iter.next() orelse return null;
    const year_s = parts_iter.next() orelse return null;
    const time_s = parts_iter.next() orelse return null;
    const tz_s = parts_iter.next() orelse "+0000";

    // Validate
    const day = std.fmt.parseInt(u32, day_s, 10) catch return null;
    _ = std.fmt.parseInt(i32, year_s, 10) catch return null;
    if (time_s.len < 8) return null; // HH:MM:SS
    if (mon_s.len < 3) return null;

    // Use only first 5 chars of tz (skip trailing "(UTC)" etc)
    const tz = if (tz_s.len >= 5) tz_s[0..5] else tz_s;

    const len = (std.fmt.bufPrint(buf, "{d:0>2}-{s}-{s} {s} {s}", .{
        day, mon_s[0..3], year_s, time_s, tz,
    }) catch return null).len;
    return buf[0..len];
}

// Tests
test "IMAP command parsing" {
    const testing = std.testing;

    const cmd = ImapCommand.fromString("LOGIN");
    try testing.expect(cmd != null);
    try testing.expectEqual(ImapCommand.login, cmd.?);

    const unknown = ImapCommand.fromString("UNKNOWN");
    try testing.expect(unknown == null);
}

test "IMAP argument parsing preserves quoted mailbox names" {
    const testing = std.testing;

    const all_mail = parseImapArg(" \"All Mail\" (MESSAGES UIDNEXT UIDVALIDITY UNSEEN)").?;
    try testing.expectEqualStrings("All Mail", all_mail.value);
    try testing.expectEqualStrings("(MESSAGES UIDNEXT UIDVALIDITY UNSEEN)", all_mail.rest);

    const loose_all_mail = parseImapArg(" All Mail (MESSAGES UIDNEXT UIDVALIDITY UNSEEN)").?;
    try testing.expectEqualStrings("All Mail", loose_all_mail.value);
    try testing.expectEqualStrings("(MESSAGES UIDNEXT UIDVALIDITY UNSEEN)", loose_all_mail.rest);

    const list_reference = parseImapArg(" \"\" \"All Mail\"").?;
    try testing.expectEqualStrings("", list_reference.value);
    const list_pattern = parseImapArg(list_reference.rest).?;
    try testing.expectEqualStrings("All Mail", list_pattern.value);
    try testing.expectEqualStrings("", list_pattern.rest);

    const inbox = parseImapArg(" INBOX").?;
    try testing.expectEqualStrings("INBOX", inbox.value);
    try testing.expectEqualStrings("", inbox.rest);
}

test "Maildir flags drive unseen counts" {
    const testing = std.testing;

    try testing.expect(MaildirFlags.fromFilename("1770000000000.eml").seen == false);
    try testing.expect(MaildirFlags.fromFilename("1770000000001.eml:2,S").seen);
    try testing.expect(MaildirFlags.fromFilename("1770000000002.eml:2,FS").flagged);
}

test "Maildir delivery counter does not break chronological ordering" {
    const testing = std.testing;

    try testing.expectEqual(@as(i64, 1_784_428_368_187), parseMessageSortKey("1784428368187.9.eml"));
    try testing.expectEqual(@as(i64, 1_784_428_368_187), parseMessageSortKey("1784428368187.9.eml:2,S"));
    try testing.expectEqual(@as(i64, 1_784_440_561_138), parseMessageSortKey("mail/chris/new/1784440561138.0.eml"));
    try testing.expectEqual(@as(i64, 0), parseMessageSortKey("legacy-random-name.eml:2,S"));
}

test "Gmail-style mailboxes are configurable and All Mail is not canonical" {
    const testing = std.testing;

    try testing.expect((ImapConfig{}).enable_gmail_labels);
    try testing.expect(isLegacySyntheticMailbox("All Mail"));
    try testing.expect(isLegacySyntheticMailbox("promotions"));
    try testing.expect(!isLegacySyntheticMailbox("INBOX"));
    try testing.expect(!isLegacySyntheticMailbox("Notes"));
    try testing.expect(std.mem.indexOf(u8, FolderType.all_mail.getAttributes(), "\\All") == null);
}

test "parseAppendArgs parses mailbox, flags and date-time" {
    const testing = std.testing;

    const bare = try parseAppendArgs("INBOX");
    try testing.expectEqualStrings("INBOX", bare.mailbox);
    try testing.expect(bare.flags == null);
    try testing.expect(bare.internal_date == null);

    const quoted = try parseAppendArgs("\"All Mail\" (\\Seen)");
    try testing.expectEqualStrings("All Mail", quoted.mailbox);
    try testing.expectEqualStrings("\\Seen", quoted.flags.?);

    const with_date = try parseAppendArgs("\"Sent\" (\\Seen \\Draft) \"14-Jul-2026 09:58:00 +0000\"");
    try testing.expectEqualStrings("Sent", with_date.mailbox);
    try testing.expectEqualStrings("\\Seen \\Draft", with_date.flags.?);
    try testing.expectEqual(try parseAppendDate("14-Jul-2026 09:58:00 +0000"), with_date.internal_date.?);

    const empty_flags = try parseAppendArgs("Drafts ()");
    try testing.expectEqualStrings("Drafts", empty_flags.mailbox);
    try testing.expectEqualStrings("", empty_flags.flags.?);

    const date_only = try parseAppendArgs("INBOX \"14-Jul-2026 15:28:00 +0530\"");
    try testing.expectEqualStrings("INBOX", date_only.mailbox);
    try testing.expect(date_only.flags == null);
    try testing.expectEqual(with_date.internal_date, date_only.internal_date);
}

test "APPEND timestamps validate dates, offsets, and optional arguments" {
    const testing = std.testing;
    try testing.expectEqual(@as(i64, -1), try parseAppendDate("31-Dec-1969 23:59:59 +0000"));
    try testing.expectEqual(@as(i64, 0), try parseAppendDate(" 1-Jan-1970 05:45:00 +0545"));
    try testing.expectEqual(@as(i64, 0), try parseAppendDate("31-Dec-1969 16:00:00 -0800"));
    try testing.expectEqual(@as(i64, 1709164800), try parseAppendDate("29-feb-2024 00:00:00 +0000"));
    for ([_][]const u8{
        "29-Feb-2025 00:00:00 +0000",
        " 0-Jan-2025 00:00:00 +0000",
        " 1-Jan-0000 00:00:00 +0000",
        " 1-Jan-2025 24:00:00 +0000",
        " 1-Jan-2025 00:60:00 +0000",
        " 1-Jan-2025 00:00:60 +0000",
        " 1-Jan-2025 00:00:00 +2460",
        " 1-Jan-2025 00:00:00 +0560",
    }) |invalid| try testing.expectError(error.InvalidAppendDate, parseAppendDate(invalid));
    try testing.expectError(error.InvalidAppendDate, parseAppendArgs("INBOX () \" 1-Jan-2025 00:00:00 +0000\" extra"));
    try testing.expectError(error.InvalidAppendArgs, parseAppendArgs("INBOX (\\Seen"));
    try testing.expectError(error.InvalidAppendArgs, parseAppendArgs("\"Incomplete mailbox"));
}

test "APPEND flag list maps to Maildir flags" {
    const testing = std.testing;

    const flags = (try FlagList.parse("\\Seen \\Draft")).system;
    try testing.expect(flags.seen);
    try testing.expect(flags.draft);
    try testing.expect(!flags.flagged);

    var suffix_buf: [16]u8 = undefined;
    try testing.expectEqualStrings(":2,DS", flags.toSuffix(&suffix_buf));
}

test "STORE adds and removes exact system flags and case-insensitive keywords" {
    const add = try StoreFlags.parse("+FLAGS.SILENT (\\Seen Review)");
    var names: maildir_keywords.Names = .{};
    const first = (MaildirFlags{}).applyStoreFlags(try add.flags.resolve(&names, add.mode), add.mode);
    try std.testing.expect(add.silent and first.seen and !first.flagged);
    const more = try StoreFlags.parse("+FLAGS (\\Flagged review)");
    const second = first.applyStoreFlags(try more.flags.resolve(&names, more.mode), more.mode);
    try std.testing.expect(second.seen and second.flagged);
    try std.testing.expectEqual(first.keywords, second.keywords);
    const remove = try StoreFlags.parse("-FLAGS (\\Seen REVIEW)");
    const last = second.applyStoreFlags(try remove.flags.resolve(&names, remove.mode), remove.mode);
    try std.testing.expect(!last.seen and last.flagged);
    try std.testing.expectEqual(@as(maildir_keywords.Bits, 0), last.keywords);
}

test "STORE replaces flags and refuses malformed atoms" {
    var names: maildir_keywords.Names = .{};
    const requested = try StoreFlags.parse("FLAGS (\\Answered Ledger)");
    const first = (MaildirFlags{ .seen = true }).applyStoreFlags(try requested.flags.resolve(&names, requested.mode), requested.mode);
    try std.testing.expect(first.answered and !first.seen and first.keywords != 0);
    const empty = try StoreFlags.parse("FLAGS ()");
    try std.testing.expectEqual(MaildirFlags{}, first.applyStoreFlags(try empty.flags.resolve(&names, empty.mode), empty.mode));
    try std.testing.expectError(error.InvalidKeyword, StoreFlags.parse("FLAGS (\\Unknown)"));
    try std.testing.expectError(error.InvalidKeyword, StoreFlags.parse("FLAGS (invalid%atom)"));
    try std.testing.expectError(error.InvalidStoreFlags, StoreFlags.parse("ADDFLAGS (Ledger)"));
}

test "IMAP message flags" {
    const testing = std.testing;

    var flags = MessageFlags{
        .seen = true,
        .flagged = true,
    };

    const flags_str = try flags.toString(testing.allocator);
    defer testing.allocator.free(flags_str);

    try testing.expect(std.mem.indexOf(u8, flags_str, "\\Seen") != null);
    try testing.expect(std.mem.indexOf(u8, flags_str, "\\Flagged") != null);
}

test "IMAP mailbox" {
    const testing = std.testing;

    var mailbox = try Mailbox.init(testing.allocator, "INBOX", "/var/spool/mail/user");
    defer mailbox.deinit(testing.allocator);

    try testing.expect(std.mem.eql(u8, mailbox.name, "INBOX"));
    try testing.expectEqual(@as(usize, 0), mailbox.exists);
}

test "the header ends at the first blank line, whichever line ending it uses" {
    try std.testing.expectEqual(@as(usize, 14), headerEnd("Subject: a\r\n\r\nbody"));
    try std.testing.expectEqual(@as(usize, 12), headerEnd("Subject: a\n\nbody"));
    // A bare-LF header must not run on to a CRLF blank line inside the body.
    try std.testing.expectEqual(@as(usize, 12), headerEnd("Subject: a\n\nline\r\n\r\nmore"));
    try std.testing.expectEqual(@as(usize, 2), headerEnd("\r\nbody only"));
    try std.testing.expectEqual(@as(usize, 10), headerEnd("Subject: a"));
}

test "header sections are parsed as requested" {
    const fields = parseHeaderSpec("HEADER.FIELDS (SUBJECT FROM DATE)").?;
    try std.testing.expectEqual(HeaderSection.Kind.fields, fields.kind);
    try std.testing.expectEqualStrings("SUBJECT FROM DATE", fields.fields);

    const not = parseHeaderSpec("HEADER.FIELDS.NOT (Received)").?;
    try std.testing.expectEqual(HeaderSection.Kind.fields_not, not.kind);
    try std.testing.expectEqualStrings("Received", not.fields);

    const all = parseHeaderSpec("header").?;
    try std.testing.expectEqual(HeaderSection.Kind.all, all.kind);

    try std.testing.expect(fetchHasAtom("RFC822.HEADER", "RFC822.HEADER"));
    try std.testing.expect(parseHeaderSpec("TEXT") == null);
    try std.testing.expect(parseHeaderSpec("1") == null);
    try std.testing.expect(parseHeaderSpec("RFC822.SIZE") == null);
}

test "header fields are filtered with their continuation lines, in order" {
    const header = "Received: from a\r\n\tby b\r\nSubject: long\r\n subject\r\nFrom: x@y\r\nTo: z@y\r\n\r\n";
    const kept = try filterHeaderFields(std.testing.allocator, header, "from SUBJECT", true);
    defer std.testing.allocator.free(kept);
    try std.testing.expectEqualStrings("Subject: long\r\n subject\r\nFrom: x@y\r\n\r\n", kept);

    const dropped = try filterHeaderFields(std.testing.allocator, header, "Received", false);
    defer std.testing.allocator.free(dropped);
    try std.testing.expectEqualStrings("Subject: long\r\n subject\r\nFrom: x@y\r\nTo: z@y\r\n\r\n", dropped);

    // Nothing matched is still a header block: just the blank line.
    const none = try filterHeaderFields(std.testing.allocator, header, "Cc", true);
    defer std.testing.allocator.free(none);
    try std.testing.expectEqualStrings("\r\n", none);
}

test "numbered body parts are echoed as requested" {
    var sections: FetchSections = .{ .items = "(BODY.PEEK[1.2]<1.5> body[1] BODY[TEXT])" };
    const nested = sections.next().?;
    try std.testing.expectEqualStrings("1.2", nested.spec);
    try std.testing.expect(nested.peek and nested.numbered());
    try std.testing.expectEqual(@as(usize, 1), nested.partial.?.offset);
    try std.testing.expectEqual(@as(usize, 5), nested.partial.?.count);
    const first = sections.next().?;
    try std.testing.expectEqualStrings("1", first.spec);
    try std.testing.expect(!first.peek and first.numbered() and first.partial == null);
    try std.testing.expect(!sections.next().?.numbered());
    try std.testing.expect(sections.next() == null);
}

/// A real ImapSession on one end of a socketpair, in a scratch directory with
/// its own SQLite database and maildir. The server resolves `mail/...`
/// against the working directory, so the harness moves into the scratch
/// directory for its lifetime.
const ImapTestHarness = struct {
    allocator: std.mem.Allocator,
    root: []u8,
    prev_cwd: [4096]u8 = undefined,
    prev_cwd_len: usize = 0,
    db: database.Database,
    auth_backend: auth.AuthBackend,
    peer: c_int,
    session: ImapSession,

    const user = "hi@test.local";

    fn create(allocator: std.mem.Allocator) !*ImapTestHarness {
        const h = try allocator.create(ImapTestHarness);
        errdefer allocator.destroy(h);
        h.allocator = allocator;

        var rnd: [8]u8 = undefined;
        io_compat.randomBytes(&rnd);
        h.root = try std.fmt.allocPrint(allocator, "/tmp/mail-imap-test-{x}", .{std.mem.readInt(u64, &rnd, .little)});
        try fs_compat.cwd().makePath(h.root);

        const cwd_ptr = std.c.getcwd(&h.prev_cwd, h.prev_cwd.len) orelse return error.GetCwdFailed;
        h.prev_cwd_len = std.mem.len(@as([*:0]u8, @ptrCast(cwd_ptr)));
        const root_z = try allocator.dupeSentinel(u8, h.root, 0);
        defer allocator.free(root_z);
        if (std.c.chdir(root_z.ptr) != 0) return error.ChdirFailed;

        try fs_compat.cwd().makePath("mail/" ++ user ++ "/new");
        h.db = try database.Database.init(allocator, "smtp.db");
        h.auth_backend = auth.AuthBackend.init(allocator, &h.db);

        var fds: [2]c_int = undefined;
        if (std.c.socketpair(std.posix.AF.UNIX, @intCast(@as(u32, std.posix.SOCK.STREAM)), 0, &fds) != 0) return error.SocketPairFailed;
        const flags = std.c.fcntl(fds[1], std.c.F.GETFL, @as(c_int, 0));
        const nonblock: c_int = @intCast(@as(u32, @bitCast(std.c.O{ .NONBLOCK = true })));
        _ = std.c.fcntl(fds[1], std.c.F.SETFL, flags | nonblock);
        h.peer = fds[1];

        h.session = ImapSession.init(allocator, .{ .fd = fds[0] }, &h.auth_backend, &h.db, true);
        h.session.username = try allocator.dupe(u8, user);
        h.session.state = .authenticated;
        return h;
    }

    fn destroy(h: *ImapTestHarness) void {
        const allocator = h.allocator;
        _ = std.c.close(h.session.connection.fd);
        h.session.deinit();
        _ = std.c.close(h.peer);
        h.auth_backend.deinit();
        h.db.deinit();
        h.prev_cwd[h.prev_cwd_len] = 0;
        _ = std.c.chdir(@ptrCast(&h.prev_cwd));
        fs_compat.cwd().deleteTree(h.root) catch {};
        allocator.free(h.root);
        allocator.destroy(h);
    }

    fn writeFile(h: *ImapTestHarness, rel: []const u8, content: []const u8) !void {
        _ = h;
        const f = try fs_compat.cwd().createFile(rel, .{});
        defer f.close();
        try f.writeAll(content);
    }

    fn exists(h: *ImapTestHarness, rel: []const u8) bool {
        _ = h;
        fs_compat.cwd().access(rel, .{}) catch return false;
        return true;
    }

    /// Run one command line and return everything the server wrote for it.
    fn run(h: *ImapTestHarness, line: []const u8) ![]u8 {
        try h.session.processCommand(line);
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(h.allocator);
        var buf: [16384]u8 = undefined;
        while (true) {
            const n = std.c.read(h.peer, &buf, buf.len);
            if (n <= 0) break;
            try out.appendSlice(h.allocator, buf[0..@intCast(n)]);
        }
        return out.toOwnedSlice(h.allocator);
    }

    fn expectContains(haystack: []const u8, needle: []const u8) !void {
        if (std.mem.indexOf(u8, haystack, needle) == null) {
            std.debug.print("expected to find {s}\n--- in ---\n{s}\n", .{ needle, haystack });
            return error.TestExpectedSubstring;
        }
    }
};

const test_message = "Received: from mx.example\r\nSubject: Hello there\r\nFrom: Sender <s@example.org>\r\nTo: hi@test.local\r\nDate: Wed, 16 Sep 2026 08:16:30 -0700\r\n\r\nBody line\r\n";

test "STORE applies the flags on disk when another connection renamed the file" {
    const h = try ImapTestHarness.create(std.testing.allocator);
    defer h.destroy();
    try h.writeFile("mail/" ++ ImapTestHarness.user ++ "/new/1789571792269.1.eml", test_message);

    std.testing.allocator.free(try h.run("a SELECT INBOX"));

    // Another connection marks it read: the file this session listed is gone.
    try std.testing.expect(renameFile(
        "mail/" ++ ImapTestHarness.user ++ "/new/1789571792269.1.eml",
        "mail/" ++ ImapTestHarness.user ++ "/new/1789571792269.1.eml:2,S",
    ));

    // Marking it unread from here has to act on the renamed file. It used to
    // compute from the stale name (already unread), rename nothing, and still
    // answer FLAGS () with OK while the disk kept \Seen.
    const resp = try h.run("b UID STORE 1 -FLAGS (\\Seen)");
    defer std.testing.allocator.free(resp);
    try ImapTestHarness.expectContains(resp, "* 1 FETCH (UID 1 FLAGS ())");
    try ImapTestHarness.expectContains(resp, "b OK");
    // Clearing the last flag leaves an empty flag list in the name.
    try std.testing.expect(h.exists("mail/" ++ ImapTestHarness.user ++ "/new/1789571792269.1.eml:2,"));
    try std.testing.expect(!h.exists("mail/" ++ ImapTestHarness.user ++ "/new/1789571792269.1.eml:2,S"));
}

test "STORE reports the flags a message still has when saving fails" {
    // Root ignores directory permissions, so the rename cannot be made to fail.
    if (std.c.geteuid() == 0) return error.SkipZigTest;

    const h = try ImapTestHarness.create(std.testing.allocator);
    defer h.destroy();
    try h.writeFile("mail/" ++ ImapTestHarness.user ++ "/new/1000.eml", test_message);
    std.testing.allocator.free(try h.run("a SELECT INBOX"));

    const new_dir = "mail/" ++ ImapTestHarness.user ++ "/new";
    try std.testing.expect(std.c.chmod(new_dir, 0o555) == 0);
    defer _ = std.c.chmod(new_dir, 0o755);

    const resp = try h.run("b STORE 1 +FLAGS.SILENT (\\Seen)");
    defer std.testing.allocator.free(resp);
    // Even under .SILENT: the client must learn the flag did not stick.
    try ImapTestHarness.expectContains(resp, "* 1 FETCH (UID 1 FLAGS ())");
    try ImapTestHarness.expectContains(resp, "b NO");
}

test "FETCH answers every message in a sequence list, with its current flags" {
    const h = try ImapTestHarness.create(std.testing.allocator);
    defer h.destroy();
    try h.writeFile("mail/" ++ ImapTestHarness.user ++ "/new/1000.eml", test_message);
    try h.writeFile("mail/" ++ ImapTestHarness.user ++ "/new/2000.eml", test_message);
    try h.writeFile("mail/" ++ ImapTestHarness.user ++ "/new/3000.eml", test_message);
    std.testing.allocator.free(try h.run("a SELECT INBOX"));

    try std.testing.expect(renameFile(
        "mail/" ++ ImapTestHarness.user ++ "/new/3000.eml",
        "mail/" ++ ImapTestHarness.user ++ "/new/3000.eml:2,S",
    ));

    const resp = try h.run("b FETCH 1,3 (FLAGS)");
    defer std.testing.allocator.free(resp);
    try ImapTestHarness.expectContains(resp, "* 1 FETCH (UID 1 FLAGS ())");
    try ImapTestHarness.expectContains(resp, "* 3 FETCH (UID 3 FLAGS (\\Seen))");
    try std.testing.expect(std.mem.indexOf(u8, resp, "* 2 FETCH") == null);
}

test "FETCH echoes the header section it was asked for and returns only those fields" {
    const h = try ImapTestHarness.create(std.testing.allocator);
    defer h.destroy();
    try h.writeFile("mail/" ++ ImapTestHarness.user ++ "/new/1000.eml", test_message);
    std.testing.allocator.free(try h.run("a SELECT INBOX"));

    const fields = try h.run("b FETCH 1 (BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)])");
    defer std.testing.allocator.free(fields);
    const want = "Subject: Hello there\r\nFrom: Sender <s@example.org>\r\n\r\n";
    var expect_buf: [128]u8 = undefined;
    const item = try std.fmt.bufPrint(&expect_buf, "BODY[HEADER.FIELDS (SUBJECT FROM)] {{{d}}}\r\n", .{want.len});
    try ImapTestHarness.expectContains(fields, item);
    try ImapTestHarness.expectContains(fields, want ++ ")");
    try std.testing.expect(std.mem.indexOf(u8, fields, "Received:") == null);

    const not = try h.run("c FETCH 1 (BODY.PEEK[HEADER.FIELDS.NOT (RECEIVED TO DATE)])");
    defer std.testing.allocator.free(not);
    try ImapTestHarness.expectContains(not, "BODY[HEADER.FIELDS.NOT (RECEIVED TO DATE)] {");
    try std.testing.expect(std.mem.indexOf(u8, not, "Received:") == null);
    try ImapTestHarness.expectContains(not, "Subject: Hello there");

    // A header section and a body section in one FETCH: both come back.
    const both = try h.run("d FETCH 1 (BODY.PEEK[HEADER.FIELDS (SUBJECT)] BODY.PEEK[TEXT])");
    defer std.testing.allocator.free(both);
    try ImapTestHarness.expectContains(both, "BODY[HEADER.FIELDS (SUBJECT)] {");
    try ImapTestHarness.expectContains(both, "BODY[TEXT] {11}\r\nBody line\r\n)");

    // PEEK leaves the message unread.
    try std.testing.expect(h.exists("mail/" ++ ImapTestHarness.user ++ "/new/1000.eml"));
}

test "FETCH returns INTERNALDATE whenever it is requested" {
    const h = try ImapTestHarness.create(std.testing.allocator);
    defer h.destroy();
    try h.writeFile("mail/" ++ ImapTestHarness.user ++ "/new/1789571792269.1.eml", test_message);
    std.testing.allocator.free(try h.run("a SELECT INBOX"));

    const resp = try h.run("b FETCH 1:* (UID FLAGS RFC822.SIZE INTERNALDATE)");
    defer std.testing.allocator.free(resp);
    // No timestamp-only filename here, so the date comes from the Date header.
    try ImapTestHarness.expectContains(resp, "INTERNALDATE \"16-Sep-2026 08:16:30 -0700\"");
    try ImapTestHarness.expectContains(resp, "RFC822.SIZE");
}

test "STATUS UIDNEXT exceeds every UID before the mailbox is ever selected" {
    const h = try ImapTestHarness.create(std.testing.allocator);
    defer h.destroy();
    try h.writeFile("mail/" ++ ImapTestHarness.user ++ "/new/1000.eml", test_message);
    try h.writeFile("mail/" ++ ImapTestHarness.user ++ "/new/2000.eml", test_message);
    try h.writeFile("mail/" ++ ImapTestHarness.user ++ "/new/3000.eml", test_message);

    const inbox = try h.run("a STATUS INBOX (MESSAGES UIDNEXT)");
    defer std.testing.allocator.free(inbox);
    try ImapTestHarness.expectContains(inbox, "MESSAGES 3 UIDNEXT 4");

    const all_mail = try h.run("b STATUS \"All Mail\" (MESSAGES UIDNEXT)");
    defer std.testing.allocator.free(all_mail);
    try ImapTestHarness.expectContains(all_mail, "MESSAGES 3 UIDNEXT 4");

    // SELECT agrees with what STATUS promised.
    const select = try h.run("c SELECT \"All Mail\"");
    defer std.testing.allocator.free(select);
    try ImapTestHarness.expectContains(select, "[UIDNEXT 4]");
}

test "the name resolver follows a renamed message by its base name" {
    const allocator = std.testing.allocator;
    const dir = "/tmp/mail-resolver-test";
    fs_compat.cwd().deleteTree(dir) catch {};
    try fs_compat.cwd().makePath(dir);
    defer fs_compat.cwd().deleteTree(dir) catch {};
    for ([_][]const u8{ dir ++ "/100.eml:2,S", dir ++ "/200.eml" }) |p| {
        const f = try fs_compat.cwd().createFile(p, .{});
        f.close();
    }

    var resolver = MaildirNameResolver.init(allocator);
    defer resolver.deinit();
    try std.testing.expectEqualStrings("100.eml:2,S", (try resolver.resolve(dir, "100.eml")).?);
    const same = "200.eml";
    try std.testing.expectEqual(@as([*]const u8, same.ptr), (try resolver.resolve(dir, same)).?.ptr);
    try std.testing.expect((try resolver.resolve(dir, "300.eml:2,S")) == null);
}

test "security: IMAP logins retain failed attempts across connections" {
    const a = std.testing.allocator;
    const h = try ImapTestHarness.create(a);
    defer h.destroy();
    a.free(h.session.username.?);
    h.session.username = null;
    h.session.state = .not_authenticated;
    // A small KDF cost keeps this protocol regression quick; production's
    // PasswordHasher.hashPassword still uses its normal 64 MB configuration.
    var hash: [32]u8 = undefined;
    try std.crypto.pwhash.argon2.kdf(a, &hash, "test-password", "0123456789abcdef", .{ .m = 8, .t = 1, .p = 1 }, .argon2id, io_compat.getIo());
    var encoded: [43]u8 = undefined;
    const hash_b64 = std.base64.standard_no_pad.Encoder.encode(&encoded, &hash);
    const stored = try std.fmt.allocPrint(a, "$argon2id$v=19$m=8,t=1,p=1$MDEyMzQ1Njc4OWFiY2RlZg${s}", .{hash_b64});
    defer a.free(stored);
    _ = try h.db.createUser(ImapTestHarness.user, stored, ImapTestHarness.user);
    for (0..10) |_| {
        const reply = try h.run("a LOGIN hi@test.local wrong-password");
        defer a.free(reply);
        try ImapTestHarness.expectContains(reply, "a NO");
    }
    // A new session shares the backend and budget, rather than resetting it.
    const connection = h.session.connection;
    h.session.deinit();
    h.session = ImapSession.init(a, connection, &h.auth_backend, &h.db, true);
    const denied = try h.run("b LOGIN hi@test.local test-password");
    defer a.free(denied);
    try ImapTestHarness.expectContains(denied, "b NO");
    try std.testing.expect(h.session.state == .not_authenticated);
    // Successful protocol reconnects on a different peer release reservations.
    for (0..20) |_| {
        var next_connection = h.session.connection;
        const peer = "192.0.2.5";
        @memcpy(next_connection.peer_ip_buf[0..peer.len], peer);
        next_connection.peer_ip_len = peer.len;
        h.session.deinit();
        h.session = ImapSession.init(a, next_connection, &h.auth_backend, &h.db, true);
        const success = try h.run("c LOGIN hi@test.local test-password");
        defer a.free(success);
        try ImapTestHarness.expectContains(success, "c OK LOGIN completed");
    }
}

// A throwaway self-signed P-256 certificate for "localhost", used only by the
// TLS tests below.
const test_tls_cert_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBljCCATugAwIBAgIUX1M5wiESaNWziXCrsk7G6Pb5G4wwCgYIKoZIzj0EAwIw
    \\FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTExODAwMTIzNloYDzIxMjYxMDI1
    \\MDAxMjM2WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
    \\PQMBBwNCAAQCG1eMT0QI+YgA9kxHRD/WgDYSlakXO8dqV5GFMMotrEi8Jh83a0OS
    \\66L458DTn6vb2OkuJDHySMHiwRBk9QABo2kwZzAdBgNVHQ4EFgQU5wd/eSQu6P9a
    \\tNPM8ujEeUW4HIEwHwYDVR0jBBgwFoAU5wd/eSQu6P9atNPM8ujEeUW4HIEwDwYD
    \\VR0TAQH/BAUwAwEB/zAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwID
    \\SQAwRgIhAPMS2073H9BocmXv0c1u959MRgha2FKuQ86+9Uc0ieLAAiEAkp+fm5O5
    \\XoYHJ6Zns0Z8ZZNU9M2XXpv5lFOHRDU/4zw=
    \\-----END CERTIFICATE-----
    \\
;
const test_tls_key_pem =
    \\-----BEGIN PRIVATE KEY-----
    \\MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTn/Z/mw5nPjcc9iF
    \\nF9Bjozq0CFkwE43+icOezXSjDihRANCAAQCG1eMT0QI+YgA9kxHRD/WgDYSlakX
    \\O8dqV5GFMMotrEi8Jh83a0OS66L458DTn6vb2OkuJDHySMHiwRBk9QAB
    \\-----END PRIVATE KEY-----
    \\
;

/// The client end of an IMAPS connection: a blocking socket and the TLS
/// state to talk through it.
const TestImapsClient = struct {
    fd: c_int,
    conn: tls.nonblock.Connection = undefined,
    inbox: [tls.input_buffer_len * 2]u8 = undefined,
    inbox_len: usize = 0,

    fn writeAll(c: *TestImapsClient, bytes: []const u8) !void {
        var sent: usize = 0;
        while (sent < bytes.len) {
            const n = std.c.write(c.fd, bytes[sent..].ptr, bytes.len - sent);
            if (n <= 0) return error.WriteFailed;
            sent += @intCast(n);
        }
    }

    fn fill(c: *TestImapsClient) !void {
        const n = std.c.read(c.fd, c.inbox[c.inbox_len..].ptr, c.inbox.len - c.inbox_len);
        if (n <= 0) return error.ServerClosed;
        c.inbox_len += @intCast(n);
    }

    fn consume(c: *TestImapsClient, n: usize) void {
        std.mem.copyForwards(u8, &c.inbox, c.inbox[n..c.inbox_len]);
        c.inbox_len -= n;
    }

    /// Read one cleartext line (before TLS) into `transcript`.
    fn readPlainLine(c: *TestImapsClient, transcript: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
        while (std.mem.indexOf(u8, c.inbox[0..c.inbox_len], "\r\n") == null) try c.fill();
        const end = std.mem.indexOf(u8, c.inbox[0..c.inbox_len], "\r\n").? + 2;
        try transcript.appendSlice(allocator, c.inbox[0..end]);
        c.consume(end);
    }

    /// Handshake, but hold back the final flight (the client Finished) and
    /// return it, so the caller decides how it reaches the server.
    ///
    /// `starttls` is a STARTTLS command line to send in the same write as the
    /// ClientHello; the server's cleartext answer to it goes to `transcript`.
    fn handshakeHoldingFinished(c: *TestImapsClient, starttls: []const u8, transcript: *std.ArrayList(u8), allocator: std.mem.Allocator, out: []u8) ![]const u8 {
        var cli = tls.nonblock.Client.init(.{
            .host = "localhost",
            .root_ca = .empty,
            .insecure_skip_verify = true,
        });
        var send_buf: [tls.output_buffer_len]u8 = undefined;
        var r = try cli.run(&.{}, &send_buf);
        @memcpy(out[0..starttls.len], starttls);
        @memcpy(out[starttls.len..][0..r.send.len], r.send);
        try c.writeAll(out[0 .. starttls.len + r.send.len]);
        if (starttls.len > 0) try c.readPlainLine(transcript, allocator);
        while (true) {
            r = try cli.run(c.inbox[0..c.inbox_len], &send_buf);
            c.consume(r.recv_pos);
            if (cli.done()) break;
            if (r.send.len > 0) try c.writeAll(r.send);
            if (r.recv_pos == 0 and r.send.len == 0) try c.fill();
        }
        c.conn = tls.nonblock.Connection.init(cli.cipher().?);
        @memcpy(out[0..r.send.len], r.send);
        return out[0..r.send.len];
    }

    fn encrypt(c: *TestImapsClient, cleartext: []const u8, out: []u8) ![]const u8 {
        const e = try c.conn.encrypt(cleartext, out);
        return e.ciphertext;
    }

    /// Read and decrypt until `needle` appears in what the server has sent.
    fn readUntil(c: *TestImapsClient, transcript: *std.ArrayList(u8), allocator: std.mem.Allocator, needle: []const u8) !void {
        var cleartext: [16384]u8 = undefined;
        while (std.mem.indexOf(u8, transcript.items, needle) == null) {
            const d = try c.conn.decrypt(c.inbox[0..c.inbox_len], &cleartext);
            try transcript.appendSlice(allocator, d.cleartext);
            c.consume(d.ciphertext_pos);
            if (d.closed) {
                if (std.mem.indexOf(u8, transcript.items, needle) == null) return error.ServerClosed;
                return;
            }
            if (d.ciphertext_pos == 0 and d.cleartext.len == 0) try c.fill();
        }
    }
};

test "IMAPS serves a command sent in the same segment as the client Finished" {
    // A client does not have to wait for the greeting before it writes: it
    // can put its first command in the same TCP segment as its Finished.
    // The handshake used to drop whatever followed the Finished. The command
    // went unanswered, and the next record was decrypted with the wrong
    // sequence number and failed as error.TlsBadRecordMac.
    const a = std.testing.allocator;
    const h = try ImapTestHarness.create(a);
    defer h.destroy();

    var server = ImapServer.init(a, .{ .enable_ssl = false }, &h.auth_backend, &h.db);
    defer server.deinit();
    server.cert_key_pair = try tls.config.CertKeyPair.fromPem(a, test_tls_cert_pem, test_tls_key_pem);

    var fds: [2]c_int = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, @intCast(@as(u32, std.posix.SOCK.STREAM)), 0, &fds) != 0) return error.SocketPairFailed;
    // Fail rather than hang when the server never answers.
    const timeout: std.posix.timeval = .{ .sec = 5, .usec = 0 };
    try std.posix.setsockopt(fds[1], std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));

    const thread = try std.Thread.spawn(.{}, struct {
        fn run(s: *ImapServer, fd: c_int) void {
            s.handleConnection(.{ .fd = fd }, true) catch {};
        }
    }.run, .{ &server, fds[0] });
    var client: TestImapsClient = .{ .fd = fds[1] };
    defer {
        _ = std.c.close(client.fd);
        thread.join();
    }

    var transcript: std.ArrayList(u8) = .empty;
    defer transcript.deinit(a);
    var flight: [tls.output_buffer_len + 256]u8 = undefined;
    const finished = try client.handshakeHoldingFinished("", &transcript, a, &flight);
    const command = try client.encrypt("a1 NOOP\r\n", flight[finished.len..]);
    try client.writeAll(flight[0 .. finished.len + command.len]);

    try client.readUntil(&transcript, a, "a1 OK");
    try ImapTestHarness.expectContains(transcript.items, "* OK");

    // The record after it has to decrypt too.
    var record: [256]u8 = undefined;
    try client.writeAll(try client.encrypt("a2 NOOP\r\n", &record));
    try client.readUntil(&transcript, a, "a2 OK");

    try client.writeAll(try client.encrypt("a3 LOGOUT\r\n", &record));
    try client.readUntil(&transcript, a, "a3 OK");
}

/// An IMAP server on one end of a socketpair, serving plaintext port 143
/// (with STARTTLS) on its own thread.
const TestPlainImap = struct {
    server: ImapServer,
    thread: std.Thread,
    client: TestImapsClient,

    fn start(t: *TestPlainImap, h: *ImapTestHarness) !void {
        const a = h.allocator;
        t.server = ImapServer.init(a, .{ .enable_ssl = false }, &h.auth_backend, &h.db);
        errdefer t.server.deinit();
        t.server.cert_key_pair = try tls.config.CertKeyPair.fromPem(a, test_tls_cert_pem, test_tls_key_pem);
        var fds: [2]c_int = undefined;
        if (std.c.socketpair(std.posix.AF.UNIX, @intCast(@as(u32, std.posix.SOCK.STREAM)), 0, &fds) != 0) return error.SocketPairFailed;
        const timeout: std.posix.timeval = .{ .sec = 5, .usec = 0 };
        try std.posix.setsockopt(fds[1], std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
        t.thread = try std.Thread.spawn(.{}, struct {
            fn run(s: *ImapServer, fd: c_int) void {
                s.handleConnection(.{ .fd = fd }, false) catch {};
            }
        }.run, .{ &t.server, fds[0] });
        t.client = .{ .fd = fds[1] };
    }

    fn stop(t: *TestPlainImap) void {
        _ = std.c.close(t.client.fd);
        t.thread.join();
        t.server.deinit();
    }
};

test "STARTTLS takes a ClientHello sent in the same segment as the command" {
    // RFC 3501 has the client wait for the tagged OK, but a client that sends
    // its ClientHello straight behind STARTTLS used to lose it: the plaintext
    // loop took the whole read as one command line, so the handshake never
    // saw the hello and both sides waited.
    const a = std.testing.allocator;
    const h = try ImapTestHarness.create(a);
    defer h.destroy();
    var t: TestPlainImap = undefined;
    try t.start(h);
    defer t.stop();

    var transcript: std.ArrayList(u8) = .empty;
    defer transcript.deinit(a);
    try t.client.readPlainLine(&transcript, a); // greeting

    var flight: [tls.output_buffer_len + 256]u8 = undefined;
    const finished = try t.client.handshakeHoldingFinished("a1 STARTTLS\r\n", &transcript, a, &flight);
    try ImapTestHarness.expectContains(transcript.items, "a1 OK");
    try t.client.writeAll(finished);

    var record: [256]u8 = undefined;
    try t.client.writeAll(try t.client.encrypt("a2 NOOP\r\n", &record));
    try t.client.readUntil(&transcript, a, "a2 OK");
    try t.client.writeAll(try t.client.encrypt("a3 LOGOUT\r\n", &record));
    try t.client.readUntil(&transcript, a, "a3 OK");
}

test "cleartext pipelined behind STARTTLS never runs as a command" {
    // The STARTTLS injection class: commands an attacker appends after
    // STARTTLS in cleartext must not execute, before or after the upgrade.
    // Pipelined commands ahead of STARTTLS are still each answered.
    const a = std.testing.allocator;
    const h = try ImapTestHarness.create(a);
    defer h.destroy();
    var t: TestPlainImap = undefined;
    try t.start(h);
    defer t.stop();

    try t.client.writeAll("a0 NOOP\r\na1 STARTTLS\r\na2 LOGOUT\r\n");
    var transcript: std.ArrayList(u8) = .empty;
    defer transcript.deinit(a);
    // Everything the server sends until it gives up on the handshake.
    while (true) {
        t.client.fill() catch break;
    }
    try transcript.appendSlice(a, t.client.inbox[0..t.client.inbox_len]);
    try ImapTestHarness.expectContains(transcript.items, "a0 OK");
    try ImapTestHarness.expectContains(transcript.items, "a1 OK");
    try std.testing.expect(std.mem.indexOf(u8, transcript.items, "a2") == null);
    try std.testing.expect(std.mem.indexOf(u8, transcript.items, "BYE") == null);
}
