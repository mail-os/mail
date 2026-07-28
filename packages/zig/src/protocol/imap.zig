const std = @import("std");
const builtin = @import("builtin");
const mutex_compat = @import("../core/mutex_compat.zig");
const posix = std.posix;
const time_compat = @import("../core/time_compat.zig");
const socket = @import("../core/socket_compat.zig");
const io_compat = @import("../core/io_compat.zig");
const auth = @import("../auth/auth.zig");
const logger = @import("../core/logger.zig");
const tls_mod = @import("../core/tls.zig");
const tls = @import("tls");
const fs_compat = @import("../core/fs_compat.zig");
const database = @import("../storage/database.zig");
const typesense = @import("../search/typesense.zig");

// std.posix.getpid is not available on this Zig version's std; libc is linked
// (the binary links sqlite3 + libc), so declare the C symbol directly.
extern "c" fn getpid() c_int;

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
    const name = stripQuotes(raw);
    if (name.len == 0 or name.len > 255) return false;
    if (name[0] == '.') return false;
    for (name) |c| {
        if (c == '/' or c == '\\' or c == 0) return false;
    }
    if (std.mem.indexOf(u8, name, "..") != null) return false;
    return true;
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
    pub fn toSuffix(self: MaildirFlags, buf: *[16]u8) []const u8 {
        var fbs = io_compat.fixedBufferStream(buf);
        const writer = fbs.writer();
        writer.writeAll(":2,") catch {};
        // Flags must be in alphabetical order per Maildir spec
        if (self.draft) writer.writeAll("D") catch {};
        if (self.flagged) writer.writeAll("F") catch {};
        if (self.answered) writer.writeAll("R") catch {};
        if (self.seen) writer.writeAll("S") catch {};
        if (self.deleted) writer.writeAll("T") catch {};
        return fbs.getWritten();
    }

    /// Apply a STORE flags action string to current flags.
    /// `action` looks like "+FLAGS (\\Seen \\Flagged)" or "-FLAGS.SILENT (\\Deleted)" etc.
    pub fn applyAction(self: *MaildirFlags, action: []const u8) void {
        const is_add = action.len > 0 and action[0] == '+';
        const is_remove = action.len > 0 and action[0] == '-';

        if (std.ascii.indexOfIgnoreCase(action, "\\Seen")) |_| {
            if (is_add) self.seen = true else if (is_remove) self.seen = false;
        }
        if (std.ascii.indexOfIgnoreCase(action, "\\Answered")) |_| {
            if (is_add) self.answered = true else if (is_remove) self.answered = false;
        }
        if (std.ascii.indexOfIgnoreCase(action, "\\Flagged")) |_| {
            if (is_add) self.flagged = true else if (is_remove) self.flagged = false;
        }
        if (std.ascii.indexOfIgnoreCase(action, "\\Draft")) |_| {
            if (is_add) self.draft = true else if (is_remove) self.draft = false;
        }
        if (std.ascii.indexOfIgnoreCase(action, "\\Deleted")) |_| {
            if (is_add) self.deleted = true else if (is_remove) self.deleted = false;
        }
        // For FLAGS (no + or -), replace all flags
        if (!is_add and !is_remove) {
            self.seen = std.ascii.indexOfIgnoreCase(action, "\\Seen") != null;
            self.answered = std.ascii.indexOfIgnoreCase(action, "\\Answered") != null;
            self.flagged = std.ascii.indexOfIgnoreCase(action, "\\Flagged") != null;
            self.draft = std.ascii.indexOfIgnoreCase(action, "\\Draft") != null;
            self.deleted = std.ascii.indexOfIgnoreCase(action, "\\Deleted") != null;
        }
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
    flags: ?[]const u8,
};

/// Parse the APPEND arguments that precede the `{N}` literal:
/// `mailbox [(\Flag ...)] ["date-time"]`. The mailbox may be quoted
/// (e.g. `"All Mail"`); the flag list and the obsolete date-time are
/// optional per RFC 3501 Section 6.3.11. The date-time is accepted and
/// ignored — filenames carry their own arrival timestamp.
fn parseAppendArgs(args_raw: []const u8) AppendArgs {
    const args = std.mem.trim(u8, args_raw, " \t");
    var result = AppendArgs{ .mailbox = "INBOX", .flags = null };
    if (args.len == 0) return result;

    var cursor: usize = 0;
    if (args[0] == '"') {
        if (std.mem.indexOfScalarPos(u8, args, 1, '"')) |q| {
            result.mailbox = args[1..q];
            cursor = q + 1;
        } else {
            // Unterminated quote — take the rest as the mailbox name.
            result.mailbox = args[1..];
            return result;
        }
    } else {
        const sp = std.mem.indexOfScalar(u8, args, ' ') orelse args.len;
        result.mailbox = args[0..sp];
        cursor = sp;
    }

    const tail = std.mem.trim(u8, args[cursor..], " \t");
    if (tail.len > 0 and tail[0] == '(') {
        if (std.mem.indexOfScalar(u8, tail, ')')) |cp| {
            result.flags = tail[1..cp];
        }
    }
    return result;
}

fn parseMessageSortKey(filename: []const u8) i64 {
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

/// Extract a quoted or unquoted argument from the remainder of a string.
/// e.g. `" \"hello world\" ..."` -> `"hello world"`, `" foo ..."` -> `"foo"`.
fn extractQuotedArg(rest: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, rest, " \t");
    if (trimmed.len == 0) return "";
    if (trimmed[0] == '"') {
        // Quoted: find closing quote
        if (std.mem.indexOfScalarPos(u8, trimmed, 1, '"')) |end| {
            return trimmed[1..end];
        }
        return trimmed[1..]; // unclosed quote — take rest
    }
    // Unquoted: take until space or end
    const end = std.mem.indexOfScalar(u8, trimmed, ' ') orelse trimmed.len;
    return trimmed[0..end];
}

/// Case-insensitively check whether `criteria` contains `keyword` as a
/// standalone token (delimited by start/end of string, whitespace, or
/// parentheses) rather than as a substring of a larger word. Used by SEARCH so
/// that e.g. a quoted search term cannot accidentally trigger a keyword match.
fn hasCriteriaToken(criteria: []const u8, keyword: []const u8) bool {
    if (keyword.len == 0) return false;
    var search_from: usize = 0;
    while (std.ascii.indexOfIgnoreCasePos(criteria, search_from, keyword)) |pos| {
        const before_ok = pos == 0 or isCriteriaDelimiter(criteria[pos - 1]);
        const after_idx = pos + keyword.len;
        const after_ok = after_idx >= criteria.len or isCriteriaDelimiter(criteria[after_idx]);
        if (before_ok and after_ok) return true;
        search_from = pos + 1;
    }
    return false;
}

fn isCriteriaDelimiter(c: u8) bool {
    return c == ' ' or c == '\t' or c == '(' or c == ')';
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

/// IMAP session
pub const ImapSession = struct {
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
    // Pending APPEND literal state
    append_tag: ?[]u8 = null,
    append_mailbox: ?[]u8 = null,
    append_flags: ?[]u8 = null,
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

    /// Build a collision-free Maildir-style destination path of the form
    /// `{dir}/{timestamp}.{pid}.{counter}.eml{flag_suffix}`. COPY/MOVE used to
    /// derive names purely from a millisecond timestamp, so two messages copied
    /// within the same millisecond (or whose timestamps overlapped via the
    /// `timestamp + n` offset) could produce the same filename and silently
    /// truncate-overwrite each other (createFile opens with O_TRUNC). We probe
    /// with access() and increment a counter until we find an unused name.
    /// Caller owns the returned slice.
    fn allocUniqueMaildirPath(self: *ImapSession, dir: []const u8, flag_suffix: []const u8) ![]u8 {
        const ts = time_compat.milliTimestamp();
        const pid: i64 = @intCast(getpid());
        var counter: u64 = 0;
        while (true) : (counter += 1) {
            const candidate = try std.fmt.allocPrint(self.allocator, "{s}/{d}.{d}.{d}.eml{s}", .{ dir, ts, pid, counter, flag_suffix });
            // If the file does not already exist, this name is free to use.
            fs_compat.cwd().access(candidate, .{}) catch {
                return candidate;
            };
            // Name taken — discard and try the next counter value.
            self.allocator.free(candidate);
            if (counter == std.math.maxInt(u64)) return error.PathAlreadyExists;
        }
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

        const root_z = try self.allocator.dupeZ(u8, root);
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
        } else {
            try self.appendAggregateFolder(&entries, "mail/new", "INBOX");
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

        // Fallback to the legacy global mail/new for INBOX if the user has none.
        if (entries.items.len == 0) {
            try self.appendInboxFolder(&entries, "mail/new");
        }

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
            const root = std.fmt.bufPrintZ(&root_buf, "mail/{s}", .{username}) catch return 0;

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
            } else {
                total = fs_compat.countEmlFiles("mail/new");
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
                if (total == 0) return fs_compat.countEmlFiles("mail/new");
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
            const root = std.fmt.bufPrintZ(&root_buf, "mail/{s}", .{username}) catch {
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
                    const folder_path = std.fmt.bufPrintZ(&folder_buf, "{s}/{s}", .{ root, folder }) catch continue;
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
            if (std.fmt.bufPrintZ(&new_buf, "mail/{s}/new", .{username})) |p| {
                if (addIdleWatchDir(fd, p)) watched += 1;
            } else |_| {}
            if (std.fmt.bufPrintZ(&cur_buf, "mail/{s}/cur", .{username})) |p| {
                if (addIdleWatchDir(fd, p)) watched += 1;
            } else |_| {}
        } else if (self.mailbox_dir) |dir| {
            var dir_buf: [1024]u8 = undefined;
            if (std.fmt.bufPrintZ(&dir_buf, "{s}", .{dir})) |p| {
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
        const n = std.c.poll(&fds, 2, 60_000);
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
        const count = self.currentMailboxEntryCount();
        if (self.idle_scan_count) |last| {
            if (count == last) return;
        }
        self.idle_scan_count = count;
        _ = self.rescanMailbox() catch {};
    }

    /// Re-scan the current mailbox for new messages.
    /// If the message count changed, sends untagged EXISTS/RECENT responses
    /// so the client knows to fetch new messages. Returns true if new mail found.
    fn rescanMailbox(self: *ImapSession) !bool {
        const old_count: usize = if (self.mailbox_files) |f| f.len else 0;

        if (self.mailbox_is_virtual) {
            const full_username = self.username orelse return false;
            const username = full_username;

            self.freeSelectedMessageLists();
            try self.loadAggregateMailboxFiles(username);
            self.syncUids() catch {};

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
                self.freeSelectedMessageLists();
                try self.loadInboxFiles(username);
                self.syncUids() catch {};
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

        // Re-read the maildir
        const new_files = fs_compat.listEmlFiles(self.allocator, dir) catch return false;
        const new_count = new_files.len;

        if (new_count != old_count) {
            // Free old file list (but keep mailbox_dir — it hasn't changed)
            if (self.mailbox_files) |old_files| {
                for (old_files) |f| self.allocator.free(f);
                self.allocator.free(old_files);
            }
            self.mailbox_files = if (new_count > 0) new_files else null;

            // Sync UIDs for new files
            self.syncUids() catch {};

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

        // No change — free the new list we just read
        for (new_files) |f| self.allocator.free(f);
        self.allocator.free(new_files);
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

        const username = self.username orelse {
            try self.sendResponse(tag, "NO", "Not authenticated");
            self.cleanupAppend();
            return;
        };

        if (!isSafeMailboxName(mailbox)) {
            try self.sendResponse(tag, "NO", "Invalid mailbox name");
            self.cleanupAppend();
            return;
        }

        // Extract local part from email address (chris@stacksjs.com -> chris)
        const local_part = username;

        // Determine folder directory
        const folder_dir = if (std.ascii.eqlIgnoreCase(mailbox, "INBOX"))
            try std.fmt.allocPrint(self.allocator, "mail/{s}/new", .{local_part})
        else
            try std.fmt.allocPrint(self.allocator, "mail/{s}/{s}", .{ local_part, mailbox });
        defer self.allocator.free(folder_dir);

        // Create directory if it doesn't exist
        fs_compat.cwd().makePath(folder_dir) catch {};

        // Write message file with timestamp-based name, honoring the flags
        // from the APPEND command (e.g. APPEND "Sent" (\Seen) {...}). Without
        // this, sent/draft copies saved by clients land on disk flagless and
        // surface as "unread" in folder counts (STATUS UNSEEN, webmail, and
        // client badges such as Apple Mail's).
        var msg_flags = MaildirFlags{};
        if (self.append_flags) |fs| {
            // No +/- prefix: applyAction treats the list as the full flag set.
            msg_flags.applyAction(fs);
        } else if (std.ascii.eqlIgnoreCase(mailbox, "Sent") or std.ascii.eqlIgnoreCase(mailbox, "Drafts")) {
            // Clients that omit the flag list for Sent/Drafts still expect
            // those copies to be read — they are the user's own messages.
            msg_flags.seen = true;
        }
        const timestamp = time_compat.milliTimestamp();
        var name_buf: [640]u8 = undefined;
        const file_name = if (msg_flags.seen or msg_flags.answered or msg_flags.flagged or msg_flags.draft or msg_flags.deleted) blk: {
            var suffix_buf: [16]u8 = undefined;
            break :blk std.fmt.bufPrint(&name_buf, "{d}.eml{s}", .{ timestamp, msg_flags.toSuffix(&suffix_buf) }) catch {
                try self.sendResponse(tag, "NO", "Failed to save message");
                self.cleanupAppend();
                return;
            };
        } else std.fmt.bufPrint(&name_buf, "{d}.eml", .{timestamp}) catch {
            try self.sendResponse(tag, "NO", "Failed to save message");
            self.cleanupAppend();
            return;
        };
        const filepath = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ folder_dir, file_name });
        defer self.allocator.free(filepath);

        const file = fs_compat.cwd().createFile(filepath, .{}) catch {
            try self.sendResponse(tag, "NO", "Failed to save message");
            self.cleanupAppend();
            return;
        };
        defer file.close();
        file.writeAll(data[0..size]) catch {
            try self.sendResponse(tag, "NO", "Failed to write message");
            self.cleanupAppend();
            return;
        };

        std.log.info("IMAP APPEND: Saved {d} bytes to {s}", .{ size, filepath });

        // The UID key for this message is its on-disk base filename (matching
        // how syncUids/getUidForFile key the imap_uids table).
        const uid_key = std.fs.path.basename(filepath);

        // Index for full-text search (best-effort, detached thread)
        typesense.indexMessageAsync(
            self.allocator,
            local_part,
            if (std.ascii.eqlIgnoreCase(mailbox, "INBOX")) "INBOX" else mailbox,
            uid_key,
            data[0..size],
        );

        // Use the mailbox's real UIDVALIDITY (matching SELECT/STATUS) so clients
        // don't invalidate their UID cache for the folder after an append.
        const append_canon = if (std.ascii.eqlIgnoreCase(mailbox, "All Mail") or std.ascii.eqlIgnoreCase(mailbox, "All"))
            "All Mail"
        else if (std.ascii.eqlIgnoreCase(mailbox, "INBOX"))
            "INBOX"
        else
            mailbox;

        // Assign a real UID via the database (matching SELECT/FETCH). Only
        // report APPENDUID when we actually have an authoritative UID; never
        // fabricate one from the file count.
        var append_uidvalidity: i64 = 0;
        var assigned_uid: ?i64 = null;
        if (self.db) |db| {
            if (db.getOrCreateMailbox(local_part, append_canon)) |info| {
                append_uidvalidity = info.uidvalidity;
                if (db.assignUid(local_part, append_canon, uid_key)) |new_uid| {
                    assigned_uid = new_uid;
                } else |_| {}
            } else |_| {}
        }

        // Send OK, including APPENDUID only when we have a real UID/UIDVALIDITY.
        if (assigned_uid) |uid| {
            var resp_buf: [256]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&resp_buf);
            fbs.writer().print("[APPENDUID {d} {d}] APPEND completed", .{ append_uidvalidity, uid }) catch {
                try self.sendResponse(tag, "OK", "APPEND completed");
                self.cleanupAppend();
                return;
            };
            try self.sendResponse(tag, "OK", fbs.getWritten());
        } else {
            try self.sendResponse(tag, "OK", "APPEND completed");
        }
        self.cleanupAppend();
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
        const path_z = self.allocator.dupeZ(u8, root) catch return stats;
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

        const path_z = self.allocator.dupeZ(u8, root) catch return stats;
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
        const greeting = "* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN AUTH=LOGIN IDLE NAMESPACE UIDPLUS SPECIAL-USE MOVE] Mail Server IMAP4rev1 ready\r\n";
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
            const attrs = folder_type.getAttributes();
            const name = folder_type.getName();
            if (!matchListPattern(clean_pattern, name)) continue;

            var buf: [512]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&buf);
            const writer = fbs.writer();
            try writer.print("LIST ({s}) \"/\" \"{s}\"", .{ attrs, name });
            try self.sendUntagged(fbs.getWritten());
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
            if (is_standard) continue;

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

        const stats = self.countMailboxStats(clean_mailbox);

        // Derive UIDVALIDITY/UIDNEXT from the database so STATUS matches what
        // SELECT reports. If STATUS advertises different values than SELECT,
        // clients such as Apple Mail treat the mailbox as invalidated on every
        // poll, repeatedly discard their cache, and fail to show unread counts.
        const canonical_mailbox = if (std.ascii.eqlIgnoreCase(clean_mailbox, "All Mail") or std.ascii.eqlIgnoreCase(clean_mailbox, "All"))
            "All Mail"
        else if (std.ascii.eqlIgnoreCase(clean_mailbox, "INBOX"))
            "INBOX"
        else
            clean_mailbox;
        var uidvalidity: i64 = 1;
        var uidnext: i64 = @as(i64, @intCast(stats.messages)) + 1;
        if (self.db) |db| {
            if (self.username) |full_username| {
                const local_part = full_username;
                if (db.getOrCreateMailbox(local_part, canonical_mailbox)) |info| {
                    uidvalidity = info.uidvalidity;
                    if (db.getUidNext(local_part, canonical_mailbox)) |next| {
                        uidnext = next;
                    } else |_| {}
                } else |_| {}
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
        const valid = self.auth_backend.verifyCredentials(username, password) catch |err| {
            std.log.err("Authentication error: {}", .{err});
            try self.sendResponse(tag, "NO", "LOGIN failed");
            return;
        };

        if (!valid) {
            std.log.warn("Failed IMAP authentication from {s}", .{self.connection.peerIp()});
            try self.sendResponse(tag, "NO", "LOGIN failed");
            return;
        }

        // Store the canonical mailbox key (a registered full address stays a
        // full address — a per-domain isolated mailbox; otherwise the local-part,
        // keeping legacy single-namespace behaviour). The maildir is keyed by this.
        self.username = try self.auth_backend.canonicalUsername(username, self.allocator);
        self.state = .authenticated;

        std.log.info("Successful IMAP login for user: {s}", .{username});
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

            const valid = self.auth_backend.verifyCredentials(username, password) catch {
                try self.sendResponse(tag, "NO", "Authentication failed");
                return;
            };
            if (!valid) {
                std.log.warn("Failed IMAP authentication from {s}", .{self.connection.peerIp()});
                try self.sendResponse(tag, "NO", "Authentication failed");
                return;
            }

            self.username = self.auth_backend.canonicalUsername(username, self.allocator) catch {
                try self.sendResponse(tag, "NO", "Internal error");
                return;
            };
            self.state = .authenticated;
            std.log.info("Successful IMAP AUTH LOGIN", .{});
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
        const valid = self.auth_backend.verifyCredentials(credentials.username, credentials.password) catch {
            try self.sendResponse(tag, "NO", "Authentication failed");
            return;
        };

        if (!valid) {
            std.log.warn("Failed IMAP authentication from {s}", .{self.connection.peerIp()});
            try self.sendResponse(tag, "NO", "Authentication failed");
            return;
        }

        self.username = self.auth_backend.canonicalUsername(credentials.username, self.allocator) catch {
            try self.sendResponse(tag, "NO", "Internal error");
            return;
        };
        self.state = .authenticated;

        std.log.info("Successful IMAP AUTHENTICATE for user: {s}", .{credentials.username});
        try self.sendResponse(tag, "OK", "AUTHENTICATE completed");
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
        const is_all_mail = std.ascii.eqlIgnoreCase(mailbox, "All Mail") or std.ascii.eqlIgnoreCase(mailbox, "All");

        // Store mailbox name for UID persistence
        const canonical_mailbox = if (is_all_mail) "All Mail" else if (std.ascii.eqlIgnoreCase(mailbox, "INBOX")) "INBOX" else mailbox;
        self.mailbox_name = try self.allocator.dupe(u8, canonical_mailbox);

        if (is_all_mail) {
            self.mailbox_is_virtual = true;
            self.mailbox_dir = try std.fmt.allocPrint(self.allocator, "mail/{s}", .{username});
            try self.loadAggregateMailboxFiles(username);

            const msg_count = if (self.mailbox_files) |f| f.len else 0;
            self.syncUids() catch {};
            // RECENT reported as 0 (see note in the INBOX branch below).
            try self.sendSelectResponse(tag, username, msg_count, 0);
            return;
        }

        const is_inbox = std.ascii.eqlIgnoreCase(mailbox, "INBOX");

        if (is_inbox) {
            // INBOX aggregates the maildir new/ and cur/ directories so messages
            // are not lost if they are ever moved into cur/. mailbox_dir points
            // at new/ (where fresh mail is delivered) for rescan purposes.
            self.mailbox_dir = try std.fmt.allocPrint(self.allocator, "mail/{s}/new", .{username});
            try self.loadInboxFiles(username);
            const msg_count = if (self.mailbox_files) |f| f.len else 0;
            self.syncUids() catch {};
            // RECENT is reported as 0: this server does not track the \Recent
            // flag, and reporting the unseen count as RECENT made clients
            // re-trigger "new mail" on every SELECT. Unread state is conveyed
            // via UNSEEN and per-message \Seen flags instead.
            try self.sendSelectResponse(tag, username, msg_count, 0);
            return;
        }

        // Non-INBOX folders store messages directly in the folder directory.
        const user_dir = try std.fmt.allocPrint(self.allocator, "mail/{s}/{s}", .{ username, mailbox });

        // Ensure directory exists for standard mailboxes (Sent, Drafts, Trash, Junk, Archive)
        fs_compat.ensureDir(user_dir) catch {};

        const files = fs_compat.listEmlFiles(self.allocator, user_dir) catch {
            // Directory doesn't exist or can't be read — treat as empty
            self.mailbox_dir = user_dir;
            self.mailbox_files = null;
            try self.sendSelectResponse(tag, username, 0, 0);
            return;
        };
        self.mailbox_dir = user_dir;
        self.mailbox_files = if (files.len > 0) files else null;
        if (files.len == 0) {
            self.allocator.free(files);
        }

        const msg_count = if (self.mailbox_files) |f| f.len else 0;
        self.syncUids() catch {};
        try self.sendSelectResponse(tag, username, msg_count, 0);
    }

    /// Send the SELECT/EXAMINE response with proper UIDVALIDITY and UIDNEXT.
    fn sendSelectResponse(self: *ImapSession, tag: []const u8, username: []const u8, msg_count: usize, recent_count: usize) !void {
        const exists_msg = try std.fmt.allocPrint(self.allocator, "{d} EXISTS", .{msg_count});
        defer self.allocator.free(exists_msg);
        try self.sendUntagged(exists_msg);

        const recent_msg = try std.fmt.allocPrint(self.allocator, "{d} RECENT", .{recent_count});
        defer self.allocator.free(recent_msg);
        try self.sendUntagged(recent_msg);

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

        // Get UIDVALIDITY and UIDNEXT from database
        const mbox_name = self.mailbox_name orelse "INBOX";
        var uidvalidity: i64 = 1;
        var uidnext: i64 = @as(i64, @intCast(msg_count)) + 1;
        if (self.db) |db| {
            if (db.getOrCreateMailbox(username, mbox_name)) |info| {
                uidvalidity = info.uidvalidity;
                if (db.getUidNext(username, mbox_name)) |next| {
                    uidnext = next;
                } else |_| {}
            } else |_| {}
            self.mailbox_uidvalidity = uidvalidity;
        }

        const uidvalidity_msg = try std.fmt.allocPrint(self.allocator, "OK [UIDVALIDITY {d}]", .{uidvalidity});
        defer self.allocator.free(uidvalidity_msg);
        try self.sendUntagged(uidvalidity_msg);

        const uidnext_msg = try std.fmt.allocPrint(self.allocator, "OK [UIDNEXT {d}]", .{uidnext});
        defer self.allocator.free(uidnext_msg);
        try self.sendUntagged(uidnext_msg);

        try self.sendUntagged("FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)");
        try self.sendUntagged("OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)]");

        self.state = .selected;
        try self.sendResponse(tag, "OK", if (self.mailbox_read_only) "[READ-ONLY] EXAMINE completed" else "[READ-WRITE] SELECT completed");
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

        // Parse sequence set (supports "n", "n:m", "n:*")
        var start: usize = 1;
        var end: usize = files.len;

        if (std.mem.indexOf(u8, sequence_set, ":")) |colon| {
            start = std.fmt.parseInt(usize, sequence_set[0..colon], 10) catch 1;
            const end_str = sequence_set[colon + 1 ..];
            if (std.mem.eql(u8, end_str, "*")) {
                end = files.len;
            } else {
                end = std.fmt.parseInt(usize, end_str, 10) catch files.len;
            }
        } else {
            start = std.fmt.parseInt(usize, sequence_set, 10) catch 1;
            end = start;
        }

        if (start < 1) start = 1;
        if (end > files.len) end = files.len;

        // RFC 3501 Section 6.4.5: BODY[] (without .PEEK) implicitly sets \Seen flag
        const is_peek = std.mem.indexOf(u8, items_raw, "BODY.PEEK") != null;
        const has_body_fetch = std.mem.indexOf(u8, items_raw, "BODY[") != null or
            (std.mem.indexOf(u8, items_raw, "RFC822") != null and
                std.mem.indexOf(u8, items_raw, "RFC822.SIZE") == null and
                std.mem.indexOf(u8, items_raw, "RFC822.HEADER") == null);
        const should_set_seen = has_body_fetch and !is_peek and !self.mailbox_read_only;

        // Determine what to fetch based on items
        const want_internaldate = std.mem.indexOf(u8, items_raw, "INTERNALDATE") != null;
        // BODY.PEEK[HEADER] or BODY[HEADER] - wants headers only
        const want_header_only = std.mem.indexOf(u8, items_raw, "HEADER") != null;
        // Detect any BODY[...] request for content (including numbered parts like BODY[1], BODY.PEEK[1.1])
        const has_body_section = blk: {
            // Look for BODY[ or BODY.PEEK[ followed by a digit (numbered MIME part)
            var i: usize = 0;
            while (i < items_raw.len) {
                if (std.mem.startsWith(u8, items_raw[i..], "BODY[") or
                    std.mem.startsWith(u8, items_raw[i..], "BODY.PEEK["))
                {
                    const bracket_start = std.mem.indexOfScalarPos(u8, items_raw, i, '[') orelse {
                        i += 1;
                        continue;
                    };
                    const after_bracket = bracket_start + 1;
                    if (after_bracket < items_raw.len and items_raw[after_bracket] >= '0' and items_raw[after_bracket] <= '9') {
                        break :blk true;
                    }
                }
                i += 1;
            }
            break :blk false;
        };
        // BODY.PEEK[] or BODY[] or BODY[TEXT] or BODY.PEEK[TEXT] or BODY[n] or RFC822 (not RFC822.SIZE) - wants full body
        const want_full_body = has_body_section or
            (std.mem.indexOf(u8, items_raw, "BODY.PEEK[]") != null) or
            (std.mem.indexOf(u8, items_raw, "BODY[]") != null) or
            (std.mem.indexOf(u8, items_raw, "BODY[TEXT]") != null) or
            (std.mem.indexOf(u8, items_raw, "BODY.PEEK[TEXT]") != null) or
            (std.mem.indexOf(u8, items_raw, "RFC822") != null and
                std.mem.indexOf(u8, items_raw, "RFC822.SIZE") == null and
                std.mem.indexOf(u8, items_raw, "RFC822.HEADER") == null);
        const want_bodystructure = std.mem.indexOf(u8, items_raw, "BODYSTRUCTURE") != null;
        // BODY[TEXT] or BODY.PEEK[TEXT] — return body only (after headers), not full message
        const want_body_text_only = (std.mem.indexOf(u8, items_raw, "BODY[TEXT]") != null) or
            (std.mem.indexOf(u8, items_raw, "BODY.PEEK[TEXT]") != null);

        // Parse partial fetch <offset.count> if present
        var partial_offset: ?usize = null;
        var partial_count: ?usize = null;
        if (std.mem.indexOf(u8, items_raw, "<")) |angle_start| {
            if (std.mem.indexOfScalarPos(u8, items_raw, angle_start, '>')) |angle_end| {
                const partial_spec = items_raw[angle_start + 1 .. angle_end];
                if (std.mem.indexOf(u8, partial_spec, ".")) |dot| {
                    partial_offset = std.fmt.parseInt(usize, partial_spec[0..dot], 10) catch null;
                    partial_count = std.fmt.parseInt(usize, partial_spec[dot + 1 ..], 10) catch null;
                }
            }
        }

        // Detect if we only need metadata (FLAGS, UID, RFC822.SIZE) — no file content read needed
        const want_rfc822_size = std.mem.indexOf(u8, items_raw, "RFC822.SIZE") != null;
        const metadata_only = !want_full_body and !want_header_only and !want_bodystructure and !want_body_text_only;

        var seq = start;
        while (seq <= end) : (seq += 1) {
            const filename = files[seq - 1];
            const uid = self.getUidForSeq(seq);

            // For metadata-only requests (FLAGS, UID, RFC822.SIZE), skip reading file content
            if (metadata_only) {
                const msg_flags = MaildirFlags.fromFilename(filename);
                var flag_str_buf: [256]u8 = undefined;
                const flag_str = msg_flags.toImapString(&flag_str_buf);

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
            const header_end = if (std.mem.indexOf(u8, content, "\r\n\r\n")) |pos|
                pos + 4
            else if (std.mem.indexOf(u8, content, "\n\n")) |pos|
                pos + 2
            else
                content.len;

            const header = content[0..header_end];
            const body = content[header_end..];

            // Extract INTERNALDATE - try filename timestamp first, then Date header
            var date_buf: [64]u8 = undefined;
            var date_str: []const u8 = "01-Jan-2026 00:00:00 +0000";
            // Try to parse epoch millis from filename (e.g., "1772259313773.eml")
            const basename = if (std.mem.lastIndexOfScalar(u8, filename, '/')) |pos| filename[pos + 1 ..] else filename;
            const base_no_flags = MaildirFlags.baseName(basename);
            const name_no_ext = if (std.mem.endsWith(u8, base_no_flags, ".eml")) base_no_flags[0 .. base_no_flags.len - 4] else base_no_flags;
            if (std.fmt.parseInt(i64, name_no_ext, 10)) |epoch_ms| {
                date_str = formatImapDate(@divFloor(epoch_ms, 1000), &date_buf);
            } else |_| {
                // Try Date header
                if (std.mem.indexOf(u8, header, "Date: ")) |date_pos| {
                    const date_start = date_pos + 6;
                    const date_line_end = std.mem.indexOfScalarPos(u8, header, date_start, '\r') orelse
                        std.mem.indexOfScalarPos(u8, header, date_start, '\n') orelse header.len;
                    const raw_date = header[date_start..date_line_end];
                    // Try to parse RFC 2822 date and reformat
                    date_str = parseAndFormatRfc2822Date(raw_date, &date_buf) orelse raw_date;
                }
            }

            // Determine content type for BODYSTRUCTURE
            var content_type: []const u8 = "text/plain";
            var charset: []const u8 = "UTF-8";
            if (std.mem.indexOf(u8, header, "Content-Type: ")) |ct_pos| {
                const ct_start = ct_pos + 14;
                const ct_end = std.mem.indexOfScalarPos(u8, header, ct_start, '\r') orelse
                    std.mem.indexOfScalarPos(u8, header, ct_start, '\n') orelse header.len;
                content_type = header[ct_start..ct_end];
                if (std.mem.indexOf(u8, content_type, "charset=")) |cs_pos| {
                    charset = std.mem.trim(u8, content_type[cs_pos + 8 ..], " \t\"");
                    if (std.mem.indexOfScalar(u8, charset, ';')) |semi| {
                        charset = charset[0..semi];
                    }
                }
            }

            // Determine if multipart
            const is_multipart = std.mem.indexOf(u8, content_type, "multipart/") != null;
            const is_html = std.mem.indexOf(u8, content_type, "text/html") != null;

            // Sanitize the charset so it can be safely emitted inside an IMAP
            // quoted-string. A charset is an atom-like token; if it contains
            // characters that would need quoting/escaping (quotes, backslash,
            // control chars, whitespace) we fall back to a safe default rather
            // than risk producing a malformed BODYSTRUCTURE response.
            const safe_charset = blk_cs: {
                if (charset.len == 0 or charset.len > 64) break :blk_cs "UTF-8";
                for (charset) |c| {
                    if (c == '"' or c == '\\' or c <= ' ' or c == 0x7f) break :blk_cs "UTF-8";
                }
                break :blk_cs charset;
            };

            // Build BODYSTRUCTURE string into a heap buffer (no fixed-size
            // truncation). The previous fixed 512-byte buffer with `catch {}`
            // would silently drop the structure for large values.
            const bodystructure = if (is_multipart)
                std.fmt.allocPrint(self.allocator, "((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"{s}\") NIL NIL \"7BIT\" {d} {d} NIL NIL NIL NIL)(\"TEXT\" \"HTML\" (\"CHARSET\" \"{s}\") NIL NIL \"7BIT\" {d} {d} NIL NIL NIL NIL) \"ALTERNATIVE\")", .{
                    safe_charset, body.len, body.len / 40 + 1, safe_charset, body.len, body.len / 40 + 1,
                }) catch try self.allocator.dupe(u8, "")
            else if (is_html)
                std.fmt.allocPrint(self.allocator, "(\"TEXT\" \"HTML\" (\"CHARSET\" \"{s}\") NIL NIL \"7BIT\" {d} {d} NIL NIL NIL NIL)", .{
                    safe_charset, body.len, body.len / 40 + 1,
                }) catch try self.allocator.dupe(u8, "")
            else
                std.fmt.allocPrint(self.allocator, "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"{s}\") NIL NIL \"7BIT\" {d} {d} NIL NIL NIL NIL)", .{
                    safe_charset, body.len, body.len / 40 + 1,
                }) catch try self.allocator.dupe(u8, "");
            defer self.allocator.free(bodystructure);

            // Read actual flags from Maildir filename
            var msg_flags = MaildirFlags.fromFilename(filename);

            // RFC 3501: BODY[] (non-PEEK) implicitly sets \Seen
            if (should_set_seen and !msg_flags.seen) {
                msg_flags.seen = true;
                const base = MaildirFlags.baseName(filename);
                var suffix_buf: [16]u8 = undefined;
                const suffix = msg_flags.toSuffix(&suffix_buf);
                var new_name_buf: [512]u8 = undefined;
                const new_name = std.fmt.bufPrint(&new_name_buf, "{s}{s}", .{ base, suffix }) catch filename;
                if (!std.mem.eql(u8, filename, new_name)) {
                    const dir = self.selectedMessageDirForIndex(seq - 1);
                    const old_path = if (dir) |d| std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ d, filename }) catch null else null;
                    const new_path = if (dir) |d| std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ d, new_name }) catch null else null;
                    if (old_path != null and new_path != null) {
                        if (renameFile(old_path.?, new_path.?)) {
                            // Update cached filename
                            const mutable_files = @constCast(files);
                            const owned_new = self.allocator.dupe(u8, new_name) catch new_name;
                            if (owned_new.ptr != new_name.ptr) {
                                self.allocator.free(filename);
                                mutable_files[seq - 1] = owned_new;
                            }
                        }
                    }
                    if (old_path) |p| self.allocator.free(p);
                    if (new_path) |p| self.allocator.free(p);
                }
            }

            var flag_str_buf: [256]u8 = undefined;
            const flag_str = msg_flags.toImapString(&flag_str_buf);

            // Build optional parts. Allocate dynamically so a long
            // BODYSTRUCTURE is not truncated by a fixed-size buffer.
            const bs_part = if (want_bodystructure)
                std.fmt.allocPrint(self.allocator, " BODYSTRUCTURE {s}", .{bodystructure}) catch try self.allocator.dupe(u8, "")
            else
                try self.allocator.dupe(u8, "");
            defer self.allocator.free(bs_part);

            var id_part_buf: [128]u8 = undefined;
            const id_part = if (want_internaldate) blk: {
                var ifbs = io_compat.fixedBufferStream(&id_part_buf);
                ifbs.writer().print(" INTERNALDATE \"{s}\"", .{date_str}) catch break :blk @as([]const u8, "");
                break :blk ifbs.getWritten();
            } else @as([]const u8, "");

            // Determine the BODY section specifier to echo back in the response
            const body_section: []const u8 = if (has_body_section) blk: {
                // Extract the section from the request (e.g., "BODY[1]" -> "1", "BODY.PEEK[1.1]" -> "1.1")
                // For numbered parts on simple messages, return the body text
                break :blk "TEXT";
            } else "";

            // Build FETCH response
            if (want_header_only and !want_full_body) {
                const resp = try std.fmt.allocPrint(self.allocator, "* {d} FETCH (UID {d} FLAGS ({s}) RFC822.SIZE {d}{s}{s} BODY[HEADER] {{{d}}}\r\n{s})", .{
                    seq, uid, flag_str, content.len, id_part, bs_part, header.len, header,
                });
                defer self.allocator.free(resp);
                try self.writeData(resp);
                try self.writeData("\r\n");
            } else if (want_body_text_only) {
                // BODY[TEXT] or BODY.PEEK[TEXT] — return just the body (after headers)
                // Apply partial fetch <offset.count> if requested
                const text_data = if (partial_offset) |off| blk: {
                    if (off >= body.len) break :blk @as([]const u8, "");
                    const remaining = body[off..];
                    if (partial_count) |cnt| {
                        break :blk remaining[0..@min(cnt, remaining.len)];
                    }
                    break :blk remaining;
                } else body;
                const section_tag = if (partial_offset) |off| blk: {
                    break :blk std.fmt.allocPrint(self.allocator, "BODY[TEXT]<{d}>", .{off}) catch "BODY[TEXT]";
                } else @as([]const u8, "BODY[TEXT]");
                defer if (partial_offset != null) {
                    if (!std.mem.eql(u8, section_tag, "BODY[TEXT]")) self.allocator.free(section_tag);
                };
                const resp = try std.fmt.allocPrint(self.allocator, "* {d} FETCH (UID {d} FLAGS ({s}) RFC822.SIZE {d} INTERNALDATE \"{s}\"{s} {s} {{{d}}}\r\n{s})", .{
                    seq, uid, flag_str, content.len, date_str, bs_part, section_tag, text_data.len, text_data,
                });
                defer self.allocator.free(resp);
                try self.writeData(resp);
                try self.writeData("\r\n");
            } else if (want_full_body and has_body_section) {
                // Numbered MIME part request — return body text
                const resp = try std.fmt.allocPrint(self.allocator, "* {d} FETCH (UID {d} FLAGS ({s}) RFC822.SIZE {d} INTERNALDATE \"{s}\"{s} BODY[{s}] {{{d}}}\r\n{s})", .{
                    seq, uid, flag_str, content.len, date_str, bs_part, body_section, body.len, body,
                });
                defer self.allocator.free(resp);
                try self.writeData(resp);
                try self.writeData("\r\n");
            } else if (want_full_body) {
                // Apply partial fetch <offset.count> if requested
                const fetch_data = if (partial_offset) |off| blk: {
                    if (off >= content.len) break :blk @as([]const u8, "");
                    const remaining = content[off..];
                    if (partial_count) |cnt| {
                        break :blk remaining[0..@min(cnt, remaining.len)];
                    }
                    break :blk remaining;
                } else content;
                const body_tag = if (partial_offset) |off| blk: {
                    break :blk std.fmt.allocPrint(self.allocator, "BODY[]<{d}>", .{off}) catch "BODY[]";
                } else @as([]const u8, "BODY[]");
                defer if (partial_offset != null) {
                    if (!std.mem.eql(u8, body_tag, "BODY[]")) self.allocator.free(body_tag);
                };
                const resp = try std.fmt.allocPrint(self.allocator, "* {d} FETCH (UID {d} FLAGS ({s}) RFC822.SIZE {d} INTERNALDATE \"{s}\"{s} {s} {{{d}}}\r\n{s})", .{
                    seq, uid, flag_str, content.len, date_str, bs_part, body_tag, fetch_data.len, fetch_data,
                });
                defer self.allocator.free(resp);
                try self.writeData(resp);
                try self.writeData("\r\n");
            } else {
                const resp = try std.fmt.allocPrint(self.allocator, "* {d} FETCH (UID {d} FLAGS ({s}) RFC822.SIZE {d}{s}{s})", .{
                    seq, uid, flag_str, content.len, id_part, bs_part,
                });
                defer self.allocator.free(resp);
                try self.writeData(resp);
                try self.writeData("\r\n");
            }
        }

        try self.sendResponse(tag, "OK", "FETCH completed");
    }

    /// Handle SEARCH command — evaluate criteria against messages.
    /// Supports: ALL, SEEN, UNSEEN, FLAGGED, UNFLAGGED, DELETED, UNDELETED,
    /// ANSWERED, UNANSWERED, DRAFT, UNDRAFT, FROM, SUBJECT, SINCE, BEFORE.
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

    /// Find `keyword` as a standalone criteria token and return the index
    /// just past it (where its argument starts), or null.
    fn findCriteriaToken(criteria: []const u8, keyword: []const u8) ?usize {
        var search_from: usize = 0;
        while (std.ascii.indexOfIgnoreCasePos(criteria, search_from, keyword)) |pos| {
            const before_ok = pos == 0 or isCriteriaDelimiter(criteria[pos - 1]);
            const after_idx = pos + keyword.len;
            const after_ok = after_idx >= criteria.len or isCriteriaDelimiter(criteria[after_idx]);
            if (before_ok and after_ok) return after_idx;
            search_from = pos + 1;
        }
        return null;
    }

    /// Run the text criteria (FROM/TO/SUBJECT/BODY/TEXT) against the
    /// Typesense index, intersecting per-criterion result sets (IMAP
    /// criteria are ANDed). Returns null when no text criterion is present;
    /// errors bubble up so the caller can fall back to the file scan.
    /// Keys are owned base filenames (free each + deinit).
    fn typesenseSearchMatches(self: *ImapSession, criteria: []const u8) !?std.StringHashMap(void) {
        const ident = self.searchIdentity() orelse return null;

        const Criterion = struct { keyword: []const u8, query_by: []const u8 };
        const criterion_table = [_]Criterion{
            .{ .keyword = "FROM", .query_by = "sender" },
            .{ .keyword = "SUBJECT", .query_by = "subject" },
            .{ .keyword = "TO", .query_by = "recipients" },
            .{ .keyword = "BODY", .query_by = "body" },
            .{ .keyword = "TEXT", .query_by = "subject,sender,recipients,body" },
        };

        var result: ?std.StringHashMap(void) = null;
        errdefer if (result) |*m| freeMatchSet(self.allocator, m);

        for (criterion_table) |c| {
            const arg_start = findCriteriaToken(criteria, c.keyword) orelse continue;
            const term = extractQuotedArg(criteria[arg_start..]);
            if (term.len == 0) continue;

            const names = try typesense.searchFilenames(self.allocator, ident.username, ident.mailbox, term, c.query_by);
            defer {
                for (names) |n| self.allocator.free(n);
                self.allocator.free(names);
            }

            if (result == null) {
                var m = std.StringHashMap(void).init(self.allocator);
                errdefer freeMatchSet(self.allocator, &m);
                for (names) |n| {
                    if (m.contains(n)) continue;
                    const key = try self.allocator.dupe(u8, n);
                    errdefer self.allocator.free(key);
                    try m.put(key, {});
                }
                result = m;
            } else {
                // Intersect: drop existing keys absent from this criterion's hits
                var keep = std.StringHashMap(void).init(self.allocator);
                defer keep.deinit();
                for (names) |n| try keep.put(n, {});

                var stale: std.ArrayList([]const u8) = .empty;
                defer stale.deinit(self.allocator);
                var it = result.?.keyIterator();
                while (it.next()) |k| {
                    if (!keep.contains(k.*)) try stale.append(self.allocator, k.*);
                }
                for (stale.items) |k| {
                    if (result.?.fetchRemove(k)) |removed| self.allocator.free(removed.key);
                }
            }
        }

        return result;
    }

    fn freeMatchSet(allocator: std.mem.Allocator, m: *std.StringHashMap(void)) void {
        var it = m.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
        m.deinit();
    }

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

        const files = self.mailbox_files orelse {
            try self.sendUntagged("SEARCH");
            try self.sendResponse(tag, "OK", "SEARCH completed");
            return;
        };

        // Parse criteria (case insensitive). Match keywords as whitespace- or
        // paren-delimited tokens, not bare substrings, so a FROM/SUBJECT term
        // like "marshall" cannot be mistaken for the ALL key (which would
        // otherwise match every message).
        const is_all = criteria.len == 0 or hasCriteriaToken(criteria, "ALL");
        const want_seen = std.ascii.indexOfIgnoreCase(criteria, "SEEN") != null and
            std.ascii.indexOfIgnoreCase(criteria, "UNSEEN") == null;
        const want_unseen = std.ascii.indexOfIgnoreCase(criteria, "UNSEEN") != null;
        const want_flagged = std.ascii.indexOfIgnoreCase(criteria, "FLAGGED") != null and
            std.ascii.indexOfIgnoreCase(criteria, "UNFLAGGED") == null;
        const want_unflagged = std.ascii.indexOfIgnoreCase(criteria, "UNFLAGGED") != null;
        const want_deleted = std.ascii.indexOfIgnoreCase(criteria, "DELETED") != null and
            std.ascii.indexOfIgnoreCase(criteria, "UNDELETED") == null;
        const want_undeleted = std.ascii.indexOfIgnoreCase(criteria, "UNDELETED") != null;
        const want_answered = std.ascii.indexOfIgnoreCase(criteria, "ANSWERED") != null and
            std.ascii.indexOfIgnoreCase(criteria, "UNANSWERED") == null;
        const want_unanswered = std.ascii.indexOfIgnoreCase(criteria, "UNANSWERED") != null;

        // Parse UID range criteria (e.g. "UID 4:*", "UID 1,3,5")
        var uid_range_start: i64 = 0;
        var uid_range_end: i64 = std.math.maxInt(i64);
        var has_uid_range = false;
        if (std.ascii.indexOfIgnoreCase(criteria, "UID")) |uid_pos| {
            // Make sure this is the UID keyword, not part of another word
            const after_uid = uid_pos + 3;
            if (after_uid < criteria.len) {
                const rest = std.mem.trim(u8, criteria[after_uid..], " \t");
                if (rest.len > 0) {
                    has_uid_range = true;
                    if (std.mem.indexOf(u8, rest, ":")) |colon| {
                        uid_range_start = std.fmt.parseInt(i64, rest[0..colon], 10) catch 1;
                        const end_part = rest[colon + 1 ..];
                        // End part might have trailing spaces or other criteria
                        const end_token = if (std.mem.indexOfAny(u8, end_part, " \t")) |sp| end_part[0..sp] else end_part;
                        if (std.mem.eql(u8, end_token, "*")) {
                            uid_range_end = std.math.maxInt(i64);
                        } else {
                            uid_range_end = std.fmt.parseInt(i64, end_token, 10) catch std.math.maxInt(i64);
                        }
                    } else {
                        // Single UID value
                        const uid_token = if (std.mem.indexOfAny(u8, rest, " \t")) |sp| rest[0..sp] else rest;
                        const single_uid = std.fmt.parseInt(i64, uid_token, 10) catch 0;
                        if (single_uid > 0) {
                            uid_range_start = single_uid;
                            uid_range_end = single_uid;
                        }
                    }
                }
            }
        }

        // Resolve text criteria (FROM/TO/SUBJECT/BODY/TEXT) through the
        // Typesense index when available: one indexed query instead of
        // reading every message file. On error (engine down, not indexed)
        // fall back to the per-file scan below.
        var ts_matches: ?std.StringHashMap(void) = null;
        defer if (ts_matches) |*m| freeMatchSet(self.allocator, m);
        if (!is_all and typesense.enabled()) {
            ts_matches = self.typesenseSearchMatches(criteria) catch null;
        }

        var buf: [8192]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        writer.writeAll("SEARCH") catch {};

        for (files, 0..) |filename, i| {
            const seq = i + 1;
            const uid = self.getUidForSeq(seq);
            const flags = MaildirFlags.fromFilename(filename);

            // Filter by UID range if specified
            if (has_uid_range) {
                if (uid < uid_range_start or uid > uid_range_end) continue;
            }

            // Evaluate flag-based criteria
            if (!is_all) {
                if (want_seen and !flags.seen) continue;
                if (want_unseen and flags.seen) continue;
                if (want_flagged and !flags.flagged) continue;
                if (want_unflagged and flags.flagged) continue;
                if (want_deleted and !flags.deleted) continue;
                if (want_undeleted and flags.deleted) continue;
                if (want_answered and !flags.answered) continue;
                if (want_unanswered and flags.answered) continue;

                // Text-based criteria, indexed path: membership in the
                // Typesense result set (keyed by maildir base name).
                if (ts_matches) |*m| {
                    if (!m.contains(MaildirFlags.baseName(filename))) continue;
                }

                // Text-based criteria, fallback path: FROM, SUBJECT —
                // require reading the file
                const need_content = ts_matches == null and
                    (std.ascii.indexOfIgnoreCase(criteria, "FROM") != null or
                        std.ascii.indexOfIgnoreCase(criteria, "SUBJECT") != null);
                if (need_content) {
                    const filepath = self.allocSelectedMessagePath(i, filename) catch continue;
                    defer self.allocator.free(filepath);
                    const content = fs_compat.readFileAlloc(self.allocator, filepath) catch continue;
                    defer self.allocator.free(content);

                    // Find header boundary
                    const hdr_end = if (std.mem.indexOf(u8, content, "\r\n\r\n")) |p| p else if (std.mem.indexOf(u8, content, "\n\n")) |p| p else content.len;
                    const hdr = content[0..hdr_end];

                    var matches = true;
                    // Extract FROM search term
                    if (std.ascii.indexOfIgnoreCase(criteria, "FROM")) |from_pos| {
                        const after = criteria[from_pos + 4 ..];
                        const term = extractQuotedArg(after);
                        if (term.len > 0) {
                            if (std.ascii.indexOfIgnoreCase(hdr, "From:")) |fp| {
                                const from_line_end = std.mem.indexOfScalarPos(u8, hdr, fp, '\n') orelse hdr.len;
                                const from_line = hdr[fp..from_line_end];
                                if (std.ascii.indexOfIgnoreCase(from_line, term) == null) matches = false;
                            } else {
                                matches = false;
                            }
                        }
                    }
                    // Extract SUBJECT search term
                    if (std.ascii.indexOfIgnoreCase(criteria, "SUBJECT")) |subj_pos| {
                        const after = criteria[subj_pos + 7 ..];
                        const term = extractQuotedArg(after);
                        if (term.len > 0) {
                            if (std.ascii.indexOfIgnoreCase(hdr, "Subject:")) |sp| {
                                const subj_line_end = std.mem.indexOfScalarPos(u8, hdr, sp, '\n') orelse hdr.len;
                                const subj_line = hdr[sp..subj_line_end];
                                if (std.ascii.indexOfIgnoreCase(subj_line, term) == null) matches = false;
                            } else {
                                matches = false;
                            }
                        }
                    }
                    if (!matches) continue;
                }
            }

            const result_id: i64 = if (is_uid) uid else @intCast(seq);
            writer.print(" {d}", .{result_id}) catch break;
        }

        try self.sendUntagged(fbs.getWritten());
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

        // Ensure destination directory exists
        fs_compat.ensureDir(dest_dir) catch {};

        // Parse sequence set and copy each message
        var copied: u32 = 0;
        var iter = SequenceIterator.init(sequence_set, files.len);
        while (iter.next()) |seq| {
            const idx = seq - 1; // sequence numbers are 1-based
            if (idx >= files.len) continue;

            const filename = files[idx];

            // Build source path
            const src_path = self.allocSelectedMessagePath(idx, filename) catch continue;
            defer self.allocator.free(src_path);

            // Read source file
            const content = fs_compat.readFileAlloc(self.allocator, src_path) catch continue;
            defer self.allocator.free(content);

            // Write to destination with a unique Maildir-style filename,
            // preserving flags. allocUniqueMaildirPath probes for an unused
            // name so a copy never truncate-overwrites an existing message.
            const src_flags = MaildirFlags.fromFilename(filename);
            var suffix_buf: [16]u8 = undefined;
            const flag_suffix = src_flags.toSuffix(&suffix_buf);
            const dest_path = self.allocUniqueMaildirPath(dest_dir, flag_suffix) catch continue;
            defer self.allocator.free(dest_path);

            const file = fs_compat.cwd().createFile(dest_path, .{}) catch continue;
            defer file.close();
            file.writeAll(content) catch continue;

            // Keep the search index in sync with the new copy
            typesense.indexMessageAsync(
                self.allocator,
                local_part,
                if (std.ascii.eqlIgnoreCase(dest_name, "INBOX")) "INBOX" else dest_name,
                std.fs.path.basename(dest_path),
                content,
            );

            copied += 1;
        }

        std.log.info("IMAP COPY: Copied {d} messages to {s}", .{ copied, dest_name });
        try self.sendResponse(tag, "OK", "COPY completed");
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

        for (to_move.items) |seq| {
            const idx = seq - 1;
            const filename = files[idx];

            // Build paths
            const src_path = self.allocSelectedMessagePath(idx, filename) catch continue;
            defer self.allocator.free(src_path);

            // Preserve flags from source filename in destination. Use a
            // collision-free Maildir-style name so a move never silently
            // truncate-overwrites an existing destination message.
            const src_flags = MaildirFlags.fromFilename(filename);
            var move_suffix_buf: [16]u8 = undefined;
            const move_flag_suffix = src_flags.toSuffix(&move_suffix_buf);
            const dest_path = self.allocUniqueMaildirPath(dest_dir, move_flag_suffix) catch continue;
            defer self.allocator.free(dest_path);

            // Copy content to destination
            const content = fs_compat.readFileAlloc(self.allocator, src_path) catch continue;
            defer self.allocator.free(content);
            const file = fs_compat.cwd().createFile(dest_path, .{}) catch continue;
            defer file.close();
            file.writeAll(content) catch continue;

            // Delete source
            const src_path_z = self.allocator.dupeZ(u8, src_path) catch continue;
            defer self.allocator.free(src_path_z);
            _ = std.c.unlink(src_path_z.ptr);

            // Search index: add the destination copy, drop the source doc
            typesense.indexMessageAsync(
                self.allocator,
                local_part,
                if (std.ascii.eqlIgnoreCase(dest_name, "INBOX")) "INBOX" else dest_name,
                std.fs.path.basename(dest_path),
                content,
            );
            typesense.deleteMessage(self.allocator, local_part, self.sourceMailboxForIndex(idx), filename);

            // Send EXPUNGE notification
            var resp_buf: [32]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&resp_buf);
            fbs.writer().print("{d} EXPUNGE", .{seq}) catch continue;
            self.sendUntagged(fbs.getWritten()) catch continue;
        }

        // Refresh mailbox
        _ = self.rescanMailbox() catch {};

        std.log.info("IMAP MOVE: Moved {d} messages to {s}", .{ to_move.items.len, dest_name });
        try self.sendResponse(tag, "OK", "MOVE completed");
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
        const local_part = full_username;

        const old = stripQuotes(old_name);
        const new = stripQuotes(new_name);

        if (std.ascii.eqlIgnoreCase(old, "INBOX")) {
            try self.sendResponse(tag, "NO", "Cannot rename INBOX");
            return;
        }

        const old_path = try std.fmt.allocPrint(self.allocator, "mail/{s}/{s}", .{ local_part, old });
        defer self.allocator.free(old_path);
        const new_path = try std.fmt.allocPrint(self.allocator, "mail/{s}/{s}", .{ local_part, new });
        defer self.allocator.free(new_path);

        if (renameFile(old_path, new_path)) {
            std.log.info("IMAP RENAME: {s} -> {s}", .{ old, new });
            try self.sendResponse(tag, "OK", "RENAME completed");
        } else {
            try self.sendResponse(tag, "NO", "RENAME failed");
        }
    }

    /// Handle STORE command — set/add/remove message flags.
    /// Persists flags by renaming files with Maildir-style `:2,FLAGS` suffix.
    /// Implements RFC 3501 Section 6.4.6.
    fn handleStore(self: *ImapSession, tag: []const u8, sequence_set: []const u8, flags_action: []const u8) !void {
        if (self.state != .selected) {
            try self.sendResponse(tag, "NO", "Must select mailbox first");
            return;
        }

        const files = self.mailbox_files orelse {
            try self.sendResponse(tag, "OK", "STORE completed");
            return;
        };

        const is_silent = std.ascii.indexOfIgnoreCase(flags_action, ".SILENT") != null;
        // Need mutable access to update cached filenames after renames
        const mutable_files = @constCast(files);

        var iter = SequenceIterator.init(sequence_set, files.len);
        while (iter.next()) |seq| {
            if (seq < 1 or seq > files.len) continue;
            const idx = seq - 1;
            const filename = files[idx];

            // Read current flags from filename, apply the action
            var flags = MaildirFlags.fromFilename(filename);
            flags.applyAction(flags_action);

            // Build new filename: base + new flag suffix
            const base = MaildirFlags.baseName(filename);
            var suffix_buf: [16]u8 = undefined;
            const suffix = flags.toSuffix(&suffix_buf);

            var new_name_buf: [512]u8 = undefined;
            const new_name = std.fmt.bufPrint(&new_name_buf, "{s}{s}", .{ base, suffix }) catch continue;

            // Rename the file if flags actually changed
            if (!std.mem.eql(u8, filename, new_name)) {
                const dir = self.selectedMessageDirForIndex(idx) orelse continue;
                const old_path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ dir, filename }) catch continue;
                defer self.allocator.free(old_path);
                const new_path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ dir, new_name }) catch continue;
                defer self.allocator.free(new_path);

                if (renameFile(old_path, new_path)) {
                    // Update cached filename
                    const owned_new = self.allocator.dupe(u8, new_name) catch continue;
                    self.allocator.free(filename);
                    mutable_files[idx] = owned_new;
                }
            }

            // Send untagged FETCH response with updated flags (unless .SILENT).
            // Always include UID: a UID STORE (which Apple Mail uses to mark
            // read/unread) requires the UID in the FETCH response so the client
            // can correlate the flag change to its UID-keyed message and update
            // its unread count. Without it the badge never reflects the change.
            if (!is_silent) {
                var flag_str_buf: [256]u8 = undefined;
                const flag_str = flags.toImapString(&flag_str_buf);
                const uid = self.getUidForSeq(seq);
                var resp_buf: [512]u8 = undefined;
                var fbs = io_compat.fixedBufferStream(&resp_buf);
                fbs.writer().print("{d} FETCH (UID {d} FLAGS ({s}))", .{ seq, uid, flag_str }) catch continue;
                self.sendUntagged(fbs.getWritten()) catch continue;
            }
        }

        try self.sendResponse(tag, "OK", "STORE completed");
    }

    /// Handle EXPUNGE command — remove messages marked with \Deleted flag.
    /// Reads \Deleted from Maildir filename suffix. Sends untagged EXPUNGE
    /// responses in descending order per RFC 3501 Section 6.4.3.
    fn handleExpunge(self: *ImapSession, tag: []const u8) !void {
        if (self.state != .selected) {
            try self.sendResponse(tag, "NO", "Must select mailbox first");
            return;
        }

        const files = self.mailbox_files orelse {
            try self.sendResponse(tag, "OK", "EXPUNGE completed");
            return;
        };

        // Collect sequence numbers of messages with \Deleted flag (from filename)
        // Process in reverse order so that earlier sequence numbers stay valid
        var seq: usize = files.len;
        while (seq >= 1) : (seq -= 1) {
            const filename = files[seq - 1];
            const flags = MaildirFlags.fromFilename(filename);
            if (!flags.deleted) continue;

            // Delete the file
            const path = self.allocSelectedMessagePath(seq - 1, filename) catch continue;
            defer self.allocator.free(path);
            const path_z = self.allocator.dupeZ(u8, path) catch continue;
            defer self.allocator.free(path_z);
            _ = std.c.unlink(path_z.ptr);

            // Drop from the search index (best-effort)
            if (self.searchIdentity()) |ident| {
                typesense.deleteMessage(self.allocator, ident.username, self.sourceMailboxForIndex(seq - 1), filename);
            }

            // Send untagged EXPUNGE
            var resp_buf: [32]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&resp_buf);
            fbs.writer().print("{d} EXPUNGE", .{seq}) catch continue;
            self.sendUntagged(fbs.getWritten()) catch continue;

            std.log.info("IMAP EXPUNGE: Deleted {s}", .{path});

            if (seq == 0) break;
        }

        // Refresh mailbox file list after deletions
        _ = self.rescanMailbox() catch {};

        try self.sendResponse(tag, "OK", "EXPUNGE completed");
    }

    /// Handle LOGOUT command
    fn handleLogout(self: *ImapSession, tag: []const u8) !void {
        try self.sendUntagged("BYE IMAP4rev1 Server logging out");
        try self.sendResponse(tag, "OK", "LOGOUT completed");
        self.state = .logout;
    }

    /// Process a single command
    pub fn processCommand(self: *ImapSession, line: []const u8) !void {
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
                self.mailbox_read_only = false;
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
            .expunge => try self.handleExpunge(tag),
            .close => {
                // RFC 3501 Section 6.4.2: CLOSE implicitly expunges \Deleted messages
                // (without sending untagged EXPUNGE responses)
                if (self.mailbox_files) |files| {
                    for (files, 0..) |filename, i| {
                        const flags = MaildirFlags.fromFilename(filename);
                        if (flags.deleted) {
                            const path = self.allocSelectedMessagePath(i, filename) catch continue;
                            defer self.allocator.free(path);
                            const path_z = self.allocator.dupeZ(u8, path) catch continue;
                            defer self.allocator.free(path_z);
                            _ = std.c.unlink(path_z.ptr);
                        }
                    }
                }
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
                    // UID EXPUNGE (RFC 4315)
                    try self.handleExpunge(tag);
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
                            const parsed = parseAppendArgs(rest[0..brace_start]);
                            const mailbox = parsed.mailbox;

                            // Reject invalid/unsafe mailbox names up front rather
                            // than after buffering the whole literal.
                            if (!isSafeMailboxName(mailbox)) {
                                try self.sendResponse(tag, "NO", "[TRYCREATE] Invalid mailbox name");
                                return;
                            }

                            // Set up pending append state
                            self.cleanupAppend();
                            self.append_tag = try self.allocator.dupe(u8, tag);
                            self.append_mailbox = try self.allocator.dupe(u8, mailbox);
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
                // CREATE mailbox - create the Maildir folder
                const create_name = stripQuotes(parts.next() orelse "");
                if (!isSafeMailboxName(create_name)) {
                    // Rejects empty names and any path-traversal attempt.
                    try self.sendResponse(tag, "NO", "Invalid mailbox name");
                } else {
                    if (self.username) |uname| {
                        const local = uname;
                        const dir = std.fmt.allocPrint(self.allocator, "mail/{s}/{s}", .{ local, create_name }) catch null;
                        if (dir) |d| {
                            fs_compat.cwd().makePath(d) catch {};
                            self.allocator.free(d);
                        }
                    }
                    try self.sendResponse(tag, "OK", "CREATE completed");
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
                const mailbox = stripQuotes(parts.next() orelse "");
                try self.handleDelete(tag, mailbox);
            },
            .rename => {
                const old_name = stripQuotes(parts.next() orelse "");
                const new_name = stripQuotes(parts.next() orelse "");
                try self.handleRename(tag, old_name, new_name);
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
        const address = try socket.Address.parseIp("0.0.0.0", self.config.port);
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
        const ssl_address = socket.Address.parseIp("0.0.0.0", self.config.ssl_port) catch |err| {
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
        var session = try self.allocator.create(ImapSession);
        session.* = ImapSession.init(self.allocator, connection, self.auth_backend, self.db, self.config.enable_gmail_labels);
        defer {
            session.deinit();
            self.allocator.destroy(session);
            connection.close();
        }

        // For IMAPS connections, perform TLS handshake first using nonblock API
        var tls_cipher: ?tls.Cipher = null;

        if (is_ssl) {
            // Check if we have a certificate loaded
            if (self.cert_key_pair == null) {
                logger.err("IMAPS connection attempted but no certificate loaded", .{});
                return error.TlsNotConfigured;
            }

            logger.info("Starting TLS handshake for IMAPS connection", .{});

            // Use nonblock TLS server handshake
            var tls_server = tls.nonblock.Server.init(.{
                .auth = &self.cert_key_pair.?,
            });

            // Buffers for TLS handshake
            var recv_buf: [tls.input_buffer_len]u8 = undefined;
            var send_buf: [tls.output_buffer_len]u8 = undefined;
            var recv_len: usize = 0;

            // Perform handshake loop
            while (!tls_server.done()) {
                // Run handshake step
                const result = tls_server.run(recv_buf[0..recv_len], &send_buf) catch |err| {
                    logger.debug("TLS handshake error: {}", .{err});
                    return error.TlsHandshakeFailed;
                };

                // Consume processed bytes
                if (result.recv_pos > 0) {
                    const remaining = recv_len - result.recv_pos;
                    if (remaining > 0) {
                        std.mem.copyForwards(u8, &recv_buf, recv_buf[result.recv_pos..recv_len]);
                    }
                    recv_len = remaining;
                }

                // Send data to client if any
                if (result.send.len > 0) {
                    logger.debug("TLS handshake: preparing to send {d} bytes", .{result.send.len});
                    var sent: usize = 0;
                    while (sent < result.send.len) {
                        const n = connection.write(result.send[sent..]) catch |err| {
                            logger.debug("TLS handshake write error: {}", .{err});
                            return error.TlsHandshakeFailed;
                        };
                        logger.debug("TLS handshake: wrote {d} bytes (total sent: {d}/{d})", .{ n, sent + n, result.send.len });
                        if (n == 0) {
                            logger.debug("TLS handshake: connection closed during write", .{});
                            return error.TlsHandshakeFailed;
                        }
                        sent += n;
                    }
                    logger.debug("TLS handshake: finished sending all {d} bytes", .{result.send.len});
                }

                // Read more data from client if handshake not done
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

            tls_cipher = tls_server.cipher();
            logger.info("IMAPS TLS handshake completed successfully", .{});
        }

        // Handle session based on whether TLS is active
        if (tls_cipher) |cipher| {
            // TLS encrypted session using nonblock connection
            var tls_conn = tls.nonblock.Connection.init(cipher);

            // Set TLS connection on session so all responses are encrypted
            session.setTlsConnection(&tls_conn);

            // Send greeting over TLS (now using session's TLS-aware write)
            session.sendGreeting() catch |err| {
                logger.err("Failed to send IMAP greeting: {}", .{err});
                return;
            };

            // Read and process commands over TLS
            var recv_buf: [tls.input_buffer_len]u8 = undefined;
            var cleartext_buf: [16384]u8 = undefined;
            var ciphertext_accum: [tls.input_buffer_len * 2]u8 = undefined;
            var ciphertext_len: usize = 0;
            // Buffer for leftover cleartext (partial lines across TLS records)
            var cleartext_accum: [16384]u8 = undefined;
            var cleartext_accum_len: usize = 0;

            // Track IDLE polling state
            var idle_poll_counter: u32 = 0;

            while (session.state != .logout) {
                // During IDLE: set a short socket timeout so we can poll for new mail
                if (session.idle_mode) {
                    if (!session.idleWaitReadable(connection.fd)) continue;
                }

                // Read ciphertext from socket
                const bytes_read = connection.read(recv_buf[0..]) catch |err| {
                    // During IDLE, timeout is expected — poll for new mail
                    if (session.idle_mode and (err == error.WouldBlock or err == error.ConnectionTimedOut)) {
                        idle_poll_counter += 1;
                        // Check for new messages every poll cycle (~5 seconds)
                        if (session.state == .selected) {
                            session.idlePollRescan();
                        }
                        continue;
                    }
                    break;
                };
                if (bytes_read == 0) break;

                // If we got data during IDLE, restore normal timeout
                if (session.idle_mode) {
                    idle_poll_counter = 0;
                }
                // Restore normal (no timeout) when not in IDLE
                if (!session.idle_mode) {
                    const no_tv: std.posix.timeval = .{ .sec = 0, .usec = 0 };
                    std.posix.setsockopt(connection.fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&no_tv)) catch {};
                }

                // Accumulate ciphertext
                if (ciphertext_len + bytes_read <= ciphertext_accum.len) {
                    @memcpy(ciphertext_accum[ciphertext_len..][0..bytes_read], recv_buf[0..bytes_read]);
                    ciphertext_len += bytes_read;
                } else {
                    logger.err("IMAP TLS: ciphertext buffer overflow", .{});
                    break;
                }

                // Try to decrypt
                const dec_result = tls_conn.decrypt(ciphertext_accum[0..ciphertext_len], &cleartext_buf) catch |err| {
                    logger.err("TLS decrypt error: {}", .{err});
                    break;
                };

                // Handle decrypted data - may contain multiple IMAP commands
                if (dec_result.cleartext.len > 0) {
                    // Append to cleartext accumulator
                    const avail = cleartext_accum.len - cleartext_accum_len;
                    const copy_len = @min(dec_result.cleartext.len, avail);
                    @memcpy(cleartext_accum[cleartext_accum_len..][0..copy_len], dec_result.cleartext[0..copy_len]);
                    cleartext_accum_len += copy_len;

                    // Process data - command lines or APPEND literal data
                    var processed: usize = 0;
                    while (processed < cleartext_accum_len) {
                        // If collecting APPEND literal data, consume bytes directly
                        if (session.append_literal_buf) |buf| {
                            const needed = session.append_literal_size - session.append_literal_pos;
                            const available = cleartext_accum_len - processed;
                            const lit_len = @min(needed, available);
                            @memcpy(buf[session.append_literal_pos..][0..lit_len], cleartext_accum[processed..][0..lit_len]);
                            session.append_literal_pos += lit_len;
                            processed += lit_len;

                            if (session.append_literal_pos >= session.append_literal_size) {
                                // Literal complete - save message and send OK
                                session.finalizeAppend() catch |err| {
                                    logger.err("IMAP APPEND finalize error: {}", .{err});
                                };
                                // Skip trailing \r\n after literal data
                                if (processed + 2 <= cleartext_accum_len and
                                    cleartext_accum[processed] == '\r' and cleartext_accum[processed + 1] == '\n')
                                {
                                    processed += 2;
                                }
                            }
                            continue;
                        }

                        // Normal: find next \r\n delimited command line
                        const remaining = cleartext_accum[processed..cleartext_accum_len];
                        const line_end = std.mem.indexOf(u8, remaining, "\r\n") orelse break;
                        if (line_end > 0) {
                            const line = remaining[0..line_end];
                            session.processCommand(line) catch |err| {
                                logger.err("IMAP command processing error: {}", .{err});
                            };
                        }
                        processed += line_end + 2; // skip \r\n
                        if (session.state == .logout) break;
                    }

                    // Move unprocessed data to front
                    if (processed > 0) {
                        const leftover = cleartext_accum_len - processed;
                        if (leftover > 0) {
                            std.mem.copyForwards(u8, &cleartext_accum, cleartext_accum[processed..cleartext_accum_len]);
                        }
                        cleartext_accum_len = leftover;
                    }
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
        } else {
            // Plain text session (non-SSL)
            try session.sendGreeting();

            var buffer: [4096]u8 = undefined;
            while (session.state != .logout and !session.starttls_requested) {
                // During IDLE: set a short socket timeout so we can poll for new mail
                if (session.idle_mode) {
                    if (!session.idleWaitReadable(connection.fd)) continue;
                }

                const bytes_read = connection.read(&buffer) catch |err| {
                    if (session.idle_mode and (err == error.WouldBlock or err == error.ConnectionTimedOut)) {
                        if (session.state == .selected) {
                            session.idlePollRescan();
                        }
                        continue;
                    }
                    break;
                };
                if (bytes_read == 0) break;

                // Restore normal timeout when leaving IDLE
                if (!session.idle_mode) {
                    const no_tv: std.posix.timeval = .{ .sec = 0, .usec = 0 };
                    std.posix.setsockopt(connection.fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&no_tv)) catch {};
                }

                // If collecting APPEND literal data, feed bytes to the buffer
                if (session.append_literal_buf) |buf| {
                    const needed = session.append_literal_size - session.append_literal_pos;
                    const copy_len = @min(needed, bytes_read);
                    @memcpy(buf[session.append_literal_pos..][0..copy_len], buffer[0..copy_len]);
                    session.append_literal_pos += copy_len;
                    if (session.append_literal_pos >= session.append_literal_size) {
                        session.finalizeAppend() catch |err| {
                            logger.err("IMAP APPEND finalize error: {}", .{err});
                        };
                    }
                    continue;
                }

                const line = std.mem.trim(u8, buffer[0..bytes_read], "\r\n");
                session.processCommand(line) catch |err| {
                    logger.err("IMAP command processing error: {}", .{err});
                    break;
                };
            }

            // STARTTLS upgrade: perform TLS handshake on the existing connection
            if (session.starttls_requested and self.cert_key_pair != null) {
                logger.info("Starting STARTTLS upgrade on port 143", .{});

                var tls_server = tls.nonblock.Server.init(.{
                    .auth = &self.cert_key_pair.?,
                });

                var recv_buf: [tls.input_buffer_len]u8 = undefined;
                var send_buf: [tls.output_buffer_len]u8 = undefined;
                var recv_len: usize = 0;

                // Perform handshake loop
                var handshake_ok = true;
                while (!tls_server.done()) {
                    const result = tls_server.run(recv_buf[0..recv_len], &send_buf) catch |err| {
                        logger.debug("STARTTLS handshake error: {}", .{err});
                        handshake_ok = false;
                        break;
                    };

                    if (result.recv_pos > 0) {
                        const remaining = recv_len - result.recv_pos;
                        if (remaining > 0) {
                            std.mem.copyForwards(u8, &recv_buf, recv_buf[result.recv_pos..recv_len]);
                        }
                        recv_len = remaining;
                    }

                    if (result.send.len > 0) {
                        var sent: usize = 0;
                        while (sent < result.send.len) {
                            const n = connection.write(result.send[sent..]) catch |err| {
                                logger.debug("STARTTLS handshake write error: {}", .{err});
                                handshake_ok = false;
                                break;
                            };
                            if (n == 0) {
                                handshake_ok = false;
                                break;
                            }
                            sent += n;
                        }
                        if (!handshake_ok) break;
                    }

                    if (!tls_server.done()) {
                        const n = connection.read(recv_buf[recv_len..]) catch |err| {
                            logger.debug("STARTTLS handshake read error: {}", .{err});
                            handshake_ok = false;
                            break;
                        };
                        if (n == 0) {
                            handshake_ok = false;
                            break;
                        }
                        recv_len += n;
                    }
                }

                if (handshake_ok) {
                    if (tls_server.cipher()) |cipher| {
                        logger.info("STARTTLS handshake completed successfully", .{});
                        var starttls_tls_conn = tls.nonblock.Connection.init(cipher);
                        session.setTlsConnection(&starttls_tls_conn);
                        session.starttls_requested = false;

                        // Enter TLS encrypted read loop (same as IMAPS)
                        var tls_recv_buf: [tls.input_buffer_len]u8 = undefined;
                        var cleartext_buf: [16384]u8 = undefined;
                        var ciphertext_accum: [tls.input_buffer_len * 2]u8 = undefined;
                        var ciphertext_len: usize = 0;
                        var cleartext_accum: [16384]u8 = undefined;
                        var cleartext_accum_len: usize = 0;

                        while (session.state != .logout) {
                            if (session.idle_mode) {
                                if (!session.idleWaitReadable(connection.fd)) continue;
                            }

                            const bytes_read = connection.read(tls_recv_buf[0..]) catch |err| {
                                if (session.idle_mode and (err == error.WouldBlock or err == error.ConnectionTimedOut)) {
                                    if (session.state == .selected) {
                                        session.idlePollRescan();
                                    }
                                    continue;
                                }
                                break;
                            };
                            if (bytes_read == 0) break;

                            if (!session.idle_mode) {
                                const no_tv: std.posix.timeval = .{ .sec = 0, .usec = 0 };
                                std.posix.setsockopt(connection.fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&no_tv)) catch {};
                            }

                            if (ciphertext_len + bytes_read <= ciphertext_accum.len) {
                                @memcpy(ciphertext_accum[ciphertext_len..][0..bytes_read], tls_recv_buf[0..bytes_read]);
                                ciphertext_len += bytes_read;
                            } else {
                                logger.err("IMAP STARTTLS: ciphertext buffer overflow", .{});
                                break;
                            }

                            const dec_result = starttls_tls_conn.decrypt(ciphertext_accum[0..ciphertext_len], &cleartext_buf) catch |err| {
                                logger.err("STARTTLS decrypt error: {}", .{err});
                                break;
                            };

                            if (dec_result.cleartext.len > 0) {
                                const avail = cleartext_accum.len - cleartext_accum_len;
                                const copy_len = @min(dec_result.cleartext.len, avail);
                                @memcpy(cleartext_accum[cleartext_accum_len..][0..copy_len], dec_result.cleartext[0..copy_len]);
                                cleartext_accum_len += copy_len;

                                var processed: usize = 0;
                                while (processed < cleartext_accum_len) {
                                    if (session.append_literal_buf) |buf| {
                                        const needed = session.append_literal_size - session.append_literal_pos;
                                        const available = cleartext_accum_len - processed;
                                        const lit_len = @min(needed, available);
                                        @memcpy(buf[session.append_literal_pos..][0..lit_len], cleartext_accum[processed..][0..lit_len]);
                                        session.append_literal_pos += lit_len;
                                        processed += lit_len;
                                        if (session.append_literal_pos >= session.append_literal_size) {
                                            session.finalizeAppend() catch |err| {
                                                logger.err("IMAP APPEND finalize error: {}", .{err});
                                            };
                                            if (processed + 2 <= cleartext_accum_len and
                                                cleartext_accum[processed] == '\r' and cleartext_accum[processed + 1] == '\n')
                                            {
                                                processed += 2;
                                            }
                                        }
                                        continue;
                                    }

                                    const remaining = cleartext_accum[processed..cleartext_accum_len];
                                    const line_end = std.mem.indexOf(u8, remaining, "\r\n") orelse break;
                                    if (line_end > 0) {
                                        const line = remaining[0..line_end];
                                        session.processCommand(line) catch |err| {
                                            logger.err("IMAP command processing error: {}", .{err});
                                        };
                                    }
                                    processed += line_end + 2;
                                    if (session.state == .logout) break;
                                }

                                if (processed > 0) {
                                    const leftover = cleartext_accum_len - processed;
                                    if (leftover > 0) {
                                        std.mem.copyForwards(u8, &cleartext_accum, cleartext_accum[processed..cleartext_accum_len]);
                                    }
                                    cleartext_accum_len = leftover;
                                }
                            }

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
                        if (starttls_tls_conn.close(&close_buf)) |close_data| {
                            _ = connection.write(close_data) catch {};
                        } else |_| {}
                    } else {
                        logger.err("STARTTLS: no cipher after handshake", .{});
                    }
                }
            }
        }
    }
};

/// Format epoch seconds as IMAP INTERNALDATE: "DD-Mon-YYYY HH:MM:SS +0000"
fn formatImapDate(epoch_secs: i64, buf: *[64]u8) []const u8 {
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

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

    const mon = months[@as(usize, month_idx) - 1];
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

    const bare = parseAppendArgs("INBOX");
    try testing.expectEqualStrings("INBOX", bare.mailbox);
    try testing.expect(bare.flags == null);

    const quoted = parseAppendArgs("\"All Mail\" (\\Seen)");
    try testing.expectEqualStrings("All Mail", quoted.mailbox);
    try testing.expectEqualStrings("\\Seen", quoted.flags.?);

    const with_date = parseAppendArgs("\"Sent\" (\\Seen \\Draft) \"14-Jul-2026 09:58:00 +0000\"");
    try testing.expectEqualStrings("Sent", with_date.mailbox);
    try testing.expectEqualStrings("\\Seen \\Draft", with_date.flags.?);

    const empty_flags = parseAppendArgs("Drafts ()");
    try testing.expectEqualStrings("Drafts", empty_flags.mailbox);
    try testing.expectEqualStrings("", empty_flags.flags.?);

    const date_only = parseAppendArgs("INBOX \"14-Jul-2026 09:58:00 +0000\"");
    try testing.expectEqualStrings("INBOX", date_only.mailbox);
    try testing.expect(date_only.flags == null);
}

test "APPEND flag list maps to Maildir flags" {
    const testing = std.testing;

    var flags = MaildirFlags{};
    flags.applyAction("\\Seen \\Draft");
    try testing.expect(flags.seen);
    try testing.expect(flags.draft);
    try testing.expect(!flags.flagged);

    var suffix_buf: [16]u8 = undefined;
    try testing.expectEqualStrings(":2,DS", flags.toSuffix(&suffix_buf));
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
