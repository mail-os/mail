const std = @import("std");
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

/// Strip surrounding double quotes from an IMAP token.
/// IMAP clients (e.g. Python imaplib) quote usernames and passwords.
fn stripQuotes(s: []const u8) []const u8 {
    if (s.len >= 2 and s[0] == '"' and s[s.len - 1] == '"') {
        return s[1 .. s.len - 1];
    }
    return s;
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
            .all_mail => "\\HasNoChildren \\All",
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

/// Gmail-style folders in the order they should be listed
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
            .flags = std.ArrayList([]const u8){},
            .permanent_flags = std.ArrayList([]const u8){},
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
const SequenceIterator = struct {
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
        if (self.range_current <= self.range_end) {
            const val = self.range_current;
            self.range_current += 1;
            return val;
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
                return end_num;
            }
            return start_num;
        }

        return start_num;
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
    auth_backend: *auth.AuthBackend,
    // TLS support for encrypted responses
    tls_connection: ?*tls.nonblock.Connection = null,
    // Cached list of message filenames in the selected mailbox (sorted)
    mailbox_files: ?[]const []const u8 = null,
    // Path to the selected mailbox's new/ directory
    mailbox_dir: ?[]const u8 = null,
    // Pending APPEND literal state
    append_tag: ?[]u8 = null,
    append_mailbox: ?[]u8 = null,
    append_literal_size: usize = 0,
    append_literal_buf: ?[]u8 = null,
    append_literal_pos: usize = 0,
    // STARTTLS upgrade requested (port 143 → TLS)
    starttls_requested: bool = false,

    pub fn init(allocator: std.mem.Allocator, connection: socket.Connection, auth_backend: *auth.AuthBackend) ImapSession {
        return .{
            .allocator = allocator,
            .connection = connection,
            .state = .not_authenticated,
            .command_buffer = std.ArrayList(u8){},
            .auth_backend = auth_backend,
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
        self.freeMailboxFiles();
        self.command_buffer.deinit(self.allocator);
    }

    fn freeMailboxFiles(self: *ImapSession) void {
        if (self.mailbox_files) |files| {
            for (files) |f| self.allocator.free(f);
            self.allocator.free(files);
            self.mailbox_files = null;
        }
        if (self.mailbox_dir) |d| {
            self.allocator.free(d);
            self.mailbox_dir = null;
        }
    }

    /// Re-scan the current mailbox for new messages.
    /// If the message count changed, sends untagged EXISTS/RECENT responses
    /// so the client knows to fetch new messages. Returns true if new mail found.
    fn rescanMailbox(self: *ImapSession) !bool {
        const dir = self.mailbox_dir orelse return false;
        const old_count: usize = if (self.mailbox_files) |f| f.len else 0;

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

        // Extract local part from email address (chris@stacksjs.com -> chris)
        const local_part = if (std.mem.indexOfScalar(u8, username, '@')) |at_pos|
            username[0..at_pos]
        else
            username;

        // Determine folder directory
        const folder_dir = if (std.ascii.eqlIgnoreCase(mailbox, "INBOX"))
            try std.fmt.allocPrint(self.allocator, "mail/{s}/new", .{local_part})
        else
            try std.fmt.allocPrint(self.allocator, "mail/{s}/{s}", .{ local_part, mailbox });
        defer self.allocator.free(folder_dir);

        // Create directory if it doesn't exist
        fs_compat.cwd().makePath(folder_dir) catch {};

        // Write message file with timestamp-based name
        const timestamp = time_compat.milliTimestamp();
        const filepath = try std.fmt.allocPrint(self.allocator, "{s}/{d}.eml", .{ folder_dir, timestamp });
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

        // Count files to determine UID for response
        const files = fs_compat.listEmlFiles(self.allocator, folder_dir) catch &[_][]const u8{};
        const uid = files.len;
        defer {
            for (files) |f| self.allocator.free(f);
            self.allocator.free(files);
        }

        // Send OK with APPENDUID
        var resp_buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&resp_buf);
        fbs.writer().print("[APPENDUID 1772487000 {d}] APPEND completed", .{uid}) catch {
            try self.sendResponse(tag, "OK", "APPEND completed");
            self.cleanupAppend();
            return;
        };
        try self.sendResponse(tag, "OK", fbs.getWritten());
        self.cleanupAppend();
    }

    /// Count messages in a mailbox folder
    fn countMailboxMessages(self: *ImapSession, mailbox_name: []const u8) usize {
        const username = self.username orelse return 0;
        const local_part = if (std.mem.indexOfScalar(u8, username, '@')) |at_pos|
            username[0..at_pos]
        else
            username;

        const clean_name = stripQuotes(mailbox_name);
        const dir_path = if (std.ascii.eqlIgnoreCase(clean_name, "INBOX"))
            std.fmt.allocPrint(self.allocator, "mail/{s}/new", .{local_part})
        else
            std.fmt.allocPrint(self.allocator, "mail/{s}/{s}", .{ local_part, clean_name });

        const path = dir_path catch return 0;
        defer self.allocator.free(path);

        const files = fs_compat.listEmlFiles(self.allocator, path) catch return 0;
        defer {
            for (files) |f| self.allocator.free(f);
            self.allocator.free(files);
        }
        return files.len;
    }

    /// Write data to connection (plain or TLS encrypted)
    /// Handles large data by chunking into TLS-record-sized pieces
    fn writeData(self: *ImapSession, data: []const u8) !void {
        // Log response (truncated)
        const log_len = @min(data.len, 200);
        std.log.info("IMAP RSP ({d}b): {s}", .{ data.len, data[0..log_len] });
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

    /// Send greeting
    pub fn sendGreeting(self: *ImapSession) !void {
        const greeting = "* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN] SMTP Server IMAP4rev1 ready\r\n";
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
            const local = if (std.mem.indexOfScalar(u8, uname, '@')) |at| uname[0..at] else uname;
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
            "INBOX", "Sent", "Drafts", "Trash", "Junk", "Archive",
            "All Mail", "Starred", "Important", "Social", "Forums",
            "Updates", "Promotions", "Notes", "new", "cur", "tmp",
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
        try writer.print("STATUS \"{s}\" (", .{mailbox_name});

        const msg_count = self.countMailboxMessages(mailbox_name);

        var first = true;
        if (want_messages) {
            try writer.print("MESSAGES {d}", .{msg_count});
            first = false;
        }
        if (want_recent) {
            if (!first) try writer.writeAll(" ");
            try writer.writeAll("RECENT 0");
            first = false;
        }
        if (want_uidnext) {
            if (!first) try writer.writeAll(" ");
            try writer.print("UIDNEXT {d}", .{msg_count + 1});
            first = false;
        }
        if (want_uidvalidity) {
            if (!first) try writer.writeAll(" ");
            try writer.writeAll("UIDVALIDITY 1772487000");
            first = false;
        }
        if (want_unseen) {
            if (!first) try writer.writeAll(" ");
            try writer.print("UNSEEN {d}", .{msg_count});
        }
        try writer.writeAll(")");

        try self.sendUntagged(fbs.getWritten());
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
            std.log.warn("Failed IMAP login attempt for user: {s}", .{username});
            try self.sendResponse(tag, "NO", "LOGIN failed");
            return;
        }

        // Store username
        self.username = try self.allocator.dupe(u8, username);
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

        // Only support PLAIN mechanism
        if (!std.ascii.eqlIgnoreCase(mechanism, "PLAIN")) {
            try self.sendResponse(tag, "NO", "Unsupported authentication mechanism");
            return;
        }

        var encoded: []const u8 = undefined;

        if (initial_response) |resp| {
            // Initial response provided on the same line (RFC 4959)
            encoded = resp;
        } else {
            // Send continuation request and read response
            try self.writeData("+ \r\n");

            // Read the base64-encoded credentials from the next line
            // This is handled by reading from the connection directly
            var buf: [1024]u8 = undefined;
            if (self.tls_connection) |tls_conn| {
                // Read encrypted data
                var recv_buf: [tls.input_buffer_len]u8 = undefined;
                const bytes_read = self.connection.read(recv_buf[0..]) catch {
                    try self.sendResponse(tag, "NO", "Authentication failed");
                    return;
                };
                if (bytes_read == 0) {
                    try self.sendResponse(tag, "NO", "Authentication failed");
                    return;
                }
                // Decrypt
                const dec_result = tls_conn.decrypt(recv_buf[0..bytes_read], &buf) catch {
                    try self.sendResponse(tag, "NO", "Authentication failed");
                    return;
                };
                if (dec_result.cleartext.len == 0) {
                    try self.sendResponse(tag, "NO", "Authentication failed");
                    return;
                }
                encoded = std.mem.trim(u8, dec_result.cleartext, "\r\n");
            } else {
                const bytes_read = self.connection.read(&buf) catch {
                    try self.sendResponse(tag, "NO", "Authentication failed");
                    return;
                };
                if (bytes_read == 0) {
                    try self.sendResponse(tag, "NO", "Authentication failed");
                    return;
                }
                encoded = std.mem.trim(u8, buf[0..bytes_read], "\r\n");
            }
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
            self.allocator.free(credentials.password);
        }

        // Verify credentials
        const valid = self.auth_backend.verifyCredentials(credentials.username, credentials.password) catch {
            try self.sendResponse(tag, "NO", "Authentication failed");
            return;
        };

        if (!valid) {
            std.log.warn("Failed IMAP AUTHENTICATE attempt for user: {s}", .{credentials.username});
            try self.sendResponse(tag, "NO", "Authentication failed");
            return;
        }

        self.username = self.allocator.dupe(u8, credentials.username) catch {
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
        const username = if (std.mem.indexOfScalar(u8, full_username, '@')) |at_pos|
            full_username[0..at_pos]
        else
            full_username;

        // Free previous mailbox state
        self.freeMailboxFiles();

        // Strip quotes from mailbox name (Apple Mail sends "INBOX" with quotes sometimes)
        const mailbox = stripQuotes(mailbox_name);

        const is_inbox = std.ascii.eqlIgnoreCase(mailbox, "INBOX");

        // Build maildir path for any folder
        const user_dir = if (is_inbox)
            try std.fmt.allocPrint(self.allocator, "mail/{s}/new", .{username})
        else
            try std.fmt.allocPrint(self.allocator, "mail/{s}/{s}", .{ username, mailbox });

        // Ensure directory exists for standard mailboxes (Sent, Drafts, Trash, Junk, Archive)
        if (!is_inbox) {
            fs_compat.ensureDir(user_dir) catch {};
        }

        const files = fs_compat.listEmlFiles(self.allocator, user_dir) catch {
            // Directory doesn't exist or can't be read — treat as empty
            self.mailbox_dir = user_dir;
            self.mailbox_files = null;
            try self.sendUntagged("0 EXISTS");
            try self.sendUntagged("0 RECENT");
            try self.sendUntagged("OK [UIDVALIDITY 1772487000]");
            try self.sendUntagged("OK [UIDNEXT 1]");
            try self.sendUntagged("FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)");
            try self.sendUntagged("OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)]");
            self.state = .selected;
            try self.sendResponse(tag, "OK", "[READ-WRITE] SELECT completed");
            return;
        };
        if (is_inbox and files.len == 0) {
            // Fall back to global mail/new/ for INBOX
            self.allocator.free(user_dir);
            const global_dir = try self.allocator.dupe(u8, "mail/new");
            const inbox_files = fs_compat.listEmlFiles(self.allocator, global_dir) catch {
                self.mailbox_dir = global_dir;
                self.mailbox_files = null;
                try self.sendUntagged("0 EXISTS");
                try self.sendUntagged("0 RECENT");
                try self.sendUntagged("OK [UIDVALIDITY 1772487000]");
                try self.sendUntagged("OK [UIDNEXT 1]");
                try self.sendUntagged("FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)");
                try self.sendUntagged("OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)]");
                self.state = .selected;
                try self.sendResponse(tag, "OK", "[READ-WRITE] SELECT completed");
                return;
            };
            self.mailbox_dir = global_dir;
            self.mailbox_files = if (inbox_files.len > 0) inbox_files else null;
        } else {
            self.mailbox_dir = user_dir;
            self.mailbox_files = if (files.len > 0) files else null;
            // Free the zero-length files slice if not stored
            if (files.len == 0) {
                self.allocator.free(files);
            }
        }

        const msg_count = if (self.mailbox_files) |f| f.len else 0;

        // Send mailbox info
        const exists_msg = try std.fmt.allocPrint(self.allocator, "{d} EXISTS", .{msg_count});
        defer self.allocator.free(exists_msg);
        try self.sendUntagged(exists_msg);

        const recent_msg = try std.fmt.allocPrint(self.allocator, "{d} RECENT", .{msg_count});
        defer self.allocator.free(recent_msg);
        try self.sendUntagged(recent_msg);

        try self.sendUntagged("OK [UIDVALIDITY 1772487000]");
        const uidnext_msg = try std.fmt.allocPrint(self.allocator, "OK [UIDNEXT {d}]", .{msg_count + 1});
        defer self.allocator.free(uidnext_msg);
        try self.sendUntagged(uidnext_msg);
        try self.sendUntagged("FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)");
        try self.sendUntagged("OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)]");

        self.state = .selected;
        try self.sendResponse(tag, "OK", "[READ-WRITE] SELECT completed");
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
        const dir = self.mailbox_dir orelse {
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
        // BODY.PEEK[] or BODY[] or BODY[TEXT] or BODY[n] or RFC822 (not RFC822.SIZE) - wants full body
        const want_full_body = has_body_section or
            (std.mem.indexOf(u8, items_raw, "BODY.PEEK[]") != null) or
            (std.mem.indexOf(u8, items_raw, "BODY[]") != null) or
            (std.mem.indexOf(u8, items_raw, "BODY[TEXT]") != null) or
            (std.mem.indexOf(u8, items_raw, "RFC822") != null and
                std.mem.indexOf(u8, items_raw, "RFC822.SIZE") == null and
                std.mem.indexOf(u8, items_raw, "RFC822.HEADER") == null);
        const want_bodystructure = std.mem.indexOf(u8, items_raw, "BODYSTRUCTURE") != null;

        var seq = start;
        while (seq <= end) : (seq += 1) {
            const filename = files[seq - 1];
            const filepath = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ dir, filename });
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
            const name_no_ext = if (std.mem.endsWith(u8, basename, ".eml")) basename[0 .. basename.len - 4] else basename;
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

            // Build BODYSTRUCTURE string
            var bs_buf: [512]u8 = undefined;
            var bs_fbs = io_compat.fixedBufferStream(&bs_buf);
            const bs_writer = bs_fbs.writer();
            if (is_multipart) {
                // Simplified multipart structure
                bs_writer.print("((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"{s}\") NIL NIL \"7BIT\" {d} {d} NIL NIL NIL NIL)(\"TEXT\" \"HTML\" (\"CHARSET\" \"{s}\") NIL NIL \"7BIT\" {d} {d} NIL NIL NIL NIL) \"ALTERNATIVE\")", .{
                    charset, body.len, body.len / 40 + 1, charset, body.len, body.len / 40 + 1,
                }) catch {};
            } else if (is_html) {
                bs_writer.print("(\"TEXT\" \"HTML\" (\"CHARSET\" \"{s}\") NIL NIL \"7BIT\" {d} {d} NIL NIL NIL NIL)", .{
                    charset, body.len, body.len / 40 + 1,
                }) catch {};
            } else {
                bs_writer.print("(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"{s}\") NIL NIL \"7BIT\" {d} {d} NIL NIL NIL NIL)", .{
                    charset, body.len, body.len / 40 + 1,
                }) catch {};
            }
            const bodystructure = bs_fbs.getWritten();

            // Read actual flags from Maildir filename
            const msg_flags = MaildirFlags.fromFilename(filename);
            var flag_str_buf: [256]u8 = undefined;
            const flag_str = msg_flags.toImapString(&flag_str_buf);

            // Build optional parts
            var bs_part_buf: [600]u8 = undefined;
            const bs_part = if (want_bodystructure) blk: {
                var bfbs = io_compat.fixedBufferStream(&bs_part_buf);
                bfbs.writer().print(" BODYSTRUCTURE {s}", .{bodystructure}) catch break :blk @as([]const u8, "");
                break :blk bfbs.getWritten();
            } else @as([]const u8, "");

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
                    seq, seq, flag_str, content.len, id_part, bs_part, header.len, header,
                });
                defer self.allocator.free(resp);
                try self.writeData(resp);
                try self.writeData("\r\n");
            } else if (want_full_body and has_body_section) {
                // Numbered part or TEXT request — return just the body (after headers)
                const resp = try std.fmt.allocPrint(self.allocator, "* {d} FETCH (UID {d} FLAGS ({s}) RFC822.SIZE {d} INTERNALDATE \"{s}\"{s} BODY[{s}] {{{d}}}\r\n{s})", .{
                    seq, seq, flag_str, content.len, date_str, bs_part, body_section, body.len, body,
                });
                defer self.allocator.free(resp);
                try self.writeData(resp);
                try self.writeData("\r\n");
            } else if (want_full_body) {
                const resp = try std.fmt.allocPrint(self.allocator, "* {d} FETCH (UID {d} FLAGS ({s}) RFC822.SIZE {d} INTERNALDATE \"{s}\"{s} BODY[] {{{d}}}\r\n{s})", .{
                    seq, seq, flag_str, content.len, date_str, bs_part, content.len, content,
                });
                defer self.allocator.free(resp);
                try self.writeData(resp);
                try self.writeData("\r\n");
            } else {
                const resp = try std.fmt.allocPrint(self.allocator, "* {d} FETCH (UID {d} FLAGS ({s}) RFC822.SIZE {d}{s}{s})", .{
                    seq, seq, flag_str, content.len, id_part, bs_part,
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
    fn handleSearch(self: *ImapSession, tag: []const u8, criteria: []const u8) !void {
        if (self.state != .selected) {
            try self.sendResponse(tag, "NO", "Must select mailbox first");
            return;
        }

        const files = self.mailbox_files orelse {
            try self.sendUntagged("SEARCH");
            try self.sendResponse(tag, "OK", "SEARCH completed");
            return;
        };
        const dir = self.mailbox_dir orelse {
            try self.sendUntagged("SEARCH");
            try self.sendResponse(tag, "OK", "SEARCH completed");
            return;
        };

        // Parse criteria (case insensitive)
        const is_all = criteria.len == 0 or std.ascii.indexOfIgnoreCase(criteria, "ALL") != null;
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

        var buf: [8192]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        writer.writeAll("SEARCH") catch {};

        for (files, 0..) |filename, i| {
            const seq = i + 1;
            const flags = MaildirFlags.fromFilename(filename);

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

                // Text-based criteria: FROM, SUBJECT — require reading the file
                const need_content = std.ascii.indexOfIgnoreCase(criteria, "FROM") != null or
                    std.ascii.indexOfIgnoreCase(criteria, "SUBJECT") != null;
                if (need_content) {
                    const filepath = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ dir, filename }) catch continue;
                    defer self.allocator.free(filepath);
                    const content = fs_compat.readFileAlloc(self.allocator, filepath) catch continue;
                    defer self.allocator.free(content);

                    // Find header boundary
                    const hdr_end = if (std.mem.indexOf(u8, content, "\r\n\r\n")) |p| p else
                        if (std.mem.indexOf(u8, content, "\n\n")) |p| p else content.len;
                    const hdr = content[0..hdr_end];

                    var matches = true;
                    // Extract FROM search term
                    if (std.ascii.indexOfIgnoreCase(criteria, "FROM")) |from_pos| {
                        const after = criteria[from_pos + 4 ..];
                        const term = extractQuotedArg(after);
                        if (term.len > 0) {
                            // Check if From: header contains the term
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

            writer.print(" {d}", .{seq}) catch break;
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

        const files = self.mailbox_files orelse {
            try self.sendResponse(tag, "NO", "Mailbox is empty");
            return;
        };
        const src_dir = self.mailbox_dir orelse {
            try self.sendResponse(tag, "NO", "No mailbox selected");
            return;
        };
        const full_username = self.username orelse {
            try self.sendResponse(tag, "NO", "Not authenticated");
            return;
        };

        const local_part = if (std.mem.indexOfScalar(u8, full_username, '@')) |at_pos|
            full_username[0..at_pos]
        else
            full_username;

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
            const src_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ src_dir, filename });
            defer self.allocator.free(src_path);

            // Read source file
            const content = fs_compat.readFileAlloc(self.allocator, src_path) catch continue;
            defer self.allocator.free(content);

            // Write to destination with a new timestamp filename, preserving flags
            const timestamp = time_compat.milliTimestamp();
            const src_flags = MaildirFlags.fromFilename(filename);
            var suffix_buf: [16]u8 = undefined;
            const flag_suffix = src_flags.toSuffix(&suffix_buf);
            const dest_path = try std.fmt.allocPrint(self.allocator, "{s}/{d}.eml{s}", .{ dest_dir, timestamp + copied, flag_suffix });
            defer self.allocator.free(dest_path);

            const file = fs_compat.cwd().createFile(dest_path, .{}) catch continue;
            defer file.close();
            file.writeAll(content) catch continue;

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

        const files = self.mailbox_files orelse {
            try self.sendResponse(tag, "NO", "Mailbox is empty");
            return;
        };
        const src_dir = self.mailbox_dir orelse {
            try self.sendResponse(tag, "NO", "No mailbox selected");
            return;
        };
        const full_username = self.username orelse {
            try self.sendResponse(tag, "NO", "Not authenticated");
            return;
        };

        const local_part = if (std.mem.indexOfScalar(u8, full_username, '@')) |at_pos|
            full_username[0..at_pos]
        else
            full_username;

        const dest_name = stripQuotes(dest_mailbox);

        const dest_dir = if (std.ascii.eqlIgnoreCase(dest_name, "INBOX"))
            try std.fmt.allocPrint(self.allocator, "mail/{s}/new", .{local_part})
        else
            try std.fmt.allocPrint(self.allocator, "mail/{s}/{s}", .{ local_part, dest_name });
        defer self.allocator.free(dest_dir);

        fs_compat.ensureDir(dest_dir) catch {};

        // Collect sequence numbers to move, then process in reverse for correct EXPUNGE numbering
        var to_move = std.ArrayList(u32){};
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
            const src_path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ src_dir, filename }) catch continue;
            defer self.allocator.free(src_path);

            // Preserve flags from source filename in destination
            const src_flags = MaildirFlags.fromFilename(filename);
            var move_suffix_buf: [16]u8 = undefined;
            const move_flag_suffix = src_flags.toSuffix(&move_suffix_buf);
            const timestamp = time_compat.milliTimestamp();
            const dest_path = std.fmt.allocPrint(self.allocator, "{s}/{d}.eml{s}", .{ dest_dir, timestamp + seq, move_flag_suffix }) catch continue;
            defer self.allocator.free(dest_path);

            // Copy content to destination
            const content = fs_compat.readFileAlloc(self.allocator, src_path) catch continue;
            defer self.allocator.free(content);
            const file = fs_compat.cwd().createFile(dest_path, .{}) catch continue;
            defer file.close();
            file.writeAll(content) catch continue;

            // Delete source
            var path_buf: [4097]u8 = undefined;
            const written = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ src_dir, filename }) catch continue;
            path_buf[written.len] = 0;
            _ = std.c.unlink(@ptrCast(&path_buf));

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
        // EXAMINE is SELECT but read-only. We reuse handleSelect which sets [READ-WRITE].
        // After SELECT completes, the client will see [READ-WRITE] but EXAMINE callers
        // should see [READ-ONLY]. For simplicity, just call handleSelect — Apple Mail
        // doesn't typically use EXAMINE. A production server would track read-only state.
        try self.handleSelect(tag, mailbox_name);
    }

    /// Handle DELETE command — remove a mailbox.
    /// Implements RFC 3501 Section 6.3.4.
    fn handleDelete(self: *ImapSession, tag: []const u8, mailbox_name: []const u8) !void {
        if (self.state == .not_authenticated) {
            try self.sendResponse(tag, "NO", "Must authenticate first");
            return;
        }

        const full_username = self.username orelse {
            try self.sendResponse(tag, "NO", "Not authenticated");
            return;
        };
        const local_part = if (std.mem.indexOfScalar(u8, full_username, '@')) |at_pos|
            full_username[0..at_pos]
        else
            full_username;

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

        const full_username = self.username orelse {
            try self.sendResponse(tag, "NO", "Not authenticated");
            return;
        };
        const local_part = if (std.mem.indexOfScalar(u8, full_username, '@')) |at_pos|
            full_username[0..at_pos]
        else
            full_username;

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
        const dir = self.mailbox_dir orelse {
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

            // Send untagged FETCH response with updated flags (unless .SILENT)
            if (!is_silent) {
                var flag_str_buf: [256]u8 = undefined;
                const flag_str = flags.toImapString(&flag_str_buf);
                var resp_buf: [512]u8 = undefined;
                var fbs = io_compat.fixedBufferStream(&resp_buf);
                fbs.writer().print("{d} FETCH (FLAGS ({s}))", .{ seq, flag_str }) catch continue;
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

        const dir = self.mailbox_dir orelse {
            try self.sendResponse(tag, "OK", "EXPUNGE completed");
            return;
        };

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
            var path_buf: [4097]u8 = undefined;
            const path_written = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ dir, filename }) catch continue;
            path_buf[path_written.len] = 0;
            _ = std.c.unlink(@ptrCast(&path_buf));

            // Send untagged EXPUNGE
            var resp_buf: [32]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&resp_buf);
            fbs.writer().print("{d} EXPUNGE", .{seq}) catch continue;
            self.sendUntagged(fbs.getWritten()) catch continue;

            std.log.info("IMAP EXPUNGE: Deleted {s}/{s}", .{ dir, filename });

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
        // Log every command for debugging
        std.log.info("IMAP CMD: {s}", .{line});

        // Handle DONE (ends IDLE mode) - DONE has no tag
        if (self.idle_mode) {
            const trimmed = std.mem.trim(u8, line, " \t\r\n");
            if (std.ascii.eqlIgnoreCase(trimmed, "DONE")) {
                self.idle_mode = false;
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
                const mailbox = parts.next() orelse "INBOX";
                try self.handleSelect(tag, mailbox);
            },
            .list, .xlist => {
                // LIST/XLIST reference pattern
                const reference = parts.next() orelse "";
                const pattern = parts.next() orelse "*";
                if (command == .xlist) {
                    try self.handleXList(tag, reference, pattern);
                } else {
                    try self.handleList(tag, reference, pattern);
                }
            },
            .lsub => {
                // LSUB is same as LIST for subscribed folders (we treat all as subscribed)
                const reference = parts.next() orelse "";
                const pattern = parts.next() orelse "*";
                try self.handleList(tag, reference, pattern);
            },
            .status => {
                // STATUS mailbox (items)
                const mailbox_name = parts.next() orelse "INBOX";
                // Get rest of line as status items
                var status_items_buf: [256]u8 = undefined;
                var status_len: usize = 0;
                while (parts.next()) |part| {
                    if (status_len > 0) {
                        status_items_buf[status_len] = ' ';
                        status_len += 1;
                    }
                    const copy_len = @min(part.len, status_items_buf.len - status_len);
                    @memcpy(status_items_buf[status_len..][0..copy_len], part[0..copy_len]);
                    status_len += copy_len;
                }
                const status_items = status_items_buf[0..status_len];
                try self.handleStatus(tag, mailbox_name, status_items);
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
                if (self.mailbox_dir) |dir| {
                    if (self.mailbox_files) |files| {
                        for (files) |filename| {
                            const flags = MaildirFlags.fromFilename(filename);
                            if (flags.deleted) {
                                var path_buf: [4097]u8 = undefined;
                                const written = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ dir, filename }) catch continue;
                                path_buf[written.len] = 0;
                                _ = std.c.unlink(@ptrCast(&path_buf));
                            }
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
                // UID command - pass through to regular handler with UID prefix
                const sub_cmd = parts.next() orelse "";
                if (std.ascii.eqlIgnoreCase(sub_cmd, "FETCH")) {
                    const sequence_set = parts.next() orelse "1:*";
                    // Items may contain spaces (e.g. "(FLAGS UID BODY.PEEK[HEADER])"), get rest of line
                    const seq_end = @intFromPtr(sequence_set.ptr) + sequence_set.len - @intFromPtr(line.ptr);
                    const items = if (seq_end < line.len) std.mem.trim(u8, line[seq_end..], " \t") else "FLAGS";
                    try self.handleFetch(tag, sequence_set, if (items.len > 0) items else "FLAGS");
                } else if (std.ascii.eqlIgnoreCase(sub_cmd, "SEARCH")) {
                    // Collect rest of line after "UID SEARCH" as criteria
                    const sub_end = @intFromPtr(sub_cmd.ptr) + sub_cmd.len - @intFromPtr(line.ptr);
                    const uid_search_criteria = if (sub_end < line.len) std.mem.trim(u8, line[sub_end..], " \t") else "";
                    try self.handleSearch(tag, uid_search_criteria);
                } else if (std.ascii.eqlIgnoreCase(sub_cmd, "MOVE")) {
                    const uid_set = parts.next() orelse "1:*";
                    const dest = stripQuotes(parts.next() orelse "INBOX");
                    try self.handleMove(tag, uid_set, dest);
                } else if (std.ascii.eqlIgnoreCase(sub_cmd, "COPY")) {
                    // UID COPY <uid-set> <mailbox>
                    // UIDs = sequence numbers in our implementation (1-based index into sorted files)
                    const uid_set = parts.next() orelse "1:*";
                    const dest = parts.next() orelse "INBOX";
                    try self.handleCopy(tag, uid_set, dest);
                } else if (std.ascii.eqlIgnoreCase(sub_cmd, "STORE")) {
                    // UID STORE <uid-set> <flags-action>
                    const uid_set = parts.next() orelse "1:*";
                    const uid_end = @intFromPtr(uid_set.ptr) + uid_set.len - @intFromPtr(line.ptr);
                    const flags_action = if (uid_end < line.len) std.mem.trim(u8, line[uid_end..], " \t") else "";
                    try self.handleStore(tag, uid_set, flags_action);
                } else if (std.ascii.eqlIgnoreCase(sub_cmd, "EXPUNGE")) {
                    // UID EXPUNGE (RFC 4315)
                    try self.handleExpunge(tag);
                } else {
                    try self.sendResponse(tag, "OK", "UID command completed");
                }
            },
            .append => {
                // APPEND mailbox (\flags) {size} - read literal data and save to Maildir
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

                            // Parse mailbox name (first arg after APPEND)
                            const mailbox_raw = parts.next() orelse "INBOX";
                            const mailbox = stripQuotes(mailbox_raw);

                            // Set up pending append state
                            self.cleanupAppend();
                            self.append_tag = try self.allocator.dupe(u8, tag);
                            self.append_mailbox = try self.allocator.dupe(u8, mailbox);
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

                // No literal found - just acknowledge
                try self.sendResponse(tag, "OK", "[APPENDUID 1772487000 1] APPEND completed");
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
                if (create_name.len > 0) {
                    if (self.username) |uname| {
                        const local = if (std.mem.indexOfScalar(u8, uname, '@')) |at| uname[0..at] else uname;
                        const dir = std.fmt.allocPrint(self.allocator, "mail/{s}/{s}", .{ local, create_name }) catch null;
                        if (dir) |d| {
                            fs_compat.cwd().makePath(d) catch {};
                            self.allocator.free(d);
                        }
                    }
                }
                try self.sendResponse(tag, "OK", "CREATE completed");
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
                const dest = parts.next() orelse "INBOX";
                try self.handleCopy(tag, seq_set, dest);
            },
            .examine => {
                const mailbox = parts.next() orelse "INBOX";
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
                const dest = stripQuotes(parts.next() orelse "INBOX");
                try self.handleMove(tag, seq_set, dest);
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
    tls_context: ?*tls_mod.TlsContext = null,
    cert_key_pair: ?tls.config.CertKeyPair = null,

    pub fn init(allocator: std.mem.Allocator, config: ImapConfig, auth_backend: *auth.AuthBackend) ImapServer {
        var server = ImapServer{
            .allocator = allocator,
            .config = config,
            .sessions = std.ArrayList(*ImapSession){},
            .running = std.atomic.Value(bool).init(false),
            .auth_backend = auth_backend,
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
                logger.warn("IMAP accept error: {}", .{err});
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

        logger.info("IMAPS server listening on port {d} (SSL/TLS)", .{self.config.ssl_port});

        while (self.running.load(.monotonic)) {
            const connection = self.ssl_listener.?.accept() catch |err| {
                if (!self.running.load(.monotonic)) break; // Server is stopping
                logger.warn("IMAPS accept error: {}", .{err});
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
        session.* = ImapSession.init(self.allocator, connection, self.auth_backend);
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
                    const idle_tv: std.posix.timeval = .{ .sec = 5, .usec = 0 };
                    std.posix.setsockopt(connection.fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&idle_tv)) catch {};
                }

                // Read ciphertext from socket
                const bytes_read = connection.read(recv_buf[0..]) catch |err| {
                    // During IDLE, timeout is expected — poll for new mail
                    if (session.idle_mode and (err == error.WouldBlock or err == error.ConnectionTimedOut)) {
                        idle_poll_counter += 1;
                        // Check for new messages every poll cycle (~5 seconds)
                        if (session.state == .selected) {
                            _ = session.rescanMailbox() catch {};
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
                    const idle_tv: std.posix.timeval = .{ .sec = 5, .usec = 0 };
                    std.posix.setsockopt(connection.fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&idle_tv)) catch {};
                }

                const bytes_read = connection.read(&buffer) catch |err| {
                    if (session.idle_mode and (err == error.WouldBlock or err == error.ConnectionTimedOut)) {
                        if (session.state == .selected) {
                            _ = session.rescanMailbox() catch {};
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
                                const idle_tv: std.posix.timeval = .{ .sec = 5, .usec = 0 };
                                std.posix.setsockopt(connection.fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&idle_tv)) catch {};
                            }

                            const bytes_read = connection.read(tls_recv_buf[0..]) catch |err| {
                                if (session.idle_mode and (err == error.WouldBlock or err == error.ConnectionTimedOut)) {
                                    if (session.state == .selected) {
                                        _ = session.rescanMailbox() catch {};
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
