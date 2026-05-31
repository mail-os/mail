const std = @import("std");

/// WBXML (Wireless Binary XML, WAP-192) codec specialised for Microsoft
/// Exchange ActiveSync (MS-ASWBXML).
///
/// iOS/macOS EAS clients speak WBXML exclusively for protocol versions 12.1
/// and above — they will neither send nor accept plaintext XML. This module
/// provides:
///
///   * `Writer` — builds a WBXML document for responses (Provision, FolderSync,
///     Sync, GetItemEstimate, Ping, ...).
///   * `decode` — parses a request body into a `Node` tree so handlers can pull
///     out SyncKey / CollectionId / options etc.
///
/// Token tables are the canonical Z-Push/Grommunio assignments (MS-ASWBXML).
/// A tag is identified by a (code page, token) pair; the same token byte means
/// different things on different pages, so handlers always pass both.

// ============================================================================
// Global WBXML tokens (WAP-192 §5.8.1)
// ============================================================================

const SWITCH_PAGE: u8 = 0x00;
const END: u8 = 0x01;
const STR_I: u8 = 0x03;
const OPAQUE: u8 = 0xC3;

/// Set on a tag byte when the element has content (children / text) and is thus
/// terminated by an END token.
const HAS_CONTENT: u8 = 0x40;
/// Mask to recover the bare token from a tag byte (strips content/attr flags).
const TOKEN_MASK: u8 = 0x3F;

// ============================================================================
// Code pages
// ============================================================================

pub const Page = struct {
    pub const air_sync: u8 = 0;
    pub const contacts: u8 = 1;
    pub const email: u8 = 2;
    pub const calendar: u8 = 4;
    pub const get_item_estimate: u8 = 6;
    pub const folder_hierarchy: u8 = 7;
    pub const ping: u8 = 11;
    pub const provision: u8 = 13;
    pub const gal: u8 = 14;
    pub const air_sync_base: u8 = 17;
};

// ============================================================================
// Tag tokens, grouped by page (bare token values, no flags)
// ============================================================================

pub const AirSync = struct {
    pub const Synchronize: u8 = 0x05;
    pub const Replies: u8 = 0x06;
    pub const Add: u8 = 0x07;
    pub const Modify: u8 = 0x08;
    pub const Remove: u8 = 0x09;
    pub const Fetch: u8 = 0x0a;
    pub const SyncKey: u8 = 0x0b;
    pub const ClientEntryId: u8 = 0x0c;
    pub const ServerEntryId: u8 = 0x0d;
    pub const Status: u8 = 0x0e;
    pub const Folder: u8 = 0x0f;
    pub const FolderType: u8 = 0x10;
    pub const Version: u8 = 0x11;
    pub const FolderId: u8 = 0x12;
    pub const GetChanges: u8 = 0x13;
    pub const MoreAvailable: u8 = 0x14;
    pub const WindowSize: u8 = 0x15;
    pub const Perform: u8 = 0x16;
    pub const Options: u8 = 0x17;
    pub const FilterType: u8 = 0x18;
    pub const Conflict: u8 = 0x1b;
    pub const Folders: u8 = 0x1c;
    pub const Data: u8 = 0x1d;
    pub const DeletesAsMoves: u8 = 0x1e;
    pub const Supported: u8 = 0x20;
    pub const SoftDelete: u8 = 0x21;
    pub const MIMESupport: u8 = 0x22;
    pub const MIMETruncation: u8 = 0x23;
    pub const Wait: u8 = 0x24;
    pub const Limit: u8 = 0x25;
    pub const Partial: u8 = 0x26;
    pub const ConversationMode: u8 = 0x27;
    pub const MaxItems: u8 = 0x28;
    pub const HeartbeatInterval: u8 = 0x29;
};

pub const FolderHierarchy = struct {
    pub const Folders: u8 = 0x05;
    pub const Folder: u8 = 0x06;
    pub const DisplayName: u8 = 0x07;
    pub const ServerEntryId: u8 = 0x08;
    pub const ParentId: u8 = 0x09;
    pub const Type: u8 = 0x0a;
    pub const Response: u8 = 0x0b;
    pub const Status: u8 = 0x0c;
    pub const ContentClass: u8 = 0x0d;
    pub const Changes: u8 = 0x0e;
    pub const Add: u8 = 0x0f;
    pub const Remove: u8 = 0x10;
    pub const Update: u8 = 0x11;
    pub const SyncKey: u8 = 0x12;
    pub const FolderCreate: u8 = 0x13;
    pub const FolderDelete: u8 = 0x14;
    pub const FolderUpdate: u8 = 0x15;
    pub const FolderSync: u8 = 0x16;
    pub const Count: u8 = 0x17;
};

pub const Provision = struct {
    pub const Provision: u8 = 0x05;
    pub const Policies: u8 = 0x06;
    pub const Policy: u8 = 0x07;
    pub const PolicyType: u8 = 0x08;
    pub const PolicyKey: u8 = 0x09;
    pub const Data: u8 = 0x0a;
    pub const Status: u8 = 0x0b;
    pub const RemoteWipe: u8 = 0x0c;
    pub const EASProvisionDoc: u8 = 0x0d;
};

pub const GetItemEstimate = struct {
    pub const GetItemEstimate: u8 = 0x05;
    pub const Version: u8 = 0x06;
    pub const Folders: u8 = 0x07;
    pub const Folder: u8 = 0x08;
    pub const FolderType: u8 = 0x09;
    pub const FolderId: u8 = 0x0a;
    pub const DateTime: u8 = 0x0b;
    pub const Estimate: u8 = 0x0c;
    pub const Response: u8 = 0x0d;
    pub const Status: u8 = 0x0e;
};

pub const Ping = struct {
    pub const Ping: u8 = 0x05;
    pub const AutdState: u8 = 0x06;
    pub const Status: u8 = 0x07;
    pub const LifeTime: u8 = 0x08;
    pub const Folders: u8 = 0x09;
    pub const Folder: u8 = 0x0a;
    pub const ServerEntryId: u8 = 0x0b;
    pub const FolderType: u8 = 0x0c;
    pub const MaxFolders: u8 = 0x0d;
};

pub const AirSyncBase = struct {
    pub const BodyPreference: u8 = 0x05;
    pub const Type: u8 = 0x06;
    pub const TruncationSize: u8 = 0x07;
    pub const AllOrNone: u8 = 0x08;
    pub const Body: u8 = 0x0a;
    pub const Data: u8 = 0x0b;
    pub const EstimatedDataSize: u8 = 0x0c;
    pub const Truncated: u8 = 0x0d;
    pub const Attachments: u8 = 0x0e;
    pub const Attachment: u8 = 0x0f;
    pub const DisplayName: u8 = 0x10;
    pub const FileReference: u8 = 0x11;
    pub const Method: u8 = 0x12;
    pub const ContentId: u8 = 0x13;
    pub const ContentLocation: u8 = 0x14;
    pub const IsInline: u8 = 0x15;
    pub const NativeBodyType: u8 = 0x16;
    pub const ContentType: u8 = 0x17;
    pub const Preview: u8 = 0x18;
};

pub const Email = struct {
    pub const Attachment: u8 = 0x05;
    pub const Attachments: u8 = 0x06;
    pub const Body: u8 = 0x0c;
    pub const BodySize: u8 = 0x0d;
    pub const BodyTruncated: u8 = 0x0e;
    pub const DateReceived: u8 = 0x0f;
    pub const DisplayName: u8 = 0x10;
    pub const DisplayTo: u8 = 0x11;
    pub const Importance: u8 = 0x12;
    pub const MessageClass: u8 = 0x13;
    pub const Subject: u8 = 0x14;
    pub const Read: u8 = 0x15;
    pub const To: u8 = 0x16;
    pub const Cc: u8 = 0x17;
    pub const From: u8 = 0x18;
    pub const ReplyTo: u8 = 0x19;
    pub const ThreadTopic: u8 = 0x35;
    pub const InternetCPID: u8 = 0x39;
    pub const Flag: u8 = 0x3a;
    pub const FlagStatus: u8 = 0x3b;
    pub const ContentClass: u8 = 0x3c;
};

pub const Contacts = struct {
    pub const Anniversary: u8 = 0x05;
    pub const Birthday: u8 = 0x08;
    pub const Body: u8 = 0x09;
    pub const BusinessCity: u8 = 0x0d;
    pub const BusinessCountry: u8 = 0x0e;
    pub const BusinessPostalCode: u8 = 0x0f;
    pub const BusinessState: u8 = 0x10;
    pub const BusinessStreet: u8 = 0x11;
    pub const BusinessFaxNumber: u8 = 0x12;
    pub const BusinessPhoneNumber: u8 = 0x13;
    pub const CompanyName: u8 = 0x19;
    pub const Department: u8 = 0x1a;
    pub const Email1Address: u8 = 0x1b;
    pub const Email2Address: u8 = 0x1c;
    pub const Email3Address: u8 = 0x1d;
    pub const FileAs: u8 = 0x1e;
    pub const FirstName: u8 = 0x1f;
    pub const HomeCity: u8 = 0x21;
    pub const HomeCountry: u8 = 0x22;
    pub const HomePostalCode: u8 = 0x23;
    pub const HomeState: u8 = 0x24;
    pub const HomeStreet: u8 = 0x25;
    pub const HomePhoneNumber: u8 = 0x27;
    pub const JobTitle: u8 = 0x28;
    pub const LastName: u8 = 0x29;
    pub const MiddleName: u8 = 0x2a;
    pub const MobilePhoneNumber: u8 = 0x2b;
    pub const OfficeLocation: u8 = 0x2c;
    pub const Suffix: u8 = 0x35;
    pub const Title: u8 = 0x36;
    pub const WebPage: u8 = 0x37;
};

pub const Calendar = struct {
    pub const Timezone: u8 = 0x05;
    pub const AllDayEvent: u8 = 0x06;
    pub const Attendees: u8 = 0x07;
    pub const Attendee: u8 = 0x08;
    pub const Email: u8 = 0x09;
    pub const Name: u8 = 0x0a;
    pub const Body: u8 = 0x0b;
    pub const BusyStatus: u8 = 0x0d;
    pub const DtStamp: u8 = 0x11;
    pub const EndTime: u8 = 0x12;
    pub const Location: u8 = 0x17;
    pub const MeetingStatus: u8 = 0x18;
    pub const OrganizerEmail: u8 = 0x19;
    pub const OrganizerName: u8 = 0x1a;
    pub const Reminder: u8 = 0x24;
    pub const Sensitivity: u8 = 0x25;
    pub const Subject: u8 = 0x26;
    pub const StartTime: u8 = 0x27;
    pub const UID: u8 = 0x28;
};

// ============================================================================
// Writer
// ============================================================================

pub const Writer = struct {
    buf: std.ArrayList(u8),
    allocator: std.mem.Allocator,
    /// Code page currently selected in the byte stream; -1 until the first tag
    /// forces a SWITCH_PAGE.
    current_page: i16 = -1,

    pub fn init(allocator: std.mem.Allocator) Writer {
        return .{ .buf = .empty, .allocator = allocator };
    }

    pub fn deinit(self: *Writer) void {
        self.buf.deinit(self.allocator);
    }

    /// Hand ownership of the encoded document to the caller.
    pub fn toOwnedSlice(self: *Writer) ![]u8 {
        return self.buf.toOwnedSlice(self.allocator);
    }

    /// Emit the WBXML 1.3 header used by EAS: version 0x03, public id 0x01
    /// (unknown), charset 106 (UTF-8), empty string table.
    pub fn writeHeader(self: *Writer) !void {
        try self.buf.append(self.allocator, 0x03); // version 1.3
        try self.writeMbUint(0x01); // public identifier: unknown
        try self.writeMbUint(106); // charset: UTF-8 (IANA MIBenum 106)
        try self.writeMbUint(0x00); // string table length
    }

    fn writeMbUint(self: *Writer, value: u32) !void {
        var v = value;
        var tmp: [5]u8 = undefined;
        var n: usize = 0;
        tmp[n] = @intCast(v & 0x7F); // least significant group: continuation bit clear
        n += 1;
        v >>= 7;
        while (v != 0) : (v >>= 7) {
            tmp[n] = @as(u8, @intCast(v & 0x7F)) | 0x80;
            n += 1;
        }
        // Emit most-significant group first.
        while (n > 0) {
            n -= 1;
            try self.buf.append(self.allocator, tmp[n]);
        }
    }

    fn ensurePage(self: *Writer, page: u8) !void {
        if (self.current_page != page) {
            try self.buf.append(self.allocator, SWITCH_PAGE);
            try self.buf.append(self.allocator, page);
            self.current_page = page;
        }
    }

    /// Open an element that will contain children/text (terminate with `end`).
    pub fn startTag(self: *Writer, page: u8, token: u8) !void {
        try self.ensurePage(page);
        try self.buf.append(self.allocator, token | HAS_CONTENT);
    }

    /// Emit a self-closing empty element (no content, no END needed).
    pub fn emptyTag(self: *Writer, page: u8, token: u8) !void {
        try self.ensurePage(page);
        try self.buf.append(self.allocator, token);
    }

    /// Close the most recently opened element.
    pub fn end(self: *Writer) !void {
        try self.buf.append(self.allocator, END);
    }

    /// Write an inline (STR_I) string as element content.
    pub fn text(self: *Writer, s: []const u8) !void {
        try self.buf.append(self.allocator, STR_I);
        // STR_I is NUL-terminated, so any embedded NUL would corrupt the stream.
        for (s) |c| {
            if (c == 0) continue;
            try self.buf.append(self.allocator, c);
        }
        try self.buf.append(self.allocator, 0x00);
    }

    /// Write raw bytes as OPAQUE content (used for MIME / body data that may
    /// contain bytes unsafe for inline strings).
    pub fn opaqueData(self: *Writer, data: []const u8) !void {
        try self.buf.append(self.allocator, OPAQUE);
        try self.writeMbUint(@intCast(data.len));
        try self.buf.appendSlice(self.allocator, data);
    }

    /// Convenience: `<tag>text</tag>`.
    pub fn element(self: *Writer, page: u8, token: u8, s: []const u8) !void {
        try self.startTag(page, token);
        try self.text(s);
        try self.end();
    }

    /// Convenience: `<tag>integer</tag>`.
    pub fn elementInt(self: *Writer, page: u8, token: u8, value: i64) !void {
        var buf: [24]u8 = undefined;
        const s = std.fmt.bufPrint(&buf, "{d}", .{value}) catch unreachable;
        try self.element(page, token, s);
    }
};

// ============================================================================
// Decoder
// ============================================================================

pub const DecodeError = error{
    Truncated,
    InvalidHeader,
    UnexpectedEnd,
};

/// A decoded element. `text` slices into the source buffer (which must outlive
/// the tree). Child storage is heap-allocated and freed by `deinit`.
pub const Node = struct {
    page: u8,
    token: u8,
    text: ?[]const u8 = null,
    children: std.ArrayList(Node) = .empty,

    pub fn deinit(self: *Node, allocator: std.mem.Allocator) void {
        for (self.children.items) |*c| c.deinit(allocator);
        self.children.deinit(allocator);
    }

    /// First direct child matching (page, token), if any.
    pub fn child(self: *const Node, page: u8, token: u8) ?*const Node {
        for (self.children.items) |*c| {
            if (c.page == page and c.token == token) return c;
        }
        return null;
    }

    /// Text of the first direct child matching (page, token).
    pub fn childText(self: *const Node, page: u8, token: u8) ?[]const u8 {
        const c = self.child(page, token) orelse return null;
        return c.text;
    }

    /// Recursively search the subtree for the first node matching (page, token).
    pub fn find(self: *const Node, page: u8, token: u8) ?*const Node {
        for (self.children.items) |*c| {
            if (c.page == page and c.token == token) return c;
            if (c.find(page, token)) |found| return found;
        }
        return null;
    }
};

const Cursor = struct {
    data: []const u8,
    pos: usize = 0,
    page: u8 = 0,

    fn byte(self: *Cursor) DecodeError!u8 {
        if (self.pos >= self.data.len) return DecodeError.Truncated;
        const b = self.data[self.pos];
        self.pos += 1;
        return b;
    }

    fn mbUint(self: *Cursor) DecodeError!u32 {
        var result: u32 = 0;
        while (true) {
            const b = try self.byte();
            result = (result << 7) | (b & 0x7F);
            if (b & 0x80 == 0) break;
        }
        return result;
    }
};

/// Parse a WBXML document. Returns a synthetic root whose children are the
/// document's top-level elements. Caller owns the result; free with
/// `root.deinit(allocator)`.
pub fn decode(allocator: std.mem.Allocator, data: []const u8) !Node {
    var cur = Cursor{ .data = data };

    // Header: version, public id (mb), charset (mb), string table length (mb).
    _ = try cur.byte(); // version
    _ = try cur.mbUint(); // public identifier
    _ = try cur.mbUint(); // charset
    const strtbl_len = try cur.mbUint();
    if (cur.pos + strtbl_len > data.len) return DecodeError.InvalidHeader;
    cur.pos += strtbl_len;

    var root = Node{ .page = 0xFF, .token = 0xFF };
    errdefer root.deinit(allocator);

    try parseChildren(allocator, &cur, &root);
    return root;
}

/// Parse elements into `parent.children` until an END token or EOF.
fn parseChildren(allocator: std.mem.Allocator, cur: *Cursor, parent: *Node) !void {
    while (cur.pos < cur.data.len) {
        const b = cur.data[cur.pos];
        switch (b) {
            END => {
                cur.pos += 1;
                return;
            },
            SWITCH_PAGE => {
                cur.pos += 1;
                cur.page = try cur.byte();
            },
            STR_I => {
                cur.pos += 1;
                const start = cur.pos;
                while (cur.pos < cur.data.len and cur.data[cur.pos] != 0) cur.pos += 1;
                if (cur.pos >= cur.data.len) return DecodeError.Truncated;
                parent.text = cur.data[start..cur.pos];
                cur.pos += 1; // consume NUL
            },
            OPAQUE => {
                cur.pos += 1;
                const len = try cur.mbUint();
                if (cur.pos + len > cur.data.len) return DecodeError.Truncated;
                parent.text = cur.data[cur.pos .. cur.pos + len];
                cur.pos += len;
            },
            else => {
                cur.pos += 1;
                const has_content = (b & HAS_CONTENT) != 0;
                var node = Node{ .page = cur.page, .token = b & TOKEN_MASK };
                errdefer node.deinit(allocator);
                if (has_content) {
                    try parseChildren(allocator, cur, &node);
                }
                try parent.children.append(allocator, node);
            },
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

test "mb_uint round trips through writer header" {
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeHeader();
    // version, then mb(1)=0x01, mb(106)=0x6A, mb(0)=0x00
    try std.testing.expectEqualSlices(u8, &.{ 0x03, 0x01, 0x6A, 0x00 }, w.buf.items);
}

test "writer emits switch page and tags once" {
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.startTag(Page.folder_hierarchy, FolderHierarchy.FolderSync);
    try w.element(Page.folder_hierarchy, FolderHierarchy.Status, "1");
    try w.end();

    // SWITCH_PAGE 0x00, page 7, FolderSync|0x40, Status|0x40, STR_I '1' 0x00,
    // END (status), END (foldersync)
    const expected = [_]u8{
        SWITCH_PAGE, 0x07,
        FolderHierarchy.FolderSync | HAS_CONTENT,
        FolderHierarchy.Status | HAS_CONTENT,
        STR_I, '1', 0x00,
        END,
        END,
    };
    try std.testing.expectEqualSlices(u8, &expected, w.buf.items);
}

test "decode recovers tags and text across pages" {
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeHeader();
    try w.startTag(Page.air_sync, AirSync.Synchronize);
    try w.startTag(Page.air_sync, AirSync.Folders);
    try w.startTag(Page.air_sync, AirSync.Folder);
    try w.element(Page.air_sync, AirSync.SyncKey, "0");
    try w.element(Page.air_sync, AirSync.FolderId, "5");
    try w.end();
    try w.end();
    try w.end();

    const bytes = try w.toOwnedSlice();
    defer std.testing.allocator.free(bytes);

    var root = try decode(std.testing.allocator, bytes);
    defer root.deinit(std.testing.allocator);

    const sync = root.child(Page.air_sync, AirSync.Synchronize) orelse return error.TestUnexpectedResult;
    const folder = sync.find(Page.air_sync, AirSync.Folder) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("0", folder.childText(Page.air_sync, AirSync.SyncKey).?);
    try std.testing.expectEqualStrings("5", folder.childText(Page.air_sync, AirSync.FolderId).?);
}

test "decode reads opaque body" {
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.writeHeader();
    try w.startTag(Page.air_sync_base, AirSyncBase.Body);
    try w.startTag(Page.air_sync_base, AirSyncBase.Data);
    try w.opaqueData("hi\x00there");
    try w.end();
    try w.end();

    const bytes = try w.toOwnedSlice();
    defer std.testing.allocator.free(bytes);

    var root = try decode(std.testing.allocator, bytes);
    defer root.deinit(std.testing.allocator);

    const body = root.child(Page.air_sync_base, AirSyncBase.Body).?;
    try std.testing.expectEqualStrings("hi\x00there", body.childText(Page.air_sync_base, AirSyncBase.Data).?);
}
