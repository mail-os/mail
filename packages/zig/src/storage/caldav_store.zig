//! CalDAV/CardDAV Storage Module
//!
//! Provides persistent storage for calendars, events, address books, and contacts.
//! Supports sync tokens for efficient synchronization (RFC 6578).
//!
//! Features:
//! - Calendar and address book collections
//! - Event and contact CRUD operations
//! - Sync tokens for incremental sync
//! - ETag management for conflict detection
//! - iCalendar (ICS) and vCard (VCF) parsing/generation
//!
//! Usage:
//! ```zig
//! var store = try CalDavStore.init(allocator, .{});
//! defer store.deinit();
//!
//! // Create calendar
//! const cal_id = try store.createCalendar(user_id, "Work Calendar", null);
//!
//! // Add event
//! const event = try store.createEvent(cal_id, event_data);
//!
//! // Sync with token
//! const changes = try store.getChangesSince(cal_id, sync_token);
//! ```

const std = @import("std");
const shared_sync = @import("dav_shared_sync.zig");
pub const contact_vcard = @import("contact_vcard.zig");
const io_compat = @import("../core/io_compat.zig");
const Allocator = std.mem.Allocator;
const mutex_compat = @import("../core/mutex_compat.zig");
const database = @import("db_sqlite.zig");
const accounts = @import("database.zig");
const teams = @import("team_store.zig");
const icalendar = @import("../protocol/icalendar.zig");
const icalendar_busy = @import("../protocol/icalendar_busy.zig");
const reminder = @import("../protocol/icalendar_reminder.zig");
const calendar_invite = @import("../api/webmail_calendar_invite.zig");

/// Get the current epoch timestamp in seconds (cross-platform).
fn currentTimestamp() i64 {
    var ts: std.c.timespec = undefined;
    const rc = std.c.clock_gettime(.REALTIME, &ts);
    if (rc != 0) return 0;
    return ts.sec;
}

// =============================================================================
// Configuration
// =============================================================================

pub const StoreConfig = struct {
    /// Base storage path
    storage_path: []const u8 = "/var/lib/mail/caldav",

    /// Enable sync tokens
    enable_sync_tokens: bool = true,

    /// Maximum sync history entries
    max_sync_history: u32 = 10000,

    /// Stable account ID of the disposable client synchronization canary.
    sync_canary_mailbox_id: ?i64 = null,

    /// Default calendar timezone
    default_timezone: []const u8 = "UTC",

    /// Maximum event size (bytes)
    max_event_size: u32 = 1024 * 1024, // 1MB

    /// Maximum contact size (bytes)
    max_contact_size: u32 = 512 * 1024, // 512KB

    /// Optional SQLite file backing the store. When set, calendars/events/
    /// address books/contacts are loaded on startup and written through on every
    /// mutation, so data survives restarts. When null the store is purely
    /// in-memory (unchanged legacy behavior).
    db_path: ?[]const u8 = null,
    account_db: ?*accounts.Database = null,
};

// =============================================================================
// Data Types
// =============================================================================

pub const Calendar = struct {
    id: u64,
    user_id: u64,
    name: []const u8,
    display_name: ?[]const u8 = null,
    description: ?[]const u8,
    color: ?[]const u8,
    timezone: []const u8,
    created_at: i64,
    modified_at: i64,
    sync_token: u64,
    dav_history_floor: u64 = 0,
    ctag: []const u8, // Collection tag
    share_id: ?teams.CalendarShareId = null,
};

pub const Event = struct {
    id: u64,
    calendar_id: u64,
    uid: []const u8,
    summary: []const u8,
    description: ?[]const u8,
    location: ?[]const u8,
    dtstart: i64,
    dtend: ?i64,
    all_day: bool,
    rrule: ?[]const u8,
    recurring: bool = false,
    shareable: bool = false,
    reminder_coverage: reminder.Coverage = .{},
    organizer: ?[]const u8,
    status: EventStatus,
    created_at: i64,
    modified_at: i64,
    etag: []const u8,
    ics_data: []const u8, // Raw ICS data
    source_message: ?MessageReference = null,
    invitation_key: ?[64]u8 = null,
    invitation_revisions: ?[]const u8 = null,
    invitation_projections: ?[]const u8 = null,

    pub const EventStatus = enum {
        tentative,
        confirmed,
        cancelled,
    };
};

pub const MessageReference = [32]u8;

pub const CalendarSummary = struct {
    id: u64,
    name: []const u8,
    display_name: ?[]const u8 = null,
    description: ?[]const u8,
    color: ?[]const u8,
    timezone: []const u8,
};

pub const CalendarEventSummary = struct {
    id: u64,
    calendar_id: u64,
    uid: []const u8,
    summary: []const u8,
    location: ?[]const u8,
    start: i64,
    end: ?i64,
    all_day: bool,
    recurrence_rule: ?[]const u8,
    recurring: bool,
    icalendar: ?[]const u8 = null,
    status: Event.EventStatus,
    etag: []const u8,
};

pub const CalendarEventDetail = struct {
    event: CalendarEventSummary,
    calendar_id: u64,
    description: ?[]const u8,
    organizer: ?[]const u8,
    modified_at: i64,
    ics_data: []const u8,
    source_message: ?MessageReference = null,
};

pub const ActiveSyncResource = struct {
    id: u64,
    etag: []const u8,
    timezone: []const u8 = "UTC",
    recurring: bool = false,
};

pub const ActiveSyncContact = struct {
    etag: []const u8,
    full_name: []const u8,
    given_name: ?[]const u8,
    family_name: ?[]const u8,
    organization: ?[]const u8,
    title: ?[]const u8,
    note: ?[]const u8,
    emails: []const []const u8,
    phones: []const PhoneNumber,
};

pub const AddressBook = struct {
    id: u64,
    user_id: u64,
    name: []const u8,
    display_name: ?[]const u8 = null,
    description: ?[]const u8,
    created_at: i64,
    modified_at: i64,
    sync_token: u64,
    dav_history_floor: u64 = 0,
    ctag: []const u8,
};

pub const Contact = struct {
    id: u64,
    addressbook_id: u64,
    uid: []const u8,
    full_name: []const u8,
    given_name: ?[]const u8,
    family_name: ?[]const u8,
    nickname: ?[]const u8,
    organization: ?[]const u8,
    title: ?[]const u8,
    birthday: ?i64,
    note: ?[]const u8,
    photo_url: ?[]const u8,
    created_at: i64,
    modified_at: i64,
    etag: []const u8,
    vcf_data: []const u8, // Raw VCF data
};

pub const EmailAddress = struct {
    contact_id: u64,
    email: []const u8,
    email_type: EmailType,
    is_primary: bool,

    pub const EmailType = enum { home, work, other };
};

pub const ContactCard = struct {
    uid: []const u8,
    card_uid: []const u8,
    name: []const u8,
    note: []const u8,
    kind: contact_vcard.Kind,
    emails: []const []const u8,
    members: []const []const u8,
    etag: []const u8,
};

pub const AddressBookSnapshot = struct {
    books: []const []const u8,
    book: []const u8,
    cards: []const ContactCard,
};

pub const ContactEdit = struct {
    kind: contact_vcard.Kind,
    name: []const u8,
    note: []const u8 = "",
    emails: []const []const u8 = &.{},
    members: []const []const u8 = &.{},
};

pub const ContactSuggestion = struct { name: []const u8, address: []const u8 };

pub const PhoneNumber = struct {
    contact_id: u64,
    number: []const u8,
    phone_type: PhoneType,
    is_primary: bool,

    pub const PhoneType = enum { home, work, mobile, fax, other };
};

pub const Address = struct {
    contact_id: u64,
    street: ?[]const u8,
    city: ?[]const u8,
    state: ?[]const u8,
    postal_code: ?[]const u8,
    country: ?[]const u8,
    address_type: AddressType,

    pub const AddressType = enum { home, work, other };
};

// =============================================================================
// Sync Types
// =============================================================================

pub const SyncToken = struct {
    collection_id: u64,
    token: u64,
    timestamp: i64,
};

pub const SyncChange = struct {
    resource_id: u64,
    collection_id: u64,
    resource_type: ResourceType,
    change_type: ChangeType,
    token: u64,
    etag: []const u8,
    uid: []const u8,
    timestamp: i64,

    pub const ResourceType = enum { event, contact };
    pub const ChangeType = enum { created, modified, deleted };
};

const SyncHistory = struct {
    changes: std.ArrayList(SyncChange) = .empty,
    limit: usize,
};

pub const SyncReport = struct {
    changes: []SyncChange,
    new_sync_token: u64,
    more_available: bool,
};

pub const DavSyncQuery = shared_sync.Query;
pub const DavSyncMember = shared_sync.Member;
pub const DavSyncReport = shared_sync.Report;

pub const DavCollection = struct {
    name: []const u8,
    ctag: []const u8,
    token: []const u8,
    properties: DavCollectionProperties,
};

pub const DavCollectionProperties = struct {
    name: []const u8 = "",
    display_name: ?[]const u8 = null,
    description: ?[]const u8 = null,
    color: ?[]const u8 = null,
};

pub const CollectionProperty = union(enum) { keep, remove, set: []const u8 };

pub const CollectionPropertyPatch = struct {
    display_name: CollectionProperty = .keep,
    description: CollectionProperty = .keep,
    color: CollectionProperty = .keep,
};

pub const ResourceConditions = struct {
    if_match: ?[]const u8 = null,
    if_none_match: ?[]const u8 = null,

    pub fn allows(self: ResourceConditions, etag: ?[]const u8) bool {
        if (self.if_match) |tags| {
            if (!matchesAny(tags, etag, false)) return false;
        }
        if (self.if_none_match) |tags| {
            if (matchesAny(tags, etag, true)) return false;
        }
        return true;
    }

    fn matchesAny(tags: []const u8, current: ?[]const u8, weak: bool) bool {
        const etag = current orelse return false;
        if (std.mem.eql(u8, tags, "*")) return true;
        var start: usize = 0;
        var quoted = false;
        for (tags, 0..) |byte, index| {
            if (byte == '"') quoted = !quoted;
            if (byte == ',' and !quoted) {
                if (matches(tags[start..index], etag, weak)) return true;
                start = index + 1;
            }
        }
        return matches(tags[start..], etag, weak);
    }

    fn matches(incoming: []const u8, etag: []const u8, weak: bool) bool {
        const candidate = std.mem.trim(u8, incoming, " \t");
        const tag = if (weak and std.mem.startsWith(u8, candidate, "W/")) candidate[2..] else candidate;
        return std.mem.eql(u8, tag, etag);
    }
};

pub const PutResource = struct {
    created: bool,
    etag_buf: [64]u8 = undefined,
    etag_len: usize,

    fn init(created: bool, value: []const u8) PutResource {
        var result = PutResource{ .created = created, .etag_len = value.len };
        @memcpy(result.etag_buf[0..value.len], value);
        return result;
    }

    pub fn etag(self: *const PutResource) []const u8 {
        return self.etag_buf[0..self.etag_len];
    }
};

pub const Resource = struct { body: []u8, etag: []u8 };

// =============================================================================
// CalDAV Store
// =============================================================================

pub const CalDavStore = struct {
    const Self = @This();

    allocator: Allocator,
    config: StoreConfig,

    /// Serialises all read/mutation access to the maps below. The store is
    /// shared across CalDAV connection threads AND the ActiveSync handler (which
    /// runs on the same TLS server's connection threads), so concurrent map
    /// iteration/mutation would otherwise corrupt state. Locked only at public
    /// leaf entry points — no public method calls another locked one, so there
    /// is no re-entrant deadlock.
    mutex: mutex_compat.Mutex = .{},

    /// Optional SQLite persistence. Null = pure in-memory. All persistence
    /// helpers no-op when this is null, so the legacy path is unchanged.
    conn: ?database.Connection = null,

    // In-memory storage (would be SQLite in production)
    calendars: std.AutoHashMap(u64, Calendar),
    events: std.AutoHashMap(u64, Event),
    addressbooks: std.AutoHashMap(u64, AddressBook),
    contacts: std.AutoHashMap(u64, Contact),
    emails: std.ArrayList(EmailAddress),
    phones: std.ArrayList(PhoneNumber),
    addresses: std.ArrayList(Address),

    // User registry (username -> user_id)
    user_ids: std.ArrayList(UserEntry),
    next_user_id: u64,

    sync_history: SyncHistory,
    // Keep several complete CalDAV and CardDAV create/delete probe cycles.
    canary_sync_history: SyncHistory = .{ .limit = 16 },
    sync_canary_user_id: ?u64 = null,
    current_sync_token: u64,
    // This changes whenever the in-memory journal is rebuilt. Persisted
    // resources can be enumerated again using an empty DAV token.
    dav_sync_epoch: [16]u8,
    shared_dav_sync: shared_sync.Store,

    // ID generators
    next_calendar_id: u64,
    next_event_id: u64,
    next_addressbook_id: u64,
    next_contact_id: u64,

    pub const UserEntry = struct {
        username: []const u8,
        user_id: u64,
        mailbox_id: ?i64,
    };

    /// Resolve the owned collection, evaluate the precondition, and write the
    /// resource under the same lock, including a first PUT into a new collection.
    pub fn putEventResource(self: *Self, user_id: u64, collection: []const u8, uid: []const u8, conditions: ResourceConditions, data: EventData) !PutResource {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.getAddressBookByName(user_id, collection) != null) return error.WrongCollectionType;
        const calendar_id = if (self.getCalendarByName(user_id, collection)) |item| item.id else blk: {
            if (!conditions.allows(null)) return error.PreconditionFailed;
            break :blk try self.createCalendarLocked(user_id, collection, null);
        };
        return self.putEventResourceLocked(calendar_id, self.getEventByUid(calendar_id, uid), conditions, data);
    }

    fn putEventResourceLocked(self: *Self, calendar_id: u64, existing: ?Event, conditions: ResourceConditions, data: EventData) !PutResource {
        if (existing) |event| {
            if (!conditions.allows(event.etag)) return error.PreconditionFailed;
            try self.updateEventLocked(event.id, data);
            return PutResource.init(false, self.events.get(event.id).?.etag);
        }
        if (!conditions.allows(null)) return error.PreconditionFailed;
        const id = try self.createEventLocked(calendar_id, data);
        return PutResource.init(true, self.events.get(id).?.etag);
    }

    pub fn putContactResource(self: *Self, user_id: u64, collection: []const u8, uid: []const u8, conditions: ResourceConditions, data: ContactData) !PutResource {
        self.mutex.lock();
        defer self.mutex.unlock();
        const book_id = if (self.getAddressBookByName(user_id, collection)) |item| item.id else blk: {
            if (!conditions.allows(null)) return error.PreconditionFailed;
            break :blk try self.createAddressBookLocked(user_id, collection, null);
        };
        if (self.getContactByUid(book_id, uid)) |contact| {
            if (!conditions.allows(contact.etag)) return error.PreconditionFailed;
            try self.updateContactLocked(contact.id, data);
            return PutResource.init(false, self.contacts.get(contact.id).?.etag);
        }
        if (!conditions.allows(null)) return error.PreconditionFailed;
        const id = try self.createContactLocked(book_id, data);
        return PutResource.init(true, self.contacts.get(id).?.etag);
    }

    /// The resource and its ETag must describe the same version even if a
    /// different connection updates or deletes it during the response.
    pub fn getResource(self: *Self, user_id: u64, collection: []const u8, uid: []const u8, kind: SyncChange.ResourceType) !?Resource {
        self.mutex.lock();
        defer self.mutex.unlock();
        const a = self.allocator;
        switch (kind) {
            .event => {
                const calendar = self.getCalendarByName(user_id, collection) orelse return null;
                const event = self.getEventByUid(calendar.id, uid) orelse return null;
                return try copyEventResource(a, event);
            },
            .contact => {
                const book = self.getAddressBookByName(user_id, collection) orelse return null;
                const contact = self.getContactByUid(book.id, uid) orelse return null;
                const etag = try a.dupe(u8, contact.etag);
                errdefer a.free(etag);
                return .{ .etag = etag, .body = try self.generateVcfLocked(contact) };
            },
        }
    }

    fn copyEventResource(a: Allocator, event: Event) !Resource {
        const etag = try a.dupe(u8, event.etag);
        errdefer a.free(etag);
        const body = if (event.ics_data.len > 0) event.ics_data else "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n";
        return .{ .etag = etag, .body = try a.dupe(u8, body) };
    }

    pub fn deleteResource(self: *Self, user_id: u64, collection: []const u8, uid: []const u8, kind: SyncChange.ResourceType, conditions: ResourceConditions) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const missing = if (conditions.allows(null)) error.NotFound else error.PreconditionFailed;
        switch (kind) {
            .event => {
                const calendar = self.getCalendarByName(user_id, collection) orelse return missing;
                const event = self.getEventByUid(calendar.id, uid) orelse return missing;
                if (!conditions.allows(event.etag)) return error.PreconditionFailed;
                try self.deleteEventLocked(event.id);
            },
            .contact => {
                const book = self.getAddressBookByName(user_id, collection) orelse return missing;
                const contact = self.getContactByUid(book.id, uid) orelse return missing;
                if (!conditions.allows(contact.etag)) return error.PreconditionFailed;
                try self.deleteContactLocked(contact.id);
            },
        }
    }

    pub fn init(allocator: Allocator, config: StoreConfig) !Self {
        var self = Self{
            .allocator = allocator,
            .config = config,
            .calendars = std.AutoHashMap(u64, Calendar).init(allocator),
            .events = std.AutoHashMap(u64, Event).init(allocator),
            .addressbooks = std.AutoHashMap(u64, AddressBook).init(allocator),
            .contacts = std.AutoHashMap(u64, Contact).init(allocator),
            .emails = .empty,
            .phones = .empty,
            .addresses = .empty,
            .user_ids = .empty,
            .next_user_id = 1,
            .sync_history = .{ .limit = config.max_sync_history },
            .current_sync_token = 1,
            .dav_sync_epoch = undefined,
            .shared_dav_sync = shared_sync.Store.init(allocator),
            .next_calendar_id = 1,
            .next_event_id = 1,
            .next_addressbook_id = 1,
            .next_contact_id = 1,
        };
        io_compat.randomBytes(&self.dav_sync_epoch);

        // Never serve persisted records until the ownership registry and its
        // reserved IDs have been loaded successfully.
        errdefer self.deinit();
        if (config.db_path) |path| {
            self.conn = try database.Connection.open(allocator, path);
            if (self.conn) |*conn| {
                try ensureSchema(conn);
                try self.loadFromDb();
            }
        }

        if (config.sync_canary_mailbox_id) |mailbox_id| {
            self.sync_canary_user_id = self.findUserIdLocked("", mailbox_id);
        }

        return self;
    }

    pub fn deinit(self: *Self) void {
        if (self.conn) |*conn| conn.close();
        var cal_iter = self.calendars.iterator();
        while (cal_iter.next()) |entry| {
            self.freeCalendar(entry.value_ptr.*);
        }
        var event_iter = self.events.iterator();
        while (event_iter.next()) |entry| {
            self.freeEvent(entry.value_ptr.*);
        }
        var ab_iter = self.addressbooks.iterator();
        while (ab_iter.next()) |entry| {
            self.freeAddressBook(entry.value_ptr.*);
        }
        var contact_iter = self.contacts.iterator();
        while (contact_iter.next()) |entry| {
            self.freeContact(entry.value_ptr.*);
        }
        for ([_]*SyncHistory{ &self.sync_history, &self.canary_sync_history }) |history| {
            for (history.changes.items) |change| self.freeChange(change);
            history.changes.deinit(self.allocator);
        }
        self.calendars.deinit();
        self.events.deinit();
        self.addressbooks.deinit();
        self.contacts.deinit();
        for (self.emails.items) |email| self.allocator.free(email.email);
        for (self.phones.items) |phone| self.allocator.free(phone.number);
        self.emails.deinit(self.allocator);
        self.phones.deinit(self.allocator);
        self.addresses.deinit(self.allocator);
        for (self.user_ids.items) |entry| self.allocator.free(entry.username);
        self.user_ids.deinit(self.allocator);
        self.shared_dav_sync.deinit();
    }

    // -------------------------------------------------------------------------
    // SQLite persistence (all helpers no-op when `conn` is null)
    // -------------------------------------------------------------------------

    fn ensureSchema(conn: *database.Connection) !void {
        try conn.exec(
            \\CREATE TABLE IF NOT EXISTS dav_users (id INTEGER PRIMARY KEY, username TEXT NOT NULL, mailbox_id INTEGER UNIQUE);
            \\CREATE UNIQUE INDEX IF NOT EXISTS idx_dav_users_local_name ON dav_users(username) WHERE mailbox_id IS NULL;
            \\CREATE TABLE IF NOT EXISTS dav_calendars (id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, description TEXT, color TEXT, timezone TEXT, created_at INTEGER, modified_at INTEGER, sync_token INTEGER, ctag TEXT, share_id TEXT, display_name TEXT);
            \\CREATE TABLE IF NOT EXISTS dav_events (id INTEGER PRIMARY KEY, calendar_id INTEGER, uid TEXT, summary TEXT, description TEXT, location TEXT, dtstart INTEGER, dtend INTEGER, all_day INTEGER, rrule TEXT, organizer TEXT, status INTEGER, created_at INTEGER, modified_at INTEGER, etag TEXT, ics_data TEXT, source_message_ref TEXT);
            \\CREATE TABLE IF NOT EXISTS dav_addressbooks (id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, description TEXT, created_at INTEGER, modified_at INTEGER, sync_token INTEGER, ctag TEXT, display_name TEXT);
            \\CREATE TABLE IF NOT EXISTS dav_contacts (id INTEGER PRIMARY KEY, addressbook_id INTEGER, uid TEXT, full_name TEXT, given_name TEXT, family_name TEXT, nickname TEXT, organization TEXT, title TEXT, birthday INTEGER, note TEXT, photo_url TEXT, created_at INTEGER, modified_at INTEGER, etag TEXT, vcf_data TEXT);
            \\CREATE TABLE IF NOT EXISTS dav_emails (contact_id INTEGER, email TEXT, email_type INTEGER, is_primary INTEGER);
            \\CREATE TABLE IF NOT EXISTS dav_phones (contact_id INTEGER, number TEXT, phone_type INTEGER, is_primary INTEGER);
            \\CREATE INDEX IF NOT EXISTS idx_dav_events_cal ON dav_events(calendar_id);
            \\CREATE TABLE IF NOT EXISTS dav_reminder_dismissals (user_id INTEGER NOT NULL, reminder_key TEXT NOT NULL, due_at INTEGER NOT NULL, PRIMARY KEY(user_id, reminder_key));
            \\CREATE INDEX IF NOT EXISTS idx_dav_reminder_due ON dav_reminder_dismissals(due_at);
            \\CREATE INDEX IF NOT EXISTS idx_dav_contacts_ab ON dav_contacts(addressbook_id);
            \\CREATE INDEX IF NOT EXISTS idx_dav_emails_c ON dav_emails(contact_id);
            \\CREATE INDEX IF NOT EXISTS idx_dav_phones_c ON dav_phones(contact_id);
        );
        try ensureTextColumn(conn, "dav_calendars", "share_id");
        try ensureTextColumn(conn, "dav_calendars", "display_name");
        try ensureTextColumn(conn, "dav_addressbooks", "display_name");
        try ensureTextColumn(conn, "dav_events", "source_message_ref");
        try ensureTextColumn(conn, "dav_events", "invitation_key");
        try ensureTextColumn(conn, "dav_events", "invitation_revisions");
        try ensureTextColumn(conn, "dav_events", "invitation_projections");
        try conn.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_dav_calendar_share_id ON dav_calendars(share_id) WHERE share_id IS NOT NULL");
    }

    fn ensureTextColumn(conn: *database.Connection, comptime table: []const u8, comptime column: []const u8) !void {
        const exists = blk: {
            var columns = try conn.prepare("SELECT 1 FROM pragma_table_info('" ++ table ++ "') WHERE name='" ++ column ++ "'");
            defer columns.finalize();
            break :blk try columns.step();
        };
        if (!exists) try conn.exec("ALTER TABLE " ++ table ++ " ADD COLUMN " ++ column ++ " TEXT");
    }

    fn bindOptText(stmt: *database.Statement, idx: c_int, v: ?[]const u8) !void {
        if (v) |s| try stmt.bindText(idx, s) else try stmt.bindNull(idx);
    }

    fn bindOptInt(stmt: *database.Statement, idx: c_int, v: ?i64) !void {
        if (v) |n| try stmt.bindInt(idx, n) else try stmt.bindNull(idx);
    }

    fn dupCol(self: *Self, stmt: *database.Statement, idx: c_int) []const u8 {
        const s = stmt.columnText(idx) catch return "";
        return self.allocator.dupe(u8, s) catch "";
    }

    fn dupColOpt(self: *Self, stmt: *database.Statement, idx: c_int) ?[]const u8 {
        if (stmt.columnIsNull(idx)) return null;
        return self.dupCol(stmt, idx);
    }

    fn dbExecId(self: *Self, comptime sql_fmt: []const u8, id: u64) void {
        const conn = if (self.conn) |*c| c else return;
        var buf: [160]u8 = undefined;
        const sql = std.fmt.bufPrint(&buf, sql_fmt, .{id}) catch return;
        conn.exec(sql) catch {};
    }

    fn persistCalendar(self: *Self, cal: Calendar) !void {
        const conn = if (self.conn) |*c| c else return;
        var stmt = try conn.prepare("INSERT OR REPLACE INTO dav_calendars (id,user_id,name,description,color,timezone,created_at,modified_at,sync_token,ctag,share_id,display_name) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)");
        defer stmt.finalize();
        try stmt.bindInt(1, @intCast(cal.id));
        try stmt.bindInt(2, @intCast(cal.user_id));
        try stmt.bindText(3, cal.name);
        try bindOptText(&stmt, 4, cal.description);
        try bindOptText(&stmt, 5, cal.color);
        try stmt.bindText(6, cal.timezone);
        try stmt.bindInt(7, cal.created_at);
        try stmt.bindInt(8, cal.modified_at);
        try stmt.bindInt(9, @intCast(cal.sync_token));
        try stmt.bindText(10, cal.ctag);
        try bindOptText(&stmt, 11, if (cal.share_id) |*value| value else null);
        try bindOptText(&stmt, 12, cal.display_name);
        _ = try stmt.step();
    }

    fn persistEvent(self: *Self, ev: Event) !void {
        const conn = if (self.conn) |*c| c else return;
        var stmt = try conn.prepare("INSERT OR REPLACE INTO dav_events (id,calendar_id,uid,summary,description,location,dtstart,dtend,all_day,rrule,organizer,status,created_at,modified_at,etag,ics_data,source_message_ref,invitation_key,invitation_revisions,invitation_projections) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
        defer stmt.finalize();
        try stmt.bindInt(1, @intCast(ev.id));
        try stmt.bindInt(2, @intCast(ev.calendar_id));
        try stmt.bindText(3, ev.uid);
        try stmt.bindText(4, ev.summary);
        try bindOptText(&stmt, 5, ev.description);
        try bindOptText(&stmt, 6, ev.location);
        try stmt.bindInt(7, ev.dtstart);
        try bindOptInt(&stmt, 8, ev.dtend);
        try stmt.bindInt(9, if (ev.all_day) 1 else 0);
        try bindOptText(&stmt, 10, ev.rrule);
        try bindOptText(&stmt, 11, ev.organizer);
        try stmt.bindInt(12, @backingInt(ev.status));
        try stmt.bindInt(13, ev.created_at);
        try stmt.bindInt(14, ev.modified_at);
        try stmt.bindText(15, ev.etag);
        try stmt.bindText(16, ev.ics_data);
        try bindOptText(&stmt, 17, if (ev.source_message) |*reference| reference else null);
        try bindOptText(&stmt, 18, if (ev.invitation_key) |*key| key else null);
        try bindOptText(&stmt, 19, ev.invitation_revisions);
        try bindOptText(&stmt, 20, ev.invitation_projections);
        _ = try stmt.step();
    }

    fn persistAddressBook(self: *Self, ab: AddressBook) void {
        const conn = if (self.conn) |*c| c else return;
        var stmt = conn.prepare("INSERT OR REPLACE INTO dav_addressbooks (id,user_id,name,description,created_at,modified_at,sync_token,ctag,display_name) VALUES (?,?,?,?,?,?,?,?,?)") catch return;
        defer stmt.finalize();
        stmt.bindInt(1, @intCast(ab.id)) catch return;
        stmt.bindInt(2, @intCast(ab.user_id)) catch return;
        stmt.bindText(3, ab.name) catch return;
        bindOptText(&stmt, 4, ab.description) catch return;
        stmt.bindInt(5, ab.created_at) catch return;
        stmt.bindInt(6, ab.modified_at) catch return;
        stmt.bindInt(7, @intCast(ab.sync_token)) catch return;
        stmt.bindText(8, ab.ctag) catch return;
        bindOptText(&stmt, 9, ab.display_name) catch return;
        _ = stmt.step() catch return;
    }

    fn persistContact(self: *Self, ct: Contact) void {
        const conn = if (self.conn) |*c| c else return;
        var stmt = conn.prepare("INSERT OR REPLACE INTO dav_contacts (id,addressbook_id,uid,full_name,given_name,family_name,nickname,organization,title,birthday,note,photo_url,created_at,modified_at,etag,vcf_data) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)") catch return;
        defer stmt.finalize();
        stmt.bindInt(1, @intCast(ct.id)) catch return;
        stmt.bindInt(2, @intCast(ct.addressbook_id)) catch return;
        stmt.bindText(3, ct.uid) catch return;
        stmt.bindText(4, ct.full_name) catch return;
        bindOptText(&stmt, 5, ct.given_name) catch return;
        bindOptText(&stmt, 6, ct.family_name) catch return;
        bindOptText(&stmt, 7, ct.nickname) catch return;
        bindOptText(&stmt, 8, ct.organization) catch return;
        bindOptText(&stmt, 9, ct.title) catch return;
        bindOptInt(&stmt, 10, ct.birthday) catch return;
        bindOptText(&stmt, 11, ct.note) catch return;
        bindOptText(&stmt, 12, ct.photo_url) catch return;
        stmt.bindInt(13, ct.created_at) catch return;
        stmt.bindInt(14, ct.modified_at) catch return;
        stmt.bindText(15, ct.etag) catch return;
        stmt.bindText(16, ct.vcf_data) catch return;
        _ = stmt.step() catch return;
        self.persistContactRelations(ct.id);
    }

    fn persistContactRelations(self: *Self, contact_id: u64) void {
        const conn = if (self.conn) |*c| c else return;
        self.dbExecId("DELETE FROM dav_emails WHERE contact_id = {d}", contact_id);
        self.dbExecId("DELETE FROM dav_phones WHERE contact_id = {d}", contact_id);
        for (self.emails.items) |e| {
            if (e.contact_id != contact_id) continue;
            var stmt = conn.prepare("INSERT INTO dav_emails (contact_id,email,email_type,is_primary) VALUES (?,?,?,?)") catch continue;
            defer stmt.finalize();
            stmt.bindInt(1, @intCast(contact_id)) catch continue;
            stmt.bindText(2, e.email) catch continue;
            stmt.bindInt(3, @backingInt(e.email_type)) catch continue;
            stmt.bindInt(4, if (e.is_primary) 1 else 0) catch continue;
            _ = stmt.step() catch continue;
        }
        for (self.phones.items) |p| {
            if (p.contact_id != contact_id) continue;
            var stmt = conn.prepare("INSERT INTO dav_phones (contact_id,number,phone_type,is_primary) VALUES (?,?,?,?)") catch continue;
            defer stmt.finalize();
            stmt.bindInt(1, @intCast(contact_id)) catch continue;
            stmt.bindText(2, p.number) catch continue;
            stmt.bindInt(3, @backingInt(p.phone_type)) catch continue;
            stmt.bindInt(4, if (p.is_primary) 1 else 0) catch continue;
            _ = stmt.step() catch continue;
        }
    }

    fn bumpIds(self: *Self, id: u64, sync_token: u64, which: enum { calendar, event, addressbook, contact }) void {
        switch (which) {
            .calendar => if (id >= self.next_calendar_id) {
                self.next_calendar_id = id + 1;
            },
            .event => if (id >= self.next_event_id) {
                self.next_event_id = id + 1;
            },
            .addressbook => if (id >= self.next_addressbook_id) {
                self.next_addressbook_id = id + 1;
            },
            .contact => if (id >= self.next_contact_id) {
                self.next_contact_id = id + 1;
            },
        }
        if (sync_token >= self.current_sync_token) self.current_sync_token = sync_token + 1;
    }

    /// Hydrate the in-memory maps from SQLite. Loaded strings are owned by
    /// `self.allocator` (ctag/etag/UID are freed by deinit; the rest persist for the
    /// store's lifetime, matching the in-session ownership model).
    fn loadFromDb(self: *Self) !void {
        const conn = if (self.conn) |*c| c else return;

        {
            var stmt = try conn.prepare("SELECT id, username, mailbox_id FROM dav_users");
            defer stmt.finalize();
            while (try stmt.step()) {
                const user_id: u64 = @intCast(stmt.columnInt(0));
                const username = try self.allocator.dupe(u8, try stmt.columnText(1));
                errdefer self.allocator.free(username);
                try self.user_ids.append(self.allocator, .{
                    .username = username,
                    .user_id = user_id,
                    .mailbox_id = if (stmt.columnIsNull(2)) null else stmt.columnInt(2),
                });
                self.next_user_id = @max(self.next_user_id, user_id + 1);
            }
        }

        // Older databases only stored numeric owners. Reserve those IDs
        // without guessing which authenticated mailbox used them.
        {
            var stmt = try conn.prepare("SELECT max(user_id) FROM (SELECT user_id FROM dav_calendars UNION ALL SELECT user_id FROM dav_addressbooks)");
            defer stmt.finalize();
            if (try stmt.step() and !stmt.columnIsNull(0)) {
                self.next_user_id = @max(self.next_user_id, @as(u64, @intCast(stmt.columnInt(0))) + 1);
            }
        }

        {
            var stmt = try conn.prepare("SELECT id,user_id,name,description,color,timezone,created_at,modified_at,sync_token,ctag,share_id,display_name FROM dav_calendars");
            defer stmt.finalize();
            while (stmt.step() catch false) {
                const id: u64 = @intCast(stmt.columnInt(0));
                const share_id = if (stmt.columnIsNull(10)) null else blk: {
                    const value = try stmt.columnText(10);
                    if (value.len != @sizeOf(teams.CalendarShareId)) return error.InvalidCalendarShareId;
                    for (value) |byte| {
                        if (!std.ascii.isHex(byte) or std.ascii.isUpper(byte)) return error.InvalidCalendarShareId;
                    }
                    break :blk value[0..@sizeOf(teams.CalendarShareId)].*;
                };
                try self.calendars.put(id, .{
                    .id = id,
                    .user_id = @intCast(stmt.columnInt(1)),
                    .name = self.dupCol(&stmt, 2),
                    .description = self.dupColOpt(&stmt, 3),
                    .color = self.dupColOpt(&stmt, 4),
                    .timezone = self.dupCol(&stmt, 5),
                    .created_at = stmt.columnInt(6),
                    .modified_at = stmt.columnInt(7),
                    .sync_token = @intCast(stmt.columnInt(8)),
                    .ctag = self.dupCol(&stmt, 9),
                    .share_id = share_id,
                    .display_name = self.dupColOpt(&stmt, 11),
                });
                self.bumpIds(id, @intCast(stmt.columnInt(8)), .calendar);
            }
        }
        {
            var stmt = try conn.prepare("SELECT id,calendar_id,uid,summary,description,location,dtstart,dtend,all_day,rrule,organizer,status,created_at,modified_at,etag,ics_data,source_message_ref,invitation_key,invitation_revisions,invitation_projections FROM dav_events");
            defer stmt.finalize();
            while (stmt.step() catch false) {
                const id: u64 = @intCast(stmt.columnInt(0));
                const rule = self.dupColOpt(&stmt, 9);
                const source = self.dupCol(&stmt, 15);
                const message = if (stmt.columnIsNull(16)) "" else try stmt.columnText(16);
                const key = if (stmt.columnIsNull(17)) "" else try stmt.columnText(17);
                const invitation_key = if (key.len == 64) key[0..64].* else null;
                try self.events.put(id, .{
                    .id = id,
                    .calendar_id = @intCast(stmt.columnInt(1)),
                    .uid = self.dupCol(&stmt, 2),
                    .summary = self.dupCol(&stmt, 3),
                    .description = self.dupColOpt(&stmt, 4),
                    .location = self.dupColOpt(&stmt, 5),
                    .dtstart = stmt.columnInt(6),
                    .dtend = if (stmt.columnIsNull(7)) null else stmt.columnInt(7),
                    .all_day = stmt.columnInt(8) != 0,
                    .rrule = rule,
                    .recurring = rule != null or icalendar.hasRecurrence(source),
                    .shareable = publicCalendarResource(self.allocator, source),
                    .reminder_coverage = try reminder.coverage(self.allocator, source),
                    .organizer = self.dupColOpt(&stmt, 10),
                    .status = switch (stmt.columnInt(11)) {
                        0 => .tentative,
                        2 => .cancelled,
                        else => .confirmed,
                    },
                    .created_at = stmt.columnInt(12),
                    .modified_at = stmt.columnInt(13),
                    .etag = self.dupCol(&stmt, 14),
                    .ics_data = source,
                    .source_message = if (message.len == @sizeOf(MessageReference)) message[0..@sizeOf(MessageReference)].* else null,
                    .invitation_key = invitation_key,
                    .invitation_revisions = self.dupColOpt(&stmt, 18),
                    .invitation_projections = self.dupColOpt(&stmt, 19),
                });
                self.bumpIds(id, 0, .event);
            }
        }
        {
            var stmt = try conn.prepare("SELECT id,user_id,name,description,created_at,modified_at,sync_token,ctag,display_name FROM dav_addressbooks");
            defer stmt.finalize();
            while (stmt.step() catch false) {
                const id: u64 = @intCast(stmt.columnInt(0));
                try self.addressbooks.put(id, .{
                    .id = id,
                    .user_id = @intCast(stmt.columnInt(1)),
                    .name = self.dupCol(&stmt, 2),
                    .description = self.dupColOpt(&stmt, 3),
                    .created_at = stmt.columnInt(4),
                    .modified_at = stmt.columnInt(5),
                    .sync_token = @intCast(stmt.columnInt(6)),
                    .ctag = self.dupCol(&stmt, 7),
                    .display_name = self.dupColOpt(&stmt, 8),
                });
                self.bumpIds(id, @intCast(stmt.columnInt(6)), .addressbook);
            }
        }
        {
            var stmt = try conn.prepare("SELECT id,addressbook_id,uid,full_name,given_name,family_name,nickname,organization,title,birthday,note,photo_url,created_at,modified_at,etag,vcf_data FROM dav_contacts");
            defer stmt.finalize();
            while (stmt.step() catch false) {
                const id: u64 = @intCast(stmt.columnInt(0));
                try self.contacts.put(id, .{
                    .id = id,
                    .addressbook_id = @intCast(stmt.columnInt(1)),
                    .uid = self.dupCol(&stmt, 2),
                    .full_name = self.dupCol(&stmt, 3),
                    .given_name = self.dupColOpt(&stmt, 4),
                    .family_name = self.dupColOpt(&stmt, 5),
                    .nickname = self.dupColOpt(&stmt, 6),
                    .organization = self.dupColOpt(&stmt, 7),
                    .title = self.dupColOpt(&stmt, 8),
                    .birthday = if (stmt.columnIsNull(9)) null else stmt.columnInt(9),
                    .note = self.dupColOpt(&stmt, 10),
                    .photo_url = self.dupColOpt(&stmt, 11),
                    .created_at = stmt.columnInt(12),
                    .modified_at = stmt.columnInt(13),
                    .etag = self.dupCol(&stmt, 14),
                    .vcf_data = self.dupCol(&stmt, 15),
                });
                self.bumpIds(id, 0, .contact);
            }
        }
        {
            var stmt = try conn.prepare("SELECT contact_id,email,email_type,is_primary FROM dav_emails");
            defer stmt.finalize();
            while (stmt.step() catch false) {
                try self.emails.append(self.allocator, .{
                    .contact_id = @intCast(stmt.columnInt(0)),
                    .email = self.dupCol(&stmt, 1),
                    .email_type = switch (stmt.columnInt(2)) {
                        0 => .home,
                        1 => .work,
                        else => .other,
                    },
                    .is_primary = stmt.columnInt(3) != 0,
                });
            }
        }
        {
            var stmt = try conn.prepare("SELECT contact_id,number,phone_type,is_primary FROM dav_phones");
            defer stmt.finalize();
            while (stmt.step() catch false) {
                try self.phones.append(self.allocator, .{
                    .contact_id = @intCast(stmt.columnInt(0)),
                    .number = self.dupCol(&stmt, 1),
                    .phone_type = switch (stmt.columnInt(2)) {
                        0 => .home,
                        1 => .work,
                        2 => .mobile,
                        3 => .fax,
                        else => .other,
                    },
                    .is_primary = stmt.columnInt(3) != 0,
                });
            }
        }
    }

    // -------------------------------------------------------------------------
    // User Operations
    // -------------------------------------------------------------------------

    /// Get existing user_id for username, or create a new one.
    pub fn getOrCreateUserId(self: *Self, username: []const u8) !u64 {
        const mailbox_id = try self.activeMailboxId(username);
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.getOrCreateUserIdLocked(username, mailbox_id);
    }

    fn getOrCreateUserIdLocked(self: *Self, username: []const u8, mailbox_id: ?i64) !u64 {
        if (self.findUserIdLocked(username, mailbox_id)) |id| return id;

        const id = self.next_user_id;
        if (id > std.math.maxInt(i64)) return error.DavUserIdExhausted;
        const name = try self.allocator.dupe(u8, username);
        errdefer self.allocator.free(name);
        try self.user_ids.ensureUnusedCapacity(self.allocator, 1);
        if (self.conn) |*conn| {
            var stmt = try conn.prepare("INSERT INTO dav_users (id, username, mailbox_id) VALUES (?, ?, ?)");
            defer stmt.finalize();
            try stmt.bindInt(1, @intCast(id));
            try stmt.bindText(2, name);
            try bindOptInt(&stmt, 3, mailbox_id);
            _ = try stmt.step();
        }
        self.user_ids.appendAssumeCapacity(.{ .username = name, .user_id = id, .mailbox_id = mailbox_id });
        if (mailbox_id != null and mailbox_id == self.config.sync_canary_mailbox_id) {
            self.sync_canary_user_id = id;
        }
        self.next_user_id += 1;
        return id;
    }

    // -------------------------------------------------------------------------
    // Calendar Operations
    // -------------------------------------------------------------------------

    pub fn createCalendar(
        self: *Self,
        user_id: u64,
        name: []const u8,
        description: ?[]const u8,
    ) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.createCalendarLocked(user_id, name, description);
    }

    fn createCalendarLocked(
        self: *Self,
        user_id: u64,
        name: []const u8,
        description: ?[]const u8,
    ) !u64 {
        const id = self.next_calendar_id;
        self.next_calendar_id += 1;

        const now = currentTimestamp();
        const ctag = try self.generateCtag(id, now);
        errdefer self.allocator.free(ctag);
        const own_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(own_name);
        const own_description = try dupeOptional(self.allocator, description);
        errdefer if (own_description) |value| self.allocator.free(value);
        const timezone = try self.allocator.dupe(u8, self.config.default_timezone);
        errdefer self.allocator.free(timezone);

        const calendar = Calendar{
            .id = id,
            .user_id = user_id,
            .name = own_name,
            .description = own_description,
            .color = null,
            .timezone = timezone,
            .created_at = now,
            .modified_at = now,
            .sync_token = self.current_sync_token,
            .ctag = ctag,
        };
        try self.calendars.ensureUnusedCapacity(1);
        try self.persistCalendar(calendar);
        self.calendars.putAssumeCapacity(id, calendar);
        return id;
    }

    fn freeCalendar(self: *Self, calendar: Calendar) void {
        self.allocator.free(calendar.name);
        if (calendar.display_name) |value| self.allocator.free(value);
        if (calendar.description) |value| self.allocator.free(value);
        if (calendar.color) |value| self.allocator.free(value);
        self.allocator.free(calendar.timezone);
        self.allocator.free(calendar.ctag);
    }

    pub fn getCalendar(self: *Self, id: u64) ?Calendar {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.calendars.get(id);
    }

    pub fn getCalendarByName(self: *Self, user_id: u64, name: []const u8) ?Calendar {
        var iter = self.calendars.valueIterator();
        while (iter.next()) |cal| {
            if (cal.user_id == user_id and std.mem.eql(u8, cal.name, name)) {
                return cal.*;
            }
        }
        return null;
    }

    pub fn getUserCalendars(self: *Self, user_id: u64) ![]Calendar {
        self.mutex.lock();
        defer self.mutex.unlock();

        var result: std.ArrayList(Calendar) = .empty;
        errdefer result.deinit(self.allocator);

        var iter = self.calendars.valueIterator();
        while (iter.next()) |cal| {
            if (cal.user_id == user_id) {
                try result.append(self.allocator, cal.*);
            }
        }

        return result.toOwnedSlice(self.allocator);
    }

    /// Snapshot the account's calendars while the DAV store owns their strings.
    /// The request arena owns the returned data, including partially built rows.
    pub fn snapshotCalendars(self: *Self, arena: Allocator, username: []const u8) ![]CalendarSummary {
        const mailbox_id = try self.activeMailboxId(username);
        self.mutex.lock();
        defer self.mutex.unlock();

        const user_id = self.findUserIdLocked(username, mailbox_id) orelse return &.{};
        var result: std.ArrayList(CalendarSummary) = .empty;
        var calendars = self.calendars.valueIterator();
        while (calendars.next()) |calendar| {
            if (calendar.user_id != user_id) continue;
            try result.append(arena, .{
                .id = calendar.id,
                .name = try arena.dupe(u8, calendar.name),
                .display_name = try dupeOptional(arena, calendar.display_name),
                .description = try dupeOptional(arena, calendar.description),
                .color = try dupeOptional(arena, calendar.color),
                .timezone = try arena.dupe(u8, calendar.timezone),
            });
        }
        std.mem.sort(CalendarSummary, result.items, {}, struct {
            fn lessThan(_: void, left: CalendarSummary, right: CalendarSummary) bool {
                const order = std.mem.order(u8, left.name, right.name);
                return order == .lt or (order == .eq and left.id < right.id);
            }
        }.lessThan);
        return result.toOwnedSlice(arena);
    }

    pub fn createMailboxCalendar(self: *Self, username: []const u8, name: []const u8) !u64 {
        const mailbox_id = try self.activeMailboxId(username);
        self.mutex.lock();
        defer self.mutex.unlock();
        const owner = try self.getOrCreateUserIdLocked(username, mailbox_id);
        if (self.getCalendarByName(owner, name) != null or self.getAddressBookByName(owner, name) != null) return error.CalendarNameConflict;
        return self.createCalendarLocked(owner, name, null);
    }

    /// Sharing follows this particular calendar even when its numeric ID,
    /// display name, or owner's address is reused or changes.
    pub fn mailboxCalendarShareId(self: *Self, username: []const u8, id: u64, create: bool) !teams.CalendarShareId {
        const mailbox_id = try self.activeMailboxId(username);
        self.mutex.lock();
        defer self.mutex.unlock();
        const calendar = self.calendars.getPtr(id) orelse return error.CalendarNotFound;
        if (self.findUserIdLocked(username, mailbox_id) != calendar.user_id) return error.CalendarNotFound;
        if (calendar.share_id) |share_id| return share_id;
        if (!create) return error.CalendarNotFound;

        var random: [16]u8 = undefined;
        io_compat.randomBytes(&random);
        const share_id = std.fmt.bytesToHex(random, .lower);
        // Updating the identifier does not change DAV collection revisions.
        if (self.conn) |*conn| {
            var stmt = try conn.prepare("UPDATE dav_calendars SET share_id=? WHERE id=?");
            defer stmt.finalize();
            try stmt.bindText(1, &share_id);
            try stmt.bindInt(2, @intCast(id));
            _ = try stmt.step();
        }
        calendar.share_id = share_id;
        return share_id;
    }

    pub const SharedCalendar = struct { id: u64, name: []const u8, display_name: ?[]const u8 };

    pub fn snapshotSharedCalendar(self: *Self, arena: Allocator, source_id: i64, share_id: teams.CalendarShareId) !?SharedCalendar {
        self.mutex.lock();
        defer self.mutex.unlock();
        const owner = self.findUserIdLocked("", source_id) orelse return null;
        var calendars = self.calendars.valueIterator();
        while (calendars.next()) |calendar| {
            if (calendar.user_id != owner) continue;
            const current = calendar.share_id orelse continue;
            if (std.mem.eql(u8, &current, &share_id))
                return .{ .id = calendar.id, .name = try arena.dupe(u8, calendar.name), .display_name = try dupeOptional(arena, calendar.display_name) };
        }
        return null;
    }

    pub fn setMailboxCalendarColor(self: *Self, username: []const u8, id: u64, color: ?[]const u8) !void {
        const mailbox_id = try self.activeMailboxId(username);
        self.mutex.lock();
        defer self.mutex.unlock();

        const calendar = self.calendars.getPtr(id) orelse return error.CalendarNotFound;
        if (self.findUserIdLocked(username, mailbox_id) != calendar.user_id) return error.CalendarNotFound;
        try self.applyDavPropertiesLocked(calendar, .{ .color = if (color) |value| .{ .set = value } else .remove });
    }

    pub fn patchOwnedDavCollection(self: *Self, user_id: u64, name: []const u8, kind: SyncChange.ResourceType, patch: CollectionPropertyPatch) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        return switch (try self.findDavCollectionLocked(user_id, name, kind)) {
            inline else => |collection| self.applyDavPropertiesLocked(collection, patch),
        };
    }

    const PropertyEdit = struct {
        value: ?[]const u8,
        changed: bool,

        fn prepare(a: Allocator, previous: ?[]const u8, change: CollectionProperty) !PropertyEdit {
            switch (change) {
                .keep => return .{ .value = previous, .changed = false },
                .remove => return .{ .value = null, .changed = previous != null },
                .set => |value| {
                    if (previous) |old| {
                        if (std.mem.eql(u8, old, value)) return .{ .value = old, .changed = false };
                    }
                    return .{ .value = try a.dupe(u8, value), .changed = true };
                },
            }
        }

        fn freeIfChanged(self: PropertyEdit, a: Allocator, value: ?[]const u8) void {
            if (self.changed) if (value) |text| a.free(text);
        }
    };

    /// Both webmail and DAV metadata writes commit a single complete row.
    /// Publish new slices only after persistence succeeds.
    fn applyDavPropertiesLocked(self: *Self, collection: anytype, patch: CollectionPropertyPatch) !void {
        const a = self.allocator;
        const is_calendar = @TypeOf(collection.*) == Calendar;
        const old_color = if (is_calendar) collection.color else null;
        if (!is_calendar and patch.color != .keep) return error.UnsupportedProperty;
        const name = try PropertyEdit.prepare(a, collection.display_name, patch.display_name);
        errdefer name.freeIfChanged(a, name.value);
        const description = try PropertyEdit.prepare(a, collection.description, patch.description);
        errdefer description.freeIfChanged(a, description.value);
        const color = try PropertyEdit.prepare(a, old_color, patch.color);
        errdefer color.freeIfChanged(a, color.value);
        if (!name.changed and !description.changed and !color.changed) return;

        const modified_at = currentTimestamp();
        if (self.conn) |*conn| {
            var stmt = try conn.prepare(if (is_calendar)
                "UPDATE dav_calendars SET display_name=?1, description=?2, modified_at=?3, color=?5 WHERE id=?4"
            else
                "UPDATE dav_addressbooks SET display_name=?1, description=?2, modified_at=?3 WHERE id=?4");
            defer stmt.finalize();
            try bindOptText(&stmt, 1, name.value);
            try bindOptText(&stmt, 2, description.value);
            try stmt.bindInt(3, modified_at);
            try stmt.bindInt(4, @intCast(collection.id));
            if (is_calendar) try bindOptText(&stmt, 5, color.value);
            _ = try stmt.step();
            if (conn.changesCount() != 1) return error.StepFailed;
        }
        name.freeIfChanged(a, collection.display_name);
        description.freeIfChanged(a, collection.description);
        color.freeIfChanged(a, old_color);
        collection.display_name = name.value;
        collection.description = description.value;
        collection.modified_at = modified_at;
        if (is_calendar) collection.color = color.value;
    }

    pub fn snapshotMailboxEvent(self: *Self, arena: Allocator, username: []const u8, id: u64) !CalendarEventDetail {
        const mailbox_id = try self.activeMailboxId(username);
        self.mutex.lock();
        defer self.mutex.unlock();
        return snapshotEventDetail(arena, try self.ownedEventLocked(username, mailbox_id, id), true);
    }

    pub fn snapshotActiveSyncEvent(self: *Self, arena: Allocator, username: []const u8, id: u64) !struct { detail: CalendarEventDetail, timezone: []const u8 } {
        const mailbox_id = try self.activeMailboxId(username);
        self.mutex.lock();
        defer self.mutex.unlock();
        const owner = self.findUserIdLocked(username, mailbox_id) orelse return error.EventNotFound;
        const event = self.events.get(id) orelse return error.EventNotFound;
        if (firstOwnedCollection(self.calendars.valueIterator(), owner) != event.calendar_id) return error.EventNotFound;
        const calendar = self.calendars.get(event.calendar_id) orelse return error.EventNotFound;
        return .{
            .detail = try snapshotEventDetail(arena, event, false),
            .timezone = try arena.dupe(u8, calendar.timezone),
        };
    }

    pub fn snapshotWebCalendarEvent(self: *Self, arena: Allocator, username: []const u8, id: u64, action: CalendarAction) !CalendarEventDetail {
        const access = try self.beginCalendarAccess(username, .read);
        defer access.deinit();
        self.mutex.lock();
        defer self.mutex.unlock();
        const allowed = try self.webEventLocked(access, id, action);
        return snapshotEventDetail(arena, allowed.event, allowed.permission == .owner);
    }

    fn snapshotEventDetail(arena: Allocator, event: Event, owner: bool) !CalendarEventDetail {
        return .{
            .event = try summarizeEvent(arena, event),
            .calendar_id = event.calendar_id,
            .description = try dupeOptional(arena, event.description),
            .organizer = try dupeOptional(arena, event.organizer),
            .modified_at = event.modified_at,
            .ics_data = try arena.dupe(u8, event.ics_data),
            .source_message = if (owner) event.source_message else null,
        };
    }

    /// ActiveSync exposes one calendar and address book. Select the first
    /// created collection consistently across restarts and copy its revisions.
    pub fn snapshotActiveSyncResources(self: *Self, arena: Allocator, username: []const u8, is_calendar: bool) ![]ActiveSyncResource {
        const mailbox_id = try self.activeMailboxId(username);
        self.mutex.lock();
        defer self.mutex.unlock();
        const owner = self.findUserIdLocked(username, mailbox_id) orelse return &.{};
        var result: std.ArrayList(ActiveSyncResource) = .empty;
        if (is_calendar) {
            const id = firstOwnedCollection(self.calendars.valueIterator(), owner) orelse return &.{};
            const timezone = try arena.dupe(u8, self.calendars.get(id).?.timezone);
            var items = self.events.valueIterator();
            while (items.next()) |event| {
                if (event.calendar_id == id) try result.append(arena, .{
                    .id = event.id,
                    .etag = try arena.dupe(u8, event.etag),
                    .timezone = timezone,
                    .recurring = event.recurring,
                });
            }
        } else {
            const id = firstOwnedCollection(self.addressbooks.valueIterator(), owner) orelse return &.{};
            var items = self.contacts.valueIterator();
            while (items.next()) |contact| {
                if (contact.addressbook_id == id) try result.append(arena, .{ .id = contact.id, .etag = try arena.dupe(u8, contact.etag) });
            }
        }
        std.mem.sort(ActiveSyncResource, result.items, {}, struct {
            fn lessThan(_: void, left: ActiveSyncResource, right: ActiveSyncResource) bool {
                return left.id < right.id;
            }
        }.lessThan);
        return result.items;
    }

    fn firstOwnedCollection(iterator: anytype, owner: u64) ?u64 {
        var collections = iterator;
        var first: ?u64 = null;
        while (collections.next()) |collection| {
            if (collection.user_id == owner and (first == null or collection.id < first.?)) first = collection.id;
        }
        return first;
    }

    pub fn snapshotActiveSyncContact(self: *Self, arena: Allocator, username: []const u8, id: u64) !ActiveSyncContact {
        const mailbox_id = try self.activeMailboxId(username);
        self.mutex.lock();
        defer self.mutex.unlock();
        const contact = self.contacts.get(id) orelse return error.ContactNotFound;
        const book = self.addressbooks.get(contact.addressbook_id) orelse return error.ContactNotFound;
        if (self.findUserIdLocked(username, mailbox_id) != book.user_id) return error.ContactNotFound;
        var emails: std.ArrayList([]const u8) = .empty;
        var phones: std.ArrayList(PhoneNumber) = .empty;
        for (self.emails.items) |entry| {
            if (entry.contact_id != id) continue;
            try emails.append(arena, try arena.dupe(u8, entry.email));
            if (emails.items.len == 3) break;
        }
        for (self.phones.items) |entry| {
            if (entry.contact_id != id) continue;
            var owned = entry;
            owned.number = try arena.dupe(u8, entry.number);
            try phones.append(arena, owned);
        }
        return .{
            .etag = try arena.dupe(u8, contact.etag),
            .full_name = try arena.dupe(u8, contact.full_name),
            .given_name = try dupeOptional(arena, contact.given_name),
            .family_name = try dupeOptional(arena, contact.family_name),
            .organization = try dupeOptional(arena, contact.organization),
            .title = try dupeOptional(arena, contact.title),
            .note = try dupeOptional(arena, contact.note),
            .emails = emails.items,
            .phones = phones.items,
        };
    }

    pub const CreatedMailboxEvent = struct { id: u64, revision: PutResource };

    pub const CalendarAction = enum { read, edit };
    const CalendarPermission = enum { owner, editor, viewer, free_busy };
    const CalendarRequest = struct {
        username: []const u8,
        mailbox_id: ?i64 = null,
        account_tx: ?accounts.Database.Transaction = null,

        fn deinit(self: CalendarRequest) void {
            if (self.account_tx) |tx| tx.deinit();
        }
    };

    /// Take the account transaction before the DAV mutex. Grant changes and
    /// membership removal must wait until an admitted shared edit commits.
    /// BEGIN IMMEDIATE also serializes against the local operator's CLI.
    fn beginCalendarAccess(self: *Self, username: []const u8, mode: enum { read, write }) !CalendarRequest {
        const db = self.config.account_db orelse return .{ .username = username };
        const tx = try db.beginTransaction(if (mode == .write) .write else .read);
        errdefer tx.deinit();
        const mailbox_id = (try teams.activeMailboxId(tx, username)) orelse return error.DavMailboxNotFound;
        return .{ .username = username, .mailbox_id = mailbox_id, .account_tx = tx };
    }

    fn calendarPermissionLocked(self: *Self, request: CalendarRequest, calendar: Calendar) !?CalendarPermission {
        if (self.findUserIdLocked(request.username, request.mailbox_id) == calendar.user_id) return .owner;
        const share_id = calendar.share_id orelse return null;
        const account_tx = request.account_tx orelse return null;
        const grantee_id = request.mailbox_id orelse return null;
        const source_id = self.mailboxIdLocked(calendar.user_id) orelse return null;
        const permission = (try teams.calendarAccess(account_tx, grantee_id, source_id, share_id)) orelse return null;
        return switch (permission) {
            .editor => .editor,
            .viewer => .viewer,
            .free_busy => .free_busy,
        };
    }

    fn mailboxIdLocked(self: *Self, user_id: u64) ?i64 {
        for (self.user_ids.items) |owner| {
            if (owner.user_id == user_id) return owner.mailbox_id;
        }
        return null;
    }

    fn webEventLocked(self: *Self, access: CalendarRequest, id: u64, action: CalendarAction) !struct { event: Event, permission: CalendarPermission } {
        const event = self.events.get(id) orelse return error.EventNotFound;
        const calendar = self.calendars.get(event.calendar_id) orelse return error.EventNotFound;
        const permission = (try self.calendarPermissionLocked(access, calendar)) orelse return error.EventNotFound;
        switch (permission) {
            .owner => {},
            .editor => if (!event.shareable) return error.EventNotFound,
            .viewer => if (action == .edit or !event.shareable) return error.EventNotFound,
            .free_busy => return error.EventNotFound,
        }
        return .{ .event = event, .permission = permission };
    }

    fn validateSharedEdit(self: *Self, permission: CalendarPermission, source: []const u8) !void {
        if (permission == .editor and !publicCalendarResource(self.allocator, source)) return error.SharedEventMustBePublic;
    }

    pub const InvitationTarget = struct { id: u64, calendarId: u64, etag: []const u8 };
    pub const InvitationSnapshot = struct { detail: CalendarEventDetail, revisions: []const u8, projections: ?[]const u8 };
    pub const InvitationAction = struct { target: ?InvitationTarget, applied: bool = false };

    fn invitationEventLocked(self: *Self, owner: u64, key: [64]u8) ?Event {
        var events = self.events.valueIterator();
        while (events.next()) |event| {
            const invitation_key = event.invitation_key orelse continue;
            if (!std.mem.eql(u8, &invitation_key, &key)) continue;
            const calendar = self.calendars.get(event.calendar_id) orelse continue;
            if (calendar.user_id == owner) return event.*;
        }
        return null;
    }

    pub fn snapshotInvitationAction(self: *Self, a: Allocator, username: []const u8, revision: calendar_invite.Revision) !?InvitationAction {
        const mailbox = try self.activeMailboxId(username);
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.findUserIdLocked(username, mailbox)) |owner| {
            if (self.invitationEventLocked(owner, revision.series)) |event| {
                const stored = event.invitation_revisions orelse return error.InvalidCalendar;
                const previous = try std.json.parseFromSliceLeaky([]const calendar_invite.Revision, a, stored, .{});
                var applied = false;
                for (previous) |item| {
                    if (item.sameVersion(revision)) {
                        applied = true;
                        break;
                    }
                }
                return .{
                    .target = .{ .id = event.id, .calendarId = event.calendar_id, .etag = try a.dupe(u8, event.etag) },
                    .applied = applied,
                };
            }
        }
        return if (revision.method == .request and revision.occurrence == null) .{ .target = null } else null;
    }

    pub fn snapshotInvitationEvent(self: *Self, a: Allocator, username: []const u8, key: [64]u8) !?InvitationSnapshot {
        const mailbox = try self.activeMailboxId(username);
        self.mutex.lock();
        defer self.mutex.unlock();
        const owner = self.findUserIdLocked(username, mailbox) orelse return null;
        const event = self.invitationEventLocked(owner, key) orelse return null;
        return .{
            .detail = try snapshotEventDetail(a, event, true),
            .revisions = try a.dupe(u8, event.invitation_revisions orelse return error.InvalidCalendar),
            .projections = try dupeOptional(a, event.invitation_projections),
        };
    }

    /// Serialize organizer delivery and Calendar edits while the prepared
    /// document and its tracking data commit with the DAV resource revision.
    pub fn saveInvitationEvent(self: *Self, username: []const u8, revision: calendar_invite.Revision, logical_uid: []const u8, calendar_id: ?u64, expected: ?InvitationTarget, data: ?EventData) !CreatedMailboxEvent {
        const access = try self.beginCalendarAccess(username, .write);
        defer access.deinit();
        if (access.account_tx) |tx| try accounts.Database.requireCurrentCalendarInvitation(tx, username, revision);
        self.mutex.lock();
        defer self.mutex.unlock();
        const owner = self.findUserIdLocked(access.username, access.mailbox_id) orelse return error.CalendarNotFound;
        if (self.invitationEventLocked(owner, revision.series)) |event| {
            const version = expected orelse return error.PreconditionFailed;
            if (event.id != version.id or !std.mem.eql(u8, version.etag, event.etag)) return error.PreconditionFailed;
            if (calendar_id) |id| if (id != event.calendar_id) return error.CalendarNotFound;
            if (data) |change| try self.updateEventLocked(event.id, change);
            return .{ .id = event.id, .revision = PutResource.init(false, self.events.get(event.id).?.etag) };
        }
        if (expected != null) return error.PreconditionFailed;
        if (revision.method == .cancel or revision.occurrence != null) return error.InvitationEventRequired;
        const id = calendar_id orelse return error.CalendarNotFound;
        const calendar = self.calendars.get(id) orelse return error.CalendarNotFound;
        if (calendar.user_id != owner) return error.CalendarNotFound;
        const change = data orelse return error.InvalidCalendar;
        if (self.getEventByUid(id, change.uid orelse return error.InvalidCalendar) != null) return error.EventAlreadyExists;
        var wanted: std.StringHashMapUnmanaged(bool) = .empty;
        defer wanted.deinit(self.allocator);
        try wanted.put(self.allocator, logical_uid, false);
        try self.findExistingImportUids(&wanted, id);
        if (wanted.get(logical_uid).?) return error.EventAlreadyExists;
        const saved = try self.createEventLocked(id, change);
        return .{ .id = saved, .revision = PutResource.init(true, self.events.get(saved).?.etag) };
    }

    pub fn createWebCalendarEvent(self: *Self, username: []const u8, calendar_id: u64, data: EventData) !CreatedMailboxEvent {
        const access = try self.beginCalendarAccess(username, .write);
        defer access.deinit();
        self.mutex.lock();
        defer self.mutex.unlock();
        const calendar = self.calendars.get(calendar_id) orelse return error.CalendarNotFound;
        const permission = (try self.calendarPermissionLocked(access, calendar)) orelse return error.CalendarNotFound;
        if (permission != .owner and permission != .editor) return error.CalendarNotFound;
        if (data.source_message != null and permission != .owner) return error.CalendarNotFound;
        try self.validateSharedEdit(permission, data.ics_data orelse "");
        if (data.uid) |uid| {
            if (self.getEventByUid(calendar_id, uid) != null) return error.EventAlreadyExists;
        }
        const id = try self.createEventLocked(calendar_id, data);
        return .{ .id = id, .revision = PutResource.init(true, self.events.get(id).?.etag) };
    }

    pub fn updateWebCalendarEvent(self: *Self, username: []const u8, id: u64, expected: []const u8, data: EventData) !PutResource {
        const access = try self.beginCalendarAccess(username, .write);
        defer access.deinit();
        self.mutex.lock();
        defer self.mutex.unlock();
        const allowed = try self.webEventLocked(access, id, .edit);
        if (!std.mem.eql(u8, expected, allowed.event.etag)) return error.PreconditionFailed;
        try self.validateSharedEdit(allowed.permission, data.ics_data orelse allowed.event.ics_data);
        try self.updateEventLocked(id, data);
        return PutResource.init(false, self.events.get(id).?.etag);
    }

    pub fn deleteWebCalendarEvent(self: *Self, username: []const u8, id: u64, expected: []const u8) !void {
        const access = try self.beginCalendarAccess(username, .write);
        defer access.deinit();
        self.mutex.lock();
        defer self.mutex.unlock();
        const allowed = try self.webEventLocked(access, id, .edit);
        if (!std.mem.eql(u8, expected, allowed.event.etag)) return error.PreconditionFailed;
        try self.deleteEventLocked(id);
    }

    fn ownedEventLocked(self: *Self, username: []const u8, mailbox_id: ?i64, id: u64) !Event {
        const event = self.events.get(id) orelse return error.EventNotFound;
        const calendar = self.calendars.get(event.calendar_id) orelse return error.EventNotFound;
        if (self.findUserIdLocked(username, mailbox_id) != calendar.user_id) return error.EventNotFound;
        return event;
    }

    pub const ImportDestination = union(enum) { existing: u64, name: []const u8 };
    pub const ImportEvent = struct { uid: []const u8, data: EventData };
    pub const ImportStatus = enum { ready, imported, skipped, failed };
    pub const ImportResult = struct { calendar_id: ?u64, statuses: []ImportStatus };

    /// Match logical iCalendar UIDs across filenames, and serialize lookup and
    /// insertion against concurrent imports and DAV writes for this mailbox.
    pub fn importEvents(self: *Self, arena: Allocator, username: []const u8, destination: ImportDestination, items: []const ?ImportEvent, preview: bool) !ImportResult {
        const mailbox_id = try self.activeMailboxId(username);
        self.mutex.lock();
        defer self.mutex.unlock();

        const owner_id = self.findUserIdLocked(username, mailbox_id);
        var calendar_id: ?u64 = switch (destination) {
            .existing => |id| blk: {
                const calendar = self.calendars.get(id) orelse return error.CalendarNotFound;
                if (owner_id != calendar.user_id) return error.CalendarNotFound;
                break :blk id;
            },
            .name => |name| if (owner_id) |id| blk: {
                if (self.getAddressBookByName(id, name) != null) return error.CalendarNameConflict;
                break :blk if (self.getCalendarByName(id, name)) |calendar| calendar.id else null;
            } else null,
        };

        var wanted: std.StringHashMapUnmanaged(bool) = .empty;
        for (items) |maybe| if (maybe) |event| try wanted.put(arena, event.uid, false);
        if (calendar_id) |id| try self.findExistingImportUids(&wanted, id);

        const statuses = try arena.alloc(ImportStatus, items.len);
        @memset(statuses, .failed);
        for (items, statuses) |maybe, *status| {
            const event = maybe orelse continue;
            const existing = wanted.getPtr(event.uid).?;
            if (existing.*) {
                status.* = .skipped;
                continue;
            }
            if (preview) {
                status.* = .ready;
                continue;
            }
            if (calendar_id == null) {
                const user_id = try self.getOrCreateUserIdLocked(username, mailbox_id);
                calendar_id = try self.createCalendarLocked(user_id, destination.name, null);
            }
            if (self.getEventByUid(calendar_id.?, event.data.uid.?) != null) continue;
            _ = self.createEventLocked(calendar_id.?, event.data) catch |err| {
                if (err == error.OutOfMemory) return err;
                std.log.warn("Could not store imported calendar event: {s}", .{@errorName(err)});
                continue;
            };
            existing.* = true;
            status.* = .imported;
        }
        return .{ .calendar_id = calendar_id, .statuses = statuses };
    }

    fn findExistingImportUids(self: *Self, wanted: *std.StringHashMapUnmanaged(bool), calendar_id: u64) !void {
        if (wanted.count() == 0) return;
        var scratch = std.heap.ArenaAllocator.init(self.allocator);
        defer scratch.deinit();
        const a = scratch.allocator();
        var events = self.events.valueIterator();
        while (events.next()) |event| {
            if (event.calendar_id != calendar_id) continue;
            if (wanted.getPtr(event.uid)) |present| present.* = true;
            if (event.ics_data.len == 0) continue;
            _ = scratch.reset(.retain_capacity);
            const children = icalendar.components(a, event.ics_data) catch |err| switch (err) {
                error.InvalidCalendar => continue,
                else => return err,
            };
            for (children) |item| {
                if (!std.ascii.eqlIgnoreCase(item.name, "VEVENT")) continue;
                const uid = try icalendar.componentText(a, item, "UID") orelse continue;
                if (wanted.getPtr(uid)) |present| present.* = true;
            }
        }
    }

    const ExportRecord = union(enum) {
        document: []const u8,
        event: icalendar.Export.Event,
    };

    const ExportSnapshot = struct {
        name: []const u8,
        records: []const ExportRecord,
    };

    pub fn exportCalendar(self: *Self, arena: Allocator, username: []const u8, calendar_id: u64) ![]const u8 {
        const mailbox_id = try self.activeMailboxId(username);
        const snapshot = try self.snapshotCalendarExport(arena, username, mailbox_id, calendar_id);
        return renderCalendarExport(arena, snapshot);
    }

    /// Used by an operator with a verified local mailbox ID. The mailbox
    /// may be disabled, but a DAV collection must still belong to that ID.
    pub fn exportCalendarForMailbox(self: *Self, arena: Allocator, mailbox_id: i64, calendar_id: u64) ![]const u8 {
        const snapshot = try self.snapshotCalendarExport(arena, "", mailbox_id, calendar_id);
        return renderCalendarExport(arena, snapshot);
    }

    pub fn exportOwnerForMailbox(self: *Self, mailbox_id: i64) ?u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.findUserIdLocked("", mailbox_id);
    }

    fn renderCalendarExport(arena: Allocator, snapshot: ExportSnapshot) ![]const u8 {
        var result = try icalendar.Export.init(arena, snapshot.name);
        for (snapshot.records) |record| switch (record) {
            .document => |document| try result.addDocument(document),
            .event => |event| try result.addEvent(event),
        };
        return result.finish();
    }

    fn snapshotCalendarExport(self: *Self, arena: Allocator, username: []const u8, mailbox_id: ?i64, calendar_id: u64) !ExportSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();

        const user_id = self.findUserIdLocked(username, mailbox_id) orelse return error.CalendarNotFound;
        const calendar = self.calendars.get(calendar_id) orelse return error.CalendarNotFound;
        if (calendar.user_id != user_id) return error.CalendarNotFound;
        var records: std.ArrayList(ExportRecord) = .empty;
        var bytes: usize = 0;
        var events = self.events.valueIterator();
        const empty: []const u8 = "";
        while (events.next()) |event| {
            if (event.calendar_id != calendar_id) continue;
            bytes += if (event.ics_data.len > 0) event.ics_data.len else 128 + event.uid.len + event.summary.len +
                (event.description orelse empty).len + (event.location orelse empty).len +
                (event.organizer orelse empty).len + (event.rrule orelse empty).len;
            if (bytes > icalendar.max_export_bytes) return error.CalendarExportTooLarge;
            try records.append(arena, if (event.ics_data.len > 0)
                .{ .document = try arena.dupe(u8, event.ics_data) }
            else
                .{ .event = .{
                    .uid = try arena.dupe(u8, event.uid),
                    .modified_at = event.modified_at,
                    .summary = try arena.dupe(u8, event.summary),
                    .description = try dupeOptional(arena, event.description),
                    .location = try dupeOptional(arena, event.location),
                    .organizer = try dupeOptional(arena, event.organizer),
                    .start = event.dtstart,
                    .end = event.dtend,
                    .all_day = event.all_day,
                    .recurrence = try dupeOptional(arena, event.rrule),
                    .status = switch (event.status) {
                        .tentative => "TENTATIVE",
                        .confirmed => "CONFIRMED",
                        .cancelled => "CANCELLED",
                    },
                } });
        }
        return .{ .name = try arena.dupe(u8, calendar.name), .records = records.items };
    }

    pub const CalendarWindow = icalendar_busy.Window;
    pub const ReminderSnapshot = struct {
        events: []CalendarEventSummary = &.{},
        dismissed: [][]const u8 = &.{},
    };

    pub fn snapshotReminderSources(self: *Self, a: Allocator, username: []const u8, window: CalendarWindow) !ReminderSnapshot {
        const mailbox_id = try self.activeMailboxId(username);
        self.mutex.lock();
        defer self.mutex.unlock();
        const owner = self.findUserIdLocked(username, mailbox_id) orelse return .{};

        var events: std.ArrayList(CalendarEventSummary) = .empty;
        var source_bytes: usize = 0;
        var rows = self.events.valueIterator();
        while (rows.next()) |event| {
            const calendar = self.calendars.get(event.calendar_id) orelse continue;
            if (calendar.user_id != owner or event.status == .cancelled) continue;
            if (!event.reminder_coverage.mayFire(window.start, window.end, event.dtstart, event.dtend, event.recurring)) continue;
            source_bytes += event.ics_data.len;
            if (events.items.len >= 500 or source_bytes > 4 * 1024 * 1024) return error.TooManySeriesBytes;
            var summary = try summarizeEvent(a, event.*);
            summary.icalendar = try a.dupe(u8, event.ics_data);
            try events.append(a, summary);
        }
        var dismissed: std.ArrayList([]const u8) = .empty;
        if (self.conn) |*conn| {
            var stmt = try conn.prepare("SELECT reminder_key FROM dav_reminder_dismissals WHERE user_id=? AND due_at>=?");
            defer stmt.finalize();
            try stmt.bindInt(1, @intCast(owner));
            try stmt.bindInt(2, window.start);
            while (try stmt.step()) try dismissed.append(a, try a.dupe(u8, try stmt.columnText(0)));
        }
        return .{ .events = try events.toOwnedSlice(a), .dismissed = try dismissed.toOwnedSlice(a) };
    }

    pub fn dismissReminder(self: *Self, username: []const u8, id: u64, key: []const u8, due: i64, cutoff: i64) !void {
        const mailbox_id = try self.activeMailboxId(username);
        self.mutex.lock();
        defer self.mutex.unlock();
        const event = try self.ownedEventLocked(username, mailbox_id, id);
        const owner = self.calendars.get(event.calendar_id).?.user_id;
        const conn = if (self.conn) |*c| c else return error.ReminderStorageUnavailable;
        var prune = try conn.prepare("DELETE FROM dav_reminder_dismissals WHERE due_at<?");
        defer prune.finalize();
        try prune.bindInt(1, cutoff);
        _ = try prune.step();
        var stmt = try conn.prepare(
            "INSERT OR IGNORE INTO dav_reminder_dismissals (user_id, reminder_key, due_at) " ++
                "SELECT ?1, ?2, ?3 WHERE (SELECT count(*) FROM dav_reminder_dismissals WHERE user_id=?1) < 2048",
        );
        defer stmt.finalize();
        try stmt.bindInt(1, @intCast(owner));
        try stmt.bindText(2, key);
        try stmt.bindInt(3, due);
        _ = try stmt.step();
        var verify = try conn.prepare("SELECT 1 FROM dav_reminder_dismissals WHERE user_id=? AND reminder_key=?");
        defer verify.finalize();
        try verify.bindInt(1, @intCast(owner));
        try verify.bindText(2, key);
        if (!try verify.step()) return error.TooManyDismissals;
    }

    pub fn snapshotCalendarEvents(self: *Self, arena: Allocator, username: []const u8, calendar_id: u64, start: i64, end: i64) ![]CalendarEventSummary {
        return self.queryMailboxEvents(arena, username, calendar_id, .{ .start = start, .end = end }, "", false);
    }

    /// List owned events intersecting a half-open window, or search their
    /// stored fields. Recurring masters are returned as candidate series.
    pub fn queryMailboxEvents(self: *Self, arena: Allocator, username: []const u8, calendar_id: ?u64, window: ?CalendarWindow, query: []const u8, include_series: bool) ![]CalendarEventSummary {
        try validateCalendarQuery(window, query);
        const mailbox_id = try self.activeMailboxId(username);

        self.mutex.lock();
        defer self.mutex.unlock();

        const user_id = self.findUserIdLocked(username, mailbox_id) orelse {
            if (calendar_id != null) return error.CalendarNotFound;
            return &.{};
        };
        if (calendar_id) |id| {
            const calendar = self.calendars.get(id) orelse return error.CalendarNotFound;
            if (calendar.user_id != user_id) return error.CalendarNotFound;
        }
        return self.queryCalendarEventsLocked(arena, user_id, calendar_id, window, query, include_series, .owner);
    }

    pub fn queryWebCalendarEvents(self: *Self, arena: Allocator, username: []const u8, calendar_id: ?u64, window: ?CalendarWindow, query: []const u8, include_series: bool) ![]CalendarEventSummary {
        const id = calendar_id orelse return self.queryMailboxEvents(arena, username, null, window, query, include_series);
        try validateCalendarQuery(window, query);
        const access = try self.beginCalendarAccess(username, .read);
        defer access.deinit();
        self.mutex.lock();
        defer self.mutex.unlock();
        const calendar = self.calendars.get(id) orelse return error.CalendarNotFound;
        const permission = (try self.calendarPermissionLocked(access, calendar)) orelse return error.CalendarNotFound;
        if (permission == .free_busy) return error.CalendarNotFound;
        return self.queryCalendarEventsLocked(arena, calendar.user_id, id, window, query, include_series, if (permission == .owner) .owner else .shared);
    }

    const BusySnapshot = struct {
        timezone: []const u8,
        sources: []const icalendar_busy.Source,
    };

    pub const DavCalendarTarget = union(enum) {
        named: struct { owner: []const u8, collection: []const u8 },
        shared: teams.CalendarShareId,
    };
    pub const WebBusyCalendars = struct {
        id: ?u64,
        include_owned: bool = false,
    };
    const BusyTarget = union(enum) { web: WebBusyCalendars, dav: DavCalendarTarget };

    fn resolveDavCalendarLocked(self: *Self, access: CalendarRequest, target: DavCalendarTarget) !Calendar {
        if (target == .shared) {
            var calendars = self.calendars.valueIterator();
            while (calendars.next()) |calendar| {
                if (calendar.share_id) |id| {
                    if (std.mem.eql(u8, &id, &target.shared)) return calendar.*;
                }
            }
            return error.CalendarNotFound;
        }
        const named = target.named;
        const mailbox_id = if (access.account_tx) |tx|
            (try teams.activeMailboxId(tx, named.owner)) orelse return error.CalendarNotFound
        else
            null;
        const owner_id = self.findUserIdLocked(named.owner, mailbox_id) orelse return error.CalendarNotFound;
        return self.getCalendarByName(owner_id, named.collection) orelse error.CalendarNotFound;
    }

    const SharedDavCalendar = struct { calendar: Calendar, permission: CalendarPermission };

    fn sharedDavCalendarLocked(self: *Self, access: CalendarRequest, target: DavCalendarTarget, action: CalendarAction) !SharedDavCalendar {
        const calendar = try self.resolveDavCalendarLocked(access, target);
        const permission = (try self.calendarPermissionLocked(access, calendar)) orelse return error.CalendarNotFound;
        if (target == .shared and permission == .owner) return error.CalendarNotFound;
        switch (permission) {
            .owner, .editor => {},
            .viewer => if (action == .edit) return error.CalendarNotFound,
            .free_busy => return error.CalendarNotFound,
        }
        return .{ .calendar = calendar, .permission = permission };
    }

    fn sharedDavEventLocked(self: *Self, calendar_id: u64, uid: []const u8) !?Event {
        const event = self.getEventByUid(calendar_id, uid) orelse return null;
        if (!event.shareable) return error.EventNotFound;
        return event;
    }

    pub fn getSharedDavEvent(self: *Self, arena: Allocator, username: []const u8, target: DavCalendarTarget, uid: []const u8) !Resource {
        const access = try self.beginCalendarAccess(username, .read);
        defer access.deinit();
        self.mutex.lock();
        defer self.mutex.unlock();
        const calendar = try self.sharedDavCalendarLocked(access, target, .read);
        const event = (try self.sharedDavEventLocked(calendar.calendar.id, uid)) orelse return error.EventNotFound;
        return copyEventResource(arena, event);
    }

    // Do not spend scanner resources on a write that cannot be admitted. The
    // write path still checks the grant and the event again after scanning.
    pub fn checkSharedDavEdit(self: *Self, username: []const u8, target: DavCalendarTarget, uid: []const u8) !void {
        const access = try self.beginCalendarAccess(username, .read);
        defer access.deinit();
        self.mutex.lock();
        defer self.mutex.unlock();
        const calendar = try self.sharedDavCalendarLocked(access, target, .edit);
        _ = try self.sharedDavEventLocked(calendar.calendar.id, uid);
    }

    pub fn putSharedDavEvent(self: *Self, username: []const u8, target: DavCalendarTarget, uid: []const u8, conditions: ResourceConditions, data: EventData) !PutResource {
        const access = try self.beginCalendarAccess(username, .write);
        defer access.deinit();
        self.mutex.lock();
        defer self.mutex.unlock();
        const calendar = try self.sharedDavCalendarLocked(access, target, .edit);
        const existing = try self.sharedDavEventLocked(calendar.calendar.id, uid);
        try self.validateSharedEdit(.editor, data.ics_data orelse "");
        return self.putEventResourceLocked(calendar.calendar.id, existing, conditions, data);
    }

    pub fn deleteSharedDavEvent(self: *Self, username: []const u8, target: DavCalendarTarget, uid: []const u8, conditions: ResourceConditions) !void {
        const access = try self.beginCalendarAccess(username, .write);
        defer access.deinit();
        self.mutex.lock();
        defer self.mutex.unlock();
        const calendar = try self.sharedDavCalendarLocked(access, target, .edit);
        const event = (try self.sharedDavEventLocked(calendar.calendar.id, uid)) orelse return error.EventNotFound;
        if (!conditions.allows(event.etag)) return error.PreconditionFailed;
        try self.deleteEventLocked(event.id);
    }

    pub const DavCalendarMember = struct { uid: []const u8, etag: []const u8, source: icalendar_busy.Source };
    pub const SharedDavListing = union(enum) {
        collection,
        etags,
        events,
        requested: std.StringHashMapUnmanaged(void),
    };
    pub const DavCalendarSnapshot = struct {
        timezone: []const u8 = "UTC",
        editable: bool = false,
        properties: DavCollectionProperties = .{},
        members: []const DavCalendarMember = &.{},
    };

    pub const DavSharedCollection = struct { id: teams.CalendarShareId, properties: DavCollectionProperties, editable: bool };

    pub fn snapshotSharedDavCollections(self: *Self, arena: Allocator, username: []const u8) ![]DavSharedCollection {
        const access = try self.beginCalendarAccess(username, .read);
        defer access.deinit();
        const tx = access.account_tx orelse return &.{};
        const user_id = access.mailbox_id orelse return &.{};
        const grants = try teams.calendarSharesFor(tx, arena, user_id, true);
        self.mutex.lock();
        defer self.mutex.unlock();

        const Readable = struct { user_id: u64, editable: bool };
        var readable: std.AutoHashMapUnmanaged(teams.CalendarShareId, Readable) = .empty;
        for (grants) |grant| {
            if (grant.access == .free_busy) continue;
            const owner = self.findUserIdLocked(grant.source, grant.source_id) orelse continue;
            const entry = try readable.getOrPut(arena, grant.calendar_share_id);
            if (!entry.found_existing) entry.value_ptr.* = .{ .user_id = owner, .editable = false };
            if (entry.value_ptr.user_id == owner and grant.access == .editor) entry.value_ptr.editable = true;
        }
        var result: std.ArrayList(DavSharedCollection) = .empty;
        var calendars = self.calendars.valueIterator();
        while (calendars.next()) |calendar| {
            const id = calendar.share_id orelse continue;
            const grant = readable.get(id) orelse continue;
            if (calendar.user_id != grant.user_id) continue;
            try result.append(arena, .{ .id = id, .properties = try snapshotCollectionProperties(arena, calendar.*), .editable = grant.editable });
        }
        return result.items;
    }

    pub fn snapshotSharedDavMembers(self: *Self, arena: Allocator, username: []const u8, target: DavCalendarTarget, listing: SharedDavListing) !DavCalendarSnapshot {
        const access = try self.beginCalendarAccess(username, .read);
        defer access.deinit();
        self.mutex.lock();
        defer self.mutex.unlock();
        const authorized = try self.sharedDavCalendarLocked(access, target, .read);
        var snapshot = try self.snapshotDavCalendarLocked(arena, authorized.calendar, listing, .shared);
        snapshot.editable = authorized.permission != .viewer;
        if (listing == .collection or listing == .etags)
            snapshot.properties = try snapshotCollectionProperties(arena, authorized.calendar);
        return snapshot;
    }

    pub fn snapshotOwnedDavQuery(self: *Self, arena: Allocator, user_id: u64, collection: []const u8) !DavCalendarSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        const calendar = self.getCalendarByName(user_id, collection) orelse return .{};
        return self.snapshotDavCalendarLocked(arena, calendar, .events, .owner);
    }

    pub const DavSharedSync = struct { properties: DavCollectionProperties, editable: bool, report: DavSyncReport };

    pub fn snapshotSharedDavSync(self: *Self, arena: Allocator, username: []const u8, target: DavCalendarTarget, query: DavSyncQuery) !DavSharedSync {
        const access = try self.beginCalendarAccess(username, .read);
        defer access.deinit();
        self.mutex.lock();
        defer self.mutex.unlock();
        const authorized = try self.sharedDavCalendarLocked(access, target, .read);
        const share_id = authorized.calendar.share_id orelse return error.CalendarNotFound;
        const tx = access.account_tx orelse return error.CalendarNotFound;
        const grantee_id = access.mailbox_id orelse return error.CalendarNotFound;
        const source_id = self.mailboxIdLocked(authorized.calendar.user_id) orelse return error.CalendarNotFound;
        const epoch = (try teams.calendarGrantEpoch(tx, grantee_id, source_id, share_id)) orelse return error.CalendarNotFound;

        var scope = std.crypto.hash.sha2.Sha256.init(.{});
        scope.update(std.mem.asBytes(&grantee_id));
        scope.update(std.mem.asBytes(&source_id));
        scope.update(&share_id);
        scope.update(&epoch);
        scope.update(@tagName(target));

        var members: std.ArrayList(DavSyncMember) = .empty;
        var bytes: usize = 0;
        var events = self.events.valueIterator();
        while (events.next()) |event| {
            if (event.calendar_id != authorized.calendar.id or !event.shareable) continue;
            bytes += @sizeOf(DavSyncMember) + event.uid.len + event.etag.len;
            if (bytes > shared_sync.max_bytes_per_snapshot) return error.CalendarExportTooLarge;
            try members.append(arena, .{ .uid = try arena.dupe(u8, event.uid), .etag = try arena.dupe(u8, event.etag) });
        }
        return .{
            .properties = if (query != .after) try snapshotCollectionProperties(arena, authorized.calendar) else .{},
            .editable = authorized.permission == .editor,
            .report = try self.shared_dav_sync.snapshot(arena, scope.finalResult(), members.items, query, self.config.max_sync_history),
        };
    }

    fn snapshotDavCalendarLocked(self: *Self, arena: Allocator, calendar: Calendar, listing: SharedDavListing, visibility: enum { owner, shared }) !DavCalendarSnapshot {
        if (listing == .collection) return .{};
        var members: std.ArrayList(DavCalendarMember) = .empty;
        var bytes: usize = 0;
        var events = self.events.valueIterator();
        while (events.next()) |event| {
            if (event.calendar_id != calendar.id or (visibility == .shared and !event.shareable)) continue;
            if (listing == .requested and !listing.requested.contains(event.uid)) continue;
            const body = if (listing == .etags) "" else event.ics_data;
            bytes += event.uid.len + event.etag.len + body.len;
            if (bytes > icalendar.max_export_bytes) return error.CalendarExportTooLarge;
            try members.append(arena, .{
                .uid = try arena.dupe(u8, event.uid),
                .etag = try arena.dupe(u8, event.etag),
                .source = try copyCalendarSource(arena, event.*, body),
            });
        }
        return .{ .timezone = try arena.dupe(u8, calendar.timezone), .members = members.items };
    }

    pub fn webCalendarBusyPeriods(self: *Self, arena: Allocator, username: []const u8, calendars: WebBusyCalendars, window: CalendarWindow) ![]icalendar_busy.Window {
        try validateBusyWindow(window);
        const snapshot = try self.snapshotCalendarBusyPeriods(arena, username, .{ .web = calendars }, true);
        const periods = try icalendar_busy.calculate(arena, self.allocator, snapshot.sources, window, snapshot.timezone, .combined);
        const result = try arena.alloc(icalendar_busy.Window, periods.len);
        for (result, periods) |*bounds, period| bounds.* = .{ .start = period.start, .end = period.end };
        return result;
    }

    pub fn davCalendarBusyPeriods(self: *Self, arena: Allocator, username: []const u8, target: DavCalendarTarget, window: CalendarWindow, include_members: bool) ![]icalendar_busy.Period {
        try validateBusyWindow(window);
        const snapshot = try self.snapshotCalendarBusyPeriods(arena, username, .{ .dav = target }, include_members);
        return icalendar_busy.calculate(arena, self.allocator, snapshot.sources, window, snapshot.timezone, .by_type);
    }

    fn validateBusyWindow(window: CalendarWindow) !void {
        try validateCalendarQuery(window, "");
        if (window.start < -62135596800 or window.end >= 253402300800) return error.InvalidRange;
    }

    fn snapshotCalendarBusyPeriods(self: *Self, arena: Allocator, username: []const u8, target: BusyTarget, include_members: bool) !BusySnapshot {
        const access = try self.beginCalendarAccess(username, .read);
        defer access.deinit();
        self.mutex.lock();
        defer self.mutex.unlock();
        const calendar: ?Calendar = switch (target) {
            .web => |web| if (web.id) |id| self.calendars.get(id) orelse return error.CalendarNotFound else null,
            .dav => |path| try self.resolveDavCalendarLocked(access, path),
        };
        if (calendar) |selected| {
            const permission = (try self.calendarPermissionLocked(access, selected)) orelse return error.CalendarNotFound;
            if (target == .dav and target.dav == .shared and permission == .owner) return error.CalendarNotFound;
        }
        if (!include_members) return .{ .timezone = "UTC", .sources = &.{} };
        const owned = if (target == .web and (calendar == null or target.web.include_owned))
            self.findUserIdLocked(username, access.mailbox_id)
        else
            null;

        // Copy a bounded snapshot under the authorization lock, then expand
        // recurrence outside both locks. No calendar source enters the response.
        var sources: std.ArrayList(icalendar_busy.Source) = .empty;
        var owned_zones: std.AutoHashMapUnmanaged(u64, []const u8) = .empty;
        var bytes: usize = 0;
        var events = self.events.valueIterator();
        while (events.next()) |event| {
            const zone: ?[]const u8 = zone: {
                if (calendar) |selected| {
                    if (event.calendar_id == selected.id) break :zone null;
                }
                const user_id = owned orelse continue;
                const personal = self.calendars.get(event.calendar_id) orelse continue;
                if (personal.user_id != user_id) continue;
                const entry = try owned_zones.getOrPut(arena, personal.id);
                if (!entry.found_existing) entry.value_ptr.* = try arena.dupe(u8, personal.timezone);
                break :zone entry.value_ptr.*;
            };
            bytes += event.ics_data.len;
            if (bytes > 16 * 1024 * 1024 or sources.items.len == 32_000) return error.AvailabilityLimit;
            var source = try copyCalendarSource(arena, event.*, event.ics_data);
            source.timezone = zone;
            try sources.append(arena, source);
        }
        return .{ .timezone = if (calendar) |selected| try arena.dupe(u8, selected.timezone) else "UTC", .sources = sources.items };
    }

    fn copyCalendarSource(arena: Allocator, event: Event, body: []const u8) !icalendar_busy.Source {
        return .{
            .icalendar = try arena.dupe(u8, body),
            .start = event.dtstart,
            .end = event.dtend,
            .all_day = event.all_day,
            .cancelled = event.status == .cancelled,
            .tentative = event.status == .tentative,
        };
    }

    fn validateCalendarQuery(window: ?CalendarWindow, query: []const u8) !void {
        if (window) |range| {
            if (range.start >= range.end or @as(i128, range.end) - range.start > 366 * 86400) return error.InvalidRange;
        } else if (query.len == 0) return error.InvalidRange;
    }

    fn queryCalendarEventsLocked(self: *Self, arena: Allocator, user_id: u64, calendar_id: ?u64, window: ?CalendarWindow, query: []const u8, include_series: bool, visibility: enum { owner, shared }) ![]CalendarEventSummary {
        const ascii = @import("ascii-compat");
        var result: std.ArrayList(CalendarEventSummary) = .empty;
        var source_bytes: usize = 0;
        var events = self.events.valueIterator();
        while (events.next()) |event| {
            if (calendar_id) |id| {
                if (event.calendar_id != id) continue;
            } else {
                const calendar = self.calendars.get(event.calendar_id) orelse continue;
                if (calendar.user_id != user_id) continue;
            }
            if (visibility == .shared and !event.shareable) continue;
            const recurring = event.recurring;
            if (window) |range| {
                // A detached instance can be moved to either side of the master.
                if ((!recurring or !include_series) and event.dtstart >= range.end) continue;
                if (!recurring) {
                    const event_end = event.dtend orelse if (event.all_day) event.dtstart +| 86400 else event.dtstart;
                    if (event_end <= range.start and event.dtstart < range.start) continue;
                }
            }
            if (query.len > 0 and ascii.indexOfIgnoreCase(event.summary, query) == null and
                ascii.indexOfIgnoreCase(event.location orelse "", query) == null and
                ascii.indexOfIgnoreCase(event.description orelse "", query) == null) continue;
            if (result.items.len == 500) return error.TooManyEvents;
            var summary = try summarizeEvent(arena, event.*);
            if (include_series and recurring and event.ics_data.len > 0) {
                source_bytes += event.ics_data.len;
                if (source_bytes > 4 * 1024 * 1024) return error.TooManySeriesBytes;
                summary.icalendar = try arena.dupe(u8, event.ics_data);
            }
            try result.append(arena, summary);
        }
        std.mem.sort(CalendarEventSummary, result.items, {}, struct {
            fn lessThan(_: void, left: CalendarEventSummary, right: CalendarEventSummary) bool {
                return left.start < right.start or (left.start == right.start and left.id < right.id);
            }
        }.lessThan);
        return result.toOwnedSlice(arena);
    }

    fn publicCalendarResource(allocator: Allocator, source: []const u8) bool {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const components = icalendar.components(a, source) catch return false;
        var found_event = false;
        for (components) |component| {
            if (std.ascii.eqlIgnoreCase(component.name, "VTIMEZONE")) continue;
            if (!std.ascii.eqlIgnoreCase(component.name, "VEVENT")) return false;
            found_event = true;
            var properties = icalendar.Properties.init(component);
            while (properties.next(a) catch return false) |property| {
                // An exception may carry a different classification from
                // its master. Never return a resource containing a private occurrence.
                if (property.named("CLASS") and !std.ascii.eqlIgnoreCase(property.value, "PUBLIC"))
                    return false;
            }
        }
        return found_event;
    }

    fn summarizeEvent(arena: Allocator, event: Event) !CalendarEventSummary {
        return .{
            .id = event.id,
            .calendar_id = event.calendar_id,
            .uid = try arena.dupe(u8, event.uid),
            .summary = try arena.dupe(u8, event.summary),
            .location = try dupeOptional(arena, event.location),
            .start = event.dtstart,
            .end = event.dtend,
            .all_day = event.all_day,
            .recurrence_rule = try dupeOptional(arena, event.rrule),
            .recurring = event.recurring,
            .status = event.status,
            .etag = try arena.dupe(u8, event.etag),
        };
    }

    fn activeMailboxId(self: *Self, username: []const u8) !?i64 {
        const db = self.config.account_db orelse return null;
        var mailbox = try db.getUserByUsername(username);
        defer mailbox.deinit(db.allocator);
        if (!mailbox.enabled) return error.DavMailboxNotFound;
        return mailbox.id;
    }

    fn findUserIdLocked(self: *Self, username: []const u8, mailbox_id: ?i64) ?u64 {
        for (self.user_ids.items) |entry| {
            if (entry.mailbox_id != mailbox_id) continue;
            if (mailbox_id != null or std.mem.eql(u8, entry.username, username)) return entry.user_id;
        }
        return null;
    }

    fn dupeOptional(arena: Allocator, value: ?[]const u8) !?[]const u8 {
        return if (value) |text| try arena.dupe(u8, text) else null;
    }

    pub fn deleteCalendar(self: *Self, id: u64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Delete all events in this calendar first
        var events_to_delete: std.ArrayList(u64) = .empty;
        defer events_to_delete.deinit(self.allocator);

        var iter = self.events.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.calendar_id == id) {
                try events_to_delete.append(self.allocator, entry.key_ptr.*);
            }
        }

        for (events_to_delete.items) |event_id| {
            if (self.events.fetchRemove(event_id)) |entry| self.freeEvent(entry.value);
        }

        if (self.calendars.fetchRemove(id)) |entry| self.freeCalendar(entry.value);
        self.dbExecId("DELETE FROM dav_events WHERE calendar_id = {d}", id);
        self.dbExecId("DELETE FROM dav_calendars WHERE id = {d}", id);
    }

    // -------------------------------------------------------------------------
    // Event Operations
    // -------------------------------------------------------------------------

    pub fn createEvent(self: *Self, calendar_id: u64, data: EventData) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.createEventLocked(calendar_id, data);
    }

    fn createEventLocked(self: *Self, calendar_id: u64, data: EventData) !u64 {
        const id = self.next_event_id;
        self.next_event_id += 1;

        const now = currentTimestamp();
        const etag = try self.generateEtag(id);
        errdefer self.allocator.free(etag);
        // UID slices belong to the stored record, including caller-supplied IDs.
        const uid = if (data.uid) |value| try self.allocator.dupe(u8, value) else try self.generateUid();
        errdefer self.allocator.free(uid);
        const own = try self.ownEventText(data, data.organizer, data.ics_data orelse "");
        errdefer self.freeEventText(own);
        const invitation_revisions = try dupeOptional(self.allocator, data.invitation_revisions);
        errdefer if (invitation_revisions) |value| self.allocator.free(value);
        const invitation_projections = try dupeOptional(self.allocator, data.invitation_projections);
        errdefer if (invitation_projections) |value| self.allocator.free(value);

        const event = Event{
            .id = id,
            .calendar_id = calendar_id,
            .uid = uid,
            .summary = own.summary,
            .description = own.description,
            .location = own.location,
            .dtstart = data.dtstart,
            .dtend = data.dtend,
            .all_day = data.all_day,
            .rrule = own.rrule,
            .recurring = own.rrule != null or icalendar.hasRecurrence(own.ics_data),
            .shareable = publicCalendarResource(self.allocator, own.ics_data),
            .reminder_coverage = try reminder.coverage(self.allocator, own.ics_data),
            .organizer = own.organizer,
            .status = data.status,
            .created_at = now,
            .modified_at = now,
            .etag = etag,
            .ics_data = own.ics_data,
            .source_message = data.source_message,
            .invitation_key = data.invitation_key,
            .invitation_revisions = invitation_revisions,
            .invitation_projections = invitation_projections,
        };
        try self.events.ensureUnusedCapacity(1);
        try self.commitEventMutationLocked(event, .created);
        return id;
    }

    /// Publish event, calendar revision, and sync history only after SQLite
    /// commits both rows. A create reserves map capacity before this call.
    fn commitEventMutationLocked(self: *Self, event: Event, kind: SyncChange.ChangeType) !void {
        const change = if (self.config.enable_sync_tokens)
            try self.prepareChange(event.calendar_id, event.id, .event, kind, event.etag, event.uid)
        else
            null;
        errdefer if (change) |item| self.freeChange(item);
        var calendar = self.calendars.get(event.calendar_id);
        if (calendar) |*updated| {
            updated.modified_at = currentTimestamp();
            updated.sync_token = if (change) |item| item.token else self.current_sync_token;
            updated.ctag = try std.fmt.allocPrint(self.allocator, "ctag-{d}-{d}-{s}", .{ event.calendar_id, updated.sync_token, event.etag });
        }
        errdefer if (calendar) |updated| self.allocator.free(updated.ctag);

        if (self.conn) |*conn| {
            try conn.beginTransaction();
            errdefer conn.rollback() catch {};
            if (kind == .deleted) {
                var stmt = try conn.prepare("DELETE FROM dav_events WHERE id = ?");
                defer stmt.finalize();
                try stmt.bindInt(1, @intCast(event.id));
                _ = try stmt.step();
            } else {
                try self.persistEvent(event);
            }
            if (calendar) |updated| try self.persistCalendar(updated);
            try conn.commit();
        }
        if (kind == .deleted) {
            _ = self.events.remove(event.id);
        } else {
            self.events.putAssumeCapacity(event.id, event);
        }
        if (calendar) |updated| {
            const live = self.calendars.getPtr(event.calendar_id).?;
            self.allocator.free(live.ctag);
            live.* = updated;
        }
        if (change) |item| self.publishChange(item);
    }

    pub const EventData = struct {
        uid: ?[]const u8 = null,
        summary: []const u8,
        description: ?[]const u8 = null,
        location: ?[]const u8 = null,
        dtstart: i64,
        dtend: ?i64 = null,
        all_day: bool = false,
        rrule: ?[]const u8 = null,
        organizer: ?[]const u8 = null,
        status: Event.EventStatus = .confirmed,
        ics_data: ?[]const u8 = null,
        source_message: ?MessageReference = null,
        invitation_key: ?[64]u8 = null,
        invitation_revisions: ?[]const u8 = null,
        invitation_projections: ?[]const u8 = null,
    };

    const EventText = struct {
        summary: []const u8,
        description: ?[]const u8,
        location: ?[]const u8,
        rrule: ?[]const u8,
        organizer: ?[]const u8,
        ics_data: []const u8,

        fn fromEvent(event: Event) EventText {
            return .{
                .summary = event.summary,
                .description = event.description,
                .location = event.location,
                .rrule = event.rrule,
                .organizer = event.organizer,
                .ics_data = event.ics_data,
            };
        }
    };

    fn ownEventText(self: *Self, data: EventData, organizer: ?[]const u8, ics_data: []const u8) !EventText {
        const a = self.allocator;
        const summary = try a.dupe(u8, data.summary);
        errdefer a.free(summary);
        const description = try dupeOptional(a, data.description);
        errdefer if (description) |value| a.free(value);
        const location = try dupeOptional(a, data.location);
        errdefer if (location) |value| a.free(value);
        const rule = try dupeOptional(a, data.rrule);
        errdefer if (rule) |value| a.free(value);
        const owner = try dupeOptional(a, organizer);
        errdefer if (owner) |value| a.free(value);
        return .{
            .summary = summary,
            .description = description,
            .location = location,
            .rrule = rule,
            .organizer = owner,
            .ics_data = try a.dupe(u8, ics_data),
        };
    }

    fn freeEventText(self: *Self, data: EventText) void {
        const a = self.allocator;
        a.free(data.summary);
        for ([_]?[]const u8{ data.description, data.location, data.rrule, data.organizer }) |item| {
            if (item) |value| a.free(value);
        }
        a.free(data.ics_data);
    }

    fn freeEvent(self: *Self, event: Event) void {
        self.freeEventText(EventText.fromEvent(event));
        self.allocator.free(event.uid);
        self.allocator.free(event.etag);
        if (event.invitation_revisions) |value| self.allocator.free(value);
        if (event.invitation_projections) |value| self.allocator.free(value);
    }

    pub fn getEvent(self: *Self, id: u64) ?Event {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.events.get(id);
    }

    pub fn getEventByUid(self: *Self, calendar_id: u64, uid: []const u8) ?Event {
        var iter = self.events.valueIterator();
        while (iter.next()) |event| {
            if (event.calendar_id == calendar_id and std.mem.eql(u8, event.uid, uid)) {
                return event.*;
            }
        }
        return null;
    }

    pub fn getCalendarEvents(self: *Self, calendar_id: u64) ![]Event {
        self.mutex.lock();
        defer self.mutex.unlock();

        var result: std.ArrayList(Event) = .empty;
        errdefer result.deinit(self.allocator);

        var iter = self.events.valueIterator();
        while (iter.next()) |event| {
            if (event.calendar_id == calendar_id) {
                try result.append(self.allocator, event.*);
            }
        }

        return result.toOwnedSlice(self.allocator);
    }

    pub fn updateEvent(self: *Self, id: u64, data: EventData) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.updateEventLocked(id, data);
    }

    fn updateEventLocked(self: *Self, id: u64, data: EventData) !void {
        const old = self.events.get(id) orelse return error.EventNotFound;
        const etag = try self.generateEtag(id);
        errdefer self.allocator.free(etag);
        const own = try self.ownEventText(data, old.organizer, data.ics_data orelse old.ics_data);
        errdefer self.freeEventText(own);
        const invitation_revisions = try dupeOptional(self.allocator, data.invitation_revisions);
        errdefer if (invitation_revisions) |value| self.allocator.free(value);
        const invitation_projections = if (invitation_revisions != null)
            try dupeOptional(self.allocator, data.invitation_projections)
        else
            null;
        errdefer if (invitation_projections) |value| self.allocator.free(value);

        var event = old;
        event.summary = own.summary;
        event.description = own.description;
        event.location = own.location;
        event.dtstart = data.dtstart;
        event.dtend = data.dtend;
        event.all_day = data.all_day;
        event.rrule = own.rrule;
        event.recurring = own.rrule != null or icalendar.hasRecurrence(own.ics_data);
        event.shareable = publicCalendarResource(self.allocator, own.ics_data);
        event.reminder_coverage = try reminder.coverage(self.allocator, own.ics_data);
        event.organizer = own.organizer;
        event.status = data.status;
        event.modified_at = currentTimestamp();
        event.etag = etag;
        event.ics_data = own.ics_data;
        if (invitation_revisions) |value| {
            event.invitation_revisions = value;
            event.invitation_projections = invitation_projections;
        }
        try self.commitEventMutationLocked(event, .modified);
        if (invitation_revisions != null) {
            if (old.invitation_revisions) |value| self.allocator.free(value);
            if (old.invitation_projections) |value| self.allocator.free(value);
        }
        self.allocator.free(old.etag);
        self.freeEventText(EventText.fromEvent(old));
    }

    pub fn deleteEvent(self: *Self, id: u64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.deleteEventLocked(id);
    }

    fn deleteEventLocked(self: *Self, id: u64) !void {
        const event = self.events.get(id) orelse return;
        try self.commitEventMutationLocked(event, .deleted);
        self.freeEvent(event);
    }

    // -------------------------------------------------------------------------
    // Address Book Operations
    // -------------------------------------------------------------------------

    pub fn createAddressBook(
        self: *Self,
        user_id: u64,
        name: []const u8,
        description: ?[]const u8,
    ) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.createAddressBookLocked(user_id, name, description);
    }

    fn createAddressBookLocked(
        self: *Self,
        user_id: u64,
        name: []const u8,
        description: ?[]const u8,
    ) !u64 {
        const id = self.next_addressbook_id;
        self.next_addressbook_id += 1;

        const now = currentTimestamp();
        const ctag = try self.generateCtag(id, now);
        errdefer self.allocator.free(ctag);
        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        const owned_description = try dupeOptional(self.allocator, description);
        errdefer if (owned_description) |text| self.allocator.free(text);

        try self.addressbooks.put(id, .{
            .id = id,
            .user_id = user_id,
            .name = owned_name,
            .description = owned_description,
            .created_at = now,
            .modified_at = now,
            .sync_token = self.current_sync_token,
            .ctag = ctag,
        });

        self.persistAddressBook(self.addressbooks.get(id).?);
        return id;
    }

    fn freeAddressBook(self: *Self, book: AddressBook) void {
        self.allocator.free(book.ctag);
        self.allocator.free(book.name);
        if (book.display_name) |value| self.allocator.free(value);
        if (book.description) |description| self.allocator.free(description);
    }

    pub fn getAddressBook(self: *Self, id: u64) ?AddressBook {
        return self.addressbooks.get(id);
    }

    pub fn getAddressBookByName(self: *Self, user_id: u64, name: []const u8) ?AddressBook {
        var iter = self.addressbooks.valueIterator();
        while (iter.next()) |ab| {
            if (ab.user_id == user_id and std.mem.eql(u8, ab.name, name)) {
                return ab.*;
            }
        }
        return null;
    }

    pub fn getUserAddressBooks(self: *Self, user_id: u64) ![]AddressBook {
        self.mutex.lock();
        defer self.mutex.unlock();

        var result: std.ArrayList(AddressBook) = .empty;
        errdefer result.deinit(self.allocator);

        var iter = self.addressbooks.valueIterator();
        while (iter.next()) |ab| {
            if (ab.user_id == user_id) {
                try result.append(self.allocator, ab.*);
            }
        }

        return result.toOwnedSlice(self.allocator);
    }

    pub fn deleteAddressBook(self: *Self, id: u64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Delete all contacts in this addressbook first
        var contacts_to_delete: std.ArrayList(u64) = .empty;
        defer contacts_to_delete.deinit(self.allocator);

        var iter = self.contacts.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.addressbook_id == id) {
                try contacts_to_delete.append(self.allocator, entry.key_ptr.*);
            }
        }

        for (contacts_to_delete.items) |contact_id| {
            if (self.contacts.fetchRemove(contact_id)) |entry| self.freeContact(entry.value);
            self.removeContactRelations(contact_id);
        }

        if (self.addressbooks.fetchRemove(id)) |entry| self.freeAddressBook(entry.value);
        self.dbExecId("DELETE FROM dav_emails WHERE contact_id IN (SELECT id FROM dav_contacts WHERE addressbook_id = {d})", id);
        self.dbExecId("DELETE FROM dav_phones WHERE contact_id IN (SELECT id FROM dav_contacts WHERE addressbook_id = {d})", id);
        self.dbExecId("DELETE FROM dav_contacts WHERE addressbook_id = {d}", id);
        self.dbExecId("DELETE FROM dav_addressbooks WHERE id = {d}", id);
    }

    // -------------------------------------------------------------------------
    // Contact Operations
    // -------------------------------------------------------------------------

    pub const default_address_book = "contacts";

    /// Use the same ownership map as CardDAV and ActiveSync. The response owns
    /// its strings and is safe to use once the DAV store lock is released.
    pub fn snapshotContactBook(self: *Self, a: Allocator, username: []const u8, requested: ?[]const u8) !AddressBookSnapshot {
        const mailbox_id = try self.activeMailboxId(username);
        self.mutex.lock();
        defer self.mutex.unlock();
        const user_id = self.findUserIdLocked(username, mailbox_id);
        var names: std.ArrayList([]const u8) = .empty;
        if (user_id) |id| {
            var books = self.addressbooks.valueIterator();
            while (books.next()) |book| {
                if (book.user_id == id and std.unicode.utf8ValidateSlice(book.name))
                    try names.append(a, try a.dupe(u8, book.name));
            }
        }
        if (names.items.len == 0) try names.append(a, default_address_book);
        std.mem.sort([]const u8, names.items, {}, struct {
            fn less(_: void, left: []const u8, right: []const u8) bool {
                return std.ascii.orderIgnoreCase(left, right) == .lt;
            }
        }.less);
        const chosen = requested orelse names.items[0];
        const book = if (user_id) |id| self.getAddressBookByName(id, chosen) else null;
        if (book == null and !std.mem.eql(u8, chosen, default_address_book)) return error.AddressBookNotFound;
        return .{
            .books = try names.toOwnedSlice(a),
            .book = chosen,
            .cards = if (book) |current| try self.contactCardsLocked(a, current.id) else &.{},
        };
    }

    fn contactCardsLocked(self: *Self, a: Allocator, book: u64) ![]ContactCard {
        var cards: std.ArrayList(ContactCard) = .empty;
        var iter = self.contacts.valueIterator();
        while (iter.next()) |contact| {
            if (contact.addressbook_id != book or !std.unicode.utf8ValidateSlice(contact.uid)) continue;
            var scratch = std.heap.ArenaAllocator.init(self.allocator);
            defer scratch.deinit();
            const fields = try contact_vcard.read(scratch.allocator(), contact.vcf_data);
            var addresses: std.ArrayList([]const u8) = .empty;
            for (fields.emails) |email| {
                if (std.unicode.utf8ValidateSlice(email)) try addresses.append(a, try a.dupe(u8, email));
            }
            if (contact.vcf_data.len == 0) for (self.emails.items) |email| {
                if (email.contact_id == contact.id and std.unicode.utf8ValidateSlice(email.email))
                    try addresses.append(a, try a.dupe(u8, email.email));
            };
            const name = if (fields.name.len > 0) fields.name else contact.full_name;
            const note = if (fields.note.len > 0) fields.note else contact.note orelse "";
            const identifier = if (fields.uid.len > 0 and std.unicode.utf8ValidateSlice(fields.uid)) fields.uid else contact.uid;
            var members: std.ArrayList([]const u8) = .empty;
            for (fields.members) |member| {
                if (std.unicode.utf8ValidateSlice(member)) try members.append(a, try a.dupe(u8, member));
            }
            try cards.append(a, .{
                .uid = try a.dupe(u8, contact.uid),
                .card_uid = try a.dupe(u8, identifier),
                .name = if (std.unicode.utf8ValidateSlice(name)) try a.dupe(u8, name) else "Unnamed contact",
                .note = if (std.unicode.utf8ValidateSlice(note)) try a.dupe(u8, note) else "",
                .kind = fields.kind,
                .emails = try addresses.toOwnedSlice(a),
                .members = try members.toOwnedSlice(a),
                .etag = try a.dupe(u8, contact.etag),
            });
        }
        std.mem.sort(ContactCard, cards.items, {}, struct {
            fn less(_: void, left: ContactCard, right: ContactCard) bool {
                const order = std.ascii.orderIgnoreCase(left.name, right.name);
                return order == .lt or (order == .eq and std.mem.order(u8, left.uid, right.uid) == .lt);
            }
        }.less);
        return cards.toOwnedSlice(a);
    }

    pub fn editOwnedContact(self: *Self, a: Allocator, username: []const u8, collection: []const u8, resource: ?[]const u8, conditions: ResourceConditions, edit: ContactEdit) !PutResource {
        const mailbox_id = try self.activeMailboxId(username);
        self.mutex.lock();
        defer self.mutex.unlock();

        if (resource != null and self.findUserIdLocked(username, mailbox_id) == null) return error.ContactNotFound;
        const owner = try self.getOrCreateUserIdLocked(username, mailbox_id);
        const existing_book = self.getAddressBookByName(owner, collection);
        if (existing_book == null and (resource != null or !std.mem.eql(u8, collection, default_address_book)))
            return error.ContactNotFound;
        const old = if (resource) |uid| self.getContactByUid(existing_book.?.id, uid) orelse return error.ContactNotFound else null;
        if (!conditions.allows(if (old) |contact| contact.etag else null)) return error.PreconditionFailed;

        var random: [16]u8 = undefined;
        io_compat.randomBytes(&random);
        const uid = resource orelse try contact_vcard.uuid(a, &random);
        const raw = if (old) |contact| try self.generateVcfLocked(contact) else "";
        defer if (old != null) self.allocator.free(raw);
        const original = try contact_vcard.read(a, raw);
        if (old != null and original.kind != edit.kind) return error.InvalidContact;
        const members = if (edit.kind == .group) try self.editedGroupMembers(a, existing_book, uid, original.members, edit.members) else &.{};
        const updated = try contact_vcard.apply(a, raw, uid, .{
            .kind = edit.kind,
            .name = edit.name,
            .note = edit.note,
            .emails = if (edit.kind == .contact) edit.emails else &.{},
            .members = members,
        });
        var data = try contactDataFromVcf(a, uid, updated);
        if (old) |contact| {
            data.birthday = contact.birthday;
            data.photo_url = contact.photo_url;
            try self.updateContactLocked(contact.id, data);
            return PutResource.init(false, self.contacts.get(contact.id).?.etag);
        }
        const book = if (existing_book) |existing| existing.id else try self.createAddressBookLocked(owner, collection, null);
        const id = try self.createContactLocked(book, data);
        return PutResource.init(true, self.contacts.get(id).?.etag);
    }

    fn editedGroupMembers(self: *Self, a: Allocator, book: ?AddressBook, group_uid: []const u8, old: []const []const u8, selected: []const []const u8) ![]const []const u8 {
        const cards = if (book) |value| try self.contactCardsLocked(a, value.id) else &.{};
        var result: std.ArrayList([]const u8) = .empty;
        // External, unresolved, and nested references may belong to another
        // CardDAV client's workflow. Preserve them during a local edit.
        for (old) |uri| {
            for (cards) |card| {
                if (card.kind == .contact and memberMatches(card, uri)) break;
            } else {
                try result.append(a, uri);
            }
        }
        for (selected) |uid| {
            if (std.mem.eql(u8, uid, group_uid)) return error.InvalidGroupMember;
            for (cards) |card| {
                if (!std.mem.eql(u8, card.uid, uid) or card.kind != .contact) continue;
                const identity = contact_vcard.cardIdentifier(card.card_uid);
                const uri = if (contact_vcard.isUuid(identity))
                    try std.fmt.allocPrint(a, "urn:uuid:{s}", .{identity})
                else if (std.ascii.startsWithIgnoreCase(card.card_uid, "urn:") or std.ascii.startsWithIgnoreCase(card.card_uid, "https:"))
                    card.card_uid
                else if (card.emails.len > 0)
                    try std.fmt.allocPrint(a, "mailto:{s}", .{card.emails[0]})
                else
                    return error.InvalidGroupMember;
                for (uri) |byte| if (byte <= ' ' or byte == 0x7f) return error.InvalidGroupMember;
                for (result.items) |known| {
                    if (std.mem.eql(u8, uri, known)) break;
                } else try result.append(a, uri);
                break;
            } else return error.InvalidGroupMember;
        }
        return result.toOwnedSlice(a);
    }

    fn memberMatches(card: ContactCard, uri: []const u8) bool {
        if (std.ascii.startsWithIgnoreCase(uri, "mailto:")) {
            for (card.emails) |email| if (std.ascii.eqlIgnoreCase(email, uri[7..])) return true;
            return false;
        }
        const left = contact_vcard.cardIdentifier(card.card_uid);
        const right = contact_vcard.cardIdentifier(uri);
        if (contact_vcard.isUuid(left) and contact_vcard.isUuid(right)) return std.ascii.eqlIgnoreCase(left, right);
        return std.mem.eql(u8, left, right);
    }

    pub fn removeOwnedContact(self: *Self, username: []const u8, collection: []const u8, uid: []const u8, expected: []const u8) !void {
        const mailbox_id = try self.activeMailboxId(username);
        self.mutex.lock();
        defer self.mutex.unlock();
        const user = self.findUserIdLocked(username, mailbox_id) orelse return error.ContactNotFound;
        const book = self.getAddressBookByName(user, collection) orelse return error.ContactNotFound;
        const contact = self.getContactByUid(book.id, uid) orelse return error.ContactNotFound;
        if (!std.mem.eql(u8, contact.etag, expected)) return error.PreconditionFailed;
        try self.deleteContactLocked(contact.id);
    }

    pub fn createContact(self: *Self, addressbook_id: u64, data: ContactData) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.createContactLocked(addressbook_id, data);
    }

    fn createContactLocked(self: *Self, addressbook_id: u64, data: ContactData) !u64 {
        const id = self.next_contact_id;
        self.next_contact_id += 1;

        const now = currentTimestamp();
        var inserted = false;
        const etag = try self.generateEtag(id);
        errdefer if (!inserted) self.allocator.free(etag);
        // UID slices belong to the stored record, including caller-supplied IDs.
        const uid = if (data.uid) |value| try self.allocator.dupe(u8, value) else try self.generateUid();
        errdefer if (!inserted) self.allocator.free(uid);

        const contact = try self.ownContactText(.{
            .id = id,
            .addressbook_id = addressbook_id,
            .uid = uid,
            .full_name = data.full_name,
            .given_name = data.given_name,
            .family_name = data.family_name,
            .nickname = data.nickname,
            .organization = data.organization,
            .title = data.title,
            .birthday = data.birthday,
            .note = data.note,
            .photo_url = data.photo_url,
            .created_at = now,
            .modified_at = now,
            .etag = etag,
            .vcf_data = data.vcf_data orelse "",
        });

        errdefer if (!inserted) self.freeContactText(contact);
        try self.contacts.ensureUnusedCapacity(1);
        try self.replaceContactRelations(id, data);
        self.contacts.putAssumeCapacity(id, contact);
        inserted = true;

        if (self.config.enable_sync_tokens) {
            try self.recordChange(addressbook_id, id, .contact, .created, etag, uid);
        }
        try self.updateAddressBookCtag(addressbook_id);
        self.persistContact(contact);

        return id;
    }

    pub const ContactData = struct {
        uid: ?[]const u8 = null,
        full_name: []const u8,
        given_name: ?[]const u8 = null,
        family_name: ?[]const u8 = null,
        nickname: ?[]const u8 = null,
        organization: ?[]const u8 = null,
        title: ?[]const u8 = null,
        birthday: ?i64 = null,
        note: ?[]const u8 = null,
        photo_url: ?[]const u8 = null,
        vcf_data: ?[]const u8 = null,
        emails: []const EmailData = &.{},
        phones: []const PhoneData = &.{},
    };

    pub const EmailData = struct {
        email: []const u8,
        email_type: EmailAddress.EmailType = .other,
        is_primary: bool = false,
    };

    pub const PhoneData = struct {
        number: []const u8,
        phone_type: PhoneNumber.PhoneType = .other,
        is_primary: bool = false,
    };

    const optional_contact_fields = [_][]const u8{
        "given_name", "family_name", "nickname", "organization", "title", "note", "photo_url",
    };

    fn ownContactText(self: *Self, contact: Contact) !Contact {
        const a = self.allocator;
        var owned = contact;
        owned.full_name = "";
        owned.vcf_data = "";
        inline for (optional_contact_fields) |field| @field(owned, field) = null;
        errdefer self.freeContactText(owned);
        owned.full_name = try a.dupe(u8, contact.full_name);
        owned.vcf_data = try a.dupe(u8, contact.vcf_data);
        inline for (optional_contact_fields) |field| @field(owned, field) = try dupeOptional(a, @field(contact, field));
        return owned;
    }

    fn freeContactText(self: *Self, contact: Contact) void {
        self.allocator.free(contact.full_name);
        self.allocator.free(contact.vcf_data);
        inline for (optional_contact_fields) |field| {
            if (@field(contact, field)) |value| self.allocator.free(value);
        }
    }

    fn freeContact(self: *Self, contact: Contact) void {
        self.freeContactText(contact);
        self.allocator.free(contact.uid);
        self.allocator.free(contact.etag);
    }

    fn removeContactRelations(self: *Self, id: u64) void {
        var index: usize = 0;
        while (index < self.emails.items.len) {
            if (self.emails.items[index].contact_id == id) {
                self.allocator.free(self.emails.orderedRemove(index).email);
            } else {
                index += 1;
            }
        }
        index = 0;
        while (index < self.phones.items.len) {
            if (self.phones.items[index].contact_id == id) {
                self.allocator.free(self.phones.orderedRemove(index).number);
            } else {
                index += 1;
            }
        }
    }

    fn replaceContactRelations(self: *Self, id: u64, data: ContactData) !void {
        const a = self.allocator;
        var emails: std.ArrayList(EmailAddress) = .empty;
        defer emails.deinit(a);
        errdefer for (emails.items) |email| a.free(email.email);
        var phones: std.ArrayList(PhoneNumber) = .empty;
        defer phones.deinit(a);
        errdefer for (phones.items) |phone| a.free(phone.number);
        try emails.ensureTotalCapacity(a, data.emails.len);
        try phones.ensureTotalCapacity(a, data.phones.len);

        for (data.emails) |email| emails.appendAssumeCapacity(.{
            .contact_id = id,
            .email = try a.dupe(u8, email.email),
            .email_type = email.email_type,
            .is_primary = email.is_primary,
        });
        for (data.phones) |phone| phones.appendAssumeCapacity(.{
            .contact_id = id,
            .number = try a.dupe(u8, phone.number),
            .phone_type = phone.phone_type,
            .is_primary = phone.is_primary,
        });
        try self.emails.ensureUnusedCapacity(a, emails.items.len);
        try self.phones.ensureUnusedCapacity(a, phones.items.len);
        self.removeContactRelations(id);
        self.emails.appendSliceAssumeCapacity(emails.items);
        self.phones.appendSliceAssumeCapacity(phones.items);
    }

    pub fn getContact(self: *Self, id: u64) ?Contact {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.contacts.get(id);
    }

    pub fn getContactByUid(self: *Self, addressbook_id: u64, uid: []const u8) ?Contact {
        var iter = self.contacts.valueIterator();
        while (iter.next()) |contact| {
            if (contact.addressbook_id == addressbook_id and std.mem.eql(u8, contact.uid, uid)) {
                return contact.*;
            }
        }
        return null;
    }

    pub fn updateContact(self: *Self, id: u64, data: ContactData) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.updateContactLocked(id, data);
    }

    fn updateContactLocked(self: *Self, id: u64, data: ContactData) !void {
        if (self.contacts.getPtr(id)) |contact| {
            const now = currentTimestamp();
            const etag = try self.generateEtag(id);
            var replaced = false;
            errdefer if (!replaced) self.allocator.free(etag);

            var updated = contact.*;
            updated.full_name = data.full_name;
            inline for (optional_contact_fields) |field| @field(updated, field) = @field(data, field);
            updated.birthday = data.birthday;
            updated.modified_at = now;
            updated.etag = etag;
            updated.vcf_data = data.vcf_data orelse contact.vcf_data;
            const owned = try self.ownContactText(updated);
            errdefer if (!replaced) self.freeContactText(owned);
            try self.replaceContactRelations(id, data);
            self.allocator.free(contact.etag);
            self.freeContactText(contact.*);
            contact.* = owned;
            replaced = true;

            if (self.config.enable_sync_tokens) {
                try self.recordChange(contact.addressbook_id, id, .contact, .modified, etag, contact.uid);
            }
            try self.updateAddressBookCtag(contact.addressbook_id);
            self.persistContact(contact.*);
        } else {
            return error.ContactNotFound;
        }
    }

    pub fn getAddressBookContacts(self: *Self, addressbook_id: u64) ![]Contact {
        self.mutex.lock();
        defer self.mutex.unlock();

        var result: std.ArrayList(Contact) = .empty;
        errdefer result.deinit(self.allocator);

        var iter = self.contacts.valueIterator();
        while (iter.next()) |contact| {
            if (contact.addressbook_id == addressbook_id) {
                try result.append(self.allocator, contact.*);
            }
        }

        return result.toOwnedSlice(self.allocator);
    }

    /// Deep-copy a bounded snapshot while holding the store lock. A concurrent
    /// CardDAV edit must not invalidate webmail's contact names or addresses.
    pub fn suggestContacts(self: *Self, allocator: Allocator, username: []const u8, query: []const u8, requested_limit: usize) ![]ContactSuggestion {
        const mailbox_id = try self.activeMailboxId(username);
        self.mutex.lock();
        defer self.mutex.unlock();
        const ascii = @import("ascii-compat");
        const limit = @min(requested_limit, 100);
        const user_id = self.findUserIdLocked(username, mailbox_id) orelse return &.{};
        if (limit == 0) return &.{};
        var result: std.ArrayList(ContactSuggestion) = .empty;
        defer result.deinit(allocator);
        for (self.emails.items) |email| {
            const contact = self.contacts.get(email.contact_id) orelse continue;
            const book = self.addressbooks.get(contact.addressbook_id) orelse continue;
            if (book.user_id != user_id) continue;
            if (query.len > 0 and ascii.indexOfIgnoreCase(email.email, query) == null and ascii.indexOfIgnoreCase(contact.full_name, query) == null) continue;
            var duplicate = false;
            for (result.items) |known| if (std.ascii.eqlIgnoreCase(known.address, email.email)) {
                duplicate = true;
                break;
            };
            if (duplicate) continue;
            var position: usize = 0;
            while (position < result.items.len and std.ascii.orderIgnoreCase(result.items[position].address, email.email) == .lt) position += 1;
            if (position >= limit) continue;
            try result.insert(allocator, position, .{ .name = contact.full_name, .address = email.email });
            if (result.items.len > limit) result.items.len = limit;
        }
        const output = try allocator.alloc(ContactSuggestion, result.items.len);
        var completed: usize = 0;
        errdefer {
            for (output[0..completed]) |item| {
                allocator.free(item.name);
                allocator.free(item.address);
            }
            allocator.free(output);
        }
        for (result.items, 0..) |item, index| {
            const name = try allocator.dupe(u8, item.name);
            errdefer allocator.free(name);
            output[index] = .{ .name = name, .address = try allocator.dupe(u8, item.address) };
            completed += 1;
        }
        return output;
    }

    pub fn getContactEmails(self: *Self, contact_id: u64) []EmailAddress {
        self.mutex.lock();
        defer self.mutex.unlock();

        var result: std.ArrayList(EmailAddress) = .empty;
        for (self.emails.items) |email| {
            if (email.contact_id == contact_id) {
                result.append(self.allocator, email) catch continue;
            }
        }
        return result.toOwnedSlice(self.allocator) catch &.{};
    }

    pub fn getContactPhones(self: *Self, contact_id: u64) []PhoneNumber {
        self.mutex.lock();
        defer self.mutex.unlock();

        var result: std.ArrayList(PhoneNumber) = .empty;
        for (self.phones.items) |phone| {
            if (phone.contact_id == contact_id) {
                result.append(self.allocator, phone) catch continue;
            }
        }
        return result.toOwnedSlice(self.allocator) catch &.{};
    }

    /// Find a contact by ID across all addressbooks (used for DELETE/PUT by path)
    pub fn findContactByUidGlobal(self: *Self, uid: []const u8) ?Contact {
        var iter = self.contacts.valueIterator();
        while (iter.next()) |contact| {
            if (std.mem.eql(u8, contact.uid, uid)) {
                return contact.*;
            }
        }
        return null;
    }

    /// Find a contact's internal ID by UID within an addressbook
    pub fn getContactIdByUid(self: *Self, addressbook_id: u64, uid: []const u8) ?u64 {
        var iter = self.contacts.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.addressbook_id == addressbook_id and std.mem.eql(u8, entry.value_ptr.uid, uid)) {
                return entry.key_ptr.*;
            }
        }
        return null;
    }

    /// Find an event's internal ID by UID within a calendar
    pub fn getEventIdByUid(self: *Self, calendar_id: u64, uid: []const u8) ?u64 {
        var iter = self.events.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.calendar_id == calendar_id and std.mem.eql(u8, entry.value_ptr.uid, uid)) {
                return entry.key_ptr.*;
            }
        }
        return null;
    }

    pub fn deleteContact(self: *Self, id: u64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.deleteContactLocked(id);
    }

    fn deleteContactLocked(self: *Self, id: u64) !void {
        if (self.contacts.get(id)) |contact| {
            const etag = contact.etag;
            const addressbook_id = contact.addressbook_id;
            if (self.config.enable_sync_tokens) try self.recordChange(addressbook_id, id, .contact, .deleted, etag, contact.uid);
            self.removeContactRelations(id);
            _ = self.contacts.remove(id);
            defer self.freeContact(contact);
            try self.updateAddressBookCtag(addressbook_id);
            self.dbExecId("DELETE FROM dav_contacts WHERE id = {d}", id);
            self.dbExecId("DELETE FROM dav_emails WHERE contact_id = {d}", id);
            self.dbExecId("DELETE FROM dav_phones WHERE contact_id = {d}", id);
        }
    }

    // -------------------------------------------------------------------------
    // Sync Token Operations
    // -------------------------------------------------------------------------

    pub fn getSyncToken(self: *Self, collection_id: u64, is_calendar: bool) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (is_calendar) {
            if (self.calendars.get(collection_id)) |cal| {
                return cal.sync_token;
            }
        } else {
            if (self.addressbooks.get(collection_id)) |ab| {
                return ab.sync_token;
            }
        }
        return 0;
    }

    pub fn getChangesSince(self: *Self, collection_id: u64, since_token: u64, is_calendar: bool) !SyncReport {
        self.mutex.lock();
        defer self.mutex.unlock();

        var changes: std.ArrayList(SyncChange) = .empty;
        errdefer changes.deinit(self.allocator);

        const expected_type: SyncChange.ResourceType = if (is_calendar) .event else .contact;

        for ([_][]const SyncChange{ self.sync_history.changes.items, self.canary_sync_history.changes.items }) |history| {
            for (history) |change| {
                if (change.resource_type == expected_type and
                    change.collection_id == collection_id and
                    change.token > since_token)
                {
                    try changes.append(self.allocator, change);
                }
            }
        }

        return SyncReport{
            .changes = try changes.toOwnedSlice(self.allocator),
            .new_sync_token = self.current_sync_token,
            .more_available = false,
        };
    }

    fn davSyncPrefix(self: *const Self, buf: []u8, kind: SyncChange.ResourceType, collection_id: u64) ![]const u8 {
        const epoch = std.fmt.bytesToHex(self.dav_sync_epoch, .lower);
        return std.fmt.bufPrint(buf, "urn:mail:dav-sync:{s}:{s}:{d}:", .{ epoch, @tagName(kind), collection_id });
    }

    /// Copy the visible collections for a Depth: 1 home-set response.
    pub fn snapshotDavCollections(self: *Self, arena: Allocator, user_id: u64, kind: SyncChange.ResourceType) ![]DavCollection {
        self.mutex.lock();
        defer self.mutex.unlock();
        return switch (kind) {
            .event => self.snapshotDavCollectionList(arena, user_id, kind, self.calendars.valueIterator()),
            .contact => self.snapshotDavCollectionList(arena, user_id, kind, self.addressbooks.valueIterator()),
        };
    }

    fn snapshotCollectionProperties(a: Allocator, collection: anytype) !DavCollectionProperties {
        return .{
            .name = try a.dupe(u8, collection.name),
            .display_name = try dupeOptional(a, collection.display_name),
            .description = try dupeOptional(a, collection.description),
            .color = if (@hasField(@TypeOf(collection), "color")) try dupeOptional(a, collection.color) else null,
        };
    }

    fn snapshotDavCollectionList(self: *const Self, arena: Allocator, user_id: u64, kind: SyncChange.ResourceType, iterator: anytype) ![]DavCollection {
        var entries = iterator;
        var result: std.ArrayList(DavCollection) = .empty;
        while (entries.next()) |collection| {
            if (collection.user_id != user_id) continue;
            var prefix_buf: [96]u8 = undefined;
            const prefix = try self.davSyncPrefix(&prefix_buf, kind, collection.id);
            const properties = try snapshotCollectionProperties(arena, collection.*);
            try result.append(arena, .{
                .name = properties.name,
                .ctag = try arena.dupe(u8, collection.ctag),
                .token = try std.fmt.allocPrint(arena, "{s}{d}", .{ prefix, collection.sync_token }),
                .properties = properties,
            });
        }
        return result.items;
    }

    const DavCollectionRef = union(SyncChange.ResourceType) {
        event: *Calendar,
        contact: *AddressBook,
    };

    fn findDavCollectionLocked(self: *Self, user_id: u64, name: []const u8, kind: SyncChange.ResourceType) !DavCollectionRef {
        return switch (kind) {
            .event => .{ .event = self.calendars.getPtr((self.getCalendarByName(user_id, name) orelse return error.NotFound).id).? },
            .contact => .{ .contact = self.addressbooks.getPtr((self.getAddressBookByName(user_id, name) orelse return error.NotFound).id).? },
        };
    }

    pub const DavPropfind = struct { properties: DavCollectionProperties, report: DavSyncReport };

    /// The metadata and member versions are copied from one locked view.
    pub fn snapshotDavPropfind(self: *Self, arena: Allocator, user_id: u64, name: []const u8, kind: SyncChange.ResourceType, query: DavSyncQuery) !DavPropfind {
        self.mutex.lock();
        defer self.mutex.unlock();
        const collection = try self.findDavCollectionLocked(user_id, name, kind);
        return .{
            .properties = switch (collection) {
                inline else => |item| try snapshotCollectionProperties(arena, item.*),
            },
            .report = try self.snapshotDavSyncLocked(arena, collection, query),
        };
    }

    pub fn snapshotDavSync(self: *Self, arena: Allocator, user_id: u64, name: []const u8, kind: SyncChange.ResourceType, query: DavSyncQuery) !DavSyncReport {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.snapshotDavSyncLocked(arena, try self.findDavCollectionLocked(user_id, name, kind), query);
    }

    fn snapshotDavSyncLocked(self: *Self, arena: Allocator, collection: DavCollectionRef, query: DavSyncQuery) !DavSyncReport {
        const kind = std.meta.activeTag(collection);
        const Version = struct { id: u64, revision: u64, floor: u64 };
        const version: Version = switch (collection) {
            inline else => |item| .{ .id = item.id, .revision = item.sync_token, .floor = item.dav_history_floor },
        };

        var prefix_buf: [96]u8 = undefined;
        const prefix = try self.davSyncPrefix(&prefix_buf, kind, version.id);
        var members: std.ArrayList(DavSyncMember) = .empty;
        switch (query) {
            .version_only => {},
            .initial => switch (kind) {
                .event => {
                    var events = self.events.valueIterator();
                    while (events.next()) |item| {
                        if (item.calendar_id == version.id) try members.append(arena, .{
                            .uid = try arena.dupe(u8, item.uid),
                            .etag = try arena.dupe(u8, item.etag),
                        });
                    }
                },
                .contact => {
                    var contacts = self.contacts.valueIterator();
                    while (contacts.next()) |item| {
                        if (item.addressbook_id == version.id) try members.append(arena, .{
                            .uid = try arena.dupe(u8, item.uid),
                            .etag = try arena.dupe(u8, item.etag),
                        });
                    }
                },
            },
            .after => |token| {
                if (!std.mem.startsWith(u8, token, prefix)) return error.InvalidSyncToken;
                const digits = token[prefix.len..];
                for (digits) |digit| if (!std.ascii.isDigit(digit)) return error.InvalidSyncToken;
                const since = std.fmt.parseInt(u64, digits, 10) catch return error.InvalidSyncToken;
                if (since < version.floor or since > version.revision) return error.InvalidSyncToken;

                // The newest change determines whether each URL is live or
                // removed, including after a delete and recreate at that URL.
                var seen: std.StringHashMapUnmanaged(void) = .empty;
                const history = self.syncHistory(kind, version.id).changes.items;
                var index = history.len;
                while (index > 0) {
                    index -= 1;
                    const change = history[index];
                    if (change.token <= since) break;
                    if (change.resource_type != kind or change.collection_id != version.id) continue;
                    if ((try seen.getOrPut(arena, change.uid)).found_existing) continue;
                    try members.append(arena, .{
                        .uid = try arena.dupe(u8, change.uid),
                        .etag = if (change.change_type == .deleted) null else try arena.dupe(u8, change.etag),
                    });
                }
                std.mem.reverse(DavSyncMember, members.items);
            },
        }
        return .{ .token = try std.fmt.allocPrint(arena, "{s}{d}", .{ prefix, version.revision }), .members = members.items };
    }

    /// Select by the persisted collection owner, including writes through a share.
    fn syncHistory(self: *Self, kind: SyncChange.ResourceType, collection_id: u64) *SyncHistory {
        if (self.sync_canary_user_id) |canary| {
            const owner: ?u64 = switch (kind) {
                .event => if (self.calendars.getPtr(collection_id)) |calendar| calendar.user_id else null,
                .contact => if (self.addressbooks.getPtr(collection_id)) |book| book.user_id else null,
            };
            if (owner == canary) return &self.canary_sync_history;
        }
        return &self.sync_history;
    }

    /// The journal owns independent copies, including the UID of deleted items.
    fn recordChange(
        self: *Self,
        collection_id: u64,
        resource_id: u64,
        resource_type: SyncChange.ResourceType,
        change_type: SyncChange.ChangeType,
        etag: []const u8,
        uid: []const u8,
    ) !void {
        self.publishChange(try self.prepareChange(collection_id, resource_id, resource_type, change_type, etag, uid));
    }

    fn prepareChange(
        self: *Self,
        collection_id: u64,
        resource_id: u64,
        resource_type: SyncChange.ResourceType,
        change_type: SyncChange.ChangeType,
        etag: []const u8,
        uid: []const u8,
    ) !SyncChange {
        const owned_uid = try self.allocator.dupe(u8, uid);
        errdefer self.allocator.free(owned_uid);
        const owned_etag = try self.allocator.dupe(u8, etag);
        errdefer self.allocator.free(owned_etag);
        const token = self.current_sync_token + 1;

        const history = self.syncHistory(resource_type, collection_id);
        try history.changes.ensureUnusedCapacity(self.allocator, 1);
        return .{
            .resource_id = resource_id,
            .collection_id = collection_id,
            .resource_type = resource_type,
            .change_type = change_type,
            .token = token,
            .etag = owned_etag,
            .uid = owned_uid,
            .timestamp = currentTimestamp(),
        };
    }

    fn freeChange(self: *Self, item: SyncChange) void {
        self.allocator.free(item.uid);
        self.allocator.free(item.etag);
    }

    fn publishChange(self: *Self, change: SyncChange) void {
        const history = self.syncHistory(change.resource_type, change.collection_id);
        history.changes.appendAssumeCapacity(change);
        self.current_sync_token = change.token;

        // Pruning only advances history floors from the selected journal.
        while (history.changes.items.len > history.limit) {
            const removed = history.changes.orderedRemove(0);
            self.freeChange(removed);
            switch (removed.resource_type) {
                .event => if (self.calendars.getPtr(removed.collection_id)) |cal| {
                    cal.dav_history_floor = removed.token;
                },
                .contact => if (self.addressbooks.getPtr(removed.collection_id)) |book| {
                    book.dav_history_floor = removed.token;
                },
            }
        }
    }

    fn updateAddressBookCtag(self: *Self, addressbook_id: u64) !void {
        if (self.addressbooks.getPtr(addressbook_id)) |ab| {
            const now = currentTimestamp();
            const old_ctag = ab.ctag;
            ab.ctag = try self.generateCtag(addressbook_id, now);
            self.allocator.free(old_ctag);
            ab.modified_at = now;
            ab.sync_token = self.current_sync_token;
            self.persistAddressBook(ab.*);
        }
    }

    // -------------------------------------------------------------------------
    // vCard Generation
    // -------------------------------------------------------------------------

    /// Generate a vCard 3.0 string from a Contact and its associated data
    pub fn generateVcf(self: *Self, contact: Contact) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.generateVcfLocked(self.contacts.get(contact.id) orelse return error.ContactNotFound);
    }

    fn generateVcfLocked(self: *Self, contact: Contact) ![]u8 {
        // If the contact already has raw vcf_data, return it
        if (contact.vcf_data.len > 0) {
            return try self.allocator.dupe(u8, contact.vcf_data);
        }

        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(self.allocator);

        try buf.appendSlice(self.allocator, "BEGIN:VCARD\r\n");
        try buf.appendSlice(self.allocator, "VERSION:3.0\r\n");

        // FN (required)
        try buf.appendSlice(self.allocator, "FN:");
        try buf.appendSlice(self.allocator, contact.full_name);
        try buf.appendSlice(self.allocator, "\r\n");

        // N
        {
            try buf.appendSlice(self.allocator, "N:");
            if (contact.family_name) |family| {
                try buf.appendSlice(self.allocator, family);
            }
            try buf.appendSlice(self.allocator, ";");
            if (contact.given_name) |given| {
                try buf.appendSlice(self.allocator, given);
            }
            try buf.appendSlice(self.allocator, ";;;\r\n");
        }

        // NICKNAME
        if (contact.nickname) |nickname| {
            try buf.appendSlice(self.allocator, "NICKNAME:");
            try buf.appendSlice(self.allocator, nickname);
            try buf.appendSlice(self.allocator, "\r\n");
        }

        // ORG
        if (contact.organization) |org| {
            try buf.appendSlice(self.allocator, "ORG:");
            try buf.appendSlice(self.allocator, org);
            try buf.appendSlice(self.allocator, "\r\n");
        }

        // TITLE
        if (contact.title) |t| {
            try buf.appendSlice(self.allocator, "TITLE:");
            try buf.appendSlice(self.allocator, t);
            try buf.appendSlice(self.allocator, "\r\n");
        }

        // NOTE
        if (contact.note) |n| try contact_vcard.appendText(self.allocator, &buf, "NOTE", n);

        // PHOTO
        if (contact.photo_url) |photo| {
            try buf.appendSlice(self.allocator, "PHOTO;VALUE=uri:");
            try buf.appendSlice(self.allocator, photo);
            try buf.appendSlice(self.allocator, "\r\n");
        }

        // Emails
        for (self.emails.items) |email| {
            if (email.contact_id != contact.id) continue;
            try buf.appendSlice(self.allocator, "EMAIL;TYPE=INTERNET");
            switch (email.email_type) {
                .home => try buf.appendSlice(self.allocator, ";TYPE=HOME"),
                .work => try buf.appendSlice(self.allocator, ";TYPE=WORK"),
                .other => {},
            }
            try buf.appendSlice(self.allocator, ":");
            try buf.appendSlice(self.allocator, email.email);
            try buf.appendSlice(self.allocator, "\r\n");
        }

        // Phones
        for (self.phones.items) |phone| {
            if (phone.contact_id != contact.id) continue;
            try buf.appendSlice(self.allocator, "TEL");
            switch (phone.phone_type) {
                .home => try buf.appendSlice(self.allocator, ";TYPE=HOME"),
                .work => try buf.appendSlice(self.allocator, ";TYPE=WORK"),
                .mobile => try buf.appendSlice(self.allocator, ";TYPE=CELL"),
                .fax => try buf.appendSlice(self.allocator, ";TYPE=FAX"),
                .other => {},
            }
            try buf.appendSlice(self.allocator, ":");
            try buf.appendSlice(self.allocator, phone.number);
            try buf.appendSlice(self.allocator, "\r\n");
        }

        // UID
        try buf.appendSlice(self.allocator, "UID:");
        try buf.appendSlice(self.allocator, contact.uid);
        try buf.appendSlice(self.allocator, "\r\n");

        try buf.appendSlice(self.allocator, "END:VCARD\r\n");

        return buf.toOwnedSlice(self.allocator);
    }

    // -------------------------------------------------------------------------
    // Helper Functions
    // -------------------------------------------------------------------------

    fn generateEtag(self: *Self, id: u64) ![]const u8 {
        var revision: [16]u8 = undefined;
        io_compat.randomBytes(&revision);
        return std.fmt.allocPrint(self.allocator, "\"{x}-{s}\"", .{ id, std.fmt.bytesToHex(revision, .lower) });
    }

    fn generateCtag(self: *Self, id: u64, timestamp: i64) ![]const u8 {
        return try std.fmt.allocPrint(self.allocator, "ctag-{d}-{d}", .{ id, timestamp });
    }

    fn generateUid(self: *Self) ![]const u8 {
        const timestamp = currentTimestamp();
        // Use timestamp + counters as seed for unique UID generation
        const counter = self.next_event_id +% self.next_contact_id;
        const seed = @as(u64, @bitCast(timestamp)) *% 6364136223846793005 +% counter;
        return try std.fmt.allocPrint(self.allocator, "{x}-{x}@localhost", .{ timestamp, seed });
    }
};

// =============================================================================
// ICS Parser (iCalendar)
// =============================================================================

pub const IcsParser = struct {
    pub fn parseEvent(ics_data: []const u8) ?ParsedEvent {
        var event = ParsedEvent{};

        // Parse physical lines directly: the returned slices point into
        // `ics_data` (the caller's request body), which must outlive the
        // result. (A buffered unfold would point into a local buffer that
        // dies on return — a use-after-free; folding is rare on the
        // properties we extract, which are single-line in practice.)
        var lines = std.mem.splitScalar(u8, ics_data, '\n');
        while (lines.next()) |raw_line| {
            const line = std.mem.trimEnd(u8, raw_line, "\r");
            if (std.mem.startsWith(u8, line, "SUMMARY:")) {
                event.summary = line[8..];
            } else if (std.mem.startsWith(u8, line, "DESCRIPTION:")) {
                event.description = line[12..];
            } else if (std.mem.startsWith(u8, line, "LOCATION:")) {
                event.location = line[9..];
            } else if (std.mem.startsWith(u8, line, "DTSTART")) {
                event.dtstart = parseDtValue(line);
                // A date-only DTSTART (VALUE=DATE / 8-digit value) is an
                // all-day event.
                if (std.mem.indexOf(u8, line, "VALUE=DATE") != null) event.all_day = true;
            } else if (std.mem.startsWith(u8, line, "DTEND")) {
                event.dtend = parseDtValue(line);
            } else if (std.mem.startsWith(u8, line, "UID:")) {
                event.uid = line[4..];
            } else if (std.mem.startsWith(u8, line, "RRULE:")) {
                event.rrule = line[6..];
            } else if (std.mem.startsWith(u8, line, "ORGANIZER")) {
                // ORGANIZER[;CN=Name]:mailto:addr — keep the address, drop the
                // "mailto:" scheme.
                if (std.mem.indexOfScalar(u8, line, ':')) |idx| {
                    var v = line[idx + 1 ..];
                    if (std.ascii.startsWithIgnoreCase(v, "mailto:")) v = v[7..];
                    event.organizer = v;
                }
            }
        }

        if (event.summary == null) return null;
        return event;
    }

    fn parseDtValue(line: []const u8) ?i64 {
        // Find the value after : or ;VALUE=DATE:
        if (std.mem.indexOf(u8, line, ":")) |idx| {
            const value = std.mem.trimEnd(u8, line[idx + 1 ..], "\r");
            if (value.len >= 8) {
                return parseIcalDate(value);
            }
        }
        return null;
    }

    /// Parse iCalendar date/time: YYYYMMDD or YYYYMMDDTHHMMSS[Z]
    fn parseIcalDate(value: []const u8) ?i64 {
        if (value.len < 8) return null;
        const year = std.fmt.parseInt(i64, value[0..4], 10) catch return null;
        const month = std.fmt.parseInt(i64, value[4..6], 10) catch return null;
        const day = std.fmt.parseInt(i64, value[6..8], 10) catch return null;

        // Days from epoch using a simplified calculation
        // (accurate enough for calendar sync; not accounting for leap seconds)
        const days = epochDays(year, month, day);

        if (value.len >= 15 and value[8] == 'T') {
            const hour = std.fmt.parseInt(i64, value[9..11], 10) catch return 0;
            const minute = std.fmt.parseInt(i64, value[11..13], 10) catch return 0;
            const second = std.fmt.parseInt(i64, value[13..15], 10) catch return 0;
            return days * 86400 + hour * 3600 + minute * 60 + second;
        }
        return days * 86400;
    }

    pub fn epochDays(year: i64, month: i64, day: i64) i64 {
        // Compute days since Unix epoch (1970-01-01) using a standard algorithm
        var y = year;
        var m = month;
        if (m <= 2) {
            y -= 1;
            m += 12;
        }
        const era_days = 365 * y + @divFloor(y, 4) - @divFloor(y, 100) + @divFloor(y, 400);
        const month_days = @divFloor((153 * (m - 3) + 2), 5) + day - 1;
        // Epoch offset: days from year 0 to 1970-01-01 = 719468
        return era_days + month_days - 719468;
    }

    pub const ParsedEvent = struct {
        uid: ?[]const u8 = null,
        summary: ?[]const u8 = null,
        description: ?[]const u8 = null,
        location: ?[]const u8 = null,
        dtstart: ?i64 = null,
        dtend: ?i64 = null,
        all_day: bool = false,
        rrule: ?[]const u8 = null,
        organizer: ?[]const u8 = null,
    };
};

// =============================================================================
// VCF Parser (vCard)
// =============================================================================

/// Populate the structured store from the same wire card for webmail and
/// CardDAV clients. The original card remains the source for DAV downloads.
pub fn contactDataFromVcf(a: Allocator, resource_uid: []const u8, raw: []const u8) !CalDavStore.ContactData {
    const parsed = VcfParser.parseContact(try contact_vcard.unfold(a, raw)) orelse
        return .{ .uid = resource_uid, .vcf_data = raw, .full_name = "Unknown" };
    const emails = try a.alloc(CalDavStore.EmailData, parsed.email_count);
    const phones = try a.alloc(CalDavStore.PhoneData, parsed.phone_count);
    const email_preferred = std.mem.indexOfScalar(bool, parsed.email_pref[0..parsed.email_count], true) != null;
    const phone_preferred = std.mem.indexOfScalar(bool, parsed.phone_pref[0..parsed.phone_count], true) != null;
    for (emails, 0..) |*item, i| item.* = .{
        .email = try contact_vcard.decode(a, parsed.emails[i]),
        .email_type = parsed.email_types[i],
        .is_primary = if (email_preferred) parsed.email_pref[i] else i == 0,
    };
    for (phones, 0..) |*item, i| item.* = .{
        .number = try contact_vcard.decode(a, parsed.phones[i]),
        .phone_type = parsed.phone_types[i],
        .is_primary = if (phone_preferred) parsed.phone_pref[i] else i == 0,
    };
    return .{
        .uid = resource_uid,
        .full_name = try contact_vcard.decode(a, parsed.full_name orelse "Unknown"),
        .given_name = if (parsed.given_name) |value| try contact_vcard.decode(a, value) else null,
        .family_name = if (parsed.family_name) |value| try contact_vcard.decode(a, value) else null,
        .nickname = if (parsed.nickname) |value| try contact_vcard.decode(a, value) else null,
        .organization = if (parsed.organization) |value| try contact_vcard.decode(a, value) else null,
        .title = if (parsed.title) |value| try contact_vcard.decode(a, value) else null,
        .note = if (parsed.note) |value| try contact_vcard.decode(a, value) else null,
        .vcf_data = raw,
        .emails = emails,
        .phones = phones,
    };
}

pub const VcfParser = struct {
    const MAX_MULTI_VALUES = 8;

    pub fn parseContact(vcf_data: []const u8) ?ParsedContact {
        var contact = ParsedContact{};

        // Parse physical lines directly: returned slices point into
        // `vcf_data` (the caller's request body), which must outlive the
        // result — buffering an unfold into a local would dangle on return.
        var lines = std.mem.splitScalar(u8, vcf_data, '\n');
        while (lines.next()) |raw_logical| {
            const line = std.mem.trimEnd(u8, raw_logical, "\r");
            // Split a content line into its property part (NAME;params) and
            // value (everything after the first unquoted colon).
            const field = contact_vcard.property(line) orelse continue;
            const value = field.value;
            const name = field.name;
            const prop = line[0 .. line.len - value.len - 1];
            const params = if (std.mem.indexOfScalar(u8, prop, ';')) |semi| prop[semi + 1 ..] else "";

            if (std.ascii.eqlIgnoreCase(name, "FN")) {
                contact.full_name = value;
            } else if (std.ascii.eqlIgnoreCase(name, "N")) {
                var parts = std.mem.splitScalar(u8, value, ';');
                contact.family_name = parts.next();
                contact.given_name = parts.next();
            } else if (std.ascii.eqlIgnoreCase(name, "EMAIL")) {
                if (contact.email_count < MAX_MULTI_VALUES) {
                    contact.emails[contact.email_count] = value;
                    contact.email_types[contact.email_count] = emailTypeFromParams(params);
                    contact.email_pref[contact.email_count] = paramHasPref(params);
                    contact.email_count += 1;
                }
            } else if (std.ascii.eqlIgnoreCase(name, "TEL")) {
                if (contact.phone_count < MAX_MULTI_VALUES) {
                    contact.phones[contact.phone_count] = value;
                    contact.phone_types[contact.phone_count] = phoneTypeFromParams(params);
                    contact.phone_pref[contact.phone_count] = paramHasPref(params);
                    contact.phone_count += 1;
                }
            } else if (std.ascii.eqlIgnoreCase(name, "ORG")) {
                // ORG is structured (Company;Department;...); take the company.
                contact.organization = if (std.mem.indexOfScalar(u8, value, ';')) |s| value[0..s] else value;
            } else if (std.ascii.eqlIgnoreCase(name, "TITLE")) {
                contact.title = value;
            } else if (std.ascii.eqlIgnoreCase(name, "NICKNAME")) {
                contact.nickname = value;
            } else if (std.ascii.eqlIgnoreCase(name, "NOTE")) {
                contact.note = value;
            } else if (std.ascii.eqlIgnoreCase(name, "UID")) {
                contact.uid = value;
            }
        }

        if (contact.full_name == null) {
            // Fall back to the structured name when FN is absent.
            if (contact.given_name) |g| contact.full_name = g else return null;
        }
        return contact;
    }

    /// True if the parameter list marks this value preferred (TYPE=pref or
    /// PREF=1 / a bare PREF). RFC 6350 (PREF=1..100) and vCard 3.0 (TYPE=pref).
    fn paramHasPref(params: []const u8) bool {
        var it = std.mem.splitScalar(u8, params, ';');
        while (it.next()) |p| {
            if (std.ascii.eqlIgnoreCase(p, "PREF")) return true;
            if (std.ascii.startsWithIgnoreCase(p, "PREF=")) return true;
            // TYPE=pref (possibly comma-joined with other types)
            if (std.ascii.startsWithIgnoreCase(p, "TYPE=")) {
                if (paramTokenContains(p[5..], "pref")) return true;
            }
        }
        return false;
    }

    /// Case-insensitive membership of `needle` in a comma/semicolon TYPE list,
    /// tolerating quotes: TYPE="WORK,VOICE" or TYPE=work;TYPE=voice.
    fn paramTokenContains(list: []const u8, needle: []const u8) bool {
        const trimmed = std.mem.trim(u8, list, "\"");
        var it = std.mem.splitAny(u8, trimmed, ",");
        while (it.next()) |tok| {
            if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, tok, " \""), needle)) return true;
        }
        return false;
    }

    fn emailTypeFromParams(params: []const u8) EmailAddress.EmailType {
        var it = std.mem.splitScalar(u8, params, ';');
        while (it.next()) |p| {
            if (!std.ascii.startsWithIgnoreCase(p, "TYPE=")) continue;
            const v = p[5..];
            if (paramTokenContains(v, "work")) return .work;
            if (paramTokenContains(v, "home")) return .home;
        }
        return .other;
    }

    fn phoneTypeFromParams(params: []const u8) PhoneNumber.PhoneType {
        var it = std.mem.splitScalar(u8, params, ';');
        while (it.next()) |p| {
            if (!std.ascii.startsWithIgnoreCase(p, "TYPE=")) continue;
            const v = p[5..];
            // Mobile aliases: cell (3.0), CELL/text, "cell"
            if (paramTokenContains(v, "cell") or paramTokenContains(v, "mobile")) return .mobile;
            if (paramTokenContains(v, "fax")) return .fax;
            if (paramTokenContains(v, "work")) return .work;
            if (paramTokenContains(v, "home")) return .home;
        }
        return .other;
    }

    pub const ParsedContact = struct {
        uid: ?[]const u8 = null,
        full_name: ?[]const u8 = null,
        given_name: ?[]const u8 = null,
        family_name: ?[]const u8 = null,
        nickname: ?[]const u8 = null,
        title: ?[]const u8 = null,
        note: ?[]const u8 = null,
        emails: [MAX_MULTI_VALUES][]const u8 = @splat(""),
        email_types: [MAX_MULTI_VALUES]EmailAddress.EmailType = @splat(.other),
        email_pref: [MAX_MULTI_VALUES]bool = @splat(false),
        email_count: usize = 0,
        phones: [MAX_MULTI_VALUES][]const u8 = @splat(""),
        phone_types: [MAX_MULTI_VALUES]PhoneNumber.PhoneType = @splat(.other),
        phone_pref: [MAX_MULTI_VALUES]bool = @splat(false),
        phone_count: usize = 0,
        organization: ?[]const u8 = null,

        /// Get first email (convenience, backward compat)
        pub fn email(self: ParsedContact) ?[]const u8 {
            if (self.email_count > 0) return self.emails[0];
            return null;
        }

        /// Get first phone (convenience, backward compat)
        pub fn phone(self: ParsedContact) ?[]const u8 {
            if (self.phone_count > 0) return self.phones[0];
            return null;
        }
    };
};

// =============================================================================
// Tests
// =============================================================================

test "calendar operations" {
    const allocator = std.testing.allocator;

    var store = try CalDavStore.init(allocator, .{});
    defer store.deinit();

    // Create calendar
    const cal_id = try store.createCalendar(1, "Test Calendar", null);
    try std.testing.expect(cal_id > 0);

    // Get calendar
    const cal = store.getCalendar(cal_id);
    try std.testing.expect(cal != null);
    try std.testing.expectEqualStrings("Test Calendar", cal.?.name);
}

test "calendar snapshots filter by authenticated account and half-open window" {
    const allocator = std.testing.allocator;
    var store = try CalDavStore.init(allocator, .{});
    defer store.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const request = arena.allocator();

    const owner = "owner@example.test";
    const guest = "guest@example.test";
    const personal = try store.createCalendar(try store.getOrCreateUserId(owner), "Personal", "My own dates");
    const another = try store.createCalendar(try store.getOrCreateUserId(guest), "Private", null);
    _ = try store.createEvent(another, .{ .summary = "Guest event", .dtstart = 100 });
    _ = try store.createEvent(personal, .{ .summary = "Before the window", .dtstart = 50, .dtend = 100 });
    _ = try store.createEvent(personal, .{ .summary = "Overlapping event", .dtstart = 90, .dtend = 110 });
    _ = try store.createEvent(personal, .{ .summary = "Recurring meeting", .dtstart = 60, .dtend = 70, .rrule = "FREQ=DAILY" });
    _ = try store.createEvent(personal, .{ .summary = "On the start", .dtstart = 100 });
    _ = try store.createEvent(personal, .{ .summary = "On the end", .dtstart = 200 });

    const calendars = try store.snapshotCalendars(request, owner);
    try std.testing.expectEqual(@as(usize, 1), calendars.len);
    try std.testing.expectEqual(personal, calendars[0].id);
    try std.testing.expectEqual(@as(usize, 0), (try store.snapshotCalendars(request, "unknown@example.test")).len);
    try std.testing.expectError(error.CalendarNotFound, store.snapshotCalendarEvents(request, owner, another, 100, 200));
    try std.testing.expectError(error.InvalidRange, store.snapshotCalendarEvents(request, owner, personal, 100, 100));
    try std.testing.expectError(error.InvalidRange, store.snapshotCalendarEvents(request, owner, personal, 0, 367 * 86400));

    const events = try store.snapshotCalendarEvents(request, owner, personal, 100, 200);
    try std.testing.expectEqual(@as(usize, 3), events.len);
    try std.testing.expectEqualStrings("Recurring meeting", events[0].summary);
    try std.testing.expectEqualStrings("Overlapping event", events[1].summary);
    try std.testing.expectEqualStrings("On the start", events[2].summary);
    try std.testing.expectEqualStrings("FREQ=DAILY", events[0].recurrence_rule.?);

    try store.deleteCalendar(personal);
    try std.testing.expectEqualStrings("Personal", calendars[0].name);
    try std.testing.expect(events[0].uid.len > 0);
    try std.testing.expect(events[0].etag.len > 0);
}

test "persistent DAV ownership follows mailbox IDs without claiming unassigned collections" {
    const allocator = std.testing.allocator;
    var mailbox_db = try accounts.Database.init(allocator, ":memory:");
    defer mailbox_db.deinit();
    _ = try mailbox_db.createUser("owner@old.test", "unused", "owner@old.test");
    _ = try mailbox_db.createUser("guest@other.test", "unused", "guest@other.test");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const directory_len = try tmp.dir.realPath(std.testing.io, &path_buffer);
    const path = try std.fs.path.join(allocator, &.{ path_buffer[0..directory_len], "dav.db" });
    defer allocator.free(path);
    const config: StoreConfig = .{ .db_path = path, .account_db = &mailbox_db };
    const owner_id = blk: {
        var store = try CalDavStore.init(allocator, config);
        defer store.deinit();
        const id = try store.getOrCreateUserId("owner@old.test");
        var name = "Personal".*;
        const calendar = try store.createCalendar(id, &name, null);
        @memset(&name, 'x');
        try std.testing.expectEqualStrings("Personal", store.getCalendar(calendar).?.name);
        _ = try store.createCalendar(42, "Unassigned legacy data", null);
        break :blk id;
    };

    var store = try CalDavStore.init(allocator, config);
    defer store.deinit();
    try std.testing.expect((try store.getOrCreateUserId("guest@other.test")) > 42);
    try std.testing.expectEqual(owner_id, try store.getOrCreateUserId("owner@old.test"));
    _ = try mailbox_db.renameDomain("old.test", "new.test");
    try std.testing.expectEqual(owner_id, try store.getOrCreateUserId("owner@new.test"));

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const request = arena.allocator();
    try std.testing.expectEqualStrings("Personal", (try store.snapshotCalendars(request, "owner@new.test"))[0].name);
    try std.testing.expectEqual(@as(usize, 0), (try store.snapshotCalendars(request, "guest@other.test")).len);
    try mailbox_db.deleteUser("owner@new.test");
    _ = try mailbox_db.createUser("owner@new.test", "unused", "owner@new.test");
    try std.testing.expect((try store.getOrCreateUserId("owner@new.test")) != owner_id);
    try std.testing.expectEqual(@as(usize, 0), (try store.snapshotCalendars(request, "owner@new.test")).len);
}

test "event operations" {
    const allocator = std.testing.allocator;

    var store = try CalDavStore.init(allocator, .{});
    defer store.deinit();

    const cal_id = try store.createCalendar(1, "Test Calendar", null);

    // Create event
    const event_id = try store.createEvent(cal_id, .{
        .summary = "Test Meeting",
        .dtstart = currentTimestamp(),
    });

    try std.testing.expect(event_id > 0);

    // Get event
    const event = store.getEvent(event_id);
    try std.testing.expect(event != null);
    try std.testing.expectEqualStrings("Test Meeting", event.?.summary);
}

test "contact operations" {
    const allocator = std.testing.allocator;

    var store = try CalDavStore.init(allocator, .{});
    defer store.deinit();

    const ab_id = try store.createAddressBook(1, "Personal", null);

    // Create contact
    const contact_id = try store.createContact(ab_id, .{
        .full_name = "John Doe",
        .given_name = "John",
        .family_name = "Doe",
    });

    try std.testing.expect(contact_id > 0);

    // Get contact
    const contact = store.getContact(contact_id);
    try std.testing.expect(contact != null);
    try std.testing.expectEqualStrings("John Doe", contact.?.full_name);
}

test "contact suggestions isolate full-address owners and remain valid after deletion" {
    const allocator = std.testing.allocator;
    var store = try CalDavStore.init(allocator, .{});
    defer store.deinit();
    const one = try store.getOrCreateUserId("person@one.test");
    const two = try store.getOrCreateUserId("person@two.test");
    const book_one = try store.createAddressBook(one, "Personal", null);
    const book_two = try store.createAddressBook(two, "Personal", null);
    const contact = try store.createContact(book_one, .{ .full_name = "Jane Doe", .emails = &.{.{ .email = "jane@one.test" }} });
    _ = try store.createContact(book_two, .{ .full_name = "Jane Other", .emails = &.{.{ .email = "jane@two.test" }} });
    const result = try store.suggestContacts(allocator, "person@one.test", "JANE", 10);
    defer {
        for (result) |item| {
            allocator.free(item.name);
            allocator.free(item.address);
        }
        allocator.free(result);
    }
    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqualStrings("jane@one.test", result[0].address);
    try store.deleteContact(contact);
    try std.testing.expectEqualStrings("Jane Doe", result[0].name);
    try std.testing.expectEqual(@as(usize, 0), (try store.suggestContacts(allocator, "person", "Jane", 10)).len);
}

test "ics parsing" {
    const ics =
        \\BEGIN:VCALENDAR
        \\VERSION:2.0
        \\BEGIN:VEVENT
        \\UID:test-event-001
        \\SUMMARY:Team Meeting
        \\DESCRIPTION:Weekly sync
        \\LOCATION:Conference Room
        \\DTSTART:20240101T100000Z
        \\DTEND:20240101T110000Z
        \\END:VEVENT
        \\END:VCALENDAR
    ;

    const event = IcsParser.parseEvent(ics);
    try std.testing.expect(event != null);
    try std.testing.expectEqualStrings("Team Meeting", event.?.summary.?);
}

test "ics parsing: all-day, real times, organizer" {
    const ics =
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\n" ++
        "UID:e1\r\n" ++
        "SUMMARY:Offsite\r\n" ++
        "DESCRIPTION:Long agenda\r\n" ++
        "ORGANIZER;CN=Ada:mailto:ada@example.com\r\n" ++
        "DTSTART;VALUE=DATE:20260615\r\n" ++
        "END:VEVENT\r\nEND:VCALENDAR\r\n";
    const e = IcsParser.parseEvent(ics).?;
    try std.testing.expectEqualStrings("Long agenda", e.description.?);
    try std.testing.expect(e.all_day);
    try std.testing.expect(e.dtstart != null); // 2026-06-15 parsed, not "now"
    try std.testing.expectEqualStrings("ada@example.com", e.organizer.?); // mailto: stripped
}

test "vcf parsing" {
    const vcf =
        \\BEGIN:VCARD
        \\VERSION:3.0
        \\FN:Jane Smith
        \\N:Smith;Jane;;;
        \\EMAIL:jane@example.com
        \\TEL:+1-555-1234
        \\ORG:Acme Corp
        \\UID:contact-001
        \\END:VCARD
    ;

    const contact = VcfParser.parseContact(vcf);
    try std.testing.expect(contact != null);
    try std.testing.expectEqualStrings("Jane Smith", contact.?.full_name.?);
}

test "vcf parsing: typed emails/phones, pref, structured ORG" {
    const vcf =
        "BEGIN:VCARD\r\n" ++
        "VERSION:3.0\r\n" ++
        "FN:Grace Hopper\r\n" ++
        "N:Hopper;Grace;;;\r\n" ++
        "ORG:US Navy;Research\r\n" ++
        "TITLE:Rear Admiral\r\n" ++
        "NICKNAME:Amazing Grace\r\n" ++
        "EMAIL;TYPE=WORK,PREF:grace@navy.mil\r\n" ++
        "EMAIL;TYPE=home:grace@example.com\r\n" ++
        "TEL;TYPE=CELL:+15551112222\r\n" ++
        "TEL;TYPE=work,voice:+15553334444\r\n" ++
        "TEL;TYPE=fax:+15555556666\r\n" ++
        "UID:grace-1\r\n" ++
        "END:VCARD\r\n";

    const c = VcfParser.parseContact(vcf).?;
    try std.testing.expectEqualStrings("Grace Hopper", c.full_name.?);
    try std.testing.expectEqualStrings("Grace", c.given_name.?);
    try std.testing.expectEqualStrings("US Navy", c.organization.?); // company only
    try std.testing.expectEqualStrings("Rear Admiral", c.title.?);
    try std.testing.expectEqualStrings("Amazing Grace", c.nickname.?);

    try std.testing.expectEqual(@as(usize, 2), c.email_count);
    try std.testing.expectEqual(PhoneNumber.PhoneType.mobile, c.phone_types[0]);
    try std.testing.expectEqual(PhoneNumber.PhoneType.work, c.phone_types[1]);
    try std.testing.expectEqual(PhoneNumber.PhoneType.fax, c.phone_types[2]);
    try std.testing.expectEqual(EmailAddress.EmailType.work, c.email_types[0]);
    try std.testing.expectEqual(EmailAddress.EmailType.home, c.email_types[1]);
    try std.testing.expect(c.email_pref[0]); // TYPE=...,PREF
    try std.testing.expectEqualStrings("grace@example.com", c.emails[1]);
}

test "calendar import can retry a failed SQLite write without an in-memory or sync record" {
    var store = try CalDavStore.init(std.testing.allocator, .{ .db_path = ":memory:" });
    defer store.deinit();
    const account = "owner@example.test";
    const owner = try store.getOrCreateUserId(account);
    const calendar = try store.createCalendar(owner, "Personal", null);
    const token = store.getSyncToken(calendar, true);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const items = [_]?CalDavStore.ImportEvent{.{
        .uid = "retry@example.test",
        .data = .{ .uid = "retry-resource", .summary = "Test", .dtstart = 1 },
    }};
    try store.conn.?.exec("CREATE TRIGGER reject_fixture BEFORE INSERT ON dav_events BEGIN SELECT RAISE(ABORT, 'fixture failure'); END");
    const rejected = try store.importEvents(a, account, .{ .existing = calendar }, &items, false);
    try std.testing.expectEqual(CalDavStore.ImportStatus.failed, rejected.statuses[0]);
    try std.testing.expectEqual(token, store.getSyncToken(calendar, true));
    try std.testing.expectEqual(@as(usize, 0), store.events.count());

    try store.conn.?.exec("DROP TRIGGER reject_fixture");
    const accepted = try store.importEvents(a, account, .{ .existing = calendar }, &items, false);
    try std.testing.expectEqual(CalDavStore.ImportStatus.imported, accepted.statuses[0]);
    try std.testing.expectEqual(@as(usize, 1), store.events.count());
}

test "event edit and delete roll back together with the calendar revision" {
    var store = try CalDavStore.init(std.testing.allocator, .{ .db_path = ":memory:" });
    defer store.deinit();
    const account = "owner@example.test";
    const calendar = try store.createMailboxCalendar(account, "Personal");
    const event = try store.createWebCalendarEvent(account, calendar, .{ .summary = "Before", .dtstart = 100 });
    const old_tag = event.revision.etag();
    const token = store.getSyncToken(calendar, true);
    try store.conn.?.exec("CREATE TRIGGER reject_revision BEFORE INSERT ON dav_calendars BEGIN SELECT RAISE(ABORT, 'fixture failure'); END");
    try std.testing.expectError(error.StepFailed, store.updateWebCalendarEvent(account, event.id, old_tag, .{ .summary = "After", .dtstart = 200 }));
    try std.testing.expectError(error.StepFailed, store.deleteWebCalendarEvent(account, event.id, old_tag));

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const snapshot = try store.snapshotMailboxEvent(arena.allocator(), account, event.id);
    try std.testing.expectEqualStrings("Before", snapshot.event.summary);
    try std.testing.expectEqualStrings(old_tag, snapshot.event.etag);
    try std.testing.expectEqual(token, store.getSyncToken(calendar, true));
    {
        var stmt = try store.conn.?.prepare("SELECT summary, etag FROM dav_events");
        defer stmt.finalize();
        try std.testing.expect(try stmt.step());
        try std.testing.expectEqualStrings("Before", try stmt.columnText(0));
        try std.testing.expectEqualStrings(old_tag, try stmt.columnText(1));
        try std.testing.expect(!try stmt.step());
    }
    try store.conn.?.exec("DROP TRIGGER reject_revision");
    const revision = try store.updateWebCalendarEvent(account, event.id, old_tag, .{ .summary = "After", .dtstart = 200 });
    try std.testing.expectError(error.PreconditionFailed, store.deleteWebCalendarEvent(account, event.id, old_tag));
    try store.deleteWebCalendarEvent(account, event.id, revision.etag());
    try std.testing.expectError(error.EventNotFound, store.snapshotMailboxEvent(arena.allocator(), account, event.id));
}

test "calendar export renders legacy events and rejects another mailbox's calendar" {
    var store = try CalDavStore.init(std.testing.allocator, .{});
    defer store.deinit();
    const owner = "owner@example.test";
    const user_id = try store.getOrCreateUserId(owner);
    const calendar_id = try store.createCalendar(user_id, "Work, home", null);
    _ = try store.createEvent(calendar_id, .{
        .uid = "legacy@example.test",
        .summary = "Planning; design",
        .dtstart = -86400,
        .dtend = 0,
        .all_day = true,
        .description = "First line\r\nSecond line",
        .rrule = "FREQ=YEARLY",
    });
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectError(error.CalendarNotFound, store.exportCalendar(a, "other@example.test", calendar_id));
    const ics = try store.exportCalendar(a, owner, calendar_id);
    const items = try icalendar.components(a, ics);
    try std.testing.expectEqual(@as(usize, 1), items.len);
    try std.testing.expect(std.mem.indexOf(u8, ics, "X-WR-CALNAME:Work\\, home\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, ics, "DTSTART;VALUE=DATE:19691231\r\nDTEND;VALUE=DATE:19700101\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, ics, "SUMMARY:Planning\\; design\r\nDESCRIPTION:First line\\nSecond line\r\n") != null);
}

test "DAV record UID ownership survives caller mutation and collection deletion" {
    const a = std.testing.allocator;
    var store = try CalDavStore.init(a, .{});
    defer store.deinit();
    const calendar = try store.createCalendar(1, "Calendar", null);
    const book = try store.createAddressBook(1, "Contacts", null);
    var event_uid = "event-uid".*;
    var contact_uid = "contact-uid".*;
    const event = try store.createEvent(calendar, .{ .uid = &event_uid, .summary = "Meeting", .dtstart = 1 });
    const contact = try store.createContact(book, .{ .uid = &contact_uid, .full_name = "Contact" });
    @memset(&event_uid, 'x');
    @memset(&contact_uid, 'x');
    try std.testing.expectEqualStrings("event-uid", store.getEvent(event).?.uid);
    try std.testing.expectEqualStrings("contact-uid", store.getContact(contact).?.uid);
    try store.deleteEvent(event);
    try store.deleteContact(contact);
    _ = try store.createEvent(calendar, .{ .summary = "Generated UID", .dtstart = 1 });
    _ = try store.createContact(book, .{ .full_name = "Generated UID" });
    try store.deleteCalendar(calendar);
    try store.deleteAddressBook(book);
    try std.testing.expectEqual(@as(u32, 0), store.events.count());
    try std.testing.expectEqual(@as(u32, 0), store.contacts.count());
}

test "DAV allocation failure before deletion retains valid record ownership" {
    const a = std.testing.allocator;
    var failing = std.testing.FailingAllocator.init(a, .{});
    var store = try CalDavStore.init(failing.allocator(), .{});
    defer store.deinit();
    const calendar = try store.createCalendar(1, "Calendar", null);
    const book = try store.createAddressBook(1, "Contacts", null);
    const event = try store.createEvent(calendar, .{ .summary = "Meeting", .dtstart = 1 });
    const contact = try store.createContact(book, .{ .full_name = "Contact" });
    const event_etag = try a.dupe(u8, store.getEvent(event).?.etag);
    defer a.free(event_etag);
    const contact_etag = try a.dupe(u8, store.getContact(contact).?.etag);
    defer a.free(contact_etag);
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, store.deleteEvent(event));
    try std.testing.expectError(error.OutOfMemory, store.deleteContact(contact));
    try std.testing.expectEqualStrings(event_etag, store.getEvent(event).?.etag);
    try std.testing.expectEqualStrings(contact_etag, store.getContact(contact).?.etag);
}
