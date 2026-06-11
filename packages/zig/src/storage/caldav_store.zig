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
const Allocator = std.mem.Allocator;
const mutex_compat = @import("../core/mutex_compat.zig");
const database = @import("db_sqlite.zig");

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
};

// =============================================================================
// Data Types
// =============================================================================

pub const Calendar = struct {
    id: u64,
    user_id: u64,
    name: []const u8,
    description: ?[]const u8,
    color: ?[]const u8,
    timezone: []const u8,
    created_at: i64,
    modified_at: i64,
    sync_token: u64,
    ctag: []const u8, // Collection tag
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
    organizer: ?[]const u8,
    status: EventStatus,
    created_at: i64,
    modified_at: i64,
    etag: []const u8,
    ics_data: []const u8, // Raw ICS data

    pub const EventStatus = enum {
        tentative,
        confirmed,
        cancelled,
    };
};

pub const AddressBook = struct {
    id: u64,
    user_id: u64,
    name: []const u8,
    description: ?[]const u8,
    created_at: i64,
    modified_at: i64,
    sync_token: u64,
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
    href: []const u8,
    timestamp: i64,

    pub const ResourceType = enum { event, contact };
    pub const ChangeType = enum { created, modified, deleted };
};

pub const SyncReport = struct {
    changes: []SyncChange,
    new_sync_token: u64,
    more_available: bool,
};

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

    // Sync history
    sync_changes: std.ArrayList(SyncChange),
    current_sync_token: u64,

    // ID generators
    next_calendar_id: u64,
    next_event_id: u64,
    next_addressbook_id: u64,
    next_contact_id: u64,

    pub const UserEntry = struct {
        username: []const u8,
        user_id: u64,
    };

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
            .sync_changes = .empty,
            .current_sync_token = 1,
            .next_calendar_id = 1,
            .next_event_id = 1,
            .next_addressbook_id = 1,
            .next_contact_id = 1,
        };

        // Optional SQLite persistence: open the file, ensure schema, and hydrate
        // the in-memory maps from disk. Failures degrade to in-memory rather than
        // taking the whole server down.
        if (config.db_path) |path| {
            self.conn = database.Connection.open(allocator, path) catch null;
            if (self.conn) |*conn| {
                ensureSchema(conn) catch {};
                self.loadFromDb() catch {};
            }
        }

        return self;
    }

    pub fn deinit(self: *Self) void {
        if (self.conn) |*conn| conn.close();
        // Free dynamically allocated ctag/etag strings
        var cal_iter = self.calendars.iterator();
        while (cal_iter.next()) |entry| {
            self.allocator.free(entry.value_ptr.ctag);
        }
        var event_iter = self.events.iterator();
        while (event_iter.next()) |entry| {
            self.allocator.free(entry.value_ptr.etag);
        }
        var ab_iter = self.addressbooks.iterator();
        while (ab_iter.next()) |entry| {
            self.allocator.free(entry.value_ptr.ctag);
        }
        var contact_iter = self.contacts.iterator();
        while (contact_iter.next()) |entry| {
            self.allocator.free(entry.value_ptr.etag);
        }
        // Free allocated etag/href strings in sync changes (both owned by the store)
        for (self.sync_changes.items) |change| {
            self.allocator.free(change.etag);
            self.allocator.free(change.href);
        }
        self.calendars.deinit();
        self.events.deinit();
        self.addressbooks.deinit();
        self.contacts.deinit();
        self.emails.deinit(self.allocator);
        self.phones.deinit(self.allocator);
        self.addresses.deinit(self.allocator);
        for (self.user_ids.items) |entry| self.allocator.free(entry.username);
        self.user_ids.deinit(self.allocator);
        self.sync_changes.deinit(self.allocator);
    }

    // -------------------------------------------------------------------------
    // SQLite persistence (all helpers no-op when `conn` is null)
    // -------------------------------------------------------------------------

    fn ensureSchema(conn: *database.Connection) !void {
        try conn.exec(
            \\CREATE TABLE IF NOT EXISTS dav_calendars (id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, description TEXT, color TEXT, timezone TEXT, created_at INTEGER, modified_at INTEGER, sync_token INTEGER, ctag TEXT);
            \\CREATE TABLE IF NOT EXISTS dav_events (id INTEGER PRIMARY KEY, calendar_id INTEGER, uid TEXT, summary TEXT, description TEXT, location TEXT, dtstart INTEGER, dtend INTEGER, all_day INTEGER, rrule TEXT, organizer TEXT, status INTEGER, created_at INTEGER, modified_at INTEGER, etag TEXT, ics_data TEXT);
            \\CREATE TABLE IF NOT EXISTS dav_addressbooks (id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, description TEXT, created_at INTEGER, modified_at INTEGER, sync_token INTEGER, ctag TEXT);
            \\CREATE TABLE IF NOT EXISTS dav_contacts (id INTEGER PRIMARY KEY, addressbook_id INTEGER, uid TEXT, full_name TEXT, given_name TEXT, family_name TEXT, nickname TEXT, organization TEXT, title TEXT, birthday INTEGER, note TEXT, photo_url TEXT, created_at INTEGER, modified_at INTEGER, etag TEXT, vcf_data TEXT);
            \\CREATE TABLE IF NOT EXISTS dav_emails (contact_id INTEGER, email TEXT, email_type INTEGER, is_primary INTEGER);
            \\CREATE TABLE IF NOT EXISTS dav_phones (contact_id INTEGER, number TEXT, phone_type INTEGER, is_primary INTEGER);
            \\CREATE INDEX IF NOT EXISTS idx_dav_events_cal ON dav_events(calendar_id);
            \\CREATE INDEX IF NOT EXISTS idx_dav_contacts_ab ON dav_contacts(addressbook_id);
            \\CREATE INDEX IF NOT EXISTS idx_dav_emails_c ON dav_emails(contact_id);
            \\CREATE INDEX IF NOT EXISTS idx_dav_phones_c ON dav_phones(contact_id);
        );
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

    fn persistCalendar(self: *Self, cal: Calendar) void {
        const conn = if (self.conn) |*c| c else return;
        var stmt = conn.prepare("INSERT OR REPLACE INTO dav_calendars (id,user_id,name,description,color,timezone,created_at,modified_at,sync_token,ctag) VALUES (?,?,?,?,?,?,?,?,?,?)") catch return;
        defer stmt.finalize();
        stmt.bindInt(1, @intCast(cal.id)) catch return;
        stmt.bindInt(2, @intCast(cal.user_id)) catch return;
        stmt.bindText(3, cal.name) catch return;
        bindOptText(&stmt, 4, cal.description) catch return;
        bindOptText(&stmt, 5, cal.color) catch return;
        stmt.bindText(6, cal.timezone) catch return;
        stmt.bindInt(7, cal.created_at) catch return;
        stmt.bindInt(8, cal.modified_at) catch return;
        stmt.bindInt(9, @intCast(cal.sync_token)) catch return;
        stmt.bindText(10, cal.ctag) catch return;
        _ = stmt.step() catch return;
    }

    fn persistEvent(self: *Self, ev: Event) void {
        const conn = if (self.conn) |*c| c else return;
        var stmt = conn.prepare("INSERT OR REPLACE INTO dav_events (id,calendar_id,uid,summary,description,location,dtstart,dtend,all_day,rrule,organizer,status,created_at,modified_at,etag,ics_data) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)") catch return;
        defer stmt.finalize();
        stmt.bindInt(1, @intCast(ev.id)) catch return;
        stmt.bindInt(2, @intCast(ev.calendar_id)) catch return;
        stmt.bindText(3, ev.uid) catch return;
        stmt.bindText(4, ev.summary) catch return;
        bindOptText(&stmt, 5, ev.description) catch return;
        bindOptText(&stmt, 6, ev.location) catch return;
        stmt.bindInt(7, ev.dtstart) catch return;
        bindOptInt(&stmt, 8, ev.dtend) catch return;
        stmt.bindInt(9, if (ev.all_day) 1 else 0) catch return;
        bindOptText(&stmt, 10, ev.rrule) catch return;
        bindOptText(&stmt, 11, ev.organizer) catch return;
        stmt.bindInt(12, @intFromEnum(ev.status)) catch return;
        stmt.bindInt(13, ev.created_at) catch return;
        stmt.bindInt(14, ev.modified_at) catch return;
        stmt.bindText(15, ev.etag) catch return;
        stmt.bindText(16, ev.ics_data) catch return;
        _ = stmt.step() catch return;
    }

    fn persistAddressBook(self: *Self, ab: AddressBook) void {
        const conn = if (self.conn) |*c| c else return;
        var stmt = conn.prepare("INSERT OR REPLACE INTO dav_addressbooks (id,user_id,name,description,created_at,modified_at,sync_token,ctag) VALUES (?,?,?,?,?,?,?,?)") catch return;
        defer stmt.finalize();
        stmt.bindInt(1, @intCast(ab.id)) catch return;
        stmt.bindInt(2, @intCast(ab.user_id)) catch return;
        stmt.bindText(3, ab.name) catch return;
        bindOptText(&stmt, 4, ab.description) catch return;
        stmt.bindInt(5, ab.created_at) catch return;
        stmt.bindInt(6, ab.modified_at) catch return;
        stmt.bindInt(7, @intCast(ab.sync_token)) catch return;
        stmt.bindText(8, ab.ctag) catch return;
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
            stmt.bindInt(3, @intFromEnum(e.email_type)) catch continue;
            stmt.bindInt(4, if (e.is_primary) 1 else 0) catch continue;
            _ = stmt.step() catch continue;
        }
        for (self.phones.items) |p| {
            if (p.contact_id != contact_id) continue;
            var stmt = conn.prepare("INSERT INTO dav_phones (contact_id,number,phone_type,is_primary) VALUES (?,?,?,?)") catch continue;
            defer stmt.finalize();
            stmt.bindInt(1, @intCast(contact_id)) catch continue;
            stmt.bindText(2, p.number) catch continue;
            stmt.bindInt(3, @intFromEnum(p.phone_type)) catch continue;
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
    /// `self.allocator` (ctag/etag are freed by deinit; the rest persist for the
    /// store's lifetime, matching the in-session ownership model).
    fn loadFromDb(self: *Self) !void {
        const conn = if (self.conn) |*c| c else return;

        {
            var stmt = try conn.prepare("SELECT id,user_id,name,description,color,timezone,created_at,modified_at,sync_token,ctag FROM dav_calendars");
            defer stmt.finalize();
            while (stmt.step() catch false) {
                const id: u64 = @intCast(stmt.columnInt(0));
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
                });
                self.bumpIds(id, @intCast(stmt.columnInt(8)), .calendar);
            }
        }
        {
            var stmt = try conn.prepare("SELECT id,calendar_id,uid,summary,description,location,dtstart,dtend,all_day,rrule,organizer,status,created_at,modified_at,etag,ics_data FROM dav_events");
            defer stmt.finalize();
            while (stmt.step() catch false) {
                const id: u64 = @intCast(stmt.columnInt(0));
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
                    .rrule = self.dupColOpt(&stmt, 9),
                    .organizer = self.dupColOpt(&stmt, 10),
                    .status = switch (stmt.columnInt(11)) {
                        0 => .tentative,
                        2 => .cancelled,
                        else => .confirmed,
                    },
                    .created_at = stmt.columnInt(12),
                    .modified_at = stmt.columnInt(13),
                    .etag = self.dupCol(&stmt, 14),
                    .ics_data = self.dupCol(&stmt, 15),
                });
                self.bumpIds(id, 0, .event);
            }
        }
        {
            var stmt = try conn.prepare("SELECT id,user_id,name,description,created_at,modified_at,sync_token,ctag FROM dav_addressbooks");
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
        self.mutex.lock();
        defer self.mutex.unlock();

        // Look up existing
        for (self.user_ids.items) |entry| {
            if (std.mem.eql(u8, entry.username, username)) {
                return entry.user_id;
            }
        }
        // Create new
        const id = self.next_user_id;
        self.next_user_id += 1;
        // Dupe the username: the caller's slice is the per-connection auth
        // buffer, freed when that connection closes. Storing it directly left a
        // dangling pointer, so the next connection's lookup never matched and
        // every connection minted a fresh user_id — orphaning the previous
        // connection's calendars/contacts (EWS/CalDAV read returned nothing).
        try self.user_ids.append(self.allocator, .{
            .username = try self.allocator.dupe(u8, username),
            .user_id = id,
        });
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

        const id = self.next_calendar_id;
        self.next_calendar_id += 1;

        const now = currentTimestamp();
        const ctag = try self.generateCtag(id, now);

        try self.calendars.put(id, .{
            .id = id,
            .user_id = user_id,
            .name = name,
            .description = description,
            .color = null,
            .timezone = self.config.default_timezone,
            .created_at = now,
            .modified_at = now,
            .sync_token = self.current_sync_token,
            .ctag = ctag,
        });

        self.persistCalendar(self.calendars.get(id).?);
        return id;
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
            if (self.events.getPtr(event_id)) |e| {
                self.allocator.free(e.etag);
            }
            _ = self.events.remove(event_id);
        }

        if (self.calendars.getPtr(id)) |cal| {
            self.allocator.free(cal.ctag);
        }
        _ = self.calendars.remove(id);
        self.dbExecId("DELETE FROM dav_events WHERE calendar_id = {d}", id);
        self.dbExecId("DELETE FROM dav_calendars WHERE id = {d}", id);
    }

    // -------------------------------------------------------------------------
    // Event Operations
    // -------------------------------------------------------------------------

    pub fn createEvent(self: *Self, calendar_id: u64, data: EventData) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const id = self.next_event_id;
        self.next_event_id += 1;

        const now = currentTimestamp();
        const etag = try self.generateEtag(id, now);
        const uid = data.uid orelse try self.generateUid();

        try self.events.put(id, .{
            .id = id,
            .calendar_id = calendar_id,
            .uid = uid,
            .summary = data.summary,
            .description = data.description,
            .location = data.location,
            .dtstart = data.dtstart,
            .dtend = data.dtend,
            .all_day = data.all_day,
            .rrule = data.rrule,
            .organizer = data.organizer,
            .status = data.status,
            .created_at = now,
            .modified_at = now,
            .etag = etag,
            .ics_data = data.ics_data orelse "",
        });

        // Record sync change
        if (self.config.enable_sync_tokens) {
            try self.recordChange(calendar_id, id, .event, .created, etag, try self.getEventHref(calendar_id, uid));
        }

        // Update calendar ctag
        try self.updateCalendarCtag(calendar_id);
        self.persistEvent(self.events.get(id).?);

        return id;
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
    };

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

        if (self.events.getPtr(id)) |event| {
            const now = currentTimestamp();
            const old_etag = event.etag;
            const etag = try self.generateEtag(id, now);
            self.allocator.free(old_etag);

            event.summary = data.summary;
            event.description = data.description;
            event.location = data.location;
            event.dtstart = data.dtstart;
            event.dtend = data.dtend;
            event.all_day = data.all_day;
            event.rrule = data.rrule;
            event.status = data.status;
            event.modified_at = now;
            event.etag = etag;
            if (data.ics_data) |ics| {
                event.ics_data = ics;
            }

            if (self.config.enable_sync_tokens) {
                try self.recordChange(event.calendar_id, id, .event, .modified, etag, try self.getEventHref(event.calendar_id, event.uid));
            }
            try self.updateCalendarCtag(event.calendar_id);
            self.persistEvent(event.*);
        } else {
            return error.EventNotFound;
        }
    }

    pub fn deleteEvent(self: *Self, id: u64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.events.get(id)) |event| {
            const etag = event.etag;
            const calendar_id = event.calendar_id;
            // The live etag is no longer owned by the map once we remove the
            // event; recordChange dupes its own copy, so free it here in all paths.
            defer self.allocator.free(etag);

            if (self.config.enable_sync_tokens) {
                const href = try self.getEventHref(event.calendar_id, event.uid);
                _ = self.events.remove(id);
                try self.recordChange(calendar_id, id, .event, .deleted, etag, href);
            } else {
                _ = self.events.remove(id);
            }
            try self.updateCalendarCtag(calendar_id);
            self.dbExecId("DELETE FROM dav_events WHERE id = {d}", id);
        }
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

        const id = self.next_addressbook_id;
        self.next_addressbook_id += 1;

        const now = currentTimestamp();
        const ctag = try self.generateCtag(id, now);

        try self.addressbooks.put(id, .{
            .id = id,
            .user_id = user_id,
            .name = name,
            .description = description,
            .created_at = now,
            .modified_at = now,
            .sync_token = self.current_sync_token,
            .ctag = ctag,
        });

        self.persistAddressBook(self.addressbooks.get(id).?);
        return id;
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
            // Free allocated etag before removing
            if (self.contacts.getPtr(contact_id)) |c| {
                self.allocator.free(c.etag);
            }
            // Remove associated emails and phones
            var i: usize = 0;
            while (i < self.emails.items.len) {
                if (self.emails.items[i].contact_id == contact_id) {
                    _ = self.emails.orderedRemove(i);
                } else {
                    i += 1;
                }
            }
            i = 0;
            while (i < self.phones.items.len) {
                if (self.phones.items[i].contact_id == contact_id) {
                    _ = self.phones.orderedRemove(i);
                } else {
                    i += 1;
                }
            }
            _ = self.contacts.remove(contact_id);
        }

        // Free allocated ctag before removing
        if (self.addressbooks.getPtr(id)) |ab| {
            self.allocator.free(ab.ctag);
        }
        _ = self.addressbooks.remove(id);
        self.dbExecId("DELETE FROM dav_emails WHERE contact_id IN (SELECT id FROM dav_contacts WHERE addressbook_id = {d})", id);
        self.dbExecId("DELETE FROM dav_phones WHERE contact_id IN (SELECT id FROM dav_contacts WHERE addressbook_id = {d})", id);
        self.dbExecId("DELETE FROM dav_contacts WHERE addressbook_id = {d}", id);
        self.dbExecId("DELETE FROM dav_addressbooks WHERE id = {d}", id);
    }

    // -------------------------------------------------------------------------
    // Contact Operations
    // -------------------------------------------------------------------------

    pub fn createContact(self: *Self, addressbook_id: u64, data: ContactData) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const id = self.next_contact_id;
        self.next_contact_id += 1;

        const now = currentTimestamp();
        const etag = try self.generateEtag(id, now);
        const uid = data.uid orelse try self.generateUid();

        try self.contacts.put(id, .{
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

        // Add emails
        for (data.emails) |email| {
            try self.emails.append(self.allocator, .{
                .contact_id = id,
                .email = email.email,
                .email_type = email.email_type,
                .is_primary = email.is_primary,
            });
        }

        // Add phones
        for (data.phones) |phone| {
            try self.phones.append(self.allocator, .{
                .contact_id = id,
                .number = phone.number,
                .phone_type = phone.phone_type,
                .is_primary = phone.is_primary,
            });
        }

        if (self.config.enable_sync_tokens) {
            try self.recordChange(addressbook_id, id, .contact, .created, etag, try self.getContactHref(addressbook_id, uid));
        }
        try self.updateAddressBookCtag(addressbook_id);
        if (self.contacts.get(id)) |ct| self.persistContact(ct);

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

        if (self.contacts.getPtr(id)) |contact| {
            const now = currentTimestamp();
            const old_etag = contact.etag;
            const etag = try self.generateEtag(id, now);
            self.allocator.free(old_etag);

            contact.full_name = data.full_name;
            contact.given_name = data.given_name;
            contact.family_name = data.family_name;
            contact.nickname = data.nickname;
            contact.organization = data.organization;
            contact.title = data.title;
            contact.birthday = data.birthday;
            contact.note = data.note;
            contact.photo_url = data.photo_url;
            contact.modified_at = now;
            contact.etag = etag;
            if (data.vcf_data) |vcf| {
                contact.vcf_data = vcf;
            }

            // Update emails: remove old, add new
            var i: usize = 0;
            while (i < self.emails.items.len) {
                if (self.emails.items[i].contact_id == id) {
                    _ = self.emails.orderedRemove(i);
                } else {
                    i += 1;
                }
            }
            for (data.emails) |email| {
                try self.emails.append(self.allocator, .{
                    .contact_id = id,
                    .email = email.email,
                    .email_type = email.email_type,
                    .is_primary = email.is_primary,
                });
            }

            // Update phones: remove old, add new
            i = 0;
            while (i < self.phones.items.len) {
                if (self.phones.items[i].contact_id == id) {
                    _ = self.phones.orderedRemove(i);
                } else {
                    i += 1;
                }
            }
            for (data.phones) |phone| {
                try self.phones.append(self.allocator, .{
                    .contact_id = id,
                    .number = phone.number,
                    .phone_type = phone.phone_type,
                    .is_primary = phone.is_primary,
                });
            }

            if (self.config.enable_sync_tokens) {
                try self.recordChange(contact.addressbook_id, id, .contact, .modified, etag, try self.getContactHref(contact.addressbook_id, contact.uid));
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

        if (self.contacts.get(id)) |contact| {
            const etag = contact.etag;
            const addressbook_id = contact.addressbook_id;
            // recordChange dupes its own etag copy; free the now-unowned live
            // etag here in all paths.
            defer self.allocator.free(etag);

            // Remove associated emails and phones
            var i: usize = 0;
            while (i < self.emails.items.len) {
                if (self.emails.items[i].contact_id == id) {
                    _ = self.emails.orderedRemove(i);
                } else {
                    i += 1;
                }
            }

            i = 0;
            while (i < self.phones.items.len) {
                if (self.phones.items[i].contact_id == id) {
                    _ = self.phones.orderedRemove(i);
                } else {
                    i += 1;
                }
            }

            if (self.config.enable_sync_tokens) {
                const href = try self.getContactHref(contact.addressbook_id, contact.uid);
                _ = self.contacts.remove(id);
                try self.recordChange(addressbook_id, id, .contact, .deleted, etag, href);
            } else {
                _ = self.contacts.remove(id);
            }
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

        for (self.sync_changes.items) |change| {
            if (change.resource_type == expected_type and
                change.collection_id == collection_id and
                change.token > since_token)
            {
                try changes.append(self.allocator, change);
            }
        }

        return SyncReport{
            .changes = try changes.toOwnedSlice(self.allocator),
            .new_sync_token = self.current_sync_token,
            .more_available = false,
        };
    }

    /// Record a sync change. The `href` slice is owned by the store after this
    /// call (ownership transferred from the caller). The `etag` slice is NOT
    /// taken over: it is duplicated here so the SyncChange owns an independent
    /// copy and does not alias the live Event/Contact etag (which may be freed
    /// by a later update/delete -> use-after-free).
    fn recordChange(
        self: *Self,
        collection_id: u64,
        resource_id: u64,
        resource_type: SyncChange.ResourceType,
        change_type: SyncChange.ChangeType,
        etag: []const u8,
        href: []const u8,
    ) !void {
        if (!self.config.enable_sync_tokens) {
            // Caller transferred ownership of href; free it since we won't store it.
            self.allocator.free(href);
            return;
        }

        self.current_sync_token += 1;

        const owned_etag = self.allocator.dupe(u8, etag) catch |err| {
            // On failure, free the caller-owned href to avoid a leak.
            self.allocator.free(href);
            return err;
        };
        errdefer self.allocator.free(owned_etag);

        try self.sync_changes.append(self.allocator, .{
            .resource_id = resource_id,
            .collection_id = collection_id,
            .resource_type = resource_type,
            .change_type = change_type,
            .token = self.current_sync_token,
            .etag = owned_etag,
            .href = href,
            .timestamp = currentTimestamp(),
        });

        // Prune old history, bounding retained changes. Free owned strings of
        // any pruned entries to avoid leaks.
        while (self.sync_changes.items.len > self.config.max_sync_history) {
            const removed = self.sync_changes.orderedRemove(0);
            self.allocator.free(removed.etag);
            self.allocator.free(removed.href);
        }
    }

    fn updateCalendarCtag(self: *Self, calendar_id: u64) !void {
        if (self.calendars.getPtr(calendar_id)) |cal| {
            const now = currentTimestamp();
            const old_ctag = cal.ctag;
            cal.ctag = try self.generateCtag(calendar_id, now);
            self.allocator.free(old_ctag);
            cal.modified_at = now;
            cal.sync_token = self.current_sync_token;
            self.persistCalendar(cal.*);
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
        if (contact.note) |n| {
            try buf.appendSlice(self.allocator, "NOTE:");
            try buf.appendSlice(self.allocator, n);
            try buf.appendSlice(self.allocator, "\r\n");
        }

        // PHOTO
        if (contact.photo_url) |photo| {
            try buf.appendSlice(self.allocator, "PHOTO;VALUE=uri:");
            try buf.appendSlice(self.allocator, photo);
            try buf.appendSlice(self.allocator, "\r\n");
        }

        // Emails
        const emails = self.getContactEmails(contact.id);
        defer self.allocator.free(emails);
        for (emails) |email| {
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
        const phones = self.getContactPhones(contact.id);
        defer self.allocator.free(phones);
        for (phones) |phone| {
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

    fn generateEtag(self: *Self, id: u64, timestamp: i64) ![]const u8 {
        return try std.fmt.allocPrint(self.allocator, "\"{d}-{d}\"", .{ id, timestamp });
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

    fn getEventHref(self: *Self, calendar_id: u64, uid: []const u8) ![]const u8 {
        return try std.fmt.allocPrint(self.allocator, "/calendars/{d}/{s}.ics", .{ calendar_id, uid });
    }

    fn getContactHref(self: *Self, addressbook_id: u64, uid: []const u8) ![]const u8 {
        return try std.fmt.allocPrint(self.allocator, "/addressbooks/{d}/{s}.vcf", .{ addressbook_id, uid });
    }
};

// =============================================================================
// ICS Parser (iCalendar)
// =============================================================================

pub const IcsParser = struct {
    pub fn parseEvent(ics_data: []const u8) ?ParsedEvent {
        var event = ParsedEvent{};

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
    };
};

// =============================================================================
// VCF Parser (vCard)
// =============================================================================

pub const VcfParser = struct {
    const MAX_MULTI_VALUES = 8;

    pub fn parseContact(vcf_data: []const u8) ?ParsedContact {
        var contact = ParsedContact{};

        // Handle both \r\n (RFC standard) and \n (common in testing/unix)
        var lines = std.mem.splitScalar(u8, vcf_data, '\n');
        while (lines.next()) |raw_line| {
            const line = std.mem.trimEnd(u8, raw_line, "\r");
            if (std.mem.startsWith(u8, line, "FN:")) {
                contact.full_name = line[3..];
            } else if (std.mem.startsWith(u8, line, "N:")) {
                const name_parts = line[2..];
                var parts = std.mem.splitScalar(u8, name_parts, ';');
                contact.family_name = parts.next();
                contact.given_name = parts.next();
            } else if (std.mem.startsWith(u8, line, "EMAIL")) {
                if (std.mem.indexOf(u8, line, ":")) |idx| {
                    const value = line[idx + 1 ..];
                    if (contact.email_count < MAX_MULTI_VALUES) {
                        contact.emails[contact.email_count] = value;
                        contact.email_count += 1;
                    }
                }
            } else if (std.mem.startsWith(u8, line, "TEL")) {
                if (std.mem.indexOf(u8, line, ":")) |idx| {
                    const value = line[idx + 1 ..];
                    if (contact.phone_count < MAX_MULTI_VALUES) {
                        contact.phones[contact.phone_count] = value;
                        contact.phone_count += 1;
                    }
                }
            } else if (std.mem.startsWith(u8, line, "ORG:")) {
                contact.organization = line[4..];
            } else if (std.mem.startsWith(u8, line, "UID:")) {
                contact.uid = line[4..];
            }
        }

        if (contact.full_name == null) return null;
        return contact;
    }

    pub const ParsedContact = struct {
        uid: ?[]const u8 = null,
        full_name: ?[]const u8 = null,
        given_name: ?[]const u8 = null,
        family_name: ?[]const u8 = null,
        emails: [MAX_MULTI_VALUES][]const u8 = [_][]const u8{""} ** MAX_MULTI_VALUES,
        email_count: usize = 0,
        phones: [MAX_MULTI_VALUES][]const u8 = [_][]const u8{""} ** MAX_MULTI_VALUES,
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
