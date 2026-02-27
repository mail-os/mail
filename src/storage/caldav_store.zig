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

/// Get the current epoch timestamp in seconds (cross-platform).
fn currentTimestamp() i64 {
    const ts = std.posix.clock_gettime(.REALTIME) catch return 0;
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
        return Self{
            .allocator = allocator,
            .config = config,
            .calendars = std.AutoHashMap(u64, Calendar).init(allocator),
            .events = std.AutoHashMap(u64, Event).init(allocator),
            .addressbooks = std.AutoHashMap(u64, AddressBook).init(allocator),
            .contacts = std.AutoHashMap(u64, Contact).init(allocator),
            .emails = .{},
            .phones = .{},
            .addresses = .{},
            .user_ids = .{},
            .next_user_id = 1,
            .sync_changes = .{},
            .current_sync_token = 1,
            .next_calendar_id = 1,
            .next_event_id = 1,
            .next_addressbook_id = 1,
            .next_contact_id = 1,
        };
    }

    pub fn deinit(self: *Self) void {
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
        // Free allocated href strings in sync changes
        for (self.sync_changes.items) |change| {
            self.allocator.free(change.href);
        }
        self.calendars.deinit();
        self.events.deinit();
        self.addressbooks.deinit();
        self.contacts.deinit();
        self.emails.deinit(self.allocator);
        self.phones.deinit(self.allocator);
        self.addresses.deinit(self.allocator);
        self.user_ids.deinit(self.allocator);
        self.sync_changes.deinit(self.allocator);
    }

    // -------------------------------------------------------------------------
    // User Operations
    // -------------------------------------------------------------------------

    /// Get existing user_id for username, or create a new one.
    pub fn getOrCreateUserId(self: *Self, username: []const u8) !u64 {
        // Look up existing
        for (self.user_ids.items) |entry| {
            if (std.mem.eql(u8, entry.username, username)) {
                return entry.user_id;
            }
        }
        // Create new
        const id = self.next_user_id;
        self.next_user_id += 1;
        try self.user_ids.append(self.allocator, .{
            .username = username,
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

        return id;
    }

    pub fn getCalendar(self: *Self, id: u64) ?Calendar {
        return self.calendars.get(id);
    }

    pub fn getUserCalendars(self: *Self, user_id: u64) ![]Calendar {
        var result: std.ArrayList(Calendar) = .{};
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
        // Delete all events in this calendar first
        var events_to_delete: std.ArrayList(u64) = .{};
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
    }

    // -------------------------------------------------------------------------
    // Event Operations
    // -------------------------------------------------------------------------

    pub fn createEvent(self: *Self, calendar_id: u64, data: EventData) !u64 {
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
        var result: std.ArrayList(Event) = .{};
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
        } else {
            return error.EventNotFound;
        }
    }

    pub fn deleteEvent(self: *Self, id: u64) !void {
        if (self.events.get(id)) |event| {
            const etag = event.etag;
            const calendar_id = event.calendar_id;

            if (self.config.enable_sync_tokens) {
                const href = try self.getEventHref(event.calendar_id, event.uid);
                _ = self.events.remove(id);
                try self.recordChange(calendar_id, id, .event, .deleted, etag, href);
            } else {
                _ = self.events.remove(id);
                self.allocator.free(etag);
            }
            try self.updateCalendarCtag(calendar_id);
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
        var result: std.ArrayList(AddressBook) = .{};
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
        // Delete all contacts in this addressbook first
        var contacts_to_delete: std.ArrayList(u64) = .{};
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
    }

    // -------------------------------------------------------------------------
    // Contact Operations
    // -------------------------------------------------------------------------

    pub fn createContact(self: *Self, addressbook_id: u64, data: ContactData) !u64 {
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
        } else {
            return error.ContactNotFound;
        }
    }

    pub fn getAddressBookContacts(self: *Self, addressbook_id: u64) ![]Contact {
        var result: std.ArrayList(Contact) = .{};
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
        var result: std.ArrayList(EmailAddress) = .{};
        for (self.emails.items) |email| {
            if (email.contact_id == contact_id) {
                result.append(self.allocator, email) catch continue;
            }
        }
        return result.toOwnedSlice(self.allocator) catch &.{};
    }

    pub fn getContactPhones(self: *Self, contact_id: u64) []PhoneNumber {
        var result: std.ArrayList(PhoneNumber) = .{};
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
        if (self.contacts.get(id)) |contact| {
            const etag = contact.etag;
            const addressbook_id = contact.addressbook_id;

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
                self.allocator.free(etag);
            }
            try self.updateAddressBookCtag(addressbook_id);
        }
    }

    // -------------------------------------------------------------------------
    // Sync Token Operations
    // -------------------------------------------------------------------------

    pub fn getSyncToken(self: *Self, collection_id: u64, is_calendar: bool) u64 {
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
        var changes: std.ArrayList(SyncChange) = .{};
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

    fn recordChange(
        self: *Self,
        collection_id: u64,
        resource_id: u64,
        resource_type: SyncChange.ResourceType,
        change_type: SyncChange.ChangeType,
        etag: []const u8,
        href: []const u8,
    ) !void {
        if (!self.config.enable_sync_tokens) return;

        self.current_sync_token += 1;

        try self.sync_changes.append(self.allocator, .{
            .resource_id = resource_id,
            .collection_id = collection_id,
            .resource_type = resource_type,
            .change_type = change_type,
            .token = self.current_sync_token,
            .etag = etag,
            .href = href,
            .timestamp = currentTimestamp(),
        });

        // Prune old history
        while (self.sync_changes.items.len > self.config.max_sync_history) {
            _ = self.sync_changes.orderedRemove(0);
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

        var buf: std.ArrayList(u8) = .{};
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
        var random_bytes: [8]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);
        const random = std.mem.readInt(u64, &random_bytes, .little);
        return try std.fmt.allocPrint(self.allocator, "{x}-{x}@localhost", .{ timestamp, random });
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

    fn epochDays(year: i64, month: i64, day: i64) i64 {
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
