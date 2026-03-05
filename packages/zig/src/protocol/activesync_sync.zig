//! ActiveSync Sync Engine
//!
//! Provides synchronization logic for ActiveSync protocol:
//! - Device provisioning and policy enforcement
//! - Email folder sync with change tracking
//! - Calendar sync with meeting responses
//! - Contact sync with GAL (Global Address List)
//! - Device management and remote wipe
//!
//! Usage:
//! ```zig
//! var engine = try SyncEngine.init(allocator, config);
//! defer engine.deinit();
//!
//! // Provision device
//! const policy = try engine.provisionDevice(device_id, device_info);
//!
//! // Sync emails
//! const changes = try engine.syncEmails(user_id, folder_id, sync_key);
//! ```

const std = @import("std");
const Allocator = std.mem.Allocator;

// =============================================================================
// Configuration
// =============================================================================

pub const SyncEngineConfig = struct {
    /// Maximum items per sync
    max_sync_items: u32 = 100,

    /// Sync window in days (0 = all)
    sync_window_days: u32 = 14,

    /// Enable conflict resolution
    enable_conflict_resolution: bool = true,

    /// Policy refresh interval (hours)
    policy_refresh_hours: u32 = 24,

    /// Enable remote wipe
    enable_remote_wipe: bool = true,

    /// Enable device password requirement
    require_device_password: bool = true,

    /// Minimum password length
    min_password_length: u8 = 6,

    /// Maximum password age (days)
    max_password_age: u32 = 90,

    /// Allow simple passwords
    allow_simple_password: bool = false,

    /// Inactivity timeout (minutes)
    max_inactivity_timeout: u32 = 15,
};

// =============================================================================
// Device Management
// =============================================================================

pub const Device = struct {
    id: []const u8,
    user_id: u64,
    device_type: DeviceType,
    model: []const u8,
    os: []const u8,
    os_version: []const u8,
    friendly_name: ?[]const u8,
    user_agent: []const u8,
    protocol_version: []const u8,
    policy_key: ?u64,
    first_sync: i64,
    last_sync: i64,
    status: DeviceStatus,
    wipe_requested: bool,
    wipe_completed: bool,

    pub const DeviceType = enum {
        iphone,
        ipad,
        android_phone,
        android_tablet,
        windows_phone,
        windows_pc,
        other,

        pub fn fromUserAgent(ua: []const u8) DeviceType {
            if (std.mem.indexOf(u8, ua, "iPhone") != null) return .iphone;
            if (std.mem.indexOf(u8, ua, "iPad") != null) return .ipad;
            if (std.mem.indexOf(u8, ua, "Android") != null) {
                if (std.mem.indexOf(u8, ua, "Mobile") != null) return .android_phone;
                return .android_tablet;
            }
            if (std.mem.indexOf(u8, ua, "Windows Phone") != null) return .windows_phone;
            if (std.mem.indexOf(u8, ua, "Windows") != null) return .windows_pc;
            return .other;
        }
    };

    pub const DeviceStatus = enum {
        pending_provision,
        provisioned,
        blocked,
        quarantined,
        wiping,
        wiped,
    };
};

pub const DevicePolicy = struct {
    policy_key: u64,
    device_password_enabled: bool,
    alpha_numeric_device_password_required: bool,
    password_recovery_enabled: bool,
    require_storage_card_encryption: bool,
    attachments_enabled: bool,
    min_device_password_length: u8,
    max_inactivity_time_device_lock: u32, // seconds
    max_device_password_failed_attempts: u8,
    max_attachment_size: u32, // bytes
    allow_simple_device_password: bool,
    device_password_expiration: u32, // days
    device_password_history: u8, // count
    allow_storage_card: bool,
    allow_camera: bool,
    require_device_encryption: bool,
    allow_unsigned_applications: bool,
    allow_unsigned_installation_packages: bool,
    min_device_password_complex_characters: u8,
    allow_wifi: bool,
    allow_text_messaging: bool,
    allow_pop_imap_email: bool,
    allow_bluetooth: bool,
    allow_irda: bool,
    require_manual_sync_when_roaming: bool,
    allow_desktop_sync: bool,
    max_calendar_age_filter: u32, // days
    allow_html_email: bool,
    max_email_age_filter: u32, // days
    max_email_body_truncation_size: u32, // bytes
    max_email_html_body_truncation_size: u32, // bytes
    require_signed_smime_messages: bool,
    require_encrypted_smime_messages: bool,
    require_signed_smime_algorithm: ?[]const u8,
    require_encryption_smime_algorithm: ?[]const u8,
    allow_smime_encryption_algorithm_negotiation: bool,
    allow_smime_soft_certs: bool,
    allow_browser: bool,
    allow_consumer_email: bool,
    allow_remote_desktop: bool,
    allow_internet_sharing: bool,
    unapproved_in_rom_application_list: []const []const u8,
    approved_application_list: []const []const u8,
};

// =============================================================================
// Sync State
// =============================================================================

pub const SyncKey = struct {
    key: u64,
    folder_id: []const u8,
    timestamp: i64,
};

pub const SyncState = struct {
    user_id: u64,
    device_id: []const u8,
    folder_id: []const u8,
    sync_key: u64,
    last_sync: i64,
    filter_type: FilterType,

    pub const FilterType = enum {
        all,
        one_day,
        three_days,
        one_week,
        two_weeks,
        one_month,
        three_months,
        six_months,
    };
};

// =============================================================================
// Sync Items
// =============================================================================

pub const SyncItem = struct {
    server_id: []const u8,
    item_type: ItemType,
    change_type: ChangeType,
    data: ItemData,

    pub const ItemType = enum {
        email,
        calendar,
        contact,
        task,
        note,
    };

    pub const ChangeType = enum {
        add,
        change,
        delete,
        soft_delete,
    };

    pub const ItemData = union(ItemType) {
        email: EmailItem,
        calendar: CalendarItem,
        contact: ContactItem,
        task: TaskItem,
        note: NoteItem,
    };
};

pub const EmailItem = struct {
    subject: []const u8,
    from: []const u8,
    to: []const u8,
    cc: ?[]const u8,
    date_received: i64,
    importance: Importance,
    read: bool,
    flagged: bool,
    body: []const u8,
    body_type: BodyType,
    attachments: []const Attachment,

    pub const Importance = enum { low, normal, high };
    pub const BodyType = enum { plain, html, rtf, mime };

    pub const Attachment = struct {
        name: []const u8,
        size: u32,
        content_type: []const u8,
        is_inline: bool,
        content_id: ?[]const u8,
    };
};

pub const CalendarItem = struct {
    subject: []const u8,
    start_time: i64,
    end_time: i64,
    all_day_event: bool,
    location: ?[]const u8,
    organizer: ?[]const u8,
    attendees: []const Attendee,
    reminder: ?u32, // minutes before
    recurrence: ?Recurrence,
    body: ?[]const u8,
    sensitivity: Sensitivity,
    busy_status: BusyStatus,

    pub const Attendee = struct {
        email: []const u8,
        name: ?[]const u8,
        status: AttendeeStatus,
        attendee_type: AttendeeType,
    };

    pub const AttendeeStatus = enum {
        unknown,
        tentative,
        accepted,
        declined,
    };

    pub const AttendeeType = enum {
        required,
        optional,
        resource,
    };

    pub const Sensitivity = enum {
        normal,
        personal,
        private,
        confidential,
    };

    pub const BusyStatus = enum {
        free,
        tentative,
        busy,
        out_of_office,
    };

    pub const Recurrence = struct {
        type: RecurrenceType,
        interval: u32,
        until: ?i64,
        occurrences: ?u32,
        day_of_week: ?u8,
        day_of_month: ?u8,
        month_of_year: ?u8,
    };

    pub const RecurrenceType = enum {
        daily,
        weekly,
        monthly,
        monthly_nth,
        yearly,
        yearly_nth,
    };
};

pub const ContactItem = struct {
    first_name: ?[]const u8,
    last_name: ?[]const u8,
    middle_name: ?[]const u8,
    title: ?[]const u8,
    suffix: ?[]const u8,
    company_name: ?[]const u8,
    department: ?[]const u8,
    job_title: ?[]const u8,
    email1_address: ?[]const u8,
    email2_address: ?[]const u8,
    email3_address: ?[]const u8,
    home_phone_number: ?[]const u8,
    mobile_phone_number: ?[]const u8,
    business_phone_number: ?[]const u8,
    home_address: ?AddressInfo,
    business_address: ?AddressInfo,
    birthday: ?i64,
    anniversary: ?i64,
    picture: ?[]const u8,
    notes: ?[]const u8,

    pub const AddressInfo = struct {
        street: ?[]const u8,
        city: ?[]const u8,
        state: ?[]const u8,
        postal_code: ?[]const u8,
        country: ?[]const u8,
    };
};

pub const TaskItem = struct {
    subject: []const u8,
    importance: EmailItem.Importance,
    start_date: ?i64,
    due_date: ?i64,
    complete: bool,
    date_completed: ?i64,
    reminder_set: bool,
    reminder_time: ?i64,
    sensitivity: CalendarItem.Sensitivity,
    body: ?[]const u8,
    categories: []const []const u8,
};

pub const NoteItem = struct {
    subject: ?[]const u8,
    body: []const u8,
    last_modified: i64,
    categories: []const []const u8,
};

// =============================================================================
// Sync Response
// =============================================================================

pub const SyncResponse = struct {
    status: SyncStatus,
    sync_key: u64,
    items: []SyncItem,
    more_available: bool,

    pub const SyncStatus = enum(u8) {
        success = 1,
        protocol_version_mismatch = 2,
        invalid_sync_key = 3,
        protocol_error = 4,
        server_error = 5,
        conversion_error = 6,
        conflict = 7,
        object_not_found = 8,
        sync_disabled = 9,
        hierarchy_changed = 12,
        incomplete = 13,
        invalid_wait = 14,
        too_many_folders = 15,
        retry = 16,
    };
};

// =============================================================================
// Folder Types
// =============================================================================

pub const FolderType = enum(u8) {
    user_created_generic = 1,
    default_inbox = 2,
    default_drafts = 3,
    default_deleted_items = 4,
    default_sent_items = 5,
    default_outbox = 6,
    default_tasks = 7,
    default_calendar = 8,
    default_contacts = 9,
    default_notes = 10,
    default_journal = 11,
    user_created_mail = 12,
    user_created_calendar = 13,
    user_created_contacts = 14,
    user_created_tasks = 15,
    user_created_journal = 16,
    user_created_notes = 17,
    unknown = 18,
    recipient_cache = 19,
};

pub const Folder = struct {
    id: []const u8,
    parent_id: []const u8,
    display_name: []const u8,
    folder_type: FolderType,
};

// =============================================================================
// Sync Engine
// =============================================================================

pub const SyncEngine = struct {
    const Self = @This();

    allocator: Allocator,
    config: SyncEngineConfig,

    // Device registry
    devices: std.StringHashMap(Device),

    // Sync states
    sync_states: std.StringHashMap(SyncState),

    // Policies
    default_policy: DevicePolicy,
    next_policy_key: u64,

    pub fn init(allocator: Allocator, config: SyncEngineConfig) !Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .devices = std.StringHashMap(Device).init(allocator),
            .sync_states = std.StringHashMap(SyncState).init(allocator),
            .default_policy = createDefaultPolicy(config),
            .next_policy_key = 1,
        };
    }

    pub fn deinit(self: *Self) void {
        self.devices.deinit();
        self.sync_states.deinit();
    }

    fn createDefaultPolicy(config: SyncEngineConfig) DevicePolicy {
        return DevicePolicy{
            .policy_key = 0,
            .device_password_enabled = config.require_device_password,
            .alpha_numeric_device_password_required = !config.allow_simple_password,
            .password_recovery_enabled = true,
            .require_storage_card_encryption = false,
            .attachments_enabled = true,
            .min_device_password_length = config.min_password_length,
            .max_inactivity_time_device_lock = config.max_inactivity_timeout * 60,
            .max_device_password_failed_attempts = 10,
            .max_attachment_size = 20 * 1024 * 1024, // 20MB
            .allow_simple_device_password = config.allow_simple_password,
            .device_password_expiration = config.max_password_age,
            .device_password_history = 5,
            .allow_storage_card = true,
            .allow_camera = true,
            .require_device_encryption = false,
            .allow_unsigned_applications = true,
            .allow_unsigned_installation_packages = true,
            .min_device_password_complex_characters = 0,
            .allow_wifi = true,
            .allow_text_messaging = true,
            .allow_pop_imap_email = true,
            .allow_bluetooth = true,
            .allow_irda = true,
            .require_manual_sync_when_roaming = false,
            .allow_desktop_sync = true,
            .max_calendar_age_filter = 0,
            .allow_html_email = true,
            .max_email_age_filter = 0,
            .max_email_body_truncation_size = 0,
            .max_email_html_body_truncation_size = 0,
            .require_signed_smime_messages = false,
            .require_encrypted_smime_messages = false,
            .require_signed_smime_algorithm = null,
            .require_encryption_smime_algorithm = null,
            .allow_smime_encryption_algorithm_negotiation = true,
            .allow_smime_soft_certs = true,
            .allow_browser = true,
            .allow_consumer_email = true,
            .allow_remote_desktop = true,
            .allow_internet_sharing = true,
            .unapproved_in_rom_application_list = &.{},
            .approved_application_list = &.{},
        };
    }

    // -------------------------------------------------------------------------
    // Provisioning
    // -------------------------------------------------------------------------

    pub fn provisionDevice(self: *Self, device_id: []const u8, info: DeviceInfo) !ProvisionResponse {
        const now = std.time.timestamp();

        // Check if device exists
        if (self.devices.get(device_id)) |existing| {
            // Device already provisioned, check if policy needs refresh
            if (existing.status == .provisioned) {
                return ProvisionResponse{
                    .status = .success,
                    .policy_key = existing.policy_key,
                    .policy = self.default_policy,
                };
            }
        }

        // Create new device entry
        const policy_key = self.next_policy_key;
        self.next_policy_key += 1;

        try self.devices.put(device_id, .{
            .id = device_id,
            .user_id = info.user_id,
            .device_type = Device.DeviceType.fromUserAgent(info.user_agent),
            .model = info.model,
            .os = info.os,
            .os_version = info.os_version,
            .friendly_name = info.friendly_name,
            .user_agent = info.user_agent,
            .protocol_version = info.protocol_version,
            .policy_key = policy_key,
            .first_sync = now,
            .last_sync = now,
            .status = .provisioned,
            .wipe_requested = false,
            .wipe_completed = false,
        });

        return ProvisionResponse{
            .status = .success,
            .policy_key = policy_key,
            .policy = self.default_policy,
        };
    }

    pub const DeviceInfo = struct {
        user_id: u64,
        model: []const u8,
        os: []const u8,
        os_version: []const u8,
        friendly_name: ?[]const u8,
        user_agent: []const u8,
        protocol_version: []const u8,
    };

    pub const ProvisionResponse = struct {
        status: ProvisionStatus,
        policy_key: ?u64,
        policy: DevicePolicy,

        pub const ProvisionStatus = enum {
            success,
            protocol_error,
            general_error,
            policy_not_defined,
            invalid_policy_key,
        };
    };

    pub fn acknowledgePolicy(self: *Self, device_id: []const u8, policy_key: u64) !bool {
        if (self.devices.getPtr(device_id)) |device| {
            if (device.policy_key == policy_key) {
                device.status = .provisioned;
                return true;
            }
        }
        return false;
    }

    // -------------------------------------------------------------------------
    // Remote Wipe
    // -------------------------------------------------------------------------

    pub fn requestRemoteWipe(self: *Self, device_id: []const u8) !bool {
        if (!self.config.enable_remote_wipe) return false;

        if (self.devices.getPtr(device_id)) |device| {
            device.wipe_requested = true;
            device.status = .wiping;
            return true;
        }
        return false;
    }

    pub fn confirmWipe(self: *Self, device_id: []const u8) !void {
        if (self.devices.getPtr(device_id)) |device| {
            device.wipe_completed = true;
            device.status = .wiped;
        }
    }

    pub fn isWipePending(self: *Self, device_id: []const u8) bool {
        if (self.devices.get(device_id)) |device| {
            return device.wipe_requested and !device.wipe_completed;
        }
        return false;
    }

    // -------------------------------------------------------------------------
    // Email Sync
    // -------------------------------------------------------------------------

    pub fn syncEmails(
        self: *Self,
        user_id: u64,
        device_id: []const u8,
        folder_id: []const u8,
        sync_key: u64,
        options: SyncOptions,
    ) !SyncResponse {
        _ = user_id;

        // Validate device
        if (!self.isDeviceProvisioned(device_id)) {
            return SyncResponse{
                .status = .sync_disabled,
                .sync_key = 0,
                .items = &.{},
                .more_available = false,
            };
        }

        // Check for initial sync (sync_key = 0)
        if (sync_key == 0) {
            // Return new sync key, no items
            return SyncResponse{
                .status = .success,
                .sync_key = 1,
                .items = &.{},
                .more_available = false,
            };
        }

        // Get changes since sync_key
        // In a real implementation, this would query the mailbox
        _ = folder_id;
        _ = options;

        return SyncResponse{
            .status = .success,
            .sync_key = sync_key + 1,
            .items = &.{}, // Would contain actual changes
            .more_available = false,
        };
    }

    pub const SyncOptions = struct {
        filter_type: SyncState.FilterType = .two_weeks,
        truncation: u32 = 0,
        mime_support: MimeSupport = .never,
        body_type: EmailItem.BodyType = .html,
        max_items: u32 = 100,

        pub const MimeSupport = enum {
            never,
            smime,
            all,
        };
    };

    // -------------------------------------------------------------------------
    // Calendar Sync
    // -------------------------------------------------------------------------

    pub fn syncCalendar(
        self: *Self,
        user_id: u64,
        device_id: []const u8,
        folder_id: []const u8,
        sync_key: u64,
    ) !SyncResponse {
        _ = user_id;

        if (!self.isDeviceProvisioned(device_id)) {
            return SyncResponse{
                .status = .sync_disabled,
                .sync_key = 0,
                .items = &.{},
                .more_available = false,
            };
        }

        if (sync_key == 0) {
            return SyncResponse{
                .status = .success,
                .sync_key = 1,
                .items = &.{},
                .more_available = false,
            };
        }

        _ = folder_id;

        return SyncResponse{
            .status = .success,
            .sync_key = sync_key + 1,
            .items = &.{},
            .more_available = false,
        };
    }

    // -------------------------------------------------------------------------
    // Contact Sync
    // -------------------------------------------------------------------------

    pub fn syncContacts(
        self: *Self,
        user_id: u64,
        device_id: []const u8,
        folder_id: []const u8,
        sync_key: u64,
    ) !SyncResponse {
        _ = user_id;

        if (!self.isDeviceProvisioned(device_id)) {
            return SyncResponse{
                .status = .sync_disabled,
                .sync_key = 0,
                .items = &.{},
                .more_available = false,
            };
        }

        if (sync_key == 0) {
            return SyncResponse{
                .status = .success,
                .sync_key = 1,
                .items = &.{},
                .more_available = false,
            };
        }

        _ = folder_id;

        return SyncResponse{
            .status = .success,
            .sync_key = sync_key + 1,
            .items = &.{},
            .more_available = false,
        };
    }

    // -------------------------------------------------------------------------
    // Folder Sync
    // -------------------------------------------------------------------------

    pub fn syncFolders(self: *Self, user_id: u64, device_id: []const u8, sync_key: u64) !FolderSyncResponse {
        _ = user_id;

        if (!self.isDeviceProvisioned(device_id)) {
            return FolderSyncResponse{
                .status = .sync_disabled,
                .sync_key = 0,
                .folders = &.{},
            };
        }

        if (sync_key == 0) {
            // Initial sync - return default folders
            return FolderSyncResponse{
                .status = .success,
                .sync_key = 1,
                .folders = &[_]Folder{
                    .{ .id = "inbox", .parent_id = "0", .display_name = "Inbox", .folder_type = .default_inbox },
                    .{ .id = "drafts", .parent_id = "0", .display_name = "Drafts", .folder_type = .default_drafts },
                    .{ .id = "sent", .parent_id = "0", .display_name = "Sent", .folder_type = .default_sent_items },
                    .{ .id = "trash", .parent_id = "0", .display_name = "Deleted Items", .folder_type = .default_deleted_items },
                    .{ .id = "calendar", .parent_id = "0", .display_name = "Calendar", .folder_type = .default_calendar },
                    .{ .id = "contacts", .parent_id = "0", .display_name = "Contacts", .folder_type = .default_contacts },
                },
            };
        }

        return FolderSyncResponse{
            .status = .success,
            .sync_key = sync_key + 1,
            .folders = &.{},
        };
    }

    pub const FolderSyncResponse = struct {
        status: SyncResponse.SyncStatus,
        sync_key: u64,
        folders: []const Folder,
    };

    // -------------------------------------------------------------------------
    // Meeting Response
    // -------------------------------------------------------------------------

    pub fn respondToMeeting(
        self: *Self,
        user_id: u64,
        device_id: []const u8,
        calendar_id: []const u8,
        response: MeetingResponse,
    ) !bool {
        _ = user_id;
        _ = calendar_id;
        _ = response;

        if (!self.isDeviceProvisioned(device_id)) {
            return false;
        }

        // In a real implementation, this would update the calendar event
        // and send a response to the organizer
        return true;
    }

    pub const MeetingResponse = enum {
        accepted,
        tentative,
        declined,
    };

    // -------------------------------------------------------------------------
    // Helper Functions
    // -------------------------------------------------------------------------

    fn isDeviceProvisioned(self: *Self, device_id: []const u8) bool {
        if (self.devices.get(device_id)) |device| {
            return device.status == .provisioned;
        }
        return false;
    }

    pub fn getDevice(self: *Self, device_id: []const u8) ?Device {
        return self.devices.get(device_id);
    }

    pub fn getUserDevices(self: *Self, user_id: u64) ![]Device {
        var result = std.ArrayList(Device).init(self.allocator);
        errdefer result.deinit();

        var iter = self.devices.valueIterator();
        while (iter.next()) |device| {
            if (device.user_id == user_id) {
                try result.append(device.*);
            }
        }

        return result.toOwnedSlice();
    }

    pub fn blockDevice(self: *Self, device_id: []const u8) !void {
        if (self.devices.getPtr(device_id)) |device| {
            device.status = .blocked;
        }
    }

    pub fn unblockDevice(self: *Self, device_id: []const u8) !void {
        if (self.devices.getPtr(device_id)) |device| {
            if (device.status == .blocked) {
                device.status = .provisioned;
            }
        }
    }
};

// =============================================================================
// Tests
// =============================================================================

test "device provisioning" {
    const allocator = std.testing.allocator;

    var engine = try SyncEngine.init(allocator, .{});
    defer engine.deinit();

    const response = try engine.provisionDevice("device-001", .{
        .user_id = 1,
        .model = "iPhone 15",
        .os = "iOS",
        .os_version = "17.0",
        .friendly_name = "John's iPhone",
        .user_agent = "Apple-iPhone15C2/1704.60",
        .protocol_version = "16.1",
    });

    try std.testing.expectEqual(SyncEngine.ProvisionResponse.ProvisionStatus.success, response.status);
    try std.testing.expect(response.policy_key != null);
}

test "folder sync" {
    const allocator = std.testing.allocator;

    var engine = try SyncEngine.init(allocator, .{});
    defer engine.deinit();

    // Provision device first
    _ = try engine.provisionDevice("device-001", .{
        .user_id = 1,
        .model = "iPhone 15",
        .os = "iOS",
        .os_version = "17.0",
        .friendly_name = null,
        .user_agent = "Apple-iPhone",
        .protocol_version = "16.1",
    });

    // Initial folder sync
    const response = try engine.syncFolders(1, "device-001", 0);

    try std.testing.expectEqual(SyncResponse.SyncStatus.success, response.status);
    try std.testing.expect(response.folders.len > 0);
}

test "device type detection" {
    try std.testing.expectEqual(Device.DeviceType.iphone, Device.DeviceType.fromUserAgent("Apple-iPhone15C2/1704.60"));
    try std.testing.expectEqual(Device.DeviceType.android_phone, Device.DeviceType.fromUserAgent("Android-Mobile/1.0"));
    try std.testing.expectEqual(Device.DeviceType.windows_pc, Device.DeviceType.fromUserAgent("Microsoft Windows NT 10.0"));
}

test "remote wipe" {
    const allocator = std.testing.allocator;

    var engine = try SyncEngine.init(allocator, .{});
    defer engine.deinit();

    _ = try engine.provisionDevice("device-001", .{
        .user_id = 1,
        .model = "Test",
        .os = "Test",
        .os_version = "1.0",
        .friendly_name = null,
        .user_agent = "Test",
        .protocol_version = "16.1",
    });

    // Request wipe
    const wipe_requested = try engine.requestRemoteWipe("device-001");
    try std.testing.expect(wipe_requested);

    // Check wipe pending
    try std.testing.expect(engine.isWipePending("device-001"));

    // Confirm wipe
    try engine.confirmWipe("device-001");
    try std.testing.expect(!engine.isWipePending("device-001"));
}
