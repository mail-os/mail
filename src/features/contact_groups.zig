const std = @import("std");

// =============================================================================
// Contact Groups / Distribution Lists
// =============================================================================
//
// ## Overview
// Allows users to create and manage groups of contacts for bulk email sending.
// Groups can be nested and support various member types.
//
// ## Features
// - Create/edit/delete contact groups
// - Add/remove members
// - Nested groups
// - Import from other groups
// - Quick expansion for compose
//
// =============================================================================

/// Contact group errors
pub const GroupError = error{
    GroupNotFound,
    MemberNotFound,
    DuplicateMember,
    CircularReference,
    GroupFull,
    InvalidEmail,
    OutOfMemory,
};

/// Contact group member types
pub const MemberType = enum {
    /// Individual email address
    email,
    /// Reference to another group
    group,

    pub fn toString(self: MemberType) []const u8 {
        return switch (self) {
            .email => "Email",
            .group => "Group",
        };
    }
};

/// Contact group member
pub const GroupMember = struct {
    /// Member ID
    id: []const u8,
    /// Display name
    name: ?[]const u8,
    /// Email address (if type is email)
    email: ?[]const u8,
    /// Group ID (if type is group)
    group_id: ?[]const u8,
    /// Member type
    member_type: MemberType,
    /// When added
    added_at: i64,

    pub fn toJson(self: *const GroupMember, allocator: std.mem.Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        errdefer buffer.deinit();
        const writer = buffer.writer();

        try writer.writeAll("{");
        try writer.print("\"id\":\"{s}\",", .{self.id});
        try writer.print("\"type\":\"{s}\",", .{self.member_type.toString()});

        if (self.name) |n| {
            try writer.print("\"name\":\"{s}\",", .{escapeJson(n)});
        } else {
            try writer.writeAll("\"name\":null,");
        }

        if (self.email) |e| {
            try writer.print("\"email\":\"{s}\",", .{e});
        } else {
            try writer.writeAll("\"email\":null,");
        }

        if (self.group_id) |g| {
            try writer.print("\"group_id\":\"{s}\",", .{g});
        } else {
            try writer.writeAll("\"group_id\":null,");
        }

        try writer.print("\"added_at\":{d}", .{self.added_at});
        try writer.writeAll("}");

        return buffer.toOwnedSlice();
    }
};

/// Contact group
pub const ContactGroup = struct {
    /// Unique group ID
    id: []const u8,
    /// Group name
    name: []const u8,
    /// Description
    description: ?[]const u8,
    /// Group color (for UI)
    color: ?[]const u8,
    /// Members
    members: std.ArrayList(GroupMember),
    /// Is this a system group
    is_system: bool,
    /// When created
    created_at: i64,
    /// When last modified
    updated_at: i64,
    /// Allocator reference
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, id: []const u8, name: []const u8) !ContactGroup {
        return .{
            .id = try allocator.dupe(u8, id),
            .name = try allocator.dupe(u8, name),
            .description = null,
            .color = null,
            .members = std.ArrayList(GroupMember).init(allocator),
            .is_system = false,
            .created_at = std.time.timestamp(),
            .updated_at = std.time.timestamp(),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ContactGroup) void {
        self.allocator.free(self.id);
        self.allocator.free(self.name);
        if (self.description) |d| self.allocator.free(d);
        if (self.color) |c| self.allocator.free(c);

        for (self.members.items) |member| {
            self.allocator.free(member.id);
            if (member.name) |n| self.allocator.free(n);
            if (member.email) |e| self.allocator.free(e);
            if (member.group_id) |g| self.allocator.free(g);
        }
        self.members.deinit();
    }

    /// Add an email member
    pub fn addEmail(self: *ContactGroup, email: []const u8, name: ?[]const u8) !void {
        // Check for duplicates
        for (self.members.items) |member| {
            if (member.email) |e| {
                if (std.mem.eql(u8, e, email)) {
                    return GroupError.DuplicateMember;
                }
            }
        }

        var rand_bytes: [4]u8 = undefined;
        std.c.arc4random_buf(&rand_bytes, rand_bytes.len);

        const member = GroupMember{
            .id = try std.fmt.allocPrint(self.allocator, "mem_{x}", .{std.mem.readInt(u32, &rand_bytes, .big)}),
            .name = if (name) |n| try self.allocator.dupe(u8, n) else null,
            .email = try self.allocator.dupe(u8, email),
            .group_id = null,
            .member_type = .email,
            .added_at = std.time.timestamp(),
        };

        try self.members.append(member);
        self.updated_at = std.time.timestamp();
    }

    /// Add a group reference
    pub fn addGroup(self: *ContactGroup, group_id: []const u8, group_name: []const u8) !void {
        // Check for circular reference (self)
        if (std.mem.eql(u8, group_id, self.id)) {
            return GroupError.CircularReference;
        }

        // Check for duplicates
        for (self.members.items) |member| {
            if (member.group_id) |g| {
                if (std.mem.eql(u8, g, group_id)) {
                    return GroupError.DuplicateMember;
                }
            }
        }

        var rand_bytes: [4]u8 = undefined;
        std.c.arc4random_buf(&rand_bytes, rand_bytes.len);

        const member = GroupMember{
            .id = try std.fmt.allocPrint(self.allocator, "mem_{x}", .{std.mem.readInt(u32, &rand_bytes, .big)}),
            .name = try self.allocator.dupe(u8, group_name),
            .email = null,
            .group_id = try self.allocator.dupe(u8, group_id),
            .member_type = .group,
            .added_at = std.time.timestamp(),
        };

        try self.members.append(member);
        self.updated_at = std.time.timestamp();
    }

    /// Remove a member
    pub fn removeMember(self: *ContactGroup, member_id: []const u8) !void {
        var found_index: ?usize = null;
        for (self.members.items, 0..) |member, i| {
            if (std.mem.eql(u8, member.id, member_id)) {
                found_index = i;
                break;
            }
        }

        if (found_index) |idx| {
            const member = self.members.orderedRemove(idx);
            self.allocator.free(member.id);
            if (member.name) |n| self.allocator.free(n);
            if (member.email) |e| self.allocator.free(e);
            if (member.group_id) |g| self.allocator.free(g);
            self.updated_at = std.time.timestamp();
        } else {
            return GroupError.MemberNotFound;
        }
    }

    /// Get member count (direct only)
    pub fn getMemberCount(self: *const ContactGroup) usize {
        return self.members.items.len;
    }

    /// Get email count (direct only)
    pub fn getEmailCount(self: *const ContactGroup) usize {
        var count: usize = 0;
        for (self.members.items) |member| {
            if (member.member_type == .email) count += 1;
        }
        return count;
    }

    /// Convert to JSON
    pub fn toJson(self: *const ContactGroup, allocator: std.mem.Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        errdefer buffer.deinit();
        const writer = buffer.writer();

        try writer.writeAll("{");
        try writer.print("\"id\":\"{s}\",", .{self.id});
        try writer.print("\"name\":\"{s}\",", .{escapeJson(self.name)});

        if (self.description) |d| {
            try writer.print("\"description\":\"{s}\",", .{escapeJson(d)});
        } else {
            try writer.writeAll("\"description\":null,");
        }

        if (self.color) |c| {
            try writer.print("\"color\":\"{s}\",", .{c});
        } else {
            try writer.writeAll("\"color\":null,");
        }

        try writer.print("\"member_count\":{d},", .{self.getMemberCount()});
        try writer.print("\"email_count\":{d},", .{self.getEmailCount()});
        try writer.print("\"is_system\":{s},", .{if (self.is_system) "true" else "false"});
        try writer.print("\"created_at\":{d},", .{self.created_at});
        try writer.print("\"updated_at\":{d},", .{self.updated_at});

        // Members
        try writer.writeAll("\"members\":[");
        for (self.members.items, 0..) |*member, i| {
            if (i > 0) try writer.writeAll(",");
            const json = try member.toJson(allocator);
            defer allocator.free(json);
            try writer.writeAll(json);
        }
        try writer.writeAll("]}");

        return buffer.toOwnedSlice();
    }
};

/// Contact group manager
pub const ContactGroupManager = struct {
    allocator: std.mem.Allocator,
    groups: std.StringHashMap(*ContactGroup),
    config: GroupConfig,

    pub const GroupConfig = struct {
        /// Maximum number of groups
        max_groups: usize = 50,
        /// Maximum members per group
        max_members_per_group: usize = 500,
        /// Maximum nesting depth
        max_nesting_depth: usize = 3,
    };

    pub fn init(allocator: std.mem.Allocator, config: GroupConfig) ContactGroupManager {
        return .{
            .allocator = allocator,
            .groups = std.StringHashMap(*ContactGroup).init(allocator),
            .config = config,
        };
    }

    pub fn deinit(self: *ContactGroupManager) void {
        var it = self.groups.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.groups.deinit();
    }

    /// Create a new group
    pub fn create(self: *ContactGroupManager, name: []const u8, description: ?[]const u8) ![]const u8 {
        if (self.groups.count() >= self.config.max_groups) {
            return GroupError.GroupFull;
        }

        var rand_bytes: [8]u8 = undefined;
        std.c.arc4random_buf(&rand_bytes, rand_bytes.len);
        const timestamp = std.time.timestamp();

        const id = try std.fmt.allocPrint(self.allocator, "grp_{x}_{x}", .{
            @as(u64, @intCast(timestamp)),
            std.mem.readInt(u64, &rand_bytes, .big),
        });
        errdefer self.allocator.free(id);

        const group = try self.allocator.create(ContactGroup);
        group.* = try ContactGroup.init(self.allocator, id, name);

        if (description) |d| {
            group.description = try self.allocator.dupe(u8, d);
        }

        const key = try self.allocator.dupe(u8, id);
        try self.groups.put(key, group);

        return id;
    }

    /// Get group by ID
    pub fn get(self: *const ContactGroupManager, id: []const u8) ?*ContactGroup {
        return self.groups.get(id);
    }

    /// Delete a group
    pub fn delete(self: *ContactGroupManager, id: []const u8) !void {
        if (self.groups.fetchRemove(id)) |entry| {
            self.allocator.free(entry.key);
            entry.value.deinit();
            self.allocator.destroy(entry.value);
        } else {
            return GroupError.GroupNotFound;
        }
    }

    /// List all groups
    pub fn list(self: *const ContactGroupManager, allocator: std.mem.Allocator) ![]*ContactGroup {
        var result = try allocator.alloc(*ContactGroup, self.groups.count());
        var i: usize = 0;

        var it = self.groups.iterator();
        while (it.next()) |entry| {
            result[i] = entry.value_ptr.*;
            i += 1;
        }

        return result;
    }

    /// Expand group to list of emails (resolves nested groups)
    pub fn expandGroup(self: *const ContactGroupManager, group_id: []const u8, allocator: std.mem.Allocator) ![]const u8 {
        const group = self.groups.get(group_id) orelse return GroupError.GroupNotFound;

        var emails = std.ArrayList([]const u8).init(allocator);
        defer {
            for (emails.items) |e| allocator.free(e);
            emails.deinit();
        }

        try self.expandGroupRecursive(group, &emails, allocator, 0);

        // Join with commas
        if (emails.items.len == 0) return try allocator.dupe(u8, "");

        var total_len: usize = 0;
        for (emails.items) |e| {
            total_len += e.len + 2; // ", "
        }

        var result = try allocator.alloc(u8, total_len);
        var pos: usize = 0;

        for (emails.items, 0..) |e, i| {
            if (i > 0) {
                @memcpy(result[pos .. pos + 2], ", ");
                pos += 2;
            }
            @memcpy(result[pos .. pos + e.len], e);
            pos += e.len;
        }

        return result[0..pos];
    }

    fn expandGroupRecursive(
        self: *const ContactGroupManager,
        group: *ContactGroup,
        emails: *std.ArrayList([]const u8),
        allocator: std.mem.Allocator,
        depth: usize,
    ) !void {
        if (depth >= self.config.max_nesting_depth) return;

        for (group.members.items) |member| {
            if (member.member_type == .email) {
                if (member.email) |e| {
                    // Check for duplicates
                    var exists = false;
                    for (emails.items) |existing| {
                        if (std.mem.eql(u8, existing, e)) {
                            exists = true;
                            break;
                        }
                    }
                    if (!exists) {
                        try emails.append(try allocator.dupe(u8, e));
                    }
                }
            } else if (member.member_type == .group) {
                if (member.group_id) |gid| {
                    if (self.groups.get(gid)) |nested| {
                        try self.expandGroupRecursive(nested, emails, allocator, depth + 1);
                    }
                }
            }
        }
    }

    /// Update group name/description
    pub fn update(self: *ContactGroupManager, id: []const u8, name: ?[]const u8, description: ?[]const u8) !void {
        const group = self.groups.get(id) orelse return GroupError.GroupNotFound;

        if (name) |n| {
            self.allocator.free(group.name);
            group.name = try self.allocator.dupe(u8, n);
        }

        if (description) |d| {
            if (group.description) |old| self.allocator.free(old);
            group.description = try self.allocator.dupe(u8, d);
        }

        group.updated_at = std.time.timestamp();
    }

    /// Set group color
    pub fn setColor(self: *ContactGroupManager, id: []const u8, color: []const u8) !void {
        const group = self.groups.get(id) orelse return GroupError.GroupNotFound;

        if (group.color) |old| self.allocator.free(old);
        group.color = try self.allocator.dupe(u8, color);
        group.updated_at = std.time.timestamp();
    }

    /// Get statistics
    pub fn getStats(self: *const ContactGroupManager) GroupStats {
        var total_members: usize = 0;
        var total_emails: usize = 0;

        var it = self.groups.iterator();
        while (it.next()) |entry| {
            total_members += entry.value_ptr.*.getMemberCount();
            total_emails += entry.value_ptr.*.getEmailCount();
        }

        return .{
            .total_groups = self.groups.count(),
            .total_members = total_members,
            .total_emails = total_emails,
        };
    }
};

/// Group statistics
pub const GroupStats = struct {
    total_groups: usize,
    total_members: usize,
    total_emails: usize,
};

/// Validate email format (basic)
pub fn isValidEmail(email: []const u8) bool {
    if (email.len < 3) return false;
    const at_pos = std.mem.indexOf(u8, email, "@") orelse return false;
    if (at_pos == 0 or at_pos == email.len - 1) return false;
    const dot_pos = std.mem.lastIndexOf(u8, email, ".") orelse return false;
    if (dot_pos <= at_pos + 1 or dot_pos == email.len - 1) return false;
    return true;
}

fn escapeJson(s: []const u8) []const u8 {
    return s;
}

// =============================================================================
// Tests
// =============================================================================

test "ContactGroup add and remove members" {
    const allocator = std.testing.allocator;

    var group = try ContactGroup.init(allocator, "test_group", "Test Group");
    defer group.deinit();

    try group.addEmail("alice@example.com", "Alice");
    try group.addEmail("bob@example.com", "Bob");

    try std.testing.expectEqual(@as(usize, 2), group.getMemberCount());
    try std.testing.expectEqual(@as(usize, 2), group.getEmailCount());

    // Remove first member
    try group.removeMember(group.members.items[0].id);
    try std.testing.expectEqual(@as(usize, 1), group.getMemberCount());
}

test "ContactGroupManager create and expand" {
    const allocator = std.testing.allocator;

    var manager = ContactGroupManager.init(allocator, .{});
    defer manager.deinit();

    const id = try manager.create("Team", "Development team");
    const group = manager.get(id).?;

    try group.addEmail("dev1@example.com", "Dev 1");
    try group.addEmail("dev2@example.com", "Dev 2");

    const expanded = try manager.expandGroup(id, allocator);
    defer allocator.free(expanded);

    try std.testing.expect(std.mem.indexOf(u8, expanded, "dev1@example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, expanded, "dev2@example.com") != null);
}

test "ContactGroup duplicate rejection" {
    const allocator = std.testing.allocator;

    var group = try ContactGroup.init(allocator, "test", "Test");
    defer group.deinit();

    try group.addEmail("test@example.com", null);
    const result = group.addEmail("test@example.com", null);
    try std.testing.expectError(GroupError.DuplicateMember, result);
}

test "isValidEmail" {
    try std.testing.expect(isValidEmail("test@example.com"));
    try std.testing.expect(isValidEmail("a@b.c"));
    try std.testing.expect(!isValidEmail("invalid"));
    try std.testing.expect(!isValidEmail("@example.com"));
    try std.testing.expect(!isValidEmail("test@"));
}
