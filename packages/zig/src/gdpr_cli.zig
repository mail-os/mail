const std = @import("std");
pub const gdpr = @import("features/gdpr.zig");
pub const env = @import("core/env.zig");
const fs_compat = @import("core/fs_compat.zig");

pub fn exportCommand(manager: *gdpr.GDPRManager, allocator: std.mem.Allocator, username: []const u8, output_file: ?[]const u8) !void {
    std.debug.print("Exporting data for user: {s}\n", .{username});

    // Log the data export access
    try manager.logDataAccess(username, "GDPR_DATA_EXPORT", "127.0.0.1");

    // Export user data
    var export_data = manager.exportUserData(username) catch |err| {
        std.debug.print("Error exporting data: {}\n", .{err});
        return err;
    };
    defer export_data.deinit();

    std.debug.print("Export complete:\n", .{});
    std.debug.print("  User: {s}\n", .{export_data.data.personal_info.username});
    std.debug.print("  Email: {s}\n", .{export_data.data.personal_info.email});
    std.debug.print("  Messages: {d}\n", .{export_data.data.messages.len});
    std.debug.print("  Activity records: {d}\n", .{export_data.data.activity.len});
    std.debug.print("  Total size: {d} bytes\n", .{export_data.data.metadata.total_size_bytes});

    // Write to file or stdout
    if (output_file) |path| {
        const file = fs_compat.cwd().createFile(path, .{}) catch |err| {
            std.debug.print("Error: Failed to create file {s}: {}\n", .{ path, err });
            return;
        };
        defer file.close();

        const json_str = try export_data.toJSONString(allocator);
        defer allocator.free(json_str);
        file.writeAll(json_str) catch |err| {
            std.debug.print("Error: Failed to write to {s}: {}\n", .{ path, err });
            return;
        };

        std.debug.print("\nData exported to: {s}\n", .{path});
    } else {
        const json_str = try export_data.toJSONString(allocator);
        defer allocator.free(json_str);
        std.debug.print("\nJSON Output:\n{s}\n", .{json_str});
    }

    std.debug.print("\nExport completed successfully\n", .{});
    std.debug.print("This export contains all personal data as required by GDPR Article 15.\n", .{});
}

pub fn deleteCommand(manager: *gdpr.GDPRManager, username: []const u8) !void {
    std.debug.print("WARNING: Deleting ALL data for user: {s}\n", .{username});
    std.debug.print("This action cannot be undone!\n", .{});
    std.debug.print("\nDeleting user data...\n", .{});

    // Log the data deletion
    try manager.logDataAccess(username, "GDPR_DATA_DELETION", "127.0.0.1");

    // Delete user data
    manager.deleteUserData(username) catch |err| {
        std.debug.print("Error deleting data: {}\n", .{err});
        return err;
    };

    std.debug.print("\nUser data deleted successfully\n", .{});
    std.debug.print("All personal data has been permanently removed as required by GDPR Article 17.\n", .{});
}

pub fn logCommand(manager: *gdpr.GDPRManager, username: []const u8, action: []const u8, ip_address: []const u8) !void {
    std.debug.print("Logging GDPR data access...\n", .{});
    std.debug.print("  User: {s}\n", .{username});
    std.debug.print("  Action: {s}\n", .{action});
    std.debug.print("  IP: {s}\n", .{ip_address});

    manager.logDataAccess(username, action, ip_address) catch |err| {
        std.debug.print("Error logging access: {}\n", .{err});
        return err;
    };

    std.debug.print("\nAccess logged successfully\n", .{});
    std.debug.print("This log entry will be retained as required by GDPR Article 30.\n", .{});
}
