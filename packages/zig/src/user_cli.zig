const std = @import("std");
const database = @import("storage/database.zig");
const password_mod = @import("auth/password.zig");
const auth = @import("auth/auth.zig");

pub fn createUser(auth_backend: *auth.AuthBackend, username: []const u8, password: []const u8, email: []const u8) !void {
    const user_id = auth_backend.createUser(username, password, email) catch |err| {
        if (err == database.DatabaseError.AlreadyExists) {
            std.debug.print("Error: User '{s}' already exists\n", .{username});
            return;
        }
        return err;
    };

    std.debug.print("User created successfully!\n", .{});
    std.debug.print("  ID: {d}\n", .{user_id});
    std.debug.print("  Username: {s}\n", .{username});
    std.debug.print("  Email: {s}\n", .{email});
}

pub fn verifyUser(auth_backend: *auth.AuthBackend, username: []const u8, password: []const u8) !void {
    const valid = try auth_backend.verifyCredentials(username, password);

    if (valid) {
        std.debug.print("Credentials valid\n", .{});
    } else {
        std.debug.print("Credentials invalid\n", .{});
    }
}

pub fn changePassword(auth_backend: *auth.AuthBackend, username: []const u8, new_password: []const u8) !void {
    try auth_backend.changePassword(username, new_password);
    std.debug.print("Password changed successfully for user '{s}'\n", .{username});
}

pub fn deleteUser(db: *database.Database, username: []const u8) !void {
    try db.deleteUser(username);
    std.debug.print("User '{s}' deleted successfully\n", .{username});
}

pub fn setUserEnabled(db: *database.Database, username: []const u8, enabled: bool) !void {
    try db.setUserEnabled(username, enabled);
    const status = if (enabled) "enabled" else "disabled";
    std.debug.print("User '{s}' {s} successfully\n", .{ username, status });
}

pub fn userInfo(db: *database.Database, allocator: std.mem.Allocator, username: []const u8) !void {
    var user = db.getUserByUsername(username) catch |err| {
        if (err == database.DatabaseError.NotFound) {
            std.debug.print("User '{s}' not found\n", .{username});
            return;
        }
        return err;
    };
    defer user.deinit(allocator);

    std.debug.print("User Information:\n", .{});
    std.debug.print("  ID: {d}\n", .{user.id});
    std.debug.print("  Username: {s}\n", .{user.username});
    std.debug.print("  Email: {s}\n", .{user.email});
    std.debug.print("  Enabled: {}\n", .{user.enabled});
    std.debug.print("  Created: {d}\n", .{user.created_at});
    std.debug.print("  Updated: {d}\n", .{user.updated_at});
}
