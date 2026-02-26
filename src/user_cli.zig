const std = @import("std");
const database = @import("storage/database.zig");
const password_mod = @import("auth/password.zig");
const auth = @import("auth/auth.zig");
const env = @import("core/env.zig");

pub fn main(init: std.process.Init) !void {
    const io_compat = @import("core/io_compat.zig");
    io_compat.initIo(init.io);

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const args = try init.minimal.args.toSlice(arena.allocator());

    if (args.len < 2) {
        try printUsage();
        return;
    }

    const db_path = env.get("SMTP_DB_PATH") orelse "./smtp.db";

    var db = try database.Database.init(allocator, db_path);
    defer db.deinit();

    var auth_backend = auth.AuthBackend.init(allocator, &db);

    const command = args[1];

    if (std.mem.eql(u8, command, "create")) {
        if (args.len != 5) {
            std.debug.print("Usage: user-cli create <username> <password> <email>\n", .{});
            return;
        }
        try createUser(&auth_backend, args[2], args[3], args[4]);
    } else if (std.mem.eql(u8, command, "verify")) {
        if (args.len != 4) {
            std.debug.print("Usage: user-cli verify <username> <password>\n", .{});
            return;
        }
        try verifyUser(&auth_backend, args[2], args[3]);
    } else if (std.mem.eql(u8, command, "change-password")) {
        if (args.len != 4) {
            std.debug.print("Usage: user-cli change-password <username> <new_password>\n", .{});
            return;
        }
        try changePassword(&auth_backend, args[2], args[3]);
    } else if (std.mem.eql(u8, command, "delete")) {
        if (args.len != 3) {
            std.debug.print("Usage: user-cli delete <username>\n", .{});
            return;
        }
        try deleteUser(&db, args[2]);
    } else if (std.mem.eql(u8, command, "disable")) {
        if (args.len != 3) {
            std.debug.print("Usage: user-cli disable <username>\n", .{});
            return;
        }
        try setUserEnabled(&db, args[2], false);
    } else if (std.mem.eql(u8, command, "enable")) {
        if (args.len != 3) {
            std.debug.print("Usage: user-cli enable <username>\n", .{});
            return;
        }
        try setUserEnabled(&db, args[2], true);
    } else if (std.mem.eql(u8, command, "info")) {
        if (args.len != 3) {
            std.debug.print("Usage: user-cli info <username>\n", .{});
            return;
        }
        try userInfo(&db, allocator, args[2]);
    } else {
        try printUsage();
    }
}

fn printUsage() !void {
    const usage =
        \\SMTP User Management CLI
        \\
        \\Usage: user-cli <command> [args]
        \\
        \\Commands:
        \\  create <username> <password> <email>  Create a new user
        \\  verify <username> <password>          Verify user credentials
        \\  change-password <username> <password> Change user password
        \\  delete <username>                     Delete a user
        \\  disable <username>                    Disable a user account
        \\  enable <username>                     Enable a user account
        \\  info <username>                       Show user information
        \\
        \\Environment Variables:
        \\  SMTP_DB_PATH    Path to SQLite database (default: ./smtp.db)
        \\
    ;
    std.debug.print("{s}\n", .{usage});
}

fn createUser(auth_backend: *auth.AuthBackend, username: []const u8, password: []const u8, email: []const u8) !void {
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

fn verifyUser(auth_backend: *auth.AuthBackend, username: []const u8, password: []const u8) !void {
    const valid = try auth_backend.verifyCredentials(username, password);

    if (valid) {
        std.debug.print("✓ Credentials valid\n", .{});
    } else {
        std.debug.print("✗ Credentials invalid\n", .{});
    }
}

fn changePassword(auth_backend: *auth.AuthBackend, username: []const u8, new_password: []const u8) !void {
    try auth_backend.changePassword(username, new_password);
    std.debug.print("Password changed successfully for user '{s}'\n", .{username});
}

fn deleteUser(db: *database.Database, username: []const u8) !void {
    try db.deleteUser(username);
    std.debug.print("User '{s}' deleted successfully\n", .{username});
}

fn setUserEnabled(db: *database.Database, username: []const u8, enabled: bool) !void {
    try db.setUserEnabled(username, enabled);
    const status = if (enabled) "enabled" else "disabled";
    std.debug.print("User '{s}' {s} successfully\n", .{ username, status });
}

fn userInfo(db: *database.Database, allocator: std.mem.Allocator, username: []const u8) !void {
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
