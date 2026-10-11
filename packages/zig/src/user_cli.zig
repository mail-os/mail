const std = @import("std");
const database = @import("storage/database.zig");
const password_mod = @import("auth/password.zig");
const auth = @import("auth/auth.zig");
const recovery = @import("api/webmail_recovery.zig");
const time_compat = @import("core/time_compat.zig");

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
    if (try recovery.get(allocator, db, username)) |r| {
        defer if (r.address) |a| allocator.free(a);
        if (r.address) |address| {
            std.debug.print("  Recovery: {s} (set by {s})\n", .{ address, if (r.source) |source| @tagName(source) else "unknown" });
        } else std.debug.print("  Recovery: none\n", .{});
    }
}

pub const RecoveryAction = union(enum) {
    show,
    clear,
    apply: struct { address: []const u8, policy: recovery.Policy },
};

/// `user:local recovery`: show, set or clear a mailbox's recovery address.
///
/// Prints one `Recovery: <outcome>` line that deploy provisioning matches on:
/// `updated`, `unchanged`, `kept` (the owner set their own and the policy is
/// `initial`), `cleared`, or the current value for `show`. A missing mailbox
/// or an unusable address is an error, so the exit status is non-zero.
pub fn recoveryCommand(db: *database.Database, allocator: std.mem.Allocator, username: []const u8, action: RecoveryAction) !void {
    const current = (try recovery.get(allocator, db, username)) orelse {
        std.debug.print("Error: user '{s}' not found\n", .{username});
        return error.UserNotFound;
    };
    defer if (current.address) |a| allocator.free(a);
    const now = time_compat.timestamp();
    switch (action) {
        .show => if (current.address) |address| {
            std.debug.print("Recovery: {s} (set by {s})\n", .{ address, if (current.source) |source| @tagName(source) else "unknown" });
        } else std.debug.print("Recovery: none\n", .{}),
        .clear => {
            try recovery.set(db, username, null, .operator, now);
            std.debug.print("Recovery: cleared\n", .{});
        },
        .apply => |wanted| {
            const result = recovery.apply(allocator, db, username, wanted.address, wanted.policy, now) catch |err| {
                switch (err) {
                    recovery.RecoveryError.SameAsMailbox => std.debug.print("Error: a mailbox cannot be its own recovery address\n", .{}),
                    recovery.RecoveryError.InvalidAddress => std.debug.print("Error: '{s}' is not a usable recovery address\n", .{wanted.address}),
                    else => {},
                }
                return err;
            };
            switch (result) {
                .updated => std.debug.print("Recovery: updated\n", .{}),
                .unchanged => std.debug.print("Recovery: unchanged\n", .{}),
                .kept_owner_choice => std.debug.print("Recovery: kept (the mailbox owner set their own; use --policy managed to replace it)\n", .{}),
            }
        },
    }
}
