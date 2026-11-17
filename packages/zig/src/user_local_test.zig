const std = @import("std");
const database = @import("storage/database.zig");
const auth = @import("auth/auth.zig");
const user_local = @import("cli/user_local.zig");
const replacePassword = user_local.replacePassword;

test "a deploy without --force cannot replace a mailbox's password" {
    const allocator = std.testing.allocator;
    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();
    var backend = auth.AuthBackend.init(allocator, &db);
    defer backend.deinit();

    _ = try backend.createUser("chris@example.com", "the-owners-password", "chris@example.com");

    try std.testing.expectError(error.PasswordReplaceRefused, replacePassword(&backend, "chris@example.com", "another-apps-password", false));
    try std.testing.expect(try backend.verifyCredentials("chris@example.com", "the-owners-password"));
    try std.testing.expect(!try backend.verifyCredentials("chris@example.com", "another-apps-password"));
}

test "an operator's --force replaces it" {
    const allocator = std.testing.allocator;
    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();
    var backend = auth.AuthBackend.init(allocator, &db);
    defer backend.deinit();

    _ = try backend.createUser("chris@example.com", "forgotten", "chris@example.com");

    try replacePassword(&backend, "chris@example.com", "reset-on-purpose", true);
    try std.testing.expect(try backend.verifyCredentials("chris@example.com", "reset-on-purpose"));
    try std.testing.expect(!try backend.verifyCredentials("chris@example.com", "forgotten"));
}
