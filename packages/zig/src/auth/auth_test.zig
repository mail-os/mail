const std = @import("std");
const testing = std.testing;
const auth = @import("auth.zig");
const database = @import("../storage/database.zig");
const password_mod = @import("password.zig");

test "AuthBackend init" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    var backend = auth.AuthBackend.init(allocator, &db);
    _ = backend;
}

test "AuthBackend createUser" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    var backend = auth.AuthBackend.init(allocator, &db);

    const user_id = try backend.createUser("testuser", "password123", "test@example.com");
    try testing.expect(user_id > 0);

    // Verify user was created in database
    var user = try db.getUserByUsername("testuser");
    defer user.deinit(allocator);

    try testing.expectEqualStrings("testuser", user.username);
    try testing.expectEqualStrings("test@example.com", user.email);
}

test "AuthBackend verifyCredentials success" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    var backend = auth.AuthBackend.init(allocator, &db);

    // Create user
    _ = try backend.createUser("testuser", "password123", "test@example.com");

    // Verify correct credentials
    const valid = try backend.verifyCredentials("testuser", "password123");
    try testing.expect(valid);
}

test "AuthBackend verifyCredentials wrong password" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    var backend = auth.AuthBackend.init(allocator, &db);

    // Create user
    _ = try backend.createUser("testuser", "password123", "test@example.com");

    // Verify wrong password
    const valid = try backend.verifyCredentials("testuser", "wrongpassword");
    try testing.expect(!valid);
}

test "AuthBackend verifyCredentials non-existent user" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    var backend = auth.AuthBackend.init(allocator, &db);

    // Verify non-existent user
    const valid = try backend.verifyCredentials("nonexistent", "password");
    try testing.expect(!valid);
}

test "AuthBackend verifyCredentials disabled user" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    var backend = auth.AuthBackend.init(allocator, &db);

    // Create user
    _ = try backend.createUser("testuser", "password123", "test@example.com");

    // Disable user
    try db.setUserEnabled("testuser", false);

    // Verify disabled user cannot authenticate
    const valid = try backend.verifyCredentials("testuser", "password123");
    try testing.expect(!valid);
}

test "AuthBackend changePassword" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    var backend = auth.AuthBackend.init(allocator, &db);

    // Create user
    _ = try backend.createUser("testuser", "oldpassword", "test@example.com");

    // Verify old password works
    try testing.expect(try backend.verifyCredentials("testuser", "oldpassword"));

    // Change password
    try backend.changePassword("testuser", "newpassword");

    // Verify old password no longer works
    try testing.expect(!try backend.verifyCredentials("testuser", "oldpassword"));

    // Verify new password works
    try testing.expect(try backend.verifyCredentials("testuser", "newpassword"));
}

test "AuthBackend changePassword non-existent user" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    var backend = auth.AuthBackend.init(allocator, &db);

    // Try to change password for non-existent user - should not error
    // (the database UPDATE will just affect 0 rows)
    try backend.changePassword("nonexistent", "newpassword");
}

test "decodeBase64Auth valid credentials" {
    const allocator = testing.allocator;

    // Base64 encode "\0testuser\0password123"
    const input = "\x00testuser\x00password123";
    const encoder = std.base64.standard.Encoder;

    var encoded: [100]u8 = undefined;
    const encoded_slice = encoder.encode(&encoded, input);

    const creds = try auth.decodeBase64Auth(allocator, encoded_slice);
    defer {
        allocator.free(creds.username);
        allocator.free(creds.password);
    }

    try testing.expectEqualStrings("testuser", creds.username);
    try testing.expectEqualStrings("password123", creds.password);
}

test "decodeBase64Auth empty password" {
    const allocator = testing.allocator;

    // Base64 encode "\0testuser\0"
    const input = "\x00testuser\x00";
    const encoder = std.base64.standard.Encoder;

    var encoded: [100]u8 = undefined;
    const encoded_slice = encoder.encode(&encoded, input);

    const creds = try auth.decodeBase64Auth(allocator, encoded_slice);
    defer {
        allocator.free(creds.username);
        allocator.free(creds.password);
    }

    try testing.expectEqualStrings("testuser", creds.username);
    try testing.expectEqualStrings("", creds.password);
}

test "decodeBase64Auth invalid format - missing password" {
    const allocator = testing.allocator;

    // Base64 encode "\0testuser" (no password separator)
    const input = "\x00testuser";
    const encoder = std.base64.standard.Encoder;

    var encoded: [100]u8 = undefined;
    const encoded_slice = encoder.encode(&encoded, input);

    const result = auth.decodeBase64Auth(allocator, encoded_slice);
    try testing.expectError(error.InvalidAuthFormat, result);
}

test "decodeBase64Auth invalid format - empty" {
    const allocator = testing.allocator;

    // Base64 encode empty string
    const input = "";
    const encoder = std.base64.standard.Encoder;

    var encoded: [100]u8 = undefined;
    const encoded_slice = encoder.encode(&encoded, input);

    const result = auth.decodeBase64Auth(allocator, encoded_slice);
    try testing.expectError(error.InvalidAuthFormat, result);
}

test "decodeBase64Auth invalid base64" {
    const allocator = testing.allocator;

    // Invalid base64 string
    const invalid_base64 = "!!!invalid!!!";

    const result = auth.decodeBase64Auth(allocator, invalid_base64);
    try testing.expectError(error.InvalidCharacter, result);
}

test "decodeBase64Auth special characters in username" {
    const allocator = testing.allocator;

    // Base64 encode "\0user-name_123\0pass"
    const input = "\x00user-name_123\x00pass";
    const encoder = std.base64.standard.Encoder;

    var encoded: [100]u8 = undefined;
    const encoded_slice = encoder.encode(&encoded, input);

    const creds = try auth.decodeBase64Auth(allocator, encoded_slice);
    defer {
        allocator.free(creds.username);
        allocator.free(creds.password);
    }

    try testing.expectEqualStrings("user-name_123", creds.username);
}

test "decodeBase64Auth special characters in password" {
    const allocator = testing.allocator;

    // Base64 encode "\0user\0p@ss!123#$%"
    const input = "\x00user\x00p@ss!123#$%";
    const encoder = std.base64.standard.Encoder;

    var encoded: [100]u8 = undefined;
    const encoded_slice = encoder.encode(&encoded, input);

    const creds = try auth.decodeBase64Auth(allocator, encoded_slice);
    defer {
        allocator.free(creds.username);
        allocator.free(creds.password);
    }

    try testing.expectEqualStrings("p@ss!123#$%", creds.password);
}

test "AuthBackend multiple users" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    var backend = auth.AuthBackend.init(allocator, &db);

    // Create multiple users
    _ = try backend.createUser("user1", "pass1", "user1@example.com");
    _ = try backend.createUser("user2", "pass2", "user2@example.com");
    _ = try backend.createUser("user3", "pass3", "user3@example.com");

    // Verify each user with correct password
    try testing.expect(try backend.verifyCredentials("user1", "pass1"));
    try testing.expect(try backend.verifyCredentials("user2", "pass2"));
    try testing.expect(try backend.verifyCredentials("user3", "pass3"));

    // Verify cross-password failures
    try testing.expect(!try backend.verifyCredentials("user1", "pass2"));
    try testing.expect(!try backend.verifyCredentials("user2", "pass3"));
    try testing.expect(!try backend.verifyCredentials("user3", "pass1"));
}

test "AuthBackend password hashing produces different hashes" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    var backend = auth.AuthBackend.init(allocator, &db);

    // Create two users with same password
    _ = try backend.createUser("user1", "samepassword", "user1@example.com");
    _ = try backend.createUser("user2", "samepassword", "user2@example.com");

    // Get users from database
    var user1 = try db.getUserByUsername("user1");
    defer user1.deinit(allocator);
    var user2 = try db.getUserByUsername("user2");
    defer user2.deinit(allocator);

    // Password hashes should be different (due to salt)
    try testing.expect(!std.mem.eql(u8, user1.password_hash, user2.password_hash));
}

test "AuthBackend empty username" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    var backend = auth.AuthBackend.init(allocator, &db);

    // Create user with empty username should work (database will handle it)
    _ = try backend.createUser("", "password", "test@example.com");

    // Verify with empty username
    try testing.expect(try backend.verifyCredentials("", "password"));
}

test "AuthBackend long password" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    var backend = auth.AuthBackend.init(allocator, &db);

    // Create user with very long password
    const long_password = "a" ** 1000;
    _ = try backend.createUser("testuser", long_password, "test@example.com");

    // Verify long password works
    try testing.expect(try backend.verifyCredentials("testuser", long_password));

    // Verify truncated password doesn't work
    const truncated = long_password[0..999];
    try testing.expect(!try backend.verifyCredentials("testuser", truncated));
}

test "AuthBackend unicode in username" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    var backend = auth.AuthBackend.init(allocator, &db);

    // Create user with unicode username
    _ = try backend.createUser("user_名前", "password", "test@example.com");

    // Verify unicode username works
    try testing.expect(try backend.verifyCredentials("user_名前", "password"));
}

test "AuthBackend unicode in password" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    var backend = auth.AuthBackend.init(allocator, &db);

    // Create user with unicode password
    _ = try backend.createUser("testuser", "パスワード", "test@example.com");

    // Verify unicode password works
    try testing.expect(try backend.verifyCredentials("testuser", "パスワード"));

    // Verify different unicode doesn't work
    try testing.expect(!try backend.verifyCredentials("testuser", "パスワー"));
}

test "AuthBackend case-sensitive usernames" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    var backend = auth.AuthBackend.init(allocator, &db);

    // Create user with specific case
    _ = try backend.createUser("TestUser", "password", "test@example.com");

    // Verify exact case works
    try testing.expect(try backend.verifyCredentials("TestUser", "password"));

    // Verify different case fails
    try testing.expect(!try backend.verifyCredentials("testuser", "password"));
    try testing.expect(!try backend.verifyCredentials("TESTUSER", "password"));
}

test "AuthBackend case-sensitive passwords" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    var backend = auth.AuthBackend.init(allocator, &db);

    // Create user with specific case password
    _ = try backend.createUser("testuser", "PassWord", "test@example.com");

    // Verify exact case works
    try testing.expect(try backend.verifyCredentials("testuser", "PassWord"));

    // Verify different case fails
    try testing.expect(!try backend.verifyCredentials("testuser", "password"));
    try testing.expect(!try backend.verifyCredentials("testuser", "PASSWORD"));
}

test "decodeBase64Auth with spaces" {
    const allocator = testing.allocator;

    // Base64 encode "\0test user\0pass word"
    const input = "\x00test user\x00pass word";
    const encoder = std.base64.standard.Encoder;

    var encoded: [100]u8 = undefined;
    const encoded_slice = encoder.encode(&encoded, input);

    const creds = try auth.decodeBase64Auth(allocator, encoded_slice);
    defer {
        allocator.free(creds.username);
        allocator.free(creds.password);
    }

    try testing.expectEqualStrings("test user", creds.username);
    try testing.expectEqualStrings("pass word", creds.password);
}

test "AuthBackend re-enable user after disable" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    var backend = auth.AuthBackend.init(allocator, &db);

    // Create user
    _ = try backend.createUser("testuser", "password", "test@example.com");

    // Verify works initially
    try testing.expect(try backend.verifyCredentials("testuser", "password"));

    // Disable user
    try db.setUserEnabled("testuser", false);
    try testing.expect(!try backend.verifyCredentials("testuser", "password"));

    // Re-enable user
    try db.setUserEnabled("testuser", true);
    try testing.expect(try backend.verifyCredentials("testuser", "password"));
}

test "AuthBackend createUser duplicate username" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    var backend = auth.AuthBackend.init(allocator, &db);

    // Create first user
    _ = try backend.createUser("testuser", "pass1", "test1@example.com");

    // Try to create user with same username
    const result = backend.createUser("testuser", "pass2", "test2@example.com");
    try testing.expectError(database.DatabaseError.AlreadyExists, result);
}

test "AuthBackend createUser duplicate email" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    var backend = auth.AuthBackend.init(allocator, &db);

    // Create first user
    _ = try backend.createUser("user1", "pass1", "same@example.com");

    // Try to create user with same email
    const result = backend.createUser("user2", "pass2", "same@example.com");
    try testing.expectError(database.DatabaseError.AlreadyExists, result);
}
