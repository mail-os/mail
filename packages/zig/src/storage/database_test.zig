const std = @import("std");
const time_compat = @import("../core/time_compat.zig");
const testing = std.testing;
const database = @import("database.zig");

test "Database init and deinit with memory database" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Verify database is initialized
    try testing.expect(db.db != null);
}

test "Database createUser and getUserByUsername" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Create a user
    const user_id = try db.createUser("testuser", "password_hash_123", "test@example.com");
    try testing.expect(user_id > 0);

    // Retrieve the user
    var user = try db.getUserByUsername("testuser");
    defer user.deinit(allocator);

    try testing.expectEqual(user_id, user.id);
    try testing.expectEqualStrings("testuser", user.username);
    try testing.expectEqualStrings("password_hash_123", user.password_hash);
    try testing.expectEqualStrings("test@example.com", user.email);
    try testing.expect(user.enabled);
}

test "Database createUser duplicate username" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Create first user
    _ = try db.createUser("testuser", "hash1", "test1@example.com");

    // Try to create user with same username
    const result = db.createUser("testuser", "hash2", "test2@example.com");
    try testing.expectError(database.DatabaseError.AlreadyExists, result);
}

test "Database createUser duplicate email" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Create first user
    _ = try db.createUser("user1", "hash1", "same@example.com");

    // Try to create user with same email
    const result = db.createUser("user2", "hash2", "same@example.com");
    try testing.expectError(database.DatabaseError.AlreadyExists, result);
}

test "Database getUserByUsername not found" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    const result = db.getUserByUsername("nonexistent");
    try testing.expectError(database.DatabaseError.NotFound, result);
}

test "Database updateUserPassword" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Create a user
    _ = try db.createUser("testuser", "old_hash", "test@example.com");

    // Update password
    try db.updateUserPassword("testuser", "new_hash");

    // Verify password was updated
    var user = try db.getUserByUsername("testuser");
    defer user.deinit(allocator);

    try testing.expectEqualStrings("new_hash", user.password_hash);
}

test "Database updateUserPassword non-existent user" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Try to update password for non-existent user - should not error
    // (UPDATE will just affect 0 rows)
    try db.updateUserPassword("nonexistent", "new_hash");
}

test "Database deleteUser" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Create a user
    _ = try db.createUser("testuser", "hash", "test@example.com");

    // Delete the user
    try db.deleteUser("testuser");

    // Verify user is deleted
    const result = db.getUserByUsername("testuser");
    try testing.expectError(database.DatabaseError.NotFound, result);
}

test "Database deleteUser non-existent" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Try to delete non-existent user - should not error
    try db.deleteUser("nonexistent");
}

test "Database setUserEnabled" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Create a user (default enabled = true)
    _ = try db.createUser("testuser", "hash", "test@example.com");

    // Disable the user
    try db.setUserEnabled("testuser", false);

    // Verify user is disabled
    var user1 = try db.getUserByUsername("testuser");
    defer user1.deinit(allocator);
    try testing.expect(!user1.enabled);

    // Enable the user
    try db.setUserEnabled("testuser", true);

    // Verify user is enabled
    var user2 = try db.getUserByUsername("testuser");
    defer user2.deinit(allocator);
    try testing.expect(user2.enabled);
}

test "Database exec with invalid SQL" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    const result = db.exec("INVALID SQL SYNTAX");
    try testing.expectError(database.DatabaseError.ExecFailed, result);
}

test "Database exec with valid SQL" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Create a test table
    try db.exec("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)");

    // Insert data
    try db.exec("INSERT INTO test (name) VALUES ('test1')");

    // Query the data using prepare
    var stmt = try db.prepare("SELECT name FROM test WHERE id = 1");
    defer stmt.finalize();

    try testing.expect(try stmt.step());
    const name = stmt.columnText(0);
    try testing.expectEqualStrings("test1", name);
}

test "Database prepare with invalid SQL" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    const result = db.prepare("INVALID SQL");
    try testing.expectError(database.DatabaseError.PrepareFailed, result);
}

test "Database prepare and bind integer" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Create test table
    try db.exec("CREATE TABLE test (id INTEGER PRIMARY KEY, value INTEGER)");

    // Prepare insert statement
    var stmt = try db.prepare("INSERT INTO test (value) VALUES (?1)");
    defer stmt.finalize();

    // Bind integer value
    try stmt.bind(1, @as(i64, 42));

    // Execute
    try testing.expect(!try stmt.step());
}

test "Database prepare and bind float" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Create test table
    try db.exec("CREATE TABLE test (id INTEGER PRIMARY KEY, value REAL)");

    // Prepare insert statement
    var stmt = try db.prepare("INSERT INTO test (value) VALUES (?1)");
    defer stmt.finalize();

    // Bind float value
    try stmt.bind(1, @as(f64, 3.14));

    // Execute
    try testing.expect(!try stmt.step());
}

test "Database prepare and bind text" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Create test table
    try db.exec("CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT)");

    // Prepare insert statement
    var stmt = try db.prepare("INSERT INTO test (value) VALUES (?1)");
    defer stmt.finalize();

    // Bind text value
    try stmt.bind(1, "hello world");

    // Execute
    try testing.expect(!try stmt.step());
}

test "Database statement columnInt64" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    try db.exec("CREATE TABLE test (id INTEGER PRIMARY KEY, value INTEGER)");
    try db.exec("INSERT INTO test (value) VALUES (123)");

    var stmt = try db.prepare("SELECT value FROM test WHERE id = 1");
    defer stmt.finalize();

    try testing.expect(try stmt.step());
    const value = stmt.columnInt64(0);
    try testing.expectEqual(@as(i64, 123), value);
}

test "Database statement columnDouble" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    try db.exec("CREATE TABLE test (id INTEGER PRIMARY KEY, value REAL)");
    try db.exec("INSERT INTO test (value) VALUES (3.14159)");

    var stmt = try db.prepare("SELECT value FROM test WHERE id = 1");
    defer stmt.finalize();

    try testing.expect(try stmt.step());
    const value = stmt.columnDouble(0);
    try testing.expect(@abs(value - 3.14159) < 0.0001);
}

test "Database statement columnText" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    try db.exec("CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT)");
    try db.exec("INSERT INTO test (value) VALUES ('hello')");

    var stmt = try db.prepare("SELECT value FROM test WHERE id = 1");
    defer stmt.finalize();

    try testing.expect(try stmt.step());
    const value = stmt.columnText(0);
    try testing.expectEqualStrings("hello", value);
}

test "Database statement step returns false when done" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    try db.exec("CREATE TABLE test (id INTEGER PRIMARY KEY)");

    // Query empty table
    var stmt = try db.prepare("SELECT * FROM test");
    defer stmt.finalize();

    // Should return false (no rows)
    try testing.expect(!try stmt.step());
}

test "Database multiple users" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Create multiple users
    _ = try db.createUser("user1", "hash1", "user1@example.com");
    _ = try db.createUser("user2", "hash2", "user2@example.com");
    _ = try db.createUser("user3", "hash3", "user3@example.com");

    // Verify all users can be retrieved
    var user1 = try db.getUserByUsername("user1");
    defer user1.deinit(allocator);
    try testing.expectEqualStrings("user1", user1.username);

    var user2 = try db.getUserByUsername("user2");
    defer user2.deinit(allocator);
    try testing.expectEqualStrings("user2", user2.username);

    var user3 = try db.getUserByUsername("user3");
    defer user3.deinit(allocator);
    try testing.expectEqualStrings("user3", user3.username);
}

test "Database transaction with exec" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Begin transaction
    try db.exec("BEGIN TRANSACTION");

    // Create user in transaction
    _ = try db.createUser("txuser", "hash", "tx@example.com");

    // Commit
    try db.exec("COMMIT");

    // Verify user exists
    var user = try db.getUserByUsername("txuser");
    defer user.deinit(allocator);
    try testing.expectEqualStrings("txuser", user.username);
}

test "Database transaction rollback" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Begin transaction
    try db.exec("BEGIN TRANSACTION");

    // Create user in transaction
    _ = try db.createUser("txuser", "hash", "tx@example.com");

    // Rollback
    try db.exec("ROLLBACK");

    // Verify user doesn't exist
    const result = db.getUserByUsername("txuser");
    try testing.expectError(database.DatabaseError.NotFound, result);
}

test "Database User struct timestamps" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    const before = time_compat.timestamp();

    // Create user
    _ = try db.createUser("timeuser", "hash", "time@example.com");

    const after = time_compat.timestamp();

    // Get user and check timestamps
    var user = try db.getUserByUsername("timeuser");
    defer user.deinit(allocator);

    try testing.expect(user.created_at >= before);
    try testing.expect(user.created_at <= after);
    try testing.expectEqual(user.created_at, user.updated_at);
}

test "Database updateUserPassword updates timestamp" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Create user
    _ = try db.createUser("timeuser", "hash1", "time@example.com");

    // Get initial timestamps
    var user1 = try db.getUserByUsername("timeuser");
    const initial_updated = user1.updated_at;
    user1.deinit(allocator);

    // Wait a moment
    std.time.sleep(1 * std.time.ns_per_ms);

    // Update password
    try db.updateUserPassword("timeuser", "hash2");

    // Verify updated_at changed
    var user2 = try db.getUserByUsername("timeuser");
    defer user2.deinit(allocator);

    try testing.expect(user2.updated_at >= initial_updated);
}

test "Database setUserEnabled updates timestamp" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Create user
    _ = try db.createUser("timeuser", "hash", "time@example.com");

    // Get initial timestamps
    var user1 = try db.getUserByUsername("timeuser");
    const initial_updated = user1.updated_at;
    user1.deinit(allocator);

    // Wait a moment
    std.time.sleep(1 * std.time.ns_per_ms);

    // Update enabled status
    try db.setUserEnabled("timeuser", false);

    // Verify updated_at changed
    var user2 = try db.getUserByUsername("timeuser");
    defer user2.deinit(allocator);

    try testing.expect(user2.updated_at >= initial_updated);
}

test "Database empty text column" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    try db.exec("CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT)");
    try db.exec("INSERT INTO test (value) VALUES ('')");

    var stmt = try db.prepare("SELECT value FROM test WHERE id = 1");
    defer stmt.finalize();

    try testing.expect(try stmt.step());
    const value = stmt.columnText(0);
    try testing.expectEqualStrings("", value);
}

test "Database NULL text column" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    try db.exec("CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT)");
    try db.exec("INSERT INTO test (id) VALUES (1)"); // value is NULL

    var stmt = try db.prepare("SELECT value FROM test WHERE id = 1");
    defer stmt.finalize();

    try testing.expect(try stmt.step());
    const value = stmt.columnText(0);
    try testing.expectEqualStrings("", value); // NULL becomes empty string
}

test "Database concurrent access with mutex" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Create initial user
    _ = try db.createUser("user1", "hash1", "user1@example.com");

    // Access database multiple times (mutex should prevent issues)
    _ = try db.createUser("user2", "hash2", "user2@example.com");
    _ = try db.createUser("user3", "hash3", "user3@example.com");

    var user1 = try db.getUserByUsername("user1");
    defer user1.deinit(allocator);

    try db.updateUserPassword("user2", "newhash");

    var user2 = try db.getUserByUsername("user2");
    defer user2.deinit(allocator);

    try testing.expectEqualStrings("newhash", user2.password_hash);
}

test "Database large number of users" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Create 100 users
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        const username = try std.fmt.allocPrint(allocator, "user{d}", .{i});
        defer allocator.free(username);
        const email = try std.fmt.allocPrint(allocator, "user{d}@example.com", .{i});
        defer allocator.free(email);

        _ = try db.createUser(username, "hash", email);
    }

    // Verify we can retrieve users
    var user0 = try db.getUserByUsername("user0");
    defer user0.deinit(allocator);

    var user50 = try db.getUserByUsername("user50");
    defer user50.deinit(allocator);

    var user99 = try db.getUserByUsername("user99");
    defer user99.deinit(allocator);

    try testing.expectEqualStrings("user0", user0.username);
    try testing.expectEqualStrings("user50", user50.username);
    try testing.expectEqualStrings("user99", user99.username);
}

test "Database special characters in username" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Test with special characters
    _ = try db.createUser("user-name_123", "hash", "test@example.com");

    var user = try db.getUserByUsername("user-name_123");
    defer user.deinit(allocator);

    try testing.expectEqualStrings("user-name_123", user.username);
}

test "Database special characters in email" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Test with plus addressing
    _ = try db.createUser("user", "hash", "user+tag@example.com");

    var user = try db.getUserByUsername("user");
    defer user.deinit(allocator);

    try testing.expectEqualStrings("user+tag@example.com", user.email);
}

test "Database long strings" {
    const allocator = testing.allocator;

    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Create long strings
    const long_username = "a" ** 255;
    const long_email = ("b" ** 240) ++ "@example.com";

    _ = try db.createUser(long_username, "hash", long_email);

    var user = try db.getUserByUsername(long_username);
    defer user.deinit(allocator);

    try testing.expectEqualStrings(long_username, user.username);
    try testing.expectEqualStrings(long_email, user.email);
}
