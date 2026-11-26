const std = @import("std");
const database = @import("storage/database.zig");
const sync_state = @import("protocol/eas_state.zig");

test "ActiveSync Ping keeps previous settings when it cannot read the updated row" {
    const test_allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(test_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var db = try database.Database.init(test_allocator, ":memory:");
    defer db.deinit();
    const user_id = try db.createUser("ping@example.test", "test-hash", "ping@example.test");
    const account: sync_state.Account = .{ .db = &db, .user_id = user_id, .device_id = "test-device" };

    _ = try account.ping(a, 60, &.{"INBOX"});
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, account.ping(failing.allocator(), 120, null));
    const retained = (try account.ping(a, null, null)).?;
    try std.testing.expectEqual(@as(u64, 60), retained.heartbeat);
    try std.testing.expectEqualStrings("INBOX", retained.folders[0]);
    try std.testing.expectEqual(@as(u64, 120), (try account.ping(a, 120, null)).?.heartbeat);
}
