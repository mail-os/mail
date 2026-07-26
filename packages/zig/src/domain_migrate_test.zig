const std = @import("std");
const testing = std.testing;
const dm = @import("domain_migrate.zig");
const database = @import("storage/database.zig");

// ── Address handling ────────────────────────────────────────────────────────

test "domainOf extracts the domain" {
    try testing.expectEqualStrings("ghostanalytics.org", dm.domainOf("hello@ghostanalytics.org").?);
}

test "domainOf returns null for a bare local part" {
    // Legacy role mailboxes are stored bare. They belong to the server's
    // primary domain, never to the one being migrated.
    try testing.expect(dm.domainOf("postmaster") == null);
}

test "domainOf returns null for a trailing @" {
    try testing.expect(dm.domainOf("broken@") == null);
}

test "domainOf uses the last @ so a quoted local part survives" {
    try testing.expectEqualStrings("example.org", dm.domainOf("odd@name@example.org").?);
}

test "addressInDomain ignores case" {
    try testing.expect(dm.addressInDomain("Hello@GhostAnalytics.ORG", "ghostanalytics.org"));
}

test "addressInDomain does not match a suffix of another domain" {
    // `analytics.org` must not sweep up `ghostanalytics.org`.
    try testing.expect(!dm.addressInDomain("hello@ghostanalytics.org", "analytics.org"));
}

test "addressInDomain does not match a subdomain" {
    try testing.expect(!dm.addressInDomain("hello@mail.example.org", "example.org"));
}

test "rewriteAddress swaps the domain" {
    const out = try dm.rewriteAddress(testing.allocator, "hello@ghostanalytics.org", "analyticshq.org");
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("hello@analyticshq.org", out);
}

test "rewriteAddress keeps a local part containing @" {
    const out = try dm.rewriteAddress(testing.allocator, "odd@name@old.org", "new.org");
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("odd@name@new.org", out);
}

test "rewriteAddress leaves a bare local part alone" {
    const out = try dm.rewriteAddress(testing.allocator, "postmaster", "new.org");
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("postmaster", out);
}

// ── Domain validation ───────────────────────────────────────────────────────

test "isValidDomain accepts ordinary domains" {
    try testing.expect(dm.isValidDomain("analyticshq.org"));
    try testing.expect(dm.isValidDomain("mail.example.co.uk"));
    try testing.expect(dm.isValidDomain("xn--80ak6aa92e.com"));
    try testing.expect(dm.isValidDomain("a-b.example.org"));
}

test "isValidDomain rejects an address" {
    // The guard that stops `mail domain migrate old.org hello@new.org` from
    // renaming every mailbox to something unroutable.
    try testing.expect(!dm.isValidDomain("hello@new.org"));
}

test "isValidDomain rejects malformed input" {
    try testing.expect(!dm.isValidDomain(""));
    try testing.expect(!dm.isValidDomain("localhost")); // no dot
    try testing.expect(!dm.isValidDomain(".example.org"));
    try testing.expect(!dm.isValidDomain("example.org."));
    try testing.expect(!dm.isValidDomain("exa..mple.org"));
    try testing.expect(!dm.isValidDomain("-bad.example.org"));
    try testing.expect(!dm.isValidDomain("bad-.example.org"));
    try testing.expect(!dm.isValidDomain("has space.org"));
    try testing.expect(!dm.isValidDomain("under_score.org"));
}

// ── Planning against a real database ────────────────────────────────────────

fn seed(db: *database.Database, address: []const u8) !void {
    _ = try db.createUser(address, "hash", address);
}

test "plan lists every mailbox on the domain" {
    var db = try database.Database.init(testing.allocator, ":memory:");
    defer db.deinit();

    try seed(&db, "hello@ghostanalytics.org");
    try seed(&db, "chris@ghostanalytics.org");
    try seed(&db, "hello@bughq.org");
    try seed(&db, "postmaster");

    var plan = try dm.plan(testing.allocator, &db, "ghostanalytics.org", "analyticshq.org", .{});
    defer plan.deinit();

    try testing.expectEqual(@as(usize, 2), plan.mailboxes.len);
    for (plan.mailboxes) |m|
        try testing.expect(std.mem.endsWith(u8, m.to, "@analyticshq.org"));
}

test "plan leaves other domains and bare local parts alone" {
    var db = try database.Database.init(testing.allocator, ":memory:");
    defer db.deinit();

    try seed(&db, "hello@ghostanalytics.org");
    try seed(&db, "hello@bughq.org");
    try seed(&db, "postmaster");

    var plan = try dm.plan(testing.allocator, &db, "ghostanalytics.org", "analyticshq.org", .{});
    defer plan.deinit();

    for (plan.mailboxes) |m| {
        try testing.expect(!std.mem.eql(u8, m.from, "hello@bughq.org"));
        try testing.expect(!std.mem.eql(u8, m.from, "postmaster"));
    }
}

test "plan refuses an empty migration" {
    var db = try database.Database.init(testing.allocator, ":memory:");
    defer db.deinit();
    try seed(&db, "hello@bughq.org");

    try testing.expectError(
        dm.Error.NoMailboxes,
        dm.plan(testing.allocator, &db, "ghostanalytics.org", "analyticshq.org", .{}),
    );
}

test "plan refuses a collision at the target" {
    // username and email are UNIQUE, so the UPDATE would abort part-way and
    // strand the domain across two names.
    var db = try database.Database.init(testing.allocator, ":memory:");
    defer db.deinit();

    try seed(&db, "hello@ghostanalytics.org");
    try seed(&db, "hello@analyticshq.org");

    try testing.expectError(
        dm.Error.TargetAddressExists,
        dm.plan(testing.allocator, &db, "ghostanalytics.org", "analyticshq.org", .{}),
    );
}

test "plan refuses a no-op and invalid input" {
    var db = try database.Database.init(testing.allocator, ":memory:");
    defer db.deinit();
    try seed(&db, "hello@ghostanalytics.org");

    try testing.expectError(
        dm.Error.SameDomain,
        dm.plan(testing.allocator, &db, "ghostanalytics.org", "GhostAnalytics.org", .{}),
    );
    try testing.expectError(
        dm.Error.InvalidDomain,
        dm.plan(testing.allocator, &db, "ghostanalytics.org", "hello@analyticshq.org", .{}),
    );
}

// ── Applying ────────────────────────────────────────────────────────────────

test "renameDomain moves only the matching mailboxes" {
    var db = try database.Database.init(testing.allocator, ":memory:");
    defer db.deinit();

    try seed(&db, "hello@ghostanalytics.org");
    try seed(&db, "chris@ghostanalytics.org");
    try seed(&db, "hello@bughq.org");
    try seed(&db, "postmaster");

    const moved = try db.renameDomain("ghostanalytics.org", "analyticshq.org");
    try testing.expectEqual(@as(u32, 2), moved);

    try testing.expect(try db.userExists("hello@analyticshq.org"));
    try testing.expect(try db.userExists("chris@analyticshq.org"));
    try testing.expect(!try db.userExists("hello@ghostanalytics.org"));

    // Untouched.
    try testing.expect(try db.userExists("hello@bughq.org"));
    try testing.expect(try db.userExists("postmaster"));
}

test "renameDomain rewrites the email column too" {
    var db = try database.Database.init(testing.allocator, ":memory:");
    defer db.deinit();
    try seed(&db, "hello@ghostanalytics.org");

    _ = try db.renameDomain("ghostanalytics.org", "analyticshq.org");

    var user = try db.getUserByUsername("hello@analyticshq.org");
    defer user.deinit(testing.allocator);
    try testing.expectEqualStrings("hello@analyticshq.org", user.email);
}

test "renameDomain preserves the local part" {
    var db = try database.Database.init(testing.allocator, ":memory:");
    defer db.deinit();
    try seed(&db, "no-reply+tag@ghostanalytics.org");

    _ = try db.renameDomain("ghostanalytics.org", "analyticshq.org");

    try testing.expect(try db.userExists("no-reply+tag@analyticshq.org"));
}

test "renameDomain does not touch a suffix-similar domain" {
    var db = try database.Database.init(testing.allocator, ":memory:");
    defer db.deinit();

    try seed(&db, "hello@ghostanalytics.org");
    try seed(&db, "hello@analytics.org");

    _ = try db.renameDomain("analytics.org", "analyticshq.org");

    // `%@analytics.org` must not have swallowed the ghost- prefixed domain.
    try testing.expect(try db.userExists("hello@ghostanalytics.org"));
    try testing.expect(try db.userExists("hello@analyticshq.org"));
}

test "countUsernamesInDomain counts only that domain" {
    var db = try database.Database.init(testing.allocator, ":memory:");
    defer db.deinit();

    try seed(&db, "hello@ghostanalytics.org");
    try seed(&db, "chris@ghostanalytics.org");
    try seed(&db, "hello@bughq.org");

    try testing.expectEqual(@as(u32, 2), try db.countUsernamesInDomain("users", "ghostanalytics.org"));
    try testing.expectEqual(@as(u32, 1), try db.countUsernamesInDomain("users", "bughq.org"));
    try testing.expectEqual(@as(u32, 0), try db.countUsernamesInDomain("users", "nowhere.org"));
}

test "listDomains groups mailboxes by domain" {
    var db = try database.Database.init(testing.allocator, ":memory:");
    defer db.deinit();

    try seed(&db, "hello@ghostanalytics.org");
    try seed(&db, "chris@ghostanalytics.org");
    try seed(&db, "hello@bughq.org");
    try seed(&db, "postmaster");

    const counts = try dm.listDomains(testing.allocator, &db);
    defer dm.freeDomainCounts(testing.allocator, counts);

    try testing.expectEqual(@as(usize, 3), counts.len);
    // Sorted by name: "(no domain)" then bughq.org then ghostanalytics.org.
    try testing.expectEqualStrings("(no domain)", counts[0].domain);
    try testing.expectEqualStrings("bughq.org", counts[1].domain);
    try testing.expectEqual(@as(u32, 1), counts[1].mailboxes);
    try testing.expectEqualStrings("ghostanalytics.org", counts[2].domain);
    try testing.expectEqual(@as(u32, 2), counts[2].mailboxes);
}
