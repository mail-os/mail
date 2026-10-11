const std = @import("std");
const api = @import("webmail_service.zig");
const store = @import("webmail_store.zig");
const maildir = @import("webmail_maildir.zig");
const database = @import("../storage/database.zig");
const auth_mod = @import("../auth/auth.zig");
const fs = @import("../core/fs_compat.zig");
const time = @import("../core/time_compat.zig");

test "autosave preserves unfinished recipients, names, bytes and conditional revisions" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var db = try database.Database.init(t.allocator, ":memory:");
    defer db.deinit();
    var auth = auth_mod.AuthBackend.init(t.allocator, &db);
    defer auth.deinit();
    const user = try std.fmt.allocPrint(a, "draft-ui-{d}@unit.test", .{time.milliTimestamp()});
    _ = try auth.createUser(user, "test-only-password", user);
    const root = try std.fmt.allocPrint(a, "mail/{s}", .{user});
    defer fs.cwd().deleteTree(root) catch {};
    var service = try api.Service.init(&db, &auth, .{ .hostname = "mail.unit.test" });
    var payload = api.Payload{ .draftId = "1234567890123456", .saveToken = "save-one", .to = &.{"incomplete@"}, .recipientInputs = .{ .cc = "still typing" }, .recipientLabels = .{ .to = &.{"Someone"} }, .text = "First body" };
    const first = try service.saveDraft(a, user, user, payload);
    try t.expectEqual(@as(i64, 1), first.revision);
    try t.expectEqual(first.uid, (try service.saveDraft(a, user, user, payload)).uid);
    const record = try store.get(a, &db, user, "draft", first.draftId);
    const saved = try std.json.parseFromSlice(api.Draft, a, record.payload, .{});
    try t.expectEqualStrings("incomplete@", saved.value.message.to[0]);
    try t.expectEqualStrings("still typing", saved.value.message.recipientInputs.cc);
    try t.expectEqualStrings("Someone", saved.value.message.recipientLabels.to[0]);
    const mime = try maildir.getMessage(a, &db, user, "Drafts", first.uid);
    try t.expectEqualStrings("First body", std.mem.trim(u8, mime.text_body, "\r\n"));
    try t.expectEqualStrings("", mime.to);
    payload.text = "Attempted overwrite";
    try t.expectError(api.ServiceError.Conflict, service.saveDraft(a, user, user, payload));
    payload.draftRevision = first.revision;
    payload.saveToken = "save-two";
    payload.text = "Second body";
    const second = try service.saveDraft(a, user, user, payload);
    try t.expectEqual(first.uid, second.uid);
    try t.expectEqual(@as(i64, 2), second.revision);
    try t.expectEqual(@as(usize, 1), (try maildir.listMessages(a, &db, user, "Drafts", 1, 50)).len);
    const binary = try a.alloc(u8, 1024 * 1024);
    @memset(binary, 0xff);
    binary[0] = 0;
    try store.addUpload(&db, user, .{ .id = "2234567890123456", .filename = "large.bin", .content_type = "application/octet-stream", .data = binary }, 100, 2 * 1024 * 1024);
    payload.draftRevision = second.revision;
    payload.saveToken = "save-three";
    payload.attachments = &.{.{ .uploadId = "2234567890123456" }};
    const third = try service.saveDraft(a, user, user, payload);
    const with_attachment = try maildir.getMessage(a, &db, user, "Drafts", third.uid);
    try t.expectEqualSlices(u8, binary, with_attachment.attachments[0].data);
    _ = try db.createUser("other@unit.test", "test-hash", "other@unit.test");
    try t.expectError(store.StoreError.NotFound, service.payloadMessage(a, payload, "other@unit.test", "other@unit.test", true));
    try db.deleteUser(user);
    try t.expectError(store.StoreError.NotFound, store.getUpload(a, &db, user, "2234567890123456"));
    try t.expectError(store.StoreError.NotFound, store.get(a, &db, user, "draft", first.draftId));
}

test "bulk undo preserves UID identity, preflights selections, and refuses changed messages" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var db = try database.Database.init(t.allocator, ":memory:");
    defer db.deinit();
    var auth = auth_mod.AuthBackend.init(t.allocator, &db);
    defer auth.deinit();
    const user = try std.fmt.allocPrint(a, "bulk-ui-{d}@unit.test", .{time.milliTimestamp()});
    _ = try auth.createUser(user, "test-only-password", user);
    const root = try std.fmt.allocPrint(a, "mail/{s}", .{user});
    defer fs.cwd().deleteTree(root) catch {};
    var service = try api.Service.init(&db, &auth, .{ .hostname = "mail.unit.test" });
    const draft = try service.saveDraft(a, user, user, .{ .draftId = "1234567890123456", .saveToken = "one", .text = "Body" });
    const original = api.MessageRef{ .uid = draft.uid, .folder = "Drafts" };
    try t.expectError(maildir.MaildirError.MessageNotFound, service.bulk(a, user, .{ .action = .trash, .messages = &.{ original, .{ .uid = 9999, .folder = "Drafts" } } }, 100));
    _ = try maildir.getMessage(a, &db, user, original.folder, original.uid);
    const moved = try service.bulk(a, user, .{ .action = .trash, .messages = &.{original} }, 100);
    try t.expect(moved.ok);
    try t.expectError(store.StoreError.NotFound, service.undo(a, "other@unit.test", moved.undoId.?, 101));
    const restored = try service.undo(a, user, moved.undoId.?, 101);
    try t.expect(restored.ok);
    const fresh = restored.results[0].new_uid.?;
    try t.expect(fresh != original.uid);
    try t.expectEqual(fresh, (try service.undo(a, user, moved.undoId.?, 102)).results[0].new_uid.?);
    _ = try store.findDraft(a, &db, user, "Drafts", fresh);
    const flagged = try service.bulk(a, user, .{ .action = .flag, .messages = &.{.{ .uid = fresh, .folder = "Drafts" }} }, 200);
    var message = try maildir.getMessage(a, &db, user, "Drafts", fresh);
    message.flags.seen = false;
    _ = try maildir.setFlags(a, &db, user, "Drafts", fresh, message.flags);
    const changed = try service.undo(a, user, flagged.undoId.?, 201);
    try t.expect(!changed.ok);
    try t.expectEqualStrings("message_changed", changed.results[0].error_code.?);
    try t.expectError(api.ServiceError.Conflict, service.undo(a, user, flagged.undoId.?, 230));
}

test "queued send survives worker recreation, cancels before dispatch and sends once after the deadline" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var db = try database.Database.init(t.allocator, ":memory:");
    defer db.deinit();
    var auth = auth_mod.AuthBackend.init(t.allocator, &db);
    defer auth.deinit();
    const user = try std.fmt.allocPrint(a, "outbox-ui-{d}@unit.test", .{time.milliTimestamp()});
    _ = try auth.createUser(user, "test-only-password", user);
    const root = try std.fmt.allocPrint(a, "mail/{s}", .{user});
    defer fs.cwd().deleteTree(root) catch {};
    var service = try api.Service.init(&db, &auth, .{ .hostname = "mail.unit.test" });
    var payload = api.Payload{ .to = &.{user}, .text = "Delayed message", .sendId = "1234567890123456", .delaySeconds = 5 };
    const queued = try service.queue(a, user, user, payload, 100);
    try t.expectEqual(@as(i64, 105), queued.due_at);
    try t.expectEqualStrings(queued.id, (try service.queue(a, user, user, payload, 101)).id);
    try t.expect(!try service.dispatchDue(a, 104));
    _ = try service.cancel(a, user, queued.id, 104);
    try t.expect(!try service.dispatchDue(a, 106));
    try t.expectEqual(@as(usize, 0), (try maildir.listMessages(a, &db, user, "INBOX", 1, 50)).len);
    payload.sendId = "2234567890123456";
    _ = try service.queue(a, user, user, payload, 110);
    var restarted = try api.Service.init(&db, &auth, .{ .hostname = "mail.unit.test" });
    try t.expect(!try restarted.dispatchDue(a, 114));
    try t.expectError(store.StoreError.Conflict, restarted.cancel(a, user, payload.sendId.?, 115));
    try t.expect(try restarted.dispatchDue(a, 115));
    try t.expect(!try restarted.dispatchDue(a, 115));
    try t.expectEqual(@as(usize, 1), (try maildir.listMessages(a, &db, user, "INBOX", 1, 50)).len);
    try t.expectEqualStrings("sent", (try store.get(a, &db, user, "outbox", payload.sendId.?)).state);
    payload.text = "Different content";
    try t.expectError(api.ServiceError.Conflict, restarted.queue(a, user, user, payload, 120));
}

test "UID allocation creates its mailbox and recovers an older UIDNEXT invariant" {
    const t = std.testing;
    var db = try database.Database.init(t.allocator, ":memory:");
    defer db.deinit();
    const first = try db.assignUid("uid-owner@unit.test", "INBOX", "first.eml");
    const second = try db.assignUid("uid-owner@unit.test", "INBOX", "second.eml");
    try t.expect(second > first);
    try t.expectEqual(second + 1, try db.getUidNext("uid-owner@unit.test", "INBOX"));
    try db.exec("UPDATE imap_mailboxes SET uidnext=1 WHERE username='uid-owner@unit.test'");
    const third = try db.assignUid("uid-owner@unit.test", "INBOX", "third.eml");
    try t.expect(third > second);
    try t.expectEqual(first, try db.assignUid("uid-owner@unit.test", "INBOX", "first.eml:2,S"));
}

test "partial delivery retries only failed recipients and interrupted sends require review" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var db = try database.Database.init(t.allocator, ":memory:");
    defer db.deinit();
    var auth = auth_mod.AuthBackend.init(t.allocator, &db);
    defer auth.deinit();
    const user = try std.fmt.allocPrint(a, "partial-ui-{d}@unit.test", .{time.milliTimestamp()});
    const missing = try std.fmt.allocPrint(a, "missing-{d}@unit.test", .{time.milliTimestamp()});
    _ = try auth.createUser(user, "test-only-password", user);
    const root = try std.fmt.allocPrint(a, "mail/{s}", .{user});
    defer fs.cwd().deleteTree(root) catch {};
    var service = try api.Service.init(&db, &auth, .{ .hostname = "mail.unit.test" });
    var payload = api.Payload{
        .draftId = "3234567890123456",
        .saveToken = "partial-save",
        .sendId = "4234567890123456",
        .to = &.{ user, missing },
        .recipientLabels = .{ .to = &.{ "Delivered name", "Failed name" } },
        .text = "Partial delivery fixture",
        .delaySeconds = 0,
    };
    const saved = try service.saveDraft(a, user, user, payload);
    payload.draftRevision = saved.revision;
    payload.draftUid = saved.uid;
    _ = try service.queue(a, user, user, payload, 100);
    try t.expectError(api.ServiceError.Conflict, service.saveDraft(a, user, user, payload));
    try t.expect(try service.dispatchDue(a, 100));
    try t.expectEqualStrings("partial", (try store.get(a, &db, user, "outbox", payload.sendId.?)).state);
    const retry_row = try store.get(a, &db, user, "draft", payload.draftId.?);
    const retry = try std.json.parseFromSlice(api.Draft, a, retry_row.payload, .{});
    try t.expectEqualStrings("saved", retry_row.state);
    try t.expectEqual(@as(usize, 1), retry.value.message.to.len);
    try t.expectEqualStrings(missing, retry.value.message.to[0]);
    try t.expectEqualStrings("Failed name", retry.value.message.recipientLabels.to[0]);
    try t.expectEqualStrings(missing, (try maildir.getMessage(a, &db, user, "Drafts", retry.value.uid)).to);
    try t.expectEqual(@as(usize, 1), (try maildir.listMessages(a, &db, user, "INBOX", 1, 50)).len);

    payload = retry.value.message;
    payload.sendId = "5234567890123456";
    payload.draftRevision = retry_row.revision;
    payload.delaySeconds = 0;
    _ = try service.queue(a, user, user, payload, 110);
    _ = (try store.claimDue(a, &db, 110)).?;
    try store.recoverInterrupted(&db);
    try t.expectEqualStrings("unknown", (try store.get(a, &db, user, "outbox", payload.sendId.?)).state);
    try t.expect(!try service.dispatchDue(a, 120));
    try t.expectEqualStrings("queued", (try store.get(a, &db, user, "draft", payload.draftId.?)).state);
    const reviewed = try service.resolveUnknown(a, user, payload.sendId.?, 120);
    try t.expectEqualStrings("resolved", reviewed.state);
    try t.expectEqualStrings("saved", (try store.get(a, &db, user, "draft", payload.draftId.?)).state);
    try t.expectEqual(reviewed.revision, (try service.resolveUnknown(a, user, payload.sendId.?, 121)).revision);
}
