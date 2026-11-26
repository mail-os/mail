//! Reconcile one reserved mailbox's external search before draining its index work.
const std = @import("std");
const env = @import("../core/env.zig");
const Database = @import("database.zig").Database;
const local = @import("hosted_erasure_search.zig");
const maildir = @import("hosted_erasure_maildir.zig");
const review_store = @import("hosted_erasure_review.zig");
const time = @import("../core/time_compat.zig");
const typesense = @import("../search/typesense_erasure.zig");

pub const Endpoint = typesense.Endpoint;
const Allocator = std.mem.Allocator;
const CollectionReceipt = [typesense.names.len]struct { name: []const u8, created_at: ?i64 };
const Collections = [typesense.names.len]?typesense.Collection;

const Receipt = struct {
    version: u8 = 1,
    state: []const u8 = "typesense_removed_other_stores_pending",
    mailbox: []const u8,
    request_id: []const u8,
    start_audit_id: i64,
    audit_id: i64,
    endpoint: []const u8,
    collections: CollectionReceipt,
};

fn requireScope(a: Allocator, io: std.Io, tx: Database.Transaction, root: std.Io.Dir, review: review_store.Review, start_id: i64) !i64 {
    const observation = try review_store.requireStarted(a, tx, review, start_id, time.timestamp());
    try maildir.requireRemoved(a, io, tx, root, review.mailbox, start_id);
    const owner = observation.identity.native_user_id;
    try local.requireRemoved(tx, review, start_id, owner);
    return owner;
}

fn recordPlan(tx: Database.Transaction, review: review_store.Review, start_id: i64, endpoint: []const u8, selected: []const u8) !?i64 {
    const existing = try tx.prepare(
        \\SELECT s.endpoint,s.collection_stamps,s.completion_audit_id,a.id
        \\FROM hosted_erasure_typesense_steps s LEFT JOIN audit_log a ON a.id=s.completion_audit_id
        \\AND a.action='hosted.erasure.typesense.removed' AND a.target=?2 AND a.target_type='hosted_mailbox'
        \\AND json_extract(a.details,'$.start_audit_id')=s.start_audit_id
        \\AND json_extract(a.details,'$.request_id')=?3 AND json_extract(a.details,'$.endpoint')=s.endpoint
        \\AND json_extract(a.details,'$.collections')=s.collection_stamps
        \\WHERE s.start_audit_id=?1
    );
    defer existing.finalize();
    try existing.bind(1, start_id);
    try existing.bind(2, review.mailbox);
    try existing.bind(3, review.request_id);
    if (try existing.step()) {
        if (!std.mem.eql(u8, endpoint, existing.columnText(0))) return error.ErasureTypesenseEndpointMismatch;
        if (!std.mem.eql(u8, selected, existing.columnText(1))) return error.ErasureTypesenseCollectionChanged;
        if (existing.columnIsNull(2)) return null;
        if (existing.columnIsNull(3)) return error.InvalidErasureJournal;
        return existing.columnInt64(2);
    }

    const create = try tx.prepare(
        \\INSERT INTO hosted_erasure_typesense_steps(start_audit_id,endpoint,collection_stamps) VALUES (?1,?2,?3)
    );
    defer create.finalize();
    try create.bind(1, start_id);
    try create.bind(2, endpoint);
    try create.bind(3, selected);
    if (try create.step()) return error.StepFailed;
    return null;
}

fn verifyWorkRemoved(tx: Database.Transaction, owner: i64) !void {
    const check = try tx.prepare(
        \\SELECT EXISTS(SELECT 1 FROM mail_search_pending WHERE user_id=?1) OR
        \\       EXISTS(SELECT 1 FROM mail_search_checkpoints WHERE user_id=?1)
    );
    defer check.finalize();
    try check.bind(1, owner);
    if (!try check.step() or check.columnInt64(0) != 0) return error.ErasureTypesenseWorkRemains;
}

fn verifyEmpty(collections: Collections, selected: typesense.Stamps) !void {
    for (collections, selected) |current, stamp| {
        const current_stamp = if (current) |present| present.created_at else null;
        if (current_stamp != stamp) return error.ErasureTypesenseCollectionChanged;
        if (current) |present| if (present.ids.items.len != 0) return error.ErasureTypesenseDocumentsRemain;
    }
}

pub fn requireVerified(a: Allocator, io: std.Io, tx: Database.Transaction, review: review_store.Review, start: i64, owner: i64) !?i64 {
    const row = try tx.prepare(
        \\SELECT s.endpoint,s.collection_stamps,a.id
        \\FROM hosted_erasure_typesense_steps s LEFT JOIN audit_log a ON a.id=s.completion_audit_id
        \\AND a.action='hosted.erasure.typesense.removed' AND a.target=?2 AND a.target_type='hosted_mailbox'
        \\AND json_extract(a.details,'$.start_audit_id')=s.start_audit_id
        \\AND json_extract(a.details,'$.request_id')=?3 AND json_extract(a.details,'$.endpoint')=s.endpoint
        \\AND json_extract(a.details,'$.collections')=s.collection_stamps
        \\WHERE s.start_audit_id=?1
    );
    defer row.finalize();
    try row.bind(1, start);
    try row.bind(2, review.mailbox);
    try row.bind(3, review.request_id);
    const recent = try row.step();
    const active = env.get("TYPESENSE_API_KEY") orelse "";
    const has_config = active.len != 0 or env.get("TYPESENSE_HOST") != null or env.get("TYPESENSE_PORT") != null;
    if (!recent and !has_config) {
        try verifyWorkRemoved(tx, owner);
        return null;
    }
    if (!recent or row.columnIsNull(2)) return error.ErasureTypesensePending;
    if (active.len == 0) return error.ErasureTypesenseUnavailable;
    const endpoint: Endpoint = .{
        .host = env.get("TYPESENSE_HOST") orelse "127.0.0.1",
        .port = std.fmt.parseInt(u16, env.get("TYPESENSE_PORT") orelse "8108", 10) catch return error.ErasureTypesenseEndpointMismatch,
    };
    const origin = try std.fmt.allocPrint(a, "{s}:{d}", .{ endpoint.host, endpoint.port });
    if (!std.mem.eql(u8, origin, row.columnText(0))) return error.ErasureTypesenseEndpointMismatch;
    const service = try typesense.Service.reviewed(endpoint);
    try typesense.validateMailbox(review.mailbox);
    const recorded = try std.json.parseFromSliceLeaky(CollectionReceipt, a, row.columnText(1), .{});
    var client: std.http.Client = .{ .allocator = a, .io = io };
    defer client.deinit();
    try service.verifyService(a, &client);
    var current: Collections = undefined;
    var expected: typesense.Stamps = undefined;
    for (typesense.names, recorded, 0..) |name, proof, index| {
        if (!std.mem.eql(u8, name, proof.name)) return error.InvalidErasureJournal;
        current[index] = try service.inspect(a, &client, name, review.mailbox);
        expected[index] = proof.created_at;
    }
    try verifyEmpty(current, expected);
    try verifyWorkRemoved(tx, owner);
    return row.columnInt64(2);
}

pub fn erase(a: Allocator, io: std.Io, db: *Database, review: review_store.Review, start_id: i64, operator: []const u8, mail_root: []const u8, endpoint: Endpoint) !Receipt {
    try review.validate();
    if (start_id < 1) return error.InvalidErasureStartAuditId;
    try typesense.validateMailbox(review.mailbox);
    const service = try typesense.Service.reviewed(endpoint);
    const origin = try std.fmt.allocPrint(a, "{s}:{d}", .{ endpoint.host, endpoint.port });
    var root = try maildir.openLockedRoot(a, io, mail_root);
    defer root.close(io);

    {
        var tx = try db.beginTransaction(.write);
        defer tx.deinit();
        _ = try requireScope(a, io, tx, root, review, start_id);
        try tx.commit();
    }

    var client: std.http.Client = .{ .allocator = a, .io = io };
    defer client.deinit();
    try service.verifyService(a, &client);
    var collections: Collections = undefined;
    var selected: typesense.Stamps = undefined;
    var receipt: Receipt = .{
        .mailbox = review.mailbox,
        .request_id = review.request_id,
        .start_audit_id = start_id,
        .audit_id = undefined,
        .endpoint = origin,
        .collections = undefined,
    };
    for (typesense.names, 0..) |name, index| {
        collections[index] = try service.inspect(a, &client, name, review.mailbox);
        selected[index] = if (collections[index]) |present| present.created_at else null;
        receipt.collections[index] = .{ .name = name, .created_at = selected[index] };
    }
    const snapshot = try std.json.Stringify.valueAlloc(a, receipt.collections, .{});
    {
        var tx = try db.beginTransaction(.write);
        defer tx.deinit();
        const owner = try requireScope(a, io, tx, root, review, start_id);
        if (try recordPlan(tx, review, start_id, origin, snapshot)) |id| {
            try verifyEmpty(collections, selected);
            try verifyWorkRemoved(tx, owner);
            try tx.commit();
            receipt.audit_id = id;
            return receipt;
        }
        try tx.commit();
    }

    for (typesense.names, collections) |name, current| {
        if (current) |present| try service.remove(a, &client, name, present);
    }
    for (typesense.names, 0..) |name, index| {
        collections[index] = try service.inspect(a, &client, name, review.mailbox);
    }
    try verifyEmpty(collections, selected);

    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const owner = try requireScope(a, io, tx, root, review, start_id);
    inline for (.{ "mail_search_pending", "mail_search_checkpoints" }) |table| {
        const stmt = try tx.prepare("DELETE FROM " ++ table ++ " WHERE user_id=?1");
        defer stmt.finalize();
        try stmt.bind(1, owner);
        if (try stmt.step()) return error.StepFailed;
    }
    try verifyWorkRemoved(tx, owner);
    const details = try std.json.Stringify.valueAlloc(a, .{
        .start_audit_id = start_id,
        .request_id = review.request_id,
        .case_reference = review.case_reference,
        .native_user_id = owner,
        .endpoint = origin,
        .collections = receipt.collections,
    }, .{});
    receipt.audit_id = try review_store.writeAudit(tx, "hosted.erasure.typesense.removed", review.mailbox, operator, time.timestamp(), details);
    const finish = try tx.prepare(
        \\UPDATE hosted_erasure_typesense_steps SET completion_audit_id=?2
        \\WHERE start_audit_id=?1 AND completion_audit_id IS NULL RETURNING start_audit_id
    );
    defer finish.finalize();
    try finish.bind(1, start_id);
    try finish.bind(2, receipt.audit_id);
    if (!try finish.step() or try finish.step()) return error.InvalidErasureJournal;
    try tx.commit();
    return receipt;
}
