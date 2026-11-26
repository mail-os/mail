//! Erase one reserved mailbox from the live DAV store while Mail is offline.
const std = @import("std");
const Database = @import("database.zig").Database;
const calendar_copy = @import("hosted_erasure_calendar_copy.zig");
const state = @import("dav_erasure_state.zig");
const inventory = @import("hosted_erasure_inventory.zig");
const maildir = @import("hosted_erasure_maildir.zig");
const shared = @import("hosted_erasure_shared.zig");
const review_store = @import("hosted_erasure_review.zig");
const io_compat = @import("../core/io_compat.zig");
const time = @import("../core/time_compat.zig");
const Allocator = std.mem.Allocator;

const Plan = struct {
    owner_id: ?i64,
    nonce: []const u8,
    completion: ?i64 = null,
};
const Receipt = struct {
    version: u8 = 1,
    state: []const u8 = "dav_owned_data_removed_other_stores_pending",
    mailbox: []const u8,
    request_id: []const u8,
    start_audit_id: i64,
    audit_id: i64,
    dav_owner_id: ?i64,
};

fn verifyStamp(a: Allocator, io: std.Io, path: []const u8, expected: []const u8) !void {
    if (!std.mem.eql(u8, expected, try inventory.davStoreStamp(a, io, path)))
        return error.ErasureDavFileChanged;
}

fn requireKnownTables(tx: Database.Transaction) !void {
    const tables = try tx.prepare(
        \\SELECT 1 FROM pragma_table_list WHERE schema='main' AND type IN ('table','virtual')
        \\AND substr(name,1,7)<>'sqlite_' AND name NOT IN (
        \\ 'dav_users','dav_calendars','dav_events','dav_addressbooks','dav_contacts',
        \\ 'dav_emails','dav_phones','dav_reminder_dismissals','dav_erasure_receipts'
        \\) LIMIT 1
    );
    defer tables.finalize();
    if (try tables.step()) return error.ErasureDavSchemaUnresolved;
}

fn requireOwnedScope(current: inventory.Dav) !void {
    if (current.legacy_name_candidates != 0) return error.ErasureDavOwnerUnresolved;
    switch (current.state) {
        .mapped => if ((current.owner_id orelse 0) < 1) return error.ErasureDavOwnerUnresolved,
        .no_owner => {},
        else => return error.ErasureDavOwnerUnresolved,
    }
    for (current.tables) |entry| {
        if (entry.matching_rows == null) return error.ErasureDavSchemaUnresolved;
    }
}

fn loadPlan(a: Allocator, tx: Database.Transaction, review: review_store.Review, start_id: i64, stamp: []const u8) !?Plan {
    const row = try tx.prepare(
        \\SELECT s.store_stamp,s.owner_id,s.nonce,s.completion_audit_id,a.id
        \\FROM hosted_erasure_dav_steps s LEFT JOIN audit_log a ON a.id=s.completion_audit_id
        \\AND a.action='hosted.erasure.dav.removed' AND a.target=?2 AND a.target_type='hosted_mailbox'
        \\AND json_extract(a.details,'$.start_audit_id')=s.start_audit_id
        \\AND json_extract(a.details,'$.request_id')=?3 AND json_extract(a.details,'$.nonce')=s.nonce
        \\WHERE s.start_audit_id=?1
    );
    defer row.finalize();
    try row.bind(1, start_id);
    try row.bind(2, review.mailbox);
    try row.bind(3, review.request_id);
    if (!try row.step()) return null;
    if (!std.mem.eql(u8, stamp, row.columnText(0))) return error.ErasureDavFileChanged;
    const nonce = row.columnText(2);
    if (nonce.len != 32) return error.InvalidErasureJournal;
    for (nonce) |byte| if (!std.ascii.isHex(byte)) return error.InvalidErasureJournal;
    const completion = row.columnInt64Opt(3);
    if (completion != null and row.columnIsNull(4)) return error.InvalidErasureJournal;
    return .{ .owner_id = row.columnInt64Opt(1), .nonce = try a.dupe(u8, nonce), .completion = completion };
}

fn recordPlan(a: Allocator, tx: Database.Transaction, start_id: i64, stamp: []const u8, owner_id: ?i64) !Plan {
    var bytes: [16]u8 = undefined;
    io_compat.randomBytes(&bytes);
    const nonce = try a.dupe(u8, &std.fmt.bytesToHex(bytes, .lower));
    const row = try tx.prepare(
        \\INSERT INTO hosted_erasure_dav_steps(start_audit_id,store_stamp,owner_id,nonce)
        \\VALUES(?1,?2,?3,?4)
    );
    defer row.finalize();
    try row.bind(1, start_id);
    try row.bind(2, stamp);
    try row.bindOpt(3, owner_id);
    try row.bind(4, nonce);
    if (try row.step()) return error.StepFailed;
    return .{ .owner_id = owner_id, .nonce = nonce };
}

fn ensureCopyProofColumn(tx: Database.Transaction) !void {
    const column = try tx.prepare("SELECT 1 FROM pragma_table_info('dav_erasure_receipts') WHERE name='retained_copy_proof'");
    defer column.finalize();
    if (try column.step()) return;
    const alter = try tx.prepare("ALTER TABLE dav_erasure_receipts ADD COLUMN retained_copy_proof TEXT");
    defer alter.finalize();
    if (try alter.step()) return error.StepFailed;
}

fn storeMarker(tx: Database.Transaction, native_id: i64, plan: Plan, proof_json: ?[]const u8) !void {
    const insert = try tx.prepare(
        \\INSERT INTO dav_erasure_receipts(nonce,native_user_id,dav_owner_id,max_owner,max_calendar,max_event,max_book,max_contact,retained_copy_proof)
        \\SELECT ?1,?2,?3,coalesce((SELECT max(id) FROM dav_users),0),
        \\ coalesce((SELECT max(id) FROM dav_calendars),0),coalesce((SELECT max(id) FROM dav_events),0),
        \\ coalesce((SELECT max(id) FROM dav_addressbooks),0),coalesce((SELECT max(id) FROM dav_contacts),0),?4
    );
    defer insert.finalize();
    try insert.bind(1, plan.nonce);
    try insert.bind(2, native_id);
    try insert.bindOpt(3, plan.owner_id);
    try insert.bindOpt(4, proof_json);
    if (try insert.step()) return error.StepFailed;
}

const Marker = struct { copy_proof: ?calendar_copy.Proof = null };

fn loadMarker(a: Allocator, tx: Database.Transaction, native_id: i64, plan: Plan) !?Marker {
    const row = try tx.prepare("SELECT native_user_id,dav_owner_id,retained_copy_proof FROM dav_erasure_receipts WHERE nonce=?1");
    defer row.finalize();
    try row.bind(1, plan.nonce);
    if (!try row.step()) return null;
    if (row.columnInt64(0) != native_id or row.columnInt64Opt(1) != plan.owner_id) return error.InvalidErasureJournal;
    return .{ .copy_proof = if (row.columnTextOpt(2)) |proof|
        try std.json.parseFromSliceLeaky(calendar_copy.Proof, a, proof, .{ .allocate = .alloc_always })
    else
        null };
}

fn deleteRows(tx: Database.Transaction, owner: i64) !void {
    inline for ([_]struct { table: []const u8, predicate: []const u8 }{
        .{ .table = "dav_emails", .predicate = inventory.contact_owner },
        .{ .table = "dav_phones", .predicate = inventory.contact_owner },
        .{ .table = "dav_contacts", .predicate = inventory.book_owner },
        .{ .table = "dav_addressbooks", .predicate = "user_id=?1" },
        .{ .table = "dav_events", .predicate = inventory.calendar_owner },
        .{ .table = "dav_calendars", .predicate = "user_id=?1" },
        .{ .table = "dav_reminder_dismissals", .predicate = "user_id=?1" },
        .{ .table = "dav_users", .predicate = "id=?1" },
    }) |scope| {
        const row = try tx.prepare("DELETE FROM " ++ scope.table ++ " WHERE " ++ scope.predicate);
        defer row.finalize();
        try row.bind(1, owner);
        if (try row.step()) return error.StepFailed;

        // Confirm children are gone before deleting the parent that identifies them.
        const check = try tx.prepare("SELECT 1 FROM " ++ scope.table ++ " WHERE " ++ scope.predicate ++ " LIMIT 1");
        defer check.finalize();
        try check.bind(1, owner);
        if (try check.step()) return error.ErasureDavRecordsRemain;
    }
}

pub fn verifyRemoved(a: Allocator, tx: Database.Transaction, mailbox: []const u8, native_id: i64, short: []const u8, previous_owner: ?i64) !void {
    const observed = try inventory.observeDavOwner(a, tx, mailbox, native_id, short);
    if (observed.state != .no_owner or observed.legacy_name_candidates != 0) return error.ErasureDavRecordsRemain;
    const owner = previous_owner orelse return;
    const orphans = try tx.prepare(
        \\SELECT EXISTS(SELECT 1 FROM dav_users WHERE id=?1) OR
        \\ EXISTS(SELECT 1 FROM dav_calendars WHERE user_id=?1) OR
        \\ EXISTS(SELECT 1 FROM dav_addressbooks WHERE user_id=?1) OR
        \\ EXISTS(SELECT 1 FROM dav_reminder_dismissals WHERE user_id=?1)
    );
    defer orphans.finalize();
    try orphans.bind(1, owner);
    if (!try orphans.step() or orphans.columnInt64(0) != 0) return error.ErasureDavRecordsRemain;
}

pub fn requireVerified(a: Allocator, io: std.Io, authority: Database.Transaction, review: review_store.Review, start: i64, owner: i64, configured: ?[]const u8) !?i64 {
    const path = configured orelse "./caldav.db";
    const reviewed = try review_store.reviewedDav(a, authority, review);
    const stamp = inventory.davStoreStamp(a, io, path) catch |err| switch (err) {
        error.FileNotFound => {
            if (configured == null and reviewed.state == .not_configured) return null;
            return error.ErasureDavPending;
        },
        else => return err,
    };
    const plan = (try loadPlan(a, authority, review, start, stamp)) orelse return error.ErasureDavPending;
    if (reviewed.owner_id != null and reviewed.owner_id != plan.owner_id) return error.ErasureDavOwnerUnresolved;
    const complete = plan.completion orelse return error.ErasureDavPending;
    var db = try Database.openReadOnly(a, path);
    defer db.deinit();
    var tx = try db.beginTransaction(.read);
    defer tx.deinit();
    try verifyStamp(a, io, path, stamp);
    try requireKnownTables(tx);
    const marker = (try loadMarker(a, tx, owner, plan)) orelse return error.ErasureDavReceiptMissing;
    if (marker.copy_proof) |proof| try shared.requireRecordedCalendarProof(a, authority, review, start, owner, proof);
    const at = std.mem.indexOfScalar(u8, review.mailbox, '@') orelse return error.InvalidErasureMailbox;
    try verifyRemoved(a, tx, review.mailbox, owner, review.mailbox[0..at], plan.owner_id);
    try verifyStamp(a, io, path, stamp);
    return complete;
}

pub fn erase(a: Allocator, io: std.Io, db: *Database, review: review_store.Review, start_id: i64, operator: []const u8, mail_root: []const u8, configured_path: []const u8, confirmed_path: []const u8) !Receipt {
    try review.validate();
    if (start_id < 1) return error.InvalidErasureStartAuditId;
    // SQLite WAL and shared-memory files are tied to the configured name.
    if (!std.mem.eql(u8, configured_path, confirmed_path)) return error.ErasureDavPathMismatch;
    const at = std.mem.indexOfScalar(u8, review.mailbox, '@') orelse return error.InvalidErasureMailbox;
    const short = review.mailbox[0..at];
    var root = try maildir.openLockedRoot(a, io, mail_root);
    defer root.close(io);
    const stamp = try inventory.davStoreStamp(a, io, configured_path);
    const scope = blk: {
        var tx = try db.beginTransaction(.read);
        defer tx.deinit();
        const owner = try review_store.requireStarted(a, tx, review, start_id, time.timestamp());
        try maildir.requireRemoved(a, io, tx, root, review.mailbox, start_id);
        const reviewed = try review_store.reviewedDav(a, tx, review);
        if (reviewed.store_stamp) |expected| {
            if (!std.mem.eql(u8, expected, stamp)) return error.ErasureDavFileChanged;
        }
        try tx.commit();
        break :blk .{ .dav = reviewed, .owner = owner.identity.native_user_id };
    };

    try db.exec("PRAGMA synchronous=FULL");
    var dav = try Database.openReadWriteExisting(a, configured_path);
    defer dav.deinit();
    // Overwrite deleted live cells and reconcile historical pages separately.
    try dav.exec("PRAGMA synchronous=FULL; PRAGMA secure_delete=ON");
    const outcome = blk: {
        var tx = try dav.beginTransaction(.write);
        defer tx.deinit();
        try verifyStamp(a, io, configured_path, stamp);
        try requireKnownTables(tx);
        var current = try inventory.observeDavOwner(a, tx, review.mailbox, scope.owner, short);
        try requireOwnedScope(current);
        current.store_stamp = stamp;
        const marker_table = try tx.prepare(state.schema);
        defer marker_table.finalize();
        if (try marker_table.step()) return error.StepFailed;
        try ensureCopyProofColumn(tx);

        const plan = plan: {
            var main_tx = try db.beginTransaction(.write);
            defer main_tx.deinit();
            const active = try review_store.requireStarted(a, main_tx, review, start_id, time.timestamp());
            if (active.identity.native_user_id != scope.owner) return error.AssignmentChanged;
            const existing = try loadPlan(a, main_tx, review, start_id, stamp);
            if (existing) |earlier| {
                try main_tx.commit();
                break :plan earlier;
            }
            try review_store.compareDav(a, scope.dav, current);
            const created = try recordPlan(a, main_tx, start_id, stamp, current.owner_id);
            try main_tx.commit();
            break :plan created;
        };

        // Keep the SMTP grant scope locked until the DAV transaction commits.
        var authority = try db.beginTransaction(.write);
        defer authority.deinit();
        const active = try review_store.requireStarted(a, authority, review, start_id, time.timestamp());
        if (active.identity.native_user_id != scope.owner) return error.AssignmentChanged;
        const marker = try loadMarker(a, tx, scope.owner, plan);
        var copy_proof: ?calendar_copy.Proof = if (marker) |stored| stored.copy_proof else null;
        if (copy_proof) |proof| try shared.requireRecordedCalendarProof(a, authority, review, start_id, scope.owner, proof);
        if (marker == null) {
            if (plan.completion != null) return error.ErasureDavReceiptMissing;
            if (current.owner_id != plan.owner_id) return error.ErasureDavOwnerUnresolved;
            try review_store.compareDav(a, scope.dav, current);
            if (plan.owner_id != null) {
                if (try shared.requireRelease(a, authority, review, start_id, scope.owner, .dav)) |release| {
                    if (release.copies.len != 0) copy_proof = .{
                        .approval_audit_id = release.audit_id,
                        .copies = try calendar_copy.verify(a, authority, tx, scope.owner, release.copies, time.timestamp()),
                    };
                }
            }
            const proof_json = if (copy_proof) |proof| try std.json.Stringify.valueAlloc(a, proof, .{}) else null;
            try storeMarker(tx, scope.owner, plan, proof_json);
            if (plan.owner_id) |id| try deleteRows(tx, id);
        }
        try verifyRemoved(a, tx, review.mailbox, scope.owner, short, plan.owner_id);
        try tx.commit();
        try authority.commit();
        break :blk .{ .plan = plan, .copy_proof = copy_proof };
    };
    try verifyStamp(a, io, configured_path, stamp);

    const plan = outcome.plan;
    var receipt: Receipt = .{
        .mailbox = review.mailbox,
        .request_id = review.request_id,
        .start_audit_id = start_id,
        .audit_id = plan.completion orelse 0,
        .dav_owner_id = plan.owner_id,
    };
    if (plan.completion != null) return receipt;

    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const now = time.timestamp();
    const active = try review_store.requireStarted(a, tx, review, start_id, now);
    if (active.identity.native_user_id != scope.owner) return error.AssignmentChanged;
    const details = try std.json.Stringify.valueAlloc(a, .{
        .start_audit_id = start_id,
        .request_id = review.request_id,
        .case_reference = review.case_reference,
        .native_user_id = scope.owner,
        .dav_owner_id = plan.owner_id,
        .nonce = plan.nonce,
        .retained_calendar_copy_proof = outcome.copy_proof,
    }, .{});
    receipt.audit_id = try review_store.writeAudit(tx, "hosted.erasure.dav.removed", review.mailbox, operator, now, details);
    const finish = try tx.prepare(
        \\UPDATE hosted_erasure_dav_steps SET completion_audit_id=?2
        \\WHERE start_audit_id=?1 AND completion_audit_id IS NULL RETURNING start_audit_id
    );
    defer finish.finalize();
    try finish.bind(1, start_id);
    try finish.bind(2, receipt.audit_id);
    if (!try finish.step() or try finish.step()) return error.InvalidErasureJournal;
    try tx.commit();
    return receipt;
}
