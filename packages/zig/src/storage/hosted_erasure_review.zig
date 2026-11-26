//! Record reviewed erasure evidence while leaving the mailbox and its stores in place.
const std = @import("std");
const Database = @import("database.zig").Database;
const inventory = @import("hosted_erasure_inventory.zig");
const preflight = @import("hosted_erasure_preflight.zig");
const mailbox_export = @import("hosted_erasure_export.zig");
const time = @import("../core/time_compat.zig");
const Allocator = std.mem.Allocator;

const Evidence = struct {
    authorization_reference: []const u8,
    retention_reference: []const u8,
    backup_reference: []const u8,
    billing_reference: []const u8,
    search_reference: []const u8,
    export_resolution_reference: []const u8,
};

pub const Review = struct {
    version: u8,
    request_id: []const u8,
    mailbox: []const u8,
    assignment_actor: []const u8,
    case_reference: []const u8,
    inventory_audit_id: i64,
    retention_disposition: enum { cleared, held },
    export_disposition: enum { not_requested, resolved },
    export_handoff_audit_id: ?i64 = null,
    evidence: Evidence,

    pub fn validate(self: Review) !void {
        if (self.version != 1 or self.inventory_audit_id < 1) return error.InvalidErasureReview;
        if (!preflight.validCaseReference(self.request_id) or !preflight.validCaseReference(self.case_reference))
            return error.InvalidCaseReference;
        const references = [_][]const u8{
            self.evidence.authorization_reference,
            self.evidence.retention_reference,
            self.evidence.backup_reference,
            self.evidence.billing_reference,
            self.evidence.search_reference,
            self.evidence.export_resolution_reference,
        };
        for (references) |reference| {
            if (!preflight.validCaseReference(reference)) return error.InvalidCaseReference;
        }
        if (self.retention_disposition == .held) return error.RetentionHold;
        switch (self.export_disposition) {
            .not_requested => if (self.export_handoff_audit_id != null) return error.InvalidExportDisposition,
            .resolved => if ((self.export_handoff_audit_id orelse 0) < 1) return error.InvalidExportDisposition,
        }
    }
};

const InventoryAudit = struct {
    case_reference: []const u8,
    inventory: inventory.Inventory,
};

fn loadInventory(a: Allocator, tx: Database.Transaction, review: Review) !InventoryAudit {
    const row = try tx.prepare(
        \\SELECT details FROM audit_log
        \\WHERE id=?1 AND action='hosted.erasure.inventory' AND target=?2 AND target_type='hosted_mailbox'
    );
    defer row.finalize();
    try row.bind(1, review.inventory_audit_id);
    try row.bind(2, review.mailbox);
    if (!try row.step()) return error.InventoryAuditNotFound;
    const reviewed = try std.json.parseFromSliceLeaky(InventoryAudit, a, row.columnText(0), .{ .allocate = .alloc_always });
    if (!std.mem.eql(u8, review.case_reference, reviewed.case_reference)) return error.InventoryCaseChanged;
    return reviewed;
}

pub fn reviewedDav(a: Allocator, tx: Database.Transaction, review: Review) !inventory.Dav {
    return (try loadInventory(a, tx, review)).inventory.dav;
}

pub fn compareDav(a: Allocator, reviewed: inventory.Dav, current: inventory.Dav) !void {
    var comparison = current;
    if (reviewed.store_stamp == null) comparison.store_stamp = null;
    if (reviewed.owner_id == null) comparison.owner_id = null;
    const earlier = try std.json.Stringify.valueAlloc(a, reviewed, .{});
    const later = try std.json.Stringify.valueAlloc(a, comparison, .{});
    if (!std.mem.eql(u8, earlier, later)) return error.InventoryChanged;
}

fn validateInventory(a: Allocator, reviewed: inventory.Inventory, current: inventory.Inventory) !void {
    if (!reviewed.identity.eql(current.identity)) return error.AssignmentChanged;
    if (current.maildir.state == .unavailable or current.maildir.legacy_short_name_present != false)
        return error.InventoryUnresolved;
    if (current.maildir.counts) |counts| {
        if (counts.symbolic_links != 0 or counts.other_entries != 0) return error.InventoryUnresolved;
    }
    switch (current.dav.state) {
        .mapped, .no_owner => if (current.dav.legacy_name_candidates != 0) return error.InventoryUnresolved,
        .not_configured => {},
        .legacy_owner_unresolved, .missing, .unavailable => return error.InventoryUnresolved,
    }
    var comparison = current;
    comparison.observed_at = reviewed.observed_at;
    if (reviewed.dav.store_stamp == null) comparison.dav.store_stamp = null;
    if (reviewed.dav.owner_id == null) comparison.dav.owner_id = null;
    if (reviewed.shared_backing == null) {
        // Older inventories did not capture the individual share grants.
        // Refresh the evidence if they would affect a second mailbox.
        if ((current.shared_backing orelse &.{}).len != 0) return error.ErasureSharedInventoryRequired;
        comparison.shared_backing = null;
    }
    const earlier = try std.json.Stringify.valueAlloc(a, reviewed, .{});
    const later = try std.json.Stringify.valueAlloc(a, comparison, .{});
    if (!std.mem.eql(u8, earlier, later)) return error.InventoryChanged;
}

pub fn verifyDeliveryDrained(observation: preflight.Observation) !void {
    const delivery = observation.delivery;
    if (delivery.pending_local_targets != 0 or delivery.remote_unattempted_targets != 0 or
        delivery.remote_unconfirmed_targets != 0 or delivery.legacy_remote_envelope_matches != 0 or
        delivery.legacy_pending_envelope_matches != 0) return error.DeliveryUnresolved;
    if (observation.outbound_queue) |queue| {
        if (queue.active_owned != 0 or queue.unattributed_address_matches != 0) return error.DeliveryUnresolved;
    }
    if (observation.webmail_outbox) |outbox| {
        if (outbox.in_progress != 0 or outbox.needs_review != 0) return error.DeliveryUnresolved;
    }
}

const Receipt = struct {
    version: u8 = 1,
    state: []const u8 = "review_recorded_data_retained",
    mailbox: []const u8,
    request_id: []const u8,
    audit_id: i64,
};

fn recordReceipt(tx: Database.Transaction, review: Review, operator: []const u8, now: i64, details: []const u8) !i64 {
    const existing = try tx.prepare(
        \\SELECT id,target,details FROM audit_log WHERE action='hosted.erasure.review.accepted'
        \\AND target_type='hosted_mailbox' AND json_extract(details,'$.request_id')=?1
    );
    defer existing.finalize();
    try existing.bind(1, review.request_id);
    if (try existing.step()) {
        const id = existing.columnInt64(0);
        if (!std.mem.eql(u8, review.mailbox, existing.columnText(1)) or
            !std.mem.eql(u8, details, existing.columnText(2)) or try existing.step()) return error.ErasureReviewConflict;
        return id;
    }

    return writeAudit(tx, "hosted.erasure.review.accepted", review.mailbox, operator, now, details);
}

pub fn writeAudit(tx: Database.Transaction, action: []const u8, mailbox: []const u8, operator: []const u8, now: i64, details: []const u8) !i64 {
    const row = try tx.prepare(
        \\INSERT INTO audit_log(timestamp,action,actor,target,target_type,details,severity)
        \\VALUES(?1,?2,?3,?4,'hosted_mailbox',?5,'info') RETURNING id
    );
    defer row.finalize();
    try row.bind(1, now);
    try row.bind(2, action);
    try row.bind(3, operator);
    try row.bind(4, mailbox);
    try row.bind(5, details);
    if (!try row.step()) return error.StepFailed;
    const id = row.columnInt64(0);
    if (try row.step()) return error.StepFailed;
    return id;
}

pub fn record(a: Allocator, io: std.Io, db: *Database, review: Review, operator: []const u8, mail_root: []const u8, dav_path: ?[]const u8) !Receipt {
    try review.validate();
    // Maildir and DAV are observed separately. A future removal must quiesce
    // those stores and verify the scope again before writing to any of them.
    const current = try inventory.collect(a, io, db, review.mailbox, review.assignment_actor, mail_root, dav_path);
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const now = time.timestamp();
    const observation = try preflight.observeInTransaction(a, tx, review.mailbox, review.assignment_actor, now);
    try verifyCurrent(a, tx, review, observation, current);
    const details = try reviewDetails(a, review, observation.identity);
    const id = try recordReceipt(tx, review, operator, now, details);
    try tx.commit();
    return .{ .mailbox = review.mailbox, .request_id = review.request_id, .audit_id = id };
}

pub fn verifyCurrent(a: Allocator, tx: Database.Transaction, review: Review, observation: preflight.Observation, sampled: inventory.Inventory) !void {
    var current = sampled;
    if (observation.access.state.readable()) return error.MailboxStillReadable;
    if (observation.identity.initial_provisioning_operation == null or !current.identity.eql(observation.identity))
        return error.AssignmentChanged;
    const reviewed = try loadInventory(a, tx, review);
    try verifyDeliveryDrained(observation);
    current.sqlite = try inventory.observeSqlite(a, tx, review.mailbox, observation.identity.native_user_id);
    current.shared_backing = try inventory.observeSharedBacking(a, tx, observation.identity.native_user_id);
    try validateInventory(a, reviewed.inventory, current);
    if (review.export_handoff_audit_id) |id| {
        try mailbox_export.validateHandoffAudit(a, tx, id, review.mailbox, review.case_reference, observation.identity);
    } else if (try mailbox_export.hasPreparedAudit(tx, review.mailbox, review.case_reference)) {
        return error.ExportResolutionRequired;
    }
}

fn reviewDetails(a: Allocator, review: Review, identity: preflight.Identity) ![]const u8 {
    return std.json.Stringify.valueAlloc(a, .{
        .version = review.version,
        .request_id = review.request_id,
        .case_reference = review.case_reference,
        .identity = identity,
        .inventory_audit_id = review.inventory_audit_id,
        .retention_disposition = review.retention_disposition,
        .export_disposition = review.export_disposition,
        .export_handoff_audit_id = review.export_handoff_audit_id,
        .evidence = review.evidence,
    }, .{});
}

const BeginReceipt = struct {
    version: u8 = 1,
    state: []const u8 = "erasure_started_data_retained",
    mailbox: []const u8,
    request_id: []const u8,
    review_audit_id: i64,
    audit_id: i64,
};

fn requireAcceptedReview(tx: Database.Transaction, mailbox: []const u8, audit_id: i64, details: []const u8) !void {
    const row = try tx.prepare(
        \\SELECT details FROM audit_log WHERE id=?1 AND action='hosted.erasure.review.accepted'
        \\AND target=?2 AND target_type='hosted_mailbox'
    );
    defer row.finalize();
    try row.bind(1, audit_id);
    try row.bind(2, mailbox);
    if (!try row.step()) return error.ErasureReviewAuditNotFound;
    if (!std.mem.eql(u8, details, row.columnText(0))) return error.ErasureReviewConflict;
}

fn existingStart(tx: Database.Transaction, review: Review, user: i64, review_id: i64) !?i64 {
    const row = try tx.prepare(
        \\SELECT request_id,mailbox,native_user_id,review_audit_id,start_audit_id FROM hosted_erasure_operations
        \\WHERE request_id=?1 OR mailbox=?2 OR native_user_id=?3
    );
    defer row.finalize();
    try row.bind(1, review.request_id);
    try row.bind(2, review.mailbox);
    try row.bind(3, user);
    if (!try row.step()) return null;
    const id = row.columnInt64(4);
    if (!std.mem.eql(u8, review.request_id, row.columnText(0)) or !std.mem.eql(u8, review.mailbox, row.columnText(1)) or
        row.columnInt64(2) != user or row.columnInt64(3) != review_id or try row.step())
        return error.ErasureAlreadyStarted;
    return id;
}

pub fn requireStarted(a: Allocator, tx: Database.Transaction, review: Review, start_id: i64, now: i64) !preflight.Observation {
    const observation = try preflight.observeInTransaction(a, tx, review.mailbox, review.assignment_actor, now);
    if (observation.access.state != .disabled) return error.MailboxStillReadable;
    const row = try tx.prepare(
        \\SELECT o.review_audit_id FROM hosted_erasure_operations o JOIN audit_log a ON a.id=o.start_audit_id
        \\WHERE o.start_audit_id=?1 AND o.request_id=?2 AND o.mailbox=?3 AND o.native_user_id=?4
        \\AND a.action='hosted.erasure.started' AND a.target=o.mailbox AND a.target_type='hosted_mailbox'
    );
    defer row.finalize();
    try row.bind(1, start_id);
    try row.bind(2, review.request_id);
    try row.bind(3, review.mailbox);
    try row.bind(4, observation.identity.native_user_id);
    if (!try row.step()) return error.ErasureStartNotFound;
    try requireAcceptedReview(tx, review.mailbox, row.columnInt64(0), try reviewDetails(a, review, observation.identity));
    try verifyDeliveryDrained(observation);
    return observation;
}

/// Reserve the mailbox identity for the reviewed erasure and preserve its data.
pub fn begin(a: Allocator, io: std.Io, db: *Database, review: Review, review_audit_id: i64, operator: []const u8, mail_root: []const u8, dav_path: ?[]const u8) !BeginReceipt {
    try review.validate();
    if (review_audit_id < 1) return error.InvalidErasureReviewAuditId;
    const current = try inventory.collect(a, io, db, review.mailbox, review.assignment_actor, mail_root, dav_path);
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const now = time.timestamp();
    const observation = try preflight.observeInTransaction(a, tx, review.mailbox, review.assignment_actor, now);
    if (observation.access.state.readable()) return error.MailboxStillReadable;
    const details = try reviewDetails(a, review, observation.identity);
    try requireAcceptedReview(tx, review.mailbox, review_audit_id, details);

    const user = observation.identity.native_user_id;
    var receipt = BeginReceipt{
        .mailbox = review.mailbox,
        .request_id = review.request_id,
        .review_audit_id = review_audit_id,
        .audit_id = undefined,
    };
    if (try existingStart(tx, review, user, review_audit_id)) |id| {
        receipt.audit_id = id;
        try tx.commit();
        return receipt;
    }

    try verifyCurrent(a, tx, review, observation, current);
    const audit_details = try std.json.Stringify.valueAlloc(a, .{
        .request_id = review.request_id,
        .case_reference = review.case_reference,
        .identity = observation.identity,
        .review_audit_id = review_audit_id,
    }, .{});
    const id = try writeAudit(tx, "hosted.erasure.started", review.mailbox, operator, now, audit_details);
    {
        const disable = try tx.prepare("UPDATE users SET enabled=0,updated_at=?1 WHERE id=?2 AND enabled<>0");
        defer disable.finalize();
        try disable.bind(1, now);
        try disable.bind(2, user);
        if (try disable.step()) return error.StepFailed;
    }
    {
        const reserve = try tx.prepare(
            \\INSERT INTO hosted_erasure_operations(request_id,mailbox,native_user_id,review_audit_id,start_audit_id)
            \\VALUES(?1,?2,?3,?4,?5)
        );
        defer reserve.finalize();
        try reserve.bind(1, review.request_id);
        try reserve.bind(2, review.mailbox);
        try reserve.bind(3, user);
        try reserve.bind(4, review_audit_id);
        try reserve.bind(5, id);
        if (try reserve.step()) return error.StepFailed;
    }
    try tx.commit();
    receipt.audit_id = id;
    return receipt;
}
