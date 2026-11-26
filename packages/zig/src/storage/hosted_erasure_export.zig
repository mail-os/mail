//! Prepare an audited private archive from a reviewed hosted exit request.
const std = @import("std");
const Database = @import("database.zig").Database;
const preflight = @import("hosted_erasure_preflight.zig");
const mailbox_export = @import("mailbox_export.zig");
const time = @import("../core/time_compat.zig");
const security = @import("../auth/security.zig");
const submission = @import("../delivery/submission.zig");

pub const Review = struct {
    version: u8,
    mailbox: []const u8,
    assignment_actor: []const u8,
    identity: preflight.Identity,
    case_reference: []const u8,
    recipient_verification_reference: []const u8,
    recipient: []const u8,
    expires_at: i64,
};

const Prepared = struct {
    identity: preflight.Identity,
    case_reference: []const u8,
    recipient_verification_reference: []const u8,
    recipient: []const u8,
    expires_at: i64,
    archive_sha256: []const u8,
    archive_bytes: u64,
};

pub const Receipt = struct {
    version: u8 = 1,
    mailbox: []const u8,
    state: []const u8 = "private_archive_published",
    audit_id: i64,
    prepared: Prepared,
};

fn validateAssignment(a: std.mem.Allocator, tx: Database.Transaction, review: Review, now: i64) !void {
    if (review.expires_at <= now) return error.InvalidExportExpiry;
    const assignment = try preflight.identify(a, tx, review.mailbox, review.assignment_actor, now);
    const actual = assignment.identity;
    if (actual.initial_provisioning_operation == null or !actual.eql(review.identity)) return error.AssignmentChanged;
    if (assignment.access.state.readable()) return error.MailboxStillReadable;
}

fn auditPrepared(tx: Database.Transaction, review: Review, now: i64, operator: []const u8, details: []const u8) !i64 {
    const stmt = try tx.prepare(
        \\INSERT INTO audit_log(timestamp,action,actor,target,target_type,details,severity)
        \\VALUES(?1,'hosted.erasure.export.prepared',?2,?3,'hosted_mailbox',?4,'info') RETURNING id
    );
    defer stmt.finalize();
    try stmt.bind(1, now);
    try stmt.bind(2, operator);
    try stmt.bind(3, review.mailbox);
    try stmt.bind(4, details);
    if (!try stmt.step()) return error.StepFailed;
    const id = stmt.columnInt64(0);
    if (try stmt.step()) return error.StepFailed;
    return id;
}

pub fn write(a: std.mem.Allocator, io: std.Io, db: *Database, review: Review, operator: []const u8, destination: []const u8, options: mailbox_export.Options) !Receipt {
    if (review.version != 1) return error.UnsupportedExportReview;
    if (!preflight.validCaseReference(review.case_reference) or
        !preflight.validCaseReference(review.recipient_verification_reference)) return error.InvalidCaseReference;
    if (!security.validateEmailAddress(review.recipient) or !submission.isSafeAddress(review.recipient))
        return error.InvalidEmail;
    {
        var tx = try db.beginTransaction(.read);
        defer tx.deinit();
        try validateAssignment(a, tx, review, time.timestamp());
        try tx.commit();
    }

    var digest: [32]u8 = undefined;
    var pending = try mailbox_export.prepare(a, io, db, review.mailbox, destination, options, &digest);
    defer pending.deinit(io);
    const hex = std.fmt.bytesToHex(digest, .lower);
    const prepared: Prepared = .{
        .identity = review.identity,
        .case_reference = review.case_reference,
        .recipient_verification_reference = review.recipient_verification_reference,
        .recipient = review.recipient,
        .expires_at = review.expires_at,
        .archive_sha256 = try a.dupe(u8, &hex),
        .archive_bytes = try pending.file.length(io),
    };
    const details = try std.json.Stringify.valueAlloc(a, prepared, .{});
    const audit_id = blk: {
        var tx = try db.beginTransaction(.write);
        defer tx.deinit();
        const now = time.timestamp();
        try validateAssignment(a, tx, review, now);
        const id = try auditPrepared(tx, review, now, operator, details);
        try tx.commit();
        break :blk id;
    };
    try pending.link(io);
    return .{ .mailbox = review.mailbox, .audit_id = audit_id, .prepared = prepared };
}

pub const Handoff = struct {
    version: u8,
    export_audit_id: i64,
    mailbox: []const u8,
    assignment_actor: []const u8,
    case_reference: []const u8,
    recipient_verification_reference: []const u8,
    recipient: []const u8,
};

pub const HandoffReceipt = struct {
    version: u8 = 1,
    state: []const u8 = "private_handoff_ready",
    mailbox: []const u8,
    export_audit_id: i64,
    audit_id: i64,
    prepared: Prepared,
};

fn loadPrepared(a: std.mem.Allocator, tx: Database.Transaction, export_audit_id: i64, mailbox: []const u8) !Prepared {
    const row = try tx.prepare(
        \\SELECT details FROM audit_log
        \\WHERE id=?1 AND action='hosted.erasure.export.prepared' AND target=?2 AND target_type='hosted_mailbox'
    );
    defer row.finalize();
    try row.bind(1, export_audit_id);
    try row.bind(2, mailbox);
    if (!try row.step()) return error.ExportAuditNotFound;
    return std.json.parseFromSliceLeaky(Prepared, a, row.columnText(0), .{ .allocate = .alloc_always });
}

pub fn hasPreparedAudit(tx: Database.Transaction, mailbox: []const u8, case_reference: []const u8) !bool {
    const row = try tx.prepare(
        \\SELECT 1 FROM audit_log WHERE action='hosted.erasure.export.prepared' AND target=?1
        \\AND target_type='hosted_mailbox' AND json_extract(details,'$.case_reference')=?2 LIMIT 1
    );
    defer row.finalize();
    try row.bind(1, mailbox);
    try row.bind(2, case_reference);
    return row.step();
}

pub fn validateHandoffAudit(a: std.mem.Allocator, tx: Database.Transaction, handoff_audit_id: i64, mailbox: []const u8, case_reference: []const u8, identity: preflight.Identity) !void {
    const row = try tx.prepare(
        \\SELECT json_extract(details,'$.export_audit_id') FROM audit_log
        \\WHERE id=?1 AND action='hosted.erasure.export.handoff_authorized' AND target=?2 AND target_type='hosted_mailbox'
    );
    defer row.finalize();
    try row.bind(1, handoff_audit_id);
    try row.bind(2, mailbox);
    if (!try row.step() or row.columnIsNull(0)) return error.ExportHandoffAuditNotFound;
    const prepared = try loadPrepared(a, tx, row.columnInt64(0), mailbox);
    if (!identity.eql(prepared.identity) or !std.mem.eql(u8, case_reference, prepared.case_reference))
        return error.ExportHandoffAssignmentChanged;
}

fn matchHandoff(a: std.mem.Allocator, tx: Database.Transaction, handoff: Handoff, prepared: Prepared, now: i64) !void {
    if (!std.mem.eql(u8, handoff.case_reference, prepared.case_reference) or
        !std.mem.eql(u8, handoff.recipient_verification_reference, prepared.recipient_verification_reference) or
        !std.mem.eql(u8, handoff.recipient, prepared.recipient)) return error.ExportRecipientChanged;
    try validateAssignment(a, tx, .{
        .version = handoff.version,
        .mailbox = handoff.mailbox,
        .assignment_actor = handoff.assignment_actor,
        .identity = prepared.identity,
        .case_reference = prepared.case_reference,
        .recipient_verification_reference = prepared.recipient_verification_reference,
        .recipient = prepared.recipient,
        .expires_at = prepared.expires_at,
    }, now);
}

fn verifyBytes(io: std.Io, input: std.Io.File, prepared: Prepared, output: ?*std.Io.Writer) !void {
    const stat = try input.stat(io);
    if (stat.kind != .file or stat.permissions.toMode() & 0o077 != 0)
        return error.ExportArchiveNotPrivate;
    if (stat.size != prepared.archive_bytes) return error.ExportArchiveChanged;
    var digest = std.crypto.hash.sha2.Sha256.init(.{});
    var total: u64 = 0;
    var file_buffer: [4096]u8 = undefined;
    var reader = input.reader(io, &file_buffer);
    var chunk: [64 * 1024]u8 = undefined;
    while (true) {
        if (time.timestamp() >= prepared.expires_at) return error.InvalidExportExpiry;
        const count = try reader.interface.readSliceShort(&chunk);
        if (count == 0) break;
        total += count;
        if (total > prepared.archive_bytes) return error.ExportArchiveChanged;
        digest.update(chunk[0..count]);
        if (output) |writer| try writer.writeAll(chunk[0..count]);
    }
    const hex = std.fmt.bytesToHex(digest.finalResult(), .lower);
    if (total != prepared.archive_bytes or !std.mem.eql(u8, &hex, prepared.archive_sha256))
        return error.ExportArchiveChanged;
}

fn recordHandoff(a: std.mem.Allocator, tx: Database.Transaction, handoff: Handoff, now: i64, operator: []const u8, prepared: Prepared) !i64 {
    const lookup = try tx.prepare(
        \\SELECT id FROM audit_log WHERE action='hosted.erasure.export.handoff_authorized' AND target=?1
        \\AND target_type='hosted_mailbox' AND json_extract(details,'$.export_audit_id')=?2
    );
    defer lookup.finalize();
    try lookup.bind(1, handoff.mailbox);
    try lookup.bind(2, handoff.export_audit_id);
    if (try lookup.step()) return lookup.columnInt64(0);

    const details = try std.json.Stringify.valueAlloc(a, .{
        .export_audit_id = handoff.export_audit_id,
        .recipient = prepared.recipient,
        .recipient_verification_reference = prepared.recipient_verification_reference,
        .expires_at = prepared.expires_at,
        .archive_sha256 = prepared.archive_sha256,
        .archive_bytes = prepared.archive_bytes,
    }, .{});
    const row = try tx.prepare(
        \\INSERT INTO audit_log(timestamp,action,actor,target,target_type,details,severity)
        \\VALUES(?1,'hosted.erasure.export.handoff_authorized',?2,?3,'hosted_mailbox',?4,'info') RETURNING id
    );
    defer row.finalize();
    try row.bind(1, now);
    try row.bind(2, operator);
    try row.bind(3, handoff.mailbox);
    try row.bind(4, details);
    if (!try row.step()) return error.StepFailed;
    const id = row.columnInt64(0);
    if (try row.step()) return error.StepFailed;
    return id;
}

pub fn handoffArchive(a: std.mem.Allocator, io: std.Io, db: *Database, handoff: Handoff, operator: []const u8, source: []const u8, destination: []const u8) !HandoffReceipt {
    if (handoff.version != 1 or handoff.export_audit_id < 1) return error.InvalidExportHandoff;
    const prepared = blk: {
        var tx = try db.beginTransaction(.read);
        defer tx.deinit();
        const prepared = try loadPrepared(a, tx, handoff.export_audit_id, handoff.mailbox);
        try matchHandoff(a, tx, handoff, prepared, time.timestamp());
        try tx.commit();
        break :blk prepared;
    };

    const cwd = std.Io.Dir.cwd();
    const source_file = try cwd.openFile(io, source, .{ .follow_symlinks = false });
    defer source_file.close(io);
    var pending = try cwd.createFileAtomic(io, destination, .{ .permissions = .fromMode(0o600) });
    defer pending.deinit(io);
    var output_buffer: [64 * 1024]u8 = undefined;
    var output = pending.file.writer(io, &output_buffer);
    try verifyBytes(io, source_file, prepared, &output.interface);
    try output.interface.flush();
    try pending.file.sync(io);

    const audit_id = blk: {
        var tx = try db.beginTransaction(.write);
        defer tx.deinit();
        const now = time.timestamp();
        const current = try loadPrepared(a, tx, handoff.export_audit_id, handoff.mailbox);
        if (!prepared.identity.eql(current.identity) or
            !std.mem.eql(u8, prepared.archive_sha256, current.archive_sha256) or
            prepared.archive_bytes != current.archive_bytes or prepared.expires_at != current.expires_at)
            return error.ExportArchiveChanged;
        try matchHandoff(a, tx, handoff, current, now);
        const id = try recordHandoff(a, tx, handoff, now, operator, current);
        try tx.commit();
        break :blk id;
    };
    if (time.timestamp() >= prepared.expires_at) return error.InvalidExportExpiry;
    pending.link(io) catch |err| switch (err) {
        error.PathAlreadyExists => {
            const existing = try cwd.openFile(io, destination, .{ .follow_symlinks = false });
            defer existing.close(io);
            try verifyBytes(io, existing, prepared, null);
        },
        else => return err,
    };
    return .{ .mailbox = handoff.mailbox, .export_audit_id = handoff.export_audit_id, .audit_id = audit_id, .prepared = prepared };
}
