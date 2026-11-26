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
    const initial = actual.initial_provisioning_operation orelse return error.AssignmentChanged;
    const expected = review.identity.initial_provisioning_operation orelse return error.AssignmentChanged;
    if (actual.native_user_id != review.identity.native_user_id or
        actual.provisioning_revision != review.identity.provisioning_revision or
        !std.mem.eql(u8, initial, expected)) return error.AssignmentChanged;
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
