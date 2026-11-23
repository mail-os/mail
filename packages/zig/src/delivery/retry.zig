//! Dispatch accepted outbound mail, retry transient failures, and deliver a
//! local DSN after permanent failure. SMTP records the first attempt in the
//! persistent queue in the same transaction as its local delivery outcomes.
//!
//! Bounces are only ever delivered locally: the outbound queue carries
//! mail submitted by our own authenticated users, and never bouncing to
//! external addresses rules out backscatter.

const maildir_path = @import("../core/maildir_path.zig");
const std = @import("std");
const time_compat = @import("../core/time_compat.zig");
const fs_compat = @import("../core/fs_compat.zig");
const io_compat = @import("../core/io_compat.zig");
const config = @import("../core/config.zig");
const database = @import("../storage/database.zig");
const queue_mod = @import("queue.zig");
const outbound = @import("outbound.zig");
const bounce_mod = @import("bounce.zig");
const hosted_limits = @import("../storage/hosted_limits.zig");
const maildir_index = @import("../search/maildir_index.zig");
const message_refs = @import("../storage/message_refs.zig");

const State = struct {
    allocator: std.mem.Allocator,
    db: *database.Database,
    queue: queue_mod.MessageQueue,
    hostname: []const u8,
    extra_local_domains: ?[]const u8,
    delivery_method: config.DeliveryMethod,
    ses_region: []const u8,
    running: std.atomic.Value(bool),
    threads: [4]?std.Thread = @splat(null),
};

var state: ?*State = null;

const poll_interval_ms: u32 = 1_000;

/// Initialize the retry queue (persisted in the main DB) and spawn the
/// background worker. Call once at startup, after the database is open.
pub fn start(
    allocator: std.mem.Allocator,
    db: *database.Database,
    hostname: []const u8,
    extra_local_domains: ?[]const u8,
    delivery_method: config.DeliveryMethod,
    ses_region: []const u8,
) !void {
    if (state != null) return;

    const s = try allocator.create(State);
    errdefer allocator.destroy(s);

    const hostname_copy = try allocator.dupe(u8, hostname);
    errdefer allocator.free(hostname_copy);
    const domains_copy = if (extra_local_domains) |domains| try allocator.dupe(u8, domains) else null;
    errdefer if (domains_copy) |domains| allocator.free(domains);
    const region_copy = try allocator.dupe(u8, ses_region);
    errdefer allocator.free(region_copy);

    s.* = .{
        .allocator = allocator,
        .db = db,
        .queue = try queue_mod.MessageQueue.initWithDB(allocator, db),
        .hostname = hostname_copy,
        .extra_local_domains = domains_copy,
        .delivery_method = delivery_method,
        .ses_region = region_copy,
        .running = std.atomic.Value(bool).init(true),
    };
    errdefer s.queue.deinit();

    const pending = s.queue.getStats();
    if (pending.total > 0) {
        std.log.info("delivery retry queue: {d} message(s) pending from previous run", .{pending.total});
    }

    errdefer {
        s.running.store(false, .release);
        for (s.threads) |thread| if (thread) |worker| worker.join();
    }
    for (&s.threads) |*thread| thread.* = try std.Thread.spawn(.{}, workerLoop, .{s});
    state = s;
}

pub fn stop() void {
    const s = state orelse return;
    s.running.store(false, .release);
    for (s.threads) |thread| if (thread) |worker| worker.join();
    s.queue.deinit();
    s.allocator.free(s.hostname);
    if (s.extra_local_domains) |domains| s.allocator.free(domains);
    s.allocator.free(s.ses_region);
    s.allocator.destroy(s);
    state = null;
}

/// Record a failed first-attempt delivery for retry. Best-effort: if the
/// pipeline isn't running, the failure is logged and dropped (matching the
/// old behavior).
pub fn enqueueFailure(from: []const u8, to: []const u8, data: []const u8, hosted_user_id: i64) void {
    const s = state orelse {
        std.log.err("delivery retry queue not running; dropping failed delivery to {s}", .{to});
        return;
    };
    _ = s.queue.enqueueForHostedUser(from, to, data, hosted_user_id) catch |err| {
        std.log.err("failed to enqueue retry for {s}: {}", .{ to, err });
        return;
    };
    std.log.info("delivery to {s} queued for retry", .{to});
}

pub fn senderCanDispatch(hosted_user_id: i64) bool {
    if (hosted_user_id == 0) return true;
    const s = state orelse return false;
    return s.db.hostedSenderActive(hosted_user_id) catch false;
}

/// Bytes of the original message quoted in a DSN.
const dsn_original_bytes = 4096;

/// What a bounce says when the recipient's own server refused the address.
pub const status_no_such_recipient = "5.1.1";
/// What a bounce says when this server ran out of attempts: the address may
/// be good, and a sender must not take it for one that is not.
pub const status_gave_up = "4.4.7";

/// Return a message to its (local) sender at once: the recipient's server
/// said the address cannot receive mail, and asking again would only tell it
/// that this server sends to addresses that do not exist.
pub fn bounceNow(from: []const u8, to: []const u8, reason: []const u8, data: []const u8) void {
    const s = state orelse {
        std.log.err("delivery pipeline not running; no bounce for {s}", .{to});
        return;
    };
    std.log.warn("delivery to {s} refused for good; sending DSN to {s}", .{ to, from });
    deliverBounceLocally(s, from, to, reason, data[0..@min(data.len, dsn_original_bytes)], status_no_such_recipient);
}

fn workerLoop(s: *State) void {
    while (s.running.load(.acquire)) {
        const msg = s.queue.getNextPending() orelse {
            time_compat.sleepMs(poll_interval_ms);
            continue;
        };

        if (msg.hosted_user_id != 0 and !(s.db.hostedSenderActive(msg.hosted_user_id) catch false)) {
            s.queue.hold(msg.id) catch |err| std.log.err("could not hold the suspended sender's delivery: {}", .{err});
            continue;
        }

        // Copies for the bounce path: a permanent markForRetry frees the
        // queued message, so nothing from `msg` may be touched after it.
        const from_copy = s.allocator.dupe(u8, msg.from) catch null;
        defer if (from_copy) |f| s.allocator.free(f);
        const to_copy = s.allocator.dupe(u8, msg.to) catch null;
        defer if (to_copy) |t| s.allocator.free(t);
        const data_head = s.allocator.dupe(u8, msg.data[0..@min(msg.data.len, dsn_original_bytes)]) catch null;
        defer if (data_head) |d| s.allocator.free(d);

        outbound.deliverToRemote(
            s.allocator,
            msg.from,
            msg.to,
            msg.data,
            s.hostname,
            s.delivery_method,
            s.ses_region,
        ) catch |err| {
            var err_buf: [128]u8 = undefined;
            const err_msg = std.fmt.bufPrint(&err_buf, "delivery failed: {}", .{err}) catch "delivery failed";
            const refused_for_good = err == error.SmtpRecipientRejected;

            const update: anyerror!queue_mod.MessageQueue.RetryDisposition = if (refused_for_good) blk: {
                s.queue.markRejected(msg.id) catch |reject_err| break :blk reject_err;
                break :blk .permanent;
            } else s.queue.markForRetry(msg.id, err_msg);
            const disposition = update catch |qerr| {
                std.log.err("retry queue update failed: {}", .{qerr});
                continue;
            };
            // `msg` may be freed now — use only the copies.
            switch (disposition) {
                .scheduled => {
                    if (to_copy) |t| std.log.info("delivery to {s} rescheduled: {s}", .{ t, err_msg });
                },
                .permanent => {
                    if (from_copy != null and to_copy != null) {
                        std.log.warn("delivery to {s} permanently failed; sending DSN to {s}", .{ to_copy.?, from_copy.? });
                        deliverBounceLocally(s, from_copy.?, to_copy.?, err_msg, data_head orelse "", if (refused_for_good) status_no_such_recipient else status_gave_up);
                    }
                },
            }
            continue;
        };

        s.queue.markDelivered(msg.id) catch {};
        if (to_copy) |t| std.log.info("queued delivery to {s} succeeded on retry", .{t});
    }
}

/// Deliver an RFC 3464 bounce into the original (local) sender's maildir.
/// `from_addr` is the failed message's envelope sender.
fn isLocalBounceDomain(hostname: []const u8, extra_local_domains: ?[]const u8, sender_domain: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(sender_domain, hostname)) return true;
    if (std.mem.indexOfScalar(u8, hostname, '.')) |dot| {
        if (std.ascii.eqlIgnoreCase(sender_domain, hostname[dot + 1 ..])) return true;
    }
    if (extra_local_domains) |domains| {
        var it = std.mem.splitScalar(u8, domains, ',');
        while (it.next()) |raw| {
            const domain = std.mem.trim(u8, raw, " \t");
            if (std.ascii.eqlIgnoreCase(sender_domain, domain)) return true;
        }
    }
    return false;
}

fn deliverBounceLocally(s: *State, from_addr: []const u8, failed_to: []const u8, error_message: []const u8, original: []const u8, status: []const u8) void {
    // Only local senders get a DSN (no backscatter).
    const at_pos = std.mem.indexOfScalar(u8, from_addr, '@') orelse return;
    const sender_domain = from_addr[at_pos + 1 ..];
    if (!isLocalBounceDomain(s.hostname, s.extra_local_domains, sender_domain)) {
        std.log.info("not bouncing to external sender {s} (backscatter guard)", .{from_addr});
        return;
    }
    const local_part = from_addr[0..at_pos];
    maildir_path.validate(from_addr) catch return;
    const mailbox = if (s.db.userExists(from_addr) catch false) from_addr else local_part;

    maildir_path.validate(mailbox) catch return;

    var gen = bounce_mod.BounceGenerator.init(s.allocator, s.hostname) catch return;
    defer gen.deinit();
    const dsn = gen.generateBounceWithStatus(from_addr, failed_to, error_message, original, status) catch return;
    defer s.allocator.free(dsn);

    const ts = time_compat.milliTimestamp();
    var nonce_bytes: [8]u8 = undefined;
    io_compat.randomBytes(&nonce_bytes);
    const nonce = std.mem.readInt(u64, &nonce_bytes, .little);
    const dir = std.fmt.allocPrint(s.allocator, "mail/{s}/new", .{mailbox}) catch return;
    defer s.allocator.free(dir);
    fs_compat.cwd().makePath(dir) catch {};

    const path = std.fmt.allocPrint(s.allocator, "{s}/{d}.{d}.eml", .{ dir, ts, nonce }) catch return;
    defer s.allocator.free(path);

    hosted_limits.write(s.db, s.allocator, mailbox, path, dsn) catch |err| {
        std.log.err("failed to write DSN for {s}: {}", .{ from_addr, err });
        return;
    };

    std.log.info("DSN delivered to {s} for failed delivery to {s}", .{ from_addr, failed_to });

    s.db.lockMailboxes();
    defer s.db.unlockMailboxes();
    maildir_index.markLocked(s.db, mailbox, false, &.{message_refs.location("INBOX", std.fs.path.basename(path))}) catch |err|
        std.log.warn("could not queue a delivery status notice for search: {}", .{err});
}

test "retry module compiles" {
    // Smoke: the module's types resolve. The pipeline itself needs a DB
    // and network, covered by e2e verification.
    _ = enqueueFailure;
    _ = start;
}

test "bounce domains include configured local domains" {
    try std.testing.expect(isLocalBounceDomain("mail.example.com", null, "example.com"));
    try std.testing.expect(isLocalBounceDomain("mail.example.com", "other.test, tenant.test", "TENANT.TEST"));
    try std.testing.expect(!isLocalBounceDomain("mail.example.com", "other.test", "external.test"));
}

test "security: a bounce sender cannot escape the Maildir root" {
    const a = std.testing.allocator;
    var rnd: [8]u8 = undefined;
    io_compat.randomBytes(&rnd);
    const root = try std.fmt.allocPrint(a, "/tmp/mail-bounce-test-{x}", .{std.mem.readInt(u64, &rnd, .little)});
    defer a.free(root);
    try fs_compat.cwd().makePath(root);
    defer fs_compat.cwd().deleteTree(root) catch {};
    var prev: [4096]u8 = undefined;
    _ = std.c.getcwd(&prev, prev.len) orelse return error.GetCwdFailed;
    const root_z = try a.dupeSentinel(u8, root, 0);
    defer a.free(root_z);
    if (std.c.chdir(root_z.ptr) != 0) return error.ChdirFailed;
    defer _ = std.c.chdir(@ptrCast(&prev));
    var db = try database.Database.init(a, ":memory:");
    defer db.deinit();
    var s = State{
        .allocator = a,
        .db = &db,
        .queue = queue_mod.MessageQueue.init(a),
        .hostname = "test.local",
        .extra_local_domains = null,
        .delivery_method = .ses,
        .ses_region = "us-east-1",
        .running = std.atomic.Value(bool).init(false),
    };
    defer s.queue.deinit();
    // Any vulnerable write stays inside this owned scratch directory.
    deliverBounceLocally(&s, "../escape@test.local", "recipient@external.test", "permanent failure", "Subject: test\n\nbody", status_gave_up);
    try std.testing.expectError(error.FileNotFound, fs_compat.cwd().access("escape", .{}));
}
