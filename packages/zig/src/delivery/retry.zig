//! Retry + DSN pipeline for failed outbound deliveries.
//!
//! The SMTP session's detached outbound workers make exactly one delivery
//! attempt. Before this module, a failure was logged and the message
//! silently dropped — the sender never learned their mail didn't arrive.
//! Now a failure lands in the DB-backed MessageQueue (persistent across
//! restarts), a background worker retries with the queue's exponential
//! backoff (2^n minutes, 5 attempts), and a permanent failure generates an
//! RFC 3464 DSN delivered into the LOCAL sender's maildir.
//!
//! Bounces are only ever delivered locally: the outbound queue carries
//! mail submitted by our own authenticated users, and never bouncing to
//! external addresses rules out backscatter.

const std = @import("std");
const time_compat = @import("../core/time_compat.zig");
const fs_compat = @import("../core/fs_compat.zig");
const config = @import("../core/config.zig");
const database = @import("../storage/database.zig");
const queue_mod = @import("queue.zig");
const outbound = @import("outbound.zig");
const bounce_mod = @import("bounce.zig");
const typesense = @import("../search/typesense.zig");

const State = struct {
    allocator: std.mem.Allocator,
    db: *database.Database,
    queue: queue_mod.MessageQueue,
    hostname: []const u8,
    extra_local_domains: ?[]const u8,
    delivery_method: config.DeliveryMethod,
    ses_region: []const u8,
    running: std.atomic.Value(bool),
};

var state: ?*State = null;

const poll_interval_ms: u32 = 30_000;

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

    const thread = try std.Thread.spawn(.{}, workerLoop, .{s});
    state = s;
    thread.detach();
}

/// Record a failed first-attempt delivery for retry. Best-effort: if the
/// pipeline isn't running, the failure is logged and dropped (matching the
/// old behavior).
pub fn enqueueFailure(from: []const u8, to: []const u8, data: []const u8) void {
    const s = state orelse {
        std.log.err("delivery retry queue not running; dropping failed delivery to {s}", .{to});
        return;
    };
    const id = s.queue.enqueue(from, to, data) catch |err| {
        std.log.err("failed to enqueue retry for {s}: {}", .{ to, err });
        return;
    };
    std.log.info("delivery to {s} queued for retry (id {s})", .{ to, id });
}

/// Bytes of the original message quoted in a DSN.
const dsn_original_bytes = 4096;

fn workerLoop(s: *State) void {
    while (s.running.load(.monotonic)) {
        const msg = s.queue.getNextPending() orelse {
            time_compat.sleepMs(poll_interval_ms);
            continue;
        };

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

            const disposition = s.queue.markForRetry(msg.id, err_msg) catch |qerr| {
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
                        deliverBounceLocally(s, from_copy.?, to_copy.?, err_msg, data_head orelse "");
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

fn deliverBounceLocally(s: *State, from_addr: []const u8, failed_to: []const u8, error_message: []const u8, original: []const u8) void {
    // Only local senders get a DSN (no backscatter).
    const at_pos = std.mem.indexOfScalar(u8, from_addr, '@') orelse return;
    const sender_domain = from_addr[at_pos + 1 ..];
    if (!isLocalBounceDomain(s.hostname, s.extra_local_domains, sender_domain)) {
        std.log.info("not bouncing to external sender {s} (backscatter guard)", .{from_addr});
        return;
    }
    const local_part = from_addr[0..at_pos];
    const mailbox = if (s.db.userExists(from_addr) catch false) from_addr else local_part;

    var gen = bounce_mod.BounceGenerator.init(s.allocator, s.hostname) catch return;
    defer gen.deinit();
    const dsn = gen.generateBounce(from_addr, failed_to, error_message, original) catch return;
    defer s.allocator.free(dsn);

    const ts = time_compat.milliTimestamp();
    const nonce = std.crypto.random.int(u64);
    const dir = std.fmt.allocPrint(s.allocator, "mail/{s}/new", .{mailbox}) catch return;
    defer s.allocator.free(dir);
    fs_compat.cwd().makePath(dir) catch {};

    const path = std.fmt.allocPrint(s.allocator, "{s}/{d}.{d}.eml", .{ dir, ts, nonce }) catch return;
    defer s.allocator.free(path);

    const file = fs_compat.cwd().createFile(path, .{ .exclusive = true }) catch |err| {
        std.log.err("failed to write DSN for {s}: {}", .{ from_addr, err });
        return;
    };
    file.writeAll(dsn) catch {
        file.close();
        fs_compat.cwd().deleteFile(path) catch {};
        return;
    };
    file.close();

    std.log.info("DSN delivered to {s} for failed delivery to {s}", .{ from_addr, failed_to });

    // Index the DSN for search like any other delivery
    var base_buf: [64]u8 = undefined;
    if (std.fmt.bufPrint(&base_buf, "{d}.{d}.eml", .{ ts, nonce })) |base| {
        typesense.indexMessageAsync(s.allocator, mailbox, "INBOX", base, dsn);
    } else |_| {}
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
