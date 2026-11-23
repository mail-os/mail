//! Admission and recovery for Maildir delivery. Call planning and acceptance
//! under the same mailbox lock used by IMAP, webmail and hosted storage quotas.
const std = @import("std");
const aliases = @import("aliases.zig");
pub const categories = @import("../message/categories.zig");
const config_mod = @import("../core/config.zig");
const db_mod = @import("../storage/database.zig");
const durable = @import("../core/durable_maildir.zig");
const forwarding = @import("../message/forwarding.zig");
const vacation = @import("../message/vacation.zig");
const fs = @import("../core/fs_compat.zig");
const hosted = @import("../storage/hosted_limits.zig");
const hot_reload = @import("../core/hot_reload.zig");
const io = @import("../core/io_compat.zig");
const logger = @import("../core/logger.zig");
const path = @import("../core/maildir_path.zig");
const message_refs = @import("../storage/message_refs.zig");
const mailbox_mime = @import("../api/webmail_maildir.zig");
const sieve = @import("../features/sieve.zig");
const submission_headers = @import("../message/submission.zig");
const thread_ids = @import("../message/thread_ids.zig");
const time = @import("../core/time_compat.zig");
const typesense = @import("../search/typesense.zig");
const webhook = @import("../features/webhook.zig");

const Allocator = std.mem.Allocator;
const Database = db_mod.Database;
pub const Target = Database.DeliveryTarget;
var id_sequence: std.atomic.Value(u64) = .init(0);

pub const SenderIdentity = struct {
    author: []const u8,
    verified: bool,

    pub fn fromHeaders(a: Allocator, raw: []const u8, authenticated: bool) !SenderIdentity {
        const author = (submission_headers.author(a, raw) catch |err| switch (err) {
            error.InvalidFrom => null,
            else => return err,
        }) orelse "";
        return .{ .author = author, .verified = authenticated and author.len > 0 };
    }
};

pub fn newId() [32]u8 {
    var bytes: [16]u8 = undefined;
    io.randomBytes(&bytes);
    const sequence = id_sequence.fetchAdd(1, .monotonic);
    const bits = std.mem.readInt(u64, bytes[8..16], .little);
    std.mem.writeInt(u64, bytes[8..16], bits ^ sequence, .little);
    return std.fmt.bytesToHex(bytes, .lower);
}

pub fn isLocal(address: []const u8, hostname: []const u8, config: ?*const config_mod.Config) bool {
    const at = std.mem.indexOfScalar(u8, address, '@') orelse return true;
    const domain = address[at + 1 ..];
    if (config) |cfg| return cfg.isLocalDomain(domain);
    if (std.ascii.eqlIgnoreCase(domain, hostname)) return true;
    const dot = std.mem.indexOfScalar(u8, hostname, '.') orelse return false;
    return std.ascii.eqlIgnoreCase(domain, hostname[dot + 1 ..]);
}

pub fn resolveMailbox(a: Allocator, db: ?*Database, config: ?*const config_mod.Config, address: []const u8) ![]const u8 {
    if (config) |cfg| if (cfg.catch_all) return a.dupe(u8, cfg.catch_all_mailbox);
    if (db) |database| {
        if (try database.userExists(address)) return a.dupe(u8, address);
        const lower = try std.ascii.allocLowerString(a, address);
        errdefer a.free(lower);
        if (try database.userExists(lower)) return lower;
        a.free(lower);
    }
    const at = std.mem.indexOfScalar(u8, address, '@') orelse address.len;
    return aliases.resolve(a, address[0..at]);
}

pub const Plan = struct {
    allocator: Allocator,
    db: *Database,
    bytes: u64,
    raw: []const u8 = "",
    junk_folder: []const u8 = "Junk",
    automatic_category: ?categories.Placement = null,
    targets: std.ArrayList(Target) = .empty,
    reservations: std.StringHashMapUnmanaged(u64) = .empty,

    pub fn classify(self: *Plan, target: *Target, sender: SenderIdentity) !void {
        if (try self.applyJunkFeedback(target, sender)) return;
        try self.applySenderRoute(target, sender);
        if (target.placement_reason == .not_junk_feedback) {
            // A soft-spam correction controls storage, never automatic copies
            // or replies. Existing sender review still applies.
            target.forward_allowed = false;
            return;
        }
        if (target.review_copy or !sender.verified) return;
        const policy = try self.db.categoryPolicy(target.mailbox, sender.author);
        const placement: ?categories.Placement = if (policy.destination) |destination|
            .{ .destination = destination, .reason = .sender_rule }
        else if (policy.automatic)
            self.automatic_category
        else
            null;
        if (placement) |selected| {
            target.folder = selected.destination.folder();
            target.placement_reason = selected.reason;
        }
    }

    fn applyJunkFeedback(self: *Plan, target: *Target, sender: SenderIdentity) !bool {
        const scored_junk = std.mem.eql(u8, target.folder, self.junk_folder);
        if (scored_junk) target.placement_reason = .spam_filter;
        if (std.mem.eql(u8, target.folder, "new") or scored_junk) {
            const feedback = if (sender.verified) try self.db.junkPreference(target.mailbox, sender.author) else null;
            if (feedback == .junk) {
                target.folder = self.junk_folder;
                target.placement_reason = .junk_feedback;
            } else if (scored_junk and feedback == .not_junk) {
                target.folder = "new";
                target.placement_reason = .not_junk_feedback;
            }
        }
        if (std.mem.eql(u8, target.folder, "new")) return false;
        target.forward_allowed = false;
        return true;
    }

    fn applySenderRoute(self: *Plan, target: *Target, sender: SenderIdentity) !void {
        const route = try self.db.senderRoute(target.mailbox, if (sender.verified) sender.author else null);
        target.forward_allowed = route == .allow;
        target.review_copy = route == .review or route == .decline;
        target.folder = switch (route) {
            .allow, .allow_without_forward => "new",
            .review => "Screening",
            .decline => "Declined",
        };
    }

    pub fn addLocal(self: *Plan, target: Target) !void {
        try path.validate(target.mailbox);
        try path.validate(target.folder);
        const already = self.reservations.get(target.mailbox) orelse 0;
        const extra = if (target.verified_forward) forwarding.loop_header.len else 0;
        const copy_bytes = if (target.reply) |reply| reply.mime.len else std.math.add(u64, self.bytes, extra) catch return error.HostedStorageFull;
        const requested = std.math.add(u64, already, copy_bytes) catch return error.HostedStorageFull;
        try hosted.checkStorage(self.db, target.mailbox, requested, null);
        try self.reservations.put(self.allocator, target.mailbox, requested);
        try self.add(target);
    }

    pub fn add(self: *Plan, target: Target) !void {
        try self.targets.append(self.allocator, target);
    }

    /// Only direct, authenticated human messages can trigger vacation mail.
    /// Requiring the authenticated author to match the reverse-path prevents
    /// backscatter to an unrelated envelope sender or Reply-To address.
    pub fn vacationReplies(self: *Plan, count: usize, from: []const u8, hostname: []const u8, config: ?*const config_mod.Config, sender: SenderIdentity, now: i64) !void {
        if (!sender.verified or !std.ascii.eqlIgnoreCase(from, sender.author) or !vacation.safeCorrespondent(from)) return;
        const a = self.allocator;
        var headers: ?vacation.Headers = null;
        var seen: std.StringHashMapUnmanaged(void) = .empty;
        defer seen.deinit(a);
        for (0..count) |primary| {
            const target = self.targets.items[primary];
            if (target.mailbox.len == 0 or target.refusal != null or target.review_copy or target.placement_reason == .not_junk_feedback) continue;
            if (!std.mem.eql(u8, target.folder, "new") and !std.mem.eql(u8, target.folder, "Newsletters") and !std.mem.eql(u8, target.folder, "Receipts")) continue;
            if (std.ascii.eqlIgnoreCase(target.mailbox, from) or std.ascii.eqlIgnoreCase(target.recipient, from)) continue;
            if (seen.contains(target.mailbox)) continue;
            const settings = try self.db.vacationSettings(a, target.mailbox);
            if (!settings.enabled or now < (settings.startsAt orelse now) or now >= (settings.endsAt orelse std.math.maxInt(i64))) continue;
            if (headers == null) headers = (try vacation.inspect(a, self.raw)) orelse return;
            const author = if (headers.?.namesMailbox(target.recipient)) target.recipient else target.mailbox;
            if (!vacation.safeCorrespondent(author) or !headers.?.namesMailbox(author)) continue;
            try seen.put(a, target.mailbox, {});
            const mailbox = if (isLocal(from, hostname, config)) try resolveMailbox(a, self.db, config, from) else "";
            if (mailbox.len > 0) {
                if (std.mem.eql(u8, mailbox, target.mailbox) or (try self.db.enabledMailboxId(mailbox)) == null) continue;
            }
            const eml = try vacation.render(a, author, from, settings.subject, settings.body, headers.?.message_id, now);
            var reply: Target = .{
                .recipient = from,
                .mailbox = mailbox,
                .folder = if (mailbox.len > 0) "new" else "",
                .forward_owner = target.mailbox,
                .forward_after = primary,
                .reply = .{ .author = author, .from = try forwarding.sender(a, author, hostname), .mime = eml },
            };
            if (mailbox.len == 0) {
                try self.add(reply);
                continue;
            }
            const identity: SenderIdentity = .{ .author = author, .verified = true };
            if (!try self.applyJunkFeedback(&reply, identity)) try self.applySenderRoute(&reply, identity);
            self.addLocal(reply) catch |err| {
                reply.refusal = switch (err) {
                    error.HostedStorageFull => "vacation_storage_full",
                    error.HostedRecipientDisabled => "vacation_recipient_disabled",
                    error.InvalidMailboxPath => "vacation_invalid_recipient",
                    error.MaildirUsageUnavailable => "vacation_storage_unavailable",
                    else => return err,
                };
                try self.add(reply);
            };
        }
    }

    /// Redirect one hop. Keep the primary copy and checkpoint per-target
    /// refusals so a full forwarding destination cannot lose the original.
    pub fn forward(self: *Plan, primary: usize, from: []const u8, hostname: []const u8, config: ?*const config_mod.Config, sender: SenderIdentity, delivered_to: []const u8) !void {
        const a = self.allocator;
        const user = self.targets.items[primary].mailbox;
        const headers = forwarding.Headers.read(self.raw);
        if (headers.forwarded) return;
        for (try forwardDestinations(a, user, from)) |recipient| {
            const mailbox = if (isLocal(recipient, hostname, config)) try resolveMailbox(a, self.db, null, recipient) else "";
            if (!std.mem.eql(u8, mailbox, user)) try self.addForward(primary, recipient, mailbox, sender, false);
        }
        if (from.len == 0 or headers.automatic) return;
        const verified = (try self.db.verifiedForward(a, user)) orelse return;
        if (verified.scope.sender) |author| {
            if (!sender.verified or !std.ascii.eqlIgnoreCase(author, sender.author)) return;
        }
        if (verified.scope.recipient) |recipient| {
            if (!std.ascii.eqlIgnoreCase(recipient, delivered_to)) return;
        }
        if (std.ascii.eqlIgnoreCase(verified.address, from)) return;
        const local = isLocal(verified.address, hostname, config);
        const mailbox = if (local) try resolveMailbox(a, self.db, config, verified.address) else "";
        if (local) {
            if (std.mem.eql(u8, mailbox, user)) return;
            const current_id = (try self.db.enabledMailboxId(mailbox)) orelse return;
            if (verified.mailbox_id != current_id) return;
        } else if (verified.mailbox_id != null) return;
        for (self.targets.items) |target| {
            if (std.ascii.eqlIgnoreCase(target.recipient, verified.address) or
                (local and std.mem.eql(u8, target.mailbox, mailbox))) return;
        }
        if (local) return self.addForward(primary, verified.address, mailbox, sender, true);

        var target: Target = .{ .recipient = verified.address, .forward_owner = user, .forward_after = primary };
        // The receiving relay can verify our own sender while the attached
        // original keeps the sender's bytes. The SES v1 raw limit includes MIME.
        const ses_limit = if (config) |cfg| cfg.delivery_method == .ses else false;
        if (ses_limit and !forwarding.fitsSes(self.raw.len)) {
            target.refusal = "forward_message_too_large";
        } else {
            target.outbound_from = try forwarding.sender(a, user, hostname);
            target.outbound_subject = headers.subject;
        }
        try self.add(target);
    }

    fn addForward(self: *Plan, primary: usize, recipient: []const u8, mailbox: []const u8, sender: SenderIdentity, verified: bool) !void {
        var target: Target = .{
            .recipient = recipient,
            .mailbox = mailbox,
            .folder = if (mailbox.len == 0) "" else "new",
            .forward_owner = self.targets.items[primary].mailbox,
            .forward_after = primary,
            .verified_forward = verified,
        };
        if (mailbox.len == 0) return self.add(target);
        try self.classify(&target, sender);
        self.addLocal(target) catch |err| {
            target.refusal = switch (err) {
                error.HostedStorageFull => "forward_storage_full",
                error.HostedRecipientDisabled => "forward_disabled",
                error.InvalidMailboxPath => "forward_invalid_target",
                error.MaildirUsageUnavailable => "forward_storage_unavailable",
                else => return err,
            };
            try self.add(target);
        };
    }
};

fn forwardDestinations(a: Allocator, user: []const u8, from: []const u8) ![]const []const u8 {
    var targets: std.ArrayList([]const u8) = .empty;
    if (fs.readFileAlloc(a, "forwards.sieve")) |source| {
        var parser = sieve.SieveParser.init(a);
        defer parser.deinit();
        var script = parser.parse(source) catch {
            std.log.warn("Invalid forwarding Sieve; keeping the original message", .{});
            return &.{};
        };
        defer script.deinit();
        if (!script.is_valid) return &.{};
        var message = sieve.SieveMessage.init(a);
        defer message.deinit();
        message.envelope_from = from;
        message.envelope_to = user;
        var evaluator = sieve.SieveEvaluator.init(a);
        for (try evaluator.evaluate(&script, &message)) |action| {
            if (action.action_type == .redirect) {
                if (action.argument) |destination| try targets.append(a, try a.dupe(u8, destination));
            }
        }
    } else |_| {
        const source = fs.readFileAlloc(a, "forwards.json") catch return &.{};
        const parsed = std.json.parseFromSlice(std.json.Value, a, source, .{}) catch return &.{};
        defer parsed.deinit();
        if (parsed.value != .object) return &.{};
        const destinations = parsed.value.object.get(user) orelse return &.{};
        if (destinations != .array) return &.{};
        for (destinations.array.items) |target| if (target == .string) try targets.append(a, try a.dupe(u8, target.string));
    }
    return targets.items;
}

/// Synchronous fast path. Admission is already durable, so a failed Maildir
/// write leaves its payload and reservation for the background worker.
pub fn publish(allocator: Allocator, db: *Database, id: []const u8) void {
    drain(allocator, db, id, std.math.maxInt(usize)) catch |err| std.log.err("could not finish accepted delivery {s}: {}", .{ id, err });
}

pub fn recover(allocator: Allocator, db: *Database) !void {
    try db.retryAcceptedDeliveriesOnStartup(time.timestamp());
    try drain(allocator, db, null, std.math.maxInt(usize));
}

fn drain(allocator: Allocator, db: *Database, id: ?[]const u8, limit: usize) !void {
    for (0..limit) |_| {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        db.lockMailboxes();
        defer db.unlockMailboxes();
        const now = time.timestamp();
        const target = (try db.pendingDelivery(a, id, now)) orelse return;
        if (target.mailbox_removed) {
            try db.finishDeliveryTarget(target.id, target.ordinal, "mailbox_removed", null);
            continue;
        }
        const filename = try std.fmt.allocPrint(a, "{d}.{s}.{d}.route.eml", .{ target.accepted_ms, target.id, target.ordinal });
        const attention = try attentionArrival(a, target.mime);
        const notification_key = if (try db.browserNotificationsEnabled(target.mailbox))
            try browserNotificationKey(a, target.mime, attention)
        else
            "";
        const revisions = try mailbox_mime.calendarRevisions(a, target.mime, target.calendar_attendee, target.calendar_author);
        const file = fileTarget(a, target, filename) catch |err| {
            std.log.warn("accepted delivery {s}/{d} is awaiting local storage: {}", .{ target.id, target.ordinal, err });
            const wait_seconds = @as(i64, 2) << @as(u6, @intCast(target.attempts));
            try db.delayDeliveryTarget(target, now + wait_seconds);
            continue;
        };
        if (!std.mem.eql(u8, target.folder, "new")) {
            _ = db.getOrCreateMailbox(target.mailbox, target.folder) catch |err|
                std.log.warn("accepted delivery could not register its destination folder: {}", .{err});
        }
        const is_team_reply = (target.team_reply_candidate or target.team_sent_reply_candidate) and
            attention != null and attention.?.reply_parent != null;
        const stamp = if (target.track_placement or target.review_copy or (target.team_sent_reply_candidate and is_team_reply)) message_refs.fileStamp(a, file) catch |err| {
            fs.cwd().deleteFile(file) catch {};
            return err;
        } else "";
        db.finishDeliveryTarget(target.id, target.ordinal, "filed", .{
            .basename = filename,
            .stamp = stamp,
            .size = target.mime.len,
            .attention = attention,
            .notification_key = notification_key,
            .thread_reply_digest = if (is_team_reply) message_refs.digest(target.mime) else null,
            .thread_reply_outgoing = is_team_reply and target.team_sent_reply_candidate,
            .calendar_revisions = revisions,
        }) catch |err| {
            // Leave the reservation intact. Do not let an active mailbox
            // session move a file whose checkpoint could not be committed.
            fs.cwd().deleteFile(file) catch |unlink_err| std.log.err("could not hide uncheckpointed delivery: {}", .{unlink_err});
            return err;
        };
    }
}

pub fn attentionArrival(a: Allocator, raw: []const u8) !?Database.AttentionArrival {
    const headers = try thread_ids.parse(a, raw);
    if (headers.parents.len == 0 and headers.own == null) return null;
    return .{
        .own = headers.own,
        .parents_json = try std.json.Stringify.valueAlloc(a, headers.parents, .{}),
        .automatic = headers.automatic,
        .reply_parent = headers.reply_parent,
    };
}

pub fn browserNotificationKey(a: Allocator, raw: []const u8, attention: ?Database.AttentionArrival) ![]const u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    const crlf = std.mem.indexOf(u8, raw, "\r\n\r\n") orelse raw.len;
    const lf = std.mem.indexOf(u8, raw, "\n\n") orelse raw.len;
    const boundary = @min(crlf, lf);
    if (attention) |headers| if (headers.own) |id| {
        hash.update(id);
    };
    // Submission can synthesize a different Date and Received header on each
    // attempt. Use the Message-ID, subject and body for the duplicate identity.
    var lines = std.mem.splitScalar(u8, raw[0..boundary], '\n');
    var collecting = false;
    while (lines.next()) |line| {
        const continuation = line.len > 0 and (line[0] == ' ' or line[0] == '\t');
        if (!continuation) collecting = std.ascii.startsWithIgnoreCase(line, "Subject:");
        if (collecting) {
            hash.update(&.{0});
            hash.update(std.mem.trim(u8, line, " \t\r"));
        }
    }
    hash.update(raw[boundary..]);
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return a.dupe(u8, &std.fmt.bytesToHex(digest, .lower));
}

fn fileTarget(a: Allocator, target: Database.PendingDelivery, filename: []const u8) ![]const u8 {
    try path.validate(target.mailbox);
    try path.validate(target.folder);
    const dir = try std.fmt.allocPrint(a, "mail/{s}/{s}", .{ target.mailbox, target.folder });
    try fs.cwd().makePath(dir);
    const file = try std.fmt.allocPrint(a, "{s}/{s}", .{ dir, filename });
    durable.resumeWrite(a, file, target.mime) catch |err| {
        if (err == error.MaildirSyncFailed) fs.cwd().deleteFile(file) catch {};
        return err;
    };
    return file;
}

pub fn runRecovery(allocator: Allocator, db: *Database, shutdown: *std.atomic.Value(bool)) void {
    var sweep_at: i64 = 0;
    while (!shutdown.load(.acquire)) {
        drain(allocator, db, null, 100) catch |err| std.log.err("local delivery recovery failed: {}", .{err});
        const now = time.timestamp();
        if (now >= sweep_at) {
            db.sweepDeliveryJournal(now - 7 * 86400) catch |err| std.log.warn("could not prune local delivery receipts: {}", .{err});
            sweep_at = now + 60;
        }
        time.sleepMs(1000);
    }
}

pub fn runEffects(allocator: Allocator, db: *Database, shutdown: *std.atomic.Value(bool), reload: *hot_reload.HotReloadManager, log: *logger.Logger) void {
    while (!shutdown.load(.acquire)) {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const effect = (db.nextDeliveryEffect(a) catch |err| blk: {
            std.log.err("could not read the delivery effects queue: {}", .{err});
            break :blk null;
        }) orelse {
            time.sleepMs(1000);
            continue;
        };
        if (!effect.mailbox_removed) {
            if (effect.index_pending and typesense.enabled()) indexDelivery(a, effect) catch |err| {
                std.log.warn("could not index delivered mail: {}", .{err});
            };
            if (effect.notice_pending) {
                const cfg = reload.snapshotWebhook(a) catch |err| {
                    std.log.warn("could not read delivery webhook settings: {}", .{err});
                    time.sleepMs(1000);
                    continue;
                };
                webhook.sendWebhook(a, cfg, .{
                    .from = effect.from,
                    .recipients = &.{effect.recipient},
                    .size = effect.size,
                    .timestamp = effect.accepted_at,
                    .remote_addr = effect.remote_addr,
                }, log) catch |err| std.log.warn("delivery webhook failed: {}", .{err});
            }
        }
        db.finishDeliveryEffect(effect) catch |err| {
            std.log.err("could not checkpoint delivery effects: {}", .{err});
            time.sleepMs(1000);
        };
    }
}

fn indexDelivery(a: Allocator, effect: Database.DeliveryEffect) !void {
    const inbox = std.mem.eql(u8, effect.folder, "new");
    const directories: []const []const u8 = if (inbox) &.{ "new", "cur" } else &.{effect.folder};
    for (directories) |subdir| {
        const dir = try std.fmt.allocPrint(a, "mail/{s}/{s}", .{ effect.mailbox, subdir });
        const names = fs.listEmlFiles(a, dir) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        for (names) |name| {
            if (!std.mem.eql(u8, db_mod.maildirBaseName(name), effect.filename)) continue;
            const file = try std.fmt.allocPrint(a, "{s}/{s}", .{ dir, name });
            const raw = try fs.readFileAlloc(a, file);
            return typesense.indexRawMessage(a, effect.mailbox, if (inbox) "INBOX" else effect.folder, name, raw);
        }
    }
}
