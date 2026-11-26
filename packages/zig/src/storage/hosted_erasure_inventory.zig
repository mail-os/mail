//! Mailbox-scoped inventory for hosted erasure review. Counts only, no cleanup.
const std = @import("std");
const Database = @import("database.zig").Database;
const preflight = @import("hosted_erasure_preflight.zig");
const maildir_path = @import("../core/maildir_path.zig");
const time = @import("../core/time_compat.zig");
const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;

const TableCount = struct { table: []const u8, matching_rows: ?u64 };
const Sqlite = struct { tables: []const TableCount, unscoped_tables: [][]const u8 };
const Names = struct { user_id: i64, mailbox: []const u8 };
const Key = enum { user_id, mailbox, both };

const by_user_id = [_][]const u8{
    "hosted_mailbox_activity",     "hosted_sending_holds",      "hosted_retired_mailboxes",     "hosted_sending_usage",
    "eas_search_keys",             "mail_search_pending",       "mail_search_checkpoints",      "mailbox_message_refs",
    "mail_ews_reply_drafts",       "mail_ews_draft_sends",      "mail_ews_draft_finalizations", "mail_retention_rules",
    "mail_retention_previews",     "mail_retention_moves",      "mailbox_junk_feedback",        "webmail_search_docs",
    "mail_private_anchors",        "mail_private_entries",      "mail_private_labels",          "mail_private_groups",
    "mail_private_collections",    "mail_private_members",      "mail_attention",               "mail_attention_replies",
    "mail_notification_settings",  "mail_notification_senders", "mail_notification_threads",    "mail_notification_events",
    "mail_category_settings",      "mail_category_rules",       "mailbox_forwarding",           "mailbox_forwarding_scopes",
    "mailbox_forwarding_requests", "mailbox_vacation",          "mailbox_vacation_sends",       "mail_calendar_day_labels",
    "mail_calendar_tasks",         "mail_calendar_tools",       "mail_calendar_revisions",      "mail_snapshot_links",
    "mail_assistant_grants",       "mail_file_links",           "sender_screening",             "sender_screening_rules",
    "sender_review_invitations",   "sender_review_messages",    "eas_mailbox_state",            "ews_item_sync",
    "eas_mailbox_ping",            "eas_folder_stamp_aliases",  "mail_team_members",            "mail_client_passwords",
    "webmail_mfa_factors",         "webmail_mfa_enrollment",    "webmail_mfa_recovery_codes",   "webmail_mfa_session_tickets",
    "provisioned_mailboxes",
};
const by_username = [_][]const u8{
    "webmail_sessions", "mailbox_reset_tokens", "password_reset_tokens",    "eas_accepted_submissions",
    "imap_mailboxes",   "imap_uids",            "imap_mailbox_generations", "webmail_records",
    "webmail_uploads",
};
const share = "share_id IN (SELECT id FROM mail_team_thread_shares WHERE owner_id=?1 OR grantee_id=?1)";
const grant = "grant_id IN (SELECT id FROM mail_assistant_grants WHERE user_id=?1)";
const scopes = [_]struct { table: []const u8, predicate: []const u8, key: Key = .user_id }{
    .{ .table = "users", .predicate = "id=?1" },
    .{ .table = "provisioning_operations", .predicate = "mailbox=?1", .key = .mailbox },
    .{ .table = "accepted_mail", .predicate = "hosted_sender_id=?1" },
    .{ .table = "accepted_mail_targets", .predicate = "mailbox_id=?1 OR delivery_id IN (SELECT id FROM accepted_mail WHERE hosted_sender_id=?1)" },
    .{ .table = "message_queue", .predicate = "hosted_user_id=?1" },
    .{ .table = "webmail_account_links", .predicate = "source_user_id=?1 OR owner_session IN (SELECT session_id FROM webmail_sessions WHERE username=?2)", .key = .both },
    .{ .table = "mail_assistant_audit", .predicate = grant },
    .{ .table = "mail_assistant_requests", .predicate = grant },
    .{ .table = "mail_team_owner_handoffs", .predicate = "departing=?1 OR successor=?1", .key = .mailbox },
    .{ .table = "mail_team_invitations", .predicate = "inviter_id=?1 OR recipient_id=?1" },
    .{ .table = "mail_team_grants", .predicate = "source_id=?1 OR grantee_id=?1" },
    .{ .table = "mail_team_calendar_shares", .predicate = "source_id=?1 OR grantee_id=?1" },
    .{ .table = "mail_team_calendar_share_epochs", .predicate = "source_id=?1 OR grantee_id=?1" },
    .{ .table = "mail_team_thread_shares", .predicate = "owner_id=?1 OR grantee_id=?1" },
    .{ .table = "mail_team_thread_restrictions", .predicate = share },
    .{ .table = "mail_team_collection_shares", .predicate = share },
    .{ .table = "mail_team_thread_messages", .predicate = share },
    .{ .table = "mail_team_thread_comments", .predicate = "author_id=?1 OR " ++ share },
    .{ .table = "mail_team_thread_follow", .predicate = share },
    .{ .table = "mail_team_thread_follow_sent", .predicate = share },
    .{ .table = "mail_team_thread_replies", .predicate = share },
    .{ .table = "mail_team_thread_submissions", .predicate = "owner_id=?1" },
    .{ .table = "mail_team_thread_native_sent", .predicate = "delivery_id IN (SELECT delivery_id FROM mail_team_thread_submissions WHERE owner_id=?1)" },
    .{ .table = "mail_team_smtp_submissions", .predicate = "owner_id=?1" },
    .{ .table = "mail_team_smtp_sent_copies", .predicate = "owner_id=?1" },
};

fn count(tx: Database.Transaction, comptime table: []const u8, comptime predicate: []const u8, key: Key, names: Names) !TableCount {
    // An older schema can lack either the table or the ownership columns.
    // Its result must be distinct from a matched table with zero rows.
    const stmt = tx.prepare("SELECT count(*) FROM " ++ table ++ " WHERE " ++ predicate) catch |err| switch (err) {
        error.PrepareFailed => return .{ .table = table, .matching_rows = null },
        else => return err,
    };
    defer stmt.finalize();
    switch (key) {
        .user_id => try stmt.bind(1, names.user_id),
        .mailbox => try stmt.bind(1, names.mailbox),
        .both => {
            try stmt.bind(1, names.user_id);
            try stmt.bind(2, names.mailbox);
        },
    }
    if (!try stmt.step()) return error.StepFailed;
    return .{ .table = table, .matching_rows = @intCast(stmt.columnInt64(0)) };
}

pub fn observeSqlite(a: Allocator, tx: Database.Transaction, mailbox: []const u8, user_id: i64) !Sqlite {
    const names: Names = .{ .mailbox = mailbox, .user_id = user_id };
    var tables: std.ArrayList(TableCount) = .empty;
    inline for (by_user_id) |table| try tables.append(a, try count(tx, table, "user_id=?1", .user_id, names));
    inline for (by_username) |table| try tables.append(a, try count(tx, table, "username=?1", .mailbox, names));
    inline for (scopes) |scope| try tables.append(a, try count(tx, scope.table, scope.predicate, scope.key, names));

    const rows = try tx.prepare(
        "SELECT name FROM pragma_table_list WHERE schema='main' AND type IN ('table','virtual') AND substr(name,1,7)<>'sqlite_' ORDER BY name",
    );
    defer rows.finalize();
    var remaining: std.ArrayList([]const u8) = .empty;
    while (try rows.step()) {
        const name = rows.columnText(0);
        // The reservation is operational evidence that outlives mailbox content.
        if (std.mem.eql(u8, name, "hosted_erasure_operations") or
            std.mem.eql(u8, name, "hosted_erasure_maildir_steps") or
            std.mem.eql(u8, name, "hosted_erasure_search_steps") or
            std.mem.eql(u8, name, "hosted_erasure_typesense_steps") or
            std.mem.eql(u8, name, "hosted_erasure_dav_steps")) continue;
        for (tables.items) |entry| {
            if (std.mem.eql(u8, entry.table, name)) break;
        } else try remaining.append(a, try a.dupe(u8, name));
    }
    return .{ .tables = tables.items, .unscoped_tables = remaining.items };
}

const FileCounts = struct { files: u64 = 0, bytes: u64 = 0, symbolic_links: u64 = 0, other_entries: u64 = 0 };
const Maildir = struct {
    state: enum { observed, absent, unavailable },
    counts: ?FileCounts = null,
    legacy_short_name_present: ?bool = null,
};

fn walk(io: std.Io, dir: Dir, totals: *FileCounts, depth: usize) !void {
    if (depth > 16) return error.MaildirDepthLimit;
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        const stat = try dir.statFile(io, entry.name, .{ .follow_symlinks = false });
        switch (stat.kind) {
            .file => {
                totals.files += 1;
                totals.bytes = try std.math.add(u64, totals.bytes, stat.size);
            },
            .directory => {
                var child = try dir.openDir(io, entry.name, .{ .iterate = true, .follow_symlinks = false });
                defer child.close(io);
                try walk(io, child, totals, depth + 1);
            },
            .sym_link => totals.symbolic_links += 1,
            else => totals.other_entries += 1,
        }
    }
}

fn observeMaildir(io: std.Io, root_path: []const u8, mailbox: []const u8, short: []const u8) !Maildir {
    try maildir_path.validate(mailbox);
    var root = Dir.cwd().openDir(io, root_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return .{ .state = .absent, .legacy_short_name_present = false },
        else => return err,
    };
    defer root.close(io);
    const legacy = if (std.mem.eql(u8, short, mailbox)) false else legacy: {
        _ = root.statFile(io, short, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => break :legacy false,
            else => return err,
        };
        break :legacy true;
    };
    var directory = root.openDir(io, mailbox, .{ .iterate = true, .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return .{ .state = .absent, .legacy_short_name_present = legacy },
        else => return err,
    };
    defer directory.close(io);
    var totals: FileCounts = .{};
    try walk(io, directory, &totals, 0);
    return .{ .state = .observed, .counts = totals, .legacy_short_name_present = legacy };
}

pub const Dav = struct {
    state: enum { mapped, no_owner, legacy_owner_unresolved, not_configured, missing, unavailable },
    legacy_name_candidates: ?u64 = null,
    tables: []const TableCount = &.{},
    store_stamp: ?[]const u8 = null,
    owner_id: ?i64 = null,
};
pub const calendar_owner = "calendar_id IN (SELECT id FROM dav_calendars WHERE user_id=?1)";
pub const book_owner = "addressbook_id IN (SELECT id FROM dav_addressbooks WHERE user_id=?1)";
pub const contact_owner = "contact_id IN (SELECT id FROM dav_contacts WHERE " ++ book_owner ++ ")";

pub fn davStoreStamp(a: Allocator, io: std.Io, path: []const u8) ![]const u8 {
    const file = try Dir.cwd().openFile(io, path, .{ .follow_symlinks = false, .allow_directory = false });
    defer file.close(io);
    var stat: std.c.Stat = undefined;
    if (std.c.fstat(file.handle, &stat) != 0 or !std.c.S.ISREG(stat.mode) or stat.nlink != 1)
        return error.ErasureDavFileUnverified;
    return std.fmt.allocPrint(a, "{d}:{d}", .{ stat.dev, stat.ino });
}

fn observeDav(a: Allocator, io: std.Io, explicit_path: ?[]const u8, names: Names, short: []const u8) !Dav {
    const path = explicit_path orelse "./caldav.db";
    const stamp = davStoreStamp(a, io, path) catch |err| switch (err) {
        error.FileNotFound => return .{ .state = if (explicit_path != null) .missing else .not_configured },
        else => return err,
    };
    var db = try Database.openReadOnly(a, path);
    defer db.deinit();
    var tx = try db.beginTransaction(.read);
    defer tx.deinit();
    var observed = try observeDavOwner(a, tx, names.mailbox, names.user_id, short);
    if (!std.mem.eql(u8, stamp, try davStoreStamp(a, io, path))) return error.ErasureDavFileChanged;
    if (observed.state == .mapped or observed.state == .no_owner) observed.store_stamp = stamp;
    try tx.commit();
    return observed;
}

pub fn observeDavOwner(a: Allocator, tx: Database.Transaction, mailbox: []const u8, user_id: i64, short: []const u8) !Dav {
    const schema = try tx.prepare("SELECT 1 FROM pragma_table_info('dav_users') WHERE name='mailbox_id'");
    defer schema.finalize();
    const has_mapping = try schema.step();
    const matches = try tx.prepare(if (has_mapping)
        "SELECT count(*) FROM dav_users WHERE mailbox_id IS NULL AND (username=?1 OR username=?2)"
    else
        "SELECT count(*) FROM dav_users WHERE username=?1 OR username=?2");
    defer matches.finalize();
    try matches.bind(1, mailbox);
    try matches.bind(2, short);
    if (!try matches.step()) return error.StepFailed;
    const legacy: u64 = @intCast(matches.columnInt64(0));
    if (!has_mapping) return .{ .state = .legacy_owner_unresolved, .legacy_name_candidates = legacy };
    const mapped = try tx.prepare("SELECT id FROM dav_users WHERE mailbox_id=?1");
    defer mapped.finalize();
    try mapped.bind(1, user_id);
    if (!try mapped.step()) return .{ .state = if (legacy != 0) .legacy_owner_unresolved else .no_owner, .legacy_name_candidates = legacy };
    const owner: Names = .{ .user_id = mapped.columnInt64(0), .mailbox = mailbox };
    if (try mapped.step()) return error.AmbiguousDavOwner;
    const tables = try a.dupe(TableCount, &.{
        try count(tx, "dav_calendars", "user_id=?1", .user_id, owner),
        try count(tx, "dav_events", calendar_owner, .user_id, owner),
        try count(tx, "dav_addressbooks", "user_id=?1", .user_id, owner),
        try count(tx, "dav_contacts", book_owner, .user_id, owner),
        try count(tx, "dav_emails", contact_owner, .user_id, owner),
        try count(tx, "dav_phones", contact_owner, .user_id, owner),
        try count(tx, "dav_reminder_dismissals", "user_id=?1", .user_id, owner),
    });
    return .{ .state = .mapped, .legacy_name_candidates = legacy, .tables = tables, .owner_id = owner.user_id };
}

pub const Inventory = struct {
    identity: preflight.Identity,
    observed_at: i64,
    maildir: Maildir,
    sqlite: Sqlite,
    dav: Dav,
    external_evidence_required: []const []const u8 = &.{ "search_provider", "backup_catalog", "hosted_billing", "support_and_retention" },
};

pub fn collect(a: Allocator, io: std.Io, db: *Database, mailbox: []const u8, actor: []const u8, mail_root: []const u8, dav_path: ?[]const u8) !Inventory {
    try maildir_path.validate(mailbox);
    const short = mailbox[0 .. std.mem.indexOfScalar(u8, mailbox, '@') orelse mailbox.len];
    const now = time.timestamp();
    const native = blk: {
        var tx = try db.beginTransaction(.read);
        defer tx.deinit();
        const assignment = try preflight.identify(a, tx, mailbox, actor, now);
        const rows = try observeSqlite(a, tx, mailbox, assignment.identity.native_user_id);
        try tx.commit();
        break :blk .{ .identity = assignment.identity, .rows = rows };
    };
    return .{
        .identity = native.identity,
        .observed_at = now,
        .sqlite = native.rows,
        .maildir = observeMaildir(io, mail_root, mailbox, short) catch .{ .state = .unavailable },
        .dav = observeDav(a, io, dav_path, .{ .mailbox = mailbox, .user_id = native.identity.native_user_id }, short) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => .{ .state = .unavailable },
        },
    };
}

/// Reject a stale observation if provisioning changed during the cross-store scan.
pub fn record(a: Allocator, db: *Database, inventory: Inventory, mailbox: []const u8, actor: []const u8, operator: []const u8, case_reference: []const u8) !i64 {
    const details = try std.json.Stringify.valueAlloc(a, .{ .case_reference = case_reference, .inventory = inventory }, .{});
    var tx = try db.beginTransaction(.write);
    defer tx.deinit();
    const current = try preflight.identify(a, tx, mailbox, actor, time.timestamp());
    if (!inventory.identity.eql(current.identity)) return error.AssignmentChanged;
    const id = blk: {
        const stmt = try tx.prepare(
            \\INSERT INTO audit_log(timestamp,action,actor,target,target_type,details,severity)
            \\VALUES(?1,'hosted.erasure.inventory',?2,?3,'hosted_mailbox',?4,'info') RETURNING id
        );
        defer stmt.finalize();
        try stmt.bind(1, inventory.observed_at);
        try stmt.bind(2, operator);
        try stmt.bind(3, mailbox);
        try stmt.bind(4, details);
        if (!try stmt.step()) return error.StepFailed;
        const row = stmt.columnInt64(0);
        if (try stmt.step()) return error.StepFailed;
        break :blk row;
    };
    try tx.commit();
    return id;
}
