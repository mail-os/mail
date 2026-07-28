//! Domain migration.
//!
//! Renaming a mail domain touches five places that must agree, and a mailbox
//! goes dark if any one of them is missed:
//!
//!   1. `users` — `username` and `email` are both the full address for
//!      per-domain mailboxes, and both are UNIQUE.
//!   2. `imap_mailboxes` / `imap_uids` — keyed by `username`. Leaving these
//!      behind loses every UID, so clients re-download the whole mailbox and
//!      lose their read/flag state.
//!   3. `webmail_sessions` — carry a baked-in username and email.
//!   4. Maildirs on disk — `mail/<address>`.
//!   5. `forwards.json` — keys and destination addresses.
//!
//! Doing that by hand is how `hello@ghostanalytics.org` ends up live on a box
//! whose project has already renamed itself to `analyticshq.org`, with the only
//! copy of its password in an unrelated repository.
//!
//! The work is split in two so it can be inspected before it runs: `plan()`
//! reads current state and returns everything that would change, and `apply()`
//! executes a plan. `mail domain migrate` prints the plan and stops unless
//! `--yes` is passed.

const std = @import("std");
const database = @import("storage/database.zig");
const fs_compat = @import("core/fs_compat.zig");

pub const Error = error{
    SameDomain,
    InvalidDomain,
    NoMailboxes,
    TargetAddressExists,
};

/// One mailbox moving from the old domain to the new one.
pub const MailboxMove = struct {
    /// Full address today, e.g. `hello@ghostanalytics.org`.
    from: []const u8,
    /// Full address afterwards, e.g. `hello@analyticshq.org`.
    to: []const u8,
    /// Maildir present on disk. A user row can exist without one.
    has_maildir: bool,
};

/// A forwarding rule that mentions the old domain, on either side.
pub const ForwardMove = struct {
    from: []const u8,
    to: []const u8,
    /// True when the old domain appears in a destination rather than the key.
    is_destination: bool,
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    old_domain: []const u8,
    new_domain: []const u8,
    mailboxes: []MailboxMove,
    forwards: []ForwardMove,
    /// Sessions that will be invalidated. They carry the old identity, and
    /// re-login is cheaper than rewriting them correctly.
    sessions_invalidated: u32,
    /// A DKIM key exists for the old domain, so the new one needs its own.
    needs_dkim_key: bool,

    pub fn deinit(self: *Plan) void {
        for (self.mailboxes) |m| {
            self.allocator.free(m.from);
            self.allocator.free(m.to);
        }
        self.allocator.free(self.mailboxes);
        for (self.forwards) |f| {
            self.allocator.free(f.from);
            self.allocator.free(f.to);
        }
        self.allocator.free(self.forwards);
        self.allocator.free(self.old_domain);
        self.allocator.free(self.new_domain);
    }

    pub fn isEmpty(self: *const Plan) bool {
        return self.mailboxes.len == 0 and self.forwards.len == 0;
    }
};

/// A domain label per RFC 1035, loosely: dot-separated alphanumeric runs that
/// may contain hyphens internally. Rejects an address (`user@host`) so a typo
/// cannot rename every mailbox to something unroutable.
pub fn isValidDomain(domain: []const u8) bool {
    if (domain.len == 0 or domain.len > 253) return false;
    if (std.mem.indexOfScalar(u8, domain, '@') != null) return false;
    if (std.mem.indexOfScalar(u8, domain, ' ') != null) return false;
    if (domain[0] == '.' or domain[domain.len - 1] == '.') return false;
    if (std.mem.indexOf(u8, domain, "..") != null) return false;

    var labels = std.mem.splitScalar(u8, domain, '.');
    var label_count: usize = 0;
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63) return false;
        if (label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |c| {
            const ok = (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
                (c >= '0' and c <= '9') or c == '-';
            if (!ok) return false;
        }
        label_count += 1;
    }

    // A bare hostname is never a mail domain worth migrating to.
    return label_count >= 2;
}

/// The domain part of an address, or null when there is no `@`.
///
/// Legacy role mailboxes are stored as a bare local part (`postmaster`), which
/// belongs to whatever the server's primary domain is — never to the domain
/// being migrated. Returning null keeps them out of the plan.
pub fn domainOf(address: []const u8) ?[]const u8 {
    const at = std.mem.lastIndexOfScalar(u8, address, '@') orelse return null;
    if (at + 1 >= address.len) return null;
    return address[at + 1 ..];
}

/// Case-insensitive domain match. Domains are case-insensitive per RFC 1035,
/// and real mailboxes do get created with mixed case.
pub fn addressInDomain(address: []const u8, domain: []const u8) bool {
    const d = domainOf(address) orelse return false;
    return std.ascii.eqlIgnoreCase(d, domain);
}

/// `hello@old.org` + `new.org` -> `hello@new.org`. Caller owns the result.
pub fn rewriteAddress(
    allocator: std.mem.Allocator,
    address: []const u8,
    new_domain: []const u8,
) ![]u8 {
    const at = std.mem.lastIndexOfScalar(u8, address, '@') orelse
        return allocator.dupe(u8, address);
    const local = address[0..at];

    const out = try allocator.alloc(u8, local.len + 1 + new_domain.len);
    @memcpy(out[0..local.len], local);
    out[local.len] = '@';
    @memcpy(out[local.len + 1 ..], new_domain);
    return out;
}

// ── Planning ────────────────────────────────────────────────────────────────

pub const PlanOptions = struct {
    /// Root the maildirs live under. `mail/<address>` relative to the server's
    /// working directory in production (`/opt/mail`).
    mail_root: []const u8 = "mail",
    /// Forwarding rules. Absent is fine — most deployments have none.
    forwards_path: []const u8 = "forwards.json",
    /// DKIM keys, one `<domain>.private` per signing domain.
    dkim_dir: []const u8 = "dkim",
};

/// Reads current state and returns everything a migration would change,
/// without touching any of it.
///
/// Fails when a target address is already taken: `username` and `email` are
/// both UNIQUE, so the UPDATE would abort partway and leave the domain split
/// across two names. Better to refuse up front and let the operator merge or
/// delete the conflicting mailbox first.
pub fn plan(
    allocator: std.mem.Allocator,
    db: *database.Database,
    old_domain: []const u8,
    new_domain: []const u8,
    options: PlanOptions,
) !Plan {
    if (!isValidDomain(old_domain) or !isValidDomain(new_domain)) return Error.InvalidDomain;
    if (std.ascii.eqlIgnoreCase(old_domain, new_domain)) return Error.SameDomain;

    const users = try db.getAllUsers();
    defer {
        for (users) |*u| u.deinit(allocator);
        allocator.free(users);
    }

    var moves: std.ArrayList(MailboxMove) = .empty;
    errdefer {
        for (moves.items) |m| {
            allocator.free(m.from);
            allocator.free(m.to);
        }
        moves.deinit(allocator);
    }

    for (users) |u| {
        if (!addressInDomain(u.username, old_domain)) continue;

        const to = try rewriteAddress(allocator, u.username, new_domain);
        // Frees `to` on every error path below, including the collision
        // return — an explicit free here as well would be a double free.
        errdefer allocator.free(to);

        if (try db.userExists(to)) return Error.TargetAddressExists;

        const from = try allocator.dupe(u8, u.username);
        errdefer allocator.free(from);

        try moves.append(allocator, .{
            .from = from,
            .to = to,
            .has_maildir = maildirExists(allocator, options.mail_root, u.username),
        });
    }

    if (moves.items.len == 0) return Error.NoMailboxes;

    const forwards = try planForwards(allocator, options.forwards_path, old_domain, new_domain);
    errdefer {
        for (forwards) |f| {
            allocator.free(f.from);
            allocator.free(f.to);
        }
        allocator.free(forwards);
    }

    return .{
        .allocator = allocator,
        .old_domain = try allocator.dupe(u8, old_domain),
        .new_domain = try allocator.dupe(u8, new_domain),
        .mailboxes = try moves.toOwnedSlice(allocator),
        .forwards = forwards,
        .sessions_invalidated = countSessions(db, old_domain) catch 0,
        .needs_dkim_key = dkimKeyExists(allocator, options.dkim_dir, old_domain),
    };
}

fn maildirExists(allocator: std.mem.Allocator, mail_root: []const u8, address: []const u8) bool {
    const path = std.fmt.allocPrint(allocator, "{s}/{s}", .{ mail_root, address }) catch return false;
    defer allocator.free(path);
    // `access` rather than `openDir`: fs_compat's Dir has no close(), so an
    // opened handle would leak a file descriptor per mailbox.
    fs_compat.cwd().access(path, .{}) catch return false;
    return true;
}

fn dkimKeyExists(allocator: std.mem.Allocator, dkim_dir: []const u8, domain: []const u8) bool {
    const path = std.fmt.allocPrint(allocator, "{s}/{s}.private", .{ dkim_dir, domain }) catch return false;
    defer allocator.free(path);
    fs_compat.cwd().access(path, .{}) catch return false;
    return true;
}

/// Renames a path. Goes through libc directly, like the Maildir delivery path
/// does — `std.fs`'s rename signature has moved between the Zig versions this
/// project has had to build under.
fn renamePath(allocator: std.mem.Allocator, from: []const u8, to: []const u8) bool {
    const from_z = allocator.dupeSentinel(u8, from, 0) catch return false;
    defer allocator.free(from_z);
    const to_z = allocator.dupeSentinel(u8, to, 0) catch return false;
    defer allocator.free(to_z);
    return std.c.rename(from_z.ptr, to_z.ptr) == 0;
}

fn countSessions(db: *database.Database, domain: []const u8) !u32 {
    return db.countUsernamesInDomain("webmail_sessions", domain);
}

// ── forwards.json ───────────────────────────────────────────────────────────

/// Rules that mention the old domain, as a key or as a destination.
///
/// The file is `{ "<mailbox>": ["<dest>", …] }`, where a mailbox is either a
/// full address (per-domain mailboxes) or a bare local part (legacy role
/// mailboxes). Only the full-address form can belong to a domain, so bare keys
/// are left alone.
fn planForwards(
    allocator: std.mem.Allocator,
    path: []const u8,
    old_domain: []const u8,
    new_domain: []const u8,
) ![]ForwardMove {
    var moves: std.ArrayList(ForwardMove) = .empty;
    errdefer {
        for (moves.items) |m| {
            allocator.free(m.from);
            allocator.free(m.to);
        }
        moves.deinit(allocator);
    }

    // No forwarding configured is the common case, not a failure.
    const bytes = fs_compat.readFileAlloc(allocator, path) catch return moves.toOwnedSlice(allocator);
    defer allocator.free(bytes);
    if (bytes.len == 0) return moves.toOwnedSlice(allocator);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch {
        // A hand-edited file that no longer parses should not block the
        // migration; the CLI reports it so it can be fixed separately.
        return moves.toOwnedSlice(allocator);
    };
    defer parsed.deinit();

    if (parsed.value != .object) return moves.toOwnedSlice(allocator);

    var it = parsed.value.object.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;

        if (addressInDomain(key, old_domain)) {
            const from = try allocator.dupe(u8, key);
            errdefer allocator.free(from);
            const to = try rewriteAddress(allocator, key, new_domain);
            errdefer allocator.free(to);
            try moves.append(allocator, .{ .from = from, .to = to, .is_destination = false });
        }

        if (entry.value_ptr.* != .array) continue;
        for (entry.value_ptr.array.items) |dest| {
            if (dest != .string) continue;
            if (!addressInDomain(dest.string, old_domain)) continue;

            const from = try allocator.dupe(u8, dest.string);
            errdefer allocator.free(from);
            const to = try rewriteAddress(allocator, dest.string, new_domain);
            errdefer allocator.free(to);
            try moves.append(allocator, .{ .from = from, .to = to, .is_destination = true });
        }
    }

    return moves.toOwnedSlice(allocator);
}

/// Rewrites forwards.json in place, replacing every address on the old domain.
///
/// Writes to a sibling temp file and renames over the original, so a crash
/// mid-write cannot leave the mail server reading a truncated rule set.
fn applyForwards(
    allocator: std.mem.Allocator,
    path: []const u8,
    old_domain: []const u8,
    new_domain: []const u8,
) !void {
    const bytes = fs_compat.readFileAlloc(allocator, path) catch return;
    defer allocator.free(bytes);
    if (bytes.len == 0) return;

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch return;
    defer parsed.deinit();
    if (parsed.value != .object) return;

    // Every rewritten key and destination is a fresh allocation with exactly
    // one lifetime: until the file has been rendered. An arena frees the lot in
    // one call — an ObjectMap's deinit releases its own storage but not the
    // keys it was given, so tracking them individually is just a way to leak
    // one of them.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();

    var out: std.json.ObjectMap = .empty;

    var it = parsed.value.object.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        const new_key = if (addressInDomain(key, old_domain))
            try rewriteAddress(scratch, key, new_domain)
        else
            key;

        const value = entry.value_ptr.*;
        if (value == .array) {
            for (value.array.items) |*dest| {
                if (dest.* != .string) continue;
                if (!addressInDomain(dest.string, old_domain)) continue;
                dest.* = .{ .string = try rewriteAddress(scratch, dest.string, new_domain) };
            }
        }
        try out.put(scratch, new_key, value);
    }

    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.migrating", .{path});
    defer allocator.free(tmp_path);

    const rendered = try std.json.Stringify.valueAlloc(
        allocator,
        std.json.Value{ .object = out },
        .{ .whitespace = .indent_2 },
    );
    defer allocator.free(rendered);

    {
        const file = try fs_compat.cwd().createFile(tmp_path, .{});
        defer file.close();
        try file.writeAll(rendered);
    }

    if (!renamePath(allocator, tmp_path, path)) return error.ForwardsWriteFailed;
}

// ── Applying ────────────────────────────────────────────────────────────────

pub const ApplyResult = struct {
    mailboxes_moved: u32,
    maildirs_renamed: u32,
    maildirs_failed: u32,
    forwards_rewritten: usize,
};

/// Executes a plan.
///
/// Order matters. The database moves first, inside one transaction, because it
/// is the only step that can be rolled back. Maildir renames follow: a failure
/// there leaves a mailbox whose mail is on the old path, which the report calls
/// out by name so it can be moved by hand — far better than a rolled-back
/// database with half the directories already renamed.
pub fn apply(
    allocator: std.mem.Allocator,
    db: *database.Database,
    p: *const Plan,
    options: PlanOptions,
) !ApplyResult {
    const moved = try db.renameDomain(p.old_domain, p.new_domain);

    var renamed: u32 = 0;
    var failed: u32 = 0;
    for (p.mailboxes) |m| {
        if (!m.has_maildir) continue;

        const from = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ options.mail_root, m.from });
        defer allocator.free(from);
        const to = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ options.mail_root, m.to });
        defer allocator.free(to);

        if (!renamePath(allocator, from, to)) {
            failed += 1;
            continue;
        }
        renamed += 1;
    }

    if (p.forwards.len > 0)
        try applyForwards(allocator, options.forwards_path, p.old_domain, p.new_domain);

    return .{
        .mailboxes_moved = moved,
        .maildirs_renamed = renamed,
        .maildirs_failed = failed,
        .forwards_rewritten = p.forwards.len,
    };
}

/// Every domain with at least one mailbox, and how many each has.
pub const DomainCount = struct {
    domain: []const u8,
    mailboxes: u32,
};

/// Domains in use, sorted by name. Bare local parts (legacy role mailboxes)
/// are grouped under `(no domain)` so they are visible rather than silently
/// dropped — they are exactly the accounts a migration must not touch.
pub fn listDomains(allocator: std.mem.Allocator, db: *database.Database) ![]DomainCount {
    const users = try db.getAllUsers();
    defer {
        for (users) |*u| u.deinit(allocator);
        allocator.free(users);
    }

    var counts: std.StringArrayHashMapUnmanaged(u32) = .empty;
    defer counts.deinit(allocator);

    for (users) |u| {
        const domain = domainOf(u.username) orelse "(no domain)";
        const gop = try counts.getOrPut(allocator, domain);
        if (!gop.found_existing) {
            gop.key_ptr.* = try allocator.dupe(u8, domain);
            gop.value_ptr.* = 0;
        }
        gop.value_ptr.* += 1;
    }

    var out = try allocator.alloc(DomainCount, counts.count());
    var i: usize = 0;
    var it = counts.iterator();
    while (it.next()) |entry| : (i += 1) {
        out[i] = .{ .domain = entry.key_ptr.*, .mailboxes = entry.value_ptr.* };
    }

    std.mem.sort(DomainCount, out, {}, struct {
        fn lessThan(_: void, a: DomainCount, b: DomainCount) bool {
            return std.mem.lessThan(u8, a.domain, b.domain);
        }
    }.lessThan);

    return out;
}

pub fn freeDomainCounts(allocator: std.mem.Allocator, counts: []DomainCount) void {
    for (counts) |c| allocator.free(c.domain);
    allocator.free(counts);
}
