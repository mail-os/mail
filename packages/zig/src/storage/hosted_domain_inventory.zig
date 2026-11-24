//! Operator inventory for an occupied hosted address namespace.
const std = @import("std");
const Database = @import("database.zig").Database;
const domains = @import("../domain_migrate.zig");

const scope =
    \\WITH domain_users AS (
    \\ SELECT id FROM users WHERE substr(username,-length(?1)-1)=('@'||?1) COLLATE NOCASE
    \\), hosted_team AS (
    \\ SELECT team_id FROM mail_hosted_teams WHERE domain=?1 COLLATE NOCASE
    \\)
;

const sections = [_]struct { key: []const u8, query: []const u8 }{
    .{ .key = "mailboxes", .query =
    \\SELECT json_object(
    \\ 'mailbox',u.username,'recovery',u.recovery_email,'recovery_source',u.recovery_source,
    \\ 'access',CASE WHEN COALESCE(u.enabled,0)=0 THEN 'disabled'
    \\               WHEN p.service_until IS NULL OR p.service_until>?2 THEN 'full'
    \\               WHEN p.read_until>?2 THEN 'read_only' ELSE 'expired' END,
    \\ 'service_until',p.service_until,'read_until',p.read_until,'actor',p.actor,'revision',p.revision,
    \\ 'operation_id',(SELECT operation_id FROM provisioning_operations
    \\                 WHERE mailbox=p.mailbox AND revision=p.revision ORDER BY operation_id LIMIT 1),
    \\ 'quota_bytes',u.quota_limit,'retirement_id',r.retirement_id)
    \\FROM domain_users d JOIN users u ON u.id=d.id
    \\LEFT JOIN provisioned_mailboxes p ON p.user_id=u.id AND p.mailbox=u.username
    \\LEFT JOIN hosted_retired_mailboxes r ON r.user_id=u.id
    \\ORDER BY u.username
    },
    .{ .key = "hosted_teams", .query =
    \\SELECT json_object('team',t.id,'name',t.name) FROM hosted_team h JOIN mail_teams t ON h.team_id=t.id
    },
    .{ .key = "memberships", .query =
    \\SELECT json_object('team',m.team_id,'mailbox',u.username,'role',m.role)
    \\FROM mail_team_members m JOIN users u ON m.user_id=u.id
    \\WHERE m.user_id IN domain_users OR m.team_id IN hosted_team ORDER BY m.team_id,u.username
    },
    .{ .key = "team_grants", .query =
    \\SELECT json_object('team',g.team_id,'source',s.username,'grantee',r.username,'scope',g.scope,'resource',g.resource)
    \\FROM mail_team_grants g JOIN users s ON g.source_id=s.id JOIN users r ON g.grantee_id=r.id
    \\WHERE g.source_id IN domain_users OR g.grantee_id IN domain_users OR g.team_id IN hosted_team
    \\ORDER BY g.team_id,s.username,r.username,g.scope,g.resource
    },
    .{ .key = "calendar_shares", .query =
    \\SELECT json_object('team',g.team_id,'source',s.username,'grantee',r.username,'calendar',g.calendar_share_id,'access',g.access)
    \\FROM mail_team_calendar_shares g JOIN users s ON g.source_id=s.id JOIN users r ON g.grantee_id=r.id
    \\WHERE g.source_id IN domain_users OR g.grantee_id IN domain_users OR g.team_id IN hosted_team
    \\ORDER BY g.team_id,s.username,r.username,g.calendar_share_id
    },
    .{ .key = "team_invitations", .query =
    \\SELECT json_object('team',i.team_id,'inviter',s.username,'recipient',r.username,'expires_at',i.expires_at)
    \\FROM mail_team_invitations i JOIN users s ON i.inviter_id=s.id JOIN users r ON i.recipient_id=r.id
    \\WHERE i.expires_at>?2 AND (i.inviter_id IN domain_users OR i.recipient_id IN domain_users OR i.team_id IN hosted_team)
    \\ORDER BY i.team_id,s.username,r.username
    },
    .{ .key = "forwarding", .query =
    \\SELECT json_object('source',u.username,'destination',COALESCE(f.address,s.address),
    \\ 'pending_destination',f.pending_address,'pending_until',f.expires_at,'sender_filter',s.sender,'recipient_filter',s.recipient)
    \\FROM mailbox_forwarding f JOIN users u ON u.id=f.user_id
    \\LEFT JOIN mailbox_forwarding_scopes s ON s.user_id=f.user_id AND s.revision=f.revision AND f.address IS NULL
    \\WHERE (COALESCE(f.address,s.address) IS NOT NULL OR f.pending_address IS NOT NULL)
    \\AND (f.user_id IN domain_users
    \\ OR substr(COALESCE(f.address,s.address),-length(?1)-1)=('@'||?1) COLLATE NOCASE
    \\ OR substr(f.pending_address,-length(?1)-1)=('@'||?1) COLLATE NOCASE)
    \\ORDER BY u.username
    },
    .{ .key = "pending_delivery", .query =
    \\SELECT json_object('mailbox',mailbox,'count',count(*),'reserved_bytes',sum(queued_bytes))
    \\FROM accepted_mail_targets WHERE outcome='pending' AND (mailbox_id IN domain_users
    \\ OR substr(recipient,-length(?1)-1)=('@'||?1) COLLATE NOCASE
    \\ OR substr(mailbox,-length(?1)-1)=('@'||?1) COLLATE NOCASE)
    \\GROUP BY mailbox ORDER BY mailbox
    },
};

pub const Routing = struct { local: bool, exact_mailboxes: bool, additional_provisioning: bool, catch_all: bool };

pub fn write(allocator: std.mem.Allocator, db: *Database, domain: []const u8, now: i64, routing: Routing, io: std.Io, writer: *std.Io.Writer) !void {
    var legacy: std.ArrayList(struct { source: []const u8, destination: []const u8 }) = .empty;
    const cwd = std.Io.Dir.cwd();
    const legacy_bytes = cwd.readFileAlloc(io, "forwards.json", allocator, .limited(16 * 1024 * 1024)) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (legacy_bytes) |bytes| {
        const rules = try std.json.parseFromSliceLeaky(std.json.Value, allocator, bytes, .{});
        if (rules != .object) return error.InvalidForwardingConfiguration;
        var entries = rules.object.iterator();
        while (entries.next()) |entry| {
            if (entry.value_ptr.* != .array) return error.InvalidForwardingConfiguration;
            for (entry.value_ptr.array.items) |item| {
                if (item != .string) return error.InvalidForwardingConfiguration;
                if (domains.addressInDomain(entry.key_ptr.*, domain) or domains.addressInDomain(item.string, domain))
                    try legacy.append(allocator, .{ .source = entry.key_ptr.*, .destination = item.string });
            }
        }
    }

    const sieve = if (cwd.access(io, "forwards.sieve", .{})) |_| true else |err| switch (err) {
        error.FileNotFound => false,
        else => return err,
    };
    var tx = try db.beginTransaction(.read);
    defer tx.deinit();
    var json: std.json.Stringify = .{ .writer = writer, .options = .{ .whitespace = .indent_2 } };
    try json.beginObject();
    try json.objectField("version");
    try json.write(@as(u8, 1));
    try json.objectField("domain");
    try json.write(domain);
    try json.objectField("observed_at");
    try json.write(now);
    try json.objectField("routing");
    try json.write(routing);
    inline for (sections) |section| {
        const stmt = try tx.prepare(scope ++ section.query);
        defer stmt.finalize();
        try stmt.bind(1, domain);
        if (std.mem.indexOf(u8, section.query, "?2") != null) try stmt.bind(2, now);
        try json.objectField(section.key);
        try json.beginArray();
        while (try stmt.step()) try json.print("{s}", .{stmt.columnText(0)});
        try json.endArray();
    }
    try tx.commit();
    try json.objectField("legacy_forwards");
    try json.write(legacy.items);
    try json.objectField("sieve_forwarding_present");
    try json.write(sieve);
    try json.endObject();
    try writer.writeByte('\n');
    try writer.flush();
}
