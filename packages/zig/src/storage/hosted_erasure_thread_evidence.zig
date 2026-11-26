//! Fingerprint the records that determine a peer's shared Mail view.
const std = @import("std");
const Database = @import("database.zig").Database;
const SharedBacking = @import("hosted_erasure_inventory.zig").SharedBacking;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Thread = struct {
    share_id: []const u8,
    records_sha256: [64]u8,
};

fn appendHash(hash: *Sha256, value: []const u8) void {
    var size: [8]u8 = undefined;
    std.mem.writeInt(u64, &size, value.len, .big);
    hash.update(&size);
    hash.update(value);
}

fn threadDigest(tx: Database.Transaction, owner: i64, share: []const u8) ![64]u8 {
    var hash = Sha256.init(.{});
    appendHash(&hash, "shared-thread-records-v1");
    inline for ([_]struct { label: []const u8, query: []const u8 }{
        .{ .label = "reader", .query =
        \\SELECT json_array(s.subject,o.username,g.username,c.name,c.revision,
        \\ f.since_ms,f.authors,f.anchors,fs.share_id IS NOT NULL)
        \\FROM mail_team_thread_shares s JOIN users o ON o.id=s.owner_id JOIN users g ON g.id=s.grantee_id
        \\LEFT JOIN mail_team_collection_shares l ON l.share_id=s.id
        \\LEFT JOIN mail_private_collections c ON c.user_id=s.owner_id AND c.id=l.collection_id
        \\LEFT JOIN mail_team_thread_follow f ON f.share_id=s.id
        \\LEFT JOIN mail_team_thread_follow_sent fs ON fs.share_id=s.id WHERE s.id=?1 AND s.owner_id=?2
        },
        .{ .label = "restrictions", .query =
        \\SELECT t.scope FROM mail_team_thread_restrictions t JOIN mail_team_thread_shares s ON s.id=t.share_id
        \\WHERE s.id=?1 AND s.owner_id=?2 ORDER BY t.scope
        },
        .{ .label = "messages", .query =
        \\SELECT json_array(m.reference,m.content_revision,r.folder,r.basename,r.file_stamp,r.next_folder,r.next_basename,r.next_digest)
        \\FROM mail_team_thread_messages m LEFT JOIN mailbox_message_refs r ON r.reference=m.reference AND r.user_id=?2
        \\WHERE m.share_id=?1 ORDER BY m.rowid
        },
        .{ .label = "replies", .query =
        \\SELECT json_array(m.reference,m.content_revision,m.outgoing,r.folder,r.basename,r.file_stamp,r.next_folder,r.next_basename,r.next_digest)
        \\FROM mail_team_thread_replies m LEFT JOIN mailbox_message_refs r ON r.reference=m.reference AND r.user_id=?2
        \\WHERE m.share_id=?1 ORDER BY m.rowid
        },
        .{ .label = "collection", .query =
        \\SELECT json_array(m.rowid,m.anchor,r.folder,r.basename,r.file_stamp,r.next_folder,r.next_basename,r.next_digest)
        \\FROM mail_team_collection_shares l JOIN mail_private_members m ON m.user_id=l.owner_id AND m.collection=l.collection_id
        \\LEFT JOIN mailbox_message_refs r ON r.user_id=m.user_id AND r.reference=m.anchor
        \\WHERE l.share_id=?1 AND l.owner_id=?2 ORDER BY m.rowid DESC
        },
        .{ .label = "comments", .query =
        \\SELECT json_array(c.id,c.author_id,u.username,c.written_at,c.text)
        \\FROM mail_team_thread_comments c JOIN mail_team_thread_shares s ON s.id=c.share_id
        \\JOIN users u ON u.id=c.author_id WHERE s.id=?1 AND s.owner_id=?2 ORDER BY c.id
        },
    }) |part| {
        const rows = try tx.prepare(part.query);
        defer rows.finalize();
        try rows.bind(1, share);
        try rows.bind(2, owner);
        appendHash(&hash, part.label);
        while (try rows.step()) {
            // Distinguish a row from the next section marker. Include exact
            // persisted data in the checksum without returning it to the audit.
            hash.update(&.{1});
            appendHash(&hash, rows.columnText(0));
        }
        hash.update(&.{0});
    }
    return std.fmt.bytesToHex(hash.finalResult(), .lower);
}

pub fn collect(a: Allocator, tx: Database.Transaction, owner: i64, shares: []const SharedBacking) ![]const Thread {
    const result = try a.alloc(Thread, shares.len);
    for (shares, result) |share, *row| row.* = .{
        .share_id = share.share_id,
        .records_sha256 = try threadDigest(tx, owner, share.share_id),
    };
    return result;
}

pub const UnresolvedReply = struct {
    team_id: []const u8,
    source_user_id: i64,
    actor_user_id: i64,
    send_id: []const u8,
    claim_state: []const u8,
    outbox_state: ?[]const u8,
};

pub fn unresolvedReplies(a: Allocator, tx: Database.Transaction, owner: i64) ![]const UnresolvedReply {
    const webmail = blk: {
        const table = try tx.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='webmail_records'");
        defer table.finalize();
        break :blk try table.step();
    };
    // A partial send or missing Sent copy may still carry the historical
    // "replied" claim state. Check the real Outbox when it is available.
    const queries = if (webmail)
        \\SELECT c.team_id,c.source_id,c.actor_id,c.send_id,c.state,r.state
        \\FROM mail_shared_reply_claims c LEFT JOIN users u ON u.id=c.actor_id
        \\LEFT JOIN webmail_records r ON r.username=u.username AND r.kind='outbox' AND r.id=c.send_id
        \\WHERE (c.source_id=?1 OR c.actor_id=?1)
        \\AND (c.state<>'replied' OR r.state IN ('pending','sending','unknown','partial','sent_unfiled'))
        \\ORDER BY c.team_id,c.source_id,c.actor_id,c.send_id
    else
        \\SELECT c.team_id,c.source_id,c.actor_id,c.send_id,c.state,NULL
        \\FROM mail_shared_reply_claims c
        \\WHERE (c.source_id=?1 OR c.actor_id=?1) AND c.state<>'replied'
        \\ORDER BY c.team_id,c.source_id,c.actor_id,c.send_id
    ;
    const rows = try tx.prepare(queries);
    defer rows.finalize();
    try rows.bind(1, owner);
    var result: std.ArrayList(UnresolvedReply) = .empty;
    while (try rows.step()) try result.append(a, .{
        .team_id = try a.dupe(u8, rows.columnText(0)),
        .source_user_id = rows.columnInt64(1),
        .actor_user_id = rows.columnInt64(2),
        .send_id = try a.dupe(u8, rows.columnText(3)),
        .claim_state = try a.dupe(u8, rows.columnText(4)),
        .outbox_state = if (rows.columnTextOpt(5)) |state| try a.dupe(u8, state) else null,
    });
    return result.toOwnedSlice(a);
}
