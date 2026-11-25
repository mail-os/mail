//! Durable search metadata. The caller reconciles these rows with its live,
//! account-scoped Maildir snapshot before allowing them into a result.
const std = @import("std");
const database = @import("../storage/database.zig");

pub const Attachment = struct {
    filename: []const u8,
    content_type: []const u8,
    size: usize,
    index: usize,
};

pub const Document = struct {
    fingerprint: []const u8 = "",
    digest: [64]u8 = undefined,
    sender: []const u8 = "",
    recipient: []const u8 = "",
    cc: []const u8 = "",
    bcc: []const u8 = "",
    subject: []const u8 = "",
    date: []const u8 = "",
    message_id: []const u8 = "",
    in_reply_to: []const u8 = "",
    references: []const u8 = "",
    snippet: []const u8 = "",
    attachment_metadata: []const u8 = "[]",
    matches: bool = true,
    uid: ?i64 = null,
    observed: bool = false,
};

pub const Progress = struct {
    indexed: usize = 0,
    total: usize = 0,

    pub fn complete(self: Progress) bool {
        return self.indexed == self.total;
    }
};

pub fn load(a: std.mem.Allocator, db: *database.Database, user: []const u8, folder: []const u8, query: []const u8, include_unmatched: bool) !std.StringHashMap(Document) {
    // Collect the folder's FTS candidates once. Filtering the FTS cursor
    // by every document rowid repeats the same trigram search per message.
    const literal = try ftsLiteral(a, query);
    const stmt = try db.prepare(
        \\SELECT basename,fingerprint,digest,sender,recipient,cc,bcc,subject,sent_date,message_id,in_reply_to,reply_chain,snippet,attachment_metadata,
        \\ CASE WHEN ?3='' THEN 1
        \\      WHEN ?4<>'' AND d.id NOT IN (
        \\          SELECT webmail_search_text.rowid FROM webmail_search_text
        \\          CROSS JOIN webmail_search_docs m ON m.id=webmail_search_text.rowid
        \\          WHERE webmail_search_text MATCH ?4
        \\          AND m.user_id=(SELECT id FROM users WHERE username=?1) AND m.folder=?2
        \\      ) THEN 0
        \\      ELSE instr(lower(sender),lower(?3))>0 OR instr(lower(recipient),lower(?3))>0
        \\        OR instr(lower(cc),lower(?3))>0 OR instr(lower(bcc),lower(?3))>0
        \\        OR instr(lower(subject),lower(?3))>0 OR instr(lower(body_text),lower(?3))>0
        \\ END, u.uid
        \\FROM webmail_search_docs d
        \\LEFT JOIN imap_uids u ON u.username=?1 AND u.mailbox=d.folder AND u.filename=d.basename
        \\WHERE d.user_id=(SELECT id FROM users WHERE username=?1) AND d.folder=?2
    );
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bind(2, folder);
    try stmt.bind(3, query);
    try stmt.bind(4, literal);
    var docs = std.StringHashMap(Document).init(a);
    while (try stmt.step()) {
        const digest = stmt.columnText(2);
        if (digest.len != 64) continue;
        const basename = try a.dupe(u8, stmt.columnText(0));
        const fingerprint = try a.dupe(u8, stmt.columnText(1));
        const matches = stmt.columnInt64(14) != 0;
        const uid = stmt.columnInt64Opt(15);
        if (!matches and !include_unmatched) {
            // Keep the identity for validation, progress and stale-row pruning.
            try docs.put(basename, .{ .fingerprint = fingerprint, .digest = digest[0..64].*, .matches = false, .uid = uid });
            continue;
        }
        try docs.put(basename, .{
            .fingerprint = fingerprint,
            .digest = digest[0..64].*,
            .sender = try a.dupe(u8, stmt.columnText(3)),
            .recipient = try a.dupe(u8, stmt.columnText(4)),
            .cc = try a.dupe(u8, stmt.columnText(5)),
            .bcc = try a.dupe(u8, stmt.columnText(6)),
            .subject = try a.dupe(u8, stmt.columnText(7)),
            .date = try a.dupe(u8, stmt.columnText(8)),
            .message_id = try a.dupe(u8, stmt.columnText(9)),
            .in_reply_to = try a.dupe(u8, stmt.columnText(10)),
            .references = try a.dupe(u8, stmt.columnText(11)),
            .snippet = try a.dupe(u8, stmt.columnText(12)),
            .attachment_metadata = try a.dupe(u8, stmt.columnText(13)),
            .matches = matches,
            .uid = uid,
        });
    }
    return docs;
}

fn ftsLiteral(a: std.mem.Allocator, query: []const u8) ![]const u8 {
    // The ASCII subset avoids differences between SQLite's case folding and
    // the trigram tokenizer, and handles short and non-UTF-8 queries by scan.
    if (query.len < 3) return "";
    for (query) |c| if (c < 0x20 or c > 0x7e) return "";
    var literal: std.ArrayList(u8) = .empty;
    try literal.append(a, '"');
    for (query) |c| {
        if (c == '"') try literal.append(a, '"');
        try literal.append(a, c);
    }
    try literal.append(a, '"');
    return literal.toOwnedSlice(a);
}

pub fn store(db: *database.Database, user: []const u8, folder: []const u8, basename: []const u8, doc: Document, body: []const u8) !void {
    const stmt = try db.prepare(
        \\INSERT INTO webmail_search_docs(user_id,folder,basename,fingerprint,digest,sender,recipient,cc,bcc,subject,
        \\ sent_date,message_id,in_reply_to,reply_chain,snippet,body_text,attachment_metadata)
        \\SELECT id,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17 FROM users WHERE username=?1
        \\ON CONFLICT(user_id,folder,basename) DO UPDATE SET fingerprint=excluded.fingerprint,digest=excluded.digest,
        \\ sender=excluded.sender,recipient=excluded.recipient,cc=excluded.cc,bcc=excluded.bcc,subject=excluded.subject,
        \\ sent_date=excluded.sent_date,message_id=excluded.message_id,in_reply_to=excluded.in_reply_to,reply_chain=excluded.reply_chain,
        \\ snippet=excluded.snippet,body_text=excluded.body_text,attachment_metadata=excluded.attachment_metadata
        \\WHERE fingerprint<>excluded.fingerprint
    );
    defer stmt.finalize();
    const values = [_][]const u8{ user, folder, basename, doc.fingerprint, &doc.digest, doc.sender, doc.recipient, doc.cc, doc.bcc, doc.subject, doc.date, doc.message_id, doc.in_reply_to, doc.references, doc.snippet, body, doc.attachment_metadata };
    for (values, 1..) |value, i| try stmt.bind(i, value);
    _ = try stmt.step();
}

pub fn prune(db: *database.Database, user: []const u8, folder: []const u8, basename: []const u8, fingerprint: []const u8) !void {
    const stmt = try db.prepare(
        \\DELETE FROM webmail_search_docs WHERE user_id=(SELECT id FROM users WHERE username=?1)
        \\ AND folder=?2 AND basename=?3 AND fingerprint=?4
    );
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bind(2, folder);
    try stmt.bind(3, basename);
    try stmt.bind(4, fingerprint);
    _ = try stmt.step();
}

pub fn pruneFolders(db: *database.Database, user: []const u8, folders: []const u8) !void {
    const stmt = try db.prepare(
        \\DELETE FROM webmail_search_docs WHERE user_id=(SELECT id FROM users WHERE username=?1)
        \\ AND folder NOT IN (SELECT value FROM json_each(?2))
    );
    defer stmt.finalize();
    try stmt.bind(1, user);
    try stmt.bind(2, folders);
    _ = try stmt.step();
}
