//! Full-text message search, backed by Typesense through the
//! zig-search-engine package (vendored at vendor/zig-search-engine,
//! tracked as github:zig-utils/zig-search-engine in pantry.jsonc).
//!
//! The `message_schema` below is the model declaration — it drives the
//! Typesense collection structure the same way a Stacks model's
//! `useSearch` trait does in @stacksjs/search-engine. This adapter:
//!
//!   - lazily ensures the collection exists (so no separate bootstrap step
//!     is needed on a fresh Typesense)
//!   - keeps the index in sync as mail is delivered/appended/expunged
//!     (best-effort, on a detached thread — search must never block or
//!     fail mail handling)
//!   - answers IMAP SEARCH text criteria with matching maildir base names
//!
//! Enabled when TYPESENSE_API_KEY is set (host/port default to
//! 127.0.0.1:8108; override with TYPESENSE_HOST / TYPESENSE_PORT).

const std = @import("std");
const se = @import("search-engine");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const collection = "messages";

/// The Message search model: which attributes are full-text searchable,
/// filterable (facets), and sortable. This is the single source of truth
/// for the Typesense collection structure.
pub const message_schema = se.Schema{
    .name = collection,
    .searchable = &.{
        .{ .name = "subject" },
        .{ .name = "sender" },
        .{ .name = "recipients" },
        .{ .name = "body" },
    },
    .filterable = &.{
        .{ .name = "username" },
        .{ .name = "mailbox" },
    },
    .sortable = &.{
        .{ .name = "date", .type = .int64 },
    },
    .displayed = &.{
        .{ .name = "filename" },
    },
};

/// Maximum body bytes indexed per message — enough for relevance, bounded
/// for index size.
pub const max_indexed_body = 32 * 1024;

// =============================================================================
// Engine configuration (env, read once)
// =============================================================================

var config_once = std.atomic.Value(u8).init(0); // 0=unread 1=disabled 2=enabled
var config_host_buf: [256]u8 = undefined;
var config_key_buf: [256]u8 = undefined;
var config_host: [:0]const u8 = "127.0.0.1";
var config_port: u16 = 8108;
var config_key: []const u8 = "";
var collection_ready = std.atomic.Value(bool).init(false);

fn loadEngine() ?se.Typesense {
    switch (config_once.load(.acquire)) {
        1 => return null,
        2 => return se.Typesense.init(.{ .host = config_host, .port = config_port, .api_key = config_key }),
        else => {},
    }

    const key_env = std.c.getenv("TYPESENSE_API_KEY");
    if (key_env == null or std.mem.sliceTo(key_env.?, 0).len == 0) {
        config_once.store(1, .release);
        return null;
    }
    const key = std.mem.sliceTo(key_env.?, 0);
    if (key.len > config_key_buf.len) {
        config_once.store(1, .release);
        return null;
    }
    @memcpy(config_key_buf[0..key.len], key);
    config_key = config_key_buf[0..key.len];

    if (std.c.getenv("TYPESENSE_HOST")) |h| {
        const host = std.mem.sliceTo(h, 0);
        if (host.len > 0 and host.len < config_host_buf.len) {
            @memcpy(config_host_buf[0..host.len], host);
            config_host_buf[host.len] = 0;
            config_host = config_host_buf[0..host.len :0];
        }
    }
    if (std.c.getenv("TYPESENSE_PORT")) |p| {
        config_port = std.fmt.parseInt(u16, std.mem.sliceTo(p, 0), 10) catch 8108;
    }

    config_once.store(2, .release);
    return se.Typesense.init(.{ .host = config_host, .port = config_port, .api_key = config_key });
}

pub fn enabled() bool {
    return loadEngine() != null;
}

/// Make sure the collection exists, shaped by message_schema. Cheap once
/// it has succeeded (a process-wide flag short-circuits).
fn ensureReady(allocator: std.mem.Allocator, engine: *const se.Typesense) bool {
    if (collection_ready.load(.acquire)) return true;
    engine.ensureCollection(allocator, message_schema) catch return false;
    collection_ready.store(true, .release);
    return true;
}

// =============================================================================
// Document identity
// =============================================================================

/// Stable document id: hex SHA-256 over the identity triple, truncated to
/// 32 chars. Keyed on the maildir BASE name (flag suffix stripped) so the
/// id survives flag renames.
pub fn docId(out: *[32]u8, username: []const u8, mailbox: []const u8, base_filename: []const u8) []const u8 {
    var h = Sha256.init(.{});
    h.update(username);
    h.update(&[_]u8{0});
    h.update(mailbox);
    h.update(&[_]u8{0});
    h.update(base_filename);
    var digest: [Sha256.digest_length]u8 = undefined;
    h.final(&digest);
    const hex = "0123456789abcdef";
    for (digest[0..16], 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0x0f];
    }
    return out[0..32];
}

// =============================================================================
// Indexing
// =============================================================================

/// Parse a raw RFC 5322 message and upsert it, synchronously.
pub fn indexRawMessage(allocator: std.mem.Allocator, username: []const u8, mailbox: []const u8, filename: []const u8, content: []const u8) !void {
    const engine = loadEngine() orelse return error.Disabled;
    if (!ensureReady(allocator, &engine)) return error.EngineUnavailable;

    const base = baseName(filename);

    const hdr_end = std.mem.indexOf(u8, content, "\r\n\r\n") orelse
        std.mem.indexOf(u8, content, "\n\n") orelse content.len;
    const headers = content[0..hdr_end];
    const body_start = @min(content.len, hdr_end + 2);
    const body = content[body_start..];

    var id_buf: [32]u8 = undefined;
    const id = docId(&id_buf, username, mailbox, base);

    var doc = se.DocBuilder.init(allocator);
    defer doc.deinit();
    try doc.putString("id", id);
    try doc.putString("username", username);
    try doc.putString("mailbox", mailbox);
    try doc.putString("filename", base);
    try doc.putString("sender", headerValue(headers, "from") orelse "");
    try doc.putString("recipients", headerValue(headers, "to") orelse "");
    try doc.putString("subject", headerValue(headers, "subject") orelse "");
    try doc.putString("body", body[0..@min(body.len, max_indexed_body)]);
    try doc.putInt("date", filenameTimestampSecs(base));
    const json = try doc.toOwned();
    defer allocator.free(json);

    try engine.upsertDocument(allocator, collection, json);
}

const IndexJob = struct {
    allocator: std.mem.Allocator,
    username: []u8,
    mailbox: []u8,
    filename: []u8,
    content: []u8,

    fn run(job: *IndexJob) void {
        defer {
            const a = job.allocator;
            a.free(job.username);
            a.free(job.mailbox);
            a.free(job.filename);
            a.free(job.content);
            a.destroy(job);
        }
        indexRawMessage(job.allocator, job.username, job.mailbox, job.filename, job.content) catch |err| {
            std.log.debug("typesense: index of {s}/{s} failed: {}", .{ job.username, job.filename, err });
        };
    }
};

/// Fire-and-forget indexing for delivery paths: copies its inputs, spawns
/// a detached thread, and never reports failure to the caller.
pub fn indexMessageAsync(allocator: std.mem.Allocator, username: []const u8, mailbox: []const u8, filename: []const u8, content: []const u8) void {
    if (!enabled()) return;

    const job = allocator.create(IndexJob) catch return;
    job.* = .{
        .allocator = allocator,
        .username = allocator.dupe(u8, username) catch {
            allocator.destroy(job);
            return;
        },
        .mailbox = undefined,
        .filename = undefined,
        .content = undefined,
    };
    job.mailbox = allocator.dupe(u8, mailbox) catch {
        allocator.free(job.username);
        allocator.destroy(job);
        return;
    };
    job.filename = allocator.dupe(u8, filename) catch {
        allocator.free(job.username);
        allocator.free(job.mailbox);
        allocator.destroy(job);
        return;
    };
    job.content = allocator.dupe(u8, content[0..@min(content.len, 256 * 1024)]) catch {
        allocator.free(job.username);
        allocator.free(job.mailbox);
        allocator.free(job.filename);
        allocator.destroy(job);
        return;
    };

    const thread = std.Thread.spawn(.{}, IndexJob.run, .{job}) catch {
        // Couldn't spawn: index inline (still bounded by the engine timeout)
        IndexJob.run(job);
        return;
    };
    thread.detach();
}

/// Remove a message document (e.g. on EXPUNGE). Best-effort.
pub fn deleteMessage(allocator: std.mem.Allocator, username: []const u8, mailbox: []const u8, filename: []const u8) void {
    const engine = loadEngine() orelse return;
    var id_buf: [32]u8 = undefined;
    const id = docId(&id_buf, username, mailbox, baseName(filename));
    engine.deleteDocument(allocator, collection, id) catch {};
}

// =============================================================================
// Search
// =============================================================================

/// Search messages for `query` over `query_by` fields, filtered to one
/// user and optionally one mailbox. Returns matching maildir base
/// filenames; caller frees each entry and the slice.
pub fn searchFilenames(
    allocator: std.mem.Allocator,
    username: []const u8,
    mailbox: ?[]const u8,
    query: []const u8,
    query_by: []const u8,
) ![][]u8 {
    const engine = loadEngine() orelse return error.Disabled;

    var filter: std.ArrayList(u8) = .empty;
    defer filter.deinit(allocator);
    try filter.appendSlice(allocator, "username:=`");
    try filter.appendSlice(allocator, username);
    try filter.appendSlice(allocator, "`");
    if (mailbox) |mb| {
        try filter.appendSlice(allocator, " && mailbox:=`");
        try filter.appendSlice(allocator, mb);
        try filter.appendSlice(allocator, "`");
    }

    var result = try engine.search(allocator, collection, .{
        .query = query,
        .query_by = query_by,
        .filter_by = filter.items,
        .per_page = 250,
    });
    defer result.deinit();

    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |f| allocator.free(f);
        out.deinit(allocator);
    }

    var it = result.hits();
    while (it.next()) |doc| {
        const fname = se.SearchResponse.docString(doc, "filename");
        if (fname.len == 0) continue;
        try out.append(allocator, try allocator.dupe(u8, fname));
    }

    return out.toOwnedSlice(allocator);
}

/// A full search hit (for the webmail/REST surface). All slices are owned
/// by the caller's allocator.
pub const MessageHit = struct {
    mailbox: []u8,
    filename: []u8,
    subject: []u8,
    sender: []u8,
    recipients: []u8,
    date: i64,

    pub fn deinit(self: *MessageHit, allocator: std.mem.Allocator) void {
        allocator.free(self.mailbox);
        allocator.free(self.filename);
        allocator.free(self.subject);
        allocator.free(self.sender);
        allocator.free(self.recipients);
    }
};

/// Search across all message fields, returning rich hits for UI surfaces.
/// Caller frees each hit (deinit) and the slice.
pub fn searchDocs(
    allocator: std.mem.Allocator,
    username: []const u8,
    mailbox: ?[]const u8,
    query: []const u8,
) ![]MessageHit {
    const engine = loadEngine() orelse return error.Disabled;

    var filter: std.ArrayList(u8) = .empty;
    defer filter.deinit(allocator);
    try filter.appendSlice(allocator, "username:=`");
    try filter.appendSlice(allocator, username);
    try filter.appendSlice(allocator, "`");
    if (mailbox) |mb| {
        try filter.appendSlice(allocator, " && mailbox:=`");
        try filter.appendSlice(allocator, mb);
        try filter.appendSlice(allocator, "`");
    }

    var result = try engine.search(allocator, collection, .{
        .query = query,
        .query_by = "subject,sender,recipients,body",
        .filter_by = filter.items,
        .per_page = 50,
    });
    defer result.deinit();

    var out: std.ArrayList(MessageHit) = .empty;
    errdefer {
        for (out.items) |*h| h.deinit(allocator);
        out.deinit(allocator);
    }

    var it = result.hits();
    while (it.next()) |doc| {
        const fname = se.SearchResponse.docString(doc, "filename");
        if (fname.len == 0) continue;

        var hit = MessageHit{
            .mailbox = try allocator.dupe(u8, se.SearchResponse.docString(doc, "mailbox")),
            .filename = undefined,
            .subject = undefined,
            .sender = undefined,
            .recipients = undefined,
            .date = std.fmt.parseInt(i64, se.SearchResponse.docString(doc, "date"), 10) catch 0,
        };
        errdefer allocator.free(hit.mailbox);
        hit.filename = try allocator.dupe(u8, fname);
        errdefer allocator.free(hit.filename);
        hit.subject = try allocator.dupe(u8, se.SearchResponse.docString(doc, "subject"));
        errdefer allocator.free(hit.subject);
        hit.sender = try allocator.dupe(u8, se.SearchResponse.docString(doc, "sender"));
        errdefer allocator.free(hit.sender);
        hit.recipients = try allocator.dupe(u8, se.SearchResponse.docString(doc, "recipients"));

        try out.append(allocator, hit);
    }

    return out.toOwnedSlice(allocator);
}

// =============================================================================
// Small helpers
// =============================================================================

fn baseName(filename: []const u8) []const u8 {
    if (std.mem.indexOf(u8, filename, ":2,")) |pos| return filename[0..pos];
    return filename;
}

fn headerValue(headers: []const u8, name_lower: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, headers, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) break;
        if (line.len > name_lower.len and line[name_lower.len] == ':' and
            std.ascii.eqlIgnoreCase(line[0..name_lower.len], name_lower))
        {
            return std.mem.trim(u8, line[name_lower.len + 1 ..], " \t");
        }
    }
    return null;
}

fn filenameTimestampSecs(base: []const u8) i64 {
    var end: usize = 0;
    while (end < base.len and base[end] >= '0' and base[end] <= '9') end += 1;
    const ms = std.fmt.parseInt(i64, base[0..end], 10) catch return 0;
    return @divTrunc(ms, 1000);
}

// =============================================================================
// Tests
// =============================================================================

test "docId is stable and differs across mailboxes" {
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    const id1 = docId(&a, "chris", "INBOX", "1781094896.eml");
    const id2 = docId(&b, "chris", "INBOX", "1781094896.eml");
    try std.testing.expectEqualStrings(id1, id2);

    var c: [32]u8 = undefined;
    const id3 = docId(&c, "chris", "Archive", "1781094896.eml");
    try std.testing.expect(!std.mem.eql(u8, id1, id3));
}

test "message schema declares the search model" {
    try std.testing.expectEqualStrings("messages", message_schema.name);
    try std.testing.expect(message_schema.searchable.len == 4);
    try std.testing.expect(message_schema.filterable.len == 2);
}

test "header parsing helpers" {
    const msg = "From: a@b.c\r\nSubject: hi\r\n\r\nbody";
    try std.testing.expectEqualStrings("a@b.c", headerValue(msg, "from").?);
    try std.testing.expectEqualStrings("hi", headerValue(msg, "subject").?);
    try std.testing.expectEqual(@as(i64, 1781094), filenameTimestampSecs("1781094896.eml"));
}
