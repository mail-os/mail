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
//!   - publishes durable Maildir updates from the delivery-effects worker
//!   - answers IMAP SEARCH text criteria with matching message identities
//!
//! Enabled when TYPESENSE_API_KEY is set (host/port default to
//! 127.0.0.1:8108; override with TYPESENSE_HOST / TYPESENSE_PORT).

const std = @import("std");
const se = @import("search-engine");
const mime = @import("../message/mime.zig").lib;
const address_header = @import("../message/address_header.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

// Earlier collections contain raw, sometimes truncated header values.
pub const collection = "messages_v3";

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

pub const MessageId = [32]u8;

/// Stable document id: hex SHA-256 over the identity triple, truncated to
/// 32 chars. The base filename omits the flag suffix so the id survives renames.
pub fn docId(out: *MessageId, username: []const u8, mailbox: []const u8, base_filename: []const u8) []const u8 {
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
    const header_copy = try allocator.dupe(u8, headers);
    defer allocator.free(header_copy);
    const unfolded: mime.Headers = .{ .block = mime.headers.unfold(header_copy) };

    var id_buf: [32]u8 = undefined;
    const id = docId(&id_buf, username, mailbox, base);

    var doc = se.DocBuilder.init(allocator);
    defer doc.deinit();
    try doc.putString("id", id);
    try doc.putString("username", username);
    try doc.putString("mailbox", mailbox);
    try doc.putString("filename", base);
    try putHeader(&doc, "sender", unfolded.get("From") orelse "", .addresses);
    try putHeader(&doc, "recipients", unfolded.get("To") orelse "", .addresses);
    try putHeader(&doc, "subject", unfolded.get("Subject") orelse "", .text);
    try doc.putString("body", body[0..@min(body.len, max_indexed_body)]);
    try doc.putInt("date", filenameTimestampSecs(base));
    const json = try doc.toOwned();
    defer allocator.free(json);

    try engine.upsertDocument(allocator, collection, json);
}

/// Delete a message document and report failures to the reconciliation worker.
pub fn deleteIndexedMessage(allocator: std.mem.Allocator, username: []const u8, mailbox: []const u8, filename: []const u8) !void {
    const engine = loadEngine() orelse return error.Disabled;
    var id_buf: [32]u8 = undefined;
    const id = docId(&id_buf, username, mailbox, baseName(filename));
    try engine.deleteDocument(allocator, collection, id);
}

// =============================================================================
// Search
// =============================================================================

pub const MessageIds = std.AutoHashMapUnmanaged(MessageId, void);

const IndexedIdentity = struct {
    username: []const u8,
    folder: []const u8,
    filename: []const u8,
    id: MessageId,

    fn fromDocument(doc: std.json.ObjectMap) !IndexedIdentity {
        const username = se.SearchResponse.docString(doc, "username");
        const folder = se.SearchResponse.docString(doc, "mailbox");
        const filename = se.SearchResponse.docString(doc, "filename");
        const id = se.SearchResponse.docString(doc, "id");
        var expected: MessageId = undefined;
        if (username.len == 0 or folder.len == 0 or filename.len == 0 or
            !std.mem.eql(u8, id, docId(&expected, username, folder, filename)))
            return error.IncompleteSearch;
        return .{ .username = username, .folder = folder, .filename = filename, .id = expected };
    }

    fn matches(self: IndexedIdentity, username: []const u8, folder: ?[]const u8) bool {
        return std.mem.eql(u8, self.username, username) and
            (folder == null or std.mem.eql(u8, self.folder, folder.?));
    }
};

/// Return a complete set of index hits scoped to the user and optional mailbox.
/// The caller owns the set. An incomplete result must fall back to a file scan.
pub fn searchMessageIds(
    allocator: std.mem.Allocator,
    username: []const u8,
    mailbox: ?[]const u8,
    query: []const u8,
    query_by: []const u8,
) !MessageIds {
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

    var params: se.SearchParams = .{
        .query = query,
        .query_by = query_by,
        .filter_by = filter.items,
        .include_fields = "id,username,mailbox,filename",
        .per_page = 250,
    };
    var ids: MessageIds = .empty;
    errdefer ids.deinit(allocator);
    var seen: MessageIds = .empty;
    defer seen.deinit(allocator);
    var expected_total: ?u64 = null;
    while (true) {
        var result = try engine.search(allocator, collection, params);
        defer result.deinit();

        const total = try completeHitCount(&result);
        if (expected_total) |previous| {
            if (total != previous) return error.IncompleteSearch;
        }
        expected_total = total;

        // Typesense compares normalized strings. Track the raw hits for paging,
        // then enforce the exact owner and folder when building the caller's set.
        const before = seen.count();
        var hits = result.hits();
        while (hits.next()) |doc| {
            const identity = try IndexedIdentity.fromDocument(doc);
            const entry = try seen.getOrPut(allocator, identity.id);
            if (entry.found_existing) return error.IncompleteSearch;
            if (identity.matches(username, mailbox)) try ids.put(allocator, identity.id, {});
        }
        if (seen.count() - before != @min(params.per_page, total - before))
            return error.IncompleteSearch;
        if (seen.count() == total) return ids;
        if (params.page == std.math.maxInt(u32)) return error.IncompleteSearch;
        params.page += 1;
    }
}

fn completeHitCount(result: *const se.SearchResponse) !u64 {
    const root = result.parsed.value;
    if (root != .object) return error.IncompleteSearch;
    const found = root.object.get("found") orelse return error.IncompleteSearch;
    const hits = root.object.get("hits") orelse return error.IncompleteSearch;
    if (found != .integer or found.integer < 0 or hits != .array) return error.IncompleteSearch;
    if (root.object.get("search_cutoff")) |cutoff| {
        if (cutoff != .bool or cutoff.bool) return error.IncompleteSearch;
    }
    return @intCast(found.integer);
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
        const identity = try IndexedIdentity.fromDocument(doc);
        if (!identity.matches(username, mailbox)) continue;

        var hit = MessageHit{
            .mailbox = try allocator.dupe(u8, identity.folder),
            .filename = undefined,
            .subject = undefined,
            .sender = undefined,
            .recipients = undefined,
            .date = std.fmt.parseInt(i64, se.SearchResponse.docString(doc, "date"), 10) catch 0,
        };
        errdefer allocator.free(hit.mailbox);
        hit.filename = try allocator.dupe(u8, identity.filename);
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

fn putHeader(doc: *se.DocBuilder, name: []const u8, unfolded_value: []const u8, kind: enum { text, addresses }) !void {
    if (std.mem.indexOf(u8, unfolded_value, "=?") == null) return doc.putString(name, unfolded_value);
    const decoded = try doc.allocator.alloc(u8, unfolded_value.len * 3);
    defer doc.allocator.free(decoded);
    const value = switch (kind) {
        .text => mime.decodeWords(unfolded_value, decoded).text,
        .addresses => decodeAddressNames(unfolded_value, decoded),
    };
    try doc.putString(name, value);
}

fn decodeAddressNames(value: []const u8, out: []u8) []const u8 {
    var list: address_header.Iterator = .{ .value = value };
    var written: usize = 0;
    while (list.next()) |part| {
        // RFC 2047 applies to the display phrase, never the addr-spec.
        const name_end = if (part.separator == ':') part.text.len else part.angle_start orelse 0;
        written += decodeDisplayPhrase(part.text[0..name_end], out[written..]);
        const address = part.text[name_end..];
        @memcpy(out[written..][0..address.len], address);
        written += address.len;
        if (part.separator) |separator| {
            out[written] = separator;
            written += 1;
        }
    }
    return out[0..written];
}

fn decodeDisplayPhrase(value: []const u8, out: []u8) usize {
    var written: usize = 0;
    var start: usize = 0;
    var quoted = false;
    var escaped = false;
    for (value, 0..) |byte, index| {
        if (escaped) {
            escaped = false;
            continue;
        }
        if (quoted and byte == '\\') {
            escaped = true;
            continue;
        }
        if (byte != '"') continue;
        if (quoted) {
            const literal = value[start .. index + 1];
            @memcpy(out[written..][0..literal.len], literal);
            written += literal.len;
            start = index + 1;
        } else {
            written += mime.decodeWords(value[start..index], out[written..]).text.len;
            start = index;
        }
        quoted = !quoted;
    }
    if (!quoted) return written + mime.decodeWords(value[start..], out[written..]).text.len;
    const literal = value[start..];
    @memcpy(out[written..][0..literal.len], literal);
    return written + literal.len;
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

test "search identity checks exact mailbox and folder and rejects a forged ID" {
    const a = std.testing.allocator;
    const owner = "index.owner@example.test";
    const folder = "Index.ed";
    const filename = "1781094896.eml";
    var id: MessageId = undefined;
    var builder = se.DocBuilder.init(a);
    defer builder.deinit();
    try builder.putString("id", docId(&id, owner, folder, filename));
    try builder.putString("username", owner);
    try builder.putString("mailbox", folder);
    try builder.putString("filename", filename);
    const json = try builder.toOwned();
    defer a.free(json);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, json, .{});
    defer parsed.deinit();
    const identity = try IndexedIdentity.fromDocument(parsed.value.object);
    try std.testing.expect(identity.matches(owner, folder));
    try std.testing.expect(identity.matches(owner, null));
    try std.testing.expect(!identity.matches("index-owner@example.test", folder));
    try std.testing.expect(!identity.matches(owner, "Indexed"));
    parsed.value.object.getPtr("username").?.* = .{ .string = "index-owner@example.test" };
    try std.testing.expectError(error.IncompleteSearch, IndexedIdentity.fromDocument(parsed.value.object));
}

test "message schema declares the search model" {
    try std.testing.expectEqualStrings("messages_v3", message_schema.name);
    try std.testing.expect(message_schema.searchable.len == 4);
    try std.testing.expect(message_schema.filterable.len == 2);
}

test "search documents decode display names without losing addresses" {
    var doc = se.DocBuilder.init(std.testing.allocator);
    defer doc.deinit();
    try putHeader(&doc, "sender", "=?UTF-8?Q?Caf=C3=A9?= <=?UTF-8?Q?literal?=@example.test>", .addresses);
    try putHeader(&doc, "recipients", "=?UTF-8?Q?Team?=: =?UTF-8?Q?Caf=C3=A9?= <two@example.test>, =?UTF-8?Q?literal?=@example.test;", .addresses);
    try putHeader(&doc, "subject", "Plain subject", .text);
    const json = try doc.toOwned();
    defer std.testing.allocator.free(json);
    try std.testing.expectEqualStrings("{\"sender\":\"Café <=?UTF-8?Q?literal?=@example.test>\",\"recipients\":\"Team: Café <two@example.test>, =?UTF-8?Q?literal?=@example.test;\",\"subject\":\"Plain subject\"}", json);
    try std.testing.expectEqual(@as(i64, 1781094), filenameTimestampSecs("1781094896.eml"));
}

test "encoded-looking text in quoted address phrases stays literal" {
    const value = "\"=?UTF-8?Q?literal?=\" =?UTF-8?Q?Caf=C3=A9?= <first@example.test>";
    var buffer: [value.len * 3]u8 = undefined;
    try std.testing.expectEqualStrings("\"=?UTF-8?Q?literal?=\" Café <first@example.test>", decodeAddressNames(value, &buffer));
}
