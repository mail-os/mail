const std = @import("std");
const clamav = @import("../antispam/clamav.zig");
const posix = std.posix;
const socket = @import("../core/socket_compat.zig");
const io_compat = @import("../core/io_compat.zig");
const auth = @import("../auth/auth.zig");
const security = @import("../auth/security.zig");
const logger = @import("../core/logger.zig");
const tls = @import("tls");
const time_compat = @import("../core/time_compat.zig");
const caldav_store = @import("../storage/caldav_store.zig");
const dav_properties = @import("caldav_properties.zig");
const calendar_import = @import("../api/webmail_calendar_import.zig");
const free_busy = @import("caldav_free_busy.zig");
const calendar_query = @import("caldav_query.zig");
const recurrence = @import("icalendar_busy.zig");
const autoconfig = @import("../api/autoconfig.zig");
const eas = @import("eas.zig");
const ews = @import("ews/ews.zig");
const core_config = @import("../core/config.zig");
const database = @import("../storage/database.zig");

/// Get the current epoch timestamp in seconds.
fn currentTimestamp() i64 {
    var ts: std.c.timespec = undefined;
    const rc = std.c.clock_gettime(.REALTIME, &ts);
    if (rc != 0) return 0;
    return ts.sec;
}

fn legacyDavEvent(body: []const u8) caldav_store.CalDavStore.EventData {
    const event = caldav_store.IcsParser.parseEvent(body) orelse return .{
        .summary = "Untitled",
        .dtstart = currentTimestamp(),
        .ics_data = body,
    };
    return .{
        .summary = event.summary orelse "Untitled",
        .description = event.description,
        .location = event.location,
        .dtstart = event.dtstart orelse currentTimestamp(),
        .dtend = event.dtend,
        .all_day = event.all_day,
        .rrule = event.rrule,
        .organizer = event.organizer,
        .ics_data = body,
    };
}

/// CalDAV/CardDAV Server Implementation
/// RFC 4791 (CalDAV) and RFC 6352 (CardDAV)
///
/// Provides calendar and contact synchronization over WebDAV

// ============================================================================
// Configuration
// ============================================================================

pub const CalDavConfig = struct {
    port: u16 = 8008,
    ssl_port: u16 = 8443,
    /// Interface to bind. See {@link ImapConfig.bind_host} for why the default
    /// is every interface and when to narrow it.
    bind_host: []const u8 = "0.0.0.0",
    enable_ssl: bool = true,
    max_connections: usize = 100,
    connection_timeout_seconds: u64 = 300,
    max_resource_size: usize = 10 * 1024 * 1024, // 10 MB
    calendar_path: []const u8 = "/var/spool/caldav/calendars",
    contacts_path: []const u8 = "/var/spool/caldav/contacts",
    enable_caldav: bool = true,
    enable_carddav: bool = true,
    // TLS configuration
    cert_path: ?[]const u8 = null,
    key_path: ?[]const u8 = null,
    // Public-facing values used to build the downloadable Apple .mobileconfig
    // profile (served unauthenticated over HTTPS at /email.mobileconfig). These
    // let a single profile install configure Mail, Notes, Calendar and Contacts
    // at once — Apple's Mail-account flow only ever offers Mail + Notes on its
    // own, so this is the one-click path for the rest.
    public_hostname: []const u8 = "localhost",
    imaps_port: u16 = 993,
    submission_port: u16 = 587,
    // Publicly reachable HTTPS port for CalDAV/CardDAV, as advertised in the
    // Apple .mobileconfig. This is intentionally separate from `ssl_port` (the
    // internal bind port): the server may bind 8443 behind a 443 firewall
    // forward / proxy, but the profile MUST advertise the port clients can
    // actually reach (443), or Calendar/Contacts silently fail to connect.
    public_dav_port: u16 = 443,
    display_name: []const u8 = "Mail",
    // MTA-STS policy mode served at /.well-known/mta-sts.txt (RFC 8461).
    // "enforce" makes sending MTAs refuse delivery if STARTTLS to our MX
    // can't be negotiated with a valid cert; "testing" reports failures
    // without blocking. Set via MTA_STS_MODE in main.zig. (The policy `id`
    // lives in the `_mta-sts` DNS TXT record, not this file — bump it there
    // when changing the mode so senders refetch.)
    mta_sts_mode: []const u8 = "enforce",
    // Outbound delivery (used by EWS CreateItem/SendItem to actually send mail).
    delivery_method: core_config.DeliveryMethod = .direct,
    mail_config: ?*const core_config.Config = null,
    scanner: ?*clamav.ClamAVScanner = null,
    draft_service: ?*@import("../api/webmail_service.zig").Service = null,
    ses_region: []const u8 = "us-east-1",
};

// ============================================================================
// HTTP Methods
// ============================================================================

pub const HttpMethod = enum {
    get,
    head,
    put,
    post,
    delete,
    options,
    propfind,
    proppatch,
    mkcalendar,
    report,
    mkcol,
    move,
    copy,

    pub fn fromString(method: []const u8) ?HttpMethod {
        const upper = std.ascii.allocUpperString(std.heap.page_allocator, method) catch return null;
        defer std.heap.page_allocator.free(upper);

        const methods = std.StaticStringMap(HttpMethod).initComptime(.{
            .{ "GET", .get },
            .{ "HEAD", .head },
            .{ "PUT", .put },
            .{ "POST", .post },
            .{ "DELETE", .delete },
            .{ "OPTIONS", .options },
            .{ "PROPFIND", .propfind },
            .{ "PROPPATCH", .proppatch },
            .{ "MKCALENDAR", .mkcalendar },
            .{ "REPORT", .report },
            .{ "MKCOL", .mkcol },
            .{ "MOVE", .move },
            .{ "COPY", .copy },
        });
        return methods.get(upper);
    }
};

// ============================================================================
// Path Parsing
// ============================================================================

/// Parsed components from a CalDAV/CardDAV URL path
pub const ParsedPath = struct {
    path_type: PathType,
    user: ?[]const u8 = null,
    collection: ?[]const u8 = null,
    resource_uid: ?[]const u8 = null,

    pub const PathType = enum {
        root,
        principals,
        principal_user,
        calendars_home,
        calendar_collection,
        calendar_resource,
        shared_calendars_home,
        shared_calendar_collection,
        shared_calendar_resource,
        addressbooks_home,
        addressbook_collection,
        addressbook_resource,
        well_known_caldav,
        well_known_carddav,
        unknown,
    };
};

fn resourceKind(path_type: ParsedPath.PathType) ?caldav_store.SyncChange.ResourceType {
    return switch (path_type) {
        .calendar_resource => .event,
        .addressbook_resource => .contact,
        else => null,
    };
}

fn resourceConditions(request: []const u8) caldav_store.ResourceConditions {
    return .{
        .if_match = requestHeader(request, "If-Match"),
        .if_none_match = requestHeader(request, "If-None-Match"),
    };
}

const max_dav_header_bytes = 64 * 1024;

/// Frame a request before dispatch, with the same limits for HTTP and HTTPS.
fn httpRequestLength(buf: []const u8, max_body: usize) error{ InvalidFraming, RequestTooLarge }!?usize {
    const header_end = std.mem.indexOf(u8, buf, "\r\n\r\n") orelse {
        if (buf.len >= max_dav_header_bytes) return error.RequestTooLarge;
        return null;
    };
    const body_start = header_end + 4;
    if (body_start > max_dav_header_bytes) return error.RequestTooLarge;

    var content_length: ?usize = null;
    var lines = std.mem.splitSequence(u8, buf[0..header_end], "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidFraming;
        const name = line[0..colon];
        if (std.ascii.eqlIgnoreCase(name, "Transfer-Encoding")) return error.InvalidFraming;
        if (std.ascii.eqlIgnoreCase(name, "Content-Length")) {
            if (content_length != null) return error.InvalidFraming;
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            for (value) |byte| {
                if (!std.ascii.isDigit(byte)) return error.InvalidFraming;
            }
            content_length = std.fmt.parseInt(usize, value, 10) catch return error.InvalidFraming;
        }
    }
    const length = content_length orelse 0;
    if (length > max_body) return error.RequestTooLarge;
    const total = std.math.add(usize, body_start, length) catch return error.RequestTooLarge;
    return if (buf.len < total) null else total;
}

/// Percent-decode `input` once into `out`, returning the decoded slice.
/// Returns null if the input does not fit in `out`. Malformed escapes are
/// passed through literally (the '%' is kept) so they cannot smuggle bytes.
fn percentDecodeOnce(input: []const u8, out: []u8) ?[]const u8 {
    var oi: usize = 0;
    var i: usize = 0;
    while (i < input.len) {
        if (oi >= out.len) return null;
        const c = input[i];
        if (c == '%' and i + 2 < input.len) {
            const byte = std.fmt.parseInt(u8, input[i + 1 .. i + 3], 16) catch {
                // Malformed escape: keep '%' literally so no byte is smuggled.
                out[oi] = c;
                oi += 1;
                i += 1;
                continue;
            };
            out[oi] = byte;
            oi += 1;
            i += 3;
        } else {
            out[oi] = c;
            oi += 1;
            i += 1;
        }
    }
    return out[0..oi];
}

fn unquotedDelimiter(input: []const u8, delimiter: u8) ?usize {
    var quoted = false;
    for (input, 0..) |byte, index| {
        if (byte == '"') quoted = !quoted;
        if (byte == delimiter and !quoted) return index;
    }
    return null;
}

fn davFieldIsBase64(field: []const u8) bool {
    var parameters = field;
    while (unquotedDelimiter(parameters, ';')) |semicolon| {
        parameters = parameters[semicolon + 1 ..];
        const parameter = parameters[0 .. unquotedDelimiter(parameters, ';') orelse parameters.len];
        const equals = std.mem.indexOfScalar(u8, parameter, '=') orelse continue;
        if (!std.ascii.eqlIgnoreCase(parameter[0..equals], "ENCODING")) continue;
        const encoding = std.mem.trim(u8, parameter[equals + 1 ..], "\"");
        return std.ascii.eqlIgnoreCase(encoding, "BASE64") or std.ascii.eqlIgnoreCase(encoding, "B");
    }
    return false;
}

fn scanDavField(a: std.mem.Allocator, scanner: *clamav.ClamAVScanner, line: []const u8) !void {
    const colon = unquotedDelimiter(line, ':') orelse return;
    const value = line[colon + 1 ..];
    var unescaped: ?[]u8 = null;
    defer if (unescaped) |buffer| a.free(buffer);
    const encoded = if (davFieldIsBase64(line[0..colon])) value else blk: {
        // vCard 4.0 embeds binary objects in data URIs. Remote URLs are never fetched.
        if (!std.ascii.startsWithIgnoreCase(value, "data:")) return;
        const comma = std.mem.indexOfScalar(u8, value, ',') orelse return;
        const uri_data = value[comma + 1 ..];
        const bytes = try a.alloc(u8, uri_data.len);
        unescaped = bytes;
        const decoded_uri = percentDecodeOnce(uri_data, bytes) orelse unreachable;
        const metadata = value[0..comma];
        const marker = ";base64";
        if (metadata.len < marker.len or !std.ascii.eqlIgnoreCase(metadata[metadata.len - marker.len ..], marker)) {
            return clamav.requireAllowed(scanner, decoded_uri);
        }
        break :blk decoded_uri;
    };
    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(encoded) catch return error.InvalidDavBinary;
    const bytes = try a.alloc(u8, size);
    defer a.free(bytes);
    decoder.decode(bytes, encoded) catch return error.InvalidDavBinary;
    try clamav.requireAllowed(scanner, bytes);
}

pub fn scanDavResource(a: std.mem.Allocator, scanner: ?*clamav.ClamAVScanner, body: []const u8) !void {
    const active = scanner orelse return;
    try clamav.requireAllowed(active, body);

    // Both iCalendar and vCard fold long content lines. Unfold only for the
    // scan so resource bytes, ETags, and existing parsers stay the same.
    var lines = std.mem.splitScalar(u8, body, '\n');
    var unfolded: std.ArrayList(u8) = .empty;
    defer unfolded.deinit(a);
    while (lines.next()) |first| {
        const line = std.mem.trimEnd(u8, first, "\r");
        unfolded.clearRetainingCapacity();
        while (lines.peek()) |next| {
            if (next.len == 0 or (next[0] != ' ' and next[0] != '\t')) break;
            if (unfolded.items.len == 0) try unfolded.appendSlice(a, line);
            try unfolded.appendSlice(a, std.mem.trimEnd(u8, next[1..], "\r"));
            _ = lines.next();
        }
        try scanDavField(a, active, if (unfolded.items.len > 0) unfolded.items else line);
    }
}

/// Returns true if a percent-decoded path is unsafe (traversal, control chars,
/// or path-escaping sequences).
fn isUnsafeDecodedPath(decoded: []const u8) bool {
    // Reject traversal in any form once decoded.
    if (std.mem.indexOf(u8, decoded, "..") != null) return true;
    // Reject backslashes (Windows-style separators / absolute-path bypass).
    if (std.mem.indexOfScalar(u8, decoded, '\\') != null) return true;
    // Reject control characters (including NUL and embedded CR/LF) which could
    // smuggle separators or corrupt downstream handling.
    for (decoded) |c| {
        if (c < 0x20 or c == 0x7f) return true;
    }
    return false;
}

/// Parse a CalDAV/CardDAV path into components.
/// Paths follow patterns like:
///   /principals/{user}
///   /calendars/{user}/{calendar}/{uid}.ics
///   /addressbooks/{user}/{addressbook}/{uid}.vcf
pub fn parsePath(path: []const u8) ParsedPath {
    // SECURITY: Reject path traversal attempts, including percent-encoded
    // bypasses (e.g. "%2e%2e", "%2f"). Decode once into a stack buffer purely
    // for validation; the returned slices still point into the original `path`.
    var decode_buf: [2048]u8 = undefined;
    if (percentDecodeOnce(path, &decode_buf)) |decoded| {
        if (isUnsafeDecodedPath(decoded)) {
            return .{ .path_type = .unknown };
        }
    } else {
        // Path too long to decode/validate safely; reject.
        return .{ .path_type = .unknown };
    }

    // Also reject traversal in the raw (still-encoded) form as a belt-and-braces
    // check in case the decoded slices are used elsewhere.
    if (std.mem.indexOf(u8, path, "..") != null) {
        return .{ .path_type = .unknown };
    }

    // Handle well-known paths
    if (std.mem.startsWith(u8, path, "/.well-known/caldav")) {
        return .{ .path_type = .well_known_caldav };
    }
    if (std.mem.startsWith(u8, path, "/.well-known/carddav")) {
        return .{ .path_type = .well_known_carddav };
    }

    // Trim trailing slash for uniform processing
    const trimmed = if (path.len > 1 and path[path.len - 1] == '/') path[0 .. path.len - 1] else path;

    // Split path segments
    var segments: [8][]const u8 = undefined;
    var seg_count: usize = 0;
    var iter = std.mem.splitScalar(u8, trimmed, '/');
    while (iter.next()) |seg| {
        if (seg.len == 0) continue; // skip leading empty segment
        if (seg_count < 8) {
            segments[seg_count] = seg;
            seg_count += 1;
        }
    }

    if (seg_count == 0) return .{ .path_type = .root };

    // /principals/...
    if (std.mem.eql(u8, segments[0], "principals")) {
        if (seg_count == 1) return .{ .path_type = .principals };
        return .{ .path_type = .principal_user, .user = segments[1] };
    }

    // /calendars/...
    if (std.mem.eql(u8, segments[0], "calendars")) {
        if (seg_count == 1) return .{ .path_type = .calendars_home };
        if (seg_count == 2) return .{ .path_type = .calendars_home, .user = segments[1] };
        if (seg_count == 3) return .{ .path_type = .calendar_collection, .user = segments[1], .collection = segments[2] };
        if (seg_count >= 4) {
            // Extract UID from filename (remove .ics)
            const filename = segments[3];
            const uid = if (std.mem.endsWith(u8, filename, ".ics")) filename[0 .. filename.len - 4] else filename;
            return .{ .path_type = .calendar_resource, .user = segments[1], .collection = segments[2], .resource_uid = uid };
        }
    }

    if (std.mem.eql(u8, segments[0], "shared-calendars")) {
        if (seg_count == 2) return .{ .path_type = .shared_calendars_home, .user = segments[1] };
        if (seg_count == 3) return .{ .path_type = .shared_calendar_collection, .user = segments[1], .collection = segments[2] };
        if (seg_count == 4) {
            const filename = segments[3];
            const uid = if (std.mem.endsWith(u8, filename, ".ics")) filename[0 .. filename.len - 4] else filename;
            return .{ .path_type = .shared_calendar_resource, .user = segments[1], .collection = segments[2], .resource_uid = uid };
        }
    }

    // /addressbooks/...
    if (std.mem.eql(u8, segments[0], "addressbooks")) {
        if (seg_count == 1) return .{ .path_type = .addressbooks_home };
        if (seg_count == 2) return .{ .path_type = .addressbooks_home, .user = segments[1] };
        if (seg_count == 3) return .{ .path_type = .addressbook_collection, .user = segments[1], .collection = segments[2] };
        if (seg_count >= 4) {
            // Extract UID from filename (remove .vcf)
            const filename = segments[3];
            const uid = if (std.mem.endsWith(u8, filename, ".vcf")) filename[0 .. filename.len - 4] else filename;
            return .{ .path_type = .addressbook_resource, .user = segments[1], .collection = segments[2], .resource_uid = uid };
        }
    }

    return .{ .path_type = .unknown };
}

// ============================================================================
// Helpers
// ============================================================================

/// Append a formatted string to an ArrayList(u8)
fn appendPrint(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
    const formatted = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(formatted);
    try buf.appendSlice(allocator, formatted);
}

/// XML-escape a string to prevent injection.
/// Escapes &, <, >, ", and ' characters.
fn xmlEscape(allocator: std.mem.Allocator, input: []const u8) ![]const u8 {
    // Quick check — if no special chars, return a copy
    var needs_escape = false;
    for (input) |c| {
        if (c == '&' or c == '<' or c == '>' or c == '"' or c == '\'') {
            needs_escape = true;
            break;
        }
    }
    if (!needs_escape) return try allocator.dupe(u8, input);

    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    for (input) |c| {
        switch (c) {
            '&' => try result.appendSlice(allocator, "&amp;"),
            '<' => try result.appendSlice(allocator, "&lt;"),
            '>' => try result.appendSlice(allocator, "&gt;"),
            '"' => try result.appendSlice(allocator, "&quot;"),
            '\'' => try result.appendSlice(allocator, "&apos;"),
            else => try result.append(allocator, c),
        }
    }
    return try result.toOwnedSlice(allocator);
}

/// Append XML with escaped user data. fmt must have exactly one {s} placeholder.
fn appendXmlEscaped(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime prefix: []const u8, value: []const u8, comptime suffix: []const u8) !void {
    const escaped = try xmlEscape(allocator, value);
    defer allocator.free(escaped);
    try buf.appendSlice(allocator, prefix);
    try buf.appendSlice(allocator, escaped);
    try buf.appendSlice(allocator, suffix);
}

/// Append a resource <D:href> element with every dynamic path component
/// XML-escaped. Produces: "    <D:href>{base}{user}/{collection}/{uid}{ext}</D:href>\n"
fn appendResourceHref(
    buf: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    base: []const u8,
    user: []const u8,
    collection: []const u8,
    uid: []const u8,
    comptime ext: []const u8,
) !void {
    const user_esc = try xmlEscape(allocator, user);
    defer allocator.free(user_esc);
    const coll_esc = try xmlEscape(allocator, collection);
    defer allocator.free(coll_esc);
    const uid_esc = try xmlEscape(allocator, uid);
    defer allocator.free(uid_esc);

    try buf.appendSlice(allocator, "    <D:href>");
    try buf.appendSlice(allocator, base);
    try buf.appendSlice(allocator, user_esc);
    try buf.appendSlice(allocator, "/");
    try buf.appendSlice(allocator, coll_esc);
    try buf.appendSlice(allocator, "/");
    try buf.appendSlice(allocator, uid_esc);
    try buf.appendSlice(allocator, ext ++ "</D:href>\n");
}

const dav_multistatus_start = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" ++
    "<D:multistatus xmlns:D=\"" ++ dav_properties.dav ++ "\" xmlns:C=\"" ++ dav_properties.caldav ++
    "\" xmlns:CARD=\"" ++ dav_properties.carddav ++ "\" xmlns:A=\"" ++ dav_properties.ical ++ "\">\n";

fn appendDavSyncMember(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, user: []const u8, collection: []const u8, kind: caldav_store.SyncChange.ResourceType, member: caldav_store.DavSyncMember) !void {
    return appendDavMemberAt(buf, allocator, user, collection, kind, if (kind == .event) "/calendars/" else "/addressbooks/", member);
}

fn appendDavMemberAt(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, user: []const u8, collection: []const u8, kind: caldav_store.SyncChange.ResourceType, base: []const u8, member: caldav_store.DavSyncMember) !void {
    try buf.appendSlice(allocator, "  <D:response>\n");
    switch (kind) {
        .event => try appendResourceHref(buf, allocator, base, user, collection, member.uid, ".ics"),
        .contact => try appendResourceHref(buf, allocator, base, user, collection, member.uid, ".vcf"),
    }
    if (member.etag) |etag| {
        try buf.appendSlice(allocator, "    <D:propstat><D:prop>\n");
        try appendXmlEscaped(buf, allocator, "      <D:getetag>", etag, "</D:getetag>\n");
        try buf.appendSlice(allocator, "    </D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>\n");
    } else {
        try buf.appendSlice(allocator, "    <D:status>HTTP/1.1 404 Not Found</D:status>\n");
    }
    try buf.appendSlice(allocator, "  </D:response>\n");
}

/// Append a plain <D:href> element with the href value XML-escaped.
fn appendHrefEscaped(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, href: []const u8) !void {
    try appendXmlEscaped(buf, allocator, "    <D:href>", href, "</D:href>\n");
}

/// Append a collection <D:href> element (trailing slash) with the user and
/// collection components XML-escaped.
/// Produces: "    <D:href>{base}{user}/{collection}/</D:href>\n"
fn appendCollectionHref(
    buf: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    base: []const u8,
    user: []const u8,
    collection: []const u8,
) !void {
    const user_esc = try xmlEscape(allocator, user);
    defer allocator.free(user_esc);
    const coll_esc = try xmlEscape(allocator, collection);
    defer allocator.free(coll_esc);

    try buf.appendSlice(allocator, "    <D:href>");
    try buf.appendSlice(allocator, base);
    try buf.appendSlice(allocator, user_esc);
    try buf.appendSlice(allocator, "/");
    try buf.appendSlice(allocator, coll_esc);
    try buf.appendSlice(allocator, "/</D:href>\n");
}

// ============================================================================
// CalDAV/CardDAV Session
// ============================================================================

// HTTP authorization belongs to one request, including on pooled keep-alive
// connections. Clear the previous identity before routing public endpoints too.
fn clearRequestAuthentication(allocator: std.mem.Allocator, username: *?[]const u8, authenticated: *bool) void {
    if (username.*) |value| allocator.free(value);
    username.* = null;
    authenticated.* = false;
}

pub const CalDavSession = struct {
    allocator: std.mem.Allocator,
    connection: socket.Connection,
    tls_conn: ?*tls.nonblock.Connection = null,
    request_buf: std.ArrayList(u8) = .empty,
    username: ?[]const u8 = null,
    authenticated: bool = false,
    auth_backend: *auth.AuthBackend,
    store: *caldav_store.CalDavStore,

    pub fn init(allocator: std.mem.Allocator, connection: socket.Connection, auth_backend: *auth.AuthBackend, store: *caldav_store.CalDavStore) CalDavSession {
        return .{
            .allocator = allocator,
            .connection = connection,
            .auth_backend = auth_backend,
            .store = store,
        };
    }

    pub fn deinit(self: *CalDavSession) void {
        clearRequestAuthentication(self.allocator, &self.username, &self.authenticated);
        self.request_buf.deinit(self.allocator);
    }

    /// Read available bytes from a plain connection.
    pub fn handleRequest(self: *CalDavSession, config: *const CalDavConfig) !bool {
        var buf: [16 * 1024]u8 = undefined;
        const received = self.connection.read(&buf) catch return false;
        if (received == 0) return false;
        return self.receive(config, buf[0..received]);
    }

    fn receive(self: *CalDavSession, config: *const CalDavConfig, bytes: []const u8) !bool {
        try self.request_buf.appendSlice(self.allocator, bytes);
        while (true) {
            const length = httpRequestLength(self.request_buf.items, config.max_resource_size) catch |err| {
                switch (err) {
                    error.InvalidFraming => try self.sendError(400, "Bad Request"),
                    error.RequestTooLarge => try self.sendError(413, "Content Too Large"),
                }
                return false;
            } orelse return true;
            const request = self.request_buf.items[0..length];
            if (!try self.dispatchRequest(config, request)) return false;
            if (requestHeader(request, "Connection")) |connection| {
                var values = std.mem.splitScalar(u8, connection, ',');
                while (values.next()) |value| {
                    if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, value, " \t"), "close")) return false;
                }
            }
            const remaining = self.request_buf.items[length..];
            std.mem.copyForwards(u8, self.request_buf.items[0..remaining.len], remaining);
            self.request_buf.shrinkRetainingCapacity(remaining.len);
        }
    }

    fn dispatchRequest(self: *CalDavSession, config: *const CalDavConfig, request: []const u8) !bool {
        clearRequestAuthentication(self.allocator, &self.username, &self.authenticated);
        // Parse HTTP request line
        var lines = std.mem.splitScalar(u8, request, '\n');
        const request_line = lines.next() orelse return false;

        var parts = std.mem.splitScalar(u8, request_line, ' ');
        const method_str = parts.next() orelse return false;
        const path = parts.next() orelse return false;

        const method = HttpMethod.fromString(method_str) orelse {
            try self.sendError(405, "Method Not Allowed");
            return true;
        };

        // Handle .well-known autodiscovery BEFORE authentication (per RFC 5785)
        if (method != .propfind and std.mem.startsWith(u8, path, "/.well-known/caldav")) {
            try self.sendWellKnownRedirect("/calendars/");
            return true;
        }
        if (method != .propfind and std.mem.startsWith(u8, path, "/.well-known/carddav")) {
            try self.sendWellKnownRedirect("/addressbooks/");
            return true;
        }

        // MTA-STS policy (RFC 8461), served at mta-sts.<domain>/.well-known/mta-sts.txt.
        // Lets senders discover that this MX requires TLS. "testing" reports
        // without enforcing (safe default); switch to "enforce" once confident.
        if (method == .get and std.mem.startsWith(u8, path, "/.well-known/mta-sts.txt")) {
            const policy = std.fmt.allocPrint(self.allocator, "version: STSv1\nmode: {s}\nmx: {s}\nmax_age: 604800\n", .{ config.mta_sts_mode, config.public_hostname }) catch {
                try self.sendError(500, "Internal Server Error");
                return true;
            };
            defer self.allocator.free(policy);
            try self.sendWeb(.{ .content_type = "text/plain; charset=utf-8", .body = policy });
            return true;
        }

        // Discovery and Exchange endpoints use the same handlers on either
        // transport. The discovery routes below run before authentication.
        if (method == .get and std.mem.startsWith(u8, path, "/email.mobileconfig")) {
            const wr = webMobileconfig(self.allocator, config, path) catch {
                try self.sendError(400, "Bad Request");
                return true;
            };
            defer if (wr.body.len > 0) self.allocator.free(wr.body);
            try self.sendWeb(wr);
            return true;
        }
        if (method == .get and std.mem.startsWith(u8, path, "/autodiscover/autodiscover.json")) {
            const wr = try webAutodiscoverV2(self.allocator, config, path);
            defer if (wr.body.len > 0) self.allocator.free(wr.body);
            try self.sendWeb(wr);
            return true;
        }
        if (method == .options and std.mem.startsWith(u8, path, "/Microsoft-Server-ActiveSync")) {
            try self.writeAll(ACTIVESYNC_OPTIONS_RESPONSE);
            return true;
        }

        // Check authentication (Digest or Basic Auth)
        if (!self.authenticated) {
            var auth_header: ?[]const u8 = null;
            while (lines.next()) |line| {
                const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
                if (trimmed.len == 0) break;

                if (trimmed.len >= 14 and std.ascii.eqlIgnoreCase(trimmed[0..14], "Authorization:")) {
                    auth_header = std.mem.trim(u8, trimmed[14..], &std.ascii.whitespace);
                    break;
                }
            }

            if (auth_header == null) {
                try self.sendAuthRequired(false);
                return true;
            }

            // Try Digest auth first, then fall back to Basic
            var validated_username: ?[]const u8 = null;
            var stale_nonce = false;

            if (std.mem.startsWith(u8, auth_header.?, "Digest ")) {
                validated_username = self.auth_backend.verifyDigestAuthForPeer(
                    self.connection.peerIp(),
                    auth_header.?,
                    method_str,
                    path,
                    "CalDAV/CardDAV Server",
                ) catch |err| blk: {
                    if (err == error.StaleDigestNonce) {
                        stale_nonce = true;
                        break :blk null;
                    }
                    logger.err("CalDAV Digest authentication error: {}", .{err});
                    break :blk null;
                };
            }

            // Fall back to Basic auth if Digest didn't work
            if (validated_username == null and std.mem.startsWith(u8, auth_header.?, "Basic ")) {
                validated_username = self.auth_backend.verifyBasicAuthForPeer(self.connection.peerIp(), auth_header.?) catch |err| blk: {
                    logger.err("CalDAV Basic authentication error: {}", .{err});
                    break :blk null;
                };
            }

            if (validated_username) |username| {
                self.authenticated = true;
                self.username = username;
                logger.info("Successful CalDAV authentication for user: {s}", .{username});
            } else {
                logger.warn("Failed CalDAV authentication attempt", .{});
                try self.sendAuthRequired(stale_nonce);
                return true;
            }
        }

        // Authenticated Exchange web services.
        if (method == .post and std.mem.startsWith(u8, path, "/Microsoft-Server-ActiveSync")) {
            const wr = try webActiveSync(self.allocator, config, self.auth_backend.db, self.store, self.username, path, request);
            defer if (wr.body.len > 0) self.allocator.free(wr.body);
            try self.sendWeb(wr);
            return true;
        }
        if (method == .post and (std.mem.startsWith(u8, path, "/autodiscover/") or std.mem.startsWith(u8, path, "/Autodiscover/"))) {
            const wr = try webAutodiscover(self.allocator, config, self.username, request);
            defer if (wr.body.len > 0) self.allocator.free(wr.body);
            try self.sendWeb(wr);
            return true;
        }
        if (method == .post and (std.mem.startsWith(u8, path, "/EWS/") or std.mem.startsWith(u8, path, "/ews/"))) {
            const wr = try webEws(self.allocator, config, self.username, self.store, self.auth_backend.db, request);
            defer if (wr.body.len > 0) self.allocator.free(wr.body);
            try self.sendWeb(wr);
            return true;
        }

        // Route request based on method and path
        try self.routeRequest(method, path, request, config);

        return true;
    }

    /// Resolve the user_id for the currently authenticated user.
    fn getUserId(self: *CalDavSession) !u64 {
        const username = self.username orelse return error.NotAuthenticated;
        return self.store.getOrCreateUserId(username);
    }

    /// Route request to appropriate handler
    fn routeRequest(
        self: *CalDavSession,
        method: HttpMethod,
        path: []const u8,
        request: []const u8,
        config: *const CalDavConfig,
    ) !void {
        const username = self.username orelse return self.sendError(401, "Unauthorized");
        const access = try self.auth_backend.db.mailboxAccess(username);
        if (!access.readable()) return self.sendError(403, "Forbidden");
        if (access == .read_only) switch (method) {
            .get, .options, .propfind, .report => {},
            else => return self.sendError(403, "Mailbox is read-only"),
        };

        const parsed = parsePath(path);
        // Free/busy also works with a grant that allows no event access.
        if (method == .report and config.enable_caldav) {
            const body = httpBody(request);
            var rest = body;
            if (nextXmlOpen(&rest)) |root| {
                if (std.mem.eql(u8, root.localName(), "free-busy-query"))
                    return self.handleFreeBusy(parsed, request, body);
            }
        }
        if (parsed.user) |owner| {
            const owned = try self.ownsPath(owner);
            switch (parsed.path_type) {
                .shared_calendars_home => {
                    if (!owned or !config.enable_caldav) return self.sendError(404, "Not Found");
                    return self.handleSharedCalendarHome(method, owner, request);
                },
                .shared_calendar_collection, .shared_calendar_resource => {
                    if (!owned) return self.sendError(404, "Not Found");
                    return self.handleSharedCalendar(method, parsed, request, config);
                },
                else => if (!owned) return self.handleSharedCalendar(method, parsed, request, config),
            }
        }
        switch (method) {
            .options => try self.handleOptions(),
            .propfind => try self.handlePropfind(path, request, config),
            .proppatch => try self.handleProppatch(parsed, request, config),
            .get, .head => try self.handleGet(path, request, method == .head),
            .put => try self.handlePut(path, request, config),
            .delete => try self.handleDelete(path, request),
            .mkcalendar => try self.handleMkcalendar(path, config),
            .mkcol => try self.handleMkcol(path, config),
            .report => try self.handleReport(path, request, config),
            else => try self.sendError(501, "Not Implemented"),
        }
    }

    fn ownsPath(self: *CalDavSession, owner: []const u8) !bool {
        const username = self.username orelse return false;
        var buffer: [2048]u8 = undefined;
        const decoded = percentDecodeOnce(owner, &buffer) orelse return false;
        if (std.mem.eql(u8, decoded, username)) return true;
        const db = self.auth_backend.db;
        var user = db.getUserByUsername(username) catch |err| switch (err) {
            error.NotFound => return false,
            else => return err,
        };
        defer user.deinit(db.allocator);
        return std.mem.eql(u8, decoded, user.email);
    }

    const DavCalendarTarget = caldav_store.CalDavStore.DavCalendarTarget;

    const CalendarPath = struct {
        user: []const u8,
        collection: []const u8,
        shared_alias: bool = false,

        fn base(self: CalendarPath) []const u8 {
            return if (self.shared_alias) "/shared-calendars/" else "/calendars/";
        }
    };

    fn parseShareId(value: []const u8) ?@FieldType(DavCalendarTarget, "shared") {
        if (value.len != 32) return null;
        for (value) |digit| if (!(std.ascii.isDigit(digit) or (digit >= 'a' and digit <= 'f'))) return null;
        return value[0..32].*;
    }

    fn handleSharedCalendarHome(self: *CalDavSession, method: HttpMethod, user: []const u8, request: []const u8) !void {
        if (method == .options) return self.handleOptions();
        if (method != .propfind) return self.sendError(404, "Not Found");
        const username = self.username orelse return error.NotAuthenticated;
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const depth = requestHeader(request, "Depth") orelse "0";
        if (!std.mem.eql(u8, depth, "0") and !std.mem.eql(u8, depth, "1") and !std.mem.eql(u8, depth, "infinity"))
            return self.sendError(400, "Invalid Depth");
        var buf: std.ArrayList(u8) = .empty;
        try buf.appendSlice(a, dav_multistatus_start ++ "  <D:response>\n");
        try appendXmlEscaped(&buf, a, "    <D:href>/shared-calendars/", user, "/</D:href>\n");
        try buf.appendSlice(a, "    <D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype>" ++
            "<D:displayname>Shared calendars</D:displayname></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>\n  </D:response>\n");
        if (!std.mem.eql(u8, depth, "0")) {
            const shares = self.store.snapshotSharedDavCollections(a, username) catch |err| return self.sendResourceError(err);
            for (shares) |*item| {
                try self.appendDavCollection(&buf, a, user, &item.id, .event, item.properties, null, null, .{
                    .editable = item.editable,
                    .alias = true,
                    .supports_sync = self.store.config.enable_sync_tokens,
                });
            }
        }
        try buf.appendSlice(a, "</D:multistatus>");
        return self.sendMultistatusResponse(buf.items);
    }

    fn handleSharedCalendar(self: *CalDavSession, method: HttpMethod, parsed: ParsedPath, request: []const u8, config: *const CalDavConfig) !void {
        if (!config.enable_caldav) return self.sendError(404, "Not Found");
        const username = self.username orelse return error.NotAuthenticated;
        const owner_path = parsed.user orelse return self.sendError(404, "Not Found");
        var owner_buf: [2048]u8 = undefined;
        const owner = percentDecodeOnce(owner_path, &owner_buf) orelse return self.sendError(404, "Not Found");
        const collection = parsed.collection orelse return self.sendError(404, "Not Found");
        const alias = parsed.path_type == .shared_calendar_collection or parsed.path_type == .shared_calendar_resource;
        const target: DavCalendarTarget = if (alias)
            .{ .shared = parseShareId(collection) orelse return self.sendError(404, "Not Found") }
        else
            .{ .named = .{ .owner = owner, .collection = collection } };
        const location: CalendarPath = .{ .user = owner_path, .collection = collection, .shared_alias = alias };

        if (parsed.path_type == .calendar_collection or parsed.path_type == .shared_calendar_collection)
            return self.handleSharedCalendarListing(method, username, location, target, request);
        if (parsed.path_type != .calendar_resource and parsed.path_type != .shared_calendar_resource) return self.sendError(404, "Not Found");
        const uid = parsed.resource_uid orelse return self.sendError(404, "Not Found");
        switch (method) {
            .put => return self.handleCalendarPut(collection, uid, request, config, target),
            .delete => {
                self.store.deleteSharedDavEvent(username, target, uid, resourceConditions(request)) catch |err|
                    return self.sendResourceError(err);
                return self.sendSuccess(204, "No Content");
            },
            .get, .head, .propfind, .options => {
                var arena = std.heap.ArenaAllocator.init(self.allocator);
                defer arena.deinit();
                const a = arena.allocator();
                const resource = self.store.getSharedDavEvent(a, username, target, uid) catch |err|
                    return self.sendResourceError(err);
                if (method == .options) return self.handleOptions();
                if (method != .propfind) return self.sendDavResource(resource, request, .event, method == .head, true);
                var buf: std.ArrayList(u8) = .empty;
                try buf.appendSlice(a, dav_multistatus_start);
                try appendDavMemberAt(&buf, a, owner_path, collection, .event, location.base(), .{ .uid = uid, .etag = resource.etag });
                try buf.appendSlice(a, "</D:multistatus>");
                return self.sendMultistatusResponse(buf.items);
            },
            else => return self.sendError(404, "Not Found"),
        }
    }

    fn handleSharedCalendarListing(self: *CalDavSession, method: HttpMethod, username: []const u8, location: CalendarPath, target: DavCalendarTarget, request: []const u8) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const body = httpBody(request);
        if (method == .propfind and self.store.config.enable_sync_tokens) {
            const depth = requestHeader(request, "Depth") orelse "0";
            const sync: ?caldav_store.CalDavStore.DavSharedSync = self.store.snapshotSharedDavSync(a, username, target, if (std.mem.eql(u8, depth, "0")) .version_only else .initial) catch |err| switch (err) {
                // A large collection can still provide the public ETag listing.
                error.CalendarExportTooLarge => null,
                else => return self.sendResourceError(err),
            };
            if (sync) |snapshot| {
                var buf: std.ArrayList(u8) = .empty;
                try buf.appendSlice(a, dav_multistatus_start);
                try self.appendDavCollection(&buf, a, location.user, location.collection, .event, snapshot.properties, snapshot.report.token, null, .{
                    .editable = snapshot.editable,
                    .alias = location.shared_alias,
                    .supports_sync = true,
                });
                for (snapshot.report.members) |member| {
                    try appendDavMemberAt(&buf, a, location.user, location.collection, .event, location.base(), member);
                }
                try buf.appendSlice(a, "</D:multistatus>");
                return self.sendMultistatusResponse(buf.items);
            }
        }
        const listing: caldav_store.CalDavStore.SharedDavListing = switch (method) {
            .options => .collection,
            .propfind => if (std.mem.eql(u8, requestHeader(request, "Depth") orelse "0", "0")) .collection else .etags,
            .report => blk: {
                var xml = body;
                const root = nextXmlOpen(&xml) orelse return self.sendError(404, "Not Found");
                if (std.mem.eql(u8, root.localName(), "calendar-query")) break :blk .events;
                if (std.mem.eql(u8, root.localName(), "calendar-multiget"))
                    return self.handleSharedCalendarMultiget(a, username, location, target, xml);
                if (std.mem.eql(u8, root.localName(), "sync-collection") and self.store.config.enable_sync_tokens)
                    return self.handleSharedDavSync(a, username, location, target, request, xml);
                return self.sendError(404, "Not Found");
            },
            else => return self.sendError(404, "Not Found"),
        };
        const snapshot = self.store.snapshotSharedDavMembers(a, username, target, listing) catch |err|
            return self.sendResourceError(err);
        if (method == .options) return self.handleOptions();
        if (listing == .events) return self.sendCalendarQuery(a, location, body, snapshot);
        var buf: std.ArrayList(u8) = .empty;
        try buf.appendSlice(a, dav_multistatus_start);
        try self.appendDavCollection(&buf, a, location.user, location.collection, .event, snapshot.properties, null, null, .{ .editable = snapshot.editable, .alias = location.shared_alias });
        for (snapshot.members) |member| {
            try appendDavMemberAt(&buf, a, location.user, location.collection, .event, location.base(), .{ .uid = member.uid, .etag = member.etag });
        }
        try buf.appendSlice(a, "</D:multistatus>");
        return self.sendMultistatusResponse(buf.items);
    }

    fn handleSharedCalendarMultiget(self: *CalDavSession, a: std.mem.Allocator, username: []const u8, location: CalendarPath, target: DavCalendarTarget, body: []const u8) !void {
        const Requested = struct { href: []const u8, uid: ?[]const u8 };
        var requests: std.ArrayList(Requested) = .empty;
        var uids: std.StringHashMapUnmanaged(void) = .empty;
        var xml = body;
        while (nextXmlText(&xml, "href")) |href| {
            const uid = sharedCalendarHrefUid(location, href);
            if (uid) |name| {
                if ((try uids.getOrPut(a, name)).found_existing) continue;
            }
            try requests.append(a, .{ .href = href, .uid = uid });
        }
        const snapshot = self.store.snapshotSharedDavMembers(a, username, target, .{ .requested = uids }) catch |err|
            return self.sendResourceError(err);
        var members: std.StringHashMapUnmanaged(caldav_store.CalDavStore.DavCalendarMember) = .empty;
        for (snapshot.members) |member| try members.put(a, member.uid, member);

        var buf: std.ArrayList(u8) = .empty;
        try buf.appendSlice(a, dav_multistatus_start);
        for (requests.items) |item| {
            try buf.appendSlice(a, "  <D:response>\n");
            try appendHrefEscaped(&buf, a, item.href);
            if (if (item.uid) |uid| members.get(uid) else null) |member| {
                try appendMultigetProperties(&buf, a, "C:calendar-data", member.etag, member.source.icalendar);
            } else {
                try appendMultigetProperties(&buf, a, "C:calendar-data", null, "");
            }
        }
        try buf.appendSlice(a, "</D:multistatus>");
        return self.sendMultistatusResponse(buf.items);
    }

    fn sharedCalendarHrefUid(location: CalendarPath, href: []const u8) ?[]const u8 {
        const item = parsePath(href);
        const resource: ParsedPath.PathType = if (location.shared_alias) .shared_calendar_resource else .calendar_resource;
        if (item.path_type != resource or !std.mem.eql(u8, item.collection orelse return null, location.collection))
            return null;
        var actual: [2048]u8 = undefined;
        var expected: [2048]u8 = undefined;
        const person = percentDecodeOnce(item.user orelse return null, &actual) orelse return null;
        const owner = percentDecodeOnce(location.user, &expected) orelse return null;
        if (!std.mem.eql(u8, person, owner)) return null;
        return item.resource_uid;
    }

    /// Send .well-known redirect
    fn sendWellKnownRedirect(self: *CalDavSession, location: []const u8) !void {
        var buf: [512]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        try writer.print(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: {s}\r\nContent-Length: 0\r\n\r\n",
            .{location},
        );
        try self.writeAll(fbs.getWritten());
    }

    /// Handle OPTIONS request (WebDAV/CalDAV/CardDAV capabilities)
    fn handleOptions(self: *CalDavSession) !void {
        const response =
            "HTTP/1.1 200 OK\r\n" ++
            "DAV: 1, 3, calendar-access, addressbook\r\n" ++
            "Allow: OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCALENDAR, MKCOL, REPORT\r\n" ++
            "Content-Length: 0\r\n\r\n";

        try self.writeAll(response);
    }

    /// Handle PROPFIND request (property discovery)
    fn handlePropfind(
        self: *CalDavSession,
        path: []const u8,
        request: []const u8,
        config: *const CalDavConfig,
    ) !void {
        const depth_header = requestHeader(request, "Depth") orelse "0";
        const depth: u8 = if (std.mem.eql(u8, depth_header, "1") or std.mem.eql(u8, depth_header, "infinity")) 1 else 0;

        const parsed = parsePath(path);
        const user_id = try self.getUserId();

        // Build XML response using dynamic buffer
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.allocator);

        switch (parsed.path_type) {
            .root, .well_known_caldav, .well_known_carddav => {
                // Root PROPFIND - return principal URLs
                try buf.appendSlice(self.allocator, "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n");
                try buf.appendSlice(self.allocator, "<D:multistatus xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\" xmlns:CARD=\"urn:ietf:params:xml:ns:carddav\">\n");
                try buf.appendSlice(self.allocator, "  <D:response>\n");
                try buf.appendSlice(self.allocator, "    <D:href>/</D:href>\n");
                try buf.appendSlice(self.allocator, "    <D:propstat>\n");
                try buf.appendSlice(self.allocator, "      <D:prop>\n");
                try buf.appendSlice(self.allocator, "        <D:resourcetype><D:collection/></D:resourcetype>\n");
                const username = self.username orelse "user";
                try appendXmlEscaped(&buf, self.allocator, "        <D:current-user-principal><D:href>/principals/", username, "</D:href></D:current-user-principal>\n");
                try buf.appendSlice(self.allocator, "      </D:prop>\n");
                try buf.appendSlice(self.allocator, "      <D:status>HTTP/1.1 200 OK</D:status>\n");
                try buf.appendSlice(self.allocator, "    </D:propstat>\n");
                try buf.appendSlice(self.allocator, "  </D:response>\n");
                try buf.appendSlice(self.allocator, "</D:multistatus>");
            },
            .principals, .principal_user => {
                const username = parsed.user orelse (self.username orelse "user");
                const username_esc = try xmlEscape(self.allocator, username);
                defer self.allocator.free(username_esc);
                try buf.appendSlice(self.allocator, "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n");
                try buf.appendSlice(self.allocator, "<D:multistatus xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\" xmlns:CARD=\"urn:ietf:params:xml:ns:carddav\">\n");
                try buf.appendSlice(self.allocator, "  <D:response>\n");
                try appendPrint(&buf, self.allocator, "    <D:href>/principals/{s}</D:href>\n", .{username_esc});
                try buf.appendSlice(self.allocator, "    <D:propstat>\n");
                try buf.appendSlice(self.allocator, "      <D:prop>\n");
                try buf.appendSlice(self.allocator, "        <D:resourcetype><D:principal/></D:resourcetype>\n");
                try appendPrint(&buf, self.allocator, "        <D:current-user-principal><D:href>/principals/{s}</D:href></D:current-user-principal>\n", .{username_esc});
                try appendPrint(&buf, self.allocator, "        <C:calendar-home-set><D:href>/calendars/{s}/</D:href>", .{username_esc});
                if (config.enable_caldav and self.store.config.account_db != null)
                    try appendPrint(&buf, self.allocator, "<D:href>/shared-calendars/{s}/</D:href>", .{username_esc});
                try buf.appendSlice(self.allocator, "</C:calendar-home-set>\n");
                try appendPrint(&buf, self.allocator, "        <CARD:addressbook-home-set><D:href>/addressbooks/{s}/</D:href></CARD:addressbook-home-set>\n", .{username_esc});
                try buf.appendSlice(self.allocator, "      </D:prop>\n");
                try buf.appendSlice(self.allocator, "      <D:status>HTTP/1.1 200 OK</D:status>\n");
                try buf.appendSlice(self.allocator, "    </D:propstat>\n");
                try buf.appendSlice(self.allocator, "  </D:response>\n");
                try buf.appendSlice(self.allocator, "</D:multistatus>");
            },
            .calendars_home, .addressbooks_home, .calendar_collection, .addressbook_collection => {
                return self.handleCollectionPropfind(parsed, user_id, depth);
            },
            else => {
                // Fallback: generic PROPFIND response for the path
                try buf.appendSlice(self.allocator, "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n");
                try buf.appendSlice(self.allocator, "<D:multistatus xmlns:D=\"DAV:\">\n");
                try buf.appendSlice(self.allocator, "  <D:response>\n");
                try appendHrefEscaped(&buf, self.allocator, path);
                try buf.appendSlice(self.allocator, "    <D:propstat>\n");
                try buf.appendSlice(self.allocator, "      <D:prop>\n");
                try buf.appendSlice(self.allocator, "        <D:resourcetype><D:collection/></D:resourcetype>\n");
                try buf.appendSlice(self.allocator, "      </D:prop>\n");
                try buf.appendSlice(self.allocator, "      <D:status>HTTP/1.1 200 OK</D:status>\n");
                try buf.appendSlice(self.allocator, "    </D:propstat>\n");
                try buf.appendSlice(self.allocator, "  </D:response>\n");
                try buf.appendSlice(self.allocator, "</D:multistatus>");
            },
        }

        const body = buf.items;
        var header_buf: [256]u8 = undefined;
        var header_fbs = io_compat.fixedBufferStream(&header_buf);
        const header_writer = header_fbs.writer();
        try header_writer.print(
            "HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: {d}\r\n\r\n",
            .{body.len},
        );

        try self.writeAll(header_fbs.getWritten());
        try self.writeAll(body);
    }

    fn handleCollectionPropfind(self: *CalDavSession, parsed: ParsedPath, user_id: u64, depth: u8) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const kind: caldav_store.SyncChange.ResourceType = switch (parsed.path_type) {
            .calendars_home, .calendar_collection => .event,
            else => .contact,
        };
        const username = parsed.user orelse self.username orelse return error.NotAuthenticated;
        var buf: std.ArrayList(u8) = .empty;
        try buf.appendSlice(a, dav_multistatus_start);
        if (parsed.collection) |collection| {
            const snapshot = self.store.snapshotDavPropfind(a, user_id, collection, kind, if (depth > 0) .initial else .version_only) catch |err| switch (err) {
                error.NotFound => return self.sendError(404, "Not Found"),
                else => return err,
            };
            try self.appendDavCollection(&buf, a, username, collection, kind, snapshot.properties, snapshot.report.token, null, null);
            for (snapshot.report.members) |member| try appendDavSyncMember(&buf, a, username, collection, kind, member);
        } else {
            const collections = try self.store.snapshotDavCollections(a, user_id, kind);
            for (collections) |collection| {
                try self.appendDavCollection(&buf, a, username, collection.name, kind, collection.properties, collection.token, collection.ctag, null);
            }
        }
        try buf.appendSlice(a, "</D:multistatus>");
        try self.sendMultistatusResponse(buf.items);
    }

    const SharedCollectionProperties = struct { editable: bool, alias: bool, supports_sync: bool = false };

    fn appendDavCollection(self: *CalDavSession, buf: *std.ArrayList(u8), a: std.mem.Allocator, username: []const u8, collection: []const u8, kind: caldav_store.SyncChange.ResourceType, properties: caldav_store.DavCollectionProperties, token: ?[]const u8, ctag: ?[]const u8, shared: ?SharedCollectionProperties) !void {
        try buf.appendSlice(a, "  <D:response>\n");
        switch (kind) {
            .event => try appendCollectionHref(buf, a, if (shared != null and shared.?.alias) "/shared-calendars/" else "/calendars/", username, collection),
            .contact => try appendCollectionHref(buf, a, "/addressbooks/", username, collection),
        }
        try buf.appendSlice(a, "    <D:propstat><D:prop>\n");
        switch (kind) {
            .event => {
                try buf.appendSlice(a, "      <D:resourcetype><D:collection/><C:calendar/></D:resourcetype>\n" ++
                    "      <C:supported-calendar-component-set><C:comp name=\"VEVENT\"/>");
                if (shared == null) try buf.appendSlice(a, "<C:comp name=\"VTODO\"/>");
                try buf.appendSlice(a, "</C:supported-calendar-component-set>\n");
            },
            .contact => try buf.appendSlice(a, "      <D:resourcetype><D:collection/><CARD:addressbook/></D:resourcetype>\n" ++
                "      <CARD:supported-address-data><CARD:address-data-type content-type=\"text/vcard\" version=\"3.0\"/></CARD:supported-address-data>\n"),
        }
        var scratch: [2048]u8 = undefined;
        const fallback = if (shared != null) percentDecodeOnce(properties.name, &scratch) orelse properties.name else collection;
        try appendXmlEscaped(buf, a, "      <D:displayname>", properties.display_name orelse fallback, "</D:displayname>\n");
        if (properties.description) |description| switch (kind) {
            .event => try appendXmlEscaped(buf, a, "      <C:calendar-description>", description, "</C:calendar-description>\n"),
            .contact => try appendXmlEscaped(buf, a, "      <CARD:addressbook-description>", description, "</CARD:addressbook-description>\n"),
        };
        if (properties.color) |color| try appendXmlEscaped(buf, a, "      <A:calendar-color>", color, "</A:calendar-color>\n");
        if (ctag) |tag| try appendXmlEscaped(buf, a, "      <CS:getctag xmlns:CS=\"http://calendarserver.org/ns/\">", tag, "</CS:getctag>\n");
        try buf.appendSlice(a, "      <D:supported-report-set>\n");
        switch (kind) {
            .event => try buf.appendSlice(a, "        <D:supported-report><D:report><C:calendar-query/></D:report></D:supported-report>\n" ++
                "        <D:supported-report><D:report><C:calendar-multiget/></D:report></D:supported-report>\n" ++
                "        <D:supported-report><D:report><C:free-busy-query/></D:report></D:supported-report>\n"),
            .contact => try buf.appendSlice(a, "        <D:supported-report><D:report><CARD:addressbook-query/></D:report></D:supported-report>\n" ++
                "        <D:supported-report><D:report><CARD:addressbook-multiget/></D:report></D:supported-report>\n"),
        }
        if (self.store.config.enable_sync_tokens and (token != null or (shared != null and shared.?.supports_sync))) {
            try buf.appendSlice(a, "        <D:supported-report><D:report><D:sync-collection/></D:report></D:supported-report>\n");
        }
        try buf.appendSlice(a, "      </D:supported-report-set>\n");
        if (self.store.config.enable_sync_tokens) {
            if (token) |value| try appendXmlEscaped(buf, a, "      <D:sync-token>", value, "</D:sync-token>\n");
        }
        if (shared) |access| {
            try buf.appendSlice(a, "      <D:current-user-privilege-set><D:privilege><D:read/></D:privilege>\n");
            if (access.editable) try buf.appendSlice(a, "        <D:privilege><D:write-content/></D:privilege><D:privilege><D:bind/></D:privilege><D:privilege><D:unbind/></D:privilege>\n");
            try buf.appendSlice(a, "      </D:current-user-privilege-set>\n");
        }
        try buf.appendSlice(a, "    </D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>\n  </D:response>\n");
    }

    /// Handle PROPPATCH on an owned calendar or address book.
    fn handleProppatch(self: *CalDavSession, parsed: ParsedPath, request: []const u8, config: *const CalDavConfig) !void {
        const kind: caldav_store.SyncChange.ResourceType = switch (parsed.path_type) {
            .calendar_collection => if (config.enable_caldav) .event else return self.sendError(404, "Not Found"),
            .addressbook_collection => if (config.enable_carddav) .contact else return self.sendError(404, "Not Found"),
            else => return self.sendError(501, "PROPPATCH not supported on this resource"),
        };
        const name = parsed.collection orelse return self.sendError(404, "Not Found");
        const username = parsed.user orelse return self.sendError(404, "Not Found");
        const user_id = try self.getUserId();
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const update = dav_properties.parse(a, httpBody(request), kind) catch |err| switch (err) {
            error.InvalidXml => return self.sendError(400, "Invalid propertyupdate XML"),
            error.PropertyUpdateTooLarge => return self.sendError(413, "Property update is too large"),
            else => return self.sendResourceError(err),
        };

        self.store.patchOwnedDavCollection(user_id, name, kind, update.patch) catch |err| switch (err) {
            error.NotFound => return self.sendError(404, "Not Found"),
            else => {
                for (update.results.items) |*result| result.status = .store_failed;
            },
        };
        var buf: std.ArrayList(u8) = .empty;
        try buf.appendSlice(a, dav_multistatus_start ++ "  <D:response>\n");
        try appendCollectionHref(&buf, a, if (kind == .event) "/calendars/" else "/addressbooks/", username, name);
        for (update.results.items) |result| {
            try buf.appendSlice(a, "    <D:propstat><D:prop><");
            const xml_prefix = std.mem.eql(u8, result.namespace, dav_properties.xml_namespace);
            if (xml_prefix) try buf.appendSlice(a, "xml:") else if (result.namespace.len != 0) try buf.appendSlice(a, "P:");
            try buf.appendSlice(a, result.name);
            if (result.namespace.len != 0 and !xml_prefix)
                try appendXmlEscaped(&buf, a, " xmlns:P=\"", result.namespace, "\"");
            try appendPrint(&buf, a, "/></D:prop><D:status>HTTP/1.1 {s}</D:status>", .{result.status.line()});
            if (result.status == .protected)
                try buf.appendSlice(a, "<D:error><D:cannot-modify-protected-property/></D:error>");
            try buf.appendSlice(a, "</D:propstat>\n");
        }
        try buf.appendSlice(a, "  </D:response>\n</D:multistatus>");
        return self.sendMultistatusResponse(buf.items);
    }

    /// Handle GET request (retrieve calendar/contact resource)
    fn handleGet(self: *CalDavSession, path: []const u8, request: []const u8, headers_only: bool) !void {
        const parsed = parsePath(path);
        const kind = resourceKind(parsed.path_type) orelse return self.sendError(404, "Not Found");
        const uid = parsed.resource_uid orelse return self.sendError(404, "Not Found");
        const name = parsed.collection orelse return self.sendError(404, "Not Found");
        const user_id = try self.getUserId();
        const resource = (self.store.getResource(user_id, name, uid, kind) catch |err|
            return self.sendResourceError(err)) orelse return self.sendError(404, "Not Found");
        defer self.store.allocator.free(resource.etag);
        defer self.store.allocator.free(resource.body);
        return self.sendDavResource(resource, request, kind, headers_only, false);
    }

    fn sendDavResource(self: *CalDavSession, resource: caldav_store.Resource, request: []const u8, kind: caldav_store.SyncChange.ResourceType, headers_only: bool, shared: bool) !void {
        const conditions = resourceConditions(request);
        if (!(caldav_store.ResourceConditions{ .if_match = conditions.if_match }).allows(resource.etag)) {
            return self.sendError(412, "Precondition Failed");
        }
        if (!conditions.allows(resource.etag)) return self.sendTaggedResponse(.not_modified, resource.etag);

        var buffer: [512]u8 = undefined;
        const content_type: []const u8 = if (kind == .event) "text/calendar" else "text/vcard";
        const header = try std.fmt.bufPrint(
            &buffer,
            "HTTP/1.1 200 OK\r\nContent-Type: {s}; charset=utf-8\r\nETag: {s}\r\n{s}Content-Length: {d}\r\n\r\n",
            .{ content_type, resource.etag, if (shared) "Cache-Control: private, no-store\r\n" else "", resource.body.len },
        );
        try self.writeAll(header);
        if (!headers_only) try self.writeAll(resource.body);
    }

    fn sendTaggedResponse(self: *CalDavSession, status: enum { created, updated, not_modified }, etag: []const u8) !void {
        var buffer: [256]u8 = undefined;
        const reason = switch (status) {
            .created => "201 Created",
            .updated => "204 No Content",
            .not_modified => "304 Not Modified",
        };
        const length = if (status == .created) "Content-Length: 0\r\n" else "";
        const response = try std.fmt.bufPrint(&buffer, "HTTP/1.1 {s}\r\nETag: {s}\r\n{s}\r\n", .{ reason, etag, length });
        try self.writeAll(response);
    }

    fn sendResourceError(self: *CalDavSession, err: anyerror) !void {
        return switch (err) {
            error.NotFound, error.CalendarNotFound, error.EventNotFound, error.DavMailboxNotFound => self.sendError(404, "Not Found"),
            error.PreconditionFailed => self.sendError(412, "Precondition Failed"),
            error.WrongCollectionType => self.sendError(400, "Path is not a calendar"),
            error.SharedEventMustBePublic => self.sendError(422, "Shared events must be public"),
            error.CalendarExportTooLarge => self.sendError(413, "Calendar listing is too large"),
            else => self.sendError(500, "Internal Server Error"),
        };
    }

    fn checkPutContent(self: *CalDavSession, config: *const CalDavConfig, body: []const u8) !bool {
        scanDavResource(self.allocator, config.scanner, body) catch |err| {
            switch (err) {
                error.MalwareDetected => try self.sendError(422, "Resource rejected by malware scanner"),
                error.InvalidDavBinary => try self.sendError(422, "Invalid embedded binary resource"),
                error.MalwareScanTooLarge => try self.sendError(413, "Resource exceeds scanner size limit"),
                error.MalwareScanUnavailable, error.OutOfMemory => try self.sendError(503, "Malware scanner unavailable"),
            }
            return false;
        };
        return true;
    }

    fn handleCalendarPut(self: *CalDavSession, collection: []const u8, uid: []const u8, request: []const u8, config: *const CalDavConfig, shared: ?caldav_store.CalDavStore.DavCalendarTarget) !void {
        const username = self.username orelse return error.NotAuthenticated;
        if (shared) |target| self.store.checkSharedDavEdit(username, target, uid) catch |err|
            return self.sendResourceError(err);
        const body = httpBody(request);
        if (std.mem.indexOf(u8, body, "BEGIN:VCALENDAR") == null) return self.sendError(400, "Invalid iCalendar format");
        if (!try self.checkPutContent(config, body)) return;

        var scratch = std.heap.ArenaAllocator.init(self.allocator);
        defer scratch.deinit();
        var data = (try calendar_import.indexDavEvent(scratch.allocator(), body)) orelse legacyDavEvent(body);
        data.uid = uid;
        const conditions = resourceConditions(request);
        const result = (if (shared) |target|
            self.store.putSharedDavEvent(username, target, uid, conditions, data)
        else
            self.store.putEventResource(try self.getUserId(), collection, uid, conditions, data)) catch |err|
            return self.sendResourceError(err);
        try self.sendTaggedResponse(if (result.created) .created else .updated, result.etag());
    }

    /// Handle PUT request (create/update calendar/contact resource)
    fn handlePut(
        self: *CalDavSession,
        path: []const u8,
        request: []const u8,
        config: *const CalDavConfig,
    ) !void {
        const parsed = parsePath(path);

        const body = httpBody(request);
        const conditions = resourceConditions(request);

        switch (parsed.path_type) {
            .calendar_resource => {
                const uid = parsed.resource_uid orelse return self.sendError(400, "Missing resource UID");
                const collection = parsed.collection orelse return self.sendError(400, "Missing calendar name");
                return self.handleCalendarPut(collection, uid, request, config, null);
            },
            .addressbook_resource => {
                if (std.mem.indexOf(u8, body, "BEGIN:VCARD") == null) {
                    try self.sendError(400, "Invalid vCard format");
                    return;
                }
                const uid = parsed.resource_uid orelse {
                    try self.sendError(400, "Missing resource UID");
                    return;
                };
                const collection_name = parsed.collection orelse {
                    try self.sendError(400, "Missing addressbook name");
                    return;
                };
                if (!try self.checkPutContent(config, body)) return;
                const user_id = try self.getUserId();

                var scratch = std.heap.ArenaAllocator.init(self.allocator);
                defer scratch.deinit();
                const contact_data = try caldav_store.contactDataFromVcf(scratch.allocator(), uid, body);
                const result = self.store.putContactResource(user_id, collection_name, uid, conditions, contact_data) catch |err|
                    return self.sendResourceError(err);
                try self.sendTaggedResponse(if (result.created) .created else .updated, result.etag());
            },
            else => {
                try self.sendError(400, "Invalid PUT path");
            },
        }
    }

    /// Handle DELETE request (delete calendar/contact resource)
    fn handleDelete(self: *CalDavSession, path: []const u8, request: []const u8) !void {
        const parsed = parsePath(path);

        switch (parsed.path_type) {
            .calendar_resource, .addressbook_resource => {
                const kind = resourceKind(parsed.path_type).?;
                const uid = parsed.resource_uid orelse return self.sendError(404, "Not Found");
                const collection = parsed.collection orelse return self.sendError(404, "Not Found");
                const user_id = try self.getUserId();
                self.store.deleteResource(user_id, collection, uid, kind, resourceConditions(request)) catch |err|
                    return self.sendResourceError(err);
                return self.sendSuccess(204, "No Content");
            },
            .calendar_collection => {
                // Delete entire calendar
                const collection_name = parsed.collection orelse {
                    try self.sendError(404, "Not Found");
                    return;
                };
                const user_id = try self.getUserId();
                const calendars = self.store.getUserCalendars(user_id) catch {
                    try self.sendError(500, "Internal Server Error");
                    return;
                };
                for (calendars) |cal| {
                    if (std.mem.eql(u8, cal.name, collection_name)) {
                        self.store.deleteCalendar(cal.id) catch {
                            try self.sendError(500, "Internal Server Error");
                            return;
                        };
                        try self.sendSuccess(204, "No Content");
                        return;
                    }
                }
                try self.sendError(404, "Not Found");
            },
            .addressbook_collection => {
                // Delete entire addressbook
                const collection_name = parsed.collection orelse {
                    try self.sendError(404, "Not Found");
                    return;
                };
                const user_id = try self.getUserId();
                const addressbooks = self.store.getUserAddressBooks(user_id) catch {
                    try self.sendError(500, "Internal Server Error");
                    return;
                };
                for (addressbooks) |ab| {
                    if (std.mem.eql(u8, ab.name, collection_name)) {
                        self.store.deleteAddressBook(ab.id) catch {
                            try self.sendError(500, "Internal Server Error");
                            return;
                        };
                        try self.sendSuccess(204, "No Content");
                        return;
                    }
                }
                try self.sendError(404, "Not Found");
            },
            else => {
                try self.sendError(404, "Not Found");
            },
        }
    }

    /// Handle MKCALENDAR request (create new calendar)
    fn handleMkcalendar(self: *CalDavSession, path: []const u8, config: *const CalDavConfig) !void {
        _ = config;
        const parsed = parsePath(path);

        if (parsed.path_type == .calendar_collection) {
            const collection_name = parsed.collection orelse {
                try self.sendError(400, "Missing calendar name");
                return;
            };
            const user_id = try self.getUserId();
            // Check for duplicate
            if (self.store.getCalendarByName(user_id, collection_name) != null) {
                try self.sendError(405, "Calendar already exists");
                return;
            }
            _ = self.store.createCalendar(user_id, collection_name, null) catch {
                try self.sendError(500, "Internal Server Error");
                return;
            };
            try self.sendSuccess(201, "Created");
        } else {
            try self.sendError(400, "Invalid MKCALENDAR path");
        }
    }

    /// Handle MKCOL request (create collection - typically addressbook)
    fn handleMkcol(self: *CalDavSession, path: []const u8, config: *const CalDavConfig) !void {
        _ = config;
        const parsed = parsePath(path);

        if (parsed.path_type == .addressbook_collection) {
            const collection_name = parsed.collection orelse {
                try self.sendError(400, "Missing addressbook name");
                return;
            };
            const user_id = try self.getUserId();
            // Check for duplicate
            if (self.store.getAddressBookByName(user_id, collection_name) != null) {
                try self.sendError(405, "Address book already exists");
                return;
            }
            _ = self.store.createAddressBook(user_id, collection_name, null) catch {
                try self.sendError(500, "Internal Server Error");
                return;
            };
            try self.sendSuccess(201, "Created");
        } else if (parsed.path_type == .calendar_collection) {
            const collection_name = parsed.collection orelse {
                try self.sendError(400, "Missing calendar name");
                return;
            };
            const user_id = try self.getUserId();
            // Check for duplicate
            if (self.store.getCalendarByName(user_id, collection_name) != null) {
                try self.sendError(405, "Calendar already exists");
                return;
            }
            _ = self.store.createCalendar(user_id, collection_name, null) catch {
                try self.sendError(500, "Internal Server Error");
                return;
            };
            try self.sendSuccess(201, "Created");
        } else {
            try self.sendError(400, "Invalid MKCOL path");
        }
    }

    fn handleFreeBusy(self: *CalDavSession, parsed: ParsedPath, request: []const u8, body: []const u8) !void {
        const requester = self.username orelse return error.NotAuthenticated;
        const owner_path = parsed.user orelse return self.sendError(404, "Not Found");
        if (parsed.path_type == .calendar_resource and try self.ownsPath(owner_path)) return self.sendError(403, "Forbidden");
        if (parsed.path_type != .calendar_collection and parsed.path_type != .shared_calendar_collection) return self.sendError(404, "Not Found");
        const collection = parsed.collection orelse return self.sendError(404, "Not Found");
        if (body.len > 8192) return self.sendError(413, "Content Too Large");
        const window = free_busy.parse(body) catch return self.sendError(400, "Invalid free-busy report");
        const depth = requestHeader(request, "Depth") orelse "0";
        const include_members = !std.mem.eql(u8, depth, "0");
        if (include_members and !std.mem.eql(u8, depth, "1") and !std.mem.eql(u8, depth, "infinity"))
            return self.sendError(400, "Invalid Depth");
        var owner_buf: [2048]u8 = undefined;
        const owned_path = try self.ownsPath(owner_path);
        const target: DavCalendarTarget = if (parsed.path_type == .shared_calendar_collection) blk: {
            if (!owned_path) return self.sendError(404, "Not Found");
            break :blk .{ .shared = parseShareId(collection) orelse return self.sendError(404, "Not Found") };
        } else .{ .named = .{
            .owner = if (owned_path) requester else percentDecodeOnce(owner_path, &owner_buf) orelse return self.sendError(404, "Not Found"),
            .collection = collection,
        } };

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const periods = self.store.davCalendarBusyPeriods(a, requester, target, window, include_members) catch |err| switch (err) {
            error.CalendarNotFound, error.DavMailboxNotFound => return self.sendError(404, "Not Found"),
            error.InvalidRange => return self.sendError(400, "Invalid time range"),
            error.AvailabilityLimit => return self.sendError(413, "Availability calculation limit"),
            error.AvailabilityUnsupported, error.InvalidCalendar, error.UnsupportedTimezone => return self.sendError(422, "Availability incomplete"),
            else => return err,
        };
        const content = try free_busy.render(a, window, periods, currentTimestamp());
        var header: [256]u8 = undefined;
        try self.writeAll(try std.fmt.bufPrint(&header, "HTTP/1.1 200 OK\r\nContent-Type: text/calendar; charset=utf-8\r\n" ++
            "Cache-Control: no-store\r\nContent-Length: {d}\r\n\r\n", .{content.len}));
        try self.writeAll(content);
    }

    /// Handle REPORT request (calendar/contact queries)
    fn handleReport(
        self: *CalDavSession,
        path: []const u8,
        request: []const u8,
        config: *const CalDavConfig,
    ) !void {
        _ = config;

        const body = httpBody(request);
        var rest = body;
        const report = nextXmlOpen(&rest) orelse return self.sendError(400, "Missing report");
        const report_name = report.localName();
        if (std.mem.eql(u8, report_name, "calendar-query")) {
            try self.handleCalendarQuery(path, request);
        } else if (std.mem.eql(u8, report_name, "calendar-multiget")) {
            try self.handleMultiget(path, body, .event);
        } else if (std.mem.eql(u8, report_name, "addressbook-query")) {
            try self.handleAddressbookQuery(path, request);
        } else if (std.mem.eql(u8, report_name, "addressbook-multiget")) {
            try self.handleMultiget(path, body, .contact);
        } else if (std.mem.eql(u8, report_name, "sync-collection")) {
            try self.handleSyncCollection(path, request, rest);
        } else {
            try self.sendError(400, "Invalid report type");
        }
    }

    fn handleCalendarQuery(self: *CalDavSession, path: []const u8, request: []const u8) !void {
        const parsed = parsePath(path);
        const user_id = try self.getUserId();
        const collection = parsed.collection orelse "default";
        const owner = parsed.user orelse "user";
        var scratch = std.heap.ArenaAllocator.init(self.allocator);
        defer scratch.deinit();
        const a = scratch.allocator();
        const snapshot = self.store.snapshotOwnedDavQuery(a, user_id, collection) catch |err|
            return self.sendResourceError(err);
        return self.sendCalendarQuery(a, .{ .user = owner, .collection = collection }, httpBody(request), snapshot);
    }

    fn sendCalendarQuery(self: *CalDavSession, a: std.mem.Allocator, location: CalendarPath, body: []const u8, snapshot: caldav_store.CalDavStore.DavCalendarSnapshot) !void {
        const query = calendar_query.parse(a, body) catch |err| switch (err) {
            error.InvalidXml, error.InvalidFilter => return self.sendError(400, "Invalid CalDAV filter"),
            error.InvalidQueryTimezone => return self.sendError(400, "Invalid CalDAV timezone"),
            error.UnsupportedFilter => return self.sendCalDavReportError("403 Forbidden", "supported-filter"),
            else => return err,
        };
        var budget = recurrence.expansion_budget;
        var buf: std.ArrayList(u8) = .empty;
        try buf.appendSlice(a, dav_multistatus_start);
        for (snapshot.members) |member| {
            if (query.window) |window| {
                const matches = recurrence.overlaps(self.allocator, member.source, window, snapshot.timezone, query.timezone, &budget) catch |err| switch (err) {
                    error.AvailabilityLimit => return self.sendDavReportError("507 Insufficient Storage", "number-of-matches-within-limits"),
                    error.AvailabilityUnsupported, error.InvalidCalendar, error.UnsupportedTimezone => return self.sendError(422, "Calendar recurrence query incomplete"),
                    else => return err,
                };
                if (!matches) continue;
            }
            try buf.appendSlice(a, "  <D:response>\n");
            try appendResourceHref(&buf, a, location.base(), location.user, location.collection, member.uid, ".ics");
            try appendMultigetProperties(&buf, a, "C:calendar-data", member.etag, member.source.icalendar);
        }
        try buf.appendSlice(a, "</D:multistatus>");
        return self.sendMultistatusResponse(buf.items);
    }

    const XmlOpen = struct {
        name: []const u8,
        empty: bool,

        fn localName(self: XmlOpen) []const u8 {
            return if (std.mem.lastIndexOfScalar(u8, self.name, ':')) |colon| self.name[colon + 1 ..] else self.name;
        }
    };

    fn nextXmlOpen(body: *[]const u8) ?XmlOpen {
        while (std.mem.indexOfScalar(u8, body.*, '<')) |start| {
            const tail = body.*[start + 1 ..];
            if (std.mem.startsWith(u8, tail, "!--")) {
                const end = std.mem.indexOf(u8, tail[3..], "-->") orelse return null;
                body.* = tail[3 + end + 3 ..];
                continue;
            }
            if (std.mem.startsWith(u8, tail, "?")) {
                const end = std.mem.indexOf(u8, tail, "?>") orelse return null;
                body.* = tail[end + 2 ..];
                continue;
            }
            const end = std.mem.indexOfScalar(u8, tail, '>') orelse return null;
            const tag = std.mem.trimEnd(u8, tail[0..end], " \t\r\n");
            body.* = tail[end + 1 ..];
            if (tag.len == 0 or tag[0] == '/' or tag[0] == '!') continue;
            const name_end = std.mem.indexOfAny(u8, tag, " \t\r\n/") orelse tag.len;
            if (name_end == 0) continue;
            return .{ .name = tag[0..name_end], .empty = tag[tag.len - 1] == '/' };
        }
        return null;
    }

    /// Read a leaf element with either a prefixed or default namespace.
    fn nextXmlText(body: *[]const u8, name: []const u8) ?[]const u8 {
        while (nextXmlOpen(body)) |tag| {
            if (!std.mem.eql(u8, tag.localName(), name)) continue;
            if (tag.empty) return "";
            const close = std.mem.indexOfScalar(u8, body.*, '<') orelse return null;
            const value = std.mem.trim(u8, body.*[0..close], " \t\r\n");
            body.* = body.*[close..];
            const close_end = std.mem.indexOfScalar(u8, body.*, '>') orelse return null;
            const closing = std.mem.trimEnd(u8, body.*[0..close_end], " \t\r\n");
            if (!std.mem.startsWith(u8, closing, "</") or !std.mem.eql(u8, closing[2..], tag.name)) return null;
            body.* = body.*[close_end + 1 ..];
            return value;
        }
        return null;
    }

    fn appendMultigetProperties(buf: *std.ArrayList(u8), a: std.mem.Allocator, payload_tag: []const u8, etag: ?[]const u8, body: []const u8) !void {
        if (etag) |version| {
            try buf.appendSlice(a, "    <D:propstat><D:prop>\n");
            try appendXmlEscaped(buf, a, "      <D:getetag>", version, "</D:getetag>\n");
            if (body.len != 0) {
                try appendPrint(buf, a, "      <{s}>", .{payload_tag});
                try appendXmlEscaped(buf, a, "", body, "");
                try appendPrint(buf, a, "</{s}>\n", .{payload_tag});
            }
            try buf.appendSlice(a, "    </D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>\n");
        } else {
            try buf.appendSlice(a, "    <D:status>HTTP/1.1 404 Not Found</D:status>\n");
        }
        try buf.appendSlice(a, "  </D:response>\n");
    }

    fn handleMultiget(self: *CalDavSession, path: []const u8, body: []const u8, kind: caldav_store.SyncChange.ResourceType) !void {
        const parsed = parsePath(path);
        const collection = parsed.collection orelse return self.sendError(404, "Not Found");
        const user_id = try self.getUserId();
        const payload_tag: []const u8 = if (kind == .event) "C:calendar-data" else "CARD:address-data";
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.allocator);
        try buf.appendSlice(self.allocator, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        try buf.appendSlice(self.allocator, "<D:multistatus xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\" xmlns:CARD=\"urn:ietf:params:xml:ns:carddav\">\n");

        var remaining = body;
        while (nextXmlText(&remaining, "href")) |href| {
            // These hrefs must be resources in the selected, authenticated collection.
            const item = parsePath(href);
            const item_collection = item.collection orelse continue;
            const uid = item.resource_uid orelse continue;
            const owner = item.user orelse continue;
            if (resourceKind(item.path_type) != kind or !std.mem.eql(u8, item_collection, collection) or
                !try self.ownsPath(owner)) continue;
            const resource = try self.store.getResource(user_id, collection, uid, kind);
            try buf.appendSlice(self.allocator, "  <D:response>\n");
            try appendHrefEscaped(&buf, self.allocator, href);
            if (resource) |version| {
                defer self.store.allocator.free(version.body);
                defer self.store.allocator.free(version.etag);
                try appendMultigetProperties(&buf, self.allocator, payload_tag, version.etag, version.body);
            } else {
                try appendMultigetProperties(&buf, self.allocator, payload_tag, null, "");
            }
        }
        try buf.appendSlice(self.allocator, "</D:multistatus>");
        try self.sendMultistatusResponse(buf.items);
    }

    /// Handle addressbook-query REPORT
    fn handleAddressbookQuery(self: *CalDavSession, path: []const u8, request: []const u8) !void {
        _ = request;
        const parsed = parsePath(path);
        const user_id = try self.getUserId();

        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.allocator);

        try buf.appendSlice(self.allocator, "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n");
        try buf.appendSlice(self.allocator, "<D:multistatus xmlns:D=\"DAV:\" xmlns:CARD=\"urn:ietf:params:xml:ns:carddav\">\n");

        const collection_name = parsed.collection orelse "default";
        const username = parsed.user orelse "user";

        const addressbooks = self.store.getUserAddressBooks(user_id) catch &[_]caldav_store.AddressBook{};
        for (addressbooks) |ab| {
            if (std.mem.eql(u8, ab.name, collection_name)) {
                const contacts = self.store.getAddressBookContacts(ab.id) catch &[_]caldav_store.Contact{};
                for (contacts) |contact| {
                    try buf.appendSlice(self.allocator, "  <D:response>\n");
                    try appendResourceHref(&buf, self.allocator, "/addressbooks/", username, collection_name, contact.uid, ".vcf");
                    try buf.appendSlice(self.allocator, "    <D:propstat>\n");
                    try buf.appendSlice(self.allocator, "      <D:prop>\n");
                    try appendXmlEscaped(&buf, self.allocator, "        <D:getetag>", contact.etag, "</D:getetag>\n");
                    const gen_vcf: ?[]u8 = if (contact.vcf_data.len == 0) (self.store.generateVcf(contact) catch null) else null;
                    defer if (gen_vcf) |g| self.allocator.free(g);
                    const vcf: []const u8 = gen_vcf orelse contact.vcf_data;
                    if (vcf.len > 0) {
                        try appendXmlEscaped(&buf, self.allocator, "        <CARD:address-data>", vcf, "</CARD:address-data>\n");
                    }
                    try buf.appendSlice(self.allocator, "      </D:prop>\n");
                    try buf.appendSlice(self.allocator, "      <D:status>HTTP/1.1 200 OK</D:status>\n");
                    try buf.appendSlice(self.allocator, "    </D:propstat>\n");
                    try buf.appendSlice(self.allocator, "  </D:response>\n");
                }
                break;
            }
        }
        try buf.appendSlice(self.allocator, "</D:multistatus>");
        try self.sendMultistatusResponse(buf.items);
    }

    const SyncOptions = struct { query: caldav_store.DavSyncQuery, limit: usize };

    fn readSyncOptions(request: []const u8, body: []const u8) !SyncOptions {
        const depth = requestHeader(request, "Depth") orelse "0";
        if (!std.mem.eql(u8, depth, "0")) return error.InvalidDepth;
        var rest = body;
        const token = nextXmlText(&rest, "sync-token") orelse return error.MissingSyncToken;
        const level = nextXmlText(&rest, "sync-level") orelse return error.MissingSyncLevel;
        if (!std.mem.eql(u8, level, "1") and !std.mem.eql(u8, level, "infinite")) return error.InvalidSyncLevel;
        return .{
            .query = if (token.len == 0) .initial else .{ .after = token },
            .limit = if (nextXmlText(&rest, "nresults")) |count|
                std.fmt.parseInt(usize, count, 10) catch return error.InvalidSyncLimit
            else
                std.math.maxInt(usize),
        };
    }

    fn sendSyncOptionsError(self: *CalDavSession, err: anyerror) !void {
        const reason = switch (err) {
            error.InvalidDepth => "Sync REPORT requires Depth: 0",
            error.MissingSyncToken => "Missing sync-token",
            error.MissingSyncLevel => "Missing sync-level",
            error.InvalidSyncLevel => "Invalid sync-level",
            error.InvalidSyncLimit => "Invalid sync result limit",
            else => return err,
        };
        return self.sendError(400, reason);
    }

    /// Handle sync-collection REPORT on flat calendar and address book collections.
    fn handleSyncCollection(self: *CalDavSession, path: []const u8, request: []const u8, body: []const u8) !void {
        if (!self.store.config.enable_sync_tokens) return self.sendError(501, "Not Implemented");
        const parsed = parsePath(path);
        const kind: caldav_store.SyncChange.ResourceType = switch (parsed.path_type) {
            .calendar_collection => .event,
            .addressbook_collection => .contact,
            else => return self.sendError(404, "Not Found"),
        };
        const user = parsed.user orelse return self.sendError(404, "Not Found");
        const collection = parsed.collection orelse return self.sendError(404, "Not Found");
        const user_id = try self.getUserId();
        const options = readSyncOptions(request, body) catch |err| return self.sendSyncOptionsError(err);
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const report = self.store.snapshotDavSync(a, user_id, collection, kind, options.query) catch |err| switch (err) {
            error.InvalidSyncToken => return self.sendDavReportError("403 Forbidden", "valid-sync-token"),
            error.NotFound => return self.sendError(404, "Not Found"),
            else => return err,
        };
        return self.sendSyncResponse(a, user, collection, kind, if (kind == .event) "/calendars/" else "/addressbooks/", report, options.limit);
    }

    fn handleSharedDavSync(self: *CalDavSession, a: std.mem.Allocator, username: []const u8, location: CalendarPath, target: DavCalendarTarget, request: []const u8, body: []const u8) !void {
        const options = readSyncOptions(request, body) catch |err| return self.sendSyncOptionsError(err);
        const snapshot = self.store.snapshotSharedDavSync(a, username, target, options.query) catch |err| switch (err) {
            error.InvalidSyncToken => return self.sendDavReportError("403 Forbidden", "valid-sync-token"),
            error.CalendarExportTooLarge => return self.sendDavReportError("507 Insufficient Storage", "number-of-matches-within-limits"),
            else => return self.sendResourceError(err),
        };
        return self.sendSyncResponse(a, location.user, location.collection, .event, location.base(), snapshot.report, options.limit);
    }

    fn sendSyncResponse(self: *CalDavSession, a: std.mem.Allocator, user: []const u8, collection: []const u8, kind: caldav_store.SyncChange.ResourceType, base: []const u8, report: caldav_store.DavSyncReport, limit: usize) !void {
        if (report.members.len > limit) return self.sendDavReportError("507 Insufficient Storage", "number-of-matches-within-limits");
        var buf: std.ArrayList(u8) = .empty;
        try buf.appendSlice(a, dav_multistatus_start);
        for (report.members) |member| try appendDavMemberAt(&buf, a, user, collection, kind, base, member);
        try appendXmlEscaped(&buf, a, "  <D:sync-token>", report.token, "</D:sync-token>\n");
        try buf.appendSlice(a, "</D:multistatus>");
        try self.sendMultistatusResponse(buf.items);
    }

    fn sendDavReportError(self: *CalDavSession, status: []const u8, condition: []const u8) !void {
        var buf: [128]u8 = undefined;
        return self.sendReportError(status, try std.fmt.bufPrint(&buf, "<D:error xmlns:D=\"DAV:\"><D:{s}/></D:error>", .{condition}));
    }

    fn sendCalDavReportError(self: *CalDavSession, status: []const u8, condition: []const u8) !void {
        var buf: [192]u8 = undefined;
        return self.sendReportError(status, try std.fmt.bufPrint(&buf, "<D:error xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\"><C:{s}/></D:error>", .{condition}));
    }

    fn sendReportError(self: *CalDavSession, status: []const u8, body: []const u8) !void {
        var header_buf: [192]u8 = undefined;
        const header = try std.fmt.bufPrint(&header_buf, "HTTP/1.1 {s}\r\nContent-Type: application/xml; charset=utf-8\r\nContent-Length: {d}\r\n\r\n", .{ status, body.len });
        try self.writeAll(header);
        try self.writeAll(body);
    }

    /// Send a 207 Multi-Status response with the given body
    fn sendMultistatusResponse(self: *CalDavSession, body: []const u8) !void {
        var header_buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&header_buf);
        const writer = fbs.writer();
        try writer.print(
            "HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: {d}\r\n\r\n",
            .{body.len},
        );
        try self.writeAll(fbs.getWritten());
        try self.writeAll(body);
    }

    /// Send authentication required response with Digest challenge
    fn sendAuthRequired(self: *CalDavSession, stale: bool) !void {
        const nonce = self.auth_backend.generateNonce() catch {
            // Fallback to Basic auth if nonce generation fails
            const response =
                "HTTP/1.1 401 Unauthorized\r\n" ++
                "WWW-Authenticate: Basic realm=\"CalDAV/CardDAV Server\"\r\n" ++
                "Content-Length: 0\r\n\r\n";
            try self.writeAll(response);
            return;
        };
        // Note: Don't free nonce here - it's owned by the NonceManager and will be freed when invalidated

        var buf: [512]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        try writer.print(
            "HTTP/1.1 401 Unauthorized\r\n" ++
                "WWW-Authenticate: Digest realm=\"CalDAV/CardDAV Server\", nonce=\"{s}\", qop=\"auth\", algorithm=SHA-256{s}\r\n" ++
                "WWW-Authenticate: Basic realm=\"CalDAV/CardDAV Server\"\r\n" ++
                "Content-Length: 0\r\n\r\n",
            .{ nonce, if (stale) ", stale=true" else "" },
        );
        try self.writeAll(fbs.getWritten());
    }

    /// Send error response
    fn sendError(self: *CalDavSession, code: u16, message: []const u8) !void {
        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        try writer.print("HTTP/1.1 {d} {s}\r\nContent-Length: 0\r\n\r\n", .{ code, message });
        try self.writeAll(fbs.getWritten());
    }

    /// Send success response
    fn sendSuccess(self: *CalDavSession, code: u16, message: []const u8) !void {
        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        const length = if (code == 204) "" else "Content-Length: 0\r\n";
        try writer.print("HTTP/1.1 {d} {s}\r\n{s}\r\n", .{ code, message, length });
        try self.writeAll(fbs.getWritten());
    }

    /// Write all bytes to the plain socket (connection.write may be partial).
    fn writeAll(self: *CalDavSession, data: []const u8) !void {
        if (self.tls_conn) |connection| return self.writeTls(connection, data);
        var off: usize = 0;
        while (off < data.len) {
            const n = try self.connection.write(data[off..]);
            if (n == 0) return error.WriteFailed;
            off += n;
        }
    }

    fn writeTls(self: *CalDavSession, connection: *tls.nonblock.Connection, data: []const u8) !void {
        // A single TLS record carries at most ~16 KiB of cleartext. Chunk larger
        // payloads (e.g. an EWS mailbox listing) so each encrypt() call fits one
        // record — encrypting the whole thing at once overflows the record and
        // fails (previously surfaced as error.WriteFailed with a 0-byte body).
        const max_chunk: usize = 15000;
        var pos: usize = 0;
        while (pos < data.len) {
            const end = @min(pos + max_chunk, data.len);
            var send_buf: [tls.output_buffer_len]u8 = undefined;
            const enc_result = try connection.encrypt(data[pos..end], &send_buf);
            var sent: usize = 0;
            while (sent < enc_result.ciphertext.len) {
                const n = try self.connection.write(enc_result.ciphertext[sent..]);
                if (n == 0) return error.ConnectionClosed;
                sent += n;
            }
            pos = end;
        }
    }

    /// Send an Exchange or mobile-profile response on the current transport.
    fn sendWeb(self: *CalDavSession, wr: WebResponse) !void {
        var hdr: [384]u8 = undefined;
        const header = if (wr.disposition) |d|
            try std.fmt.bufPrint(&hdr, "HTTP/1.1 {d} OK\r\nContent-Type: {s}\r\nContent-Disposition: {s}\r\nContent-Length: {d}\r\nConnection: keep-alive\r\n\r\n", .{ wr.status, wr.content_type, d, wr.body.len })
        else
            try std.fmt.bufPrint(&hdr, "HTTP/1.1 {d} OK\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: keep-alive\r\n\r\n", .{ wr.status, wr.content_type, wr.body.len });
        try self.writeAll(header);
        if (wr.body.len > 0) try self.writeAll(wr.body);
    }
};

// ============================================================================
// Transport-agnostic web handlers (EWS / autodiscover / EAS / mobileconfig).
// These return a body owned by `allocator` so the SAME logic can be served
// either by the mail server's own TLS server (443) OR over plain HTTP by the
// CalDavSession behind a TLS-terminating reverse proxy (rpx on the shared box).
// ============================================================================

const WebResponse = struct {
    status: u16 = 200,
    content_type: []const u8 = "application/xml; charset=utf-8",
    body: []const u8 = "",
    disposition: ?[]const u8 = null,
};

/// The HTTP body (after the blank line) of a raw request.
fn httpBody(request: []const u8) []const u8 {
    return if (std.mem.indexOf(u8, request, "\r\n\r\n")) |i| request[i + 4 ..] else "";
}

/// EWS SOAP → response (body owned by allocator).
fn webEws(allocator: std.mem.Allocator, config: *const CalDavConfig, username: ?[]const u8, store: *caldav_store.CalDavStore, db: *database.Database, request: []const u8) !WebResponse {
    const user = username orelse return error.Unauthenticated;
    const managed = (try db.hostedLimits(user)) != null;
    var ctx = ews.Context{
        .allocator = allocator,
        .username = user,
        .local_part = user,
        .hosted = managed,
        .hostname = config.public_hostname,
        .db = db,
        .store = store,
        .delivery_method = config.delivery_method,
        .ses_region = config.ses_region,
        .scanner = config.scanner,
        .draft_service = config.draft_service,
        .mail_config = config.mail_config,
    };
    const resp = try ews.handleSoap(&ctx, httpBody(request));
    return .{ .status = resp.status, .content_type = resp.content_type, .body = resp.body };
}

/// Exchange ActiveSync dispatch shared by HTTP and HTTPS.
fn webActiveSync(allocator: std.mem.Allocator, config: *const CalDavConfig, db: *database.Database, store: *caldav_store.CalDavStore, username: ?[]const u8, path: []const u8, request: []const u8) !WebResponse {
    const user = username orelse return .{ .status = 401 };
    const query_start = std.mem.indexOfScalar(u8, path, '?') orelse return .{ .status = 400 };
    const query = path[query_start + 1 ..];
    var binary_query: [1024]u8 = undefined;
    var folder_buffer: [256]u8 = undefined;
    var item_buffer: [256]u8 = undefined;
    var long_id_buffer: [1024]u8 = undefined;
    const params = if (autoconfig.extractQueryParam(query, "Cmd")) |cmd| ActiveSyncQuery{
        .cmd = cmd,
        .device_id = autoconfig.extractQueryParam(query, "DeviceId") orelse "",
        .version = easVersion(requestHeader(request, "MS-ASProtocolVersion")),
        .save_legacy_copy = std.ascii.eqlIgnoreCase(autoconfig.extractQueryParam(query, "SaveInSent") orelse "", "T"),
        .source = .{
            .folder_id = if (autoconfig.extractQueryParam(query, "CollectionId")) |id|
                (percentDecodeOnce(id, &folder_buffer) orelse return .{ .status = 400 })
            else
                null,
            .item_id = if (autoconfig.extractQueryParam(query, "ItemId")) |id|
                (percentDecodeOnce(id, &item_buffer) orelse return .{ .status = 400 })
            else
                null,
            .long_id = if (autoconfig.extractQueryParam(query, "LongId")) |id|
                (percentDecodeOnce(id, &long_id_buffer) orelse return .{ .status = 400 })
            else
                null,
            .instance_id = autoconfig.extractQueryParam(query, "Occurrence"),
        },
    } else decodeActiveSyncQuery(query, &binary_query) catch |err|
        return .{ .status = if (err == error.UnsupportedCommand) 501 else 400 };
    const managed = (try db.hostedLimits(user)) != null;
    const content_type = requestHeader(request, "Content-Type") orelse "";
    const semi = std.mem.indexOfScalar(u8, content_type, ';') orelse content_type.len;
    const mime = std.ascii.eqlIgnoreCase(std.mem.trim(u8, content_type[0..semi], " \t"), "message/rfc822");
    var ctx = eas.Context{
        .allocator = allocator,
        .db = db,
        .store = store,
        .username = user,
        .local_part = user,
        .device_id = params.device_id,
        .protocol_version = params.version,
        .hosted = managed,
        .mail_config = config.mail_config,
        .scanner = config.scanner,
        .send_format = switch (params.version) {
            25, 120, 121 => if (mime) .mime else .invalid,
            140, 141 => if (mime) .invalid else .wbxml,
            else => .invalid,
        },
        .save_legacy_copy = params.save_legacy_copy,
        .legacy_source = params.source,
        .legacy_forward_attachment = params.version == 25,
    };
    const resp = try eas.dispatch(&ctx, params.cmd, httpBody(request));
    return .{ .status = resp.status, .content_type = resp.content_type, .body = resp.body };
}

const ActiveSyncQuery = struct {
    cmd: []const u8,
    device_id: []const u8,
    version: u8,
    save_legacy_copy: bool = false,
    source: eas.MessageSource = .{},
};

fn requestHeader(request: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, request, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(name, line[0..colon])) return std.mem.trim(u8, line[colon + 1 ..], " \t");
    }
    return null;
}

fn easVersion(header: ?[]const u8) u8 {
    const value = header orelse return 141;
    const versions = [_][]const u8{ "2.5", "12.0", "12.1", "14.0", "14.1" };
    for (versions, [_]u8{ 25, 120, 121, 140, 141 }) |name, version| {
        if (std.mem.eql(u8, value, name)) return version;
    }
    return 0;
}

fn readQueryField(rest: *[]const u8) ![]const u8 {
    if (rest.len == 0) return error.InvalidQuery;
    const length = rest.*[0];
    if (rest.len - 1 < length) return error.InvalidQuery;
    const field = rest.*[1 .. 1 + @as(usize, length)];
    rest.* = rest.*[1 + @as(usize, length) ..];
    return field;
}

/// MS-ASHTTP base64 query layout. Client-supplied User is never an identity.
fn decodeActiveSyncQuery(query: []const u8, buffer: []u8) !ActiveSyncQuery {
    var uri_buffer: [2048]u8 = undefined;
    const encoded = percentDecodeOnce(query, &uri_buffer) orelse return error.InvalidQuery;
    const decoder = std.base64.standard.Decoder;
    const size = try decoder.calcSizeForSlice(encoded);
    if (size < 7 or size > buffer.len) return error.InvalidQuery;
    try decoder.decode(buffer[0..size], encoded);
    const version = buffer[0];
    const cmd: []const u8 = switch (buffer[1]) {
        0 => "Sync",
        1 => "SendMail",
        2 => "SmartForward",
        3 => "SmartReply",
        9 => "FolderSync",
        10 => "FolderCreate",
        11 => "FolderDelete",
        12 => "FolderUpdate",
        13 => "MoveItems",
        14 => "GetItemEstimate",
        16 => "Search",
        18 => "Ping",
        20 => "Provision",
        else => return error.UnsupportedCommand,
    };
    var rest: []const u8 = buffer[4..size];
    const device_id = try readQueryField(&rest);
    const policy_key = try readQueryField(&rest);
    if (policy_key.len != 0 and policy_key.len != 4) return error.InvalidQuery;
    _ = try readQueryField(&rest); // device type
    var save_copy = false;
    var source: eas.MessageSource = .{};
    while (rest.len != 0) {
        const tag = rest[0];
        rest = rest[1..];
        const value = try readQueryField(&rest);
        if (tag == 7 and buffer[1] >= 1 and buffer[1] <= 3) {
            if (value.len != 1) return error.InvalidQuery;
            save_copy = value[0] & 1 != 0;
        } else if (buffer[1] == 2 or buffer[1] == 3) {
            const field = switch (tag) {
                1 => &source.folder_id,
                3 => &source.item_id,
                4 => &source.long_id,
                6 => &source.instance_id,
                else => continue,
            };
            if (field.* != null) return error.InvalidQuery;
            field.* = value;
        }
    }
    return .{ .cmd = cmd, .device_id = device_id, .version = version, .save_legacy_copy = save_copy, .source = source };
}

/// Autodiscover v1 XML (Outlook/EXCH for macOS, MobileSync for iOS).
fn webAutodiscover(allocator: std.mem.Allocator, config: *const CalDavConfig, username: ?[]const u8, request: []const u8) !WebResponse {
    const user = username orelse "user";
    const wants_mobilesync = std.mem.indexOf(u8, httpBody(request), "mobilesync") != null;
    const xml = if (wants_mobilesync)
        try ews.autodiscover.buildMobileSyncXml(allocator, user, config.public_hostname)
    else
        try ews.autodiscover.buildOutlookExchXml(allocator, user, config.public_hostname);
    return .{ .content_type = "application/xml; charset=utf-8", .body = xml };
}

/// Autodiscover v2 JSON (EWS endpoint URL).
fn webAutodiscoverV2(allocator: std.mem.Allocator, config: *const CalDavConfig, path: []const u8) !WebResponse {
    const protocol = ews.autodiscover.protocolParam(path);
    const url = try ews.autodiscover.urlForProtocol(allocator, config.public_hostname, protocol);
    defer allocator.free(url);
    const json = try ews.autodiscover.buildJson(allocator, protocol, url);
    return .{ .content_type = "application/json; charset=utf-8", .body = json };
}

// Monotonic sequence so two profile downloads in the same nanosecond still get
// distinct nonces.
var mobileconfig_nonce_seq = std.atomic.Value(u64).init(0);

/// Build a per-download nonce (hex of the current time + a sequence counter)
/// into `buf` and return the slice. Folded into the .mobileconfig payload
/// UUIDs/identifiers so each download is unique and reinstalls never hit
/// Apple's "This account already exists" dead-end. Alphanumeric/hex only, so it
/// is safe inside reverse-DNS PayloadIdentifiers.
fn nextProfileNonce(buf: []u8) []const u8 {
    const seq = mobileconfig_nonce_seq.fetchAdd(1, .monotonic);
    const ts: u64 = @bitCast(@as(i64, @truncate(time_compat.nanoTimestamp())));
    return std.fmt.bufPrint(buf, "{x}{x}", .{ ts, seq }) catch "0";
}

/// Apple .mobileconfig profile (Mail+CalDAV+CardDAV, or ?services=eas/dav).
fn webMobileconfig(allocator: std.mem.Allocator, config: *const CalDavConfig, path: []const u8) !WebResponse {
    const query: ?[]const u8 = if (std.mem.indexOfScalar(u8, path, '?')) |q| path[q + 1 ..] else null;
    const encoded_email = autoconfig.extractQueryParam(query, "email") orelse return error.MissingEmail;
    var email_buffer: [254]u8 = undefined;
    const email = percentDecodeOnce(encoded_email, &email_buffer) orelse return error.InvalidEmail;
    if (!security.validateEmailAddress(email)) return error.InvalidEmail;
    const escaped_email = try xmlEscape(allocator, email);
    defer allocator.free(escaped_email);
    const services = autoconfig.extractQueryParam(query, "services");
    const dav_only = services != null and std.mem.eql(u8, services.?, "dav");
    const eas_only = services != null and std.mem.eql(u8, services.?, "eas");
    const domain = autoconfig.extractDomainFromEmail(email) orelse "localhost";
    var nonce_buf: [40]u8 = undefined;
    const ac = autoconfig.AutoconfigConfig{
        .hostname = config.public_hostname,
        .domain = domain,
        .imaps_port = config.imaps_port,
        .smtp_port = config.submission_port,
        .display_name = config.display_name,
        .enable_email = !dav_only and !eas_only,
        .enable_carddav = config.enable_carddav and !eas_only,
        .enable_caldav_profile = config.enable_caldav and !eas_only,
        .enable_eas = eas_only,
        .caldav_hostname = config.public_hostname,
        .caldav_port = config.public_dav_port,
        .profile_nonce = nextProfileNonce(&nonce_buf),
    };
    const profile = try autoconfig.generateAppleMobileconfig(allocator, ac, escaped_email);
    return .{ .content_type = "application/x-apple-aspen-config; charset=utf-8", .body = profile, .disposition = "attachment; filename=\"mail.mobileconfig\"" };
}

/// ActiveSync OPTIONS capability response (constant, unauthenticated).
const ACTIVESYNC_OPTIONS_RESPONSE =
    "HTTP/1.1 200 OK\r\n" ++
    "MS-Server-ActiveSync: 14.1\r\n" ++
    "MS-ASProtocolVersions: 2.5,12.0,12.1,14.0,14.1\r\n" ++
    "MS-ASProtocolCommands: Sync,SendMail,SmartForward,SmartReply,FolderSync,FolderCreate,FolderDelete,FolderUpdate,MoveItems,GetItemEstimate,Ping,Provision,Search\r\n" ++
    "Public: OPTIONS,POST\r\n" ++
    "Allow: OPTIONS,POST\r\n" ++
    "Content-Length: 0\r\n\r\n";

// ============================================================================
// CalDAV/CardDAV Server
// ============================================================================

// Process-wide cap on concurrent CalDAV/CardDAV connections so a burst (or a
// client holding many keep-alive sockets) cannot spawn unbounded threads.
var caldav_active_conns = std.atomic.Value(u32).init(0);
const max_caldav_conns: u32 = 128;

/// Per-connection thread context + entry point. Each accepted connection is
/// handled on its own detached thread so one slow/keep-alive client can never
/// block others (the old code handled connections serially in the accept loop).
const CalDavConnContext = struct {
    server: *CalDavServer,
    connection: socket.Connection,
    is_ssl: bool,
};

fn calDavConnectionThread(ctx: CalDavConnContext) void {
    defer _ = caldav_active_conns.fetchSub(1, .monotonic);
    ctx.server.handleConnection(ctx.connection, ctx.is_ssl) catch |err| {
        logger.err("CalDAV connection error: {}", .{err});
    };
}

pub const CalDavServer = struct {
    allocator: std.mem.Allocator,
    config: CalDavConfig,
    listener: ?socket.Server = null,
    ssl_listener: ?socket.Server = null,
    running: std.atomic.Value(bool),
    auth_backend: *auth.AuthBackend,
    store: *caldav_store.CalDavStore,
    cert_key_pair: ?tls.config.CertKeyPair = null,

    pub fn init(allocator: std.mem.Allocator, config: CalDavConfig, auth_backend: *auth.AuthBackend, store: *caldav_store.CalDavStore) CalDavServer {
        var server = CalDavServer{
            .allocator = allocator,
            .config = config,
            .running = std.atomic.Value(bool).init(false),
            .auth_backend = auth_backend,
            .store = store,
        };

        // Load TLS certificate if configured
        if (config.enable_ssl and config.cert_path != null and config.key_path != null) {
            server.cert_key_pair = tls.config.CertKeyPair.fromFilePathAbsolute(
                allocator,
                io_compat.getIo(),
                config.cert_path.?,
                config.key_path.?,
            ) catch |err| {
                logger.err("Failed to load TLS certificate for CalDAV: {}", .{err});
                return server;
            };
            logger.info("Loaded TLS certificate for CalDAV", .{});
        }

        return server;
    }

    pub fn deinit(self: *CalDavServer) void {
        self.stop();
        if (self.cert_key_pair) |*ckp| {
            ckp.deinit(self.allocator);
        }
    }

    /// Start the CalDAV/CardDAV server
    pub fn start(self: *CalDavServer) !void {
        const address = try socket.Address.parseIp(self.config.bind_host, self.config.port);
        self.listener = try socket.Server.listen(address, .{
            .reuse_address = true,
        });
        try self.listener.?.setNonBlocking(true);

        self.running.store(true, .monotonic);

        logger.info("CalDAV/CardDAV server listening on port {d}", .{self.config.port});

        // Also start CalDAVS (SSL) if enabled and certs are configured
        if (self.config.enable_ssl and self.config.cert_path != null and self.config.key_path != null) {
            _ = std.Thread.spawn(.{}, startSslListener, .{self}) catch |err| {
                logger.warn("Failed to start CalDAV SSL listener: {} (CalDAV on port {d} still available)", .{ err, self.config.port });
            };
        }

        while (self.running.load(.monotonic)) {
            const connection = self.listener.?.accept() catch |err| {
                if (!self.running.load(.monotonic)) break;
                if (err == error.OperationCancelled or err == error.WouldBlock) {
                    self.listener.?.waitReadable(1000);
                    continue;
                }
                logger.warn("CalDAV accept error: {}", .{err});
                time_compat.sleepMs(500);
                continue;
            };

            // Dispatch on a detached thread so connections are handled
            // concurrently (defer in handleConnection closes the connection).
            if (caldav_active_conns.fetchAdd(1, .monotonic) >= max_caldav_conns) {
                _ = caldav_active_conns.fetchSub(1, .monotonic);
                logger.warn("CalDAV: connection cap reached, rejecting", .{});
                connection.close();
                continue;
            }
            const ctx = CalDavConnContext{ .server = self, .connection = connection, .is_ssl = false };
            const t = std.Thread.spawn(.{}, calDavConnectionThread, .{ctx}) catch |err| {
                logger.err("CalDAV: failed to spawn handler: {}", .{err});
                _ = caldav_active_conns.fetchSub(1, .monotonic);
                connection.close();
                continue;
            };
            t.detach();
        }
    }

    /// Start the SSL listener (runs in separate thread)
    fn startSslListener(self: *CalDavServer) void {
        const ssl_address = socket.Address.parseIp(self.config.bind_host, self.config.ssl_port) catch |err| {
            logger.err("Failed to parse CalDAV SSL address: {}", .{err});
            return;
        };

        self.ssl_listener = socket.Server.listen(ssl_address, .{
            .reuse_address = true,
        }) catch |err| {
            logger.err("Failed to start CalDAV SSL listener: {}", .{err});
            return;
        };
        self.ssl_listener.?.setNonBlocking(true) catch |err| {
            logger.err("Failed to set CalDAV SSL listener nonblocking: {}", .{err});
            return;
        };

        logger.info("CalDAV SSL server listening on port {d} (HTTPS)", .{self.config.ssl_port});

        while (self.running.load(.monotonic)) {
            const connection = self.ssl_listener.?.accept() catch |err| {
                if (!self.running.load(.monotonic)) break;
                if (err == error.OperationCancelled or err == error.WouldBlock) {
                    self.ssl_listener.?.waitReadable(1000);
                    continue;
                }
                logger.warn("CalDAV SSL accept error: {}", .{err});
                time_compat.sleepMs(500);
                continue;
            };

            // Dispatch on a detached thread (defer in handleConnection closes it).
            if (caldav_active_conns.fetchAdd(1, .monotonic) >= max_caldav_conns) {
                _ = caldav_active_conns.fetchSub(1, .monotonic);
                logger.warn("CalDAV SSL: connection cap reached, rejecting", .{});
                connection.close();
                continue;
            }
            const ctx = CalDavConnContext{ .server = self, .connection = connection, .is_ssl = true };
            const t = std.Thread.spawn(.{}, calDavConnectionThread, .{ctx}) catch |err| {
                logger.debug("CalDAV SSL: failed to spawn handler: {}", .{err});
                _ = caldav_active_conns.fetchSub(1, .monotonic);
                connection.close();
                continue;
            };
            t.detach();
        }
    }

    /// Stop the server
    pub fn stop(self: *CalDavServer) void {
        self.running.store(false, .monotonic);
        if (self.listener) |*listener| {
            listener.close();
            self.listener = null;
        }
        if (self.ssl_listener) |*ssl_listener| {
            ssl_listener.close();
            self.ssl_listener = null;
        }
    }

    /// Handle client connection
    fn handleConnection(self: *CalDavServer, connection: socket.Connection, is_ssl: bool) !void {
        connection.setBlocking();
        // Bound how long a (TLS handshake or request) read can block, so an idle
        // keep-alive or stuck client eventually releases this connection's thread
        // instead of pinning it forever.
        const rcv_tv: std.posix.timeval = .{ .sec = 120, .usec = 0 };
        std.posix.setsockopt(connection.fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&rcv_tv)) catch {};

        var session = CalDavSession.init(self.allocator, connection, self.auth_backend, self.store);
        defer {
            session.deinit();
            connection.close();
        }

        // For SSL connections, perform TLS handshake first
        var tls_cipher: ?tls.Cipher = null;

        if (is_ssl) {
            if (self.cert_key_pair == null) {
                logger.err("CalDAV SSL connection attempted but no certificate loaded", .{});
                return error.TlsNotConfigured;
            }

            logger.info("Starting TLS handshake for CalDAV connection", .{});

            var tls_server = tls.nonblock.Server.init(.{
                .auth = &self.cert_key_pair.?,
            });

            var recv_buf: [tls.input_buffer_len]u8 = undefined;
            var send_buf: [tls.output_buffer_len]u8 = undefined;
            var recv_len: usize = 0;
            var first_read = true;

            while (!tls_server.done()) {
                // Log raw data before processing (for debugging Mail.app issues)
                if (first_read and recv_len > 0) {
                    logger.debug("CalDAV TLS: first {d} bytes received, record type: {d}", .{ recv_len, recv_buf[0] });
                    if (recv_len >= 5) {
                        logger.debug("CalDAV TLS: version=0x{x:0>2}{x:0>2}, length={d}", .{ recv_buf[1], recv_buf[2], @as(u16, recv_buf[3]) << 8 | recv_buf[4] });
                    }
                    first_read = false;
                }

                const result = tls_server.run(recv_buf[0..recv_len], &send_buf) catch |err| {
                    logger.debug("CalDAV TLS handshake error: {} (recv_len={d})", .{ err, recv_len });
                    if (recv_len > 0) {
                        logger.debug("CalDAV TLS: first byte=0x{x:0>2}", .{recv_buf[0]});
                    }
                    return error.TlsHandshakeFailed;
                };

                if (result.recv_pos > 0) {
                    const remaining = recv_len - result.recv_pos;
                    if (remaining > 0) {
                        std.mem.copyForwards(u8, &recv_buf, recv_buf[result.recv_pos..recv_len]);
                    }
                    recv_len = remaining;
                }

                if (result.send.len > 0) {
                    var sent: usize = 0;
                    while (sent < result.send.len) {
                        const n = connection.write(result.send[sent..]) catch |err| {
                            logger.debug("CalDAV TLS handshake write error: {}", .{err});
                            return error.TlsHandshakeFailed;
                        };
                        if (n == 0) return error.TlsHandshakeFailed;
                        sent += n;
                    }
                }

                if (!tls_server.done()) {
                    const n = connection.read(recv_buf[recv_len..]) catch |err| {
                        logger.debug("CalDAV TLS handshake read error: {}", .{err});
                        return error.TlsHandshakeFailed;
                    };
                    if (n == 0) return error.TlsHandshakeFailed;
                    recv_len += n;
                }
            }

            tls_cipher = tls_server.cipher();
            logger.debug("CalDAV TLS handshake completed successfully", .{});

            // Handle TLS session - must be inside this block to access recv_buf/recv_len
            if (tls_cipher) |cipher| {
                var tls_conn = tls.nonblock.Connection.init(cipher);
                var cleartext_buf: [tls.input_buffer_len]u8 = undefined;

                session.tls_conn = &tls_conn;

                // `cipher_len` tracks ciphertext buffered at the front of recv_buf,
                // including any partial TLS record left unconsumed by a previous
                // decrypt. Seeded with leftover handshake bytes.
                var cipher_len: usize = recv_len;
                var closed = false;

                while (!closed) {
                    // Decrypt and dispatch whatever ciphertext is ALREADY buffered
                    // before blocking on another read. The client's HTTP request
                    // commonly arrives in the same TCP segment as its final TLS
                    // handshake flight, so it is already sitting in recv_buf (seeded
                    // into cipher_len as the handshake leftover). Reading first in
                    // that case deadlocks: the client is waiting for our response and
                    // will not send another byte. Whether the request piggybacks on
                    // the handshake segment or arrives separately is timing-dependent,
                    // which is why this manifested as an intermittent (~65%) hang.
                    // IMAP has the same exposure even though its server speaks
                    // first: a client may still send its first command with its
                    // Finished (see ImapServer.tlsHandshake).
                    var made_progress = false;
                    if (cipher_len > 0) {
                        const dec = tls_conn.decrypt(recv_buf[0..cipher_len], &cleartext_buf) catch |err| {
                            logger.err("CalDAV TLS decrypt error: {}", .{err});
                            break;
                        };
                        if (dec.closed) closed = true;

                        // Preserve any ciphertext not consumed (a partial record) by
                        // shifting it to the front of recv_buf for the next read.
                        const consumed = dec.ciphertext_pos;
                        const leftover = cipher_len - consumed;
                        if (leftover > 0 and consumed > 0) {
                            std.mem.copyForwards(u8, recv_buf[0..leftover], recv_buf[consumed..cipher_len]);
                        }
                        cipher_len = leftover;
                        if (consumed > 0) made_progress = true;

                        if (dec.cleartext.len > 0) {
                            made_progress = true;
                            if (!try session.receive(&self.config, dec.cleartext)) break;
                        }
                    }

                    if (closed) break;

                    // Drain any further buffered records before blocking on a read.
                    if (made_progress and cipher_len > 0) continue;

                    // A single record larger than the whole buffer can never be
                    // decrypted -> give up rather than spin.
                    if (cipher_len >= recv_buf.len) break;

                    // Block for more ciphertext from the client.
                    const bytes_read = connection.read(recv_buf[cipher_len..]) catch break;
                    if (bytes_read == 0) break;
                    cipher_len += bytes_read;
                }

                // Send close notify
                var close_buf: [64]u8 = undefined;
                if (tls_conn.close(&close_buf)) |close_data| {
                    _ = connection.write(close_data) catch {};
                } else |_| {}
            }
            return;
        }

        // Handle plain text session (non-SSL)
        if (!is_ssl) {
            // Serve requests until the client closes or errors (HTTP
            // keep-alive). This path sits behind the rpx gateway, which
            // reuses upstream connections — handling a single request per
            // TCP connection forced a reconnect for every proxied request
            // while the TLS path above already looped. The socket RCVTIMEO
            // set at the top bounds idle keep-alive connections.
            while (session.handleRequest(&self.config) catch false) {}
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

test "CalDAV server initialization" {
    const testing = std.testing;

    // Can't test without auth backend in unit tests
    // Just verify the config struct compiles
    const config = CalDavConfig{};
    try testing.expectEqual(@as(u16, 8008), config.port);
    try testing.expectEqual(@as(u16, 8443), config.ssl_port);
}

test "HTTP method parsing" {
    const testing = std.testing;

    try testing.expectEqual(HttpMethod.propfind, HttpMethod.fromString("PROPFIND").?);
    try testing.expectEqual(HttpMethod.mkcalendar, HttpMethod.fromString("MKCALENDAR").?);
    try testing.expectEqual(HttpMethod.report, HttpMethod.fromString("REPORT").?);
    try testing.expect(HttpMethod.fromString("INVALID") == null);
}

test "security: DAV authenticates each request on a reused connection" {
    const a = std.testing.allocator;
    var db = try database.Database.init(a, ":memory:");
    defer db.deinit();
    var backend = auth.AuthBackend.init(a, &db);
    defer backend.deinit();
    _ = try backend.createUser("alice@example.test", "secret", "alice@example.test");
    var store = try caldav_store.CalDavStore.init(a, .{});
    defer store.deinit();
    var fds: [2]c_int = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, @intCast(@as(u32, std.posix.SOCK.STREAM)), 0, &fds) != 0) return error.SocketPairFailed;
    defer _ = std.c.close(fds[0]);
    defer _ = std.c.close(fds[1]);
    var session = CalDavSession.init(a, .{ .fd = fds[0] }, &backend, &store);
    defer session.deinit();
    const config = CalDavConfig{};
    const requests = [_][]const u8{
        "OPTIONS / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWxpY2VAZXhhbXBsZS50ZXN0OnNlY3JldA==\r\n\r\n",
        "OPTIONS / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "OPTIONS / HTTP/1.1\r\nHost: localhost\r\nauthorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n",
    };
    for (requests, 0..) |request, index| {
        try std.testing.expectEqual(request.len, @as(usize, @intCast(std.c.write(fds[1], request.ptr, request.len))));
        try std.testing.expect(try session.handleRequest(&config));
        var reply: [4096]u8 = undefined;
        const n = std.c.read(fds[1], &reply, reply.len);
        try std.testing.expect(n > 0);
        const expected = if (index == 1) "HTTP/1.1 401" else "HTTP/1.1 200";
        try std.testing.expect(std.mem.startsWith(u8, reply[0..@intCast(n)], expected));
        if (index != 1) try std.testing.expectEqualStrings("alice@example.test", session.username.?);
    }
}

test "security: DAV rejects a Digest proof signed for a different request target" {
    const a = std.testing.allocator;
    var db = try database.Database.init(a, ":memory:");
    defer db.deinit();
    _ = try db.createUser("Mufasa", "unused", "mufasa@example.test");
    try db.exec("UPDATE users SET digest_ha1 = '03669d897755d170477e46b59491df2d' WHERE username = 'Mufasa'");
    var backend = auth.AuthBackend.init(a, &db);
    defer backend.deinit();
    // A precomputed MD5 client proof, with a live server nonce.
    const nonce = try a.dupe(u8, "dcd98b7102dd2f0e8b11d0f600bfb0c093");
    try backend.nonce_manager.nonces.put(nonce, .{ .created = currentTimestamp() });
    var store = try caldav_store.CalDavStore.init(a, .{});
    defer store.deinit();
    var fds: [2]c_int = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, @intCast(@as(u32, std.posix.SOCK.STREAM)), 0, &fds) != 0) return error.SocketPairFailed;
    defer _ = std.c.close(fds[0]);
    defer _ = std.c.close(fds[1]);
    var session = CalDavSession.init(a, .{ .fd = fds[0] }, &backend, &store);
    defer session.deinit();
    // A proof for /dir/index.html must not authorize another resource.
    const request = "GET /not-signed HTTP/1.1\r\nHost: localhost\r\nAuthorization: Digest username=\"Mufasa\", realm=\"CalDAV/CardDAV Server\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", response=\"7a97d241e140440ea5e1ea085e7fc6ac\"\r\n\r\n";
    try std.testing.expectEqual(request.len, @as(usize, @intCast(std.c.write(fds[1], request.ptr, request.len))));
    try std.testing.expect(try session.handleRequest(&.{}));
    var reply: [4096]u8 = undefined;
    const n = std.c.read(fds[1], &reply, reply.len);
    try std.testing.expect(n > 0);
    try std.testing.expect(std.mem.startsWith(u8, reply[0..@intCast(n)], "HTTP/1.1 401"));
    try std.testing.expect(!session.authenticated);
}
