const std = @import("std");
const posix = std.posix;
const socket = @import("../core/socket_compat.zig");
const io_compat = @import("../core/io_compat.zig");
const auth = @import("../auth/auth.zig");
const logger = @import("../core/logger.zig");
const tls = @import("tls");
const time_compat = @import("../core/time_compat.zig");
const caldav_store = @import("../storage/caldav_store.zig");
const autoconfig = @import("../api/autoconfig.zig");
const eas = @import("eas.zig");

/// Get the current epoch timestamp in seconds.
fn currentTimestamp() i64 {
    var ts: std.c.timespec = undefined;
    const rc = std.c.clock_gettime(.REALTIME, &ts);
    if (rc != 0) return 0;
    return ts.sec;
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
    display_name: []const u8 = "Mail",
};

// ============================================================================
// HTTP Methods
// ============================================================================

pub const HttpMethod = enum {
    get,
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
        addressbooks_home,
        addressbook_collection,
        addressbook_resource,
        well_known_caldav,
        well_known_carddav,
        unknown,
    };
};

/// Determine the total byte length of the first complete HTTP request in `buf`,
/// honoring Content-Length. Returns null if the request is not yet complete
/// (headers not fully received, or body shorter than Content-Length).
fn httpRequestLength(buf: []const u8) ?usize {
    const header_end = std.mem.indexOf(u8, buf, "\r\n\r\n") orelse return null;
    const body_start = header_end + 4;
    const headers = buf[0..header_end];

    var content_length: usize = 0;
    var h_lines = std.mem.splitSequence(u8, headers, "\r\n");
    while (h_lines.next()) |hline| {
        if (hline.len >= 15 and std.ascii.eqlIgnoreCase(hline[0..15], "content-length:")) {
            const val = std.mem.trim(u8, hline[15..], &std.ascii.whitespace);
            content_length = std.fmt.parseInt(usize, val, 10) catch 0;
            break;
        }
    }

    const total = body_start + content_length;
    if (buf.len < total) return null;
    return total;
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
    comptime base: []const u8,
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

    try buf.appendSlice(allocator, "    <D:href>" ++ base);
    try buf.appendSlice(allocator, user_esc);
    try buf.appendSlice(allocator, "/");
    try buf.appendSlice(allocator, coll_esc);
    try buf.appendSlice(allocator, "/");
    try buf.appendSlice(allocator, uid_esc);
    try buf.appendSlice(allocator, ext ++ "</D:href>\n");
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
    comptime base: []const u8,
    user: []const u8,
    collection: []const u8,
) !void {
    const user_esc = try xmlEscape(allocator, user);
    defer allocator.free(user_esc);
    const coll_esc = try xmlEscape(allocator, collection);
    defer allocator.free(coll_esc);

    try buf.appendSlice(allocator, "    <D:href>" ++ base);
    try buf.appendSlice(allocator, user_esc);
    try buf.appendSlice(allocator, "/");
    try buf.appendSlice(allocator, coll_esc);
    try buf.appendSlice(allocator, "/</D:href>\n");
}

// ============================================================================
// CalDAV/CardDAV Session
// ============================================================================

pub const CalDavSession = struct {
    allocator: std.mem.Allocator,
    connection: socket.Connection,
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
        if (self.username) |username| {
            self.allocator.free(username);
        }
    }

    /// Handle incoming HTTP request
    pub fn handleRequest(self: *CalDavSession, config: *const CalDavConfig) !bool {
        // Initial read for headers (up to 64KB)
        var header_buf: [65536]u8 = undefined;
        const bytes_read = self.connection.read(&header_buf) catch return false;

        if (bytes_read == 0) {
            return false; // Connection closed
        }

        // Check if we need to read more data based on Content-Length
        var request_data: ?[]u8 = null;
        defer if (request_data) |rd| self.allocator.free(rd);

        const initial = header_buf[0..bytes_read];
        const request = blk: {
            // Find Content-Length header and end of headers
            if (std.mem.indexOf(u8, initial, "\r\n\r\n")) |header_end| {
                const headers = initial[0..header_end];
                const body_start = header_end + 4;
                const body_received = bytes_read - body_start;

                // Parse Content-Length
                var content_length: usize = 0;
                var h_lines = std.mem.splitSequence(u8, headers, "\r\n");
                while (h_lines.next()) |hline| {
                    if (hline.len >= 15 and std.ascii.eqlIgnoreCase(hline[0..15], "content-length:")) {
                        const val = std.mem.trim(u8, hline[15..], &std.ascii.whitespace);
                        content_length = std.fmt.parseInt(usize, val, 10) catch 0;
                        break;
                    }
                }

                // SECURITY: Reject requests with bodies exceeding max_resource_size
                if (content_length > config.max_resource_size) {
                    try self.sendError(413, "Request Entity Too Large");
                    return true;
                }

                if (content_length > 0 and content_length > body_received) {
                    // Need to read more body data
                    const total_size = body_start + content_length;
                    var full_buf = try self.allocator.alloc(u8, total_size);
                    @memcpy(full_buf[0..bytes_read], initial);

                    var total_read = bytes_read;
                    while (total_read < total_size) {
                        const n = self.connection.read(full_buf[total_read..total_size]) catch break;
                        if (n == 0) break;
                        total_read += n;
                    }
                    request_data = full_buf;
                    break :blk full_buf[0..total_read];
                }
            }
            break :blk initial;
        };

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
        if (std.mem.startsWith(u8, path, "/.well-known/caldav")) {
            try self.sendWellKnownRedirect("/calendars/");
            return true;
        }
        if (std.mem.startsWith(u8, path, "/.well-known/carddav")) {
            try self.sendWellKnownRedirect("/addressbooks/");
            return true;
        }

        // Check authentication (Digest or Basic Auth)
        if (!self.authenticated) {
            var auth_header: ?[]const u8 = null;
            while (lines.next()) |line| {
                const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
                if (trimmed.len == 0) break;

                if (std.mem.startsWith(u8, trimmed, "Authorization:")) {
                    auth_header = std.mem.trim(u8, trimmed[14..], &std.ascii.whitespace);
                    break;
                }
            }

            if (auth_header == null) {
                try self.sendAuthRequired();
                return true;
            }

            // Try Digest auth first, then fall back to Basic
            var validated_username: ?[]const u8 = null;

            if (std.mem.startsWith(u8, auth_header.?, "Digest ")) {
                validated_username = self.auth_backend.verifyDigestAuth(
                    auth_header.?,
                    method_str,
                    "CalDAV/CardDAV Server",
                ) catch |err| blk: {
                    logger.err("CalDAV Digest authentication error: {}", .{err});
                    break :blk null;
                };
            }

            // Fall back to Basic auth if Digest didn't work
            if (validated_username == null and std.mem.startsWith(u8, auth_header.?, "Basic ")) {
                validated_username = self.auth_backend.verifyBasicAuth(auth_header.?) catch |err| blk: {
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
                try self.sendAuthRequired();
                return true;
            }
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
        switch (method) {
            .options => try self.handleOptions(path),
            .propfind => try self.handlePropfind(path, request, config),
            .proppatch => try self.handleProppatch(path, request, config),
            .get => try self.handleGet(path, config),
            .put => try self.handlePut(path, request, config),
            .delete => try self.handleDelete(path, config),
            .mkcalendar => try self.handleMkcalendar(path, config),
            .mkcol => try self.handleMkcol(path, config),
            .report => try self.handleReport(path, request, config),
            else => try self.sendError(501, "Not Implemented"),
        }
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
        _ = try self.connection.write(fbs.getWritten());
    }

    /// Handle OPTIONS request (WebDAV/CalDAV/CardDAV capabilities)
    fn handleOptions(self: *CalDavSession, path: []const u8) !void {
        _ = path;

        const response =
            "HTTP/1.1 200 OK\r\n" ++
            "DAV: 1, 2, 3, calendar-access, addressbook\r\n" ++
            "Allow: OPTIONS, GET, HEAD, POST, PUT, DELETE, PROPFIND, PROPPATCH, MKCALENDAR, MKCOL, REPORT\r\n" ++
            "Content-Length: 0\r\n\r\n";

        _ = try self.connection.write(response);
    }

    /// Handle PROPFIND request (property discovery)
    fn handlePropfind(
        self: *CalDavSession,
        path: []const u8,
        request: []const u8,
        config: *const CalDavConfig,
    ) !void {
        _ = config;

        // Parse Depth header (0 = resource only, 1 = resource + children)
        var depth: u8 = 0;
        var lines = std.mem.splitScalar(u8, request, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
            if (trimmed.len == 0) break;
            if (std.mem.startsWith(u8, trimmed, "Depth:")) {
                const depth_val = std.mem.trim(u8, trimmed[6..], &std.ascii.whitespace);
                if (std.mem.eql(u8, depth_val, "1")) depth = 1;
                if (std.mem.eql(u8, depth_val, "infinity")) depth = 1;
                break;
            }
        }

        const parsed = parsePath(path);
        const user_id = self.getUserId() catch 1;

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
                try appendPrint(&buf, self.allocator, "        <D:current-user-principal><D:href>/principals/{s}</D:href></D:current-user-principal>\n", .{username});
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
                try appendPrint(&buf, self.allocator, "        <C:calendar-home-set><D:href>/calendars/{s}/</D:href></C:calendar-home-set>\n", .{username_esc});
                try appendPrint(&buf, self.allocator, "        <CARD:addressbook-home-set><D:href>/addressbooks/{s}/</D:href></CARD:addressbook-home-set>\n", .{username_esc});
                try buf.appendSlice(self.allocator, "      </D:prop>\n");
                try buf.appendSlice(self.allocator, "      <D:status>HTTP/1.1 200 OK</D:status>\n");
                try buf.appendSlice(self.allocator, "    </D:propstat>\n");
                try buf.appendSlice(self.allocator, "  </D:response>\n");
                try buf.appendSlice(self.allocator, "</D:multistatus>");
            },
            .calendars_home => {
                try buf.appendSlice(self.allocator, "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n");
                try buf.appendSlice(self.allocator, "<D:multistatus xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\n");
                // List user's calendars
                const calendars = self.store.getUserCalendars(user_id) catch &[_]caldav_store.Calendar{};
                for (calendars) |cal| {
                    try buf.appendSlice(self.allocator, "  <D:response>\n");
                    const username = parsed.user orelse "user";
                    try appendCollectionHref(&buf, self.allocator, "/calendars/", username, cal.name);
                    try buf.appendSlice(self.allocator, "    <D:propstat>\n");
                    try buf.appendSlice(self.allocator, "      <D:prop>\n");
                    try buf.appendSlice(self.allocator, "        <D:resourcetype><D:collection/><C:calendar/></D:resourcetype>\n");
                    try appendXmlEscaped(&buf, self.allocator, "        <D:displayname>", cal.name, "</D:displayname>\n");
                    try appendPrint(&buf, self.allocator, "        <CS:getctag xmlns:CS=\"http://calendarserver.org/ns/\">{s}</CS:getctag>\n", .{cal.ctag});
                    try appendPrint(&buf, self.allocator, "        <D:sync-token>http://mail/sync/{d}</D:sync-token>\n", .{cal.sync_token});
                    try buf.appendSlice(self.allocator, "      </D:prop>\n");
                    try buf.appendSlice(self.allocator, "      <D:status>HTTP/1.1 200 OK</D:status>\n");
                    try buf.appendSlice(self.allocator, "    </D:propstat>\n");
                    try buf.appendSlice(self.allocator, "  </D:response>\n");
                }
                try buf.appendSlice(self.allocator, "</D:multistatus>");
            },
            .calendar_collection => {
                try buf.appendSlice(self.allocator, "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n");
                try buf.appendSlice(self.allocator, "<D:multistatus xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\n");

                const collection_name = parsed.collection orelse "default";
                const username = parsed.user orelse "user";

                // Collection itself
                try buf.appendSlice(self.allocator, "  <D:response>\n");
                try appendCollectionHref(&buf, self.allocator, "/calendars/", username, collection_name);
                try buf.appendSlice(self.allocator, "    <D:propstat>\n");
                try buf.appendSlice(self.allocator, "      <D:prop>\n");
                try buf.appendSlice(self.allocator, "        <D:resourcetype><D:collection/><C:calendar/></D:resourcetype>\n");
                try appendXmlEscaped(&buf, self.allocator, "        <D:displayname>", collection_name, "</D:displayname>\n");
                try buf.appendSlice(self.allocator, "        <C:supported-calendar-component-set><C:comp name=\"VEVENT\"/><C:comp name=\"VTODO\"/></C:supported-calendar-component-set>\n");
                try buf.appendSlice(self.allocator, "      </D:prop>\n");
                try buf.appendSlice(self.allocator, "      <D:status>HTTP/1.1 200 OK</D:status>\n");
                try buf.appendSlice(self.allocator, "    </D:propstat>\n");
                try buf.appendSlice(self.allocator, "  </D:response>\n");

                // List events if Depth: 1
                if (depth >= 1) {
                    const calendars = self.store.getUserCalendars(user_id) catch &[_]caldav_store.Calendar{};
                    for (calendars) |cal| {
                        if (std.mem.eql(u8, cal.name, collection_name)) {
                            const events = self.store.getCalendarEvents(cal.id) catch &[_]caldav_store.Event{};
                            for (events) |event| {
                                try buf.appendSlice(self.allocator, "  <D:response>\n");
                                try appendResourceHref(&buf, self.allocator, "/calendars/", username, collection_name, event.uid, ".ics");
                                try buf.appendSlice(self.allocator, "    <D:propstat>\n");
                                try buf.appendSlice(self.allocator, "      <D:prop>\n");
                                try appendXmlEscaped(&buf, self.allocator, "        <D:getetag>", event.etag, "</D:getetag>\n");
                                try buf.appendSlice(self.allocator, "      </D:prop>\n");
                                try buf.appendSlice(self.allocator, "      <D:status>HTTP/1.1 200 OK</D:status>\n");
                                try buf.appendSlice(self.allocator, "    </D:propstat>\n");
                                try buf.appendSlice(self.allocator, "  </D:response>\n");
                            }
                            break;
                        }
                    }
                }
                try buf.appendSlice(self.allocator, "</D:multistatus>");
            },
            .addressbooks_home => {
                try buf.appendSlice(self.allocator, "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n");
                try buf.appendSlice(self.allocator, "<D:multistatus xmlns:D=\"DAV:\" xmlns:CARD=\"urn:ietf:params:xml:ns:carddav\">\n");
                const addressbooks = self.store.getUserAddressBooks(user_id) catch &[_]caldav_store.AddressBook{};
                for (addressbooks) |ab| {
                    try buf.appendSlice(self.allocator, "  <D:response>\n");
                    const username = parsed.user orelse "user";
                    try appendCollectionHref(&buf, self.allocator, "/addressbooks/", username, ab.name);
                    try buf.appendSlice(self.allocator, "    <D:propstat>\n");
                    try buf.appendSlice(self.allocator, "      <D:prop>\n");
                    try buf.appendSlice(self.allocator, "        <D:resourcetype><D:collection/><CARD:addressbook/></D:resourcetype>\n");
                    try appendXmlEscaped(&buf, self.allocator, "        <D:displayname>", ab.name, "</D:displayname>\n");
                    try appendPrint(&buf, self.allocator, "        <CS:getctag xmlns:CS=\"http://calendarserver.org/ns/\">{s}</CS:getctag>\n", .{ab.ctag});
                    try appendPrint(&buf, self.allocator, "        <D:sync-token>http://mail/sync/{d}</D:sync-token>\n", .{ab.sync_token});
                    try buf.appendSlice(self.allocator, "        <CARD:supported-address-data><CARD:address-data-type content-type=\"text/vcard\" version=\"3.0\"/></CARD:supported-address-data>\n");
                    try buf.appendSlice(self.allocator, "      </D:prop>\n");
                    try buf.appendSlice(self.allocator, "      <D:status>HTTP/1.1 200 OK</D:status>\n");
                    try buf.appendSlice(self.allocator, "    </D:propstat>\n");
                    try buf.appendSlice(self.allocator, "  </D:response>\n");
                }
                try buf.appendSlice(self.allocator, "</D:multistatus>");
            },
            .addressbook_collection => {
                try buf.appendSlice(self.allocator, "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n");
                try buf.appendSlice(self.allocator, "<D:multistatus xmlns:D=\"DAV:\" xmlns:CARD=\"urn:ietf:params:xml:ns:carddav\">\n");

                const collection_name = parsed.collection orelse "default";
                const username = parsed.user orelse "user";

                // Collection itself
                try buf.appendSlice(self.allocator, "  <D:response>\n");
                try appendCollectionHref(&buf, self.allocator, "/addressbooks/", username, collection_name);
                try buf.appendSlice(self.allocator, "    <D:propstat>\n");
                try buf.appendSlice(self.allocator, "      <D:prop>\n");
                try buf.appendSlice(self.allocator, "        <D:resourcetype><D:collection/><CARD:addressbook/></D:resourcetype>\n");
                try appendXmlEscaped(&buf, self.allocator, "        <D:displayname>", collection_name, "</D:displayname>\n");
                try buf.appendSlice(self.allocator, "        <CARD:supported-address-data><CARD:address-data-type content-type=\"text/vcard\" version=\"3.0\"/></CARD:supported-address-data>\n");
                try buf.appendSlice(self.allocator, "      </D:prop>\n");
                try buf.appendSlice(self.allocator, "      <D:status>HTTP/1.1 200 OK</D:status>\n");
                try buf.appendSlice(self.allocator, "    </D:propstat>\n");
                try buf.appendSlice(self.allocator, "  </D:response>\n");

                // List contacts if Depth: 1
                if (depth >= 1) {
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
                                try buf.appendSlice(self.allocator, "      </D:prop>\n");
                                try buf.appendSlice(self.allocator, "      <D:status>HTTP/1.1 200 OK</D:status>\n");
                                try buf.appendSlice(self.allocator, "    </D:propstat>\n");
                                try buf.appendSlice(self.allocator, "  </D:response>\n");
                            }
                            break;
                        }
                    }
                }
                try buf.appendSlice(self.allocator, "</D:multistatus>");
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
            "HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml; charset=utf-8\r\nContent-Length: {d}\r\n\r\n",
            .{body.len},
        );

        _ = try self.connection.write(header_fbs.getWritten());
        _ = try self.connection.write(body);
    }

    /// Handle PROPPATCH request (modify properties on calendar/addressbook)
    fn handleProppatch(
        self: *CalDavSession,
        path: []const u8,
        request: []const u8,
        config: *const CalDavConfig,
    ) !void {
        _ = config;
        const parsed = parsePath(path);

        // Extract body from request
        var body: []const u8 = "";
        if (std.mem.indexOf(u8, request, "\r\n\r\n")) |idx| {
            body = request[idx + 4 ..];
        }

        // Parse displayname and calendar-color from the XML body
        var new_name: ?[]const u8 = null;
        var new_color: ?[]const u8 = null;

        if (std.mem.indexOf(u8, body, "<D:displayname>")) |start| {
            const val_start = start + 15;
            if (std.mem.indexOf(u8, body[val_start..], "</D:displayname>")) |end| {
                new_name = body[val_start .. val_start + end];
            }
        }
        if (std.mem.indexOf(u8, body, "<A:calendar-color>")) |start| {
            const val_start = start + 18;
            if (std.mem.indexOf(u8, body[val_start..], "</A:calendar-color>")) |end| {
                new_color = body[val_start .. val_start + end];
            }
        }

        switch (parsed.path_type) {
            .calendar_collection => {
                if (parsed.collection) |col_name| {
                    const user_id = self.getUserId() catch 1;
                    if (self.store.getCalendarByName(user_id, col_name)) |cal| {
                        if (self.store.calendars.getPtr(cal.id)) |cal_ptr| {
                            // SECURITY/CORRECTNESS: new_name/new_color point into the
                            // request buffer, which is freed after this request. Dupe
                            // with the store allocator so the stored slices stay valid.
                            if (new_name) |name| {
                                cal_ptr.name = try self.store.allocator.dupe(u8, name);
                            }
                            if (new_color) |color| {
                                cal_ptr.color = try self.store.allocator.dupe(u8, color);
                            }
                        }
                        // Return 207 Multi-Status success
                        const resp = "HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml; charset=utf-8\r\n\r\n" ++
                            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" ++
                            "<D:multistatus xmlns:D=\"DAV:\">\n" ++
                            "  <D:response>\n" ++
                            "    <D:propstat>\n" ++
                            "      <D:status>HTTP/1.1 200 OK</D:status>\n" ++
                            "    </D:propstat>\n" ++
                            "  </D:response>\n" ++
                            "</D:multistatus>\n";
                        _ = try self.connection.write(resp);
                        return;
                    }
                }
                try self.sendError(404, "Not Found");
            },
            .addressbook_collection => {
                if (parsed.collection) |col_name| {
                    const user_id = self.getUserId() catch 1;
                    if (self.store.getAddressBookByName(user_id, col_name)) |ab| {
                        if (self.store.addressbooks.getPtr(ab.id)) |ab_ptr| {
                            // SECURITY/CORRECTNESS: new_name points into the request
                            // buffer (freed after this request). Dupe with the store
                            // allocator so the stored slice stays valid.
                            if (new_name) |name| {
                                ab_ptr.name = try self.store.allocator.dupe(u8, name);
                            }
                        }
                        const resp = "HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml; charset=utf-8\r\n\r\n" ++
                            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" ++
                            "<D:multistatus xmlns:D=\"DAV:\">\n" ++
                            "  <D:response>\n" ++
                            "    <D:propstat>\n" ++
                            "      <D:status>HTTP/1.1 200 OK</D:status>\n" ++
                            "    </D:propstat>\n" ++
                            "  </D:response>\n" ++
                            "</D:multistatus>\n";
                        _ = try self.connection.write(resp);
                        return;
                    }
                }
                try self.sendError(404, "Not Found");
            },
            else => try self.sendError(501, "PROPPATCH not supported on this resource"),
        }
    }

    /// Handle GET request (retrieve calendar/contact resource)
    fn handleGet(self: *CalDavSession, path: []const u8, config: *const CalDavConfig) !void {
        _ = config;
        const parsed = parsePath(path);

        switch (parsed.path_type) {
            .calendar_resource => {
                const uid = parsed.resource_uid orelse {
                    try self.sendError(404, "Not Found");
                    return;
                };
                const collection_name = parsed.collection orelse {
                    try self.sendError(404, "Not Found");
                    return;
                };
                // Look up calendar by name for the user (use user_id=1 as default)
                const user_id = self.getUserId() catch 1;
                const calendars = self.store.getUserCalendars(user_id) catch {
                    try self.sendError(500, "Internal Server Error");
                    return;
                };
                var calendar_id: ?u64 = null;
                for (calendars) |cal| {
                    if (std.mem.eql(u8, cal.name, collection_name)) {
                        calendar_id = cal.id;
                        break;
                    }
                }
                const cal_id = calendar_id orelse {
                    try self.sendError(404, "Not Found");
                    return;
                };
                const event = self.store.getEventByUid(cal_id, uid) orelse {
                    try self.sendError(404, "Not Found");
                    return;
                };
                const ics_data = if (event.ics_data.len > 0) event.ics_data else "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n";
                try self.sendResourceResponse("text/calendar", event.etag, ics_data);
            },
            .addressbook_resource => {
                const uid = parsed.resource_uid orelse {
                    try self.sendError(404, "Not Found");
                    return;
                };
                const collection_name = parsed.collection orelse {
                    try self.sendError(404, "Not Found");
                    return;
                };
                const user_id = self.getUserId() catch 1;
                const addressbooks = self.store.getUserAddressBooks(user_id) catch {
                    try self.sendError(500, "Internal Server Error");
                    return;
                };
                var ab_id: ?u64 = null;
                for (addressbooks) |ab| {
                    if (std.mem.eql(u8, ab.name, collection_name)) {
                        ab_id = ab.id;
                        break;
                    }
                }
                const addressbook_id = ab_id orelse {
                    try self.sendError(404, "Not Found");
                    return;
                };
                const contact = self.store.getContactByUid(addressbook_id, uid) orelse {
                    try self.sendError(404, "Not Found");
                    return;
                };
                const generated_vcf: ?[]u8 = if (contact.vcf_data.len == 0) (self.store.generateVcf(contact) catch {
                    try self.sendError(500, "Internal Server Error");
                    return;
                }) else null;
                defer if (generated_vcf) |g| self.allocator.free(g);
                const vcf_data: []const u8 = generated_vcf orelse contact.vcf_data;
                try self.sendResourceResponse("text/vcard", contact.etag, vcf_data);
            },
            else => {
                try self.sendError(404, "Not Found");
            },
        }
    }

    /// Send a resource response with Content-Type, ETag, and body
    fn sendResourceResponse(self: *CalDavSession, content_type: []const u8, etag: []const u8, body: []const u8) !void {
        var header_buf: [512]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&header_buf);
        const writer = fbs.writer();
        try writer.print(
            "HTTP/1.1 200 OK\r\nContent-Type: {s}; charset=utf-8\r\nETag: {s}\r\nContent-Length: {d}\r\n\r\n",
            .{ content_type, etag, body.len },
        );
        _ = try self.connection.write(fbs.getWritten());
        _ = try self.connection.write(body);
    }

    /// Handle PUT request (create/update calendar/contact resource)
    fn handlePut(
        self: *CalDavSession,
        path: []const u8,
        request: []const u8,
        config: *const CalDavConfig,
    ) !void {
        _ = config;
        const parsed = parsePath(path);

        // Extract body from request
        const body_start = std.mem.indexOf(u8, request, "\r\n\r\n") orelse {
            try self.sendError(400, "Bad Request");
            return;
        };
        const body = request[body_start + 4 ..];

        // Extract If-Match header for conflict detection
        var if_match: ?[]const u8 = null;
        var lines = std.mem.splitScalar(u8, request[0..body_start], '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
            if (std.mem.startsWith(u8, trimmed, "If-Match:")) {
                if_match = std.mem.trim(u8, trimmed[9..], &std.ascii.whitespace);
                break;
            }
        }

        switch (parsed.path_type) {
            .calendar_resource => {
                if (std.mem.indexOf(u8, body, "BEGIN:VCALENDAR") == null) {
                    try self.sendError(400, "Invalid iCalendar format");
                    return;
                }
                const uid = parsed.resource_uid orelse {
                    try self.sendError(400, "Missing resource UID");
                    return;
                };
                const collection_name = parsed.collection orelse {
                    try self.sendError(400, "Missing calendar name");
                    return;
                };
                const user_id = self.getUserId() catch 1;

                // Find or create calendar
                var cal_id: u64 = undefined;
                if (self.store.getAddressBookByName(user_id, collection_name)) |_| {
                    // Wrong type - this is an addressbook path
                    try self.sendError(400, "Path is not a calendar");
                    return;
                }
                const calendars = self.store.getUserCalendars(user_id) catch {
                    try self.sendError(500, "Internal Server Error");
                    return;
                };
                var found = false;
                for (calendars) |cal| {
                    if (std.mem.eql(u8, cal.name, collection_name)) {
                        cal_id = cal.id;
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    cal_id = self.store.createCalendar(user_id, collection_name, null) catch {
                        try self.sendError(500, "Internal Server Error");
                        return;
                    };
                }

                // Parse event summary from ICS
                const parsed_event = caldav_store.IcsParser.parseEvent(body);
                const summary = if (parsed_event) |e| (e.summary orelse "Untitled") else "Untitled";

                // Check if this is an update
                if (self.store.getEventIdByUid(cal_id, uid)) |event_id| {
                    // Update existing: check ETag if If-Match provided
                    if (if_match) |etag| {
                        if (self.store.getEvent(event_id)) |existing| {
                            if (!std.mem.eql(u8, existing.etag, etag)) {
                                try self.sendError(412, "Precondition Failed");
                                return;
                            }
                        }
                    }
                    self.store.updateEvent(event_id, .{ .summary = summary, .dtstart = currentTimestamp(), .ics_data = body }) catch {
                        try self.sendError(500, "Internal Server Error");
                        return;
                    };
                    try self.sendSuccess(204, "No Content");
                } else {
                    // Create new
                    _ = self.store.createEvent(cal_id, .{ .uid = uid, .summary = summary, .dtstart = currentTimestamp(), .ics_data = body }) catch {
                        try self.sendError(500, "Internal Server Error");
                        return;
                    };
                    try self.sendSuccess(201, "Created");
                }
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
                const user_id = self.getUserId() catch 1;

                // Find or create addressbook
                var ab_id: u64 = undefined;
                const addressbooks = self.store.getUserAddressBooks(user_id) catch {
                    try self.sendError(500, "Internal Server Error");
                    return;
                };
                var found_ab = false;
                for (addressbooks) |ab| {
                    if (std.mem.eql(u8, ab.name, collection_name)) {
                        ab_id = ab.id;
                        found_ab = true;
                        break;
                    }
                }
                if (!found_ab) {
                    ab_id = self.store.createAddressBook(user_id, collection_name, null) catch {
                        try self.sendError(500, "Internal Server Error");
                        return;
                    };
                }

                // Parse contact from vCard
                const parsed_contact = caldav_store.VcfParser.parseContact(body);
                const full_name = if (parsed_contact) |c| (c.full_name orelse "Unknown") else "Unknown";

                // Check if this is an update
                if (self.store.getContactIdByUid(ab_id, uid)) |contact_id| {
                    if (if_match) |etag| {
                        if (self.store.getContact(contact_id)) |existing| {
                            if (!std.mem.eql(u8, existing.etag, etag)) {
                                try self.sendError(412, "Precondition Failed");
                                return;
                            }
                        }
                    }
                    self.store.updateContact(contact_id, .{ .full_name = full_name, .vcf_data = body }) catch {
                        try self.sendError(500, "Internal Server Error");
                        return;
                    };
                    try self.sendSuccess(204, "No Content");
                } else {
                    _ = self.store.createContact(ab_id, .{ .uid = uid, .full_name = full_name, .vcf_data = body }) catch {
                        try self.sendError(500, "Internal Server Error");
                        return;
                    };
                    try self.sendSuccess(201, "Created");
                }
            },
            else => {
                try self.sendError(400, "Invalid PUT path");
            },
        }
    }

    /// Handle DELETE request (delete calendar/contact resource)
    fn handleDelete(self: *CalDavSession, path: []const u8, config: *const CalDavConfig) !void {
        _ = config;
        const parsed = parsePath(path);

        switch (parsed.path_type) {
            .calendar_resource => {
                const uid = parsed.resource_uid orelse {
                    try self.sendError(404, "Not Found");
                    return;
                };
                const collection_name = parsed.collection orelse {
                    try self.sendError(404, "Not Found");
                    return;
                };
                const user_id = self.getUserId() catch 1;
                const calendars = self.store.getUserCalendars(user_id) catch {
                    try self.sendError(500, "Internal Server Error");
                    return;
                };
                for (calendars) |cal| {
                    if (std.mem.eql(u8, cal.name, collection_name)) {
                        if (self.store.getEventIdByUid(cal.id, uid)) |event_id| {
                            self.store.deleteEvent(event_id) catch {
                                try self.sendError(500, "Internal Server Error");
                                return;
                            };
                            try self.sendSuccess(204, "No Content");
                            return;
                        }
                    }
                }
                try self.sendError(404, "Not Found");
            },
            .addressbook_resource => {
                const uid = parsed.resource_uid orelse {
                    try self.sendError(404, "Not Found");
                    return;
                };
                const collection_name = parsed.collection orelse {
                    try self.sendError(404, "Not Found");
                    return;
                };
                const user_id = self.getUserId() catch 1;
                const addressbooks = self.store.getUserAddressBooks(user_id) catch {
                    try self.sendError(500, "Internal Server Error");
                    return;
                };
                for (addressbooks) |ab| {
                    if (std.mem.eql(u8, ab.name, collection_name)) {
                        if (self.store.getContactIdByUid(ab.id, uid)) |contact_id| {
                            self.store.deleteContact(contact_id) catch {
                                try self.sendError(500, "Internal Server Error");
                                return;
                            };
                            try self.sendSuccess(204, "No Content");
                            return;
                        }
                    }
                }
                try self.sendError(404, "Not Found");
            },
            .calendar_collection => {
                // Delete entire calendar
                const collection_name = parsed.collection orelse {
                    try self.sendError(404, "Not Found");
                    return;
                };
                const user_id = self.getUserId() catch 1;
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
                const user_id = self.getUserId() catch 1;
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
            const user_id = self.getUserId() catch 1;
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
            const user_id = self.getUserId() catch 1;
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
            const user_id = self.getUserId() catch 1;
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

    /// Handle REPORT request (calendar/contact queries)
    fn handleReport(
        self: *CalDavSession,
        path: []const u8,
        request: []const u8,
        config: *const CalDavConfig,
    ) !void {
        _ = config;

        // Check report type
        if (std.mem.indexOf(u8, request, "calendar-query") != null) {
            try self.handleCalendarQuery(path, request);
        } else if (std.mem.indexOf(u8, request, "calendar-multiget") != null) {
            try self.handleCalendarMultiget(path, request);
        } else if (std.mem.indexOf(u8, request, "addressbook-query") != null) {
            try self.handleAddressbookQuery(path, request);
        } else if (std.mem.indexOf(u8, request, "addressbook-multiget") != null) {
            try self.handleAddressbookMultiget(path, request);
        } else if (std.mem.indexOf(u8, request, "sync-collection") != null) {
            try self.handleSyncCollection(path, request);
        } else {
            try self.sendError(400, "Invalid report type");
        }
    }

    /// Parse iCalendar date from XML attribute value (YYYYMMDDTHHMMSSZ)
    fn parseIcalDateFromXml(value: []const u8) ?i64 {
        if (value.len < 8) return null;
        var year = std.fmt.parseInt(i64, value[0..4], 10) catch return null;
        var month = std.fmt.parseInt(i64, value[4..6], 10) catch return null;
        const day = std.fmt.parseInt(i64, value[6..8], 10) catch return null;
        // Compute days since epoch
        if (month <= 2) {
            year -= 1;
            month += 12;
        }
        const days = 365 * year + @divFloor(year, 4) - @divFloor(year, 100) + @divFloor(year, 400) + @divFloor((153 * (month - 3) + 2), 5) + day - 1 - 719468;
        if (value.len >= 15 and value[8] == 'T') {
            const hour = std.fmt.parseInt(i64, value[9..11], 10) catch return null;
            const minute = std.fmt.parseInt(i64, value[11..13], 10) catch return null;
            const second = std.fmt.parseInt(i64, value[13..15], 10) catch return null;
            return days * 86400 + hour * 3600 + minute * 60 + second;
        }
        return days * 86400;
    }

    /// Handle calendar-query REPORT
    fn handleCalendarQuery(self: *CalDavSession, path: []const u8, request: []const u8) !void {
        const parsed = parsePath(path);
        const user_id = self.getUserId() catch 1;

        // Parse time-range filter from request body
        var time_range_start: ?i64 = null;
        var time_range_end: ?i64 = null;
        const body_start = std.mem.indexOf(u8, request, "\r\n\r\n") orelse request.len;
        const body = if (body_start + 4 <= request.len) request[body_start + 4 ..] else "";
        if (std.mem.indexOf(u8, body, "time-range")) |_| {
            if (std.mem.indexOf(u8, body, "start=\"")) |s| {
                const val_start = s + 7;
                if (std.mem.indexOf(u8, body[val_start..], "\"")) |val_end| {
                    time_range_start = parseIcalDateFromXml(body[val_start .. val_start + val_end]);
                }
            }
            if (std.mem.indexOf(u8, body, "end=\"")) |s| {
                const val_start = s + 5;
                if (std.mem.indexOf(u8, body[val_start..], "\"")) |val_end| {
                    time_range_end = parseIcalDateFromXml(body[val_start .. val_start + val_end]);
                }
            }
        }

        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.allocator);

        try buf.appendSlice(self.allocator, "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n");
        try buf.appendSlice(self.allocator, "<D:multistatus xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\n");

        const collection_name = parsed.collection orelse "default";
        const username = parsed.user orelse "user";

        const calendars = self.store.getUserCalendars(user_id) catch &[_]caldav_store.Calendar{};
        for (calendars) |cal| {
            if (std.mem.eql(u8, cal.name, collection_name)) {
                const events = self.store.getCalendarEvents(cal.id) catch &[_]caldav_store.Event{};
                for (events) |event| {
                    // Apply time-range filter if present
                    if (time_range_start) |start| {
                        const event_end = event.dtend orelse event.dtstart;
                        if (event_end < start) continue;
                    }
                    if (time_range_end) |end| {
                        if (event.dtstart >= end) continue;
                    }
                    try buf.appendSlice(self.allocator, "  <D:response>\n");
                    try appendResourceHref(&buf, self.allocator, "/calendars/", username, collection_name, event.uid, ".ics");
                    try buf.appendSlice(self.allocator, "    <D:propstat>\n");
                    try buf.appendSlice(self.allocator, "      <D:prop>\n");
                    try appendXmlEscaped(&buf, self.allocator, "        <D:getetag>", event.etag, "</D:getetag>\n");
                    if (event.ics_data.len > 0) {
                        try appendXmlEscaped(&buf, self.allocator, "        <C:calendar-data>", event.ics_data, "</C:calendar-data>\n");
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

    /// Handle calendar-multiget REPORT
    fn handleCalendarMultiget(self: *CalDavSession, path: []const u8, request: []const u8) !void {
        _ = path;
        const user_id = self.getUserId() catch 1;

        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.allocator);

        try buf.appendSlice(self.allocator, "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n");
        try buf.appendSlice(self.allocator, "<D:multistatus xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\n");

        // Parse <D:href> elements from request body
        const body_start = std.mem.indexOf(u8, request, "\r\n\r\n") orelse request.len;
        const body = if (body_start + 4 <= request.len) request[body_start + 4 ..] else "";

        var search_pos: usize = 0;
        while (std.mem.indexOf(u8, body[search_pos..], "<D:href>")) |href_start| {
            const abs_start = search_pos + href_start + 8;
            if (std.mem.indexOf(u8, body[abs_start..], "</D:href>")) |href_end| {
                const href = body[abs_start .. abs_start + href_end];
                const href_parsed = parsePath(href);
                if (href_parsed.path_type == .calendar_resource) {
                    if (href_parsed.resource_uid) |uid| {
                        if (href_parsed.collection) |coll| {
                            // Find calendar and event
                            const calendars = self.store.getUserCalendars(user_id) catch &[_]caldav_store.Calendar{};
                            for (calendars) |cal| {
                                if (std.mem.eql(u8, cal.name, coll)) {
                                    if (self.store.getEventByUid(cal.id, uid)) |event| {
                                        try buf.appendSlice(self.allocator, "  <D:response>\n");
                                        try appendHrefEscaped(&buf, self.allocator, href);
                                        try buf.appendSlice(self.allocator, "    <D:propstat>\n");
                                        try buf.appendSlice(self.allocator, "      <D:prop>\n");
                                        try appendXmlEscaped(&buf, self.allocator, "        <D:getetag>", event.etag, "</D:getetag>\n");
                                        if (event.ics_data.len > 0) {
                                            try appendXmlEscaped(&buf, self.allocator, "        <C:calendar-data>", event.ics_data, "</C:calendar-data>\n");
                                        }
                                        try buf.appendSlice(self.allocator, "      </D:prop>\n");
                                        try buf.appendSlice(self.allocator, "      <D:status>HTTP/1.1 200 OK</D:status>\n");
                                        try buf.appendSlice(self.allocator, "    </D:propstat>\n");
                                        try buf.appendSlice(self.allocator, "  </D:response>\n");
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
                search_pos = abs_start + href_end + 9;
            } else break;
        }

        try buf.appendSlice(self.allocator, "</D:multistatus>");
        try self.sendMultistatusResponse(buf.items);
    }

    /// Handle addressbook-query REPORT
    fn handleAddressbookQuery(self: *CalDavSession, path: []const u8, request: []const u8) !void {
        _ = request;
        const parsed = parsePath(path);
        const user_id = self.getUserId() catch 1;

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

    /// Handle addressbook-multiget REPORT
    fn handleAddressbookMultiget(self: *CalDavSession, path: []const u8, request: []const u8) !void {
        _ = path;
        const user_id = self.getUserId() catch 1;

        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.allocator);

        try buf.appendSlice(self.allocator, "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n");
        try buf.appendSlice(self.allocator, "<D:multistatus xmlns:D=\"DAV:\" xmlns:CARD=\"urn:ietf:params:xml:ns:carddav\">\n");

        // Parse <D:href> elements from request body
        const body_start = std.mem.indexOf(u8, request, "\r\n\r\n") orelse request.len;
        const body = if (body_start + 4 <= request.len) request[body_start + 4 ..] else "";

        var search_pos: usize = 0;
        while (std.mem.indexOf(u8, body[search_pos..], "<D:href>")) |href_start| {
            const abs_start = search_pos + href_start + 8;
            if (std.mem.indexOf(u8, body[abs_start..], "</D:href>")) |href_end| {
                const href = body[abs_start .. abs_start + href_end];
                const href_parsed = parsePath(href);
                if (href_parsed.path_type == .addressbook_resource) {
                    if (href_parsed.resource_uid) |uid| {
                        if (href_parsed.collection) |coll| {
                            const addressbooks = self.store.getUserAddressBooks(user_id) catch &[_]caldav_store.AddressBook{};
                            for (addressbooks) |ab| {
                                if (std.mem.eql(u8, ab.name, coll)) {
                                    if (self.store.getContactByUid(ab.id, uid)) |contact| {
                                        try buf.appendSlice(self.allocator, "  <D:response>\n");
                                        try appendHrefEscaped(&buf, self.allocator, href);
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
                        }
                    }
                }
                search_pos = abs_start + href_end + 9;
            } else break;
        }

        try buf.appendSlice(self.allocator, "</D:multistatus>");
        try self.sendMultistatusResponse(buf.items);
    }

    /// Handle sync-collection REPORT (RFC 6578)
    fn handleSyncCollection(self: *CalDavSession, path: []const u8, request: []const u8) !void {
        const parsed = parsePath(path);
        const user_id = self.getUserId() catch 1;

        // Parse sync-token from request body
        var sync_token: u64 = 0;
        const body_start = std.mem.indexOf(u8, request, "\r\n\r\n") orelse request.len;
        const body = if (body_start + 4 <= request.len) request[body_start + 4 ..] else "";

        if (std.mem.indexOf(u8, body, "<D:sync-token>")) |token_start| {
            const abs_start = token_start + 14;
            if (std.mem.indexOf(u8, body[abs_start..], "</D:sync-token>")) |token_end| {
                const token_str = body[abs_start .. abs_start + token_end];
                // Token format: "http://..." or just a number
                if (std.mem.lastIndexOf(u8, token_str, "/")) |slash| {
                    sync_token = std.fmt.parseInt(u64, token_str[slash + 1 ..], 10) catch 0;
                } else {
                    sync_token = std.fmt.parseInt(u64, token_str, 10) catch 0;
                }
            }
        }

        const is_calendar = parsed.path_type == .calendar_collection;

        // Find collection ID
        var collection_id: u64 = 0;
        if (parsed.collection) |coll_name| {
            if (is_calendar) {
                const calendars = self.store.getUserCalendars(user_id) catch &[_]caldav_store.Calendar{};
                for (calendars) |cal| {
                    if (std.mem.eql(u8, cal.name, coll_name)) {
                        collection_id = cal.id;
                        break;
                    }
                }
            } else {
                const addressbooks = self.store.getUserAddressBooks(user_id) catch &[_]caldav_store.AddressBook{};
                for (addressbooks) |ab| {
                    if (std.mem.eql(u8, ab.name, coll_name)) {
                        collection_id = ab.id;
                        break;
                    }
                }
            }
        }

        const report = self.store.getChangesSince(collection_id, sync_token, is_calendar) catch {
            try self.sendError(500, "Internal Server Error");
            return;
        };
        // getChangesSince allocates the changes slice with the store allocator; the
        // SyncChange entries themselves alias store-owned strings, so only free the
        // slice (not its elements).
        defer self.store.allocator.free(report.changes);

        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.allocator);

        try buf.appendSlice(self.allocator, "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n");
        try buf.appendSlice(self.allocator, "<D:multistatus xmlns:D=\"DAV:\">\n");

        for (report.changes) |change| {
            try buf.appendSlice(self.allocator, "  <D:response>\n");
            try appendHrefEscaped(&buf, self.allocator, change.href);
            if (change.change_type == .deleted) {
                try buf.appendSlice(self.allocator, "    <D:status>HTTP/1.1 404 Not Found</D:status>\n");
            } else {
                try buf.appendSlice(self.allocator, "    <D:propstat>\n");
                try buf.appendSlice(self.allocator, "      <D:prop>\n");
                try appendXmlEscaped(&buf, self.allocator, "        <D:getetag>", change.etag, "</D:getetag>\n");
                try buf.appendSlice(self.allocator, "      </D:prop>\n");
                try buf.appendSlice(self.allocator, "      <D:status>HTTP/1.1 200 OK</D:status>\n");
                try buf.appendSlice(self.allocator, "    </D:propstat>\n");
            }
            try buf.appendSlice(self.allocator, "  </D:response>\n");
        }

        try appendPrint(&buf, self.allocator, "  <D:sync-token>http://mail/sync/{d}</D:sync-token>\n", .{report.new_sync_token});
        try buf.appendSlice(self.allocator, "</D:multistatus>");
        try self.sendMultistatusResponse(buf.items);
    }

    /// Send a 207 Multi-Status response with the given body
    fn sendMultistatusResponse(self: *CalDavSession, body: []const u8) !void {
        var header_buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&header_buf);
        const writer = fbs.writer();
        try writer.print(
            "HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml; charset=utf-8\r\nContent-Length: {d}\r\n\r\n",
            .{body.len},
        );
        _ = try self.connection.write(fbs.getWritten());
        _ = try self.connection.write(body);
    }

    /// Send authentication required response with Digest challenge
    fn sendAuthRequired(self: *CalDavSession) !void {
        const nonce = self.auth_backend.generateNonce() catch {
            // Fallback to Basic auth if nonce generation fails
            const response =
                "HTTP/1.1 401 Unauthorized\r\n" ++
                "WWW-Authenticate: Basic realm=\"CalDAV/CardDAV Server\"\r\n" ++
                "Content-Length: 0\r\n\r\n";
            _ = try self.connection.write(response);
            return;
        };
        // Note: Don't free nonce here - it's owned by the NonceManager and will be freed when invalidated

        var buf: [512]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        try writer.print(
            "HTTP/1.1 401 Unauthorized\r\n" ++
                "WWW-Authenticate: Digest realm=\"CalDAV/CardDAV Server\", nonce=\"{s}\", qop=\"auth\", algorithm=SHA-256\r\n" ++
                "WWW-Authenticate: Basic realm=\"CalDAV/CardDAV Server\"\r\n" ++
                "Content-Length: 0\r\n\r\n",
            .{nonce},
        );
        _ = try self.connection.write(fbs.getWritten());
    }

    /// Send error response
    fn sendError(self: *CalDavSession, code: u16, message: []const u8) !void {
        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        try writer.print("HTTP/1.1 {d} {s}\r\nContent-Length: 0\r\n\r\n", .{ code, message });
        _ = try self.connection.write(fbs.getWritten());
    }

    /// Send success response
    fn sendSuccess(self: *CalDavSession, code: u16, message: []const u8) !void {
        var buf: [256]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        try writer.print("HTTP/1.1 {d} {s}\r\nContent-Length: 0\r\n\r\n", .{ code, message });
        _ = try self.connection.write(fbs.getWritten());
    }
};

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
        const address = try socket.Address.parseIp("0.0.0.0", self.config.port);
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
                    time_compat.sleepMs(100);
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
        const ssl_address = socket.Address.parseIp("0.0.0.0", self.config.ssl_port) catch |err| {
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
                    time_compat.sleepMs(100);
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

                var tls_session = TlsCalDavSession.init(self.allocator, connection, self.auth_backend, self.store, &tls_conn);
                defer tls_session.deinit();

                // Accumulate decrypted cleartext until a full HTTP request (headers
                // + Content-Length body) has been received, then dispatch. This
                // prevents truncating large PUTs (bug: previously capped at 8192).
                var request_accum: std.ArrayList(u8) = .empty;
                defer request_accum.deinit(self.allocator);

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
                    // (IMAP avoids this only because its server speaks first.)
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
                            // SECURITY: bound total buffered request size.
                            if (request_accum.items.len + dec.cleartext.len > self.config.max_resource_size) {
                                try tls_session.sendTls("HTTP/1.1 413 Request Entity Too Large\r\nContent-Length: 0\r\n\r\n");
                                break;
                            }
                            try request_accum.appendSlice(self.allocator, dec.cleartext);
                        }

                        // Dispatch every complete request currently buffered (handles
                        // pipelining), keeping any trailing partial request.
                        while (httpRequestLength(request_accum.items)) |req_len| {
                            _ = tls_session.handleRequest(&self.config, request_accum.items[0..req_len]) catch {};
                            // Drop the consumed request, shifting any remainder down.
                            const remaining = request_accum.items.len - req_len;
                            if (remaining > 0) {
                                std.mem.copyForwards(u8, request_accum.items[0..remaining], request_accum.items[req_len..]);
                            }
                            request_accum.shrinkRetainingCapacity(remaining);
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
            // Plain text session
            _ = session.handleRequest(&self.config) catch {};
        }
    }
};

/// TLS-wrapped CalDAV session for encrypted connections
const TlsCalDavSession = struct {
    allocator: std.mem.Allocator,
    connection: socket.Connection,
    username: ?[]const u8 = null,
    authenticated: bool = false,
    auth_backend: *auth.AuthBackend,
    store: *caldav_store.CalDavStore,
    tls_conn: *tls.nonblock.Connection,

    pub fn init(
        allocator: std.mem.Allocator,
        connection: socket.Connection,
        auth_backend: *auth.AuthBackend,
        store: *caldav_store.CalDavStore,
        tls_conn: *tls.nonblock.Connection,
    ) TlsCalDavSession {
        return .{
            .allocator = allocator,
            .connection = connection,
            .auth_backend = auth_backend,
            .store = store,
            .tls_conn = tls_conn,
        };
    }

    pub fn deinit(self: *TlsCalDavSession) void {
        if (self.username) |username| {
            self.allocator.free(username);
        }
    }

    fn sendTls(self: *TlsCalDavSession, data: []const u8) !void {
        var send_buf: [tls.output_buffer_len]u8 = undefined;
        const enc_result = try self.tls_conn.encrypt(data, &send_buf);
        var sent: usize = 0;
        while (sent < enc_result.ciphertext.len) {
            const n = try self.connection.write(enc_result.ciphertext[sent..]);
            if (n == 0) return error.ConnectionClosed;
            sent += n;
        }
    }

    /// Generate and send an Apple .mobileconfig profile for the email given in
    /// the `?email=` query parameter. Bundles IMAP/SMTP (Mail + Notes), CalDAV
    /// (Calendar) and CardDAV (Contacts) so one install configures everything.
    fn serveMobileconfig(self: *TlsCalDavSession, config: *const CalDavConfig, path: []const u8) !void {
        const query: ?[]const u8 = if (std.mem.indexOfScalar(u8, path, '?')) |q| path[q + 1 ..] else null;
        const email = autoconfig.extractQueryParam(query, "email") orelse {
            const msg = "Missing ?email=you@domain query parameter.\n";
            var hdr: [128]u8 = undefined;
            const resp = try std.fmt.bufPrint(&hdr, "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{msg.len});
            try self.sendTls(resp);
            try self.sendTls(msg);
            return;
        };

        // `?services=dav` emits a Calendar/Contacts-only profile (no IMAP/SMTP
        // email payload) so it cannot collide with an email account the user
        // already has configured. `?services=eas` emits a single unified
        // Exchange ActiveSync account (Mail+Contacts+Calendars+Notes with
        // toggles, like Google). Default includes the separate IMAP/CalDAV/
        // CardDAV payloads.
        const services = autoconfig.extractQueryParam(query, "services");
        const dav_only = services != null and std.mem.eql(u8, services.?, "dav");
        const eas_only = services != null and std.mem.eql(u8, services.?, "eas");

        const domain = autoconfig.extractDomainFromEmail(email) orelse "localhost";
        const ac = autoconfig.AutoconfigConfig{
            .hostname = config.public_hostname,
            .domain = domain,
            .imaps_port = config.imaps_port,
            .smtp_port = config.submission_port,
            .display_name = config.display_name,
            // EAS is a single account covering everything, so when requested it
            // replaces the separate IMAP/CalDAV/CardDAV payloads to avoid dupes.
            .enable_email = !dav_only and !eas_only,
            .enable_carddav = config.enable_carddav and !eas_only,
            .enable_caldav_profile = config.enable_caldav and !eas_only,
            .enable_eas = eas_only,
            .caldav_hostname = config.public_hostname,
            .caldav_port = config.ssl_port,
        };

        const profile = try autoconfig.generateAppleMobileconfig(self.allocator, ac, email);
        defer self.allocator.free(profile);

        var hdr: [256]u8 = undefined;
        const header = try std.fmt.bufPrint(
            &hdr,
            "HTTP/1.1 200 OK\r\n" ++
                "Content-Type: application/x-apple-aspen-config; charset=utf-8\r\n" ++
                "Content-Disposition: attachment; filename=\"mail.mobileconfig\"\r\n" ++
                "Content-Length: {d}\r\n" ++
                "Cache-Control: no-cache, no-store\r\n" ++
                "Connection: close\r\n\r\n",
            .{profile.len},
        );
        try self.sendTls(header);
        try self.sendTls(profile);
    }

    /// Dispatch an Exchange ActiveSync command. The full HTTP request (headers
    /// + WBXML body) is in `request`; the command and device id come from the
    /// query string. The response is WBXML written back over TLS.
    fn serveActiveSync(self: *TlsCalDavSession, path: []const u8, request: []const u8) !void {
        const query: ?[]const u8 = if (std.mem.indexOfScalar(u8, path, '?')) |q| path[q + 1 ..] else null;
        const cmd = autoconfig.extractQueryParam(query, "Cmd") orelse "";
        const device_id = autoconfig.extractQueryParam(query, "DeviceId") orelse "unknown";

        const body: []const u8 = if (std.mem.indexOf(u8, request, "\r\n\r\n")) |i| request[i + 4 ..] else "";

        const user = self.username orelse "";
        const local_part = if (std.mem.indexOfScalar(u8, user, '@')) |i| user[0..i] else user;

        var ctx = eas.Context{
            .allocator = self.allocator,
            .db = self.auth_backend.db,
            .store = self.store,
            .username = user,
            .local_part = local_part,
            .device_id = device_id,
        };

        const resp = try eas.dispatch(&ctx, cmd, body);
        defer if (resp.body.len > 0) self.allocator.free(resp.body);

        var hdr: [256]u8 = undefined;
        const header = try std.fmt.bufPrint(
            &hdr,
            "HTTP/1.1 {d} OK\r\n" ++
                "Content-Type: {s}\r\n" ++
                "Content-Length: {d}\r\n" ++
                "Connection: keep-alive\r\n\r\n",
            .{ resp.status, resp.content_type, resp.body.len },
        );
        try self.sendTls(header);
        if (resp.body.len > 0) try self.sendTls(resp.body);
    }

    /// Send authentication required response with Digest challenge over TLS
    fn sendTlsAuthRequired(self: *TlsCalDavSession) !void {
        const nonce = self.auth_backend.generateNonce() catch {
            // Fallback to Basic auth if nonce generation fails
            try self.sendTls("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"CalDAV/CardDAV Server\"\r\nContent-Length: 0\r\n\r\n");
            return;
        };
        // Note: Don't free nonce here - it's owned by the NonceManager and will be freed when invalidated

        var buf: [512]u8 = undefined;
        var fbs = io_compat.fixedBufferStream(&buf);
        const writer = fbs.writer();
        try writer.print(
            "HTTP/1.1 401 Unauthorized\r\n" ++
                "WWW-Authenticate: Digest realm=\"CalDAV/CardDAV Server\", nonce=\"{s}\", qop=\"auth\", algorithm=SHA-256\r\n" ++
                "WWW-Authenticate: Basic realm=\"CalDAV/CardDAV Server\"\r\n" ++
                "Content-Length: 0\r\n\r\n",
            .{nonce},
        );
        try self.sendTls(fbs.getWritten());
    }

    pub fn handleRequest(self: *TlsCalDavSession, config: *const CalDavConfig, request: []const u8) !bool {
        // Debug: log incoming request
        logger.info("CalDAV TLS received request ({d} bytes)", .{request.len});
        if (request.len > 0 and request.len < 500) {
            logger.info("CalDAV request: {s}", .{request});
        }

        // Parse HTTP request line
        var lines = std.mem.splitScalar(u8, request, '\n');
        const request_line = lines.next() orelse return false;

        var parts = std.mem.splitScalar(u8, request_line, ' ');
        const method_str = parts.next() orelse return false;
        const path = parts.next() orelse return false;

        const method = HttpMethod.fromString(method_str) orelse {
            try self.sendTls("HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n");
            return true;
        };

        // Handle .well-known autodiscovery
        // For PROPFIND, we need to authenticate and return proper discovery response
        // For GET, we can redirect
        const is_well_known_caldav = std.mem.startsWith(u8, path, "/.well-known/caldav");
        const is_well_known_carddav = std.mem.startsWith(u8, path, "/.well-known/carddav");

        if (is_well_known_caldav or is_well_known_carddav) {
            // For non-PROPFIND methods, just redirect
            if (method != .propfind) {
                if (is_well_known_caldav) {
                    try self.sendTls("HTTP/1.1 301 Moved Permanently\r\nLocation: /calendars/\r\nContent-Length: 0\r\n\r\n");
                } else {
                    try self.sendTls("HTTP/1.1 301 Moved Permanently\r\nLocation: /addressbooks/\r\nContent-Length: 0\r\n\r\n");
                }
                return true;
            }
            // For PROPFIND, fall through to authentication and handle below
        }

        // Serve the downloadable Apple configuration profile (unauthenticated:
        // it carries no secrets, only server names/ports, and the user must
        // supply their password when installing). One install configures Mail,
        // Notes, Calendar and Contacts together.
        if (method == .get and std.mem.startsWith(u8, path, "/email.mobileconfig")) {
            self.serveMobileconfig(config, path) catch |err| {
                logger.err("CalDAV: mobileconfig generation failed: {}", .{err});
                self.sendTls("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n") catch {};
            };
            return true;
        }

        // Exchange ActiveSync capability discovery. iOS issues OPTIONS to the
        // ActiveSync endpoint before setting up the account; answer it without
        // requiring auth so the client learns the supported versions/commands.
        if (method == .options and std.mem.startsWith(u8, path, "/Microsoft-Server-ActiveSync")) {
            try self.sendTls(
                "HTTP/1.1 200 OK\r\n" ++
                    "MS-Server-ActiveSync: 14.1\r\n" ++
                    "MS-ASProtocolVersions: 2.5,12.0,12.1,14.0,14.1\r\n" ++
                    "MS-ASProtocolCommands: Sync,SendMail,SmartForward,SmartReply,GetAttachment,FolderSync,FolderCreate,FolderDelete,FolderUpdate,MoveItems,GetItemEstimate,MeetingResponse,Search,Settings,Ping,ItemOperations,Provision,ResolveRecipients,ValidateCert\r\n" ++
                    "Public: OPTIONS,POST\r\n" ++
                    "Allow: OPTIONS,POST\r\n" ++
                    "Content-Length: 0\r\n\r\n",
            );
            return true;
        }

        // Check authentication (Digest or Basic Auth)
        if (!self.authenticated) {
            var auth_header: ?[]const u8 = null;
            while (lines.next()) |line| {
                const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
                if (trimmed.len == 0) break;

                if (std.mem.startsWith(u8, trimmed, "Authorization:")) {
                    auth_header = std.mem.trim(u8, trimmed[14..], &std.ascii.whitespace);
                    break;
                }
            }

            if (auth_header == null) {
                logger.info("CalDAV: No Authorization header, sending 401", .{});
                try self.sendTlsAuthRequired();
                return true;
            }

            logger.info("CalDAV: Got Authorization header: {s}", .{auth_header.?[0..@min(auth_header.?.len, 100)]});

            // Try Digest auth first, then fall back to Basic
            var validated_username: ?[]const u8 = null;

            if (std.mem.startsWith(u8, auth_header.?, "Digest ")) {
                logger.info("CalDAV: Attempting Digest auth", .{});
                validated_username = self.auth_backend.verifyDigestAuth(
                    auth_header.?,
                    method_str,
                    "CalDAV/CardDAV Server",
                ) catch |err| blk: {
                    logger.err("CalDAV TLS Digest authentication error: {}", .{err});
                    break :blk null;
                };
                if (validated_username == null) {
                    logger.warn("CalDAV: Digest auth returned null (failed verification)", .{});
                }
            }

            // Fall back to Basic auth if Digest didn't work
            if (validated_username == null and std.mem.startsWith(u8, auth_header.?, "Basic ")) {
                logger.info("CalDAV: Attempting Basic auth", .{});
                validated_username = self.auth_backend.verifyBasicAuth(auth_header.?) catch |err| blk: {
                    logger.err("CalDAV TLS Basic authentication error: {}", .{err});
                    break :blk null;
                };
            }

            if (validated_username) |username| {
                self.authenticated = true;
                self.username = username;
                logger.info("Successful CalDAV TLS authentication for user: {s}", .{username});
            } else {
                logger.warn("CalDAV: Authentication failed, sending 401", .{});
                try self.sendTlsAuthRequired();
                return true;
            }
        }

        // Exchange ActiveSync command dispatch (authenticated). All EAS commands
        // are POSTed to this endpoint with the command in the `?Cmd=` query.
        if (method == .post and std.mem.startsWith(u8, path, "/Microsoft-Server-ActiveSync")) {
            self.serveActiveSync(path, request) catch |err| {
                logger.err("ActiveSync dispatch failed: {}", .{err});
                self.sendTls("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n") catch {};
            };
            return true;
        }

        // Handle OPTIONS for CalDAV capabilities
        if (method == .options) {
            try self.sendTls(
                "HTTP/1.1 200 OK\r\n" ++
                    "DAV: 1, 2, 3, calendar-access, addressbook\r\n" ++
                    "Allow: OPTIONS, GET, HEAD, POST, PUT, DELETE, PROPFIND, PROPPATCH, MKCALENDAR, MKCOL, REPORT\r\n" ++
                    "Content-Length: 0\r\n\r\n",
            );
            return true;
        }

        // Handle PROPFIND
        if (method == .propfind) {
            // Get the authenticated username for principal URLs
            const username = self.username orelse "user";

            // Check path type for different responses
            const is_addressbook = std.mem.startsWith(u8, path, "/addressbooks");
            const is_principals = std.mem.startsWith(u8, path, "/principals");
            const is_well_known = std.mem.startsWith(u8, path, "/.well-known/");
            const is_root = std.mem.eql(u8, path, "/") or std.mem.eql(u8, path, "") or is_well_known;

            var response_body_buf: [4096]u8 = undefined;
            var response_fbs = io_compat.fixedBufferStream(&response_body_buf);
            const response_writer = response_fbs.writer();

            // TODO(security): `path` and `username` are written into the XML below
            // unescaped. The non-TLS PROPFIND path (handlePropfind) XML-escapes all
            // dynamic values; this TLS stub still uses a fixed-buffer writer. It
            // should be migrated to the ArrayList + appendXmlEscaped helpers used
            // elsewhere so `<` `>` `&` `"` `'` in the path/username are escaped.

            if (is_principals or is_root) {
                // Principal discovery - return current-user-principal, calendar-home-set, addressbook-home-set
                try response_writer.writeAll(
                    \\<?xml version="1.0" encoding="utf-8" ?>
                    \\<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:CARD="urn:ietf:params:xml:ns:carddav">
                    \\  <D:response>
                    \\    <D:href>
                );
                try response_writer.writeAll(path);
                try response_writer.writeAll(
                    \\</D:href>
                    \\    <D:propstat>
                    \\      <D:prop>
                    \\        <D:current-user-principal>
                    \\          <D:href>/principals/
                );
                try response_writer.writeAll(username);
                try response_writer.writeAll(
                    \\/</D:href>
                    \\        </D:current-user-principal>
                    \\        <C:calendar-home-set>
                    \\          <D:href>/calendars/
                );
                try response_writer.writeAll(username);
                try response_writer.writeAll(
                    \\/</D:href>
                    \\        </C:calendar-home-set>
                    \\        <CARD:addressbook-home-set>
                    \\          <D:href>/addressbooks/
                );
                try response_writer.writeAll(username);
                try response_writer.writeAll(
                    \\/</D:href>
                    \\        </CARD:addressbook-home-set>
                    \\        <D:resourcetype>
                    \\          <D:principal/>
                    \\        </D:resourcetype>
                    \\        <D:displayname>
                );
                try response_writer.writeAll(username);
                try response_writer.writeAll(
                    \\</D:displayname>
                    \\      </D:prop>
                    \\      <D:status>HTTP/1.1 200 OK</D:status>
                    \\    </D:propstat>
                    \\  </D:response>
                    \\</D:multistatus>
                );
            } else if (is_addressbook) {
                // CardDAV response for addressbooks
                try response_writer.writeAll(
                    \\<?xml version="1.0" encoding="utf-8" ?>
                    \\<D:multistatus xmlns:D="DAV:" xmlns:CARD="urn:ietf:params:xml:ns:carddav" xmlns:C="urn:ietf:params:xml:ns:caldav">
                    \\  <D:response>
                    \\    <D:href>
                );
                try response_writer.writeAll(path);
                try response_writer.writeAll(
                    \\</D:href>
                    \\    <D:propstat>
                    \\      <D:prop>
                    \\        <D:current-user-principal>
                    \\          <D:href>/principals/
                );
                try response_writer.writeAll(username);
                try response_writer.writeAll(
                    \\/</D:href>
                    \\        </D:current-user-principal>
                    \\        <D:resourcetype>
                    \\          <D:collection/>
                    \\          <CARD:addressbook/>
                    \\        </D:resourcetype>
                    \\        <D:displayname>Contacts</D:displayname>
                    \\        <CARD:supported-address-data>
                    \\          <CARD:address-data-type content-type="text/vcard" version="3.0"/>
                    \\          <CARD:address-data-type content-type="text/vcard" version="4.0"/>
                    \\        </CARD:supported-address-data>
                    \\        <CARD:addressbook-home-set>
                    \\          <D:href>/addressbooks/
                );
                try response_writer.writeAll(username);
                try response_writer.writeAll(
                    \\/</D:href>
                    \\        </CARD:addressbook-home-set>
                    \\      </D:prop>
                    \\      <D:status>HTTP/1.1 200 OK</D:status>
                    \\    </D:propstat>
                    \\  </D:response>
                    \\</D:multistatus>
                );
            } else {
                // CalDAV response for calendars
                try response_writer.writeAll(
                    \\<?xml version="1.0" encoding="utf-8" ?>
                    \\<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:CARD="urn:ietf:params:xml:ns:carddav">
                    \\  <D:response>
                    \\    <D:href>
                );
                try response_writer.writeAll(path);
                try response_writer.writeAll(
                    \\</D:href>
                    \\    <D:propstat>
                    \\      <D:prop>
                    \\        <D:current-user-principal>
                    \\          <D:href>/principals/
                );
                try response_writer.writeAll(username);
                try response_writer.writeAll(
                    \\/</D:href>
                    \\        </D:current-user-principal>
                    \\        <D:resourcetype>
                    \\          <D:collection/>
                    \\          <C:calendar/>
                    \\        </D:resourcetype>
                    \\        <D:displayname>Calendar</D:displayname>
                    \\        <C:supported-calendar-component-set>
                    \\          <C:comp name="VEVENT"/>
                    \\          <C:comp name="VTODO"/>
                    \\        </C:supported-calendar-component-set>
                    \\        <C:calendar-home-set>
                    \\          <D:href>/calendars/
                );
                try response_writer.writeAll(username);
                try response_writer.writeAll(
                    \\/</D:href>
                    \\        </C:calendar-home-set>
                    \\      </D:prop>
                    \\      <D:status>HTTP/1.1 200 OK</D:status>
                    \\    </D:propstat>
                    \\  </D:response>
                    \\</D:multistatus>
                );
            }

            const response_body = response_fbs.getWritten();

            var header_buf: [256]u8 = undefined;
            var fbs = io_compat.fixedBufferStream(&header_buf);
            const writer = fbs.writer();
            try writer.print(
                "HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml; charset=utf-8\r\nContent-Length: {d}\r\n\r\n",
                .{response_body.len},
            );

            try self.sendTls(fbs.getWritten());
            try self.sendTls(response_body);
            return true;
        }

        // Default: not implemented
        try self.sendTls("HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n");
        return true;
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
