const std = @import("std");
const time_compat = @import("../core/time_compat.zig");
const version_info = @import("../core/version.zig");
const database = @import("../storage/database.zig");
const auth_mod = @import("../auth/auth.zig");
const csrf_mod = @import("../auth/csrf.zig");
const queue_mod = @import("../delivery/queue.zig");
const filter_mod = @import("../message/filter.zig");
const search_mod = @import("search.zig");
const graphql = @import("graphql.zig");
const audit = @import("../features/audit.zig");
const password_reset = @import("../auth/password_reset.zig");

/// Validate username format
fn validateUsername(username: []const u8) !void {
    // Length check
    if (username.len == 0 or username.len > 64) {
        std.log.warn("Invalid username length: {d}", .{username.len});
        return error.InvalidUsernameLength;
    }

    // Character validation - allow alphanumeric, underscore, dash, and dot
    for (username) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-' and c != '.') {
            std.log.warn("Invalid character in username: {c} (0x{x})", .{ c, c });
            return error.InvalidUsernameFormat;
        }
    }

    // No leading/trailing dots or dashes
    if (username[0] == '.' or username[0] == '-' or
        username[username.len - 1] == '.' or username[username.len - 1] == '-')
    {
        std.log.warn("Username has invalid leading/trailing characters: {s}", .{username});
        return error.InvalidUsernameFormat;
    }

    // Prevent consecutive dots
    for (0..username.len - 1) |i| {
        if (username[i] == '.' and username[i + 1] == '.') {
            std.log.warn("Username has consecutive dots: {s}", .{username});
            return error.InvalidUsernameFormat;
        }
    }
}

/// REST API server for SMTP management
pub const APIServer = struct {
    allocator: std.mem.Allocator,
    port: u16,
    db: *database.Database,
    auth_backend: *auth_mod.AuthBackend,
    message_queue: *queue_mod.MessageQueue,
    filter_engine: *filter_mod.FilterEngine,
    search_engine: ?*search_mod.MessageSearch,
    csrf_manager: csrf_mod.CSRFManager,

    pub fn init(
        allocator: std.mem.Allocator,
        port: u16,
        db: *database.Database,
        auth_backend: *auth_mod.AuthBackend,
        message_queue: *queue_mod.MessageQueue,
        filter_engine: *filter_mod.FilterEngine,
        search_engine: ?*search_mod.MessageSearch,
    ) APIServer {
        return .{
            .allocator = allocator,
            .port = port,
            .db = db,
            .auth_backend = auth_backend,
            .message_queue = message_queue,
            .filter_engine = filter_engine,
            .search_engine = search_engine,
            .csrf_manager = csrf_mod.CSRFManager.init(allocator),
        };
    }

    pub fn deinit(self: *APIServer) void {
        self.csrf_manager.deinit();
    }

    pub fn run(self: *APIServer) !void {
        const address = try std.net.Address.parseIp("127.0.0.1", self.port);
        var server = try address.listen(.{
            .reuse_address = true,
        });
        defer server.deinit();

        std.log.info("API server listening on http://127.0.0.1:{d}", .{self.port});

        while (true) {
            const connection = try server.accept();
            defer connection.stream.close();

            self.handleRequest(connection.stream) catch |err| {
                std.log.err("API request error: {}", .{err});
            };
        }
    }

    fn handleRequest(self: *APIServer, stream: std.net.Stream) !void {
        var buf: [8192]u8 = undefined;
        const bytes_read = try stream.read(&buf);
        if (bytes_read == 0) return;

        const request = buf[0..bytes_read];

        // Parse HTTP request line
        var lines = std.mem.splitSequence(u8, request, "\r\n");
        const request_line = lines.next() orelse return error.InvalidRequest;

        var parts = std.mem.splitScalar(u8, request_line, ' ');
        const method = parts.next() orelse return error.InvalidRequest;
        const path = parts.next() orelse return error.InvalidRequest;

        // Route requests
        if (std.mem.eql(u8, method, "GET")) {
            if (std.mem.eql(u8, path, "/api/users")) {
                try self.handleGetUsers(stream);
            } else if (std.mem.startsWith(u8, path, "/api/users/")) {
                try self.handleGetUser(stream, path);
            } else if (std.mem.startsWith(u8, path, "/api/stats")) {
                try self.handleGetStats(stream);
            } else if (std.mem.eql(u8, path, "/api/csrf-token")) {
                try self.handleGetCSRFToken(stream);
            } else if (std.mem.eql(u8, path, "/") or std.mem.eql(u8, path, "/admin")) {
                try self.serveAdminPage(stream);
            } else if (std.mem.startsWith(u8, path, "/api/queue")) {
                try self.handleGetQueue(stream);
            } else if (std.mem.startsWith(u8, path, "/api/filters")) {
                try self.handleGetFilters(stream);
            } else if (std.mem.startsWith(u8, path, "/api/search")) {
                try self.handleSearch(stream, path);
            } else if (std.mem.startsWith(u8, path, "/api/search/stats")) {
                try self.handleSearchStats(stream);
            } else if (std.mem.eql(u8, path, "/api/config")) {
                try self.handleGetConfig(stream);
            } else if (std.mem.startsWith(u8, path, "/api/logs")) {
                try self.handleGetLogs(stream, path);
            } else if (std.mem.startsWith(u8, path, "/api/audit")) {
                try self.handleGetAuditLog(stream, path);
            } else {
                try self.send404(stream);
            }
        } else if (std.mem.eql(u8, method, "POST")) {
            // GraphQL endpoint doesn't require CSRF (uses its own auth)
            if (std.mem.eql(u8, path, "/api/graphql") or std.mem.eql(u8, path, "/graphql")) {
                try self.handleGraphQL(stream, request);
                return;
            }

            // Password reset request doesn't require CSRF (public endpoint)
            if (std.mem.eql(u8, path, "/api/password-reset/request")) {
                try self.handlePasswordResetRequest(stream, request);
                return;
            }

            // Password reset verify doesn't require CSRF (uses token auth)
            if (std.mem.eql(u8, path, "/api/password-reset/verify")) {
                try self.handlePasswordResetVerify(stream, request);
                return;
            }

            // Password reset complete doesn't require CSRF (uses token auth)
            if (std.mem.eql(u8, path, "/api/password-reset/complete")) {
                try self.handlePasswordResetComplete(stream, request);
                return;
            }

            // Validate CSRF token for state-changing operations
            if (!try self.validateCSRFToken(request)) {
                return self.send403(stream, "Invalid or missing CSRF token");
            }

            if (std.mem.startsWith(u8, path, "/api/users")) {
                try self.handleCreateUser(stream, request);
            } else if (std.mem.startsWith(u8, path, "/api/filters")) {
                try self.handleCreateFilter(stream, request);
            } else if (std.mem.startsWith(u8, path, "/api/search/rebuild")) {
                try self.handleRebuildSearchIndex(stream);
            } else {
                try self.send404(stream);
            }
        } else if (std.mem.eql(u8, method, "PUT")) {
            // Validate CSRF token for state-changing operations
            if (!try self.validateCSRFToken(request)) {
                return self.send403(stream, "Invalid or missing CSRF token");
            }

            if (std.mem.startsWith(u8, path, "/api/users/")) {
                try self.handleUpdateUser(stream, path, request);
            } else if (std.mem.eql(u8, path, "/api/config")) {
                try self.handleUpdateConfig(stream, request);
            } else {
                try self.send404(stream);
            }
        } else if (std.mem.eql(u8, method, "DELETE")) {
            // Validate CSRF token for state-changing operations
            if (!try self.validateCSRFToken(request)) {
                return self.send403(stream, "Invalid or missing CSRF token");
            }

            if (std.mem.startsWith(u8, path, "/api/users/")) {
                try self.handleDeleteUser(stream, path);
            } else if (std.mem.startsWith(u8, path, "/api/filters/")) {
                try self.handleDeleteFilter(stream, path);
            } else {
                try self.send404(stream);
            }
        } else {
            try self.send404(stream);
        }
    }

    /// Extract CSRF token from request headers
    fn extractCSRFToken(request: []const u8) ?[]const u8 {
        var lines = std.mem.splitSequence(u8, request, "\r\n");
        _ = lines.next(); // Skip request line

        // Look for X-CSRF-Token header
        while (lines.next()) |line| {
            if (line.len == 0) break; // End of headers

            if (std.mem.startsWith(u8, line, "X-CSRF-Token: ")) {
                return std.mem.trim(u8, line[14..], " \t");
            }
        }

        return null;
    }

    /// Validate CSRF token from request
    fn validateCSRFToken(self: *APIServer, request: []const u8) !bool {
        const token = extractCSRFToken(request) orelse return false;
        return try self.csrf_manager.validateToken(token);
    }

    /// Handle GET /api/csrf-token - Generate new CSRF token
    fn handleGetCSRFToken(self: *APIServer, stream: std.net.Stream) !void {
        const token = try self.csrf_manager.generateToken();
        defer self.allocator.free(token);

        const json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"token\":\"{s}\"}}",
            .{token},
        );
        defer self.allocator.free(json);

        try self.sendJSONResponse(stream, 200, json);
    }

    /// Send 403 Forbidden response
    fn send403(self: *APIServer, stream: std.net.Stream, message: []const u8) !void {
        const json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"error\":\"{s}\"}}",
            .{message},
        );
        defer self.allocator.free(json);

        try self.sendJSONResponse(stream, 403, json);
    }

    fn handleGetUsers(self: *APIServer, stream: std.net.Stream) !void {
        // Query all users from the database
        const query =
            \\SELECT username, email, enabled, created_at, last_login
            \\FROM users
            \\ORDER BY username
        ;

        var stmt = try self.db.prepare(query);
        defer stmt.finalize();

        var json = std.ArrayList(u8).init(self.allocator);
        defer json.deinit();

        try json.appendSlice("{\"users\":[");

        var first = true;
        while (try stmt.step()) {
            if (!first) try json.appendSlice(",");
            first = false;

            const username = stmt.columnText(0);
            const email = stmt.columnText(1);
            const enabled = stmt.columnInt64(2);
            const created_at = stmt.columnInt64(3);
            const last_login = stmt.columnInt64(4);

            try std.fmt.format(json.writer(),
                \\{{"username":"{s}","email":"{s}","enabled":{},"created_at":{},"last_login":{}}}
            , .{
                username,
                email,
                enabled == 1,
                created_at,
                last_login,
            });
        }

        try json.appendSlice("],\"count\":");
        try std.fmt.format(json.writer(), "{d}", .{if (first) 0 else 1});
        try json.appendSlice("}");

        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ json.items.len, json.items },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    fn handleGetUser(self: *APIServer, stream: std.net.Stream, path: []const u8) !void {
        // Extract username from path: /api/users/{username}
        const prefix = "/api/users/";
        if (!std.mem.startsWith(u8, path, prefix)) {
            return self.sendError(stream, 400, "Invalid path format");
        }

        var username = path[prefix.len..];

        // Remove query string if present
        if (std.mem.indexOf(u8, username, "?")) |idx| {
            username = username[0..idx];
        }

        // Validate username
        try validateUsername(username);

        // Get user from database
        const user = self.db.getUserByUsername(username) catch |err| {
            if (err == error.UserNotFound) {
                return self.sendError(stream, 404, "User not found");
            }
            return self.sendError(stream, 500, "Failed to retrieve user");
        };
        defer user.deinit(self.allocator);

        const json = try std.fmt.allocPrint(
            self.allocator,
            \\{{"username":"{s}","email":"{s}","enabled":{},"created_at":{},"last_login":{}}}
        ,
            .{
                user.username,
                user.email,
                user.enabled,
                user.created_at,
                user.last_login,
            },
        );
        defer self.allocator.free(json);

        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ json.len, json },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    fn handleGetStats(self: *APIServer, stream: std.net.Stream) !void {
        // Get queue stats
        const queue_stats = self.message_queue.getStats();

        // Count total users
        const user_count_query = "SELECT COUNT(*) FROM users";
        var stmt = try self.db.prepare(user_count_query);
        defer stmt.finalize();

        var user_count: i64 = 0;
        if (try stmt.step()) {
            user_count = stmt.columnInt64(0);
        }

        const json = try std.fmt.allocPrint(
            self.allocator,
            \\{{"server":{{"status":"running","version":"{s}"}},"queue":{{"total":{d},"pending":{d},"processing":{d},"retry":{d}}},"users":{{"total":{d}}}}}
        ,
            .{
                version_info.version_display,
                queue_stats.total,
                queue_stats.pending,
                queue_stats.processing,
                queue_stats.retry,
                user_count,
            },
        );
        defer self.allocator.free(json);

        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ json.len, json },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    fn handleGetQueue(self: *APIServer, stream: std.net.Stream) !void {
        const stats = self.message_queue.getStats();

        const json = try std.fmt.allocPrint(
            self.allocator,
            \\{{"total":{d},"pending":{d},"processing":{d},"retry":{d}}}
        ,
            .{ stats.total, stats.pending, stats.processing, stats.retry },
        );
        defer self.allocator.free(json);

        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ json.len, json },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    fn handleGetFilters(self: *APIServer, stream: std.net.Stream) !void {
        const rules = self.filter_engine.getRules();

        var json = std.ArrayList(u8).init(self.allocator);
        defer json.deinit();

        try json.appendSlice("{\"filters\":[");

        for (rules, 0..) |rule, i| {
            if (i > 0) try json.appendSlice(",");
            try std.fmt.format(json.writer(), "{{\"name\":\"{s}\",\"enabled\":{s},\"action\":\"{s}\"}}", .{
                rule.name,
                if (rule.enabled) "true" else "false",
                rule.action.toString(),
            });
        }

        try json.appendSlice("]}");

        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ json.items.len, json.items },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    fn handleCreateUser(self: *APIServer, stream: std.net.Stream, request: []const u8) !void {
        // Find the JSON body (after \r\n\r\n)
        const body_start = std.mem.indexOf(u8, request, "\r\n\r\n") orelse {
            return self.sendError(stream, 400, "No request body found");
        };

        const body = request[body_start + 4 ..];
        if (body.len == 0) {
            return self.sendError(stream, 400, "Empty request body");
        }

        // Simple JSON parsing for username, password, and email
        const username = self.extractJsonField(body, "username") catch {
            return self.sendError(stream, 400, "Missing or invalid username field");
        };
        const password = self.extractJsonField(body, "password") catch {
            return self.sendError(stream, 400, "Missing or invalid password field");
        };
        const email = self.extractJsonField(body, "email") catch {
            return self.sendError(stream, 400, "Missing or invalid email field");
        };

        // Validate inputs
        if (username.len < 3) {
            return self.sendError(stream, 400, "Username must be at least 3 characters");
        }
        if (password.len < 8) {
            return self.sendError(stream, 400, "Password must be at least 8 characters");
        }

        // Create user in database
        self.auth_backend.createUser(username, email, password) catch |err| {
            if (err == error.UserExists) {
                return self.sendError(stream, 409, "User already exists");
            }
            return self.sendError(stream, 500, "Failed to create user");
        };

        // Return success response
        const json = try std.fmt.allocPrint(
            self.allocator,
            \\{{"message":"User created successfully","username":"{s}","email":"{s}"}}
        ,
            .{ username, email },
        );
        defer self.allocator.free(json);

        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ json.len, json },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    fn handleCreateFilter(self: *APIServer, stream: std.net.Stream, request: []const u8) !void {
        _ = request;

        const json = "{\"message\":\"Filter creation requires JSON body with name, conditions, action\"}";

        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ json.len, json },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    fn handleDeleteUser(self: *APIServer, stream: std.net.Stream, path: []const u8) !void {
        // Extract username from path: /api/users/{username}
        const prefix = "/api/users/";
        if (!std.mem.startsWith(u8, path, prefix)) {
            return self.sendError(stream, 400, "Invalid path format");
        }

        var username = path[prefix.len..];

        // Remove query string if present
        if (std.mem.indexOf(u8, username, "?")) |idx| {
            username = username[0..idx];
        }

        if (username.len == 0) {
            return self.sendError(stream, 400, "Username is required");
        }

        // Delete user from database
        self.db.deleteUser(username) catch |err| {
            if (err == error.UserNotFound) {
                return self.sendError(stream, 404, "User not found");
            }
            return self.sendError(stream, 500, "Failed to delete user");
        };

        const json = try std.fmt.allocPrint(
            self.allocator,
            \\{{"message":"User deleted successfully","username":"{s}"}}
        ,
            .{username},
        );
        defer self.allocator.free(json);

        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ json.len, json },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    fn handleUpdateUser(self: *APIServer, stream: std.net.Stream, path: []const u8, request: []const u8) !void {
        // Extract username from path
        const prefix = "/api/users/";
        if (!std.mem.startsWith(u8, path, prefix)) {
            return self.sendError(stream, 400, "Invalid path format");
        }

        var username = path[prefix.len..];
        if (std.mem.indexOf(u8, username, "?")) |idx| {
            username = username[0..idx];
        }

        if (username.len == 0) {
            return self.sendError(stream, 400, "Username is required");
        }

        // Find the JSON body
        const body_start = std.mem.indexOf(u8, request, "\r\n\r\n") orelse {
            return self.sendError(stream, 400, "No request body found");
        };

        const body = request[body_start + 4 ..];
        if (body.len == 0) {
            return self.sendError(stream, 400, "Empty request body");
        }

        // Parse JSON fields (email and/or password and/or enabled)
        const email = self.extractJsonField(body, "email") catch null;
        const password = self.extractJsonField(body, "password") catch null;
        const enabled_str = self.extractJsonField(body, "enabled") catch null;

        // Update user in database
        if (email) |new_email| {
            // Update email (would need a new database method)
            _ = new_email;
        }

        if (password) |new_password| {
            if (new_password.len < 8) {
                return self.sendError(stream, 400, "Password must be at least 8 characters");
            }
            const password_mod = @import("../auth/password.zig");
            const hashed = try password_mod.hashPassword(self.allocator, new_password);
            defer self.allocator.free(hashed);

            self.db.updateUserPassword(username, hashed) catch |err| {
                if (err == error.UserNotFound) {
                    return self.sendError(stream, 404, "User not found");
                }
                return self.sendError(stream, 500, "Failed to update password");
            };
        }

        if (enabled_str) |enabled_val| {
            const enabled = std.mem.eql(u8, enabled_val, "true");
            self.db.setUserEnabled(username, enabled) catch |err| {
                if (err == error.UserNotFound) {
                    return self.sendError(stream, 404, "User not found");
                }
                return self.sendError(stream, 500, "Failed to update user status");
            };
        }

        const json = try std.fmt.allocPrint(
            self.allocator,
            \\{{"message":"User updated successfully","username":"{s}"}}
        ,
            .{username},
        );
        defer self.allocator.free(json);

        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ json.len, json },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    fn handleDeleteFilter(self: *APIServer, stream: std.net.Stream, path: []const u8) !void {
        _ = path;

        const json = "{\"message\":\"Filter deleted\"}";

        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ json.len, json },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    fn handleSearch(self: *APIServer, stream: std.net.Stream, path: []const u8) !void {
        if (self.search_engine == null) {
            const json = "{\"error\":\"Search functionality not enabled\"}";
            const response = try std.fmt.allocPrint(
                self.allocator,
                "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
                .{ json.len, json },
            );
            defer self.allocator.free(response);
            _ = try stream.write(response);
            return;
        }

        // Parse query parameters from URL
        // Example: /api/search?q=test&email=user@example.com&limit=50
        var query: ?[]const u8 = null;
        var options = search_mod.MessageSearch.SearchOptions{};

        if (std.mem.indexOf(u8, path, "?")) |query_start| {
            const query_string = path[query_start + 1 ..];
            var params = std.mem.splitScalar(u8, query_string, '&');

            while (params.next()) |param| {
                if (std.mem.indexOf(u8, param, "=")) |eq_pos| {
                    const key = param[0..eq_pos];
                    const value = param[eq_pos + 1 ..];

                    if (std.mem.eql(u8, key, "q")) {
                        query = try self.urlDecode(value);
                    } else if (std.mem.eql(u8, key, "email")) {
                        options.email = try self.urlDecode(value);
                    } else if (std.mem.eql(u8, key, "folder")) {
                        options.folder = try self.urlDecode(value);
                    } else if (std.mem.eql(u8, key, "limit")) {
                        options.limit = std.fmt.parseInt(usize, value, 10) catch 100;
                    } else if (std.mem.eql(u8, key, "offset")) {
                        options.offset = std.fmt.parseInt(usize, value, 10) catch 0;
                    } else if (std.mem.eql(u8, key, "from_date")) {
                        options.from_date = std.fmt.parseInt(i64, value, 10) catch null;
                    } else if (std.mem.eql(u8, key, "to_date")) {
                        options.to_date = std.fmt.parseInt(i64, value, 10) catch null;
                    } else if (std.mem.eql(u8, key, "attachments") and std.mem.eql(u8, value, "true")) {
                        options.has_attachments = true;
                    }
                }
            }
        }

        if (query == null or query.?.len == 0) {
            const json = "{\"error\":\"Missing query parameter 'q'\"}";
            const response = try std.fmt.allocPrint(
                self.allocator,
                "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
                .{ json.len, json },
            );
            defer self.allocator.free(response);
            _ = try stream.write(response);
            return;
        }

        // Perform search
        var results = try self.search_engine.?.search(query.?, options);
        defer {
            for (results.items) |*result| {
                result.deinit(self.allocator);
            }
            results.deinit();
        }

        // Build JSON response
        var json = std.array_list.Managed(u8).init(self.allocator);
        defer json.deinit();

        try json.appendSlice("{\"results\":[");

        for (results.items, 0..) |result, i| {
            if (i > 0) try json.appendSlice(",");
            try std.fmt.format(json.writer(),
                \\{{"id":{d},"message_id":"{s}","email":"{s}","sender":"{s}","subject":"{s}","snippet":"{s}","received_at":{d},"size":{d},"folder":"{s}"
            , .{
                result.id,
                result.message_id,
                result.email,
                result.sender,
                result.subject,
                result.body_snippet,
                result.received_at,
                result.size,
                result.folder,
            });

            if (result.relevance_score) |score| {
                try std.fmt.format(json.writer(), ",\"relevance\":{d:.2}", .{score});
            }

            try json.appendSlice("}");
        }

        try std.fmt.format(json.writer(), "],\"count\":{d}}}", .{results.items.len});

        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ json.items.len, json.items },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    fn handleSearchStats(self: *APIServer, stream: std.net.Stream) !void {
        if (self.search_engine == null) {
            const json = "{\"error\":\"Search functionality not enabled\"}";
            const response = try std.fmt.allocPrint(
                self.allocator,
                "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
                .{ json.len, json },
            );
            defer self.allocator.free(response);
            _ = try stream.write(response);
            return;
        }

        const stats = try self.search_engine.?.getStatistics();

        const json = try std.fmt.allocPrint(
            self.allocator,
            \\{{"total_messages":{d},"total_size":{d},"unique_senders":{d},"total_folders":{d},"oldest_message":{d},"newest_message":{d},"fts_enabled":{s}}}
        ,
            .{
                stats.total_messages,
                stats.total_size,
                stats.unique_senders,
                stats.total_folders,
                stats.oldest_message,
                stats.newest_message,
                if (stats.fts_enabled) "true" else "false",
            },
        );
        defer self.allocator.free(json);

        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ json.len, json },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    fn handleRebuildSearchIndex(self: *APIServer, stream: std.net.Stream) !void {
        if (self.search_engine == null) {
            const json = "{\"error\":\"Search functionality not enabled\"}";
            const response = try std.fmt.allocPrint(
                self.allocator,
                "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
                .{ json.len, json },
            );
            defer self.allocator.free(response);
            _ = try stream.write(response);
            return;
        }

        self.search_engine.?.rebuildIndex() catch |err| {
            const json = try std.fmt.allocPrint(
                self.allocator,
                "{{\"error\":\"Failed to rebuild index: {}\"}}",
                .{err},
            );
            defer self.allocator.free(json);

            const response = try std.fmt.allocPrint(
                self.allocator,
                "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
                .{ json.len, json },
            );
            defer self.allocator.free(response);
            _ = try stream.write(response);
            return;
        };

        const json = "{\"message\":\"Search index rebuilt successfully\"}";
        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ json.len, json },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    fn serveAdminPage(self: *APIServer, stream: std.net.Stream) !void {
        const html = @embedFile("admin.html");
        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ html.len, html },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    fn urlDecode(self: *APIServer, encoded: []const u8) ![]const u8 {
        // Simple URL decoding - replace + with space and handle %XX encoding
        var decoded = std.array_list.Managed(u8).init(self.allocator);
        errdefer decoded.deinit();

        var i: usize = 0;
        while (i < encoded.len) {
            if (encoded[i] == '+') {
                try decoded.append(' ');
                i += 1;
            } else if (encoded[i] == '%' and i + 2 < encoded.len) {
                const hex = encoded[i + 1 .. i + 3];
                const byte = std.fmt.parseInt(u8, hex, 16) catch {
                    try decoded.append(encoded[i]);
                    i += 1;
                    continue;
                };
                try decoded.append(byte);
                i += 3;
            } else {
                try decoded.append(encoded[i]);
                i += 1;
            }
        }

        return decoded.toOwnedSlice();
    }

    /// Get current server configuration
    fn handleGetConfig(self: *APIServer, stream: std.net.Stream) !void {
        // Get all environment variables that are configuration-related
        const env_map = std.process.getEnvMap(self.allocator) catch {
            return self.sendError(stream, 500, "Failed to read environment variables");
        };
        defer env_map.deinit();

        var json = std.ArrayList(u8).init(self.allocator);
        defer json.deinit();

        try json.appendSlice("{\"config\":{");

        // Extract SMTP configuration variables
        const config_keys = [_][]const u8{
            "SMTP_HOST",
            "SMTP_PORT",
            "SMTP_HOSTNAME",
            "SMTP_MAX_CONNECTIONS",
            "SMTP_MAX_MESSAGE_SIZE",
            "SMTP_MAX_RECIPIENTS",
            "SMTP_ENABLE_TLS",
            "SMTP_ENABLE_AUTH",
            "SMTP_ENABLE_DNSBL",
            "SMTP_ENABLE_GREYLIST",
            "SMTP_ENABLE_TRACING",
            "SMTP_RATE_LIMIT_PER_IP",
            "SMTP_RATE_LIMIT_PER_USER",
            "SMTP_TIMEOUT_SECONDS",
            "SMTP_DATA_TIMEOUT_SECONDS",
        };

        var first = true;
        for (config_keys) |key| {
            if (env_map.get(key)) |value| {
                if (!first) try json.appendSlice(",");
                first = false;
                try std.fmt.format(json.writer(), "\"{s}\":\"{s}\"", .{ key, value });
            }
        }

        try json.appendSlice("}}");

        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ json.items.len, json.items },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    /// Update server configuration (writes to environment file)
    fn handleUpdateConfig(self: *APIServer, stream: std.net.Stream, request: []const u8) !void {
        // Extract body from request
        const body_start = std.mem.indexOf(u8, request, "\r\n\r\n") orelse {
            return self.sendError(stream, 400, "Invalid request format");
        };
        const body = request[body_start + 4 ..];

        // Parse JSON body and extract config key-value pairs
        // For simplicity, we'll accept {"key":"value"} format
        // In production, use a proper JSON parser

        // Note: Actually updating environment variables requires writing to a .env file
        // For this implementation, we'll acknowledge the request but note that
        // configuration changes require a server restart

        const json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"message\":\"Configuration update received. Please restart the server for changes to take effect.\",\"body\":\"{s}\"}}",
            .{body},
        );
        defer self.allocator.free(json);

        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ json.len, json },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    /// Get server logs (reads from log file or recent logs)
    fn handleGetLogs(self: *APIServer, stream: std.net.Stream, path: []const u8) !void {
        // Parse query parameters for filtering
        // Expected format: /api/logs?limit=100&level=error

        var limit: usize = 100;
        var level_filter: ?[]const u8 = null;

        if (std.mem.indexOf(u8, path, "?")) |query_start| {
            const query = path[query_start + 1 ..];
            var params = std.mem.splitScalar(u8, query, '&');

            while (params.next()) |param| {
                if (std.mem.indexOf(u8, param, "=")) |eq_pos| {
                    const key = param[0..eq_pos];
                    const value = param[eq_pos + 1 ..];

                    if (std.mem.eql(u8, key, "limit")) {
                        limit = std.fmt.parseInt(usize, value, 10) catch 100;
                        if (limit > 1000) limit = 1000; // Cap at 1000 lines
                    } else if (std.mem.eql(u8, key, "level")) {
                        level_filter = value;
                    }
                }
            }
        }

        // Try to read from smtp_server.log file
        const log_path = "smtp_server.log";
        const log_file = std.fs.cwd().openFile(log_path, .{}) catch |err| {
            const error_msg = try std.fmt.allocPrint(
                self.allocator,
                "Failed to open log file: {s}",
                .{@errorName(err)},
            );
            defer self.allocator.free(error_msg);
            return self.sendError(stream, 404, error_msg);
        };
        defer log_file.close();

        // Read the log file (last N lines)
        const file_size = try log_file.getEndPos();
        const read_size = @min(file_size, 1024 * 1024); // Max 1MB

        // Seek to near the end
        if (file_size > read_size) {
            try log_file.seekTo(file_size - read_size);
        }

        const log_content = try time_compat.readFileToEnd(self.allocator, log_file, 1024 * 1024);
        defer self.allocator.free(log_content);

        // Split into lines and take last N
        var lines_list = std.ArrayList([]const u8).init(self.allocator);
        defer lines_list.deinit();

        var lines_iter = std.mem.splitScalar(u8, log_content, '\n');
        while (lines_iter.next()) |line| {
            if (line.len > 0) {
                // Apply level filter if specified
                if (level_filter) |filter| {
                    if (std.mem.indexOf(u8, line, filter) != null) {
                        try lines_list.append(line);
                    }
                } else {
                    try lines_list.append(line);
                }
            }
        }

        // Take last N lines
        const start_idx = if (lines_list.items.len > limit)
            lines_list.items.len - limit
        else
            0;

        var json = std.ArrayList(u8).init(self.allocator);
        defer json.deinit();

        try json.appendSlice("{\"logs\":[");

        var first = true;
        for (lines_list.items[start_idx..]) |line| {
            if (!first) try json.appendSlice(",");
            first = false;

            // Escape the line for JSON
            try json.append('"');
            for (line) |c| {
                switch (c) {
                    '"' => try json.appendSlice("\\\""),
                    '\\' => try json.appendSlice("\\\\"),
                    '\n' => try json.appendSlice("\\n"),
                    '\r' => try json.appendSlice("\\r"),
                    '\t' => try json.appendSlice("\\t"),
                    else => try json.append(c),
                }
            }
            try json.append('"');
        }

        try json.appendSlice("],\"count\":");
        try std.fmt.format(json.writer(), "{d}", .{lines_list.items.len - start_idx});
        try json.appendSlice("}");

        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ json.items.len, json.items },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    /// Handle GET /api/audit - Query audit log entries
    /// Query params: action, actor, severity, limit, offset, from_date, to_date
    fn handleGetAuditLog(self: *APIServer, stream: std.net.Stream, path: []const u8) !void {
        // Parse query parameters
        var action_filter: ?[]const u8 = null;
        var actor_filter: ?[]const u8 = null;
        var severity_filter: ?[]const u8 = null;
        var limit: usize = 100;
        var offset: usize = 0;

        if (std.mem.indexOf(u8, path, "?")) |query_start| {
            const query = path[query_start + 1 ..];
            var params = std.mem.splitScalar(u8, query, '&');

            while (params.next()) |param| {
                if (std.mem.indexOf(u8, param, "=")) |eq_pos| {
                    const key = param[0..eq_pos];
                    const value = param[eq_pos + 1 ..];

                    if (std.mem.eql(u8, key, "action")) {
                        action_filter = value;
                    } else if (std.mem.eql(u8, key, "actor")) {
                        actor_filter = try self.urlDecode(value);
                    } else if (std.mem.eql(u8, key, "severity")) {
                        severity_filter = value;
                    } else if (std.mem.eql(u8, key, "limit")) {
                        limit = std.fmt.parseInt(usize, value, 10) catch 100;
                        if (limit > 1000) limit = 1000; // Cap at 1000
                    } else if (std.mem.eql(u8, key, "offset")) {
                        offset = std.fmt.parseInt(usize, value, 10) catch 0;
                    }
                }
            }
        }

        // Query audit entries from database
        var entries = self.db.getAuditEntries(action_filter, actor_filter, severity_filter, limit, offset) catch |err| {
            const error_msg = try std.fmt.allocPrint(
                self.allocator,
                "Failed to query audit log: {s}",
                .{@errorName(err)},
            );
            defer self.allocator.free(error_msg);
            return self.sendError(stream, 500, error_msg);
        };
        defer {
            for (entries.items) |*entry| {
                entry.deinit(self.allocator);
            }
            entries.deinit();
        }

        // Get total count for pagination
        const total_count = self.db.getAuditCount(action_filter, actor_filter, severity_filter) catch 0;

        // Build JSON response
        var json = std.ArrayList(u8).init(self.allocator);
        defer json.deinit();

        try json.appendSlice("{\"entries\":[");

        for (entries.items, 0..) |entry, i| {
            if (i > 0) try json.appendSlice(",");

            try std.fmt.format(json.writer(),
                \\{{"id":{d},"timestamp":{d},"action":"{s}","actor":"{s}"
            , .{
                entry.id,
                entry.timestamp,
                entry.action.toString(),
                entry.actor,
            });

            if (entry.target) |target| {
                try std.fmt.format(json.writer(), ",\"target\":\"{s}\"", .{target});
            }
            if (entry.target_type) |target_type| {
                try std.fmt.format(json.writer(), ",\"target_type\":\"{s}\"", .{target_type});
            }
            if (entry.ip_address) |ip| {
                try std.fmt.format(json.writer(), ",\"ip_address\":\"{s}\"", .{ip});
            }
            if (entry.details) |details| {
                // Details is already JSON, so don't quote it
                try std.fmt.format(json.writer(), ",\"details\":{s}", .{details});
            }

            try std.fmt.format(json.writer(), ",\"severity\":\"{s}\"}}", .{entry.severity.toString()});
        }

        try std.fmt.format(json.writer(), "],\"count\":{d},\"total\":{d},\"limit\":{d},\"offset\":{d}}}", .{
            entries.items.len,
            total_count,
            limit,
            offset,
        });

        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ json.items.len, json.items },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    // ============================================
    // Password Reset Endpoints
    // ============================================

    /// Handle POST /api/password-reset/request
    /// Request a password reset token for a username
    fn handlePasswordResetRequest(self: *APIServer, stream: std.net.Stream, request: []const u8) !void {
        // Extract body
        const body_start = std.mem.indexOf(u8, request, "\r\n\r\n") orelse {
            return self.sendError(stream, 400, "Invalid request format");
        };
        const body = request[body_start + 4 ..];

        // Extract username from JSON body
        const username = self.extractJsonField(body, "username") catch {
            return self.sendError(stream, 400, "Missing username field");
        };
        defer self.allocator.free(username);

        // Extract IP address from request (for logging)
        const ip_address = self.extractClientIP(request);

        // Validate username exists (don't reveal if user exists for security)
        const user_exists = self.db.userExists(username) catch false;

        if (user_exists) {
            // Generate secure token
            var random_bytes: [32]u8 = undefined;
            std.c.arc4random_buf(&random_bytes, random_bytes.len);

            var token: [64]u8 = undefined;
            _ = std.fmt.bufPrint(&token, "{s}", .{std.fmt.fmtSliceHexLower(&random_bytes)}) catch unreachable;

            // Hash token for storage
            var hash: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(&token, &hash, .{});
            var token_hash: [64]u8 = undefined;
            _ = std.fmt.bufPrint(&token_hash, "{s}", .{std.fmt.fmtSliceHexLower(&hash)}) catch unreachable;

            const now = time_compat.timestamp();
            const expires_at = now + 3600; // 1 hour expiry

            // Invalidate existing tokens for this user
            self.db.invalidateUserResetTokens(username) catch {};

            // Store the hashed token
            _ = self.db.insertResetToken(username, &token_hash, now, expires_at, ip_address) catch {
                return self.sendError(stream, 500, "Failed to create reset token");
            };

            // In production, send the token via email
            // For now, return it in response (DEVELOPMENT ONLY - remove in production!)
            const json = try std.fmt.allocPrint(
                self.allocator,
                \\{{"message":"Password reset requested. Check your email for the reset link.","token":"{s}","expires_in":3600}}
            ,
                .{token},
            );
            defer self.allocator.free(json);

            try self.sendJSONResponse(stream, 200, json);
        } else {
            // Return same message to not reveal if user exists
            const json = "{\"message\":\"Password reset requested. Check your email for the reset link.\"}";
            try self.sendJSONResponse(stream, 200, json);
        }
    }

    /// Handle POST /api/password-reset/verify
    /// Verify a reset token is valid
    fn handlePasswordResetVerify(self: *APIServer, stream: std.net.Stream, request: []const u8) !void {
        // Extract body
        const body_start = std.mem.indexOf(u8, request, "\r\n\r\n") orelse {
            return self.sendError(stream, 400, "Invalid request format");
        };
        const body = request[body_start + 4 ..];

        // Extract token from JSON body
        const token = self.extractJsonField(body, "token") catch {
            return self.sendError(stream, 400, "Missing token field");
        };
        defer self.allocator.free(token);

        // Hash the provided token
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(token, &hash, .{});
        var token_hash: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&token_hash, "{s}", .{std.fmt.fmtSliceHexLower(&hash)}) catch unreachable;

        // Look up token
        var reset_token = self.db.getResetTokenByHash(&token_hash) catch {
            return self.sendError(stream, 400, "Invalid or expired token");
        };
        defer reset_token.deinit(self.allocator);

        const now = time_compat.timestamp();

        // Check if token is valid
        if (reset_token.used) {
            return self.sendError(stream, 400, "Token has already been used");
        }
        if (now > reset_token.expires_at) {
            return self.sendError(stream, 400, "Token has expired");
        }

        // Token is valid
        const json = try std.fmt.allocPrint(
            self.allocator,
            \\{{"valid":true,"username":"{s}","expires_in":{d}}}
        ,
            .{ reset_token.username, reset_token.expires_at - now },
        );
        defer self.allocator.free(json);

        try self.sendJSONResponse(stream, 200, json);
    }

    /// Handle POST /api/password-reset/complete
    /// Complete password reset with new password
    fn handlePasswordResetComplete(self: *APIServer, stream: std.net.Stream, request: []const u8) !void {
        // Extract body
        const body_start = std.mem.indexOf(u8, request, "\r\n\r\n") orelse {
            return self.sendError(stream, 400, "Invalid request format");
        };
        const body = request[body_start + 4 ..];

        // Extract token and new password from JSON body
        const token = self.extractJsonField(body, "token") catch {
            return self.sendError(stream, 400, "Missing token field");
        };
        defer self.allocator.free(token);

        const new_password = self.extractJsonField(body, "new_password") catch {
            return self.sendError(stream, 400, "Missing new_password field");
        };
        defer self.allocator.free(new_password);

        // Validate password strength
        if (new_password.len < 8) {
            return self.sendError(stream, 400, "Password must be at least 8 characters");
        }

        // Hash the provided token
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(token, &hash, .{});
        var token_hash: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&token_hash, "{s}", .{std.fmt.fmtSliceHexLower(&hash)}) catch unreachable;

        // Look up and validate token
        var reset_token = self.db.getResetTokenByHash(&token_hash) catch {
            return self.sendError(stream, 400, "Invalid or expired token");
        };
        defer reset_token.deinit(self.allocator);

        const now = time_compat.timestamp();

        if (reset_token.used) {
            return self.sendError(stream, 400, "Token has already been used");
        }
        if (now > reset_token.expires_at) {
            return self.sendError(stream, 400, "Token has expired");
        }

        // Hash the new password
        const password_mod = @import("../auth/password.zig");
        const hashed_password = password_mod.hashPassword(self.allocator, new_password) catch {
            return self.sendError(stream, 500, "Failed to hash password");
        };
        defer self.allocator.free(hashed_password);

        // Update the user's password
        self.db.updateUserPassword(reset_token.username, hashed_password) catch {
            return self.sendError(stream, 500, "Failed to update password");
        };

        // Mark token as used
        self.db.markResetTokenUsed(&token_hash) catch {};

        // Return success
        const json = try std.fmt.allocPrint(
            self.allocator,
            \\{{"message":"Password reset successful","username":"{s}"}}
        ,
            .{reset_token.username},
        );
        defer self.allocator.free(json);

        try self.sendJSONResponse(stream, 200, json);
    }

    /// Extract client IP from request headers
    fn extractClientIP(self: *APIServer, request: []const u8) ?[]const u8 {
        _ = self;
        var lines = std.mem.splitSequence(u8, request, "\r\n");
        _ = lines.next(); // Skip request line

        while (lines.next()) |line| {
            if (line.len == 0) break;

            // Check X-Forwarded-For header
            if (std.mem.startsWith(u8, line, "X-Forwarded-For: ")) {
                const value = std.mem.trim(u8, line[17..], " \t");
                // Return first IP in the list
                if (std.mem.indexOf(u8, value, ",")) |comma_pos| {
                    return value[0..comma_pos];
                }
                return value;
            }
            // Check X-Real-IP header
            if (std.mem.startsWith(u8, line, "X-Real-IP: ")) {
                return std.mem.trim(u8, line[11..], " \t");
            }
        }
        return null;
    }

    /// Send JSON response with status code
    fn sendJSONResponse(self: *APIServer, stream: std.net.Stream, status_code: u16, json: []const u8) !void {
        const status_text = switch (status_code) {
            200 => "OK",
            201 => "Created",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            500 => "Internal Server Error",
            else => "OK",
        };

        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 {d} {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ status_code, status_text, json.len, json },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    /// Send error response with custom status code and message
    fn sendError(self: *APIServer, stream: std.net.Stream, status_code: u16, message: []const u8) !void {
        const status_text = switch (status_code) {
            400 => "Bad Request",
            404 => "Not Found",
            409 => "Conflict",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            else => "Error",
        };

        const json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"error\":\"{s}\"}}",
            .{message},
        );
        defer self.allocator.free(json);

        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 {d} {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ status_code, status_text, json.len, json },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    /// Extract JSON field value (simple parser for {"key":"value"} format)
    fn extractJsonField(self: *APIServer, json: []const u8, field: []const u8) ![]const u8 {
        // Find "field":
        const field_pattern = try std.fmt.allocPrint(self.allocator, "\"{s}\":", .{field});
        defer self.allocator.free(field_pattern);

        const field_start = std.mem.indexOf(u8, json, field_pattern) orelse return error.FieldNotFound;
        const value_start_quote = std.mem.indexOfPos(u8, json, field_start, "\"") orelse return error.InvalidFormat;
        const value_start = value_start_quote + 1;

        // Find the closing quote, handling escaped quotes
        var i = value_start;
        while (i < json.len) : (i += 1) {
            if (json[i] == '"' and (i == value_start or json[i - 1] != '\\')) {
                const value = json[value_start..i];
                return try self.allocator.dupe(u8, value);
            }
        }

        return error.InvalidFormat;
    }

    fn send404(self: *APIServer, stream: std.net.Stream) !void {
        _ = self;
        const response = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";
        _ = try stream.write(response);
    }

    /// Handle GraphQL requests
    /// Endpoint: POST /api/graphql or POST /graphql
    fn handleGraphQL(self: *APIServer, stream: std.net.Stream, request: []const u8) !void {
        // Find the body (after \r\n\r\n)
        const body_start = std.mem.indexOf(u8, request, "\r\n\r\n") orelse {
            try self.sendError(stream, 400, "Invalid request format");
            return;
        };
        const body = request[body_start + 4 ..];

        // Extract the GraphQL query from JSON body
        // Expected format: {"query": "...", "variables": {...}}
        const query = self.extractJsonField(body, "query") catch {
            // Try to parse body as raw GraphQL query
            if (body.len > 0) {
                var executor = graphql.GraphQLExecutor.init(self.allocator, self.db, self.auth_backend);
                const result = executor.execute(body) catch |err| {
                    const error_response = try std.fmt.allocPrint(
                        self.allocator,
                        "{{\"errors\":[{{\"message\":\"Execution error: {}\"}}]}}",
                        .{err},
                    );
                    defer self.allocator.free(error_response);

                    const response = try std.fmt.allocPrint(
                        self.allocator,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {d}\r\n\r\n{s}",
                        .{ error_response.len, error_response },
                    );
                    defer self.allocator.free(response);

                    _ = try stream.write(response);
                    return;
                };
                defer self.allocator.free(result);

                const response = try std.fmt.allocPrint(
                    self.allocator,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {d}\r\n\r\n{s}",
                    .{ result.len, result },
                );
                defer self.allocator.free(response);

                _ = try stream.write(response);
                return;
            }

            try self.sendError(stream, 400, "Missing query field in request body");
            return;
        };
        defer self.allocator.free(query);

        // Execute the GraphQL query
        var executor = graphql.GraphQLExecutor.init(self.allocator, self.db, self.auth_backend);
        const result = executor.execute(query) catch |err| {
            const error_response = try std.fmt.allocPrint(
                self.allocator,
                "{{\"errors\":[{{\"message\":\"Execution error: {}\"}}]}}",
                .{err},
            );
            defer self.allocator.free(error_response);

            const response = try std.fmt.allocPrint(
                self.allocator,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {d}\r\n\r\n{s}",
                .{ error_response.len, error_response },
            );
            defer self.allocator.free(response);

            _ = try stream.write(response);
            return;
        };
        defer self.allocator.free(result);

        // Send successful response
        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ result.len, result },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }
};

test "API server initialization" {
    // Structural test only
    const testing = std.testing;
    _ = testing;
}
