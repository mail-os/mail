const std = @import("std");
const multitenancy = @import("../features/multitenancy.zig");
const TenantDB = @import("../storage/tenant_db.zig").TenantDB;

/// Tenant management API endpoints
pub const TenantsAPI = struct {
    allocator: std.mem.Allocator,
    tenant_manager: *multitenancy.MultiTenancyManager,

    pub fn init(allocator: std.mem.Allocator, tenant_manager: *multitenancy.MultiTenancyManager) TenantsAPI {
        return .{
            .allocator = allocator,
            .tenant_manager = tenant_manager,
        };
    }

    /// Handle tenant API requests
    pub fn handleRequest(self: *TenantsAPI, method: []const u8, path: []const u8, body: ?[]const u8, stream: std.net.Stream) !void {
        if (std.mem.eql(u8, path, "/api/tenants") and std.mem.eql(u8, method, "GET")) {
            try self.listTenants(stream);
        } else if (std.mem.eql(u8, path, "/api/tenants") and std.mem.eql(u8, method, "POST")) {
            try self.createTenant(stream, body);
        } else if (std.mem.startsWith(u8, path, "/api/tenants/") and std.mem.eql(u8, method, "GET")) {
            const tenant_id = path["/api/tenants/".len..];
            try self.getTenant(stream, tenant_id);
        } else if (std.mem.startsWith(u8, path, "/api/tenants/") and std.mem.eql(u8, method, "PUT")) {
            const tenant_id = path["/api/tenants/".len..];
            try self.updateTenant(stream, tenant_id, body);
        } else if (std.mem.startsWith(u8, path, "/api/tenants/") and std.mem.eql(u8, method, "DELETE")) {
            const tenant_id = path["/api/tenants/".len..];
            try self.deleteTenant(stream, tenant_id);
        } else if (std.mem.startsWith(u8, path, "/api/tenants/") and std.mem.endsWith(u8, path, "/usage")) {
            const end = std.mem.indexOf(u8, path["/api/tenants/".len..], "/usage") orelse return error.InvalidPath;
            const tenant_id = path["/api/tenants/".len..][0..end];
            try self.getTenantUsage(stream, tenant_id);
        } else {
            try self.sendError(stream, 404, "Not Found");
        }
    }

    /// List all tenants
    fn listTenants(self: *TenantsAPI, stream: std.net.Stream) !void {
        const tenant_db = self.tenant_manager.db;
        const tenants = try tenant_db.listTenants();
        defer {
            for (tenants) |tenant| {
                tenant.deinit(self.allocator);
            }
            self.allocator.free(tenants);
        }

        var json = std.ArrayList(u8).init(self.allocator);
        defer json.deinit();

        try json.appendSlice("{\"tenants\":[");

        for (tenants, 0..) |tenant, i| {
            if (i > 0) try json.appendSlice(",");

            try std.fmt.format(json.writer(),
                \\{{"id":"{s}","name":"{s}","domain":"{s}","enabled":{s},"created_at":{},"max_users":{},"max_domains":{},"max_storage_mb":{},"max_messages_per_day":{}}}
            , .{
                tenant.id,
                tenant.name,
                tenant.domain,
                if (tenant.enabled) "true" else "false",
                tenant.created_at,
                tenant.max_users,
                tenant.max_domains,
                tenant.max_storage_mb,
                tenant.max_messages_per_day,
            });
        }

        try json.appendSlice("]}");

        try self.sendJSON(stream, 200, json.items);
    }

    /// Get single tenant
    fn getTenant(self: *TenantsAPI, stream: std.net.Stream, tenant_id: []const u8) !void {
        const tenant = self.tenant_manager.getTenant(tenant_id) catch |err| {
            if (err == error.TenantNotFound) {
                return self.sendError(stream, 404, "Tenant not found");
            }
            return err;
        };

        var json = std.ArrayList(u8).init(self.allocator);
        defer json.deinit();

        try std.fmt.format(json.writer(),
            \\{{"id":"{s}","name":"{s}","domain":"{s}","enabled":{s},"created_at":{},"updated_at":{},"max_users":{},"max_domains":{},"max_storage_mb":{},"max_messages_per_day":{},"features":{{}}}}
        , .{
            tenant.id,
            tenant.name,
            tenant.domain,
            if (tenant.enabled) "true" else "false",
            tenant.created_at,
            tenant.updated_at,
            tenant.max_users,
            tenant.max_domains,
            tenant.max_storage_mb,
            tenant.max_messages_per_day,
        });

        // Add features
        const writer = json.writer();
        try writer.writeAll("\"spam_filtering\":");
        try writer.writeAll(if (tenant.features.spam_filtering) "true" else "false");
        try writer.writeAll(",\"virus_scanning\":");
        try writer.writeAll(if (tenant.features.virus_scanning) "true" else "false");
        try writer.writeAll(",\"dkim_signing\":");
        try writer.writeAll(if (tenant.features.dkim_signing) "true" else "false");
        try writer.writeAll(",\"mailing_lists\":");
        try writer.writeAll(if (tenant.features.mailing_lists) "true" else "false");
        try writer.writeAll(",\"webhooks\":");
        try writer.writeAll(if (tenant.features.webhooks) "true" else "false");
        try writer.writeAll(",\"api_access\":");
        try writer.writeAll(if (tenant.features.api_access) "true" else "false");
        try writer.writeAll(",\"custom_domains\":");
        try writer.writeAll(if (tenant.features.custom_domains) "true" else "false");
        try writer.writeAll(",\"priority_support\":");
        try writer.writeAll(if (tenant.features.priority_support) "true" else "false");
        try writer.writeAll("}}");

        try self.sendJSON(stream, 200, json.items);
    }

    /// Create tenant
    fn createTenant(self: *TenantsAPI, stream: std.net.Stream, body: ?[]const u8) !void {
        if (body == null) {
            return self.sendError(stream, 400, "Missing request body");
        }

        const parsed = try std.json.parseFromSlice(
            struct {
                name: []const u8,
                domain: []const u8,
                tier: ?[]const u8 = null,
            },
            self.allocator,
            body.?,
            .{},
        );
        defer parsed.deinit();

        const tier_name = parsed.value.tier orelse "free";
        const tier = std.meta.stringToEnum(multitenancy.TenantTier, tier_name) orelse {
            return self.sendError(stream, 400, "Invalid tier");
        };

        const tenant = try self.tenant_manager.createTenant(
            parsed.value.name,
            parsed.value.domain,
            tier,
        );

        var json = std.ArrayList(u8).init(self.allocator);
        defer json.deinit();

        try std.fmt.format(json.writer(),
            \\{{"id":"{s}","name":"{s}","domain":"{s}","tier":"{s}","created_at":{}}}
        , .{
            tenant.id,
            tenant.name,
            tenant.domain,
            tier_name,
            tenant.created_at,
        });

        try self.sendJSON(stream, 201, json.items);
    }

    /// Update tenant
    fn updateTenant(self: *TenantsAPI, stream: std.net.Stream, tenant_id: []const u8, body: ?[]const u8) !void {
        if (body == null) {
            return self.sendError(stream, 400, "Missing request body");
        }

        var tenant = self.tenant_manager.getTenant(tenant_id) catch |err| {
            if (err == error.TenantNotFound) {
                return self.sendError(stream, 404, "Tenant not found");
            }
            return err;
        };

        const parsed = try std.json.parseFromSlice(
            struct {
                name: ?[]const u8 = null,
                domain: ?[]const u8 = null,
                enabled: ?bool = null,
                max_users: ?u32 = null,
                max_domains: ?u32 = null,
                max_storage_mb: ?u64 = null,
                max_messages_per_day: ?u32 = null,
            },
            self.allocator,
            body.?,
            .{},
        );
        defer parsed.deinit();

        if (parsed.value.name) |name| {
            self.allocator.free(tenant.name);
            tenant.name = try self.allocator.dupe(u8, name);
        }
        if (parsed.value.domain) |domain| {
            self.allocator.free(tenant.domain);
            tenant.domain = try self.allocator.dupe(u8, domain);
        }
        if (parsed.value.enabled) |enabled| {
            tenant.enabled = enabled;
        }
        if (parsed.value.max_users) |max_users| {
            tenant.max_users = max_users;
        }
        if (parsed.value.max_domains) |max_domains| {
            tenant.max_domains = max_domains;
        }
        if (parsed.value.max_storage_mb) |max_storage_mb| {
            tenant.max_storage_mb = max_storage_mb;
        }
        if (parsed.value.max_messages_per_day) |max_messages_per_day| {
            tenant.max_messages_per_day = max_messages_per_day;
        }

        try self.tenant_manager.updateTenant(tenant);

        try self.sendJSON(stream, 200, "{\"success\":true}");
    }

    /// Delete tenant
    fn deleteTenant(self: *TenantsAPI, stream: std.net.Stream, tenant_id: []const u8) !void {
        self.tenant_manager.deleteTenant(tenant_id) catch |err| {
            if (err == error.TenantNotFound) {
                return self.sendError(stream, 404, "Tenant not found");
            }
            return err;
        };

        try self.sendJSON(stream, 200, "{\"success\":true}");
    }

    /// Get tenant usage statistics
    fn getTenantUsage(self: *TenantsAPI, stream: std.net.Stream, tenant_id: []const u8) !void {
        const tenant_db = self.tenant_manager.db;

        const user_count = try tenant_db.getUserCount(tenant_id);
        const domain_count = try tenant_db.getDomainCount(tenant_id);
        const storage_mb = try tenant_db.getStorageUsageMB(tenant_id);
        const messages_today = try tenant_db.getTodayMessageCount(tenant_id);

        const tenant = self.tenant_manager.getTenant(tenant_id) catch |err| {
            if (err == error.TenantNotFound) {
                return self.sendError(stream, 404, "Tenant not found");
            }
            return err;
        };

        var json = std.ArrayList(u8).init(self.allocator);
        defer json.deinit();

        try std.fmt.format(json.writer(),
            \\{{"tenant_id":"{s}","usage":{{"users":{},"domains":{},"storage_mb":{},"messages_today":{}}},"limits":{{"max_users":{},"max_domains":{},"max_storage_mb":{},"max_messages_per_day":{}}}}}
        , .{
            tenant_id,
            user_count,
            domain_count,
            storage_mb,
            messages_today,
            tenant.max_users,
            tenant.max_domains,
            tenant.max_storage_mb,
            tenant.max_messages_per_day,
        });

        try self.sendJSON(stream, 200, json.items);
    }

    /// Send JSON response
    fn sendJSON(self: *TenantsAPI, stream: std.net.Stream, status: u16, json: []const u8) !void {
        _ = self;

        const status_text = switch (status) {
            200 => "OK",
            201 => "Created",
            400 => "Bad Request",
            404 => "Not Found",
            500 => "Internal Server Error",
            else => "Unknown",
        };

        const response = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 {d} {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ status, status_text, json.len, json },
        );
        defer self.allocator.free(response);

        _ = try stream.write(response);
    }

    /// Send error response (JSON-escapes the message to prevent injection)
    fn sendError(self: *TenantsAPI, stream: std.net.Stream, status: u16, message: []const u8) !void {
        const escaped = try escapeJsonStr(self.allocator, message);
        defer self.allocator.free(escaped);

        const json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"error\":\"{s}\"}}",
            .{escaped},
        );
        defer self.allocator.free(json);

        try self.sendJSON(stream, status, json);
    }

    fn escapeJsonStr(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
        var needs_escape = false;
        for (s) |c| {
            if (c == '"' or c == '\\' or c < 0x20) { needs_escape = true; break; }
        }
        if (!needs_escape) return try allocator.dupe(u8, s);
        var result: std.ArrayList(u8) = .{};
        errdefer result.deinit(allocator);
        for (s) |c| {
            switch (c) {
                '"' => try result.appendSlice(allocator, "\\\""),
                '\\' => try result.appendSlice(allocator, "\\\\"),
                '\n' => try result.appendSlice(allocator, "\\n"),
                '\r' => try result.appendSlice(allocator, "\\r"),
                '\t' => try result.appendSlice(allocator, "\\t"),
                else => {
                    if (c < 0x20) {
                        const hex = "0123456789abcdef";
                        try result.appendSlice(allocator, "\\u00");
                        try result.append(allocator, hex[c >> 4]);
                        try result.append(allocator, hex[c & 0x0f]);
                    } else {
                        try result.append(allocator, c);
                    }
                },
            }
        }
        return try result.toOwnedSlice(allocator);
    }
};
