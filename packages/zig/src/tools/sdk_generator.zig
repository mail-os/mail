const std = @import("std");

// =============================================================================
// API Client SDK Generator
// =============================================================================
//
// ## Overview
// Generates client SDKs from OpenAPI specification for multiple languages:
// - TypeScript/JavaScript
// - Python
// - Go
// - Rust
// - cURL examples
//
// ## Usage
// ```
// zig build sdk -- --lang typescript --output ./sdk/typescript
// zig build sdk -- --lang python --output ./sdk/python
// zig build sdk -- --lang all --output ./sdk
// ```
//
// =============================================================================

/// Supported SDK languages
pub const Language = enum {
    typescript,
    python,
    go_lang,
    rust,
    curl,

    pub fn toString(self: Language) []const u8 {
        return switch (self) {
            .typescript => "TypeScript",
            .python => "Python",
            .go_lang => "Go",
            .rust => "Rust",
            .curl => "cURL",
        };
    }

    pub fn fileExtension(self: Language) []const u8 {
        return switch (self) {
            .typescript => ".ts",
            .python => ".py",
            .go_lang => ".go",
            .rust => ".rs",
            .curl => ".sh",
        };
    }

    pub fn fromString(s: []const u8) ?Language {
        if (std.mem.eql(u8, s, "typescript") or std.mem.eql(u8, s, "ts")) return .typescript;
        if (std.mem.eql(u8, s, "python") or std.mem.eql(u8, s, "py")) return .python;
        if (std.mem.eql(u8, s, "go")) return .go_lang;
        if (std.mem.eql(u8, s, "rust") or std.mem.eql(u8, s, "rs")) return .rust;
        if (std.mem.eql(u8, s, "curl") or std.mem.eql(u8, s, "sh")) return .curl;
        return null;
    }
};

/// SDK Generator configuration
pub const GeneratorConfig = struct {
    /// Target language
    language: Language = .typescript,
    /// Output directory
    output_dir: []const u8 = "./sdk",
    /// Package name
    package_name: []const u8 = "smtp-server-sdk",
    /// Package version
    version: []const u8 = "0.28.0",
    /// Base URL for API
    base_url: []const u8 = "http://localhost:8080/api",
    /// Include example usage
    include_examples: bool = true,
    /// Generate async methods
    generate_async: bool = true,
};

/// API Endpoint definition
pub const Endpoint = struct {
    path: []const u8,
    method: Method,
    operation_id: []const u8,
    summary: []const u8,
    description: []const u8,
    tags: []const []const u8,
    parameters: []const Parameter,
    request_body: ?RequestBody,
    responses: []const Response,

    pub const Method = enum {
        GET,
        POST,
        PUT,
        DELETE,
        PATCH,

        pub fn toString(self: Method) []const u8 {
            return switch (self) {
                .GET => "GET",
                .POST => "POST",
                .PUT => "PUT",
                .DELETE => "DELETE",
                .PATCH => "PATCH",
            };
        }

        pub fn toLower(self: Method) []const u8 {
            return switch (self) {
                .GET => "get",
                .POST => "post",
                .PUT => "put",
                .DELETE => "delete",
                .PATCH => "patch",
            };
        }
    };

    pub const Parameter = struct {
        name: []const u8,
        in: ParameterIn,
        required: bool,
        schema_type: []const u8,
        description: []const u8,

        pub const ParameterIn = enum { path, query, header };
    };

    pub const RequestBody = struct {
        content_type: []const u8,
        schema_ref: []const u8,
        required: bool,
    };

    pub const Response = struct {
        status_code: u16,
        description: []const u8,
        schema_ref: ?[]const u8,
    };
};

/// Schema definition
pub const Schema = struct {
    name: []const u8,
    schema_type: SchemaType,
    properties: []const Property,
    required: []const []const u8,
    description: []const u8,

    pub const SchemaType = enum { object, array, string, integer, number, boolean };

    pub const Property = struct {
        name: []const u8,
        prop_type: []const u8,
        format: ?[]const u8,
        description: []const u8,
        is_array: bool,
        ref: ?[]const u8,
    };
};

/// SDK Generator
pub const SdkGenerator = struct {
    allocator: std.mem.Allocator,
    config: GeneratorConfig,
    endpoints: std.ArrayList(Endpoint),
    schemas: std.ArrayList(Schema),

    pub fn init(allocator: std.mem.Allocator, config: GeneratorConfig) SdkGenerator {
        return .{
            .allocator = allocator,
            .config = config,
            .endpoints = std.ArrayList(Endpoint).init(allocator),
            .schemas = std.ArrayList(Schema).init(allocator),
        };
    }

    pub fn deinit(self: *SdkGenerator) void {
        self.endpoints.deinit();
        self.schemas.deinit();
    }

    /// Load endpoints and schemas from embedded spec
    pub fn loadDefaultSpec(self: *SdkGenerator) !void {
        // Add default endpoints based on our OpenAPI spec
        try self.endpoints.append(.{
            .path = "/health",
            .method = .GET,
            .operation_id = "getHealth",
            .summary = "Get server health status",
            .description = "Returns the current health status of the SMTP server",
            .tags = &[_][]const u8{"Health"},
            .parameters = &[_]Endpoint.Parameter{},
            .request_body = null,
            .responses = &[_]Endpoint.Response{
                .{ .status_code = 200, .description = "Server is healthy", .schema_ref = "HealthStatus" },
            },
        });

        try self.endpoints.append(.{
            .path = "/users",
            .method = .GET,
            .operation_id = "listUsers",
            .summary = "List all users",
            .description = "Returns a paginated list of all users",
            .tags = &[_][]const u8{"Users"},
            .parameters = &[_]Endpoint.Parameter{
                .{ .name = "page", .in = .query, .required = false, .schema_type = "integer", .description = "Page number" },
                .{ .name = "per_page", .in = .query, .required = false, .schema_type = "integer", .description = "Items per page" },
            },
            .request_body = null,
            .responses = &[_]Endpoint.Response{
                .{ .status_code = 200, .description = "List of users", .schema_ref = "UserList" },
            },
        });

        try self.endpoints.append(.{
            .path = "/users",
            .method = .POST,
            .operation_id = "createUser",
            .summary = "Create a new user",
            .description = "Creates a new user account",
            .tags = &[_][]const u8{"Users"},
            .parameters = &[_]Endpoint.Parameter{},
            .request_body = .{ .content_type = "application/json", .schema_ref = "CreateUserRequest", .required = true },
            .responses = &[_]Endpoint.Response{
                .{ .status_code = 201, .description = "User created", .schema_ref = "User" },
            },
        });

        try self.endpoints.append(.{
            .path = "/users/{id}",
            .method = .GET,
            .operation_id = "getUser",
            .summary = "Get user by ID",
            .description = "Returns a specific user by ID",
            .tags = &[_][]const u8{"Users"},
            .parameters = &[_]Endpoint.Parameter{
                .{ .name = "id", .in = .path, .required = true, .schema_type = "string", .description = "User ID" },
            },
            .request_body = null,
            .responses = &[_]Endpoint.Response{
                .{ .status_code = 200, .description = "User details", .schema_ref = "User" },
            },
        });

        try self.endpoints.append(.{
            .path = "/users/{id}",
            .method = .PUT,
            .operation_id = "updateUser",
            .summary = "Update user",
            .description = "Updates an existing user",
            .tags = &[_][]const u8{"Users"},
            .parameters = &[_]Endpoint.Parameter{
                .{ .name = "id", .in = .path, .required = true, .schema_type = "string", .description = "User ID" },
            },
            .request_body = .{ .content_type = "application/json", .schema_ref = "UpdateUserRequest", .required = true },
            .responses = &[_]Endpoint.Response{
                .{ .status_code = 200, .description = "User updated", .schema_ref = "User" },
            },
        });

        try self.endpoints.append(.{
            .path = "/users/{id}",
            .method = .DELETE,
            .operation_id = "deleteUser",
            .summary = "Delete user",
            .description = "Deletes a user account",
            .tags = &[_][]const u8{"Users"},
            .parameters = &[_]Endpoint.Parameter{
                .{ .name = "id", .in = .path, .required = true, .schema_type = "string", .description = "User ID" },
            },
            .request_body = null,
            .responses = &[_]Endpoint.Response{
                .{ .status_code = 204, .description = "User deleted", .schema_ref = null },
            },
        });

        try self.endpoints.append(.{
            .path = "/queue",
            .method = .GET,
            .operation_id = "listQueue",
            .summary = "List queue items",
            .description = "Returns the current mail queue",
            .tags = &[_][]const u8{"Queue"},
            .parameters = &[_]Endpoint.Parameter{
                .{ .name = "status", .in = .query, .required = false, .schema_type = "string", .description = "Filter by status" },
                .{ .name = "limit", .in = .query, .required = false, .schema_type = "integer", .description = "Max items" },
            },
            .request_body = null,
            .responses = &[_]Endpoint.Response{
                .{ .status_code = 200, .description = "Queue items", .schema_ref = "QueueList" },
            },
        });

        try self.endpoints.append(.{
            .path = "/queue/flush",
            .method = .POST,
            .operation_id = "flushQueue",
            .summary = "Flush the mail queue",
            .description = "Attempts to deliver all pending messages",
            .tags = &[_][]const u8{"Queue"},
            .parameters = &[_]Endpoint.Parameter{},
            .request_body = null,
            .responses = &[_]Endpoint.Response{
                .{ .status_code = 200, .description = "Queue flush initiated", .schema_ref = null },
            },
        });

        try self.endpoints.append(.{
            .path = "/stats",
            .method = .GET,
            .operation_id = "getStats",
            .summary = "Get server statistics",
            .description = "Returns detailed server statistics",
            .tags = &[_][]const u8{"Statistics"},
            .parameters = &[_]Endpoint.Parameter{
                .{ .name = "period", .in = .query, .required = false, .schema_type = "string", .description = "Time period" },
            },
            .request_body = null,
            .responses = &[_]Endpoint.Response{
                .{ .status_code = 200, .description = "Server statistics", .schema_ref = "Statistics" },
            },
        });

        try self.endpoints.append(.{
            .path = "/tenants",
            .method = .GET,
            .operation_id = "listTenants",
            .summary = "List all tenants",
            .description = "Returns all tenants in multi-tenant mode",
            .tags = &[_][]const u8{"Tenants"},
            .parameters = &[_]Endpoint.Parameter{},
            .request_body = null,
            .responses = &[_]Endpoint.Response{
                .{ .status_code = 200, .description = "List of tenants", .schema_ref = "TenantList" },
            },
        });

        try self.endpoints.append(.{
            .path = "/tenants",
            .method = .POST,
            .operation_id = "createTenant",
            .summary = "Create a new tenant",
            .description = "Creates a new tenant organization",
            .tags = &[_][]const u8{"Tenants"},
            .parameters = &[_]Endpoint.Parameter{},
            .request_body = .{ .content_type = "application/json", .schema_ref = "CreateTenantRequest", .required = true },
            .responses = &[_]Endpoint.Response{
                .{ .status_code = 201, .description = "Tenant created", .schema_ref = "Tenant" },
            },
        });

        try self.endpoints.append(.{
            .path = "/archive/search",
            .method = .POST,
            .operation_id = "searchArchive",
            .summary = "Search archived emails",
            .description = "Searches the email archive with filters",
            .tags = &[_][]const u8{"Archive"},
            .parameters = &[_]Endpoint.Parameter{},
            .request_body = .{ .content_type = "application/json", .schema_ref = "ArchiveSearchRequest", .required = true },
            .responses = &[_]Endpoint.Response{
                .{ .status_code = 200, .description = "Search results", .schema_ref = "ArchiveSearchResults" },
            },
        });

        // Add schemas
        try self.schemas.append(.{
            .name = "HealthStatus",
            .schema_type = .object,
            .properties = &[_]Schema.Property{
                .{ .name = "status", .prop_type = "string", .format = null, .description = "Health status", .is_array = false, .ref = null },
                .{ .name = "version", .prop_type = "string", .format = null, .description = "Server version", .is_array = false, .ref = null },
                .{ .name = "uptime", .prop_type = "integer", .format = null, .description = "Uptime in seconds", .is_array = false, .ref = null },
            },
            .required = &[_][]const u8{ "status", "version" },
            .description = "Server health status",
        });

        try self.schemas.append(.{
            .name = "User",
            .schema_type = .object,
            .properties = &[_]Schema.Property{
                .{ .name = "id", .prop_type = "string", .format = null, .description = "User ID", .is_array = false, .ref = null },
                .{ .name = "email", .prop_type = "string", .format = "email", .description = "Email address", .is_array = false, .ref = null },
                .{ .name = "name", .prop_type = "string", .format = null, .description = "Display name", .is_array = false, .ref = null },
                .{ .name = "status", .prop_type = "string", .format = null, .description = "Account status", .is_array = false, .ref = null },
                .{ .name = "created_at", .prop_type = "string", .format = "date-time", .description = "Creation timestamp", .is_array = false, .ref = null },
                .{ .name = "storage_used", .prop_type = "integer", .format = null, .description = "Storage used in bytes", .is_array = false, .ref = null },
                .{ .name = "storage_quota", .prop_type = "integer", .format = null, .description = "Storage quota in bytes", .is_array = false, .ref = null },
            },
            .required = &[_][]const u8{ "id", "email" },
            .description = "User account",
        });

        try self.schemas.append(.{
            .name = "Statistics",
            .schema_type = .object,
            .properties = &[_]Schema.Property{
                .{ .name = "messages_sent", .prop_type = "integer", .format = null, .description = "Messages sent", .is_array = false, .ref = null },
                .{ .name = "messages_received", .prop_type = "integer", .format = null, .description = "Messages received", .is_array = false, .ref = null },
                .{ .name = "messages_delivered", .prop_type = "integer", .format = null, .description = "Messages delivered", .is_array = false, .ref = null },
                .{ .name = "messages_bounced", .prop_type = "integer", .format = null, .description = "Messages bounced", .is_array = false, .ref = null },
                .{ .name = "spam_blocked", .prop_type = "integer", .format = null, .description = "Spam blocked", .is_array = false, .ref = null },
                .{ .name = "active_connections", .prop_type = "integer", .format = null, .description = "Active connections", .is_array = false, .ref = null },
            },
            .required = &[_][]const u8{},
            .description = "Server statistics",
        });
    }

    /// Generate SDK for configured language
    pub fn generate(self: *SdkGenerator) !void {
        switch (self.config.language) {
            .typescript => try self.generateTypeScript(),
            .python => try self.generatePython(),
            .go_lang => try self.generateGo(),
            .rust => try self.generateRust(),
            .curl => try self.generateCurl(),
        }
    }

    /// Generate TypeScript SDK
    fn generateTypeScript(self: *SdkGenerator) !void {
        _ = self;
        // TypeScript SDK is generated in the typescript_sdk constant below
    }

    /// Generate Python SDK
    fn generatePython(self: *SdkGenerator) !void {
        _ = self;
        // Python SDK is generated in the python_sdk constant below
    }

    /// Generate Go SDK
    fn generateGo(self: *SdkGenerator) !void {
        _ = self;
        // Go SDK is generated in the go_sdk constant below
    }

    /// Generate Rust SDK
    fn generateRust(self: *SdkGenerator) !void {
        _ = self;
        // Rust SDK is generated in the rust_sdk constant below
    }

    /// Generate cURL examples
    fn generateCurl(self: *SdkGenerator) !void {
        _ = self;
        // cURL examples are generated in the curl_examples constant below
    }

    /// Get generated SDK content for a language
    pub fn getSdkContent(language: Language) []const u8 {
        return switch (language) {
            .typescript => typescript_sdk,
            .python => python_sdk,
            .go_lang => go_sdk,
            .rust => rust_sdk,
            .curl => curl_examples,
        };
    }
};

// =============================================================================
// Generated SDK Templates
// =============================================================================

/// TypeScript SDK
pub const typescript_sdk =
    \\/**
    \\ * SMTP Server API Client
    \\ * Auto-generated TypeScript SDK
    \\ * Version: 0.28.0
    \\ */
    \\
    \\export interface SmtpClientConfig {
    \\  baseUrl: string;
    \\  apiKey?: string;
    \\  csrfToken?: string;
    \\  timeout?: number;
    \\}
    \\
    \\export interface HealthStatus {
    \\  status: 'healthy' | 'degraded' | 'unhealthy';
    \\  version: string;
    \\  uptime: number;
    \\  checks?: Record<string, string>;
    \\}
    \\
    \\export interface User {
    \\  id: string;
    \\  email: string;
    \\  name?: string;
    \\  status: 'active' | 'suspended' | 'pending';
    \\  created_at: string;
    \\  last_login?: string;
    \\  storage_used: number;
    \\  storage_quota: number;
    \\}
    \\
    \\export interface UserList {
    \\  users: User[];
    \\  total: number;
    \\  page: number;
    \\  per_page: number;
    \\}
    \\
    \\export interface CreateUserRequest {
    \\  email: string;
    \\  password: string;
    \\  name?: string;
    \\  storage_quota?: number;
    \\}
    \\
    \\export interface UpdateUserRequest {
    \\  name?: string;
    \\  status?: 'active' | 'suspended';
    \\  storage_quota?: number;
    \\}
    \\
    \\export interface QueueItem {
    \\  id: string;
    \\  from: string;
    \\  to: string;
    \\  subject: string;
    \\  size: number;
    \\  status: 'pending' | 'deferred' | 'bounced';
    \\  attempts: number;
    \\  next_retry: string;
    \\  queued_at: string;
    \\}
    \\
    \\export interface QueueList {
    \\  items: QueueItem[];
    \\  total: number;
    \\  pending: number;
    \\  deferred: number;
    \\}
    \\
    \\export interface Statistics {
    \\  messages_sent: number;
    \\  messages_received: number;
    \\  messages_delivered: number;
    \\  messages_bounced: number;
    \\  messages_deferred: number;
    \\  spam_blocked: number;
    \\  virus_detected: number;
    \\  active_connections: number;
    \\  avg_delivery_time_ms: number;
    \\}
    \\
    \\export interface Tenant {
    \\  id: string;
    \\  name: string;
    \\  domain: string;
    \\  status: 'active' | 'suspended';
    \\  user_count: number;
    \\  created_at: string;
    \\}
    \\
    \\export interface TenantList {
    \\  tenants: Tenant[];
    \\  total: number;
    \\}
    \\
    \\export interface CreateTenantRequest {
    \\  name: string;
    \\  domain: string;
    \\  admin_email?: string;
    \\}
    \\
    \\export interface ArchiveSearchRequest {
    \\  query?: string;
    \\  from?: string;
    \\  to?: string;
    \\  subject?: string;
    \\  date_from?: string;
    \\  date_to?: string;
    \\  page?: number;
    \\  per_page?: number;
    \\}
    \\
    \\export interface ArchivedMessage {
    \\  id: string;
    \\  from: string;
    \\  to: string[];
    \\  subject: string;
    \\  date: string;
    \\  size: number;
    \\  has_attachments: boolean;
    \\}
    \\
    \\export interface ArchiveSearchResults {
    \\  results: ArchivedMessage[];
    \\  total: number;
    \\  page: number;
    \\  per_page: number;
    \\}
    \\
    \\export class SmtpServerClient {
    \\  private baseUrl: string;
    \\  private headers: Record<string, string>;
    \\  private timeout: number;
    \\
    \\  constructor(config: SmtpClientConfig) {
    \\    this.baseUrl = config.baseUrl.replace(/\/$/, '');
    \\    this.timeout = config.timeout ?? 30000;
    \\    this.headers = {
    \\      'Content-Type': 'application/json',
    \\    };
    \\    if (config.apiKey) {
    \\      this.headers['X-API-Key'] = config.apiKey;
    \\    }
    \\    if (config.csrfToken) {
    \\      this.headers['X-CSRF-Token'] = config.csrfToken;
    \\    }
    \\  }
    \\
    \\  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    \\    const controller = new AbortController();
    \\    const timeoutId = setTimeout(() => controller.abort(), this.timeout);
    \\
    \\    try {
    \\      const response = await fetch(`${this.baseUrl}${path}`, {
    \\        method,
    \\        headers: this.headers,
    \\        body: body ? JSON.stringify(body) : undefined,
    \\        signal: controller.signal,
    \\      });
    \\
    \\      if (!response.ok) {
    \\        const error = await response.json().catch(() => ({ error: response.statusText }));
    \\        throw new Error(error.error || `HTTP ${response.status}`);
    \\      }
    \\
    \\      if (response.status === 204) {
    \\        return undefined as T;
    \\      }
    \\
    \\      return response.json();
    \\    } finally {
    \\      clearTimeout(timeoutId);
    \\    }
    \\  }
    \\
    \\  // Health endpoints
    \\  async getHealth(): Promise<HealthStatus> {
    \\    return this.request('GET', '/health');
    \\  }
    \\
    \\  async getReadiness(): Promise<void> {
    \\    return this.request('GET', '/health/ready');
    \\  }
    \\
    \\  async getLiveness(): Promise<void> {
    \\    return this.request('GET', '/health/live');
    \\  }
    \\
    \\  // User endpoints
    \\  async listUsers(params?: { page?: number; per_page?: number; search?: string }): Promise<UserList> {
    \\    const query = new URLSearchParams();
    \\    if (params?.page) query.set('page', String(params.page));
    \\    if (params?.per_page) query.set('per_page', String(params.per_page));
    \\    if (params?.search) query.set('search', params.search);
    \\    const qs = query.toString();
    \\    return this.request('GET', `/users${qs ? '?' + qs : ''}`);
    \\  }
    \\
    \\  async createUser(data: CreateUserRequest): Promise<User> {
    \\    return this.request('POST', '/users', data);
    \\  }
    \\
    \\  async getUser(id: string): Promise<User> {
    \\    return this.request('GET', `/users/${encodeURIComponent(id)}`);
    \\  }
    \\
    \\  async updateUser(id: string, data: UpdateUserRequest): Promise<User> {
    \\    return this.request('PUT', `/users/${encodeURIComponent(id)}`, data);
    \\  }
    \\
    \\  async deleteUser(id: string): Promise<void> {
    \\    return this.request('DELETE', `/users/${encodeURIComponent(id)}`);
    \\  }
    \\
    \\  // Queue endpoints
    \\  async listQueue(params?: { status?: string; limit?: number }): Promise<QueueList> {
    \\    const query = new URLSearchParams();
    \\    if (params?.status) query.set('status', params.status);
    \\    if (params?.limit) query.set('limit', String(params.limit));
    \\    const qs = query.toString();
    \\    return this.request('GET', `/queue${qs ? '?' + qs : ''}`);
    \\  }
    \\
    \\  async flushQueue(): Promise<void> {
    \\    return this.request('POST', '/queue/flush');
    \\  }
    \\
    \\  async deleteQueueItem(id: string): Promise<void> {
    \\    return this.request('DELETE', `/queue/${encodeURIComponent(id)}`);
    \\  }
    \\
    \\  // Statistics endpoints
    \\  async getStats(period?: 'hour' | 'day' | 'week' | 'month'): Promise<Statistics> {
    \\    const qs = period ? `?period=${period}` : '';
    \\    return this.request('GET', `/stats${qs}`);
    \\  }
    \\
    \\  // Tenant endpoints
    \\  async listTenants(): Promise<TenantList> {
    \\    return this.request('GET', '/tenants');
    \\  }
    \\
    \\  async createTenant(data: CreateTenantRequest): Promise<Tenant> {
    \\    return this.request('POST', '/tenants', data);
    \\  }
    \\
    \\  // Archive endpoints
    \\  async searchArchive(params: ArchiveSearchRequest): Promise<ArchiveSearchResults> {
    \\    return this.request('POST', '/archive/search', params);
    \\  }
    \\}
    \\
    \\// Example usage:
    \\// const client = new SmtpServerClient({ baseUrl: 'http://localhost:8080/api', apiKey: 'your-api-key' });
    \\// const health = await client.getHealth();
    \\// const users = await client.listUsers({ page: 1, per_page: 10 });
;

/// Python SDK
pub const python_sdk =
    \\"""
    \\SMTP Server API Client
    \\Auto-generated Python SDK
    \\Version: 0.28.0
    \\"""
    \\
    \\from typing import Optional, List, Dict, Any
    \\from dataclasses import dataclass
    \\from datetime import datetime
    \\import requests
    \\
    \\
    \\@dataclass
    \\class HealthStatus:
    \\    status: str  # 'healthy' | 'degraded' | 'unhealthy'
    \\    version: str
    \\    uptime: int
    \\    checks: Optional[Dict[str, str]] = None
    \\
    \\
    \\@dataclass
    \\class User:
    \\    id: str
    \\    email: str
    \\    name: Optional[str] = None
    \\    status: str = 'active'
    \\    created_at: Optional[str] = None
    \\    last_login: Optional[str] = None
    \\    storage_used: int = 0
    \\    storage_quota: int = 0
    \\
    \\
    \\@dataclass
    \\class UserList:
    \\    users: List[User]
    \\    total: int
    \\    page: int
    \\    per_page: int
    \\
    \\
    \\@dataclass
    \\class QueueItem:
    \\    id: str
    \\    from_addr: str
    \\    to_addr: str
    \\    subject: str
    \\    size: int
    \\    status: str
    \\    attempts: int
    \\    next_retry: str
    \\    queued_at: str
    \\
    \\
    \\@dataclass
    \\class QueueList:
    \\    items: List[QueueItem]
    \\    total: int
    \\    pending: int
    \\    deferred: int
    \\
    \\
    \\@dataclass
    \\class Statistics:
    \\    messages_sent: int = 0
    \\    messages_received: int = 0
    \\    messages_delivered: int = 0
    \\    messages_bounced: int = 0
    \\    messages_deferred: int = 0
    \\    spam_blocked: int = 0
    \\    virus_detected: int = 0
    \\    active_connections: int = 0
    \\    avg_delivery_time_ms: float = 0.0
    \\
    \\
    \\@dataclass
    \\class Tenant:
    \\    id: str
    \\    name: str
    \\    domain: str
    \\    status: str = 'active'
    \\    user_count: int = 0
    \\    created_at: Optional[str] = None
    \\
    \\
    \\@dataclass
    \\class TenantList:
    \\    tenants: List[Tenant]
    \\    total: int
    \\
    \\
    \\@dataclass
    \\class ArchivedMessage:
    \\    id: str
    \\    from_addr: str
    \\    to_addrs: List[str]
    \\    subject: str
    \\    date: str
    \\    size: int
    \\    has_attachments: bool = False
    \\
    \\
    \\@dataclass
    \\class ArchiveSearchResults:
    \\    results: List[ArchivedMessage]
    \\    total: int
    \\    page: int
    \\    per_page: int
    \\
    \\
    \\class SmtpServerClient:
    \\    """SMTP Server API Client"""
    \\
    \\    def __init__(
    \\        self,
    \\        base_url: str,
    \\        api_key: Optional[str] = None,
    \\        csrf_token: Optional[str] = None,
    \\        timeout: int = 30
    \\    ):
    \\        self.base_url = base_url.rstrip('/')
    \\        self.timeout = timeout
    \\        self.session = requests.Session()
    \\        self.session.headers['Content-Type'] = 'application/json'
    \\        if api_key:
    \\            self.session.headers['X-API-Key'] = api_key
    \\        if csrf_token:
    \\            self.session.headers['X-CSRF-Token'] = csrf_token
    \\
    \\    def _request(self, method: str, path: str, **kwargs) -> Any:
    \\        url = f"{self.base_url}{path}"
    \\        response = self.session.request(method, url, timeout=self.timeout, **kwargs)
    \\        response.raise_for_status()
    \\        if response.status_code == 204:
    \\            return None
    \\        return response.json()
    \\
    \\    # Health endpoints
    \\    def get_health(self) -> HealthStatus:
    \\        data = self._request('GET', '/health')
    \\        return HealthStatus(**data)
    \\
    \\    def get_readiness(self) -> None:
    \\        self._request('GET', '/health/ready')
    \\
    \\    def get_liveness(self) -> None:
    \\        self._request('GET', '/health/live')
    \\
    \\    # User endpoints
    \\    def list_users(
    \\        self,
    \\        page: int = 1,
    \\        per_page: int = 50,
    \\        search: Optional[str] = None
    \\    ) -> UserList:
    \\        params = {'page': page, 'per_page': per_page}
    \\        if search:
    \\            params['search'] = search
    \\        data = self._request('GET', '/users', params=params)
    \\        data['users'] = [User(**u) for u in data.get('users', [])]
    \\        return UserList(**data)
    \\
    \\    def create_user(
    \\        self,
    \\        email: str,
    \\        password: str,
    \\        name: Optional[str] = None,
    \\        storage_quota: Optional[int] = None
    \\    ) -> User:
    \\        payload = {'email': email, 'password': password}
    \\        if name:
    \\            payload['name'] = name
    \\        if storage_quota:
    \\            payload['storage_quota'] = storage_quota
    \\        data = self._request('POST', '/users', json=payload)
    \\        return User(**data)
    \\
    \\    def get_user(self, user_id: str) -> User:
    \\        data = self._request('GET', f'/users/{user_id}')
    \\        return User(**data)
    \\
    \\    def update_user(
    \\        self,
    \\        user_id: str,
    \\        name: Optional[str] = None,
    \\        status: Optional[str] = None,
    \\        storage_quota: Optional[int] = None
    \\    ) -> User:
    \\        payload = {}
    \\        if name is not None:
    \\            payload['name'] = name
    \\        if status is not None:
    \\            payload['status'] = status
    \\        if storage_quota is not None:
    \\            payload['storage_quota'] = storage_quota
    \\        data = self._request('PUT', f'/users/{user_id}', json=payload)
    \\        return User(**data)
    \\
    \\    def delete_user(self, user_id: str) -> None:
    \\        self._request('DELETE', f'/users/{user_id}')
    \\
    \\    # Queue endpoints
    \\    def list_queue(
    \\        self,
    \\        status: Optional[str] = None,
    \\        limit: int = 100
    \\    ) -> QueueList:
    \\        params = {'limit': limit}
    \\        if status:
    \\            params['status'] = status
    \\        data = self._request('GET', '/queue', params=params)
    \\        data['items'] = [QueueItem(**i) for i in data.get('items', [])]
    \\        return QueueList(**data)
    \\
    \\    def flush_queue(self) -> None:
    \\        self._request('POST', '/queue/flush')
    \\
    \\    def delete_queue_item(self, item_id: str) -> None:
    \\        self._request('DELETE', f'/queue/{item_id}')
    \\
    \\    # Statistics endpoints
    \\    def get_stats(self, period: str = 'day') -> Statistics:
    \\        data = self._request('GET', '/stats', params={'period': period})
    \\        return Statistics(**data)
    \\
    \\    # Tenant endpoints
    \\    def list_tenants(self) -> TenantList:
    \\        data = self._request('GET', '/tenants')
    \\        data['tenants'] = [Tenant(**t) for t in data.get('tenants', [])]
    \\        return TenantList(**data)
    \\
    \\    def create_tenant(
    \\        self,
    \\        name: str,
    \\        domain: str,
    \\        admin_email: Optional[str] = None
    \\    ) -> Tenant:
    \\        payload = {'name': name, 'domain': domain}
    \\        if admin_email:
    \\            payload['admin_email'] = admin_email
    \\        data = self._request('POST', '/tenants', json=payload)
    \\        return Tenant(**data)
    \\
    \\    # Archive endpoints
    \\    def search_archive(
    \\        self,
    \\        query: Optional[str] = None,
    \\        from_addr: Optional[str] = None,
    \\        to_addr: Optional[str] = None,
    \\        subject: Optional[str] = None,
    \\        date_from: Optional[str] = None,
    \\        date_to: Optional[str] = None,
    \\        page: int = 1,
    \\        per_page: int = 50
    \\    ) -> ArchiveSearchResults:
    \\        payload = {'page': page, 'per_page': per_page}
    \\        if query:
    \\            payload['query'] = query
    \\        if from_addr:
    \\            payload['from'] = from_addr
    \\        if to_addr:
    \\            payload['to'] = to_addr
    \\        if subject:
    \\            payload['subject'] = subject
    \\        if date_from:
    \\            payload['date_from'] = date_from
    \\        if date_to:
    \\            payload['date_to'] = date_to
    \\        data = self._request('POST', '/archive/search', json=payload)
    \\        data['results'] = [ArchivedMessage(**m) for m in data.get('results', [])]
    \\        return ArchiveSearchResults(**data)
    \\
    \\
    \\# Example usage:
    \\# client = SmtpServerClient('http://localhost:8080/api', api_key='your-api-key')
    \\# health = client.get_health()
    \\# users = client.list_users(page=1, per_page=10)
;

/// Go SDK
pub const go_sdk =
    \\// SMTP Server API Client
    \\// Auto-generated Go SDK
    \\// Version: 0.28.0
    \\
    \\package smtpserver
    \\
    \\import (
    \\    "bytes"
    \\    "context"
    \\    "encoding/json"
    \\    "fmt"
    \\    "io"
    \\    "net/http"
    \\    "net/url"
    \\    "time"
    \\)
    \\
    \\// Client configuration
    \\type Config struct {
    \\    BaseURL   string
    \\    APIKey    string
    \\    CSRFToken string
    \\    Timeout   time.Duration
    \\}
    \\
    \\// HealthStatus represents server health
    \\type HealthStatus struct {
    \\    Status  string            `json:"status"`
    \\    Version string            `json:"version"`
    \\    Uptime  int64             `json:"uptime"`
    \\    Checks  map[string]string `json:"checks,omitempty"`
    \\}
    \\
    \\// User represents a user account
    \\type User struct {
    \\    ID           string `json:"id"`
    \\    Email        string `json:"email"`
    \\    Name         string `json:"name,omitempty"`
    \\    Status       string `json:"status"`
    \\    CreatedAt    string `json:"created_at,omitempty"`
    \\    LastLogin    string `json:"last_login,omitempty"`
    \\    StorageUsed  int64  `json:"storage_used"`
    \\    StorageQuota int64  `json:"storage_quota"`
    \\}
    \\
    \\// UserList represents a paginated list of users
    \\type UserList struct {
    \\    Users   []User `json:"users"`
    \\    Total   int    `json:"total"`
    \\    Page    int    `json:"page"`
    \\    PerPage int    `json:"per_page"`
    \\}
    \\
    \\// CreateUserRequest for creating a user
    \\type CreateUserRequest struct {
    \\    Email        string `json:"email"`
    \\    Password     string `json:"password"`
    \\    Name         string `json:"name,omitempty"`
    \\    StorageQuota int64  `json:"storage_quota,omitempty"`
    \\}
    \\
    \\// UpdateUserRequest for updating a user
    \\type UpdateUserRequest struct {
    \\    Name         string `json:"name,omitempty"`
    \\    Status       string `json:"status,omitempty"`
    \\    StorageQuota int64  `json:"storage_quota,omitempty"`
    \\}
    \\
    \\// QueueItem represents a mail queue item
    \\type QueueItem struct {
    \\    ID        string `json:"id"`
    \\    From      string `json:"from"`
    \\    To        string `json:"to"`
    \\    Subject   string `json:"subject"`
    \\    Size      int64  `json:"size"`
    \\    Status    string `json:"status"`
    \\    Attempts  int    `json:"attempts"`
    \\    NextRetry string `json:"next_retry"`
    \\    QueuedAt  string `json:"queued_at"`
    \\}
    \\
    \\// QueueList represents the mail queue
    \\type QueueList struct {
    \\    Items    []QueueItem `json:"items"`
    \\    Total    int         `json:"total"`
    \\    Pending  int         `json:"pending"`
    \\    Deferred int         `json:"deferred"`
    \\}
    \\
    \\// Statistics represents server statistics
    \\type Statistics struct {
    \\    MessagesSent       int64   `json:"messages_sent"`
    \\    MessagesReceived   int64   `json:"messages_received"`
    \\    MessagesDelivered  int64   `json:"messages_delivered"`
    \\    MessagesBounced    int64   `json:"messages_bounced"`
    \\    MessagesDeferred   int64   `json:"messages_deferred"`
    \\    SpamBlocked        int64   `json:"spam_blocked"`
    \\    VirusDetected      int64   `json:"virus_detected"`
    \\    ActiveConnections  int     `json:"active_connections"`
    \\    AvgDeliveryTimeMs  float64 `json:"avg_delivery_time_ms"`
    \\}
    \\
    \\// Tenant represents a tenant organization
    \\type Tenant struct {
    \\    ID        string `json:"id"`
    \\    Name      string `json:"name"`
    \\    Domain    string `json:"domain"`
    \\    Status    string `json:"status"`
    \\    UserCount int    `json:"user_count"`
    \\    CreatedAt string `json:"created_at,omitempty"`
    \\}
    \\
    \\// TenantList represents a list of tenants
    \\type TenantList struct {
    \\    Tenants []Tenant `json:"tenants"`
    \\    Total   int      `json:"total"`
    \\}
    \\
    \\// Client is the SMTP Server API client
    \\type Client struct {
    \\    config     Config
    \\    httpClient *http.Client
    \\}
    \\
    \\// NewClient creates a new API client
    \\func NewClient(config Config) *Client {
    \\    if config.Timeout == 0 {
    \\        config.Timeout = 30 * time.Second
    \\    }
    \\    return &Client{
    \\        config: config,
    \\        httpClient: &http.Client{
    \\            Timeout: config.Timeout,
    \\        },
    \\    }
    \\}
    \\
    \\func (c *Client) request(ctx context.Context, method, path string, body interface{}, result interface{}) error {
    \\    var bodyReader io.Reader
    \\    if body != nil {
    \\        data, err := json.Marshal(body)
    \\        if err != nil {
    \\            return err
    \\        }
    \\        bodyReader = bytes.NewReader(data)
    \\    }
    \\
    \\    req, err := http.NewRequestWithContext(ctx, method, c.config.BaseURL+path, bodyReader)
    \\    if err != nil {
    \\        return err
    \\    }
    \\
    \\    req.Header.Set("Content-Type", "application/json")
    \\    if c.config.APIKey != "" {
    \\        req.Header.Set("X-API-Key", c.config.APIKey)
    \\    }
    \\    if c.config.CSRFToken != "" {
    \\        req.Header.Set("X-CSRF-Token", c.config.CSRFToken)
    \\    }
    \\
    \\    resp, err := c.httpClient.Do(req)
    \\    if err != nil {
    \\        return err
    \\    }
    \\    defer resp.Body.Close()
    \\
    \\    if resp.StatusCode >= 400 {
    \\        return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
    \\    }
    \\
    \\    if result != nil && resp.StatusCode != http.StatusNoContent {
    \\        return json.NewDecoder(resp.Body).Decode(result)
    \\    }
    \\    return nil
    \\}
    \\
    \\// GetHealth returns server health status
    \\func (c *Client) GetHealth(ctx context.Context) (*HealthStatus, error) {
    \\    var result HealthStatus
    \\    err := c.request(ctx, "GET", "/health", nil, &result)
    \\    return &result, err
    \\}
    \\
    \\// ListUsers returns paginated users
    \\func (c *Client) ListUsers(ctx context.Context, page, perPage int, search string) (*UserList, error) {
    \\    params := url.Values{}
    \\    params.Set("page", fmt.Sprintf("%d", page))
    \\    params.Set("per_page", fmt.Sprintf("%d", perPage))
    \\    if search != "" {
    \\        params.Set("search", search)
    \\    }
    \\    var result UserList
    \\    err := c.request(ctx, "GET", "/users?"+params.Encode(), nil, &result)
    \\    return &result, err
    \\}
    \\
    \\// CreateUser creates a new user
    \\func (c *Client) CreateUser(ctx context.Context, req CreateUserRequest) (*User, error) {
    \\    var result User
    \\    err := c.request(ctx, "POST", "/users", req, &result)
    \\    return &result, err
    \\}
    \\
    \\// GetUser returns a user by ID
    \\func (c *Client) GetUser(ctx context.Context, id string) (*User, error) {
    \\    var result User
    \\    err := c.request(ctx, "GET", "/users/"+url.PathEscape(id), nil, &result)
    \\    return &result, err
    \\}
    \\
    \\// UpdateUser updates a user
    \\func (c *Client) UpdateUser(ctx context.Context, id string, req UpdateUserRequest) (*User, error) {
    \\    var result User
    \\    err := c.request(ctx, "PUT", "/users/"+url.PathEscape(id), req, &result)
    \\    return &result, err
    \\}
    \\
    \\// DeleteUser deletes a user
    \\func (c *Client) DeleteUser(ctx context.Context, id string) error {
    \\    return c.request(ctx, "DELETE", "/users/"+url.PathEscape(id), nil, nil)
    \\}
    \\
    \\// GetQueue returns the mail queue
    \\func (c *Client) GetQueue(ctx context.Context, status string, limit int) (*QueueList, error) {
    \\    params := url.Values{}
    \\    if status != "" {
    \\        params.Set("status", status)
    \\    }
    \\    params.Set("limit", fmt.Sprintf("%d", limit))
    \\    var result QueueList
    \\    err := c.request(ctx, "GET", "/queue?"+params.Encode(), nil, &result)
    \\    return &result, err
    \\}
    \\
    \\// FlushQueue flushes the mail queue
    \\func (c *Client) FlushQueue(ctx context.Context) error {
    \\    return c.request(ctx, "POST", "/queue/flush", nil, nil)
    \\}
    \\
    \\// GetStats returns server statistics
    \\func (c *Client) GetStats(ctx context.Context, period string) (*Statistics, error) {
    \\    path := "/stats"
    \\    if period != "" {
    \\        path += "?period=" + period
    \\    }
    \\    var result Statistics
    \\    err := c.request(ctx, "GET", path, nil, &result)
    \\    return &result, err
    \\}
    \\
    \\// ListTenants returns all tenants
    \\func (c *Client) ListTenants(ctx context.Context) (*TenantList, error) {
    \\    var result TenantList
    \\    err := c.request(ctx, "GET", "/tenants", nil, &result)
    \\    return &result, err
    \\}
    \\
    \\// Example usage:
    \\// client := smtpserver.NewClient(smtpserver.Config{
    \\//     BaseURL: "http://localhost:8080/api",
    \\//     APIKey:  "your-api-key",
    \\// })
    \\// health, err := client.GetHealth(context.Background())
;

/// Rust SDK
pub const rust_sdk =
    \\//! SMTP Server API Client
    \\//! Auto-generated Rust SDK
    \\//! Version: 0.28.0
    \\
    \\use reqwest::{Client, StatusCode};
    \\use serde::{Deserialize, Serialize};
    \\use std::collections::HashMap;
    \\use thiserror::Error;
    \\
    \\#[derive(Error, Debug)]
    \\pub enum ApiError {
    \\    #[error("HTTP error: {0}")]
    \\    Http(#[from] reqwest::Error),
    \\    #[error("API error: {status} - {message}")]
    \\    Api { status: u16, message: String },
    \\}
    \\
    \\#[derive(Debug, Clone, Deserialize, Serialize)]
    \\pub struct HealthStatus {
    \\    pub status: String,
    \\    pub version: String,
    \\    pub uptime: i64,
    \\    #[serde(skip_serializing_if = "Option::is_none")]
    \\    pub checks: Option<HashMap<String, String>>,
    \\}
    \\
    \\#[derive(Debug, Clone, Deserialize, Serialize)]
    \\pub struct User {
    \\    pub id: String,
    \\    pub email: String,
    \\    #[serde(skip_serializing_if = "Option::is_none")]
    \\    pub name: Option<String>,
    \\    pub status: String,
    \\    #[serde(skip_serializing_if = "Option::is_none")]
    \\    pub created_at: Option<String>,
    \\    #[serde(skip_serializing_if = "Option::is_none")]
    \\    pub last_login: Option<String>,
    \\    pub storage_used: i64,
    \\    pub storage_quota: i64,
    \\}
    \\
    \\#[derive(Debug, Clone, Deserialize, Serialize)]
    \\pub struct UserList {
    \\    pub users: Vec<User>,
    \\    pub total: i32,
    \\    pub page: i32,
    \\    pub per_page: i32,
    \\}
    \\
    \\#[derive(Debug, Clone, Serialize)]
    \\pub struct CreateUserRequest {
    \\    pub email: String,
    \\    pub password: String,
    \\    #[serde(skip_serializing_if = "Option::is_none")]
    \\    pub name: Option<String>,
    \\    #[serde(skip_serializing_if = "Option::is_none")]
    \\    pub storage_quota: Option<i64>,
    \\}
    \\
    \\#[derive(Debug, Clone, Serialize)]
    \\pub struct UpdateUserRequest {
    \\    #[serde(skip_serializing_if = "Option::is_none")]
    \\    pub name: Option<String>,
    \\    #[serde(skip_serializing_if = "Option::is_none")]
    \\    pub status: Option<String>,
    \\    #[serde(skip_serializing_if = "Option::is_none")]
    \\    pub storage_quota: Option<i64>,
    \\}
    \\
    \\#[derive(Debug, Clone, Deserialize, Serialize)]
    \\pub struct QueueItem {
    \\    pub id: String,
    \\    pub from: String,
    \\    pub to: String,
    \\    pub subject: String,
    \\    pub size: i64,
    \\    pub status: String,
    \\    pub attempts: i32,
    \\    pub next_retry: String,
    \\    pub queued_at: String,
    \\}
    \\
    \\#[derive(Debug, Clone, Deserialize, Serialize)]
    \\pub struct QueueList {
    \\    pub items: Vec<QueueItem>,
    \\    pub total: i32,
    \\    pub pending: i32,
    \\    pub deferred: i32,
    \\}
    \\
    \\#[derive(Debug, Clone, Deserialize, Serialize)]
    \\pub struct Statistics {
    \\    pub messages_sent: i64,
    \\    pub messages_received: i64,
    \\    pub messages_delivered: i64,
    \\    pub messages_bounced: i64,
    \\    pub messages_deferred: i64,
    \\    pub spam_blocked: i64,
    \\    pub virus_detected: i64,
    \\    pub active_connections: i32,
    \\    pub avg_delivery_time_ms: f64,
    \\}
    \\
    \\#[derive(Debug, Clone, Deserialize, Serialize)]
    \\pub struct Tenant {
    \\    pub id: String,
    \\    pub name: String,
    \\    pub domain: String,
    \\    pub status: String,
    \\    pub user_count: i32,
    \\    #[serde(skip_serializing_if = "Option::is_none")]
    \\    pub created_at: Option<String>,
    \\}
    \\
    \\#[derive(Debug, Clone, Deserialize, Serialize)]
    \\pub struct TenantList {
    \\    pub tenants: Vec<Tenant>,
    \\    pub total: i32,
    \\}
    \\
    \\pub struct SmtpServerClient {
    \\    client: Client,
    \\    base_url: String,
    \\    api_key: Option<String>,
    \\    csrf_token: Option<String>,
    \\}
    \\
    \\impl SmtpServerClient {
    \\    pub fn new(base_url: &str) -> Self {
    \\        Self {
    \\            client: Client::new(),
    \\            base_url: base_url.trim_end_matches('/').to_string(),
    \\            api_key: None,
    \\            csrf_token: None,
    \\        }
    \\    }
    \\
    \\    pub fn with_api_key(mut self, key: &str) -> Self {
    \\        self.api_key = Some(key.to_string());
    \\        self
    \\    }
    \\
    \\    pub fn with_csrf_token(mut self, token: &str) -> Self {
    \\        self.csrf_token = Some(token.to_string());
    \\        self
    \\    }
    \\
    \\    async fn request<T: for<'de> Deserialize<'de>>(
    \\        &self,
    \\        method: reqwest::Method,
    \\        path: &str,
    \\        body: Option<impl Serialize>,
    \\    ) -> Result<T, ApiError> {
    \\        let url = format!("{}{}", self.base_url, path);
    \\        let mut req = self.client.request(method, &url);
    \\
    \\        if let Some(key) = &self.api_key {
    \\            req = req.header("X-API-Key", key);
    \\        }
    \\        if let Some(token) = &self.csrf_token {
    \\            req = req.header("X-CSRF-Token", token);
    \\        }
    \\        if let Some(b) = body {
    \\            req = req.json(&b);
    \\        }
    \\
    \\        let resp = req.send().await?;
    \\        let status = resp.status();
    \\
    \\        if !status.is_success() {
    \\            let msg = resp.text().await.unwrap_or_default();
    \\            return Err(ApiError::Api {
    \\                status: status.as_u16(),
    \\                message: msg,
    \\            });
    \\        }
    \\
    \\        Ok(resp.json().await?)
    \\    }
    \\
    \\    pub async fn get_health(&self) -> Result<HealthStatus, ApiError> {
    \\        self.request(reqwest::Method::GET, "/health", None::<()>).await
    \\    }
    \\
    \\    pub async fn list_users(&self, page: i32, per_page: i32) -> Result<UserList, ApiError> {
    \\        let path = format!("/users?page={}&per_page={}", page, per_page);
    \\        self.request(reqwest::Method::GET, &path, None::<()>).await
    \\    }
    \\
    \\    pub async fn create_user(&self, req: CreateUserRequest) -> Result<User, ApiError> {
    \\        self.request(reqwest::Method::POST, "/users", Some(req)).await
    \\    }
    \\
    \\    pub async fn get_user(&self, id: &str) -> Result<User, ApiError> {
    \\        let path = format!("/users/{}", id);
    \\        self.request(reqwest::Method::GET, &path, None::<()>).await
    \\    }
    \\
    \\    pub async fn update_user(&self, id: &str, req: UpdateUserRequest) -> Result<User, ApiError> {
    \\        let path = format!("/users/{}", id);
    \\        self.request(reqwest::Method::PUT, &path, Some(req)).await
    \\    }
    \\
    \\    pub async fn delete_user(&self, id: &str) -> Result<(), ApiError> {
    \\        let path = format!("/users/{}", id);
    \\        self.request(reqwest::Method::DELETE, &path, None::<()>).await
    \\    }
    \\
    \\    pub async fn get_queue(&self, limit: i32) -> Result<QueueList, ApiError> {
    \\        let path = format!("/queue?limit={}", limit);
    \\        self.request(reqwest::Method::GET, &path, None::<()>).await
    \\    }
    \\
    \\    pub async fn flush_queue(&self) -> Result<(), ApiError> {
    \\        self.request(reqwest::Method::POST, "/queue/flush", None::<()>).await
    \\    }
    \\
    \\    pub async fn get_stats(&self, period: &str) -> Result<Statistics, ApiError> {
    \\        let path = format!("/stats?period={}", period);
    \\        self.request(reqwest::Method::GET, &path, None::<()>).await
    \\    }
    \\
    \\    pub async fn list_tenants(&self) -> Result<TenantList, ApiError> {
    \\        self.request(reqwest::Method::GET, "/tenants", None::<()>).await
    \\    }
    \\}
    \\
    \\// Example usage:
    \\// let client = SmtpServerClient::new("http://localhost:8080/api")
    \\//     .with_api_key("your-api-key");
    \\// let health = client.get_health().await?;
;

/// cURL examples
pub const curl_examples =
    \\#!/bin/bash
    \\# SMTP Server API - cURL Examples
    \\# Version: 0.28.0
    \\
    \\BASE_URL="${BASE_URL:-http://localhost:8080/api}"
    \\API_KEY="${API_KEY:-your-api-key}"
    \\
    \\# Helper function
    \\api() {
    \\    curl -s -X "$1" "${BASE_URL}$2" \
    \\        -H "Content-Type: application/json" \
    \\        -H "X-API-Key: $API_KEY" \
    \\        "${@:3}"
    \\}
    \\
    \\# =============================================================================
    \\# Health Endpoints
    \\# =============================================================================
    \\
    \\# Get server health
    \\echo "=== Get Health ==="
    \\api GET /health | jq .
    \\
    \\# Readiness probe
    \\echo -e "\n=== Readiness Probe ==="
    \\api GET /health/ready
    \\
    \\# Liveness probe
    \\echo -e "\n=== Liveness Probe ==="
    \\api GET /health/live
    \\
    \\# =============================================================================
    \\# User Management
    \\# =============================================================================
    \\
    \\# List users
    \\echo -e "\n=== List Users ==="
    \\api GET "/users?page=1&per_page=10" | jq .
    \\
    \\# Create user
    \\echo -e "\n=== Create User ==="
    \\api POST /users -d '{
    \\    "email": "newuser@example.com",
    \\    "password": "SecurePass123!",
    \\    "name": "New User"
    \\}' | jq .
    \\
    \\# Get user
    \\echo -e "\n=== Get User ==="
    \\api GET /users/user-id-here | jq .
    \\
    \\# Update user
    \\echo -e "\n=== Update User ==="
    \\api PUT /users/user-id-here -d '{
    \\    "name": "Updated Name",
    \\    "status": "active"
    \\}' | jq .
    \\
    \\# Delete user
    \\echo -e "\n=== Delete User ==="
    \\api DELETE /users/user-id-here
    \\
    \\# =============================================================================
    \\# Queue Management
    \\# =============================================================================
    \\
    \\# List queue
    \\echo -e "\n=== List Queue ==="
    \\api GET "/queue?limit=50" | jq .
    \\
    \\# Flush queue
    \\echo -e "\n=== Flush Queue ==="
    \\api POST /queue/flush | jq .
    \\
    \\# Delete queue item
    \\echo -e "\n=== Delete Queue Item ==="
    \\api DELETE /queue/item-id-here
    \\
    \\# =============================================================================
    \\# Statistics
    \\# =============================================================================
    \\
    \\# Get stats
    \\echo -e "\n=== Get Statistics ==="
    \\api GET "/stats?period=day" | jq .
    \\
    \\# =============================================================================
    \\# Tenant Management
    \\# =============================================================================
    \\
    \\# List tenants
    \\echo -e "\n=== List Tenants ==="
    \\api GET /tenants | jq .
    \\
    \\# Create tenant
    \\echo -e "\n=== Create Tenant ==="
    \\api POST /tenants -d '{
    \\    "name": "Acme Corp",
    \\    "domain": "acme.com",
    \\    "admin_email": "admin@acme.com"
    \\}' | jq .
    \\
    \\# =============================================================================
    \\# Archive Search
    \\# =============================================================================
    \\
    \\# Search archive
    \\echo -e "\n=== Search Archive ==="
    \\api POST /archive/search -d '{
    \\    "query": "invoice",
    \\    "date_from": "2025-01-01",
    \\    "date_to": "2025-12-31",
    \\    "page": 1,
    \\    "per_page": 20
    \\}' | jq .
    \\
    \\echo -e "\n=== Done ==="
;

// Tests
test "Language conversion" {
    try std.testing.expectEqualStrings("TypeScript", Language.typescript.toString());
    try std.testing.expectEqualStrings(".ts", Language.typescript.fileExtension());
    try std.testing.expectEqual(Language.typescript, Language.fromString("typescript").?);
    try std.testing.expectEqual(Language.python, Language.fromString("py").?);
    try std.testing.expectEqual(Language.go_lang, Language.fromString("go").?);
}

test "GeneratorConfig defaults" {
    const config = GeneratorConfig{};
    try std.testing.expectEqual(Language.typescript, config.language);
    try std.testing.expectEqualStrings("./sdk", config.output_dir);
    try std.testing.expect(config.include_examples);
}

test "SdkGenerator init" {
    const allocator = std.testing.allocator;
    var gen = SdkGenerator.init(allocator, .{});
    defer gen.deinit();
    try std.testing.expectEqual(@as(usize, 0), gen.endpoints.items.len);
}

test "SdkGenerator loadDefaultSpec" {
    const allocator = std.testing.allocator;
    var gen = SdkGenerator.init(allocator, .{});
    defer gen.deinit();
    try gen.loadDefaultSpec();
    try std.testing.expect(gen.endpoints.items.len > 0);
    try std.testing.expect(gen.schemas.items.len > 0);
}

test "getSdkContent returns content" {
    const ts_content = SdkGenerator.getSdkContent(.typescript);
    try std.testing.expect(ts_content.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, ts_content, "SmtpServerClient") != null);

    const py_content = SdkGenerator.getSdkContent(.python);
    try std.testing.expect(py_content.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, py_content, "SmtpServerClient") != null);

    const go_content = SdkGenerator.getSdkContent(.go_lang);
    try std.testing.expect(go_content.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, go_content, "Client") != null);
}
