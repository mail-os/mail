const std = @import("std");
const version_info = @import("../core/version.zig");

// =============================================================================
// Swagger UI Integration - Interactive API Documentation
// =============================================================================
//
// ## Overview
// Provides Swagger UI for interactive API documentation and testing:
// - OpenAPI 3.0.3 specification viewer
// - Interactive API testing ("Try it out")
// - Request/response schema documentation
// - Authentication configuration
//
// ## Endpoints
// - /api/docs       - Swagger UI interface
// - /api/docs/spec  - OpenAPI JSON specification
//
// =============================================================================

/// Swagger UI configuration
pub const SwaggerConfig = struct {
    /// Title shown in Swagger UI
    title: []const u8 = "SMTP Server API",
    /// API description
    description: []const u8 = "REST API for SMTP Server administration and management",
    /// Version of the API
    version: []const u8 = version_info.version_display,
    /// Base URL for API requests
    base_url: []const u8 = "/api",
    /// Enable "Try it out" feature
    enable_try_it_out: bool = true,
    /// Deep linking support
    enable_deep_linking: bool = true,
    /// Display operation ID
    display_operation_id: bool = false,
    /// Default models expand depth
    default_models_expand_depth: i32 = 1,
    /// OAuth2 redirect URL
    oauth2_redirect_url: ?[]const u8 = null,
};

/// Swagger UI handler
pub const SwaggerHandler = struct {
    allocator: std.mem.Allocator,
    config: SwaggerConfig,
    openapi_spec: ?[]const u8,

    pub fn init(allocator: std.mem.Allocator, config: SwaggerConfig) SwaggerHandler {
        return .{
            .allocator = allocator,
            .config = config,
            .openapi_spec = null,
        };
    }

    /// Set custom OpenAPI spec (loaded from file)
    pub fn setOpenApiSpec(self: *SwaggerHandler, spec: []const u8) void {
        self.openapi_spec = spec;
    }

    /// Handle HTTP request
    pub fn handleRequest(self: *SwaggerHandler, path: []const u8, method: []const u8) ![]u8 {
        if (!std.mem.eql(u8, method, "GET")) {
            return self.serveError(405, "Method Not Allowed");
        }

        if (std.mem.eql(u8, path, "/api/docs") or std.mem.eql(u8, path, "/api/docs/")) {
            return self.serveSwaggerUI();
        } else if (std.mem.eql(u8, path, "/api/docs/spec") or std.mem.eql(u8, path, "/api/docs/spec.json")) {
            return self.serveOpenApiSpec();
        } else if (std.mem.eql(u8, path, "/api/docs/oauth2-redirect.html")) {
            return self.serveOAuth2Redirect();
        }

        return self.serveError(404, "Not Found");
    }

    fn serveError(self: *SwaggerHandler, status: u16, message: []const u8) ![]u8 {
        return std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 {d} {s}\r\nContent-Type: application/json\r\n\r\n{{\"error\": \"{s}\"}}",
            .{ status, message, message },
        );
    }

    /// Serve the Swagger UI HTML page
    pub fn serveSwaggerUI(self: *SwaggerHandler) ![]u8 {
        const html = swagger_ui_html;
        return std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ html.len, html },
        );
    }

    /// Serve the OpenAPI specification
    pub fn serveOpenApiSpec(self: *SwaggerHandler) ![]u8 {
        const spec = self.openapi_spec orelse default_openapi_spec;
        return std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ spec.len, spec },
        );
    }

    /// Serve OAuth2 redirect page for authentication flows
    fn serveOAuth2Redirect(self: *SwaggerHandler) ![]u8 {
        const html = oauth2_redirect_html;
        return std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ html.len, html },
        );
    }
};

/// Swagger UI HTML template (loads from CDN)
const swagger_ui_html =
    \\<!DOCTYPE html>
    \\<html lang="en">
    \\<head>
    \\    <meta charset="UTF-8">
    \\    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    \\    <meta name="description" content="SMTP Server API Documentation">
    \\    <title>API Documentation - SMTP Server</title>
    \\    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui.css">
    \\    <style>
    \\        * { margin: 0; padding: 0; box-sizing: border-box; }
    \\        body { background: #fafafa; }
    \\        .swagger-ui .topbar { display: none; }
    \\        .swagger-ui .info { margin: 30px 0; }
    \\        .swagger-ui .info .title { font-size: 2rem; }
    \\        .swagger-ui .info .description { font-size: 1rem; color: #555; }
    \\        .custom-header {
    \\            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    \\            color: white;
    \\            padding: 20px 40px;
    \\            display: flex;
    \\            align-items: center;
    \\            gap: 16px;
    \\        }
    \\        .custom-header h1 { font-size: 1.5rem; font-weight: 600; }
    \\        .custom-header .version {
    \\            background: rgba(255,255,255,0.2);
    \\            padding: 4px 12px;
    \\            border-radius: 12px;
    \\            font-size: 0.8rem;
    \\        }
    \\        .custom-header .links {
    \\            margin-left: auto;
    \\            display: flex;
    \\            gap: 16px;
    \\        }
    \\        .custom-header a {
    \\            color: white;
    \\            text-decoration: none;
    \\            font-size: 0.875rem;
    \\            opacity: 0.9;
    \\            transition: opacity 0.2s;
    \\        }
    \\        .custom-header a:hover { opacity: 1; }
    \\        #swagger-ui { max-width: 1400px; margin: 0 auto; padding: 0 20px; }
    \\        .swagger-ui .opblock.opblock-get { border-color: #61affe; background: rgba(97, 175, 254, 0.1); }
    \\        .swagger-ui .opblock.opblock-post { border-color: #49cc90; background: rgba(73, 204, 144, 0.1); }
    \\        .swagger-ui .opblock.opblock-put { border-color: #fca130; background: rgba(252, 161, 48, 0.1); }
    \\        .swagger-ui .opblock.opblock-delete { border-color: #f93e3e; background: rgba(249, 62, 62, 0.1); }
    \\        .swagger-ui .opblock .opblock-summary-method {
    \\            font-weight: 600;
    \\            min-width: 80px;
    \\        }
    \\        .swagger-ui .btn.execute { background: #667eea; border-color: #667eea; }
    \\        .swagger-ui .btn.execute:hover { background: #5a6fd6; }
    \\        .swagger-ui .model-box { background: #f7f7f7; }
    \\        .swagger-ui section.models { border: 1px solid #e0e0e0; border-radius: 8px; }
    \\        .swagger-ui section.models h4 { padding: 16px; background: #f5f5f5; border-radius: 8px 8px 0 0; }
    \\        @media (max-width: 768px) {
    \\            .custom-header { padding: 16px 20px; flex-wrap: wrap; }
    \\            .custom-header .links { width: 100%; margin-top: 12px; margin-left: 0; }
    \\        }
    \\    </style>
    \\</head>
    \\<body>
    \\    <header class="custom-header">
    \\        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
    \\            <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
    \\            <polyline points="22,6 12,13 2,6"/>
    \\        </svg>
    \\        <h1>SMTP Server API</h1>
    \\        <span class="version">v0.28.0</span>
    \\        <div class="links">
    \\            <a href="/admin">Admin Panel</a>
    \\            <a href="/api/docs/spec" target="_blank">OpenAPI Spec</a>
    \\            <a href="https://github.com/stacksjs/mail" target="_blank">GitHub</a>
    \\        </div>
    \\    </header>
    \\    <div id="swagger-ui"></div>
    \\    <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-bundle.js"></script>
    \\    <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-standalone-preset.js"></script>
    \\    <script>
    \\        window.onload = () => {
    \\            window.ui = SwaggerUIBundle({
    \\                url: '/api/docs/spec',
    \\                dom_id: '#swagger-ui',
    \\                deepLinking: true,
    \\                presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
    \\                plugins: [SwaggerUIBundle.plugins.DownloadUrl],
    \\                layout: 'StandaloneLayout',
    \\                defaultModelsExpandDepth: 1,
    \\                displayRequestDuration: true,
    \\                filter: true,
    \\                showExtensions: true,
    \\                showCommonExtensions: true,
    \\                tryItOutEnabled: true,
    \\                requestSnippetsEnabled: true,
    \\                persistAuthorization: true,
    \\                withCredentials: true
    \\            });
    \\        };
    \\    </script>
    \\</body>
    \\</html>
;

/// OAuth2 redirect page for Swagger UI auth flows
const oauth2_redirect_html =
    \\<!DOCTYPE html>
    \\<html lang="en">
    \\<head>
    \\    <title>OAuth2 Redirect</title>
    \\</head>
    \\<body>
    \\    <script src="https://unpkg.com/swagger-ui-dist@5.9.0/oauth2-redirect.js"></script>
    \\</body>
    \\</html>
;

/// Default OpenAPI specification (embedded)
const default_openapi_spec =
    \\{
    \\  "openapi": "3.0.3",
    \\  "info": {
    \\    "title": "SMTP Server API",
    \\    "description": "REST API for SMTP Server administration, monitoring, and email management.\n\n## Authentication\nAll endpoints require authentication via CSRF token or API key.\n\n## Rate Limiting\nAPI requests are rate limited to 100 requests per minute per IP address.",
    \\    "version": "0.28.0",
    \\    "contact": {
    \\      "name": "SMTP Server Support",
    \\      "url": "https://github.com/stacksjs/mail"
    \\    },
    \\    "license": {
    \\      "name": "MIT",
    \\      "url": "https://opensource.org/licenses/MIT"
    \\    }
    \\  },
    \\  "servers": [
    \\    {
    \\      "url": "/api",
    \\      "description": "Local server"
    \\    }
    \\  ],
    \\  "tags": [
    \\    {"name": "Health", "description": "Server health and status endpoints"},
    \\    {"name": "Users", "description": "User management operations"},
    \\    {"name": "Domains", "description": "Domain configuration"},
    \\    {"name": "Queue", "description": "Mail queue management"},
    \\    {"name": "Messages", "description": "Message operations"},
    \\    {"name": "Statistics", "description": "Server statistics and metrics"},
    \\    {"name": "Tenants", "description": "Multi-tenancy management"},
    \\    {"name": "Archive", "description": "Email archiving operations"}
    \\  ],
    \\  "paths": {
    \\    "/health": {
    \\      "get": {
    \\        "tags": ["Health"],
    \\        "summary": "Get server health status",
    \\        "description": "Returns the current health status of the SMTP server including uptime, version, and component status.",
    \\        "operationId": "getHealth",
    \\        "responses": {
    \\          "200": {
    \\            "description": "Server is healthy",
    \\            "content": {
    \\              "application/json": {
    \\                "schema": {"$ref": "#/components/schemas/HealthStatus"}
    \\              }
    \\            }
    \\          },
    \\          "503": {
    \\            "description": "Server is unhealthy",
    \\            "content": {
    \\              "application/json": {
    \\                "schema": {"$ref": "#/components/schemas/HealthStatus"}
    \\              }
    \\            }
    \\          }
    \\        }
    \\      }
    \\    },
    \\    "/health/ready": {
    \\      "get": {
    \\        "tags": ["Health"],
    \\        "summary": "Readiness probe",
    \\        "description": "Kubernetes readiness probe endpoint. Returns 200 if server is ready to accept traffic.",
    \\        "operationId": "getReadiness",
    \\        "responses": {
    \\          "200": {"description": "Server is ready"},
    \\          "503": {"description": "Server is not ready"}
    \\        }
    \\      }
    \\    },
    \\    "/health/live": {
    \\      "get": {
    \\        "tags": ["Health"],
    \\        "summary": "Liveness probe",
    \\        "description": "Kubernetes liveness probe endpoint. Returns 200 if server is alive.",
    \\        "operationId": "getLiveness",
    \\        "responses": {
    \\          "200": {"description": "Server is alive"},
    \\          "503": {"description": "Server is not responding"}
    \\        }
    \\      }
    \\    },
    \\    "/users": {
    \\      "get": {
    \\        "tags": ["Users"],
    \\        "summary": "List all users",
    \\        "description": "Returns a paginated list of all users.",
    \\        "operationId": "listUsers",
    \\        "parameters": [
    \\          {"name": "page", "in": "query", "schema": {"type": "integer", "default": 1}},
    \\          {"name": "per_page", "in": "query", "schema": {"type": "integer", "default": 50}},
    \\          {"name": "search", "in": "query", "schema": {"type": "string"}}
    \\        ],
    \\        "responses": {
    \\          "200": {
    \\            "description": "List of users",
    \\            "content": {
    \\              "application/json": {
    \\                "schema": {"$ref": "#/components/schemas/UserList"}
    \\              }
    \\            }
    \\          }
    \\        },
    \\        "security": [{"csrfToken": []}, {"apiKey": []}]
    \\      },
    \\      "post": {
    \\        "tags": ["Users"],
    \\        "summary": "Create a new user",
    \\        "description": "Creates a new user account with the specified email and password.",
    \\        "operationId": "createUser",
    \\        "requestBody": {
    \\          "required": true,
    \\          "content": {
    \\            "application/json": {
    \\              "schema": {"$ref": "#/components/schemas/CreateUserRequest"}
    \\            }
    \\          }
    \\        },
    \\        "responses": {
    \\          "201": {
    \\            "description": "User created",
    \\            "content": {
    \\              "application/json": {
    \\                "schema": {"$ref": "#/components/schemas/User"}
    \\              }
    \\            }
    \\          },
    \\          "400": {"description": "Invalid request"},
    \\          "409": {"description": "User already exists"}
    \\        },
    \\        "security": [{"csrfToken": []}, {"apiKey": []}]
    \\      }
    \\    },
    \\    "/users/{id}": {
    \\      "get": {
    \\        "tags": ["Users"],
    \\        "summary": "Get user by ID",
    \\        "operationId": "getUser",
    \\        "parameters": [
    \\          {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}
    \\        ],
    \\        "responses": {
    \\          "200": {
    \\            "description": "User details",
    \\            "content": {
    \\              "application/json": {
    \\                "schema": {"$ref": "#/components/schemas/User"}
    \\              }
    \\            }
    \\          },
    \\          "404": {"description": "User not found"}
    \\        },
    \\        "security": [{"csrfToken": []}, {"apiKey": []}]
    \\      },
    \\      "put": {
    \\        "tags": ["Users"],
    \\        "summary": "Update user",
    \\        "operationId": "updateUser",
    \\        "parameters": [
    \\          {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}
    \\        ],
    \\        "requestBody": {
    \\          "content": {
    \\            "application/json": {
    \\              "schema": {"$ref": "#/components/schemas/UpdateUserRequest"}
    \\            }
    \\          }
    \\        },
    \\        "responses": {
    \\          "200": {"description": "User updated"},
    \\          "404": {"description": "User not found"}
    \\        },
    \\        "security": [{"csrfToken": []}, {"apiKey": []}]
    \\      },
    \\      "delete": {
    \\        "tags": ["Users"],
    \\        "summary": "Delete user",
    \\        "operationId": "deleteUser",
    \\        "parameters": [
    \\          {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}
    \\        ],
    \\        "responses": {
    \\          "204": {"description": "User deleted"},
    \\          "404": {"description": "User not found"}
    \\        },
    \\        "security": [{"csrfToken": []}, {"apiKey": []}]
    \\      }
    \\    },
    \\    "/queue": {
    \\      "get": {
    \\        "tags": ["Queue"],
    \\        "summary": "List queue items",
    \\        "description": "Returns the current mail queue with filtering options.",
    \\        "operationId": "listQueue",
    \\        "parameters": [
    \\          {"name": "status", "in": "query", "schema": {"type": "string", "enum": ["pending", "deferred", "bounced"]}},
    \\          {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 100}}
    \\        ],
    \\        "responses": {
    \\          "200": {
    \\            "description": "Queue items",
    \\            "content": {
    \\              "application/json": {
    \\                "schema": {"$ref": "#/components/schemas/QueueList"}
    \\              }
    \\            }
    \\          }
    \\        },
    \\        "security": [{"csrfToken": []}, {"apiKey": []}]
    \\      }
    \\    },
    \\    "/queue/flush": {
    \\      "post": {
    \\        "tags": ["Queue"],
    \\        "summary": "Flush the mail queue",
    \\        "description": "Attempts to deliver all pending messages in the queue.",
    \\        "operationId": "flushQueue",
    \\        "responses": {
    \\          "200": {"description": "Queue flush initiated"},
    \\          "500": {"description": "Failed to flush queue"}
    \\        },
    \\        "security": [{"csrfToken": []}, {"apiKey": []}]
    \\      }
    \\    },
    \\    "/queue/{id}": {
    \\      "delete": {
    \\        "tags": ["Queue"],
    \\        "summary": "Remove item from queue",
    \\        "operationId": "deleteQueueItem",
    \\        "parameters": [
    \\          {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}
    \\        ],
    \\        "responses": {
    \\          "204": {"description": "Item removed"},
    \\          "404": {"description": "Item not found"}
    \\        },
    \\        "security": [{"csrfToken": []}, {"apiKey": []}]
    \\      }
    \\    },
    \\    "/stats": {
    \\      "get": {
    \\        "tags": ["Statistics"],
    \\        "summary": "Get server statistics",
    \\        "description": "Returns detailed server statistics including message counts, delivery rates, and performance metrics.",
    \\        "operationId": "getStats",
    \\        "parameters": [
    \\          {"name": "period", "in": "query", "schema": {"type": "string", "enum": ["hour", "day", "week", "month"], "default": "day"}}
    \\        ],
    \\        "responses": {
    \\          "200": {
    \\            "description": "Server statistics",
    \\            "content": {
    \\              "application/json": {
    \\                "schema": {"$ref": "#/components/schemas/Statistics"}
    \\              }
    \\            }
    \\          }
    \\        },
    \\        "security": [{"csrfToken": []}, {"apiKey": []}]
    \\      }
    \\    },
    \\    "/tenants": {
    \\      "get": {
    \\        "tags": ["Tenants"],
    \\        "summary": "List all tenants",
    \\        "operationId": "listTenants",
    \\        "responses": {
    \\          "200": {
    \\            "description": "List of tenants",
    \\            "content": {
    \\              "application/json": {
    \\                "schema": {"$ref": "#/components/schemas/TenantList"}
    \\              }
    \\            }
    \\          }
    \\        },
    \\        "security": [{"csrfToken": []}, {"apiKey": []}]
    \\      },
    \\      "post": {
    \\        "tags": ["Tenants"],
    \\        "summary": "Create a new tenant",
    \\        "operationId": "createTenant",
    \\        "requestBody": {
    \\          "required": true,
    \\          "content": {
    \\            "application/json": {
    \\              "schema": {"$ref": "#/components/schemas/CreateTenantRequest"}
    \\            }
    \\          }
    \\        },
    \\        "responses": {
    \\          "201": {"description": "Tenant created"},
    \\          "400": {"description": "Invalid request"}
    \\        },
    \\        "security": [{"csrfToken": []}, {"apiKey": []}]
    \\      }
    \\    },
    \\    "/archive/search": {
    \\      "post": {
    \\        "tags": ["Archive"],
    \\        "summary": "Search archived emails",
    \\        "operationId": "searchArchive",
    \\        "requestBody": {
    \\          "required": true,
    \\          "content": {
    \\            "application/json": {
    \\              "schema": {"$ref": "#/components/schemas/ArchiveSearchRequest"}
    \\            }
    \\          }
    \\        },
    \\        "responses": {
    \\          "200": {
    \\            "description": "Search results",
    \\            "content": {
    \\              "application/json": {
    \\                "schema": {"$ref": "#/components/schemas/ArchiveSearchResults"}
    \\              }
    \\            }
    \\          }
    \\        },
    \\        "security": [{"csrfToken": []}, {"apiKey": []}]
    \\      }
    \\    }
    \\  },
    \\  "components": {
    \\    "schemas": {
    \\      "HealthStatus": {
    \\        "type": "object",
    \\        "properties": {
    \\          "status": {"type": "string", "enum": ["healthy", "degraded", "unhealthy"]},
    \\          "version": {"type": "string"},
    \\          "uptime": {"type": "integer", "description": "Uptime in seconds"},
    \\          "checks": {
    \\            "type": "object",
    \\            "additionalProperties": {"type": "string"}
    \\          }
    \\        }
    \\      },
    \\      "User": {
    \\        "type": "object",
    \\        "properties": {
    \\          "id": {"type": "string"},
    \\          "email": {"type": "string", "format": "email"},
    \\          "name": {"type": "string"},
    \\          "status": {"type": "string", "enum": ["active", "suspended", "pending"]},
    \\          "created_at": {"type": "string", "format": "date-time"},
    \\          "last_login": {"type": "string", "format": "date-time"},
    \\          "storage_used": {"type": "integer"},
    \\          "storage_quota": {"type": "integer"}
    \\        }
    \\      },
    \\      "UserList": {
    \\        "type": "object",
    \\        "properties": {
    \\          "users": {"type": "array", "items": {"$ref": "#/components/schemas/User"}},
    \\          "total": {"type": "integer"},
    \\          "page": {"type": "integer"},
    \\          "per_page": {"type": "integer"}
    \\        }
    \\      },
    \\      "CreateUserRequest": {
    \\        "type": "object",
    \\        "required": ["email", "password"],
    \\        "properties": {
    \\          "email": {"type": "string", "format": "email"},
    \\          "password": {"type": "string", "minLength": 8},
    \\          "name": {"type": "string"},
    \\          "storage_quota": {"type": "integer", "default": 1073741824}
    \\        }
    \\      },
    \\      "UpdateUserRequest": {
    \\        "type": "object",
    \\        "properties": {
    \\          "name": {"type": "string"},
    \\          "status": {"type": "string", "enum": ["active", "suspended"]},
    \\          "storage_quota": {"type": "integer"}
    \\        }
    \\      },
    \\      "QueueItem": {
    \\        "type": "object",
    \\        "properties": {
    \\          "id": {"type": "string"},
    \\          "from": {"type": "string", "format": "email"},
    \\          "to": {"type": "string", "format": "email"},
    \\          "subject": {"type": "string"},
    \\          "size": {"type": "integer"},
    \\          "status": {"type": "string", "enum": ["pending", "deferred", "bounced"]},
    \\          "attempts": {"type": "integer"},
    \\          "next_retry": {"type": "string", "format": "date-time"},
    \\          "queued_at": {"type": "string", "format": "date-time"}
    \\        }
    \\      },
    \\      "QueueList": {
    \\        "type": "object",
    \\        "properties": {
    \\          "items": {"type": "array", "items": {"$ref": "#/components/schemas/QueueItem"}},
    \\          "total": {"type": "integer"},
    \\          "pending": {"type": "integer"},
    \\          "deferred": {"type": "integer"}
    \\        }
    \\      },
    \\      "Statistics": {
    \\        "type": "object",
    \\        "properties": {
    \\          "messages_sent": {"type": "integer"},
    \\          "messages_received": {"type": "integer"},
    \\          "messages_delivered": {"type": "integer"},
    \\          "messages_bounced": {"type": "integer"},
    \\          "messages_deferred": {"type": "integer"},
    \\          "spam_blocked": {"type": "integer"},
    \\          "virus_detected": {"type": "integer"},
    \\          "active_connections": {"type": "integer"},
    \\          "avg_delivery_time_ms": {"type": "number"}
    \\        }
    \\      },
    \\      "Tenant": {
    \\        "type": "object",
    \\        "properties": {
    \\          "id": {"type": "string"},
    \\          "name": {"type": "string"},
    \\          "domain": {"type": "string"},
    \\          "status": {"type": "string", "enum": ["active", "suspended"]},
    \\          "user_count": {"type": "integer"},
    \\          "created_at": {"type": "string", "format": "date-time"}
    \\        }
    \\      },
    \\      "TenantList": {
    \\        "type": "object",
    \\        "properties": {
    \\          "tenants": {"type": "array", "items": {"$ref": "#/components/schemas/Tenant"}},
    \\          "total": {"type": "integer"}
    \\        }
    \\      },
    \\      "CreateTenantRequest": {
    \\        "type": "object",
    \\        "required": ["name", "domain"],
    \\        "properties": {
    \\          "name": {"type": "string"},
    \\          "domain": {"type": "string"},
    \\          "admin_email": {"type": "string", "format": "email"}
    \\        }
    \\      },
    \\      "ArchiveSearchRequest": {
    \\        "type": "object",
    \\        "properties": {
    \\          "query": {"type": "string"},
    \\          "from": {"type": "string"},
    \\          "to": {"type": "string"},
    \\          "subject": {"type": "string"},
    \\          "date_from": {"type": "string", "format": "date"},
    \\          "date_to": {"type": "string", "format": "date"},
    \\          "page": {"type": "integer", "default": 1},
    \\          "per_page": {"type": "integer", "default": 50}
    \\        }
    \\      },
    \\      "ArchiveSearchResults": {
    \\        "type": "object",
    \\        "properties": {
    \\          "results": {"type": "array", "items": {"$ref": "#/components/schemas/ArchivedMessage"}},
    \\          "total": {"type": "integer"},
    \\          "page": {"type": "integer"},
    \\          "per_page": {"type": "integer"}
    \\        }
    \\      },
    \\      "ArchivedMessage": {
    \\        "type": "object",
    \\        "properties": {
    \\          "id": {"type": "string"},
    \\          "from": {"type": "string"},
    \\          "to": {"type": "array", "items": {"type": "string"}},
    \\          "subject": {"type": "string"},
    \\          "date": {"type": "string", "format": "date-time"},
    \\          "size": {"type": "integer"},
    \\          "has_attachments": {"type": "boolean"}
    \\        }
    \\      }
    \\    },
    \\    "securitySchemes": {
    \\      "csrfToken": {
    \\        "type": "apiKey",
    \\        "in": "header",
    \\        "name": "X-CSRF-Token",
    \\        "description": "CSRF token obtained from /api/csrf endpoint"
    \\      },
    \\      "apiKey": {
    \\        "type": "apiKey",
    \\        "in": "header",
    \\        "name": "X-API-Key",
    \\        "description": "API key for programmatic access"
    \\      },
    \\      "bearerAuth": {
    \\        "type": "http",
    \\        "scheme": "bearer",
    \\        "bearerFormat": "JWT"
    \\      }
    \\    }
    \\  },
    \\  "security": [
    \\    {"csrfToken": []},
    \\    {"apiKey": []},
    \\    {"bearerAuth": []}
    \\  ]
    \\}
;

// Tests
test "SwaggerConfig defaults" {
    const config = SwaggerConfig{};
    try std.testing.expectEqualStrings("SMTP Server API", config.title);
    try std.testing.expect(config.enable_try_it_out);
    try std.testing.expect(config.enable_deep_linking);
}

test "SwaggerHandler init" {
    const allocator = std.testing.allocator;
    const handler = SwaggerHandler.init(allocator, .{});
    try std.testing.expect(handler.openapi_spec == null);
    try std.testing.expect(handler.config.enable_try_it_out);
}

test "SwaggerHandler setOpenApiSpec" {
    const allocator = std.testing.allocator;
    var handler = SwaggerHandler.init(allocator, .{});
    const custom_spec = "{\"openapi\": \"3.0.3\"}";
    handler.setOpenApiSpec(custom_spec);
    try std.testing.expect(handler.openapi_spec != null);
    try std.testing.expectEqualStrings(custom_spec, handler.openapi_spec.?);
}
